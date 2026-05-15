/* SPDX-License-Identifier: ISC */
/*
 * test_proxy_9p — TLY-A2-impl-2 raw 9P-frame proxy.
 *
 * Two halves:
 *
 *   1. Parser unit tests for `stm_proxy_9p_parse_tattach_aname` —
 *      pins the refusal class (R139 doctrine carry: truncated body,
 *      oversize aname, embedded NUL, empty, "/").
 *
 *   2. End-to-end bilateral tests: stand up a fake coord (a stratumd
 *      FS-server) on socket A; stand up a proxy worker on socket B
 *      that dials socket A on demand; drive raw 9P Tversion+Tattach
 *      through socket B; confirm the proxy admits/refuses per its
 *      `--datasets-allowed` pattern list, and that admission yields
 *      the coord's canonical response while refusal short-circuits
 *      with Rlerror(EACCES) without ever touching the coord.
 */

#include "tharness.h"
#include "test_fs_common.h"

#include "../src/cmd/stratumd/proxy_9p.h"

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/stratumd.h>
#include <stratum/types.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Wire helpers (shared with test_stratumd_user_policy.c).                */
/* ────────────────────────────────────────────────────────────────────── */

/* Build a well-formed Tattach with the supplied aname. fid = 1,
 * afid = NOFID = 0xFFFFFFFF, uname = "" (length 0), n_uname = 0. */
static size_t build_tattach(uint8_t *out, size_t out_cap,
                              const uint8_t *aname, size_t alen)
{
    size_t body = 4 + 4 + 2 + 0 + 2 + alen + 4;
    size_t total = 7 + body;
    if (total > out_cap) return 0;

    out[0] = (uint8_t)(total & 0xFF);
    out[1] = (uint8_t)((total >> 8) & 0xFF);
    out[2] = (uint8_t)((total >> 16) & 0xFF);
    out[3] = (uint8_t)((total >> 24) & 0xFF);
    out[4] = 104; /* Tattach */
    out[5] = 0x01; out[6] = 0x00; /* tag = 1 */
    out[7] = 1; out[8] = 0; out[9] = 0; out[10] = 0;
    out[11] = 0xFF; out[12] = 0xFF; out[13] = 0xFF; out[14] = 0xFF;
    out[15] = 0; out[16] = 0;
    out[17] = (uint8_t)(alen & 0xFF);
    out[18] = (uint8_t)((alen >> 8) & 0xFF);
    if (alen) memcpy(out + 19, aname, alen);
    size_t p = 19 + alen;
    out[p+0] = 0; out[p+1] = 0; out[p+2] = 0; out[p+3] = 0;
    return total;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Parser unit tests.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(proxy_9p_parse_tattach_happy_path)
{
    uint8_t frame[64];
    const uint8_t aname[] = "users/michael";
    size_t n = build_tattach(frame, sizeof frame, aname, sizeof aname - 1);
    STM_ASSERT(n > 0);

    size_t off = 0;
    uint16_t alen = 0;
    STM_ASSERT(stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                    &off, &alen));
    STM_ASSERT_EQ((long long)alen, (long long)(sizeof aname - 1));
    STM_ASSERT_EQ(memcmp(frame + off, aname, sizeof aname - 1), 0);
}

STM_TEST(proxy_9p_parse_tattach_refuses_truncated_body)
{
    /* body_len = 8 (only fid + afid). */
    uint8_t frame[15] = {0};
    frame[0] = 15;
    frame[4] = 104;
    frame[5] = 1; frame[6] = 0;

    size_t off = 0; uint16_t alen = 0;
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, 15u, &off, &alen));
}

STM_TEST(proxy_9p_parse_tattach_refuses_embedded_nul)
{
    /* aname = "users\x00escape" (alen=12). */
    uint8_t aname[12];
    memcpy(aname, "users", 5);
    aname[5] = 0x00;
    memcpy(aname + 6, "escape", 6);

    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, aname, sizeof aname);
    STM_ASSERT(n > 0);

    size_t off = 0; uint16_t alen = 0;
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     &off, &alen));
}

STM_TEST(proxy_9p_parse_tattach_refuses_empty_aname)
{
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, NULL, 0);
    STM_ASSERT(n > 0);

    size_t off = 0; uint16_t alen = 0;
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     &off, &alen));
}

STM_TEST(proxy_9p_parse_tattach_refuses_slash_aname)
{
    const uint8_t aname[] = "/";
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, aname, 1);
    STM_ASSERT(n > 0);

    size_t off = 0; uint16_t alen = 0;
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     &off, &alen));
}

STM_TEST(proxy_9p_parse_tattach_refuses_non_tattach_type)
{
    /* Build a frame that LOOKS like Tattach in length but has type
     * Tversion (100) — the parser must return false. */
    uint8_t frame[64];
    const uint8_t aname[] = "x";
    size_t n = build_tattach(frame, sizeof frame, aname, 1);
    STM_ASSERT(n > 0);
    frame[4] = 100; /* override type to Tversion */

    size_t off = 0; uint16_t alen = 0;
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     &off, &alen));
}

STM_TEST(proxy_9p_parse_tattach_refuses_non_nul_control_bytes)
{
    /* R140 P2-5 regression: aname containing a non-NUL control
     * byte must be refused at the wrapper. Pre-R140 the wrapper
     * refused only NUL; control bytes flowed to the matcher,
     * which doesn't refuse name-side bytes. */
    uint8_t aname[14] = {
        'u', 's', 'e', 'r', 's', '/', 'm', 'i', 'c', 'h', 0x01, 'a', 'e', 'l'
    };
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, aname, sizeof aname);
    STM_ASSERT(n > 0);

    size_t off = 0; uint16_t alen = 0;
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     &off, &alen));

    /* 0x7F (DEL) — same class. */
    uint8_t aname2[13] = {
        'u', 's', 'e', 'r', 's', '/', 'd', 'e', 'l', 0x7F, 'e', 't', 'e'
    };
    n = build_tattach(frame, sizeof frame, aname2, sizeof aname2);
    STM_ASSERT(n > 0);
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     &off, &alen));

    /* High-bit byte (UTF-8 multi-byte continuation) — passes
     * through (no refusal). */
    uint8_t aname3[4] = { 'u', 'i', 0xC3, 0xA9 }; /* "ué" */
    n = build_tattach(frame, sizeof frame, aname3, 4);
    STM_ASSERT(n > 0);
    STM_ASSERT(stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                    &off, &alen));
}

STM_TEST(proxy_9p_parse_tattach_refuses_null_args)
{
    size_t off = 0; uint16_t alen = 0;
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(NULL, 64u, &off, &alen));

    uint8_t frame[64];
    const uint8_t aname[] = "x";
    size_t n = build_tattach(frame, sizeof frame, aname, 1);
    STM_ASSERT(n > 0);
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     NULL, &alen));
    STM_ASSERT(!stm_proxy_9p_parse_tattach_aname(frame, (uint32_t)n,
                                                     &off, NULL));
}

/* ────────────────────────────────────────────────────────────────────── */
/* End-to-end bilateral fixture: coord (FS stratumd) + proxy worker.    */
/* ────────────────────────────────────────────────────────────────────── */

static char g_coord_sock[256];
static char g_proxy_sock[256];

static void build_paths(const char *tag)
{
    snprintf(g_coord_sock, sizeof g_coord_sock,
             "/tmp/stm_proxy_coord_%d_%s.sock", (int)getpid(), tag);
    snprintf(g_proxy_sock, sizeof g_proxy_sock,
             "/tmp/stm_proxy_up_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(g_coord_sock);
    (void)unlink(g_proxy_sock);
}

typedef struct {
    int          listen_fd;
    stm_fs      *fs;
    atomic_bool  stop_flag;
} coord_ctx;

static void *coord_main(void *arg)
{
    coord_ctx *c = (coord_ctx *)arg;
    (void)stm_stratumd_accept_loop(c->listen_fd, c->fs,
                                       STM_9P_MSIZE_DEFAULT,
                                       /*root_dataset=*/1u,
                                       /*idle_timeout_ms=*/0,
                                       /*allow_unauth=*/false,
                                       &c->stop_flag,
                                       /*user_policy=*/NULL);
    return NULL;
}

typedef struct {
    int                 listen_fd;
    const char         *coord_path;
    const char *const  *patterns;
    size_t              n_patterns;
    /* TLY-A2-impl-3: optional downstream-side SO_PEERCRED check. */
    bool                coord_uid_check_enabled;
    uid_t               coord_uid;
    atomic_bool         stop_flag;
} proxy_ctx;

/* Single-connection proxy accept thread. accept() one upstream conn,
 * dispatch to stm_proxy_9p_serve_client, repeat until stop_flag fires. */
static void *proxy_main(void *arg)
{
    proxy_ctx *p = (proxy_ctx *)arg;
    while (!atomic_load_explicit(&p->stop_flag, memory_order_acquire)) {
        struct pollfd pfd = { p->listen_fd, POLLIN, 0 };
        int prc = poll(&pfd, 1, 200);
        if (prc <= 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        int up = accept(p->listen_fd, NULL, NULL);
        if (up < 0) continue;
        /* Serve synchronously on the accept thread for v1 of the
         * test harness — only one upstream client per test. */
        (void)stm_proxy_9p_serve_client(up, p->coord_path,
                                            p->patterns, p->n_patterns,
                                            /*peer_uid=*/(uid_t)getuid(),
                                            /*peer_gid=*/(gid_t)getgid(),
                                            STM_9P_MSIZE_DEFAULT,
                                            /*idle_timeout_ms=*/0,
                                            p->coord_uid_check_enabled,
                                            p->coord_uid);
    }
    return NULL;
}

typedef struct {
    coord_ctx     cc;
    proxy_ctx     pc;
    pthread_t     coord_tid;
    pthread_t     proxy_tid;
    stm_fs       *fs;
} bilateral_fixture;

static void bilateral_init_with_uid_check(bilateral_fixture *f,
                                              const char *tag,
                                              const char *const *patterns,
                                              size_t n_patterns,
                                              bool coord_uid_check_enabled,
                                              uid_t coord_uid);

static void bilateral_init(bilateral_fixture *f, const char *tag,
                              const char *const *patterns,
                              size_t n_patterns)
{
    bilateral_init_with_uid_check(f, tag, patterns, n_patterns,
                                       /*coord_uid_check_enabled=*/false,
                                       /*coord_uid=*/(uid_t)-1);
}

static void bilateral_init_with_uid_check(bilateral_fixture *f,
                                              const char *tag,
                                              const char *const *patterns,
                                              size_t n_patterns,
                                              bool coord_uid_check_enabled,
                                              uid_t coord_uid)
{
    memset(f, 0, sizeof *f);
    make_tmp(tag);
    build_paths(tag);

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &f->fs));

    int coord_fd = stm_stratumd_listen_unix(g_coord_sock, 4, 0600);
    STM_ASSERT(coord_fd >= 0);
    f->cc.listen_fd = coord_fd;
    f->cc.fs        = f->fs;
    atomic_init(&f->cc.stop_flag, false);
    pthread_create(&f->coord_tid, NULL, coord_main, &f->cc);

    int proxy_fd = stm_stratumd_listen_unix(g_proxy_sock, 4, 0600);
    STM_ASSERT(proxy_fd >= 0);
    f->pc.listen_fd  = proxy_fd;
    f->pc.coord_path = g_coord_sock;
    f->pc.patterns   = patterns;
    f->pc.n_patterns = n_patterns;
    f->pc.coord_uid_check_enabled = coord_uid_check_enabled;
    f->pc.coord_uid               = coord_uid;
    atomic_init(&f->pc.stop_flag, false);
    pthread_create(&f->proxy_tid, NULL, proxy_main, &f->pc);
}

static void bilateral_teardown(bilateral_fixture *f)
{
    /* Stop proxy first — it holds a downstream conn to coord. */
    atomic_store_explicit(&f->pc.stop_flag, true, memory_order_release);
    (void)shutdown(f->pc.listen_fd, SHUT_RDWR);
    pthread_join(f->proxy_tid, NULL);
    close(f->pc.listen_fd);
    (void)unlink(g_proxy_sock);

    atomic_store_explicit(&f->cc.stop_flag, true, memory_order_release);
    (void)shutdown(f->cc.listen_fd, SHUT_RDWR);
    pthread_join(f->coord_tid, NULL);
    close(f->cc.listen_fd);
    (void)unlink(g_coord_sock);

    (void)stm_fs_unmount(f->fs);
}

/* Dial the proxy upstream socket; complete Tversion. Return fd or -1. */
static int dial_proxy_version(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_proxy_sock, sizeof addr.sun_path - 1);
    for (int i = 0; i < 100; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) break;
        usleep(10 * 1000);
        if (i == 99) { close(fd); return -1; }
    }

    uint8_t tv[21];
    tv[0] = 21; tv[1] = 0; tv[2] = 0; tv[3] = 0;
    tv[4] = 100;
    tv[5] = 0xFF; tv[6] = 0xFF;
    uint32_t msize = STM_9P_MSIZE_DEFAULT;
    tv[7]  = (uint8_t)(msize & 0xFF);
    tv[8]  = (uint8_t)((msize >> 8) & 0xFF);
    tv[9]  = (uint8_t)((msize >> 16) & 0xFF);
    tv[10] = (uint8_t)((msize >> 24) & 0xFF);
    tv[11] = 8; tv[12] = 0;
    memcpy(tv + 13, "9P2000.L", 8);
    if (write(fd, tv, sizeof tv) != (ssize_t)sizeof tv) {
        close(fd); return -1;
    }
    uint8_t rv[256];
    ssize_t n = read(fd, rv, sizeof rv);
    if (n < 5 || rv[4] != 101) { close(fd); return -1; }
    return fd;
}

static int send_tattach_and_get_type(int fd, const uint8_t *frame,
                                         size_t frame_len,
                                         uint8_t *out_type,
                                         uint32_t *out_ecode)
{
    if (write(fd, frame, frame_len) != (ssize_t)frame_len) return -1;
    uint8_t resp[256];
    ssize_t n = read(fd, resp, sizeof resp);
    if (n < 5) return -1;
    *out_type = resp[4];
    if (resp[4] == STM_9P_RLERROR && n >= 11) {
        *out_ecode = (uint32_t)resp[7]
                       | ((uint32_t)resp[8] << 8)
                       | ((uint32_t)resp[9] << 16)
                       | ((uint32_t)resp[10] << 24);
    } else {
        *out_ecode = 0;
    }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* E2E: matching aname goes through to coord; refuses on mismatch.       */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(proxy_9p_e2e_refuses_aname_not_in_allowlist)
{
    const char *pats[] = { "users/michael", "users/michael/**" };
    bilateral_fixture f;
    bilateral_init(&f, "refuse", pats, 2);

    int fd = dial_proxy_version();
    STM_ASSERT(fd >= 0);

    const char *aname = "users/susan";
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame,
                                 (const uint8_t *)aname, strlen(aname));
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_and_get_type(fd, frame, n, &type, &ecode), 0);
    STM_ASSERT_EQ(type, STM_9P_RLERROR);
    STM_ASSERT_EQ((long long)ecode, 13LL); /* EACCES */

    close(fd);
    bilateral_teardown(&f);
}

STM_TEST(proxy_9p_e2e_admits_matching_aname_forwards_to_coord)
{
    const char *pats[] = { "users/michael", "users/michael/**" };
    bilateral_fixture f;
    bilateral_init(&f, "admit", pats, 2);

    int fd = dial_proxy_version();
    STM_ASSERT(fd >= 0);

    const char *aname = "users/michael";
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame,
                                 (const uint8_t *)aname, strlen(aname));
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_and_get_type(fd, frame, n, &type, &ecode), 0);
    /* The proxy admitted. Coord's canonical h_attach now owns the
     * decision: for a non-`/` non-`spec:` aname, v2.0 returns
     * Rlerror with ecode = EINVAL (22) per stm_9p_server_handle's
     * aname-resolution discipline. The KEY assertion is "not EACCES
     * from the proxy gate" — anything other than ecode 13 means the
     * proxy forwarded and coord owned the downstream response. */
    if (type == STM_9P_RLERROR) {
        STM_ASSERT_NE((long long)ecode, 13LL);
    }

    close(fd);
    bilateral_teardown(&f);
}

STM_TEST(proxy_9p_e2e_empty_allowlist_admits_all_anames)
{
    /* No patterns → no gate. Used by tests + by non-Thylacine deployments
     * that just want the proxy hop. Confirm "" still goes through
     * (and gets coord's canonical refusal — not the proxy's EACCES). */
    bilateral_fixture f;
    bilateral_init(&f, "noallow", NULL, 0);

    int fd = dial_proxy_version();
    STM_ASSERT(fd >= 0);

    const char *aname = "any/path";
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame,
                                 (const uint8_t *)aname, strlen(aname));
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_and_get_type(fd, frame, n, &type, &ecode), 0);
    /* Same posture: not-EACCES means proxy forwarded. */
    if (type == STM_9P_RLERROR) {
        STM_ASSERT_NE((long long)ecode, 13LL);
    }

    close(fd);
    bilateral_teardown(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* TLY-A2-impl-3 — downstream-side SO_PEERCRED check.                     */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(proxy_9p_e2e_coord_uid_match_admits)
{
    /* coord runs as the test runner's uid → match → proxy admits. */
    const char *pats[] = { "users/michael", "users/michael/**" };
    bilateral_fixture f;
    bilateral_init_with_uid_check(&f, "uidmatch", pats, 2,
                                       /*enabled=*/true,
                                       /*coord_uid=*/(uid_t)getuid());

    int fd = dial_proxy_version();
    STM_ASSERT(fd >= 0);

    const char *aname = "users/michael";
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame,
                                 (const uint8_t *)aname, strlen(aname));
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_and_get_type(fd, frame, n, &type, &ecode), 0);
    /* Same posture as the existing admit test: not-EACCES means
     * the proxy forwarded after passing both the aname gate AND
     * the coord-uid match. */
    if (type == STM_9P_RLERROR) {
        STM_ASSERT_NE((long long)ecode, 13LL);
    }

    close(fd);
    bilateral_teardown(&f);
}

STM_TEST(proxy_9p_e2e_coord_uid_mismatch_refused)
{
    /* coord runs as the test runner's uid, but proxy expects a
     * different uid. Proxy must refuse on dial; upstream sees the
     * connection drop. dial_proxy_version reads back the proxy's
     * Rversion — but here the proxy never even forwards Tversion
     * because the coord-uid check fires immediately after dial,
     * so dial_proxy_version sees EOF on its read. Returns -1. */
    const char *pats[] = { "users/michael" };
    /* Pick a uid we know is NOT the test runner. */
    uid_t wrong = ((uid_t)getuid() == 12345u) ? (uid_t)12346u : (uid_t)12345u;

    bilateral_fixture f;
    bilateral_init_with_uid_check(&f, "uidmismatch", pats, 1,
                                       /*enabled=*/true,
                                       /*coord_uid=*/wrong);

    int fd = dial_proxy_version();
    STM_ASSERT_EQ(fd, -1);

    bilateral_teardown(&f);
}

STM_TEST_MAIN("proxy_9p")
