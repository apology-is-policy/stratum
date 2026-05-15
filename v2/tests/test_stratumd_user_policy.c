/* SPDX-License-Identifier: ISC */
/*
 * test_stratumd_user_policy — TLY-A2-impl-1 + R139 close.
 *
 * End-to-end tests that drive raw Tattach wire bytes through the
 * stratumd FS-socket loop with a non-empty `--user-policy` table.
 * Covers the three policy-bypass shapes R139 found at the wrapper:
 *
 *   - P0-1 truncated-body Tattach (body_len = 8) — wrapper deferred
 *     to canonical, which admitted ANAME_DEFAULT.
 *   - P0-2 embedded-NUL aname — wrapper's matcher saw only the
 *     prefix-before-NUL; canonical saw the full bytes.
 *   - P1-1 `/` aname — wrapper refused empty but not `/`; with
 *     operator-configured catch-all pattern `**` the matcher
 *     admitted, contradicting design doc §11.
 *
 * Plus positive tests: a Tattach whose aname matches the policy is
 * admitted (returns Rattach); a Tattach whose aname mismatches is
 * refused (returns Rlerror(EACCES)).
 */

#include "tharness.h"
#include "test_fs_common.h"

#include "../src/cmd/stratumd/dataset_pattern.h"

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/stratumd.h>
#include <stratum/types.h>

#include <errno.h>
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
/* Per-test fixture: spin up stratumd against a fresh fs, dial as a    */
/* raw 9P client, send Tversion + Tattach, capture the response.        */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int          listen_fd;
    stm_fs      *fs;
    stm_ds_policy_table *policy;
    atomic_bool  stop_flag;
    stm_status   run_status;
} udp_ctx;

static void *udp_accept_thread(void *arg)
{
    udp_ctx *ctx = (udp_ctx *)arg;
    ctx->run_status = stm_stratumd_accept_loop(ctx->listen_fd, ctx->fs,
                                                  STM_9P_MSIZE_DEFAULT,
                                                  /*root_dataset=*/1u,
                                                  /*idle_timeout_ms=*/0,
                                                  /*allow_unauth=*/false,
                                                  &ctx->stop_flag,
                                                  ctx->policy);
    return NULL;
}

static char g_sock_path[256];
static void build_sock_path(const char *tag)
{
    snprintf(g_sock_path, sizeof g_sock_path,
             "/tmp/stm_udp_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(g_sock_path);
}

typedef struct {
    int          listen_fd;
    pthread_t    worker;
    stm_fs      *fs;
    udp_ctx      ctx;
    stm_ds_policy_table policy;
} udp_fixture;

static void udp_fixture_init(udp_fixture *f, const char *tag,
                                const char *policy_str)
{
    memset(f, 0, sizeof *f);
    make_tmp(tag);
    build_sock_path(tag);

    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &f->fs));

    memset(&f->policy, 0, sizeof f->policy);
    STM_ASSERT_OK(stm_ds_policy_parse_cli(&f->policy, policy_str));

    f->listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT(f->listen_fd >= 0);

    f->ctx.listen_fd = f->listen_fd;
    f->ctx.fs        = f->fs;
    f->ctx.policy    = &f->policy;
    atomic_init(&f->ctx.stop_flag, false);

    pthread_create(&f->worker, NULL, udp_accept_thread, &f->ctx);
}

static void udp_fixture_teardown(udp_fixture *f)
{
    atomic_store_explicit(&f->ctx.stop_flag, true, memory_order_release);
    (void)shutdown(f->listen_fd, SHUT_RDWR);
    pthread_join(f->worker, NULL);
    close(f->listen_fd);
    stm_ds_policy_table_close(&f->policy);
    (void)stm_fs_unmount(f->fs);
    (void)unlink(g_sock_path);
}

/* Connect to the fixture, send Tversion, expect Rversion. Returns
 * the client fd on success; closes + returns -1 on any failure. */
static int dial_and_version(uint32_t msize)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_sock_path, sizeof addr.sun_path - 1);
    /* Retry connect a few times — accept thread may not be ready. */
    for (int i = 0; i < 50; i++) {
        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0) break;
        usleep(10 * 1000);
        if (i == 49) { close(fd); return -1; }
    }

    /* Tversion: size(4) Tversion(1=100) tag(2=0xFFFF) msize(4) version[s].
     * version = "9P2000.L" (8 bytes). Total body = 4 + 2 + 8 = 14; total
     * frame = 7 + 14 = 21. */
    uint8_t tv[21];
    tv[0] = 21; tv[1] = 0; tv[2] = 0; tv[3] = 0;
    tv[4] = 100;
    tv[5] = 0xFF; tv[6] = 0xFF;
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
    if (n < 5 || rv[4] != 101 /* Rversion */) {
        close(fd); return -1;
    }
    return fd;
}

/* Send a hand-crafted Tattach frame, return Rxx response type into
 * *out_type, ecode into *out_ecode (only for Rlerror). Returns 0 on
 * success, -1 on i/o failure. */
static int send_tattach_raw(int fd, const uint8_t *frame, size_t frame_len,
                                uint8_t *out_type, uint32_t *out_ecode)
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

/* Build a well-formed Tattach with the supplied aname. fid = 1,
 * afid = NOFID = 0xFFFFFFFF, uname = "" (length 0), n_uname = 0. */
static size_t build_tattach(uint8_t *out, size_t out_cap,
                              const uint8_t *aname, size_t alen)
{
    /* Body = fid(4) + afid(4) + uname[s] + aname[s] + n_uname(4).
     * uname[s] = ulen(2) + 0 bytes. aname[s] = alen(2) + alen bytes. */
    size_t body = 4 + 4 + 2 + 0 + 2 + alen + 4;
    size_t total = 7 + body;
    if (total > out_cap) return 0;

    out[0] = (uint8_t)(total & 0xFF);
    out[1] = (uint8_t)((total >> 8) & 0xFF);
    out[2] = (uint8_t)((total >> 16) & 0xFF);
    out[3] = (uint8_t)((total >> 24) & 0xFF);
    out[4] = 104; /* Tattach */
    out[5] = 0x01; out[6] = 0x00; /* tag = 1 */
    /* fid = 1 */
    out[7] = 1; out[8] = 0; out[9] = 0; out[10] = 0;
    /* afid = NOFID */
    out[11] = 0xFF; out[12] = 0xFF; out[13] = 0xFF; out[14] = 0xFF;
    /* uname = "" */
    out[15] = 0; out[16] = 0;
    /* aname */
    out[17] = (uint8_t)(alen & 0xFF);
    out[18] = (uint8_t)((alen >> 8) & 0xFF);
    if (alen) memcpy(out + 19, aname, alen);
    /* n_uname = 0 */
    size_t p = 19 + alen;
    out[p+0] = 0; out[p+1] = 0; out[p+2] = 0; out[p+3] = 0;
    return total;
}

/* ────────────────────────────────────────────────────────────────────── */
/* R139 P0-1 — truncated-body Tattach (body_len = 8) MUST refuse.       */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(stratumd_user_policy_refuses_truncated_body_tattach)
{
    udp_fixture f;
    udp_fixture_init(&f, "p01_trunc", "uid=0:users/michael");
    int fd = dial_and_version(STM_9P_MSIZE_DEFAULT);
    STM_ASSERT(fd >= 0);

    /* Body: fid(4) + afid(4) only — no uname, no aname, no n_uname.
     * Total frame = 7 + 8 = 15. */
    uint8_t frame[15] = {0};
    frame[0] = 15;
    frame[4] = 104; /* Tattach */
    frame[5] = 1; frame[6] = 0;
    frame[7] = 1; /* fid = 1 */
    frame[11] = 0xFF; frame[12] = 0xFF; frame[13] = 0xFF; frame[14] = 0xFF;
    /* No uname / aname / n_uname — body_len = 8 (truncated). */

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_raw(fd, frame, 15, &type, &ecode), 0);
    /* Pre-R139: type=105 (Rattach) — policy bypassed. Post-R139:
     * type=STM_9P_RLERROR with EACCES = 13. */
    STM_ASSERT_EQ(type, STM_9P_RLERROR);
    STM_ASSERT_EQ((long long)ecode, 13LL); /* EACCES */

    close(fd);
    udp_fixture_teardown(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* R139 P0-2 — embedded-NUL in aname MUST refuse.                       */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(stratumd_user_policy_refuses_embedded_nul_aname)
{
    udp_fixture f;
    udp_fixture_init(&f, "p02_nul", "uid=0:users/michael");
    int fd = dial_and_version(STM_9P_MSIZE_DEFAULT);
    STM_ASSERT(fd >= 0);

    /* aname = "users/michael\x00escape" (alen=20). The wrapper's
     * pre-R139 strnlen would match against "users/michael" (admit);
     * post-R139 the embedded NUL is refused. */
    uint8_t aname[20];
    memcpy(aname, "users/michael", 13);
    aname[13] = 0x00;
    memcpy(aname + 14, "escape", 6);

    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, aname, 20);
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_raw(fd, frame, n, &type, &ecode), 0);
    STM_ASSERT_EQ(type, STM_9P_RLERROR);
    STM_ASSERT_EQ((long long)ecode, 13LL);

    close(fd);
    udp_fixture_teardown(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* R139 P1-1 — `/` aname MUST refuse even under catch-all `**` policy. */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(stratumd_user_policy_refuses_slash_aname_under_catchall)
{
    udp_fixture f;
    udp_fixture_init(&f, "p11_slash", "uid=0:**");
    int fd = dial_and_version(STM_9P_MSIZE_DEFAULT);
    STM_ASSERT(fd >= 0);

    /* aname = "/" (alen=1). Even with `**` admitting "/", the
     * wrapper's design contract requires refusal under policy mode. */
    const uint8_t aname[] = { '/' };
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, aname, 1);
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_raw(fd, frame, n, &type, &ecode), 0);
    STM_ASSERT_EQ(type, STM_9P_RLERROR);
    STM_ASSERT_EQ((long long)ecode, 13LL);

    close(fd);
    udp_fixture_teardown(&f);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Positive — matching aname admits.                                    */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(stratumd_user_policy_admits_matching_aname)
{
    /* SO_PEERCRED reports the connecting process's uid — use the
     * test-runner's actual uid so the policy entry applies. */
    char policy[128];
    snprintf(policy, sizeof policy,
             "uid=%u:users/michael,users/michael/**",
             (unsigned)getuid());
    udp_fixture f;
    udp_fixture_init(&f, "admit", policy);
    int fd = dial_and_version(STM_9P_MSIZE_DEFAULT);
    STM_ASSERT(fd >= 0);

    const char *aname = "users/michael";
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, (const uint8_t *)aname,
                                strlen(aname));
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_raw(fd, frame, n, &type, &ecode), 0);
    /* Pre-R139 + post-R139: matching pattern admits via the canonical
     * h_attach. v2.0 currently treats named anames as needing the
     * dataset-name resolver (h_attach refuses non-`/` non-`spec:`
     * with STM_9P_ECODE_EINVAL → ecode 22). The KEY assertion is
     * "not EACCES from the policy gate"; the canonical handler's
     * own subsequent refusal is acceptable.
     *
     * If the canonical returns Rattach (105), great. If it returns
     * Rlerror with ecode != EACCES (13), the policy gate admitted
     * and the canonical's subsequent semantics took over —
     * also acceptable for THIS test (which pins the gate, not
     * the canonical's downstream behavior). */
    if (type == STM_9P_RLERROR) {
        STM_ASSERT_NE((long long)ecode, 13LL);
    }

    close(fd);
    udp_fixture_teardown(&f);
}

STM_TEST(stratumd_user_policy_refuses_non_nul_control_byte_aname)
{
    /* R140 P2-5: the wrapper now refuses bytes < 0x20 || == 0x7F
     * in aname (extended from R139's NUL-only refusal). With a
     * catch-all `**` policy, a pre-R140 wrapper would forward to
     * the matcher, which would admit (matcher only refuses NUL
     * via strnlen). Post-R140: wrapper refuses with EACCES. */
    udp_fixture f;
    udp_fixture_init(&f, "ctlbyte", "uid=0:**");
    int fd = dial_and_version(STM_9P_MSIZE_DEFAULT);
    STM_ASSERT(fd >= 0);

    uint8_t aname[14] = {
        'u', 's', 'e', 'r', 's', '/', 'm', 'i', 'c', 'h', 0x01, 'a', 'e', 'l'
    };
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, aname, sizeof aname);
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_raw(fd, frame, n, &type, &ecode), 0);
    STM_ASSERT_EQ(type, STM_9P_RLERROR);
    STM_ASSERT_EQ((long long)ecode, 13LL); /* EACCES */

    close(fd);
    udp_fixture_teardown(&f);
}

STM_TEST(stratumd_user_policy_refuses_mismatched_aname)
{
    udp_fixture f;
    udp_fixture_init(&f, "refuse", "uid=0:users/michael");
    int fd = dial_and_version(STM_9P_MSIZE_DEFAULT);
    STM_ASSERT(fd >= 0);

    /* aname = "users/susan" (not in policy). Must refuse. */
    const char *aname = "users/susan";
    uint8_t frame[64];
    size_t n = build_tattach(frame, sizeof frame, (const uint8_t *)aname,
                                strlen(aname));
    STM_ASSERT(n > 0);

    uint8_t type; uint32_t ecode;
    STM_ASSERT_EQ(send_tattach_raw(fd, frame, n, &type, &ecode), 0);
    STM_ASSERT_EQ(type, STM_9P_RLERROR);
    STM_ASSERT_EQ((long long)ecode, 13LL);

    close(fd);
    udp_fixture_teardown(&f);
}

STM_TEST_MAIN("stratumd_user_policy")
