/* SPDX-License-Identifier: ISC */
/*
 * test_9p_socket — integration tests for P9-9P-4 stratumd Unix-socket
 * transport. Drives the accept_loop in a worker pthread and connects
 * from the main thread via Unix socket; exercises end-to-end framing
 * over a real socket (Tversion + Tattach + Tgetattr + Tclunk) and
 * verifies serial-accept multi-client behavior.
 *
 * The accept loop's stop-flag exit path is tested by setting the
 * flag and shutdown()ing the listen fd from the main thread to
 * unblock accept(), then joining the worker.
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/stratumd.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Wire helpers (mirror the test_9p ones — separate file to keep the    */
/* socket-transport tests independent of the in-process 9P tests).      */
/* ────────────────────────────────────────────────────────────────────── */

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t load_u32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Worker thread context.                                                 */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int            listen_fd;
    stm_fs        *fs;
    uint32_t       idle_timeout_ms;  /* 0 → loop substitutes default 30 s */
    atomic_bool    stop_flag;
    stm_status     run_status;       /* set by worker on exit */
} accept_ctx;

static void *accept_loop_thread(void *arg)
{
    accept_ctx *ctx = (accept_ctx *)arg;
    /* allow_unauthenticated_peer = false: tests run on Linux/macOS
     * where SO_PEERCRED / getpeereid succeed for connected Unix
     * sockets, so the strict policy never fires the refusal path. */
    ctx->run_status = stm_stratumd_accept_loop(ctx->listen_fd, ctx->fs,
                                                  STM_9P_MSIZE_DEFAULT,
                                                  /*root_dataset=*/1u,
                                                  ctx->idle_timeout_ms,
                                                  /*allow_unauth=*/false,
                                                  &ctx->stop_flag);
    return NULL;
}

/* Wake up an accept() call by setting stop_flag and shutting down
 * the listen fd. Robust on Linux + macOS. */
static void wake_and_join(accept_ctx *ctx, pthread_t worker)
{
    atomic_store_explicit(&ctx->stop_flag, true, memory_order_release);
    (void)shutdown(ctx->listen_fd, SHUT_RDWR);
    /* If the worker was inside serve_client at the moment of stop,
     * it will return on the next read EOF (when the test client
     * closes its socket); the next accept() returns an error and
     * the loop sees stop_flag. */
    pthread_join(worker, NULL);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Client helpers.                                                        */
/* ────────────────────────────────────────────────────────────────────── */

/* Connect a client socket to the listening Unix path. Retries up to
 * 50 × 10ms (= 500ms) to tolerate the worker thread being scheduled
 * after the test thread reaches connect(). */
static int connect_client(const char *sock_path)
{
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof addr.sun_path - 1);

    for (int attempt = 0; attempt < 50; attempt++) {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -errno;
        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0)
            return fd;
        close(fd);
        if (errno != ENOENT && errno != ECONNREFUSED)
            return -errno;
        struct timespec ts = { 0, 10 * 1000 * 1000 };  /* 10ms */
        nanosleep(&ts, NULL);
    }
    return -ETIMEDOUT;
}

static int send_msg(int fd, const uint8_t *buf, uint32_t len)
{
    uint32_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, buf + done, len - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        if (n == 0) return -EPIPE;
        done += (uint32_t)n;
    }
    return 0;
}

static int recv_msg(int fd, uint8_t *buf, uint32_t cap, uint32_t *out_len)
{
    /* Read 4-byte size header, then the rest. */
    uint32_t done = 0;
    while (done < 4u) {
        ssize_t n = read(fd, buf + done, 4u - done);
        if (n == 0) return -EPIPE;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        done += (uint32_t)n;
    }
    uint32_t size = load_u32(buf);
    if (size < 7u || size > cap) return -EPROTO;
    while (done < size) {
        ssize_t n = read(fd, buf + done, size - done);
        if (n == 0) return -EPIPE;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        done += (uint32_t)n;
    }
    *out_len = size;
    return 0;
}

/* Unique per-test socket path; reuses g_tmp_path's scheme. */
static char g_sock_path[256];
static void build_sock_path(const char *tag)
{
    snprintf(g_sock_path, sizeof g_sock_path,
             "/tmp/stm_socktest_%d_%s.sock",
             (int)getpid(), tag);
    /* Pre-clean any stale socket. */
    (void)unlink(g_sock_path);
}

/* Tversion + Tattach pair via the socket. */
static int do_handshake(int fd, uint32_t fid)
{
    uint8_t buf[1024];
    uint32_t rlen = 0;

    /* Tversion(STM_9P_MSIZE_DEFAULT, "9P2000.L"). */
    uint8_t *p = buf + 7;
    pack_u32(p, STM_9P_MSIZE_DEFAULT);  p += 4;
    pack_u16(p, 8);                     p += 2;
    memcpy(p, "9P2000.L", 8);           p += 8;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TVERSION;
    pack_u16(buf + 5, STM_9P_NOTAG);
    if (send_msg(fd, buf, sz) != 0) return -1;
    if (recv_msg(fd, buf, sizeof buf, &rlen) != 0) return -2;
    if (buf[4] != STM_9P_RVERSION) return -3;

    /* Tattach(fid, afid=NOFID, uname="", aname="", n_uname=-1). */
    p = buf + 7;
    pack_u32(p, fid);                   p += 4;
    pack_u32(p, STM_9P_NOFID);          p += 4;
    pack_u16(p, 0);                     p += 2;  /* uname */
    pack_u16(p, 0);                     p += 2;  /* aname */
    pack_u32(p, (uint32_t)-1);          p += 4;
    sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TATTACH;
    pack_u16(buf + 5, 1);
    if (send_msg(fd, buf, sz) != 0) return -4;
    if (recv_msg(fd, buf, sizeof buf, &rlen) != 0) return -5;
    if (buf[4] != STM_9P_RATTACH) return -6;
    return 0;
}

static int do_clunk(int fd, uint16_t tag, uint32_t fid)
{
    uint8_t buf[256];
    uint32_t rlen = 0;
    uint8_t *p = buf + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TCLUNK;
    pack_u16(buf + 5, tag);
    if (send_msg(fd, buf, sz) != 0) return -1;
    if (recv_msg(fd, buf, sizeof buf, &rlen) != 0) return -2;
    if (buf[4] != STM_9P_RCLUNK) return -3;
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                  */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(p9_socket_listen_path_too_long_rejected) {
    /* sun_path is bounded; an over-long path must refuse with
     * ENAMETOOLONG before any socket is created. */
    char too_long[200];
    memset(too_long, 'a', sizeof too_long - 1);
    too_long[sizeof too_long - 1] = '\0';
    int fd = stm_stratumd_listen_unix(too_long, 4, 0600);
    STM_ASSERT_TRUE(fd < 0);
    STM_ASSERT_EQ(fd, -ENAMETOOLONG);
}

STM_TEST(p9_socket_listen_then_handshake) {
    /* Format + init root + listen on Unix socket; spawn accept loop;
     * connect a client; do Tversion + Tattach + Tclunk over the
     * socket; clean shutdown. */
    make_tmp("9p_sock_handshake");
    build_sock_path("handshake");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, /*ds=*/1u, /*mode=*/0755u,
                                              /*uid=*/0, /*gid=*/0,
                                              &root_ino));

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(listen_fd >= 0);

    accept_ctx ctx = { .listen_fd = listen_fd, .fs = fs,
                        .run_status = STM_EBACKEND };
    /* R95 P3-2: atomic_bool on auto-storage requires atomic_init per
     * C11 §7.17.2.1 (designated-init via plain `false` is impl-defined). */
    atomic_init(&ctx.stop_flag, false);
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL, accept_loop_thread, &ctx), 0);

    int cfd = connect_client(g_sock_path);
    STM_ASSERT_TRUE(cfd >= 0);

    STM_ASSERT_EQ(do_handshake(cfd, /*fid=*/100), 0);
    STM_ASSERT_EQ(do_clunk(cfd, /*tag=*/2, /*fid=*/100), 0);

    /* Disconnect client; daemon's serve_client returns on read EOF. */
    close(cfd);

    wake_and_join(&ctx, worker);
    STM_ASSERT_EQ(ctx.run_status, STM_OK);

    close(listen_fd);
    (void)unlink(g_sock_path);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_socket_two_sequential_clients) {
    /* Verify the serial accept loop accepts a SECOND client after
     * the first disconnects. Both attach with different fid numbers
     * and clunk cleanly. */
    make_tmp("9p_sock_seq");
    build_sock_path("seq");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1u, 0755u, 0, 0, &root_ino));

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(listen_fd >= 0);

    accept_ctx ctx = { .listen_fd = listen_fd, .fs = fs,
                        .run_status = STM_EBACKEND };
    /* R95 P3-2: atomic_bool on auto-storage requires atomic_init per
     * C11 §7.17.2.1 (designated-init via plain `false` is impl-defined). */
    atomic_init(&ctx.stop_flag, false);
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL, accept_loop_thread, &ctx), 0);

    /* Client A: handshake + clunk + disconnect. */
    int cfd_a = connect_client(g_sock_path);
    STM_ASSERT_TRUE(cfd_a >= 0);
    STM_ASSERT_EQ(do_handshake(cfd_a, /*fid=*/100), 0);
    STM_ASSERT_EQ(do_clunk(cfd_a, /*tag=*/2, /*fid=*/100), 0);
    close(cfd_a);

    /* Client B: must succeed after A's disconnect. Different fid. */
    int cfd_b = connect_client(g_sock_path);
    STM_ASSERT_TRUE(cfd_b >= 0);
    STM_ASSERT_EQ(do_handshake(cfd_b, /*fid=*/200), 0);
    STM_ASSERT_EQ(do_clunk(cfd_b, /*tag=*/2, /*fid=*/200), 0);
    close(cfd_b);

    wake_and_join(&ctx, worker);
    STM_ASSERT_EQ(ctx.run_status, STM_OK);

    close(listen_fd);
    (void)unlink(g_sock_path);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST(p9_socket_protocol_violation_disconnects) {
    /* A client that sends an out-of-range size header (size > msize)
     * triggers stm_stratumd_serve_client's protocol-violation exit;
     * the daemon closes the connection. The client observes EOF on
     * the next read. The accept loop returns to accept() and is
     * available for further clients. */
    make_tmp("9p_sock_proto");
    build_sock_path("proto");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1u, 0755u, 0, 0, &root_ino));

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(listen_fd >= 0);
    accept_ctx ctx = { .listen_fd = listen_fd, .fs = fs,
                        .run_status = STM_EBACKEND };
    /* R95 P3-2: atomic_bool on auto-storage requires atomic_init per
     * C11 §7.17.2.1 (designated-init via plain `false` is impl-defined). */
    atomic_init(&ctx.stop_flag, false);
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL, accept_loop_thread, &ctx), 0);

    int cfd = connect_client(g_sock_path);
    STM_ASSERT_TRUE(cfd >= 0);
    /* Send a 4-byte header with size = 0xFFFFFFFF (bigger than msize_max
     * STM_9P_MSIZE_MAX = 1 MiB). Daemon should close. */
    uint8_t hdr[4];
    pack_u32(hdr, 0xFFFFFFFFu);
    STM_ASSERT_EQ(send_msg(cfd, hdr, 4), 0);

    /* Client reads — should EOF (daemon closed the fd). */
    uint8_t buf[16];
    ssize_t n = read(cfd, buf, sizeof buf);
    /* Either returns 0 (EOF) or -1 with ECONNRESET, both indicate
     * the daemon-side close. */
    STM_ASSERT_TRUE(n == 0 || (n < 0 && (errno == ECONNRESET ||
                                            errno == EPIPE)));
    close(cfd);

    /* A subsequent fresh client must still succeed — accept loop
     * recovered. */
    int cfd2 = connect_client(g_sock_path);
    STM_ASSERT_TRUE(cfd2 >= 0);
    STM_ASSERT_EQ(do_handshake(cfd2, /*fid=*/100), 0);
    STM_ASSERT_EQ(do_clunk(cfd2, /*tag=*/2, /*fid=*/100), 0);
    close(cfd2);

    wake_and_join(&ctx, worker);
    STM_ASSERT_EQ(ctx.run_status, STM_OK);

    close(listen_fd);
    (void)unlink(g_sock_path);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* ── R95 regression tests ─────────────────────────────────────────── */

/* R95 P1-1: stm_stratumd_listen_unix MUST clamp the socket file's
 * mode tight (default 0600) so a local-user "any-can-connect" hole
 * doesn't exist. Janus has the same gate (R11 P1-1); replicating
 * here. */
STM_TEST(p9_socket_r95_p1_1_socket_mode_is_0600) {
    build_sock_path("r95_p1_1_mode");
    int fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(fd >= 0);

    struct stat st;
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_EQ(st.st_mode & 07777, (mode_t)0600);

    close(fd);
    (void)unlink(g_sock_path);
}

/* R95 P3-1: non-socket file at the listen path → -EEXIST refusal. */
STM_TEST(p9_socket_r95_p3_1_non_socket_refused) {
    build_sock_path("r95_p3_1_non_socket");
    /* Create a regular file at the path. */
    int rfd = open(g_sock_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    STM_ASSERT_TRUE(rfd >= 0);
    close(rfd);

    int fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_EQ(fd, -EEXIST);

    /* The pre-existing regular file must still be there (we refused
     * to clobber it). */
    struct stat st;
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISREG(st.st_mode));

    (void)unlink(g_sock_path);
}

/* R95 P2-1: a slow-loris client (connects but never sends) must NOT
 * indefinitely block the serial accept loop. With idle_timeout_ms
 * set small (250 ms here for fast test), the daemon's serve_client
 * times out on the size-header read; serve_client returns STM_EIO,
 * accept loop frees up to accept the next client. */
STM_TEST(p9_socket_r95_p2_1_slow_loris_releases_slot) {
    make_tmp("9p_sock_r95_p2_1");
    build_sock_path("r95_p2_1_slow");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1u, 0755u, 0, 0, &root_ino));

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600);
    STM_ASSERT_TRUE(listen_fd >= 0);

    accept_ctx ctx = { .listen_fd = listen_fd, .fs = fs,
                        .idle_timeout_ms = 250u,    /* short for test */
                        .run_status = STM_EBACKEND };
    atomic_init(&ctx.stop_flag, false);
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL, accept_loop_thread, &ctx), 0);

    /* Slow-loris: connect, send NOTHING, eventually close on test
     * exit. Worker's serve_client should time out on the size-header
     * read and return STM_EIO, freeing the accept slot. */
    int loris_fd = connect_client(g_sock_path);
    STM_ASSERT_TRUE(loris_fd >= 0);
    /* Wait long enough for the daemon's read to time out (idle
     * timeout = 250ms); 600ms gives 2.4× safety margin under
     * sanitizer/CI scheduling jitter. */
    struct timespec ts = { 0, 600 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    /* A SECOND client must succeed even though loris is still
     * holding its connection — verifies the daemon released the
     * serial slot. */
    int cfd = connect_client(g_sock_path);
    STM_ASSERT_TRUE(cfd >= 0);
    STM_ASSERT_EQ(do_handshake(cfd, /*fid=*/100), 0);
    STM_ASSERT_EQ(do_clunk(cfd, /*tag=*/2, /*fid=*/100), 0);
    close(cfd);

    /* Now close the loris fd. */
    close(loris_fd);

    wake_and_join(&ctx, worker);
    STM_ASSERT_EQ(ctx.run_status, STM_OK);

    close(listen_fd);
    (void)unlink(g_sock_path);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

STM_TEST_MAIN("9p_socket")
