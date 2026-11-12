/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * test_9p_socket — integration tests for P9-9P-4 stratumd Unix-socket
 * transport. Drives the accept_loop in a worker pthread and connects
 * from the main thread via Unix socket; exercises end-to-end framing
 * over a real socket (Tversion + Tattach + Tgetattr + Tclunk) and
 * verifies serial-accept multi-client behavior.
 *
 * The accept loop's stop-flag exit path is tested by setting the
 * flag from the main thread, which the loop sees at its next poll,
 * then joining the worker; the shutdown() of the listen fd beside it
 * wakes the loop sooner on Linux only.
 */
#include "tharness.h"
#include "tsock.h"
#include "test_fs_common.h"

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/listen.h>
#include <stratum/stratumd.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
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
                                                  &ctx->stop_flag, NULL);
    return NULL;
}

/* End an accept loop by its stop flag, which it sees within one poll.
 * The shutdown() of the listen fd wakes it sooner on Linux only. */
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
    tsock_addr(&addr, sock_path);

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

/* The tests' sockets, in a directory of this program's own: a lock that anyone
 * may keep on /tmp is then nothing to its listeners. */
static char g_sock_dir[32];
static void remove_sock_dir(void) { (void)rmdir(g_sock_dir); }

static char g_sock_path[256];
static void build_sock_path(const char *tag)
{
    if (!g_sock_dir[0]) {
        snprintf(g_sock_dir, sizeof g_sock_dir, "/tmp/stm_socktest_XXXXXX");
        if (!mkdtemp(g_sock_dir)) {
            perror("mkdtemp");
            exit(1);
        }
        atexit(remove_sock_dir);
    }
    snprintf(g_sock_path, sizeof g_sock_path, "%s/%s.sock", g_sock_dir, tag);
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
    int fd = stm_stratumd_listen_unix(too_long, 4, 0600, 0);
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

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
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

#ifdef STRATUM_BUILD_TESTING_HOOKS
STM_TEST(p9_socket_a_connection_that_cannot_be_duplicated_is_served) {
    /* Thylacine's pouch answers ENOSYS to dup() of a socket, and the daemon dups
     * each connection so that a stop can reach it. Refusing every connection
     * there would leave the volume unreachable. */
    make_tmp("9p_sock_nodup");
    build_sock_path("nodup");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, /*ds=*/1u, /*mode=*/0755u,
                                              /*uid=*/0, /*gid=*/0,
                                              &root_ino));
    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(listen_fd >= 0);

    accept_ctx ctx = { .listen_fd = listen_fd, .fs = fs,
                        .run_status = STM_EBACKEND };
    atomic_init(&ctx.stop_flag, false);
    stm_stratumd_test_dup_unsupported = true;
    pthread_t worker;
    STM_ASSERT_EQ(pthread_create(&worker, NULL, accept_loop_thread, &ctx), 0);

    int cfd = connect_client(g_sock_path);
    STM_ASSERT_TRUE(cfd >= 0);
    STM_ASSERT_EQ(do_handshake(cfd, /*fid=*/100), 0);
    STM_ASSERT_EQ(do_clunk(cfd, /*tag=*/2, /*fid=*/100), 0);
    if (cfd >= 0) close(cfd);

    wake_and_join(&ctx, worker);
    stm_stratumd_test_dup_unsupported = false;
    STM_ASSERT_EQ(ctx.run_status, STM_OK);

    close(listen_fd);
    (void)unlink(g_sock_path);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}
#endif

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

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
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

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
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
    int fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
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

    int fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_EQ(fd, -EEXIST);

    /* The pre-existing regular file must still be there (we refused
     * to clobber it). */
    struct stat st;
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISREG(st.st_mode));

    (void)unlink(g_sock_path);
}

/* A name that can be seen can be dialed. One thread makes the listener while
 * this one looks for the name with no sleep between the looks and dials the
 * moment it is there: a name there from bind() is dialed before listen(), and
 * that dial is refused. */
typedef struct {
    const char *path;
    int         fd;
    atomic_bool done;
} listen_race;

static void *listen_race_thread(void *p)
{
    listen_race *r = p;
    r->fd = stm_stratumd_listen_unix(r->path, 4, 0600, 0);
    atomic_store(&r->done, true);
    return NULL;
}

STM_TEST(p9_socket_name_is_there_only_once_it_listens) {
    build_sock_path("ready");
    struct sockaddr_un addr;
    tsock_addr(&addr, g_sock_path);
    char staged[sizeof g_sock_path + 32];
    snprintf(staged, sizeof staged, "%s.%ld", g_sock_path, (long)getpid());

    int dialed = 0, refused = 0, other = 0, left = 0;
    for (int i = 0; i < 400; i++) {
        listen_race r = { .path = g_sock_path, .fd = -1 };
        atomic_init(&r.done, false);
        pthread_t t;
        STM_ASSERT_EQ(pthread_create(&t, NULL, listen_race_thread, &r), 0);
        struct stat st;
        while (lstat(g_sock_path, &st) != 0 && !atomic_load(&r.done)) { }
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        STM_ASSERT_TRUE(c >= 0);
        if (connect(c, (struct sockaddr *)&addr, sizeof addr) == 0) dialed++;
        else if (errno == ECONNREFUSED) refused++;
        else other++;
        close(c);
        pthread_join(t, NULL);
        STM_ASSERT_TRUE(r.fd >= 0);
        if (lstat(staged, &st) == 0) left++;
        close(r.fd);
        (void)unlink(g_sock_path);
    }
    STM_ASSERT_EQ(refused, 0);
    STM_ASSERT_EQ(other, 0);
    STM_ASSERT_EQ(dialed, 400);
    /* Nothing stays at the name the socket was bound under. */
    STM_ASSERT_EQ(left, 0);
}

/* The socket is given its path only if the path is still free: one taken since
 * the look is left as it is, and nothing stays at the name the socket was bound
 * under. */
STM_TEST(p9_socket_publish_refuses_a_path_taken_since_the_look) {
    build_sock_path("taken");
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(fd >= 0);
    char staged[STM_UNIX_STAGED_MAX];
    STM_ASSERT_EQ(stm_unix_listen_staged(fd, g_sock_path, 0600, 4, staged, sizeof staged), 0);
    struct stat st;
    STM_ASSERT_EQ(lstat(staged, &st), 0);
    STM_ASSERT_TRUE(S_ISSOCK(st.st_mode));
    /* It listens, and the path is not there yet. */
    STM_ASSERT_TRUE(lstat(g_sock_path, &st) != 0 && errno == ENOENT);

    int rfd = open(g_sock_path, O_CREAT | O_WRONLY | O_EXCL, 0644);
    STM_ASSERT_TRUE(rfd >= 0);
    close(rfd);
    STM_ASSERT_EQ(stm_unix_listen_publish(fd, staged, g_sock_path), -EEXIST);
    close(fd);

    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISREG(st.st_mode));
    STM_ASSERT_TRUE(lstat(staged, &st) != 0 && errno == ENOENT);
    (void)unlink(g_sock_path);

    /* A socket there since the look is a daemon's that started beside this one. */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(fd >= 0);
    STM_ASSERT_EQ(stm_unix_listen_staged(fd, g_sock_path, 0600, 4, staged, sizeof staged), 0);
    struct sockaddr_un addr;
    tsock_addr(&addr, g_sock_path);
    int other = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(other >= 0);
    STM_ASSERT_EQ(bind(other, (struct sockaddr *)&addr, sizeof addr), 0);
    STM_ASSERT_EQ(stm_unix_listen_publish(fd, staged, g_sock_path), -EADDRINUSE);
    close(fd);
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISSOCK(st.st_mode));
    STM_ASSERT_TRUE(lstat(staged, &st) != 0 && errno == ENOENT);
    close(other);
    (void)unlink(g_sock_path);
}

/* A daemon whose socket is at the path keeps it: a second listener is refused,
 * the first sees nothing of the look and can still be dialed, and its queue being
 * full changes nothing. Once no process holds the socket it is a dead daemon's,
 * and the next listener clears it. */
STM_TEST(p9_socket_listen_leaves_a_live_socket_and_clears_a_dead_one) {
    build_sock_path("live");
    int first = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(first >= 0);
    struct stat before, after;
    STM_ASSERT_EQ(lstat(g_sock_path, &before), 0);

    STM_ASSERT_EQ(stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0), -EADDRINUSE);
    STM_ASSERT_EQ(lstat(g_sock_path, &after), 0);
    STM_ASSERT_EQ(before.st_ino, after.st_ino);
    struct pollfd seen = { .fd = first, .events = POLLIN };
    STM_ASSERT_EQ(poll(&seen, 1, 0), 0);

    /* Dials nobody accepts, until one is turned away. */
    struct sockaddr_un addr;
    tsock_addr(&addr, g_sock_path);
    int held[64];
    int n_held = 0;
    bool full = false;
    while (n_held < 64 && !full) {
        int c = socket(AF_UNIX, SOCK_STREAM, 0);
        STM_ASSERT_TRUE(c >= 0);
        (void)fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
        if (connect(c, (struct sockaddr *)&addr, sizeof addr) == 0) {
            held[n_held++] = c;
        } else {
            full = true;
            close(c);
        }
    }
    STM_ASSERT_TRUE(full);
    STM_ASSERT_EQ(stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0), -EADDRINUSE);
    STM_ASSERT_EQ(lstat(g_sock_path, &after), 0);
    STM_ASSERT_EQ(before.st_ino, after.st_ino);
    for (int i = 0; i < n_held; i++) close(held[i]);

    close(first);
    int second = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(second >= 0);
    int c = connect_client(g_sock_path);
    STM_ASSERT_TRUE(c >= 0);
    close(c);
    close(second);
    (void)unlink(g_sock_path);

    /* Bound and not yet listening: a daemon's all the same. */
    int bound = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(bound >= 0);
    STM_ASSERT_EQ(bind(bound, (struct sockaddr *)&addr, sizeof addr), 0);
    STM_ASSERT_EQ(stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0), -EADDRINUSE);
    close(bound);
    (void)unlink(g_sock_path);
}

/* A listener's path goes before the listener is closed. Once it is, the next
 * listener at its path takes its socket for a dead daemon's and the path for
 * its own: what the first does after its close must not take the new one's
 * name. */
STM_TEST(p9_socket_a_listeners_end_leaves_the_next_ones_name) {
    build_sock_path("end");
    int first = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(first >= 0);
    stm_unix_listen_retire(first, g_sock_path);
    struct stat st;
    STM_ASSERT_TRUE(lstat(g_sock_path, &st) != 0 && errno == ENOENT);

    int second = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(second >= 0);
    close(first);
    stm_unix_listen_closed(g_sock_path);
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISSOCK(st.st_mode));
    int c = connect_client(g_sock_path);
    STM_ASSERT_TRUE(c >= 0);
    close(c);
    close(second);
    (void)unlink(g_sock_path);
}

/* A socket file no process holds: what a daemon that was killed leaves. */
static void leave_dead_socket(const char *path)
{
    struct sockaddr_un addr;
    tsock_addr(&addr, path);
    int dead = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(dead >= 0);
    STM_ASSERT_EQ(bind(dead, (struct sockaddr *)&addr, sizeof addr), 0);
    close(dead);
}

/* A listener's end removes its path only while the file there is its own. A path
 * somebody removed under it, and another daemon then took, is that daemon's. */
STM_TEST(p9_socket_a_listeners_end_leaves_a_path_no_longer_its_own) {
    build_sock_path("notown");
    int first = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(first >= 0);
    STM_ASSERT_EQ(unlink(g_sock_path), 0);
    struct sockaddr_un addr;
    tsock_addr(&addr, g_sock_path);
    int other = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(other >= 0);
    STM_ASSERT_EQ(bind(other, (struct sockaddr *)&addr, sizeof addr), 0);
    STM_ASSERT_EQ(listen(other, 4), 0);

    stm_unix_listen_retire(first, g_sock_path);
    close(first);
    stm_unix_listen_closed(g_sock_path);
    struct stat st;
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISSOCK(st.st_mode));
    int c = connect_client(g_sock_path);
    STM_ASSERT_TRUE(c >= 0);
    close(c);
    close(other);
    (void)unlink(g_sock_path);

    /* A file put where its socket was is left as well. */
    first = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(first >= 0);
    STM_ASSERT_EQ(unlink(g_sock_path), 0);
    int rfd = open(g_sock_path, O_CREAT | O_WRONLY | O_EXCL, 0644);
    STM_ASSERT_TRUE(rfd >= 0);
    close(rfd);
    stm_unix_listen_retire(first, g_sock_path);
    close(first);
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISREG(st.st_mode));
    (void)unlink(g_sock_path);
}

/* What a listener's end removes is told by its descriptor, and a number is used
 * again once its listener is closed. A socket bound on a number has nothing of
 * the listener that had it before: one closed without giving its path up would
 * else have the later one's end remove a name that was never its own. (Here the
 * name is the first one's dead socket; where file numbers are used again it
 * could be a running daemon's.) */
STM_TEST(p9_socket_a_descriptor_used_again_has_no_path_of_the_one_before) {
    build_sock_path("again");
    int first = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(first >= 0);
    close(first);
    struct stat st;
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);

    int second = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(second >= 0);
    if (second != first) {
        STM_ASSERT_EQ(dup2(second, first), first);
        close(second);
        second = first;
    }
    char other[sizeof g_sock_path + 8], staged[STM_UNIX_STAGED_MAX];
    snprintf(other, sizeof other, "%s.b", g_sock_path);
    STM_ASSERT_EQ(stm_unix_listen_staged(second, other, 0600, 4, staged, sizeof staged), 0);
    stm_unix_listen_retire(second, g_sock_path);
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISSOCK(st.st_mode));
    close(second);
    (void)unlink(staged);
    (void)unlink(g_sock_path);
}

/* Daemons started at once on one path take turns at the look at a socket found
 * there and its removal, by a lock on the path's directory. A listener that finds
 * no socket asks for no turn. One that finds one asks, waits for a turn another
 * holds, and not for good; and it gives its own turn up, whether it comes to
 * listen or is refused. */
static unsigned g_turns_asked;
static void count_turn(void) { g_turns_asked++; }

STM_TEST(p9_socket_listen_takes_its_turn_at_a_socket_alone_and_gives_it_up) {
    char dir[] = "/tmp/stm_socktest_turn_XXXXXX";
    STM_ASSERT_TRUE(mkdtemp(dir) != NULL);
    char path[64];
    snprintf(path, sizeof path, "%s/s.sock", dir);
    int held = open(dir, O_RDONLY | O_DIRECTORY);
    STM_ASSERT_TRUE(held >= 0);

    /* Nothing at the path: no turn asked for, whoever keeps the lock. */
    STM_ASSERT_EQ(flock(held, LOCK_EX | LOCK_NB), 0);
    stm_unix_listen_test_turn_asked = count_turn;
    unsigned asked = g_turns_asked;
    int fd = stm_stratumd_listen_unix(path, 4, 0600, 0);
    STM_ASSERT_TRUE(fd >= 0);
    STM_ASSERT_EQ(g_turns_asked - asked, 0);
    STM_ASSERT_EQ(flock(held, LOCK_UN), 0);

    /* A running daemon's socket there: asked for, and given up by the one refused. */
    asked = g_turns_asked;
    STM_ASSERT_EQ(stm_stratumd_listen_unix(path, 4, 0600, 0), -EADDRINUSE);
    STM_ASSERT_EQ(g_turns_asked - asked, 1);
    STM_ASSERT_EQ(flock(held, LOCK_EX | LOCK_NB), 0);
    STM_ASSERT_EQ(flock(held, LOCK_UN), 0);
    stm_unix_listen_retire(fd, path);
    close(fd);

    /* A dead daemon's: asked for, and given up by the one that comes to listen. */
    leave_dead_socket(path);
    asked = g_turns_asked;
    fd = stm_stratumd_listen_unix(path, 4, 0600, 0);
    STM_ASSERT_TRUE(fd >= 0);
    STM_ASSERT_EQ(g_turns_asked - asked, 1);
    STM_ASSERT_EQ(flock(held, LOCK_EX | LOCK_NB), 0);
    stm_unix_listen_retire(fd, path);
    close(fd);

    /* Another holds the turn, and keeps it: waited for, and then gone on without. */
    leave_dead_socket(path);
    struct timespec began, ended;
    clock_gettime(CLOCK_MONOTONIC, &began);
    fd = stm_stratumd_listen_unix(path, 4, 0600, 0);
    clock_gettime(CLOCK_MONOTONIC, &ended);
    STM_ASSERT_TRUE(fd >= 0);
    long waited_ms = (long)(ended.tv_sec - began.tv_sec) * 1000 +
                     (ended.tv_nsec - began.tv_nsec) / 1000000;
    STM_ASSERT_TRUE(waited_ms >= 50);

    stm_unix_listen_test_turn_asked = NULL;
    close(held);
    stm_unix_listen_retire(fd, path);
    close(fd);
    STM_ASSERT_EQ(rmdir(dir), 0);
}

/* A turn can be waited for, so what is at the name is looked at again once one is
 * asked for: a file put there meanwhile is somebody's, left and refused as a file.
 * (On Linux a file answers the look as a dead socket does, and would be removed.) */
static const char *g_swap_path;
static void swap_socket_for_file(void)
{
    (void)unlink(g_swap_path);
    int fd = open(g_swap_path, O_CREAT | O_WRONLY | O_EXCL, 0644);
    if (fd >= 0) close(fd);
}

STM_TEST(p9_socket_listen_looks_again_once_it_has_asked_for_its_turn) {
    build_sock_path("relook");
    leave_dead_socket(g_sock_path);
    g_swap_path = g_sock_path;
    stm_unix_listen_test_turn_asked = swap_socket_for_file;
    int fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    stm_unix_listen_test_turn_asked = NULL;
    STM_ASSERT_EQ(fd, -EEXIST);
    struct stat st;
    STM_ASSERT_EQ(lstat(g_sock_path, &st), 0);
    STM_ASSERT_TRUE(S_ISREG(st.st_mode));
    if (fd >= 0) close(fd);
    (void)unlink(g_sock_path);
}

/* The turn is kept from the look to the removal: between the two, over a dead
 * daemon's socket, nobody else can take it. */
static const char *g_turn_dir;
static int g_turn_tried = -1;

static void try_the_turn(void)
{
    int fd = open(g_turn_dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return;
    g_turn_tried = flock(fd, LOCK_EX | LOCK_NB) == 0 ? 0 : errno;
    close(fd);
}

STM_TEST(p9_socket_turn_is_kept_from_the_look_to_the_removal) {
    char dir[] = "/tmp/stm_socktest_kept_XXXXXX";
    STM_ASSERT_TRUE(mkdtemp(dir) != NULL);
    char path[64];
    snprintf(path, sizeof path, "%s/s.sock", dir);
    leave_dead_socket(path);

    g_turn_dir = dir;
    g_turn_tried = -1;
    stm_unix_listen_test_before_removal = try_the_turn;
    int fd = stm_stratumd_listen_unix(path, 4, 0600, 0);
    stm_unix_listen_test_before_removal = NULL;
    STM_ASSERT_TRUE(fd >= 0);
    STM_ASSERT_EQ(g_turn_tried, EWOULDBLOCK);

    stm_unix_listen_retire(fd, path);
    close(fd);
    STM_ASSERT_EQ(rmdir(dir), 0);
}

/* A whole stratumd, with /ctl/ on, whose start fails once its /ctl/ worker runs:
 * the worker is stopped and the run returns, whoever set the daemon's stop flag
 * or nobody, and nothing of the daemon is left. */
typedef struct {
    stm_stratumd_opts opts;
    stm_status        rc;
    atomic_bool       done;
} failing_run;

static void *failing_run_thread(void *arg)
{
    failing_run *r = arg;
    r->rc = stm_stratumd_run(&r->opts);
    atomic_store(&r->done, true);
    return NULL;
}

static const char *g_take_path;
static void take_the_path(void)
{
    int fd = open(g_take_path, O_CREAT | O_WRONLY | O_EXCL, 0600);
    if (fd >= 0) close(fd);
}

/* The run's status. A run still going after ten seconds is not coming back, and
 * its thread cannot be joined: the program ends there, failed. */
static stm_status failing_run_status(failing_run *r, const char *what)
{
    atomic_init(&r->done, false);
    r->rc = STM_OK;
    pthread_t tid;
    STM_ASSERT_EQ(pthread_create(&tid, NULL, failing_run_thread, r), 0);
    for (int i = 0; i < 1000 && !atomic_load(&r->done); i++) usleep(10 * 1000);
    if (!atomic_load(&r->done)) {
        fprintf(stderr, "  FAIL %s: stm_stratumd_run has not returned after 10 s\n", what);
        _exit(1);
    }
    pthread_join(tid, NULL);
    return r->rc;
}

STM_TEST(p9_socket_stratumd_whose_start_fails_past_its_ctl_ends) {
    make_tmp("9p_sock_failing");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    char dir[] = "/tmp/stm_socktest_fail_XXXXXX";
    STM_ASSERT_TRUE(mkdtemp(dir) != NULL);
    char fs_path[64], ctl_path[64];
    snprintf(fs_path, sizeof fs_path, "%s/fs.sock", dir);
    snprintf(ctl_path, sizeof ctl_path, "%s/ctl.sock", dir);
    struct stat st;
    atomic_bool stop;
    atomic_init(&stop, false);

    failing_run r;
    memset(&r.opts, 0, sizeof r.opts);
    r.opts.fs_path         = g_tmp_path;
    r.opts.keyfile_path    = g_key_path;
    r.opts.socket_path     = fs_path;
    r.opts.ctl_socket_path = ctl_path;
    r.opts.stop_flag       = &stop;

    /* Its path taken between the look and the last step, with no corvus consumer
     * to set the stop flag. */
    g_take_path = fs_path;
    stm_stratumd_test_before_publish = take_the_path;
    stm_status rc = failing_run_status(&r, "a path taken since the look");
    stm_stratumd_test_before_publish = NULL;
    STM_ASSERT_EQ((int)rc, (int)STM_EBACKEND);
    STM_ASSERT_FALSE(atomic_load(&stop));
    STM_ASSERT_EQ(lstat(fs_path, &st), 0);
    STM_ASSERT_TRUE(S_ISREG(st.st_mode));
    STM_ASSERT_EQ(unlink(fs_path), 0);
    STM_ASSERT_TRUE(lstat(ctl_path, &st) != 0 && errno == ENOENT);

    /* The same with a corvus consumer running, waiting for a corvus that is not
     * there. The consumer is stopped too, and its stop is what sets the daemon's
     * flag: the one sign of it to be had from here. */
    char corvus_path[64];
    snprintf(corvus_path, sizeof corvus_path, "%s/no-corvus", dir);
    r.opts.corvus_user          = "michael";
    r.opts.corvus_notify_socket = corvus_path;
    stm_stratumd_test_before_publish = take_the_path;
    rc = failing_run_status(&r, "a path taken since the look, a corvus consumer running");
    stm_stratumd_test_before_publish = NULL;
    STM_ASSERT_EQ((int)rc, (int)STM_EBACKEND);
    STM_ASSERT_TRUE(atomic_load(&stop));
    STM_ASSERT_EQ(unlink(fs_path), 0);
    STM_ASSERT_TRUE(lstat(ctl_path, &st) != 0 && errno == ENOENT);
    atomic_store(&stop, false);
    r.opts.corvus_notify_socket = NULL;

    /* A corvus consumer that cannot start, the stop flag never set. */
    r.opts.corvus_user = "michael\nthe-injector";
    rc = failing_run_status(&r, "a corvus consumer that cannot start");
    STM_ASSERT_TRUE(rc != STM_OK);
    STM_ASSERT_FALSE(atomic_load(&stop));

    /* A corvus consumer asked for with no stop flag at all. */
    r.opts.corvus_user = "michael";
    r.opts.stop_flag   = NULL;
    rc = failing_run_status(&r, "a corvus consumer and no stop flag");
    STM_ASSERT_EQ((int)rc, (int)STM_EINVAL);

    /* Neither path, nor the name the FS socket was bound under. */
    STM_ASSERT_EQ(rmdir(dir), 0);
}

/* A socket left at the name the listener binds under first is a killed
 * process's, and is cleared; a file there is somebody's, and is left. */
STM_TEST(p9_socket_listen_clears_only_a_socket_from_its_staged_name) {
    build_sock_path("staged");
    char staged[sizeof g_sock_path + 32];
    snprintf(staged, sizeof staged, "%s.%ld", g_sock_path, (long)getpid());
    (void)unlink(staged);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    STM_ASSERT_TRUE(strlen(staged) < sizeof addr.sun_path);
    memcpy(addr.sun_path, staged, strlen(staged) + 1);
    int left = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT_TRUE(left >= 0);
    STM_ASSERT_EQ(bind(left, (struct sockaddr *)&addr, sizeof addr), 0);
    close(left);
    int fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
    STM_ASSERT_TRUE(fd >= 0);
    struct stat st;
    STM_ASSERT_TRUE(lstat(staged, &st) != 0 && errno == ENOENT);
    close(fd);
    (void)unlink(g_sock_path);

    int rfd = open(staged, O_CREAT | O_WRONLY | O_EXCL, 0644);
    STM_ASSERT_TRUE(rfd >= 0);
    close(rfd);
    STM_ASSERT_EQ(stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0), -EEXIST);
    STM_ASSERT_EQ(lstat(staged, &st), 0);
    STM_ASSERT_TRUE(S_ISREG(st.st_mode));
    STM_ASSERT_TRUE(lstat(g_sock_path, &st) != 0 && errno == ENOENT);
    (void)unlink(staged);
}

/* A path that fits sun_path alone and leaves no room for a dot and the pid is
 * refused, with nothing made at it. */
STM_TEST(p9_socket_listen_path_with_no_room_to_stage_rejected) {
    char path[sizeof ((struct sockaddr_un *)0)->sun_path];
    int n = snprintf(path, sizeof path, "/tmp/stm_socktest_%d_", (int)getpid());
    STM_ASSERT_TRUE(n > 0 && (size_t)n < sizeof path - 1);
    memset(path + n, 'a', sizeof path - 1 - (size_t)n);
    path[sizeof path - 1] = '\0';

    int fd = stm_stratumd_listen_unix(path, 4, 0600, 0);
    STM_ASSERT_EQ(fd, -ENAMETOOLONG);
    struct stat st;
    STM_ASSERT_TRUE(lstat(path, &st) != 0 && errno == ENOENT);
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

    int listen_fd = stm_stratumd_listen_unix(g_sock_path, 4, 0600, 0);
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

/* A stop first shuts the reading side of each connection. What that does to a request
 * the client had already sent, and to one it sends next, is the kernel's to decide, and
 * two of them decide differently: Linux still hands over what was queued and refuses
 * what is sent next, macOS drops what was queued and takes what is sent next only to
 * drop it. ARCHITECTURE 15.8 says which, and this holds it to that. */
STM_TEST(p9_socket_a_request_already_sent_when_the_reading_side_is_shut) {
    int p[2];
    char buf[16];
    STM_ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, p), 0);
    void (*was)(int) = signal(SIGPIPE, SIG_IGN);
    STM_ASSERT_EQ(write(p[0], "sent", 4), 4);
    STM_ASSERT_EQ(shutdown(p[1], SHUT_RD), 0);
    ssize_t queued = read(p[1], buf, sizeof buf);
    errno = 0;
    ssize_t next = write(p[0], "next", 4);
    int next_errno = errno;
    ssize_t after = read(p[1], buf, sizeof buf);
#if defined(__linux__)
    STM_ASSERT_EQ(queued, 4);
    STM_ASSERT_EQ(next, -1);
    STM_ASSERT_EQ(next_errno, EPIPE);
#elif defined(__APPLE__)
    STM_ASSERT_EQ(queued, 0);
    STM_ASSERT_EQ(next, 4);
    (void)next_errno;
#else
    (void)queued;
    (void)next;
    (void)next_errno;
#endif
    STM_ASSERT_EQ(after, 0);
    /* A reply still goes out on either. */
    STM_ASSERT_EQ(write(p[1], "back", 4), 4);
    STM_ASSERT_EQ(read(p[0], buf, sizeof buf), 4);
    (void)signal(SIGPIPE, was);
    close(p[0]);
    close(p[1]);
}

STM_TEST_MAIN("9p_socket")
