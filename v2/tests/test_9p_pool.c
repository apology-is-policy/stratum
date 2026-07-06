/* SPDX-License-Identifier: ISC */
/*
 * test_9p_pool — CF-2a: the stratumd per-connection dispatch pool
 * (src/cmd/stratumd/fs_pool.c; docs/cf-2-design.md §3 + §8).
 *
 * Drives stm_fs_pool_serve DIRECTLY over a socketpair with a raw-frame
 * client (the test_9p_socket idiom minus the accept loop). Determinism
 * for "flush an EXECUTING op" / worker overlap comes from the pool's
 * test hook (stm_fs_pool_set_test_hooks): pre_handle parks a chosen
 * tag set on a condvar until the test releases it — no timing
 * dependence anywhere (the flake-dismissal discipline).
 *
 * Invariants exercised: CF2-I1 (exactly one reply per admitted op,
 * zero for flushed-before-reply), CF2-I2 (Rflush ordering; a
 * flushed-while-queued op never executes), CF2-I4 (Tversion barrier),
 * CF2-I6 (frame gate), CF2-I7 (serial-vs-pool byte equivalence),
 * CF2-I8 (clean-EOF drain).
 */
#include "tharness.h"
#include "test_fs_common.h"

#include "../src/9p/server_internal.h"
#include "../src/cmd/stratumd/fs_pool.h"

#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/stratumd.h>
#include <stratum/types.h>

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Wire helpers.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void pack_u64(uint8_t *p, uint64_t v) {
    pack_u32(p, (uint32_t)v);
    pack_u32(p + 4, (uint32_t)(v >> 32));
}
static uint32_t load_u32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t load_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static int send_all(int fd, const uint8_t *buf, uint32_t len)
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

/* Receive one frame. Returns 0, or -EPIPE on EOF/short, -errno else. */
static int recv_frame(int fd, uint8_t *buf, uint32_t cap, uint32_t *out_len)
{
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

/* Frame builders (into caller buf; return total size). */
static uint32_t build_tversion(uint8_t *buf, uint32_t msize)
{
    uint8_t *p = buf + 7;
    pack_u32(p, msize);       p += 4;
    pack_u16(p, 8);           p += 2;
    memcpy(p, "9P2000.L", 8); p += 8;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TVERSION;
    pack_u16(buf + 5, STM_9P_NOTAG);
    return sz;
}

static uint32_t build_tattach(uint8_t *buf, uint16_t tag, uint32_t fid)
{
    uint8_t *p = buf + 7;
    pack_u32(p, fid);           p += 4;
    pack_u32(p, STM_9P_NOFID);  p += 4;
    pack_u16(p, 0);             p += 2;   /* uname "" */
    pack_u16(p, 0);             p += 2;   /* aname "" */
    pack_u32(p, (uint32_t)-1);  p += 4;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TATTACH;
    pack_u16(buf + 5, tag);
    return sz;
}

static uint32_t build_tgetattr(uint8_t *buf, uint16_t tag, uint32_t fid)
{
    uint8_t *p = buf + 7;
    pack_u32(p, fid);                 p += 4;
    pack_u64(p, ~UINT64_C(0));        p += 8;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TGETATTR;
    pack_u16(buf + 5, tag);
    return sz;
}

static uint32_t build_tclunk(uint8_t *buf, uint16_t tag, uint32_t fid)
{
    uint8_t *p = buf + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TCLUNK;
    pack_u16(buf + 5, tag);
    return sz;
}

static uint32_t build_tflush(uint8_t *buf, uint16_t tag, uint16_t oldtag)
{
    uint8_t *p = buf + 7;
    pack_u16(p, oldtag); p += 2;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TFLUSH;
    pack_u16(buf + 5, tag);
    return sz;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Pool fixture: fs + socketpair + a serve thread.                        */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int            fd;         /* server side of the pair */
    stm_fs        *fs;
    uint32_t       workers;
    stm_status     rc;         /* pool_serve result */
    stm_9p_server *srv;
} serve_ctx;

static void *serve_thread(void *arg)
{
    serve_ctx *c = arg;
    stm_status crc = stm_9p_server_create(c->fs, /*root_dataset=*/1u,
                                            getuid(), getgid(),
                                            STM_9P_MSIZE_DEFAULT, &c->srv);
    if (crc != STM_OK) { c->rc = crc; close(c->fd); c->fd = -1; return NULL; }
    c->rc = stm_fs_pool_serve(c->fd, c->srv, c->workers,
                                 getuid(), /*user_policy=*/NULL);
    stm_9p_server_destroy(c->srv);
    c->srv = NULL;
    /* Mirror serve_client's teardown order (pool -> destroy -> close):
     * the client side must observe EOF once the pool is gone — the
     * fatal-path tests drain to EOF before joining. */
    close(c->fd);
    c->fd = -1;
    return NULL;
}

typedef struct {
    stm_fs    *fs;
    int        client_fd;
    serve_ctx  sc;
    pthread_t  tid;
} pool_fix;

/* Format + mount a fresh pool, init the root, socketpair, spawn the
 * pool serve thread. Returns false on fixture failure. */
static bool fix_up(pool_fix *fx, const char *tag, uint32_t workers)
{
    memset(fx, 0, sizeof *fx);
    make_tmp(tag);
    stm_fs_format_opts fopts = default_format_opts();
    if (stm_fs_format(g_tmp_path, &fopts) != STM_OK) return false;
    stm_fs_mount_opts mopts = rw_mount_opts();
    if (stm_fs_mount(g_tmp_path, &mopts, &fx->fs) != STM_OK) return false;
    uint64_t root_ino = 0;
    if (stm_fs_init_dataset_root(fx->fs, 1u, 0755u, 0, 0,
                                    &root_ino) != STM_OK)
        return false;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return false;
    fx->client_fd    = sv[0];
    fx->sc.fd        = sv[1];
    fx->sc.fs        = fx->fs;
    fx->sc.workers   = workers;
    fx->sc.rc        = STM_EBACKEND;
    if (pthread_create(&fx->tid, NULL, serve_thread, &fx->sc) != 0)
        return false;
    return true;
}

/* Close the client side (EOF to the pool), join, unmount. The serve
 * thread closes its own fd. */
static void fix_down(pool_fix *fx)
{
    if (fx->client_fd >= 0) close(fx->client_fd);
    (void)pthread_join(fx->tid, NULL);
    if (fx->fs) (void)stm_fs_unmount(fx->fs);
    stm_fs_pool_set_test_hooks(NULL);
    stm_9p_server_set_test_hooks(NULL, NULL);
}

/* Handshake over the client fd: Tversion + Tattach(fid). */
static int fix_handshake(pool_fix *fx, uint32_t fid)
{
    uint8_t  buf[512];
    uint32_t rlen = 0;
    uint32_t sz = build_tversion(buf, STM_9P_MSIZE_DEFAULT);
    if (send_all(fx->client_fd, buf, sz) != 0) return -1;
    if (recv_frame(fx->client_fd, buf, sizeof buf, &rlen) != 0) return -2;
    if (buf[4] != STM_9P_RVERSION) return -3;
    sz = build_tattach(buf, 1, fid);
    if (send_all(fx->client_fd, buf, sz) != 0) return -4;
    if (recv_frame(fx->client_fd, buf, sizeof buf, &rlen) != 0) return -5;
    if (buf[4] != STM_9P_RATTACH) return -6;
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Stall-hook controller (the determinism substrate).                     */
/* ────────────────────────────────────────────────────────────────────── */

#define STALL_MAX 8

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    uint16_t park_tags[STALL_MAX];
    int      n_park;
    bool     released;
    int      n_entered;
    uint16_t entered[STALL_MAX];
    bool     fatal_seen;        /* on_fatal fired (first dead latch) */
} stall_ctl;

static void stall_init(stall_ctl *c, const uint16_t *tags, int n)
{
    memset(c, 0, sizeof *c);
    pthread_mutex_init(&c->mu, NULL);
    pthread_cond_init(&c->cv, NULL);
    for (int i = 0; i < n && i < STALL_MAX; i++) c->park_tags[i] = tags[i];
    c->n_park = n;
}

static void stall_destroy(stall_ctl *c)
{
    pthread_mutex_destroy(&c->mu);
    pthread_cond_destroy(&c->cv);
}

static void stall_pre_handle(void *arg, uint16_t tag, uint8_t type)
{
    (void)type;
    stall_ctl *c = arg;
    pthread_mutex_lock(&c->mu);
    bool park = false;
    for (int i = 0; i < c->n_park; i++)
        if (c->park_tags[i] == tag) { park = true; break; }
    if (park) {
        if (c->n_entered < STALL_MAX) c->entered[c->n_entered] = tag;
        c->n_entered++;
        pthread_cond_broadcast(&c->cv);
        while (!c->released)
            pthread_cond_wait(&c->cv, &c->mu);
    }
    pthread_mutex_unlock(&c->mu);
}

/* Block until n ops are parked in the hook. */
static void stall_await_entered(stall_ctl *c, int n)
{
    pthread_mutex_lock(&c->mu);
    while (c->n_entered < n)
        pthread_cond_wait(&c->cv, &c->mu);
    pthread_mutex_unlock(&c->mu);
}

/* on_fatal hook + its waiter: order a park release strictly AFTER the
 * connection's dead latch. Runs under the POOL mutex — touches only
 * the ctl's own mutex (no lock-order interaction). */
static void stall_on_fatal(void *arg, stm_status rc)
{
    (void)rc;
    stall_ctl *c = arg;
    pthread_mutex_lock(&c->mu);
    c->fatal_seen = true;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static void stall_await_fatal(stall_ctl *c)
{
    pthread_mutex_lock(&c->mu);
    while (!c->fatal_seen)
        pthread_cond_wait(&c->cv, &c->mu);
    pthread_mutex_unlock(&c->mu);
}

static void stall_release(stall_ctl *c)
{
    pthread_mutex_lock(&c->mu);
    c->released = true;
    pthread_cond_broadcast(&c->cv);
    pthread_mutex_unlock(&c->mu);
}

static void stall_install(stall_ctl *c)
{
    stm_fs_pool_test_hooks h = { .pre_handle = stall_pre_handle, .arg = c };
    stm_fs_pool_set_test_hooks(&h);
}

/* CF-2b: park inside a 3-phase handler's unlocked (b) phase — the fid
 * pin(s) HELD, s->lock NOT held. Same park logic / controller as the
 * pool-level pre_handle stall, different hook point. */
static void bstall_phase_b(uint8_t type, uint16_t tag, void *arg)
{
    stall_pre_handle(arg, tag, type);
}

static void bstall_install(stall_ctl *c)
{
    stm_9p_server_set_test_hooks(bstall_phase_b, c);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                 */
/* ────────────────────────────────────────────────────────────────────── */

/* Pipelined mixed tags complete exactly once each (CF2-I1), any order. */
STM_TEST(p9_pool_pipeline_getattr_storm) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_storm", /*workers=*/4));
    STM_ASSERT_EQ(fix_handshake(&fx, /*fid=*/0), 0);

    enum { N = 24 };
    uint8_t buf[512];
    /* Send N Tgetattrs on the root fid, tags 100..100+N-1, without
     * reading a single reply (pipelining). */
    for (int i = 0; i < N; i++) {
        uint32_t sz = build_tgetattr(buf, (uint16_t)(100 + i), 0);
        STM_ASSERT_EQ(send_all(fx.client_fd, buf, sz), 0);
    }
    /* Collect N replies; every tag exactly once; every type Rgetattr. */
    int seen[N];
    memset(seen, 0, sizeof seen);
    for (int i = 0; i < N; i++) {
        uint32_t rlen = 0;
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
        STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
        uint16_t tag = load_u16(buf + 5);
        STM_ASSERT_TRUE(tag >= 100 && tag < 100 + N);
        seen[tag - 100]++;
    }
    for (int i = 0; i < N; i++) STM_ASSERT_EQ(seen[i], 1);

    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tclunk(buf, 9, 0)), 0);
    uint32_t rlen = 0;
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RCLUNK);

    fix_down(&fx);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);   /* clean EOF */
}

/* Workers genuinely overlap: with 2 workers, two parked ops are inside
 * pre_handle SIMULTANEOUSLY — impossible under a serial loop. */
STM_TEST(p9_pool_workers_overlap) {
    pool_fix fx;
    stall_ctl st;
    uint16_t park[2] = { 200, 201 };
    stall_init(&st, park, 2);
    stall_install(&st);

    STM_ASSERT_TRUE(fix_up(&fx, "pool_overlap", /*workers=*/2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[512];
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 200, 0)), 0);
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 201, 0)), 0);

    /* Both parked at once = two workers concurrently mid-request. */
    stall_await_entered(&st, 2);
    stall_release(&st);

    for (int i = 0; i < 2; i++) {
        uint32_t rlen = 0;
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
        STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
    }

    fix_down(&fx);
    stall_destroy(&st);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* Tflush of an unknown oldtag: immediate Rflush (CF2-I2 trivial arm). */
STM_TEST(p9_pool_flush_unknown_tag) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_flush_unk", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[256];
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                             build_tflush(buf, 50, /*oldtag=*/999)), 0);
    uint32_t rlen = 0;
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RFLUSH);
    STM_ASSERT_EQ(load_u16(buf + 5), 50);

    fix_down(&fx);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* Tflush of an EXECUTING op: its reply is DISCARDED; only Rflush
 * arrives; the connection keeps working (CF2-I1 + I2). */
STM_TEST(p9_pool_flush_executing_discards_reply) {
    pool_fix fx;
    stall_ctl st;
    uint16_t park[1] = { 300 };
    stall_init(&st, park, 1);
    stall_install(&st);

    STM_ASSERT_TRUE(fix_up(&fx, "pool_flush_exec", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[512];
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 300, 0)), 0);
    stall_await_entered(&st, 1);           /* tag 300 is EXECUTING */

    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                             build_tflush(buf, 51, 300)), 0);
    stall_release(&st);

    /* Two LEGAL wire outcomes (the reader's flush processing races the
     * released worker's completion — both sides are correct 9P):
     *   A (flush won):  Rflush(51) only — the reply was discarded;
     *   B (worker won): Rgetattr(300) first, THEN Rflush(51) — the op
     *     completed before the flush was seen; CF2-I2 requires the
     *     reply to PRECEDE the Rflush, never follow it.
     * In practice A dominates (the idle reader processes the queued
     * Tflush in microseconds); both must be sound. */
    uint32_t rlen = 0;
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    if (buf[4] == STM_9P_RGETATTR) {           /* outcome B */
        STM_ASSERT_EQ(load_u16(buf + 5), 300);
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    }
    STM_ASSERT_EQ(buf[4], STM_9P_RFLUSH);
    STM_ASSERT_EQ(load_u16(buf + 5), 51);

    /* Tag 300 is reusable; the connection still serves. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 300, 0)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
    STM_ASSERT_EQ(load_u16(buf + 5), 300);

    fix_down(&fx);
    stall_destroy(&st);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* Tflush of a QUEUED op: it NEVER executes and never replies; Rflush
 * arrives immediately even while workers stay parked (CF2-I2). */
STM_TEST(p9_pool_flush_queued_never_executes) {
    pool_fix fx;
    stall_ctl st;
    uint16_t park[2] = { 400, 401 };
    stall_init(&st, park, 2);
    stall_install(&st);

    STM_ASSERT_TRUE(fix_up(&fx, "pool_flush_queued", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[512];
    /* Park BOTH workers. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 400, 0)), 0);
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 401, 0)), 0);
    stall_await_entered(&st, 2);

    /* Tag 402 can only sit QUEUED (no free worker). */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 402, 0)), 0);
    /* Flush it while queued: Rflush must arrive with the workers still
     * parked — the queued op is cancelled, not waited for. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                             build_tflush(buf, 52, 402)), 0);
    uint32_t rlen = 0;
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RFLUSH);
    STM_ASSERT_EQ(load_u16(buf + 5), 52);

    stall_release(&st);

    /* Drain: exactly three replies remain (the two parked ops + a
     * sentinel) in ANY order — out-of-order completion is the pool's
     * contract. Tag 402 must NEVER appear (it was cancelled while
     * queued). */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 500, 0)), 0);
    bool seen_402 = false, seen_400 = false, seen_401 = false,
         seen_500 = false;
    for (int i = 0; i < 3; i++) {
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
        uint16_t tag = load_u16(buf + 5);
        if (tag == 402) seen_402 = true;
        if (tag == 400) seen_400 = true;
        if (tag == 401) seen_401 = true;
        if (tag == 500) seen_500 = true;
    }
    STM_ASSERT_TRUE(!seen_402);
    STM_ASSERT_TRUE(seen_400);
    STM_ASSERT_TRUE(seen_401);
    STM_ASSERT_TRUE(seen_500);

    fix_down(&fx);
    stall_destroy(&st);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* 9P allows the client to reuse oldtag the moment Rflush arrives —
 * even while the cancelled corpse still occupies a slot (no worker has
 * popped it yet, both being parked). The reuse must NOT trip the
 * duplicate-tag gate (the self-audit F1 regression: the kernel
 * client's #845 flush-then-reuse discipline does exactly this). */
STM_TEST(p9_pool_tag_reuse_after_flush_of_queued) {
    pool_fix fx;
    stall_ctl st;
    uint16_t park[2] = { 450, 451 };
    stall_init(&st, park, 2);
    stall_install(&st);

    STM_ASSERT_TRUE(fix_up(&fx, "pool_flush_reuse", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[512];
    uint32_t rlen = 0;
    /* Park both workers; queue tag 460; flush it. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 450, 0)), 0);
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 451, 0)), 0);
    stall_await_entered(&st, 2);
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 460, 0)), 0);
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tflush(buf, 53, 460)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RFLUSH);

    /* Reuse tag 460 IMMEDIATELY — the corpse is still queued (workers
     * parked). Must be admitted, not connection-fatal. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 460, 0)), 0);
    stall_release(&st);

    /* Exactly three replies: 450, 451, and the REUSED 460 — once. */
    int got_460 = 0, got_parked = 0;
    for (int i = 0; i < 3; i++) {
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
        STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
        uint16_t tag = load_u16(buf + 5);
        if (tag == 460) got_460++;
        if (tag == 450 || tag == 451) got_parked++;
    }
    STM_ASSERT_EQ(got_460, 1);
    STM_ASSERT_EQ(got_parked, 2);

    fix_down(&fx);
    stall_destroy(&st);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* The kernel client's tags are TABLE INDICES: a synchronous op stream
 * reuses tag 0 on every single request, sending op N+1 the instant op
 * N's reply arrives. The completion path must unregister the tag
 * BEFORE the reply write, or the client's next same-tag op races the
 * worker's slot-free and trips the duplicate-tag gate (the boot-gate
 * F2 regression: probe46's mount death on the first pool-on boot).
 * 5000 iterations makes the pre-fix race land reliably on a loaded
 * host; post-fix it is structurally impossible. */
STM_TEST(p9_pool_synchronous_same_tag_reuse_storm) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_tag0_storm", /*workers=*/4));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[512];
    uint32_t rlen = 0;
    for (int i = 0; i < 5000; i++) {
        uint32_t sz = build_tgetattr(buf, /*tag=*/0, 0);
        if (send_all(fx.client_fd, buf, sz) != 0) {
            stm_test_fail(__FILE__, __LINE__, "send failed at i=%d", i);
            break;
        }
        int rc = recv_frame(fx.client_fd, buf, sizeof buf, &rlen);
        if (rc != 0 || buf[4] != STM_9P_RGETATTR) {
            stm_test_fail(__FILE__, __LINE__,
                          "iteration %d: rc=%d type=%d (connection died"
                          " -- the tag-reuse completion race)",
                          i, rc, (int)buf[4]);
            break;
        }
    }

    fix_down(&fx);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* Tversion mid-pipeline: drains the in-flight op (its reply is
 * delivered FIRST), then Rversion; the fid table is reset (CF2-I4). */
STM_TEST(p9_pool_version_barrier) {
    pool_fix fx;
    stall_ctl st;
    uint16_t park[1] = { 600 };
    stall_init(&st, park, 1);
    stall_install(&st);

    STM_ASSERT_TRUE(fix_up(&fx, "pool_version", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[512];
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 600, 0)), 0);
    stall_await_entered(&st, 1);

    /* Tversion while tag 600 executes. The reader must WAIT (barrier);
     * releasing the op lets it reply, then Rversion follows. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                             build_tversion(buf, STM_9P_MSIZE_DEFAULT)), 0);
    stall_release(&st);

    uint32_t rlen = 0;
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
    STM_ASSERT_EQ(load_u16(buf + 5), 600);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RVERSION);

    /* h_version clunked every fid: the old fid 0 must now EBADF. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 601, 0)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RLERROR);

    fix_down(&fx);
    stall_destroy(&st);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* Duplicate in-flight tag: connection-fatal (protocol violation). */
STM_TEST(p9_pool_duplicate_tag_fatal) {
    pool_fix fx;
    stall_ctl st;
    uint16_t park[1] = { 700 };
    stall_init(&st, park, 1);
    stm_fs_pool_test_hooks h = { .pre_handle = stall_pre_handle,
                                 .on_fatal   = stall_on_fatal,
                                 .arg        = &st };
    stm_fs_pool_set_test_hooks(&h);

    STM_ASSERT_TRUE(fix_up(&fx, "pool_dup_tag", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    uint8_t buf[512];
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 700, 0)), 0);
    stall_await_entered(&st, 1);
    /* Same tag again while in flight — and provably STILL in flight
     * when the reader runs its dup-check: the first incarnation's
     * worker stays parked (slot pinned EXECUTING) until the fatal
     * latch is OBSERVED via the on_fatal hook. Releasing before that
     * races the reader — the losing interleave completes op #1 into
     * REPLYING first, the dup is then admitted as LEGAL tag reuse (the
     * F2 rule), the connection stays healthy, and the drain below
     * blocks forever (the ctest -j4 timeout that exposed this). */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 700, 0)), 0);
    stall_await_fatal(&st);
    stall_release(&st);

    /* The connection dies: whatever frames may still drain, the stream
     * must reach EOF. (The parked op's reply is skipped once the dead
     * latch is set; tolerate it racing the latch.) */
    uint32_t rlen = 0;
    int rc;
    do {
        rc = recv_frame(fx.client_fd, buf, sizeof buf, &rlen);
    } while (rc == 0);
    STM_ASSERT_EQ(rc, -EPIPE);

    fix_down(&fx);
    stall_destroy(&st);
    STM_ASSERT_EQ(fx.sc.rc, STM_EPROTOCOL);
}

/* Frame above the negotiated msize: connection-fatal (CF2-I6 gate). */
STM_TEST(p9_pool_oversize_frame_fatal) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_oversize", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    /* Claim a frame one byte over the negotiated msize. */
    uint8_t hdr[7];
    pack_u32(hdr, STM_9P_MSIZE_DEFAULT + 1u);
    hdr[4] = STM_9P_TGETATTR;
    pack_u16(hdr + 5, 800);
    STM_ASSERT_EQ(send_all(fx.client_fd, hdr, sizeof hdr), 0);

    uint8_t  buf[64];
    uint32_t rlen = 0;
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), -EPIPE);

    fix_down(&fx);
    STM_ASSERT_EQ(fx.sc.rc, STM_EPROTOCOL);
}

/* Clean-EOF drain: pipeline a batch, half-close the send side, and
 * every reply must still arrive (CF2-I8). */
STM_TEST(p9_pool_clean_eof_drains_pipeline) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_eof_drain", 4));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    enum { N = 16 };
    uint8_t buf[512];
    for (int i = 0; i < N; i++) {
        uint32_t sz = build_tgetattr(buf, (uint16_t)(900 + i), 0);
        STM_ASSERT_EQ(send_all(fx.client_fd, buf, sz), 0);
    }
    STM_ASSERT_EQ(shutdown(fx.client_fd, SHUT_WR), 0);

    int got = 0;
    for (;;) {
        uint32_t rlen = 0;
        int rc = recv_frame(fx.client_fd, buf, sizeof buf, &rlen);
        if (rc == -EPIPE) break;
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
        got++;
    }
    STM_ASSERT_EQ(got, N);

    fix_down(&fx);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* Slot exhaustion back-pressure: with every worker parked, pipeline
 * far past the queue capacity; after release, EVERY op must complete
 * exactly once (no drops, reader unblocks) (CF2-I6). */
STM_TEST(p9_pool_backpressure_no_drops) {
    pool_fix fx;
    stall_ctl st;
    uint16_t park[2] = { 1000, 1001 };
    stall_init(&st, park, 2);
    stall_install(&st);

    STM_ASSERT_TRUE(fix_up(&fx, "pool_backpressure", 2));
    STM_ASSERT_EQ(fix_handshake(&fx, 0), 0);

    /* Park both workers, then pipeline 80 more ops (> 64 slots): the
     * reader must block on admission and resume without losing any. */
    enum { EXTRA = 80 };
    uint8_t buf[512];
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 1000, 0)), 0);
    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tgetattr(buf, 1001, 0)), 0);
    stall_await_entered(&st, 2);
    for (int i = 0; i < EXTRA; i++) {
        uint32_t sz = build_tgetattr(buf, (uint16_t)(1100 + i), 0);
        STM_ASSERT_EQ(send_all(fx.client_fd, buf, sz), 0);
    }
    stall_release(&st);

    int total = 0;
    int seen[EXTRA + 2];
    memset(seen, 0, sizeof seen);
    while (total < EXTRA + 2) {
        uint32_t rlen = 0;
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
        STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
        uint16_t tag = load_u16(buf + 5);
        int idx = -1;
        if (tag == 1000) idx = EXTRA;
        else if (tag == 1001) idx = EXTRA + 1;
        else if (tag >= 1100 && tag < 1100 + EXTRA) idx = tag - 1100;
        STM_ASSERT_TRUE(idx >= 0);
        if (idx >= 0) seen[idx]++;
        total++;
    }
    for (int i = 0; i < EXTRA + 2; i++) STM_ASSERT_EQ(seen[i], 1);

    fix_down(&fx);
    stall_destroy(&st);
    STM_ASSERT_EQ(fx.sc.rc, STM_OK);
}

/* CF2-I7: the same synchronous script through the serial loop
 * (stm_stratumd_serve_client, workers=1 default) and the pool produces
 * byte-identical replies. */
typedef struct {
    int        fd;
    stm_fs    *fs;
    stm_status rc;
} serial_ctx;

static void *serial_thread(void *arg)
{
    serial_ctx *c = arg;
    /* serve_client closes the fd itself. idle_timeout=0 (tests drive
     * the wire synchronously). */
    c->rc = stm_stratumd_serve_client(c->fd, c->fs, getuid(), getgid(),
                                         STM_9P_MSIZE_DEFAULT,
                                         /*root_dataset=*/1u,
                                         /*idle_timeout_ms=*/0u, NULL);
    return NULL;
}

STM_TEST(p9_pool_serial_byte_equivalence) {
    /* One pool fixture; run the script twice against the SAME mounted
     * fs — once through the serial loop, once through the pool — and
     * compare every reply byte-for-byte. */
    make_tmp("pool_equiv");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    uint64_t root_ino = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, 1u, 0755u, 0, 0, &root_ino));

    uint8_t serial_replies[4][512];
    uint32_t serial_lens[4];
    uint8_t pool_replies[4][512];
    uint32_t pool_lens[4];

    /* The script: Tversion, Tattach, Tgetattr, Tclunk — synchronous
     * (one op at a time), so ordering is forced identical. */
    for (int leg = 0; leg < 2; leg++) {
        int sv[2];
        STM_ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
        pthread_t tid;
        serve_ctx  pc;
        serial_ctx sc;
        if (leg == 0) {
            sc.fd = sv[1]; sc.fs = fs; sc.rc = STM_EBACKEND;
            STM_ASSERT_EQ(pthread_create(&tid, NULL, serial_thread, &sc), 0);
        } else {
            memset(&pc, 0, sizeof pc);
            pc.fd = sv[1]; pc.fs = fs; pc.workers = 4;
            pc.rc = STM_EBACKEND;
            STM_ASSERT_EQ(pthread_create(&tid, NULL, serve_thread, &pc), 0);
        }

        uint8_t  (*replies)[512] = leg == 0 ? serial_replies : pool_replies;
        uint32_t *lens           = leg == 0 ? serial_lens    : pool_lens;

        uint8_t  buf[512];
        uint32_t sz;

        sz = build_tversion(buf, STM_9P_MSIZE_DEFAULT);
        STM_ASSERT_EQ(send_all(sv[0], buf, sz), 0);
        STM_ASSERT_EQ(recv_frame(sv[0], replies[0], 512, &lens[0]), 0);

        sz = build_tattach(buf, 1, 0);
        STM_ASSERT_EQ(send_all(sv[0], buf, sz), 0);
        STM_ASSERT_EQ(recv_frame(sv[0], replies[1], 512, &lens[1]), 0);

        sz = build_tgetattr(buf, 2, 0);
        STM_ASSERT_EQ(send_all(sv[0], buf, sz), 0);
        STM_ASSERT_EQ(recv_frame(sv[0], replies[2], 512, &lens[2]), 0);

        sz = build_tclunk(buf, 3, 0);
        STM_ASSERT_EQ(send_all(sv[0], buf, sz), 0);
        STM_ASSERT_EQ(recv_frame(sv[0], replies[3], 512, &lens[3]), 0);

        close(sv[0]);
        pthread_join(tid, NULL);
        /* Both serve drivers close sv[1] themselves (serve_client by
         * contract; serve_thread mirrors it). */
    }

    for (int i = 0; i < 4; i++) {
        STM_ASSERT_EQ(serial_lens[i], pool_lens[i]);
        if (serial_lens[i] == pool_lens[i])
            STM_ASSERT_EQ(memcmp(serial_replies[i], pool_replies[i],
                                   serial_lens[i]), 0);
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
}

/* ────────────────────────────────────────────────────────────────────── */
/* CF-2b — the s->lock 3-phase surgery + per-fid pin.                     */
/* ────────────────────────────────────────────────────────────────────── */

static uint32_t build_twalk_clone(uint8_t *buf, uint16_t tag,
                                     uint32_t fid, uint32_t newfid)
{
    uint8_t *p = buf + 7;
    pack_u32(p, fid);    p += 4;
    pack_u32(p, newfid); p += 4;
    pack_u16(p, 0);      p += 2;    /* nwname = 0 (clone) */
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TWALK;
    pack_u16(buf + 5, tag);
    return sz;
}

static uint32_t build_tlcreate(uint8_t *buf, uint16_t tag, uint32_t fid,
                                  const char *name, uint32_t flags,
                                  uint32_t mode)
{
    uint16_t nlen = (uint16_t)strlen(name);
    uint8_t *p = buf + 7;
    pack_u32(p, fid);        p += 4;
    pack_u16(p, nlen);       p += 2;
    memcpy(p, name, nlen);   p += nlen;
    pack_u32(p, flags);      p += 4;
    pack_u32(p, mode);       p += 4;
    pack_u32(p, 0);          p += 4;    /* gid */
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TLCREATE;
    pack_u16(buf + 5, tag);
    return sz;
}

static uint32_t build_twrite(uint8_t *buf, uint16_t tag, uint32_t fid,
                                uint64_t off, const void *data, uint32_t n)
{
    uint8_t *p = buf + 7;
    pack_u32(p, fid);      p += 4;
    pack_u64(p, off);      p += 8;
    pack_u32(p, n);        p += 4;
    memcpy(p, data, n);    p += n;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TWRITE;
    pack_u16(buf + 5, tag);
    return sz;
}

static uint32_t build_tread(uint8_t *buf, uint16_t tag, uint32_t fid,
                               uint64_t off, uint32_t count)
{
    uint8_t *p = buf + 7;
    pack_u32(p, fid);   p += 4;
    pack_u64(p, off);   p += 8;
    pack_u32(p, count); p += 4;
    uint32_t sz = (uint32_t)(p - buf);
    pack_u32(buf, sz);
    buf[4] = STM_9P_TREAD;
    pack_u16(buf + 5, tag);
    return sz;
}

/* Expect NO bytes on fd within ms (poll returns 0). */
static bool fd_quiet_for(int fd, int ms)
{
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    return poll(&pfd, 1, ms) == 0;
}

/* Clone root fid 0 -> fid, lcreate name O_RDWR 0644 (fid becomes the
 * open file), write payload at 0. Uses tags 90..92. */
static int fix_open_file(pool_fix *fx, uint32_t fid, const char *name,
                            const void *payload, uint32_t n)
{
    uint8_t  buf[512];
    uint32_t rlen = 0;
    if (send_all(fx->client_fd, buf,
                  build_twalk_clone(buf, 90, 0, fid)) != 0) return -1;
    if (recv_frame(fx->client_fd, buf, sizeof buf, &rlen) != 0) return -2;
    if (buf[4] != STM_9P_RWALK) return -3;
    if (send_all(fx->client_fd, buf,
                  build_tlcreate(buf, 91, fid, name,
                                  STM_9P_O_RDWR, 0644u)) != 0) return -4;
    if (recv_frame(fx->client_fd, buf, sizeof buf, &rlen) != 0) return -5;
    if (buf[4] != STM_9P_RLCREATE) return -6;
    if (n > 0) {
        if (send_all(fx->client_fd, buf,
                      build_twrite(buf, 92, fid, 0, payload, n)) != 0)
            return -7;
        if (recv_frame(fx->client_fd, buf, sizeof buf, &rlen) != 0) return -8;
        if (buf[4] != STM_9P_RWRITE) return -9;
    }
    return 0;
}

/* Tclunk must WAIT for a pinned fid: park a Tread mid-(b) (pin held),
 * send Tclunk on the same fid, prove the clunk does NOT complete while
 * the pin is held, then release and prove both complete correctly and
 * the fid is gone. Revert-proof: without h_clunk's busy-wait the
 * release memsets the slot under the parked op and its (c) unpin hits
 * the busy==0 abort tripwire (crash = test failure). */
STM_TEST(p9_pool_pin_read_clunk_waits) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_pin_clunk", /*workers=*/4));
    STM_ASSERT_EQ(fix_handshake(&fx, /*fid=*/0), 0);
    static const char payload[] = "thylacine";   /* 9 bytes, no NUL */
    STM_ASSERT_EQ(fix_open_file(&fx, 1, "pinf", payload, 9), 0);

    stall_ctl ctl;
    uint16_t park[] = { 200 };
    stall_init(&ctl, park, 1);
    bstall_install(&ctl);

    uint8_t  buf[512];
    uint32_t rlen = 0;
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tread(buf, 200, 1, 0, 64)), 0);
    stall_await_entered(&ctl, 1);       /* the read is mid-(b), pinned */

    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tclunk(buf, 201, 1)), 0);
    /* The clunk must be waiting on the pin — nothing may arrive. */
    STM_ASSERT_TRUE(fd_quiet_for(fx.client_fd, 150));

    stall_release(&ctl);
    /* Both replies arrive (wire order unspecified — the two workers'
     * writes race to the writer mutex after the pin drops). */
    bool got_read = false, got_clunk = false;
    for (int i = 0; i < 2; i++) {
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
        uint16_t tag = load_u16(buf + 5);
        if (tag == 200) {
            STM_ASSERT_EQ(buf[4], STM_9P_RREAD);
            STM_ASSERT_EQ(load_u32(buf + 7), 9u);
            STM_ASSERT_EQ(memcmp(buf + 11, payload, 9), 0);
            got_read = true;
        } else {
            STM_ASSERT_EQ(tag, 201);
            STM_ASSERT_EQ(buf[4], STM_9P_RCLUNK);
            got_clunk = true;
        }
    }
    STM_ASSERT_TRUE(got_read);
    STM_ASSERT_TRUE(got_clunk);

    /* The fid is gone. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tgetattr(buf, 202, 1)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(buf + 7), STM_9P_ECODE_EBADF);

    fix_down(&fx);
    stall_destroy(&ctl);
}

/* The pin is SHARED, not exclusive: two clone-walks from ONE source
 * fid to the SAME newfid park mid-(b) SIMULTANEOUSLY (source busy == 2
 * — the overlap proof), then their (c) phases serialize on the bind:
 * exactly one Rwalk binds the newfid, the loser gets EBADF. */
STM_TEST(p9_pool_pin_walk_walk_same_newfid) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_pin_ww", /*workers=*/4));
    STM_ASSERT_EQ(fix_handshake(&fx, /*fid=*/0), 0);

    stall_ctl ctl;
    uint16_t park[] = { 300, 301 };
    stall_init(&ctl, park, 2);
    bstall_install(&ctl);

    uint8_t  buf[512];
    uint32_t rlen = 0;
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_twalk_clone(buf, 300, 0, 7)), 0);
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_twalk_clone(buf, 301, 0, 7)), 0);
    /* BOTH walks are parked inside (b) at once — two ops overlapping
     * on one pinned source fid. */
    stall_await_entered(&ctl, 2);
    stall_release(&ctl);

    int n_walk = 0, n_ebadf = 0;
    for (int i = 0; i < 2; i++) {
        STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
        uint16_t tag = load_u16(buf + 5);
        STM_ASSERT_TRUE(tag == 300 || tag == 301);
        if (buf[4] == STM_9P_RWALK) {
            n_walk++;
        } else {
            STM_ASSERT_EQ(buf[4], STM_9P_RLERROR);
            STM_ASSERT_EQ(load_u32(buf + 7), STM_9P_ECODE_EBADF);
            n_ebadf++;
        }
    }
    STM_ASSERT_EQ(n_walk, 1);
    STM_ASSERT_EQ(n_ebadf, 1);

    /* The winner's newfid is live. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tgetattr(buf, 302, 7)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);

    fix_down(&fx);
    stall_destroy(&ctl);
}

/* Non-exclusivity the other way: while a Twrite is parked mid-(b) on
 * an open file fid, a Tgetattr on the SAME fid completes — same-fid
 * ops overlap under the shared pin instead of serializing. */
STM_TEST(p9_pool_pin_getattr_overlaps_parked_write) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_pin_ov", /*workers=*/4));
    STM_ASSERT_EQ(fix_handshake(&fx, /*fid=*/0), 0);
    STM_ASSERT_EQ(fix_open_file(&fx, 1, "ovf", NULL, 0), 0);

    stall_ctl ctl;
    uint16_t park[] = { 400 };
    stall_init(&ctl, park, 1);
    bstall_install(&ctl);

    uint8_t  buf[512];
    uint32_t rlen = 0;
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_twrite(buf, 400, 1, 0, "x", 1)), 0);
    stall_await_entered(&ctl, 1);       /* write parked, fid 1 pinned */

    /* The getattr must complete WHILE the write is parked. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tgetattr(buf, 401, 1)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
    STM_ASSERT_EQ(load_u16(buf + 5), 401);

    stall_release(&ctl);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RWRITE);
    STM_ASSERT_EQ(load_u16(buf + 5), 400);

    STM_ASSERT_EQ(send_all(fx.client_fd, buf, build_tclunk(buf, 402, 1)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RCLUNK);

    fix_down(&fx);
    stall_destroy(&ctl);
}

/* Tversion's quiesce barrier vs a PINNED op: the pool must drain the
 * pinned op before running h_version inline — h_version releases every
 * fid, and fid_release_locked abort-tripwires on busy > 0, so a
 * barrier hole is a crash, not a silent corruption. */
STM_TEST(p9_pool_pin_version_barrier_waits) {
    pool_fix fx;
    STM_ASSERT_TRUE(fix_up(&fx, "pool_pin_ver", /*workers=*/4));
    STM_ASSERT_EQ(fix_handshake(&fx, /*fid=*/0), 0);

    stall_ctl ctl;
    uint16_t park[] = { 500 };
    stall_init(&ctl, park, 1);
    bstall_install(&ctl);

    uint8_t  buf[512];
    uint32_t rlen = 0;
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tgetattr(buf, 500, 0)), 0);
    stall_await_entered(&ctl, 1);       /* getattr parked, fid 0 pinned */

    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tversion(buf, STM_9P_MSIZE_DEFAULT)), 0);
    /* The barrier must hold Rversion back while the pin is live. */
    STM_ASSERT_TRUE(fd_quiet_for(fx.client_fd, 150));

    stall_release(&ctl);
    /* Drained reply first (its worker writes before the reader runs
     * h_version), then Rversion. */
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RGETATTR);
    STM_ASSERT_EQ(load_u16(buf + 5), 500);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RVERSION);

    /* Tversion abandoned every fid. */
    STM_ASSERT_EQ(send_all(fx.client_fd, buf,
                            build_tgetattr(buf, 501, 0)), 0);
    STM_ASSERT_EQ(recv_frame(fx.client_fd, buf, sizeof buf, &rlen), 0);
    STM_ASSERT_EQ(buf[4], STM_9P_RLERROR);
    STM_ASSERT_EQ(load_u32(buf + 7), STM_9P_ECODE_EBADF);

    fix_down(&fx);
    stall_destroy(&ctl);
}

STM_TEST_MAIN("9p pool (CF-2a/2b)")
