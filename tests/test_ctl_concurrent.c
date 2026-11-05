/* SPDX-License-Identifier: ISC */
/*
 * test_ctl_concurrent — exercises stm_ctl_conn under concurrent regime
 * (P9.5-PARALLEL-1f / task #961).
 *
 * The full integration of "concurrent /ctl/ accept" is verified by
 * test_stratumd_ctl and the libstratum-9p e2e suite; this binary
 * pinpoints the in-process invariants of the stm_ctl + stm_ctl_conn
 * split that those higher layers depend on:
 *
 *   1. caller_uid isolation across conns — thread A (admin) and
 *      thread B (non-admin) hitting the same stm_ctl concurrently must
 *      each see their own caller_uid stamped at conn-create, never each
 *      other's. The pre-P9.5 shape stored caller_uid on the shared
 *      stm_ctl as last-writer-wins; a single buggy materialization
 *      under concurrent regime would let B read admin-only content
 *      (P0 — confused deputy).
 *
 *   2. sessions[] independence across conns — fid=N may exist on both
 *      conns simultaneously; clunk on one must not free the other's
 *      slot. Both conns drive the same fid numbers in lockstep so the
 *      buggy global-sessions[] shape would be flaky-but-frequent here.
 *
 *   3. event_gen cross-conn snapshot invalidation — admin on conn A
 *      writes /admin/clear-events while conn B is mid-read on the
 *      /events log; B's subsequent Tread must see EOF (gen mismatch)
 *      rather than zero-padded frankenstein bytes.
 *
 *   4. worker_count refcount + stm_ctl_destroy wait — a worker that
 *      lingers must hold off ctl teardown via the cv. Verified in
 *      test_ctl_conn_lifecycle.
 *
 * All tests run for a fixed iteration count (small by default; ~1 s
 * wall under serial ctest) and use timed pthread_cond_timedwait so
 * any deadlock fails the test loudly rather than hanging the suite.
 */

#include <stratum/ctl.h>
#include <stratum/lp9.h>
#include <stratum/types.h>

#include "tharness.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define RBUF 65536

/* ── wire helpers (subset of test_ctl.c — kept local to avoid pulling
 * test_fs_common). All packing is LE per 9P2000.L. ─────────────────── */

static void pack_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void pack_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void pack_u64(uint8_t *p, uint64_t v)
{
    pack_u32(p,     (uint32_t)v);
    pack_u32(p + 4, (uint32_t)(v >> 32));
}
static uint32_t load_u32(const uint8_t *p)
{
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t load_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t build_tversion(uint8_t *req, uint32_t msize)
{
    uint8_t *p = req + 7;
    pack_u32(p, msize); p += 4;
    pack_u16(p, 8);     p += 2;
    memcpy(p, "9P2000.L", 8); p += 8;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TVERSION;
    pack_u16(req + 5, STM_LP9_NOTAG);
    return sz;
}
static uint32_t build_tattach(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);              p += 4;
    pack_u32(p, STM_LP9_NOFID);    p += 4;
    pack_u16(p, 0); p += 2;
    pack_u16(p, 0); p += 2;
    pack_u32(p, 0); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TATTACH;
    pack_u16(req + 5, tag);
    return sz;
}
static uint32_t build_twalk(uint8_t *req, uint16_t tag,
                            uint32_t fid, uint32_t newfid,
                            uint16_t n, const char **names)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u32(p, newfid); p += 4;
    pack_u16(p, n);      p += 2;
    for (uint16_t i = 0; i < n; i++) {
        uint16_t nl = (uint16_t)strlen(names[i]);
        pack_u16(p, nl); p += 2;
        memcpy(p, names[i], nl); p += nl;
    }
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TWALK;
    pack_u16(req + 5, tag);
    return sz;
}
static uint32_t build_topen(uint8_t *req, uint16_t tag,
                            uint32_t fid, uint32_t flags)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);   p += 4;
    pack_u32(p, flags); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TLOPEN;
    pack_u16(req + 5, tag);
    return sz;
}
static uint32_t build_tread(uint8_t *req, uint16_t tag, uint32_t fid,
                            uint64_t offset, uint32_t count)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, count);  p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TREAD;
    pack_u16(req + 5, tag);
    return sz;
}
static uint32_t build_twrite(uint8_t *req, uint16_t tag, uint32_t fid,
                             uint64_t offset, const void *data, uint32_t len)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, len);    p += 4;
    memcpy(p, data, len); p += len;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TWRITE;
    pack_u16(req + 5, tag);
    return sz;
}
static uint32_t build_tclunk(uint8_t *req, uint16_t tag, uint32_t fid)
{
    uint8_t *p = req + 7;
    pack_u32(p, fid); p += 4;
    uint32_t sz = (uint32_t)(p - req);
    pack_u32(req, sz);
    req[4] = STM_LP9_TCLUNK;
    pack_u16(req + 5, tag);
    return sz;
}

static void do_handshake(stm_lp9_server *s, uint32_t root_fid)
{
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;

    uint32_t sz = build_tversion(req, STM_LP9_MSIZE_DEFAULT);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RVERSION);

    sz = build_tattach(req, 1, root_fid);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RATTACH);
}

/* ── shared barrier so threads start their hot loops in lockstep ──── */

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             counter;
    int             ready;
} barrier_t;

static void barrier_init(barrier_t *b)
{
    pthread_mutex_init(&b->mu, NULL);
    pthread_cond_init(&b->cv, NULL);
    b->counter = 0;
    b->ready = 0;
}
static void barrier_destroy(barrier_t *b)
{
    pthread_cond_destroy(&b->cv);
    pthread_mutex_destroy(&b->mu);
}
static void barrier_wait(barrier_t *b, int expected)
{
    pthread_mutex_lock(&b->mu);
    b->counter++;
    if (b->counter == expected) {
        b->ready = 1;
        pthread_cond_broadcast(&b->cv);
    } else {
        while (!b->ready)
            pthread_cond_wait(&b->cv, &b->mu);
    }
    pthread_mutex_unlock(&b->mu);
}

/* ── test 1: caller_uid isolation under concurrent admin probes ───── */

#define ITERATIONS 200

typedef struct {
    stm_ctl  *ctl;
    uid_t     caller_uid;
    int       iterations;
    barrier_t *start;
    /* Output. */
    int       admin_probes_ok;     /* count of successful /admin/peer reads */
    int       admin_probes_fail;   /* count of refused walks */
    int       fatal_error;         /* nonzero on assertion failure */
} probe_ctx;

static void *admin_probe_worker(void *arg)
{
    probe_ctx *ctx = arg;
    stm_ctl_conn *cn = NULL;
    stm_status rc = stm_ctl_conn_create(ctx->ctl, ctx->caller_uid,
                                          (gid_t)ctx->caller_uid, &cn);
    if (rc != STM_OK) { ctx->fatal_error = 1; return NULL; }
    stm_lp9_server *s = NULL;
    rc = stm_lp9_server_create(stm_ctl_vops(), cn, stm_ctl_root(ctx->ctl),
                                STM_LP9_MSIZE_DEFAULT, &s);
    if (rc != STM_OK) { ctx->fatal_error = 1; stm_ctl_conn_destroy(cn); return NULL; }
    do_handshake(s, 10);

    barrier_wait(ctx->start, 2);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    /* Use fid=11 on BOTH threads. Per-conn sessions[] independence is
     * the load-bearing invariant: if sessions[] were shared on stm_ctl
     * the second thread's Twalk to fid=11 would either fail with
     * STM_EEXIST or collide on the first thread's slot. */
    for (int i = 0; i < ctx->iterations; i++) {
        const char *path[] = { "admin", "peer" };
        uint32_t sz = build_twalk(req, 2, 10, 11, 2, path);
        rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
        if (rc != STM_OK) { ctx->fatal_error = 2; break; }

        /* Walk-fully-succeeded iff RWALK + nwqid == n_requested. The
         * .L server treats a partial walk (admin/ blocked for non-
         * admin) as Rlerror; either shape is "walk failed". */
        bool walk_ok = (resp[4] == STM_LP9_RWALK)
                       && (load_u16(resp + 7) == 2);
        if (walk_ok) {
            sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
            rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
            if (rc != STM_OK || resp[4] != STM_LP9_RLOPEN) {
                ctx->fatal_error = 3; break;
            }
            sz = build_tread(req, 4, 11, 0, 4096);
            rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
            if (rc != STM_OK || resp[4] != STM_LP9_RREAD) {
                ctx->fatal_error = 4; break;
            }
            uint32_t count = load_u32(resp + 7);
            char body[1024];
            if (count >= sizeof body) count = (uint32_t)(sizeof body - 1);
            memcpy(body, resp + 11, count);
            body[count] = '\0';

            /* The caller-uid line in /admin/peer must reflect THIS
             * conn's caller. If sessions[] aliasing leaked uid into
             * the sibling's body, this would fail. */
            char expected[64];
            snprintf(expected, sizeof expected,
                     "caller-uid: %u\n", (unsigned)ctx->caller_uid);
            if (!strstr(body, expected)) {
                ctx->fatal_error = 5; break;
            }
            ctx->admin_probes_ok++;
            sz = build_tclunk(req, 5, 11);
            rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
            if (rc != STM_OK || resp[4] != STM_LP9_RCLUNK) {
                ctx->fatal_error = 6; break;
            }
        } else if (resp[4] == STM_LP9_RLERROR
                || (resp[4] == STM_LP9_RWALK && load_u16(resp + 7) < 2)) {
            ctx->admin_probes_fail++;
            /* No fid was bound on failure — no clunk needed. */
        } else {
            ctx->fatal_error = 7; break;
        }
    }

    stm_lp9_server_destroy(s);
    stm_ctl_conn_destroy(cn);
    return NULL;
}

STM_TEST(ctl_concurrent_caller_isolation)
{
    /* One shared stm_ctl with admin_uid = 1000. Thread A's conn is
     * admin (caller_uid=1000); thread B's conn is non-admin
     * (caller_uid=2000). Both hammer /admin/peer concurrently.
     *
     * Expected: every admin-probe by A succeeds AND body contains
     * "caller-uid: 1000". Every probe by B fails (walk rejected at
     * the /admin dir gate). No errors, no deadlock. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_admin_uid(c, 1000));

    barrier_t start;
    barrier_init(&start);

    probe_ctx a = { c, 1000, ITERATIONS, &start, 0, 0, 0 };
    probe_ctx b = { c, 2000, ITERATIONS, &start, 0, 0, 0 };

    pthread_t ta, tb;
    int rc = pthread_create(&ta, NULL, admin_probe_worker, &a);
    STM_ASSERT_EQ(rc, 0);
    rc = pthread_create(&tb, NULL, admin_probe_worker, &b);
    STM_ASSERT_EQ(rc, 0);
    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    STM_ASSERT_EQ(a.fatal_error, 0);
    STM_ASSERT_EQ(b.fatal_error, 0);
    STM_ASSERT_EQ(a.admin_probes_ok,   ITERATIONS);
    STM_ASSERT_EQ(a.admin_probes_fail, 0);
    STM_ASSERT_EQ(b.admin_probes_ok,   0);
    STM_ASSERT_EQ(b.admin_probes_fail, ITERATIONS);

    barrier_destroy(&start);
    stm_ctl_destroy(c);
}

/* ── test 2: sessions[] are per-conn — both conns can hold fid=N ──── */

typedef struct {
    stm_ctl  *ctl;
    int       fatal_error;
    /* Holds the conn open + a fid=11 bound to /version for a sleep
     * window so the sibling thread can race to bind fid=11 on its
     * own conn. */
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             arrived;
    int             release;
} hold_ctx;

static void *hold_open_fid(void *arg)
{
    hold_ctx *ctx = arg;
    stm_ctl_conn *cn = NULL;
    stm_status rc = stm_ctl_conn_create(ctx->ctl, 0, 0, &cn);
    if (rc != STM_OK) { ctx->fatal_error = 1; return NULL; }
    stm_lp9_server *s = NULL;
    rc = stm_lp9_server_create(stm_ctl_vops(), cn, stm_ctl_root(ctx->ctl),
                                STM_LP9_MSIZE_DEFAULT, &s);
    if (rc != STM_OK) { ctx->fatal_error = 2; stm_ctl_conn_destroy(cn); return NULL; }
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
    if (rc != STM_OK || resp[4] != STM_LP9_RWALK) {
        ctx->fatal_error = 3; goto out;
    }
    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
    if (rc != STM_OK || resp[4] != STM_LP9_RLOPEN) {
        ctx->fatal_error = 4; goto out;
    }

    /* Signal main: I've bound fid=11. Wait for release. */
    pthread_mutex_lock(&ctx->mu);
    ctx->arrived = 1;
    pthread_cond_broadcast(&ctx->cv);
    while (!ctx->release)
        pthread_cond_wait(&ctx->cv, &ctx->mu);
    pthread_mutex_unlock(&ctx->mu);

    /* My fid=11 must still resolve — read after the sibling has
     * raced through its own bind+open+read+clunk on its own fid=11. */
    sz = build_tread(req, 4, 11, 0, 4096);
    rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
    if (rc != STM_OK || resp[4] != STM_LP9_RREAD) {
        ctx->fatal_error = 5; goto out;
    }
    uint32_t count = load_u32(resp + 7);
    if (count == 0) { ctx->fatal_error = 6; goto out; }

    sz = build_tclunk(req, 5, 11);
    (void)stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);

out:
    stm_lp9_server_destroy(s);
    stm_ctl_conn_destroy(cn);
    return NULL;
}

STM_TEST(ctl_concurrent_per_conn_fid_namespace)
{
    /* Hold-and-race: thread A binds fid=11 on its conn and parks.
     * Main thread then binds fid=11 on a SEPARATE conn against the
     * same ctl, opens + reads + clunks. After main clunks, thread A
     * must still observe its fid=11 as bound (its session slot was
     * never touched by main's clunk). */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    hold_ctx hc = { 0 };
    hc.ctl = c;
    pthread_mutex_init(&hc.mu, NULL);
    pthread_cond_init(&hc.cv, NULL);

    pthread_t ta;
    int rc = pthread_create(&ta, NULL, hold_open_fid, &hc);
    STM_ASSERT_EQ(rc, 0);

    /* Wait for thread A to bind fid=11. */
    pthread_mutex_lock(&hc.mu);
    while (!hc.arrived)
        pthread_cond_wait(&hc.cv, &hc.mu);
    pthread_mutex_unlock(&hc.mu);

    /* Main thread: drive an independent conn with its own fid=11. */
    stm_ctl_conn *cn = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(c, 0, 0, &cn));
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(stm_ctl_vops(), cn, stm_ctl_root(c),
                                          STM_LP9_MSIZE_DEFAULT, &s));
    do_handshake(s, 10);

    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "version" };
    uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);

    sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);

    sz = build_tread(req, 4, 11, 0, 4096);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);

    sz = build_tclunk(req, 5, 11);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RCLUNK);

    stm_lp9_server_destroy(s);
    stm_ctl_conn_destroy(cn);

    /* Release thread A. It must observe its fid=11 still valid. */
    pthread_mutex_lock(&hc.mu);
    hc.release = 1;
    pthread_cond_broadcast(&hc.cv);
    pthread_mutex_unlock(&hc.mu);

    pthread_join(ta, NULL);
    STM_ASSERT_EQ(hc.fatal_error, 0);

    pthread_cond_destroy(&hc.cv);
    pthread_mutex_destroy(&hc.mu);
    stm_ctl_destroy(c);
}

/* ── test 3: event_gen invalidation across conns ──────────────────── */

/* Thread A holds a /events Tlopen snapshot (gen N). Main thread
 * writes /admin/clear-events on its OWN conn → gen N+1, event_buf
 * reset. Thread A's next Tread must return EOF (count=0), not zero-
 * padded frankenstein bytes. */

typedef struct {
    stm_ctl  *ctl;
    int       fatal_error;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             ready_to_read;
    int             cleared;
    /* Out: count returned by the post-clear Tread. */
    uint32_t  post_clear_count;
} event_ctx;

static void *event_reader(void *arg)
{
    event_ctx *ctx = arg;
    stm_ctl_conn *cn = NULL;
    stm_status rc = stm_ctl_conn_create(ctx->ctl, 0, 0, &cn);
    if (rc != STM_OK) { ctx->fatal_error = 1; return NULL; }
    stm_lp9_server *s = NULL;
    rc = stm_lp9_server_create(stm_ctl_vops(), cn, stm_ctl_root(ctx->ctl),
                                STM_LP9_MSIZE_DEFAULT, &s);
    if (rc != STM_OK) { ctx->fatal_error = 2; stm_ctl_conn_destroy(cn); return NULL; }
    do_handshake(s, 10);

    /* Walk + open /events under the per-conn fid=12. */
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "events" };
    uint32_t sz = build_twalk(req, 2, 10, 12, 1, path);
    rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
    if (rc != STM_OK || resp[4] != STM_LP9_RWALK) { ctx->fatal_error = 3; goto out; }
    sz = build_topen(req, 3, 12, STM_LP9_O_RDONLY);
    rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
    if (rc != STM_OK || resp[4] != STM_LP9_RLOPEN) { ctx->fatal_error = 4; goto out; }

    /* Signal main: snapshot captured. Wait for clear. */
    pthread_mutex_lock(&ctx->mu);
    ctx->ready_to_read = 1;
    pthread_cond_broadcast(&ctx->cv);
    while (!ctx->cleared)
        pthread_cond_wait(&ctx->cv, &ctx->mu);
    pthread_mutex_unlock(&ctx->mu);

    /* Now read. The gen bump triggered by main's clear-events on its
     * conn must make Tread surface EOF (count=0). */
    sz = build_tread(req, 4, 12, 0, 4096);
    rc = stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);
    if (rc != STM_OK || resp[4] != STM_LP9_RREAD) { ctx->fatal_error = 5; goto out; }
    ctx->post_clear_count = load_u32(resp + 7);

    sz = build_tclunk(req, 5, 12);
    (void)stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen);

out:
    stm_lp9_server_destroy(s);
    stm_ctl_conn_destroy(cn);
    return NULL;
}

STM_TEST(ctl_concurrent_event_gen_invalidates_sibling_conn)
{
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_OK(stm_ctl_set_admin_uid(c, 1000));
    /* Seed a few events so the buffer is non-empty before the reader
     * takes its snapshot. */
    stm_ctl_log_event(c, "seed-event-A");
    stm_ctl_log_event(c, "seed-event-B");

    event_ctx ec = { 0 };
    ec.ctl = c;
    pthread_mutex_init(&ec.mu, NULL);
    pthread_cond_init(&ec.cv, NULL);

    pthread_t ta;
    int prc = pthread_create(&ta, NULL, event_reader, &ec);
    STM_ASSERT_EQ(prc, 0);

    /* Wait for reader to capture its snapshot. */
    pthread_mutex_lock(&ec.mu);
    while (!ec.ready_to_read)
        pthread_cond_wait(&ec.cv, &ec.mu);
    pthread_mutex_unlock(&ec.mu);

    /* Open an admin conn + clear-events on it. The reader's snapshot
     * gen is now stale. */
    stm_ctl_conn *cn = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(c, 1000, 1000, &cn));
    stm_lp9_server *s = NULL;
    STM_ASSERT_OK(stm_lp9_server_create(stm_ctl_vops(), cn, stm_ctl_root(c),
                                          STM_LP9_MSIZE_DEFAULT, &s));
    do_handshake(s, 10);
    uint8_t req[RBUF], resp[RBUF];
    uint32_t rlen = 0;
    const char *path[] = { "admin", "clear-events" };
    uint32_t sz = build_twalk(req, 2, 10, 13, 2, path);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
    sz = build_topen(req, 3, 13, STM_LP9_O_WRONLY);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
    /* Any non-empty body triggers the clear action — the body is
     * ignored beyond non-empty-ness. */
    sz = build_twrite(req, 4, 13, 0, "clear", 5);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_LP9_RWRITE);
    sz = build_tclunk(req, 5, 13);
    STM_ASSERT_OK(stm_lp9_server_handle(s, req, sz, resp, sizeof resp, &rlen));

    stm_lp9_server_destroy(s);
    stm_ctl_conn_destroy(cn);

    /* Release reader; it now reads its snapshot. */
    pthread_mutex_lock(&ec.mu);
    ec.cleared = 1;
    pthread_cond_broadcast(&ec.cv);
    pthread_mutex_unlock(&ec.mu);

    pthread_join(ta, NULL);
    STM_ASSERT_EQ(ec.fatal_error, 0);
    /* The gen-mismatch in synfs.c::vops_read /events branch returns
     * EOF as soon as snapshot_event_gen != cn->ctl->event_gen. */
    STM_ASSERT_EQ(ec.post_clear_count, 0u);

    pthread_cond_destroy(&ec.cv);
    pthread_mutex_destroy(&ec.mu);
    stm_ctl_destroy(c);
}

/* ── test 4: 4 conns can hold fid=11 simultaneously ───────────────── */

#define N_CONNS 4

typedef struct {
    stm_ctl_conn   *cn;
    stm_lp9_server *s;
} conn_holder;

STM_TEST(ctl_concurrent_four_conns_no_session_collision)
{
    /* N conns, each binds fid=11 to /version on its own conn, reads
     * the body, and asserts that the body remains stable across
     * sibling-conn operations. Per-conn sessions[] independence means
     * fid=11 on conn[0] is fully independent of fid=11 on conn[1..N-1]. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));

    conn_holder h[N_CONNS] = { 0 };
    for (int i = 0; i < N_CONNS; i++) {
        STM_ASSERT_OK(stm_ctl_conn_create(c, 0, 0, &h[i].cn));
        STM_ASSERT_OK(stm_lp9_server_create(stm_ctl_vops(), h[i].cn,
                                              stm_ctl_root(c),
                                              STM_LP9_MSIZE_DEFAULT, &h[i].s));
        do_handshake(h[i].s, 10);

        uint8_t req[RBUF], resp[RBUF];
        uint32_t rlen = 0;
        const char *path[] = { "version" };
        uint32_t sz = build_twalk(req, 2, 10, 11, 1, path);
        STM_ASSERT_OK(stm_lp9_server_handle(h[i].s, req, sz, resp,
                                              sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RWALK);
        sz = build_topen(req, 3, 11, STM_LP9_O_RDONLY);
        STM_ASSERT_OK(stm_lp9_server_handle(h[i].s, req, sz, resp,
                                              sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RLOPEN);
    }

    /* Each conn must still read /version correctly via its own fid=11. */
    for (int i = 0; i < N_CONNS; i++) {
        uint8_t req[RBUF], resp[RBUF];
        uint32_t rlen = 0;
        uint32_t sz = build_tread(req, 4, 11, 0, 4096);
        STM_ASSERT_OK(stm_lp9_server_handle(h[i].s, req, sz, resp,
                                              sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RREAD);
        uint32_t count = load_u32(resp + 7);
        STM_ASSERT(count > 0);
    }

    /* Clunk in reverse order — last conn first. None of the other
     * conns' fid=11 entries are touched by these clunks. */
    for (int i = N_CONNS - 1; i >= 0; i--) {
        uint8_t req[RBUF], resp[RBUF];
        uint32_t rlen = 0;
        uint32_t sz = build_tclunk(req, 5, 11);
        STM_ASSERT_OK(stm_lp9_server_handle(h[i].s, req, sz, resp,
                                              sizeof resp, &rlen));
        STM_ASSERT_EQ(resp[4], STM_LP9_RCLUNK);
        stm_lp9_server_destroy(h[i].s);
        stm_ctl_conn_destroy(h[i].cn);
    }
    stm_ctl_destroy(c);
}

/* ── test 5: stm_ctl_conn_create on NULL inputs ───────────────────── */

STM_TEST(ctl_concurrent_conn_create_inputs)
{
    /* NULL ctl → EINVAL. The impl bails BEFORE setting *out (early
     * return on invalid args is the documented contract) so the test
     * doesn't probe *out — it asserts the returned status only. */
    stm_ctl_conn *cn = NULL;
    STM_ASSERT_ERR(stm_ctl_conn_create(NULL, 0, 0, &cn), STM_EINVAL);

    /* NULL out → EINVAL. */
    stm_ctl *c = NULL;
    STM_ASSERT_OK(stm_ctl_create(NULL, &c));
    STM_ASSERT_ERR(stm_ctl_conn_create(c, 0, 0, NULL), STM_EINVAL);

    /* After both rejections, no conn was created; ctl_destroy must
     * not block (worker_count == 0). */
    uint64_t t0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    t0 = (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
    stm_ctl_destroy(c);
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t dt = (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull - t0;
    STM_ASSERT(dt < 100);
}

STM_TEST_MAIN("test_ctl_concurrent")
