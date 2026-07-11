/* SPDX-License-Identifier: ISC */
/*
 * RC-3 concurrent write path tests — s->lock retired from writes.
 *
 *   see v2/docs/rc-design.md "RC-3"  — the design this validates: the
 *     public stm_sync_write_extent runs reserve (locked) → encrypt +
 *     device write (UNLOCKED) → index commit (locked), so writers to
 *     distinct extents overlap in the expensive middle.
 *
 * Coverage:
 *   - rc3_disjoint_writer_hammer: N concurrent writers (one ino each,
 *     extents at BOTH LE-boundary offsets — the RC-2 F1 discipline)
 *     race lock-free readers. Every read must be ENTIRELY one
 *     version's pattern (per-op atomicity: the epilogue's single
 *     s->lock hold publishes whole extents); the final read-back must
 *     be exactly the last version (no lost writes, no nonce/AEAD
 *     confusion between overlapped encrypts).
 *   - rc3_write_key_liveness_retry: THE deterministic regression for
 *     the key-sweep-vs-in-flight-write race the unlocked window
 *     opens. A phase-2 test hook lands rotate + keyschema_sweep
 *     inside a single write: the resolved CURRENT key is PRUNED
 *     mid-flight (zero refs — the write isn't indexed yet). The
 *     epilogue's keyschema re-validation must catch it and retry the
 *     whole op against the fresh CURRENT; without it the write
 *     indexes a record whose durable wrapped key is GONE and the
 *     read-back fails ECORRUPT (silent data loss made loud).
 *   - rc3_writers_vs_rotate_sweep_hammer: the probabilistic companion
 *     — concurrent writers race a rotate+sweep churn thread; every
 *     write must land decryptable (retry-absorbed collisions), final
 *     content exact.
 *
 * The evict-dek populate-gate regressions live in test_corvus_mount.c
 * (evict requires a CORVUS-wrapped slot; the fake-corvus fixture is
 * there).
 */

#include "tharness.h"
#include "test_fs_common.h"
#include <sys/stat.h>

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ========================================================================= */
/* Raw-sync fixture (the test_rc2_concurrent shape).                          */
/* ========================================================================= */

static const uint64_t POOL_UUID[2]   = { 0x00c0ffee, 0x00decade };
static const uint64_t DEVICE_UUID[2] = { 0x11115555, 0x2222aaaa };

static char g_dev_path[256];

static void rc3_make_path(const char *tag)
{
    snprintf(g_dev_path, sizeof g_dev_path, "/tmp/stm_v2_rc3_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_dev_path);
}

static stm_bdev *rc3_open_device(void)
{
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_dev_path, &bo, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_pool *rc3_make_pool(stm_bdev *bd)
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(bd);
    STM_ASSERT(caps != NULL);
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = bd;
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    return p;
}

static stm_hybrid_keys g_rc3_wk;
static bool g_rc3_wk_init = false;

static const stm_hybrid_keys *rc3_wk(void)
{
    if (!g_rc3_wk_init) {
        STM_ASSERT_OK(stm_crypto_init());
        STM_ASSERT_OK(stm_hybrid_keygen(g_rc3_wk.pk, g_rc3_wk.sk));
        g_rc3_wk_init = true;
    }
    return &g_rc3_wk;
}

struct rc3_fixture {
    stm_bdev  *bd;
    stm_pool  *pool;
    stm_alloc *alloc;
    stm_sync  *sync;
};

static void rc3_fixture_open(struct rc3_fixture *f, const char *tag)
{
    rc3_make_path(tag);
    f->bd    = rc3_open_device();
    f->pool  = rc3_make_pool(f->bd);
    f->alloc = NULL;
    STM_ASSERT_OK(stm_alloc_create(f->bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &f->alloc));
    f->sync = NULL;
    STM_ASSERT_OK(stm_sync_create(f->pool, f->alloc, rc3_wk(), NULL,
                                    &f->sync));
}

static void rc3_fixture_close(struct rc3_fixture *f)
{
    stm_sync_close(f->sync);
    stm_alloc_close(f->alloc);
    stm_pool_close(f->pool);
    stm_bdev_close(f->bd);
    unlink(g_dev_path);
}

/* ========================================================================= */
/* Version-stamped, FILE-ABSOLUTE patterns (the rc2 discipline): the         */
/* version is recoverable from any byte given (ino, absolute offset), so a   */
/* reader derives it from byte 0 and verifies EVERY byte belongs to that     */
/* one version — the single-version (no-mix) check.                          */
/* ========================================================================= */

#define VER_INV_101 109u

static inline uint8_t rc3_pat(uint64_t ino, uint32_t ver, size_t j)
{
    return (uint8_t)((uint32_t)ino * 37u + ver * 101u + (uint32_t)j * 7u + 5u);
}

static void rc3_fill_at(uint8_t *b, uint64_t ino, uint32_t ver,
                        size_t base, size_t len)
{
    for (size_t j = 0; j < len; j++) b[j] = rc3_pat(ino, ver, base + j);
}

static inline uint8_t rc3_ver_of(uint64_t ino, size_t j0, uint8_t byte0)
{
    uint8_t base = (uint8_t)((uint32_t)ino * 37u + (uint32_t)j0 * 7u + 5u);
    return (uint8_t)((uint8_t)(byte0 - base) * VER_INV_101);
}

static size_t rc3_verify_ver(const uint8_t *b, uint64_t ino, uint32_t ver,
                             size_t j0, size_t n)
{
    size_t bad = 0;
    for (size_t j = 0; j < n; j++)
        if (b[j] != rc3_pat(ino, ver, j0 + j)) bad++;
    return bad;
}

/* ========================================================================= */
/* rc3_disjoint_writer_hammer                                                 */
/* ========================================================================= */

#define DWH_WRITERS   4
#define DWH_READERS   2
#define DWH_LEN       4096u
#define DWH_ROUNDS    28u             /* bounded: no commit mid-hammer —
                                       * 4 * 28 * 2 * 8 KiB ≈ 1.8 MiB of
                                       * monotone CoW growth fits the dev. */
#define DWH_READS_MIN 2000u
#define DWH_READS_CAP (4u * 1000u * 1000u)

/* Both LE-boundary offsets, per the RC-2 F1 lesson: LE(65536) lex-sorts
 * BEFORE LE(4096), so every probe exercises the per-ino key-order
 * disorder the concurrent lookup must scan around. */
static const uint64_t dwh_offs[2] = { 4096u, 65536u };

typedef struct {
    stm_sync       *s;
    uint64_t        ino;
    _Atomic size_t *write_err;
} dwh_writer_ctx;

static void *dwh_writer(void *arg)
{
    dwh_writer_ctx *c = arg;
    uint8_t *buf = malloc(DWH_LEN);
    if (!buf) { atomic_fetch_add(c->write_err, 1u); return NULL; }
    for (uint32_t v = 1; v <= DWH_ROUNDS; v++) {
        for (int oi = 0; oi < 2; oi++) {
            rc3_fill_at(buf, c->ino, v, (size_t)dwh_offs[oi], DWH_LEN);
            stm_status rc = stm_sync_write_extent(c->s, 1u, c->ino,
                                                     dwh_offs[oi], buf,
                                                     DWH_LEN);
            if (rc != STM_OK) atomic_fetch_add(c->write_err, 1u);
        }
    }
    free(buf);
    return NULL;
}

typedef struct {
    stm_sync       *s;
    atomic_bool    *stop;
    _Atomic size_t *reads_ok;
    _Atomic size_t *content_bad;
    _Atomic size_t *read_err;
} dwh_reader_ctx;

static void *dwh_reader(void *arg)
{
    dwh_reader_ctx *c = arg;
    uint8_t *buf = malloc(DWH_LEN);
    if (!buf) { atomic_fetch_add(c->read_err, 1u); return NULL; }
    uint32_t rr = 13u;
    for (size_t i = 0;
         !(atomic_load(c->stop) && i >= DWH_READS_MIN) && i < DWH_READS_CAP;
         i++) {
        uint64_t ino = (uint64_t)(rr % DWH_WRITERS) + 1u;
        uint64_t off = dwh_offs[(rr >> 8) & 1u];
        rr = rr * 1103515245u + 12345u;
        size_t got = 0;
        stm_status rc = stm_sync_read_extent(c->s, 1u, ino, off,
                                                buf, DWH_LEN, &got);
        if (rc != STM_OK) { atomic_fetch_add(c->read_err, 1u); continue; }
        if (got != DWH_LEN) { atomic_fetch_add(c->content_bad, 1u); continue; }
        /* A hole read (all zeros, before the ino's first write at this
         * offset lands) is legal early — but a zero buffer never
         * matches a version pattern, so distinguish: version 0 with a
         * perfect all-zero buffer at pattern-mismatch is the hole. */
        bool all_zero = true;
        for (size_t j = 0; j < DWH_LEN && all_zero; j++)
            if (buf[j] != 0u) all_zero = false;
        if (all_zero) { atomic_fetch_add(c->reads_ok, 1u); continue; }
        uint8_t ver = rc3_ver_of(ino, (size_t)off, buf[0]);
        if (ver == 0u || ver > DWH_ROUNDS
            || rc3_verify_ver(buf, ino, ver, (size_t)off, got) != 0)
            atomic_fetch_add(c->content_bad, 1u);
        else
            atomic_fetch_add(c->reads_ok, 1u);
    }
    free(buf);
    return NULL;
}

STM_TEST(rc3_disjoint_writer_hammer) {
    struct rc3_fixture f;
    rc3_fixture_open(&f, "dwh");

    atomic_bool    stop        = false;
    _Atomic size_t reads_ok    = 0;
    _Atomic size_t content_bad = 0;
    _Atomic size_t read_err    = 0;
    _Atomic size_t write_err   = 0;

    dwh_writer_ctx wctx[DWH_WRITERS];
    pthread_t      writers[DWH_WRITERS];
    dwh_reader_ctx rctx = { f.sync, &stop, &reads_ok, &content_bad,
                            &read_err };
    pthread_t      readers[DWH_READERS];

    for (int i = 0; i < DWH_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&readers[i], NULL, dwh_reader, &rctx), 0);
    for (int i = 0; i < DWH_WRITERS; i++) {
        wctx[i].s         = f.sync;
        wctx[i].ino       = (uint64_t)i + 1u;
        wctx[i].write_err = &write_err;
        STM_ASSERT_EQ(pthread_create(&writers[i], NULL, dwh_writer,
                                       &wctx[i]), 0);
    }

    for (int i = 0; i < DWH_WRITERS; i++)
        STM_ASSERT_EQ(pthread_join(writers[i], NULL), 0);
    atomic_store(&stop, true);
    for (int i = 0; i < DWH_READERS; i++)
        STM_ASSERT_EQ(pthread_join(readers[i], NULL), 0);

    stm_test_info("rc3 dwh: reads_ok=%zu content_bad=%zu read_err=%zu "
                  "write_err=%zu",
                  atomic_load(&reads_ok), atomic_load(&content_bad),
                  atomic_load(&read_err), atomic_load(&write_err));

    STM_ASSERT_EQ(atomic_load(&write_err), 0u);
    STM_ASSERT_EQ(atomic_load(&content_bad), 0u);
    STM_ASSERT_EQ(atomic_load(&read_err), 0u);
    STM_ASSERT(atomic_load(&reads_ok) >= DWH_READS_MIN);

    /* Final exact read-back: every ino at both offsets holds EXACTLY
     * the last version — no lost write, no stale index entry. */
    uint8_t *buf = malloc(DWH_LEN);
    STM_ASSERT(buf != NULL);
    for (uint64_t ino = 1; ino <= DWH_WRITERS; ino++) {
        for (int oi = 0; oi < 2; oi++) {
            size_t got = 0;
            STM_ASSERT_OK(stm_sync_read_extent(f.sync, 1u, ino,
                                                  dwh_offs[oi], buf,
                                                  DWH_LEN, &got));
            STM_ASSERT_EQ(got, DWH_LEN);
            STM_ASSERT_EQ(rc3_verify_ver(buf, ino, DWH_ROUNDS,
                                           (size_t)dwh_offs[oi], got), 0u);
        }
    }
    free(buf);
    rc3_fixture_close(&f);
}

/* ========================================================================= */
/* rc3_write_key_liveness_retry (deterministic; the phase-2 hook)             */
/* ========================================================================= */

typedef struct {
    stm_sync *s;
    int       calls;     /* every hook invocation (armed or not)       */
    int       fired;     /* the armed invocation ran rotate + sweep    */
    size_t    pruned;    /* keys the in-window sweep pruned            */
    uint64_t  new_kid;
    uint64_t  old_kid;
} klr_hook_ctx;

static void klr_hook(void *arg)
{
    klr_hook_ctx *c = arg;
    c->calls++;
    if (c->fired) return;              /* disarm after the first strike */
    c->fired = 1;
    /* Rotate: the write's resolved CURRENT becomes RETIRED. Sweep: it
     * has ZERO extent refs (the in-flight write is not indexed yet),
     * so it is PRUNED — keyschema slot deleted, DEK-map slot removed.
     * Exactly the window the RC-3 split opens. */
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(c->s, 1u, rc3_wk(), NULL,
                                                 &c->new_kid, &c->old_kid));
    STM_ASSERT_OK(stm_sync_keyschema_sweep(c->s, 1u, &c->pruned));
}

STM_TEST(rc3_write_key_liveness_retry) {
    struct rc3_fixture f;
    rc3_fixture_open(&f, "klr");

    /* Fresh pool: ds=1's create-seeded CURRENT key has no extent refs,
     * so the hook's sweep deterministically prunes it mid-write. */
    klr_hook_ctx hc = { .s = f.sync };
    stm_sync_set_write_phase2_hook_for_test(f.sync, klr_hook, &hc);

    uint8_t *buf = malloc(4096u);
    STM_ASSERT(buf != NULL);
    rc3_fill_at(buf, 1u, 1u, 0u, 4096u);
    STM_ASSERT_OK(stm_sync_write_extent(f.sync, 1u, 1u, 0u, buf, 4096u));

    stm_sync_set_write_phase2_hook_for_test(f.sync, NULL, NULL);

    /* The strike really happened mid-window... */
    STM_ASSERT_EQ(hc.fired, 1);
    STM_ASSERT_EQ(hc.pruned, 1u);
    /* ...and the write retried (attempt 2 called the disarmed hook). */
    STM_ASSERT_EQ(hc.calls, 2);

    /* The record decrypts — it was re-encrypted under the fresh
     * CURRENT, not indexed against the pruned key. Pre-fix this read
     * fails ECORRUPT: the record carries the pruned key_id whose DEK
     * and durable wrapped blob are both gone. */
    uint8_t rbuf[4096u];
    size_t  got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(f.sync, 1u, 1u, 0u,
                                          rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    STM_ASSERT_EQ(rc3_verify_ver(rbuf, 1u, 1u, 0u, got), 0u);

    free(buf);
    rc3_fixture_close(&f);
}

/* ========================================================================= */
/* rc3_write_exhaustion_locked_fallback (deterministic; RC-3 audit F2)        */
/* ========================================================================= */

/* Non-disarming strike: rotate + sweep on EVERY phase-2 invocation, so
 * every lock-free attempt's resolved key is pruned mid-window and the
 * bounded retry EXHAUSTS — the locked fallback must carry the op (it
 * runs no phase-2 hook and the sweep cannot interleave its single
 * s->lock span). */
static void klr_hook_always(void *arg)
{
    klr_hook_ctx *c = arg;
    c->calls++;
    uint64_t nk = 0, ok_ = 0;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(c->s, 1u, rc3_wk(), NULL,
                                                 &nk, &ok_));
    size_t pruned_now = 0;
    STM_ASSERT_OK(stm_sync_keyschema_sweep(c->s, 1u, &pruned_now));
    c->pruned += pruned_now;
    c->fired++;
}

STM_TEST(rc3_write_exhaustion_locked_fallback) {
    struct rc3_fixture f;
    rc3_fixture_open(&f, "exf");

    klr_hook_ctx hc = { .s = f.sync };
    stm_sync_set_write_phase2_hook_for_test(f.sync, klr_hook_always, &hc);

    uint8_t *buf = malloc(4096u);
    STM_ASSERT(buf != NULL);
    rc3_fill_at(buf, 1u, 7u, 0u, 4096u);
    /* Every attempt collides -> exhaustion -> the fallback. The write
     * must still succeed outright (no STM_EBUSY may escape). */
    STM_ASSERT_OK(stm_sync_write_extent(f.sync, 1u, 1u, 0u, buf, 4096u));
    stm_sync_set_write_phase2_hook_for_test(f.sync, NULL, NULL);

    /* All four lock-free attempts ran (the fallback calls no hook)... */
    STM_ASSERT_EQ(hc.calls, 4);
    /* ...and every strike really pruned the attempt's resolved key
     * (fresh pool: each just-retired CURRENT has zero refs). */
    STM_ASSERT_EQ(hc.pruned, 4u);

    /* The record decrypts under the surviving key — the fallback
     * indexed it inside one s->lock span (NoDeadKeyIndexed by the
     * pre-RC-3 argument). */
    uint8_t rbuf[4096u];
    size_t  got = 0;
    STM_ASSERT_OK(stm_sync_read_extent(f.sync, 1u, 1u, 0u,
                                          rbuf, sizeof rbuf, &got));
    STM_ASSERT_EQ(got, sizeof rbuf);
    STM_ASSERT_EQ(rc3_verify_ver(rbuf, 1u, 7u, 0u, got), 0u);

    free(buf);
    rc3_fixture_close(&f);
}

/* ========================================================================= */
/* rc3_writers_vs_rotate_sweep_hammer                                         */
/* ========================================================================= */

#define WRS_WRITERS  3
#define WRS_ROUNDS   16u
#define WRS_LEN      4096u
#define WRS_CYCLES   40u

typedef struct {
    stm_sync       *s;
    uint64_t        ino;
    _Atomic size_t *write_err;
} wrs_writer_ctx;

static void *wrs_writer(void *arg)
{
    wrs_writer_ctx *c = arg;
    uint8_t *buf = malloc(WRS_LEN);
    if (!buf) { atomic_fetch_add(c->write_err, 1u); return NULL; }
    for (uint32_t v = 1; v <= WRS_ROUNDS; v++) {
        rc3_fill_at(buf, c->ino, v, 0u, WRS_LEN);
        /* EVERY write must succeed outright: a key-prune collision is
         * absorbed by the bounded retry, and retry exhaustion (this
         * hammer under host contention reached it — 4 collisions in
         * one op) degrades to the fully-locked body, which the sweep
         * cannot interleave. No STM_EBUSY may escape. */
        stm_status rc = stm_sync_write_extent(c->s, 1u, c->ino, 0u,
                                                 buf, WRS_LEN);
        if (rc != STM_OK) atomic_fetch_add(c->write_err, 1u);
        sched_yield();
    }
    free(buf);
    return NULL;
}

STM_TEST(rc3_writers_vs_rotate_sweep_hammer) {
    struct rc3_fixture f;
    rc3_fixture_open(&f, "wrs");

    _Atomic size_t write_err = 0;

    wrs_writer_ctx wctx[WRS_WRITERS];
    pthread_t      writers[WRS_WRITERS];
    for (int i = 0; i < WRS_WRITERS; i++) {
        wctx[i].s         = f.sync;
        wctx[i].ino       = (uint64_t)i + 1u;
        wctx[i].write_err = &write_err;
        STM_ASSERT_EQ(pthread_create(&writers[i], NULL, wrs_writer,
                                       &wctx[i]), 0);
    }

    /* Rotate + sweep churn racing the writers. Keys with live refs are
     * never pruned (the sweep's refcount gate); a freshly-rotated key
     * a writer resolved but has not indexed yet CAN be — that is the
     * race the epilogue re-validation + retry absorbs. */
    size_t cycles = 0, total_pruned = 0;
    for (size_t cyc = 0; cyc < WRS_CYCLES; cyc++) {
        uint64_t nk = 0, ok = 0;
        stm_status rc = stm_sync_rotate_dataset_key(f.sync, 1u, rc3_wk(),
                                                      NULL, &nk, &ok);
        STM_ASSERT_OK(rc);
        size_t pruned = 0;
        STM_ASSERT_OK(stm_sync_keyschema_sweep(f.sync, 1u, &pruned));
        total_pruned += pruned;
        cycles++;
        sched_yield();
    }

    for (int i = 0; i < WRS_WRITERS; i++)
        STM_ASSERT_EQ(pthread_join(writers[i], NULL), 0);

    stm_test_info("rc3 wrs: cycles=%zu pruned=%zu write_err=%zu",
                  cycles, total_pruned, atomic_load(&write_err));

    STM_ASSERT_EQ(atomic_load(&write_err), 0u);

    /* Every ino's final content is the last version, decryptable under
     * whatever key survived the churn — no dead-key record ever
     * indexed. */
    uint8_t rbuf[WRS_LEN];
    for (uint64_t ino = 1; ino <= WRS_WRITERS; ino++) {
        size_t got = 0;
        STM_ASSERT_OK(stm_sync_read_extent(f.sync, 1u, ino, 0u,
                                              rbuf, sizeof rbuf, &got));
        STM_ASSERT_EQ(got, (size_t)WRS_LEN);
        STM_ASSERT_EQ(rc3_verify_ver(rbuf, ino, WRS_ROUNDS, 0u, got), 0u);
    }

    rc3_fixture_close(&f);
}

STM_TEST_MAIN("rc3_concurrent")
