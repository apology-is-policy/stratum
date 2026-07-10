/* SPDX-License-Identifier: ISC */
/*
 * RC-1 decrypted-extent cache (dcache) tests — the EBR-pinned rework.
 *
 *   see v2/docs/rc-design.md §4 (RC-1)  — the design this validates.
 *   see v2/specs/dcache_ebr.tla         — the model; these tests are its
 *                                          runtime witnesses.
 *   see <stratum/sync_testing.h>        — the pass-through hooks driven
 *                                          here (the dcache functions are
 *                                          static in sync.c).
 *
 * Coverage:
 *   - dcache_semantics: insert → pinned lookup returns the exact bytes
 *     (full + slice); len is part of the match; dedup keeps one copy
 *     (cached_bytes stable); drain empties (the evict-dek fail-closed
 *     shape) and re-insert works after it.
 *   - dcache_slot_lru_evict: filling past the entry cap evicts strictly
 *     least-recently-used (the oldest keys miss, the newest hit).
 *     Encodes the cap being < 2100 (STM_DCACHE_ENTRIES is 2048 today;
 *     bump the constant here if it is ever resized upward).
 *   - dcache_concurrent_hammer: N pinned reader threads slice-verify
 *     pattern-filled entries while a writer insert/evict/drain-churns
 *     the cache past its byte budget. Every hit is verified
 *     byte-for-byte against the key-derived pattern — a torn entry, a
 *     wrong-key copy, or a use-after-free-corrupted buffer fails the
 *     content check. Workers report through atomics (the harness
 *     failure flag is thread-local); the main thread asserts.
 *
 * The readers hold the production contract: stm_ebr_enter/_exit around
 * every lookup (the copy-under-pin discipline dcache_ebr.tla proves
 * safe; buggy cfg evict_frees_pinned is the counterexample this hammer
 * would surface as content-check failures or a crash).
 */

#include "tharness.h"

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/ebr.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)

/* ========================================================================= */
/* Fixture (the test_scrub single-device shape).                              */
/* ========================================================================= */

static const uint64_t POOL_UUID[2]   = { 0xfeedcafe, 0x0badc0de };
static const uint64_t DEVICE_UUID[2] = { 0xaa55aa55, 0xbeefbeef };

static char g_path[256];

static void make_path(const char *tag)
{
    snprintf(g_path, sizeof g_path, "/tmp/stm_v2_dcache_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_path);
}

static stm_bdev *open_device(void)
{
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_path, &bo, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_pool *make_single_pool(stm_bdev *bd, const uint64_t duuid[2])
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(bd);
    STM_ASSERT(caps != NULL);
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = duuid[0];
    opts.devices[0].uuid[1]    = duuid[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = bd;
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    return p;
}

static stm_hybrid_keys g_wk;
static bool g_wk_initialized = false;

static const stm_hybrid_keys *make_wk(void)
{
    if (!g_wk_initialized) {
        STM_ASSERT_OK(stm_crypto_init());
        STM_ASSERT_OK(stm_hybrid_keygen(g_wk.pk, g_wk.sk));
        g_wk_initialized = true;
    }
    return &g_wk;
}

struct dc_fixture {
    stm_bdev  *bd;
    stm_pool  *pool;
    stm_alloc *alloc;
    stm_sync  *sync;
};

static void dc_fixture_open(struct dc_fixture *f, const char *tag)
{
    make_path(tag);
    f->bd   = open_device();
    f->pool = make_single_pool(f->bd, DEVICE_UUID);
    f->alloc = NULL;
    STM_ASSERT_OK(stm_alloc_create(f->bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &f->alloc));
    f->sync = NULL;
    STM_ASSERT_OK(stm_sync_create(f->pool, f->alloc, make_wk(), NULL,
                                    &f->sync));
}

static void dc_fixture_close(struct dc_fixture *f)
{
    stm_sync_close(f->sync);
    stm_alloc_close(f->alloc);
    stm_pool_close(f->pool);
    stm_bdev_close(f->bd);
    unlink(g_path);
}

/* ========================================================================= */
/* Key / pattern helpers. The pattern is position-dependent so a hit's
 * bytes are verifiable at ANY slice offset, and key-derived so a
 * wrong-key copy (the dek_guard-class swap hazard, here the ABA class)
 * can never verify.                                                          */
/* ========================================================================= */

static void dc_key(uint8_t out[32], uint32_t id)
{
    memset(out, 0, 32);
    memcpy(out, &id, sizeof id);
    out[31] = 0x5A;
}

static inline uint8_t dc_pat(uint32_t id, size_t j)
{
    return (uint8_t)(id * 131u + j * 7u + 13u);
}

static void dc_fill(uint8_t *b, uint32_t id, size_t len)
{
    for (size_t j = 0; j < len; j++) b[j] = dc_pat(id, j);
}

/* Verify b[0..n) == pattern(id) at base offset `off`. Returns mismatches. */
static size_t dc_verify(const uint8_t *b, uint32_t id, size_t off, size_t n)
{
    size_t bad = 0;
    for (size_t j = 0; j < n; j++)
        if (b[j] != dc_pat(id, off + j)) bad++;
    return bad;
}

static bool dc_lookup_pinned(stm_sync *s, const uint8_t key[32],
                             size_t len, size_t slice_off, size_t slice_len,
                             uint8_t *out)
{
    stm_ebr_thread *ebr = stm_ebr_thread_current();
    STM_ASSERT(ebr != NULL);
    stm_ebr_enter(ebr);
    bool hit = stm_sync_dcache_lookup_for_test(s, key, 1u, len,
                                               slice_off, slice_len, out);
    stm_ebr_exit(ebr);
    return hit;
}

/* ========================================================================= */
/* Semantics.                                                                 */
/* ========================================================================= */

STM_TEST(dcache_semantics) {
    struct dc_fixture f;
    dc_fixture_open(&f, "sem");

    enum { LEN = 8192 };
    uint8_t key[32], src[LEN], got[LEN];
    dc_key(key, 7);
    dc_fill(src, 7, LEN);

    /* Miss on the empty cache. */
    STM_ASSERT(!dc_lookup_pinned(f.sync, key, LEN, 0, LEN, got));

    stm_sync_dcache_insert_for_test(f.sync, key, 1u, src, LEN);

    uint64_t hits, misses; size_t bytes;
    stm_sync_dcache_stats(f.sync, &hits, &misses, &bytes);
    STM_ASSERT_EQ(bytes, (size_t)LEN);

    /* Full copy, byte-exact. */
    memset(got, 0, LEN);
    STM_ASSERT(dc_lookup_pinned(f.sync, key, LEN, 0, LEN, got));
    STM_ASSERT_EQ(dc_verify(got, 7, 0, LEN), (size_t)0);

    /* Slice copy at an interior offset. */
    memset(got, 0, LEN);
    STM_ASSERT(dc_lookup_pinned(f.sync, key, LEN, 4096, 100, got));
    STM_ASSERT_EQ(dc_verify(got, 7, 4096, 100), (size_t)0);

    /* len participates in the match: a different-length probe misses. */
    STM_ASSERT(!dc_lookup_pinned(f.sync, key, LEN - 1, 0, 16, got));

    /* A different kind tag misses. */
    {
        stm_ebr_thread *ebr = stm_ebr_thread_current();
        stm_ebr_enter(ebr);
        STM_ASSERT(!stm_sync_dcache_lookup_for_test(f.sync, key, 2u, LEN,
                                                    0, 16, got));
        stm_ebr_exit(ebr);
    }

    /* Dedup: re-inserting the same (key, kind, len) keeps ONE copy. */
    stm_sync_dcache_insert_for_test(f.sync, key, 1u, src, LEN);
    stm_sync_dcache_stats(f.sync, &hits, &misses, &bytes);
    STM_ASSERT_EQ(bytes, (size_t)LEN);

    /* Drain empties (the evict-dek fail-closed shape) ... */
    stm_sync_dcache_drain_for_test(f.sync);
    stm_sync_dcache_stats(f.sync, &hits, &misses, &bytes);
    STM_ASSERT_EQ(bytes, (size_t)0);
    STM_ASSERT(!dc_lookup_pinned(f.sync, key, LEN, 0, LEN, got));

    /* ... and the cache stays serviceable after it. */
    stm_sync_dcache_insert_for_test(f.sync, key, 1u, src, LEN);
    memset(got, 0, LEN);
    STM_ASSERT(dc_lookup_pinned(f.sync, key, LEN, 0, LEN, got));
    STM_ASSERT_EQ(dc_verify(got, 7, 0, LEN), (size_t)0);

    dc_fixture_close(&f);
}

/* ========================================================================= */
/* Slot-bound LRU eviction.                                                   */
/* ========================================================================= */

STM_TEST(dcache_slot_lru_evict) {
    struct dc_fixture f;
    dc_fixture_open(&f, "lru");

    /* 2100 unique small keys against the 2048-entry cap: inserting the
     * last 52 evicts exactly the 52 least-recently-used (== oldest;
     * nothing re-touches them), keys 0..51. If STM_DCACHE_ENTRIES is
     * ever raised past 2100, raise N here to keep the eviction real. */
    enum { N = 2100, SLEN = 64 };
    uint8_t key[32], src[SLEN], got[SLEN];

    for (uint32_t id = 0; id < N; id++) {
        dc_key(key, id);
        dc_fill(src, id, SLEN);
        stm_sync_dcache_insert_for_test(f.sync, key, 1u, src, SLEN);
    }

    dc_key(key, 0);
    STM_ASSERT(!dc_lookup_pinned(f.sync, key, SLEN, 0, SLEN, got));
    dc_key(key, 51);
    STM_ASSERT(!dc_lookup_pinned(f.sync, key, SLEN, 0, SLEN, got));
    dc_key(key, 52);
    STM_ASSERT(dc_lookup_pinned(f.sync, key, SLEN, 0, SLEN, got));
    STM_ASSERT_EQ(dc_verify(got, 52, 0, SLEN), (size_t)0);
    dc_key(key, N - 1);
    STM_ASSERT(dc_lookup_pinned(f.sync, key, SLEN, 0, SLEN, got));
    STM_ASSERT_EQ(dc_verify(got, N - 1, 0, SLEN), (size_t)0);

    dc_fixture_close(&f);
}

/* ========================================================================= */
/* The concurrency hammer.                                                    */
/* ========================================================================= */

/* Keys sized so the working set (~96 x ~1.5 MiB ~= 145 MiB) exceeds the
 * 128 MiB byte budget: the writer's steady state is constant LRU
 * eviction churn under the readers, plus periodic full drains — every
 * writer-side removal path runs against pinned readers. */
#define HAM_KEYS        96u
#define HAM_WRITES      1500u
#define HAM_DRAIN_EVERY 301u          /* not a divisor of WRITES: the run
                                       * must not END on a drain, so the
                                       * final cache is non-empty */
#define HAM_READS_MIN   40000u        /* floor per reader ... */
#define HAM_READS_CAP   20000000u     /* ... and a termination backstop */
#define HAM_READERS     4
#define HAM_SLICE       4096u

static inline size_t ham_len(uint32_t id)
{
    return (size_t)(1400u * 1024u) + (size_t)id * 4096u;
}

struct ham_shared {
    stm_sync        *sync;
    _Atomic uint64_t content_failures;
    _Atomic uint64_t hits;
    _Atomic bool     stop;
};

static void *ham_writer(void *arg)
{
    struct ham_shared *sh = arg;
    size_t max_len = ham_len(HAM_KEYS - 1);
    uint8_t *src = malloc(max_len);
    if (!src) { atomic_store(&sh->stop, true); return NULL; }

    for (uint32_t i = 0; i < HAM_WRITES; i++) {
        uint32_t id = i % HAM_KEYS;
        size_t len = ham_len(id);
        uint8_t key[32];
        dc_key(key, id);
        dc_fill(src, id, len);
        stm_sync_dcache_insert_for_test(sh->sync, key, 1u, src, len);
        if ((i + 1u) % HAM_DRAIN_EVERY == 0u)
            stm_sync_dcache_drain_for_test(sh->sync);
    }
    free(src);
    atomic_store(&sh->stop, true);
    return NULL;
}

static void *ham_reader(void *arg)
{
    struct ham_shared *sh = arg;
    stm_ebr_thread *ebr = stm_ebr_thread_current();
    if (!ebr) { atomic_fetch_add(&sh->content_failures, 1); return NULL; }

    uint8_t *got = malloc(HAM_SLICE);
    if (!got) { atomic_fetch_add(&sh->content_failures, 1); return NULL; }

    /* Thread-local LCG; seeded off the ebr handle address for spread. */
    uint64_t rng = (uint64_t)(uintptr_t)ebr | 1u;
    uint64_t local_fail = 0, local_hits = 0;

    /* Race for the WRITER's whole duration (the writer's pattern fills
     * dominate wall time; a fixed reader count finishes before anything
     * is even inserted — hits==0, vacuous). Floor + backstop keep the
     * iteration count sane on both sides. */
    for (uint64_t i = 0;
         !(atomic_load_explicit(&sh->stop, memory_order_relaxed)
           && i >= HAM_READS_MIN)
         && i < HAM_READS_CAP;
         i++) {
        rng = rng * UINT64_C(6364136223846793005) + 1442695040888963407u;
        uint32_t id = (uint32_t)((rng >> 33) % HAM_KEYS);
        size_t len = ham_len(id);
        size_t off = (size_t)((rng >> 17) % (len - HAM_SLICE));
        uint8_t key[32];
        dc_key(key, id);

        stm_ebr_enter(ebr);
        bool hit = stm_sync_dcache_lookup_for_test(sh->sync, key, 1u, len,
                                                   off, HAM_SLICE, got);
        stm_ebr_exit(ebr);

        if (hit) {
            local_hits++;
            local_fail += dc_verify(got, id, off, HAM_SLICE);
        }
    }
    atomic_fetch_add(&sh->hits, local_hits);
    atomic_fetch_add(&sh->content_failures, local_fail);
    free(got);
    return NULL;
}

STM_TEST(dcache_concurrent_hammer) {
    struct dc_fixture f;
    dc_fixture_open(&f, "hammer");

    struct ham_shared sh;
    sh.sync = f.sync;
    atomic_init(&sh.content_failures, 0);
    atomic_init(&sh.hits, 0);
    atomic_init(&sh.stop, false);

    pthread_t wr, rd[HAM_READERS];
    STM_ASSERT_EQ(pthread_create(&wr, NULL, ham_writer, &sh), 0);
    for (int i = 0; i < HAM_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&rd[i], NULL, ham_reader, &sh), 0);

    pthread_join(wr, NULL);
    for (int i = 0; i < HAM_READERS; i++) pthread_join(rd[i], NULL);

    uint64_t fails = atomic_load(&sh.content_failures);
    uint64_t hits  = atomic_load(&sh.hits);
    stm_test_info("hammer: hits=%llu content_failures=%llu",
                  (unsigned long long)hits, (unsigned long long)fails);

    /* Zero tolerance: any mismatched byte is a torn/wrong/freed read. */
    STM_ASSERT_EQ(fails, (uint64_t)0);
    /* Non-vacuous: the readers must actually have raced live entries. */
    STM_ASSERT(hits > 1000u);

    dc_fixture_close(&f);
}

STM_TEST_MAIN("dcache_concurrent")
