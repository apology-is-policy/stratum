/* SPDX-License-Identifier: ISC */
/*
 * bench_write_amp -- CF-1 chunk 11 (9.8-BE-bench): metadata write
 * amplification, 9.7 serial write regime vs 9.8 Be concurrent regime,
 * measured as PHYSICAL NODE COW WRITES via the engine's chunk-11
 * counters (stm_btree_engine_stats.node_writes; the single physical
 * writer is eng_node_write, reached only from commit_node, so the
 * counter is exact -- design doc section 9.2).
 *
 * Both regimes batch dirty state in memory and write ONLY at commit,
 * so write amplification is a function of COMMIT CADENCE (updates per
 * commit, `C`) and KEY SPREAD -- not a single number. The bench
 * therefore sweeps the cadence and reports the per-cadence
 * apples-to-apples ratio, in two workloads:
 *
 *   A "create-storm": N inserts into an initially-empty tree (the
 *     section-9.2 "create 100K files" shape). Patterns: seq (one
 *     ascending cursor: sequential ino allocation), dirs (1K
 *     interleaved ascending cursors: 100K files round-robin across
 *     1K directories), rand (uniform random keys).
 *
 *   B "sparse-update": S sequential keys are seeded IDENTICALLY on
 *     both legs (serial inserts + one commit), then M uniform-random
 *     UPDATES run at the swept cadence. batch << leaves is the regime
 *     the design's section-5.4 write-amp math actually describes (a
 *     plain COW tree pays ~1 leaf + amortized internals per update;
 *     Be absorbs the batch in upper-level buffers).
 *
 * Legs per configuration (fresh store + fresh tree each run, same
 * deterministic key stream -- byte-comparable):
 *   serial: stm_btree_engine_insert       (the 9.7-shipped write path)
 *   be:     stm_btree_engine_insert_concurrent (9.8 CAS-prepend + Be
 *           buffers + clone commit; EBR-registered, per-op epoch)
 *
 * The store is a self-contained in-RAM node store: vt->free actually
 * frees the slot buffer (paddrs are never reused, so a read-after-free
 * fails loudly with STM_EINVAL instead of returning stale bytes) --
 * this bounds bench memory to the live tree, unlike the test suite's
 * deferred-free memstore. Single-threaded, so reclaiming superseded
 * bytes at finalize is trivially safe.
 *
 * Env knobs (override without recompiling):
 *   STM_BENCH_WORKLOAD  a | b | both                     (default both)
 *   STM_BENCH_PATTERN   seq | dirs | rand | all          (default all; A only)
 *   STM_BENCH_N         workload A inserts               (default 100000)
 *   STM_BENCH_SEED      workload B seeded keys           (default 500000)
 *   STM_BENCH_UPDATES   workload B updates               (default 20000)
 *   STM_BENCH_VAL       value bytes                      (default 56)
 *   STM_BENCH_CADENCES  comma list; 0 = single commit at the end
 *                       (default A: 1,10,100,1000,10000,0
 *                                B: 1,10,100,1000,0)
 *
 * Build + run on the NON-sanitized build (real timing):
 *   cmake --build build --target bench_write_amp -j8
 *   ./build/tests/bench_write_amp
 *   STM_BENCH_WORKLOAD=b STM_BENCH_SEED=2000000 ./build/tests/bench_write_amp
 */

#include <stratum/btree_engine.h>
#include <stratum/ebr.h>
#include <stratum/types.h>

#include <inttypes.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ========================================================================= */
/* In-RAM node store — free-at-vt->free, paddrs never reused.                 */
/* ========================================================================= */

typedef struct {
    uint8_t **slots;                 /* index = paddr - 1; NULL = freed */
    size_t    n, cap;
    uint64_t  live, live_peak;       /* allocated slot buffers          */
    uint64_t  frees;
} wa_store;

static void wa_store_init(wa_store *st) { memset(st, 0, sizeof *st); }

static void wa_store_destroy(wa_store *st)
{
    for (size_t i = 0; i < st->n; i++) free(st->slots[i]);
    free(st->slots);
    memset(st, 0, sizeof *st);
}

static stm_status wa_reserve(void *ctx, uint64_t *out_paddr)
{
    wa_store *st = ctx;
    if (st->n == st->cap) {
        size_t nc = st->cap ? st->cap * 2 : 1024;
        uint8_t **p = realloc(st->slots, nc * sizeof *p);
        if (!p) return STM_ENOMEM;
        st->slots = p;
        st->cap = nc;
    }
    uint8_t *buf = calloc(1, STM_BTREE_ENGINE_NODE_SIZE);
    if (!buf) return STM_ENOMEM;
    st->slots[st->n++] = buf;
    st->live++;
    if (st->live > st->live_peak) st->live_peak = st->live;
    *out_paddr = (uint64_t)st->n;    /* 1-based; fresh, never reused */
    return STM_OK;
}

static stm_status wa_free(void *ctx, uint64_t paddr, uint64_t free_gen)
{
    (void)free_gen;
    wa_store *st = ctx;
    if (paddr == 0 || paddr > st->n) return STM_EINVAL;
    if (!st->slots[paddr - 1]) {
        fprintf(stderr, "bench_write_amp: DOUBLE vt->free of paddr %" PRIu64 "\n",
                paddr);
        exit(1);                     /* an engine bug — fail loud */
    }
    free(st->slots[paddr - 1]);
    st->slots[paddr - 1] = NULL;
    st->live--;
    st->frees++;
    return STM_OK;
}

static stm_status wa_write(void *ctx, uint64_t paddr,
                           const void *buf, size_t len)
{
    wa_store *st = ctx;
    if (paddr == 0 || paddr > st->n) return STM_EINVAL;
    if (!st->slots[paddr - 1] || len > STM_BTREE_ENGINE_NODE_SIZE)
        return STM_EINVAL;
    memcpy(st->slots[paddr - 1], buf, len);
    return STM_OK;
}

static stm_status wa_read(void *ctx, uint64_t paddr, void *buf, size_t len)
{
    wa_store *st = ctx;
    if (paddr == 0 || paddr > st->n) return STM_EINVAL;
    if (!st->slots[paddr - 1] || len > STM_BTREE_ENGINE_NODE_SIZE)
        return STM_EINVAL;           /* read-after-free fails loud */
    memcpy(buf, st->slots[paddr - 1], len);
    return STM_OK;
}

static const stm_btree_store_vtable g_wa_vt = {
    .reserve = wa_reserve,
    .free    = wa_free,
    .write   = wa_write,
    .read    = wa_read,
};

/* ========================================================================= */
/* Fixtures + key streams.                                                    */
/* ========================================================================= */

static const uint8_t g_bench_key[32] = {
    0x42, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78,
    0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
};

static stm_btree_crypt_ctx bench_cx(void)
{
    stm_btree_crypt_ctx cx;
    cx.metadata_key   = g_bench_key;
    cx.pool_uuid[0]   = UINT64_C(0x1111111111111111);
    cx.pool_uuid[1]   = UINT64_C(0x2222222222222222);
    cx.device_uuid[0] = UINT64_C(0x3333333333333333);
    cx.device_uuid[1] = UINT64_C(0x4444444444444444);
    return cx;
}

static void be64_key(uint64_t v, uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* Deterministic splitmix64 — the uniform-random key stream. */
static uint64_t splitmix64(uint64_t x)
{
    x += UINT64_C(0x9E3779B97F4A7C15);
    x = (x ^ (x >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94D049BB133111EB);
    return x ^ (x >> 31);
}

typedef enum { PAT_SEQ, PAT_DIRS, PAT_RAND } wa_pattern;
static const char *pat_name(wa_pattern p)
{
    return p == PAT_SEQ ? "seq" : p == PAT_DIRS ? "dirs" : "rand";
}

/* Workload A key for op i. */
static uint64_t key_a(wa_pattern p, uint64_t i)
{
    switch (p) {
    case PAT_SEQ:  return i;
    case PAT_DIRS: return ((i % 1000u) << 32) | (i / 1000u);
    default:       return splitmix64(i);
    }
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ========================================================================= */
/* Leg runner.                                                                */
/* ========================================================================= */

typedef struct {
    uint64_t writes, leaf_writes, reads;
    uint64_t commits;
    uint64_t n_keys;
    uint32_t height;
    uint64_t live_peak_mib;
    double   secs;
} wa_result;

#define WA_DIE(msg, st) do {                                              \
        fprintf(stderr, "bench_write_amp: %s failed: %d\n", (msg), (st)); \
        exit(1);                                                          \
    } while (0)

/* One upsert on the chosen leg. The be leg holds an EBR epoch across
 * the call (the insert_concurrent contract) and retries the documented
 * STM_EBUSY consolidation back-pressure (single-threaded it should not
 * occur; the cap fails loud rather than spinning forever). */
static void wa_put(stm_btree_engine *eng, stm_ebr_thread *me, bool be,
                   const uint8_t key[8], const uint8_t *val, size_t val_len)
{
    stm_status s;
    if (!be) {
        s = stm_btree_engine_insert(eng, key, 8, val, val_len);
        if (s != STM_OK) WA_DIE("serial insert", s);
        return;
    }
    stm_ebr_enter(me);
    for (uint32_t tries = 0; ; tries++) {
        s = stm_btree_engine_insert_concurrent(eng, me, key, 8, val, val_len);
        if (s == STM_OK) break;
        if (s != STM_EBUSY || tries > 1000000u) {
            stm_ebr_exit(me);
            WA_DIE("concurrent insert", s);
        }
        if ((tries & 63u) == 63u) sched_yield();
    }
    stm_ebr_exit(me);
}

static void wa_commit(stm_btree_engine *eng, uint64_t *gen, bool be)
{
    uint64_t rp = 0;
    uint8_t  rc[32];
    stm_status s = stm_btree_engine_commit(eng, ++*gen, &rp, rc);
    if (s != STM_OK) WA_DIE("commit", s);
    if (be) (void)stm_ebr_try_advance();  /* reclaim retired trees */
}

/*
 * One measured run: fresh store + engine; optional seed of `seed_keys`
 * sequential keys (serial inserts + one commit — identical on both
 * legs); then `ops` updates keyed by (workload, pattern), committing
 * every `cadence` ops (0 = once at the end). Counter deltas are taken
 * around the UPDATE phase only, so the seed's writes never count.
 */
static void wa_run(bool be, char workload, wa_pattern pat,
                   uint64_t seed_keys, uint64_t ops, uint64_t cadence,
                   size_t val_len, wa_result *out)
{
    wa_store st;
    wa_store_init(&st);
    stm_btree_crypt_ctx cx = bench_cx();
    stm_btree_engine *eng = NULL;
    stm_status s = stm_btree_engine_create(&g_wa_vt, &st, &cx, 0, &eng);
    if (s != STM_OK) WA_DIE("engine create", s);

    stm_ebr_thread *me = NULL;
    if (be) {
        s = stm_ebr_init();
        if (s != STM_OK) WA_DIE("ebr init", s);
        me = stm_ebr_register();
        if (!me) WA_DIE("ebr register", STM_ENOMEM);
    }

    uint8_t *val = malloc(val_len ? val_len : 1u);
    if (!val) WA_DIE("val alloc", STM_ENOMEM);
    memset(val, 0xA5, val_len);

    uint64_t gen = 0;
    uint8_t  key[8];

    /* Seed (workload B): serial on BOTH legs — byte-identical trees. */
    for (uint64_t i = 0; i < seed_keys; i++) {
        be64_key(i, key);
        s = stm_btree_engine_insert(eng, key, 8, val, val_len);
        if (s != STM_OK) WA_DIE("seed insert", s);
    }
    if (seed_keys) wa_commit(eng, &gen, false);

    stm_btree_engine_stats st0;
    s = stm_btree_engine_stats_get(eng, &st0);
    if (s != STM_OK) WA_DIE("stats before", s);

    /* The measured update phase. */
    double t0 = now_s();
    uint64_t commits = 0;
    for (uint64_t i = 0; i < ops; i++) {
        uint64_t k = (workload == 'a') ? key_a(pat, i)
                                       : splitmix64(i) % seed_keys;
        be64_key(k, key);
        val[0] = (uint8_t)i;             /* a real content change */
        wa_put(eng, me, be, key, val, val_len);
        if (cadence && (i + 1u) % cadence == 0u) {
            wa_commit(eng, &gen, be);
            commits++;
        }
    }
    if (!cadence || ops % cadence) {     /* trailing partial batch */
        wa_commit(eng, &gen, be);
        commits++;
    }
    double t1 = now_s();

    stm_btree_engine_stats st1;
    s = stm_btree_engine_stats_get(eng, &st1);
    if (s != STM_OK) WA_DIE("stats after", s);

    out->writes      = st1.node_writes - st0.node_writes;
    out->leaf_writes = st1.node_leaf_writes - st0.node_leaf_writes;
    out->reads       = st1.node_reads - st0.node_reads;
    out->commits     = commits;
    out->n_keys      = st1.n_keys;
    out->height      = st1.height;
    out->live_peak_mib =
        st.live_peak * (uint64_t)STM_BTREE_ENGINE_NODE_SIZE / (1024u * 1024u);
    out->secs        = t1 - t0;

    free(val);
    stm_btree_engine_destroy(eng);
    if (be) {
        for (int i = 0; i < 4; i++) (void)stm_ebr_try_advance();
        while (stm_ebr_try_advance() > 0) { }
        stm_ebr_thread_free(me);
    }
    wa_store_destroy(&st);
}

/* ========================================================================= */
/* Sweep + report.                                                            */
/* ========================================================================= */

static void report_pair(char workload, const char *pat, uint64_t cadence,
                        uint64_t ops, const wa_result *ser,
                        const wa_result *be)
{
    double ratio = be->writes ? (double)ser->writes / (double)be->writes : 0.0;
    printf("WA|wl=%c|pat=%s|C=%" PRIu64 "|ops=%" PRIu64
           "|serial_w=%" PRIu64 "|serial_leaf=%" PRIu64
           "|serial_w_op=%.3f|serial_s=%.2f"
           "|be_w=%" PRIu64 "|be_leaf=%" PRIu64
           "|be_w_op=%.3f|be_s=%.2f|ratio=%.2f\n",
           workload, pat, cadence, ops,
           ser->writes, ser->leaf_writes,
           ops ? (double)ser->writes / (double)ops : 0.0, ser->secs,
           be->writes, be->leaf_writes,
           ops ? (double)be->writes / (double)ops : 0.0, be->secs,
           ratio);
    fflush(stdout);
}

static unsigned long env_u(const char *k, unsigned long dflt)
{
    const char *v = getenv(k);
    if (!v || !*v) return dflt;
    return strtoul(v, NULL, 10);
}

static const char *env_s(const char *k, const char *dflt)
{
    const char *v = getenv(k);
    return (v && *v) ? v : dflt;
}

static size_t parse_cadences(const char *spec, uint64_t *out, size_t max)
{
    size_t n = 0;
    while (*spec && n < max) {
        out[n++] = strtoull(spec, (char **)&spec, 10);
        while (*spec == ',' || *spec == ' ') spec++;
    }
    return n;
}

int main(void)
{
    const char *wl  = env_s("STM_BENCH_WORKLOAD", "both");
    const char *pt  = env_s("STM_BENCH_PATTERN", "all");
    uint64_t  n_a   = env_u("STM_BENCH_N", 100000u);
    uint64_t  seed  = env_u("STM_BENCH_SEED", 500000u);
    uint64_t  m_b   = env_u("STM_BENCH_UPDATES", 20000u);
    size_t    vlen  = env_u("STM_BENCH_VAL", 56u);
    uint64_t  cad[16];
    size_t    ncad;

    printf("bench_write_amp: node=%u KiB, val=%zu B "
           "(A: N=%" PRIu64 "; B: seed=%" PRIu64 " updates=%" PRIu64 ")\n",
           STM_BTREE_ENGINE_NODE_SIZE / 1024u, vlen, n_a, seed, m_b);

    if (strcmp(wl, "b") != 0) {
        ncad = parse_cadences(env_s("STM_BENCH_CADENCES",
                                    "1,10,100,1000,10000,0"), cad, 16);
        wa_pattern pats[3] = { PAT_SEQ, PAT_DIRS, PAT_RAND };
        for (int p = 0; p < 3; p++) {
            if (strcmp(pt, "all") != 0 &&
                strcmp(pt, pat_name(pats[p])) != 0)
                continue;
            for (size_t c = 0; c < ncad; c++) {
                wa_result ser, be;
                wa_run(false, 'a', pats[p], 0, n_a, cad[c], vlen, &ser);
                wa_run(true,  'a', pats[p], 0, n_a, cad[c], vlen, &be);
                report_pair('a', pat_name(pats[p]), cad[c], n_a, &ser, &be);
            }
        }
    }

    if (strcmp(wl, "a") != 0 && seed > 0 && m_b > 0) {
        ncad = parse_cadences(env_s("STM_BENCH_CADENCES",
                                    "1,10,100,1000,0"), cad, 16);
        for (size_t c = 0; c < ncad; c++) {
            wa_result ser, be;
            wa_run(false, 'b', PAT_RAND, seed, m_b, cad[c], vlen, &ser);
            wa_run(true,  'b', PAT_RAND, seed, m_b, cad[c], vlen, &be);
            report_pair('b', "rand", cad[c], m_b, &ser, &be);
        }
    }

    return 0;
}
