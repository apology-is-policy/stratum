/* SPDX-License-Identifier: ISC */
/*
 * stm_xor_filter — xor8 construction (Phase 3 chunk 4d).
 *
 *   see include/stratum/xor_filter.h for the surface.
 *   see docs/ARCHITECTURE.md §6.6.2 for design context.
 *
 *   reference: "Xor Filters: Faster and Smaller Than Bloom and Cuckoo
 *              Filters", Graf & Lemire 2020.
 *
 * Canonical xor8 peeling builder:
 *
 *   1. Choose a seed s. For each key x, compute three slot indices
 *      h0, h1, h2 in disjoint thirds of a table of 3 * seg_size slots
 *      (seg_size = ceil(1.23 * count / 3)), and an 8-bit fingerprint
 *      fp(x).
 *   2. Build a 3-uniform hypergraph: each key is a hyperedge
 *      {h0, h1, h2}. For each slot maintain (count-of-adjacent-edges,
 *      XOR-of-adjacent-keys).
 *   3. Peel: repeatedly find a slot with count == 1 (its XOR is the
 *      only key there). Stack the (slot, key) pair and remove the
 *      edge — decrement the other two slots' counts and XOR the key
 *      out. If every edge peels, the seed is good; otherwise bump
 *      seed and retry.
 *   4. Pop the stack in reverse and assign slots[s] = fp(k) XOR
 *      slots[other_a] XOR slots[other_b] for each (slot, key). The
 *      peel invariant guarantees the two "other" slots are already
 *      assigned by the time we reach this step.
 *
 *   Query: slots[h0] XOR slots[h1] XOR slots[h2] == fp(x)  iff x is a
 *          member (or a rare false positive at ~0.4% rate).
 *
 * Hashing is splitmix64-based so the module has no dependencies
 * beyond libc.
 */

#include <stratum/xor_filter.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Peeling typically succeeds on the first seed at 1.23 overhead; 64
 * retries is well past the paper's empirical worst case. STM_ENOMEM
 * is returned only if every seed fails, which is vanishingly rare
 * for count > a handful. */
#define STM_XOR_MAX_SEEDS 64u

struct stm_xor_filter {
    uint64_t seed;
    size_t   count;           /* keys built in (m)               */
    size_t   seg_size;        /* per-third slot count            */
    size_t   nslots;          /* = 3 * seg_size                  */
    uint8_t *slots;           /* nslots 8-bit fingerprints       */
};

/* ========================================================================= */
/* Hashing.                                                                   */
/* ========================================================================= */

static inline uint64_t splitmix64(uint64_t x)
{
    x += UINT64_C(0x9e3779b97f4a7c15);
    x  = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x  = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

/* Map (seed, key) to three disjoint-third slot indices and an 8-bit
 * fingerprint. Fingerprint is re-rolled to 1 if it would be 0 so an
 * all-zero slot reliably means "empty" during debugging (not strictly
 * required by xor8 — queries compare acc == fp either way). */
static void xor_hashes(uint64_t seed, uint64_t key, size_t seg_size,
                        size_t *h0, size_t *h1, size_t *h2, uint8_t *fp)
{
    uint64_t mix = splitmix64(key ^ seed);
    uint64_t a   = splitmix64(mix + UINT64_C(1));
    uint64_t b   = splitmix64(mix + UINT64_C(2));
    uint64_t c   = splitmix64(mix + UINT64_C(3));
    uint64_t f   = splitmix64(mix + UINT64_C(4));

    *h0 = (size_t)(a % (uint64_t)seg_size);
    *h1 = seg_size + (size_t)(b % (uint64_t)seg_size);
    *h2 = 2u * seg_size + (size_t)(c % (uint64_t)seg_size);

    uint8_t fp8 = (uint8_t)(f & 0xFFu);
    if (fp8 == 0u) fp8 = 1u;
    *fp = fp8;
}

/* ========================================================================= */
/* Duplicate-free input check.                                                */
/* ========================================================================= */

static int cmp_u64(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return  1;
    return 0;
}

static stm_status validate_unique(const uint64_t *keys, size_t count)
{
    if (count < 2u) return STM_OK;
    uint64_t *sorted = malloc(count * sizeof *sorted);
    if (!sorted) return STM_ENOMEM;
    memcpy(sorted, keys, count * sizeof *sorted);
    qsort(sorted, count, sizeof *sorted, cmp_u64);
    for (size_t i = 1; i < count; i++) {
        if (sorted[i] == sorted[i - 1]) { free(sorted); return STM_EINVAL; }
    }
    free(sorted);
    return STM_OK;
}

/* ========================================================================= */
/* Peeling.                                                                   */
/* ========================================================================= */

struct builder {
    size_t     seg_size;
    size_t     nslots;
    size_t     count;

    uint64_t  *key_xor;        /* per-slot XOR of adjacent keys  */
    uint32_t  *key_count;      /* per-slot adjacent-edge count   */

    size_t    *peel_slots;     /* stack of (slot, key) in peel order */
    uint64_t  *peel_keys;
    size_t     peel_top;
};

/* Try a single seed. On success the peel stack holds `count` entries
 * and the caller advances to fingerprint assignment. */
static bool try_seed(struct builder *b, const uint64_t *keys, uint64_t seed)
{
    memset(b->key_xor,   0, b->nslots * sizeof b->key_xor[0]);
    memset(b->key_count, 0, b->nslots * sizeof b->key_count[0]);
    b->peel_top = 0u;

    /* Hypergraph population. */
    for (size_t i = 0; i < b->count; i++) {
        size_t  h0, h1, h2;
        uint8_t fp_dummy;
        xor_hashes(seed, keys[i], b->seg_size, &h0, &h1, &h2, &fp_dummy);

        b->key_xor[h0]   ^= keys[i];
        b->key_xor[h1]   ^= keys[i];
        b->key_xor[h2]   ^= keys[i];
        b->key_count[h0] += 1u;
        b->key_count[h1] += 1u;
        b->key_count[h2] += 1u;
    }

    /* Peel via explicit degree-1 queue (amortized O(count)). */
    size_t *q = malloc(b->nslots * sizeof *q);
    if (!q) return false;
    size_t qhead = 0u, qtail = 0u;
    for (size_t s = 0; s < b->nslots; s++) {
        if (b->key_count[s] == 1u) q[qtail++] = s;
    }

    while (qhead < qtail) {
        size_t s = q[qhead++];
        if (b->key_count[s] != 1u) continue;   /* may have been reduced */
        uint64_t k = b->key_xor[s];

        b->peel_slots[b->peel_top] = s;
        b->peel_keys [b->peel_top] = k;
        b->peel_top++;

        size_t  h0, h1, h2;
        uint8_t fp_dummy;
        xor_hashes(seed, k, b->seg_size, &h0, &h1, &h2, &fp_dummy);

        const size_t rest[3] = { h0, h1, h2 };
        for (int t = 0; t < 3; t++) {
            size_t r = rest[t];
            if (r == s) continue;
            b->key_xor  [r] ^= k;
            b->key_count[r] -= 1u;
            if (b->key_count[r] == 1u) q[qtail++] = r;
        }
    }

    free(q);
    return b->peel_top == b->count;
}

/* ========================================================================= */
/* Public builder.                                                            */
/* ========================================================================= */

stm_status stm_xor_filter_build(const uint64_t *keys, size_t count,
                                 stm_xor_filter **out_filter)
{
    if (!out_filter) return STM_EINVAL;
    *out_filter = NULL;
    if (count > 0u && keys == NULL) return STM_EINVAL;

    stm_status v = validate_unique(keys, count);
    if (v != STM_OK) return v;

    stm_xor_filter *f = calloc(1, sizeof *f);
    if (!f) return STM_ENOMEM;
    f->count = count;

    /* seg_size = ceil(1.23 * count / 3); minimum 2 so a tiny input
     * still has enough peeling headroom. */
    size_t seg_size;
    if (count == 0u) {
        seg_size = 1u;
    } else {
        double   target = (1.23 * (double)count) / 3.0;
        seg_size = (size_t)target + 1u;
        if (seg_size < 2u) seg_size = 2u;
    }
    f->seg_size = seg_size;
    f->nslots   = 3u * seg_size;

    f->slots = calloc(f->nslots, sizeof f->slots[0]);
    if (!f->slots) { stm_xor_filter_free(f); return STM_ENOMEM; }

    /* Empty set: every query returns acc == 0 != fp, false. */
    if (count == 0u) {
        f->seed = 0u;
        *out_filter = f;
        return STM_OK;
    }

    struct builder b = {
        .seg_size   = seg_size,
        .nslots     = f->nslots,
        .count      = count,
        .key_xor    = calloc(f->nslots, sizeof(uint64_t)),
        .key_count  = calloc(f->nslots, sizeof(uint32_t)),
        .peel_slots = malloc(count * sizeof(size_t)),
        .peel_keys  = malloc(count * sizeof(uint64_t)),
        .peel_top   = 0u,
    };
    if (!b.key_xor || !b.key_count || !b.peel_slots || !b.peel_keys) {
        free(b.key_xor);
        free(b.key_count);
        free(b.peel_slots);
        free(b.peel_keys);
        stm_xor_filter_free(f);
        return STM_ENOMEM;
    }

    /* Seed-retry loop. Seeds are derived from a fixed constant via
     * splitmix64 so the sequence is deterministic (tests get
     * reproducible builds). */
    uint64_t seed   = 0u;
    bool     peeled = false;
    for (unsigned attempt = 0; attempt < STM_XOR_MAX_SEEDS; attempt++) {
        seed = splitmix64(UINT64_C(0xC0FFEE00D15EA5E0) ^
                          ((uint64_t)attempt * UINT64_C(0x100000001b3)));
        if (try_seed(&b, keys, seed)) { peeled = true; break; }
    }

    if (!peeled) {
        free(b.key_xor);
        free(b.key_count);
        free(b.peel_slots);
        free(b.peel_keys);
        stm_xor_filter_free(f);
        return STM_ENOMEM;
    }
    f->seed = seed;

    /* Fingerprint assignment: walk the peel stack in reverse. By the
     * peel invariant, the two "other" slots for each popped key are
     * already fixed in f->slots (either by a later pop or by staying
     * zero — unreached slots contribute 0 to the XOR, which is
     * consistent with a fingerprint-0 convention enforced at query
     * time via the re-roll in xor_hashes). */
    for (size_t i = b.peel_top; i-- > 0; ) {
        size_t   s = b.peel_slots[i];
        uint64_t k = b.peel_keys [i];
        size_t   h[3];
        uint8_t  fp;
        xor_hashes(seed, k, seg_size, &h[0], &h[1], &h[2], &fp);

        uint8_t acc = fp;
        for (int t = 0; t < 3; t++) {
            if (h[t] != s) acc ^= f->slots[h[t]];
        }
        f->slots[s] = acc;
    }

    free(b.key_xor);
    free(b.key_count);
    free(b.peel_slots);
    free(b.peel_keys);

    *out_filter = f;
    return STM_OK;
}

void stm_xor_filter_free(stm_xor_filter *f)
{
    if (!f) return;
    free(f->slots);
    free(f);
}

/* ========================================================================= */
/* Query + accessors.                                                         */
/* ========================================================================= */

bool stm_xor_filter_contains(const stm_xor_filter *f, uint64_t key)
{
    if (!f || f->count == 0u) return false;

    size_t  h[3];
    uint8_t fp;
    xor_hashes(f->seed, key, f->seg_size, &h[0], &h[1], &h[2], &fp);
    uint8_t acc = (uint8_t)(f->slots[h[0]] ^ f->slots[h[1]] ^ f->slots[h[2]]);
    return acc == fp;
}

size_t   stm_xor_filter_count     (const stm_xor_filter *f) { return f ? f->count      : 0u; }
size_t   stm_xor_filter_size_bytes(const stm_xor_filter *f) { return f ? sizeof *f + f->nslots : 0u; }
uint64_t stm_xor_filter_seed      (const stm_xor_filter *f) { return f ? f->seed       : 0u; }
