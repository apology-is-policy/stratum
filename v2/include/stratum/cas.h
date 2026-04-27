/* SPDX-License-Identifier: ISC */
/*
 * Content-addressed cold-tier index (P7-CAS, v18).
 *
 *   see v2/specs/cas.tla — formal model.
 *   see docs/ARCHITECTURE.md §6.9 — CAS cold tier allocator (index design,
 *     write path, GC, chunk sizing).
 *   see docs/ARCHITECTURE.md §7.6.3 — CAS-entry AEAD AD (binds ciphertext
 *     to content_hash).
 *   see docs/ARCHITECTURE.md §12.10 — Hot ↔ Cold tier migration paths.
 *   see docs/NOVEL.md §3.3 — Venti-style CAS with content-defined chunking.
 *   see docs/ROADMAP-V2.md §10 — Phase 7 (cold tier + features).
 *
 * The CAS index tracks the COLD tier's content-addressable store: a
 * Bε-tree keyed by `BLAKE3-256(content)` whose values are
 * `(replicas, refcount, length, gen)`. Multiple cold extents (across
 * files, snapshots, datasets) can reference the same hash — that is the
 * CAS dedup property. The refcount tracks how many cold-extent records
 * currently reference each hash; when the refcount falls to zero, the
 * chunk's backing replicas are eligible for reclamation.
 *
 * Load-bearing invariants (cas.tla):
 *
 *   - RefcountConsistent: for every live CAS entry, refcount equals the
 *     count of live cold extents naming this hash.
 *   - NoDanglingColdRef: every live cold extent's hash names a live CAS
 *     entry.
 *   - HotColdReplicasDisjoint: a hot extent's replicas never collide
 *     with any CAS entry's replicas. (AEAD ADs differ between hot and
 *     cold; reusing a paddr across the boundary would imply two distinct
 *     ciphertexts decrypt at the same physical location.)
 *   - CASReplicasDisjoint: distinct CAS entries reference distinct
 *     paddrs. Each chunk is independently AEAD-encrypted under its own
 *     `(paddr, gen)` nonce.
 *
 * Composition with the extent layer:
 *
 *   - cas.tla::WriteHot is the existing extent.tla::Write path
 *     (paddr-addressed extent records).
 *   - cas.tla::MigrateToCold is realized by the sync layer's
 *     `stm_sync_migrate_to_cold`, which:
 *       (a) reads the source hot extent's plaintext,
 *       (b) chunks via FastCDC,
 *       (c) hashes each chunk with BLAKE3-256,
 *       (d) for each chunk: CAS lookup; on miss, allocates fresh paddrs
 *           + AEAD-encrypts under CAS AD onto fresh replicas + inserts
 *           a new CAS entry; on hit, bumps refcount on the existing
 *           entry,
 *       (e) inserts a COLD extent record per chunk into the extent tree,
 *       (f) drops the source hot extent + frees its replicas via the
 *           refcount-aware drop path.
 *   - cas.tla::RehydrateOnWrite is the C-impl write path's auto-rehydrate
 *     when it encounters a cold extent at the write target.
 *   - cas.tla::GC is realized by `stm_cas_gc` (manual trigger MVP).
 *     Background GC under scrub is post-MVP.
 *
 * Thread safety: every public API holds an internal pthread mutex
 * (ERRORCHECK type) for the duration of the call. Iterator callbacks
 * run UNDER the mutex and MUST NOT call back into stm_cas_*.
 *
 * On-disk format: STM_UB_VERSION 17 → 18.
 *   - New `ub_cas_index_root` (stm_bptr, 64 B at UB offset 3280) +
 *     `ub_cas_index_root_gen` (le64, 8 B at UB offset 3344) carved
 *     from the head of `ub_reserved`. ub_reserved shrinks 784 → 712.
 *   - The CAS index tree's bp_kind is `STM_BPTR_KIND_CAS` (already
 *     allocated at v3, used here for the first time).
 *   - Cold-extent records in the per-file extent tree gain a `kind`
 *     discriminator at value byte 0 (0x01 = HOT, 0x02 = COLD). HOT
 *     keeps the v17 layout (n_replicas at byte 1, paddrs at 8..39,
 *     gen/dlen/clen/key_id/origin/link_gen at 40..95). COLD replaces
 *     bytes 1..39 with reserved (1..7) + content_hash (8..39); bytes
 *     40..95 are identical to HOT.
 *   - The CAS index value layout is 64 bytes:
 *       0    1   n_replicas (u8; 1..STM_CAS_MAX_REPLICAS)
 *       1    7   reserved (zero)
 *       8   32   paddrs[STM_CAS_MAX_REPLICAS=4] (le64 each)
 *      40    8   refcount (le64; clamped at UINT32_MAX semantically,
 *                  encoded as u64 for alignment)
 *      48    8   length (le64; chunk plaintext length in bytes)
 *      56    8   gen (le64; AEAD gen of the underlying chunk; PINNED
 *                  across dedup-hit refcount bumps)
 */
#ifndef STRATUM_V2_CAS_H
#define STRATUM_V2_CAS_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev       stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap  stm_bootstrap;

/* AEAD AD magic / version for CAS chunks (ARCH §7.6.3). */
#define STM_AD_MAGIC_CAS        UINT32_C(0x45534143)   /* 'CASE' */
#define STM_AD_VERSION_CAS      1u

/* 56-byte AD struct per ARCH §7.6.3. Binds ciphertext to its content
 * hash — an attacker cannot substitute a chunk for another without
 * breaking AEAD. */
typedef struct {
    uint32_t magic;             /* STM_AD_MAGIC_CAS */
    uint32_t version;           /* STM_AD_VERSION_CAS */
    uint64_t pool_uuid[2];
    uint8_t  content_hash[32];  /* BLAKE3-256 of the chunk's plaintext */
} stm_ad_cas;

#define STM_AD_CAS_PACKED_LEN   56u

void stm_ad_cas_pack(const stm_ad_cas *ad,
                     uint8_t out[STM_AD_CAS_PACKED_LEN]);

/* Maximum number of replica paddrs per CAS entry (P7-CAS / v18).
 * Sized at 4 to mirror STM_EXTENT_MAX_REPLICAS — production mirror
 * configs are typically N ∈ {2, 3}. */
#define STM_CAS_MAX_REPLICAS    4u

/* BLAKE3-256 hash length (32 bytes). Defined here for in-RAM struct
 * parity with the on-disk layout; the `<stratum/hash.h>` header has
 * the underlying primitive. */
#define STM_CAS_HASH_LEN        32u

/* Per-CAS-entry record. In-RAM mirror of the on-disk layout under
 * `ub_cas_index_root`. */
typedef struct {
    uint8_t  content_hash[STM_CAS_HASH_LEN];   /* BLAKE3-256, the index key */
    uint8_t  n_replicas;                        /* 1..STM_CAS_MAX_REPLICAS */
    uint64_t paddrs[STM_CAS_MAX_REPLICAS];     /* valid 0..n_replicas-1 */
    uint32_t refcount;                          /* live cold-extent refs */
    uint64_t length;                            /* chunk plaintext bytes */
    uint64_t gen;                               /* AEAD nonce gen; pinned */
} stm_cas_record;

struct stm_cas_index;
typedef struct stm_cas_index stm_cas_index;

/* ========================================================================= */
/* Lifecycle.                                                                  */
/* ========================================================================= */

/*
 * Create a new CAS index. `current_txg` becomes the initial txg counter;
 * later operations advance it via _advance_txg.
 *
 * Returns STM_OK on success. STM_EINVAL on NULL out. STM_ENOMEM if
 * allocation fails.
 */
STM_MUST_USE
stm_status stm_cas_index_create(uint64_t current_txg,
                                  stm_cas_index **out);

/*
 * Release the index. Frees all entries. Caller must ensure no concurrent
 * access.
 */
void stm_cas_index_close(stm_cas_index *idx);

STM_MUST_USE
stm_status stm_cas_index_current_txg(const stm_cas_index *idx,
                                       uint64_t *out_txg);

/*
 * Advance the internal txg counter. Refuses regression
 * (new_txg < current_txg) with STM_EINVAL. Equal value is a no-op.
 */
STM_MUST_USE
stm_status stm_cas_index_advance_txg(stm_cas_index *idx,
                                       uint64_t new_txg);

/* ========================================================================= */
/* Mutations.                                                                  */
/* ========================================================================= */

/*
 * Insert a new CAS entry at content_hash with the given replicas,
 * length, and gen. refcount is initialized to 1.
 *
 * Refusals:
 *   - content_hash == NULL OR all-zero (STM_EINVAL).
 *   - n_paddrs < 1 OR n_paddrs > STM_CAS_MAX_REPLICAS (STM_EINVAL).
 *   - any paddrs[i] == 0 OR within-set duplicate (STM_EINVAL).
 *   - length == 0 (STM_EINVAL — cas.tla::LengthPositive).
 *   - gen > current_txg (STM_EINVAL — cas.tla::BirthTxgBound).
 *   - hash already present (STM_EEXIST — caller must use _ref instead).
 *
 * Models cas.tla::MigrateToCold's CAS-miss branch.
 */
STM_MUST_USE
stm_status stm_cas_insert(stm_cas_index *idx,
                            const uint8_t content_hash[STM_CAS_HASH_LEN],
                            const uint64_t *paddrs, size_t n_paddrs,
                            uint64_t length, uint64_t gen);

/*
 * Bump the refcount of an existing CAS entry. Used by the dedup-hit
 * branch of MigrateToCold (when a chunk's hash already exists, the new
 * cold extent record references the existing entry rather than allocating
 * a duplicate one).
 *
 * Refusals:
 *   - hash == NULL (STM_EINVAL).
 *   - hash not present (STM_ENOENT — caller must use _insert).
 *   - refcount would overflow UINT32_MAX (STM_EOVERFLOW).
 *
 * Models cas.tla::MigrateToCold's CAS-hit branch.
 */
STM_MUST_USE
stm_status stm_cas_ref(stm_cas_index *idx,
                        const uint8_t content_hash[STM_CAS_HASH_LEN]);

/*
 * Decrement the refcount of an existing CAS entry. The entry remains in
 * the index even if refcount hits 0; explicit GC via `stm_cas_gc` is
 * required to remove it (so a subsequent migrate hitting the same hash
 * can re-bump the refcount before GC fires, avoiding spurious
 * allocate→free→allocate churn).
 *
 * Refusals:
 *   - hash == NULL (STM_EINVAL).
 *   - hash not present (STM_ENOENT).
 *   - refcount already 0 (STM_EINVAL — caller bug).
 *
 * Models cas.tla::RehydrateOnWrite + DeleteFile's per-hash decrement.
 */
STM_MUST_USE
stm_status stm_cas_deref(stm_cas_index *idx,
                          const uint8_t content_hash[STM_CAS_HASH_LEN]);

/*
 * Remove a CAS entry whose refcount has fallen to 0. Returns the entry's
 * paddrs in `out_paddrs[0..*out_n_paddrs)` (caller-owned `out_paddrs`
 * buffer of length `paddrs_cap`; STM_ERANGE if cap is too small).
 *
 * Caller MUST route each returned paddr through the allocator's free
 * path (`stm_alloc_free` or refcount-aware drop) AFTER the GC commits
 * to disk.
 *
 * Refusals:
 *   - hash == NULL (STM_EINVAL).
 *   - hash not present (STM_ENOENT).
 *   - refcount > 0 (STM_EBUSY — entry still has live cold-extent refs).
 *   - paddrs_cap < entry's n_replicas (STM_ERANGE).
 *
 * Models cas.tla::GC.
 */
STM_MUST_USE
stm_status stm_cas_gc(stm_cas_index *idx,
                        const uint8_t content_hash[STM_CAS_HASH_LEN],
                        uint64_t *out_paddrs, size_t paddrs_cap,
                        size_t *out_n_paddrs);

/* ========================================================================= */
/* Lookup + iteration.                                                         */
/* ========================================================================= */

/*
 * Look up the CAS entry at `content_hash`. Returns STM_OK with
 * `*out_record` filled on hit; STM_ENOENT on miss; STM_EINVAL on bad
 * args.
 */
STM_MUST_USE
stm_status stm_cas_lookup(const stm_cas_index *idx,
                            const uint8_t content_hash[STM_CAS_HASH_LEN],
                            stm_cas_record *out_record);

/*
 * Iterate every entry in hash-ascending order. Returns false from the
 * callback to terminate early. Callback runs under the index's mutex;
 * MUST NOT call back into stm_cas_* (deadlock — ERRORCHECK mutex
 * returns EDEADLK on reentry). The record pointer passed to the
 * callback is valid only for the callback's lifetime.
 *
 * Returns: STM_OK on completion, STM_EINVAL on bad args, STM_ENOMEM if
 * the temporary order index fails to allocate.
 */
typedef bool (*stm_cas_iter_cb)(const stm_cas_record *r, void *ctx);

STM_MUST_USE
stm_status stm_cas_iter(const stm_cas_index *idx,
                          stm_cas_iter_cb cb, void *ctx);

/*
 * Count CAS entries.
 */
STM_MUST_USE
stm_status stm_cas_count(const stm_cas_index *idx, size_t *out_count);

/* ========================================================================= */
/* Persistence (P7-CAS, v18).                                                  */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_cas_index_set_storage(stm_cas_index *idx,
                                        stm_bdev *bdev_0,
                                        stm_bootstrap *boot_0);

STM_MUST_USE
stm_status stm_cas_index_set_crypt_ctx(stm_cas_index *idx,
                                          const uint8_t *metadata_key,
                                          const uint64_t pool_uuid[2],
                                          const uint64_t device_uuid_0[2]);

/*
 * Hydrate the index from on-disk state. Same semantics as
 * stm_extent_index_load_at — wipes existing in-RAM state, replaces with
 * on-disk contents, sets dirty=false on success.
 *
 * Returns STM_OK on full hydration; STM_ECORRUPT on Merkle mismatch or
 * malformed entries (zero hash, zero length, zero refcount, paddr
 * collision among loaded entries); STM_EBADTAG on AEAD failure;
 * STM_EINVAL on missing storage / crypt ctx.
 */
STM_MUST_USE
stm_status stm_cas_index_load_at(stm_cas_index *idx,
                                    uint64_t root_paddr, uint64_t root_gen,
                                    const uint8_t expected_csum[32]);

/*
 * Serialize current state, AEAD-encrypt, write a fresh root, free the
 * previous root's nodes (if any), return new (paddr, csum). Idempotent
 * when clean.
 */
STM_MUST_USE
stm_status stm_cas_index_commit(stm_cas_index *idx,
                                   uint64_t committed_gen,
                                   uint64_t *out_root_paddr,
                                   uint8_t out_root_csum[32]);

STM_MUST_USE
stm_status stm_cas_index_get_root(const stm_cas_index *idx,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]);

STM_MUST_USE
stm_status stm_cas_index_get_gen(const stm_cas_index *idx,
                                    uint64_t *out_root_gen);

STM_MUST_USE
stm_status stm_cas_index_verify(const stm_cas_index *idx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CAS_H */
