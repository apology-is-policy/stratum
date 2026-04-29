/* SPDX-License-Identifier: ISC */
/*
 * Data-extent AEAD wrapper (Phase 4 chunk P4-5 stub).
 *
 *   see ARCHITECTURE §7.5 (AEAD construction) + §7.6.1 (AD struct).
 *
 * Stub scope (MVP for the Phase 4 exit bullet "encrypted writes
 * round-trip correctly with AEGIS-256 and XChaCha20-SIV"):
 *
 *   - Single-buffer encrypt / decrypt of a data extent.
 *   - stm_ad_extent binds ciphertext to (pool, dataset, ino,
 *     offset, content_kind). Any mismatch → STM_EBADTAG.
 *   - Mode picker — AEGIS-256 or XChaCha20-SIV per caller's choice
 *     (which in turn is resolved from pool + per-dataset override
 *     per ARCH §7.5.3).
 *   - No extent manager — the caller owns paddrs, no on-disk
 *     index. Phase 6's extent-layer elaborates.
 *
 * Nonce construction matches P4-3b's metadata-node wrapper
 * (paddr || gen || pool_uuid). Safe: bootstrap's deferred-free
 * guarantees (paddr, gen) unique within a pool's lifetime. This is
 * a subset of ARCH §7.4.1's (paddr, txg, seq_in_txg, reserved,
 * pool_uuid-high) — see phase4-status.md "Known deltas from ARCH"
 * for the rationale.
 */
#ifndef STRATUM_V2_EXTENT_H
#define STRATUM_V2_EXTENT_H

#include <stratum/crypto.h>
#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev       stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap  stm_bootstrap;

/* ARCH §7.6.1 AD magic / version. */
#define STM_AD_MAGIC_EXTENT     UINT32_C(0x44545845)   /* 'EXTD' */
#define STM_AD_VERSION_EXTENT   1u

/* 56-byte AD struct per ARCH §7.6.1. Every field little-endian on
 * disk; `stm_ad_extent_pack` serializes. Binding a write to its
 * (pool, dataset, ino, offset) — swapping any field breaks decrypt. */
typedef struct {
    uint32_t magic;            /* STM_AD_MAGIC_EXTENT */
    uint32_t version;          /* STM_AD_VERSION_EXTENT */
    uint64_t pool_uuid[2];     /* 16 bytes */
    uint64_t dataset_id;
    uint64_t ino;
    uint64_t offset;           /* byte offset within file */
    uint64_t content_kind;     /* 0 = file data, 1 = xattr, 2 = inline, ... */
} stm_ad_extent;

#define STM_AD_EXTENT_PACKED_LEN  56u

/* Pack an stm_ad_extent into 56 little-endian bytes. */
void stm_ad_extent_pack(const stm_ad_extent *ad,
                         uint8_t out[STM_AD_EXTENT_PACKED_LEN]);

/* ========================================================================= */
/* Encrypt / decrypt.                                                         */
/* ========================================================================= */

/*
 * Encrypt `plaintext` (of `pt_len` bytes) under (`mode`, `key`) into
 * `out` (of `out_cap` bytes). `out_cap` must be at least
 * `pt_len + stm_aead_tag_len(mode)`.
 *
 * Nonce bound to (paddr, gen, cx->pool_uuid). AD bound to the
 * caller's `ad` struct.
 *
 * Returns STM_OK on success, STM_ERANGE if out_cap is too small,
 * STM_EINVAL for NULL params.
 */
STM_MUST_USE
stm_status stm_extent_encrypt(stm_aead_mode mode,
                               const uint8_t *key,
                               uint64_t paddr, uint64_t gen,
                               const stm_ad_extent *ad,
                               const void *plaintext, size_t pt_len,
                               void *out, size_t out_cap,
                               size_t *out_len);

/*
 * Decrypt `ct_and_tag` (ciphertext followed by an inline tag) into
 * `out_plaintext`. `out_pt_cap` must be at least
 * `ct_and_tag_len - stm_aead_tag_len(mode)`.
 *
 * Returns STM_EBADTAG if the AD or nonce mismatches what the
 * encrypt call used (tampered ciphertext, wrong paddr / gen / AD
 * field).
 */
STM_MUST_USE
stm_status stm_extent_decrypt(stm_aead_mode mode,
                               const uint8_t *key,
                               uint64_t paddr, uint64_t gen,
                               const stm_ad_extent *ad,
                               const void *ct_and_tag, size_t ct_and_tag_len,
                               void *out_plaintext, size_t out_pt_cap,
                               size_t *out_pt_len);

/* =========================================================================
 * Extent INDEX (P7-2 in-RAM MVP).
 *
 *   see v2/specs/extent.tla — formal model.
 *   see docs/ARCHITECTURE.md §11.6 — extent record + extent tree key.
 *   see docs/ROADMAP-V2.md §10 — Phase 7 (cold tier + features).
 *
 * The extent index tracks the LOGICAL data layer between datasets and
 * stored bytes — for every (dataset_id, ino) pair, an ordered set of
 * extent records that map a byte range of the file to a paddr in the
 * pool. extent.tla pins the load-bearing invariant `NoOverlapWithinIno`
 * — two distinct extents in the same (ds, ino) cannot cover overlapping
 * byte ranges. Other captured invariants:
 *
 *   - LengthPositive: every extent has length ≥ 1 (zero-length is a
 *     hole, not an extent).
 *   - BirthTxgBound: every extent's gen ≤ current_txg.
 *   - PaddrFreshness (live-paddr interpretation): no two LIVE extents
 *     share a paddr at any time. The C impl narrows the spec's
 *     monotonic `used_paddrs` to "paddrs in current extents"; this
 *     pins the safety property the spec actually needs and composes
 *     with allocator-level cross-gen reuse (allocator.tla::
 *     NoReuseInSameGen) for end-to-end (paddr, gen) nonce uniqueness.
 *
 * Storage backend (P7-2): in-RAM linear array of extent records.
 * O(n) lookup; persistent storage (per-inode Bε-tree under
 * ub_extent_root) is a follow-on chunk (P7-3) with a corresponding
 * STM_UB_VERSION bump.
 *
 * Out of scope for this chunk:
 *   - Persistence (P7-3 — needs format break).
 *   - Compression (`se_clen_and_comp`) — metadata-only field, doesn't
 *     affect extent identity (extent.tla "Intentionally OUT OF SCOPE").
 *   - Per-extent integrity (xxHash3 vs AEAD tag) — covered by AEAD
 *     model + ARCH §7.11.2.
 *   - Reflinks / refcount-bump path — Phase 7 §10.4.
 *   - CAS / cold-tier extents — Phase 7 §10.1 (separate spec).
 *   - Coalescing — quality-of-implementation; correctness is preserved
 *     by NoOverlapWithinIno regardless of whether adjacent extents
 *     coalesce.
 *   - Partial-extent split on Truncate (truncating mid-extent) — this
 *     MVP only drops fully-past-truncation extents. Production needs
 *     to shrink the crossing extent's length or split it; spec
 *     models this as a simplification too.
 *
 * Composition with snapshots: when Overwrite / Truncate / DeleteFile
 * drop a live extent, the dropped paddr flows to the snapshot dead-
 * list machinery via `stm_snapshot_index_overwrite_block` (per
 * dead_list.tla::OverwriteBlock). The extent module returns dropped
 * paddrs to the caller; the caller routes each to the snapshot index.
 *
 * Thread safety: every public API holds an internal pthread mutex
 * for the duration of the call. ERRORCHECK type — contract violations
 * (cb-from-iter reentrancy) abort with EDEADLK.
 * ========================================================================= */

/* Maximum number of replica paddrs per extent (P7-6 / v13). Sized at
 * 4 to comfortably cover mirror-N pools up to N=4 without a record
 * format change; production mirror configs are typically N ∈ {2, 3}.
 * The on-disk format reserves all 4 slots regardless of n_replicas;
 * unused slots store 0 (sentinel). */
#define STM_EXTENT_MAX_REPLICAS  4u

/* P7-CAS / v18: extent_kind discriminator at on-disk value byte 0.
 *
 *   STM_EXTENT_KIND_HOT  (0x01) — paddr-addressed; replicas[0..n_replicas)
 *                                 hold the AEAD ciphertext+tag of the
 *                                 plaintext at this byte range.
 *   STM_EXTENT_KIND_COLD (0x02) — content-addressed (CAS tier); the
 *                                 chunk's plaintext is BLAKE3-hashed and
 *                                 the hash names a CAS index entry whose
 *                                 replicas hold the AEAD ciphertext under
 *                                 CAS AD (ARCH §7.6.3).
 *
 * v17 had no kind byte (byte 0 = n_replicas, range 1..4). v18 mounts
 * of v17 pools rely on the SB version check rejecting first; in-place
 * forward-compat at the value layer is NOT supported. */
typedef enum {
    STM_EXTENT_KIND_HOT  = 0x01u,
    STM_EXTENT_KIND_COLD = 0x02u,
} stm_extent_kind;

/* BLAKE3-256 hash length (32 bytes). For COLD extents, names the CAS
 * index entry whose backing replicas hold the chunk's ciphertext. */
#define STM_EXTENT_HASH_LEN     32u

/*
 * Per-extent record. Mirrors ARCH §11.6.1 stm_extent_v2 in spirit —
 * stores the modeled fields (ds, ino, off, len, replicas, gen). The
 * `paddrs[0..n_replicas-1]` array carries every replica paddr (each
 * on a distinct device per the pool's redundancy profile); the
 * higher slots `[n_replicas..STM_EXTENT_MAX_REPLICAS)` are zero
 * (sentinel) and do not refer to any block. Compression / xxh
 * fields are stored on disk (P7-3 layout) but the in-RAM MVP only
 * carries the logical-correctness fields modeled by extent.tla.
 *
 * Replication semantics (P7-6): each replica holds a bytewise-
 * identical copy of the AEAD ciphertext+tag of the same plaintext,
 * encrypted ONCE with the canonical nonce (paddrs[0], gen). The
 * scrub β cb walks the replica array; on AEAD-tag failure at any
 * replica, rewrites from a verified replica per bptr.tla.
 */
typedef struct {
    uint64_t dataset_id;                          /* > 0 */
    uint64_t ino;                                 /* > 0 */
    uint64_t off;                                 /* byte offset within file */
    uint64_t len;                                 /* extent length in bytes; ≥ 1 */
    /* P7-CAS / v18: kind discriminator. HOT extents use paddrs[]; COLD
     * extents use content_hash[]. STM_EXTENT_KIND_HOT is the default;
     * stm_extent_write / _overwrite / _reflink stamp HOT, while the
     * sync layer's MigrateToCold path uses stm_extent_write_cold. */
    stm_extent_kind kind;
    uint8_t  n_replicas;                          /* HOT: 1..STM_EXTENT_MAX_REPLICAS; COLD: 0 */
    uint64_t paddrs[STM_EXTENT_MAX_REPLICAS];     /* HOT: valid 0..n_replicas-1; COLD: zeros */
    uint8_t  content_hash[STM_EXTENT_HASH_LEN];   /* COLD: BLAKE3-256; HOT: zeros */
    uint64_t gen;                                 /* write_gen; nonce uniqueness */
    /* P7-10: key_id of the dataset DEK that AEAD-encrypted the extent.
     * Resolved at read time via stm_sync_get_dek(dataset_id, key_id).
     * key_id 0 is the dataset's first DEK; rotation advances by 1.
     * Stored on disk at value offset 56 (le64), repurposing the always-
     * zero `xxh` slot from v14. extent.tla::ExtentRec.key_id (typed). */
    uint64_t key_id;
    /* P7-16: origin (dataset_id, ino, offset) at which this extent's
     * AEAD ciphertext was first written. For freshly-written extents
     * origin = (dataset_id, ino, off); for reflinked extents origin is
     * INHERITED from the source — so two reflink-siblings sharing the
     * same `paddrs` reconstruct the SAME AEAD AD at read/scrub time
     * and AEGIS-256 verify succeeds across the share. Tampering with
     * origin requires defeating the metadata-tree (btnode) AEAD; the
     * field is no weaker than the live (dataset_id, ino, off) was for
     * non-reflinked extents. extent.tla::ExtentRec.origin_*. */
    uint64_t origin_dataset_id;
    uint64_t origin_ino;
    uint64_t origin_off;
    /* P7-16 / R48 P0-1: link_gen — gen at which THIS record was
     * inserted into the live extent index (separate from `gen` which
     * is the AEAD encryption gen, inherited from src for reflinks).
     * Used by the send/recv pipeline's incremental gen filter so a
     * reflinked record created in window (S_from, S_to] is included
     * even though its `gen` (= src's AEAD gen) may predate
     * S_from.extent_txg. For freshly-written extents link_gen == gen;
     * for reflinked extents link_gen == current_txg-at-reflink-time
     * (caller-provided to stm_extent_reflink). */
    uint64_t link_gen;
    /* P7-CAS-11: per-COLD-extent read-frequency counter for the
     * promotion (cold → hot) heuristic. Incremented by
     * stm_sync_read_extent_locked's COLD branch after every successful
     * decrypt; reset to 1 if the record's last_read_gen is more than
     * `decay_window` txgs behind the current gen (windowed-counting
     * scheme; v1 simple, v2 may switch to exponential decay). HOT
     * extents always have read_count == 0; the on-disk decoder enforces
     * this via the bytes-96..108 anti-tamper check. Saturating uint32:
     * a cold extent read 4 billion times stays at UINT32_MAX rather
     * than wrapping (`bytes_promoted` accounting still scales). */
    uint32_t read_count;
    /* P7-CAS-11: gen at which read_count was last incremented (or
     * reset). Used by the promote-policy step's recency filter
     * (`min_recency_txgs` — only inos with last_read_gen >= cutoff
     * are eligible). HOT records always have last_read_gen == 0
     * (encoder + decoder enforce). Freshly-migrated COLD records
     * have last_read_gen == 0 (sentinel: "never read yet") — the
     * struct initializer in stm_extent_migrate_to_cold leaves the
     * field zero, and the first read after migration triggers the
     * sentinel-reset path in stm_extent_record_promote_read_hit
     * (count = 1, last_read_gen = current_gen). With
     * last_read_gen == 0 the eligibility check
     * `last_read_gen >= cutoff` necessarily fails, so a never-read
     * extent is never a promotion candidate — correct behavior. */
    uint64_t last_read_gen;
} stm_extent_record;

struct stm_extent_index;
typedef struct stm_extent_index stm_extent_index;

/*
 * Create a new extent index. `current_txg` becomes the initial txg
 * counter; later operations advance it via _advance_txg.
 *
 * Returns STM_OK on success. STM_EINVAL on NULL out. STM_ENOMEM if
 * allocation fails.
 */
STM_MUST_USE
stm_status stm_extent_index_create(uint64_t current_txg,
                                      stm_extent_index **out);

/*
 * Release the index. Frees all extent records. Caller must ensure no
 * concurrent access.
 */
void stm_extent_index_close(stm_extent_index *idx);

/*
 * Read the current txg.
 */
STM_MUST_USE
stm_status stm_extent_index_current_txg(const stm_extent_index *idx,
                                           uint64_t *out_txg);

/*
 * Advance the internal txg counter. Refuses regression
 * (new_txg < current_txg) with STM_EINVAL. Equal value is a no-op.
 *
 * Models extent.tla::AdvanceTxg.
 */
STM_MUST_USE
stm_status stm_extent_index_advance_txg(stm_extent_index *idx,
                                           uint64_t new_txg);

/*
 * Insert a fresh extent for (`dataset_id`, `ino`) covering [`off`,
 * `off`+`len`) backed by the replica set `paddrs[0..n_paddrs)`,
 * stamped with `write_gen`. No existing extent for (ds, ino) may
 * overlap [off, off+len). All paddrs in the new replica set must be
 * fresh from any live extent's replica set (extent.tla::
 * LiveReplicasDisjoint).
 *
 * Refusals:
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - len == 0 (STM_EINVAL — extent.tla::LengthPositive).
 *   - n_paddrs < 1 OR n_paddrs > STM_EXTENT_MAX_REPLICAS (STM_EINVAL —
 *     extent.tla::ReplicasNonEmpty / ReplicaCountBounded).
 *   - any paddrs[i] == 0 (STM_EINVAL — reserved sentinel).
 *   - any pair paddrs[i] == paddrs[j] for i != j (STM_EINVAL —
 *     within-replica-set distinctness).
 *   - write_gen > current_txg (STM_EINVAL — extent.tla::BirthTxgBound).
 *   - any paddrs[i] already used by a live extent's replica set
 *     (STM_EEXIST — extent.tla::LiveReplicasDisjoint).
 *   - any existing live extent of (ds, ino) overlaps [off, off+len)
 *     (STM_EEXIST — extent.tla::NoOverlapWithinIno).
 *   - off + len overflows uint64 (STM_EOVERFLOW).
 *
 * Models extent.tla::Write. Pure insert — no extent is dropped.
 * Use stm_extent_overwrite for the COW path.
 */
STM_MUST_USE
stm_status stm_extent_write(stm_extent_index *idx,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t off, uint64_t len,
                              const uint64_t *paddrs, size_t n_paddrs,
                              uint64_t write_gen, uint64_t key_id);

/*
 * COW overwrite: drop every live extent of (ds, ino) overlapping
 * [`off`, `off`+`len`), then insert a fresh extent backed by the
 * replica set `new_paddrs[0..n_new_paddrs)` stamped with `write_gen`.
 *
 * Refusals: same as stm_extent_write, plus:
 *   - any new_paddrs[i] equals any paddr in any to-be-dropped
 *     extent's replica set (cycle — caller bug). Refused with
 *     STM_EINVAL.
 *
 * On success:
 *   - *out_dropped_paddrs receives a malloc'd array of every paddr
 *     in every dropped extent's replica set, flattened (caller owns;
 *     MUST `free()`). Caller MUST route each via
 *     `stm_snapshot_index_overwrite_block` (composes with
 *     dead_list.tla::OverwriteBlock).
 *   - *out_n_dropped is the array length (sum of replica counts of
 *     dropped extents).
 *   - When zero extents were dropped (overwrite into a hole),
 *     *out_dropped_paddrs is NULL and *out_n_dropped is 0.
 *
 * On failure, *out_dropped_paddrs is NULL and *out_n_dropped is 0;
 * the index is unchanged.
 *
 * Models extent.tla::Overwrite.
 */
STM_MUST_USE
stm_status stm_extent_overwrite(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  const uint64_t *new_paddrs,
                                  size_t n_new_paddrs,
                                  uint64_t write_gen, uint64_t key_id,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped);

/*
 * Truncate (ds, ino) to `new_size` bytes: drop every live extent
 * whose off ≥ new_size. Partial-extent shrinking (an extent crossing
 * the boundary) is NOT modeled in this MVP — see "OUT OF SCOPE" in
 * the module preamble. Spec: extent.tla::Truncate.
 *
 * On success:
 *   - *out_dropped_paddrs receives a malloc'd array of dropped paddrs
 *     (caller owns; MUST `free()`).
 *   - *out_n_dropped is the array length.
 *   - If nothing was dropped, *out_dropped_paddrs is NULL and
 *     *out_n_dropped is 0.
 *
 * Refusals:
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_extent_truncate(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t new_size,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped);

/*
 * P7-12: peek-only count of past-truncation extents + their total
 * replicas, without mutating the index. Returns the exact buffer
 * sizes a subsequent `stm_extent_truncate_into` will need. Pure
 * read; idempotent.
 *
 * If nothing would be dropped, `*out_n_extents = *out_n_replicas_total
 * = 0`. Used by `stm_sync_truncate` to pre-allocate Phase 3 buffers
 * BEFORE Phase 2's overwrite, eliminating the R41 P3-1 case-(b)
 * partial-state hazard (Phase 3 ENOMEM after Phase 2 succeeded).
 */
STM_MUST_USE
stm_status stm_extent_truncate_peek(const stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t new_size,
                                       size_t *out_n_extents,
                                       size_t *out_n_replicas_total);

/*
 * P7-12: truncate using caller-provided pre-allocated buffers.
 *
 * `drop_idx_buf[drop_idx_cap]` is internal scratch (records the
 * dropped record indices for the compacting walk). `paddrs_buf
 * [paddrs_cap]` is the output (flattened replica paddrs of every
 * dropped extent). Both buffers are caller-owned; this function
 * NEVER allocates.
 *
 * Sizing: caller MUST first call `stm_extent_truncate_peek` and
 * allocate `drop_idx_cap >= out_n_extents`, `paddrs_cap >=
 * out_n_replicas_total`. Bigger is fine. Smaller surfaces as
 * STM_ERANGE — atomic, the index is unchanged.
 *
 * Atomicity property (R41 P3-1 case (b) closure): if peek-then-
 * allocate-then-into is invoked sequentially under one outer lock
 * (stm_sync_truncate's pattern post-P7-11 single-lock-span),
 * `_into` is fault-free for the cap match: it cannot return
 * STM_ENOMEM because it never allocates. The whole truncate becomes
 * commit-atomic w.r.t. the in-RAM extent_idx.
 *
 * Returns:
 *   STM_OK         — drops committed; *out_n_dropped populated;
 *                     paddrs_buf[0..*out_n_dropped) holds dropped
 *                     paddrs in record-then-replica order.
 *   STM_ERANGE     — drop_idx_cap or paddrs_cap insufficient;
 *                     index unchanged; *out_n_dropped = 0.
 *   STM_EINVAL     — bad args (NULL idx/buffers/out, zero ds/ino).
 */
STM_MUST_USE
stm_status stm_extent_truncate_into(stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t new_size,
                                       size_t *drop_idx_buf, size_t drop_idx_cap,
                                       uint64_t *paddrs_buf, size_t paddrs_cap,
                                       size_t *out_n_dropped);

/*
 * Drop every live extent for (ds, ino). Used on file unlink.
 *
 * Same out-arg semantics as truncate. Models extent.tla::DeleteFile.
 */
STM_MUST_USE
stm_status stm_extent_delete_file(stm_extent_index *idx,
                                    uint64_t dataset_id, uint64_t ino,
                                    uint64_t **out_dropped_paddrs,
                                    size_t *out_n_dropped);

/*
 * P7-16: Reflink — insert a new extent record at (`dst_dataset_id`,
 * `dst_ino`, `dst_off`) inheriting `paddrs[0..n_paddrs)`, `gen`,
 * `key_id`, AND the (`origin_dataset_id`, `origin_ino`, `origin_off`)
 * triple from a SOURCE extent. The resulting record shares its replica
 * set with the source — both extents AEAD-decrypt under the same AD
 * because `origin_*` is invariant across reflink siblings (extent.tla
 * ::SharedReplicasAreCohabit).
 *
 * Caller MUST have already bumped allocator refcounts on each paddr —
 * this API just inserts the record. Atomicity at the sync layer.
 *
 * Refusals:
 *   - dst_dataset_id == 0 OR dst_ino == 0 (STM_EINVAL).
 *   - origin_dataset_id == 0 OR origin_ino == 0 (STM_EINVAL — origin
 *     fields must be valid).
 *   - len == 0 (STM_EINVAL — extent.tla::LengthPositive).
 *   - n_paddrs out of bounds OR any paddr == 0 OR within-set duplicate
 *     (STM_EINVAL).
 *   - dst overlap: an existing live extent at (dst_dataset_id, dst_ino)
 *     overlaps [dst_off, dst_off + len) (STM_EEXIST).
 *   - SharedReplicasAreCohabit violation: any paddr in the new replica
 *     set already lives in another extent record whose (replicas, gen,
 *     key_id, origin_*) tuple differs (STM_EEXIST). Catches the
 *     "partial-overlap" and "different-origin" buggy patterns.
 *
 * Models extent.tla::Reflink. Caller-provided origin lets the sync
 * layer pass the SRC's origin (inherited) rather than the dst's
 * live identity (a buggy "rotates origin" implementation).
 */
STM_MUST_USE
stm_status stm_extent_reflink(stm_extent_index *idx,
                                uint64_t dst_dataset_id, uint64_t dst_ino,
                                uint64_t dst_off, uint64_t len,
                                const uint64_t *paddrs, size_t n_paddrs,
                                uint64_t gen, uint64_t key_id,
                                uint64_t origin_dataset_id,
                                uint64_t origin_ino,
                                uint64_t origin_off,
                                uint64_t link_gen);

/*
 * P7-CAS: insert a COLD extent record at (`dataset_id`, `ino`, `off`)
 * covering [`off`, `off`+`len`) referencing `content_hash` (the BLAKE3-
 * 256 of the chunk's plaintext). The CAS index entry at `content_hash`
 * MUST exist + its refcount MUST already be bumped — this API just
 * inserts the extent record. Atomicity at the sync layer.
 *
 * `origin_*` is the (dataset_id, ino, off) at which the chunk's
 * plaintext was first stored (== the live position for fresh
 * migrations; differs only for reflinked-then-migrated extents in
 * future cross-dataset paths).
 *
 * Refusals:
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - len == 0 (STM_EINVAL — extent.tla::LengthPositive).
 *   - content_hash all-zero (STM_EINVAL — reserved sentinel).
 *   - gen > current_txg (STM_EINVAL — extent.tla::BirthTxgBound).
 *   - off + len overflows uint64 (STM_EOVERFLOW).
 *   - any existing live extent of (ds, ino) overlaps [off, off+len)
 *     (STM_EEXIST — extent.tla::NoOverlapWithinIno; cas.tla::
 *     NoOverlapWithinIno extends to cover hot+cold).
 *
 * Models cas.tla::MigrateToCold's cold-extent-record insert. Pure
 * insert — no extent is dropped. The caller (sync_migrate_to_cold)
 * separately drops the source hot extent before invoking this on a
 * per-chunk basis.
 */
STM_MUST_USE
stm_status stm_extent_write_cold(stm_extent_index *idx,
                                    uint64_t dataset_id, uint64_t ino,
                                    uint64_t off, uint64_t len,
                                    const uint8_t content_hash[STM_EXTENT_HASH_LEN],
                                    uint64_t gen, uint64_t key_id,
                                    uint64_t origin_dataset_id,
                                    uint64_t origin_ino,
                                    uint64_t origin_off,
                                    uint64_t link_gen);

/*
 * P7-CAS-2: atomic per-extent hot→cold swap. Drops the existing live
 * HOT extent at exactly (`dataset_id`, `ino`, `off`) (matching `len`)
 * AND inserts a COLD extent at the same coordinates referencing
 * `content_hash`. Returns the dropped HOT extent's replica paddrs in
 * `out_paddrs[0..*out_n_replicas)` (caller-owned cap of
 * STM_EXTENT_MAX_REPLICAS) for routing through the sync layer's
 * refcount-aware drop helper AFTER this call returns.
 *
 * Atomic at the index level: the swap holds extent_idx.lock across both
 * the drop and the insert, so no observer ever sees a state where the
 * (ds, ino, off, len) range is empty (which would let a concurrent
 * inserter slip in). The swap therefore preserves NoOverlapWithinIno
 * across the transition.
 *
 * The caller has already (a) read+decrypted the source HOT extent's
 * plaintext, (b) BLAKE3-hashed it to `content_hash`, (c) populated
 * the CAS index entry at `content_hash` (insert on miss; ref-bump on
 * hit), and (d) written the chunk's ciphertext to the CAS replicas
 * (on miss). This API focuses on the extent-tree mutation only.
 *
 * `gen` / `key_id` / `origin_*` / `link_gen` are stamped on the new
 * COLD extent record. For fresh migrations origin_* equals the live
 * position; key_id matches the source HOT extent's stamped key_id (so
 * subsequent rehydrate can re-encrypt under a fresh key without
 * re-deriving). `link_gen` mirrors the reflink contract (gen at which
 * THIS record was inserted into the live extent index, not the AEAD
 * gen of the underlying chunk).
 *
 * Refusals:
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - origin_dataset_id == 0 OR origin_ino == 0 (STM_EINVAL).
 *   - len == 0 (STM_EINVAL — extent.tla::LengthPositive).
 *   - content_hash all-zero (STM_EINVAL — reserved sentinel).
 *   - gen > current_txg OR link_gen > current_txg (STM_EINVAL —
 *     extent.tla::BirthTxgBound).
 *   - off + len OR origin_off + len overflows uint64 (STM_EOVERFLOW /
 *     STM_EINVAL).
 *   - No HOT extent at exactly (ds, ino, off) (STM_ENOENT).
 *   - The matching extent has a different `len` than the caller
 *     supplied (STM_EINVAL — partial migrate not modeled).
 *   - The matching extent is COLD already (STM_EINVAL — caller bug;
 *     COLD extents go through rehydrate, not migrate).
 *   - out_paddrs == NULL OR out_n_replicas == NULL (STM_EINVAL).
 *
 * On STM_OK: out_paddrs[0..*out_n_replicas) holds the dropped HOT
 * extent's replica paddrs in the original record's slot order. Caller
 * MUST route each through `sync_drop_paddr_locked` (P7-16 / R48 P1-1
 * refcount-aware) BEFORE the next sync_commit. On any non-OK return
 * the index is unchanged and *out_n_replicas is 0.
 *
 * Models cas.tla::MigrateToCold (the "drop hot, insert cold" core
 * transition); the AEAD chunk write + CAS index update + paddr drop-
 * route compose at the sync layer (`stm_sync_migrate_to_cold`).
 */
STM_MUST_USE
stm_status stm_extent_migrate_to_cold(stm_extent_index *idx,
                                         uint64_t dataset_id, uint64_t ino,
                                         uint64_t off, uint64_t len,
                                         const uint8_t content_hash[STM_EXTENT_HASH_LEN],
                                         uint64_t gen, uint64_t key_id,
                                         uint64_t origin_dataset_id,
                                         uint64_t origin_ino,
                                         uint64_t origin_off,
                                         uint64_t link_gen,
                                         uint64_t out_paddrs[STM_EXTENT_MAX_REPLICAS],
                                         uint8_t  *out_n_replicas);

/*
 * P7-CAS-11: atomic per-extent cold→hot swap (the inverse of
 * stm_extent_migrate_to_cold). Drops the existing live COLD extent at
 * exactly (`dataset_id`, `ino`, `off`) (matching `len`) AND inserts a
 * HOT extent at the same coordinates referencing the caller-provided
 * fresh replica set. Returns the dropped COLD extent's content_hash
 * via `out_content_hash` for the caller to route through
 * `stm_cas_deref` AFTER this call returns.
 *
 * The caller has already (a) read+decrypted the cold chunk's
 * plaintext via the source CAS replicas + pool metadata key + stm_ad_cas,
 * (b) reserved fresh `new_paddrs` from the allocator, and (c) AEAD-
 * encrypted the same plaintext under the new (paddr_0, gen) nonce +
 * stm_ad_extent + the dataset's CURRENT DEK, and (d) replicated the
 * ciphertext bytewise to all `new_paddrs`. This API mutates the
 * extent-tree only.
 *
 * Atomic at the index level: the swap holds extent_idx.lock across both
 * the drop and the insert, so no observer ever sees a state where the
 * (ds, ino, off, len) range is empty (which would let a concurrent
 * inserter slip in). Preserves NoOverlapWithinIno across the
 * transition.
 *
 * `gen` / `key_id` / `origin_*` / `link_gen` are stamped on the new
 * HOT extent record. For freshly-promoted extents origin_* equals the
 * live position (the previous cold record's origin is INHERITED from
 * the original HOT-side write — but on promote we re-AEAD-encrypt
 * under fresh paddrs so the new HOT extent's AD is reconstructible
 * from the live identity, the same as a fresh stm_extent_write would
 * stamp). `link_gen` mirrors the reflink contract (gen at which THIS
 * record was inserted into the live extent index, NOT the AEAD gen
 * of the underlying ciphertext).
 *
 * Refusals:
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - origin_dataset_id == 0 OR origin_ino == 0 (STM_EINVAL).
 *   - len == 0 (STM_EINVAL — extent.tla::LengthPositive).
 *   - n_replicas not in [1, STM_EXTENT_MAX_REPLICAS] (STM_EINVAL).
 *   - any new_paddrs[i] == 0 OR within-set duplicate (STM_EINVAL).
 *   - gen > current_txg OR link_gen > current_txg (STM_EINVAL).
 *   - off + len OR origin_off + len overflows uint64 (STM_EOVERFLOW).
 *   - No COLD extent at exactly (ds, ino, off) (STM_ENOENT).
 *   - The matching extent has a different `len` than the caller
 *     supplied (STM_EINVAL — partial promote not modeled).
 *   - The matching extent is HOT already (STM_EINVAL — caller bug;
 *     HOT extents need no promotion).
 *   - out_content_hash == NULL (STM_EINVAL).
 *
 * On STM_OK: out_content_hash holds the dropped COLD extent's
 * content_hash. Caller MUST route through `stm_cas_deref` BEFORE the
 * next sync_commit so the cas refcount stays consistent with the live
 * cold extent count. On any non-OK return the index is unchanged and
 * out_content_hash is zeroed.
 *
 * Models cas.tla::RehydrateOnWrite (the "drop cold, insert hot" core
 * transition); the AEAD chunk read + new HOT replica reservation +
 * cas index deref compose at the sync layer (stm_sync_promote_to_hot).
 */
STM_MUST_USE
stm_status stm_extent_promote_swap_to_hot(stm_extent_index *idx,
                                            uint64_t dataset_id, uint64_t ino,
                                            uint64_t off, uint64_t len,
                                            const uint64_t *new_paddrs,
                                            uint8_t n_replicas,
                                            uint64_t gen, uint64_t key_id,
                                            uint64_t origin_dataset_id,
                                            uint64_t origin_ino,
                                            uint64_t origin_off,
                                            uint64_t link_gen,
                                            uint8_t out_content_hash[STM_EXTENT_HASH_LEN]);

/*
 * P7-CAS-11: bump the read counter on the COLD extent record at
 * (`dataset_id`, `ino`, `off`). Called by the sync layer's COLD-read
 * path (stm_sync_read_extent_locked's COLD branch) after every
 * successful chunk decrypt. Windowed-count semantics:
 *   - If `current_gen - last_read_gen` exceeds `decay_window` (or if
 *     the field is at its u64 sentinel 0): reset count = 1.
 *   - Else: count = saturating_add(count, 1) (clamped at UINT32_MAX).
 *   - Either way: last_read_gen = current_gen.
 *
 * No-op (returns STM_OK) for HOT extents — the counter is COLD-only.
 *
 * Refusals:
 *   - NULL idx (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - current_gen > current_txg (STM_EINVAL — caller drift).
 *   - No live extent at (ds, ino, off): STM_OK no-op (race-tolerant —
 *     a concurrent overwrite, truncate, or migrate may have removed
 *     the record between the sync-layer read and this counter bump).
 *
 * The C-impl is best-effort: counter mutations are non-load-bearing
 * heuristic state, so spurious updates or skipped updates don't
 * compromise any soundness invariant — the worst outcome is a less-
 * accurate promotion decision. Crash before commit loses any in-flight
 * counter bumps (acceptable per the heuristic's MVP scope).
 */
STM_MUST_USE
stm_status stm_extent_record_promote_read_hit(stm_extent_index *idx,
                                                uint64_t dataset_id,
                                                uint64_t ino,
                                                uint64_t off,
                                                uint64_t current_gen,
                                                uint64_t decay_window);

/*
 * Per-chunk descriptor for `stm_extent_migrate_to_cold_chunked` (P7-CAS-4b).
 *
 * Each chunk represents one cold-extent record that the chunked-migrate
 * inserts atomically alongside the drop of the source HOT extent. The
 * chunks must tile the source range [src_off, src_off + src_len) exactly:
 *   - chunks[0].off == src_off
 *   - for i > 0: chunks[i].off == chunks[i-1].off + chunks[i-1].len
 *   - chunks[n-1].off + chunks[n-1].len == src_off + src_len
 *   - all chunks[i].len > 0
 *   - all chunks[i].content_hash non-zero (zero is the sentinel)
 *
 * Composes cas.tla::ChunkedMigrateToColdK2 (and its K-fold generalization
 * by induction on chunk count). The AEAD AD on each chunk's CAS chunk is
 * stm_ad_cas(pool_uuid, content_hash) — independent per chunk.
 */
typedef struct {
    uint64_t off;                                   /* absolute file offset */
    uint64_t len;                                   /* > 0, in bytes */
    uint8_t  content_hash[STM_EXTENT_HASH_LEN];     /* BLAKE3-256 of chunk plaintext */
} stm_extent_cold_chunk;

/*
 * Atomically replace the source HOT extent at (ds, ino, src_off, src_len)
 * with `n_chunks` COLD extent records tiling the same byte range.
 * P7-CAS-4b — the FastCDC-driven extension of `stm_extent_migrate_to_cold`.
 *
 * Behavior:
 *   - Find the matching HOT extent at (ds, ino, src_off). Verify
 *     existence, kind=HOT, len=src_len. Capture the dropped paddrs.
 *   - Pre-grow records[] capacity to fit n_chunks-1 additional records.
 *     If realloc fails, return STM_ENOMEM (no state change).
 *   - In-place overwrite the src slot with chunks[0] as a COLD record;
 *     append chunks[1..n_chunks-1] as additional COLD records.
 *   - Each chunk's record fields:
 *       (ds, ino, off, len) — from chunks[i].
 *       kind = COLD; n_replicas = 0; paddrs = zeros.
 *       content_hash = chunks[i].content_hash.
 *       gen = src_gen; key_id = src_key_id (inherited from the source
 *         HOT extent).
 *       origin_dataset_id = src_origin_dataset_id; origin_ino =
 *         src_origin_ino. origin_off = src_origin_off + (chunks[i].off
 *         - src_off) — preserving origin chains across chunked migrate.
 *       link_gen = link_gen (current_gen of the migrate operation).
 *
 * Atomicity: extent_idx.lock is held across all mutations. NoOverlap-
 * WithinIno is preserved by the tile property — chunks pairwise disjoint
 * by construction (precondition checks) and other extents in (ds, ino)
 * either don't overlap src's range (already true pre-call) or are
 * exactly src (being replaced atomically).
 *
 * Refuses with STM_EINVAL if:
 *   - idx, chunks NULL OR n_chunks == 0.
 *   - dataset_id == 0, ino == 0, src_origin_dataset_id == 0,
 *     src_origin_ino == 0, src_len == 0, any chunks[i].len == 0.
 *   - Chunks don't tile [src_off, src_off+src_len) exactly.
 *   - Any chunk's content_hash is all-zero.
 *   - src_gen > current_txg, link_gen > current_txg, src_origin_off
 *     overflows.
 *   - n_chunks == 1 (callers should use stm_extent_migrate_to_cold for
 *     the K=1 case).
 *
 * Refuses STM_ENOENT if no HOT extent exists at (ds, ino, src_off).
 * STM_ECORRUPT if the matching record's n_replicas is out of bounds.
 *
 * Returns STM_OK with out_paddrs[0..*out_n_replicas) filled with the
 * dropped HOT replicas. Caller routes each through
 * sync_drop_paddr_locked.
 */
STM_MUST_USE
stm_status stm_extent_migrate_to_cold_chunked(
        stm_extent_index *idx,
        uint64_t dataset_id, uint64_t ino,
        uint64_t src_off, uint64_t src_len,
        const stm_extent_cold_chunk *chunks, size_t n_chunks,
        uint64_t src_gen, uint64_t src_key_id,
        uint64_t src_origin_dataset_id,
        uint64_t src_origin_ino,
        uint64_t src_origin_off,
        uint64_t link_gen,
        uint64_t out_paddrs[STM_EXTENT_MAX_REPLICAS],
        uint8_t  *out_n_replicas);

/*
 * Look up the live extent of (ds, ino) covering byte offset `off`.
 * On STM_OK, *out_extent is filled. STM_ENOENT if `off` falls in a
 * hole (no extent covers it). STM_EINVAL on bad args.
 */
STM_MUST_USE
stm_status stm_extent_lookup_at(const stm_extent_index *idx,
                                   uint64_t dataset_id, uint64_t ino,
                                   uint64_t off,
                                   stm_extent_record *out_extent);

/*
 * Look up the live extent backed by `paddr`. Used by the production
 * scrub cb (P7-5) to resolve paddr → bptr at verify time: the cb is
 * invoked with a paddr and needs the (ds, ino, off, len, gen) of the
 * containing extent to reconstruct AD + nonce for AEAD verify.
 *
 * Match semantics: exact equality with `record.paddr`. Live-paddr
 * `PaddrFreshness` (the C impl's narrowing of extent.tla's
 * monotonic `used_paddrs`) guarantees at most one live extent has
 * any given paddr — first match suffices. Mid-extent paddrs (a
 * paddr in [base+1, base+nblocks)) DO NOT match — only the base
 * paddr each extent record carries does.
 *
 * Returns STM_OK with `*out_extent` filled on match; STM_ENOENT if
 * no live extent has paddr == queried (a metadata block, bootstrap
 * region, or trailing block of a multi-block extent — the
 * production cb treats ENOENT as "no extent verify path; charge
 * to OK"); STM_EINVAL on NULL args or paddr == 0 (reserved).
 */
STM_MUST_USE
stm_status stm_extent_lookup_by_paddr(const stm_extent_index *idx,
                                         uint64_t paddr,
                                         stm_extent_record *out_extent);

/*
 * Iterate every live extent of (ds, ino) in off-ascending order.
 * Returns false from the callback to terminate early. Callback runs
 * under the index's mutex; MUST NOT call back into stm_extent_*
 * (deadlock — ERRORCHECK mutex returns EDEADLK on reentry). The
 * record pointer passed to the callback is valid only for the
 * callback's lifetime — DO NOT retain it past the callback's return
 * (a concurrent mutator may realloc the records array, leaving the
 * saved pointer dangling). R34 P3-1.
 *
 * Returns: STM_OK on completion (whether cb terminated early or not),
 * STM_EINVAL on bad args, STM_ENOMEM if the temporary order index
 * fails to allocate.
 */
typedef bool (*stm_extent_iter_cb)(const stm_extent_record *e, void *ctx);

STM_MUST_USE
stm_status stm_extent_iter(const stm_extent_index *idx,
                              uint64_t dataset_id, uint64_t ino,
                              stm_extent_iter_cb cb, void *ctx);

/*
 * Iterate every live extent of `dataset_id` (any ino) in
 * (ino, off)-ascending order. Used by send/recv (P7-7) to enumerate
 * a dataset's complete extent set without prior knowledge of which
 * inos exist. Same locking + cb-borrowed-pointer rules as
 * `stm_extent_iter`.
 *
 * Returns STM_OK / STM_EINVAL / STM_ENOMEM as for stm_extent_iter.
 */
STM_MUST_USE
stm_status stm_extent_iter_ds(const stm_extent_index *idx,
                                 uint64_t dataset_id,
                                 stm_extent_iter_cb cb, void *ctx);

/*
 * Count live extents in the index (across all datasets / inos).
 */
STM_MUST_USE
stm_status stm_extent_count(const stm_extent_index *idx,
                               size_t *out_count);

/*
 * Count live extents for a specific (ds, ino).
 */
STM_MUST_USE
stm_status stm_extent_count_for_ino(const stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       size_t *out_count);

/* ========================================================================= */
/* Persistence (P7-3, v12).                                                   */
/* ========================================================================= */

/*
 * The extent index is persisted as a btree_store-encoded, AEAD-encrypted
 * Bε-tree under `ub_extent_root`. Same envelope as the dataset / snapshot
 * trees — AEAD nonce `paddr || gen || pool_uuid`, AD `pool_uuid ||
 * device_uuid_0`, idempotent commit via internal dirty flag, atomic
 * shadow-swap on load_at.
 *
 * Key (24 bytes, lexicographically sorted):
 *
 *   off  size  field
 *    0    8    dataset_id (le64)
 *    8    8    ino        (le64)
 *   16    8    offset     (le64) — byte offset within the file
 *
 * Value (32 bytes, ARCH §11.6.1 stm_extent_v2 layout):
 *
 *   off  size  field
 *    0    8    paddr            (le64)
 *    8    8    write_gen        (le64)
 *   16    4    dlen             (le32) — logical byte length
 *   20    4    clen_and_comp    (le32) — low 24: stored length; high 8: comp algo
 *   24    8    xxh              (le64) — 0 in this MVP (AEAD tag is integrity)
 *
 * Total: 32 bytes per ARCH §11.6.1.
 *
 * MVP caps:
 *   - `len` must fit in 24 bits (≤ 0xFFFFFF; ~16 MiB-1) so both `dlen`
 *     and `clen` (low 24 bits of clen_and_comp) can hold it without
 *     compression. Production recordsizes (default 128 KiB) are far
 *     under this. Refuse with STM_ERANGE on commit if any extent's
 *     length exceeds the cap.
 *   - Compression algorithm field is always 0 (no compression in this
 *     MVP).
 *   - `xxh` is always 0 (AEAD tag is the integrity check; the
 *     unencrypted-extent path with non-zero xxh is a future extension).
 *
 * The unified key shape (ds || ino || off) places all extents in a
 * single Bε-tree under `ub_extent_root`. ARCH §11.6.2 specifies a
 * per-file Bε-tree keyed by `(ino, type, offset)`; the unified MVP
 * here is structurally compatible (no semantic divergence) and the
 * migration to per-file or per-dataset trees is incremental.
 */

STM_MUST_USE
stm_status stm_extent_index_set_storage(stm_extent_index *idx,
                                           stm_bdev *bdev_0,
                                           stm_bootstrap *boot_0);

STM_MUST_USE
stm_status stm_extent_index_set_crypt_ctx(stm_extent_index *idx,
                                             const uint8_t *metadata_key,
                                             const uint64_t pool_uuid[2],
                                             const uint64_t device_uuid_0[2]);

/*
 * Hydrate the index from on-disk state. Wipes existing in-RAM extent
 * records and replaces with the on-disk contents. Sets dirty=false on
 * success.
 *
 * `root_paddr` MUST be non-zero (the caller checks for "no commit yet"
 * by inspecting the UB before invoking). `root_gen` is the AEAD gen
 * at which the tree was last serialized (= ub_extent_root_gen).
 * `expected_csum` is the Merkle link from ub_extent_root.bp_csum.
 *
 * On success, current_txg is bumped to max(loaded write_gen) per
 * extent.tla::BirthTxgBound — post-mount Write/Overwrite must not stamp
 * extents with gen less than the highest persisted gen.
 *
 * Returns STM_OK on full hydration; STM_ECORRUPT on Merkle mismatch
 * or malformed entries (zero ds/ino, zero len, key/value length
 * mismatch, NoOverlapWithinIno violation, paddr collision among
 * loaded records); STM_EBADTAG on AEAD failure; STM_EINVAL on
 * missing storage / crypt ctx.
 */
STM_MUST_USE
stm_status stm_extent_index_load_at(stm_extent_index *idx,
                                       uint64_t root_paddr, uint64_t root_gen,
                                       const uint8_t expected_csum[32]);

/*
 * Serialize current state, AEAD-encrypt, write a fresh root, free the
 * previous root's nodes (if any), return new (paddr, csum).
 *
 * Idempotent when clean (dirty=false + prior commit exists): returns
 * cached values without on-disk activity. Mandatory for
 * quorum.tla::ContentQuorumAtGen under retry — sync_commit may invoke
 * us multiple times at the same target_gen and every call must produce
 * byte-identical UB bytes across devices.
 *
 * `committed_gen` is the AEAD gen for the new root AND the free_gen for
 * reclaiming the previous root.
 *
 * Returns STM_ERANGE if any live extent's length exceeds the MVP
 * 24-bit cap (see preamble).
 */
STM_MUST_USE
stm_status stm_extent_index_commit(stm_extent_index *idx,
                                      uint64_t committed_gen,
                                      uint64_t *out_root_paddr,
                                      uint8_t out_root_csum[32]);

/* Durable root paddr + csum as last persisted by _commit / _load_at.
 * Both zero before any commit. */
STM_MUST_USE
stm_status stm_extent_index_get_root(const stm_extent_index *idx,
                                        uint64_t *out_root_paddr,
                                        uint8_t out_root_csum[32]);

/* Gen at which the durable root was AEAD-encrypted. May differ from
 * the current commit's gen when _commit idempotent-shortcircuits.
 * 0 before any commit. Stamped into ub_extent_root_gen. */
STM_MUST_USE
stm_status stm_extent_index_get_gen(const stm_extent_index *idx,
                                       uint64_t *out_root_gen);

STM_MUST_USE
stm_status stm_extent_index_verify(const stm_extent_index *idx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_EXTENT_H */
