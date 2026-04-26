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

/*
 * Per-extent record. Mirrors ARCH §11.6.1 stm_extent_v2 in spirit —
 * stores the modeled fields (ds, ino, off, len, paddr, gen) plus the
 * paddr-encoded device id. Compression / xxh fields are deferred to
 * the persistence chunk (P7-3); the in-RAM MVP only carries the
 * logical-correctness fields modeled by extent.tla.
 */
typedef struct {
    uint64_t dataset_id;          /* > 0 */
    uint64_t ino;                 /* > 0 */
    uint64_t off;                 /* byte offset within file */
    uint64_t len;                 /* extent length in bytes; ≥ 1 */
    uint64_t paddr;               /* (device_id<<48) | offset */
    uint64_t gen;                 /* write_gen at encrypt; nonce uniqueness */
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
 * `off`+`len`) backed by `paddr`, stamped with `write_gen`. No
 * existing extent for (ds, ino) may overlap [off, off+len).
 *
 * Refusals:
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - len == 0 (STM_EINVAL — extent.tla::LengthPositive).
 *   - paddr == 0 (STM_EINVAL — reserved sentinel).
 *   - write_gen > current_txg (STM_EINVAL — extent.tla::BirthTxgBound).
 *   - paddr already used by a live extent (STM_EEXIST —
 *     extent.tla::PaddrFreshness, live interpretation).
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
                              uint64_t paddr, uint64_t write_gen);

/*
 * COW overwrite: drop every live extent of (ds, ino) overlapping
 * [`off`, `off`+`len`), then insert a fresh extent backed by
 * `new_paddr` stamped with `write_gen`.
 *
 * Refusals: same as stm_extent_write, plus:
 *   - new_paddr equals the paddr of one of the to-be-dropped extents
 *     (cycle — caller bug). Refused with STM_EINVAL.
 *
 * On success:
 *   - *out_dropped_paddrs receives a malloc'd array of every dropped
 *     extent's paddr (caller owns; MUST `free()`). Caller MUST route
 *     each via `stm_snapshot_index_overwrite_block` (composes with
 *     dead_list.tla::OverwriteBlock).
 *   - *out_n_dropped is the array length.
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
                                  uint64_t new_paddr, uint64_t write_gen,
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
 * Iterate every live extent of (ds, ino) in off-ascending order.
 * Returns false from the callback to terminate early. Callback runs
 * under the index's mutex; MUST NOT call back into stm_extent_*
 * (deadlock — ERRORCHECK mutex returns EDEADLK on reentry).
 */
typedef bool (*stm_extent_iter_cb)(const stm_extent_record *e, void *ctx);

STM_MUST_USE
stm_status stm_extent_iter(const stm_extent_index *idx,
                              uint64_t dataset_id, uint64_t ino,
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

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_EXTENT_H */
