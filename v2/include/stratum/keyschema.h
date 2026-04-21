/* SPDX-License-Identifier: ISC */
/*
 * Key-schema sub-tree (Phase 4 chunk P4-4a).
 *
 *   see ARCHITECTURE §7.3 / §7.7.3 for the full design.
 *   see v2/docs/phase4-status.md §P4-4 for implementation plan.
 *   see v2/specs/key_schema.tla for the formal model.
 *
 * What this module does:
 *
 *   - Holds the pool's wrapped dataset keys. Each entry is a
 *     (dataset_id, key_id) → (state, wrapped_blob) mapping.
 *   - Persists via a single-leaf on-disk node today; expands to a
 *     multi-level tree (reusing btree_store machinery) when the
 *     entry count exceeds what fits one leaf (~107 entries).
 *   - Node is plaintext + Merkle-covered via bp_csum; sensitive
 *     bytes (wrapped keys) are AEAD-wrapped by stm_hybrid inside
 *     each entry, so no plaintext key material hits disk.
 *
 * Lifecycle:
 *
 *   stm_keyschema_create(d, boot, ...)
 *       Fresh-pool handle. Empty in-RAM state.
 *
 *   stm_keyschema_open(d, boot)
 *       Re-open handle; call stm_keyschema_load_at afterwards to
 *       hydrate from the on-disk tree.
 *
 *   stm_keyschema_load_at(ks, root_paddr, expected_csum)
 *       Read the durable node + verify Merkle + decode entries.
 *
 *   stm_keyschema_insert_wrapped(ks, dataset_id, key_id, state,
 *                                  wrapped_blob, wrapped_len)
 *       Insert or replace an entry in RAM. Persists on commit.
 *
 *   stm_keyschema_lookup(ks, dataset_id, key_id,
 *                          out_state, out_wrapped, out_cap, out_len)
 *       Read back a specific entry.
 *
 *   stm_keyschema_lookup_current(ks, dataset_id,
 *                                  out_key_id,
 *                                  out_wrapped, out_cap, out_len)
 *       Read the CURRENT (non-retired) key for the dataset.
 *
 *   stm_keyschema_commit(ks, committed_gen, &out_paddr, &out_csum)
 *       Serialize the current state to a fresh on-disk node and
 *       return paddr + bp_csum. Caller plumbs these into the
 *       uberblock's ub_key_schema header.
 */
#ifndef STRATUM_V2_KEYSCHEMA_H
#define STRATUM_V2_KEYSCHEMA_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev       stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap  stm_bootstrap;

typedef struct stm_keyschema stm_keyschema;

/* Entry state byte. Matches ARCH §7.7's "CURRENT / RETIRED /
 * PRUNING" set; on-disk encoding is little-endian 1 byte. */
typedef enum {
    STM_KS_STATE_INVALID  = 0,
    STM_KS_STATE_CURRENT  = 1,
    STM_KS_STATE_RETIRED  = 2,
    STM_KS_STATE_PRUNING  = 3,
} stm_keyschema_state;

/* Maximum wrapped-blob size we support per entry. Sized for the
 * PQ-hybrid wrap of a 32-byte dek: 32 + STM_HYBRID_WRAP_OVERHEAD
 * (1160) = 1192 bytes. Round up to give a little future headroom. */
#define STM_KEYSCHEMA_WRAPPED_MAX   1280u

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

/* Fresh handle with an empty in-RAM map. Does not touch disk. */
STM_MUST_USE
stm_status stm_keyschema_create(stm_bdev *d, stm_bootstrap *boot,
                                  stm_keyschema **out_ks);

/* Same as _create — alias for readability at call sites that just
 * want a handle to later _load_at. */
STM_MUST_USE
stm_status stm_keyschema_open(stm_bdev *d, stm_bootstrap *boot,
                                stm_keyschema **out_ks);

void stm_keyschema_close(stm_keyschema *ks);

/* ========================================================================= */
/* Persistence.                                                               */
/* ========================================================================= */

/*
 * Read the on-disk schema node rooted at `root_paddr`, verify its
 * plaintext self-csum (btnode's BLAKE3 over the node encoding)
 * matches `expected_csum` (the parent bptr's bp_csum), and decode
 * entries into the in-RAM map.
 *
 * `root_paddr == 0` is a valid no-op — used when a pool was just
 * formatted but no schema has been written yet. Leaves the map
 * empty.
 *
 * Returns STM_ECORRUPT on Merkle / self-csum / decode failure.
 */
STM_MUST_USE
stm_status stm_keyschema_load_at(stm_keyschema *ks, uint64_t root_paddr,
                                   const uint8_t expected_csum[32]);

/*
 * Serialize current in-RAM state to a fresh single-leaf node,
 * write via the bootstrap pool, free the previous node (if any) at
 * `committed_gen`, and return the new root paddr + bp_csum.
 *
 * If the schema is empty, still emits one empty node so callers
 * always have a valid bptr in the uberblock.
 *
 * On success advances internal bookkeeping so the next commit
 * knows to free THIS paddr.
 */
STM_MUST_USE
stm_status stm_keyschema_commit(stm_keyschema *ks, uint64_t committed_gen,
                                  uint64_t *out_root_paddr,
                                  uint8_t out_root_csum[32]);

/*
 * Last-committed root paddr + csum. Both zero before any commit.
 */
STM_MUST_USE
stm_status stm_keyschema_get_root(const stm_keyschema *ks,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32]);

/* ========================================================================= */
/* Entry manipulation.                                                        */
/* ========================================================================= */

/*
 * Insert (or replace) an entry keyed by (dataset_id, key_id).
 * `wrapped_len` must be <= STM_KEYSCHEMA_WRAPPED_MAX.
 */
STM_MUST_USE
stm_status stm_keyschema_insert_wrapped(stm_keyschema *ks,
                                          uint64_t dataset_id,
                                          uint64_t key_id,
                                          stm_keyschema_state state,
                                          const void *wrapped, size_t wrapped_len);

/*
 * Read the entry for (dataset_id, key_id). `out_wrapped` may be
 * NULL if the caller only wants `out_state` / `out_len`.
 *
 * Returns STM_ENOENT if no entry exists, STM_ERANGE if out_cap is
 * smaller than the stored blob.
 */
STM_MUST_USE
stm_status stm_keyschema_lookup(const stm_keyschema *ks,
                                  uint64_t dataset_id, uint64_t key_id,
                                  stm_keyschema_state *out_state,
                                  void *out_wrapped, size_t out_cap,
                                  size_t *out_len);

/*
 * Find the CURRENT entry for `dataset_id`, regardless of key_id.
 * There must be exactly one; STM_ECORRUPT otherwise.
 *
 * Returns STM_ENOENT if no current entry exists (no such dataset,
 * or all its keys are retired).
 */
STM_MUST_USE
stm_status stm_keyschema_lookup_current(const stm_keyschema *ks,
                                          uint64_t dataset_id,
                                          uint64_t *out_key_id,
                                          void *out_wrapped, size_t out_cap,
                                          size_t *out_len);

/*
 * Number of entries currently in RAM. Primarily for tests.
 */
size_t stm_keyschema_count(const stm_keyschema *ks);

/* ========================================================================= */
/* Rotation + retired-key sweeper (P4-4c, ARCH §7.7.2).                       */
/* ========================================================================= */

/*
 * Next monotonic key_id for `dataset_id`. 0 if no entries exist for
 * the dataset; max(key_id)+1 otherwise — including entries currently
 * RETIRED or PRUNING. Key-ids never recycle; a pruned slot becomes
 * NONE but the id remains burned so retired-blob lookups stay
 * unambiguous (key_schema.tla's MonotonicKeyIds).
 */
STM_MUST_USE
stm_status stm_keyschema_next_key_id(const stm_keyschema *ks,
                                       uint64_t dataset_id,
                                       uint64_t *out_next_key_id);

/*
 * Atomic dataset-key rotation (ARCH §7.7.2). Inserts
 * (dataset_id, new_key_id, CURRENT, wrapped) AND flips the existing
 * CURRENT entry for the dataset to RETIRED, in a single call. The
 * on-disk visibility is atomic via the commit protocol's CommitAtomic
 * (the schema tree's new root is only reachable once the uberblock
 * lands).
 *
 * Preconditions enforced:
 *   - `new_key_id` must equal `stm_keyschema_next_key_id(dataset_id)`
 *     (strict monotonicity; callers that pass a stale value get
 *     STM_EINVAL).
 *   - The dataset currently has exactly one CURRENT entry (the one
 *     being retired). Zero or more-than-one → STM_ECORRUPT.
 *
 * On success, `*out_old_key_id` is set to the retired key's id.
 *
 * On failure the in-RAM schema is untouched (operation is
 * all-or-nothing with respect to the list mutations).
 */
STM_MUST_USE
stm_status stm_keyschema_rotate(stm_keyschema *ks,
                                  uint64_t dataset_id,
                                  uint64_t new_key_id,
                                  const void *wrapped, size_t wrapped_len,
                                  uint64_t *out_old_key_id);

/*
 * Transition RETIRED → PRUNING. Per key_schema.tla's MarkPruning,
 * the caller must have verified refs == 0; Phase 4 has no extent
 * layer, so refs == 0 is trivially true, and this primitive accepts
 * the transition unconditionally. Phase 6's extent manager will own
 * the refcount check before invoking this.
 *
 * STM_EINVAL if the entry is not in RETIRED state; STM_ENOENT if no
 * entry exists at (dataset_id, key_id).
 */
STM_MUST_USE
stm_status stm_keyschema_mark_pruning(stm_keyschema *ks,
                                        uint64_t dataset_id,
                                        uint64_t key_id);

/*
 * Remove a PRUNING entry. Frees the wrapped-blob allocation and
 * removes the list slot. STM_EINVAL if the entry is not in PRUNING
 * state; STM_ENOENT if no entry exists.
 *
 * The burned key_id is NOT recycled — a subsequent rotate still
 * picks `max(live_key_id) + 1` (see `stm_keyschema_next_key_id`'s
 * contract). This matches the spec's MonotonicKeyIds invariant.
 */
STM_MUST_USE
stm_status stm_keyschema_prune(stm_keyschema *ks,
                                 uint64_t dataset_id,
                                 uint64_t key_id);

/*
 * Callback signature for `stm_keyschema_iter`. Returns 0 to continue,
 * non-zero to stop; iter propagates the non-zero value to its caller.
 */
typedef int (*stm_keyschema_iter_cb)(uint64_t dataset_id, uint64_t key_id,
                                       stm_keyschema_state state,
                                       const void *wrapped, size_t wrapped_len,
                                       void *ctx);

/*
 * Walk every entry in sorted (dataset_id, key_id) order, invoking
 * `cb` per entry. If `cb` returns non-zero the iteration short-
 * circuits with that return value; STM_OK otherwise.
 */
STM_MUST_USE
stm_status stm_keyschema_iter(const stm_keyschema *ks,
                                stm_keyschema_iter_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_KEYSCHEMA_H */
