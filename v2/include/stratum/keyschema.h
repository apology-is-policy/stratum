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

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_KEYSCHEMA_H */
