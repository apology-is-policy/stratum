/* SPDX-License-Identifier: ISC */
/*
 * Allocator-roots object (Phase 5 chunk P5-3b).
 *
 *   see ARCHITECTURE §6.1 — per-device allocator trees + pool-level
 *     allocator-roots object.
 *
 * What this module owns
 *
 *   ARCH §6.1 specifies that each pool device has its own Bε-tree of
 *   allocated ranges (one tree per device). Pool-level coordination of
 *   those per-device roots happens through a single "allocator-roots
 *   object" — itself a small Bε-tree stored on device 0's bootstrap
 *   pool — keyed by device_id, valued with each device's alloc-tree
 *   root bptr (paddr + csum).
 *
 *   `ub_alloc_root` in the uberblock now points at the allocator-roots
 *   object's root node, NOT directly at a single alloc tree (as pre-
 *   P5-3b). On mount, sync loads the roots object, iterates its
 *   entries, and loads each device's alloc tree from the recorded
 *   (paddr, csum) pair.
 *
 *   The Merkle chain stays transitively complete:
 *     ub_alloc_root.bp_csum == BLAKE3(roots-obj ciphertext)
 *     → roots-obj leaf bytes include each device's alloc-tree
 *       root bptr (paddr + csum)
 *     → each device's alloc-tree root's bp_csum is checked against
 *       that recorded csum at tree-load time.
 *
 *   So any on-disk tamper to the roots object's ciphertext fails
 *   either ub's bp_csum check or (if ciphertext matches a valid blob)
 *   the AEAD-tag check. Tamper to per-device alloc tree roots fails
 *   the per-device tree-load Merkle check.
 *
 * On-disk format (single-leaf btree_store node, AEAD-encrypted)
 *
 *   Entry key:    le16 device_id                            (2 bytes)
 *   Entry value:  le64 alloc_root_paddr || blake3 csum[32]  (40 bytes)
 *
 *   Up to STM_POOL_DEVICES_MAX entries (64). Total payload
 *   <= 64 * (2 + 40) = 2688 bytes — easily fits in one 128 KiB
 *   btnode leaf. Single-leaf invariant simplifies the tamper surface.
 *
 * Crypto
 *
 *   Encrypted via stm_btree_store_serialize under (metadata_key,
 *   pool_uuid, device_uuid_0). Nonce = paddr || gen || pool_uuid.
 *   AD = pool_uuid || device_uuid_0. Lives on device 0 (metadata
 *   primary); device_uuid_0 in the AD ensures a roots-object blob
 *   cannot be replayed as a device-1 blob in a future multi-device
 *   pool configuration.
 *
 * Idempotency (R14b parallel)
 *
 *   `stm_alloc_roots_commit` carries a dirty flag and short-circuits
 *   to the cached (paddr, csum) when clean — same pattern as
 *   `stm_alloc_commit` (R7c P2-5) and `stm_keyschema_commit` (R14b
 *   P2-1). Retries produce byte-identical ub_alloc_root bytes,
 *   preserving quorum.tla's ContentQuorumAtGen invariant.
 *
 * Phase 5 MVP scope
 *
 *   Today (P5-3b), the only entry is for device 0 — single-device
 *   pools still behave as before, with one extra indirection layer.
 *   Multi-entry exercise lands with P5-3c (per-device alloc trees on
 *   all pool members + mirror reservation).
 */
#ifndef STRATUM_V2_ALLOC_ROOTS_H
#define STRATUM_V2_ALLOC_ROOTS_H

#include <stratum/types.h>
#include <stratum/pool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev       stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap  stm_bootstrap;

typedef struct stm_alloc_roots stm_alloc_roots;

/* On-disk per-entry value size. paddr(8 LE) + blake3(32). */
#define STM_ALLOC_ROOTS_VALUE_BYTES   40u

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

/*
 * Fresh in-RAM handle bound to device 0's bdev + bootstrap. Empty
 * entry map. Caller MUST install the crypt ctx via
 * stm_alloc_roots_set_crypt_ctx before the first _commit or _load_at.
 *
 * `bdev_0` and `boot_0` are borrowed. The handle holds no ownership
 * over them; caller closes them after the handle.
 */
STM_MUST_USE
stm_status stm_alloc_roots_create(stm_bdev *bdev_0, stm_bootstrap *boot_0,
                                    stm_alloc_roots **out);

/* Alias for _create — semantically used at mount time, followed by
 * stm_alloc_roots_load_at to hydrate from disk. */
STM_MUST_USE
stm_status stm_alloc_roots_open(stm_bdev *bdev_0, stm_bootstrap *boot_0,
                                  stm_alloc_roots **out);

void stm_alloc_roots_close(stm_alloc_roots *r);

/*
 * Install pool-wide crypt ctx. `metadata_key` is borrowed (must
 * outlive the handle). `pool_uuid` + `device_uuid_0` are copied.
 * Mandatory before _commit / _load_at — returns STM_EINVAL from
 * those if not set.
 */
STM_MUST_USE
stm_status stm_alloc_roots_set_crypt_ctx(stm_alloc_roots *r,
                                            const uint8_t *metadata_key,
                                            const uint64_t pool_uuid[2],
                                            const uint64_t device_uuid_0[2]);

/* ========================================================================= */
/* Persistence.                                                               */
/* ========================================================================= */

/*
 * Load the on-disk roots object rooted at `root_paddr`. `expected_csum`
 * is ub_alloc_root.bp_csum (Merkle link from the UB). `root_gen` is
 * ub_alloc_root_gen (AEAD nonce component).
 *
 * `root_paddr == 0` is NOT valid post-v6 — every committed pool has a
 * non-zero roots-object root (first commit emits at least device 0's
 * entry). Returns STM_EINVAL on paddr==0 and STM_EINVAL on
 * expected_csum == NULL.
 *
 * On STM_OK, the in-RAM entry map is populated from disk + `dirty`
 * is cleared (loaded state matches durable).
 *
 * Returns STM_ECORRUPT on Merkle mismatch, STM_EBADTAG on AEAD
 * failure, STM_ENOTSUPPORTED for > 2-level trees (not expected at
 * N <= 64 entries).
 */
STM_MUST_USE
stm_status stm_alloc_roots_load_at(stm_alloc_roots *r,
                                      uint64_t root_paddr, uint64_t root_gen,
                                      const uint8_t expected_csum[32]);

/*
 * Serialize current state, AEAD-encrypt, write a fresh root node,
 * free the previous root's nodes (if any), return new (paddr, csum).
 *
 * Idempotent when clean (dirty=false + prior commit exists): returns
 * cached (root_paddr, root_csum) with no on-disk activity.
 *
 * `committed_gen` is the AEAD gen for the new node AND the free_gen
 * for reclaiming the previous root (symmetric with stm_alloc_commit
 * + stm_keyschema_commit).
 *
 * On success: `*out_root_paddr` != 0, in-RAM dirty := false,
 * root_paddr/csum/gen advance to the new values.
 *
 * Returns STM_EINVAL on !crypt_ctx_set, STM_ENOMEM on allocation
 * failures, STM_ENOSPC if bootstrap is exhausted,
 * STM_ENOTSUPPORTED if > 2-level tree (never expected).
 */
STM_MUST_USE
stm_status stm_alloc_roots_commit(stm_alloc_roots *r, uint64_t committed_gen,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]);

/*
 * Durable root paddr + csum as last persisted by _commit / _load_at.
 * Both zero before any commit.
 */
STM_MUST_USE
stm_status stm_alloc_roots_get_root(const stm_alloc_roots *r,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32]);

/*
 * Gen at which the durable root was AEAD-encrypted. May differ from
 * the current commit's gen when _commit idempotent-shortcircuits. 0
 * before any commit.
 *
 * Callers writing a mount-claim UB (that advances ub_gen past any
 * orphan writes WITHOUT rewriting the tree) use this to stamp
 * ub_alloc_root_gen — symmetric to stm_alloc_get_tree_gen. Mount-
 * claim preservation is load-bearing for AEAD decrypt at next mount.
 */
STM_MUST_USE
stm_status stm_alloc_roots_get_gen(const stm_alloc_roots *r,
                                      uint64_t *out_root_gen);

/* ========================================================================= */
/* Entry manipulation (pre-commit, in-RAM).                                   */
/* ========================================================================= */

/*
 * Register device's alloc-tree root. If an entry for `device_id`
 * exists, the (paddr, csum) are replaced (upsert). Marks dirty.
 *
 * `device_id < STM_POOL_DEVICES_MAX` enforced.
 */
STM_MUST_USE
stm_status stm_alloc_roots_set(stm_alloc_roots *r, uint16_t device_id,
                                 uint64_t root_paddr,
                                 const uint8_t root_csum[32]);

/*
 * Read a device's entry. `out_csum` may be NULL if only the paddr is
 * wanted. STM_ENOENT if no entry exists for `device_id`.
 */
STM_MUST_USE
stm_status stm_alloc_roots_get(const stm_alloc_roots *r, uint16_t device_id,
                                 uint64_t *out_root_paddr,
                                 uint8_t out_root_csum[32]);

/* Count of registered entries. Primarily for tests. */
size_t stm_alloc_roots_count(const stm_alloc_roots *r);

/* Per-entry callback: return 0 to continue, non-zero to stop (and
 * that return value is propagated to the caller). */
typedef int (*stm_alloc_roots_iter_cb)(
    uint16_t device_id, uint64_t root_paddr,
    const uint8_t root_csum[32], void *ctx);

/*
 * Walk every entry in ascending device_id order.
 */
STM_MUST_USE
stm_status stm_alloc_roots_iter(const stm_alloc_roots *r,
                                   stm_alloc_roots_iter_cb cb, void *ctx);

/* ========================================================================= */
/* Scrubber.                                                                  */
/* ========================================================================= */

/*
 * Walk the on-disk roots-object node and verify its Merkle + AEAD
 * chain without mutating in-RAM state. STM_OK on a fully consistent
 * durable root; STM_ECORRUPT on Merkle mismatch, STM_EBADTAG on
 * AEAD tag verify failure. STM_OK trivially if no commit has
 * persisted yet (root_paddr == 0).
 */
STM_MUST_USE
stm_status stm_alloc_roots_verify(const stm_alloc_roots *r);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_ALLOC_ROOTS_H */
