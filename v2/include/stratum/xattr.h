/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — extended attribute (xattr) layer (P8-POSIX-6).
 *
 * Implements the on-disk xattr record + the per-pool xattr index per
 * ARCHITECTURE §11.5. The index is the canonical mapping from
 * `(dataset_id, ino, hash_probe)` → xattr record, where
 * `hash_probe = fnv1a64(name) + probe_offset` resolves hash collisions
 * via open-addressing per ARCH §11.5.1.
 *
 * Spec-to-code: this file realizes the xattr state machine modeled in
 * `v2/specs/xattr.tla` (which is structurally isomorphic to dirent.tla's
 * write-side — only the keyed-on entity differs: ino instead of
 * dir_ino). Each new public action below maps to a TLA+ action of the
 * same name. The three buggy variants in the spec enumerate the
 * canonical chain-integrity failure modes the reviewer must rule out —
 * `BuggyUnlinkUsesEmpty` (silent loss of colliding-name reachability),
 * `BuggyCreateOverwritesNoProbe` (silent overwrite of colliding
 * occupant), and `BuggyLookupStopsOnTombstone` (read-side analog of
 * UnlinkUsesEmpty).
 *
 * MVP scope (P8-POSIX-6):
 *   - Per-pool xattr tree backed by btree_store (mirrors stm_dirent_index
 *     persistence shape). Format break STM_UB_VERSION 25 → 26 adds a
 *     new `ub_xattr_root` tree-root field and binds its csum into the
 *     pool's Merkle root chain (R70 P0-1 lesson — the 10th input).
 *   - Open-addressing chain integrity per xattr.tla. Tombstones are
 *     kept in the btree on Remove (encoded via STM_XATTR_FLAG_TOMBSTONE
 *     in the value's flags byte) so a colliding name at a higher probe
 *     index stays reachable. Lookup walks past tombstones.
 *   - Probe cap STM_XATTR_PROBE_MAX = 64 (same value as dirent's; ARCH
 *     §11.5.1 uses the same chain-cap convention).
 *   - Writer-side invariants symmetric with decoder-side (R71 P1-1 +
 *     R77 P1-1 lesson): every constraint the decoder enforces on read
 *     is also enforced at the alloc API boundary, so a buggy or hostile
 *     caller cannot commit a record that would wedge the pool on next
 *     mount or trigger an OOB read on lookup.
 *
 * Out of scope here:
 *   - listxattr cursor stability — not modeled in MVP. listxattr scans
 *     all records under (ds, ino), filters tombstones, returns concat.
 *     A future P8-POSIX-6b chunk could extend xattr.tla to model
 *     cursor-stable iteration analogously to P8-POSIX-4's readdir
 *     extension to dirent.tla.
 *   - POSIX namespace gating (`user.` / `system.` / `security.` /
 *     `trusted.`): policy at the fs.c wrapper layer, not a load-bearing
 *     chain-integrity invariant. The xattr.c layer accepts any
 *     non-empty name in the byte range [1, STM_XATTR_NAME_MAX].
 *   - Higher-level fs APIs (stm_fs_setxattr / _getxattr / _listxattr /
 *     _removexattr) — landed in fs.c at the same chunk; they compose
 *     this layer with namespace validation + the per-fs lock.
 */
#ifndef STRATUM_V2_XATTR_H
#define STRATUM_V2_XATTR_H

#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* On-disk constants. ARCH §11.5.                                            */
/* ========================================================================= */

/* POSIX XATTR_NAME_MAX — the byte cap on a single xattr's name field.
 * Matches Linux <linux/limits.h> XATTR_NAME_MAX = 255. */
#define STM_XATTR_NAME_MAX  255u

/* POSIX XATTR_SIZE_MAX — the byte cap on a single xattr's value field.
 * Matches Linux <linux/limits.h> XATTR_SIZE_MAX = 65536. Implementations
 * may set tighter caps; ours uses the POSIX max so callers get the full
 * POSIX shape. */
#define STM_XATTR_VALUE_MAX  65536u

/* Probe-chain cap per ARCH §11.5.1: a lookup at probe=k for k ≥ 64
 * gives up and returns ENODATA (or ENOSPC at allocation). Same value
 * as STM_DIRENT_PROBE_MAX — both follow ARCH's bounded-tail convention
 * for chain termination.
 *
 * The xattr layer uses an independent macro (rather than reusing
 * STM_DIRENT_PROBE_MAX) so future tuning can move them independently. */
#define STM_XATTR_PROBE_MAX  64u

/* Tombstone flag — set in the value's `flags` byte to mark an xattr
 * record whose name has been Removed but whose slot must remain present
 * in the chain so a colliding name at a higher probe index stays
 * reachable. Per xattr.tla: Remove leaves a TOMBSTONE marker; Lookup
 * walks past tombstones. */
#define STM_XATTR_FLAG_TOMBSTONE  0x01u

/* On-disk value layout (variable-length, 16 + name_len + value_len bytes):
 *
 *   off  size  field                       contract
 *    0     4   le32 value_len              live: 0..STM_XATTR_VALUE_MAX;
 *                                          tombstone: 0
 *    4     1   u8   name_len               live: 1..255; tombstone: 0
 *    5     1   u8   flags                  bit 0: TOMBSTONE
 *    6    10   u8[10] reserved             zero (anti-tamper)
 *   16   var   u8[name_len] name           live: name_len bytes (no NUL);
 *                                          tombstone: 0 bytes
 *    *   var   u8[value_len] value         live: value_len bytes;
 *                                          tombstone: 0 bytes
 *
 * Total = 16 + name_len + value_len bytes (live), 16 bytes (tombstone).
 *
 * On-disk key layout (fixed 24 bytes):
 *
 *   off  size  field                       contract
 *    0     8   le64 dataset_id             non-zero
 *    8     8   le64 ino                    non-zero
 *   16     8   le64 hash_probe             fnv1a64(name) + probe_offset
 */

/* ========================================================================= */
/* Forward decl + lifecycle.                                                 */
/* ========================================================================= */

struct stm_xattr_index;
typedef struct stm_xattr_index stm_xattr_index;

/* Allocate an empty in-memory xattr index. Returns NULL on STM_ENOMEM.
 * Mirrors `stm_dirent_index_create`. */
stm_xattr_index *stm_xattr_index_create(void);

/* Free the index (in-RAM records, persistence handles, every record's
 * heap-allocated value buffer). Safe on NULL. */
void stm_xattr_index_close(stm_xattr_index *idx);

/* ========================================================================= */
/* In-memory operations. Models xattr.tla's actions.                          */
/* ========================================================================= */

/*
 * Set — write `name → value` for inode `ino` of `dataset_id`. Models
 * `xattr.tla::Set`.
 *
 * Walks the open-addressing chain from probe 0 looking for either:
 *   - first EMPTY slot (no record at that key) → install here;
 *   - first TOMBSTONE slot → remember as install candidate, keep
 *     walking to verify `name` not already present further in the chain;
 *   - record with same name → REPLACE in place (POSIX setxattr default
 *     semantics: replace-or-create);
 *   - record with different name → continue probing.
 *
 * The `flags` parameter selects POSIX setxattr semantics:
 *   - 0                       : default (replace-or-create)
 *   - STM_XATTR_FLAG_CREATE   : refuse if exists (STM_EEXIST)
 *   - STM_XATTR_FLAG_REPLACE  : refuse if doesn't exist (STM_ENODATA)
 * Setting both bits is invalid (STM_EINVAL).
 *
 * `out_replaced` (optional) is set to true iff a prior live record for
 * `name` was replaced (i.e. `flags == 0` AND name was found live).
 * Pass NULL to ignore.
 *
 * Refusals:
 *   - NULL idx OR NULL name OR NULL value when value_len > 0 (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_XATTR_NAME_MAX (STM_EINVAL).
 *   - value_len > STM_XATTR_VALUE_MAX (STM_E2BIG-equivalent — we use
 *     STM_ERANGE since STM_E2BIG isn't in the taxonomy).
 *   - flags has bits other than CREATE/REPLACE (STM_EINVAL).
 *   - flags is (CREATE | REPLACE) (STM_EINVAL).
 *   - CREATE flag set + name already linked (STM_EEXIST).
 *   - REPLACE flag set + name not present (STM_ENODATA).
 *   - chain exhausted (STM_XATTR_PROBE_MAX probes consumed without
 *     finding an install slot) → STM_ENOSPC.
 *
 * Lock posture: takes `idx->lock`. No cross-layer dependencies.
 */
#define STM_XATTR_FLAG_CREATE   0x01u
#define STM_XATTR_FLAG_REPLACE  0x02u

STM_MUST_USE
stm_status stm_xattr_set(stm_xattr_index *idx,
                            uint64_t dataset_id, uint64_t ino,
                            const uint8_t *name, uint8_t name_len,
                            const uint8_t *value, uint32_t value_len,
                            uint32_t flags,
                            bool *out_replaced);

/*
 * Lookup `name` for inode `ino`. Models `xattr.tla::LookupWalk`.
 *
 * Walks the chain from probe 0:
 *   - EMPTY slot → STM_ENODATA (chain ends here).
 *   - TOMBSTONE slot → continue.
 *   - record with same name → return value via out params.
 *   - record with different name → continue.
 *   - chain exhausted (STM_XATTR_PROBE_MAX probes) → STM_ENODATA.
 *
 * POSIX getxattr shape:
 *   - `*out_size` is set to the FULL value byte count regardless of
 *     `value_max`. Callers can probe by passing `value_max=0` to get
 *     the size, then reallocate and re-call. This matches the POSIX
 *     `getxattr(2)` contract.
 *   - If `value_max > 0` AND `value_max < *out_size`, returns
 *     STM_ERANGE (POSIX ERANGE), `*out_size` set to the full size.
 *   - If `value_max >= *out_size`, copies the full value into
 *     `value_buf` and returns STM_OK.
 *
 * `out_size` is required; `value_buf` may be NULL iff `value_max == 0`.
 *
 * Refusals:
 *   - NULL idx OR NULL name OR NULL out_size (STM_EINVAL).
 *   - NULL value_buf with value_max > 0 (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_XATTR_NAME_MAX (STM_EINVAL).
 *   - No match in chain → STM_ENODATA.
 *   - value_max > 0 AND value_max < value_len → STM_ERANGE
 *     (*out_size still set to the full value size).
 */
STM_MUST_USE
stm_status stm_xattr_get(const stm_xattr_index *idx,
                            uint64_t dataset_id, uint64_t ino,
                            const uint8_t *name, uint8_t name_len,
                            uint8_t *value_buf, uint32_t value_max,
                            uint32_t *out_size);

/*
 * Remove `name` from inode `ino`. Models `xattr.tla::Remove`.
 *
 * Walks the chain to find the live record matching `name`, replaces
 * the slot with a TOMBSTONE (NOT EMPTY — that would break colliding
 * names at higher probe indices per xattr.tla::BuggyUnlinkUsesEmpty).
 *
 * Refusals:
 *   - NULL idx OR NULL name (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_XATTR_NAME_MAX (STM_EINVAL).
 *   - No match in chain → STM_ENODATA.
 */
STM_MUST_USE
stm_status stm_xattr_remove(stm_xattr_index *idx,
                               uint64_t dataset_id, uint64_t ino,
                               const uint8_t *name, uint8_t name_len);

/*
 * On-the-wire entry returned by stm_xattr_list. The `hash_probe` field
 * is informational (= the slot at which the record lives in the
 * open-addressing chain) — useful for debugging and for callers that
 * want to encode a per-entry resume token. The fs-layer wrapper
 * (`stm_fs_listxattr`) does not surface this field; it concats the
 * names with NUL separators per POSIX listxattr(2).
 *
 * `value_len` is also informational (callers fetch the value via
 * stm_xattr_get, not via the list iterator).
 */
typedef struct stm_xattr_entry {
    uint64_t hash_probe;
    uint8_t  name_len;
    uint8_t  name[STM_XATTR_NAME_MAX];
    uint32_t value_len;
} stm_xattr_entry;

/*
 * List all live xattrs under (dataset_id, ino), filling up to
 * `max_entries` into `out_entries[]`. Tombstones are skipped.
 *
 * MVP semantics — single-call, full enumeration. If
 * `n_total > max_entries`, returns STM_ERANGE and `*out_total` is set
 * to the full count so the caller can reallocate. (No streaming
 * cursor — listxattr is rarely called on inodes with > 64 attrs in
 * practice; ARCH §11.5 commits to FULL POSIX shape but doesn't
 * commit to streaming. Future cursor extension would compose with
 * a `xattr.tla` extension analogous to readdir's.)
 *
 * `out_total` is required; reports the count regardless of
 * `max_entries` so callers can probe with `max_entries == 0`.
 *
 * Refusals:
 *   - NULL idx OR NULL out_total (STM_EINVAL).
 *   - NULL out_entries with max_entries > 0 (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - max_entries > 0 AND max_entries < n_total → STM_ERANGE
 *     (*out_total still set).
 */
STM_MUST_USE
stm_status stm_xattr_list(const stm_xattr_index *idx,
                             uint64_t dataset_id, uint64_t ino,
                             stm_xattr_entry *out_entries,
                             size_t max_entries,
                             size_t *out_total);

/*
 * Drop EVERY record (live + tombstone) keyed at `(dataset_id, ino, *)`.
 * Used by `stm_fs_unlink` / `_rmdir` to GC an inode's xattrs when the
 * inode itself is freed. Without this, an inode whose ino is later
 * AllocReused inherits the prior tenant's xattrs.
 *
 * Output: `*out_dropped` (optional) is set to the number of records
 * removed (live + tombstone, summed). Pass NULL to ignore.
 *
 * Refusals:
 *   - NULL idx (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_xattr_drop_for_ino(stm_xattr_index *idx,
                                     uint64_t dataset_id, uint64_t ino,
                                     size_t *out_dropped);

/* ========================================================================= */
/* Persistence (P8-POSIX-6, v26).                                            */
/*                                                                            */
/* The xattr index is persisted as a btree_store-encoded, AEAD-encrypted    */
/* Bε-tree under `ub_xattr_root` on device 0. Same envelope as the inode    */
/* / dirent / extent / cas trees: AEAD nonce `paddr || gen || pool_uuid`,   */
/* AD `pool_uuid || device_uuid_0`, idempotent commit via internal dirty    */
/* flag, atomic shadow-swap on load_at.                                      */
/* ========================================================================= */

struct stm_bdev;       typedef struct stm_bdev stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap stm_bootstrap;

STM_MUST_USE
stm_status stm_xattr_index_set_storage(stm_xattr_index *idx,
                                          stm_bdev *bdev_0,
                                          stm_bootstrap *boot_0);

STM_MUST_USE
stm_status stm_xattr_index_set_crypt_ctx(stm_xattr_index *idx,
                                            const uint8_t *metadata_key,
                                            const uint64_t pool_uuid[2],
                                            const uint64_t device_uuid_0[2]);

STM_MUST_USE
stm_status stm_xattr_index_commit(stm_xattr_index *idx,
                                     uint64_t committed_gen,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]);

STM_MUST_USE
stm_status stm_xattr_index_load_at(stm_xattr_index *idx,
                                      uint64_t root_paddr,
                                      uint64_t root_gen,
                                      const uint8_t expected_csum[32]);

STM_MUST_USE
stm_status stm_xattr_index_get_root(const stm_xattr_index *idx,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32]);

STM_MUST_USE
stm_status stm_xattr_index_get_gen(const stm_xattr_index *idx,
                                      uint64_t *out_root_gen);

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_XATTR_H */
