/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — directory entry layer (P8-POSIX-2).
 *
 * Implements the on-disk dirent record + the per-pool dirent index
 * per ARCHITECTURE §11.4. The index is the canonical mapping from
 * `(dataset_id, dir_ino, hash_probe)` → dirent record, where
 * `hash_probe = fnv1a64(name) + probe_offset` resolves hash
 * collisions via open-addressing per ARCH §11.4.2.
 *
 * Spec-to-code: this file realizes the dirent state machine modeled
 * in `v2/specs/dirent.tla`. Each new public action below maps to a
 * TLA+ action of the same name. The three buggy variants in the
 * spec enumerate the canonical chain-integrity failure modes the
 * reviewer must rule out — `BuggyUnlinkUsesEmpty` (silent loss of
 * colliding-name reachability), `BuggyCreateOverwritesNoProbe`
 * (silent overwrite of colliding occupant), and
 * `BuggyLookupStopsOnTombstone` (read-side analog of
 * UnlinkUsesEmpty).
 *
 * MVP scope (P8-POSIX-2 + P8-POSIX-4):
 *   - Per-pool dirent tree backed by btree_store (mirrors stm_inode_index
 *     persistence shape). Format break STM_UB_VERSION 24 → 25 adds a
 *     new `ub_dirent_root` tree-root field and binds its csum into the
 *     pool's Merkle root chain (R70 P0-1 lesson).
 *   - Open-addressing chain integrity per dirent.tla. Tombstones are
 *     kept in the btree on Unlink (encoded via STM_DIRENT_FLAG_TOMBSTONE
 *     in the value's flags byte) so a colliding name at a higher probe
 *     index stays reachable. Lookup walks past tombstones.
 *   - Probe cap STM_DIRENT_PROBE_MAX = 64 per ARCH §11.4.2.
 *   - Writer-side invariants symmetric with decoder-side (R71 P1-1
 *     lesson): every constraint the decoder enforces on read is also
 *     enforced at the alloc API boundary, so a buggy or hostile caller
 *     cannot commit a record that would wedge the pool on next mount.
 *   - readdir cursor stability per dirent.tla (P8-POSIX-4):
 *     `stm_dirent_readdir` emits live records in hash_probe-ascending
 *     order, skipping tombstones. The opaque uint64_t cursor advances
 *     past every emitted slot — same probe never returned twice within
 *     an iteration. Caller-side iteration is safe under concurrent
 *     Create/Unlink (mutations may interleave between calls); the
 *     cursor's monotone advance guarantees that no entry returned by
 *     a prior call is returned again by a later call within the same
 *     iteration.
 *
 * Out of scope here:
 *   - rename atomicity — P8-POSIX-9.
 *   - case-insensitivity (per-dataset property) — abstracted via the
 *     hash function; `casesensitive=insensitive` substitutes
 *     `fnv1a64(NFKD(lower(name)))` at the call site without changing
 *     the on-disk shape. Full impl deferred to the property layer.
 *   - Higher-level fs APIs (stm_fs_lookup / _create_file / _mkdir /
 *     _unlink / _rmdir) that compose this layer with the inode
 *     allocator — landed in P8-POSIX-2b (or P8-POSIX-3 depending on
 *     scope).
 */
#ifndef STRATUM_V2_DIRENT_H
#define STRATUM_V2_DIRENT_H

#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* On-disk constants. ARCH §11.4.                                            */
/* ========================================================================= */

/* POSIX NAME_MAX — the byte cap on a single dirent's name field. */
#define STM_DIRENT_NAME_MAX 255u

/* Probe-chain cap per ARCH §11.4.2: a lookup at probe=k for k ≥ 64
 * gives up and returns ENOENT. 64 is the bounded tail that lets the
 * reviewer assert termination without unbounded scan. */
#define STM_DIRENT_PROBE_MAX 64u

/* Tombstone flag — set in the value's `flags` byte to mark a dirent
 * record whose name has been Unlinked but whose slot must remain
 * present in the chain so a colliding name at a higher probe index
 * stays reachable. Per dirent.tla: Unlink leaves a TOMBSTONE marker;
 * Lookup walks past tombstones. */
#define STM_DIRENT_FLAG_TOMBSTONE 0x01u

/* Child-type discriminator (POSIX-shape; matches dirent.h DT_*).
 *
 * STM_DT_UNKNOWN = 0 is INVALID for live records (the writer rejects
 * it; the decoder rejects it). Tombstones encode child_type = 0
 * implicitly via the TOMBSTONE flag. */
#define STM_DT_UNKNOWN  0u
#define STM_DT_FIFO     1u
#define STM_DT_CHR      2u
#define STM_DT_DIR      4u
#define STM_DT_BLK      6u
#define STM_DT_REG      8u
#define STM_DT_LNK     10u
#define STM_DT_SOCK    12u

/* On-disk value layout (variable-length, 32 + name_len bytes):
 *
 *   off  size  field                       contract
 *    0     8   le64 child_ino              live: != 0; tombstone: 0
 *    8     8   le64 child_gen              live: any; tombstone: 0
 *   16     1   u8   child_type             live: STM_DT_* (non-zero, valid);
 *                                          tombstone: 0
 *   17     1   u8   name_len               live: 1..255; tombstone: 0
 *   18     1   u8   flags                  bit 0: TOMBSTONE
 *   19    13   u8[13] reserved             zero (anti-tamper)
 *   32   var   u8[name_len] name           live: name_len bytes (no NUL);
 *                                          tombstone: 0 bytes
 *
 * Total = 32 + name_len bytes.
 *
 * On-disk key layout (fixed 24 bytes):
 *
 *   off  size  field                       contract
 *    0     8   le64 dataset_id             non-zero
 *    8     8   le64 dir_ino                non-zero
 *   16     8   le64 hash_probe             fnv1a64(name) + probe_offset
 */

/* ========================================================================= */
/* Forward decl + lifecycle.                                                 */
/* ========================================================================= */

struct stm_dirent_index;
typedef struct stm_dirent_index stm_dirent_index;

/* Allocate an empty in-memory dirent index. Returns NULL on
 * STM_ENOMEM. Mirrors `stm_inode_index_create`. */
stm_dirent_index *stm_dirent_index_create(void);

/* Free the index (in-RAM records, persistence handles). Safe on NULL. */
void stm_dirent_index_close(stm_dirent_index *idx);

/* ========================================================================= */
/* In-memory operations. Models dirent.tla's actions.                         */
/* ========================================================================= */

/*
 * Create — link `name` to `child_ino` in directory `dir_ino` of
 * `dataset_id`. Models `dirent.tla::Create`.
 *
 * Walks the open-addressing chain from probe 0 looking for either:
 *   - first EMPTY slot (no record at that key) → install here;
 *   - first TOMBSTONE slot → remember as install candidate, keep walking
 *     to verify `name` not already present further in the chain;
 *   - record with same name → STM_EEXIST;
 *   - record with different name → continue probing.
 *
 * Refusals:
 *   - NULL idx OR NULL name (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 OR child_ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_DIRENT_NAME_MAX (STM_EINVAL).
 *   - child_type not one of {STM_DT_FIFO, _CHR, _DIR, _BLK, _REG, _LNK,
 *     _SOCK} (STM_EINVAL — STM_DT_UNKNOWN=0 is reserved for tombstones).
 *   - name already linked in (dataset_id, dir_ino) (STM_EEXIST).
 *   - chain exhausted (STM_DIRENT_PROBE_MAX probes consumed without finding
 *     an install slot) → STM_ENOSPC.
 */
STM_MUST_USE
stm_status stm_dirent_alloc(stm_dirent_index *idx,
                                uint64_t dataset_id, uint64_t dir_ino,
                                const uint8_t *name, uint8_t name_len,
                                uint64_t child_ino, uint64_t child_gen,
                                uint8_t child_type);

/*
 * Lookup `name` in directory `dir_ino`. Models `dirent.tla::LookupWalk`.
 *
 * Walks the chain from probe 0:
 *   - EMPTY slot → STM_ENOENT (chain ends here).
 *   - TOMBSTONE slot → continue.
 *   - record with same name → return child triple via out params.
 *   - record with different name → continue.
 *   - chain exhausted (STM_DIRENT_PROBE_MAX probes) → STM_ENOENT.
 *
 * `out_child_ino` is required; `out_child_gen` and `out_child_type`
 * are optional (pass NULL if not needed).
 *
 * Refusals:
 *   - NULL idx OR NULL name OR NULL out_child_ino (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_DIRENT_NAME_MAX (STM_EINVAL).
 *   - No match in chain → STM_ENOENT.
 */
STM_MUST_USE
stm_status stm_dirent_lookup(const stm_dirent_index *idx,
                                 uint64_t dataset_id, uint64_t dir_ino,
                                 const uint8_t *name, uint8_t name_len,
                                 uint64_t *out_child_ino,
                                 uint64_t *out_child_gen,
                                 uint8_t *out_child_type);

/*
 * Unlink `name` from directory `dir_ino`. Models `dirent.tla::Unlink`.
 *
 * Walks the chain to find the live record matching `name`, replaces
 * the slot with a TOMBSTONE (NOT EMPTY — that would break colliding
 * names at higher probe indices per dirent.tla::BuggyUnlinkUsesEmpty).
 *
 * Refusals:
 *   - NULL idx OR NULL name (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_DIRENT_NAME_MAX (STM_EINVAL).
 *   - No match in chain → STM_ENOENT.
 */
STM_MUST_USE
stm_status stm_dirent_unlink(stm_dirent_index *idx,
                                 uint64_t dataset_id, uint64_t dir_ino,
                                 const uint8_t *name, uint8_t name_len);

/*
 * Count live (non-tombstone) dirents in directory `dir_ino`. Used to
 * implement POSIX `nlink` for directories (parent + children + 1 for
 * `.` self-link) and to gate `rmdir` on empty directories.
 *
 * Refusals:
 *   - NULL idx OR NULL out_count (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_dirent_count_for_dir(const stm_dirent_index *idx,
                                        uint64_t dataset_id, uint64_t dir_ino,
                                        size_t *out_count);

/* ========================================================================= */
/* Readdir (P8-POSIX-4). Models dirent.tla's ReaddirReset/Step/End cycle.    */
/* ========================================================================= */

/*
 * On-the-wire entry returned by stm_dirent_readdir. The `hash_probe`
 * field is informational (= the slot at which the record lives in the
 * open-addressing chain) — useful for debugging and for callers that
 * want to encode a per-entry resume token. The fs-layer wrapper
 * (`stm_fs_readdir`) does not surface this field.
 */
typedef struct stm_dirent_entry {
    uint64_t child_ino;
    uint64_t child_gen;
    uint64_t hash_probe;
    uint8_t  child_type;          /* STM_DT_* */
    uint8_t  name_len;
    uint8_t  name[STM_DIRENT_NAME_MAX];
} stm_dirent_entry;

/*
 * Iterate live records under (dataset_id, dir_ino) in hash_probe
 * ascending order. Models dirent.tla's `ReaddirReset(d) ; ReaddirStep(d)*
 * ; ReaddirEnd(d)` cycle, but collapsed to a single C call boundary —
 * a single call advances the cursor through up to `max_entries` records.
 *
 * Cursor semantics (opaque to caller; treat as `uint64_t`):
 *   - First call: pass `*cursor = 0`. The impl returns the smallest-
 *     probe live records.
 *   - Subsequent calls: pass back the `*cursor` value the prior call
 *     returned. The impl resumes at the next probe past the last
 *     returned record (strict monotonic advance — no duplicate emit).
 *   - Iteration done: `*out_returned == 0` after a call. The cursor
 *     value at that point is "past the highest-probe live record",
 *     saturated at UINT64_MAX if the highest live record was at
 *     UINT64_MAX itself.
 *
 * UINT64_MAX as iteration sentinel (R75 P2-1): when the impl
 * advances the cursor to UINT64_MAX (either organically from
 * `last_probe + 1` or saturating from a record at probe=UINT64_MAX
 * itself), subsequent calls short-circuit on entry — they return
 * STM_OK with `*out_returned = 0` regardless of whether further
 * records exist at lower probes. This means callers MUST start
 * iteration at `*cursor = 0` (not UINT64_MAX) and treat
 * `*cursor == UINT64_MAX` after a call as "iteration done"
 * equivalently to `*out_returned == 0`.
 *
 * Stability under concurrent Create/Unlink (between-call interleaving):
 *   - A Create that installs at probe < cursor is invisible to the
 *     remaining iteration (the cursor has already passed).
 *   - A Create at probe ≥ cursor will be returned IF the iteration
 *     reaches that probe before the next Create displaces it.
 *   - An Unlink (which leaves a tombstone) at any probe is honored:
 *     tombstones are skipped — never returned as live entries.
 *   - The same record's hash_probe never appears twice within a
 *     single iteration, even under interleaved Create/Unlink — the
 *     cursor's strict monotone advance guarantees this.
 *
 * POSIX: matches the contract of `readdir(3)` — caller-relative
 * stability for entries that survive the iteration window; entries
 * created/deleted mid-iteration are caller-defined (POSIX permits
 * either visible or invisible).
 *
 * Refusals:
 *   - NULL idx OR NULL cursor OR NULL out_entries OR NULL out_returned
 *     (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 (STM_EINVAL).
 *   - max_entries == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_dirent_readdir(const stm_dirent_index *idx,
                                  uint64_t dataset_id, uint64_t dir_ino,
                                  uint64_t *cursor,
                                  stm_dirent_entry *out_entries,
                                  size_t max_entries,
                                  size_t *out_returned);

/*
 * Drop EVERY record (live + tombstone) keyed at `(dataset_id, dir_ino,
 * *)`. Used by `stm_fs_rmdir` (P8-POSIX-2b R73 P2-1) to GC the
 * orphan-tombstone trail left by unlinks of the directory's prior
 * children before the directory itself is freed. Without this, a
 * directory with churn (create-then-unlink across many entries)
 * leaves tombstones in the btree that survive the rmdir; if the dir's
 * ino is later AllocReused for a fresh directory, that new directory
 * inherits the old tombstones and burns probe budget walking past
 * them.
 *
 * Output: `*out_dropped` (optional) is set to the number of records
 * removed (live + tombstone, summed). Pass NULL to ignore.
 *
 * Caller-visible-elsewhere semantic: tests + future scrub-style GC
 * passes use this to drive directory-scope cleanup. Live records
 * removed are not POSIX-orphaned in the rmdir use-case (the dir
 * itself was just empty-checked) — for general callers, ensure the
 * dir is empty BEFORE calling.
 *
 * Refusals:
 *   - NULL idx (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_dirent_drop_for_dir(stm_dirent_index *idx,
                                       uint64_t dataset_id, uint64_t dir_ino,
                                       size_t *out_dropped);

/* ========================================================================= */
/* Persistence (P8-POSIX-2, v25).                                            */
/*                                                                            */
/* The dirent index is persisted as a btree_store-encoded, AEAD-encrypted    */
/* Bε-tree under `ub_dirent_root` on device 0. Same envelope as the inode    */
/* / extent / cas trees: AEAD nonce `paddr || gen || pool_uuid`, AD          */
/* `pool_uuid || device_uuid_0`, idempotent commit via internal dirty flag,  */
/* atomic shadow-swap on load_at.                                            */
/* ========================================================================= */

struct stm_bdev;       typedef struct stm_bdev stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap stm_bootstrap;

STM_MUST_USE
stm_status stm_dirent_index_set_storage(stm_dirent_index *idx,
                                            stm_bdev *bdev_0,
                                            stm_bootstrap *boot_0);

STM_MUST_USE
stm_status stm_dirent_index_set_crypt_ctx(stm_dirent_index *idx,
                                              const uint8_t *metadata_key,
                                              const uint64_t pool_uuid[2],
                                              const uint64_t device_uuid_0[2]);

STM_MUST_USE
stm_status stm_dirent_index_commit(stm_dirent_index *idx,
                                       uint64_t committed_gen,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32]);

STM_MUST_USE
stm_status stm_dirent_index_load_at(stm_dirent_index *idx,
                                        uint64_t root_paddr,
                                        uint64_t root_gen,
                                        const uint8_t expected_csum[32]);

STM_MUST_USE
stm_status stm_dirent_index_get_root(const stm_dirent_index *idx,
                                         uint64_t *out_root_paddr,
                                         uint8_t out_root_csum[32]);

STM_MUST_USE
stm_status stm_dirent_index_get_gen(const stm_dirent_index *idx,
                                        uint64_t *out_root_gen);

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_DIRENT_H */
