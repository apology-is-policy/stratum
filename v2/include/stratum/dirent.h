/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — directory entry layer (P8-POSIX-2).
 *
 * Implements the on-disk dirent record + the per-dataset dirent index
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
 * Storage evolution:
 *   - P8-POSIX-2 → 9.6-impl-4c: per-pool dirent tree backed by
 *     btree_engine, keyed by 24-byte `(le64 dataset_id || le64 dir_ino
 *     || le64 hash_probe)`. STM_UB_VERSION 24..29.
 *   - 9.7-impl-1c-iii: per-dataset btree_engine. Each dataset's
 *     dirent records live in that dataset's engine (the substrate
 *     from 9.7-impl-1c-i), resolved via an attached
 *     `stm_dataset_index *`. Keys shrink to 17 bytes — the 1-byte
 *     STM_METAKEY_KIND_DIRENT tag replaces the 8-byte dataset_id
 *     prefix; the dataset id is woven into the engine's AEAD
 *     additional-data via `tree_id = dataset_id`. Cross-dataset
 *     substitution attacks fail decrypt rather than relying on the
 *     key prefix.
 *
 * Open-addressing chain integrity per dirent.tla. Tombstones are
 * kept in the engine on Unlink (encoded via STM_DIRENT_FLAG_TOMBSTONE
 * in the value's flags byte) so a colliding name at a higher probe
 * index stays reachable. Lookup walks past tombstones.
 *
 * Probe cap STM_DIRENT_PROBE_MAX = 64 per ARCH §11.4.2.
 *
 * Writer-side invariants symmetric with decoder-side (R71 P1-1
 * lesson): every constraint the decoder enforces on read is also
 * enforced at the alloc API boundary, so a buggy or hostile caller
 * cannot commit a record that would wedge the pool on next mount.
 *
 * readdir cursor stability per dirent.tla (P8-POSIX-4):
 * `stm_dirent_readdir` emits live records in hash_probe-ascending
 * order, skipping tombstones. The opaque uint64_t cursor advances
 * past every emitted slot — same probe never returned twice within
 * an iteration. Caller-side iteration is safe under concurrent
 * Create/Unlink (mutations may interleave between calls); the
 * cursor's monotone advance guarantees that no entry returned by
 * a prior call is returned again by a later call within the same
 * iteration.
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

/* Forward-decl (9.7-impl-1c-iii): the dirent module borrows a dataset
 * index via stm_dirent_index_attach_dataset_index. */
struct stm_dataset_index;
typedef struct stm_dataset_index stm_dataset_index;

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

/* Whiteout flag (P8-POSIX-9b — Linux renameat2 RENAME_WHITEOUT) —
 * marks a slot as a whiteout: distinct from TOMBSTONE in that the
 * `name` field is preserved (so readdir can EMIT the whiteout for
 * overlayfs userspace to interpret) but child_ino is zero (so the
 * name is hidden from lookup). Mutually exclusive with TOMBSTONE
 * — a slot is exactly one of {live record, tombstone, whiteout,
 * empty}. Per dirent.tla::Whiteout. */
#define STM_DIRENT_FLAG_WHITEOUT 0x02u

/* Child-type discriminator (POSIX-shape; matches dirent.h DT_*).
 *
 * STM_DT_UNKNOWN = 0 is INVALID for live records (the writer rejects
 * it; the decoder rejects it). Tombstones encode child_type = 0
 * implicitly via the TOMBSTONE flag. Whiteouts encode child_type =
 * STM_DT_WHITEOUT = 14 (matches Linux DT_WHT). */
#define STM_DT_UNKNOWN  0u
#define STM_DT_FIFO     1u
#define STM_DT_CHR      2u
#define STM_DT_DIR      4u
#define STM_DT_BLK      6u
#define STM_DT_REG      8u
#define STM_DT_LNK     10u
#define STM_DT_SOCK    12u
#define STM_DT_WHITEOUT 14u

/* On-disk value layout (variable-length, 32 + name_len bytes):
 *
 *   off  size  field           live           tombstone   whiteout (P9b)
 *    0     8   le64 child_ino  != 0           0           0
 *    8     8   le64 child_gen  any            0           0
 *   16     1   u8   child_type STM_DT_*       0           STM_DT_WHITEOUT (14)
 *                              (1,2,4,6,8,
 *                              10,12; not 14)
 *   17     1   u8   name_len   1..255         0           1..255
 *   18     1   u8   flags      0              bit 0       bit 1
 *                                             (TOMBSTONE) (WHITEOUT)
 *   19    13   u8[13] reserved 0 (anti-tamper, all kinds)
 *   32   var   u8[name_len]    name_len bytes 0 bytes     name_len bytes
 *              name            (no NUL)                   (no NUL — preserved
 *                                                          from prior live
 *                                                          record)
 *
 * Bits 0 (TOMBSTONE) and 1 (WHITEOUT) are mutually exclusive — the
 * decoder rejects records with both set. Bits 2..7 are reserved
 * zero. STM_DT_WHITEOUT (=14) is reserved for whiteout slots ONLY:
 * the decoder rejects "live" records claiming type=14, and rejects
 * whiteouts claiming any other type.
 *
 * Total = 32 + name_len bytes.
 *
 * On-disk key layout (9.7-impl-1c-iii — fixed 17 bytes):
 *
 *   off  size  field                       contract
 *    0     1   u8   STM_METAKEY_KIND_DIRENT  metakey tag (=0x02)
 *    1     8   le64 dir_ino                non-zero
 *    9     8   le64 hash_probe             fnv1a64(name) + probe_offset
 *
 * The dataset_id prefix is retired; cross-dataset substitution
 * defense lives in the engine layer via `tree_id = dataset_id` in
 * AEAD AD. R71 P1-1 doctrine: writer-side and decoder-side bounds
 * checks SYMMETRIC at the tag byte (stm_metakey_compose /
 * stm_metakey_parse pin the tag chokepoint) AND at the body
 * (the per-module decoder enforces the 16-byte body length +
 * dir_ino-non-zero invariant on every read-back).
 */

/* ========================================================================= */
/* Forward decl + lifecycle.                                                 */
/* ========================================================================= */

struct stm_dirent_index;
typedef struct stm_dirent_index stm_dirent_index;

/* Allocate an empty in-memory dirent index. Returns NULL on
 * STM_ENOMEM. Mirrors `stm_inode_index_create`. */
stm_dirent_index *stm_dirent_index_create(void);

/* Free the index (in-RAM records, borrowed ds_idx pointer is NOT
 * freed — its lifecycle is owned by the caller, typically stm_sync).
 * Safe on NULL. */
void stm_dirent_index_close(stm_dirent_index *idx);

/*
 * 9.7-impl-1c-iii: attach the dataset index. The dirent module borrows
 * the `ds_idx` pointer; the caller MUST keep it alive for the dirent
 * index's lifetime. The attach is one-time — re-binding returns
 * STM_EINVAL.
 *
 * Lifetime: idx and ds_idx are typically both owned by stm_sync; they
 * are created together at open and destroyed together at close. The
 * borrow is safe by construction in the production path.
 *
 * Every public dirent op resolves the dataset's per-dataset engine via
 * the attached ds_idx, lazily opening the engine on first use per
 * `stm_dataset_index_get_engine`.
 *
 * Refusals:
 *   - NULL idx OR NULL ds_idx (STM_EINVAL).
 *   - Re-attach (STM_EINVAL — the attach is one-time).
 */
STM_MUST_USE
stm_status stm_dirent_index_attach_dataset_index(stm_dirent_index *idx,
                                                 stm_dataset_index *ds_idx);

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
 * P8-POSIX-9b: atomically swap the (child_ino, child_gen, child_type)
 * triples of two live dirents. Models `dirent.tla::Swap`.
 *
 * Linux `renameat2(2)` `RENAME_EXCHANGE` semantics: after the call,
 *   dir1/name1 refers to what dir2/name2 used to refer to (and vice
 *   versa); both names continue to exist; no inode is created or
 *   freed.
 *
 * Implementation: walks each chain to find the live record at
 * (dir1, name1) and (dir2, name2), then swaps the (ino, gen, type)
 * fields in-place. Slot positions don't move — chain integrity is
 * preserved by construction.
 *
 * Same-dir + cross-dir cases are unified — `dir1 == dir2` is legal
 * provided `name1 != name2`. Self-swap (same dir AND same name)
 * refuses with STM_EINVAL.
 *
 * Atomicity: under the dirent-index mutex (the only lock dirent
 * primitives take), the two slot updates land in one critical
 * section — no observer can see a half-swapped state.
 *
 * Refusals:
 *   - NULL idx OR NULL name1 OR NULL name2 (STM_EINVAL).
 *   - dataset_id == 0 OR either dir_ino == 0 (STM_EINVAL).
 *   - any name_len == 0 OR > STM_DIRENT_NAME_MAX (STM_EINVAL).
 *   - dir1 == dir2 AND name1 == name2 (STM_EINVAL — self-swap).
 *   - either name not found in its dir (STM_ENOENT).
 */
STM_MUST_USE
stm_status stm_dirent_swap_two(stm_dirent_index *idx,
                                   uint64_t dataset_id,
                                   uint64_t dir1_ino,
                                   const uint8_t *name1, uint8_t name1_len,
                                   uint64_t dir2_ino,
                                   const uint8_t *name2, uint8_t name2_len);

/*
 * P8-POSIX-9b: convert a live record at `(dataset_id, dir_ino, name)`
 * to a WHITEOUT marker. Models `dirent.tla::Whiteout`.
 *
 * Linux `renameat2(2)` `RENAME_WHITEOUT` semantics: after the rename,
 *   - dst gets src's prior inode reference (handled by the caller via
 *     `stm_dirent_alloc(dst, src_ino)`),
 *   - src becomes a WHITEOUT slot — preserves the name (visible to
 *     readdir as a `STM_DT_WHITEOUT` entry with `child_ino = 0`)
 *     so overlayfs userspace can interpret it as "hide the lower
 *     layer's same name".
 *
 * Distinct from TOMBSTONE:
 *   - TOMBSTONE: invisible to readdir + invisible to lookup; the
 *     name field is cleared.
 *   - WHITEOUT:  VISIBLE to readdir (with `STM_DT_WHITEOUT` type +
 *     `child_ino=0`); INVISIBLE to lookup (returns STM_ENOENT); the
 *     name field is PRESERVED so userspace sees the whiteout marker.
 *
 * After this returns:
 *   - `stm_dirent_lookup(name)` returns `STM_ENOENT` (the whiteout
 *     hides the name).
 *   - `stm_dirent_alloc(name, ...)` SUCCEEDS by overwriting the
 *     whiteout slot with a fresh live record (chain integrity
 *     preserved by construction — the slot position doesn't change).
 *   - `stm_dirent_readdir` emits the whiteout entry with
 *     `child_ino=0`, `child_type=STM_DT_WHITEOUT`, and the original
 *     name preserved in the entry.
 *
 * Refusals:
 *   - NULL idx OR NULL name (STM_EINVAL).
 *   - dataset_id == 0 OR dir_ino == 0 (STM_EINVAL).
 *   - name_len == 0 OR name_len > STM_DIRENT_NAME_MAX (STM_EINVAL).
 *   - No live record at `(dataset_id, dir_ino, name)` (STM_ENOENT —
 *     the chain ended at EMPTY/TOMBSTONE/WHITEOUT/end before
 *     finding a matching live record).
 */
STM_MUST_USE
stm_status stm_dirent_whiteout(stm_dirent_index *idx,
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
/* Persistence (9.7-impl-1c-iii: per-dataset metadata-tree engines).          */
/*                                                                            */
/* As of 9.7-impl-1c-iii the dirent module owns NO storage of its own. Each  */
/* dataset's dirent records live in that dataset's per-dataset btree_engine  */
/* (the substrate from 9.7-impl-1c-i), keyed by `stm_metakey_compose`:       */
/*                                                                            */
/*   key (17 bytes): le8 STM_METAKEY_KIND_DIRENT || le64 dir_ino             */
/*                   || le64 hash_probe                                       */
/*   value (32 + name_len bytes): tombstone/whiteout/live encoded per the    */
/*   layout doc at the top of this header.                                   */
/*                                                                            */
/* The dataset id is folded into the engine's AEAD additional-data via the   */
/* engine's tree_id; cross-dataset substitution attacks fail decrypt.        */
/* That is why the key no longer carries the dataset_id prefix it had at    */
/* P8-POSIX-2 / 9.6-impl-4c.                                                  */
/*                                                                            */
/* The pool-global `ub_dirent_root` / `ub_dirent_root_gen` /                  */
/* `ub_dirent_root_csum` fields are stamped ZERO at 1c-iii; the dirent_csum  */
/* slot in the pool Merkle root is also zero bytes. The per-dataset engine  */
/* roots are transitively covered by `main_csum` (the dataset_index tree's  */
/* root csum, which serializes each slot's (di_tree_root, di_root_gen,      */
/* di_root_csum) triple). Full UB field retirement to reserved-on-the-wire  */
/* happens at 1c-vi when all four pool-global engines (inode, dirent, xattr,*/
/* extent) are retired together.                                             */
/* ========================================================================= */

/* ========================================================================= */
/* 9.7-impl-5: readable .snaps support — frozen-tree dirent lookup + readdir. */
/* ========================================================================= */

/*
 * Look up `name` under `dir_ino` in the FROZEN tree rooted at
 * `(root_paddr, root_gen, root_csum)`. Opens a THROWAWAY read-only
 * engine via the attached `ds_idx`, walks the open-addressing hash
 * chain via repeated `stm_dataset_index_lookup_engine_at` probes
 * (mirrors the live `stm_dirent_lookup` semantics: TOMBSTONE skips,
 * matching WHITEOUT hides as STM_ENOENT, EMPTY ends the chain),
 * and returns the child inode info.
 *
 * `dataset_id` is the snapshot's dataset (AEAD `tree_id`). The triple
 * is the snapshot's captured tree-root. Used by the .snaps surface
 * to resolve path components inside a snap.
 *
 * Refusals: same shape as `stm_dirent_lookup` — NULL idx / name /
 * out_child_ino, name_len == 0 OR > STM_DIRENT_NAME_MAX,
 * dataset_id == 0 OR dir_ino == 0 → STM_EINVAL. STM_ENOENT if no
 * matching record OR a matching whiteout. STM_ECORRUPT on Merkle /
 * decoder. STM_EBADTAG on AEAD.
 */
STM_MUST_USE
stm_status stm_dirent_lookup_at_root(const stm_dirent_index *idx,
                                        uint64_t dataset_id,
                                        uint64_t root_paddr,
                                        uint64_t root_gen,
                                        const uint8_t root_csum[32],
                                        uint64_t dir_ino,
                                        const uint8_t *name, uint8_t name_len,
                                        uint64_t *out_child_ino,
                                        uint64_t *out_child_gen,
                                        uint8_t *out_child_type);

/*
 * Iterate live records under `dir_ino` in the FROZEN tree rooted at
 * `(root_paddr, root_gen, root_csum)`. Same cursor semantics as
 * `stm_dirent_readdir` (caller starts at *cursor = 0; subsequent
 * calls pass the returned cursor back; *out_returned == 0 indicates
 * iteration done). Opens a THROWAWAY engine via the attached
 * `ds_idx`, runs `stm_btree_engine_scan_range` over the dir's
 * keyspace, sorts by hash_probe, applies the cursor filter, emits.
 *
 * The frozen tree is read-only — there are no concurrent mutators —
 * so the stability-under-Create/Unlink contract from the live
 * readdir trivially holds (no Creates or Unlinks happen against a
 * snapshot). Tombstones are skipped; whiteouts are skipped (snap-view
 * doesn't surface overlayfs whiteout semantics at v1.0).
 *
 * Refusals: same shape as `stm_dirent_readdir`.
 */
STM_MUST_USE
stm_status stm_dirent_readdir_at_root(const stm_dirent_index *idx,
                                         uint64_t dataset_id,
                                         uint64_t root_paddr,
                                         uint64_t root_gen,
                                         const uint8_t root_csum[32],
                                         uint64_t dir_ino,
                                         uint64_t *cursor,
                                         stm_dirent_entry *out_entries,
                                         size_t max_entries,
                                         size_t *out_returned);

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_DIRENT_H */
