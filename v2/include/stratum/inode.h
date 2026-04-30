/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — inode layer (P8-POSIX-1).
 *
 * Implements the on-disk inode struct and the in-memory inode index
 * per ARCHITECTURE §11.3. The index is the canonical mapping from
 * `(dataset_id, ino)` → 256-byte inode value, plus the allocator
 * state machine (`stm_inode_alloc` / `stm_inode_free`) that maintains
 * the (ino, si_gen) tuple-uniqueness invariant pinned by inode.tla.
 *
 * Spec-to-code: this file realizes the allocator state machine modeled
 * in `v2/specs/inode.tla`. Each new public action below maps to a TLA+
 * action of the same name. The two buggy configs in the spec
 * enumerate the canonical allocator failure modes the reviewer must
 * rule out — `BuggyReuseNoGenBump` (silent (ino, gen) aliasing) and
 * `BuggyDoubleAllocate` (double-issue without intervening free).
 *
 * MVP scope (P8-POSIX-1):
 *   - In-memory only. Persistence (per-dataset inode tree backed by
 *     the existing btree_store envelope) lands at P8-POSIX-1b
 *     alongside the STM_UB_VERSION 23 → 24 format break.
 *   - Alloc-fresh only — `stm_inode_alloc` always returns
 *     `next_ino++`. Re-use of FREED inos is deferred to P8-POSIX-1b.
 *     The (ino, si_gen) uniqueness invariant still holds: every
 *     freshly-allocated ino has si_gen=0 and the same ino is never
 *     issued twice (no AllocReused path yet). Future P8-POSIX-1b
 *     add the reuse path with si_gen += 1, exactly as inode.tla
 *     models AllocReused.
 *   - No nlink-driven cascade-free yet — caller-driven Free only.
 *     nlink semantics + auto-delete on nlink == 0 land at P8-POSIX-3.
 *   - No tagged data union state machine (extent vs inline vs
 *     symlink vs device) — the inode value carries the bytes but
 *     no helper APIs flip kinds yet. P8-POSIX-5 covers
 *     inline-to-extent.
 *
 * Out of scope here:
 *   - `stm_fs_lookup` / `stm_fs_create_file` / etc. — those are
 *     dirent-layer ops at P8-POSIX-2.
 *   - xattr / ACL — P8-POSIX-6.
 *   - Persistence + sync_commit hookup — P8-POSIX-1b.
 */
#ifndef STRATUM_V2_INODE_H
#define STRATUM_V2_INODE_H

#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* On-disk inode value. ARCH §11.3.                                          */
/* ========================================================================= */

#define STM_INODE_SIZE_BYTES 256u

/* Tagged data-union variants. Stored in `si_data_kind`. */
#define STM_DATA_EXTENT   0x01u   /* `si_data.extent_tree` is valid */
#define STM_DATA_INLINE   0x02u   /* `si_data.inline_data[si_data_len]` is valid */
#define STM_DATA_SYMLINK  0x03u   /* `si_data.symlink_target[si_data_len]` is valid */
#define STM_DATA_DEVICE   0x04u   /* `si_data.device.{dev_major, dev_minor}` valid */

/* Cap on inline data + symlink target (ARCH §11.3.3). */
#define STM_INODE_INLINE_MAX 100u

/* Common file flags (subset of v1's set; extends as needed). */
#define STM_INO_FLAG_IMMUTABLE  0x00000001u
#define STM_INO_FLAG_APPEND     0x00000002u
#define STM_INO_FLAG_NODUMP     0x00000004u

/*
 * 256-byte inode value. Layout per ARCH §11.3.
 *
 * v2 simplification vs ARCH §11.3.1: the extent-tree-root variant
 * stores `(paddr, gen)` (16 bytes) rather than ARCH's `struct stm_bptr`
 * (57 bytes). v2's existing dataset / extent / cas / snapshot trees
 * also reference their roots by `(paddr, gen)` — AEAD MAC-tag
 * verification at read time replaces v1's BLAKE3 csum field, so the
 * stm_bptr's separate csum is redundant. The 41 bytes saved become
 * additional padding in `si_reserved`.
 *
 * All multi-byte integer fields use the `le*` host-to-LE wrappers
 * defined in `stratum/types.h` so on-disk persistence is endian-stable.
 */
struct __attribute__((packed)) stm_inode_value {
    /* Identity + ownership — 40 bytes. */
    le64    si_ino;            /* inode number (unique within dataset) */
    le64    si_dataset_id;     /* dataset containing this inode */
    le64    si_gen;            /* generation counter (P8-POSIX-1: 0 always) */
    le32    si_mode;           /* file type + permissions (POSIX mode_t) */
    le32    si_uid;            /* owner UID */
    le32    si_gid;            /* owner GID */
    le32    si_nlink;          /* hard-link count */

    /* Timestamps — 48 bytes (4 × 12 each: 8B sec + 4B nsec). */
    le64    si_btime_sec;      /* creation time (immutable; ARCH §11.3) */
    le32    si_btime_nsec;
    le64    si_atime_sec;      /* access time */
    le32    si_atime_nsec;
    le64    si_mtime_sec;      /* content modification */
    le32    si_mtime_nsec;
    le64    si_ctime_sec;      /* metadata change */
    le32    si_ctime_nsec;

    /* Size + flags — 24 bytes. */
    le64    si_size;           /* logical size in bytes */
    le64    si_allocated;      /* blocks actually allocated */
    uint8_t si_data_kind;      /* STM_DATA_* */
    uint8_t si_data_len;       /* bytes of inline / symlink storage used (≤100) */
    le16    si_xattr_count;    /* quick count (auth via xattr-tree walk) */
    le32    si_flags;          /* STM_INO_FLAG_* */

    /* Tagged data union — 100 bytes. */
    union {
        struct {
            le64    paddr;     /* tree root paddr */
            le64    gen;       /* tree root gen for AEAD nonce reconstruction */
            uint8_t pad[84];
        } extent_tree;                      /* STM_DATA_EXTENT */
        uint8_t inline_data[STM_INODE_INLINE_MAX];     /* STM_DATA_INLINE */
        uint8_t symlink_target[STM_INODE_INLINE_MAX];  /* STM_DATA_SYMLINK */
        struct {
            le32    dev_major;
            le32    dev_minor;
            uint8_t pad[92];
        } device;                           /* STM_DATA_DEVICE */
    } si_data;

    /* Reserved (44 bytes) — padding to STM_INODE_SIZE_BYTES. */
    uint8_t si_reserved[44];
};

STM_STATIC_ASSERT(sizeof(struct stm_inode_value) == STM_INODE_SIZE_BYTES,
                  "stm_inode_value must be exactly STM_INODE_SIZE_BYTES (256)");

/* ========================================================================= */
/* In-memory inode index.                                                    */
/* ========================================================================= */

struct stm_inode_index;
typedef struct stm_inode_index stm_inode_index;

/*
 * Create an empty inode index. The returned handle owns its lock and
 * its records array; callers must `stm_inode_index_close` to free.
 *
 * Returns NULL on allocation failure.
 */
stm_inode_index *stm_inode_index_create(void);

/* Close + free the index. Safe with NULL. */
void stm_inode_index_close(stm_inode_index *idx);

/*
 * Allocate a fresh inode in `dataset_id`, returning the new inode
 * number in `*out_ino`. `mode` / `uid` / `gid` populate the initial
 * inode value's identity fields; `nlink` starts at 1, all timestamps
 * at 0 (caller is expected to stamp them on the next set), data_kind
 * = STM_DATA_INLINE with len=0 (empty inline file).
 *
 * Reserved sentinel ino values: `0` (caller-rejected at every public
 * API) and `UINT64_MAX` (saturation guard — when next_ino reaches
 * UINT64_MAX, alloc returns STM_ENOSPC rather than wrap on the
 * subsequent bump). Practical ceiling is therefore UINT64_MAX-1
 * issued inodes per dataset. [R69 P3-1: sentinel previously
 * undocumented; future callers using UINT64_MAX as a "no inode"
 * marker now have authoritative coverage.]
 *
 * MVP — alloc-fresh-only path: `*out_ino = next_ino[dataset_id]++`.
 * `si_gen` = 0. Models inode.tla's AllocFresh action.
 *
 * Refusals:
 *   - NULL idx OR NULL out_ino (STM_EINVAL).
 *   - dataset_id == 0 (STM_EINVAL — root dataset id reserved).
 *   - mode == 0 (STM_EINVAL — non-zero mode required; full S_IFMT
 *     file-type validation is the dirent layer's responsibility at
 *     P8-POSIX-2, since the inode allocator alone cannot distinguish
 *     a regular-file create from a mkdir from a special-file mknod).
 *     [R69 P2-1: contract reconciled — impl checks non-zero, this
 *      docstring previously claimed "file type bits required" which
 *      didn't match the impl. Until P8-POSIX-2 lands the dirent
 *      layer, callers asking for an inode are trusted with mode.]
 *   - STM_ENOMEM if records array can't grow.
 */
STM_MUST_USE
stm_status stm_inode_alloc(stm_inode_index *idx, uint64_t dataset_id,
                              uint32_t mode, uint32_t uid, uint32_t gid,
                              uint64_t *out_ino);

/*
 * Free the inode at (dataset_id, ino). The record's state flips to
 * FREED but the record's `si_gen` is preserved for a future
 * AllocReused (P8-POSIX-1b). Models inode.tla's Free action.
 *
 * Refusals:
 *   - NULL idx OR dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - No record at (dataset_id, ino) OR record already FREED (STM_ENOENT).
 */
STM_MUST_USE
stm_status stm_inode_free(stm_inode_index *idx, uint64_t dataset_id,
                             uint64_t ino);

/*
 * Look up the inode at (dataset_id, ino). Returns the 256-byte value
 * via `*out_value`.
 *
 * Refusals:
 *   - NULL idx OR NULL out_value (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - No record OR record FREED (STM_ENOENT).
 */
STM_MUST_USE
stm_status stm_inode_lookup(const stm_inode_index *idx,
                               uint64_t dataset_id, uint64_t ino,
                               struct stm_inode_value *out_value);

/*
 * Replace the inode value at (dataset_id, ino). The caller-provided
 * `in_value` MUST have `si_ino` and `si_dataset_id` matching the
 * lookup key; `si_gen` MUST match the record's stored gen (so callers
 * cannot accidentally overwrite the spec's tuple-uniqueness invariant
 * via a buggy gen value); `si_data_kind` MUST be one of STM_DATA_*.
 * The 44-byte `si_reserved` region is zeroed on every successful
 * Set so a future format extension reading those bytes inherits a
 * defined-zero value rather than caller-controlled noise. [R69 P3-2
 * + P3-3: reserved-passthrough + data_kind-passthrough hardened.]
 *
 * Refusals:
 *   - NULL idx OR NULL in_value (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - in_value->si_ino mismatch (STM_EINVAL).
 *   - in_value->si_dataset_id mismatch (STM_EINVAL).
 *   - in_value->si_gen mismatch (STM_EINVAL — protects the tuple
 *     uniqueness invariant from caller error).
 *   - in_value->si_data_kind not in {STM_DATA_EXTENT, STM_DATA_INLINE,
 *     STM_DATA_SYMLINK, STM_DATA_DEVICE} (STM_EINVAL — protects
 *     downstream union readers from undefined kind values).
 *   - No record OR record FREED (STM_ENOENT).
 */
STM_MUST_USE
stm_status stm_inode_set(stm_inode_index *idx, uint64_t dataset_id,
                            uint64_t ino,
                            const struct stm_inode_value *in_value);

/*
 * Count ALLOCATED inodes in `dataset_id`. FREED records are excluded.
 *
 * Refusals:
 *   - NULL idx OR NULL out_count (STM_EINVAL).
 *   - dataset_id == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_inode_count_for_ds(const stm_inode_index *idx,
                                     uint64_t dataset_id,
                                     size_t *out_count);

/*
 * Read the per-dataset `next_ino` high-water mark — the value the
 * NEXT alloc would return. Useful for tests + persistence
 * checkpointing (P8-POSIX-1b will commit this value into the
 * dataset_idx entry).
 *
 * Returns 0 in `*out_next` if no inode has ever been allocated in
 * the dataset.
 *
 * Refusals:
 *   - NULL idx OR NULL out_next (STM_EINVAL).
 *   - dataset_id == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_inode_next_ino(const stm_inode_index *idx,
                                 uint64_t dataset_id,
                                 uint64_t *out_next);

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_INODE_H */
