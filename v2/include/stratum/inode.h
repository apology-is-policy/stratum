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

/*
 * `si_flags` is a 32-bit field. Bit allocation (R82 P3-2,
 * P8-POSIX-7a-anon update):
 *
 *   bits  0..2   ext-style flags (IMMUTABLE / APPEND / NODUMP) — defined
 *   bits  3..7   reserved for future ext-style flag bits (DIRSYNC,
 *                NOATIME, etc.); must be zero on writes today
 *   bits  8..12  P8-POSIX-7a-seals SEAL_* (SEAL / SHRINK / GROW / WRITE
 *                / FUTURE_WRITE)
 *   bits 13..29  reserved-zero — not yet allocated to any feature; must
 *                be zero on writes; future feature blocks claim these
 *   bit  30      STM_INO_FLAG_ORPHAN — internal allocator state for
 *                P8-POSIX-7a-anon O_TMPFILE inodes (ALLOCATED + nlink=0
 *                + never-linked). Cleared on stm_inode_materialize.
 *                Caller MUST NOT set via stm_inode_set; the dedicated
 *                stm_inode_alloc_anon / _materialize paths manage it.
 *   bit  31      STM_INO_FLAG_FREED — internal allocator state encoding
 *                (FREED ⇔ ALLOCATED). Caller MUST NOT set via stm_inode_set;
 *                the write paths protect against this.
 */

/* Common file flags (subset of v1's set; extends as needed). */
#define STM_INO_FLAG_IMMUTABLE  0x00000001u
#define STM_INO_FLAG_APPEND     0x00000002u
#define STM_INO_FLAG_NODUMP     0x00000004u

/*
 * P8-POSIX-7a-seals: per-inode file seals (Linux memfd_create
 * F_SEAL_* surface; POSIX shape via fcntl(F_ADD_SEALS, F_GET_SEALS)).
 * Seals are sticky additions on a per-inode basis — they can only be
 * ADDED, never cleared. Once `STM_INO_FLAG_SEAL_SEAL` is set, no
 * further seal additions are accepted (refused with STM_EPERM at the
 * fs-layer wrapper).
 *
 * Bit layout (bits 8..12 inside the 32-bit `si_flags`):
 *
 *   - SEAL_SEAL          (0x100u): refuse further seal additions.
 *   - SEAL_SHRINK        (0x200u): refuse truncate-down.
 *   - SEAL_GROW          (0x400u): refuse truncate-up + write past EOF
 *                                  (any size-extending operation).
 *   - SEAL_WRITE         (0x800u): refuse all content modification —
 *                                  write, truncate (any direction).
 *   - SEAL_FUTURE_WRITE  (0x1000u): semantically identical to SEAL_WRITE
 *                                  in v2 MVP (no mmap surface yet);
 *                                  the bit is published so future mmap
 *                                  support can distinguish "block new
 *                                  writers" from "block all writes" per
 *                                  Linux fcntl(2) F_SEAL_FUTURE_WRITE.
 *
 * Bits 3..7 are reserved for future ext-style flag bits (DIRSYNC,
 * NOATIME, etc.) so that the seal block is contiguous + non-colliding.
 *
 * Spec posture: seals compose over inode.tla — adding a flag bit
 * doesn't change the alloc/free/link/unlink state machine; the
 * write/truncate refusal is enforced at the fs-layer wrapper which
 * sits above the inode-tree state machine.
 */
#define STM_INO_FLAG_SEAL_SEAL          0x00000100u
#define STM_INO_FLAG_SEAL_SHRINK        0x00000200u
#define STM_INO_FLAG_SEAL_GROW          0x00000400u
#define STM_INO_FLAG_SEAL_WRITE         0x00000800u
#define STM_INO_FLAG_SEAL_FUTURE_WRITE  0x00001000u

#define STM_INO_FLAG_SEAL_MASK          (STM_INO_FLAG_SEAL_SEAL | \
                                         STM_INO_FLAG_SEAL_SHRINK | \
                                         STM_INO_FLAG_SEAL_GROW | \
                                         STM_INO_FLAG_SEAL_WRITE | \
                                         STM_INO_FLAG_SEAL_FUTURE_WRITE)

/*
 * P8-POSIX-7a-anon: orphan-inode marker. Set on an ALLOCATED
 * record produced by `stm_inode_alloc_anon` (Linux O_TMPFILE
 * shape — no dirent points here yet, nlink is 0). Cleared by
 * `stm_inode_materialize` when the orphan is linked into a parent
 * directory for the first time.
 *
 * The orphan state is the ONLY way an ALLOCATED inode can have
 * nlink = 0 (post-AllocAnon, pre-Materialize). Linked inodes
 * always have nlink ≥ 1; cascade-free transitions ALLOCATED →
 * FREED at nlink=0 atomically. Models inode.tla's `~ever_linked`
 * shadow var.
 *
 * Caller-visible `si_flags` value MUST NOT include this bit
 * directly via stm_inode_set; the dedicated _alloc_anon /
 * _materialize paths manage it.
 */
#define STM_INO_FLAG_ORPHAN     0x40000000u

/*
 * Reserved internal flag — set on a record whose ino has been freed
 * and is eligible for AllocReused. Encodes the inode.tla FREED state
 * inline within the existing 256-byte struct (no separate state byte
 * in the persisted format). Distinct from si_nlink == 0 which can
 * also represent "unlinked but still open" — the FREED flag is set
 * only when the ino number itself is eligible for reuse with a
 * bumped si_gen.
 *
 * Caller-visible `si_flags` value MUST NOT include this bit; the
 * stm_inode_set / _alloc paths protect callers from setting it.
 */
#define STM_INO_FLAG_FREED      0x80000000u

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
 * Allocation policy: prefer reuse of FREED inos (with si_gen bumped
 * by 1 — models inode.tla's AllocReused action and preserves the
 * (ino, gen) tuple-uniqueness invariant); fall back to a fresh ino
 * at `next_ino[dataset_id]++` when no FREED slot is available
 * (models inode.tla's AllocFresh action with si_gen = 0). The
 * caller cannot select between paths — the allocator picks
 * deterministically based on the FREED set.
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
 * P8-POSIX-7a-anon: allocate an ANONYMOUS (orphan) inode. Mirrors
 * `stm_inode_alloc`'s allocation policy (AllocReused-from-FREED
 * preferred, AllocFresh-from-next_ino fallback) but produces an
 * inode with `nlink = 0` and `STM_INO_FLAG_ORPHAN` set in
 * `si_flags`. The orphan state encodes inode.tla's
 * `~ever_linked` shadow var: an orphan inode is ALLOCATED but
 * has never been linked to a dirent.
 *
 * Models inode.tla's `AllocAnon` action. The (ino, si_gen) tuple
 * is unique-across-time per `TupleUniqueAllTime`; gen bumps on the
 * AllocReused path same as `stm_inode_alloc`.
 *
 * Lifecycle: an orphan inode lives until either:
 *   - `stm_inode_materialize` flips it to linked (nlink := 1,
 *     ORPHAN flag cleared) — models `Materialize`.
 *   - `stm_inode_free` frees it explicitly — models `FreeAnon`.
 *
 * NB: regular `stm_inode_link` / `_unlink` REJECT orphan inodes
 * (the orphan must materialize first). The fs.c-layer wrappers
 * route through the appropriate path.
 *
 * Refusals: same shape as `stm_inode_alloc`.
 */
STM_MUST_USE
stm_status stm_inode_alloc_anon(stm_inode_index *idx, uint64_t dataset_id,
                                   uint32_t mode, uint32_t uid, uint32_t gid,
                                   uint64_t *out_ino);

/*
 * P8-POSIX-7a-anon: materialize an orphan inode — flip nlink 0→1
 * and clear `STM_INO_FLAG_ORPHAN` in `si_flags`. Models
 * inode.tla's `Materialize` action: ALLOCATED + nlink=0 +
 * ~ever_linked → ALLOCATED + nlink=1 + ever_linked=TRUE.
 *
 * `si_gen` is preserved (matches the inode.tla's
 * `TupleUniqueAllTime` invariant — the (ino, gen) tuple identity
 * is stable across materialization).
 *
 * Refusals:
 *   - NULL idx OR dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - No record at (dataset_id, ino) OR record FREED (STM_ENOENT).
 *   - Record is NOT in the orphan state (i.e., `STM_INO_FLAG_ORPHAN`
 *     not set OR nlink != 0) — STM_EINVAL. Caller must use
 *     `stm_inode_link` for already-linked inodes.
 */
STM_MUST_USE
stm_status stm_inode_materialize(stm_inode_index *idx, uint64_t dataset_id,
                                    uint64_t ino);

/*
 * Free the inode at (dataset_id, ino). Sets `STM_INO_FLAG_FREED`
 * in `si_flags` and clears `si_nlink` to 0. The record's `si_gen`
 * is preserved so the next AllocReused at this ino bumps it by 1
 * — preserving the (ino, gen) tuple-uniqueness invariant from
 * inode.tla. Models inode.tla's Free action.
 *
 * Refusals:
 *   - NULL idx OR dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - No record at (dataset_id, ino) OR record already FREED (STM_ENOENT).
 */
/*
 * Bump nlink on (dataset_id, ino). Models inode.tla's `Link` action:
 * ALLOCATED + nlink ≥ 1 + nlink < UINT32_MAX → nlink := nlink + 1.
 * Used by stm_fs_link to add a second-or-later dirent referencing
 * an existing inode (POSIX hard link).
 *
 * Refusals:
 *   - NULL idx OR dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - No record at (dataset_id, ino) OR record FREED (STM_ENOENT).
 *   - nlink at UINT32_MAX (STM_EOVERFLOW — caller must enforce the
 *     POSIX LINK_MAX cap before reaching this).
 */
STM_MUST_USE
stm_status stm_inode_link(stm_inode_index *idx, uint64_t dataset_id,
                              uint64_t ino);

/*
 * Decrement nlink on (dataset_id, ino). Models inode.tla's `Unlink`
 * action: ALLOCATED + nlink ≥ 1 → nlink := nlink - 1. If nlink
 * reaches 0, the record atomically transitions to FREED via the
 * cascade-free path (sets STM_INO_FLAG_FREED in si_flags + zeros
 * si_nlink); the `si_gen` is preserved so the next AllocReused
 * bumps it. Caller can detect the cascade-free via *out_freed (if
 * non-NULL) — true iff this unlink was the last reference.
 *
 * Refusals:
 *   - NULL idx OR dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - No record at (dataset_id, ino) OR record FREED (STM_ENOENT).
 *   - nlink at 0 (STM_ECORRUPT — invariant violation; healthy paths
 *     never reach this).
 */
STM_MUST_USE
stm_status stm_inode_unlink(stm_inode_index *idx, uint64_t dataset_id,
                                uint64_t ino, bool *out_freed);

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
 * NEXT alloc would return for a fresh slot (i.e., when no FREED ino
 * is available for reuse). FREED inos are reused with a bumped gen
 * before next_ino is touched.
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

/* ========================================================================= */
/* Persistence (P8-POSIX-1b, v24).                                           */
/*                                                                            */
/* The inode index is persisted as a btree_store-encoded, AEAD-encrypted     */
/* Bε-tree under `ub_inode_root` on device 0. Same envelope as the dataset / */
/* extent / cas trees: AEAD nonce `paddr || gen || pool_uuid`, AD            */
/* `pool_uuid || device_uuid_0`, idempotent commit via internal dirty flag,  */
/* atomic shadow-swap on load_at.                                            */
/*                                                                            */
/* Key (16 bytes, lexicographically sorted):                                 */
/*                                                                            */
/*   off  size  field                                                        */
/*    0    8    le64 dataset_id                                              */
/*    8    8    le64 ino                                                     */
/*                                                                            */
/* Value: 256-byte struct stm_inode_value as defined above. The FREED        */
/* state is encoded inline via STM_INO_FLAG_FREED in si_flags.               */
/*                                                                            */
/* `next_ino` per-dataset high-water mark is reconstructed at load_at        */
/* time from the deserialized records (max(ino over records-for-ds) + 1),   */
/* so it does not need a separate persistence slot.                          */
/* ========================================================================= */

struct stm_bdev;       typedef struct stm_bdev stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap stm_bootstrap;

/*
 * Bind the inode index to its on-disk storage (device 0 + bootstrap
 * allocator). MUST be called before commit() / load_at(). Mirrors
 * `stm_extent_index_set_storage`.
 */
STM_MUST_USE
stm_status stm_inode_index_set_storage(stm_inode_index *idx,
                                          stm_bdev *bdev_0,
                                          stm_bootstrap *boot_0);

/*
 * Bind the AEAD context (metadata key + pool/device UUIDs). MUST be
 * called before commit() / load_at(). The pointer to `metadata_key`
 * is stored — caller MUST keep the buffer alive.
 */
STM_MUST_USE
stm_status stm_inode_index_set_crypt_ctx(stm_inode_index *idx,
                                            const uint8_t *metadata_key,
                                            const uint64_t pool_uuid[2],
                                            const uint64_t device_uuid_0[2]);

/*
 * Commit the in-RAM index to disk under `committed_gen`. Returns the
 * new tree's root paddr + 32-byte BLAKE3 csum via out-params, which
 * the caller stamps into `ub_inode_root`. Idempotent when clean.
 *
 * Refusals: STM_EINVAL (NULL idx / out_paddr / out_csum, or storage
 * / crypt context unset), and any error bubbled from
 * stm_btree_store_serialize.
 */
STM_MUST_USE
stm_status stm_inode_index_commit(stm_inode_index *idx,
                                     uint64_t committed_gen,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]);

/*
 * Atomic shadow-swap load_at. Reads the tree under (root_paddr,
 * root_gen), validates against expected_csum, deserializes records,
 * and atomically swaps in the new state. After return, all prior
 * in-RAM records are replaced (no preservation across load_at).
 */
STM_MUST_USE
stm_status stm_inode_index_load_at(stm_inode_index *idx,
                                      uint64_t root_paddr, uint64_t root_gen,
                                      const uint8_t expected_csum[32]);

/* Read the current root paddr / csum — for the sync layer's
 * dirty-tracking + uberblock stamping. `out_root_paddr` is required;
 * `out_root_csum` is optional (pass NULL if the csum is not needed).
 * For the AEAD gen, use the sibling `stm_inode_index_get_gen` below.
 * (R71 P2-2: docstring referenced "/ gen" but the function does not
 * return it; gen lives in the dedicated accessor.)
 *
 * Forward use: P8-POSIX-2's dirent layer + future POSIX-surface
 * chunks call this to mirror the inode tree's root state during
 * the per-fs commit cadence. R70 P2-2 + P3-8: presently no in-tree
 * caller — the accessor is published with the persistence API as
 * part of P8-POSIX-1b so the sync.c → inode.c contract stays
 * symmetric with the equivalent extent / cas / repair_log
 * accessors that all carry their own root-mirror getter. */
STM_MUST_USE
stm_status stm_inode_index_get_root(const stm_inode_index *idx,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32]);
STM_MUST_USE
stm_status stm_inode_index_get_gen(const stm_inode_index *idx,
                                      uint64_t *out_root_gen);

#ifdef __cplusplus
}
#endif

#endif /* STRATUM_V2_INODE_H */
