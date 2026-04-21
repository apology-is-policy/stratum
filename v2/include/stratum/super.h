/* SPDX-License-Identifier: ISC */
/*
 * Superblock / uberblock on-disk format.
 *
 * ARCHITECTURE §5: the pool's per-device label layout + the 4 KiB
 * uberblock that sits in every ring slot. Each commit produces a new
 * uberblock; mount selects the authoritative one by gen + quorum.
 *
 * This header is the canonical format definition. Any change to field
 * positions or sizes is a format change, bumping STM_UB_VERSION and
 * requiring the feature-flags dance described in ARCHITECTURE §5.2
 * (compat / ro-compat / incompat). We use _Static_assert below to
 * wedge the struct sizes so accidental padding changes get caught at
 * compile time.
 *
 * Endianness: every multi-byte number is little-endian. Access via
 * stm_load_le* / stm_store_le* in types.h; never cast directly.
 *
 * Phase 3 MVP (this file) defines the layout + encode/decode. The
 * semantics of individual fields (tree roots, roster management,
 * merkle root) fill in as subsequent Phase 3 and Phase 4 work lands.
 * Unused fields in Phase 3 tests are zeroed.
 */
#ifndef STRATUM_V2_SUPER_H
#define STRATUM_V2_SUPER_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Constants.                                                                 */
/* ========================================================================= */

/* 8-byte magic at the head of every uberblock. ASCII "STRATUM2" — as an
 * on-disk little-endian uint64 the bytes read S,T,R,A,T,U,M,2 in order
 * when viewed with `xxd` on the raw block. */
#define STM_UB_MAGIC          UINT64_C(0x324d555441525453) /* "STRATUM2" */

/* Format version. Bumped on incompatible layout changes.
 *
 * v1 → v2 (Phase 4 chunk P4-1): carved ub_merkle_root_salt[32]
 * from ub_reserved (unchanged offset; field size shrunk). v1 pools
 * had this region zero, so v2 readers cannot treat a v1 uberblock
 * as having a populated salt — hence the version bump.
 *
 * v2 → v3 (Phase 4 chunk P4-3b R9 P0-1): carved
 * ub_alloc_root_gen[8 bytes le64] from ub_reserved. Records the
 * gen at which ub_alloc_root's tree was AEAD-encrypted — may
 * differ from ub_gen when a mount-claim UB advances the gen
 * counter past orphan metadata writes without rewriting the tree.
 * v2 pools had this region zero, which AEAD-decrypts as nonce
 * gen=0 — would fail-loud at mount, but the version bump makes
 * the intent explicit and refuses v2 mounts up-front. */
#define STM_UB_VERSION        3u

/* Fixed sizes. */
#define STM_UB_SIZE           4096u                      /* one uberblock */
#define STM_LABEL_SIZE        (64u * STM_UB_SIZE)        /* 256 KiB */
#define STM_LABELS_PER_DEVICE 4u
#define STM_UB_SLOTS_PER_LABEL 63u                       /* commit ring */
#define STM_UB_MIRROR_SLOT    63u                        /* pool-config mirror */

/* Minimum device size: 4 × labels + some user-data breathing room.
 * Labels are 2 × 256 KiB at head + 2 × 256 KiB at tail, so 1 MiB each
 * end. 8 MiB minimum is conservative. */
#define STM_DEVICE_MIN_BYTES  (8u * 1024u * 1024u)

/* Redundancy kinds for ub_redundancy_kind. */
typedef enum {
    STM_RED_NONE    = 0,
    STM_RED_MIRROR  = 1,
    STM_RED_RS      = 2,
    STM_RED_LRC     = 3,
} stm_redundancy_kind;

/* Device class / role (ARCH §4). */
typedef enum {
    STM_DEV_CLASS_UNSET = 0,
    STM_DEV_CLASS_SSD   = 1,
    STM_DEV_CLASS_HDD   = 2,
    STM_DEV_CLASS_PMEM  = 3,
    STM_DEV_CLASS_ZNS   = 4,
} stm_device_class;

typedef enum {
    STM_DEV_ROLE_UNSET = 0,
    STM_DEV_ROLE_DATA  = 1,
    STM_DEV_ROLE_LOG   = 2,
    STM_DEV_ROLE_CACHE = 3,
    STM_DEV_ROLE_SPARE = 4,
} stm_device_role;

/* ========================================================================= */
/* Block pointer (stm_bptr) — 64 bytes.                                       */
/* ========================================================================= */

/*
 * A block pointer identifies one stripe on the pool.
 *
 * ARCH §4.4: paddr is (16-bit device, 48-bit offset). Offset is in
 * 4 KiB blocks, so addressable range per device is 2^48 × 4 KiB = 1 EiB.
 * Device field is 0 for single-device pools.
 *
 * csum is BLAKE3-256 over the referenced stripe's content (AEAD-AD
 * input in Phase 4; plain-content in Phase 3 tests).
 *
 * `kind` tags the target: leaf, internal, extent, etc. `flags` carries
 * per-kind bits (e.g. "compressed"). Reserved bytes pad to 64 and give
 * space for format growth without bumping STM_UB_VERSION.
 */
typedef enum {
    STM_BPTR_KIND_NONE     = 0,   /* null pointer */
    STM_BPTR_KIND_INTERNAL = 1,   /* Bε-tree internal node */
    STM_BPTR_KIND_LEAF     = 2,   /* Bε-tree leaf node */
    STM_BPTR_KIND_EXTENT   = 3,   /* user-data extent */
    STM_BPTR_KIND_ALLOC    = 4,   /* allocator tree node */
    STM_BPTR_KIND_SNAP     = 5,   /* snapshot-index tree node */
    STM_BPTR_KIND_CAS      = 6,   /* CAS-tier index node */
} stm_bptr_kind;

typedef struct {
    le64    bp_paddr;              /* packed (device<<48) | offset */
    uint8_t bp_kind;               /* stm_bptr_kind */
    uint8_t bp_flags;
    uint8_t bp_reserved1[6];       /* pad to 16 */
    uint8_t bp_csum[32];           /* BLAKE3-256 of target */
    uint8_t bp_reserved2[16];      /* future growth */
} stm_bptr;

_Static_assert(sizeof(stm_bptr) == 64, "stm_bptr must be 64 bytes");

/* Paddr packing: top 16 bits device, low 48 bits block offset. */
static inline uint64_t stm_paddr_make(uint16_t device, uint64_t block_offset) {
    return ((uint64_t)device << 48) | (block_offset & ((UINT64_C(1) << 48) - 1));
}
static inline uint16_t stm_paddr_device(uint64_t paddr) {
    return (uint16_t)(paddr >> 48);
}
static inline uint64_t stm_paddr_offset(uint64_t paddr) {
    return paddr & ((UINT64_C(1) << 48) - 1);
}

/* ========================================================================= */
/* Uberblock (stm_uberblock) — 4096 bytes.                                    */
/* ========================================================================= */

typedef struct {
    /* Identity */
    le64    ub_magic;                           /*   0 :  8 — STM_UB_MAGIC  */
    le32    ub_version;                         /*   8 :  4 */
    le32    ub_flags_compat;                    /*  12 :  4 */
    le32    ub_flags_ro_compat;                 /*  16 :  4 */
    le32    ub_flags_incompat;                  /*  20 :  4 */
    le64    ub_pool_uuid[2];                    /*  24 : 16 */
    le64    ub_device_uuid[2];                  /*  40 : 16 */

    /* Transaction state */
    le64    ub_gen;                             /*  56 :  8 — monotonic per commit */
    le64    ub_txg;                             /*  64 :  8 — transaction group counter */
    le64    ub_roster_hash;                     /*  72 :  8 */
    le16    ub_device_count;                    /*  80 :  2 */
    le16    ub_device_id;                       /*  82 :  2 */
    uint8_t ub_reserved_hdr[12];                /*  84 : 12 — align to 96 */

    /* Metadata roots */
    stm_bptr ub_main_root;                      /*  96 : 64 — main fs tree */
    stm_bptr ub_alloc_root;                     /* 160 : 64 — allocator tree */
    stm_bptr ub_snap_root;                      /* 224 : 64 — snapshot tree */
    stm_bptr ub_cas_index_root;                 /* 288 : 64 — CAS tier index */

    /* Integrity */
    uint8_t ub_merkle_root[32];                 /* 352 : 32 */

    /* Pool-wide counters */
    le64    ub_next_ino;                        /* 384 :  8 */
    le64    ub_next_dataset_id;                 /* 392 :  8 */
    le64    ub_next_snap_id;                    /* 400 :  8 */
    le64    ub_total_blocks;                    /* 408 :  8 */
    le64    ub_free_blocks;                     /* 416 :  8 */

    /* Default redundancy profile (§4.5) */
    uint8_t ub_redundancy_kind;                 /* 424 :  1 */
    uint8_t ub_redundancy_params[15];           /* 425 : 15 */

    /* Key schema (§7) — wrapped keys + IV + KDF salt + version */
    uint8_t ub_key_schema[512];                 /* 440 : 512 */

    /* Device class / role */
    uint8_t ub_device_class;                    /* 952 :  1 */
    uint8_t ub_device_role;                     /* 953 :  1 */
    uint8_t ub_reserved_mid[6];                 /* 954 :  6 — align to 960 */

    /* Compact roster (up to 64 devices × 32 B each) */
    uint8_t ub_roster[2048];                    /* 960 : 2048 */

    /* Merkle root salt — 32 bytes random per pool, seeded at format
     * time from a CSPRNG. Mixes into the ub_merkle_root computation
     * (§7.11.3) to prevent certain precomputation attacks. Stable
     * across the pool's lifetime; never rotated. */
    uint8_t ub_merkle_root_salt[32];            /* 3008 : 32 */

    /* Gen at which `ub_alloc_root`'s tree was AEAD-encrypted
     * (P4-3b). Usually equals `ub_gen`, but may be strictly less
     * when `stm_sync_open` writes a "mount-claim" UB that advances
     * the durable gen past any orphan-data writes without
     * rewriting the tree. The AEAD nonce on every tree-node read
     * uses THIS field, not ub_gen, so a mount-claim UB keeps the
     * existing tree decryptable. */
    le64    ub_alloc_root_gen;                  /* 3040 :  8 */

    /* Reserved for future fields + alignment to csum. */
    uint8_t ub_reserved[1016];                  /* 3048 : 1016 */

    /* Checksum: BLAKE3-256 over the rest of the uberblock with this
     * field zeroed. Self-verifying; a blob whose first 4064 bytes
     * hash to ub_csum is structurally valid. */
    uint8_t ub_csum[32];                        /* 4064 : 32 */
} stm_uberblock;

_Static_assert(sizeof(stm_uberblock) == 4096, "stm_uberblock must be 4096 bytes");

/* ========================================================================= */
/* Encode / decode.                                                           */
/* ========================================================================= */

/*
 * Encode an uberblock into `buf` (must be at least STM_UB_SIZE bytes).
 * Writes every field in little-endian and finalizes ub_csum as the
 * BLAKE3-256 of bytes [0, STM_UB_SIZE - 32). Caller keeps ownership
 * of both `ub` (read-only) and `buf` (written).
 */
STM_MUST_USE
stm_status stm_ub_encode(const stm_uberblock *ub, void *buf, size_t buf_len);

/*
 * Decode `buf` (STM_UB_SIZE bytes expected) into `*out_ub`. Verifies:
 *   - buf_len == STM_UB_SIZE.
 *   - ub_magic matches STM_UB_MAGIC.
 *   - ub_version is supported (== STM_UB_VERSION; future: feature-flag check).
 *   - ub_csum matches BLAKE3-256 over bytes [0, STM_UB_SIZE - 32).
 *
 * On csum mismatch returns STM_ECORRUPT. On magic or version mismatch
 * returns STM_EBADVERSION. Feature-flag checks are a Phase-3-later
 * addition (need the pool-config context to decide).
 */
STM_MUST_USE
stm_status stm_ub_decode(const void *buf, size_t buf_len, stm_uberblock *out_ub);

/* Compute just the csum of an encoded buffer (bytes [0, size-32) →
 * BLAKE3-256 into out[32]). Exposed for tests and emergency tools. */
void stm_ub_csum(const void *buf, size_t buf_len, uint8_t out[32]);

/* ========================================================================= */
/* Label placement.                                                           */
/* ========================================================================= */

/*
 * Populate `offsets[STM_LABELS_PER_DEVICE]` with the byte offsets of
 * each label on a device of `device_bytes` total size.
 *
 *   offsets[0] = 0
 *   offsets[1] = STM_LABEL_SIZE
 *   offsets[2] = device_bytes - 2 * STM_LABEL_SIZE
 *   offsets[3] = device_bytes - STM_LABEL_SIZE
 *
 * Returns STM_EINVAL if device_bytes < STM_DEVICE_MIN_BYTES.
 */
STM_MUST_USE
stm_status stm_label_offsets(uint64_t device_bytes,
                              uint64_t offsets[STM_LABELS_PER_DEVICE]);

/*
 * Offset (bytes) of commit-ring slot `slot_idx` (0..STM_UB_SLOTS_PER_LABEL-1)
 * within a label whose head is at byte `label_offset`. Slot sizes are
 * STM_UB_SIZE. The mirror slot (STM_UB_MIRROR_SLOT) is accessed the same
 * way but is reserved for pool-config snapshots, not commit rotation.
 */
STM_MUST_USE
stm_status stm_ub_slot_offset(uint64_t label_offset, uint32_t slot_idx,
                               uint64_t *out_byte_offset);

/* Round-robin slot for commit gen `gen`: gen mod STM_UB_SLOTS_PER_LABEL. */
static inline uint32_t stm_ub_ring_slot(uint64_t gen) {
    return (uint32_t)(gen % STM_UB_SLOTS_PER_LABEL);
}

/* ========================================================================= */
/* Device-backed label I/O.                                                   */
/* ========================================================================= */

typedef struct stm_bdev stm_bdev;   /* forward from block.h */

/*
 * Encode `ub` and write it to (label_idx, slot_idx) on `d`. Fsyncs
 * before returning. Caller must ensure label_idx < STM_LABELS_PER_DEVICE
 * and slot_idx <= STM_UB_MIRROR_SLOT.
 */
STM_MUST_USE
stm_status stm_sb_label_write(stm_bdev *d, uint32_t label_idx,
                               uint32_t slot_idx, const stm_uberblock *ub);

/*
 * Read the uberblock at (label_idx, slot_idx) from `d` and decode it
 * into `*out_ub`. Returns STM_ECORRUPT on csum failure,
 * STM_EBADVERSION on magic/version mismatch.
 */
STM_MUST_USE
stm_status stm_sb_label_read(stm_bdev *d, uint32_t label_idx,
                              uint32_t slot_idx, stm_uberblock *out_ub);

/*
 * Scan all STM_LABELS_PER_DEVICE labels × STM_UB_SLOTS_PER_LABEL
 * commit-ring slots on `d`, pick the uberblock with the highest valid
 * `ub_gen`, and hand it back via `*out_ub`. Also reports which label +
 * slot position it came from (useful for diagnostics and for deciding
 * where to write the NEXT commit's ring slot).
 *
 * Returns STM_ENOENT if no valid uberblock is found on the device
 * (fresh / never-mounted / irrecoverably corrupt). Per-slot
 * STM_ECORRUPT / STM_EBADVERSION failures are NOT errors — they're
 * expected for unused slots and get silently filtered out.
 *
 * Single-device: this is the authoritative mount-time selection.
 * Multi-device pools (Phase 5) will add a quorum layer on top.
 */
STM_MUST_USE
stm_status stm_sb_mount_scan(stm_bdev *d, stm_uberblock *out_ub,
                              uint32_t *out_label_idx,
                              uint32_t *out_slot_idx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SUPER_H */
