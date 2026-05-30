/* SPDX-License-Identifier: ISC */
/*
 * Bootstrap pool allocator (Phase 3 chunk 4a).
 *
 *   see ARCHITECTURE §6.5 (Bootstrap pool: no recursion)
 *   see v2/specs/allocator.tla (refcount + deferred-free spec)
 *
 *   Revised 9.6-impl-1a (2026-05-17): the bitmap quantum dropped from a
 *   128-KiB unit to a 16-KiB NODE (STM_BOOTSTRAP_NODE_BLOCKS), and the
 *   bitmap region grew from one 4 KiB block to STM_BOOTSTRAP_BITMAP_BLOCKS.
 *   On-disk header format → v2 (clean break; v2 is pre-release).
 *
 * On-disk layout inside the bootstrap pool:
 *
 *   block 0       hdr slot A         (4 KiB)
 *   block 1       hdr slot B         (4 KiB)      ping-pong torn-write safety
 *   block 2..15   bitmap slot A      (14 × 4 KiB)
 *   block 16..29  bitmap slot B      (14 × 4 KiB) ping-pong torn-write safety
 *   block 30..31  padding            (2 × 4 KiB)  reserved
 *   block 32..    data area; allocated in 4-block nodes (16 KiB each)
 *
 * The header records which bitmap slot is "live" (slot A or B) by its
 * first-block index, along with a BLAKE3-256 csum of the bitmap region's
 * full payload (STM_BOOTSTRAP_BITMAP_BLOCKS blocks). Commits COW:
 *
 *   1. Build the new bitmap region in RAM, write it to the non-live
 *      bitmap slot, fsync.
 *   2. Build the new header (bitmap_gen+1, pointing at the new bitmap
 *      slot, with its csum), write to the non-live header slot, fsync.
 *
 * A crash between steps 1 and 2 leaves the old header still live — mount
 * picks it, reads the old (still valid) bitmap, and proceeds. A crash
 * mid-write in either slot is defeated by the self-csum: the half-written
 * slot's csum mismatches, so mount falls back to the other slot.
 */

#include <stratum/bootstrap.h>
#include <stratum/block.h>
#include <stratum/hash.h>
#include <stratum/super.h>       /* STM_UB_SIZE = 4096 */

#include <stdlib.h>
#include <string.h>

/* The on-disk bitmap region: STM_BOOTSTRAP_BITMAP_BLOCKS contiguous 4 KiB
 * blocks. 14 × 4096 = 57344 bytes = 458752 bits = STM_BOOTSTRAP_MAX_NODES. */
#define BITMAP_REGION_BYTES  ((size_t)STM_BOOTSTRAP_BITMAP_BLOCKS * STM_UB_SIZE)

_Static_assert(BITMAP_REGION_BYTES * 8u == STM_BOOTSTRAP_MAX_NODES,
               "bitmap region must hold exactly STM_BOOTSTRAP_MAX_NODES bits");
_Static_assert(STM_BOOTSTRAP_BITMAP_SLOT_B + STM_BOOTSTRAP_BITMAP_BLOCKS
               <= STM_BOOTSTRAP_DATA_START_BLOCK,
               "the two bitmap slots must fit before the data area");
_Static_assert(STM_BOOTSTRAP_DATA_START_BLOCK % STM_BOOTSTRAP_NODE_BLOCKS == 0,
               "the data area must start at a node-aligned block");
_Static_assert(STM_BOOTSTRAP_UNIT_BLOCKS % STM_BOOTSTRAP_NODE_BLOCKS == 0,
               "the 128-KiB unit must be a whole number of nodes");

/* ========================================================================= */
/* On-disk header.                                                            */
/* ========================================================================= */

/* Magic "STMALOC1" read as a little-endian uint64. */
#define STM_BOOTSTRAP_HDR_MAGIC    UINT64_C(0x31434F4C414D5453)

typedef struct {
    le64    h_magic;                 /*    0 :  8 */
    le32    h_version;               /*    8 :  4 */
    le32    h_flags;                 /*   12 :  4 */
    le64    h_pool_uuid[2];          /*   16 : 16 */
    le64    h_device_uuid[2];        /*   32 : 16 */
    le64    h_bitmap_gen;            /*   48 :  8 */
    le64    h_bitmap_block;          /*   56 :  8 — first block of live bitmap slot */
    le64    h_bitmap_bit_count;      /*   64 :  8 — node count                      */
    le64    h_bootstrap_size_blocks; /*   72 :  8 */
    le64    h_data_node_blocks;      /*   80 :  8 — 4 KiB blocks per node            */
    le64    h_data_start_block;      /*   88 :  8 */
    le64    h_bitmap_block_count;    /*   96 :  8 — 4 KiB blocks per bitmap slot     */
    uint8_t h_bitmap_csum[32];       /*  104 : 32 */
    uint8_t h_user_data[STM_BOOTSTRAP_USER_DATA_SIZE]; /*  136 : 256 */
    uint8_t h_reserved[3672];        /*  392 : 3672 */
    uint8_t h_csum[32];              /* 4064 : 32 */
} stm_bootstrap_hdr;

_Static_assert(sizeof(stm_bootstrap_hdr) == 4096,
               "stm_bootstrap_hdr must be exactly one 4 KiB block");

/* ========================================================================= */
/* In-RAM state.                                                              */
/* ========================================================================= */

typedef struct pending_entry pending_entry;
struct pending_entry {
    uint64_t       paddr;       /* absolute device paddr of first block */
    uint32_t       nblocks;     /* multiple of STM_BOOTSTRAP_NODE_BLOCKS */
    uint64_t       free_gen;    /* free_gen stamp */
    pending_entry *next;
};

struct stm_bootstrap {
    stm_bdev  *d;
    uint64_t   bootstrap_size_blocks;
    uint64_t   total_nodes;
    uint64_t   data_start_block;    /* in-pool block index of node 0 */
    uint64_t   pool_uuid[2];
    uint64_t   device_uuid[2];

    /* Which slots are live. A commit flips to the other slot. */
    uint32_t   hdr_slot_live;       /* 0 or 1 (STM_BOOTSTRAP_HDR_SLOT_A/B)   */
    uint32_t   bitmap_slot_live;    /* 0 or 1                            */
    uint64_t   bitmap_gen;

    /* In-RAM bitmap: bit i = 1 iff node i is allocated (or PENDING). */
    uint8_t   *bitmap;
    size_t     bitmap_bytes;        /* = ceil(total_nodes / 8)           */

    /* Deferred-free list. Head is the most-recently-freed entry. */
    pending_entry *pending_head;
    uint64_t       pending_count;   /* #entries                          */
    uint64_t       pending_nodes;   /* total nodes across all entries    */

    /* Roving allocation cursor (in nodes). */
    uint64_t   rove_next_node;

    /* #791 mount-time reconcile: a transient "marked-live" bitmap, allocated
     * by stm_bootstrap_reconcile_begin and freed by _end. NULL outside a
     * reconcile pass. See the reconcile section below. */
    uint8_t   *reconcile_marked;

    /* Chunk 5d: opaque user-data region stored in the header. Persisted
     * atomically with the bootstrap commit. */
    uint8_t    user_data[STM_BOOTSTRAP_USER_DATA_SIZE];
};

/* ========================================================================= */
/* Helpers.                                                                   */
/* ========================================================================= */

/* STM_BOOTSTRAP_OFFSET in 4 KiB blocks. */
static inline uint64_t bootstrap_start_block(void)
{
    return STM_BOOTSTRAP_OFFSET / STM_UB_SIZE;
}

/* Device-level byte offset of a given in-pool block. */
static inline uint64_t device_byte_offset(uint64_t pool_block_idx)
{
    return STM_BOOTSTRAP_OFFSET + pool_block_idx * (uint64_t)STM_UB_SIZE;
}

/* Byte offset of header slot A/B (pool block 0 or 1). */
static inline uint64_t hdr_slot_offset(uint32_t slot)
{
    return device_byte_offset((slot == 0) ? STM_BOOTSTRAP_HDR_SLOT_A
                                           : STM_BOOTSTRAP_HDR_SLOT_B);
}

/* In-pool first-block index of bitmap slot A/B. */
static inline uint64_t bitmap_slot_block(uint32_t slot)
{
    return (slot == 0) ? STM_BOOTSTRAP_BITMAP_SLOT_A
                       : STM_BOOTSTRAP_BITMAP_SLOT_B;
}

/* Byte offset of bitmap slot A/B's first block. */
static inline uint64_t bitmap_slot_offset(uint32_t slot)
{
    return device_byte_offset(bitmap_slot_block(slot));
}

/* Map a bitmap-slot first-block index back to slot 0/1. The caller must
 * have validated `block` is one of the two slot block indices (which
 * load_bitmap_for_hdr does before the chosen header is used). */
static inline uint32_t block_to_bitmap_slot(uint64_t block)
{
    return (block == STM_BOOTSTRAP_BITMAP_SLOT_A) ? 0u : 1u;
}

/* Node index → absolute device paddr of the first block. */
static inline uint64_t node_to_paddr(const stm_bootstrap *a, uint64_t node_idx)
{
    uint64_t pool_block = a->data_start_block +
                          node_idx * (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;
    return stm_paddr_make(0, bootstrap_start_block() + pool_block);
}

/* paddr → node index. Returns true on a valid, node-aligned, in-range paddr. */
static bool paddr_to_node(const stm_bootstrap *a, uint64_t paddr,
                          uint64_t *out_node_idx)
{
    if (stm_paddr_device(paddr) != 0) return false;
    uint64_t block = stm_paddr_offset(paddr);
    uint64_t bootstrap_first = bootstrap_start_block();
    if (block < bootstrap_first + a->data_start_block) return false;

    uint64_t pool_block = block - bootstrap_first;
    if ((pool_block - a->data_start_block) %
            (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS != 0) return false;

    uint64_t node = (pool_block - a->data_start_block) /
                    (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;
    if (node >= a->total_nodes) return false;

    *out_node_idx = node;
    return true;
}

/* Bitmap bit accessors. */
static inline bool bit_is_set(const uint8_t *bm, uint64_t idx)
{
    return (bm[idx >> 3] & (uint8_t)(1u << (idx & 7u))) != 0;
}
static inline void bit_set(uint8_t *bm, uint64_t idx)
{
    bm[idx >> 3] |= (uint8_t)(1u << (idx & 7u));
}
static inline void bit_clear(uint8_t *bm, uint64_t idx)
{
    bm[idx >> 3] &= (uint8_t)~(1u << (idx & 7u));
}

/* BLAKE3 of the full bitmap region (STM_BOOTSTRAP_BITMAP_BLOCKS × 4 KiB). */
static void compute_bitmap_csum(const uint8_t *bitmap_region, uint8_t out[32])
{
    stm_blake3_hash h;
    stm_blake3(bitmap_region, BITMAP_REGION_BYTES, &h);
    memcpy(out, h.bytes, 32);
}

/*
 * Build the on-disk bitmap region from the in-RAM bitmap (zero-padded to
 * BITMAP_REGION_BYTES), csum it, and write it to bitmap slot `slot`. Does
 * NOT fsync — the caller fsyncs at the point its COW discipline requires.
 * `region` is a caller-owned BITMAP_REGION_BYTES scratch buffer (heap, to
 * keep 56 KiB off the stack).
 */
static stm_status write_bitmap_region(stm_bdev *d, uint32_t slot,
                                       const uint8_t *bitmap, size_t bitmap_bytes,
                                       uint8_t *region, uint8_t out_csum[32])
{
    memset(region, 0, BITMAP_REGION_BYTES);
    memcpy(region, bitmap, bitmap_bytes);   /* bitmap_bytes ≤ BITMAP_REGION_BYTES */
    compute_bitmap_csum(region, out_csum);
    return stm_bdev_write(d, bitmap_slot_offset(slot), region,
                          BITMAP_REGION_BYTES);
}

/* ========================================================================= */
/* Header encode / decode.                                                    */
/* ========================================================================= */

/*
 * Serialize `hdr_in` into a 4 KiB buffer suitable for direct bdev write.
 * Populates h_csum as BLAKE3-256 over bytes [0, 4064).
 */
static void encode_hdr(const stm_bootstrap_hdr *hdr_in, uint8_t buf[STM_UB_SIZE])
{
    memcpy(buf, hdr_in, sizeof *hdr_in);

    /* Zero the csum field before hashing. */
    memset(buf + offsetof(stm_bootstrap_hdr, h_csum), 0, 32);

    stm_blake3_hash h;
    stm_blake3(buf, STM_UB_SIZE - 32, &h);
    memcpy(buf + offsetof(stm_bootstrap_hdr, h_csum), h.bytes, 32);
}

/*
 * Deserialize a 4 KiB header buffer. Validates magic, version, self-csum.
 * Returns STM_EBADVERSION on magic/version mismatch, STM_ECORRUPT on csum.
 */
static stm_status decode_hdr(const uint8_t buf[STM_UB_SIZE],
                              stm_bootstrap_hdr *out_hdr)
{
    const stm_bootstrap_hdr *on_disk = (const stm_bootstrap_hdr *)buf;

    uint64_t magic = stm_load_le64(on_disk->h_magic);
    if (magic != STM_BOOTSTRAP_HDR_MAGIC) return STM_EBADVERSION;
    uint32_t version = stm_load_le32(on_disk->h_version);
    if (version != STM_BOOTSTRAP_HDR_VERSION) return STM_EBADVERSION;

    /* Recompute csum with the field zeroed. */
    uint8_t staged[STM_UB_SIZE];
    memcpy(staged, buf, STM_UB_SIZE);
    memset(staged + offsetof(stm_bootstrap_hdr, h_csum), 0, 32);

    uint8_t expected[32];
    stm_blake3_hash h;
    stm_blake3(staged, STM_UB_SIZE - 32, &h);
    memcpy(expected, h.bytes, 32);

    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(expected[i] ^ on_disk->h_csum[i]);
    }
    if (diff != 0) return STM_ECORRUPT;

    memcpy(out_hdr, buf, sizeof *out_hdr);
    return STM_OK;
}

/* ========================================================================= */
/* Bootstrap-size computation.                                                */
/* ========================================================================= */

static stm_status compute_bootstrap_size(stm_bdev *d,
                                          uint64_t requested_bytes,
                                          uint64_t *out_size_bytes)
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    if (!caps) return STM_EINVAL;

    /* Head labels (2 × 256K) + margin (512K) = 1 MiB before pool.
     * Tail labels (2 × 256K) = 512K after pool. */
    const uint64_t overhead = STM_BOOTSTRAP_OFFSET +
                              (uint64_t)STM_LABEL_SIZE * 2u;
    if (caps->size_bytes <= overhead) return STM_ENOSPC;
    uint64_t max_bootstrap = caps->size_bytes - overhead;

    uint64_t size = requested_bytes;
    bool     size_explicit = (requested_bytes != 0);
    if (!size_explicit) {
        /* Default formula from ARCH §6.5.1: max(MIN, device / DIVISOR).
         * Explicit callers (tests, dev scenarios) can bypass the MIN
         * floor below by passing a specific size. */
        uint64_t div_size = caps->size_bytes / STM_BOOTSTRAP_SIZE_DIVISOR;
        size = STM_BOOTSTRAP_MIN_SIZE_BYTES > div_size ?
                    STM_BOOTSTRAP_MIN_SIZE_BYTES : div_size;
    }

    if (size % STM_UB_SIZE != 0) return STM_EINVAL;

    /* The ARCH-mandated minimum only applies to the default path.
     * Explicit sizes down to one data node plus reserved blocks are
     * permitted (useful for tests that don't want to allocate 64 MiB
     * files). */
    if (!size_explicit && size < STM_BOOTSTRAP_MIN_SIZE_BYTES)
        return STM_EINVAL;
    if (size > max_bootstrap) return STM_ENOSPC;

    /* Node count check (single-region bitmap MVP: STM_BOOTSTRAP_MAX_NODES
     * is one 14-block bitmap slot's worth of bits, ≈ 7 GiB of pool). */
    uint64_t size_blocks = size / STM_UB_SIZE;
    if (size_blocks <= STM_BOOTSTRAP_DATA_START_BLOCK) return STM_ENOSPC;
    uint64_t data_blocks = size_blocks - STM_BOOTSTRAP_DATA_START_BLOCK;
    uint64_t num_nodes = data_blocks / (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;
    if (num_nodes == 0) return STM_ENOSPC;
    if (num_nodes > STM_BOOTSTRAP_MAX_NODES) return STM_ENOTSUPPORTED;

    *out_size_bytes = size;
    return STM_OK;
}

/* ========================================================================= */
/* Lifecycle: create, open, close.                                            */
/* ========================================================================= */

static stm_bootstrap *alloc_new(stm_bdev *d, uint64_t size_bytes,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2])
{
    stm_bootstrap *a = calloc(1, sizeof *a);
    if (!a) return NULL;

    a->d = d;
    a->bootstrap_size_blocks = size_bytes / STM_UB_SIZE;
    a->data_start_block = STM_BOOTSTRAP_DATA_START_BLOCK;
    a->total_nodes =
        (a->bootstrap_size_blocks - a->data_start_block) /
        (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;

    memcpy(a->pool_uuid,   pool_uuid,   sizeof a->pool_uuid);
    memcpy(a->device_uuid, device_uuid, sizeof a->device_uuid);

    /* Bitmap sized to exactly hold total_nodes bits, rounded up to a
     * byte. Zero-initialized = all nodes free. */
    a->bitmap_bytes = (size_t)((a->total_nodes + 7u) / 8u);
    a->bitmap = calloc(1, a->bitmap_bytes);
    if (!a->bitmap) {
        free(a);
        return NULL;
    }

    return a;
}

stm_status stm_bootstrap_create(stm_bdev *d,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2],
                             uint64_t bootstrap_size_bytes,
                             stm_bootstrap **out_alloc)
{
    if (!d || !pool_uuid || !device_uuid || !out_alloc) return STM_EINVAL;

    uint64_t size_bytes = 0;
    stm_status s = compute_bootstrap_size(d, bootstrap_size_bytes, &size_bytes);
    if (s != STM_OK) return s;

    stm_bootstrap *a = alloc_new(d, size_bytes, pool_uuid, device_uuid);
    if (!a) return STM_ENOMEM;

    /* The bitmap region is 56 KiB — heap, not stack. */
    uint8_t *region = malloc(BITMAP_REGION_BYTES);
    if (!region) {
        free(a->bitmap);
        free(a);
        return STM_ENOMEM;
    }

    /* Fresh pool: bitmap is all zeros (all nodes free), gen starts at 0.
     * The initial live slots are slot-0 (hdr A, bitmap A). Slot-1 is
     * explicitly overwritten with zeros below so any stale state from a
     * prior pool formatted on this device (which could otherwise
     * out-gen slot 0 and get mis-selected by mount) is invalidated. */
    a->bitmap_gen       = 0;
    a->hdr_slot_live    = 0;
    a->bitmap_slot_live = 0;

    /* Step 1 of the COW discipline: write the live bitmap slot. */
    uint8_t bitmap_csum[32];
    s = write_bitmap_region(d, a->bitmap_slot_live, a->bitmap, a->bitmap_bytes,
                            region, bitmap_csum);
    if (s != STM_OK) goto fail;

    /* Invalidate slot 1's bitmap region with zeros (R7a P1-1). Any
     * stale bytes there from a prior pool must not outlive this reformat. */
    memset(region, 0, BITMAP_REGION_BYTES);
    s = stm_bdev_write(d, bitmap_slot_offset(1u), region, BITMAP_REGION_BYTES);
    if (s != STM_OK) goto fail;

    s = stm_bdev_fsync(d);
    if (s != STM_OK) goto fail;

    /* Step 2 — the header. */
    stm_bootstrap_hdr hdr = { 0 };
    hdr.h_magic                 = stm_store_le64(STM_BOOTSTRAP_HDR_MAGIC);
    hdr.h_version               = stm_store_le32(STM_BOOTSTRAP_HDR_VERSION);
    hdr.h_flags                 = stm_store_le32(0);
    hdr.h_pool_uuid[0]          = stm_store_le64(pool_uuid[0]);
    hdr.h_pool_uuid[1]          = stm_store_le64(pool_uuid[1]);
    hdr.h_device_uuid[0]        = stm_store_le64(device_uuid[0]);
    hdr.h_device_uuid[1]        = stm_store_le64(device_uuid[1]);
    hdr.h_bitmap_gen            = stm_store_le64(a->bitmap_gen);
    hdr.h_bitmap_block          = stm_store_le64(bitmap_slot_block(a->bitmap_slot_live));
    hdr.h_bitmap_bit_count      = stm_store_le64(a->total_nodes);
    hdr.h_bootstrap_size_blocks = stm_store_le64(a->bootstrap_size_blocks);
    hdr.h_data_node_blocks      = stm_store_le64(STM_BOOTSTRAP_NODE_BLOCKS);
    hdr.h_data_start_block      = stm_store_le64(a->data_start_block);
    hdr.h_bitmap_block_count    = stm_store_le64(STM_BOOTSTRAP_BITMAP_BLOCKS);
    memcpy(hdr.h_bitmap_csum, bitmap_csum, 32);
    /* User data starts zero in a fresh pool; caller can set via
     * stm_bootstrap_set_user_data and it'll persist on next commit. */
    memcpy(hdr.h_user_data, a->user_data, STM_BOOTSTRAP_USER_DATA_SIZE);

    uint8_t hdr_buf[STM_UB_SIZE];
    encode_hdr(&hdr, hdr_buf);

    s = stm_bdev_write(d, hdr_slot_offset(a->hdr_slot_live),
                       hdr_buf, sizeof hdr_buf);
    if (s != STM_OK) goto fail;

    /* Invalidate header slot 1 (R7a P1-1). */
    uint8_t zero_block[STM_UB_SIZE] = { 0 };
    s = stm_bdev_write(d, hdr_slot_offset(1u), zero_block, sizeof zero_block);
    if (s != STM_OK) goto fail;

    s = stm_bdev_fsync(d);
    if (s != STM_OK) goto fail;

    free(region);
    *out_alloc = a;
    return STM_OK;

fail:
    free(region);
    free(a->bitmap);
    free(a);
    return s;
}

/* Try to read + csum-verify the bitmap region designated by `hdr`. On
 * success fills `out_region` (BITMAP_REGION_BYTES) and returns STM_OK. On
 * failure returns an error suitable for the caller to fall back to a
 * different header. */
static stm_status load_bitmap_for_hdr(stm_bdev *d, const stm_bootstrap_hdr *hdr,
                                       uint8_t *out_region)
{
    uint64_t idx = stm_load_le64(hdr->h_bitmap_block);
    if (idx != STM_BOOTSTRAP_BITMAP_SLOT_A && idx != STM_BOOTSTRAP_BITMAP_SLOT_B)
        return STM_ECORRUPT;

    stm_status s = stm_bdev_read(d, device_byte_offset(idx),
                                  out_region, BITMAP_REGION_BYTES);
    if (s != STM_OK) return s;

    uint8_t expected[32];
    compute_bitmap_csum(out_region, expected);
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(expected[i] ^ hdr->h_bitmap_csum[i]);
    }
    return diff == 0 ? STM_OK : STM_ECORRUPT;
}

stm_status stm_bootstrap_open(stm_bdev *d, stm_bootstrap **out_alloc)
{
    if (!d || !out_alloc) return STM_EINVAL;

    /* Read both header slots. */
    uint8_t hdr_buf_a[STM_UB_SIZE];
    uint8_t hdr_buf_b[STM_UB_SIZE];

    stm_status s = stm_bdev_read(d, hdr_slot_offset(0),
                                  hdr_buf_a, sizeof hdr_buf_a);
    if (s != STM_OK) return s;
    s = stm_bdev_read(d, hdr_slot_offset(1), hdr_buf_b, sizeof hdr_buf_b);
    if (s != STM_OK) return s;

    stm_bootstrap_hdr hdr_a, hdr_b;
    stm_status s_a = decode_hdr(hdr_buf_a, &hdr_a);
    stm_status s_b = decode_hdr(hdr_buf_b, &hdr_b);

    bool have_a = (s_a == STM_OK);
    bool have_b = (s_b == STM_OK);
    if (!have_a && !have_b) {
        /* If either slot is STM_EBADVERSION (magic/version mismatch), the
         * operator needs to know the format isn't what we expected;
         * otherwise report generic corruption. */
        if (s_a == STM_EBADVERSION || s_b == STM_EBADVERSION) {
            return STM_EBADVERSION;
        }
        return STM_ECORRUPT;
    }

    /* Build candidate list in highest-gen-first order. R7a P2-1: if the
     * top candidate's bitmap fails csum (e.g. a single bad sector in
     * the live bitmap slot) we fall back to the other valid header's
     * bitmap so the pool can mount at the prior gen rather than being
     * wedged. */
    stm_bootstrap_hdr *cand_hdr[2]  = { NULL, NULL };
    uint32_t       cand_slot[2] = { 0, 0 };
    int            ncand        = 0;

    if (have_a && have_b) {
        uint64_t ga = stm_load_le64(hdr_a.h_bitmap_gen);
        uint64_t gb = stm_load_le64(hdr_b.h_bitmap_gen);
        if (gb > ga) {
            cand_hdr[0] = &hdr_b; cand_slot[0] = 1;
            cand_hdr[1] = &hdr_a; cand_slot[1] = 0;
        } else {
            cand_hdr[0] = &hdr_a; cand_slot[0] = 0;
            cand_hdr[1] = &hdr_b; cand_slot[1] = 1;
        }
        ncand = 2;
    } else if (have_a) {
        cand_hdr[0] = &hdr_a; cand_slot[0] = 0; ncand = 1;
    } else {
        cand_hdr[0] = &hdr_b; cand_slot[0] = 1; ncand = 1;
    }

    /* The bitmap region is 56 KiB — heap, not stack (open may run on
     * threads with modest stacks). One scratch buffer threads from the
     * candidate loop through the final memcpy into the in-RAM bitmap. */
    uint8_t *bitmap_region = malloc(BITMAP_REGION_BYTES);
    if (!bitmap_region) return STM_ENOMEM;

    stm_bootstrap     *a  = NULL;
    stm_status         rc = STM_OK;

    stm_bootstrap_hdr *chosen_hdr  = NULL;
    uint32_t        chosen_slot = 0;
    for (int i = 0; i < ncand; i++) {
        stm_status cs = load_bitmap_for_hdr(d, cand_hdr[i], bitmap_region);
        if (cs == STM_OK) {
            chosen_hdr  = cand_hdr[i];
            chosen_slot = cand_slot[i];
            break;
        }
    }
    if (!chosen_hdr) { rc = STM_ECORRUPT; goto done; }

    /* Validate bounds on decoded sizes before using them (R7a P2-2):
     * an attacker-controlled header with a valid csum must not drive
     * arithmetic overflow or geometry drift. */
    uint64_t size_blocks = stm_load_le64(chosen_hdr->h_bootstrap_size_blocks);
    uint64_t node_blocks = stm_load_le64(chosen_hdr->h_data_node_blocks);
    uint64_t data_start  = stm_load_le64(chosen_hdr->h_data_start_block);
    uint64_t bit_count   = stm_load_le64(chosen_hdr->h_bitmap_bit_count);
    uint64_t bm_blocks   = stm_load_le64(chosen_hdr->h_bitmap_block_count);

    if (node_blocks != STM_BOOTSTRAP_NODE_BLOCKS) { rc = STM_EBADVERSION; goto done; }
    if (bm_blocks   != STM_BOOTSTRAP_BITMAP_BLOCKS) { rc = STM_EBADVERSION; goto done; }
    if (data_start  != STM_BOOTSTRAP_DATA_START_BLOCK) { rc = STM_EBADVERSION; goto done; }
    if (bit_count == 0 || bit_count > STM_BOOTSTRAP_MAX_NODES) {
        rc = STM_ECORRUPT; goto done;
    }

    /* Overflow: size_blocks * STM_UB_SIZE must fit in uint64_t. */
    if (size_blocks > UINT64_MAX / (uint64_t)STM_UB_SIZE) {
        rc = STM_ECORRUPT; goto done;
    }
    /* Overflow: data_start + bit_count * node_blocks. */
    if (bit_count > (UINT64_MAX - data_start) / node_blocks) {
        rc = STM_ECORRUPT; goto done;
    }
    if (data_start + bit_count * node_blocks > size_blocks) {
        rc = STM_ECORRUPT; goto done;
    }

    /* The pool must physically fit on the device. */
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    if (!caps) { rc = STM_EINVAL; goto done; }
    uint64_t size_bytes = size_blocks * (uint64_t)STM_UB_SIZE;
    if (STM_BOOTSTRAP_OFFSET > caps->size_bytes) { rc = STM_ECORRUPT; goto done; }
    if (size_bytes > caps->size_bytes - STM_BOOTSTRAP_OFFSET) {
        rc = STM_ECORRUPT; goto done;
    }

    uint64_t pool_uuid[2]   = {
        stm_load_le64(chosen_hdr->h_pool_uuid[0]),
        stm_load_le64(chosen_hdr->h_pool_uuid[1]),
    };
    uint64_t device_uuid[2] = {
        stm_load_le64(chosen_hdr->h_device_uuid[0]),
        stm_load_le64(chosen_hdr->h_device_uuid[1]),
    };

    a = alloc_new(d, size_bytes, pool_uuid, device_uuid);
    if (!a) { rc = STM_ENOMEM; goto done; }

    a->bitmap_gen       = stm_load_le64(chosen_hdr->h_bitmap_gen);
    a->hdr_slot_live    = chosen_slot;
    a->bitmap_slot_live =
        block_to_bitmap_slot(stm_load_le64(chosen_hdr->h_bitmap_block));

    /* Header's bit_count and our computed total_nodes must agree. */
    if (bit_count != a->total_nodes) { rc = STM_ECORRUPT; goto done; }

    memcpy(a->bitmap, bitmap_region, a->bitmap_bytes);
    memcpy(a->user_data, chosen_hdr->h_user_data,
           STM_BOOTSTRAP_USER_DATA_SIZE);

done:
    free(bitmap_region);
    if (rc != STM_OK) {
        if (a) { free(a->bitmap); free(a); }
        return rc;
    }
    *out_alloc = a;
    return STM_OK;
}

void stm_bootstrap_close(stm_bootstrap *a)
{
    if (!a) return;
    pending_entry *e = a->pending_head;
    while (e) {
        pending_entry *next = e->next;
        free(e);
        e = next;
    }
    free(a->reconcile_marked);   /* #791: defensive -- frees an abandoned pass */
    free(a->bitmap);
    free(a);
}

/* ========================================================================= */
/* Reserve / free / commit.                                                   */
/* ========================================================================= */

/* Scan for a run of `nnodes` consecutive free nodes starting at `start`.
 * Returns true + *out_first_node on success; false on no-fit. */
static bool find_free_run(const stm_bootstrap *a, uint64_t start, uint64_t nnodes,
                           uint64_t *out_first_node)
{
    if (nnodes == 0 || nnodes > a->total_nodes) return false;

    uint64_t scanned = 0;
    uint64_t cursor  = start % a->total_nodes;

    while (scanned < a->total_nodes) {
        if (bit_is_set(a->bitmap, cursor)) {
            cursor = (cursor + 1) % a->total_nodes;
            scanned++;
            continue;
        }

        /* Candidate run starts at `cursor`. Confirm nnodes free. */
        uint64_t end = cursor + nnodes;
        if (end > a->total_nodes) {
            /* Wrap-around not allowed for a contiguous run. Skip past
             * the end and retry from 0. */
            uint64_t skip = a->total_nodes - cursor;
            scanned += skip;
            cursor = 0;
            continue;
        }

        bool     ok    = true;
        uint64_t advance = nnodes;   /* nodes scanned forward this iter */
        for (uint64_t i = cursor; i < end; i++) {
            if (bit_is_set(a->bitmap, i)) {
                ok = false;
                advance = (i + 1) - cursor;
                cursor  = i + 1;
                break;
            }
        }
        if (ok) {
            *out_first_node = cursor;
            return true;
        }
        scanned += advance;
    }
    return false;
}

stm_status stm_bootstrap_reserve(stm_bootstrap *a, uint32_t nblocks,
                              uint64_t hint_paddr,
                              uint64_t *out_paddr)
{
    if (!a || !out_paddr) return STM_EINVAL;
    if (nblocks == 0) return STM_EINVAL;
    if (nblocks % STM_BOOTSTRAP_NODE_BLOCKS != 0) return STM_EINVAL;

    uint64_t nnodes = nblocks / (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;

    /* Determine start node from hint + rove. */
    uint64_t start = a->rove_next_node;
    if (hint_paddr != 0) {
        uint64_t hint_node = 0;
        if (paddr_to_node(a, hint_paddr, &hint_node) &&
            !bit_is_set(a->bitmap, hint_node)) {
            start = hint_node;
        }
    }

    uint64_t first_node = 0;
    if (!find_free_run(a, start, nnodes, &first_node)) {
        return STM_ENOSPC;
    }

    /* Set bits. */
    for (uint64_t i = 0; i < nnodes; i++) {
        bit_set(a->bitmap, first_node + i);
    }

    a->rove_next_node = (first_node + nnodes) % a->total_nodes;
    *out_paddr = node_to_paddr(a, first_node);
    return STM_OK;
}

stm_status stm_bootstrap_free(stm_bootstrap *a, uint64_t paddr, uint32_t nblocks,
                           uint64_t free_gen)
{
    if (!a) return STM_EINVAL;
    if (nblocks == 0) return STM_EINVAL;
    if (nblocks % STM_BOOTSTRAP_NODE_BLOCKS != 0) return STM_EINVAL;

    uint64_t nnodes = nblocks / (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;
    uint64_t first_node = 0;
    if (!paddr_to_node(a, paddr, &first_node)) return STM_EINVAL;
    if (first_node + nnodes > a->total_nodes) return STM_EINVAL;

    /* Verify every node is currently allocated (bit set).
     *
     * The PENDING scan below is O(N) per free and thus O(N^2) for a
     * burst of N frees between commits (R7a P2-3). The single-region
     * bitmap cap of STM_BOOTSTRAP_MAX_NODES nodes keeps this bounded; a
     * future upgrade to a sorted-interval structure could make it
     * O(log N) if the pattern becomes hot. */
    for (uint64_t i = 0; i < nnodes; i++) {
        if (!bit_is_set(a->bitmap, first_node + i)) return STM_EINVAL;
    }

    /* R7c P1-1/P2-2: idempotent retry — if the exact same (paddr,
     * nblocks) is already in PENDING, this is a commit-retry after a
     * transient failure. Update the free_gen stamp to the max (so the
     * later retry's gen wins) and return STM_OK. Callers that emitted
     * partial frees in a failed free_tree walk can safely retry the
     * entire walk.
     *
     * Non-identical overlap (different paddr/nblocks but intersecting
     * range) remains a caller bug → STM_EINVAL. */
    for (pending_entry *e = a->pending_head; e; e = e->next) {
        uint64_t e_first = 0;
        bool ok = paddr_to_node(a, e->paddr, &e_first);
        if (!ok) return STM_ECORRUPT;
        uint64_t e_nnodes = e->nblocks / (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;

        if (e->paddr == paddr && e->nblocks == nblocks) {
            /* Exact match: retry semantics. */
            if (free_gen > e->free_gen) e->free_gen = free_gen;
            return STM_OK;
        }
        if (first_node < e_first + e_nnodes && e_first < first_node + nnodes) {
            return STM_EINVAL;
        }
    }

    pending_entry *ent = calloc(1, sizeof *ent);
    if (!ent) return STM_ENOMEM;
    ent->paddr    = paddr;
    ent->nblocks  = nblocks;
    ent->free_gen = free_gen;
    ent->next     = a->pending_head;
    a->pending_head = ent;
    a->pending_count++;
    a->pending_nodes += nnodes;
    return STM_OK;
}

stm_status stm_bootstrap_commit(stm_bootstrap *a, uint64_t committed_gen)
{
    if (!a) return STM_EINVAL;

    /*
     * Three-phase commit (R7a P1-2 fix):
     *   Phase 1 — scan: compute the new bitmap in a scratch region and
     *     count which PENDING entries *would* sweep. Do NOT touch the
     *     pending list or the in-RAM bitmap yet.
     *   Phase 2 — I/O: write new bitmap → fsync → write new header →
     *     fsync. On failure, return without mutating in-RAM state.
     *   Phase 3 — finalize: I/O succeeded, so commit the sweep to
     *     in-RAM state (unlink + free entries, update counters, swap
     *     live slots, promote bitmap + gen).
     *
     * A failed commit leaves the caller's view of the allocator exactly
     * as it was. The on-disk new-slot write may partially succeed, but
     * the old slot is still live and mount recovers the pre-commit state.
     */

    /* The bitmap region is 56 KiB — heap, not stack. */
    uint8_t *new_region = malloc(BITMAP_REGION_BYTES);
    if (!new_region) return STM_ENOMEM;

    stm_status s = STM_OK;

    /* Phase 1 — scan + compute new bitmap region. */
    memset(new_region, 0, BITMAP_REGION_BYTES);
    memcpy(new_region, a->bitmap, a->bitmap_bytes);

    uint64_t swept_count = 0;
    uint64_t swept_nodes = 0;
    for (const pending_entry *e = a->pending_head; e; e = e->next) {
        if (e->free_gen >= committed_gen) continue;

        uint64_t first_node = 0;
        bool ok = paddr_to_node(a, e->paddr, &first_node);
        /* Invariant: every PENDING entry's paddr was validated on free().
         * A failure here means a pending_head link was corrupted — fatal. */
        if (!ok) { s = STM_ECORRUPT; goto out; }

        uint64_t nnodes = e->nblocks / (uint64_t)STM_BOOTSTRAP_NODE_BLOCKS;
        for (uint64_t i = 0; i < nnodes; i++) {
            bit_clear(new_region, first_node + i);
        }
        swept_nodes += nnodes;
        swept_count++;
    }

    uint8_t bitmap_csum[32];
    compute_bitmap_csum(new_region, bitmap_csum);

    /* Phase 2 — I/O. */
    uint32_t new_bitmap_slot = 1u - a->bitmap_slot_live;
    s = stm_bdev_write(a->d, bitmap_slot_offset(new_bitmap_slot),
                       new_region, BITMAP_REGION_BYTES);
    if (s != STM_OK) goto out;
    s = stm_bdev_fsync(a->d);
    if (s != STM_OK) goto out;

    stm_bootstrap_hdr hdr = { 0 };
    hdr.h_magic                 = stm_store_le64(STM_BOOTSTRAP_HDR_MAGIC);
    hdr.h_version               = stm_store_le32(STM_BOOTSTRAP_HDR_VERSION);
    hdr.h_flags                 = stm_store_le32(0);
    hdr.h_pool_uuid[0]          = stm_store_le64(a->pool_uuid[0]);
    hdr.h_pool_uuid[1]          = stm_store_le64(a->pool_uuid[1]);
    hdr.h_device_uuid[0]        = stm_store_le64(a->device_uuid[0]);
    hdr.h_device_uuid[1]        = stm_store_le64(a->device_uuid[1]);
    hdr.h_bitmap_gen            = stm_store_le64(a->bitmap_gen + 1);
    hdr.h_bitmap_block          = stm_store_le64(bitmap_slot_block(new_bitmap_slot));
    hdr.h_bitmap_bit_count      = stm_store_le64(a->total_nodes);
    hdr.h_bootstrap_size_blocks = stm_store_le64(a->bootstrap_size_blocks);
    hdr.h_data_node_blocks      = stm_store_le64(STM_BOOTSTRAP_NODE_BLOCKS);
    hdr.h_data_start_block      = stm_store_le64(a->data_start_block);
    hdr.h_bitmap_block_count    = stm_store_le64(STM_BOOTSTRAP_BITMAP_BLOCKS);
    memcpy(hdr.h_bitmap_csum, bitmap_csum, 32);
    memcpy(hdr.h_user_data, a->user_data, STM_BOOTSTRAP_USER_DATA_SIZE);

    uint8_t hdr_buf[STM_UB_SIZE];
    encode_hdr(&hdr, hdr_buf);

    uint32_t new_hdr_slot = 1u - a->hdr_slot_live;
    s = stm_bdev_write(a->d, hdr_slot_offset(new_hdr_slot),
                       hdr_buf, sizeof hdr_buf);
    if (s != STM_OK) goto out;
    s = stm_bdev_fsync(a->d);
    if (s != STM_OK) goto out;

    /* Phase 3 — finalize. I/O succeeded; promote in-RAM state. */
    pending_entry **link = &a->pending_head;
    pending_entry  *e    = a->pending_head;
    while (e) {
        pending_entry *next = e->next;
        if (e->free_gen < committed_gen) {
            *link = next;
            free(e);
        } else {
            link = &e->next;
        }
        e = next;
    }

    memcpy(a->bitmap, new_region, a->bitmap_bytes);
    a->bitmap_slot_live = new_bitmap_slot;
    a->hdr_slot_live    = new_hdr_slot;
    a->bitmap_gen      += 1;
    a->pending_count   -= swept_count;
    a->pending_nodes   -= swept_nodes;
    s = STM_OK;

out:
    free(new_region);
    return s;
}

/* ========================================================================= */
/* #791 mount-time reconcile (rollback / crash orphan reclamation).           */
/*                                                                            */
/* Deferred-free (R50 / P7-CAS-3): a CoW commit frees metadata nodes as       */
/* PENDING(free_gen=committed_gen), NOT swept until the NEXT commit; and the   */
/* final bootstrap commit precedes the UB write, so a crash in that window     */
/* "leaks the freshly-flushed nodes" (sync.c 9.6-impl-4b). Across repeated     */
/* crashes (a reboot loop) these orphans accumulate and exhaust the bootstrap  */
/* pool (#791: ~9 nodes/boot -> brick at ~boot 50). The 1-bit allocated bitmap */
/* can't tell an orphan from a live node, so reclamation needs the LIVE set.   */
/*                                                                            */
/* Mark-sweep rooted at the durable uberblock: after mount loads every         */
/* bootstrap-backed tree, the caller walks each (stm_btree_engine_walk_paddrs) */
/* and marks every reachable node; the sweep frees every ALLOCATED-but-        */
/* UNMARKED node -- both rolled-back orphan allocs AND unswept-pending frees   */
/* are, by definition, unreachable from the durable UB. Freed bits become      */
/* durable on the next stm_bootstrap_commit.                                   */
/*                                                                            */
/* COMPLETENESS IS THE CALLER'S OBLIGATION: every node reachable from the      */
/* durable UB MUST be marked, or the sweep frees a live node -> corruption.    */
/* The bootstrap-backed trees to walk (the completeness checklist for the      */
/* sync-layer driver, a separate chunk): alloc (per device) + alloc_roots +    */
/* keyschema + repair_log + cas + dataset + snapshot + engine_store. The pass  */
/* must run at mount BEFORE any free, so pending_head is empty (this format    */
/* does no pending rebuild on open) and the sweep need not touch it.           */
/* ========================================================================= */

stm_status stm_bootstrap_reconcile_begin(stm_bootstrap *a)
{
    if (!a) return STM_EINVAL;
    if (a->reconcile_marked) return STM_EBUSY;   /* a pass is already open */
    uint8_t *marked = calloc(1, a->bitmap_bytes);
    if (!marked) return STM_ENOMEM;
    a->reconcile_marked = marked;
    return STM_OK;
}

stm_status stm_bootstrap_reconcile_mark(stm_bootstrap *a, uint64_t paddr)
{
    if (!a || !a->reconcile_marked) return STM_EINVAL;
    /* Filter: only paddrs that land in THIS bootstrap's node space are marks.
     * The caller may pass every paddr a tree walk yields (data-area blocks,
     * other devices' paddrs); paddr_to_node rejects those and we ignore them. */
    uint64_t node = 0;
    if (!paddr_to_node(a, paddr, &node)) return STM_OK;
    bit_set(a->reconcile_marked, node);
    return STM_OK;
}

stm_status stm_bootstrap_reconcile_end(stm_bootstrap *a, uint64_t *out_freed_nodes)
{
    if (!a || !a->reconcile_marked) return STM_EINVAL;
    uint64_t freed = 0;
    for (uint64_t node = 0; node < a->total_nodes; node++) {
        if (bit_is_set(a->bitmap, node) &&
            !bit_is_set(a->reconcile_marked, node)) {
            bit_clear(a->bitmap, node);   /* orphan -> free; durable on next commit */
            freed++;
        }
    }
    free(a->reconcile_marked);
    a->reconcile_marked = NULL;
    if (out_freed_nodes) *out_freed_nodes = freed;
    return STM_OK;
}

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

stm_status stm_bootstrap_stats_get(const stm_bootstrap *a, stm_bootstrap_stats *out)
{
    if (!a || !out) return STM_EINVAL;

    uint64_t allocated = 0;
    for (uint64_t i = 0; i < a->total_nodes; i++) {
        if (bit_is_set(a->bitmap, i)) allocated++;
    }

    out->bootstrap_size_blocks = a->bootstrap_size_blocks;
    out->data_node_blocks      = STM_BOOTSTRAP_NODE_BLOCKS;
    out->total_nodes           = a->total_nodes;
    out->allocated_nodes       = allocated;
    out->pending_nodes         = a->pending_nodes;
    out->free_nodes            = a->total_nodes - allocated;
    out->header_slot_live      = a->hdr_slot_live;
    out->bitmap_slot_live      = a->bitmap_slot_live;
    out->bitmap_gen            = a->bitmap_gen;
    return STM_OK;
}

stm_status stm_bootstrap_is_allocated(const stm_bootstrap *a, uint64_t paddr,
                                   bool *out_allocated)
{
    if (!a || !out_allocated) return STM_EINVAL;
    uint64_t node = 0;
    if (!paddr_to_node(a, paddr, &node)) return STM_EINVAL;
    *out_allocated = bit_is_set(a->bitmap, node);
    return STM_OK;
}

/* ========================================================================= */
/* User-data slot (chunk 5d).                                                 */
/* ========================================================================= */

stm_status stm_bootstrap_set_user_data(stm_bootstrap *a,
                                        const void *data, size_t len)
{
    if (!a) return STM_EINVAL;
    if (len > STM_BOOTSTRAP_USER_DATA_SIZE) return STM_ERANGE;
    if (len > 0 && !data) return STM_EINVAL;

    memset(a->user_data, 0, STM_BOOTSTRAP_USER_DATA_SIZE);
    if (len) memcpy(a->user_data, data, len);
    return STM_OK;
}

stm_status stm_bootstrap_get_user_data(const stm_bootstrap *a,
                                        void *out_data, size_t len)
{
    if (!a || (len > 0 && !out_data)) return STM_EINVAL;
    if (len > STM_BOOTSTRAP_USER_DATA_SIZE) return STM_ERANGE;

    if (len) memcpy(out_data, a->user_data, len);
    return STM_OK;
}
