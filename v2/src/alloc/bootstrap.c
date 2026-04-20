/* SPDX-License-Identifier: ISC */
/*
 * Bootstrap pool allocator (Phase 3 chunk 4a).
 *
 *   see ARCHITECTURE §6.5 (Bootstrap pool: no recursion)
 *   see v2/specs/allocator.tla (refcount + deferred-free spec)
 *
 * On-disk layout inside the bootstrap pool:
 *
 *   block 0    hdr slot A            (4 KiB)
 *   block 1    hdr slot B            (4 KiB)     ping-pong torn-write safety
 *   block 2    bitmap slot A         (4 KiB)
 *   block 3    bitmap slot B         (4 KiB)     ping-pong torn-write safety
 *   block 4..31            padding   (28 × 4 KiB) — reserved so data starts
 *                                                  at a STM_BOOTSTRAP_UNIT_BLOCKS
 *                                                  boundary
 *   block 32..             data area; allocated in 32-block units (128 KiB each)
 *
 * The header records which bitmap block is "live" (slot A or B) along with
 * a BLAKE3-256 csum of the bitmap block's payload. Commits COW:
 *
 *   1. Build the new bitmap in RAM, write it to the non-live bitmap slot,
 *      fsync.
 *   2. Build the new header (bitmap_gen+1, pointing at the new bitmap
 *      slot, with its csum), write to the non-live header slot, fsync.
 *
 * A crash between steps 1 and 2 leaves the old header still live — mount
 * picks it, reads the old (still valid) bitmap, and proceeds. A crash
 * mid-write in either slot is defeated by the self-csum: the half-written
 * slot's csum mismatches, so mount falls back to the other slot.
 */

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/hash.h>
#include <stratum/super.h>       /* STM_UB_SIZE = 4096 */

#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* On-disk header.                                                            */
/* ========================================================================= */

/* Magic "STMALOC1" read as a little-endian uint64. */
#define STM_ALLOC_HDR_MAGIC    UINT64_C(0x31434F4C414D5453)

typedef struct {
    le64    h_magic;                 /*    0 :  8 */
    le32    h_version;               /*    8 :  4 */
    le32    h_flags;                 /*   12 :  4 */
    le64    h_pool_uuid[2];          /*   16 : 16 */
    le64    h_device_uuid[2];        /*   32 : 16 */
    le64    h_bitmap_gen;            /*   48 :  8 */
    le64    h_bitmap_block;          /*   56 :  8 — block index in bootstrap */
    le64    h_bitmap_bit_count;      /*   64 :  8 */
    le64    h_bootstrap_size_blocks; /*   72 :  8 */
    le64    h_data_unit_blocks;      /*   80 :  8 */
    le64    h_data_start_block;      /*   88 :  8 */
    uint8_t h_bitmap_csum[32];       /*   96 : 32 */
    uint8_t h_reserved[3936];        /*  128 : 3936 */
    uint8_t h_csum[32];              /* 4064 : 32 */
} stm_alloc_hdr;

_Static_assert(sizeof(stm_alloc_hdr) == 4096,
               "stm_alloc_hdr must be exactly one 4 KiB block");

/* ========================================================================= */
/* In-RAM state.                                                              */
/* ========================================================================= */

typedef struct pending_entry pending_entry;
struct pending_entry {
    uint64_t       paddr;       /* absolute device paddr of first block */
    uint32_t       nblocks;     /* multiple of STM_BOOTSTRAP_UNIT_BLOCKS */
    uint64_t       free_gen;    /* free_gen stamp */
    pending_entry *next;
};

struct stm_alloc {
    stm_bdev  *d;
    uint64_t   bootstrap_size_blocks;
    uint64_t   total_units;
    uint64_t   data_start_block;    /* in-pool block index of unit 0 */
    uint64_t   pool_uuid[2];
    uint64_t   device_uuid[2];

    /* Which slots are live. A commit flips to the other slot. */
    uint32_t   hdr_slot_live;       /* 0 or 1 (STM_ALLOC_HDR_SLOT_A/B)   */
    uint32_t   bitmap_slot_live;    /* 0 or 1                            */
    uint64_t   bitmap_gen;

    /* In-RAM bitmap: bit i = 1 iff unit i is allocated (or PENDING). */
    uint8_t   *bitmap;
    size_t     bitmap_bytes;        /* = ceil(total_units / 8)           */

    /* Deferred-free list. Head is the most-recently-freed entry. */
    pending_entry *pending_head;
    uint64_t       pending_count;   /* #entries                          */
    uint64_t       pending_units;   /* total units across all entries    */

    /* Roving allocation cursor (in units). */
    uint64_t   rove_next_unit;
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
    return device_byte_offset((slot == 0) ? STM_ALLOC_HDR_SLOT_A
                                           : STM_ALLOC_HDR_SLOT_B);
}

/* Byte offset of bitmap slot A/B (pool block 2 or 3). */
static inline uint64_t bitmap_slot_offset(uint32_t slot)
{
    return device_byte_offset((slot == 0) ? STM_ALLOC_BITMAP_SLOT_A
                                           : STM_ALLOC_BITMAP_SLOT_B);
}

/* In-pool block index of bitmap slot A/B. */
static inline uint64_t bitmap_slot_block(uint32_t slot)
{
    return (slot == 0) ? STM_ALLOC_BITMAP_SLOT_A : STM_ALLOC_BITMAP_SLOT_B;
}

/* Unit index → absolute device paddr of the first block. */
static inline uint64_t unit_to_paddr(const stm_alloc *a, uint64_t unit_idx)
{
    uint64_t pool_block = a->data_start_block +
                          unit_idx * (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;
    return stm_paddr_make(0, bootstrap_start_block() + pool_block);
}

/* paddr → unit index. Returns true on valid, unit-aligned, in-range paddr. */
static bool paddr_to_unit(const stm_alloc *a, uint64_t paddr,
                          uint64_t *out_unit_idx)
{
    if (stm_paddr_device(paddr) != 0) return false;
    uint64_t block = stm_paddr_offset(paddr);
    uint64_t bootstrap_first = bootstrap_start_block();
    if (block < bootstrap_first + a->data_start_block) return false;

    uint64_t pool_block = block - bootstrap_first;
    if ((pool_block - a->data_start_block) %
            (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS != 0) return false;

    uint64_t unit = (pool_block - a->data_start_block) /
                    (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;
    if (unit >= a->total_units) return false;

    *out_unit_idx = unit;
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

/* BLAKE3 of a bitmap block (4 KiB). */
static void compute_bitmap_csum(const uint8_t *bitmap_block,
                                 uint8_t out[32])
{
    stm_blake3_hash h;
    stm_blake3(bitmap_block, STM_UB_SIZE, &h);
    memcpy(out, h.bytes, 32);
}

/* ========================================================================= */
/* Header encode / decode.                                                    */
/* ========================================================================= */

/*
 * Serialize `hdr_in` into a 4 KiB buffer suitable for direct bdev write.
 * Populates h_csum as BLAKE3-256 over bytes [0, 4064).
 */
static void encode_hdr(const stm_alloc_hdr *hdr_in, uint8_t buf[STM_UB_SIZE])
{
    memcpy(buf, hdr_in, sizeof *hdr_in);

    /* Zero the csum field before hashing. */
    memset(buf + offsetof(stm_alloc_hdr, h_csum), 0, 32);

    stm_blake3_hash h;
    stm_blake3(buf, STM_UB_SIZE - 32, &h);
    memcpy(buf + offsetof(stm_alloc_hdr, h_csum), h.bytes, 32);
}

/*
 * Deserialize a 4 KiB header buffer. Validates magic, version, self-csum.
 * Returns STM_EBADVERSION on magic/version mismatch, STM_ECORRUPT on csum.
 */
static stm_status decode_hdr(const uint8_t buf[STM_UB_SIZE],
                              stm_alloc_hdr *out_hdr)
{
    const stm_alloc_hdr *on_disk = (const stm_alloc_hdr *)buf;

    uint64_t magic = stm_load_le64(on_disk->h_magic);
    if (magic != STM_ALLOC_HDR_MAGIC) return STM_EBADVERSION;
    uint32_t version = stm_load_le32(on_disk->h_version);
    if (version != STM_ALLOC_HDR_VERSION) return STM_EBADVERSION;

    /* Recompute csum with the field zeroed. */
    uint8_t staged[STM_UB_SIZE];
    memcpy(staged, buf, STM_UB_SIZE);
    memset(staged + offsetof(stm_alloc_hdr, h_csum), 0, 32);

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
     * Explicit sizes down to one data unit plus reserved blocks are
     * permitted (useful for tests that don't want to allocate 64 MiB
     * files). */
    if (!size_explicit && size < STM_BOOTSTRAP_MIN_SIZE_BYTES)
        return STM_EINVAL;
    if (size > max_bootstrap) return STM_ENOSPC;

    /* Unit count check (chunk 4a MVP: single-block bitmap). */
    uint64_t size_blocks = size / STM_UB_SIZE;
    if (size_blocks <= STM_ALLOC_DATA_START_BLOCK) return STM_ENOSPC;
    uint64_t data_blocks = size_blocks - STM_ALLOC_DATA_START_BLOCK;
    uint64_t num_units = data_blocks / (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;
    if (num_units == 0) return STM_ENOSPC;
    if (num_units > STM_BOOTSTRAP_MAX_UNITS) return STM_ENOTSUPPORTED;

    *out_size_bytes = size;
    return STM_OK;
}

/* ========================================================================= */
/* Lifecycle: create, open, close.                                            */
/* ========================================================================= */

static stm_alloc *alloc_new(stm_bdev *d, uint64_t size_bytes,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2])
{
    stm_alloc *a = calloc(1, sizeof *a);
    if (!a) return NULL;

    a->d = d;
    a->bootstrap_size_blocks = size_bytes / STM_UB_SIZE;
    a->data_start_block = STM_ALLOC_DATA_START_BLOCK;
    a->total_units =
        (a->bootstrap_size_blocks - a->data_start_block) /
        (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;

    memcpy(a->pool_uuid,   pool_uuid,   sizeof a->pool_uuid);
    memcpy(a->device_uuid, device_uuid, sizeof a->device_uuid);

    /* Bitmap sized to exactly hold total_units bits, rounded up to a
     * byte. Zero-initialized = all units free. */
    a->bitmap_bytes = (size_t)((a->total_units + 7u) / 8u);
    a->bitmap = calloc(1, a->bitmap_bytes);
    if (!a->bitmap) {
        free(a);
        return NULL;
    }

    return a;
}

stm_status stm_alloc_create(stm_bdev *d,
                             const uint64_t pool_uuid[2],
                             const uint64_t device_uuid[2],
                             uint64_t bootstrap_size_bytes,
                             stm_alloc **out_alloc)
{
    if (!d || !pool_uuid || !device_uuid || !out_alloc) return STM_EINVAL;

    uint64_t size_bytes = 0;
    stm_status s = compute_bootstrap_size(d, bootstrap_size_bytes, &size_bytes);
    if (s != STM_OK) return s;

    stm_alloc *a = alloc_new(d, size_bytes, pool_uuid, device_uuid);
    if (!a) return STM_ENOMEM;

    /* Fresh pool: bitmap is all zeros (all units free), gen starts at 0.
     * The initial live slots are slot-0 (hdr A, bitmap A). Slot-1 is left
     * zero; its decode will fail with STM_EBADVERSION on magic mismatch,
     * ensuring open() unambiguously selects slot-0. */
    a->bitmap_gen       = 0;
    a->hdr_slot_live    = 0;
    a->bitmap_slot_live = 0;

    /* Write the bitmap block first (step 1 of our COW discipline). */
    uint8_t bitmap_block[STM_UB_SIZE] = { 0 };
    memcpy(bitmap_block, a->bitmap, a->bitmap_bytes);

    uint8_t bitmap_csum[32];
    compute_bitmap_csum(bitmap_block, bitmap_csum);

    s = stm_bdev_write(d, bitmap_slot_offset(a->bitmap_slot_live),
                       bitmap_block, sizeof bitmap_block);
    if (s != STM_OK) goto fail;
    s = stm_bdev_fsync(d);
    if (s != STM_OK) goto fail;

    /* Now the header (step 2). */
    stm_alloc_hdr hdr = { 0 };
    hdr.h_magic                 = stm_store_le64(STM_ALLOC_HDR_MAGIC);
    hdr.h_version               = stm_store_le32(STM_ALLOC_HDR_VERSION);
    hdr.h_flags                 = stm_store_le32(0);
    hdr.h_pool_uuid[0]          = stm_store_le64(pool_uuid[0]);
    hdr.h_pool_uuid[1]          = stm_store_le64(pool_uuid[1]);
    hdr.h_device_uuid[0]        = stm_store_le64(device_uuid[0]);
    hdr.h_device_uuid[1]        = stm_store_le64(device_uuid[1]);
    hdr.h_bitmap_gen            = stm_store_le64(a->bitmap_gen);
    hdr.h_bitmap_block          = stm_store_le64(bitmap_slot_block(a->bitmap_slot_live));
    hdr.h_bitmap_bit_count      = stm_store_le64(a->total_units);
    hdr.h_bootstrap_size_blocks = stm_store_le64(a->bootstrap_size_blocks);
    hdr.h_data_unit_blocks      = stm_store_le64(STM_BOOTSTRAP_UNIT_BLOCKS);
    hdr.h_data_start_block      = stm_store_le64(a->data_start_block);
    memcpy(hdr.h_bitmap_csum, bitmap_csum, 32);

    uint8_t hdr_buf[STM_UB_SIZE];
    encode_hdr(&hdr, hdr_buf);

    s = stm_bdev_write(d, hdr_slot_offset(a->hdr_slot_live),
                       hdr_buf, sizeof hdr_buf);
    if (s != STM_OK) goto fail;
    s = stm_bdev_fsync(d);
    if (s != STM_OK) goto fail;

    *out_alloc = a;
    return STM_OK;

fail:
    free(a->bitmap);
    free(a);
    return s;
}

stm_status stm_alloc_open(stm_bdev *d, stm_alloc **out_alloc)
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

    stm_alloc_hdr hdr_a, hdr_b;
    stm_status s_a = decode_hdr(hdr_buf_a, &hdr_a);
    stm_status s_b = decode_hdr(hdr_buf_b, &hdr_b);

    bool have_a = (s_a == STM_OK);
    bool have_b = (s_b == STM_OK);
    if (!have_a && !have_b) {
        /* No valid header on either slot. Either version mismatch (via
         * whichever slot decoded non-OK for version-y reasons) or csum
         * corruption. Return the more specific error when possible. */
        if (s_a == STM_EBADVERSION || s_b == STM_EBADVERSION) {
            /* One might be STM_EBADVERSION while the other's STM_ECORRUPT.
             * If either is STM_EBADVERSION, report it — the operator
             * needs to know the format isn't what we expected. */
            return STM_EBADVERSION;
        }
        return STM_ECORRUPT;
    }

    /* Pick higher bitmap_gen among valid slots. */
    stm_alloc_hdr *live_hdr;
    uint32_t       live_slot;
    if (have_a && have_b) {
        uint64_t ga = stm_load_le64(hdr_a.h_bitmap_gen);
        uint64_t gb = stm_load_le64(hdr_b.h_bitmap_gen);
        if (gb > ga) {
            live_hdr = &hdr_b; live_slot = 1;
        } else {
            live_hdr = &hdr_a; live_slot = 0;
        }
    } else if (have_a) {
        live_hdr = &hdr_a; live_slot = 0;
    } else {
        live_hdr = &hdr_b; live_slot = 1;
    }

    /* Read the designated bitmap block. */
    uint64_t bitmap_block_idx = stm_load_le64(live_hdr->h_bitmap_block);
    if (bitmap_block_idx != STM_ALLOC_BITMAP_SLOT_A &&
        bitmap_block_idx != STM_ALLOC_BITMAP_SLOT_B) return STM_ECORRUPT;

    uint8_t bitmap_block[STM_UB_SIZE];
    s = stm_bdev_read(d, device_byte_offset(bitmap_block_idx),
                      bitmap_block, sizeof bitmap_block);
    if (s != STM_OK) return s;

    /* Verify bitmap csum. */
    uint8_t expected_csum[32];
    compute_bitmap_csum(bitmap_block, expected_csum);
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(expected_csum[i] ^ live_hdr->h_bitmap_csum[i]);
    }
    if (diff != 0) return STM_ECORRUPT;

    /* Build the stm_alloc. */
    uint64_t size_blocks = stm_load_le64(live_hdr->h_bootstrap_size_blocks);
    uint64_t unit_blocks = stm_load_le64(live_hdr->h_data_unit_blocks);
    uint64_t data_start  = stm_load_le64(live_hdr->h_data_start_block);
    uint64_t bit_count   = stm_load_le64(live_hdr->h_bitmap_bit_count);

    if (unit_blocks != STM_BOOTSTRAP_UNIT_BLOCKS) return STM_EBADVERSION;
    if (data_start  != STM_ALLOC_DATA_START_BLOCK) return STM_EBADVERSION;
    if (bit_count  == 0 || bit_count > STM_BOOTSTRAP_MAX_UNITS) return STM_ECORRUPT;
    if (data_start + bit_count * unit_blocks > size_blocks) return STM_ECORRUPT;

    uint64_t pool_uuid[2]   = {
        stm_load_le64(live_hdr->h_pool_uuid[0]),
        stm_load_le64(live_hdr->h_pool_uuid[1]),
    };
    uint64_t device_uuid[2] = {
        stm_load_le64(live_hdr->h_device_uuid[0]),
        stm_load_le64(live_hdr->h_device_uuid[1]),
    };

    uint64_t size_bytes = size_blocks * (uint64_t)STM_UB_SIZE;
    stm_alloc *a = alloc_new(d, size_bytes, pool_uuid, device_uuid);
    if (!a) return STM_ENOMEM;

    a->bitmap_gen       = stm_load_le64(live_hdr->h_bitmap_gen);
    a->hdr_slot_live    = live_slot;
    a->bitmap_slot_live = (uint32_t)(bitmap_block_idx - STM_ALLOC_BITMAP_SLOT_A);

    /* Load bitmap. `bit_count` and our internal total_units must agree
     * (alloc_new computed it from size). */
    if (bit_count != a->total_units) {
        /* Header records differ from geometry — format drift. */
        free(a->bitmap);
        free(a);
        return STM_ECORRUPT;
    }
    memcpy(a->bitmap, bitmap_block, a->bitmap_bytes);

    *out_alloc = a;
    return STM_OK;
}

void stm_alloc_close(stm_alloc *a)
{
    if (!a) return;
    pending_entry *e = a->pending_head;
    while (e) {
        pending_entry *next = e->next;
        free(e);
        e = next;
    }
    free(a->bitmap);
    free(a);
}

/* ========================================================================= */
/* Reserve / free / commit.                                                   */
/* ========================================================================= */

/* Scan for a run of `nunits` consecutive free units starting at `start`.
 * Returns true + *out_first_unit on success; false on no-fit. */
static bool find_free_run(const stm_alloc *a, uint64_t start, uint64_t nunits,
                           uint64_t *out_first_unit)
{
    if (nunits == 0 || nunits > a->total_units) return false;

    uint64_t scanned = 0;
    uint64_t cursor  = start % a->total_units;

    while (scanned < a->total_units) {
        if (bit_is_set(a->bitmap, cursor)) {
            cursor = (cursor + 1) % a->total_units;
            scanned++;
            continue;
        }

        /* Candidate run starts at `cursor`. Confirm nunits free. */
        uint64_t end = cursor + nunits;
        if (end > a->total_units) {
            /* Wrap-around not allowed for a contiguous run. Skip past
             * the end and retry from 0. */
            uint64_t skip = a->total_units - cursor;
            scanned += skip;
            cursor = 0;
            continue;
        }

        bool     ok    = true;
        uint64_t advance = nunits;   /* units scanned forward this iter */
        for (uint64_t i = cursor; i < end; i++) {
            if (bit_is_set(a->bitmap, i)) {
                ok = false;
                advance = (i + 1) - cursor;
                cursor  = i + 1;
                break;
            }
        }
        if (ok) {
            *out_first_unit = cursor;
            return true;
        }
        scanned += advance;
    }
    return false;
}

stm_status stm_alloc_reserve(stm_alloc *a, uint32_t nblocks,
                              uint64_t hint_paddr,
                              uint64_t *out_paddr)
{
    if (!a || !out_paddr) return STM_EINVAL;
    if (nblocks == 0) return STM_EINVAL;
    if (nblocks % STM_BOOTSTRAP_UNIT_BLOCKS != 0) return STM_EINVAL;

    uint64_t nunits = nblocks / (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;

    /* Determine start unit from hint + rove. */
    uint64_t start = a->rove_next_unit;
    if (hint_paddr != 0) {
        uint64_t hint_unit = 0;
        if (paddr_to_unit(a, hint_paddr, &hint_unit) &&
            !bit_is_set(a->bitmap, hint_unit)) {
            start = hint_unit;
        }
    }

    uint64_t first_unit = 0;
    if (!find_free_run(a, start, nunits, &first_unit)) {
        return STM_ENOSPC;
    }

    /* Set bits. */
    for (uint64_t i = 0; i < nunits; i++) {
        bit_set(a->bitmap, first_unit + i);
    }

    a->rove_next_unit = (first_unit + nunits) % a->total_units;
    *out_paddr = unit_to_paddr(a, first_unit);
    return STM_OK;
}

stm_status stm_alloc_free(stm_alloc *a, uint64_t paddr, uint32_t nblocks,
                           uint64_t free_gen)
{
    if (!a) return STM_EINVAL;
    if (nblocks == 0) return STM_EINVAL;
    if (nblocks % STM_BOOTSTRAP_UNIT_BLOCKS != 0) return STM_EINVAL;

    uint64_t nunits = nblocks / (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;
    uint64_t first_unit = 0;
    if (!paddr_to_unit(a, paddr, &first_unit)) return STM_EINVAL;
    if (first_unit + nunits > a->total_units) return STM_EINVAL;

    /* Verify every unit is currently allocated (bit set) and not already
     * in a PENDING entry — overlapping PENDING entries would corrupt the
     * commit-sweep accounting. */
    for (uint64_t i = 0; i < nunits; i++) {
        if (!bit_is_set(a->bitmap, first_unit + i)) return STM_EINVAL;
    }
    for (pending_entry *e = a->pending_head; e; e = e->next) {
        uint64_t e_first = 0;
        (void)paddr_to_unit(a, e->paddr, &e_first);
        uint64_t e_nunits = e->nblocks / (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;
        /* overlap check */
        if (first_unit < e_first + e_nunits && e_first < first_unit + nunits) {
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
    a->pending_units += nunits;
    return STM_OK;
}

stm_status stm_alloc_commit(stm_alloc *a, uint64_t committed_gen)
{
    if (!a) return STM_EINVAL;

    /* Build the post-sweep bitmap in a scratch block. Sweep criterion
     * (allocator.tla): PENDING with free_gen < committed_gen → clear. */
    uint8_t new_bitmap_block[STM_UB_SIZE];
    memset(new_bitmap_block, 0, sizeof new_bitmap_block);
    memcpy(new_bitmap_block, a->bitmap, a->bitmap_bytes);

    pending_entry **link = &a->pending_head;
    pending_entry  *e    = a->pending_head;
    uint64_t        swept_count = 0;
    uint64_t        swept_units = 0;
    while (e) {
        pending_entry *next = e->next;
        if (e->free_gen < committed_gen) {
            /* Sweep: clear bits in the staged bitmap. */
            uint64_t first_unit = 0;
            if (paddr_to_unit(a, e->paddr, &first_unit)) {
                uint64_t nunits = e->nblocks /
                                  (uint64_t)STM_BOOTSTRAP_UNIT_BLOCKS;
                for (uint64_t i = 0; i < nunits; i++) {
                    bit_clear(new_bitmap_block, first_unit + i);
                }
                swept_units += nunits;
            }
            *link = next;
            free(e);
            swept_count++;
        } else {
            link = &e->next;
        }
        e = next;
    }

    uint8_t bitmap_csum[32];
    compute_bitmap_csum(new_bitmap_block, bitmap_csum);

    /* Step 1: write new bitmap to the non-live slot, fsync. */
    uint32_t new_bitmap_slot = 1u - a->bitmap_slot_live;
    stm_status s = stm_bdev_write(a->d, bitmap_slot_offset(new_bitmap_slot),
                                   new_bitmap_block, sizeof new_bitmap_block);
    if (s != STM_OK) return s;
    s = stm_bdev_fsync(a->d);
    if (s != STM_OK) return s;

    /* Step 2: write new header to the non-live slot, fsync. */
    stm_alloc_hdr hdr = { 0 };
    hdr.h_magic                 = stm_store_le64(STM_ALLOC_HDR_MAGIC);
    hdr.h_version               = stm_store_le32(STM_ALLOC_HDR_VERSION);
    hdr.h_flags                 = stm_store_le32(0);
    hdr.h_pool_uuid[0]          = stm_store_le64(a->pool_uuid[0]);
    hdr.h_pool_uuid[1]          = stm_store_le64(a->pool_uuid[1]);
    hdr.h_device_uuid[0]        = stm_store_le64(a->device_uuid[0]);
    hdr.h_device_uuid[1]        = stm_store_le64(a->device_uuid[1]);
    hdr.h_bitmap_gen            = stm_store_le64(a->bitmap_gen + 1);
    hdr.h_bitmap_block          = stm_store_le64(bitmap_slot_block(new_bitmap_slot));
    hdr.h_bitmap_bit_count      = stm_store_le64(a->total_units);
    hdr.h_bootstrap_size_blocks = stm_store_le64(a->bootstrap_size_blocks);
    hdr.h_data_unit_blocks      = stm_store_le64(STM_BOOTSTRAP_UNIT_BLOCKS);
    hdr.h_data_start_block      = stm_store_le64(a->data_start_block);
    memcpy(hdr.h_bitmap_csum, bitmap_csum, 32);

    uint8_t hdr_buf[STM_UB_SIZE];
    encode_hdr(&hdr, hdr_buf);

    uint32_t new_hdr_slot = 1u - a->hdr_slot_live;
    s = stm_bdev_write(a->d, hdr_slot_offset(new_hdr_slot),
                       hdr_buf, sizeof hdr_buf);
    if (s != STM_OK) return s;
    s = stm_bdev_fsync(a->d);
    if (s != STM_OK) return s;

    /* Promote in-RAM state. */
    memcpy(a->bitmap, new_bitmap_block, a->bitmap_bytes);
    a->bitmap_slot_live = new_bitmap_slot;
    a->hdr_slot_live    = new_hdr_slot;
    a->bitmap_gen      += 1;

    a->pending_count   -= swept_count;
    a->pending_units   -= swept_units;
    return STM_OK;
}

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

stm_status stm_alloc_stats_get(const stm_alloc *a, stm_alloc_stats *out)
{
    if (!a || !out) return STM_EINVAL;

    uint64_t allocated = 0;
    for (uint64_t i = 0; i < a->total_units; i++) {
        if (bit_is_set(a->bitmap, i)) allocated++;
    }

    out->bootstrap_size_blocks = a->bootstrap_size_blocks;
    out->data_unit_blocks      = STM_BOOTSTRAP_UNIT_BLOCKS;
    out->total_units           = a->total_units;
    out->allocated_units       = allocated;
    out->pending_units         = a->pending_units;
    out->free_units            = a->total_units - allocated;
    out->header_slot_live      = a->hdr_slot_live;
    out->bitmap_slot_live      = a->bitmap_slot_live;
    out->bitmap_gen            = a->bitmap_gen;
    return STM_OK;
}

stm_status stm_alloc_is_allocated(const stm_alloc *a, uint64_t paddr,
                                   bool *out_allocated)
{
    if (!a || !out_allocated) return STM_EINVAL;
    uint64_t unit = 0;
    if (!paddr_to_unit(a, paddr, &unit)) return STM_EINVAL;
    *out_allocated = bit_is_set(a->bitmap, unit);
    return STM_OK;
}
