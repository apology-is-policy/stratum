#ifndef STM_FS_INTERNAL_H
#define STM_FS_INTERNAL_H

#include "stratum/fs.h"
#include "stratum/btree.h"
#include "stratum/super.h"
#include "stratum/key.h"
#include "stratum/bptr.h"
#include "stratum/crypto.h"
#include "stratum/alloc.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* On-disk extent record — stored as btree value for DATA keys.
 *
 * Layout: 24 bytes total. se_write_gen holds the sync generation at
 * encrypt time; the crypto layer uses (paddr, write_gen) as the AEAD
 * nonce input, so a paddr reused across free+realloc cycles still gets
 * a unique (key, nonce) pair. Unused on unencrypted volumes but always
 * populated for consistency.
 *
 * The compression algorithm is packed into the high byte of
 * se_clen_and_comp; the low 24 bits hold the stored (compressed
 * and/or encrypted) disk length. 24 bits covers up to 16 MiB, far more
 * than needed for 128 KiB extents (max dlen = STM_EXTENT_SIZE).
 *
 * If the data wouldn't compress smaller, se_clen equals se_dlen and
 * the comp algo is STM_COMP_NONE — the data is stored raw. */
struct __attribute__((packed)) stm_extent {
    le64 se_paddr;          /* physical byte address of data on disk */
    le64 se_write_gen;       /* write-gen counter (nonce uniqueness) */
    le32 se_dlen;            /* logical (uncompressed) data length */
    le32 se_clen_and_comp;   /* low 24 bits: stored disk length (pre-AEAD-tag)
                              * high 8 bits: compression algo (STM_COMP_*) */
};
STM_STATIC_ASSERT(sizeof(struct stm_extent) == 24, stm_extent_size);

static inline uint32_t stm_extent_clen(const struct stm_extent *e)
{
    return le32_to_cpu(e->se_clen_and_comp) & 0x00FFFFFFu;
}

static inline uint8_t stm_extent_comp(const struct stm_extent *e)
{
    return (uint8_t)((le32_to_cpu(e->se_clen_and_comp) >> 24) & 0xFFu);
}

static inline void stm_extent_set(struct stm_extent *e, uint64_t paddr,
                                  uint64_t write_gen,
                                  uint32_t dlen, uint32_t clen, uint8_t comp)
{
    e->se_paddr     = cpu_to_le64(paddr);
    e->se_write_gen = cpu_to_le64(write_gen);
    e->se_dlen      = cpu_to_le32(dlen);
    e->se_clen_and_comp =
        cpu_to_le32((clen & 0x00FFFFFFu) | ((uint32_t)comp << 24));
}

struct stm_fs {
    struct stm_block_dev dev;
    struct stm_btree    *tree;
    struct stm_btree    *snap_tree;     /* NULL until first snapshot */
    uint64_t gen;
    uint64_t next_ino;
    uint64_t next_snap_id;
    int      sb_slot;
    /* encryption state (copied from superblock for sync) */
    uint8_t  enc_algo;
    uint8_t  enc_kdf_salt[32];
    uint8_t  enc_wrapped_key[64];
    uint8_t  enc_nonce[24];
    /* DEK kept for creating crypto contexts on snap tree */
    uint8_t  dek[STM_CRYPTO_KEY_LEN];
    int      encrypted;
    struct stm_alloc *alloc;
    /* Reusable scratch buffers for extent I/O (avoid malloc per extent) */
    uint8_t *extent_buf;     /* STM_EXTENT_SIZE bytes — plaintext */
    uint8_t *comp_buf;       /* compression bound bytes — compressed plaintext */
    uint8_t *cipher_buf;     /* STM_EXTENT_SIZE + STM_CRYPTO_TAG_LEN bytes */
    /* Default compression algorithm for new extents (STM_COMP_*) */
    uint8_t  comp_algo;
    /* R10-3: set to 1 by stm_fs_open_ro; mutation APIs return -EROFS
     * when set. Without this the RO contract was docstring-only —
     * a buggy caller issuing writes through an RO-opened fs would
     * produce orphan ciphertexts that violate the AEAD nonce invariant
     * once the next RW session mounts. */
    int      read_only;
    /* R10-2: set to 1 when an internal failure (e.g. rollback reopen)
     * leaves fs->tree in an unusable state (NULL or inconsistent).
     * Public mutation / read APIs early-return -EIO rather than
     * dereferencing a NULL tree and crashing the server. The only
     * legal subsequent op on a wedged fs is stm_fs_close. */
    int      wedged;
};

static inline struct stm_key stm_mk_key(uint64_t ino, uint8_t type,
                                        uint64_t off)
{
    struct stm_key_cpu kc = { .ino = ino, .type = type, .offset = off };
    return stm_key_from_cpu(&kc);
}

static inline uint64_t stm_fnv1a(const char *data, size_t len)
{
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= (uint8_t)data[i];
        h *= UINT64_C(0x100000001b3);
    }
    return h;
}

/* Configure compression + crypto on a btree from fs state. Returns
 * non-zero on failure (stm_crypto_init OOM) — callers MUST propagate,
 * otherwise the tree is left without a crypto context and subsequent
 * writes go out as plaintext on what the user considers an encrypted
 * volume. That plaintext persists to disk, breaks the AEAD invariant
 * on next mount (decrypt of plaintext as ciphertext fails), and worst
 * case exposes the data to any reader of the raw device. */
static inline int stm_fs_configure_tree(struct stm_fs *fs,
                                        struct stm_btree *t)
{
#ifdef STM_HAVE_LZ4
    stm_btree_set_compression(t, STM_COMP_LZ4);
#else
    (void)fs; (void)t;
#endif
    if (fs->encrypted) {
        struct stm_crypto *ctx = NULL;
        int rc = stm_crypto_init(fs->dek, &ctx);
        if (rc) return rc;
        stm_btree_set_crypto(t, ctx);
    }
    return 0;
}

/* Write an SB at ss_gen = fs->gen + 1 with the current tree roots to the
 * opposite slot and fsync. Establishes/refreshes the R8-1 invariant:
 * disk ss_gen > fs->gen. Used at mount time (encrypted volumes) and after
 * stm_snap_rollback (R9-1) where the allocator has been rebuilt and any
 * pre-rollback in-session orphans need to be decoupled from future writes
 * by advancing the write-gen floor. Returns 0 on success, negative on
 * write/fsync failure — caller must handle (typically by refusing mount or
 * unwinding the operation). */
int stm_fs_gen_bump_disk(struct stm_fs *fs);

/* Read + decrypt + decompress an extent into buf (>= STM_EXTENT_SIZE bytes).
 * Exposed for the scrub CLI so it can force AEAD tag verification on every
 * extent. Returns 0 on success, -EIO on csum/AEAD/bounds failure. */
int extent_read_data(struct stm_fs *fs, const struct stm_extent *ext,
                     void *buf, uint32_t buf_len);

#endif /* STM_FS_INTERNAL_H */
