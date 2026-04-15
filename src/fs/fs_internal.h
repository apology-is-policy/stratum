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

/* Configure compression + crypto on a btree from fs state. */
static inline void stm_fs_configure_tree(struct stm_fs *fs,
                                         struct stm_btree *t)
{
#ifdef STM_HAVE_LZ4
    stm_btree_set_compression(t, STM_COMP_LZ4);
#else
    (void)fs; (void)t;
#endif
    if (fs->encrypted) {
        struct stm_crypto *ctx = NULL;
        stm_crypto_init(fs->dek, &ctx);
        stm_btree_set_crypto(t, ctx);
    }
}

#endif /* STM_FS_INTERNAL_H */
