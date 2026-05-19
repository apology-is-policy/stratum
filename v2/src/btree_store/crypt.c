/* SPDX-License-Identifier: ISC */
/*
 * Metadata-node AEAD wrapper (Phase 4 chunk P4-3b).
 *
 *   see include/stratum/btree_store.h for the public surface.
 *   see v2/docs/phase4-status.md §"P4-3b" for the design doc.
 *
 * What this module does:
 *   - Encrypts every btnode image in place under AEGIS-256 using a
 *     per-pool 32-byte metadata key (P4-3a).
 *   - Binds paddr + gen + pool_uuid into the 32-byte AEAD nonce so
 *     (paddr, gen, pool_uuid) uniqueness → nonce uniqueness (ARCH §7.4.1,
 *     sync.tla's MountGenBump + stm_bootstrap's deferred-free).
 *   - Binds pool_uuid + device_uuid into the 32-byte AD so cross-pool
 *     and cross-device replay is rejected.
 *   - Tag is placed in the trailing 32 bytes of the on-disk image
 *     (same slot that carried the plaintext BLAKE3 self-csum before
 *     P4-3b). Tag bytes = STM_AEAD_TAG_LEN_AEGIS256 = 32, exactly the
 *     STM_BTNODE_CSUM_SIZE slot.
 *
 * 9.6-impl-1b: the node image size is a per-call parameter (`node_size`)
 * — STM_BTNODE_SIZE for the legacy metadata path, ~16 KiB for the COW
 * B+tree engine. The ciphertext region is node_size - STM_BTNODE_CSUM_SIZE
 * and the AEAD tag occupies the trailing STM_BTNODE_CSUM_SIZE bytes, at
 * any node size. The nonce / AD construction is node-size-independent.
 *
 * In-place semantics (outward): the public API mutates the caller's
 * buffer in place so the serialize / deserialize paths don't have
 * to keep two scratch buffers per node. Internally we go through a
 * heap-allocated intermediate because libsodium's AEGIS-256 does NOT
 * guarantee safety under aliased input/output — the state-update step
 * in the AEGIS round reads the plaintext AFTER the ciphertext write,
 * which clobbers subsequent reads on aliased buffers. Empirically
 * confirmed: with aliased pt/ct, the decrypted plaintext came back as
 * zeros. The intermediate is wiped via `stm_ct_memzero` before free so
 * plaintext key material does not linger in the freed block.
 */

#include <stratum/btnode.h>
#include <stratum/btree_store.h>
#include <stratum/crypto.h>
#include <stratum/types.h>

#include <stdlib.h>
#include <string.h>

_Static_assert(STM_AEAD_TAG_LEN_AEGIS256 == STM_BTNODE_CSUM_SIZE,
               "AEGIS-256 tag must fit exactly the btnode's trailing csum slot");
_Static_assert(STM_AEAD_NONCE_LEN == 32,
               "AEAD nonce must be 32 bytes for paddr||gen||pool_uuid layout");

/* Nonce layout (32 B): paddr (8 LE) ‖ gen (8 LE) ‖ pool_uuid (16 LE).
 *
 * Why those three inputs:
 *   - paddr is unique within a gen (stm_bootstrap's deferred-free
 *     prevents paddr reuse within a single commit).
 *   - gen is monotone across commits (sync.tla's MountGenBump forces
 *     current_gen > any durable gen on every mount).
 *   - pool_uuid scopes the whole nonce space to this pool so an
 *     attacker who observes ciphertext from pool A cannot splice it
 *     into pool B — even if A and B happen to reuse the same paddr/gen.
 *
 * LE encoding matches the rest of the on-disk format (uberblock
 * fields, btnode headers). Endianness is consistent across the code
 * base, so the nonce is byte-identical on every architecture. */
static void build_nonce(uint64_t paddr, uint64_t gen,
                         const uint64_t pool_uuid[2],
                         uint8_t out[STM_AEAD_NONCE_LEN])
{
    le64 p = stm_store_le64(paddr);
    le64 g = stm_store_le64(gen);
    le64 u0 = stm_store_le64(pool_uuid[0]);
    le64 u1 = stm_store_le64(pool_uuid[1]);
    memcpy(out +  0, p.v,  8);
    memcpy(out +  8, g.v,  8);
    memcpy(out + 16, u0.v, 8);
    memcpy(out + 24, u1.v, 8);
}

/* AD layout (32 B): pool_uuid (16 LE) ‖ device_uuid (16 LE). */
#define AD_LEN 32u

static void build_ad(const uint64_t pool_uuid[2],
                      const uint64_t device_uuid[2],
                      uint8_t out[AD_LEN])
{
    le64 u0 = stm_store_le64(pool_uuid[0]);
    le64 u1 = stm_store_le64(pool_uuid[1]);
    le64 d0 = stm_store_le64(device_uuid[0]);
    le64 d1 = stm_store_le64(device_uuid[1]);
    memcpy(out +  0, u0.v, 8);
    memcpy(out +  8, u1.v, 8);
    memcpy(out + 16, d0.v, 8);
    memcpy(out + 24, d1.v, 8);
}

stm_status stm_btree_node_encrypt(const stm_btree_crypt_ctx *cx,
                                    uint64_t paddr, uint64_t gen,
                                    uint8_t *buf, size_t node_size)
{
    if (!cx || !cx->metadata_key || !buf) return STM_EINVAL;
    if (node_size < STM_BTNODE_MIN_SIZE) return STM_EINVAL;

    /* Ciphertext region = node minus the trailing tag slot. */
    size_t ciphertext_len = node_size - STM_BTNODE_CSUM_SIZE;

    uint8_t nonce[STM_AEAD_NONCE_LEN];
    uint8_t ad[AD_LEN];
    build_nonce(paddr, gen, cx->pool_uuid, nonce);
    build_ad(cx->pool_uuid, cx->device_uuid, ad);

    /* Heap scratch for the plaintext input (see module comment). */
    uint8_t *pt = malloc(ciphertext_len);
    if (!pt) return STM_ENOMEM;
    memcpy(pt, buf, ciphertext_len);

    size_t out_len = 0;
    stm_status s = stm_aead_encrypt(STM_AEAD_AEGIS256,
                                      cx->metadata_key, nonce,
                                      ad, AD_LEN,
                                      pt, ciphertext_len,
                                      buf, &out_len);
    /* pt held plaintext key material (btnode headers + keys +
     * values). Wipe before free so freed-memory scans can't recover
     * tree contents. */
    stm_ct_memzero(pt, ciphertext_len);
    free(pt);
    if (s != STM_OK) return s;
    /* AEAD output = ciphertext + tag = node_size bytes. */
    if (out_len != node_size) return STM_EBACKEND;
    return STM_OK;
}

stm_status stm_btree_node_decrypt(const stm_btree_crypt_ctx *cx,
                                    uint64_t paddr, uint64_t gen,
                                    uint8_t *buf, size_t node_size)
{
    if (!cx || !cx->metadata_key || !buf) return STM_EINVAL;
    if (node_size < STM_BTNODE_MIN_SIZE) return STM_EINVAL;

    size_t ciphertext_len = node_size - STM_BTNODE_CSUM_SIZE;

    uint8_t nonce[STM_AEAD_NONCE_LEN];
    uint8_t ad[AD_LEN];
    build_nonce(paddr, gen, cx->pool_uuid, nonce);
    build_ad(cx->pool_uuid, cx->device_uuid, ad);

    /* Heap scratch for the ciphertext+tag input. libsodium's
     * aegis256_decrypt verifies the tag before committing any
     * plaintext, so a tag-fail leaves buf in undefined state (the
     * caller must discard it). */
    uint8_t *ct = malloc(node_size);
    if (!ct) return STM_ENOMEM;
    memcpy(ct, buf, node_size);

    size_t pt_len = 0;
    stm_status s = stm_aead_decrypt(STM_AEAD_AEGIS256,
                                      cx->metadata_key, nonce,
                                      ad, AD_LEN,
                                      ct, node_size,
                                      buf, &pt_len);
    free(ct);
    if (s != STM_OK) return s;
    if (pt_len != ciphertext_len) return STM_EBACKEND;
    return STM_OK;
}
