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
 * In-place semantics (outward): the public API mutates the caller's
 * buffer in place so the serialize / deserialize paths don't have
 * to keep two 128 KiB scratch buffers per node. Internally we go
 * through a heap-allocated intermediate because libsodium's
 * AEGIS-256 does NOT guarantee safety under aliased input/output —
 * the state-update step in the AEGIS round reads the plaintext
 * AFTER the ciphertext write, which clobbers subsequent reads on
 * aliased buffers. Empirically confirmed: with aliased pt/ct, the
 * decrypted plaintext came back as zeros. The intermediate is
 * wiped via `stm_ct_memzero` before free so plaintext key material
 * does not linger in the freed block.
 */

#include <stratum/btnode.h>
#include <stratum/btree_store.h>
#include <stratum/crypto.h>
#include <stratum/types.h>

#include <stdlib.h>
#include <string.h>

#define CIPHERTEXT_LEN  (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE)

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
                                    uint8_t *buf)
{
    if (!cx || !cx->metadata_key || !buf) return STM_EINVAL;

    uint8_t nonce[STM_AEAD_NONCE_LEN];
    uint8_t ad[AD_LEN];
    build_nonce(paddr, gen, cx->pool_uuid, nonce);
    build_ad(cx->pool_uuid, cx->device_uuid, ad);

    /* Heap scratch for the plaintext input (see module comment). The
     * commit hot path allocates one 128 KiB block per node; the
     * allocator commit already does this (serialize's outer scratch),
     * so the O(nodes) extra allocation is in the noise. If this
     * shows up in profiles later, pass a caller-owned scratch
     * through the serialize path to amortize. */
    uint8_t *pt = malloc(CIPHERTEXT_LEN);
    if (!pt) return STM_ENOMEM;
    memcpy(pt, buf, CIPHERTEXT_LEN);

    size_t out_len = 0;
    stm_status s = stm_aead_encrypt(STM_AEAD_AEGIS256,
                                      cx->metadata_key, nonce,
                                      ad, AD_LEN,
                                      pt, CIPHERTEXT_LEN,
                                      buf, &out_len);
    /* pt held plaintext key material (btnode headers + keys +
     * values). Wipe before free so freed-memory scans can't recover
     * tree contents. */
    stm_ct_memzero(pt, CIPHERTEXT_LEN);
    free(pt);
    if (s != STM_OK) return s;
    if (out_len != STM_BTNODE_SIZE) return STM_EBACKEND;
    return STM_OK;
}

stm_status stm_btree_node_decrypt(const stm_btree_crypt_ctx *cx,
                                    uint64_t paddr, uint64_t gen,
                                    uint8_t *buf)
{
    if (!cx || !cx->metadata_key || !buf) return STM_EINVAL;

    uint8_t nonce[STM_AEAD_NONCE_LEN];
    uint8_t ad[AD_LEN];
    build_nonce(paddr, gen, cx->pool_uuid, nonce);
    build_ad(cx->pool_uuid, cx->device_uuid, ad);

    /* Heap scratch for the ciphertext+tag input. libsodium's
     * aegis256_decrypt verifies the tag before committing any
     * plaintext, so a tag-fail leaves buf in undefined state (the
     * caller must discard it). */
    uint8_t *ct = malloc(STM_BTNODE_SIZE);
    if (!ct) return STM_ENOMEM;
    memcpy(ct, buf, STM_BTNODE_SIZE);

    size_t pt_len = 0;
    stm_status s = stm_aead_decrypt(STM_AEAD_AEGIS256,
                                      cx->metadata_key, nonce,
                                      ad, AD_LEN,
                                      ct, STM_BTNODE_SIZE,
                                      buf, &pt_len);
    free(ct);
    if (s != STM_OK) return s;
    if (pt_len != CIPHERTEXT_LEN) return STM_EBACKEND;
    return STM_OK;
}
