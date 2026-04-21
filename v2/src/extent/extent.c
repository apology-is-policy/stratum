/* SPDX-License-Identifier: ISC */
/*
 * Data-extent AEAD stub (Phase 4 chunk P4-5).
 *
 *   see include/stratum/extent.h for the surface + design notes.
 *   see ARCHITECTURE §7.5 / §7.6.1 for the committed nonce + AD layout.
 */
#include <stratum/extent.h>

#include <string.h>

/* Nonce layout (32 bytes), same shape as P4-3b's metadata nonce:
 *   paddr (8 LE) || gen (8 LE) || pool_uuid (16 LE)
 * Uniqueness of (paddr, gen, pool_uuid) follows from
 * stm_bootstrap's deferred-free + sync.tla's MountGenBump. The
 * pool_uuid prefix scopes the nonce space so cross-pool replay is
 * rejected independent of the AD check. */
static void build_nonce(uint64_t paddr, uint64_t gen,
                         const uint64_t pool_uuid[2],
                         uint8_t out[STM_AEAD_NONCE_LEN])
{
    le64 p  = stm_store_le64(paddr);
    le64 g  = stm_store_le64(gen);
    le64 u0 = stm_store_le64(pool_uuid[0]);
    le64 u1 = stm_store_le64(pool_uuid[1]);
    memcpy(out +  0, p.v,  8);
    memcpy(out +  8, g.v,  8);
    memcpy(out + 16, u0.v, 8);
    memcpy(out + 24, u1.v, 8);
}

void stm_ad_extent_pack(const stm_ad_extent *ad,
                         uint8_t out[STM_AD_EXTENT_PACKED_LEN])
{
    le32 magic    = stm_store_le32(ad->magic);
    le32 version  = stm_store_le32(ad->version);
    le64 pu0      = stm_store_le64(ad->pool_uuid[0]);
    le64 pu1      = stm_store_le64(ad->pool_uuid[1]);
    le64 ds_id    = stm_store_le64(ad->dataset_id);
    le64 ino      = stm_store_le64(ad->ino);
    le64 offset   = stm_store_le64(ad->offset);
    le64 ck       = stm_store_le64(ad->content_kind);

    size_t o = 0;
    memcpy(out + o, magic.v,   4); o += 4;
    memcpy(out + o, version.v, 4); o += 4;
    memcpy(out + o, pu0.v,     8); o += 8;
    memcpy(out + o, pu1.v,     8); o += 8;
    memcpy(out + o, ds_id.v,   8); o += 8;
    memcpy(out + o, ino.v,     8); o += 8;
    memcpy(out + o, offset.v,  8); o += 8;
    memcpy(out + o, ck.v,      8); o += 8;
    /* 4+4+16+8+8+8+8 = 56 bytes — matches ARCH §7.6.1. */
    (void)o;
}

stm_status stm_extent_encrypt(stm_aead_mode mode,
                               const uint8_t *key,
                               uint64_t paddr, uint64_t gen,
                               const stm_ad_extent *ad,
                               const void *plaintext, size_t pt_len,
                               void *out, size_t out_cap,
                               size_t *out_len)
{
    if (!key || !ad || !out) return STM_EINVAL;
    if (pt_len > 0 && !plaintext) return STM_EINVAL;

    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) return STM_EINVAL;
    if (out_cap < pt_len + tag_len) return STM_ERANGE;

    uint64_t pool_uuid[2] = { ad->pool_uuid[0], ad->pool_uuid[1] };

    uint8_t nonce[STM_AEAD_NONCE_LEN];
    uint8_t ad_packed[STM_AD_EXTENT_PACKED_LEN];
    build_nonce(paddr, gen, pool_uuid, nonce);
    stm_ad_extent_pack(ad, ad_packed);

    size_t written = 0;
    stm_status s = stm_aead_encrypt(mode, key, nonce,
                                      ad_packed, STM_AD_EXTENT_PACKED_LEN,
                                      plaintext, pt_len,
                                      out, &written);
    if (s != STM_OK) return s;
    if (out_len) *out_len = written;
    return STM_OK;
}

stm_status stm_extent_decrypt(stm_aead_mode mode,
                               const uint8_t *key,
                               uint64_t paddr, uint64_t gen,
                               const stm_ad_extent *ad,
                               const void *ct_and_tag, size_t ct_and_tag_len,
                               void *out_plaintext, size_t out_pt_cap,
                               size_t *out_pt_len)
{
    if (!key || !ad || !ct_and_tag) return STM_EINVAL;

    size_t tag_len = stm_aead_tag_len(mode);
    if (tag_len == 0) return STM_EINVAL;
    if (ct_and_tag_len < tag_len) return STM_EINVAL;

    size_t pt_len = ct_and_tag_len - tag_len;
    if (out_pt_cap < pt_len) return STM_ERANGE;

    uint64_t pool_uuid[2] = { ad->pool_uuid[0], ad->pool_uuid[1] };

    uint8_t nonce[STM_AEAD_NONCE_LEN];
    uint8_t ad_packed[STM_AD_EXTENT_PACKED_LEN];
    build_nonce(paddr, gen, pool_uuid, nonce);
    stm_ad_extent_pack(ad, ad_packed);

    size_t written = 0;
    stm_status s = stm_aead_decrypt(mode, key, nonce,
                                      ad_packed, STM_AD_EXTENT_PACKED_LEN,
                                      ct_and_tag, ct_and_tag_len,
                                      out_plaintext, &written);
    if (s != STM_OK) return s;
    if (out_pt_len) *out_pt_len = written;
    return STM_OK;
}
