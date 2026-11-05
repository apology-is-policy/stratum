/* SPDX-License-Identifier: ISC */
/*
 * Data-extent AEAD tests (Phase 4 chunk P4-5 stub).
 *
 * Satisfies ROADMAP §7.2's "encrypted writes round-trip correctly
 * with AEGIS-256 and XChaCha20-SIV" at the crypto layer. No extent
 * manager — those tests come in Phase 6 when the extent tree lands.
 *
 * Coverage:
 *   - Round-trip with each AEAD mode.
 *   - AD-field mismatch rejects (pool_uuid / dataset_id / ino /
 *     offset / content_kind each tampered individually).
 *   - Tag tamper detected.
 *   - Nonce mismatch (wrong paddr / gen) rejects.
 */
#include "tharness.h"
#include <stratum/crypto.h>
#include <stratum/extent.h>

#include <string.h>

static const uint8_t KEY_AEGIS[STM_AEAD_KEY_LEN_AEGIS256] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static const uint8_t KEY_XCHACHA[STM_AEAD_KEY_LEN_XCHACHA20_SIV] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
};

static stm_ad_extent make_ad(void)
{
    stm_ad_extent ad = {
        .magic        = STM_AD_MAGIC_EXTENT,
        .version      = STM_AD_VERSION_EXTENT,
        .pool_uuid    = { 0xA1A1A1A1A1A1A1A1ULL, 0xB2B2B2B2B2B2B2B2ULL },
        .dataset_id   = 0,
        .ino          = 42,
        .offset       = 0x1000,
        .content_kind = 0,
    };
    return ad;
}

/* Helper: round-trip a plaintext under a given mode + key. */
static void roundtrip_mode(stm_aead_mode mode, const uint8_t *key)
{
    STM_ASSERT_OK(stm_crypto_init());
    stm_ad_extent ad = make_ad();

    const uint8_t plaintext[256] = {
        'h','e','l','l','o',' ','e','x','t','e','n','t',' ','d','a','t','a',
    };
    const size_t pt_len = sizeof plaintext;
    const size_t tag_len = stm_aead_tag_len(mode);

    uint8_t ct[sizeof plaintext + STM_AEAD_TAG_LEN_MAX] = { 0 };
    size_t  ct_len = 0;
    STM_ASSERT_OK(stm_extent_encrypt(mode, key,
                                       /*paddr=*/ 7u, /*gen=*/ 3u, &ad,
                                       plaintext, pt_len,
                                       ct, sizeof ct, &ct_len));
    STM_ASSERT_EQ(ct_len, pt_len + tag_len);

    uint8_t pt_back[sizeof plaintext] = { 0 };
    size_t  pt_back_len = 0;
    STM_ASSERT_OK(stm_extent_decrypt(mode, key,
                                       /*paddr=*/ 7u, /*gen=*/ 3u, &ad,
                                       ct, ct_len,
                                       pt_back, sizeof pt_back, &pt_back_len));
    STM_ASSERT_EQ(pt_back_len, pt_len);
    STM_ASSERT_EQ(memcmp(pt_back, plaintext, pt_len), 0);
}

STM_TEST(extent_roundtrip_aegis256) {
    roundtrip_mode(STM_AEAD_AEGIS256, KEY_AEGIS);
}

STM_TEST(extent_roundtrip_xchacha20_siv) {
    roundtrip_mode(STM_AEAD_XCHACHA20_SIV, KEY_XCHACHA);
}

/* AD-field tamper — each field independently proves its binding. */
static void ad_tamper_rejects(stm_aead_mode mode, const uint8_t *key,
                                stm_ad_extent tamper_ad)
{
    STM_ASSERT_OK(stm_crypto_init());
    stm_ad_extent ad = make_ad();

    const uint8_t plaintext[32] = { 0 };
    uint8_t ct[sizeof plaintext + STM_AEAD_TAG_LEN_MAX] = { 0 };
    size_t  ct_len = 0;
    STM_ASSERT_OK(stm_extent_encrypt(mode, key, 1u, 1u, &ad,
                                       plaintext, sizeof plaintext,
                                       ct, sizeof ct, &ct_len));

    uint8_t pt_back[sizeof plaintext] = { 0 };
    size_t  pt_back_len = 0;
    stm_status s = stm_extent_decrypt(mode, key, 1u, 1u, &tamper_ad,
                                        ct, ct_len,
                                        pt_back, sizeof pt_back, &pt_back_len);
    STM_ASSERT_ERR(s, STM_EBADTAG);
}

STM_TEST(extent_ad_pool_uuid_tamper_rejects) {
    stm_ad_extent t = make_ad();
    t.pool_uuid[0] ^= 0xFFULL;
    ad_tamper_rejects(STM_AEAD_AEGIS256, KEY_AEGIS, t);
}

STM_TEST(extent_ad_dataset_id_tamper_rejects) {
    stm_ad_extent t = make_ad();
    t.dataset_id = 99;
    ad_tamper_rejects(STM_AEAD_AEGIS256, KEY_AEGIS, t);
}

STM_TEST(extent_ad_ino_tamper_rejects) {
    stm_ad_extent t = make_ad();
    t.ino = 43;
    ad_tamper_rejects(STM_AEAD_AEGIS256, KEY_AEGIS, t);
}

STM_TEST(extent_ad_offset_tamper_rejects) {
    stm_ad_extent t = make_ad();
    t.offset += 16;
    ad_tamper_rejects(STM_AEAD_AEGIS256, KEY_AEGIS, t);
}

STM_TEST(extent_ad_content_kind_tamper_rejects) {
    stm_ad_extent t = make_ad();
    t.content_kind = 1;
    ad_tamper_rejects(STM_AEAD_AEGIS256, KEY_AEGIS, t);
}

/* Nonce tamper — wrong paddr / gen at decrypt time. */
STM_TEST(extent_nonce_paddr_tamper_rejects) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_ad_extent ad = make_ad();
    const uint8_t plaintext[32] = { 0 };
    uint8_t ct[sizeof plaintext + STM_AEAD_TAG_LEN_MAX] = { 0 };
    size_t  ct_len = 0;
    STM_ASSERT_OK(stm_extent_encrypt(STM_AEAD_AEGIS256, KEY_AEGIS,
                                       /*paddr=*/ 100u, /*gen=*/ 1u, &ad,
                                       plaintext, sizeof plaintext,
                                       ct, sizeof ct, &ct_len));
    uint8_t pt_back[sizeof plaintext]; size_t pl = 0;
    stm_status s = stm_extent_decrypt(STM_AEAD_AEGIS256, KEY_AEGIS,
                                        /*paddr=*/ 101u, /*gen=*/ 1u, &ad,
                                        ct, ct_len,
                                        pt_back, sizeof pt_back, &pl);
    STM_ASSERT_ERR(s, STM_EBADTAG);
}

STM_TEST(extent_nonce_gen_tamper_rejects) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_ad_extent ad = make_ad();
    const uint8_t plaintext[32] = { 0 };
    uint8_t ct[sizeof plaintext + STM_AEAD_TAG_LEN_MAX] = { 0 };
    size_t  ct_len = 0;
    STM_ASSERT_OK(stm_extent_encrypt(STM_AEAD_AEGIS256, KEY_AEGIS,
                                       /*paddr=*/ 5u, /*gen=*/ 10u, &ad,
                                       plaintext, sizeof plaintext,
                                       ct, sizeof ct, &ct_len));
    uint8_t pt_back[sizeof plaintext]; size_t pl = 0;
    stm_status s = stm_extent_decrypt(STM_AEAD_AEGIS256, KEY_AEGIS,
                                        /*paddr=*/ 5u, /*gen=*/ 11u, &ad,
                                        ct, ct_len,
                                        pt_back, sizeof pt_back, &pl);
    STM_ASSERT_ERR(s, STM_EBADTAG);
}

/* Tag tamper — flip a byte in the trailing tag; decrypt fails. */
STM_TEST(extent_tag_tamper_rejects) {
    STM_ASSERT_OK(stm_crypto_init());
    stm_ad_extent ad = make_ad();
    const uint8_t plaintext[32] = { 0 };
    uint8_t ct[sizeof plaintext + STM_AEAD_TAG_LEN_MAX] = { 0 };
    size_t  ct_len = 0;
    STM_ASSERT_OK(stm_extent_encrypt(STM_AEAD_AEGIS256, KEY_AEGIS,
                                       1u, 1u, &ad,
                                       plaintext, sizeof plaintext,
                                       ct, sizeof ct, &ct_len));
    ct[ct_len - 1] ^= 0x01;
    uint8_t pt_back[sizeof plaintext]; size_t pl = 0;
    stm_status s = stm_extent_decrypt(STM_AEAD_AEGIS256, KEY_AEGIS,
                                        1u, 1u, &ad,
                                        ct, ct_len,
                                        pt_back, sizeof pt_back, &pl);
    STM_ASSERT_ERR(s, STM_EBADTAG);
}

/* AD packed size pinned by ARCH §7.6.1. */
STM_TEST(extent_ad_packed_size_matches_arch) {
    STM_ASSERT_EQ((int)STM_AD_EXTENT_PACKED_LEN, 56);
}

STM_TEST_MAIN("extent")
