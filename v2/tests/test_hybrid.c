/* SPDX-License-Identifier: ISC */
/*
 * PQ-hybrid wrap tests. When liboqs is absent these tests still exercise the
 * classical (X25519-only) path — that's the degraded-but-functional mode.
 */
#include "tharness.h"
#include <stratum/crypto.h>

#include <string.h>

STM_TEST(hybrid_roundtrip_small) {
    STM_ASSERT_OK(stm_crypto_init());

    uint8_t pk[STM_HYBRID_PK_LEN];
    uint8_t sk[STM_HYBRID_SK_LEN];
    STM_ASSERT_OK(stm_hybrid_keygen(pk, sk));

    uint8_t dek[32];
    stm_random_bytes(dek, sizeof dek);

    uint8_t wrapped[sizeof dek + STM_HYBRID_WRAP_OVERHEAD];
    size_t wlen = 0;
    STM_ASSERT_OK(stm_hybrid_wrap(pk, dek, sizeof dek, wrapped, &wlen));
    STM_ASSERT_EQ(wlen, sizeof dek + STM_HYBRID_WRAP_OVERHEAD);

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_OK(stm_hybrid_unwrap(sk, wrapped, wlen, out, &olen));
    STM_ASSERT_EQ(olen, sizeof dek);
    STM_ASSERT_MEM_EQ(out, dek, sizeof dek);
}

STM_TEST(hybrid_roundtrip_large) {
    STM_ASSERT_OK(stm_crypto_init());

    uint8_t pk[STM_HYBRID_PK_LEN];
    uint8_t sk[STM_HYBRID_SK_LEN];
    STM_ASSERT_OK(stm_hybrid_keygen(pk, sk));

    /* 64-byte DEK for XChaCha20-SIV. */
    uint8_t dek[64];
    stm_random_bytes(dek, sizeof dek);

    uint8_t wrapped[sizeof dek + STM_HYBRID_WRAP_OVERHEAD];
    size_t wlen = 0;
    STM_ASSERT_OK(stm_hybrid_wrap(pk, dek, sizeof dek, wrapped, &wlen));

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_OK(stm_hybrid_unwrap(sk, wrapped, wlen, out, &olen));
    STM_ASSERT_EQ(olen, sizeof dek);
    STM_ASSERT_MEM_EQ(out, dek, sizeof dek);
}

STM_TEST(hybrid_tamper_ct_fails) {
    STM_ASSERT_OK(stm_crypto_init());

    uint8_t pk[STM_HYBRID_PK_LEN], sk[STM_HYBRID_SK_LEN];
    STM_ASSERT_OK(stm_hybrid_keygen(pk, sk));

    uint8_t dek[32];
    stm_random_bytes(dek, sizeof dek);

    uint8_t wrapped[sizeof dek + STM_HYBRID_WRAP_OVERHEAD];
    size_t wlen = 0;
    STM_ASSERT_OK(stm_hybrid_wrap(pk, dek, sizeof dek, wrapped, &wlen));

    /* Flip a byte in the encrypted payload region. */
    wrapped[wlen - 5] ^= 1;

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_ERR(stm_hybrid_unwrap(sk, wrapped, wlen, out, &olen),
                   STM_EBADTAG);
}

STM_TEST(hybrid_wrong_sk_fails) {
    STM_ASSERT_OK(stm_crypto_init());

    uint8_t pk_a[STM_HYBRID_PK_LEN], sk_a[STM_HYBRID_SK_LEN];
    uint8_t pk_b[STM_HYBRID_PK_LEN], sk_b[STM_HYBRID_SK_LEN];
    STM_ASSERT_OK(stm_hybrid_keygen(pk_a, sk_a));
    STM_ASSERT_OK(stm_hybrid_keygen(pk_b, sk_b));

    uint8_t dek[32];
    stm_random_bytes(dek, sizeof dek);

    uint8_t wrapped[sizeof dek + STM_HYBRID_WRAP_OVERHEAD];
    size_t wlen = 0;
    STM_ASSERT_OK(stm_hybrid_wrap(pk_a, dek, sizeof dek, wrapped, &wlen));

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_ERR(stm_hybrid_unwrap(sk_b, wrapped, wlen, out, &olen),
                   STM_EBADTAG);
}

STM_TEST(hybrid_wraps_differ_randomness) {
    /* Same inputs, two wraps — should produce different blobs (ephemeral key
     * + random nonce). */
    STM_ASSERT_OK(stm_crypto_init());

    uint8_t pk[STM_HYBRID_PK_LEN], sk[STM_HYBRID_SK_LEN];
    STM_ASSERT_OK(stm_hybrid_keygen(pk, sk));

    uint8_t dek[32];
    stm_random_bytes(dek, sizeof dek);

    uint8_t w1[sizeof dek + STM_HYBRID_WRAP_OVERHEAD];
    uint8_t w2[sizeof dek + STM_HYBRID_WRAP_OVERHEAD];
    size_t l1 = 0, l2 = 0;
    STM_ASSERT_OK(stm_hybrid_wrap(pk, dek, sizeof dek, w1, &l1));
    STM_ASSERT_OK(stm_hybrid_wrap(pk, dek, sizeof dek, w2, &l2));
    STM_ASSERT_MEM_NE(w1, w2, l1);
}

STM_TEST_MAIN("hybrid")
