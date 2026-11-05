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
    STM_ASSERT_OK(stm_hybrid_wrap(pk, NULL, 0, dek, sizeof dek, wrapped, &wlen));
    STM_ASSERT_EQ(wlen, sizeof dek + STM_HYBRID_WRAP_OVERHEAD);

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_OK(stm_hybrid_unwrap(sk, NULL, 0, wrapped, wlen, out, &olen));
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
    STM_ASSERT_OK(stm_hybrid_wrap(pk, NULL, 0, dek, sizeof dek, wrapped, &wlen));

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_OK(stm_hybrid_unwrap(sk, NULL, 0, wrapped, wlen, out, &olen));
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
    STM_ASSERT_OK(stm_hybrid_wrap(pk, NULL, 0, dek, sizeof dek, wrapped, &wlen));

    /* Flip a byte in the encrypted payload region. */
    wrapped[wlen - 5] ^= 1;

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_ERR(stm_hybrid_unwrap(sk, NULL, 0, wrapped, wlen, out, &olen),
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
    STM_ASSERT_OK(stm_hybrid_wrap(pk_a, NULL, 0, dek, sizeof dek, wrapped, &wlen));

    uint8_t out[sizeof dek];
    size_t olen = 0;
    STM_ASSERT_ERR(stm_hybrid_unwrap(sk_b, NULL, 0, wrapped, wlen, out, &olen),
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
    STM_ASSERT_OK(stm_hybrid_wrap(pk, NULL, 0, dek, sizeof dek, w1, &l1));
    STM_ASSERT_OK(stm_hybrid_wrap(pk, NULL, 0, dek, sizeof dek, w2, &l2));
    STM_ASSERT_MEM_NE(w1, w2, l1);
}

/* R10 P2-2: AD binding — wrap with one AD, unwrap with another
 * must fail the Poly1305 tag. */
STM_TEST(hybrid_ad_mismatch_fails) {
    STM_ASSERT_OK(stm_crypto_init());

    uint8_t pk[STM_HYBRID_PK_LEN], sk[STM_HYBRID_SK_LEN];
    STM_ASSERT_OK(stm_hybrid_keygen(pk, sk));

    uint8_t dek[32];
    stm_random_bytes(dek, sizeof dek);

    const uint8_t ad_wrap[16]   = "stratum-pool-AA";
    const uint8_t ad_unwrap[16] = "stratum-pool-BB";

    uint8_t wrapped[sizeof dek + STM_HYBRID_WRAP_OVERHEAD];
    size_t wlen = 0;
    STM_ASSERT_OK(stm_hybrid_wrap(pk, ad_wrap, sizeof ad_wrap,
                                     dek, sizeof dek, wrapped, &wlen));

    uint8_t out[sizeof dek];
    size_t olen = 0;

    /* Matching AD → OK. */
    STM_ASSERT_OK(stm_hybrid_unwrap(sk, ad_wrap, sizeof ad_wrap,
                                       wrapped, wlen, out, &olen));
    STM_ASSERT_MEM_EQ(out, dek, sizeof dek);

    /* Mismatched AD → STM_EBADTAG. */
    STM_ASSERT_ERR(stm_hybrid_unwrap(sk, ad_unwrap, sizeof ad_unwrap,
                                        wrapped, wlen, out, &olen),
                   STM_EBADTAG);

    /* Omitted AD → also STM_EBADTAG (ad_len=0 != 16 at wrap time). */
    STM_ASSERT_ERR(stm_hybrid_unwrap(sk, NULL, 0,
                                        wrapped, wlen, out, &olen),
                   STM_EBADTAG);
}

STM_TEST_MAIN("hybrid")
