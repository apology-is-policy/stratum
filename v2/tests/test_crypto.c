/* SPDX-License-Identifier: ISC */
/*
 * AEAD, HKDF, Argon2, X25519, random — correctness tests.
 *
 * No classical KAT vectors are committed for AEAD (AEGIS-256 has libsodium's
 * own self-test; XChaCha20-SIV is a Stratum v2 construction). Instead we
 * verify the SIV / AEAD properties directly: determinism, tamper detection,
 * key separation, nonce-misuse behavior.
 */
#include "tharness.h"
#include <stratum/crypto.h>

#include <stdlib.h>
#include <string.h>

static void init_once(void)
{
    static bool done = false;
    if (!done) { STM_ASSERT_OK(stm_crypto_init()); done = true; }
}

/* ------------------------------------------------------------------------- */
/* AEGIS-256.                                                                 */
/* ------------------------------------------------------------------------- */

STM_TEST(aegis256_roundtrip) {
    init_once();
    uint8_t key[32], nonce[32], ad[16], pt[1000];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(ad, sizeof ad);
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_AEGIS256, key, nonce,
                                   ad, sizeof ad, pt, sizeof pt,
                                   ct, &clen));
    STM_ASSERT_EQ(clen, sizeof pt + stm_aead_tag_len(STM_AEAD_AEGIS256));

    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_OK(stm_aead_decrypt(STM_AEAD_AEGIS256, key, nonce,
                                   ad, sizeof ad, ct, clen,
                                   rec, &plen));
    STM_ASSERT_EQ(plen, sizeof pt);
    STM_ASSERT_MEM_EQ(rec, pt, sizeof pt);
}

STM_TEST(aegis256_tamper_ct_fails) {
    init_once();
    uint8_t key[32], nonce[32], pt[100];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_AEGIS256, key, nonce,
                                   NULL, 0, pt, sizeof pt, ct, &clen));

    ct[10] ^= 1;
    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_ERR(stm_aead_decrypt(STM_AEAD_AEGIS256, key, nonce,
                                    NULL, 0, ct, clen, rec, &plen),
                   STM_EBADTAG);
}

STM_TEST(aegis256_tamper_ad_fails) {
    init_once();
    uint8_t key[32], nonce[32], ad[16], pt[100];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(ad, sizeof ad);
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_AEGIS256, key, nonce,
                                   ad, sizeof ad, pt, sizeof pt, ct, &clen));

    ad[0] ^= 1;
    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_ERR(stm_aead_decrypt(STM_AEAD_AEGIS256, key, nonce,
                                    ad, sizeof ad, ct, clen, rec, &plen),
                   STM_EBADTAG);
}

STM_TEST(aegis256_wrong_nonce_fails) {
    init_once();
    uint8_t key[32], nonce[32], nonce2[32], pt[100];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    memcpy(nonce2, nonce, sizeof nonce);
    nonce2[0] ^= 1;
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_AEGIS256, key, nonce,
                                   NULL, 0, pt, sizeof pt, ct, &clen));

    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_ERR(stm_aead_decrypt(STM_AEAD_AEGIS256, key, nonce2,
                                    NULL, 0, ct, clen, rec, &plen),
                   STM_EBADTAG);
}

/* ------------------------------------------------------------------------- */
/* XChaCha20-SIV.                                                             */
/* ------------------------------------------------------------------------- */

STM_TEST(xchacha20siv_roundtrip) {
    init_once();
    uint8_t key[64], nonce[32], ad[32], pt[500];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(ad, sizeof ad);
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   ad, sizeof ad, pt, sizeof pt, ct, &clen));
    STM_ASSERT_EQ(clen, sizeof pt + stm_aead_tag_len(STM_AEAD_XCHACHA20_SIV));

    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_OK(stm_aead_decrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   ad, sizeof ad, ct, clen, rec, &plen));
    STM_ASSERT_EQ(plen, sizeof pt);
    STM_ASSERT_MEM_EQ(rec, pt, sizeof pt);
}

STM_TEST(xchacha20siv_deterministic) {
    /* SIV property: same (key, nonce, AD, PT) -> same (tag, CT). */
    init_once();
    uint8_t key[64], nonce[32], pt[64];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct1[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    uint8_t ct2[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t l1 = 0, l2 = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, pt, sizeof pt, ct1, &l1));
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, pt, sizeof pt, ct2, &l2));
    STM_ASSERT_EQ(l1, l2);
    STM_ASSERT_MEM_EQ(ct1, ct2, l1);
}

STM_TEST(xchacha20siv_nonce_misuse_differs_on_different_pt) {
    /* Under identical (key, nonce), differing plaintexts produce differing
     * (tag, ciphertext). No CPA break. */
    init_once();
    uint8_t key[64], nonce[32];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);

    uint8_t pt1[64] = { 0 };
    uint8_t pt2[64] = { 0 };
    pt2[5] = 1;

    uint8_t ct1[64 + STM_AEAD_TAG_LEN_MAX];
    uint8_t ct2[64 + STM_AEAD_TAG_LEN_MAX];
    size_t l1 = 0, l2 = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, pt1, sizeof pt1, ct1, &l1));
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, pt2, sizeof pt2, ct2, &l2));
    STM_ASSERT_MEM_NE(ct1, ct2, l1);
}

STM_TEST(xchacha20siv_tamper_ct_fails) {
    init_once();
    uint8_t key[64], nonce[32], pt[100];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, pt, sizeof pt, ct, &clen));

    ct[50] ^= 1;
    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_ERR(stm_aead_decrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                    NULL, 0, ct, clen, rec, &plen),
                   STM_EBADTAG);
}

STM_TEST(xchacha20siv_tamper_tag_fails) {
    init_once();
    uint8_t key[64], nonce[32], pt[100];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);
    stm_random_bytes(pt, sizeof pt);

    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, pt, sizeof pt, ct, &clen));

    ct[0] ^= 1;                 /* flip a bit of tag */
    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_ERR(stm_aead_decrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                    NULL, 0, ct, clen, rec, &plen),
                   STM_EBADTAG);
}

STM_TEST(xchacha20siv_empty_plaintext) {
    init_once();
    uint8_t key[64], nonce[32];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);

    uint8_t ct[STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, NULL, 0, ct, &clen));
    STM_ASSERT_EQ(clen, stm_aead_tag_len(STM_AEAD_XCHACHA20_SIV));

    size_t plen = 42;
    STM_ASSERT_OK(stm_aead_decrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, ct, clen, NULL, &plen));
    STM_ASSERT_EQ(plen, 0);
}

/* ------------------------------------------------------------------------- */
/* HKDF-SHA256 (RFC 5869 test vectors, case 1).                               */
/* ------------------------------------------------------------------------- */

STM_TEST(hkdf_sha256_rfc5869_case1) {
    init_once();
    /* Test Case 1: SHA-256, 22-byte IKM, 13-byte salt, 10-byte info. */
    const uint8_t ikm[] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b };
    const uint8_t salt[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,
        0x0a,0x0b,0x0c };
    const uint8_t info[] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9 };
    const uint8_t expected_prk[32] = {
        0x07,0x77,0x09,0x36,0x2c,0x2e,0x32,0xdf,0x0d,0xdc,
        0x3f,0x0d,0xc4,0x7b,0xba,0x63,0x90,0xb6,0xc7,0x3b,
        0xb5,0x0f,0x9c,0x31,0x22,0xec,0x84,0x4a,0xd7,0xc2,
        0xb3,0xe5 };
    const uint8_t expected_okm[42] = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,
        0x4f,0x64,0xd0,0x36,0x2f,0x2a,0x2d,0x2d,0x0a,0x90,
        0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,
        0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,
        0x58,0x65 };

    uint8_t prk[32];
    stm_hkdf_sha256_extract(salt, sizeof salt, ikm, sizeof ikm, prk);
    STM_ASSERT_MEM_EQ(prk, expected_prk, 32);

    uint8_t okm[42];
    STM_ASSERT_OK(stm_hkdf_sha256_expand(prk, info, sizeof info, okm, sizeof okm));
    STM_ASSERT_MEM_EQ(okm, expected_okm, 42);
}

/* ------------------------------------------------------------------------- */
/* Argon2id.                                                                  */
/* ------------------------------------------------------------------------- */

STM_TEST(argon2id_deterministic) {
    init_once();
    uint8_t salt[16];
    memset(salt, 0x42, sizeof salt);
    stm_argon2id_params p = stm_argon2id_params_interactive(salt);
    /* Shorten for test speed: use smaller memlimit. */
    p.m_cost_kib = 8192;
    p.t_cost     = 1;

    const char *pw = "correct horse battery staple";
    uint8_t h1[32], h2[32];
    STM_ASSERT_OK(stm_argon2id(&p, pw, strlen(pw), h1, sizeof h1));
    STM_ASSERT_OK(stm_argon2id(&p, pw, strlen(pw), h2, sizeof h2));
    STM_ASSERT_MEM_EQ(h1, h2, sizeof h1);
}

STM_TEST(argon2id_different_salt_differs) {
    init_once();
    uint8_t salt1[16] = { 0 }, salt2[16] = { 1 };
    stm_argon2id_params p1 = stm_argon2id_params_interactive(salt1);
    stm_argon2id_params p2 = stm_argon2id_params_interactive(salt2);
    p1.m_cost_kib = 8192; p1.t_cost = 1;
    p2.m_cost_kib = 8192; p2.t_cost = 1;

    uint8_t h1[32], h2[32];
    const char *pw = "samepass";
    STM_ASSERT_OK(stm_argon2id(&p1, pw, strlen(pw), h1, sizeof h1));
    STM_ASSERT_OK(stm_argon2id(&p2, pw, strlen(pw), h2, sizeof h2));
    STM_ASSERT_MEM_NE(h1, h2, sizeof h1);
}

/* ------------------------------------------------------------------------- */
/* X25519.                                                                    */
/* ------------------------------------------------------------------------- */

STM_TEST(x25519_dh_agreement) {
    init_once();
    uint8_t pk_a[32], sk_a[32];
    uint8_t pk_b[32], sk_b[32];
    stm_x25519_keygen(pk_a, sk_a);
    stm_x25519_keygen(pk_b, sk_b);

    uint8_t ss_ab[32], ss_ba[32];
    STM_ASSERT_OK(stm_x25519_dh(sk_a, pk_b, ss_ab));
    STM_ASSERT_OK(stm_x25519_dh(sk_b, pk_a, ss_ba));
    STM_ASSERT_MEM_EQ(ss_ab, ss_ba, 32);
}

/* ------------------------------------------------------------------------- */
/* random + ct helpers.                                                       */
/* ------------------------------------------------------------------------- */

STM_TEST(random_bytes_nonzero) {
    init_once();
    uint8_t a[64] = { 0 }, b[64] = { 0 };
    stm_random_bytes(a, sizeof a);
    stm_random_bytes(b, sizeof b);
    STM_ASSERT_MEM_NE(a, b, sizeof a);
}

STM_TEST(ct_equal_basics) {
    uint8_t a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t b[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    STM_ASSERT_TRUE(stm_ct_equal(a, b, 8));
    b[4] ^= 1;
    STM_ASSERT_FALSE(stm_ct_equal(a, b, 8));
}

STM_TEST(ct_memzero_clears) {
    uint8_t a[16];
    memset(a, 0xAB, sizeof a);
    stm_ct_memzero(a, sizeof a);
    uint8_t zero[16] = { 0 };
    STM_ASSERT_MEM_EQ(a, zero, 16);
}

/* -------------------------------------------------------------------------
 * Audit-driven regression tests (R0 findings).
 * -------------------------------------------------------------------------
 */

/* Regression for R0-P2-6 + strengthened MAC: N[24:32] is part of the MAC
 * input, so two encryptions that differ only in N[24:32] must produce
 * differing tags (and differing ciphertexts). */
STM_TEST(xchacha20siv_nonce_high_bytes_affect_tag) {
    init_once();
    uint8_t key[64];
    stm_random_bytes(key, sizeof key);

    uint8_t n1[32] = { 0 };
    uint8_t n2[32] = { 0 };
    /* Identical first 24 bytes. */
    stm_random_bytes(n1, 24);
    memcpy(n2, n1, 24);
    /* Differ only in N[24..32]. */
    n2[24] = 1;

    const char pt[] = "same plaintext";
    uint8_t ct1[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    uint8_t ct2[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t l1 = 0, l2 = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, n1,
                                   NULL, 0, pt, sizeof pt, ct1, &l1));
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, n2,
                                   NULL, 0, pt, sizeof pt, ct2, &l2));
    /* Tag (first 16 bytes) must differ — N[24..32] is part of MAC input. */
    STM_ASSERT_MEM_NE(ct1, ct2, 16);
}

/* Regression for R0-P2-1: on a forced XChaCha20 failure the caller's buffer
 * must be untouched. libsodium's XChaCha20 doesn't fail on any sane inputs,
 * so we can only test the positive path here: verify a successful encrypt
 * writes exactly the expected ciphertext + tag length. */
STM_TEST(xchacha20siv_success_writes_tag_and_ct_contiguous) {
    init_once();
    uint8_t key[64], nonce[32];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);

    uint8_t canary = 0xA5;
    uint8_t buf[128 + STM_AEAD_TAG_LEN_MAX + 16];
    memset(buf, canary, sizeof buf);

    const char pt[128] = "foo";
    size_t outlen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   NULL, 0, pt, sizeof pt,
                                   buf, &outlen));
    STM_ASSERT_EQ(outlen, sizeof pt + stm_aead_tag_len(STM_AEAD_XCHACHA20_SIV));
    /* Trailing canary bytes must be untouched. */
    for (size_t i = outlen; i < sizeof buf; i++) {
        STM_ASSERT_EQ(buf[i], canary);
    }
}

/* Regression for R0-P1-4: wrap under a pk whose ML-KEM half is all zero
 * (classical-only origin) must round-trip. */
STM_TEST(hybrid_wrap_zero_mlkem_pk_roundtrips) {
    init_once();

    uint8_t pk[STM_HYBRID_PK_LEN];
    uint8_t sk[STM_HYBRID_SK_LEN];
    stm_x25519_keygen(pk, sk);
    /* Zero both ML-KEM halves, emulating a pool created without liboqs. */
    memset(pk + STM_X25519_PK_LEN, 0, STM_MLKEM768_PK_LEN);
    memset(sk + STM_X25519_SK_LEN, 0, STM_MLKEM768_SK_LEN);

    uint8_t dek[32];
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

/* Regression for R0-P1-2: length serialization in MAC must handle inputs
 * that would need a 64-bit shift on 32-bit platforms. Direct test is
 * impossible (we're not on a 32-bit platform), but we can verify that the
 * encrypt/decrypt path handles a modest AD length correctly via roundtrip. */
STM_TEST(xchacha20siv_roundtrip_with_long_ad) {
    init_once();
    uint8_t key[64], nonce[32];
    stm_random_bytes(key, sizeof key);
    stm_random_bytes(nonce, sizeof nonce);

    size_t ad_len = 1 << 16;   /* 64 KiB AD */
    uint8_t *ad = malloc(ad_len);
    STM_ASSERT(ad != NULL);
    stm_prop_seed(0xdead);
    stm_prop_fill(ad, ad_len);

    const uint8_t pt[64] = { 1, 2, 3 };
    uint8_t ct[sizeof pt + STM_AEAD_TAG_LEN_MAX];
    size_t clen = 0;
    STM_ASSERT_OK(stm_aead_encrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   ad, ad_len, pt, sizeof pt, ct, &clen));

    uint8_t rec[sizeof pt];
    size_t plen = 0;
    STM_ASSERT_OK(stm_aead_decrypt(STM_AEAD_XCHACHA20_SIV, key, nonce,
                                   ad, ad_len, ct, clen, rec, &plen));
    STM_ASSERT_EQ(plen, sizeof pt);
    STM_ASSERT_MEM_EQ(rec, pt, sizeof pt);

    free(ad);
}

STM_TEST_MAIN("crypto")
