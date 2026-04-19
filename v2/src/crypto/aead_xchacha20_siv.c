/* SPDX-License-Identifier: ISC */
/*
 * XChaCha20-Poly1305-SIV — Stratum v2 nonce-misuse-resistant AEAD.
 *
 * Construction (deterministic, not a published RFC; see ARCHITECTURE §7.5.2
 * and the design note at the bottom of this file):
 *
 *   Key K (64 bytes) is split as K_MAC || K_ENC, 32 bytes each.
 *
 *   Encrypt(K, N_32, AD, PT):
 *       mac_input = N_32[0:24]
 *                || le64(|AD|) || AD
 *                || le64(|PT|) || PT
 *       V         = HMAC-SHA256(K_MAC, mac_input)     -- 32 bytes
 *       TAG       = V[0:16]                            -- on-disk tag (16 bytes)
 *       xnonce24  = TAG || N_32[24:32]                 -- 24-byte XChaCha20 nonce
 *       CT        = XChaCha20(K_ENC, xnonce24, PT)
 *       return TAG || CT
 *
 *   Decrypt(K, N_32, AD, TAG || CT):
 *       xnonce24  = TAG || N_32[24:32]
 *       PT        = XChaCha20(K_ENC, xnonce24, CT)
 *       V'        = HMAC-SHA256(K_MAC, N_32[0:24] ||
 *                                     le64(|AD|) || AD ||
 *                                     le64(|PT|) || PT)
 *       if not ct_equal(TAG, V'[0:16]): reject
 *       return PT
 *
 * Security properties:
 *
 *   - With unique (N_32, AD, PT): TAG is a cryptographic MAC under HMAC-SHA256.
 *     XChaCha20 encrypts with a unique-per-call 24-byte nonce (TAG is
 *     effectively PRF(K_MAC, ...)), so no CPA weakness.
 *
 *   - With repeated (N_32, AD, PT): SIV property — attacker learns only that
 *     two plaintexts are equal under the same AD + nonce. No CPA-break.
 *
 *   - With repeated N_32 but differing PT: different TAG → different xnonce →
 *     different CT; no cross-plaintext leakage.
 *
 *   - AD binding: AD is part of the MAC input, so any AD tamper fails the tag
 *     check.
 *
 *   - N_32's last 8 bytes are mixed into xnonce (pool UUID bits per
 *     ARCHITECTURE §7.4.1), giving additional domain separation across pools.
 *
 * This is implemented atop libsodium primitives only (HMAC-SHA256 via
 * `crypto_auth_hmacsha256` and XChaCha20 via `crypto_stream_xchacha20_xor`);
 * no raw crypto is written here.
 */
#include "aead_internal.h"

#include <sodium.h>
#include <string.h>
#include <stdlib.h>

STM_STATIC_ASSERT(crypto_auth_hmacsha256_BYTES >= 16, "HMAC too small for SIV tag");
STM_STATIC_ASSERT(crypto_stream_xchacha20_NONCEBYTES == 24, "XChaCha20 nonce len");

/*
 * Compute V = HMAC-SHA256(K_MAC, N24 || le64(|AD|) || AD || le64(|PT|) || PT).
 * Writes 32 bytes to `out_v`.
 */
static stm_status compute_mac(const uint8_t k_mac[32],
                              const uint8_t n24[24],
                              const void *ad, size_t ad_len,
                              const void *pt, size_t pt_len,
                              uint8_t out_v[32])
{
    crypto_auth_hmacsha256_state st;
    if (crypto_auth_hmacsha256_init(&st, k_mac, 32) != 0) return STM_EBACKEND;

    /* Feed N (24 bytes). */
    if (crypto_auth_hmacsha256_update(&st, n24, 24) != 0) return STM_EBACKEND;

    /* Feed le64(|AD|) || AD. */
    uint8_t lenbuf[8];
    for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(ad_len >> (8 * i));
    if (crypto_auth_hmacsha256_update(&st, lenbuf, 8) != 0) return STM_EBACKEND;
    if (ad_len > 0 && crypto_auth_hmacsha256_update(&st, ad, ad_len) != 0) return STM_EBACKEND;

    /* Feed le64(|PT|) || PT. */
    for (int i = 0; i < 8; i++) lenbuf[i] = (uint8_t)(pt_len >> (8 * i));
    if (crypto_auth_hmacsha256_update(&st, lenbuf, 8) != 0) return STM_EBACKEND;
    if (pt_len > 0 && crypto_auth_hmacsha256_update(&st, pt, pt_len) != 0) return STM_EBACKEND;

    if (crypto_auth_hmacsha256_final(&st, out_v) != 0) return STM_EBACKEND;
    return STM_OK;
}

stm_status stm_xchacha20_siv_encrypt(const uint8_t key[64],
                                     const uint8_t nonce[32],
                                     const void *ad, size_t ad_len,
                                     const void *pt, size_t pt_len,
                                     void *ct_and_tag, size_t *out_len)
{
    const uint8_t *k_mac = key;
    const uint8_t *k_enc = key + 32;

    uint8_t V[32];
    stm_status s = compute_mac(k_mac, nonce, ad, ad_len, pt, pt_len, V);
    if (s != STM_OK) { stm_ct_memzero(V, sizeof V); return s; }

    /* TAG = V[0:16]. xnonce = TAG || nonce[24:32]. */
    uint8_t xnonce[24];
    memcpy(xnonce, V, 16);
    memcpy(xnonce + 16, nonce + 24, 8);

    uint8_t *out = (uint8_t *)ct_and_tag;
    memcpy(out, V, 16);                            /* tag */

    /* XChaCha20 encrypt plaintext into out+16. */
    if (crypto_stream_xchacha20_xor(out + 16,
                                    (const unsigned char *)pt,
                                    (unsigned long long)pt_len,
                                    xnonce, k_enc) != 0)
    {
        stm_ct_memzero(V, sizeof V);
        stm_ct_memzero(xnonce, sizeof xnonce);
        return STM_EBACKEND;
    }

    if (out_len) *out_len = pt_len + 16;

    stm_ct_memzero(V, sizeof V);
    stm_ct_memzero(xnonce, sizeof xnonce);
    return STM_OK;
}

stm_status stm_xchacha20_siv_decrypt(const uint8_t key[64],
                                     const uint8_t nonce[32],
                                     const void *ad, size_t ad_len,
                                     const void *ct_and_tag, size_t ct_and_tag_len,
                                     void *pt, size_t *out_pt_len)
{
    if (ct_and_tag_len < 16) return STM_EINVAL;

    const uint8_t *k_mac = key;
    const uint8_t *k_enc = key + 32;

    const uint8_t *in  = (const uint8_t *)ct_and_tag;
    const uint8_t *tag = in;
    const uint8_t *ct  = in + 16;
    size_t ct_len      = ct_and_tag_len - 16;

    uint8_t xnonce[24];
    memcpy(xnonce, tag, 16);
    memcpy(xnonce + 16, nonce + 24, 8);

    /*
     * Decrypt into a scratch buffer so we don't leave partial plaintext in the
     * caller's output if tag verification later fails. Stack-allocate for
     * small payloads, heap for large.
     */
    enum { SCRATCH_STACK = 4096 };
    uint8_t  stack_buf[SCRATCH_STACK];
    uint8_t *buf = (ct_len <= SCRATCH_STACK) ? stack_buf : malloc(ct_len);
    if (!buf) {
        stm_ct_memzero(xnonce, sizeof xnonce);
        return STM_ENOMEM;
    }

    if (crypto_stream_xchacha20_xor(buf, ct, (unsigned long long)ct_len,
                                    xnonce, k_enc) != 0)
    {
        if (buf != stack_buf) free(buf);
        stm_ct_memzero(xnonce, sizeof xnonce);
        return STM_EBACKEND;
    }

    uint8_t V_prime[32];
    stm_status s = compute_mac(k_mac, nonce, ad, ad_len, buf, ct_len, V_prime);
    if (s != STM_OK) {
        stm_ct_memzero(buf, ct_len);
        if (buf != stack_buf) free(buf);
        stm_ct_memzero(xnonce, sizeof xnonce);
        return s;
    }

    if (!stm_ct_equal(V_prime, tag, 16)) {
        stm_ct_memzero(buf, ct_len);
        stm_ct_memzero(V_prime, sizeof V_prime);
        if (buf != stack_buf) free(buf);
        stm_ct_memzero(xnonce, sizeof xnonce);
        return STM_EBADTAG;
    }

    memcpy(pt, buf, ct_len);
    if (out_pt_len) *out_pt_len = ct_len;

    stm_ct_memzero(buf, ct_len);
    stm_ct_memzero(V_prime, sizeof V_prime);
    stm_ct_memzero(xnonce, sizeof xnonce);
    if (buf != stack_buf) free(buf);
    return STM_OK;
}
