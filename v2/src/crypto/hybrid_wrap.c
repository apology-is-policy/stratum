/* SPDX-License-Identifier: ISC */
/*
 * PQ-hybrid key wrap: X25519 + ML-KEM-768, HPKE-style (§7.3.4).
 *
 * Wire format of `wrapped`:
 *
 *   [0 .. 32)    ephemeral X25519 public key
 *   [32 .. 1120) ML-KEM-768 ciphertext
 *   [1120 .. 1144) wrap nonce (24 bytes; random per wrap, carried for
 *                  XChaCha20-Poly1305 decrypt)
 *   [1144 .. ]   XChaCha20-Poly1305(shared_key, nonce) of dek || 16-byte tag
 *
 * Shared-secret derivation (both wrap and unwrap):
 *
 *   ss1 = X25519(ephem_sk, peer_x25519_pk)            32 bytes
 *   ss2 = ML-KEM-768.{encap,decap}(peer_mlkem_pk)     32 bytes
 *   K   = HKDF-SHA256(salt=ephem_pk||mlkem_ct,
 *                     ikm=ss1||ss2,
 *                     info="stratum-wrap-v1",
 *                     okm_len=32)                     32 bytes XChaCha20-P1305 key
 *
 * If liboqs is absent, wrap still runs in X25519-only mode (mlkem_ct section
 * is 1088 zero bytes, ss2 is 32 zero bytes). The wire layout is unchanged so
 * a PQ-capable build can still read a classical-only pool after adoption.
 * At mount time, if the wrapped blob's mlkem_ct is all zero, the reader
 * infers classical-only and skips decap.
 */
#include <stratum/crypto.h>

#include <sodium.h>
#include <string.h>

#define WRAP_NONCE_LEN        24  /* XChaCha20-Poly1305 nonce length */
#define WRAP_INFO_STR         "stratum-wrap-v1"

static stm_status derive_shared_key(const uint8_t ephem_x25519_pk[32],
                                    const uint8_t mlkem_ct[STM_MLKEM768_CT_LEN],
                                    const uint8_t ss1[32],
                                    const uint8_t ss2[32],
                                    uint8_t out_k[32])
{
    /* salt = ephem_pk || mlkem_ct (length 32 + 1088 = 1120). */
    uint8_t salt[32 + STM_MLKEM768_CT_LEN];
    memcpy(salt, ephem_x25519_pk, 32);
    memcpy(salt + 32, mlkem_ct, STM_MLKEM768_CT_LEN);

    /* ikm = ss1 || ss2. */
    uint8_t ikm[64];
    memcpy(ikm, ss1, 32);
    memcpy(ikm + 32, ss2, 32);

    stm_status s = stm_hkdf_sha256(salt, sizeof salt,
                                   ikm, sizeof ikm,
                                   (const uint8_t *)WRAP_INFO_STR,
                                   sizeof WRAP_INFO_STR - 1,
                                   out_k, 32);
    stm_ct_memzero(ikm, sizeof ikm);
    stm_ct_memzero(salt, sizeof salt);
    return s;
}

stm_status stm_hybrid_keygen(uint8_t pk[STM_HYBRID_PK_LEN],
                             uint8_t sk[STM_HYBRID_SK_LEN])
{
    stm_x25519_keygen(pk, sk);  /* pk[0:32], sk[0:32] */

#if STM_HAVE_LIBOQS
    if (stm_mlkem768_available()) {
        stm_status s = stm_mlkem768_keygen(pk + STM_X25519_PK_LEN,
                                           sk + STM_X25519_SK_LEN);
        if (s != STM_OK) return s;
    } else {
        memset(pk + STM_X25519_PK_LEN, 0, STM_MLKEM768_PK_LEN);
        memset(sk + STM_X25519_SK_LEN, 0, STM_MLKEM768_SK_LEN);
    }
#else
    memset(pk + STM_X25519_PK_LEN, 0, STM_MLKEM768_PK_LEN);
    memset(sk + STM_X25519_SK_LEN, 0, STM_MLKEM768_SK_LEN);
#endif
    return STM_OK;
}

stm_status stm_hybrid_wrap(const uint8_t pk[STM_HYBRID_PK_LEN],
                           const void *dek, size_t dek_len,
                           void *wrapped, size_t *out_len)
{
    if (!pk || !dek || !wrapped || dek_len == 0) return STM_EINVAL;

    size_t total = dek_len + STM_HYBRID_WRAP_OVERHEAD;
    uint8_t *out = (uint8_t *)wrapped;

    /* (1) Generate ephemeral X25519 keypair. */
    uint8_t ephem_pk[32], ephem_sk[32];
    stm_x25519_keygen(ephem_pk, ephem_sk);

    /* (2) ss1 = X25519(ephem_sk, peer_x25519_pk). */
    uint8_t ss1[32];
    stm_status s = stm_x25519_dh(ephem_sk, pk, ss1);
    if (s != STM_OK) {
        stm_ct_memzero(ephem_sk, sizeof ephem_sk);
        stm_ct_memzero(ss1, sizeof ss1);
        return s;
    }

    /*
     * (3) ML-KEM encap — only if BOTH liboqs is available locally AND the
     * peer's ML-KEM public key slot is populated. A keypair generated on a
     * classical-only host has an all-zero ML-KEM half; invoking encap on
     * such a key would pass zero-valued bytes into a ML-KEM implementation
     * that performs no input validation, producing garbage that the decap
     * side (even on PQ-capable hosts) cannot reverse. Detect that here and
     * take the classical fallback path so the wire format stays uniform.
     */
    uint8_t mlkem_ct[STM_MLKEM768_CT_LEN];
    uint8_t ss2[32];
    bool peer_has_mlkem = false;
    {
        const uint8_t *peer_mlkem_pk = pk + STM_X25519_PK_LEN;
        for (size_t i = 0; i < STM_MLKEM768_PK_LEN; i++) {
            if (peer_mlkem_pk[i] != 0) { peer_has_mlkem = true; break; }
        }
    }

    if (stm_mlkem768_available() && peer_has_mlkem) {
        s = stm_mlkem768_encap(pk + STM_X25519_PK_LEN, mlkem_ct, ss2);
        if (s != STM_OK) {
            stm_ct_memzero(ephem_sk, sizeof ephem_sk);
            stm_ct_memzero(ss1, sizeof ss1);
            stm_ct_memzero(ss2, sizeof ss2);
            return s;
        }
    } else {
        memset(mlkem_ct, 0, sizeof mlkem_ct);
        memset(ss2, 0, sizeof ss2);
    }

    /* (4) Derive wrap key. */
    uint8_t wrap_key[32];
    s = derive_shared_key(ephem_pk, mlkem_ct, ss1, ss2, wrap_key);
    stm_ct_memzero(ss1, sizeof ss1);
    stm_ct_memzero(ss2, sizeof ss2);
    stm_ct_memzero(ephem_sk, sizeof ephem_sk);
    if (s != STM_OK) { stm_ct_memzero(wrap_key, sizeof wrap_key); return s; }

    /* (5) Random wrap nonce. */
    uint8_t wrap_nonce[WRAP_NONCE_LEN];
    randombytes_buf(wrap_nonce, WRAP_NONCE_LEN);

    /* (6) Lay out the output. */
    memcpy(out, ephem_pk, 32);
    memcpy(out + 32, mlkem_ct, STM_MLKEM768_CT_LEN);
    memcpy(out + 32 + STM_MLKEM768_CT_LEN, wrap_nonce, WRAP_NONCE_LEN);

    /* (7) XChaCha20-Poly1305 encrypt dek under wrap_key, wrap_nonce. */
    unsigned long long clen = 0;
    int r = crypto_aead_xchacha20poly1305_ietf_encrypt(
        out + 32 + STM_MLKEM768_CT_LEN + WRAP_NONCE_LEN, &clen,
        (const unsigned char *)dek, (unsigned long long)dek_len,
        NULL, 0,        /* no AD */
        NULL,           /* nsec */
        wrap_nonce,
        wrap_key);
    stm_ct_memzero(wrap_key, sizeof wrap_key);
    stm_ct_memzero(wrap_nonce, sizeof wrap_nonce);
    if (r != 0) return STM_EBACKEND;

    if (out_len) *out_len = total;
    return STM_OK;
}

stm_status stm_hybrid_unwrap(const uint8_t sk[STM_HYBRID_SK_LEN],
                             const void *wrapped, size_t wrapped_len,
                             void *dek, size_t *out_dek_len)
{
    if (!sk || !wrapped || !dek) return STM_EINVAL;
    if (wrapped_len < STM_HYBRID_WRAP_OVERHEAD) return STM_EINVAL;

    const uint8_t *in = (const uint8_t *)wrapped;

    const uint8_t *ephem_pk   = in;
    const uint8_t *mlkem_ct   = in + 32;
    const uint8_t *wrap_nonce = in + 32 + STM_MLKEM768_CT_LEN;
    const uint8_t *ct_tag     = in + 32 + STM_MLKEM768_CT_LEN + WRAP_NONCE_LEN;
    size_t ct_tag_len         = wrapped_len - (32 + STM_MLKEM768_CT_LEN + WRAP_NONCE_LEN);

    if (ct_tag_len < 16) return STM_EINVAL;  /* Poly1305 tag on XChaCha20-Poly1305 */

    /* ss1 = X25519(our_x25519_sk, ephem_x25519_pk). */
    uint8_t ss1[32];
    stm_status s = stm_x25519_dh(sk, ephem_pk, ss1);
    if (s != STM_OK) { stm_ct_memzero(ss1, sizeof ss1); return s; }

    /* ss2: decap if we have liboqs AND mlkem_ct is non-zero. */
    uint8_t ss2[32];
    bool mlkem_all_zero = true;
    for (size_t i = 0; i < STM_MLKEM768_CT_LEN; i++) {
        if (mlkem_ct[i] != 0) { mlkem_all_zero = false; break; }
    }
    if (stm_mlkem768_available() && !mlkem_all_zero) {
        s = stm_mlkem768_decap(sk + STM_X25519_SK_LEN, mlkem_ct, ss2);
        if (s != STM_OK) { stm_ct_memzero(ss1, sizeof ss1); return s; }
    } else {
        memset(ss2, 0, sizeof ss2);
    }

    /* Derive wrap key. */
    uint8_t wrap_key[32];
    s = derive_shared_key(ephem_pk, mlkem_ct, ss1, ss2, wrap_key);
    stm_ct_memzero(ss1, sizeof ss1);
    stm_ct_memzero(ss2, sizeof ss2);
    if (s != STM_OK) { stm_ct_memzero(wrap_key, sizeof wrap_key); return s; }

    /* Decrypt. */
    unsigned long long plen = 0;
    int r = crypto_aead_xchacha20poly1305_ietf_decrypt(
        (unsigned char *)dek, &plen,
        NULL,
        ct_tag, (unsigned long long)ct_tag_len,
        NULL, 0,
        wrap_nonce,
        wrap_key);
    stm_ct_memzero(wrap_key, sizeof wrap_key);
    if (r != 0) return STM_EBADTAG;

    if (out_dek_len) *out_dek_len = (size_t)plen;
    return STM_OK;
}
