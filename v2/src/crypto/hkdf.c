/* SPDX-License-Identifier: ISC */
/*
 * HKDF-SHA256 via libsodium's crypto_kdf_hkdf_sha256_*.
 *
 * Matches RFC 5869. Used for HPKE hybrid wrap derivation (§7.3.4) and for any
 * context-specific key expansion outside AEAD's built-in derivation.
 */
#include <stratum/crypto.h>

#include <sodium.h>

void stm_hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                             const uint8_t *ikm, size_t ikm_len,
                             uint8_t out_prk[32])
{
    /* libsodium accepts NULL salt (treated as 32 zero bytes per RFC 5869). */
    (void)crypto_kdf_hkdf_sha256_extract(out_prk, salt, salt_len, ikm, ikm_len);
}

stm_status stm_hkdf_sha256_expand(const uint8_t prk[32],
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *okm, size_t okm_len)
{
    /* RFC 5869: max L = 255 * HashLen = 255 * 32 = 8160 bytes. */
    if (okm_len > 8160) return STM_ERANGE;
    int r = crypto_kdf_hkdf_sha256_expand(okm, okm_len, (const char *)info, info_len, prk);
    if (r != 0) return STM_EBACKEND;
    return STM_OK;
}

stm_status stm_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *info, size_t info_len,
                           uint8_t *okm, size_t okm_len)
{
    uint8_t prk[32];
    stm_hkdf_sha256_extract(salt, salt_len, ikm, ikm_len, prk);
    stm_status s = stm_hkdf_sha256_expand(prk, info, info_len, okm, okm_len);
    stm_ct_memzero(prk, sizeof prk);
    return s;
}
