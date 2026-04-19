/* SPDX-License-Identifier: ISC */
/*
 * AEGIS-256 via libsodium ≥ 1.0.19.
 *
 * 32-byte key, 32-byte nonce (uses all bytes), 16-byte tag.
 * CAESAR portfolio winner. Hardware AES acceleration recommended.
 */
#include "aead_internal.h"

#include <sodium.h>
#include <string.h>

stm_status stm_aegis256_encrypt(const uint8_t key[32],
                                const uint8_t nonce[32],
                                const void *ad, size_t ad_len,
                                const void *pt, size_t pt_len,
                                void *ct_and_tag, size_t *out_len)
{
    unsigned long long clen = 0;
    int r = crypto_aead_aegis256_encrypt(
        (unsigned char *)ct_and_tag, &clen,
        (const unsigned char *)pt, (unsigned long long)pt_len,
        (const unsigned char *)ad, (unsigned long long)ad_len,
        NULL,                     /* nsec — unused for AEGIS */
        (const unsigned char *)nonce,
        (const unsigned char *)key);
    if (r != 0) return STM_EBACKEND;
    if (out_len) *out_len = (size_t)clen;
    return STM_OK;
}

stm_status stm_aegis256_decrypt(const uint8_t key[32],
                                const uint8_t nonce[32],
                                const void *ad, size_t ad_len,
                                const void *ct_and_tag, size_t ct_and_tag_len,
                                void *pt, size_t *out_pt_len)
{
    if (ct_and_tag_len < crypto_aead_aegis256_ABYTES) return STM_EINVAL;

    unsigned long long plen = 0;
    int r = crypto_aead_aegis256_decrypt(
        (unsigned char *)pt, &plen,
        NULL,                    /* nsec */
        (const unsigned char *)ct_and_tag, (unsigned long long)ct_and_tag_len,
        (const unsigned char *)ad, (unsigned long long)ad_len,
        (const unsigned char *)nonce,
        (const unsigned char *)key);
    if (r != 0) return STM_EBADTAG;
    if (out_pt_len) *out_pt_len = (size_t)plen;
    return STM_OK;
}

/* Sanity check that libsodium's AEGIS-256 constants match the spec. */
STM_STATIC_ASSERT(crypto_aead_aegis256_KEYBYTES  == STM_AEAD_KEY_LEN_AEGIS256,  "AEGIS key len");
STM_STATIC_ASSERT(crypto_aead_aegis256_NPUBBYTES == STM_AEAD_NONCE_LEN,         "AEGIS nonce len");
STM_STATIC_ASSERT(crypto_aead_aegis256_ABYTES    == STM_AEAD_TAG_LEN_AEGIS256,  "AEGIS tag len");
