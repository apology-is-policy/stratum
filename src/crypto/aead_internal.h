/* SPDX-License-Identifier: ISC */
/*
 * Internal (non-public) per-mode entry points dispatched from aead.c.
 * Split per mode so Phase-9 SIMD drop-ins can replace one without touching
 * the dispatch layer.
 */
#ifndef STRATUM_V2_AEAD_INTERNAL_H
#define STRATUM_V2_AEAD_INTERNAL_H

#include <stratum/crypto.h>

stm_status stm_aegis256_encrypt(const uint8_t key[32],
                                const uint8_t nonce[32],
                                const void *ad, size_t ad_len,
                                const void *pt, size_t pt_len,
                                void *ct_and_tag, size_t *out_len);

stm_status stm_aegis256_decrypt(const uint8_t key[32],
                                const uint8_t nonce[32],
                                const void *ad, size_t ad_len,
                                const void *ct_and_tag, size_t ct_and_tag_len,
                                void *pt, size_t *out_pt_len);

stm_status stm_xchacha20_siv_encrypt(const uint8_t key[64],
                                     const uint8_t nonce[32],
                                     const void *ad, size_t ad_len,
                                     const void *pt, size_t pt_len,
                                     void *ct_and_tag, size_t *out_len);

stm_status stm_xchacha20_siv_decrypt(const uint8_t key[64],
                                     const uint8_t nonce[32],
                                     const void *ad, size_t ad_len,
                                     const void *ct_and_tag, size_t ct_and_tag_len,
                                     void *pt, size_t *out_pt_len);

#endif
