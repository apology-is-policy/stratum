/* SPDX-License-Identifier: ISC */
/*
 * AEAD dispatch.
 *
 * Maps the public stm_aead_mode enum onto a concrete implementation. Phase 9
 * SIMD tuning happens behind the per-mode entry points in
 * aead_{aegis256,xchacha20_siv}.c — this file stays stable.
 */
#include "aead_internal.h"

#include <sodium.h>

size_t stm_aead_key_len(stm_aead_mode m)
{
    switch (m) {
    case STM_AEAD_AEGIS256:       return STM_AEAD_KEY_LEN_AEGIS256;
    case STM_AEAD_XCHACHA20_SIV:  return STM_AEAD_KEY_LEN_XCHACHA20_SIV;
    case STM_AEAD_INVALID:
    default:                      return 0;
    }
}

size_t stm_aead_tag_len(stm_aead_mode m)
{
    switch (m) {
    case STM_AEAD_AEGIS256:       return STM_AEAD_TAG_LEN_AEGIS256;
    case STM_AEAD_XCHACHA20_SIV:  return STM_AEAD_TAG_LEN_XCHACHA20_SIV;
    case STM_AEAD_INVALID:
    default:                      return 0;
    }
}

/*
 * AEAD autodetect. On x86-64 with AES-NI or ARMv8 with crypto extensions,
 * AEGIS-256 is strongly preferred (hardware AES + efficient round structure).
 * Otherwise fall back to XChaCha20-SIV which is software-uniform.
 *
 * libsodium's `sodium_runtime_has_aesni` / `sodium_runtime_has_armcrypto` are
 * the canonical probes. Missing probes (non-x86, non-ARM) → XChaCha20-SIV.
 */
stm_aead_mode stm_aead_autodetect(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    if (sodium_runtime_has_aesni()) return STM_AEAD_AEGIS256;
#elif defined(__aarch64__)
    if (sodium_runtime_has_armcrypto()) return STM_AEAD_AEGIS256;
#endif
    return STM_AEAD_XCHACHA20_SIV;
}

stm_status stm_aead_encrypt(stm_aead_mode mode,
                            const uint8_t *key,
                            const uint8_t nonce[STM_AEAD_NONCE_LEN],
                            const void *ad, size_t ad_len,
                            const void *pt, size_t pt_len,
                            void *ct_and_tag, size_t *out_ct_and_tag_len)
{
    if (!key || !nonce || !ct_and_tag) return STM_EINVAL;
    if (pt_len > 0 && !pt) return STM_EINVAL;
    if (ad_len > 0 && !ad) return STM_EINVAL;

    switch (mode) {
    case STM_AEAD_AEGIS256:
        return stm_aegis256_encrypt(key, nonce, ad, ad_len, pt, pt_len,
                                    ct_and_tag, out_ct_and_tag_len);
    case STM_AEAD_XCHACHA20_SIV:
        return stm_xchacha20_siv_encrypt(key, nonce, ad, ad_len, pt, pt_len,
                                         ct_and_tag, out_ct_and_tag_len);
    case STM_AEAD_INVALID:
    default:
        return STM_EINVAL;
    }
}

stm_status stm_aead_decrypt(stm_aead_mode mode,
                            const uint8_t *key,
                            const uint8_t nonce[STM_AEAD_NONCE_LEN],
                            const void *ad, size_t ad_len,
                            const void *ct_and_tag, size_t ct_and_tag_len,
                            void *pt, size_t *out_pt_len)
{
    if (!key || !nonce || !ct_and_tag) return STM_EINVAL;
    size_t taglen = stm_aead_tag_len(mode);
    if (taglen == 0) return STM_EINVAL;
    if (ct_and_tag_len > 0 && ct_and_tag_len < taglen) return STM_EINVAL;

    switch (mode) {
    case STM_AEAD_AEGIS256:
        return stm_aegis256_decrypt(key, nonce, ad, ad_len,
                                    ct_and_tag, ct_and_tag_len,
                                    pt, out_pt_len);
    case STM_AEAD_XCHACHA20_SIV:
        return stm_xchacha20_siv_decrypt(key, nonce, ad, ad_len,
                                         ct_and_tag, ct_and_tag_len,
                                         pt, out_pt_len);
    case STM_AEAD_INVALID:
    default:
        return STM_EINVAL;
    }
}
