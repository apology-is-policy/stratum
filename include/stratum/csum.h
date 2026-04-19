#ifndef STM_CSUM_H
#define STM_CSUM_H

/*
 * Block integrity checksums — xxHash3-128, zero-padded to 32 bytes.
 *
 * Detects bit rot, partial writes, and media errors. Not a security
 * mechanism (encrypted volumes have AEAD integrity via Poly1305).
 */

#include "stratum/types.h"
#include <string.h>

#define STM_CSUM_LEN 32  /* field size in on-disk structs */

#ifdef STM_HAVE_XXHASH
#include <xxhash.h>

static inline void stm_csum_compute(const void *data, uint32_t len,
                                    uint8_t out[STM_CSUM_LEN])
{
    XXH128_hash_t h = XXH3_128bits(data, len);
    memset(out, 0, STM_CSUM_LEN);
    memcpy(out, &h, sizeof(h));  /* 16 bytes, rest zero-padded */
}

static inline int stm_csum_verify(const void *data, uint32_t len,
                                  const uint8_t expected[STM_CSUM_LEN])
{
    uint8_t actual[STM_CSUM_LEN];
    /* No zero-csum backward-compat clause — all v1 volumes carry a
     * computed xxHash3-128 csum, and accepting a zeroed field would let
     * an attacker with raw-disk access substitute SB/node content with
     * a zeroed csum and pass verification. */
    stm_csum_compute(data, len, actual);
    return memcmp(actual, expected, STM_CSUM_LEN) == 0 ? 0 : -1;
}

/* 64-bit xxHash3 for per-extent integrity (Phase D #7). Not a security
 * mechanism — detects bit rot / torn writes / media errors only. An
 * attacker with raw-disk write access can rewrite content and re-hash;
 * adversarial integrity on encrypted volumes comes from AEAD, and
 * unencrypted volumes explicitly opt out of adversarial defense. */
static inline uint64_t stm_xxh64(const void *data, uint32_t len)
{
    return (uint64_t)XXH3_64bits(data, len);
}

#else /* !STM_HAVE_XXHASH */

static inline void stm_csum_compute(const void *data, uint32_t len,
                                    uint8_t out[STM_CSUM_LEN])
{
    (void)data; (void)len;
    memset(out, 0, STM_CSUM_LEN);  /* no checksum without xxhash */
}

static inline int stm_csum_verify(const void *data, uint32_t len,
                                  const uint8_t expected[STM_CSUM_LEN])
{
    (void)data; (void)len; (void)expected;
    return 0;  /* always pass without xxhash */
}

static inline uint64_t stm_xxh64(const void *data, uint32_t len)
{
    (void)data; (void)len;
    return 0;  /* no checksum without xxhash */
}

#endif /* STM_HAVE_XXHASH */

#endif /* STM_CSUM_H */
