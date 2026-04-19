/* SPDX-License-Identifier: ISC */
/*
 * xxHash3 wrapper.
 *
 * Defined as non-inline to give the compiler freedom to specialize; inlining
 * the primary xxHash3 entry point into every caller would bloat object size
 * without measurable benefit at filesystem scale.
 */
#include <stratum/hash.h>

#define XXH_INLINE_ALL
#include "xxhash.h"

uint64_t stm_xxh3_64(const void *data, size_t len)
{
    return XXH3_64bits(data, len);
}

uint64_t stm_xxh3_64_seeded(const void *data, size_t len, uint64_t seed)
{
    return XXH3_64bits_withSeed(data, len, seed);
}

stm_xxh128_hash stm_xxh3_128(const void *data, size_t len)
{
    XXH128_hash_t h = XXH3_128bits(data, len);
    return (stm_xxh128_hash){ .low64 = h.low64, .high64 = h.high64 };
}
