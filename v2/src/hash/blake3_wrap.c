/* SPDX-License-Identifier: ISC */
/*
 * BLAKE3 wrapper.
 *
 * Keeps the BLAKE3 reference headers out of Stratum public headers. The
 * reference library's streaming state is ~1.9 KiB on 64-bit; we heap-allocate
 * it so callers don't see the size or layout.
 *
 * The vendored reference is the portable build (no SIMD). Phase 9 benchmarks
 * will tell us whether to enable AVX2/AVX-512/NEON paths.
 */
#include <stratum/hash.h>

#include <stdlib.h>
#include <string.h>

#include "blake3.h"

struct stm_blake3_ctx {
    blake3_hasher h;
};

void stm_blake3(const void *data, size_t len, stm_blake3_hash *out)
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out->bytes, STM_BLAKE3_HASH_LEN);
}

void stm_blake3_keyed(const uint8_t key[STM_BLAKE3_KEY_LEN],
                      const void *data, size_t len,
                      stm_blake3_hash *out)
{
    blake3_hasher h;
    blake3_hasher_init_keyed(&h, key);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, out->bytes, STM_BLAKE3_HASH_LEN);
}

void stm_blake3_derive_key(const char *context,
                           const void *ikm, size_t ikm_len,
                           uint8_t *out, size_t out_len)
{
    blake3_hasher h;
    blake3_hasher_init_derive_key(&h, context);
    blake3_hasher_update(&h, ikm, ikm_len);
    blake3_hasher_finalize(&h, out, out_len);
}

stm_blake3_ctx *stm_blake3_new(void)
{
    stm_blake3_ctx *c = malloc(sizeof *c);
    if (c) blake3_hasher_init(&c->h);
    return c;
}

stm_blake3_ctx *stm_blake3_new_keyed(const uint8_t key[STM_BLAKE3_KEY_LEN])
{
    stm_blake3_ctx *c = malloc(sizeof *c);
    if (c) blake3_hasher_init_keyed(&c->h, key);
    return c;
}

stm_blake3_ctx *stm_blake3_new_kdf(const char *context)
{
    stm_blake3_ctx *c = malloc(sizeof *c);
    if (c) blake3_hasher_init_derive_key(&c->h, context);
    return c;
}

void stm_blake3_free(stm_blake3_ctx *ctx)
{
    if (!ctx) return;
    /* No sensitive material — hash state is not a key. Plain free. */
    free(ctx);
}

void stm_blake3_reset(stm_blake3_ctx *ctx)
{
    blake3_hasher_reset(&ctx->h);
}

void stm_blake3_update(stm_blake3_ctx *ctx, const void *data, size_t len)
{
    blake3_hasher_update(&ctx->h, data, len);
}

void stm_blake3_final(stm_blake3_ctx *ctx, uint8_t *out, size_t out_len)
{
    blake3_hasher_finalize(&ctx->h, out, out_len);
}
