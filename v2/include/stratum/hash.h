/* SPDX-License-Identifier: ISC */
/*
 * Hash primitives used throughout Stratum v2.
 *
 *   BLAKE3-256   — Merkle-rooted metadata integrity (ARCHITECTURE §7.11, §5.4).
 *                  Selected for tree-friendliness (deterministic chunk merges),
 *                  speed (~2–6 GB/s/core), and modern construction.
 *
 *   xxHash3-64   — Per-extent integrity on *unencrypted* volumes and for
 *                  in-memory structural hashing. Extremely fast (~15 GB/s/core)
 *                  but not cryptographic. Never used as a Merkle input.
 *
 *   xxHash3-128  — Superblock integrity (unencrypted tamper detection), and
 *                  node-level csum on unencrypted mode. Carried forward from
 *                  v1's `xxh3_128`.
 *
 * Both are oneshot-and-streaming. Streaming state is opaque and stack-sized.
 */
#ifndef STRATUM_V2_HASH_H
#define STRATUM_V2_HASH_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* BLAKE3-256                                                                 */
/* ========================================================================= */

#define STM_BLAKE3_HASH_LEN     32
#define STM_BLAKE3_KEY_LEN      32

typedef struct {
    uint8_t bytes[STM_BLAKE3_HASH_LEN];
} stm_blake3_hash;

/* Opaque streaming context. Size tracks the BLAKE3 reference impl. */
typedef struct stm_blake3_ctx stm_blake3_ctx;

/* One-shot hash. */
void stm_blake3(const void *data, size_t len, stm_blake3_hash *out);

/* One-shot keyed hash (MAC-style). Key must be exactly 32 bytes. */
void stm_blake3_keyed(const uint8_t key[STM_BLAKE3_KEY_LEN],
                      const void *data, size_t len,
                      stm_blake3_hash *out);

/* One-shot KDF (domain-separated via `context` string). */
void stm_blake3_derive_key(const char *context,
                           const void *ikm, size_t ikm_len,
                           uint8_t *out, size_t out_len);

/* Streaming API. Context is heap-allocated to keep this header free of the */
/* BLAKE3 internals. Balance init/update/final calls.                       */
stm_blake3_ctx *stm_blake3_new(void);
stm_blake3_ctx *stm_blake3_new_keyed(const uint8_t key[STM_BLAKE3_KEY_LEN]);
stm_blake3_ctx *stm_blake3_new_kdf(const char *context);
void            stm_blake3_free(stm_blake3_ctx *ctx);
void            stm_blake3_reset(stm_blake3_ctx *ctx);
void            stm_blake3_update(stm_blake3_ctx *ctx, const void *data, size_t len);
void            stm_blake3_final(stm_blake3_ctx *ctx, uint8_t *out, size_t out_len);

static inline bool stm_blake3_eq(const stm_blake3_hash *a, const stm_blake3_hash *b)
{
    /* Byte-by-byte equality. Hashes are public values; no constant-time need. */
    for (size_t i = 0; i < STM_BLAKE3_HASH_LEN; i++) {
        if (a->bytes[i] != b->bytes[i]) return false;
    }
    return true;
}

/* ========================================================================= */
/* xxHash3                                                                    */
/* ========================================================================= */

uint64_t stm_xxh3_64(const void *data, size_t len);
uint64_t stm_xxh3_64_seeded(const void *data, size_t len, uint64_t seed);

typedef struct { uint64_t low64, high64; } stm_xxh128_hash;
stm_xxh128_hash stm_xxh3_128(const void *data, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_HASH_H */
