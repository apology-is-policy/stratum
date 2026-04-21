/* SPDX-License-Identifier: ISC */
/*
 * Data-extent AEAD wrapper (Phase 4 chunk P4-5 stub).
 *
 *   see ARCHITECTURE §7.5 (AEAD construction) + §7.6.1 (AD struct).
 *
 * Stub scope (MVP for the Phase 4 exit bullet "encrypted writes
 * round-trip correctly with AEGIS-256 and XChaCha20-SIV"):
 *
 *   - Single-buffer encrypt / decrypt of a data extent.
 *   - stm_ad_extent binds ciphertext to (pool, dataset, ino,
 *     offset, content_kind). Any mismatch → STM_EBADTAG.
 *   - Mode picker — AEGIS-256 or XChaCha20-SIV per caller's choice
 *     (which in turn is resolved from pool + per-dataset override
 *     per ARCH §7.5.3).
 *   - No extent manager — the caller owns paddrs, no on-disk
 *     index. Phase 6's extent-layer elaborates.
 *
 * Nonce construction matches P4-3b's metadata-node wrapper
 * (paddr || gen || pool_uuid). Safe: bootstrap's deferred-free
 * guarantees (paddr, gen) unique within a pool's lifetime. This is
 * a subset of ARCH §7.4.1's (paddr, txg, seq_in_txg, reserved,
 * pool_uuid-high) — see phase4-status.md "Known deltas from ARCH"
 * for the rationale.
 */
#ifndef STRATUM_V2_EXTENT_H
#define STRATUM_V2_EXTENT_H

#include <stratum/crypto.h>
#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ARCH §7.6.1 AD magic / version. */
#define STM_AD_MAGIC_EXTENT     UINT32_C(0x44545845)   /* 'EXTD' */
#define STM_AD_VERSION_EXTENT   1u

/* 56-byte AD struct per ARCH §7.6.1. Every field little-endian on
 * disk; `stm_ad_extent_pack` serializes. Binding a write to its
 * (pool, dataset, ino, offset) — swapping any field breaks decrypt. */
typedef struct {
    uint32_t magic;            /* STM_AD_MAGIC_EXTENT */
    uint32_t version;          /* STM_AD_VERSION_EXTENT */
    uint64_t pool_uuid[2];     /* 16 bytes */
    uint64_t dataset_id;
    uint64_t ino;
    uint64_t offset;           /* byte offset within file */
    uint64_t content_kind;     /* 0 = file data, 1 = xattr, 2 = inline, ... */
} stm_ad_extent;

#define STM_AD_EXTENT_PACKED_LEN  56u

/* Pack an stm_ad_extent into 56 little-endian bytes. */
void stm_ad_extent_pack(const stm_ad_extent *ad,
                         uint8_t out[STM_AD_EXTENT_PACKED_LEN]);

/* ========================================================================= */
/* Encrypt / decrypt.                                                         */
/* ========================================================================= */

/*
 * Encrypt `plaintext` (of `pt_len` bytes) under (`mode`, `key`) into
 * `out` (of `out_cap` bytes). `out_cap` must be at least
 * `pt_len + stm_aead_tag_len(mode)`.
 *
 * Nonce bound to (paddr, gen, cx->pool_uuid). AD bound to the
 * caller's `ad` struct.
 *
 * Returns STM_OK on success, STM_ERANGE if out_cap is too small,
 * STM_EINVAL for NULL params.
 */
STM_MUST_USE
stm_status stm_extent_encrypt(stm_aead_mode mode,
                               const uint8_t *key,
                               uint64_t paddr, uint64_t gen,
                               const stm_ad_extent *ad,
                               const void *plaintext, size_t pt_len,
                               void *out, size_t out_cap,
                               size_t *out_len);

/*
 * Decrypt `ct_and_tag` (ciphertext followed by an inline tag) into
 * `out_plaintext`. `out_pt_cap` must be at least
 * `ct_and_tag_len - stm_aead_tag_len(mode)`.
 *
 * Returns STM_EBADTAG if the AD or nonce mismatches what the
 * encrypt call used (tampered ciphertext, wrong paddr / gen / AD
 * field).
 */
STM_MUST_USE
stm_status stm_extent_decrypt(stm_aead_mode mode,
                               const uint8_t *key,
                               uint64_t paddr, uint64_t gen,
                               const stm_ad_extent *ad,
                               const void *ct_and_tag, size_t ct_and_tag_len,
                               void *out_plaintext, size_t out_pt_cap,
                               size_t *out_pt_len);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_EXTENT_H */
