/* SPDX-License-Identifier: ISC */
/*
 * Crypto primitives — AEAD + KDF + key wrap.
 *
 * Implementation notes per ARCHITECTURE §7:
 *
 *   - AEGIS-256            (§7.5.1) — default AEAD on AES-accelerated hardware.
 *                                      32-byte key, 32-byte nonce, 16-byte tag.
 *   - XChaCha20-SIV        (§7.5.2) — fallback AEAD, nonce-misuse resistant.
 *                                      64-byte key (two subkeys via SIV
 *                                      construction), 24-byte nonce, 16-byte tag.
 *   - HKDF-SHA256                   — RFC 5869 extract/expand.
 *   - Argon2id                      — passphrase → wrap key derivation.
 *   - X25519 + ML-KEM-768 HPKE-hybrid — PQ wrap (§7.3.4).
 *
 * AEAD selection is a runtime decision recorded per-dataset (§7.5.3). This
 * header exposes both primitives through one enum; the filesystem-facing
 * caller picks the mode at encrypt time.
 *
 * Nonce allocation is *not* done here — nonces are minted by the commit
 * coordinator under End A serialization (ARCHITECTURE §7.4, §3.7.4). This
 * layer only *consumes* a nonce.
 */
#ifndef STRATUM_V2_CRYPTO_H
#define STRATUM_V2_CRYPTO_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* AEAD                                                                       */
/* ========================================================================= */

/* AEAD mode discriminator (stored per-dataset, ARCHITECTURE §7.5.3). */
typedef enum {
    STM_AEAD_INVALID        = 0,
    STM_AEAD_AEGIS256       = 1,
    STM_AEAD_XCHACHA20_SIV  = 2,
} stm_aead_mode;

/*
 * Per-mode AEAD tag length. AEGIS-256 (libsodium default) emits a 32-byte
 * authentication tag; XChaCha20-SIV emits a 16-byte SIV tag. Callers that
 * don't know the mode up front should size buffers using STM_AEAD_TAG_LEN_MAX.
 */
#define STM_AEAD_TAG_LEN_AEGIS256       32
#define STM_AEAD_TAG_LEN_XCHACHA20_SIV  16
#define STM_AEAD_TAG_LEN_MAX            32

/* Returns tag length for a given mode, or 0 for invalid. */
size_t stm_aead_tag_len(stm_aead_mode m);

/* Nonces are unified at 32 bytes: the real nonce occupies some prefix and the
 * suffix is zero/reserved/pool-UUID. See ARCHITECTURE §7.4.1.
 *
 *   AEGIS-256      : uses all 32 bytes.
 *   XChaCha20-SIV  : uses the first 24 bytes; bytes 24..31 must be zero.
 */
#define STM_AEAD_NONCE_LEN      32

/* Key lengths differ by mode. */
#define STM_AEAD_KEY_LEN_AEGIS256        32
#define STM_AEAD_KEY_LEN_XCHACHA20_SIV   64

/* Largest key length — storage allocations sized for the max. */
#define STM_AEAD_KEY_LEN_MAX             64

size_t stm_aead_key_len(stm_aead_mode m);

/*
 * Auto-detect: returns AEGIS-256 if the running CPU has AES-NI (x86) or
 * ARMv8 crypto extensions, XChaCha20-SIV otherwise.
 */
stm_aead_mode stm_aead_autodetect(void);

/*
 * Encrypt `pt` into `ct_and_tag`. The output buffer must be at least
 * `pt_len + stm_aead_tag_len(mode)` bytes; the tag is appended to the ciphertext.
 *
 * `nonce` is STM_AEAD_NONCE_LEN bytes; caller guarantees global uniqueness
 * for the lifetime of `key`.
 *
 * `ad` may be NULL / `ad_len` 0.
 *
 * Returns STM_OK on success, negative stm_status on failure. Failure does
 * not write partial ciphertext.
 */
STM_MUST_USE
stm_status stm_aead_encrypt(stm_aead_mode mode,
                            const uint8_t *key,       /* stm_aead_key_len(mode) */
                            const uint8_t nonce[STM_AEAD_NONCE_LEN],
                            const void *ad, size_t ad_len,
                            const void *pt, size_t pt_len,
                            void       *ct_and_tag,
                            size_t     *out_ct_and_tag_len);

/*
 * Decrypt `ct_and_tag` (length `ct_and_tag_len`, must be ≥ TAG_LEN) into
 * `pt`. On tag-verify failure returns STM_EBADTAG and does NOT write plaintext.
 */
STM_MUST_USE
stm_status stm_aead_decrypt(stm_aead_mode mode,
                            const uint8_t *key,
                            const uint8_t nonce[STM_AEAD_NONCE_LEN],
                            const void *ad, size_t ad_len,
                            const void *ct_and_tag, size_t ct_and_tag_len,
                            void       *pt,
                            size_t     *out_pt_len);

/* ========================================================================= */
/* KDF                                                                        */
/* ========================================================================= */

/* HKDF-SHA256 (RFC 5869). */
void stm_hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                             const uint8_t *ikm, size_t ikm_len,
                             uint8_t out_prk[32]);

STM_MUST_USE
stm_status stm_hkdf_sha256_expand(const uint8_t prk[32],
                                  const uint8_t *info, size_t info_len,
                                  uint8_t *okm, size_t okm_len);

/* Convenience: HKDF extract-then-expand in one call. */
STM_MUST_USE
stm_status stm_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                           const uint8_t *ikm, size_t ikm_len,
                           const uint8_t *info, size_t info_len,
                           uint8_t *okm, size_t okm_len);

/* ------------------------------------------------------------------------- */
/* Argon2id (libsodium's `crypto_pwhash` with alg=ARGON2ID13).                */
/* ------------------------------------------------------------------------- */

typedef struct {
    uint32_t t_cost;        /* iterations (libsodium `opslimit` equivalent)   */
    size_t   m_cost_kib;    /* memory in KiB                                  */
    uint32_t parallelism;   /* currently forced to 1 by libsodium             */
    uint8_t  salt[16];      /* caller-provided; must be stored alongside hash */
} stm_argon2id_params;

/*
 * Reasonable defaults: interactive (~100 ms laptop) and sensitive (~1 s).
 * Used at pool create / passphrase change.
 */
stm_argon2id_params stm_argon2id_params_interactive(const uint8_t salt[16]);
stm_argon2id_params stm_argon2id_params_sensitive  (const uint8_t salt[16]);

STM_MUST_USE
stm_status stm_argon2id(const stm_argon2id_params *params,
                        const char *passphrase, size_t pass_len,
                        uint8_t *out, size_t out_len);

/* ========================================================================= */
/* X25519                                                                     */
/* ========================================================================= */

#define STM_X25519_PK_LEN       32
#define STM_X25519_SK_LEN       32
#define STM_X25519_SS_LEN       32

void stm_x25519_keygen(uint8_t pk[STM_X25519_PK_LEN],
                       uint8_t sk[STM_X25519_SK_LEN]);

STM_MUST_USE
stm_status stm_x25519_dh(const uint8_t sk[STM_X25519_SK_LEN],
                         const uint8_t pk[STM_X25519_PK_LEN],
                         uint8_t ss[STM_X25519_SS_LEN]);

/* ========================================================================= */
/* ML-KEM-768 (NIST FIPS 203)                                                 */
/* ========================================================================= */

/* These constants match FIPS 203 for ML-KEM-768. */
#define STM_MLKEM768_PK_LEN     1184
#define STM_MLKEM768_SK_LEN     2400
#define STM_MLKEM768_CT_LEN     1088
#define STM_MLKEM768_SS_LEN     32

bool stm_mlkem768_available(void);   /* false if liboqs not linked            */

STM_MUST_USE
stm_status stm_mlkem768_keygen(uint8_t pk[STM_MLKEM768_PK_LEN],
                               uint8_t sk[STM_MLKEM768_SK_LEN]);

/* Encapsulate a shared secret under receiver's pk. */
STM_MUST_USE
stm_status stm_mlkem768_encap(const uint8_t pk[STM_MLKEM768_PK_LEN],
                              uint8_t ct[STM_MLKEM768_CT_LEN],
                              uint8_t ss[STM_MLKEM768_SS_LEN]);

STM_MUST_USE
stm_status stm_mlkem768_decap(const uint8_t sk[STM_MLKEM768_SK_LEN],
                              const uint8_t ct[STM_MLKEM768_CT_LEN],
                              uint8_t ss[STM_MLKEM768_SS_LEN]);

/* ========================================================================= */
/* PQ-hybrid wrap (X25519 ∥ ML-KEM-768 via HPKE-style derive, ARCH §7.3.4).  */
/* ========================================================================= */

#define STM_HYBRID_PK_LEN     (STM_X25519_PK_LEN + STM_MLKEM768_PK_LEN)      /* 1216 */
#define STM_HYBRID_SK_LEN     (STM_X25519_SK_LEN + STM_MLKEM768_SK_LEN)      /* 2432 */
#define STM_HYBRID_CT_LEN     (STM_X25519_PK_LEN + STM_MLKEM768_CT_LEN)      /* 1120 */
/*
 * Wrap of an N-byte dataset key produces:
 *   [ephemeral_x25519_pk: 32][mlkem_ct: 1088][wrap_nonce: 24][wrapped: N + 16]
 *
 * The trailing 16 bytes is XChaCha20-Poly1305's Poly1305 tag (fixed by the
 * HPKE wrapping construction, independent of the AEAD mode used for data
 * encryption). Wrap is authenticated: any field tamper breaks decrypt.
 */
#define STM_HYBRID_WRAP_OVERHEAD (STM_HYBRID_CT_LEN + 24 + 16)

STM_MUST_USE
stm_status stm_hybrid_keygen(uint8_t pk[STM_HYBRID_PK_LEN],
                             uint8_t sk[STM_HYBRID_SK_LEN]);

/*
 * Wraps `dek` (length `dek_len`) under `pk`, producing a self-contained blob
 * of `dek_len + STM_HYBRID_WRAP_OVERHEAD` bytes.
 *
 *   `wrapped`: caller buffer of at least that length.
 *   `out_len`: bytes written.
 */
STM_MUST_USE
stm_status stm_hybrid_wrap(const uint8_t pk[STM_HYBRID_PK_LEN],
                           const void *dek, size_t dek_len,
                           void *wrapped, size_t *out_len);

/*
 * Unwraps a wrapped blob. `dek` buffer size = `wrapped_len - STM_HYBRID_WRAP_OVERHEAD`.
 * Returns STM_EBADTAG on tamper / wrong key.
 */
STM_MUST_USE
stm_status stm_hybrid_unwrap(const uint8_t sk[STM_HYBRID_SK_LEN],
                             const void *wrapped, size_t wrapped_len,
                             void *dek, size_t *out_dek_len);

/* ========================================================================= */
/* Random                                                                     */
/* ========================================================================= */

/* CSPRNG — thin wrapper over libsodium's `randombytes_buf`. */
void stm_random_bytes(void *out, size_t n);

/* ========================================================================= */
/* Constant-time comparison                                                   */
/* ========================================================================= */

/* Returns true iff `a` and `b` of `n` bytes are equal. Constant-time in `n`. */
bool stm_ct_equal(const void *a, const void *b, size_t n);

/* Wipe in a way the compiler cannot optimize away (libsodium `memzero`). */
void stm_ct_memzero(void *p, size_t n);

/* ========================================================================= */
/* Initialization                                                             */
/* ========================================================================= */

/*
 * Initializes libsodium (once per process). Must be called before any crypto
 * op. Subsequent calls are cheap no-ops. Thread-safe via libsodium's internal
 * once-init.
 *
 * Returns STM_OK on first successful init; STM_EBACKEND if libsodium itself
 * reports a failure (rare — generally a broken build).
 */
STM_MUST_USE
stm_status stm_crypto_init(void);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_CRYPTO_H */
