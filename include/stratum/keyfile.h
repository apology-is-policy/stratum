/* SPDX-License-Identifier: ISC */
/*
 * Keyfile — MVP wrap-key backend (Phase 4 chunk P4-4a).
 *
 *   see ARCHITECTURE §7.9.3 for the full backend list.
 *
 * Keyfiles hold a hybrid (X25519 + ML-KEM-768) key pair on the host
 * filesystem. Used at pool format and mount time to wrap / unwrap
 * the pool's dataset keys.
 *
 * Status: this is the **MVP backend** — simple, explicit about its
 * trust boundary (the keyfile is what's lost if you lose the key).
 * Janus (ARCH §7.9) supersedes this in P4-4b with passphrase /
 * TPM / PKCS#11 / YubiKey backends; the keyfile backend stays
 * around as the lowest-common-denominator automation path.
 *
 * Wire format:
 *
 *   [0..4)      magic = 'KFIL'
 *   [4..8)      version = 1
 *   [8..1224)   hybrid_pk (1216 bytes)
 *   [1224..3656) hybrid_sk (2432 bytes)
 *
 * Security posture: the keyfile is a plaintext secret. Callers are
 * responsible for mode bits (0600), directory permissions, and
 * secure deletion. This file IS the wrap key — losing it loses the
 * pool; leaking it breaks the pool's encryption.
 */
#ifndef STRATUM_V2_KEYFILE_H
#define STRATUM_V2_KEYFILE_H

#include <stratum/crypto.h>
#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hybrid key pair in RAM. Callers pass this to stm_sync_{create,open}. */
typedef struct stm_hybrid_keys {
    uint8_t pk[STM_HYBRID_PK_LEN];
    uint8_t sk[STM_HYBRID_SK_LEN];
} stm_hybrid_keys;

/* Keyfile on-disk layout constants. */
#define STM_KEYFILE_MAGIC        UINT32_C(0x4C49464B)    /* 'KFIL' */
#define STM_KEYFILE_VERSION      1u
#define STM_KEYFILE_SIZE         (8u + STM_HYBRID_PK_LEN + STM_HYBRID_SK_LEN)

/* SWISS-4m: passphrase-encrypted keyfile (v2 format). The plaintext
 * v1 keyfile (above) stays for tests + janus + automation paths;
 * interactive opens via the TUI use the v2 encrypted format so users
 * never need to manage a separate keyfile alongside the volume.
 *
 * Wire format (variable-length):
 *
 *   [0..4)            magic = 'KFP1' (passphrase-encrypted v1)
 *   [4..8)            version = 1
 *   [8..12)           argon2id t_cost (iterations, LE)
 *   [12..16)          argon2id m_cost_kib (memory in KiB, LE)
 *   [16..20)          argon2id parallelism (LE; libsodium forces 1)
 *   [20..24)          aead_mode (LE; stm_aead_mode enum)
 *   [24..40)          kdf_salt (16 bytes, CSPRNG)
 *   [40..72)          aead_nonce (STM_AEAD_NONCE_LEN = 32 bytes, CSPRNG)
 *   [72..72+CT)       ciphertext_with_tag (CT = PK_LEN + SK_LEN + tag_len)
 *
 * KEK derivation: Argon2id(passphrase, kdf_salt, params) → 32 bytes.
 * AEAD: encrypts PK||SK as one blob; tag is appended to ciphertext.
 *
 * Security posture: without the passphrase, the file is opaque
 * ciphertext. With a brute-forced passphrase, attacker pays Argon2id
 * cost per attempt — for `interactive` params (~100 ms) on commodity
 * hardware, that's a meaningful deterrent for low-entropy
 * passphrases and a non-issue for high-entropy ones. */
#define STM_KEYFILE_PASS_MAGIC      UINT32_C(0x31504650)  /* 'KFP1' */
#define STM_KEYFILE_PASS_VERSION    1u
#define STM_KEYFILE_PASS_HEADER_LEN 72u

/*
 * Generate a fresh hybrid key pair via stm_hybrid_keygen and write
 * it to `path` UNENCRYPTED. File is created with mode 0600; existing
 * file at `path` is overwritten.
 *
 * Returns STM_EBACKEND on I/O failure, STM_ENOMEM on allocation
 * failure, STM_EINVAL for NULL args.
 */
STM_MUST_USE
stm_status stm_keyfile_generate(const char *path);

/*
 * Load an UNENCRYPTED keyfile from `path` into `out`.
 *
 * Returns STM_EBADVERSION on magic/version mismatch (including v2
 * passphrase-encrypted format — caller must use the _passphrase
 * variant for those), STM_ERANGE if the file is the wrong size,
 * STM_EBACKEND on I/O failure.
 */
STM_MUST_USE
stm_status stm_keyfile_load(const char *path, stm_hybrid_keys *out);

/*
 * Generate a fresh hybrid key pair, encrypt PK||SK under a KEK
 * derived from `passphrase` via Argon2id (interactive params), and
 * write the encrypted keyfile to `path`. File mode 0600. Caller's
 * `passphrase` buffer is NOT wiped — caller is responsible for
 * `stm_ct_memzero`-ing it after this call returns.
 *
 * `pass_len` is the byte count, NOT including any trailing NUL.
 * Passphrase MAY contain non-ASCII bytes; treated as opaque bytes.
 *
 * Returns STM_EINVAL on NULL/zero args, STM_ENOMEM on allocation
 * failure, STM_EBACKEND on I/O failure.
 */
STM_MUST_USE
stm_status stm_keyfile_generate_passphrase(const char *path,
                                              const char *passphrase,
                                              size_t      pass_len);

/*
 * Load a passphrase-encrypted keyfile (KFP1 magic) from `path`,
 * derive the KEK from `passphrase`, decrypt PK||SK into `out`.
 *
 * Returns STM_EBADTAG on wrong passphrase (AEAD tag verification
 * failed) or any tampered ciphertext, STM_EBADVERSION on magic
 * mismatch (file is plaintext-v1 or unrelated), STM_ERANGE on size
 * mismatch, STM_EBACKEND on I/O failure. Caller is responsible for
 * wiping `passphrase` after this call returns.
 */
STM_MUST_USE
stm_status stm_keyfile_load_passphrase(const char *path,
                                          const char *passphrase,
                                          size_t      pass_len,
                                          stm_hybrid_keys *out);

/*
 * Wipe key material (both fields) with stm_ct_memzero. Callers
 * holding a `stm_hybrid_keys` on the stack should call this before
 * scope exit so key bytes don't linger.
 */
void stm_hybrid_keys_wipe(stm_hybrid_keys *kp);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_KEYFILE_H */
