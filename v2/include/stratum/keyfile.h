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

/*
 * Generate a fresh hybrid key pair via stm_hybrid_keygen and write
 * it to `path`. File is created with mode 0600; existing file at
 * `path` is overwritten.
 *
 * Returns STM_EBACKEND on I/O failure, STM_ENOMEM on allocation
 * failure, STM_EINVAL for NULL args.
 */
STM_MUST_USE
stm_status stm_keyfile_generate(const char *path);

/*
 * Load a keyfile from `path` into `out`.
 *
 * Returns STM_EBADVERSION on magic/version mismatch, STM_ERANGE if
 * the file is the wrong size, STM_EBACKEND on I/O failure.
 */
STM_MUST_USE
stm_status stm_keyfile_load(const char *path, stm_hybrid_keys *out);

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
