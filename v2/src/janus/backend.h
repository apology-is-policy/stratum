/* SPDX-License-Identifier: ISC */
/*
 * Internal backend interface for janus. A backend holds the wrap
 * key material (hybrid SK) for one or more pools and performs the
 * unwrap operation on request.
 *
 * Backends are chosen at daemon startup via configuration. Each
 * pool binds to exactly one backend instance; backend instances
 * can serve multiple pools if the daemon wires them that way.
 *
 * The backend's `unwrap` callback sees the same AD the FS built
 * in sync.c::build_wrap_ad — pool_uuid || dataset_id || key_id —
 * so an AD mismatch is detectable here, not only after the AEAD
 * tag check. This closes a class of "use the wrong wrap key" bugs
 * early.
 */
#ifndef STRATUM_V2_JANUS_BACKEND_H
#define STRATUM_V2_JANUS_BACKEND_H

#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>

typedef struct janus_backend {
    /* Backend name for /pools/<uuid>/wrap-key-info introspection. */
    char name[32];

    /* Unwrap `wrapped` under AD = pool_uuid || dataset_id || key_id.
     * On success, `*inout_dek_len` is set to bytes written. Fails
     * STM_EBADTAG on wrap-tag mismatch, STM_EACCES if the backend
     * doesn't own a key for this pool. */
    stm_status (*unwrap)(void *ctx,
                         const uint8_t pool_uuid[16],
                         uint64_t dataset_id,
                         uint64_t key_id,
                         const void *wrapped, size_t wrapped_len,
                         void *out_dek, size_t *inout_dek_len);

    /* Release all backend state including key material. Must wipe
     * any hybrid_sk bytes before freeing. */
    void (*destroy)(void *ctx);

    void *ctx;
} janus_backend;

/* Move-assign: transfers ownership; leaves src->ctx == NULL so a
 * double-destroy is safe. */
static inline void janus_backend_move(janus_backend *dst,
                                        janus_backend *src)
{
    *dst = *src;
    src->ctx = NULL;
    src->unwrap = NULL;
    src->destroy = NULL;
}

/* Backend factories. Each opens state from its configured source and
 * fills `*out`. On error, `*out` is untouched. */

/* File backend: hybrid keypair sits in a keyfile on the host FS (see
 * stm_keyfile). Intended for automation / container use. */
stm_status janus_backend_file_open(const char *keyfile_path,
                                     janus_backend *out);

/* Passphrase backend: Argon2id on the passphrase derives a 32-byte
 * KEK that AEAD-decrypts an on-disk wrapped hybrid keypair.
 *
 *   `state_dir` must contain:
 *     `hybrid.wrapped`  — the AEAD-wrapped hybrid keypair
 *     `argon2.salt`     — 16-byte Argon2id salt
 *     `argon2.params`   — Argon2id m/t/p parameters
 *
 *   `passphrase` is the user-supplied UTF-8 passphrase; never stored.
 *
 * Returns STM_EBADTAG if the passphrase is wrong (KEK decrypt fails),
 * STM_ENOENT if state_dir lacks the required files.
 */
stm_status janus_backend_passphrase_open(const char *state_dir,
                                           const char *passphrase,
                                           janus_backend *out);

/* One-time setup: generate a fresh hybrid keypair, derive the KEK
 * from `passphrase`, wrap the SK, and populate `state_dir`. Writes
 * the generated public key to `out_pk`. Returns STM_EEXIST if
 * state_dir already has `hybrid.wrapped`. */
stm_status janus_backend_passphrase_setup(const char *state_dir,
                                            const char *passphrase,
                                            uint8_t out_pk[1216 /* STM_HYBRID_PK_LEN */]);

#endif /* STRATUM_V2_JANUS_BACKEND_H */
