/* SPDX-License-Identifier: ISC */
/*
 * Passphrase backend — Argon2id-derived KEK AEAD-wraps the hybrid
 * keypair in janus's per-pool state directory.
 *
 *   see ARCHITECTURE §7.9.3 "passphrase" — the default backend for
 *   laptops and personal deployments (NOVEL §3.10).
 *
 * State file layout (`<state_dir>/hybrid.janus`):
 *
 *   [0..4)     magic 'JPAS'
 *   [4..8)     version = 1
 *   [8..12)    t_cost         u32 LE  Argon2id iterations
 *   [12..20)   m_cost_kib     u64 LE  Argon2id memory (KiB)
 *   [20..24)   parallelism    u32 LE
 *   [24..40)   salt           16 B    Argon2id salt
 *   [40..72)   aead_nonce     32 B    AEGIS-256 nonce (random per rewrap)
 *   [72..ct_end)               3648 B ciphertext (hybrid_pk ‖ hybrid_sk)
 *   [ct_end..tag_end)          32 B   AEGIS-256 tag
 *
 * AD = "stratum-janus-pass-v1" — binds the wrap to this format. If we
 * ever bump the format we bump the AD alongside.
 *
 * Security notes:
 *   - The passphrase is wiped from RAM as soon as the KEK is derived.
 *   - The hybrid_sk lives in RAM for the daemon's lifetime. Janus should
 *     run as a dedicated user with core dumps disabled (setrlimit) and
 *     (on Linux) mlock'd pages. Those hardenings happen in janusd.c;
 *     this file only guarantees it never writes the sk in plaintext to
 *     disk.
 *   - Argon2id params default to `stm_argon2id_params_interactive` at
 *     setup time; they are persisted in the state file so a later
 *     open can reproduce the same KEK derivation.
 *   - The KEK is deterministic per (passphrase, salt); the AEAD nonce
 *     is freshly randomised on setup / rewrap so two wraps by the
 *     same passphrase never collide on (nonce, key).
 */

#include "backend.h"

#include <stratum/crypto.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PASS_STATE_FILE        "hybrid.janus"
/* R11 P3-1: the on-disk bytes now read "JPAS" matching the doc-
 * comment at the top. The previous encoding 0x53415046 packed as
 * "FPAS" in LE order, disagreeing with the header. J=0x4A, P=0x50,
 * A=0x41, S=0x53 → LE u32 = 0x5341504A. */
#define PASS_MAGIC             UINT32_C(0x5341504A) /* 'JPAS' on-disk LE */
#define PASS_VERSION           1u
#define PASS_AD_STR            "stratum-janus-pass-v1"
#define PASS_KEK_LEN           32u
#define PASS_NONCE_LEN         32u
#define PASS_TAG_LEN           32u
#define PASS_PT_LEN            (STM_HYBRID_PK_LEN + STM_HYBRID_SK_LEN)
#define PASS_CT_LEN            PASS_PT_LEN
#define PASS_FILE_SIZE         (72u + PASS_CT_LEN + PASS_TAG_LEN)

#define STM_JANUS_WRAP_AD_LEN  32u

/* ── little-endian helpers ──────────────────────────────────────────── */

static void pack_u32_le(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)v;         out[1] = (uint8_t)(v >> 8);
    out[2] = (uint8_t)(v >> 16); out[3] = (uint8_t)(v >> 24);
}

static void pack_u64_le(uint64_t v, uint8_t out[8])
{
    pack_u32_le((uint32_t)v, out);
    pack_u32_le((uint32_t)(v >> 32), out + 4);
}

static uint32_t load_u32_le(const uint8_t in[4])
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8)
         | ((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static uint64_t load_u64_le(const uint8_t in[8])
{
    return (uint64_t)load_u32_le(in) | ((uint64_t)load_u32_le(in + 4) << 32);
}

/* ── file I/O ──────────────────────────────────────────────────────── */

static int join_path(char *out, size_t cap, const char *dir, const char *name)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

static stm_status read_exact(const char *path, uint8_t *buf, size_t len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return (errno == ENOENT) ? STM_ENOENT : STM_EBACKEND;
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return STM_EBACKEND; }
    if ((uint64_t)st.st_size != (uint64_t)len) { close(fd); return STM_ERANGE; }
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return STM_EBACKEND;
        }
        if (n == 0) { close(fd); return STM_ERANGE; }
        got += (size_t)n;
    }
    close(fd);
    return STM_OK;
}

static stm_status write_exact(const char *path, const uint8_t *buf, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) return (errno == EEXIST) ? STM_EEXIST : STM_EBACKEND;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(path);
            return STM_EBACKEND;
        }
        written += (size_t)n;
    }
    if (fsync(fd) < 0) {
        close(fd);
        unlink(path);
        return STM_EBACKEND;
    }
    close(fd);
    return STM_OK;
}

/* ── KEK derivation ─────────────────────────────────────────────────── */

static stm_status derive_kek(const char *passphrase,
                              const stm_argon2id_params *params,
                              uint8_t out_kek[PASS_KEK_LEN])
{
    if (!passphrase) return STM_EINVAL;
    size_t plen = strlen(passphrase);
    if (plen == 0) return STM_EINVAL;
    return stm_argon2id(params, passphrase, plen, out_kek, PASS_KEK_LEN);
}

/* ── wire pack/unpack ───────────────────────────────────────────────── */

static void pack_header(uint8_t buf[72],
                         const stm_argon2id_params *params,
                         const uint8_t nonce[PASS_NONCE_LEN])
{
    pack_u32_le(PASS_MAGIC,   buf + 0);
    pack_u32_le(PASS_VERSION, buf + 4);
    pack_u32_le(params->t_cost, buf + 8);
    pack_u64_le((uint64_t)params->m_cost_kib, buf + 12);
    pack_u32_le(params->parallelism, buf + 20);
    memcpy(buf + 24, params->salt, 16);
    memcpy(buf + 40, nonce, PASS_NONCE_LEN);
}

static stm_status unpack_header(const uint8_t buf[72],
                                  stm_argon2id_params *out_params,
                                  uint8_t out_nonce[PASS_NONCE_LEN])
{
    if (load_u32_le(buf + 0) != PASS_MAGIC
     || load_u32_le(buf + 4) != PASS_VERSION) return STM_EBADVERSION;
    out_params->t_cost      = load_u32_le(buf + 8);
    out_params->m_cost_kib  = (size_t)load_u64_le(buf + 12);
    out_params->parallelism = load_u32_le(buf + 20);
    memcpy(out_params->salt, buf + 24, 16);
    memcpy(out_nonce, buf + 40, PASS_NONCE_LEN);
    return STM_OK;
}

/* ── setup (one-time): generate keys, wrap, write state ─────────────── */

stm_status janus_backend_passphrase_setup(const char *state_dir,
                                            const char *passphrase,
                                            uint8_t out_pk[STM_HYBRID_PK_LEN])
{
    if (!state_dir || !passphrase || !out_pk) return STM_EINVAL;
    stm_status rc = stm_crypto_init();
    if (rc != STM_OK) return rc;

    /* Make state dir if it doesn't exist (mode 0700). */
    if (mkdir(state_dir, 0700) != 0 && errno != EEXIST)
        return STM_EBACKEND;

    char path[1024];
    if (join_path(path, sizeof path, state_dir, PASS_STATE_FILE) != 0)
        return STM_EINVAL;

    struct stat st;
    if (stat(path, &st) == 0) return STM_EEXIST;

    uint8_t salt[16];
    stm_random_bytes(salt, sizeof salt);
    stm_argon2id_params params = stm_argon2id_params_interactive(salt);

    uint8_t kek[PASS_KEK_LEN];
    rc = derive_kek(passphrase, &params, kek);
    if (rc != STM_OK) {
        stm_ct_memzero(kek, sizeof kek);
        return rc;
    }

    /* Generate fresh hybrid keypair. */
    uint8_t *plaintext = calloc(1, PASS_PT_LEN);
    if (!plaintext) { stm_ct_memzero(kek, sizeof kek); return STM_ENOMEM; }
    rc = stm_hybrid_keygen(plaintext, plaintext + STM_HYBRID_PK_LEN);
    if (rc != STM_OK) {
        stm_ct_memzero(plaintext, PASS_PT_LEN);
        free(plaintext);
        stm_ct_memzero(kek, sizeof kek);
        return rc;
    }

    uint8_t nonce[PASS_NONCE_LEN];
    stm_random_bytes(nonce, sizeof nonce);

    uint8_t *ct_and_tag = calloc(1, PASS_CT_LEN + PASS_TAG_LEN);
    if (!ct_and_tag) {
        stm_ct_memzero(plaintext, PASS_PT_LEN);
        free(plaintext);
        stm_ct_memzero(kek, sizeof kek);
        return STM_ENOMEM;
    }
    size_t ct_len = PASS_CT_LEN + PASS_TAG_LEN;
    rc = stm_aead_encrypt(STM_AEAD_AEGIS256, kek, nonce,
                          PASS_AD_STR, sizeof PASS_AD_STR - 1,
                          plaintext, PASS_PT_LEN,
                          ct_and_tag, &ct_len);
    stm_ct_memzero(kek, sizeof kek);
    if (rc != STM_OK) {
        stm_ct_memzero(plaintext, PASS_PT_LEN);
        free(plaintext);
        free(ct_and_tag);
        return rc;
    }

    /* Assemble the on-disk blob. */
    uint8_t *blob = calloc(1, PASS_FILE_SIZE);
    if (!blob) {
        stm_ct_memzero(plaintext, PASS_PT_LEN);
        free(plaintext);
        free(ct_and_tag);
        return STM_ENOMEM;
    }
    pack_header(blob, &params, nonce);
    memcpy(blob + 72, ct_and_tag, PASS_CT_LEN + PASS_TAG_LEN);

    rc = write_exact(path, blob, PASS_FILE_SIZE);
    stm_ct_memzero(blob, PASS_FILE_SIZE);
    free(blob);
    free(ct_and_tag);

    if (rc != STM_OK) {
        stm_ct_memzero(plaintext, PASS_PT_LEN);
        free(plaintext);
        return rc;
    }

    /* Return the public key to the caller; wipe the secret. */
    memcpy(out_pk, plaintext, STM_HYBRID_PK_LEN);
    stm_ct_memzero(plaintext, PASS_PT_LEN);
    free(plaintext);
    return STM_OK;
}

/* ── open (daemon startup): decrypt hybrid_sk into RAM ──────────────── */

typedef struct pass_ctx {
    uint8_t hybrid_sk[STM_HYBRID_SK_LEN];
    uint8_t hybrid_pk[STM_HYBRID_PK_LEN];
} pass_ctx;

static void build_ad(const uint8_t pool_uuid[16],
                      uint64_t dataset_id, uint64_t key_id,
                      uint8_t out[STM_JANUS_WRAP_AD_LEN])
{
    memcpy(out, pool_uuid, 16);
    for (size_t i = 0; i < 8; i++)
        out[16 + i] = (uint8_t)(dataset_id >> (i * 8));
    for (size_t i = 0; i < 8; i++)
        out[24 + i] = (uint8_t)(key_id    >> (i * 8));
}

static stm_status pass_unwrap(void *ctx,
                                const uint8_t pool_uuid[16],
                                uint64_t dataset_id, uint64_t key_id,
                                const void *wrapped, size_t wrapped_len,
                                void *out_dek, size_t *inout_dek_len)
{
    pass_ctx *p = ctx;
    uint8_t ad[STM_JANUS_WRAP_AD_LEN];
    build_ad(pool_uuid, dataset_id, key_id, ad);
    stm_status rc = stm_hybrid_unwrap(p->hybrid_sk, ad, sizeof ad,
                                        wrapped, wrapped_len,
                                        out_dek, inout_dek_len);
    stm_ct_memzero(ad, sizeof ad);
    return rc;
}

static stm_status pass_wrap(void *ctx,
                              const uint8_t pool_uuid[16],
                              uint64_t dataset_id, uint64_t key_id,
                              const void *dek, size_t dek_len,
                              void *out_wrapped, size_t *inout_wrapped_len)
{
    pass_ctx *p = ctx;
    uint8_t ad[STM_JANUS_WRAP_AD_LEN];
    build_ad(pool_uuid, dataset_id, key_id, ad);
    stm_status rc = stm_hybrid_wrap(p->hybrid_pk, ad, sizeof ad,
                                      dek, dek_len,
                                      out_wrapped, inout_wrapped_len);
    stm_ct_memzero(ad, sizeof ad);
    return rc;
}

static void pass_destroy(void *ctx)
{
    if (!ctx) return;
    pass_ctx *p = ctx;
    stm_ct_memzero(p->hybrid_sk, sizeof p->hybrid_sk);
    stm_ct_memzero(p->hybrid_pk, sizeof p->hybrid_pk);
    free(p);
}

stm_status janus_backend_passphrase_open(const char *state_dir,
                                           const char *passphrase,
                                           janus_backend *out)
{
    if (!state_dir || !passphrase || !out) return STM_EINVAL;
    stm_status rc = stm_crypto_init();
    if (rc != STM_OK) return rc;

    char path[1024];
    if (join_path(path, sizeof path, state_dir, PASS_STATE_FILE) != 0)
        return STM_EINVAL;

    uint8_t *blob = calloc(1, PASS_FILE_SIZE);
    if (!blob) return STM_ENOMEM;
    rc = read_exact(path, blob, PASS_FILE_SIZE);
    if (rc != STM_OK) { free(blob); return rc; }

    stm_argon2id_params params;
    uint8_t nonce[PASS_NONCE_LEN];
    rc = unpack_header(blob, &params, nonce);
    if (rc != STM_OK) { stm_ct_memzero(blob, PASS_FILE_SIZE); free(blob); return rc; }

    uint8_t kek[PASS_KEK_LEN];
    rc = derive_kek(passphrase, &params, kek);
    if (rc != STM_OK) {
        stm_ct_memzero(kek, sizeof kek);
        stm_ct_memzero(blob, PASS_FILE_SIZE);
        free(blob);
        return rc;
    }

    uint8_t *plaintext = calloc(1, PASS_PT_LEN);
    if (!plaintext) {
        stm_ct_memzero(kek, sizeof kek);
        stm_ct_memzero(blob, PASS_FILE_SIZE);
        free(blob);
        return STM_ENOMEM;
    }
    size_t pt_len = PASS_PT_LEN;
    rc = stm_aead_decrypt(STM_AEAD_AEGIS256, kek, nonce,
                          PASS_AD_STR, sizeof PASS_AD_STR - 1,
                          blob + 72, PASS_CT_LEN + PASS_TAG_LEN,
                          plaintext, &pt_len);
    stm_ct_memzero(kek, sizeof kek);
    stm_ct_memzero(blob, PASS_FILE_SIZE);
    free(blob);
    if (rc != STM_OK) {
        stm_ct_memzero(plaintext, PASS_PT_LEN);
        free(plaintext);
        /* Wrong passphrase or tampered state. */
        return rc;
    }

    pass_ctx *c = calloc(1, sizeof *c);
    if (!c) {
        stm_ct_memzero(plaintext, PASS_PT_LEN);
        free(plaintext);
        return STM_ENOMEM;
    }
    memcpy(c->hybrid_pk, plaintext,                     STM_HYBRID_PK_LEN);
    memcpy(c->hybrid_sk, plaintext + STM_HYBRID_PK_LEN, STM_HYBRID_SK_LEN);
    stm_ct_memzero(plaintext, PASS_PT_LEN);
    free(plaintext);

    memset(out, 0, sizeof *out);
    snprintf(out->name, sizeof out->name, "passphrase");
    out->ctx     = c;
    out->unwrap  = pass_unwrap;
    out->wrap    = pass_wrap;
    out->destroy = pass_destroy;
    return STM_OK;
}
