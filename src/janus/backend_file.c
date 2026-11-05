/* SPDX-License-Identifier: ISC */
/*
 * File backend — janus reads its hybrid keypair from a stm_keyfile.
 *
 *   see ARCHITECTURE §7.9.3 "file" — intended for automation /
 *   container contexts where interactive passphrase entry isn't
 *   practical. The keyfile IS the wrap key; protect with mode 0600
 *   on trusted storage.
 *
 * The same keyfile material can serve multiple pools — each `unwrap`
 * call passes its own AD (pool_uuid || dataset_id || key_id), so the
 * wrap tag distinguishes between pools correctly even from a shared
 * keyfile. The AD binding was added pre-emptively in R10 P2-2.
 */

#include "backend.h"

#include <stratum/crypto.h>
#include <stratum/keyfile.h>
#include <stratum/types.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct file_ctx {
    stm_hybrid_keys keys;
} file_ctx;

#define STM_JANUS_WRAP_AD_LEN 32u

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

static stm_status file_unwrap(void *ctx,
                                const uint8_t pool_uuid[16],
                                uint64_t dataset_id, uint64_t key_id,
                                const void *wrapped, size_t wrapped_len,
                                void *out_dek, size_t *inout_dek_len)
{
    file_ctx *c = ctx;
    uint8_t ad[STM_JANUS_WRAP_AD_LEN];
    build_ad(pool_uuid, dataset_id, key_id, ad);
    stm_status rc = stm_hybrid_unwrap(c->keys.sk, ad, sizeof ad,
                                        wrapped, wrapped_len,
                                        out_dek, inout_dek_len);
    stm_ct_memzero(ad, sizeof ad);
    return rc;
}

static stm_status file_wrap(void *ctx,
                              const uint8_t pool_uuid[16],
                              uint64_t dataset_id, uint64_t key_id,
                              const void *dek, size_t dek_len,
                              void *out_wrapped, size_t *inout_wrapped_len)
{
    file_ctx *c = ctx;
    uint8_t ad[STM_JANUS_WRAP_AD_LEN];
    build_ad(pool_uuid, dataset_id, key_id, ad);
    stm_status rc = stm_hybrid_wrap(c->keys.pk, ad, sizeof ad,
                                      dek, dek_len,
                                      out_wrapped, inout_wrapped_len);
    stm_ct_memzero(ad, sizeof ad);
    return rc;
}

static void file_destroy(void *ctx)
{
    if (!ctx) return;
    file_ctx *c = ctx;
    stm_hybrid_keys_wipe(&c->keys);
    free(c);
}

stm_status janus_backend_file_open(const char *keyfile_path,
                                     janus_backend *out)
{
    if (!keyfile_path || !out) return STM_EINVAL;
    file_ctx *c = calloc(1, sizeof *c);
    if (!c) return STM_ENOMEM;
    stm_status rc = stm_keyfile_load(keyfile_path, &c->keys);
    if (rc != STM_OK) {
        stm_hybrid_keys_wipe(&c->keys);
        free(c);
        return rc;
    }
    memset(out, 0, sizeof *out);
    snprintf(out->name, sizeof out->name, "file");
    out->ctx     = c;
    out->unwrap  = file_unwrap;
    out->wrap    = file_wrap;
    out->destroy = file_destroy;
    return STM_OK;
}
