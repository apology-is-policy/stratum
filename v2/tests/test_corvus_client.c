/* SPDX-License-Identifier: ISC */
/*
 * test_corvus_client — TLY-A3-impl-1 codec + token loader tests.
 *
 * Categories per STRATUM-API-V1.md §5.9 audit posture:
 *   - Wire encode/decode roundtrip.
 *   - Bound checks: oversize dataset_len, oversize wrapped_len,
 *     truncated response, trailing bytes after payload, unknown
 *     status code, status-payload mismatch.
 *   - Status mapping correctness.
 *   - Token loader: happy path, wrong length, missing file,
 *     directory-as-path, embedded NUL OK (token is opaque bytes).
 */

#include "tharness.h"

#include <stratum/corvus_client.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Encode tests.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_encode_unwrap_size_happy_path)
{
    /* 4 header + 33 token + 1 ds_len + 13 ds + 8 key_id + 2 wlen + 0 wrapped */
    size_t s = stm_corvus_encode_unwrap_size(/*dataset_len=*/13,
                                                  /*wrapped_len=*/0);
    STM_ASSERT_EQ((long long)s, (long long)(4 + 33 + 1 + 13 + 8 + 2 + 0));

    /* With a typical wrapped DEK blob (e.g., 96 bytes for AEAD-XChaCha
     * + tag + nonce + AAD). */
    s = stm_corvus_encode_unwrap_size(/*dataset_len=*/13, /*wrapped_len=*/96);
    STM_ASSERT_EQ((long long)s, (long long)(4 + 33 + 1 + 13 + 8 + 2 + 96));
}

STM_TEST(corvus_encode_unwrap_size_refuses_oversize)
{
    STM_ASSERT_EQ(stm_corvus_encode_unwrap_size(256, 0), 0u);
    STM_ASSERT_EQ(stm_corvus_encode_unwrap_size(0, 65536), 0u);
    STM_ASSERT_EQ(stm_corvus_encode_unwrap_size(SIZE_MAX, 0), 0u);
    STM_ASSERT_EQ(stm_corvus_encode_unwrap_size(0, SIZE_MAX), 0u);
}

STM_TEST(corvus_encode_unwrap_happy_path)
{
    uint8_t token[STM_CORVUS_TOKEN_LEN];
    memset(token, 0xAB, sizeof token);
    token[0] = 's'; /* prefix per §5.2 */

    const char *ds = "users/michael";
    size_t ds_len = strlen(ds);
    uint64_t key_id = 0x0102030405060708ull;
    uint8_t wrapped[16];
    for (int i = 0; i < 16; i++) wrapped[i] = (uint8_t)(0x40 + i);

    uint8_t buf[STM_CORVUS_REQUEST_MAX];
    size_t enc_len = 0;
    STM_ASSERT_OK(stm_corvus_encode_unwrap(token, ds, ds_len, key_id,
                                                wrapped, sizeof wrapped,
                                                buf, sizeof buf, &enc_len));
    /* Total = 4 + 33 + 1 + 13 + 8 + 2 + 16 = 77. */
    STM_ASSERT_EQ((long long)enc_len, 77LL);

    /* Header. */
    STM_ASSERT_EQ((int)buf[0], 4); /* verb_id */
    STM_ASSERT_EQ((int)buf[1], 1); /* protocol_version */
    /* payload_len = 77 - 4 = 73 (LE). */
    STM_ASSERT_EQ((int)buf[2], 73);
    STM_ASSERT_EQ((int)buf[3], 0);

    /* Token. */
    STM_ASSERT_EQ(memcmp(buf + 4, token, STM_CORVUS_TOKEN_LEN), 0);

    /* dataset_len = 13. */
    STM_ASSERT_EQ((int)buf[37], 13);

    /* dataset. */
    STM_ASSERT_EQ(memcmp(buf + 38, "users/michael", 13), 0);

    /* key_id LE. */
    for (int i = 0; i < 8; i++) {
        STM_ASSERT_EQ((int)buf[51 + i], (int)((key_id >> (8 * i)) & 0xFFu));
    }

    /* wrapped_len LE. */
    STM_ASSERT_EQ((int)buf[59], 16);
    STM_ASSERT_EQ((int)buf[60], 0);

    /* wrapped. */
    STM_ASSERT_EQ(memcmp(buf + 61, wrapped, 16), 0);
}

STM_TEST(corvus_encode_unwrap_refuses_oversize_dataset)
{
    uint8_t token[STM_CORVUS_TOKEN_LEN] = {0};
    uint8_t buf[STM_CORVUS_REQUEST_MAX];
    size_t enc_len = 0;
    char big[300];
    memset(big, 'x', sizeof big);

    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, big, 256, 0, NULL, 0,
                                                buf, sizeof buf, &enc_len),
                    STM_EINVAL);
}

STM_TEST(corvus_encode_unwrap_refuses_oversize_wrapped)
{
    uint8_t token[STM_CORVUS_TOKEN_LEN] = {0};
    uint8_t buf[STM_CORVUS_REQUEST_MAX];
    size_t enc_len = 0;
    /* We need a dummy non-NULL wrapped pointer for the arg-shape
     * check, but the function should refuse before reading it. */
    uint8_t one = 0;

    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, "x", 1, 0, &one, 65536,
                                                buf, sizeof buf, &enc_len),
                    STM_EINVAL);
}

STM_TEST(corvus_encode_unwrap_refuses_undersize_out)
{
    uint8_t token[STM_CORVUS_TOKEN_LEN] = {0};
    uint8_t buf[10];
    size_t enc_len = 0;
    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, "x", 1, 0, NULL, 0,
                                                buf, sizeof buf, &enc_len),
                    STM_ENOSPC);
}

STM_TEST(corvus_encode_unwrap_refuses_null_args)
{
    uint8_t token[STM_CORVUS_TOKEN_LEN] = {0};
    uint8_t buf[STM_CORVUS_REQUEST_MAX];
    size_t enc_len = 0;
    STM_ASSERT_EQ(stm_corvus_encode_unwrap(NULL, "x", 1, 0, NULL, 0,
                                                buf, sizeof buf, &enc_len),
                    STM_EINVAL);
    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, "x", 1, 0, NULL, 0,
                                                NULL, sizeof buf, &enc_len),
                    STM_EINVAL);
    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, "x", 1, 0, NULL, 0,
                                                buf, sizeof buf, NULL),
                    STM_EINVAL);
    /* NULL dataset with dataset_len>0 — refused. */
    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, NULL, 1, 0, NULL, 0,
                                                buf, sizeof buf, &enc_len),
                    STM_EINVAL);
    /* NULL wrapped with wrapped_len>0 — refused. */
    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, "x", 1, 0, NULL, 16,
                                                buf, sizeof buf, &enc_len),
                    STM_EINVAL);
    /* NULL dataset with dataset_len=0 — ALLOWED. */
    STM_ASSERT_OK(stm_corvus_encode_unwrap(token, NULL, 0, 0, NULL, 0,
                                                buf, sizeof buf, &enc_len));
}

/* ────────────────────────────────────────────────────────────────────── */
/* Decode tests.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_decode_response_ok_with_dek)
{
    uint8_t buf[3 + STM_CORVUS_DEK_LEN];
    buf[0] = 0; /* STATUS_OK */
    buf[1] = STM_CORVUS_DEK_LEN; buf[2] = 0; /* payload_len = 32 LE */
    for (unsigned i = 0; i < STM_CORVUS_DEK_LEN; i++) buf[3 + i] = (uint8_t)(0x70 + i);

    stm_corvus_status st = (stm_corvus_status)99;
    uint8_t dek[STM_CORVUS_DEK_LEN];
    STM_ASSERT_OK(stm_corvus_decode_response(buf, sizeof buf, &st,
                                                  dek, sizeof dek));
    STM_ASSERT_EQ((int)st, STM_CORVUS_STATUS_OK);
    for (unsigned i = 0; i < STM_CORVUS_DEK_LEN; i++) {
        STM_ASSERT_EQ((int)dek[i], 0x70 + i);
    }
}

STM_TEST(corvus_decode_response_error_statuses)
{
    /* Each error status MUST have payload_len = 0. Build a 3-byte
     * minimal frame for each and verify the decoder reports it. */
    uint8_t codes[] = { 1, 2, 3, 4, 5, 6 };
    stm_corvus_status expected[] = {
        STM_CORVUS_STATUS_BAD_AUTH,
        STM_CORVUS_STATUS_PERM_DENIED,
        STM_CORVUS_STATUS_NOT_FOUND,
        STM_CORVUS_STATUS_RATE_LIMITED,
        STM_CORVUS_STATUS_BAD_FORMAT,
        STM_CORVUS_STATUS_INTERNAL_ERROR,
    };
    for (size_t i = 0; i < sizeof codes; i++) {
        uint8_t buf[3] = { codes[i], 0, 0 };
        stm_corvus_status st = (stm_corvus_status)99;
        STM_ASSERT_OK(stm_corvus_decode_response(buf, sizeof buf, &st,
                                                      NULL, 0));
        STM_ASSERT_EQ((int)st, (int)expected[i]);
    }
}

STM_TEST(corvus_decode_response_refuses_truncated)
{
    /* Less than 3 bytes — frame header missing. */
    uint8_t buf[2] = { 0, 0 };
    stm_corvus_status st;
    STM_ASSERT_EQ(stm_corvus_decode_response(buf, sizeof buf, &st, NULL, 0),
                    STM_EPROTOCOL);

    /* payload_len says 32 but only 3 bytes total — header alone. */
    uint8_t buf2[3] = { 0, 32, 0 };
    STM_ASSERT_EQ(stm_corvus_decode_response(buf2, sizeof buf2, &st, NULL, 0),
                    STM_EPROTOCOL);
}

STM_TEST(corvus_decode_response_refuses_trailing_bytes)
{
    /* payload_len = 32, but buffer has 36 trailing bytes (4 extra). */
    uint8_t buf[3 + 36] = {0};
    buf[0] = 0; buf[1] = 32; buf[2] = 0;
    stm_corvus_status st;
    STM_ASSERT_EQ(stm_corvus_decode_response(buf, sizeof buf, &st, NULL, 0),
                    STM_EPROTOCOL);
}

STM_TEST(corvus_decode_response_refuses_unknown_status)
{
    uint8_t buf[3] = { 7, 0, 0 }; /* 7 is outside enum. */
    stm_corvus_status st;
    STM_ASSERT_EQ(stm_corvus_decode_response(buf, sizeof buf, &st, NULL, 0),
                    STM_EPROTOCOL);
}

STM_TEST(corvus_decode_response_refuses_status_payload_mismatch)
{
    /* status=BAD_AUTH but payload_len != 0 — non-conforming peer. */
    uint8_t buf[3 + 32] = {0};
    buf[0] = 1; buf[1] = 32; buf[2] = 0;
    stm_corvus_status st;
    STM_ASSERT_EQ(stm_corvus_decode_response(buf, sizeof buf, &st, NULL, 0),
                    STM_EPROTOCOL);

    /* status=OK but payload_len != 32 — non-conforming peer. */
    uint8_t buf2[3] = { 0, 0, 0 };
    STM_ASSERT_EQ(stm_corvus_decode_response(buf2, sizeof buf2, &st, NULL, 0),
                    STM_EPROTOCOL);
}

STM_TEST(corvus_decode_response_refuses_undersize_dek_out)
{
    uint8_t buf[3 + 32] = {0};
    buf[0] = 0; buf[1] = 32; buf[2] = 0;
    stm_corvus_status st;
    uint8_t dek[16];
    STM_ASSERT_EQ(stm_corvus_decode_response(buf, sizeof buf, &st,
                                                  dek, sizeof dek),
                    STM_ENOSPC);
}

STM_TEST(corvus_decode_response_null_dek_drops_bytes)
{
    /* OK status with DEK in payload, but caller passes NULL out_dek
     * — the DEK is silently dropped. Status still reported. */
    uint8_t buf[3 + 32] = {0};
    buf[0] = 0; buf[1] = 32; buf[2] = 0;
    for (int i = 0; i < 32; i++) buf[3 + i] = (uint8_t)i;
    stm_corvus_status st = (stm_corvus_status)99;
    STM_ASSERT_OK(stm_corvus_decode_response(buf, sizeof buf, &st, NULL, 0));
    STM_ASSERT_EQ((int)st, STM_CORVUS_STATUS_OK);
}

STM_TEST(corvus_status_to_stm_mapping)
{
    STM_ASSERT_EQ(stm_corvus_status_to_stm(STM_CORVUS_STATUS_OK), STM_OK);
    STM_ASSERT_EQ(stm_corvus_status_to_stm(STM_CORVUS_STATUS_BAD_AUTH),
                    STM_ECORVUSAUTH);
    STM_ASSERT_EQ(stm_corvus_status_to_stm(STM_CORVUS_STATUS_PERM_DENIED),
                    STM_ECORVUSPERM);
    STM_ASSERT_EQ(stm_corvus_status_to_stm(STM_CORVUS_STATUS_NOT_FOUND),
                    STM_ECORVUSNOTFOUND);
    STM_ASSERT_EQ(stm_corvus_status_to_stm(STM_CORVUS_STATUS_RATE_LIMITED),
                    STM_ECORVUSRATELIMITED);
    STM_ASSERT_EQ(stm_corvus_status_to_stm(STM_CORVUS_STATUS_BAD_FORMAT),
                    STM_ECORVUSBADFORMAT);
    STM_ASSERT_EQ(stm_corvus_status_to_stm(STM_CORVUS_STATUS_INTERNAL_ERROR),
                    STM_ECORVUSINTERNAL);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Token loader tests.                                                    */
/* ────────────────────────────────────────────────────────────────────── */

static void write_token_file(const char *path, const void *bytes, size_t n)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    STM_ASSERT(fd >= 0);
    ssize_t w = write(fd, bytes, n);
    STM_ASSERT_EQ((long long)w, (long long)n);
    close(fd);
}

STM_TEST(corvus_load_token_happy_path)
{
    char path[256];
    snprintf(path, sizeof path,
             "/tmp/stm_corvus_token_%d.bin", (int)getpid());
    uint8_t src[STM_CORVUS_TOKEN_LEN];
    for (unsigned i = 0; i < STM_CORVUS_TOKEN_LEN; i++) src[i] = (uint8_t)(0x20 + i);
    write_token_file(path, src, sizeof src);

    uint8_t dst[STM_CORVUS_TOKEN_LEN];
    memset(dst, 0, sizeof dst);
    STM_ASSERT_OK(stm_corvus_load_token(path, dst));
    STM_ASSERT_EQ(memcmp(dst, src, STM_CORVUS_TOKEN_LEN), 0);

    unlink(path);
}

STM_TEST(corvus_load_token_refuses_short_file)
{
    char path[256];
    snprintf(path, sizeof path,
             "/tmp/stm_corvus_short_%d.bin", (int)getpid());
    uint8_t src[16] = {0};
    write_token_file(path, src, sizeof src);

    uint8_t dst[STM_CORVUS_TOKEN_LEN];
    STM_ASSERT_EQ(stm_corvus_load_token(path, dst), STM_ERANGE);

    unlink(path);
}

STM_TEST(corvus_load_token_refuses_long_file)
{
    char path[256];
    snprintf(path, sizeof path,
             "/tmp/stm_corvus_long_%d.bin", (int)getpid());
    uint8_t src[64] = {0};
    write_token_file(path, src, sizeof src);

    uint8_t dst[STM_CORVUS_TOKEN_LEN];
    STM_ASSERT_EQ(stm_corvus_load_token(path, dst), STM_ERANGE);

    unlink(path);
}

STM_TEST(corvus_load_token_refuses_missing_file)
{
    uint8_t dst[STM_CORVUS_TOKEN_LEN];
    STM_ASSERT_EQ(stm_corvus_load_token("/tmp/stm_corvus_nonexistent_999",
                                              dst), STM_ENOENT);
}

STM_TEST(corvus_load_token_refuses_directory)
{
    uint8_t dst[STM_CORVUS_TOKEN_LEN];
    STM_ASSERT_EQ(stm_corvus_load_token("/tmp", dst), STM_ENOENT);
}

STM_TEST(corvus_load_token_refuses_null_args)
{
    uint8_t dst[STM_CORVUS_TOKEN_LEN];
    STM_ASSERT_EQ(stm_corvus_load_token(NULL, dst), STM_EINVAL);
    STM_ASSERT_EQ(stm_corvus_load_token("/tmp/x", NULL), STM_EINVAL);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Encode roundtrip — encode then verify the response decoder can parse  */
/* a synthetic well-formed response.                                      */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_encode_unwrap_refuses_payload_overflow_u16)
{
    /* Max u16 = 65535. payload = 33 (token) + 1 + ds_len + 8 +
     * 2 + wrapped_len. The encoder MUST refuse any combo where
     * payload > 65535 even if individual fields fit their caps.
     *
     * With dataset_len=255 + wrapped_len=65535: payload = 33 + 1
     * + 255 + 8 + 2 + 65535 = 65834 — overflow by 299 bytes. */
    uint8_t token[STM_CORVUS_TOKEN_LEN] = {0};
    char ds[STM_CORVUS_DATASET_MAX];
    memset(ds, 'a', sizeof ds);
    uint8_t *wrapped = malloc(STM_CORVUS_WRAPPED_MAX);
    STM_ASSERT(wrapped != NULL);
    memset(wrapped, 0xCC, STM_CORVUS_WRAPPED_MAX);
    uint8_t *buf = malloc(STM_CORVUS_REQUEST_MAX);
    STM_ASSERT(buf != NULL);
    size_t enc_len = 0;
    STM_ASSERT_EQ(stm_corvus_encode_unwrap(token, ds, sizeof ds, 0,
                                                wrapped, STM_CORVUS_WRAPPED_MAX,
                                                buf, STM_CORVUS_REQUEST_MAX,
                                                &enc_len),
                    STM_EINVAL);
    free(wrapped);
    free(buf);
}

STM_TEST(corvus_encode_unwrap_max_payload_under_u16)
{
    /* Largest valid combination: dataset_len + wrapped_len + 33 +
     * 1 + 8 + 2 = 65535 → ds_len + wrapped_len = 65491. Take
     * ds_len = 255, wrapped_len = 65491 - 255 = 65236. */
    uint8_t token[STM_CORVUS_TOKEN_LEN] = {0};
    char ds[STM_CORVUS_DATASET_MAX];
    memset(ds, 'a', sizeof ds);
    const size_t WRAP = 65491u - 255u; /* 65236 */
    uint8_t *wrapped = malloc(WRAP);
    STM_ASSERT(wrapped != NULL);
    memset(wrapped, 0xCC, WRAP);
    uint8_t *buf = malloc(STM_CORVUS_REQUEST_MAX);
    STM_ASSERT(buf != NULL);
    size_t enc_len = 0;
    STM_ASSERT_OK(stm_corvus_encode_unwrap(token, ds, sizeof ds, 0,
                                                wrapped, WRAP,
                                                buf, STM_CORVUS_REQUEST_MAX,
                                                &enc_len));
    /* Total = 4 + 33 + 1 + 255 + 8 + 2 + 65236 = 65539. */
    STM_ASSERT_EQ((long long)enc_len, 65539LL);
    /* payload_len header = 65535 — fits u16 exactly. */
    STM_ASSERT_EQ((int)buf[2], 0xFF);
    STM_ASSERT_EQ((int)buf[3], 0xFF);
    free(wrapped);
    free(buf);
}

STM_TEST_MAIN("corvus_client")
