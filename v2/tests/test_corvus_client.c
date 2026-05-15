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
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
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

/* ────────────────────────────────────────────────────────────────────── */
/* Transport + retry tests (TLY-A3-impl-2).                                */
/* Fake corvus emitter is a Unix-socket listener in the test process.     */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int          listen_fd;
    char         sock_path[128];
    /* Scripted response per attempt — the harness sends responses[i]
     * to the i-th connection, then closes. If n_responses == 0 the
     * harness reads the request and then closes (immediate-EOF). */
    uint8_t    **responses;
    size_t      *response_lens;
    size_t       n_responses;
    /* Last request bytes received, captured for assertions. */
    uint8_t      last_request[STM_CORVUS_REQUEST_MAX];
    size_t       last_request_len;
    /* Counter — increments on every accept. */
    atomic_int   n_accepts;
} fake_corvus_unwrap;

static void *fake_corvus_unwrap_thread(void *arg)
{
    fake_corvus_unwrap *fc = arg;
    for (;;) {
        int cfd = accept(fc->listen_fd, NULL, NULL);
        if (cfd < 0) return NULL;
        int n = atomic_fetch_add(&fc->n_accepts, 1);

        /* Read the request — encoded length is bounded by the
         * encoder's caps but we read with a fixed cap. */
        size_t got = 0;
        while (got < sizeof fc->last_request) {
            ssize_t r = read(cfd, fc->last_request + got,
                                sizeof fc->last_request - got);
            if (r <= 0) break;
            got += (size_t)r;
            /* Detect end-of-request by reading the 4-byte header
             * then exactly payload_len bytes. */
            if (got >= 4u) {
                uint16_t plen = (uint16_t)((uint16_t)fc->last_request[2] |
                                              ((uint16_t)fc->last_request[3] << 8));
                if (got >= 4u + plen) break;
            }
        }
        fc->last_request_len = got;

        /* Send scripted response for this attempt index. */
        if ((size_t)n < fc->n_responses && fc->responses
            && fc->response_lens[n] > 0) {
            (void)write(cfd, fc->responses[n], fc->response_lens[n]);
        }
        close(cfd);

        /* If we've exhausted the script, exit so the harness joins
         * cleanly. Caller-side dial after this will get ECONNREFUSED. */
        if ((size_t)(n + 1) >= fc->n_responses) {
            /* shutdown the listen socket so subsequent dials don't
             * succeed-then-EOF. The caller's stop() also closes it. */
            return NULL;
        }
    }
}

static int fake_corvus_unwrap_start(fake_corvus_unwrap *fc, const char *tag)
{
    memset(fc, 0, sizeof *fc);
    atomic_init(&fc->n_accepts, 0);
    snprintf(fc->sock_path, sizeof fc->sock_path,
             "/tmp/stm_corvus_unwrap_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(fc->sock_path);

    fc->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fc->listen_fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, fc->sock_path, sizeof addr.sun_path - 1);
    if (bind(fc->listen_fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        close(fc->listen_fd);
        return -1;
    }
    if (listen(fc->listen_fd, 8) < 0) {
        close(fc->listen_fd);
        (void)unlink(fc->sock_path);
        return -1;
    }
    return 0;
}

static void fake_corvus_unwrap_stop(fake_corvus_unwrap *fc)
{
    if (fc->listen_fd >= 0) {
        (void)shutdown(fc->listen_fd, SHUT_RDWR);
        close(fc->listen_fd);
    }
    (void)unlink(fc->sock_path);
}

/* Build a response frame { status, payload }. Caller frees. */
static uint8_t *build_resp(stm_corvus_status status,
                              const uint8_t *payload, size_t payload_len,
                              size_t *out_len)
{
    uint8_t *buf = malloc(3u + payload_len);
    if (!buf) return NULL;
    buf[0] = (uint8_t)status;
    buf[1] = (uint8_t)(payload_len & 0xFFu);
    buf[2] = (uint8_t)((payload_len >> 8) & 0xFFu);
    if (payload_len > 0u && payload) memcpy(buf + 3, payload, payload_len);
    *out_len = 3u + payload_len;
    return buf;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Transport tests.                                                        */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_unwrap_once_happy_path)
{
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "once_happy") == 0);

    /* Scripted response: OK + 32-byte DEK. */
    uint8_t dek_payload[STM_CORVUS_DEK_LEN];
    memset(dek_payload, 0x77, sizeof dek_payload);
    size_t resp_len;
    uint8_t *resp = build_resp(STM_CORVUS_STATUS_OK, dek_payload,
                                   STM_CORVUS_DEK_LEN, &resp_len);
    STM_ASSERT(resp != NULL);
    fc.responses     = &resp;
    fc.response_lens = &resp_len;
    fc.n_responses   = 1;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 0,
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN];
    memset(token, 0xAB, sizeof token);
    token[0] = 's';
    uint8_t wrapped[64];
    memset(wrapped, 0x33, sizeof wrapped);

    stm_corvus_status status = STM_CORVUS_STATUS_INTERNAL_ERROR;
    uint8_t dek[STM_CORVUS_DEK_LEN];
    memset(dek, 0, sizeof dek);
    stm_status rc = stm_corvus_unwrap_once(&t, token, "users/michael", 13,
                                                42, wrapped, sizeof wrapped,
                                                &status, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_OK);
    STM_ASSERT_EQ((int)status, (int)STM_CORVUS_STATUS_OK);
    for (unsigned i = 0; i < STM_CORVUS_DEK_LEN; i++) {
        STM_ASSERT_EQ((int)dek[i], 0x77);
    }

    /* Verify the request the fake received matches what the encoder
     * would build. */
    STM_ASSERT(fc.last_request_len > 0);
    STM_ASSERT_EQ((int)fc.last_request[0], STM_CORVUS_VERB_UNWRAP);
    STM_ASSERT_EQ((int)fc.last_request[1], STM_CORVUS_PROTO_V1);
    /* token immediately after the 4-byte header. */
    for (unsigned i = 0; i < STM_CORVUS_TOKEN_LEN; i++) {
        STM_ASSERT_EQ((int)fc.last_request[4 + i], (int)token[i]);
    }

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
    free(resp);
}

STM_TEST(corvus_unwrap_once_refuses_null_args)
{
    stm_corvus_transport_opts t = { .socket_path = "/tmp/x", .connect_timeout_ms = 100, .io_timeout_ms = 100 };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_corvus_status status = STM_CORVUS_STATUS_OK;

    STM_ASSERT_EQ((int)stm_corvus_unwrap_once(NULL, token, "a", 1, 0, NULL, 0, &status, dek),
                  (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_corvus_unwrap_once(&t, NULL, "a", 1, 0, NULL, 0, &status, dek),
                  (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_corvus_unwrap_once(&t, token, "a", 1, 0, NULL, 0, NULL, dek),
                  (int)STM_EINVAL);
    STM_ASSERT_EQ((int)stm_corvus_unwrap_once(&t, token, "a", 1, 0, NULL, 0, &status, NULL),
                  (int)STM_EINVAL);

    /* Empty socket_path also refused. */
    stm_corvus_transport_opts t_empty = { .socket_path = "", .connect_timeout_ms = 100, .io_timeout_ms = 100 };
    STM_ASSERT_EQ((int)stm_corvus_unwrap_once(&t_empty, token, "a", 1, 0, NULL, 0, &status, dek),
                  (int)STM_EINVAL);
}

STM_TEST(corvus_unwrap_once_dial_refused_is_ebackend)
{
    /* Socket path that doesn't exist → connect ECONNREFUSED/ENOENT
     * → STM_EBACKEND (retry-eligible class). */
    stm_corvus_transport_opts t = {
        .socket_path        = "/tmp/stm_corvus_does_not_exist.sock",
        .connect_timeout_ms = 100,
        .io_timeout_ms      = 100,
        .n_retries          = 0,
    };
    (void)unlink(t.socket_path);
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    token[0] = 's';
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_corvus_status status = STM_CORVUS_STATUS_OK;
    stm_status rc = stm_corvus_unwrap_once(&t, token, "a", 1, 0, NULL, 0,
                                                &status, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_EBACKEND);
}

STM_TEST(corvus_unwrap_once_eof_mid_response_is_ebackend)
{
    /* Fake corvus accepts but sends 0 bytes before closing. The
     * client should see EOF at the 3-byte header read and surface
     * STM_EBACKEND. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "eof_mid") == 0);
    fc.n_responses = 1; /* one accept, zero-byte response → EOF */
    size_t empty_len = 0;
    uint8_t *empty_resp = NULL;
    /* responses[0] = NULL/0 → harness sends nothing before close. */
    fc.responses = &empty_resp;
    fc.response_lens = &empty_len;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 0,
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    token[0] = 's';
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_corvus_status status = STM_CORVUS_STATUS_OK;
    stm_status rc = stm_corvus_unwrap_once(&t, token, "a", 1, 0, NULL, 0,
                                                &status, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_EBACKEND);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
}

STM_TEST(corvus_unwrap_once_malformed_payload_len_is_eprotocol)
{
    /* Send a response with status=OK + payload_len=1 (must be 32 for
     * OK). Client must surface STM_EPROTOCOL after decode. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "malformed") == 0);
    uint8_t bad[4] = { STM_CORVUS_STATUS_OK, 0x01, 0x00, 0xAA };
    size_t bad_len = sizeof bad;
    uint8_t *bad_p = bad;
    fc.responses     = &bad_p;
    fc.response_lens = &bad_len;
    fc.n_responses   = 1;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 0,
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    token[0] = 's';
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_corvus_status status = STM_CORVUS_STATUS_OK;
    stm_status rc = stm_corvus_unwrap_once(&t, token, "a", 1, 0, NULL, 0,
                                                &status, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_EPROTOCOL);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
}

STM_TEST(corvus_unwrap_once_bad_auth_returns_ok_with_status)
{
    /* Single attempt; corvus returns BadAuth. stm_corvus_unwrap_once
     * still returns STM_OK (frame parsed); caller inspects out_status. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "bad_auth") == 0);
    size_t resp_len;
    uint8_t *resp = build_resp(STM_CORVUS_STATUS_BAD_AUTH, NULL, 0, &resp_len);
    STM_ASSERT(resp != NULL);
    fc.responses     = &resp;
    fc.response_lens = &resp_len;
    fc.n_responses   = 1;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 0,
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_corvus_status status = STM_CORVUS_STATUS_OK;
    stm_status rc = stm_corvus_unwrap_once(&t, token, "a", 1, 0, NULL, 0,
                                                &status, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_OK);
    STM_ASSERT_EQ((int)status, (int)STM_CORVUS_STATUS_BAD_AUTH);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
    free(resp);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Retry tests (stm_corvus_unwrap).                                        */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_unwrap_retries_on_internal_then_succeeds)
{
    /* Attempt 1: InternalError (retry-eligible).
     * Attempt 2: OK + DEK. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "retry_int") == 0);

    uint8_t dek_payload[STM_CORVUS_DEK_LEN];
    memset(dek_payload, 0x55, sizeof dek_payload);

    size_t r1_len, r2_len;
    uint8_t *r1 = build_resp(STM_CORVUS_STATUS_INTERNAL_ERROR, NULL, 0, &r1_len);
    uint8_t *r2 = build_resp(STM_CORVUS_STATUS_OK, dek_payload,
                                STM_CORVUS_DEK_LEN, &r2_len);
    STM_ASSERT(r1 && r2);
    uint8_t *resps[2] = { r1, r2 };
    size_t   r_lens[2] = { r1_len, r2_len };
    fc.responses     = resps;
    fc.response_lens = r_lens;
    fc.n_responses   = 2;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 1, /* allow one retry */
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    token[0] = 's';
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_status rc = stm_corvus_unwrap(&t, token, "a", 1, 0, NULL, 0, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_OK);
    for (unsigned i = 0; i < STM_CORVUS_DEK_LEN; i++) {
        STM_ASSERT_EQ((int)dek[i], 0x55);
    }
    STM_ASSERT_EQ(atomic_load(&fc.n_accepts), 2);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
    free(r1);
    free(r2);
}

STM_TEST(corvus_unwrap_no_retry_on_bad_auth)
{
    /* BadAuth is fatal — first attempt's status maps directly to
     * STM_ECORVUSAUTH; no second attempt. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "no_retry_auth") == 0);

    size_t r1_len, r2_len;
    uint8_t *r1 = build_resp(STM_CORVUS_STATUS_BAD_AUTH, NULL, 0, &r1_len);
    /* r2 would be used if the impl wrongly retried — assert it does NOT. */
    uint8_t dek_payload[STM_CORVUS_DEK_LEN];
    memset(dek_payload, 0x77, sizeof dek_payload);
    uint8_t *r2 = build_resp(STM_CORVUS_STATUS_OK, dek_payload,
                                STM_CORVUS_DEK_LEN, &r2_len);
    uint8_t *resps[2] = { r1, r2 };
    size_t   r_lens[2] = { r1_len, r2_len };
    fc.responses     = resps;
    fc.response_lens = r_lens;
    fc.n_responses   = 2;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 3,
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN];
    memset(dek, 0xCC, sizeof dek);
    stm_status rc = stm_corvus_unwrap(&t, token, "a", 1, 0, NULL, 0, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_ECORVUSAUTH);
    /* Only ONE accept should have happened. */
    STM_ASSERT_EQ(atomic_load(&fc.n_accepts), 1);
    /* DEK buffer defensively zeroed. */
    for (unsigned i = 0; i < STM_CORVUS_DEK_LEN; i++) {
        STM_ASSERT_EQ((int)dek[i], 0);
    }

    /* Cleanly stop the harness by accepting a probe connection — the
     * thread is sitting in accept() since we configured n_responses=2.
     * Easiest cleanup: shutdown the listener which wakes accept. */
    fake_corvus_unwrap_stop(&fc);
    pthread_join(tid, NULL);
    free(r1);
    free(r2);
}

STM_TEST(corvus_unwrap_exhausts_retries_then_returns_last)
{
    /* Three responses, all InternalError; n_retries=2 → 3 attempts;
     * the wrapper exhausts and returns STM_ECORVUSINTERNAL. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "exhaust") == 0);
    size_t lens[3];
    uint8_t *resps[3] = {
        build_resp(STM_CORVUS_STATUS_INTERNAL_ERROR, NULL, 0, &lens[0]),
        build_resp(STM_CORVUS_STATUS_INTERNAL_ERROR, NULL, 0, &lens[1]),
        build_resp(STM_CORVUS_STATUS_INTERNAL_ERROR, NULL, 0, &lens[2]),
    };
    STM_ASSERT(resps[0] && resps[1] && resps[2]);
    fc.responses     = resps;
    fc.response_lens = lens;
    fc.n_responses   = 3;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 2, /* 3 attempts total */
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_status rc = stm_corvus_unwrap(&t, token, "a", 1, 0, NULL, 0, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_ECORVUSINTERNAL);
    STM_ASSERT_EQ(atomic_load(&fc.n_accepts), 3);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
    for (int i = 0; i < 3; i++) free(resps[i]);
}

STM_TEST(corvus_unwrap_clamps_n_retries_to_three)
{
    /* n_retries=10 → clamped to 3 → 4 attempts max. We supply 4
     * InternalError responses; the wrapper should exhaust at attempt
     * 4 and return STM_ECORVUSINTERNAL (not loop indefinitely). */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "clamp") == 0);
    size_t lens[4];
    uint8_t *resps[4];
    for (int i = 0; i < 4; i++)
        resps[i] = build_resp(STM_CORVUS_STATUS_INTERNAL_ERROR, NULL, 0, &lens[i]);
    fc.responses     = resps;
    fc.response_lens = lens;
    fc.n_responses   = 4;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 10, /* gets clamped to 3 */
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_status rc = stm_corvus_unwrap(&t, token, "a", 1, 0, NULL, 0, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_ECORVUSINTERNAL);
    STM_ASSERT_EQ(atomic_load(&fc.n_accepts), 4);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
    for (int i = 0; i < 4; i++) free(resps[i]);
}

STM_TEST(corvus_unwrap_retries_on_transport_failure)
{
    /* Attempt 1: dial succeeds, EOF before any bytes → STM_EBACKEND
     *            (transport, retry-eligible).
     * Attempt 2: OK + DEK. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "retry_tport") == 0);

    uint8_t dek_payload[STM_CORVUS_DEK_LEN];
    memset(dek_payload, 0xEE, sizeof dek_payload);
    size_t r1_len = 0, r2_len = 0;
    uint8_t *r1 = NULL; /* zero-byte response */
    uint8_t *r2 = build_resp(STM_CORVUS_STATUS_OK, dek_payload,
                                STM_CORVUS_DEK_LEN, &r2_len);
    STM_ASSERT(r2 != NULL);
    uint8_t *resps[2] = { r1, r2 };
    size_t   r_lens[2] = { r1_len, r2_len };
    fc.responses     = resps;
    fc.response_lens = r_lens;
    fc.n_responses   = 2;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 1,
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_status rc = stm_corvus_unwrap(&t, token, "a", 1, 0, NULL, 0, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_OK);
    for (unsigned i = 0; i < STM_CORVUS_DEK_LEN; i++) {
        STM_ASSERT_EQ((int)dek[i], 0xEE);
    }
    STM_ASSERT_EQ(atomic_load(&fc.n_accepts), 2);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
    free(r2);
}

STM_TEST(corvus_unwrap_zero_retries_single_attempt)
{
    /* n_retries=0 → single attempt; InternalError is the FIRST and
     * ONLY attempt, surfaces immediately as STM_ECORVUSINTERNAL. */
    fake_corvus_unwrap fc;
    STM_ASSERT(fake_corvus_unwrap_start(&fc, "zero_retry") == 0);
    size_t r_len;
    uint8_t *r = build_resp(STM_CORVUS_STATUS_INTERNAL_ERROR, NULL, 0, &r_len);
    STM_ASSERT(r != NULL);
    fc.responses     = &r;
    fc.response_lens = &r_len;
    fc.n_responses   = 1;

    pthread_t tid;
    pthread_create(&tid, NULL, fake_corvus_unwrap_thread, &fc);

    stm_corvus_transport_opts t = {
        .socket_path        = fc.sock_path,
        .connect_timeout_ms = 1000,
        .io_timeout_ms      = 1000,
        .n_retries          = 0,
    };
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_status rc = stm_corvus_unwrap(&t, token, "a", 1, 0, NULL, 0, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_ECORVUSINTERNAL);
    STM_ASSERT_EQ(atomic_load(&fc.n_accepts), 1);

    pthread_join(tid, NULL);
    fake_corvus_unwrap_stop(&fc);
    free(r);
}

STM_TEST(corvus_unwrap_dial_failure_propagates_as_ebackend)
{
    /* No fake corvus running → dial fails on every attempt → after
     * retries-exhausted, surface STM_EBACKEND. */
    stm_corvus_transport_opts t = {
        .socket_path        = "/tmp/stm_corvus_no_listener_at_all.sock",
        .connect_timeout_ms = 50,
        .io_timeout_ms      = 50,
        .n_retries          = 1,
    };
    (void)unlink(t.socket_path);
    uint8_t token[STM_CORVUS_TOKEN_LEN] = { 0 };
    uint8_t dek[STM_CORVUS_DEK_LEN] = { 0 };
    stm_status rc = stm_corvus_unwrap(&t, token, "a", 1, 0, NULL, 0, dek);
    STM_ASSERT_EQ((int)rc, (int)STM_EBACKEND);
}

STM_TEST_MAIN("corvus_client")
