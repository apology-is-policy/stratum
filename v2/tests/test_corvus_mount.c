/* SPDX-License-Identifier: ISC */
/*
 * test_corvus_mount — TLY-A3-keyslot-impl-3b mount-time UNWRAP wiring.
 *
 * Exercises the real stm_sync_open code path (sync_unwrap_cb's
 * STM_KS_WRAPPER_CORVUS branch) against a fake corvus key agent:
 *
 *   - happy path: a pool carrying a CURRENT CORVUS-tagged keyschema
 *     slot mounts, and the slot's DEK resolves over corvus into the
 *     sync DEK map (key_schema.tla::MountResolvesKeyBeforeData — the
 *     resolve happens before stm_sync_open returns a usable handle).
 *   - fail-fast, no corvus configured: the same pool refused at
 *     mount when stm_sync_open gets a NULL corvus cfg.
 *   - fail-fast, corvus rejects: a fatal corvus status (BAD_AUTH)
 *     aborts the mount — never a half-mount.
 *   - fail-fast, corvus unreachable: a transport failure aborts the
 *     mount.
 *
 * The CORVUS slot is injected via the stm_sync_keyschema_insert_for_test
 * seam because the production WRAP path that would produce a genuine
 * corvus-sealed blob does not exist yet (STRATUM-API-V1.md §5.2 specs
 * only the UNWRAP verb — the open bilateral question). The fake corvus
 * maps any UNWRAP request to a canned DEK, which is sufficient to
 * prove the mount-time routing.
 */

#include "tharness.h"

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/corvus_client.h>
#include <stratum/crypto.h>
#include <stratum/keyfile.h>
#include <stratum/keyschema.h>
#include <stratum/pool.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define TEST_DEVICE_BYTES      (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES   (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t POOL_UUID[2]   = { 0xc0c0face, 0xfeed5151 };
static const uint64_t DEVICE_UUID[2] = { 0x9090a0a0, 0xb0b0c0c0 };

/* The corvus user dataset under test. Distinct from the auto-created
 * pool (0,0) + root (1,0) datasets so the CORVUS slot is unambiguous. */
#define CORVUS_DATASET_ID  200u
#define CORVUS_KEY_ID      0u

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_cvmnt_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

static stm_bdev *open_fresh_device(void)
{
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_hybrid_keys g_wk;
static bool            g_wk_initialized = false;

static const stm_hybrid_keys *make_wk(void)
{
    if (!g_wk_initialized) {
        STM_ASSERT_OK(stm_crypto_init());
        STM_ASSERT_OK(stm_hybrid_keygen(g_wk.pk, g_wk.sk));
        g_wk_initialized = true;
    }
    return &g_wk;
}

static stm_pool *make_test_pool(stm_bdev *d)
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    STM_ASSERT(caps != NULL);
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = d;
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    return p;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Fake corvus key agent — perpetual Unix-socket UNWRAP responder.        */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    int               listen_fd;
    char              sock_path[128];
    pthread_t         thread;
    bool              thread_started;
    stm_corvus_status status;       /* status byte to return */
    uint8_t           dek[32];      /* DEK returned when status == OK */
} fake_corvus;

static void *fake_corvus_thread(void *arg)
{
    fake_corvus *fc = arg;
    for (;;) {
        int cfd = accept(fc->listen_fd, NULL, NULL);
        if (cfd < 0) return NULL;   /* listen fd shut down → exit */

        /* Read the full request: 4-byte header (verb, proto,
         * payload_len LE16) then exactly payload_len bytes. */
        uint8_t req[STM_CORVUS_REQUEST_MAX];
        size_t  got = 0;
        while (got < sizeof req) {
            ssize_t r = read(cfd, req + got, sizeof req - got);
            if (r <= 0) break;
            got += (size_t)r;
            if (got >= 4u) {
                uint16_t plen = (uint16_t)((uint16_t)req[2] |
                                              ((uint16_t)req[3] << 8));
                if (got >= 4u + (size_t)plen) break;
            }
        }

        /* Respond. OK → status + payload_len(32) + 32-byte DEK;
         * any error → status + payload_len(0). */
        uint8_t resp[3u + 32u];
        size_t  resp_len;
        resp[0] = (uint8_t)fc->status;
        if (fc->status == STM_CORVUS_STATUS_OK) {
            resp[1] = 32u;
            resp[2] = 0u;
            memcpy(resp + 3, fc->dek, 32);
            resp_len = 3u + 32u;
        } else {
            resp[1] = 0u;
            resp[2] = 0u;
            resp_len = 3u;
        }
        (void)write(cfd, resp, resp_len);
        close(cfd);
    }
}

static void fake_corvus_start(fake_corvus *fc, const char *tag,
                                stm_corvus_status status,
                                const uint8_t dek[32])
{
    memset(fc, 0, sizeof *fc);
    fc->status = status;
    if (dek) memcpy(fc->dek, dek, 32);
    snprintf(fc->sock_path, sizeof fc->sock_path,
             "/tmp/stm_cvmnt_unwrap_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(fc->sock_path);

    fc->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT(fc->listen_fd >= 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, fc->sock_path, sizeof addr.sun_path - 1);
    STM_ASSERT(bind(fc->listen_fd, (struct sockaddr *)&addr,
                       sizeof addr) == 0);
    STM_ASSERT(listen(fc->listen_fd, 8) == 0);
    STM_ASSERT(pthread_create(&fc->thread, NULL,
                                fake_corvus_thread, fc) == 0);
    fc->thread_started = true;
}

static void fake_corvus_stop(fake_corvus *fc)
{
    if (fc->listen_fd >= 0) {
        (void)shutdown(fc->listen_fd, SHUT_RDWR);
        close(fc->listen_fd);
        fc->listen_fd = -1;
    }
    if (fc->thread_started) {
        pthread_join(fc->thread, NULL);
        fc->thread_started = false;
    }
    (void)unlink(fc->sock_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Fixture: build a pool whose keyschema carries a CURRENT CORVUS slot     */
/* for CORVUS_DATASET_ID, persist it, and leave the device on disk.        */
/* ────────────────────────────────────────────────────────────────────── */

static void build_pool_with_corvus_slot(void)
{
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL;
    stm_sync  *s = NULL;
    STM_ASSERT_OK(stm_alloc_create(d, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_pool *pool = make_test_pool(d);
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    /* Inject a CURRENT CORVUS-tagged keyschema slot. The blob is an
     * opaque marker — the fake corvus ignores it and returns a canned
     * DEK. (No production WRAP path exists yet — see header comment.) */
    static const uint8_t blob[16] = {
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
    };
    STM_ASSERT_OK(stm_sync_keyschema_insert_for_test(
                      s, CORVUS_DATASET_ID, CORVUS_KEY_ID,
                      STM_KS_WRAPPER_CORVUS, blob, sizeof blob));
    STM_ASSERT_OK(stm_sync_commit(s));

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(d);
}

/* A fixed 33-byte session token. The fake corvus does not inspect it;
 * a real corvus would validate it. */
static const uint8_t TEST_TOKEN[STM_CORVUS_TOKEN_LEN] = {
    's',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
};

/* ────────────────────────────────────────────────────────────────────── */
/* Tests.                                                                  */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_mount_resolves_corvus_slot) {
    make_tmp("resolve");
    build_pool_with_corvus_slot();

    /* The DEK the fake corvus will hand back for the CORVUS slot. */
    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x40 + i);

    fake_corvus fc;
    fake_corvus_start(&fc, "resolve", STM_CORVUS_STATUS_OK, canned_dek);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, &cc, &s2));

    /* The CORVUS slot's DEK resolved over corvus and is now in the
     * sync DEK map — stm_sync_get_dek serves it transparently (this
     * is also why the send path needs no corvus-specific code). */
    uint8_t got_dek[32];
    STM_ASSERT_OK(stm_sync_get_dek(s2, CORVUS_DATASET_ID,
                                      CORVUS_KEY_ID, got_dek));
    STM_ASSERT_MEM_EQ(got_dek, canned_dek, 32);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

STM_TEST(corvus_mount_fails_fast_without_corvus) {
    make_tmp("nocorvus");
    build_pool_with_corvus_slot();

    /* Reopen with NO corvus cfg — the CURRENT CORVUS slot cannot be
     * unwrapped, so the mount must abort (never a half-mount). */
    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);

    stm_sync *s2 = NULL;
    STM_ASSERT_ERR(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2),
                     STM_EINVAL);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(corvus_mount_fails_fast_on_corvus_reject) {
    make_tmp("badauth");
    build_pool_with_corvus_slot();

    /* corvus rejects the UNWRAP with a fatal status — the mount must
     * abort with the typed corvus error, never a half-mount. */
    fake_corvus fc;
    fake_corvus_start(&fc, "badauth", STM_CORVUS_STATUS_BAD_AUTH, NULL);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    stm_sync *s2 = NULL;
    STM_ASSERT_ERR(stm_sync_open(pool2, a2, make_wk(), NULL, &cc, &s2),
                     STM_ECORVUSAUTH);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

STM_TEST(corvus_mount_fails_fast_on_unreachable_corvus) {
    make_tmp("unreach");
    build_pool_with_corvus_slot();

    /* corvus socket points at a path with nothing listening — the
     * transport fails and the mount aborts. n_retries = 0 keeps the
     * test fast (single attempt, no backoff). */
    char dead_sock[128];
    snprintf(dead_sock, sizeof dead_sock,
             "/tmp/stm_cvmnt_dead_%d.sock", (int)getpid());
    (void)unlink(dead_sock);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);

    stm_corvus_mount_cfg cc = {
        .socket_path        = dead_sock,
        .session_token      = TEST_TOKEN,
        .connect_timeout_ms = 200,
        .io_timeout_ms      = 200,
        .n_retries          = 0,
    };
    stm_sync *s2 = NULL;
    STM_ASSERT_ERR(stm_sync_open(pool2, a2, make_wk(), NULL, &cc, &s2),
                     STM_EBACKEND);
    STM_ASSERT(s2 == NULL);

    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("corvus_mount")
