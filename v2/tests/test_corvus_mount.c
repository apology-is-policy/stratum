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
 *   - provision round-trip (TLY-A3-keyslot-wrap chunk 5a): the
 *     production WRAP path `stm_sync_add_dataset_key_corvus` seals a
 *     fresh DEK, the slot persists, and a remount UNWRAPs it back to
 *     the same DEK.
 *
 * The four mount-failure-mode tests inject the CORVUS slot via the
 * stm_sync_keyschema_insert_for_test seam (a canned opaque blob + a
 * canned-DEK fake corvus — simplest way to drive the failure paths).
 * The provision-round-trip test instead uses the real WRAP path; its
 * fake corvus is a toy seal/unseal pair (see FAKE_ENVELOPE_MAGIC). A
 * single verb-aware fake corvus serves both: a wrapped blob that does
 * NOT carry the toy MAGIC falls back to the canned DEK.
 */

#include "tharness.h"

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/corvus_client.h>
#include <stratum/crypto.h>
#include <stratum/dataset.h>
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

/* Toy WRAP envelope used by the provision-round-trip test: corvus
 * WRAP seals a DEK as MAGIC(8) || dek(32) = 40 bytes; UNWRAP
 * recognizes that shape and hands the DEK straight back. The format
 * is opaque to Stratum, so any internally-consistent encoding
 * round-trips. A wrapped blob that does NOT carry the MAGIC (e.g. the
 * 16-byte opaque blob the seam injects for the mount-failure tests)
 * falls back to the canned fc->dek — so one verb-aware fake serves
 * both kinds of test. */
static const uint8_t FAKE_ENVELOPE_MAGIC[8] = {
    'F','A','K','E','W','R','A','P',
};
#define FAKE_ENVELOPE_LEN  (8u + 32u)

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

        /* Build the response. Branch on the verb byte (req[0]):
         *   WRAP (10)   → status + envelope (MAGIC || plaintext DEK
         *                 lifted out of the request).
         *   UNWRAP (4)  → status + 32-byte DEK: extracted from the
         *                 envelope if it carries the MAGIC, else the
         *                 canned fc->dek.
         * A non-OK fc->status short-circuits to a payload-less error
         * frame for either verb. The request layout (both verbs share
         * the first 38 bytes: 4 header + 33 token + 1 ds_len) is per
         * corvus_client.h. */
        uint8_t resp[3u + FAKE_ENVELOPE_LEN];
        size_t  resp_len = 3u;
        resp[0] = (uint8_t)fc->status;
        resp[1] = 0u;
        resp[2] = 0u;

        if (fc->status == STM_CORVUS_STATUS_OK && got >= 38u) {
            uint8_t verb   = req[0];
            uint8_t ds_len = req[37];
            if (verb == STM_CORVUS_VERB_WRAP
                && got >= 48u + (size_t)ds_len + 32u) {
                /* envelope = MAGIC || (plaintext DEK at req[48+dl]). */
                memcpy(resp + 3, FAKE_ENVELOPE_MAGIC, 8);
                memcpy(resp + 3 + 8, req + 48u + ds_len, 32);
                resp[1] = (uint8_t)(FAKE_ENVELOPE_LEN & 0xFFu);
                resp[2] = (uint8_t)((FAKE_ENVELOPE_LEN >> 8) & 0xFFu);
                resp_len = 3u + FAKE_ENVELOPE_LEN;
            } else if (verb == STM_CORVUS_VERB_UNWRAP) {
                uint16_t wlen = 0;
                if (got >= 48u + (size_t)ds_len)
                    wlen = (uint16_t)((uint16_t)req[46u + ds_len] |
                              ((uint16_t)req[47u + ds_len] << 8));
                const uint8_t *wrapped = req + 48u + ds_len;
                if (wlen == FAKE_ENVELOPE_LEN
                    && got >= 48u + (size_t)ds_len + FAKE_ENVELOPE_LEN
                    && memcmp(wrapped, FAKE_ENVELOPE_MAGIC, 8) == 0) {
                    /* Round-trip: hand back the DEK provisioning sealed. */
                    memcpy(resp + 3, wrapped + 8, 32);
                } else {
                    /* Seam-injected opaque blob → canned DEK. */
                    memcpy(resp + 3, fc->dek, 32);
                }
                resp[1] = 32u;
                resp_len = 3u + 32u;
            }
            /* else: malformed/short request — status-only frame. */
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
     * DEK. TLY-A3-keyslot-wrap: a CORVUS slot MUST record a corvus
     * dataset-path (the binding the mount-time UNWRAP sends back); the
     * fake corvus echoes a DEK regardless of the path it receives. */
    static const uint8_t blob[16] = {
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
    };
    static const char ds_path[] = "users/corvus-test";
    STM_ASSERT_OK(stm_sync_keyschema_insert_for_test(
                      s, CORVUS_DATASET_ID, CORVUS_KEY_ID,
                      STM_KS_WRAPPER_CORVUS, blob, sizeof blob,
                      ds_path, sizeof ds_path - 1));
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

STM_TEST(corvus_mount_soft_skips_locked_user_dataset) {
    /* TLY-A5b deferred-unwrap: the long-lived system coordinator boots
     * with NO user session token, so a user-sealed (CORVUS-wrapped) home
     * dataset must mount present-but-LOCKED rather than aborting -- a
     * runtime install-dek fills the DEK in later. Before TLY-A5b this
     * exact configuration hard-failed the mount with STM_EINVAL. The
     * locked dataset's write path returns the distinct STM_ELOCKED (NOT
     * STM_ECORRUPT, which would feed a wedge/integrity policy -- F6). */
    make_tmp("softskip");
    build_pool_with_corvus_slot();   /* CURRENT CORVUS slot at ds=200 */

    /* Reopen with NO corvus cfg. ds=200 is a non-system dataset, so its
     * CURRENT CORVUS slot soft-skips and the mount SUCCEEDS. (A CORVUS
     * CURRENT at the pool/root system datasets would still fail-fast: a
     * sound pool never CORVUS-wraps those -- sync_create wk-seals them --
     * so that leg is a defense-in-depth guard, unconstructible via the
     * create path.) */
    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);

    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));
    STM_ASSERT(s2 != NULL);

    /* The locked dataset has a CURRENT keyslot but no DEK in the RAM
     * map. get_dek is a raw map query -> STM_ENOENT (DEK simply absent). */
    uint8_t dek[32];
    STM_ASSERT_ERR(stm_sync_get_dek(s2, CORVUS_DATASET_ID, CORVUS_KEY_ID,
                                      dek), STM_ENOENT);

    /* A write resolves the dataset's CURRENT DEK first: the keyslot
     * exists (lookup_current succeeds) but its DEK is not installed ->
     * STM_ELOCKED. This is the load-bearing F6 property: locked, not
     * corrupt. */
    uint8_t buf[4096];   /* one STM_UB_SIZE block */
    memset(buf, 0xA5, sizeof buf);
    STM_ASSERT_ERR(stm_sync_write_extent(s2, CORVUS_DATASET_ID,
                                           /*ino=*/1u, /*off=*/0u,
                                           buf, sizeof buf), STM_ELOCKED);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(corvus_install_evict_dek_roundtrip) {
    /* TLY-A5b: the runtime DEK install/evict round-trip. A user-sealed
     * dataset mounts LOCKED (no session token at boot); the coordinator
     * installs the DEK when the user logs in (stm_sync_install_dek with
     * the login-forwarded token) and evicts it at logout. The write-path
     * STM_ELOCKED is the lock-state indicator -- get_dek confirms the DEK
     * is/ isn't in the map. */
    make_tmp("instevict");
    build_pool_with_corvus_slot();   /* CURRENT CORVUS slot at ds=200 */

    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);

    fake_corvus fc;
    fake_corvus_start(&fc, "instevict", STM_CORVUS_STATUS_OK, canned_dek);

    /* Mount with NO corvus cfg -> ds=200 soft-skips, present-but-LOCKED. */
    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    /* Locked: no DEK in the map; a write resolves no CURRENT DEK. */
    uint8_t dek[32];
    STM_ASSERT_ERR(stm_sync_get_dek(s2, CORVUS_DATASET_ID, CORVUS_KEY_ID,
                                      dek), STM_ENOENT);
    uint8_t buf[4096];   /* one STM_UB_SIZE block */
    memset(buf, 0xC3, sizeof buf);
    STM_ASSERT_ERR(stm_sync_write_extent(s2, CORVUS_DATASET_ID, 1u, 0u,
                                           buf, sizeof buf), STM_ELOCKED);

    /* CORVUS-only guard: install/evict on a keyfile-wrapped dataset
     * (root ds=1) is refused before any map mutation. */
    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    STM_ASSERT_ERR(stm_sync_install_dek(s2, /*root*/1u, &cc), STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_evict_dek(s2, /*root*/1u), STM_EINVAL);

    /* install_dek with the session token -> UNWRAPs over the fake corvus
     * and installs the canned DEK. The dataset is now unlocked. */
    STM_ASSERT_OK(stm_sync_install_dek(s2, CORVUS_DATASET_ID, &cc));
    STM_ASSERT_OK(stm_sync_get_dek(s2, CORVUS_DATASET_ID, CORVUS_KEY_ID,
                                     dek));
    STM_ASSERT_MEM_EQ(dek, canned_dek, 32);

    /* Idempotent re-install -> OK, no re-unwrap, no double-insert. */
    STM_ASSERT_OK(stm_sync_install_dek(s2, CORVUS_DATASET_ID, &cc));

    /* Regression: evict_dek must drain the decrypted-extent cache.
     * A fresh CORVUS dataset (real create_child + real WRAP over the
     * fake corvus -- CORVUS_DATASET_ID has a keyschema slot but no
     * dataset-index presence, so extent writes to it ENOENT) is
     * written while unlocked: the write path populates the cache with
     * the plaintext -- the extent need never be READ for its cleartext
     * to become resident. After evict, a read of that extent must be
     * DENIED, not served from RAM past the DEK denial (pre-drain this
     * returned STM_OK + the plaintext). Asserted as "not OK" rather
     * than an exact code: the read path's missing-DEK error is
     * STM_ECORRUPT today (the write path's is STM_ELOCKED -- a
     * recorded alignment seam). */
    {
        uint64_t ds_ev = 0;
        STM_ASSERT_OK(stm_dataset_create_child(stm_sync_dataset_index(s2),
                                                  1u, "evictcache", &ds_ev));
        static const char ev_path[] = "users/evictcache";
        uint64_t ev_kid = 999;
        STM_ASSERT_OK(stm_sync_add_dataset_key_corvus(
                          s2, ds_ev, ev_path, sizeof ev_path - 1, &cc,
                          &ev_kid));
        STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u,
                                              buf, sizeof buf));
        STM_ASSERT_OK(stm_sync_evict_dek(s2, ds_ev));
        uint8_t rout[4096] = {0};
        size_t rgot = 0;
        stm_status rrs = stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                                rout, sizeof rout, &rgot);
        STM_ASSERT(rrs != STM_OK);
    }

    /* evict_dek removes + zeroes the DEK -> the dataset re-locks. */
    STM_ASSERT_OK(stm_sync_evict_dek(s2, CORVUS_DATASET_ID));
    STM_ASSERT_ERR(stm_sync_get_dek(s2, CORVUS_DATASET_ID, CORVUS_KEY_ID,
                                      dek), STM_ENOENT);
    STM_ASSERT_ERR(stm_sync_write_extent(s2, CORVUS_DATASET_ID, 1u, 0u,
                                           buf, sizeof buf), STM_ELOCKED);


    /* Idempotent re-evict -> OK. */
    STM_ASSERT_OK(stm_sync_evict_dek(s2, CORVUS_DATASET_ID));

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
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

/* ────────────────────────────────────────────────────────────────────── */
/* TLY-A3-keyslot-wrap chunk 5a: production WRAP provisioning path.        */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_provision_roundtrip) {
    make_tmp("provision");

    /* One verb-aware fake corvus serves both the provisioning WRAP
     * and the remount UNWRAP. NULL canned DEK — the round-trip path
     * extracts the DEK from the envelope, so no canned DEK is used. */
    fake_corvus fc;
    fake_corvus_start(&fc, "provision", STM_CORVUS_STATUS_OK, NULL);

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };

    /* --- Provision: fresh pool, WRAP-seal a CORVUS dataset key. --- */
    uint8_t provisioned_dek[32];
    {
        stm_bdev *d = open_fresh_device();
        stm_alloc *a = NULL;
        STM_ASSERT_OK(stm_alloc_create(d, POOL_UUID, DEVICE_UUID,
                                          TEST_BOOTSTRAP_BYTES, &a));
        stm_pool *pool = make_test_pool(d);
        stm_sync *s = NULL;
        STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

        static const char ds_path[] = "users/corvus-test";
        uint64_t kid = 999;
        STM_ASSERT_OK(stm_sync_add_dataset_key_corvus(
                          s, CORVUS_DATASET_ID,
                          ds_path, sizeof ds_path - 1, &cc, &kid));
        STM_ASSERT_EQ((long long)kid, 0LL);

        /* The DEK is live in the sync DEK map immediately — the
         * freshly-provisioned dataset is usable without a remount. */
        STM_ASSERT_OK(stm_sync_get_dek(s, CORVUS_DATASET_ID,
                                          CORVUS_KEY_ID, provisioned_dek));

        STM_ASSERT_OK(stm_sync_commit(s));
        stm_sync_close(s);
        stm_alloc_close(a);
        stm_pool_close(pool);
        stm_bdev_close(d);
    }

    /* --- Remount: the persisted CORVUS slot resolves via mount-time
     *     UNWRAP back to the very DEK provisioning generated. --- */
    {
        stm_bdev *d = open_fresh_device();
        stm_alloc *a2 = NULL;
        STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
        stm_pool *pool2 = make_test_pool(d);
        stm_sync *s2 = NULL;
        STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, &cc, &s2));

        uint8_t resolved_dek[32];
        STM_ASSERT_OK(stm_sync_get_dek(s2, CORVUS_DATASET_ID,
                                          CORVUS_KEY_ID, resolved_dek));
        /* WRAP → keyschema slot → mount-time UNWRAP round-trips to the
         * same DEK: the production provisioning path is sound. */
        STM_ASSERT_MEM_EQ(resolved_dek, provisioned_dek, 32);

        stm_sync_close(s2);
        stm_alloc_close(a2);
        stm_pool_close(pool2);
        stm_bdev_close(d);
    }

    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

STM_TEST(corvus_provision_refuses_bad_args) {
    make_tmp("provrefuse");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(d, POOL_UUID, DEVICE_UUID,
                                      TEST_BOOTSTRAP_BYTES, &a));
    stm_pool *pool = make_test_pool(d);
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    /* Every call below fails arg validation BEFORE the lock + WRAP,
     * so socket_path is never dialed. */
    stm_corvus_mount_cfg cc = {
        .socket_path   = "/tmp/stm_cvmnt_unused.sock",
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    stm_corvus_mount_cfg cc_no_token = {
        .socket_path   = "/tmp/stm_cvmnt_unused.sock",
        .session_token = NULL,
        .n_retries     = 0,
    };
    uint64_t kid = 0;

    /* NULL path. */
    STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                       s, CORVUS_DATASET_ID, NULL, 5, &cc, &kid),
                     STM_EINVAL);
    /* Zero-length path — a WRAP must bind a real dataset path. */
    STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                       s, CORVUS_DATASET_ID, "users/x", 0, &cc, &kid),
                     STM_EINVAL);
    /* Oversize path (> STM_KEYSCHEMA_CORVUS_PATH_MAX). */
    {
        char big[STM_KEYSCHEMA_CORVUS_PATH_MAX + 8];
        memset(big, 'a', sizeof big);
        STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                           s, CORVUS_DATASET_ID, big, sizeof big,
                           &cc, &kid), STM_EINVAL);
    }
    /* Missing session token — cannot WRAP. */
    STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                       s, CORVUS_DATASET_ID, "users/x", 7,
                       &cc_no_token, &kid), STM_EINVAL);
    /* ds=0 is the pool metadata key — refused. */
    STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                       s, 0, "users/x", 7, &cc, &kid), STM_EINVAL);
    /* NULL corvus cfg / NULL out param. */
    STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                       s, CORVUS_DATASET_ID, "users/x", 7, NULL, &kid),
                     STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                       s, CORVUS_DATASET_ID, "users/x", 7, &cc, NULL),
                     STM_EINVAL);

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(corvus_provision_refuses_duplicate) {
    make_tmp("provdup");
    fake_corvus fc;
    fake_corvus_start(&fc, "provdup", STM_CORVUS_STATUS_OK, NULL);
    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };

    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL;
    STM_ASSERT_OK(stm_alloc_create(d, POOL_UUID, DEVICE_UUID,
                                      TEST_BOOTSTRAP_BYTES, &a));
    stm_pool *pool = make_test_pool(d);
    stm_sync *s = NULL;
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    static const char ds_path[] = "users/corvus-test";
    uint64_t kid = 0;
    STM_ASSERT_OK(stm_sync_add_dataset_key_corvus(
                      s, CORVUS_DATASET_ID, ds_path, sizeof ds_path - 1,
                      &cc, &kid));
    /* Second add for the same dataset — strictly "new dataset", so
     * refused (the EEXIST gate fires before any WRAP round-trip). */
    STM_ASSERT_ERR(stm_sync_add_dataset_key_corvus(
                       s, CORVUS_DATASET_ID, ds_path, sizeof ds_path - 1,
                       &cc, &kid), STM_EEXIST);

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* R148 P2-2: validate_corvus_path refuses control bytes in the corvus    */
/* dataset path — at the keyschema layer no producer can bypass.          */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(corvus_keyslot_refuses_control_byte_path) {
    make_tmp("ctlbyte");
    stm_bdev *d = open_fresh_device();
    stm_alloc *a = NULL;
    stm_sync  *s = NULL;
    STM_ASSERT_OK(stm_alloc_create(d, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &a));
    stm_pool *pool = make_test_pool(d);
    STM_ASSERT_OK(stm_sync_create(pool, a, make_wk(), NULL, &s));

    static const uint8_t blob[16] = {
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44,
    };
    /* A CORVUS keyslot path carrying a control byte (0x01) must be
     * refused at validate_corvus_path — reached here via the test
     * seam -> stm_keyschema_insert_wrapped, the layer no producer can
     * bypass (R99 line-injection doctrine). The split literal stops
     * \x01 from greedily eating the "bad" hex digits. */
    static const char bad_path[] = "users/\x01" "bad";
    STM_ASSERT_ERR(stm_sync_keyschema_insert_for_test(
                       s, CORVUS_DATASET_ID, CORVUS_KEY_ID,
                       STM_KS_WRAPPER_CORVUS, blob, sizeof blob,
                       bad_path, sizeof bad_path - 1),
                     STM_EINVAL);

    stm_sync_close(s);
    stm_alloc_close(a);
    stm_pool_close(pool);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("corvus_mount")
