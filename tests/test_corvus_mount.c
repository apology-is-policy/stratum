/* SPDX-License-Identifier: GPL-3.0-or-later */
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
#include "tsock.h"

#include <stratum/alloc.h>
#include <stratum/cas.h>
#include <stratum/9p.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/hash.h>
#include <stratum/inode.h>
#include <stratum/locks.h>
#include <stratum/block.h>
#include <stratum/block_inject.h>
#include <stratum/corvus_client.h>
#include <stratum/crypto.h>
#include <stratum/dataset.h>
#include <stratum/keyfile.h>
#include <stratum/keyschema.h>
#include <stratum/extent.h>
#include <stratum/extent_testing.h>
#include <stratum/pool.h>
#include <stratum/scrub.h>
#include <stratum/send_recv.h>
#include <stratum/snapshot.h>
#include <stratum/super.h>
#include <stratum/sync.h>
#include <stratum/sync_testing.h>
#include <stratum/types.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
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
    atomic_bool       stop;
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
        int cfd = tsock_accept(fc->listen_fd, &fc->stop);
        if (cfd < 0) return NULL;   /* stopped, or the socket failed */

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
    atomic_init(&fc->stop, false);
    fc->status = status;
    if (dek) memcpy(fc->dek, dek, 32);
    snprintf(fc->sock_path, sizeof fc->sock_path,
             "/tmp/stm_cvmnt_unwrap_%d_%s.sock", (int)getpid(), tag);
    (void)unlink(fc->sock_path);

    fc->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    STM_ASSERT(fc->listen_fd >= 0);
    struct sockaddr_un addr;
    tsock_addr(&addr, fc->sock_path);
    STM_ASSERT(bind(fc->listen_fd, (struct sockaddr *)&addr,
                       sizeof addr) == 0);
    STM_ASSERT(listen(fc->listen_fd, 8) == 0);
    STM_ASSERT(pthread_create(&fc->thread, NULL,
                                fake_corvus_thread, fc) == 0);
    fc->thread_started = true;
}

/* Flag, join, then close (see tsock.h). */
static void fake_corvus_stop(fake_corvus *fc)
{
    if (fc->thread_started) {
        atomic_store_explicit(&fc->stop, true, memory_order_release);
        pthread_join(fc->thread, NULL);
        fc->thread_started = false;
    }
    if (fc->listen_fd >= 0) {
        close(fc->listen_fd);
        fc->listen_fd = -1;
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
    /* Asked whether it is locked, the same key is; a key the pool does not
     * have is not. */
    STM_ASSERT_ERR(stm_sync_get_dek_or_locked(s2, CORVUS_DATASET_ID,
                                              CORVUS_KEY_ID, dek), STM_ELOCKED);
    STM_ASSERT_ERR(stm_sync_get_dek_or_locked(s2, CORVUS_DATASET_ID,
                                              CORVUS_KEY_ID + 1000u, dek),
                   STM_ENOENT);

    /* A write resolves the dataset's CURRENT DEK first: the keyslot
     * exists (lookup_current succeeds) but its DEK is not installed ->
     * STM_ELOCKED. This is the load-bearing F6 property: locked, not
     * corrupt. */
    uint8_t buf[4096];   /* one STM_UB_SIZE block */
    memset(buf, 0xA5, sizeof buf);
    STM_ASSERT_ERR(stm_sync_write_extent(s2, CORVUS_DATASET_ID,
                                           /*ino=*/1u, /*off=*/0u,
                                           buf, sizeof buf), STM_ELOCKED);

    /* A rotation would wrap the dataset's new key with the pool's key, out
     * of its user's seal: refused, the user's key still CURRENT. The root
     * dataset, sealed by the pool's key, rotates. */
    uint64_t nid = 0, oid = 0;
    STM_ASSERT_ERR(stm_sync_rotate_dataset_key(s2, CORVUS_DATASET_ID,
                                               make_wk(), NULL, &nid, &oid),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_sync_get_dek_or_locked(s2, CORVUS_DATASET_ID,
                                              CORVUS_KEY_ID, dek), STM_ELOCKED);
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(s2, 1u, make_wk(), NULL,
                                              &nid, &oid));

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

    /* Re-install proves the new caller even when the key is already live. */
    STM_ASSERT_OK(stm_sync_install_dek(s2, CORVUS_DATASET_ID, &cc));
    fake_corvus_stop(&fc);
    fake_corvus_start(&fc, "instevict", STM_CORVUS_STATUS_BAD_AUTH, NULL);
    STM_ASSERT(stm_sync_install_dek(s2, CORVUS_DATASET_ID, &cc) != STM_OK);
    STM_ASSERT_OK(stm_sync_get_dek(s2, CORVUS_DATASET_ID, CORVUS_KEY_ID, dek));
    STM_ASSERT_MEM_EQ(dek, canned_dek, 32);
    fake_corvus_stop(&fc);
    uint8_t wrong_dek[32] = {0};
    fake_corvus_start(&fc, "instevict", STM_CORVUS_STATUS_OK, wrong_dek);
    STM_ASSERT_ERR(stm_sync_install_dek(s2, CORVUS_DATASET_ID, &cc), STM_EACCES);
    STM_ASSERT_OK(stm_sync_get_dek(s2, CORVUS_DATASET_ID, CORVUS_KEY_ID, dek));
    STM_ASSERT_MEM_EQ(dek, canned_dek, 32);
    fake_corvus_stop(&fc);
    fake_corvus_start(&fc, "instevict", STM_CORVUS_STATUS_OK, canned_dek);

    /* Regression: evict_dek must drain the decrypted-extent cache.
     * A fresh CORVUS dataset (real create_child + real WRAP over the
     * fake corvus -- CORVUS_DATASET_ID has a keyschema slot but no
     * dataset-index presence, so extent writes to it ENOENT) is
     * written while unlocked: the write path populates the cache with
     * the plaintext -- the extent need never be READ for its cleartext
     * to become resident. After evict, a read of that extent must be
     * DENIED, not served from RAM past the DEK denial (pre-drain this
     * returned STM_OK + the plaintext), and denied as locked: the read
     * path's missing key is STM_ELOCKED, as the write path's is. A send
     * of it is refused the same way, not as a retry. */
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
        STM_ASSERT_OK(stm_sync_commit(s2));
        /* Read as a captured tree (the snapshot read, which has no locked
         * fallback for the lock-free branch's answer): served while the key
         * is in, refused as locked once it is out. */
        stm_dataset_entry de_ev;
        STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(s2), ds_ev,
                                         &de_ev));
        uint8_t rout[4096] = {0};
        size_t rgot = 0;
        STM_ASSERT_OK(stm_sync_read_extent_at_snap(
                          s2, ds_ev, de_ev.di_tree_root, de_ev.di_root_gen,
                          de_ev.di_root_csum, 1u, 0u, rout, sizeof rout,
                          &rgot));
        STM_ASSERT_EQ(rgot, sizeof buf);
        STM_ASSERT_MEM_EQ(rout, buf, sizeof buf);
        STM_ASSERT_OK(stm_sync_evict_dek(s2, ds_ev));
        rgot = 0;
        stm_status rrs = stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                                rout, sizeof rout, &rgot);
        STM_ASSERT_ERR(rrs, STM_ELOCKED);
        STM_ASSERT_ERR(stm_sync_read_extent_at_snap(
                           s2, ds_ev, de_ev.di_tree_root, de_ev.di_root_gen,
                           de_ev.di_root_csum, 1u, 0u, rout, sizeof rout,
                           &rgot), STM_ELOCKED);
        stm_send_handle *sh = NULL;
        STM_ASSERT_ERR(stm_send_init(s2, ds_ev, 0u, 0u, &sh), STM_ELOCKED);
        STM_ASSERT(sh == NULL);
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

/* ────────────────────────────────────────────────────────────────────── */
/* RC-3 evict-dek race windows (docs/rc-design.md "RC-3"). The three-    */
/* phase write and the RC-2 unlocked read fetch both open a window       */
/* between "DEK resolved/copied" and "plaintext cached" that             */
/* stm_sync_evict_dek (slot replace -> dcache drain, one s->lock hold)   */
/* can land inside. The populate gates must keep the cleartext out of    */
/* the cache — the CF-5a F1 contract — while the WRITE still indexes     */
/* its record (durable, decryptable-on-reinstall) and the in-flight      */
/* READ still returns its bytes (it resolved before the logout           */
/* completed). Deterministic via the sync_testing.h window hooks.        */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    stm_sync *s;
    uint64_t  ds;
    int       calls;
    int       fired;
} rc3_evict_hook_ctx;

static void rc3_evict_hook(void *arg)
{
    rc3_evict_hook_ctx *c = arg;
    c->calls++;
    if (c->fired) return;
    c->fired = 1;
    STM_ASSERT_OK(stm_sync_evict_dek(c->s, c->ds));
}

/* Shared setup: a fresh CORVUS child dataset with a REAL-wrapped key
 * (the fake's WRAP envelope carries the actual DEK, so a later
 * install_dek round-trips it). Returns the new dataset id. */
static uint64_t rc3_evict_fixture(stm_sync *s2, stm_corvus_mount_cfg *cc,
                                    const char *name, const char *path,
                                    size_t path_len)
{
    uint64_t ds_ev = 0;
    STM_ASSERT_OK(stm_dataset_create_child(stm_sync_dataset_index(s2),
                                              1u, name, &ds_ev));
    uint64_t ev_kid = 0;
    STM_ASSERT_OK(stm_sync_add_dataset_key_corvus(s2, ds_ev, path,
                                                     path_len, cc,
                                                     &ev_kid));
    return ds_ev;
}

STM_TEST(corvus_rc3_write_evict_window) {
    make_tmp("rc3wev");
    build_pool_with_corvus_slot();

    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);
    fake_corvus fc;
    fake_corvus_start(&fc, "rc3wev", STM_CORVUS_STATUS_OK, canned_dek);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    static const char ev_path[] = "users/rc3wev";
    uint64_t ds_ev = rc3_evict_fixture(s2, &cc, "rc3wev", ev_path,
                                         sizeof ev_path - 1);

    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof buf; j++) buf[j] = (uint8_t)(0x5A ^ j);

    /* The logout lands between the write's unlocked Phase 2 and its
     * index-commit epilogue. The write must still SUCCEED — evict
     * removes only the in-RAM DEK slot; the keyschema entry persists,
     * so the epilogue's key-liveness check passes on attempt 1 (no
     * retry: calls == 1) — but its plaintext must NOT go resident
     * past the DEK denial (the populate gate). */
    rc3_evict_hook_ctx hc = { .s = s2, .ds = ds_ev };
    stm_sync_set_write_phase2_hook_for_test(s2, rc3_evict_hook, &hc);
    STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u, buf, sizeof buf));
    stm_sync_set_write_phase2_hook_for_test(s2, NULL, NULL);
    STM_ASSERT_EQ(hc.fired, 1);
    STM_ASSERT_EQ(hc.calls, 1);

    /* Post-evict read: DENIED. Pre-gate, the write's populate landed
     * after the evict's drain and this read was served from RAM. */
    uint8_t rout[4096] = {0};
    size_t  rgot = 0;
    stm_status rrs = stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                             rout, sizeof rout, &rgot);
    STM_ASSERT(rrs != STM_OK);

    /* Re-login: the record WAS indexed and decrypts under the
     * reinstalled DEK — the write survived the mid-flight logout. */
    STM_ASSERT_OK(stm_sync_install_dek(s2, ds_ev, &cc));
    STM_ASSERT_OK(stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                          rout, sizeof rout, &rgot));
    STM_ASSERT_EQ(rgot, sizeof rout);
    STM_ASSERT_MEM_EQ(rout, buf, sizeof buf);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

STM_TEST(corvus_rc3_read_evict_window) {
    make_tmp("rc3rev");
    build_pool_with_corvus_slot();

    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);
    fake_corvus fc;
    fake_corvus_start(&fc, "rc3rev", STM_CORVUS_STATUS_OK, canned_dek);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    static const char ev_path[] = "users/rc3rev";
    uint64_t ds_ev = rc3_evict_fixture(s2, &cc, "rc3rev", ev_path,
                                         sizeof ev_path - 1);

    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof buf; j++) buf[j] = (uint8_t)(0xA7 ^ j);
    STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u, buf, sizeof buf));
    /* Clear the write-populate so the armed read takes the fetch. */
    stm_sync_dcache_drain_for_test(s2);

    /* The RC-2 latent (task #34): the fetch copies the DEK, decrypts,
     * then populates UNLOCKED — the logout (slot remove + drain) lands
     * between the decrypt and the populate. The in-flight read itself
     * is served (it resolved before the logout completed — pre-RC-3
     * parity), but its populate must NOT survive: the post-insert
     * liveness re-check self-removes the entry. */
    rc3_evict_hook_ctx hc = { .s = s2, .ds = ds_ev };
    stm_sync_set_read_prepopulate_hook_for_test(s2, rc3_evict_hook, &hc);
    uint8_t rout[4096] = {0};
    size_t  rgot = 0;
    STM_ASSERT_OK(stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                          rout, sizeof rout, &rgot));
    stm_sync_set_read_prepopulate_hook_for_test(s2, NULL, NULL);
    STM_ASSERT_EQ(hc.fired, 1);
    STM_ASSERT_EQ(rgot, sizeof rout);
    STM_ASSERT_MEM_EQ(rout, buf, sizeof buf);

    /* THE regression: a second read must be DENIED. Pre-fix the stale
     * populate survived the drain and this read returned STM_OK + the
     * plaintext from RAM, past the DEK denial. */
    uint8_t r2[4096] = {0};
    size_t  rg2 = 0;
    stm_status rrs = stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                             r2, sizeof r2, &rg2);
    STM_ASSERT(rrs != STM_OK);
    /* A read of a locked dataset now refuses before the cache, so look in
     * the cache itself: the populate did not survive the logout. */
    size_t cached = 1;
    stm_sync_dcache_stats(s2, NULL, NULL, &cached);
    STM_ASSERT_EQ(cached, 0u);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* RC-6 (#35): the provisional dcache insert. The RC-3 audit-F1          */
/* residual was a THIRD reader probe-hitting the fetch populate inside   */
/* the [insert, self-remove] span after evict_dek returned. RC-6 births  */
/* the entry probe-INVISIBLE and commits-or-kills it with the liveness   */
/* re-check under the same dcache_wlock hold that flips                  */
/* (specs/dcache_provisional.tla). The read_postinsert seam exposes the  */
/* exact [insert, publish] window deterministically.                     */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    stm_sync  *s;
    uint64_t   ds;
    int        fired;
    stm_status inner_rc;             /* the in-window third-party read */
    size_t     inner_got;
    uint8_t    inner_buf[4096];
    uint64_t   hits_before, misses_before;
    uint64_t   hits_after,  misses_after;
} rc6_postinsert_ctx;

/* The third party: a read that STARTS inside the [insert, publish]
 * window — i.e. strictly after any evict the prepopulate hook landed
 * has returned. Runs on the fetching thread (the hook contract: no
 * sync locks held), which is exactly a fresh reader's shape: the
 * fetch path is pinless at the populate, so the re-entrant read's own
 * probe pin is at-outermost. Guarded: the re-entrant read can reach
 * this hook again only via its own successful fetch populate (it
 * either probe-hits pre-fix or fails at the DEK resolve when evicted;
 * with no evict it fetches fully — the guard stops the recursion). */
static void rc6_third_party_hook(void *arg)
{
    rc6_postinsert_ctx *c = arg;
    if (c->fired) return;
    c->fired = 1;
    stm_sync_dcache_stats(c->s, &c->hits_before, &c->misses_before, NULL);
    c->inner_got = 0;
    c->inner_rc = stm_sync_read_extent(c->s, c->ds, 1u, 0u,
                                          c->inner_buf,
                                          sizeof c->inner_buf,
                                          &c->inner_got);
    stm_sync_dcache_stats(c->s, &c->hits_after, &c->misses_after, NULL);
}

STM_TEST(corvus_rc6_read_evict_third_party) {
    make_tmp("rc6tp");
    build_pool_with_corvus_slot();

    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);
    fake_corvus fc;
    fake_corvus_start(&fc, "rc6tp", STM_CORVUS_STATUS_OK, canned_dek);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    static const char ev_path[] = "users/rc6tp";
    uint64_t ds_ev = rc3_evict_fixture(s2, &cc, "rc6tp", ev_path,
                                         sizeof ev_path - 1);

    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof buf; j++) buf[j] = (uint8_t)(0x3C ^ j);
    STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u, buf, sizeof buf));
    stm_sync_dcache_drain_for_test(s2);   /* force the fetch path */

    /* Arm BOTH windows: the prepopulate hook lands the logout BEFORE
     * the insert (so the insert lands after the drain — the F1 setup),
     * and the postinsert hook is the THIRD READER, probing strictly
     * after evict_dek returned, inside the [insert, publish] span. */
    rc3_evict_hook_ctx hc = { .s = s2, .ds = ds_ev };
    rc6_postinsert_ctx pc = { .s = s2, .ds = ds_ev };
    stm_sync_set_read_prepopulate_hook_for_test(s2, rc3_evict_hook, &hc);
    stm_sync_set_read_postinsert_hook_for_test(s2, rc6_third_party_hook,
                                                  &pc);
    uint8_t rout[4096] = {0};
    size_t  rgot = 0;
    STM_ASSERT_OK(stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                          rout, sizeof rout, &rgot));
    stm_sync_set_read_prepopulate_hook_for_test(s2, NULL, NULL);
    stm_sync_set_read_postinsert_hook_for_test(s2, NULL, NULL);
    STM_ASSERT_EQ(hc.fired, 1);
    STM_ASSERT_EQ(pc.fired, 1);

    /* The in-flight outer read is served (it resolved before the
     * logout completed — pre-RC-3 parity, unchanged by RC-6). */
    STM_ASSERT_EQ(rgot, sizeof rout);
    STM_ASSERT_MEM_EQ(rout, buf, sizeof buf);

    /* THE regression (the F1 exact denial): the third-party read ran
     * entirely after evict_dek returned. Pre-RC-6 the just-inserted
     * entry was probe-VISIBLE and this read returned STM_OK + the
     * plaintext from RAM, past the DEK denial. Now the probe skips the
     * provisional entry and the fetch's DEK resolve refuses. */
    STM_ASSERT(pc.inner_rc != STM_OK);

    /* Nothing was left servable either: the publish took the kill arm. */
    uint8_t r2[4096] = {0};
    size_t  rg2 = 0;
    STM_ASSERT(stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                       r2, sizeof r2, &rg2) != STM_OK);
    /* A read of a locked dataset now refuses before the cache, so look in
     * the cache itself: the populate did not survive the logout. */
    size_t cached = 1;
    stm_sync_dcache_stats(s2, NULL, NULL, &cached);
    STM_ASSERT_EQ(cached, 0u);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

STM_TEST(corvus_rc6_read_populate_publish) {
    make_tmp("rc6pp");
    build_pool_with_corvus_slot();

    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);
    fake_corvus fc;
    fake_corvus_start(&fc, "rc6pp", STM_CORVUS_STATUS_OK, canned_dek);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    static const char ev_path[] = "users/rc6pp";
    uint64_t ds_ev = rc3_evict_fixture(s2, &cc, "rc6pp", ev_path,
                                         sizeof ev_path - 1);

    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof buf; j++) buf[j] = (uint8_t)(0xE1 ^ j);
    STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u, buf, sizeof buf));
    stm_sync_dcache_drain_for_test(s2);   /* force the fetch path */

    /* No evict. The in-window third-party read probes while the entry
     * is still PROVISIONAL: it must MISS (its own full fetch — a miss
     * accounted, no hit) and still return the right bytes. Pre-RC-6
     * the entry was already visible here: a HIT. */
    rc6_postinsert_ctx pc = { .s = s2, .ds = ds_ev };
    stm_sync_set_read_postinsert_hook_for_test(s2, rc6_third_party_hook,
                                                  &pc);
    uint8_t rout[4096] = {0};
    size_t  rgot = 0;
    STM_ASSERT_OK(stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                          rout, sizeof rout, &rgot));
    stm_sync_set_read_postinsert_hook_for_test(s2, NULL, NULL);
    STM_ASSERT_EQ(pc.fired, 1);
    STM_ASSERT_EQ(rgot, sizeof rout);
    STM_ASSERT_MEM_EQ(rout, buf, sizeof buf);

    STM_ASSERT_OK(pc.inner_rc);
    STM_ASSERT_EQ(pc.inner_got, sizeof buf);
    STM_ASSERT_MEM_EQ(pc.inner_buf, buf, sizeof buf);
    STM_ASSERT_EQ(pc.hits_after, pc.hits_before);         /* not a hit */
    STM_ASSERT(pc.misses_after > pc.misses_before);       /* a real miss */

    /* The anti-silent-regression pin: the publish must have flipped
     * the entry visible — the next read is a cache HIT. A broken
     * publish would leave every fetch populate invisible: correct
     * bytes, the cache silently dead, and no other test red. */
    uint64_t h0 = 0, m0 = 0, h1 = 0, m1 = 0;
    stm_sync_dcache_stats(s2, &h0, &m0, NULL);
    uint8_t r2[4096] = {0};
    size_t  rg2 = 0;
    STM_ASSERT_OK(stm_sync_read_extent(s2, ds_ev, 1u, 0u,
                                          r2, sizeof r2, &rg2));
    stm_sync_dcache_stats(s2, &h1, &m1, NULL);
    STM_ASSERT_EQ(rg2, sizeof r2);
    STM_ASSERT_MEM_EQ(r2, buf, sizeof buf);
    STM_ASSERT_EQ(h1, h0 + 1);
    STM_ASSERT_EQ(m1, m0);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

/* corvus_rc6_readers_vs_evict_hammer — the real-path runtime witness:
 * N lock-free readers against evict/install cycles. The odd/even phase
 * stamp turns wall-clock "after logout" into a checkable predicate: the
 * evictor bumps phase to ODD only AFTER stm_sync_evict_dek returns and
 * to EVEN before any reinstall begins, so a read that observed the SAME
 * ODD phase on both sides ran entirely inside an evicted-stable window
 * (started causally after the logout — the reader's acquire of the odd
 * value syncs-with the evictor's post-return bump) and MUST fail. */
typedef struct {
    stm_sync         *s;
    uint64_t          ds;
    _Atomic uint64_t *phase;
    _Atomic int      *stop;
    const uint8_t    *expect;        /* 4096 bytes */
    int               violations;
    int               reads;
} rc6_reader_arg;

static void *rc6_reader_main(void *arg)
{
    rc6_reader_arg *a = arg;
    uint8_t out[4096];
    while (!atomic_load(a->stop)) {
        uint64_t p0 = atomic_load(a->phase);
        size_t   got = 0;
        stm_status rc = stm_sync_read_extent(a->s, a->ds, 1u, 0u,
                                                out, sizeof out, &got);
        uint64_t p1 = atomic_load(a->phase);
        a->reads++;
        if (rc == STM_OK) {
            if (got != 4096u || memcmp(out, a->expect, 4096u) != 0)
                a->violations++;     /* wrong bytes: always a bug */
            if (p0 == p1 && (p0 & 1u) != 0u)
                a->violations++;     /* served inside an evicted-stable
                                      * window — the F1 class, live */
        }
    }
    return NULL;
}

STM_TEST(corvus_rc6_readers_vs_evict_hammer) {
    make_tmp("rc6hm");
    build_pool_with_corvus_slot();

    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);
    fake_corvus fc;
    fake_corvus_start(&fc, "rc6hm", STM_CORVUS_STATUS_OK, canned_dek);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    static const char ev_path[] = "users/rc6hm";
    uint64_t ds_ev = rc3_evict_fixture(s2, &cc, "rc6hm", ev_path,
                                         sizeof ev_path - 1);

    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof buf; j++) buf[j] = (uint8_t)(0x99 ^ j);
    STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u, buf, sizeof buf));
    stm_sync_dcache_drain_for_test(s2);   /* start every reader cold */

    _Atomic uint64_t phase = 0;           /* even: installed / installing */
    _Atomic int      stop  = 0;
    enum { RC6_READERS = 4, RC6_CYCLES = 40 };
    rc6_reader_arg ra[RC6_READERS];
    pthread_t      rt[RC6_READERS];
    for (int i = 0; i < RC6_READERS; i++) {
        ra[i] = (rc6_reader_arg){ .s = s2, .ds = ds_ev, .phase = &phase,
                                  .stop = &stop, .expect = buf };
        STM_ASSERT(pthread_create(&rt[i], NULL, rc6_reader_main,
                                  &ra[i]) == 0);
    }

    for (int c = 0; c < RC6_CYCLES; c++) {
        STM_ASSERT_OK(stm_sync_evict_dek(s2, ds_ev));
        atomic_fetch_add(&phase, 1);      /* ODD: evicted AND returned */
        usleep(200);
        atomic_fetch_add(&phase, 1);      /* EVEN: reinstall may begin */
        STM_ASSERT_OK(stm_sync_install_dek(s2, ds_ev, &cc));
        usleep(100);
    }

    atomic_store(&stop, 1);
    int total_reads = 0, total_violations = 0;
    for (int i = 0; i < RC6_READERS; i++) {
        pthread_join(rt[i], NULL);
        total_reads      += ra[i].reads;
        total_violations += ra[i].violations;
    }
    STM_ASSERT(total_reads > 0);
    STM_ASSERT_EQ(total_violations, 0);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("corvus_mount")

/* D7-R4: a logout must not strand buffered writes behind a removed DEK.
 * A later unrelated fsync used to fail ELOCKED (Corvus account creation was
 * the first visible victim). Drive the public filesystem, not sync alone. */
STM_TEST(corvus_logout_flushes_dirty_home_before_key_eviction) {
    make_tmp("dirtylogout");
    char key_path[300];
    snprintf(key_path, sizeof key_path, "%s.key", g_tmp_path);
    unlink(key_path);
    STM_ASSERT_OK(stm_keyfile_generate(key_path));
    stm_fs_format_opts fo = {
        .device_size_bytes = TEST_DEVICE_BYTES,
        .bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES,
        .pool_uuid = {0xc0c0face, 0xfeed5151},
        .device_uuid = {0x9090a0a0, 0xb0b0c0c0},
        .keyfile_path = key_path,
    };
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fo));
    stm_fs_mount_opts mo = {.keyfile_path = key_path};
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mo, &fs));
    fake_corvus fc;
    fake_corvus_start(&fc, "dirtylogout", STM_CORVUS_STATUS_OK, NULL);
    stm_corvus_mount_cfg cc = {.socket_path = fc.sock_path, .session_token = TEST_TOKEN};
    uint64_t ds = 0, ino = 0;
    STM_ASSERT_OK(stm_fs_provision_corvus_dataset(fs, 1, "home", "users/alice", 11,
                                                 1000, 1000, &cc, &ds));
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)"file", 4,
                                    0600, 1000, 1000, &ino));
    uint8_t bytes[4096]; memset(bytes, 0x65, sizeof bytes);
    STM_ASSERT_OK(stm_fs_write(fs, ds, ino, 0, bytes, sizeof bytes));
    STM_ASSERT_OK(stm_fs_evict_dek(fs, ds));
    STM_ASSERT_OK(stm_fs_commit(fs)); // unrelated user's durability barrier
    STM_ASSERT_OK(stm_fs_install_dek(fs, ds, &cc));
    uint8_t got[4096]; size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(fs, ds, ino, 0, got, sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof bytes);
    STM_ASSERT_MEM_EQ(got, bytes, sizeof bytes);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fake_corvus_stop(&fc);
    unlink(g_tmp_path); unlink(key_path);
}

/* T0.91: a clone's own writes go under a key the pool seals, so a clone of a
 * user's dataset would take the user's new data out of the user's seal.
 * Refused with the user logged in, logged out, and after a remount with no
 * session; nothing is minted (no dataset id, key, hold or name). A clone of a
 * pool-keyed sibling, one variable away, is made. */
STM_TEST(corvus_clone_of_a_user_sealed_dataset_is_refused) {
    make_tmp("sealclone");
    char key_path[300];
    snprintf(key_path, sizeof key_path, "%s.key", g_tmp_path);
    unlink(key_path);
    STM_ASSERT_OK(stm_keyfile_generate(key_path));
    stm_fs_format_opts fo = {
        .device_size_bytes = TEST_DEVICE_BYTES,
        .bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES,
        .pool_uuid = {0xc0c0face, 0xfeed5252},
        .device_uuid = {0x9090a0a0, 0xb0b0c0c1},
        .keyfile_path = key_path,
    };
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fo));
    stm_fs_mount_opts mo = {.keyfile_path = key_path};
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mo, &fs));
    if (!fs) return;
    fake_corvus fc;
    fake_corvus_start(&fc, "sealclone", STM_CORVUS_STATUS_OK, NULL);
    stm_corvus_mount_cfg cc = {.socket_path = fc.sock_path,
                               .session_token = TEST_TOKEN};
    uint64_t ds = 0, sib = 0, ino = 0;
    STM_ASSERT_OK(stm_fs_provision_corvus_dataset(fs, 1, "home", "users/alice",
                                                 11, 1000, 1000, &cc, &ds));
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "sib", &sib));
    STM_ASSERT_EQ(sib, ds + 1u);
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)"file", 4,
                                    0600, 1000, 1000, &ino));
    uint8_t bytes[4096];
    memset(bytes, 0x5c, sizeof bytes);
    STM_ASSERT_OK(stm_fs_write(fs, ds, ino, 0, bytes, sizeof bytes));
    STM_ASSERT_OK(stm_fs_commit(fs));

    stm_sync *sync = stm_fs_sync(fs);
    bool sealed = false;
    STM_ASSERT_OK(stm_sync_dataset_key_user_sealed(sync, ds, &sealed));
    STM_ASSERT(sealed);
    STM_ASSERT_OK(stm_sync_dataset_key_user_sealed(sync, sib, &sealed));
    STM_ASSERT(!sealed);
    STM_ASSERT_OK(stm_sync_dataset_key_user_sealed(sync, 1, &sealed));
    STM_ASSERT(!sealed);
    sealed = true;
    STM_ASSERT_OK(stm_sync_dataset_key_user_sealed(sync, ds + 1000u, &sealed));
    STM_ASSERT(!sealed);

    uint64_t snap = 0, ssnap = 0, clone = 77, probe = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, ds, "s", 1, &snap));
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, "c", snap, &clone),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(clone, 0u);
    /* Logged out: the seal is in the keyschema, not in RAM. */
    STM_ASSERT_OK(stm_fs_evict_dek(fs, ds));
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, "c", snap, &clone),
                   STM_ENOTSUPPORTED);
    /* Remounted with no session: the home is locked, still sealed. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mo, &fs));
    if (!fs) { fake_corvus_stop(&fc); return; }
    sync = stm_fs_sync(fs);
    sealed = false;
    STM_ASSERT_OK(stm_sync_dataset_key_user_sealed(sync, ds, &sealed));
    STM_ASSERT(sealed);
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, "c", snap, &clone),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(clone, 0u);

    /* Nothing minted: no such child, no key for the next id, no hold. */
    STM_ASSERT_ERR(stm_fs_lookup_child_dataset(fs, 1, "c", 1, &probe),
                   STM_ENOENT);
    uint8_t dek[32];
    STM_ASSERT_ERR(stm_sync_get_dek(sync, sib + 1u, 0, dek), STM_ENOENT);
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap, NULL));
    /* A pool-keyed sibling's snapshot clones, at the next id. */
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, sib, "t", 1, &ssnap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", ssnap, &clone));
    STM_ASSERT_EQ(clone, sib + 1u);
    STM_ASSERT_OK(stm_fs_lookup_child_dataset(fs, 1, "c", 1, &probe));
    STM_ASSERT_EQ(probe, clone);
    STM_ASSERT_OK(stm_sync_get_dek(sync, clone, 0, dek));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
    unlink(key_path);
}

/* ===================================================================== */
/* T0.87: scrub's second look meets a dataset whose key was evicted      */
/* ===================================================================== */
/* A damaged extent of a user's dataset: scrub's first look resolves its */
/* key and fails on the bytes, so the second look, under s->lock, judges */
/* the record again. A logout between the two evicts the key: the second */
/* look can verify nothing, and that is not damage it may report. The    */
/* control run, no logout, reports the damage.                           */

typedef struct {
    stm_sync *s;
    uint64_t  ds;
    bool      evict;
    int       fired;
    stm_status st;
} scrub_evict_ctx;

static void scrub_evict_hook(void *arg)
{
    scrub_evict_ctx *c = arg;
    if (c->fired++) return;
    c->st = c->evict ? stm_sync_evict_dek(c->s, c->ds) : STM_OK;
}

static void scrub_evict_case(const char *tag, bool evict)
{
    make_tmp(tag);
    build_pool_with_corvus_slot();
    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);
    fake_corvus fc;
    fake_corvus_start(&fc, tag, STM_CORVUS_STATUS_OK, canned_dek);

    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));
    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    static const char ev_path[] = "users/scrubev";
    uint64_t ds_ev = rc3_evict_fixture(s2, &cc, tag, ev_path,
                                         sizeof ev_path - 1);
    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof buf; j++) buf[j] = (uint8_t)(0x3C ^ j);
    STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u, buf, sizeof buf));
    STM_ASSERT_OK(stm_sync_commit(s2));

    stm_extent_record e;
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(s2), ds_ev, 1u,
                                         0u, &e));
    STM_ASSERT_EQ((int)e.n_replicas, 1);
    int fd = open(g_tmp_path, O_WRONLY);
    STM_ASSERT(fd >= 0);
    uint8_t junk[4096];
    memset(junk, 0xEE, sizeof junk);
    STM_ASSERT_EQ((size_t)pwrite(fd, junk, sizeof junk,
                                 (off_t)(stm_paddr_offset(e.paddrs[0]) *
                                         (uint64_t)STM_UB_SIZE)),
                  sizeof junk);
    STM_ASSERT_EQ(close(fd), 0);

    scrub_evict_ctx c = { s2, ds_ev, evict, 0, STM_EINVAL };
    stm_scrub *sc = NULL;
    STM_ASSERT_OK(stm_scrub_create(s2, &sc));
    STM_ASSERT_OK(stm_sync_scrub_install_production_cb(s2, sc));
    stm_sync_set_scrub_verify_hook_for_test(s2, scrub_evict_hook, &c);
    STM_ASSERT_OK(stm_scrub_start(sc));
    stm_scrub_status st;
    for (int i = 0; i < 4096; i++) {
        STM_ASSERT_OK(stm_scrub_step(sc));
        STM_ASSERT_OK(stm_scrub_status_get(sc, &st));
        if (st.state == STM_SCRUB_STATE_COMPLETED) break;
    }
    stm_sync_set_scrub_verify_hook_for_test(s2, NULL, NULL);
    STM_ASSERT_EQ((int)st.state, (int)STM_SCRUB_STATE_COMPLETED);

    /* The premise: the first look met the extent, with its key. */
    STM_ASSERT_EQ(c.fired, 1);
    STM_ASSERT_OK(c.st);
    STM_ASSERT_EQ(st.blocks_repaired, 0u);
    STM_ASSERT_EQ(st.blocks_unrepairable, evict ? 0u : 1u);

    stm_scrub_close(sc);
    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

STM_TEST(corvus_scrub_damage_reported_while_unlocked) {
    scrub_evict_case("scrubctl", false);
}

STM_TEST(corvus_scrub_second_look_after_logout_reports_nothing) {
    scrub_evict_case("scrubev", true);
}

/* ===================================================================== */
/* T0.92: a LOCKED home is refused whole                                  */
/* ===================================================================== */
/* A user's home holds, beside its HOT extents, records the pool's own    */
/* key opens: names, small files (inline), xattrs, symlink targets. Once  */
/* its user logs out, every op on its files answers STM_ELOCKED. A        */
/* pool-keyed sibling written the same way, one variable away, answers.   */

typedef struct {
    uint64_t ds;
    uint64_t small, fresh, big, lnk, dir;
} seal_tree;

typedef struct {
    char        key_path[300];
    stm_fs     *fs;
    fake_corvus fc;
    stm_corvus_mount_cfg cc;
    seal_tree   home, sib;
} seal_pool;

static const char SEAL_SECRET[] = "totp-seed=JBSWY3DPEHPK3PXP";

static void seal_tree_fill(stm_fs *fs, seal_tree *t)
{
    /* "small" as an older pool holds it, in a home too: its bytes inline in
     * the inode (the seam), as they stay until it is rewritten. "fresh" as a
     * home's small file is made now: extent-kind. */
    stm_fs_set_inline_in_sealed_for_test(fs, true);
    STM_ASSERT_OK(stm_fs_create_file(fs, t->ds, 1, (const uint8_t *)"small", 5,
                                    0600, 1000, 1000, &t->small));
    STM_ASSERT_OK(stm_fs_write(fs, t->ds, t->small, 0, SEAL_SECRET,
                               sizeof SEAL_SECRET - 1));
    stm_fs_set_inline_in_sealed_for_test(fs, false);
    STM_ASSERT_OK(stm_fs_setxattr(fs, t->ds, t->small,
                                  (const uint8_t *)"user.k", 6,
                                  (const uint8_t *)"xv", 2, 0, NULL));
    STM_ASSERT_OK(stm_fs_create_file(fs, t->ds, 1, (const uint8_t *)"small2", 6,
                                    0600, 1000, 1000, &t->fresh));
    STM_ASSERT_OK(stm_fs_write(fs, t->ds, t->fresh, 0, SEAL_SECRET,
                               sizeof SEAL_SECRET - 1));
    STM_ASSERT_OK(stm_fs_create_file(fs, t->ds, 1, (const uint8_t *)"big", 3,
                                    0600, 1000, 1000, &t->big));
    uint8_t b[4096];
    memset(b, 0x5a, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, t->ds, t->big, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_symlink(fs, t->ds, 1, (const uint8_t *)"lnk", 3,
                                 (const uint8_t *)"target", 6, 1000, 1000,
                                 &t->lnk));
    STM_ASSERT_OK(stm_fs_mkdir(fs, t->ds, 1, (const uint8_t *)"dir", 3,
                               0700, 1000, 1000, &t->dir));
}

static bool seal_pool_open_sz(seal_pool *sp, const char *tag,
                              uint64_t device_bytes, uint64_t bootstrap_bytes)
{
    memset(sp, 0, sizeof *sp);
    make_tmp(tag);
    snprintf(sp->key_path, sizeof sp->key_path, "%s.key", g_tmp_path);
    unlink(sp->key_path);
    STM_ASSERT_OK(stm_keyfile_generate(sp->key_path));
    stm_fs_format_opts fo = {
        .device_size_bytes = device_bytes,
        .bootstrap_size_bytes = bootstrap_bytes,
        .pool_uuid = {0xc0c0face, 0xfeed5454},
        .device_uuid = {0x9090a0a0, 0xb0b0c0c3},
        .keyfile_path = sp->key_path,
    };
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fo));
    stm_fs_mount_opts mo = {.keyfile_path = sp->key_path};
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mo, &sp->fs));
    if (!sp->fs) return false;
    fake_corvus_start(&sp->fc, tag, STM_CORVUS_STATUS_OK, NULL);
    sp->cc = (stm_corvus_mount_cfg){.socket_path = sp->fc.sock_path,
                                    .session_token = TEST_TOKEN};
    STM_ASSERT_OK(stm_fs_provision_corvus_dataset(sp->fs, 1, "home",
                                                 "users/alice", 11, 1000, 1000,
                                                 &sp->cc, &sp->home.ds));
    STM_ASSERT_OK(stm_fs_create_dataset(sp->fs, 1, "sib", &sp->sib.ds));
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(sp->fs, sp->sib.ds, 0700, 1000,
                                           1000, &r));
    STM_ASSERT_EQ(r, 1u);
    seal_tree_fill(sp->fs, &sp->home);
    seal_tree_fill(sp->fs, &sp->sib);
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    return true;
}

static bool seal_pool_open(seal_pool *sp, const char *tag)
{
    return seal_pool_open_sz(sp, tag, TEST_DEVICE_BYTES, TEST_BOOTSTRAP_BYTES);
}

/* Remount with the pool's key alone: no session. */
static bool seal_pool_remount(seal_pool *sp)
{
    STM_ASSERT_OK(stm_fs_unmount(sp->fs));
    sp->fs = NULL;
    stm_fs_mount_opts mo = {.keyfile_path = sp->key_path};
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mo, &sp->fs));
    return sp->fs != NULL;
}

/* Remount holding the session: the home's key unwraps at mount. */
static bool seal_pool_remount_session(seal_pool *sp)
{
    char tok[340];
    snprintf(tok, sizeof tok, "%s.tok", g_tmp_path);
    int fd = open(tok, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    STM_ASSERT(fd >= 0);
    if (fd < 0) return false;
    ssize_t w = write(fd, TEST_TOKEN, STM_CORVUS_TOKEN_LEN);
    close(fd);
    STM_ASSERT_EQ((long long)w, (long long)STM_CORVUS_TOKEN_LEN);
    STM_ASSERT_OK(stm_fs_unmount(sp->fs));
    sp->fs = NULL;
    stm_fs_mount_opts mo = {.keyfile_path = sp->key_path,
                            .corvus_socket = sp->fc.sock_path,
                            .corvus_session_token_file = tok};
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mo, &sp->fs));
    (void)unlink(tok);
    if (!sp->fs) return false;
    STM_ASSERT(!stm_fs_dataset_locked(sp->fs, sp->home.ds));
    return true;
}

static void seal_pool_close(seal_pool *sp)
{
    if (sp->fs) STM_ASSERT_OK(stm_fs_unmount(sp->fs));
    sp->fs = NULL;
    fake_corvus_stop(&sp->fc);
    unlink(g_tmp_path);
    unlink(sp->key_path);
}

#define SEAL_WANT(expr) do {                                              \
    stm_status r_ = (expr);                                               \
    if (locked) STM_ASSERT_ERR(r_, STM_ELOCKED);                          \
    else        STM_ASSERT_OK(r_);                                        \
} while (0)

/* Every op on t's files: STM_ELOCKED when `locked`, else STM_OK. `h` is a
 * handle to t's "small", made while t answered. */
static void seal_ops(stm_fs *fs, const seal_tree *t,
                     const stm_fs_file_handle *h, bool locked)
{
    const uint64_t ds = t->ds;
    struct stm_inode_value iv;
    uint64_t ino = 0, n_ino = 0, n2_ino = 0, anon = 0;
    uint8_t buf[4096];
    size_t got = 0;
    uint32_t xs = 0;
    size_t xl = 0;
    bool grant = false, replaced = false;
    uint32_t seals = 0;
    uint64_t copied = 0;
    stm_fs_file_handle h2;
    stm_lock_conflict conflict;

    /* Reads. */
    SEAL_WANT(stm_fs_stat(fs, ds, t->small, &iv));
    SEAL_WANT(stm_fs_lookup(fs, ds, 1, (const uint8_t *)"small", 5, &ino));
    memset(buf, 0, sizeof buf);
    SEAL_WANT(stm_fs_read(fs, ds, t->small, 0, buf, sizeof buf, &got));
    if (!locked) {
        STM_ASSERT_EQ(got, sizeof SEAL_SECRET - 1);
        STM_ASSERT_MEM_EQ(buf, SEAL_SECRET, got);
    } else {
        STM_ASSERT_EQ(got, 0u);
    }
    SEAL_WANT(stm_fs_read(fs, ds, t->big, 0, buf, sizeof buf, &got));
    SEAL_WANT(stm_fs_getxattr(fs, ds, t->small, (const uint8_t *)"user.k", 6,
                              buf, sizeof buf, &xs));
    SEAL_WANT(stm_fs_listxattr(fs, ds, t->small, buf, sizeof buf, &xl));
    SEAL_WANT(stm_fs_readlink(fs, ds, t->lnk, buf, sizeof buf, &got));
    {
        uint64_t cursor = 0;
        stm_fs_dirent_entry ents[8];
        size_t ret = 0;
        SEAL_WANT(stm_fs_readdir(fs, ds, 1, 1, 0, &cursor, ents, 8, &ret));
    }
    SEAL_WANT(stm_fs_get_seals(fs, ds, t->small, &seals));
    SEAL_WANT(stm_fs_name_to_handle(fs, ds, 1, (const uint8_t *)"small", 5,
                                    &h2));
    SEAL_WANT(stm_fs_open_by_handle(fs, h, &ino));
    SEAL_WANT(stm_fs_lock_test(fs, ds, t->small, 7u, STM_LOCK_EXCLUSIVE, 0, 1,
                               &grant, &conflict));
    SEAL_WANT(stm_fs_lock(fs, ds, t->small, 7u, STM_LOCK_EXCLUSIVE, 0, 1));
    STM_ASSERT_OK(stm_fs_release_lock_owner(fs, 7u));

    /* Writes. */
    SEAL_WANT(stm_fs_write(fs, ds, t->small, 0, "x", 1));
    memset(buf, 0x6b, sizeof buf);
    SEAL_WANT(stm_fs_write(fs, ds, t->big, 0, buf, sizeof buf));
    SEAL_WANT(stm_fs_truncate(fs, ds, t->big, 4096));
    SEAL_WANT(stm_fs_fallocate(fs, ds, t->big, 0, 4096, 0));
    SEAL_WANT(stm_fs_chmod(fs, ds, t->small, 0600));
    SEAL_WANT(stm_fs_chown(fs, ds, t->small, 1000, 1000));
    SEAL_WANT(stm_fs_utimens(fs, ds, t->small, 1, 0, 2, 0, 3, 0));
    SEAL_WANT(stm_fs_setxattr(fs, ds, t->small, (const uint8_t *)"user.j", 6,
                              (const uint8_t *)"v", 1, 0, &replaced));
    SEAL_WANT(stm_fs_removexattr(fs, ds, t->small,
                                 (const uint8_t *)"user.j", 6));
    SEAL_WANT(stm_fs_fadvise(fs, ds, t->big, 0, 4096, STM_FS_FADV_WILLNEED));

    /* The namespace. */
    SEAL_WANT(stm_fs_create_file(fs, ds, 1, (const uint8_t *)"n", 1, 0600,
                                 1000, 1000, &n_ino));
    SEAL_WANT(stm_fs_create_file(fs, ds, 1, (const uint8_t *)"n2", 2, 0600,
                                 1000, 1000, &n2_ino));
    SEAL_WANT(stm_fs_add_seals(fs, ds, locked ? t->small : n2_ino,
                               STM_FS_SEAL_SEAL));
    SEAL_WANT(stm_fs_mkdir(fs, ds, 1, (const uint8_t *)"d2", 2, 0700, 1000,
                           1000, &ino));
    SEAL_WANT(stm_fs_symlink(fs, ds, 1, (const uint8_t *)"l2", 2,
                             (const uint8_t *)"t", 1, 1000, 1000, &ino));
    SEAL_WANT(stm_fs_link(fs, ds, 1, (const uint8_t *)"small", 5, 1,
                          (const uint8_t *)"hard", 4));
    SEAL_WANT(stm_fs_link_by_ino(fs, ds, t->small, 1,
                                 (const uint8_t *)"hard2", 5));
    SEAL_WANT(stm_fs_rename(fs, ds, 1, (const uint8_t *)"hard", 4, 1,
                            (const uint8_t *)"hard3", 5, 0));
    SEAL_WANT(stm_fs_unlink(fs, ds, 1, (const uint8_t *)"hard3", 5));
    SEAL_WANT(stm_fs_rmdir(fs, ds, 1, (const uint8_t *)"d2", 2));
    SEAL_WANT(stm_fs_create_anon(fs, ds, 0600, 1000, 1000, &anon));
    SEAL_WANT(stm_fs_linkat_anon(fs, ds, locked ? t->small : anon, 1,
                                 (const uint8_t *)"anon", 4));
    SEAL_WANT(stm_fs_reflink(fs, ds, t->big, ds, locked ? t->small : n_ino));
    SEAL_WANT(stm_fs_copy_file_range(fs, ds, t->big, 0, ds,
                                     locked ? t->small : n2_ino, 0, 4096,
                                     &copied));
}

STM_TEST(corvus_locked_home_refuses_every_file_op) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealops")) return;
    stm_fs_file_handle h, hs;
    STM_ASSERT_OK(stm_fs_name_to_handle(sp.fs, sp.home.ds, 1,
                                        (const uint8_t *)"small", 5, &h));
    STM_ASSERT_OK(stm_fs_name_to_handle(sp.fs, sp.sib.ds, 1,
                                        (const uint8_t *)"small", 5, &hs));
    STM_ASSERT(!stm_fs_dataset_locked(sp.fs, sp.home.ds));

    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(sp.fs, sp.home.ds, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));    /* logout */
    STM_ASSERT(stm_fs_dataset_locked(sp.fs, sp.home.ds));
    STM_ASSERT(!stm_fs_dataset_locked(sp.fs, sp.sib.ds));
    STM_ASSERT(!stm_fs_dataset_locked(sp.fs, 1));
    seal_ops(sp.fs, &sp.home, &h, true);
    /* Below the fs, every key lookup passes over the locked slot: no
     * read decrypts and no write encrypts with its empty key. */
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint8_t blk[4096], dek[32];
    size_t got = 0;
    memset(blk, 0x11, sizeof blk);
    STM_ASSERT_ERR(stm_sync_read_extent(sync, sp.home.ds, sp.home.big, 0, blk,
                                        sizeof blk, &got), STM_ELOCKED);
    STM_ASSERT_ERR(stm_sync_write_extent(sync, sp.home.ds, sp.home.big, 0,
                                         blk, sizeof blk), STM_ELOCKED);
    STM_ASSERT_ERR(stm_sync_get_dek(sync, sp.home.ds, 0, dek), STM_ENOENT);
    STM_ASSERT_ERR(stm_sync_get_dek_or_locked(sync, sp.home.ds, 0, dek),
                   STM_ELOCKED);
    stm_send_handle *sh = NULL;
    STM_ASSERT_ERR(stm_send_init(sync, sp.home.ds, 0, snap, &sh),
                   STM_ELOCKED);
    STM_ASSERT(sh == NULL);
    seal_ops(sp.fs, &sp.sib, &hs, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));

    /* Remounted with no session, the home mounts locked. */
    if (!seal_pool_remount(&sp)) { seal_pool_close(&sp); return; }
    STM_ASSERT(stm_fs_dataset_locked(sp.fs, sp.home.ds));
    STM_ASSERT(!stm_fs_dataset_locked(sp.fs, sp.sib.ds));
    seal_ops(sp.fs, &sp.home, &h, true);

    /* Its user logs in: the home answers, with what it held. */
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT(!stm_fs_dataset_locked(sp.fs, sp.home.ds));
    seal_ops(sp.fs, &sp.home, &h, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* A write that passed the check just before its user's logout, and buffers
 * after it, would leave a range only that user's key can drain: every
 * commit of every dataset would then fail. The insert refuses it. */
typedef struct {
    stm_fs  *fs;
    uint64_t ds;
    int      fired;
    stm_status evict_rc;
} seal_admit_ctx;

static void seal_admit_evict(uint64_t ds, uint64_t ino, void *arg)
{
    seal_admit_ctx *c = arg;
    (void)ino;
    if (ds != c->ds || c->fired++ != 0) return;
    c->evict_rc = stm_fs_evict_dek(c->fs, ds);
}

static void seal_admit_leg(seal_pool *sp, uint64_t ino)
{
    seal_admit_ctx c = {sp->fs, sp->home.ds, 0, STM_EINVAL};
    stm_fs_set_write_admitted_hook_for_test(sp->fs, seal_admit_evict, &c);
    uint8_t a[4096];
    memset(a, 0xa5, sizeof a);
    STM_ASSERT_ERR(stm_fs_write(sp->fs, sp->home.ds, ino, 0, a, sizeof a),
                   STM_ELOCKED);
    stm_fs_set_write_admitted_hook_for_test(sp->fs, NULL, NULL);
    STM_ASSERT_EQ(c.fired, 1);
    STM_ASSERT_OK(c.evict_rc);
    STM_ASSERT(stm_fs_dataset_locked(sp->fs, sp->home.ds));
    /* Another user's write commits. */
    uint8_t b[4096];
    memset(b, 0xb6, sizeof b);
    STM_ASSERT_OK(stm_fs_write(sp->fs, sp->sib.ds, sp->sib.big, 0, b,
                               sizeof b));
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
}

STM_TEST(corvus_write_racing_logout_leaves_the_pool_committable) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealrace")) return;
    uint64_t late = 0;
    stm_fs_set_inline_in_sealed_for_test(sp.fs, true);   /* an older file */
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, sp.home.ds, 1,
                                     (const uint8_t *)"late", 4, 0600, 1000,
                                     1000, &late));
    stm_fs_set_inline_in_sealed_for_test(sp.fs, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    {
        struct stm_inode_value liv;
        STM_ASSERT_OK(stm_inode_lookup(stm_sync_inode_index(stm_fs_sync(sp.fs)),
                                       sp.home.ds, late, &liv));
        STM_ASSERT_EQ(liv.si_data_kind, STM_DATA_INLINE);
    }
    /* An empty older inline file's first block: the write cuts the file
     * over to EXTENT, then buffers the block as an extent file's. */
    seal_admit_leg(&sp, late);
    /* An extent file's overwrite: the buffered arm. */
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    seal_admit_leg(&sp, sp.home.big);

    /* The pool unmounts clean, and holds what was written. */
    if (!seal_pool_remount(&sp)) { seal_pool_close(&sp); return; }
    uint8_t got[4096], want[4096];
    size_t n = 0;
    memset(want, 0xb6, sizeof want);
    STM_ASSERT_OK(stm_fs_read(sp.fs, sp.sib.ds, sp.sib.big, 0, got,
                              sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof got);
    STM_ASSERT_MEM_EQ(got, want, sizeof got);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    memset(want, 0x5a, sizeof want);
    STM_ASSERT_OK(stm_fs_read(sp.fs, sp.home.ds, sp.home.big, 0, got,
                              sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof got);
    STM_ASSERT_MEM_EQ(got, want, sizeof got);
    struct stm_inode_value iv;
    STM_ASSERT_OK(stm_fs_stat(sp.fs, sp.home.ds, late, &iv));
    STM_ASSERT_EQ(stm_load_le64(iv.si_size), 0u);
    seal_pool_close(&sp);
}

/* A logout drains its own dataset's buffered writes, and only those: an
 * unflushable range of another dataset does not keep its key in RAM, and
 * an unflushable range of its own does. */
STM_TEST(corvus_logout_drains_only_its_own_dataset) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealdrain")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint8_t dek[32];
    uint8_t a[4096], b[4096];
    memset(a, 0xa7, sizeof a);
    memset(b, 0xc7, sizeof b);

    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, sp.sib.big, 0, b, sizeof b));
    stm_fs_fail_drains_for_test(sp.fs, STM_EIO);
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));
    STM_ASSERT(stm_fs_dataset_locked(sp.fs, sp.home.ds));
    STM_ASSERT_ERR(stm_sync_get_dek_or_locked(sync, sp.home.ds, 0, dek),
                   STM_ELOCKED);

    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.home.ds, sp.home.big, 0, a,
                               sizeof a));
    STM_ASSERT_ERR(stm_fs_evict_dek(sp.fs, sp.home.ds), STM_EIO);
    STM_ASSERT(!stm_fs_dataset_locked(sp.fs, sp.home.ds));
    STM_ASSERT_OK(stm_sync_get_dek(sync, sp.home.ds, 0, dek));

    stm_fs_fail_drains_for_test(sp.fs, STM_OK);
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));
    STM_ASSERT(stm_fs_dataset_locked(sp.fs, sp.home.ds));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));

    if (!seal_pool_remount(&sp)) { seal_pool_close(&sp); return; }
    uint8_t got[4096];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_read(sp.fs, sp.sib.ds, sp.sib.big, 0, got,
                              sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof got);
    STM_ASSERT_MEM_EQ(got, b, sizeof got);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_read(sp.fs, sp.home.ds, sp.home.big, 0, got,
                              sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof got);
    STM_ASSERT_MEM_EQ(got, a, sizeof got);
    seal_pool_close(&sp);
}

/* The cold tier seals its chunks with the pool's key. A home's file never
 * goes there: not by fadvise, a migrate, the policy or a receive. The
 * sibling's file, one variable away, does. */
/* Send `src` whole and receive it into `dst`; the first failing status,
 * and in *failed_type the type of the record it failed on. */
static stm_status seal_send_recv(stm_sync *sync, uint64_t src, uint64_t dst,
                                 uint32_t *failed_type)
{
    *failed_type = 0;
    stm_send_handle *sh = NULL;
    stm_recv_handle *rh = NULL;
    stm_status rc = stm_send_init(sync, src, 0, 0, &sh);
    if (rc != STM_OK) return rc;
    rc = stm_recv_init(sync, dst, &rh);
    if (rc != STM_OK) { stm_send_close(sh); return rc; }
    size_t cap = 1u << 16;
    uint8_t *buf = malloc(cap);
    for (int guard = 0; buf && guard < 4096; guard++) {
        size_t len = 0, need = 0;
        stm_status sn = stm_send_next(sh, buf, cap, &len, &need);
        if (sn == STM_ENOENT) { rc = stm_recv_finish(rh); break; }
        if (sn == STM_ERANGE && need > cap) {
            free(buf);
            cap = need;
            buf = malloc(cap);
            continue;
        }
        if (sn != STM_OK) { rc = sn; break; }
        rc = stm_recv_apply(rh, buf, len);
        if (rc != STM_OK) {
            *failed_type = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8)
                         | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
            break;
        }
    }
    if (!buf) rc = STM_ENOMEM;
    free(buf);
    stm_recv_close(rh);
    stm_send_close(sh);
    return rc;
}

static uint8_t seal_extent_kind(stm_fs *fs, uint64_t ds, uint64_t ino)
{
    stm_extent_record e;
    memset(&e, 0, sizeof e);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(stm_fs_sync(fs)),
                                       ds, ino, 0, &e));
    return (uint8_t)e.kind;
}

STM_TEST(corvus_sealed_home_never_moves_to_the_cold_tier) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealcold")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t home = sp.home.ds, sib = sp.sib.ds;

    STM_ASSERT_EQ(seal_extent_kind(sp.fs, home, sp.home.big),
                  STM_EXTENT_KIND_HOT);
    STM_ASSERT_OK(stm_fs_fadvise(sp.fs, home, sp.home.big, 0, 4096,
                                 STM_FS_FADV_DONTNEED));
    STM_ASSERT_ERR(stm_fs_migrate_to_cold(sp.fs, home, sp.home.big),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_sync_migrate_to_cold(sync, home, sp.home.big),
                   STM_ENOTSUPPORTED);
    stm_fs_migrate_policy_params pp;
    memset(&pp, 0, sizeof pp);
    stm_fs_migrate_policy_stats ps;
    STM_ASSERT_OK(stm_fs_migrate_policy_step(sp.fs, home, &pp, &ps));
    STM_ASSERT_EQ(ps.inos_migrated, 0u);
    STM_ASSERT_OK(ps.last_err);
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, home, sp.home.big),
                  STM_EXTENT_KIND_HOT);

    uint8_t plain[4096];
    memset(plain, 0x3c, sizeof plain);
    stm_blake3_hash hh;
    stm_blake3(plain, sizeof plain, &hh);
    uint64_t rh = 0, rs = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, home, 1, (const uint8_t *)"rcv", 3,
                                     0600, 1000, 1000, &rh));
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, sib, 1, (const uint8_t *)"rcv", 3,
                                     0600, 1000, 1000, &rs));
    STM_ASSERT_ERR(stm_sync_recv_cold_extent(sync, home, rh, 0, sizeof plain,
                                             hh.bytes, plain, sizeof plain),
                   STM_ENOTSUPPORTED);
    /* The control, then a reference to the chunk it interned. */
    STM_ASSERT_OK(stm_sync_recv_cold_extent(sync, sib, rs, 0, sizeof plain,
                                            hh.bytes, plain, sizeof plain));
    STM_ASSERT_ERR(stm_sync_recv_cold_extent_ref(sync, home, rh, 0,
                                                 sizeof plain, hh.bytes),
                   STM_ENOTSUPPORTED);
    uint64_t rs2 = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, sib, 1, (const uint8_t *)"rcv2", 4,
                                     0600, 1000, 1000, &rs2));
    STM_ASSERT_OK(stm_sync_recv_cold_extent_ref(sync, sib, rs2, 0,
                                                sizeof plain, hh.bytes));
    STM_ASSERT_OK(stm_fs_fadvise(sp.fs, sib, sp.sib.big, 0, 4096,
                                 STM_FS_FADV_DONTNEED));
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sib, sp.sib.big),
                  STM_EXTENT_KIND_COLD);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));

    /* A stream with a cold file, received into the home, stops at its
     * first CHUNK record, before the chunk lands; into a pool-keyed
     * dataset it goes through. */
    uint64_t sib2 = 0, r2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(sp.fs, 1, "sib2", &sib2));
    STM_ASSERT_OK(stm_fs_init_dataset_root(sp.fs, sib2, 0700, 1000, 1000, &r2));
    uint32_t failed_type = 0;
    STM_ASSERT_ERR(seal_send_recv(sync, sib, home, &failed_type),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(failed_type, (uint32_t)STM_SEND_REC_CHUNK);
    STM_ASSERT_OK(seal_send_recv(sync, sib, sib2, &failed_type));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));

    /* Logged out, and remounted with no session, the home's file reads
     * nothing; the sibling's cold file reads. */
    uint8_t got[4096];
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, home));
    STM_ASSERT_ERR(stm_fs_read(sp.fs, home, sp.home.big, 0, got, sizeof got,
                               &n), STM_ELOCKED);
    if (!seal_pool_remount(&sp)) { seal_pool_close(&sp); return; }
    STM_ASSERT_ERR(stm_fs_read(sp.fs, home, sp.home.big, 0, got, sizeof got,
                               &n), STM_ELOCKED);
    STM_ASSERT_OK(stm_fs_read(sp.fs, sib, sp.sib.big, 0, got, sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof got);
    seal_pool_close(&sp);
}

/* A pool-keyed dataset under a home would hold that user's tree outside the
 * seal. Refused, made directly or as a clone, logged in or out; nothing is
 * minted. Under the sibling, both are made. */
/* A pool written before the cold tier refused sealed data may hold a home's
 * file there, under the pool's key; the seam builds one, the home's extent
 * files all cold, so a send holds no key that could refuse it. Locked, no
 * path serves it: the live read, the snapshot read, a send. The sibling's cold
 * file, one variable away, answers each; logged in, the home's reads. */
STM_TEST(corvus_legacy_cold_file_of_a_locked_home_is_served_by_no_path) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealleg")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    for (int i = 0; i < 2; i++)
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->big));
    /* The home's "small2" is an extent file (the sibling's is inline). */
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.home.ds, sp.home.fresh));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    for (int i = 0; i < 2; i++)
        STM_ASSERT_EQ(seal_extent_kind(sp.fs, ts[i]->ds, ts[i]->big),
                      STM_EXTENT_KIND_COLD);
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.fresh),
                  STM_EXTENT_KIND_COLD);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));    /* logout */

    uint8_t want[4096], got[4096];
    memset(want, 0x5a, sizeof want);
    for (int i = 0; i < 2; i++) {
        bool locked = (i == 0);
        seal_tree *t = ts[i];
        stm_dataset_entry de;
        STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(sync), t->ds,
                                         &de));
        size_t n = 0;
        memset(got, 0, sizeof got);
        stm_status r1 = stm_sync_read_extent(sync, t->ds, t->big, 0, got,
                                             sizeof got, &n);
        stm_status r2 = stm_sync_read_extent_at_snap(
            sync, t->ds, de.di_tree_root, de.di_root_gen, de.di_root_csum,
            t->big, 0, got, sizeof got, &n);
        stm_send_handle *sh = NULL;
        stm_status r3 = stm_send_init(sync, t->ds, 0, 0, &sh);
        if (sh) stm_send_close(sh);
        if (locked) {
            STM_ASSERT_ERR(r1, STM_ELOCKED);
            STM_ASSERT_ERR(r2, STM_ELOCKED);
            STM_ASSERT_ERR(r3, STM_ELOCKED);
            STM_ASSERT(sh == NULL);
            STM_ASSERT(memcmp(got, want, sizeof got) != 0);
        } else {
            STM_ASSERT_OK(r1);
            STM_ASSERT_OK(r2);
            STM_ASSERT_OK(r3);
            STM_ASSERT(memcmp(got, want, sizeof got) == 0);
        }
    }

    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    size_t n = 0;
    memset(got, 0, sizeof got);
    STM_ASSERT_OK(stm_sync_read_extent(sync, sp.home.ds, sp.home.big, 0, got,
                                       sizeof got, &n));
    STM_ASSERT(memcmp(got, want, sizeof got) == 0);
    seal_pool_close(&sp);
}

STM_TEST(corvus_pool_keyed_child_of_a_sealed_home_is_refused) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealkid")) return;
    const uint64_t home = sp.home.ds, sib = sp.sib.ds;
    uint64_t snap = 0, id = 77, probe = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(sp.fs, sib, "s", 1, &snap));

    STM_ASSERT_ERR(stm_fs_create_dataset(sp.fs, home, "kid", &id),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_fs_create_clone(sp.fs, home, "kc", snap, &id),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(id, 0u);
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, home));
    STM_ASSERT_ERR(stm_fs_create_dataset(sp.fs, home, "kid", &id),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_fs_create_clone(sp.fs, home, "kc", snap, &id),
                   STM_ENOTSUPPORTED);
    STM_ASSERT_ERR(stm_fs_lookup_child_dataset(sp.fs, home, "kid", 3, &probe),
                   STM_ENOENT);
    STM_ASSERT_ERR(stm_fs_lookup_child_dataset(sp.fs, home, "kc", 2, &probe),
                   STM_ENOENT);
    /* No id was spent: the next dataset is the sibling's successor. */
    STM_ASSERT_OK(stm_fs_create_dataset(sp.fs, sib, "kid", &id));
    STM_ASSERT_EQ(id, sib + 1u);
    STM_ASSERT_OK(stm_fs_create_clone(sp.fs, sib, "kc", snap, &id));
    STM_ASSERT_EQ(id, sib + 2u);
    seal_pool_close(&sp);
}

/* The 9P server's `ds:<name>` attach: a locked home is refused, and a fid
 * attached before the logout reads nothing after it. Both answer EACCES. */
static void seal_p9_pack_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void seal_p9_pack_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t seal_p9_load_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint32_t seal_p9_finish(uint8_t *req, uint8_t *p, uint8_t type,
                               uint16_t tag)
{
    uint32_t sz = (uint32_t)(p - req);
    seal_p9_pack_u32(req, sz);
    req[4] = type;
    seal_p9_pack_u16(req + 5, tag);
    return sz;
}

/* Tversion, then Tattach of `aname` at fid 100; the reply's type, and the
 * Rlerror ecode in *ecode. */
static uint8_t seal_p9_attach(stm_9p_server *s, const char *aname,
                              uint32_t *ecode)
{
    uint8_t req[256], resp[256];
    uint32_t rlen = 0;
    uint8_t *p = req + 7;
    seal_p9_pack_u32(p, STM_9P_MSIZE_DEFAULT); p += 4;
    seal_p9_pack_u16(p, 8); p += 2;
    memcpy(p, "9P2000.L", 8); p += 8;
    uint32_t sz = seal_p9_finish(req, p, STM_9P_TVERSION, STM_9P_NOTAG);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RVERSION);
    p = req + 7;
    seal_p9_pack_u32(p, 100u); p += 4;
    seal_p9_pack_u32(p, STM_9P_NOFID); p += 4;
    seal_p9_pack_u16(p, 0); p += 2;
    uint16_t alen = (uint16_t)strlen(aname);
    seal_p9_pack_u16(p, alen); p += 2;
    memcpy(p, aname, alen); p += alen;
    seal_p9_pack_u32(p, (uint32_t)-1); p += 4;
    sz = seal_p9_finish(req, p, STM_9P_TATTACH, 1);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    *ecode = resp[4] == STM_9P_RLERROR ? seal_p9_load_u32(resp + 7) : 0u;
    return resp[4];
}

/* Tgetattr on fid 100; the reply's type, and the Rlerror ecode. */
static uint8_t seal_p9_getattr(stm_9p_server *s, uint32_t *ecode)
{
    uint8_t req[64], resp[512];
    uint32_t rlen = 0;
    uint8_t *p = req + 7;
    seal_p9_pack_u32(p, 100u); p += 4;
    seal_p9_pack_u32(p, (uint32_t)STM_9P_GETATTR_INO); p += 4;
    seal_p9_pack_u32(p, 0); p += 4;
    uint32_t sz = seal_p9_finish(req, p, STM_9P_TGETATTR, 2);
    STM_ASSERT_OK(stm_9p_server_handle(s, req, sz, resp, sizeof resp, &rlen));
    *ecode = resp[4] == STM_9P_RLERROR ? seal_p9_load_u32(resp + 7) : 0u;
    return resp[4];
}

static stm_9p_server *seal_p9_server(stm_fs *fs)
{
    stm_9p_server *s = NULL;
    STM_ASSERT_OK(stm_9p_server_create(fs, 1u, 0, 0, STM_9P_MSIZE_DEFAULT,
                                       &s));
    return s;
}

STM_TEST(corvus_9p_attach_of_a_locked_home_is_refused) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealp9")) return;
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(sp.fs, 1, 0755, 0, 0, &r));
    uint32_t ec = 0;

    stm_9p_server *before = seal_p9_server(sp.fs);
    STM_ASSERT_EQ(seal_p9_attach(before, "ds:home", &ec), STM_9P_RATTACH);
    STM_ASSERT_EQ(seal_p9_getattr(before, &ec), STM_9P_RGETATTR);

    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));     /* logout */
    STM_ASSERT_EQ(seal_p9_getattr(before, &ec), STM_9P_RLERROR);
    STM_ASSERT_EQ(ec, STM_9P_ECODE_EACCES);
    stm_9p_server_destroy(before);

    stm_9p_server *after = seal_p9_server(sp.fs);
    STM_ASSERT_EQ(seal_p9_attach(after, "ds:home", &ec), STM_9P_RLERROR);
    STM_ASSERT_EQ(ec, STM_9P_ECODE_EACCES);
    stm_9p_server_destroy(after);
    stm_9p_server *ctl_s = seal_p9_server(sp.fs);
    STM_ASSERT_EQ(seal_p9_attach(ctl_s, "ds:sib", &ec), STM_9P_RATTACH);
    STM_ASSERT_EQ(seal_p9_getattr(ctl_s, &ec), STM_9P_RGETATTR);
    stm_9p_server_destroy(ctl_s);

    if (!seal_pool_remount(&sp)) { seal_pool_close(&sp); return; }
    stm_9p_server *cold = seal_p9_server(sp.fs);
    STM_ASSERT_EQ(seal_p9_attach(cold, "ds:home", &ec), STM_9P_RLERROR);
    STM_ASSERT_EQ(ec, STM_9P_ECODE_EACCES);
    stm_9p_server_destroy(cold);
    /* Its user logs in: the attach goes through. */
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    stm_9p_server *back = seal_p9_server(sp.fs);
    STM_ASSERT_EQ(seal_p9_attach(back, "ds:home", &ec), STM_9P_RATTACH);
    STM_ASSERT_EQ(seal_p9_getattr(back, &ec), STM_9P_RGETATTR);
    stm_9p_server_destroy(back);
    seal_pool_close(&sp);
}

/* Tread `fid` from offset 0. The reply type; in *val the count (RREAD) or
 * the ecode (RLERROR). */
static uint8_t seal_p9_tread(stm_9p_server *sv, uint32_t fid, uint16_t tag,
                             uint8_t *resp, uint32_t cap, uint32_t *val)
{
    uint8_t req[64];
    uint32_t rlen = 0;
    uint8_t *p = req + 7;
    seal_p9_pack_u32(p, fid); p += 4;
    memset(p, 0, 8); p += 8;
    seal_p9_pack_u32(p, 64u); p += 4;
    uint32_t sz = seal_p9_finish(req, p, STM_9P_TREAD, tag);
    STM_ASSERT_OK(stm_9p_server_handle(sv, req, sz, resp, cap, &rlen));
    *val = seal_p9_load_u32(resp + 7);
    return resp[4];
}

/* An xattr fid holds the value read at its Txattrwalk. Its read asks the
 * gate again: after the logout EACCES, not the value it holds; the same fid,
 * before the logout and after the login, answers. */
STM_TEST(corvus_9p_xattr_fid_read_after_logout_is_refused) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealxat")) return;
    uint64_t r = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(sp.fs, 1, 0755, 0, 0, &r));
    uint32_t ec = 0;
    stm_9p_server *sv = seal_p9_server(sp.fs);
    STM_ASSERT_EQ(seal_p9_attach(sv, "ds:home", &ec), STM_9P_RATTACH);
    uint8_t req[256], resp[512];
    uint32_t rlen = 0;
    uint8_t *p = req + 7;
    seal_p9_pack_u32(p, 100u); p += 4;
    seal_p9_pack_u32(p, 101u); p += 4;
    seal_p9_pack_u16(p, 1); p += 2;
    seal_p9_pack_u16(p, 5); p += 2;
    memcpy(p, "small", 5); p += 5;
    uint32_t sz = seal_p9_finish(req, p, STM_9P_TWALK, 3);
    STM_ASSERT_OK(stm_9p_server_handle(sv, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RWALK);
    p = req + 7;
    seal_p9_pack_u32(p, 101u); p += 4;
    seal_p9_pack_u32(p, 102u); p += 4;
    seal_p9_pack_u16(p, 6); p += 2;
    memcpy(p, "user.k", 6); p += 6;
    sz = seal_p9_finish(req, p, STM_9P_TXATTRWALK, 4);
    STM_ASSERT_OK(stm_9p_server_handle(sv, req, sz, resp, sizeof resp, &rlen));
    STM_ASSERT_EQ(resp[4], STM_9P_RXATTRWALK);

    uint32_t v = 0;
    STM_ASSERT_EQ(seal_p9_tread(sv, 102u, 5, resp, sizeof resp, &v),
                  STM_9P_RREAD);
    STM_ASSERT_EQ(v, 2u);
    STM_ASSERT(memcmp(resp + 11, "xv", 2) == 0);
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));     /* logout */
    STM_ASSERT_EQ(seal_p9_tread(sv, 102u, 6, resp, sizeof resp, &v),
                  STM_9P_RLERROR);
    STM_ASSERT_EQ(v, STM_9P_ECODE_EACCES);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_EQ(seal_p9_tread(sv, 102u, 7, resp, sizeof resp, &v),
                  STM_9P_RREAD);
    STM_ASSERT_EQ(v, 2u);
    stm_9p_server_destroy(sv);
    seal_pool_close(&sp);
}

/* A snapshot read racing a logout: its lock check passes, and the logout
 * lands before its fetch resolves the key. The lock-free key lookup passes
 * over the locked slot, so the read answers STM_ELOCKED, not a tag
 * mismatch from decrypting with the slot's empty key. */
STM_TEST(corvus_snapshot_read_racing_logout_answers_locked) {
    make_tmp("rc3snap");
    build_pool_with_corvus_slot();
    uint8_t canned_dek[32];
    for (int i = 0; i < 32; i++) canned_dek[i] = (uint8_t)(0x70 + i);
    fake_corvus fc;
    fake_corvus_start(&fc, "rc3snap", STM_CORVUS_STATUS_OK, canned_dek);
    stm_bdev *d = open_fresh_device();
    stm_alloc *a2 = NULL;
    STM_ASSERT_OK(stm_alloc_open_blank(d, &a2));
    stm_pool *pool2 = make_test_pool(d);
    stm_sync *s2 = NULL;
    STM_ASSERT_OK(stm_sync_open(pool2, a2, make_wk(), NULL, NULL, &s2));
    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };
    static const char ev_path[] = "users/rc3snap";
    uint64_t ds_ev = rc3_evict_fixture(s2, &cc, "rc3snap", ev_path,
                                       sizeof ev_path - 1);
    uint8_t buf[4096];
    for (size_t j = 0; j < sizeof buf; j++) buf[j] = (uint8_t)(0x3c ^ j);
    STM_ASSERT_OK(stm_sync_write_extent(s2, ds_ev, 1u, 0u, buf, sizeof buf));
    STM_ASSERT_OK(stm_sync_commit(s2));
    stm_dataset_entry de;
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(s2), ds_ev, &de));
    stm_sync_dcache_drain_for_test(s2);

    /* The control, one variable away: no logout, the read answers. */
    uint8_t rout[4096] = {0};
    size_t rgot = 0;
    STM_ASSERT_OK(stm_sync_read_extent_at_snap(s2, ds_ev, de.di_tree_root,
                                               de.di_root_gen, de.di_root_csum,
                                               1u, 0u, rout, sizeof rout,
                                               &rgot));
    STM_ASSERT_MEM_EQ(rout, buf, sizeof buf);
    stm_sync_dcache_drain_for_test(s2);

    rc3_evict_hook_ctx hc = { .s = s2, .ds = ds_ev };
    stm_sync_set_read_prefetch_hook_for_test(s2, rc3_evict_hook, &hc);
    memset(rout, 0, sizeof rout);
    stm_status r = stm_sync_read_extent_at_snap(s2, ds_ev, de.di_tree_root,
                                                de.di_root_gen,
                                                de.di_root_csum, 1u, 0u,
                                                rout, sizeof rout, &rgot);
    stm_sync_set_read_prefetch_hook_for_test(s2, NULL, NULL);
    STM_ASSERT_EQ(hc.fired, 1);
    STM_ASSERT_ERR(r, STM_ELOCKED);
    STM_ASSERT(memcmp(rout, buf, sizeof buf) != 0);

    stm_sync_close(s2);
    stm_alloc_close(a2);
    stm_pool_close(pool2);
    stm_bdev_close(d);
    fake_corvus_stop(&fc);
    unlink(g_tmp_path);
}

/* ===================================================================== */
/* T0.94: a home's file bytes out of the pool key's reach                 */
/* ===================================================================== */

/* Whether the m bytes at pat occur in the n bytes at p. */
static bool seal_has(const void *p, size_t n, const void *pat, size_t m)
{
    const uint8_t *b = p;
    for (size_t i = 0; m <= n && i <= n - m; i++)
        if (memcmp(b + i, pat, m) == 0) return true;
    return false;
}

/* An inode as the pool's key alone reads it: the index, under no gate. */
static void seal_raw_inode(stm_fs *fs, uint64_t ds, uint64_t ino,
                           struct stm_inode_value *iv)
{
    memset(iv, 0, sizeof *iv);
    STM_ASSERT_OK(stm_inode_lookup(stm_sync_inode_index(stm_fs_sync(fs)), ds,
                                   ino, iv));
}

/* A home's small file, made and written as the sibling's is, keeps its bytes
 * in an extent under the home's key: remounted with the pool's key alone,
 * its inode shows none of them. The sibling's inode, one variable away,
 * shows them, so the probe reads what the pool's key reveals. An O_TMPFILE
 * likewise. */
STM_TEST(corvus_home_file_bytes_never_sit_in_its_inode) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealinl")) return;
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    static const char TMP[] = "anon-secret=7d1e5c";
    for (int i = 0; i < 2; i++) {
        bool sealed = (i == 0);
        uint64_t anon = 0, fresh = 0;
        struct stm_inode_value iv;
        /* Made so, before any write could cut it over. */
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, ts[i]->ds, 1,
                                         (const uint8_t *)"fresh", 5, 0600,
                                         1000, 1000, &fresh));
        seal_raw_inode(sp.fs, ts[i]->ds, fresh, &iv);
        STM_ASSERT_EQ(iv.si_data_kind,
                      sealed ? STM_DATA_EXTENT : STM_DATA_INLINE);
        STM_ASSERT_OK(stm_fs_create_anon(sp.fs, ts[i]->ds, 0600, 1000, 1000,
                                         &anon));
        seal_raw_inode(sp.fs, ts[i]->ds, anon, &iv);
        STM_ASSERT_EQ(iv.si_data_kind,
                      sealed ? STM_DATA_EXTENT : STM_DATA_INLINE);
        STM_ASSERT_OK(stm_fs_write(sp.fs, ts[i]->ds, anon, 0, TMP,
                                   sizeof TMP - 1));
        seal_raw_inode(sp.fs, ts[i]->ds, anon, &iv);
        STM_ASSERT_EQ(iv.si_data_kind,
                      sealed ? STM_DATA_EXTENT : STM_DATA_INLINE);
        STM_ASSERT(seal_has(&iv, sizeof iv, TMP, sizeof TMP - 1) == !sealed);
        uint8_t buf[64];
        size_t got = 0;
        memset(buf, 0, sizeof buf);
        STM_ASSERT_OK(stm_fs_read(sp.fs, ts[i]->ds, anon, 0, buf, sizeof buf,
                                  &got));
        STM_ASSERT_EQ(got, sizeof TMP - 1);
        STM_ASSERT_MEM_EQ(buf, TMP, got);
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (!seal_pool_remount(&sp)) return;
    for (int i = 0; i < 2; i++) {
        bool sealed = (i == 0);
        struct stm_inode_value iv;
        seal_raw_inode(sp.fs, ts[i]->ds, ts[i]->fresh, &iv);
        STM_ASSERT_EQ(iv.si_data_kind,
                      sealed ? STM_DATA_EXTENT : STM_DATA_INLINE);
        STM_ASSERT_EQ(stm_load_le64(iv.si_size), sizeof SEAL_SECRET - 1);
        STM_ASSERT(seal_has(&iv, sizeof iv, SEAL_SECRET,
                            sizeof SEAL_SECRET - 1) == !sealed);
        /* An older inline file keeps its bytes there until rewritten. */
        seal_raw_inode(sp.fs, ts[i]->ds, ts[i]->small, &iv);
        STM_ASSERT_EQ(iv.si_data_kind, STM_DATA_INLINE);
        STM_ASSERT(seal_has(&iv, sizeof iv, SEAL_SECRET,
                            sizeof SEAL_SECRET - 1));
    }
    /* Made after a login (the mount locked the home), and under a mount
     * that held the session: extent-kind in the home still. */
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    for (int leg = 0; leg < 2; leg++) {
        if (leg == 1 && !seal_pool_remount_session(&sp)) return;
        for (int i = 0; i < 2; i++) {
            bool sealed = (i == 0);
            uint64_t f = 0;
            struct stm_inode_value iv;
            STM_ASSERT_OK(stm_fs_create_file(sp.fs, ts[i]->ds, 1,
                                             (const uint8_t *)(leg ? "m1" : "m0"),
                                             2, 0600, 1000, 1000, &f));
            seal_raw_inode(sp.fs, ts[i]->ds, f, &iv);
            STM_ASSERT_EQ(iv.si_data_kind,
                          sealed ? STM_DATA_EXTENT : STM_DATA_INLINE);
        }
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
    }
    seal_pool_close(&sp);
}

/* A home's small file from before that rule keeps its bytes inline (the seam
 * makes one, the sibling's alike). Its next write moves it out whole: the old
 * bytes and the new go under the home's key and read back intact, and the
 * inode keeps none. The sibling's stays inline. */
STM_TEST(corvus_write_to_an_older_inline_home_file_moves_it_out) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealold")) return;
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    uint8_t a[40], b[10], want[50];
    memset(a, 'A', sizeof a);
    memset(b, 'B', sizeof b);
    memcpy(want, a, sizeof a);
    memcpy(want + sizeof a, b, sizeof b);
    uint64_t old[2] = {0, 0};
    stm_fs_set_inline_in_sealed_for_test(sp.fs, true);
    for (int i = 0; i < 2; i++) {
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, ts[i]->ds, 1,
                                         (const uint8_t *)"old", 3, 0600,
                                         1000, 1000, &old[i]));
        STM_ASSERT_OK(stm_fs_write(sp.fs, ts[i]->ds, old[i], 0, a, sizeof a));
        struct stm_inode_value iv;
        seal_raw_inode(sp.fs, ts[i]->ds, old[i], &iv);
        STM_ASSERT_EQ(iv.si_data_kind, STM_DATA_INLINE);
        STM_ASSERT(seal_has(&iv, sizeof iv, a, sizeof a));
    }
    stm_fs_set_inline_in_sealed_for_test(sp.fs, false);
    for (int i = 0; i < 2; i++) {
        bool sealed = (i == 0);
        STM_ASSERT_OK(stm_fs_write(sp.fs, ts[i]->ds, old[i], sizeof a, b,
                                   sizeof b));
        struct stm_inode_value iv;
        seal_raw_inode(sp.fs, ts[i]->ds, old[i], &iv);
        STM_ASSERT_EQ(iv.si_data_kind,
                      sealed ? STM_DATA_EXTENT : STM_DATA_INLINE);
        STM_ASSERT(seal_has(&iv, sizeof iv, a, sizeof a) == !sealed);
        STM_ASSERT_EQ(stm_load_le64(iv.si_size), sizeof want);
        uint8_t got[64];
        size_t n = 0;
        memset(got, 0, sizeof got);
        STM_ASSERT_OK(stm_fs_read(sp.fs, ts[i]->ds, old[i], 0, got,
                                  sizeof got, &n));
        STM_ASSERT_EQ(n, sizeof want);
        STM_ASSERT_MEM_EQ(got, want, n);
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* The cold tier's residue in a pool written before it refused sealed data: a
 * home's file in the CAS, under the pool's key (the seam puts it there). The
 * login moves it back to the hot tier under the home's key; the sibling's
 * cold file, one variable away, stays. A login whose move fails (the move's
 * first write fails) stands: the file stays cold, read while logged in and
 * refused once locked, and the next login moves it. */
STM_TEST(corvus_login_moves_a_homes_legacy_cold_file_to_the_hot_tier) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealprom")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    uint8_t want[4096], got[4096];
    memset(want, 0x5a, sizeof want);
    size_t n = 0;
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.sib.ds, sp.sib.big));
    for (int round = 0; round < 2; round++) {
        bool fail = (round == 1);
        stm_sync_set_cas_admits_sealed_for_test(sync, true);
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.home.ds, sp.home.big));
        stm_sync_set_cas_admits_sealed_for_test(sync, false);
        STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.big),
                      STM_EXTENT_KIND_COLD);
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
        STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));      /* logout */
        STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
        STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.big),
                      STM_EXTENT_KIND_COLD);
        uint32_t fired = stm_bdev_inject_fired_count(d);
        if (fail) stm_bdev_inject_fail_after(d, 1);
        stm_fs_promote_policy_stats st;
        STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                                 (uint64_t)1 << 20, &st));
        stm_bdev_inject_fail_after(d, 0);
        STM_ASSERT_EQ(stm_bdev_inject_fired_count(d),
                      fired + (fail ? 1u : 0u));
        STM_ASSERT_EQ(st.inos_promoted, fail ? 0u : 1u);
        STM_ASSERT(fail ? st.last_err != STM_OK : st.last_err == STM_OK);
        STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.big),
                      fail ? STM_EXTENT_KIND_COLD : STM_EXTENT_KIND_HOT);
        STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.sib.ds, sp.sib.big),
                      STM_EXTENT_KIND_COLD);
        memset(got, 0, sizeof got);
        STM_ASSERT_OK(stm_fs_read(sp.fs, sp.home.ds, sp.home.big, 0, got,
                                  sizeof got, &n));
        STM_ASSERT_MEM_EQ(got, want, sizeof got);
    }
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));
    STM_ASSERT_ERR(stm_sync_read_extent(sync, sp.home.ds, sp.home.big, 0, got,
                                        sizeof got, &n), STM_ELOCKED);
    STM_ASSERT_ERR(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                              (uint64_t)1 << 20, NULL),
                   STM_ELOCKED);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                             (uint64_t)1 << 20, NULL));
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.big),
                  STM_EXTENT_KIND_HOT);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* A send opened before the logout stops at it: the home's next record
 * answers STM_ELOCKED, and every call after, and the handle's keys are wiped.
 * So does a stream of a pool-keyed clone of the home (a pool written before
 * such clones were refused may hold one; the seam makes it), whose shared
 * extents read under the home's key. The sibling's stream, opened alike, one
 * variable away, runs to its end with its keys. */
STM_TEST(corvus_send_opened_before_logout_stops_at_it) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealsend")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint64_t snap = 0, clone = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(sp.fs, sp.home.ds, "s", 1, &snap));
    stm_fs_set_clone_of_sealed_for_test(sp.fs, true);
    STM_ASSERT_OK(stm_fs_create_clone(sp.fs, 1, "c", snap, &clone));
    stm_fs_set_clone_of_sealed_for_test(sp.fs, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    uint64_t ds[3] = {sp.home.ds, clone, sp.sib.ds};
    stm_send_handle *sh[3] = {NULL, NULL, NULL};
    size_t cap = (size_t)1 << 16;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);
    for (int i = 0; i < 3; i++) {
        size_t n = 0, need = 0;
        STM_ASSERT_OK(stm_send_init(sync, ds[i], 0, 0, &sh[i]));
        STM_ASSERT(!stm_send_keys_wiped_for_test(sh[i]));
        STM_ASSERT_OK(stm_send_next(sh[i], buf, cap, &n, &need));  /* HEADER */
        STM_ASSERT_OK(stm_send_next(sh[i], buf, cap, &n, &need));
    }
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));            /* logout */
    for (int i = 0; i < 3; i++) {
        bool stops = (i < 2);
        size_t n = 0, need = 0;
        int records = 0;
        stm_status r;
        while ((r = stm_send_next(sh[i], buf, cap, &n, &need)) == STM_OK)
            records++;
        if (stops) {
            STM_ASSERT_ERR(r, STM_ELOCKED);
            STM_ASSERT_EQ(records, 0);
            STM_ASSERT_ERR(stm_send_next(sh[i], buf, cap, &n, &need),
                           STM_ELOCKED);
            STM_ASSERT(stm_send_keys_wiped_for_test(sh[i]));
        } else {
            STM_ASSERT_ERR(r, STM_ENOENT);
            STM_ASSERT(records > 0);
            STM_ASSERT(!stm_send_keys_wiped_for_test(sh[i]));
        }
    }
    /* A stopped stream stays stopped across the next login. */
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    for (int i = 0; i < 3; i++) {
        size_t n = 0, need = 0;
        if (i < 2)
            STM_ASSERT_ERR(stm_send_next(sh[i], buf, cap, &n, &need),
                           STM_ELOCKED);
        stm_send_close(sh[i]);
    }
    free(buf);
    seal_pool_close(&sp);
}

/* A home with no cold record costs the login one scan that stops at the
 * first, and no walk (inos_visited 0), though the CAS holds a chunk (the
 * sibling's). A pool-keyed dataset is not the login's to move: its cold file
 * stays. One variable away, a home that holds a cold file is walked and the
 * file moved. A locked home is refused. */
STM_TEST(corvus_login_promote_walks_only_a_home_with_a_cold_record) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealgate")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t budget = (uint64_t)1 << 20;
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.sib.ds, sp.sib.big));
    stm_fs_promote_policy_stats st;
    for (int i = 0; i < 2; i++) {
        uint64_t ds = i == 0 ? sp.home.ds : sp.sib.ds;
        memset(&st, 0xff, sizeof st);
        STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, ds, budget, &st));
        STM_ASSERT_EQ(st.inos_visited, 0u);
        STM_ASSERT_EQ(st.bytes_promoted, 0u);
    }
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.sib.ds, sp.sib.big),
                  STM_EXTENT_KIND_COLD);
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.home.ds, sp.home.big));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, budget, &st));
    STM_ASSERT(st.inos_visited >= 1u);
    STM_ASSERT_EQ(st.inos_promoted, 1u);
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.big),
                  STM_EXTENT_KIND_HOT);
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));
    STM_ASSERT_ERR(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, budget, &st),
                   STM_ELOCKED);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

static uint8_t seal_extent_kind_at(stm_fs *fs, uint64_t ds, uint64_t ino,
                                   uint64_t off)
{
    stm_extent_record e;
    memset(&e, 0, sizeof e);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(stm_fs_sync(fs)),
                                       ds, ino, off, &e));
    return (uint8_t)e.kind;
}

/* Each login moves at most its budget, and the next takes up the rest: two
 * cold files of a block each, then a file of two cold blocks, a block per
 * pass. */
STM_TEST(corvus_login_promote_moves_a_budget_per_login) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealbudg")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint8_t blk[4096];
    uint64_t f[3] = {0, 0, 0};
    for (int i = 0; i < 3; i++) {
        char nm[4] = {'b', (char)('0' + i), 0, 0};
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, sp.home.ds, 1,
                                         (const uint8_t *)nm, 2, 0600, 1000,
                                         1000, &f[i]));
        memset(blk, 0x30 + i, sizeof blk);
        STM_ASSERT_OK(stm_fs_write(sp.fs, sp.home.ds, f[i], 0, blk,
                                   sizeof blk));
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
        if (i == 2) {
            STM_ASSERT_OK(stm_fs_write(sp.fs, sp.home.ds, f[i], 4096, blk,
                                       sizeof blk));
            STM_ASSERT_OK(stm_fs_commit(sp.fs));
        }
    }
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    for (int i = 0; i < 3; i++)
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.home.ds, f[i]));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_EQ(seal_extent_kind_at(sp.fs, sp.home.ds, f[2], 4096),
                  STM_EXTENT_KIND_COLD);
    stm_fs_promote_policy_stats st;
    int hot0 = 0;
    for (int pass = 0; pass < 4; pass++) {
        STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, 4096, &st));
        STM_ASSERT_EQ(st.bytes_promoted, 4096u);
        int hot = 0;
        for (int i = 0; i < 2; i++)
            hot += seal_extent_kind(sp.fs, sp.home.ds, f[i]) ==
                   STM_EXTENT_KIND_HOT;
        bool f2a = seal_extent_kind_at(sp.fs, sp.home.ds, f[2], 0) ==
                   STM_EXTENT_KIND_HOT;
        bool f2b = seal_extent_kind_at(sp.fs, sp.home.ds, f[2], 4096) ==
                   STM_EXTENT_KIND_HOT;
        /* A block a pass, whichever file the collect gave first. */
        STM_ASSERT_EQ(hot + (int)f2a + (int)f2b, pass + 1);
        STM_ASSERT(!f2b || f2a);       /* a file's blocks in offset order */
        if (pass == 0) hot0 = hot;
    }
    (void)hot0;
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, 4096, &st));
    STM_ASSERT_EQ(st.inos_visited, 0u);         /* nothing cold is left */
    for (int i = 0; i < 3; i++) {
        memset(blk, 0x30 + i, sizeof blk);
        for (uint64_t off = 0; off < (i == 2 ? 8192u : 4096u); off += 4096u) {
            uint8_t got[4096];
            size_t n = 0;
            STM_ASSERT_OK(stm_fs_read(sp.fs, sp.home.ds, f[i], off, got,
                                      sizeof got, &n));
            STM_ASSERT_EQ(n, sizeof got);
            STM_ASSERT_MEM_EQ(got, blk, sizeof got);
        }
    }
    /* Again, three new files alike, with a budget of three blocks: the
     * third file gets what is left of the pass's budget, one block, not a
     * budget of its own. */
    uint64_t g[3] = {0, 0, 0};
    for (int i = 0; i < 3; i++) {
        char nm[4] = {'c', (char)('0' + i), 0, 0};
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, sp.home.ds, 1,
                                         (const uint8_t *)nm, 2, 0600, 1000,
                                         1000, &g[i]));
        memset(blk, 0x40 + i, sizeof blk);
        for (uint64_t off = 0; off < (i == 2 ? 8192u : 4096u); off += 4096u) {
            STM_ASSERT_OK(stm_fs_write(sp.fs, sp.home.ds, g[i], off, blk,
                                       sizeof blk));
            STM_ASSERT_OK(stm_fs_commit(sp.fs));
        }
    }
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    for (int i = 0; i < 3; i++)
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.home.ds, g[i]));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    {
        stm_extent_record e;
        memset(&e, 0, sizeof e);
        STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync),
                                           sp.home.ds, g[2], 4096, &e));
        STM_ASSERT_EQ(e.off, 4096u);           /* two cold records */
        STM_ASSERT_EQ((int)e.kind, (int)STM_EXTENT_KIND_COLD);
    }
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, 3u * 4096u,
                                             &st));
    STM_ASSERT_EQ(st.bytes_promoted, 3u * 4096u);
    STM_ASSERT_EQ(seal_extent_kind_at(sp.fs, sp.home.ds, g[2], 0),
                  STM_EXTENT_KIND_HOT);
    STM_ASSERT_EQ(seal_extent_kind_at(sp.fs, sp.home.ds, g[2], 4096),
                  STM_EXTENT_KIND_COLD);
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, 3u * 4096u,
                                             &st));
    STM_ASSERT_EQ(st.bytes_promoted, 4096u);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* A logout and then a login between two calls still stops the stream: the
 * keys it holds were copied before the logout. The sibling's stream, opened
 * alike, one variable away, runs to its end: another dataset's logout stops
 * none of it. */
STM_TEST(corvus_send_stops_at_a_logout_a_login_followed) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealrelog")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint64_t ds[2] = {sp.home.ds, sp.sib.ds};
    stm_send_handle *sh[2] = {NULL, NULL};
    size_t cap = (size_t)1 << 16;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);
    for (int i = 0; i < 2; i++) {
        size_t n = 0, need = 0;
        STM_ASSERT_OK(stm_send_init(sync, ds[i], 0, 0, &sh[i]));
        STM_ASSERT_OK(stm_send_next(sh[i], buf, cap, &n, &need));  /* HEADER */
    }
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));            /* logout */
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));  /* login */
    for (int i = 0; i < 2; i++) {
        size_t n = 0, need = 0;
        int records = 0;
        stm_status r;
        while ((r = stm_send_next(sh[i], buf, cap, &n, &need)) == STM_OK)
            records++;
        if (i == 0) {
            STM_ASSERT_ERR(r, STM_ELOCKED);
            STM_ASSERT_EQ(records, 0);
            STM_ASSERT(stm_send_keys_wiped_for_test(sh[i]));
        } else {
            STM_ASSERT_ERR(r, STM_ENOENT);
            STM_ASSERT(records > 0);
            STM_ASSERT(!stm_send_keys_wiped_for_test(sh[i]));
        }
        stm_send_close(sh[i]);
    }
    free(buf);
    seal_pool_close(&sp);
}

/* A home whose files are all cold (an older pool) gives its stream no key to
 * hold: the sent dataset's own logout must stop it. The sibling's cold-only
 * stream runs to its end. */
STM_TEST(corvus_send_of_a_cold_only_home_stops_at_logout) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealsco")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    stm_send_handle *sh[2] = {NULL, NULL};
    size_t cap = (size_t)1 << 16;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    for (int i = 0; i < 2; i++) {
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->big));
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->fresh));
    }
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    for (int i = 0; i < 2; i++) {
        size_t n = 0, need = 0;
        STM_ASSERT_OK(stm_send_init(sync, ts[i]->ds, 0, 0, &sh[i]));
        STM_ASSERT_OK(stm_send_next(sh[i], buf, cap, &n, &need));  /* HEADER */
    }
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));            /* logout */
    for (int i = 0; i < 2; i++) {
        size_t n = 0, need = 0;
        int records = 0;
        stm_status r;
        while ((r = stm_send_next(sh[i], buf, cap, &n, &need)) == STM_OK)
            records++;
        STM_ASSERT_ERR(r, i == 0 ? STM_ELOCKED : STM_ENOENT);
        STM_ASSERT(i == 0 ? records == 0 : records > 0);
        stm_send_close(sh[i]);
    }
    free(buf);
    seal_pool_close(&sp);
}

/* An EMPTY older inline home file (made before the rule, or truncated to 0
 * by an O_TRUNC rewrite) takes its first write out of the inode too. The
 * sibling's stays inline. */
STM_TEST(corvus_first_write_to_an_empty_older_inline_home_file_moves_it_out) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealeo")) return;
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    static const char S[] = "empty-older-secret-77";
    for (int i = 0; i < 2; i++) {
        bool sealed = (i == 0);
        uint64_t f = 0;
        stm_fs_set_inline_in_sealed_for_test(sp.fs, true);
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, ts[i]->ds, 1,
                                         (const uint8_t *)"eo", 2, 0600, 1000,
                                         1000, &f));
        stm_fs_set_inline_in_sealed_for_test(sp.fs, false);
        struct stm_inode_value iv;
        seal_raw_inode(sp.fs, ts[i]->ds, f, &iv);
        STM_ASSERT_EQ(iv.si_data_kind, STM_DATA_INLINE);
        STM_ASSERT_OK(stm_fs_write(sp.fs, ts[i]->ds, f, 0, S, sizeof S - 1));
        seal_raw_inode(sp.fs, ts[i]->ds, f, &iv);
        STM_ASSERT_EQ(iv.si_data_kind,
                      sealed ? STM_DATA_EXTENT : STM_DATA_INLINE);
        STM_ASSERT(seal_has(&iv, sizeof iv, S, sizeof S - 1) == !sealed);
        uint8_t got[64];
        size_t n = 0;
        STM_ASSERT_OK(stm_fs_read(sp.fs, ts[i]->ds, f, 0, got, sizeof got, &n));
        STM_ASSERT_EQ(n, sizeof S - 1);
        STM_ASSERT_MEM_EQ(got, S, n);
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* An older pool's pool-keyed clone of a home (the seam makes one) shares the
 * home's cold records, which name the home as their origin (all its files
 * cold, so the clone's send captures no key of the home's): while the home
 * is locked, the clone's open stream stops, a new one is refused, and a read
 * of the shared file is refused; once logged in, all three serve. A clone of
 * the sibling, one variable away, serves throughout. */
STM_TEST(corvus_clone_of_a_home_serves_its_cold_records_only_while_logged_in) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealclc")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    uint64_t clone[2] = {0, 0};
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    for (int i = 0; i < 2; i++) {
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->big));
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->fresh));
        uint64_t snap = 0;
        STM_ASSERT_OK(stm_fs_create_snapshot(sp.fs, ts[i]->ds, "s", 1, &snap));
        stm_fs_set_clone_of_sealed_for_test(sp.fs, i == 0);
        STM_ASSERT_OK(stm_fs_create_clone(sp.fs, 1, i == 0 ? "c0" : "c1", snap,
                                          &clone[i]));
        stm_fs_set_clone_of_sealed_for_test(sp.fs, false);
    }
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    size_t cap = (size_t)1 << 16;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);
    uint8_t want[4096], got[4096];
    memset(want, 0x5a, sizeof want);
    stm_send_handle *sh[2] = {NULL, NULL};
    for (int i = 0; i < 2; i++) {
        size_t n = 0, need = 0;
        STM_ASSERT_OK(stm_send_init(sync, clone[i], 0, 0, &sh[i]));
        STM_ASSERT_OK(stm_send_next(sh[i], buf, cap, &n, &need));  /* HEADER */
    }
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));            /* logout */
    for (int i = 0; i < 2; i++) {
        bool home = (i == 0);
        size_t n = 0, need = 0;
        int records = 0;
        stm_status r;
        while ((r = stm_send_next(sh[i], buf, cap, &n, &need)) == STM_OK)
            records++;
        STM_ASSERT_ERR(r, home ? STM_ELOCKED : STM_ENOENT);
        STM_ASSERT(home ? records == 0 : records > 0);
        stm_send_close(sh[i]);
        stm_send_handle *h2 = NULL;
        stm_status ri = stm_send_init(sync, clone[i], 0, 0, &h2);
        STM_ASSERT_ERR(ri, home ? STM_ELOCKED : STM_OK);
        if (h2) stm_send_close(h2);
        size_t g = 0;
        memset(got, 0, sizeof got);
        stm_status rr = stm_fs_read(sp.fs, clone[i], ts[i]->big, 0, got,
                                    sizeof got, &g);
        STM_ASSERT_ERR(rr, home ? STM_ELOCKED : STM_OK);
        STM_ASSERT_EQ(g, home ? 0u : sizeof got);
    }
    /* The sibling's clone read put the chunk both files share (the same
     * bytes) in the cache: the home clone's read still refuses. */
    {
        size_t g = 0;
        STM_ASSERT_ERR(stm_fs_read(sp.fs, clone[0], sp.home.big, 0, got,
                                   sizeof got, &g), STM_ELOCKED);
    }
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));  /* login */
    {
        size_t g = 0;
        STM_ASSERT_OK(stm_fs_read(sp.fs, clone[0], sp.home.big, 0, got,
                                  sizeof got, &g));
        STM_ASSERT_EQ(g, sizeof got);
        STM_ASSERT_MEM_EQ(got, want, sizeof got);
        stm_send_handle *h2 = NULL;
        STM_ASSERT_OK(stm_send_init(sync, clone[0], 0, 0, &h2));
        stm_send_close(h2);
    }
    free(buf);
    seal_pool_close(&sp);
}

/* ---- work a logout's evict meets while it holds s->lock ---------------- */
/* The evict's seam runs after it publishes the locked slot and before it   */
/* moves the evict count. Two threads start there and the seam waits.       */

typedef struct {
    stm_sync        *sync;
    uint64_t         ds[2];
    int              mode;        /* 0: stm_send_init; 1: the sealed answer */
    int              fired;
    pthread_t        th[2];
    bool             started[2];
    stm_send_handle *h[2];
    stm_status       rc[2];
    bool             sealed[2];
    atomic_bool      done[2];
    bool             done_in_seam[2];
} seal_evict_seam;

typedef struct {
    seal_evict_seam *z;
    int              i;
} seal_seam_arg;

static seal_seam_arg g_seal_seam_args[2];

static void *seal_seam_thread(void *a_)
{
    seal_seam_arg *a = a_;
    seal_evict_seam *z = a->z;
    int i = a->i;
    if (z->mode == 0)
        z->rc[i] = stm_send_init(z->sync, z->ds[i], 0, 0, &z->h[i]);
    else
        z->rc[i] = stm_sync_dataset_key_user_sealed(z->sync, z->ds[i],
                                                    &z->sealed[i]);
    atomic_store(&z->done[i], true);
    return NULL;
}

static void seal_evict_seam_hook(void *ctx)
{
    seal_evict_seam *z = ctx;
    if (z->fired++) return;
    for (int i = 0; i < 2; i++) {
        g_seal_seam_args[i] = (seal_seam_arg){z, i};
        z->started[i] = pthread_create(&z->th[i], NULL, seal_seam_thread,
                                       &g_seal_seam_args[i]) == 0;
    }
    for (int ms = 0; ms < 2000 && !atomic_load(&z->done[0]); ms++)
        usleep(1000);
    usleep(200000);
    for (int i = 0; i < 2; i++) z->done_in_seam[i] = atomic_load(&z->done[i]);
}

static void seal_evict_seam_run(seal_pool *sp, seal_evict_seam *z)
{
    stm_sync *sync = stm_fs_sync(sp->fs);
    stm_sync_set_evict_published_hook_for_test(sync, seal_evict_seam_hook, z);
    STM_ASSERT_OK(stm_fs_evict_dek(sp->fs, sp->home.ds));       /* logout */
    stm_sync_set_evict_published_hook_for_test(sync, NULL, NULL);
    for (int i = 0; i < 2; i++)
        if (z->started[i]) pthread_join(z->th[i], NULL);
    STM_ASSERT_EQ(z->fired, 1);
    STM_ASSERT(z->started[0] && z->started[1]);
}

/* A send opened while the logout is between showing the home locked and
 * moving the evict count is refused: the count it read is the old one, so
 * the lock it asks next shows the logout. The home's files are all cold (an
 * older pool), so no key capture would refuse it. The sibling's send, opened
 * at the same point, one variable away, runs to its end. */
STM_TEST(corvus_send_init_inside_a_logout_is_refused) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealevw")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    for (int i = 0; i < 2; i++) {
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->big));
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->fresh));
    }
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    static seal_evict_seam z;
    memset(&z, 0, sizeof z);
    z.sync = sync;
    z.ds[0] = sp.home.ds;
    z.ds[1] = sp.sib.ds;
    seal_evict_seam_run(&sp, &z);
    STM_ASSERT_ERR(z.rc[0], STM_ELOCKED);
    STM_ASSERT(z.h[0] == NULL);
    STM_ASSERT_OK(z.rc[1]);
    size_t cap = (size_t)1 << 16;
    uint8_t *buf = malloc(cap);
    STM_ASSERT(buf != NULL);
    for (int i = 0; i < 2 && buf; i++) {
        if (!z.h[i]) continue;
        size_t n = 0, need = 0;
        int records = 0;
        stm_status r;
        while ((r = stm_send_next(z.h[i], buf, cap, &n, &need)) == STM_OK)
            records++;
        STM_ASSERT_ERR(r, i == 0 ? STM_ELOCKED : STM_ENOENT);
        STM_ASSERT(i == 0 ? records == 0 : records > 1);
        stm_send_close(z.h[i]);
    }
    free(buf);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* Whether a dataset is user-sealed (asked by every create) is answered from
 * its slot without s->lock: it returns while a logout holds the lock. A
 * dataset with no slot, one variable away, asks the keyschema under the lock
 * and so waits for the logout -- which shows the seam really holds it. */
STM_TEST(corvus_sealed_answer_waits_for_no_logout) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealans")) return;
    static seal_evict_seam z;
    memset(&z, 0, sizeof z);
    z.sync = stm_fs_sync(sp.fs);
    z.mode = 1;
    z.ds[0] = sp.home.ds;
    z.ds[1] = 4242u;
    seal_evict_seam_run(&sp, &z);
    STM_ASSERT(z.done_in_seam[0]);
    STM_ASSERT_OK(z.rc[0]);
    STM_ASSERT(z.sealed[0]);
    STM_ASSERT(!z.done_in_seam[1]);
    STM_ASSERT_OK(z.rc[1]);
    STM_ASSERT(!z.sealed[1]);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* ---- cold records over the recordsize (an older pool's cold tier) ------ */

#define SEAL_BIG_LEN ((size_t)24 << 20)

static void seal_noise(uint64_t *x, uint8_t *p, size_t n)
{
    for (size_t j = 0; j + 8u <= n; j += 8u) {
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        memcpy(p + j, x, 8);
    }
}

/* A 24 MiB file of incompressible bytes, migrated whole to the cold tier
 * with its chunks capped at the recordsize, or not (as the cold tier made
 * them before: the chunker's 8 MiB average gives records of up to 16 MiB).
 * Returns the bytes; the caller frees them. */
static uint8_t *seal_big_cold_file(stm_fs *fs, uint64_t ds, const char *name,
                                   bool uncapped, uint64_t *out_ino)
{
    stm_sync *sync = stm_fs_sync(fs);
    uint8_t *all = malloc(SEAL_BIG_LEN);
    STM_ASSERT(all != NULL);
    if (!all) return NULL;
    uint64_t x = 0x1234567887654321ull;
    seal_noise(&x, all, SEAL_BIG_LEN);
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)name,
                                     (uint8_t)strlen(name), 0600, 1000, 1000,
                                     out_ino));
    const size_t MB4 = (size_t)4 << 20;
    for (size_t k = 0; k < SEAL_BIG_LEN; k += MB4)
        STM_ASSERT_OK(stm_fs_write(fs, ds, *out_ino, k, all + k, MB4));
    STM_ASSERT_OK(stm_fs_commit(fs));
    bool sealed = false;
    STM_ASSERT_OK(stm_sync_dataset_key_user_sealed(sync, ds, &sealed));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, uncapped);
    stm_sync_set_cas_admits_sealed_for_test(sync, sealed);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, ds, *out_ino));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    stm_sync_set_cold_chunks_uncapped_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(fs));
    return all;
}

typedef struct {
    int      n, cold;
    uint64_t sum, max_len;
    uint64_t big_off, big_len;   /* the largest COLD record */
} seal_ext_sum;

static bool seal_ext_sum_cb(const stm_extent_record *e, void *c_)
{
    seal_ext_sum *c = c_;
    c->n++;
    c->sum += e->len;
    if (e->len > c->max_len) c->max_len = e->len;
    if (e->kind == STM_EXTENT_KIND_COLD) {
        c->cold++;
        if (e->len > c->big_len) {
            c->big_off = e->off;
            c->big_len = e->len;
        }
    }
    return true;
}

static seal_ext_sum seal_extents(stm_fs *fs, uint64_t ds, uint64_t ino)
{
    seal_ext_sum c;
    memset(&c, 0, sizeof c);
    STM_ASSERT_OK(stm_extent_iter(stm_sync_extent_index(stm_fs_sync(fs)), ds,
                                  ino, seal_ext_sum_cb, &c));
    return c;
}

/* The file's bytes [off, off + len) are want's. */
static void seal_read_eq(stm_fs *fs, uint64_t ds, uint64_t ino, uint64_t off,
                         const uint8_t *want, size_t len)
{
    const size_t MB = (size_t)1 << 20;
    uint8_t *got = malloc(MB);
    STM_ASSERT(got != NULL);
    if (!got) return;
    size_t at = 0;
    while (at < len) {
        size_t ask = len - at < MB ? len - at : MB;
        size_t n = 0;
        stm_status r = stm_fs_read(fs, ds, ino, off + at, got, ask, &n);
        STM_ASSERT_OK(r);
        STM_ASSERT(n > 0u);
        if (r != STM_OK || n == 0u) break;
        if (memcmp(got, want + at, n) != 0) {
            printf("    bytes differ in [%llu, +%zu)\n",
                   (unsigned long long)(off + at), n);
            STM_ASSERT_MEM_EQ(got, want + at, n);
            break;
        }
        at += n;
    }
    free(got);
}

/* A home's cold record longer than the recordsize goes back to the hot tier
 * at login as pieces of at most the recordsize, a pass's budget at a time,
 * its bytes intact. One variable away, the cold tier as it is now caps its
 * chunks: the same bytes migrated in the sibling give no record over the
 * recordsize. */
STM_TEST(corvus_login_promote_moves_a_cold_record_over_the_recordsize) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "sealbig", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    const uint64_t REC = STM_FS_RECORDSIZE_MAX;
    uint64_t f = 0, g = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.home.ds, "b24", true, &f);
    uint8_t *want2 = seal_big_cold_file(sp.fs, sp.sib.ds, "b24", false, &g);
    if (!want || !want2) { free(want); free(want2); seal_pool_close(&sp); return; }
    seal_ext_sum e = seal_extents(sp.fs, sp.home.ds, f);
    STM_ASSERT_EQ(e.cold, e.n);
    STM_ASSERT(e.max_len > REC);
    STM_ASSERT_EQ(e.sum, (uint64_t)SEAL_BIG_LEN);
    seal_ext_sum e2 = seal_extents(sp.fs, sp.sib.ds, g);
    STM_ASSERT_EQ(e2.cold, e2.n);
    STM_ASSERT(e2.n > 2);
    STM_ASSERT(e2.max_len <= REC);
    STM_ASSERT_EQ(e2.sum, (uint64_t)SEAL_BIG_LEN);
    seal_read_eq(sp.fs, sp.sib.ds, g, 0, want2, SEAL_BIG_LEN);
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));      /* logout */
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    stm_fs_promote_policy_stats st;
    int passes = 0;
    printf("    %d cold records, the largest %llu bytes\n", e.n,
           (unsigned long long)e.max_len);
    for (; passes < 8; passes++) {
        STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, REC, &st));
        printf("    pass %d: %llu bytes\n", passes,
               (unsigned long long)st.bytes_promoted);
        if (st.inos_visited == 0u) break;    /* nothing cold is left */
        STM_ASSERT(st.bytes_promoted > 0u);
        /* Past the budget by less than one record (the last step's). */
        STM_ASSERT(st.bytes_promoted < REC + e.max_len);
        STM_ASSERT_OK(st.last_err);
    }
    STM_ASSERT(passes >= 2);
    e = seal_extents(sp.fs, sp.home.ds, f);
    STM_ASSERT_EQ(e.cold, 0);
    STM_ASSERT(e.max_len <= REC);
    STM_ASSERT_EQ(e.sum, (uint64_t)SEAL_BIG_LEN);
    seal_read_eq(sp.fs, sp.home.ds, f, 0, want, SEAL_BIG_LEN);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (seal_pool_remount_session(&sp))
        seal_read_eq(sp.fs, sp.home.ds, f, 0, want, SEAL_BIG_LEN);
    free(want);
    free(want2);
    seal_pool_close(&sp);
}

/* A two-byte write into a cold record longer than the recordsize commits:
 * the covering write promotes the record as pieces first. The pool keeps
 * committing -- another file's later write survives a remount -- and the
 * file reads its bytes with the write in them. */
STM_TEST(fs_write_into_a_cold_record_over_the_recordsize_commits) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "sealx2", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    const uint64_t REC = STM_FS_RECORDSIZE_MAX;
    uint64_t f = 0, g = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.sib.ds, "x24", true, &f);
    if (!want) { seal_pool_close(&sp); return; }
    seal_ext_sum e = seal_extents(sp.fs, sp.sib.ds, f);
    STM_ASSERT(e.big_len > REC);
    uint64_t at = e.big_off + 4096u + 10u;
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, f, at, "zz", 2));
    want[at] = 'z';
    want[at + 1u] = 'z';
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, sp.sib.ds, 1,
                                     (const uint8_t *)"g", 1, 0600, 1000, 1000,
                                     &g));
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, g, 0, "other", 5));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(stm_fs_sync(sp.fs)),
                                       sp.sib.ds, f, at, &r));
    STM_ASSERT(r.len <= REC);
    STM_ASSERT_EQ(seal_extents(sp.fs, sp.sib.ds, f).sum, (uint64_t)SEAL_BIG_LEN);
    if (seal_pool_remount(&sp)) {
        uint8_t got[8] = {0};
        size_t n = 0;
        STM_ASSERT_OK(stm_fs_read(sp.fs, sp.sib.ds, g, 0, got, 5, &n));
        STM_ASSERT_EQ(n, 5u);
        STM_ASSERT_MEM_EQ(got, "other", 5);
        seal_read_eq(sp.fs, sp.sib.ds, f, e.big_off, want + e.big_off,
                     (size_t)e.big_len);
    }
    free(want);
    seal_pool_close(&sp);
}

/* A truncate into a cold record longer than the recordsize, keeping more of
 * it than a hot extent may hold, works: the record is promoted as pieces
 * first, so the kept prefix the truncate rewrites is one piece's. */
STM_TEST(fs_truncate_into_a_cold_record_over_the_recordsize) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "sealtr", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    const uint64_t REC = STM_FS_RECORDSIZE_MAX;
    uint64_t t = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.sib.ds, "t24", true, &t);
    if (!want) { seal_pool_close(&sp); return; }
    seal_ext_sum e = seal_extents(sp.fs, sp.sib.ds, t);
    STM_ASSERT(e.big_len > REC + 8192u + 100u);
    /* A truncate at the record's end leaves it cold: only a record the new
     * size crosses is promoted. */
    uint64_t end = e.big_off + e.big_len;
    STM_ASSERT(end < (uint64_t)SEAL_BIG_LEN);
    STM_ASSERT_OK(stm_fs_truncate(sp.fs, sp.sib.ds, t, end));
    STM_ASSERT_EQ(seal_extent_kind_at(sp.fs, sp.sib.ds, t, e.big_off),
                  STM_EXTENT_KIND_COLD);
    uint64_t ns = e.big_off + REC + 8192u + 100u;
    STM_ASSERT_OK(stm_fs_truncate(sp.fs, sp.sib.ds, t, ns));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_EQ(seal_extents(sp.fs, sp.sib.ds, t).sum,
                  (ns + 4095u) & ~(uint64_t)4095u);
    seal_read_eq(sp.fs, sp.sib.ds, t, 0, want, (size_t)ns);
    if (seal_pool_remount(&sp)) {
        seal_read_eq(sp.fs, sp.sib.ds, t, 0, want, (size_t)ns);
        uint8_t b[16];
        size_t n = 99;
        STM_ASSERT_OK(stm_fs_read(sp.fs, sp.sib.ds, t, ns, b, sizeof b, &n));
        STM_ASSERT_EQ(n, 0u);
    }
    free(want);
    seal_pool_close(&sp);
}

/* ---- the login promote passes over a bad record, stops at a pool error -- */

/* A file of n cold records of len bytes each, written apart (a hole between
 * them), so the migrate moves each extent alone; record k holds fill + k. */
static uint64_t seal_sparse_cold_file(stm_fs *fs, uint64_t ds, const char *name,
                                      int n, size_t len, uint8_t fill)
{
    stm_sync *sync = stm_fs_sync(fs);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)name,
                                     (uint8_t)strlen(name), 0600, 1000, 1000,
                                     &f));
    uint8_t *b = malloc(len);
    STM_ASSERT(b != NULL);
    if (!b) return f;
    for (int k = 0; k < n; k++) {
        memset(b, (uint8_t)(fill + k), len);
        STM_ASSERT_OK(stm_fs_write(fs, ds, f, (uint64_t)k * 2u * len, b, len));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    free(b);
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, ds, f));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(fs));
    return f;
}

/* A file whose first cold record cannot be read: the pass moves the record
 * after it, says which file failed, and the next pass tries again. */
STM_TEST(corvus_login_promote_passes_over_a_bad_cold_record) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealbad")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint64_t f = seal_sparse_cold_file(sp.fs, sp.home.ds, "two", 2, 4096u, 0x31);
    stm_extent_record e0, e1;
    memset(&e0, 0, sizeof e0);
    memset(&e1, 0, sizeof e1);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), sp.home.ds,
                                       f, 0, &e0));
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), sp.home.ds,
                                       f, 8192, &e1));
    STM_ASSERT_EQ(e1.off, 8192u);
    STM_ASSERT_EQ((int)e0.kind, (int)STM_EXTENT_KIND_COLD);
    STM_ASSERT_EQ((int)e1.kind, (int)STM_EXTENT_KIND_COLD);
    STM_ASSERT(memcmp(e0.content_hash, e1.content_hash,
                      sizeof e0.content_hash) != 0);      /* two chunks */
    stm_cas_record cr;
    STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(sync), e0.content_hash, &cr));
    uint8_t junk[64];
    memset(junk, 0xee, sizeof junk);
    STM_ASSERT_OK(stm_bdev_write(stm_fs_bdev_for_test(sp.fs),
                                 stm_paddr_offset(cr.paddrs[0]) *
                                 (uint64_t)STM_UB_SIZE, junk, sizeof junk));
    for (int pass = 0; pass < 2; pass++) {
        stm_fs_promote_policy_stats st;
        STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                                 (uint64_t)1 << 20, &st));
        STM_ASSERT_EQ(st.bytes_promoted, pass == 0 ? 4096u : 0u);
        STM_ASSERT(st.last_err != STM_OK);
        STM_ASSERT_EQ(st.last_err_ino, f);
        STM_ASSERT_EQ(seal_extent_kind_at(sp.fs, sp.home.ds, f, 0),
                      STM_EXTENT_KIND_COLD);
        STM_ASSERT_EQ(seal_extent_kind_at(sp.fs, sp.home.ds, f, 8192),
                      STM_EXTENT_KIND_HOT);
    }
    uint8_t got[4096], want[4096];
    size_t n = 0;
    memset(want, 0x32, sizeof want);
    STM_ASSERT_OK(stm_fs_read(sp.fs, sp.home.ds, f, 8192, got, sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof got);
    STM_ASSERT_MEM_EQ(got, want, sizeof got);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

static int seal_reclaims;
static void seal_reclaim_hook(bool locked, void *arg)
{
    (void)locked;
    (void)arg;
    seal_reclaims++;
}

/* The login promote never reclaims (a reclaim drains and commits the whole
 * pool): a drain of the home's file that answers STM_ENOSPC stops the pass
 * with it, the fs not wedged. With the drain working, one variable away,
 * the same pass moves the file, its buffered write kept. */
STM_TEST(corvus_login_promote_never_reclaims_the_pool) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealrcl")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.home.ds, sp.home.big));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    uint8_t b[4096];
    memset(b, 0x61, sizeof b);
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, sp.sib.big, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    memset(b, 0x62, sizeof b);
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, sp.sib.big, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));        /* old blocks wait, PENDING */
    /* Buffered past the cold record, so the drain leaves it cold. */
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.home.ds, sp.home.big, 8192u + 10u,
                               "z", 1));
    seal_reclaims = 0;
    stm_fs_set_reclaim_hook_for_test(sp.fs, seal_reclaim_hook, NULL);
    stm_fs_fail_drains_for_test(sp.fs, STM_ENOSPC);
    stm_fs_promote_policy_stats st;
    stm_status pr = stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                               (uint64_t)1 << 20, &st);
    stm_fs_fail_drains_for_test(sp.fs, STM_OK);
    stm_fs_set_reclaim_hook_for_test(sp.fs, NULL, NULL);
    STM_ASSERT_ERR(pr, STM_ENOSPC);
    STM_ASSERT_ERR(st.last_err, STM_ENOSPC);
    STM_ASSERT_EQ(st.bytes_promoted, 0u);
    STM_ASSERT_EQ(seal_reclaims, 0);
    stm_fs_stats fst;
    STM_ASSERT_OK(stm_fs_stats_get(sp.fs, &fst));
    STM_ASSERT(!fst.wedged);
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.big),
                  STM_EXTENT_KIND_COLD);
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                             (uint64_t)1 << 20, &st));
    STM_ASSERT_EQ(st.inos_promoted, 1u);
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, sp.home.big),
                  STM_EXTENT_KIND_HOT);
    uint8_t want[4096], got[4096];
    size_t n = 0;
    memset(want, 0x5a, sizeof want);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_read(sp.fs, sp.home.ds, sp.home.big, 0, got,
                              sizeof got, &n));
    STM_ASSERT_EQ(n, sizeof got);
    STM_ASSERT_MEM_EQ(got, want, sizeof got);
    STM_ASSERT_OK(stm_fs_read(sp.fs, sp.home.ds, sp.home.big, 8192u + 10u,
                              got, 1, &n));
    STM_ASSERT_EQ(n, 1u);
    STM_ASSERT_EQ(got[0], 'z');
    seal_pool_close(&sp);
}

/* The pass leaves a sixteenth of the pool free past twice its bytes: with
 * the pool filled to just under that line for a 128 KiB pass, the pass is
 * refused and moves nothing. One variable away, a pass of one block, whose
 * line is lower, moves the same file (one record at least). */
STM_TEST(corvus_login_promote_leaves_a_sixteenth_of_the_pool_free) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealfloor")) return;
    const size_t K128 = (size_t)128 << 10;
    uint64_t f = seal_sparse_cold_file(sp.fs, sp.home.ds, "f128", 1, K128,
                                       0x66);
    seal_ext_sum e = seal_extents(sp.fs, sp.home.ds, f);
    STM_ASSERT_EQ(e.n, 1);
    STM_ASSERT_EQ(e.cold, 1);
    uint64_t fill = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, sp.sib.ds, 1,
                                     (const uint8_t *)"fill", 4, 0600, 1000,
                                     1000, &fill));
    uint8_t *b = malloc((size_t)64 << 10);
    STM_ASSERT(b != NULL);
    if (!b) { seal_pool_close(&sp); return; }
    memset(b, 0x77, (size_t)64 << 10);
    const uint64_t line_big = K128 / 4096u + 1u;      /* blocks per due, x2 */
    stm_fs_stats fst;
    uint64_t off = 0;
    for (int i = 0; i < 4000; i++) {
        STM_ASSERT_OK(stm_fs_stats_get(sp.fs, &fst));
        uint64_t floor = fst.data_total_blocks / 16u;
        if (fst.data_avail_blocks <= floor + line_big * 2u) break;
        size_t n = fst.data_avail_blocks > floor + line_big * 2u + 64u
                 ? (size_t)64 << 10 : 4096u;
        stm_status w = stm_fs_write(sp.fs, sp.sib.ds, fill, off, b, n);
        STM_ASSERT_OK(w);
        if (w != STM_OK) break;
        off += n;
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
    }
    free(b);
    STM_ASSERT_OK(stm_fs_stats_get(sp.fs, &fst));
    uint64_t floor = fst.data_total_blocks / 16u;
    printf("    floor %llu, avail %llu, filled %llu bytes\n",
           (unsigned long long)floor,
           (unsigned long long)fst.data_avail_blocks, (unsigned long long)off);
    STM_ASSERT(fst.data_avail_blocks <= floor + line_big * 2u);
    /* Room for the move (33 blocks) above the one-block pass's line. */
    STM_ASSERT(fst.data_avail_blocks > floor + 4u + line_big + 8u);
    stm_fs_promote_policy_stats st;
    STM_ASSERT_ERR(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, K128, &st),
                   STM_ENOSPC);
    STM_ASSERT_EQ(st.bytes_promoted, 0u);
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, f), STM_EXTENT_KIND_COLD);
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, 4096u, &st));
    STM_ASSERT_EQ(st.bytes_promoted, (uint64_t)K128);
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.home.ds, f), STM_EXTENT_KIND_HOT);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

typedef struct {
    stm_fs  *fs;
    uint64_t ds;
    bool     logout;
    int      calls;
    uint64_t ino[16], got[16];
} seal_step_log;

static void seal_step_hook(uint64_t ino, uint64_t got, void *arg)
{
    seal_step_log *l = arg;
    if (l->calls < 16) {
        l->ino[l->calls] = ino;
        l->got[l->calls] = got;
    }
    l->calls++;
    if (l->logout && l->calls == 1)
        STM_ASSERT_OK(stm_fs_evict_dek(l->fs, l->ds));
}

/* The pass moves a file a step (1 MiB) at a time, so a commit or a logout
 * waits one step: eight cold records of 256 KiB, a 2 MiB budget, two steps
 * of four records. A logout between two files stops the pass with
 * STM_ELOCKED, the second file left cold; the bounded promote stops at that
 * error too and says a record is left untried. */
STM_TEST(corvus_login_promote_moves_a_step_at_a_time_and_stops_at_a_logout) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "sealstep", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t STEP = (uint64_t)1 << 20;
    uint64_t f = seal_sparse_cold_file(sp.fs, sp.home.ds, "s8", 8,
                                       (size_t)256 << 10, 0x41);
    seal_ext_sum e = seal_extents(sp.fs, sp.home.ds, f);
    STM_ASSERT_EQ(e.n, 8);
    STM_ASSERT_EQ(e.cold, 8);
    STM_ASSERT_EQ(e.max_len, (uint64_t)256 << 10);
    seal_step_log l;
    memset(&l, 0, sizeof l);
    l.fs = sp.fs;
    l.ds = sp.home.ds;
    stm_fs_set_promote_step_hook_for_test(sp.fs, seal_step_hook, &l);
    stm_fs_promote_policy_stats st;
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, 2u * STEP, &st));
    STM_ASSERT_EQ(st.bytes_promoted, 2u * STEP);
    STM_ASSERT_EQ(l.calls, 2);
    for (int i = 0; i < l.calls && i < 16; i++) {
        STM_ASSERT_EQ(l.ino[i], f);
        STM_ASSERT_EQ(l.got[i], STEP);
    }
    STM_ASSERT_EQ(seal_extents(sp.fs, sp.home.ds, f).cold, 0);
    uint64_t c[2];
    c[0] = seal_sparse_cold_file(sp.fs, sp.home.ds, "c0", 2, 4096u, 0x51);
    c[1] = seal_sparse_cold_file(sp.fs, sp.home.ds, "c1", 2, 4096u, 0x52);
    memset(&l, 0, sizeof l);
    l.fs = sp.fs;
    l.ds = sp.home.ds;
    l.logout = true;
    stm_status pr = stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, 2u * STEP,
                                               &st);
    stm_fs_set_promote_step_hook_for_test(sp.fs, NULL, NULL);
    STM_ASSERT_ERR(pr, STM_ELOCKED);
    STM_ASSERT_ERR(st.last_err, STM_ELOCKED);
    STM_ASSERT_EQ(st.bytes_promoted, 8192u);
    STM_ASSERT(stm_fs_dataset_locked(sp.fs, sp.home.ds));
    seal_ext_sum a = seal_extents(sp.fs, sp.home.ds, c[0]);
    seal_ext_sum z = seal_extents(sp.fs, sp.home.ds, c[1]);
    STM_ASSERT_EQ(a.cold + z.cold, 2);
    uint64_t left = a.cold ? c[0] : c[1];
    stm_sync_promote_step ps;
    STM_ASSERT_ERR(stm_sync_promote_to_hot_bounded(sync, sp.home.ds, left, 0u,
                                                   STEP, &ps), STM_ELOCKED);
    STM_ASSERT_EQ(ps.bytes, 0u);
    STM_ASSERT_EQ(ps.tried, 0u);
    STM_ASSERT(ps.more);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* An older pool's pool-keyed clone of a home shares the home's cold record
 * (origin: the home). Promoting it would put the home's bytes under the
 * clone's key, the pool's: refused, logged in or out, the record left as it
 * is. A clone of the sibling, one variable away, promotes its shared record. */
STM_TEST(corvus_clone_of_a_home_cannot_promote_its_shared_cold_record) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "sealcpr")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    seal_tree *ts[2] = {&sp.home, &sp.sib};
    uint64_t clone[2] = {0, 0};
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    for (int i = 0; i < 2; i++) {
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ts[i]->ds, ts[i]->big));
        uint64_t snap = 0;
        STM_ASSERT_OK(stm_fs_create_snapshot(sp.fs, ts[i]->ds, "s", 1, &snap));
        stm_fs_set_clone_of_sealed_for_test(sp.fs, i == 0);
        STM_ASSERT_OK(stm_fs_create_clone(sp.fs, 1, i == 0 ? "c0" : "c1", snap,
                                          &clone[i]));
        stm_fs_set_clone_of_sealed_for_test(sp.fs, false);
    }
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    for (int leg = 0; leg < 2; leg++) {
        if (leg == 1) STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));
        STM_ASSERT_ERR(stm_sync_promote_to_hot(sync, clone[0], sp.home.big),
                       STM_ENOTSUPPORTED);
        STM_ASSERT_ERR(stm_sync_promote_cold_at(sync, clone[0], sp.home.big, 0, NULL),
                       STM_ENOTSUPPORTED);
        stm_extent_record r;
        memset(&r, 0, sizeof r);
        STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), clone[0],
                                           sp.home.big, 0, &r));
        STM_ASSERT_EQ((int)r.kind, (int)STM_EXTENT_KIND_COLD);
        STM_ASSERT_EQ(r.origin_dataset_id, sp.home.ds);
    }
    STM_ASSERT_OK(stm_sync_promote_to_hot(sync, clone[1], sp.sib.big));
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, clone[1], sp.sib.big),
                  STM_EXTENT_KIND_HOT);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* ========================================================================= */
/* Round 3 of T0.94: an older pool's oversized COLD records at a cover's    */
/* edges, the multi-piece promote's failures, a relogin inside a send's     */
/* init, and a login pass over unreadable records.                          */
/* ========================================================================= */

static void r3_noise17(uint8_t *p, size_t n)
{
    uint64_t x = 0x9E3779B97F4A7C15ull * 17u + 12345u;
    for (size_t j = 0; j + 8u <= n; j += 8u) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        memcpy(p + j, &x, 8);
    }
}

static void r3_read_all(stm_fs *fs, uint64_t ds, uint64_t ino, uint64_t off,
                        uint8_t *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        size_t got = 0;
        stm_status rs = stm_fs_read(fs, ds, ino, off + done, buf + done,
                                    len - done, &got);
        STM_ASSERT_OK(rs);
        if (rs != STM_OK || got == 0u) break;
        done += got;
    }
    STM_ASSERT_EQ(done, len);
}

/* A 64 MiB file migrated as an older pool's cold tier did (chunks
 * uncapped), whose records A = [0, 15622144), B, C = [22212608, 35303424)
 * have A + B + C over 4 recordsizes; a buffered rewrite from inside A to
 * inside C in 512 KiB writes, one drain run. Before, the cover took A and
 * C whole and the drain answered STM_ERANGE at every commit (another
 * file's write was lost), and a home's logout, which drains first, could
 * not evict its key. Now the cover promotes A and C. */
static void r3_big_edges(bool home)
{
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, home ? "r3edgeh" : "r3edge",
                           UINT64_C(1) << 30, UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t ds = home ? sp.home.ds : sp.sib.ds;
    const uint64_t REC = STM_FS_RECORDSIZE_MAX;
    const size_t LEN = (size_t)64 << 20;
    uint8_t *all = malloc(LEN);
    STM_ASSERT(all != NULL);
    if (!all) { seal_pool_close(&sp); return; }
    r3_noise17(all, LEN);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, ds, 1, (const uint8_t *)"b64", 3,
                                     0600, 1000, 1000, &f));
    for (size_t k = 0; k < LEN; k += (size_t)4 << 20)
        STM_ASSERT_OK(stm_fs_write(sp.fs, ds, f, k, all + k, (size_t)4 << 20));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, true);
    if (home) stm_sync_set_cas_admits_sealed_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ds, f));
    if (home) stm_sync_set_cas_admits_sealed_for_test(sync, false);
    stm_sync_set_cold_chunks_uncapped_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    const uint64_t lo = 15622144u - 4096u, hi = 22212608u + 4096u;
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record a, c;
    memset(&a, 0, sizeof a);
    memset(&c, 0, sizeof c);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, f, lo, &a));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, f, hi - 1u, &c));
    /* The layout under test: two COLD records over the recordsize, a
     * cover over 4 recordsizes. */
    STM_ASSERT_EQ(a.kind, STM_EXTENT_KIND_COLD);
    STM_ASSERT_EQ(c.kind, STM_EXTENT_KIND_COLD);
    STM_ASSERT(a.len > REC && c.len > REC);
    STM_ASSERT(c.off + c.len - a.off > 4u * REC);
    const uint64_t P = (uint64_t)512 << 10;
    for (uint64_t at = lo; at < hi; at += P) {
        size_t n = (hi - at) < P ? (size_t)(hi - at) : (size_t)P;
        memset(all + at, 'W', n);
        STM_ASSERT_OK(stm_fs_write(sp.fs, ds, f, at, all + at, n));
    }
    /* Admitted on what the drain writes: both promotes, and the cover over
     * the pieces at their edges, each block up to twice on one device (a
     * drain's pieces may be as short as the free runs). */
    stm_fs_stats fst;
    memset(&fst, 0, sizeof fst);
    STM_ASSERT_OK(stm_fs_stats_get(sp.fs, &fst));
    STM_ASSERT(fst.data_dirty_reserved_blocks >=
               2u * ((a.len + c.len + (c.off - a.off)) / 4096u));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_fsync(sp.fs, ds, f, NULL));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, f, lo, &a));
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, f, hi - 1u, &c));
    STM_ASSERT_EQ(a.kind, STM_EXTENT_KIND_HOT);
    STM_ASSERT_EQ(c.kind, STM_EXTENT_KIND_HOT);
    STM_ASSERT(a.len <= REC && c.len <= REC);
    const uint64_t r0 = lo - ((uint64_t)1 << 20), rn = (hi - lo) + ((uint64_t)2 << 20);
    uint8_t *got = malloc((size_t)rn);
    STM_ASSERT(got != NULL);
    if (home) {
        STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, ds));          /* the logout */
        STM_ASSERT(stm_fs_dataset_locked(sp.fs, ds));
        size_t n = 0;
        STM_ASSERT_ERR(stm_fs_read(sp.fs, ds, f, 0, got, 16, &n), STM_ELOCKED);
        STM_ASSERT_OK(stm_fs_install_dek(sp.fs, ds, &sp.cc));
    }
    uint64_t g = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, ds, 1, (const uint8_t *)"g", 1,
                                     0600, 1000, 1000, &g));
    STM_ASSERT_OK(stm_fs_write(sp.fs, ds, g, 0, "other", 5));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (got && !home && seal_pool_remount(&sp)) {
        r3_read_all(sp.fs, ds, f, r0, got, (size_t)rn);
        STM_ASSERT(memcmp(got, all + r0, (size_t)rn) == 0);
        uint64_t g2 = 0;
        uint8_t o[8] = {0};
        size_t n = 0;
        STM_ASSERT_OK(stm_fs_lookup(sp.fs, ds, 1, (const uint8_t *)"g", 1, &g2));
        STM_ASSERT_OK(stm_fs_read(sp.fs, ds, g2, 0, o, 5, &n));
        STM_ASSERT(n == 5u && memcmp(o, "other", 5) == 0);
    } else if (got) {
        r3_read_all(sp.fs, ds, f, r0, got, (size_t)rn);
        STM_ASSERT(memcmp(got, all + r0, (size_t)rn) == 0);
    }
    free(got);
    free(all);
    seal_pool_close(&sp);
}

STM_TEST(corvus_write_across_two_big_cold_records_promotes_them) {
    r3_big_edges(false);
}

STM_TEST(corvus_logout_after_a_write_across_two_big_cold_records_locks_the_home) {
    r3_big_edges(true);
}

/* The multi-piece promote: the second piece's index insert fails (the
 * index's put seam), after the first replaced the record: the handle
 * wedges and no commit makes the half-done index durable. */
STM_TEST(corvus_promote_whose_second_piece_insert_fails_wedges) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r3ins", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint64_t f = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.sib.ds, "c24", true, &f);
    if (!want) { seal_pool_close(&sp); return; }
    seal_ext_sum e = seal_extents(sp.fs, sp.sib.ds, f);
    STM_ASSERT(e.big_len > STM_FS_RECORDSIZE_MAX);
    stm_extent_fail_next_put_for_test(stm_sync_extent_index(sync), 2u, STM_ENOMEM);
    stm_status pr = stm_sync_promote_cold_at(sync, sp.sib.ds, f, e.big_off, NULL);
    stm_extent_fail_next_put_for_test(stm_sync_extent_index(sync), 0u, STM_OK);
    STM_ASSERT_ERR(pr, STM_EWEDGED);
    STM_ASSERT(stm_fs_commit(sp.fs) != STM_OK);
    free(want);
    seal_pool_close(&sp);
}

/* The second piece's device write fails: the promote answers the error,
 * the record stays COLD, and after a commit every block is free again,
 * the first piece's included. */
STM_TEST(corvus_promote_whose_second_piece_write_fails_frees_the_first) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r3pcw", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint64_t f = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.sib.ds, "h24", true, &f);
    if (!want) { seal_pool_close(&sp); return; }
    seal_ext_sum e = seal_extents(sp.fs, sp.sib.ds, f);
    STM_ASSERT(e.big_len > STM_FS_RECORDSIZE_MAX);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_fs_stats a, b;
    STM_ASSERT_OK(stm_fs_stats_get(sp.fs, &a));
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    stm_bdev_inject_fail_after(d, 2);
    stm_status pr = stm_sync_promote_cold_at(sync, sp.sib.ds, f, e.big_off, NULL);
    stm_bdev_inject_fail_after(d, 0);
    STM_ASSERT(pr != STM_OK);
    STM_ASSERT_EQ(seal_extent_kind_at(sp.fs, sp.sib.ds, f, e.big_off),
                  STM_EXTENT_KIND_COLD);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_stats_get(sp.fs, &b));
    STM_ASSERT_EQ(b.data_avail_blocks, a.data_avail_blocks);
    free(want);
    seal_pool_close(&sp);
}

/* A logout and a login inside stm_send_init stop the stream at its first
 * record, wherever they land: after the evict baseline is read and the
 * lock checked (the baseline must be that read, not a later one), and
 * after the key capture (the keys captured before a logout must not go
 * out). */
static stm_fs *g_relog_fs;
static uint64_t g_relog_ds;
static stm_corvus_mount_cfg *g_relog_cc;
static int g_relog_stage, g_relog_fired;
static stm_status g_relog_out, g_relog_in;

static void r3_relog_hook(void *ctx, int stage)
{
    (void)ctx;
    if (stage != g_relog_stage || g_relog_fired) return;
    g_relog_fired = 1;
    g_relog_out = stm_fs_evict_dek(g_relog_fs, g_relog_ds);
    g_relog_in  = stm_fs_install_dek(g_relog_fs, g_relog_ds, g_relog_cc);
}

static void r3_relog_send(int stage)
{
    seal_pool sp;
    if (!seal_pool_open(&sp, "r3relog")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    g_relog_fs = sp.fs;
    g_relog_ds = sp.home.ds;
    g_relog_cc = &sp.cc;
    g_relog_stage = stage;
    g_relog_fired = 0;
    g_relog_out = g_relog_in = STM_EINVAL;
    stm_send_set_init_hook_for_test(r3_relog_hook, NULL);
    stm_send_handle *h = NULL;
    stm_status ir = stm_send_init(sync, sp.home.ds, 0, 0, &h);
    stm_send_set_init_hook_for_test(NULL, NULL);
    STM_ASSERT_OK(ir);
    STM_ASSERT_EQ(g_relog_fired, 1);
    STM_ASSERT_OK(g_relog_out);
    STM_ASSERT_OK(g_relog_in);
    if (ir == STM_OK) {
        size_t cap = (size_t)1 << 16, n = 0, need = 0;
        uint8_t *buf = malloc(cap);
        int records = 0;
        stm_status r;
        while ((r = stm_send_next(h, buf, cap, &n, &need)) == STM_OK) records++;
        STM_ASSERT_ERR(r, STM_ELOCKED);
        STM_ASSERT_EQ(records, 0);
        free(buf);
        stm_send_close(h);
    }
    /* The control: with no relogin the same home sends records. */
    STM_ASSERT_OK(stm_send_init(sync, sp.home.ds, 0, 0, &h));
    if (h) {
        size_t cap = (size_t)1 << 16, n = 0, need = 0;
        uint8_t *buf = malloc(cap);
        int records = 0;
        while (stm_send_next(h, buf, cap, &n, &need) == STM_OK) records++;
        STM_ASSERT(records > 0);
        free(buf);
        stm_send_close(h);
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

STM_TEST(corvus_send_stops_after_a_relogin_past_its_lock_check) {
    r3_relog_send(STM_SEND_INIT_HOOK_AFTER_LOCK_CHECK);
}

STM_TEST(corvus_send_stops_after_a_relogin_after_its_key_capture) {
    r3_relog_send(STM_SEND_INIT_HOOK_BEFORE_PINS);
}

/* Damages, on the device, the first n records of a seal_sparse_cold_file
 * file of len-byte records. */
static void r3_damage(seal_pool *sp, uint64_t f, int n, uint64_t len)
{
    stm_sync *sync = stm_fs_sync(sp->fs);
    for (int k = 0; k < n; k++) {
        stm_extent_record e;
        memset(&e, 0, sizeof e);
        STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync),
                                           sp->home.ds, f,
                                           (uint64_t)k * 2u * len, &e));
        stm_cas_record cr;
        memset(&cr, 0, sizeof cr);
        STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(sync), e.content_hash,
                                     &cr));
        uint8_t junk[64];
        memset(junk, 0xee, sizeof junk);
        STM_ASSERT_OK(stm_bdev_write(stm_fs_bdev_for_test(sp->fs),
                                     stm_paddr_offset(cr.paddrs[0]) *
                                         (uint64_t)STM_UB_SIZE,
                                     junk, sizeof junk));
    }
}

/* A login pass tries an unreadable record once: it counts against the
 * pass's budget, the next step resumes past it, and the next pass where
 * this one stopped. A home file of eleven 256 KiB cold records whose
 * first three are damaged; passes of 2 MiB in 1 MiB steps. Before, each
 * step tried the damaged three again, and they cost nothing: two steps
 * moved 1 MiB each. */
static uint64_t g_r3_moved[8];
static int g_r3_steps;

static void r3_step_hook(uint64_t ino, uint64_t got, void *arg)
{
    (void)ino;
    (void)arg;
    if (g_r3_steps < 8) g_r3_moved[g_r3_steps] = got;
    g_r3_steps++;
}

STM_TEST(corvus_login_promote_tries_an_unreadable_record_once_a_pass) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r3bad", UINT64_C(256) << 20,
                           UINT64_C(16) << 20)) return;
    const uint64_t L = (uint64_t)256 << 10;
    uint64_t f = seal_sparse_cold_file(sp.fs, sp.home.ds, "bad3", 11, (size_t)L, 0x41);
    r3_damage(&sp, f, 3, L);
    const uint64_t want[3][3] = {
        { L, 4u * L, UINT64_MAX },          /* 3 damaged + 1, then 4 */
        { 3u * L, UINT64_MAX, UINT64_MAX }, /* from where it stopped: the last 3 */
        { 0, UINT64_MAX, UINT64_MAX },      /* round again: the 3 damaged */
    };
    stm_fs_set_promote_step_hook_for_test(sp.fs, r3_step_hook, NULL);
    for (int pass = 0; pass < 3; pass++) {
        g_r3_steps = 0;
        memset(g_r3_moved, 0, sizeof g_r3_moved);
        stm_fs_promote_policy_stats st;
        stm_status pr = stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                                   (uint64_t)2 << 20, &st);
        STM_ASSERT_OK(pr);
        STM_ASSERT((st.last_err != STM_OK) == (pass != 1));
        int n = 0;
        while (n < 3 && want[pass][n] != UINT64_MAX) n++;
        STM_ASSERT_EQ(g_r3_steps, n);
        for (int k = 0; k < n && k < g_r3_steps; k++)
            STM_ASSERT_EQ(g_r3_moved[k], want[pass][k]);
    }
    stm_fs_set_promote_step_hook_for_test(sp.fs, NULL, NULL);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* A file whose eight records are all damaged takes a whole pass's budget;
 * the next pass starts past it, at the file after it. Before (every pass
 * from the first file) no login moved the second file's records. */
STM_TEST(corvus_login_promote_resumes_past_a_file_of_unreadable_records) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r3res", UINT64_C(256) << 20,
                           UINT64_C(16) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t L = (uint64_t)256 << 10, PASS = (uint64_t)2 << 20;
    uint64_t bad = seal_sparse_cold_file(sp.fs, sp.home.ds, "bad8", 8, (size_t)L, 0x41);
    uint64_t good = seal_sparse_cold_file(sp.fs, sp.home.ds, "good4", 4, (size_t)L, 0x61);
    STM_ASSERT(bad < good);   /* a pass in ino order meets bad8 first */
    r3_damage(&sp, bad, 8, L);
    stm_fs_promote_policy_stats st;
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, PASS, &st));
    STM_ASSERT(st.last_err != STM_OK);
    STM_ASSERT_EQ(st.last_err_ino, bad);
    STM_ASSERT_EQ(st.bytes_promoted, 0u);
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds, PASS, &st));
    STM_ASSERT_EQ(st.bytes_promoted, 4u * L);
    for (int k = 0; k < 4; k++) {
        stm_extent_record e;
        memset(&e, 0, sizeof e);
        STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), sp.home.ds,
                                           good, (uint64_t)k * 2u * L, &e));
        STM_ASSERT_EQ(e.kind, STM_EXTENT_KIND_HOT);
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

/* Seventeen 512 KiB records 1 MiB apart, the last at 16 MiB, which the
 * extent index's key order (offsets stored little-endian) puts second.
 * Each step of the bounded promote resumes past the last record it tried,
 * so it needs a file's records in offset order (stm_extent_iter sorts
 * them): in key order its first 1 MiB step would end past every record but
 * the first, and the steps after it would skip them. */
STM_TEST(corvus_login_promote_moves_every_record_of_a_file_past_16_mib) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r3ord", UINT64_C(256) << 20,
                           UINT64_C(16) << 20)) return;
    const uint64_t L = (uint64_t)512 << 10;
    (void)seal_sparse_cold_file(sp.fs, sp.home.ds, "ord17", 17, (size_t)L, 0x21);
    stm_fs_promote_policy_stats st;
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, sp.home.ds,
                                             (uint64_t)32 << 20, &st));
    STM_ASSERT_EQ(st.last_err, STM_OK);
    STM_ASSERT_EQ(st.bytes_promoted, 17u * L);
    bool has_cold = true;
    STM_ASSERT_OK(stm_sync_dataset_has_cold(stm_fs_sync(sp.fs), sp.home.ds,
                                            &has_cold));
    STM_ASSERT(!has_cold);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    seal_pool_close(&sp);
}

static int g_r3_writes;
static stm_fs *g_r3_fs;

/* After the second piece's device write: the third piece's fails. */
static void r3_fail_third_piece(void *ctx)
{
    (void)ctx;
    if (++g_r3_writes == 2)
        stm_bdev_inject_fail_after(stm_fs_bdev_for_test(g_r3_fs), 1);
}

/* A direct write (a megabyte or more) over the whole of an older pool's
 * cold record over the recordsize, C of r3_big_edges' file: the cover's
 * edges are in the records beside it, and its split meets C inside. A
 * write replaces every record it overlaps whole, so the piece ending
 * inside C would take C's tail with it; the split promotes C first, so
 * that piece replaces only C's first piece. With `fail`, the piece after
 * it fails: the write lands a prefix and C's tail keeps its old bytes. */
static void r3_direct_over_big(bool fail)
{
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r3dir", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t ds = sp.sib.ds;
    const uint64_t REC = STM_FS_RECORDSIZE_MAX;
    const size_t LEN = (size_t)64 << 20;
    uint8_t *all = malloc(LEN);
    STM_ASSERT(all != NULL);
    if (!all) { seal_pool_close(&sp); return; }
    r3_noise17(all, LEN);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, ds, 1, (const uint8_t *)"d64", 3,
                                     0600, 1000, 1000, &f));
    uint8_t *old = malloc(LEN);
    STM_ASSERT(old != NULL);
    if (!old) { free(all); seal_pool_close(&sp); return; }
    memcpy(old, all, LEN);
    for (size_t k = 0; k < LEN; k += (size_t)4 << 20)
        STM_ASSERT_OK(stm_fs_write(sp.fs, ds, f, k, all + k, (size_t)4 << 20));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ds, f));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record c;
    memset(&c, 0, sizeof c);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, f, 22212608u, &c));
    STM_ASSERT_EQ(c.kind, STM_EXTENT_KIND_COLD);
    STM_ASSERT_EQ(c.off, 22212608u);
    STM_ASSERT(c.len > REC);
    const uint64_t lo = c.off - 4096u, hi = c.off + c.len + 4096u;
    memset(all + lo, 'D', (size_t)(hi - lo));
    size_t wrote = 0;
    if (fail) {
        g_r3_writes = 0;
        g_r3_fs = sp.fs;
        stm_sync_set_write_phase2_hook_for_test(sync, r3_fail_third_piece, NULL);
    }
    STM_ASSERT_OK(stm_fs_pwrite(sp.fs, ds, f, lo, all + lo, (size_t)(hi - lo),
                                &wrote));
    stm_sync_set_write_phase2_hook_for_test(sync, NULL, NULL);
    if (fail) {
        /* The pieces: [B.off, C.off), C's first recordsize, then C's
         * tail, which failed. */
        STM_ASSERT_EQ(stm_bdev_inject_fired_count(stm_fs_bdev_for_test(sp.fs)), 1u);
        STM_ASSERT_EQ((uint64_t)wrote, c.off + REC - lo);
        memcpy(all + lo + wrote, old + lo + wrote, (size_t)(hi - lo - wrote));
    } else {
        STM_ASSERT_EQ((uint64_t)wrote, hi - lo);
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_fsync(sp.fs, ds, f, NULL));
    for (uint64_t at = lo; !fail && at < hi; at += REC / 2u) {
        stm_extent_record e;
        memset(&e, 0, sizeof e);
        STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, f, at, &e));
        STM_ASSERT_EQ(e.kind, STM_EXTENT_KIND_HOT);
        STM_ASSERT(e.len <= REC);
    }
    const uint64_t r0 = lo - ((uint64_t)1 << 20), rn = (hi - lo) + ((uint64_t)2 << 20);
    uint8_t *got = malloc((size_t)rn);
    STM_ASSERT(got != NULL);
    if (got && seal_pool_remount(&sp)) {
        uint64_t f2 = 0;
        STM_ASSERT_OK(stm_fs_lookup(sp.fs, ds, 1, (const uint8_t *)"d64", 3, &f2));
        r3_read_all(sp.fs, ds, f2, r0, got, (size_t)rn);
        STM_ASSERT(memcmp(got, all + r0, (size_t)rn) == 0);
    }
    free(got);
    free(old);
    free(all);
    seal_pool_close(&sp);
}

STM_TEST(corvus_direct_write_over_a_whole_big_cold_record_promotes_it) {
    r3_direct_over_big(false);
}

STM_TEST(corvus_direct_write_over_a_big_cold_record_failing_part_way_keeps_its_tail) {
    r3_direct_over_big(true);
}

/* After the first piece's device write: the second piece's fails. */
static void r4_fail_second_piece(void *ctx)
{
    (void)ctx;
    if (++g_r3_writes == 1)
        stm_bdev_inject_fail_after(stm_fs_bdev_for_test(g_r3_fs), 1);
}

/* r3_direct_over_big's file, named `name`: *c is its cold record over the
 * recordsize at 22212608, and old holds every byte. */
static uint64_t r4_cold_file(seal_pool *sp, const char *name, uint8_t *old,
                             size_t LEN, stm_extent_record *c)
{
    stm_sync *sync = stm_fs_sync(sp->fs);
    const uint64_t ds = sp->sib.ds;
    r3_noise17(old, LEN);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp->fs, ds, 1, (const uint8_t *)name,
                                     (uint8_t)strlen(name), 0600, 1000, 1000, &f));
    for (size_t k = 0; k < LEN; k += (size_t)4 << 20)
        STM_ASSERT_OK(stm_fs_write(sp->fs, ds, f, k, old + k, (size_t)4 << 20));
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp->fs, ds, f));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    memset(c, 0, sizeof *c);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), ds, f,
                                       22212608u, c));
    STM_ASSERT_EQ(c->kind, STM_EXTENT_KIND_COLD);
    STM_ASSERT_EQ(c->off, 22212608u);
    STM_ASSERT(c->len > STM_FS_RECORDSIZE_MAX);
    return f;
}

/* X5: a send of a home holding an older pool's cold record over the wire
 * cap holds that record's decrypted chunk while its pieces' CHUNKs go. A
 * logout stops the stream (STM_ELOCKED) and wipes the chunk with the keys;
 * the sibling's stream, one variable away, keeps its chunk across the
 * home's logout, and lets it go once its CHUNKs end. */
STM_TEST(corvus_a_send_at_logout_wipes_a_long_cold_records_bytes) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "x5wipe", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)24 << 20;
    uint8_t *all = malloc(LEN);
    size_t cap = STM_SEND_RECORD_MAX_LEN;
    uint8_t *rec = malloc(cap);
    STM_ASSERT(all != NULL && rec != NULL);
    if (!all || !rec) { free(all); free(rec); seal_pool_close(&sp); return; }
    r3_noise17(all, LEN);
    const uint64_t ds[2] = {sp.home.ds, sp.sib.ds};
    stm_send_handle *sh[2] = {NULL, NULL};
    for (int i = 0; i < 2; i++) {
        uint64_t f = 0;
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, ds[i], 1, (const uint8_t *)"x5",
                                         2, 0600, 1000, 1000, &f));
        for (size_t k = 0; k < LEN; k += (size_t)4 << 20)
            STM_ASSERT_OK(stm_fs_write(sp.fs, ds[i], f, k, all + k,
                                       (size_t)4 << 20));
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
        stm_sync_set_cold_chunks_uncapped_for_test(sync, true);
        stm_sync_set_cas_admits_sealed_for_test(sync, true);
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ds[i], f));
        stm_sync_set_cas_admits_sealed_for_test(sync, false);
        stm_sync_set_cold_chunks_uncapped_for_test(sync, false);
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
        stm_extent_record a;
        memset(&a, 0, sizeof a);
        STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), ds[i],
                                           f, 0, &a));
        STM_ASSERT_EQ(a.kind, STM_EXTENT_KIND_COLD);
        STM_ASSERT(a.len > STM_SEND_CHUNK_PLAIN_MAX);

        size_t n = 0, need = 0;
        STM_ASSERT_OK(stm_send_init(sync, ds[i], 0, 0, &sh[i]));
        if (!sh[i]) continue;
        STM_ASSERT_OK(stm_send_next(sh[i], rec, cap, &n, &need));  /* HEADER */
        STM_ASSERT_OK(stm_send_next(sh[i], rec, cap, &n, &need));
        STM_ASSERT_EQ(rec[0], (uint8_t)STM_SEND_REC_CHUNK);
        STM_ASSERT(stm_send_parent_held_for_test(sh[i]));
    }
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));            /* logout */
    for (int i = 0; i < 2 && sh[0] && sh[1]; i++) {
        size_t n = 0, need = 0;
        stm_status r = stm_send_next(sh[i], rec, cap, &n, &need);
        if (i == 0) {
            STM_ASSERT_ERR(r, STM_ELOCKED);
            STM_ASSERT(!stm_send_parent_held_for_test(sh[i]));
            STM_ASSERT(stm_send_keys_wiped_for_test(sh[i]));
            continue;
        }
        STM_ASSERT_OK(r);
        STM_ASSERT(stm_send_parent_held_for_test(sh[i]));
        while (r == STM_OK && rec[0] == (uint8_t)STM_SEND_REC_CHUNK)
            r = stm_send_next(sh[i], rec, cap, &n, &need);
        STM_ASSERT_OK(r);
        STM_ASSERT_EQ(rec[0], (uint8_t)STM_SEND_REC_EXTENT);
        STM_ASSERT(!stm_send_parent_held_for_test(sh[i]));
        while ((r = stm_send_next(sh[i], rec, cap, &n, &need)) == STM_OK)
            ;
        STM_ASSERT_ERR(r, STM_ENOENT);
    }
    for (int i = 0; i < 2; i++)
        if (sh[i]) stm_send_close(sh[i]);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    free(all);
    free(rec);
    seal_pool_close(&sp);
}

/* After a remount, [r0, r0 + rn) of `name` reads as want does. */
static void r4_cold_check(seal_pool *sp, const char *name, const uint8_t *want,
                          uint64_t r0, uint64_t rn)
{
    uint8_t *got = malloc((size_t)rn);
    STM_ASSERT(got != NULL);
    if (got && seal_pool_remount(sp)) {
        uint64_t f2 = 0;
        STM_ASSERT_OK(stm_fs_lookup(sp->fs, sp->sib.ds, 1, (const uint8_t *)name,
                                    (uint8_t)strlen(name), &f2));
        r3_read_all(sp->fs, sp->sib.ds, f2, r0, got, (size_t)rn);
        STM_ASSERT(memcmp(got, want + r0, (size_t)rn) == 0);
    }
    free(got);
}

/* A direct write from C's last block on past it: the cover's lower edge is
 * inside C, so the edge promotes C and the first piece replaces only C's
 * last piece. The piece after it fails. However much of the write lands
 * (none, if the device error meets the first write past C's start), every
 * byte it did not land keeps its old bytes, C's among them. */
STM_TEST(corvus_direct_write_from_inside_a_big_cold_record_failing_part_way_keeps_it) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r4dirin", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    const size_t LEN = (size_t)64 << 20;
    const uint64_t REC = STM_FS_RECORDSIZE_MAX;
    uint8_t *old = malloc(LEN), *want = malloc(LEN);
    STM_ASSERT(old != NULL && want != NULL);
    if (!old || !want) { free(old); free(want); seal_pool_close(&sp); return; }
    stm_extent_record c;
    uint64_t f = r4_cold_file(&sp, "i64", old, LEN, &c);
    const uint64_t lo = c.off + c.len - 4096u, hi = lo + 2u * REC;
    STM_ASSERT(hi <= LEN);
    if (hi > LEN) { free(old); free(want); seal_pool_close(&sp); return; }
    memcpy(want, old, LEN);
    memset(want + lo, 'D', (size_t)(hi - lo));
    size_t wrote = 0;
    g_r3_writes = 0;
    g_r3_fs = sp.fs;
    stm_sync_set_write_phase2_hook_for_test(stm_fs_sync(sp.fs),
                                            r4_fail_second_piece, NULL);
    stm_status ws = stm_fs_pwrite(sp.fs, sp.sib.ds, f, lo, want + lo,
                                  (size_t)(hi - lo), &wrote);
    stm_sync_set_write_phase2_hook_for_test(stm_fs_sync(sp.fs), NULL, NULL);
    STM_ASSERT_EQ(stm_bdev_inject_fired_count(stm_fs_bdev_for_test(sp.fs)), 1u);
    STM_ASSERT((ws == STM_OK && wrote > 0u && wrote < hi - lo) ||
               (ws == STM_EIO && wrote == 0u));
    memcpy(want + lo + wrote, old + lo + wrote, (size_t)(hi - lo - wrote));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_fsync(sp.fs, sp.sib.ds, f, NULL));
    r4_cold_check(&sp, "i64", want, c.off, hi - c.off);
    free(old);
    free(want);
    seal_pool_close(&sp);
}

/* A buffered write over the last block before C and C's first block: the
 * cover's upper edge is inside C, so the edge promotes C and the run's
 * pieces end at C's first piece. A second run, near the file's end, makes
 * the third piece, which fails; the commit after it lands that run. C's
 * blocks past its first keep their old bytes. */
STM_TEST(corvus_buffered_write_ending_inside_a_big_cold_record_keeps_its_tail) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r4bufin", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    const size_t LEN = (size_t)64 << 20;
    uint8_t *old = malloc(LEN), *want = malloc(LEN);
    STM_ASSERT(old != NULL && want != NULL);
    if (!old || !want) { free(old); free(want); seal_pool_close(&sp); return; }
    stm_extent_record c;
    uint64_t f = r4_cold_file(&sp, "u64", old, LEN, &c);
    memcpy(want, old, LEN);
    const uint64_t lo = c.off - 4096u, far = LEN - 4096u;
    memset(want + lo, 'U', 8192u);
    memset(want + far, 'V', 100u);
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, f, lo, want + lo, 8192u));
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, f, far, want + far, 100u));
    g_r3_writes = 0;
    g_r3_fs = sp.fs;
    stm_sync_set_write_phase2_hook_for_test(stm_fs_sync(sp.fs),
                                            r3_fail_third_piece, NULL);
    STM_ASSERT_ERR(stm_fs_commit(sp.fs), STM_EIO);
    stm_sync_set_write_phase2_hook_for_test(stm_fs_sync(sp.fs), NULL, NULL);
    STM_ASSERT_EQ(stm_bdev_inject_fired_count(stm_fs_bdev_for_test(sp.fs)), 1u);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_fsync(sp.fs, sp.sib.ds, f, NULL));
    r4_cold_check(&sp, "u64", want, lo - STM_FS_RECORDSIZE_MAX,
                  c.len + 2u * STM_FS_RECORDSIZE_MAX);
    free(old);
    free(want);
    seal_pool_close(&sp);
}

/* ========================================================================= */
/* Review round 4: an older pool's big COLD record on a fragmented pool.      */
/* ========================================================================= */

/* Cut the pool's free space into 1024-block holes: no free run holds one
 * promote part of the recordsize (2049 blocks with its tag). */
static void r4_fragment(stm_sync *sync)
{
    stm_alloc *al = stm_sync_alloc(sync, 0);
    static uint64_t pas[8192];
    size_t n = 0;
    stm_alloc_set_guarded(al, false);
    while (n < 8192u && stm_alloc_reserve(al, 1024u, 0, &pas[n]) == STM_OK)
        n++;
    for (size_t i = 0; i < n; i += 2)
        STM_ASSERT_OK(stm_alloc_unreserve(al, pas[i]));
    uint64_t pa = 0;
    STM_ASSERT_ERR(stm_alloc_reserve(al, 2049u, 0, &pa), STM_ENOSPC);
    stm_alloc_set_guarded(al, true);
}

/* A file whose first record is an older pool's COLD record over the
 * recordsize (the migrate uncapped); *a is that record. */
static uint64_t r4_big_file(seal_pool *sp, uint64_t ds, bool home,
                            uint8_t *all, size_t LEN, stm_extent_record *a)
{
    stm_sync *sync = stm_fs_sync(sp->fs);
    r3_noise17(all, LEN);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp->fs, ds, 1, (const uint8_t *)"b64", 3,
                                     0600, 1000, 1000, &f));
    for (size_t k = 0; k < LEN; k += (size_t)4 << 20)
        STM_ASSERT_OK(stm_fs_write(sp->fs, ds, f, k, all + k, (size_t)4 << 20));
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, true);
    if (home) stm_sync_set_cas_admits_sealed_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp->fs, ds, f));
    if (home) stm_sync_set_cas_admits_sealed_for_test(sync, false);
    stm_sync_set_cold_chunks_uncapped_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    memset(a, 0, sizeof *a);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), ds, f, 0, a));
    STM_ASSERT_EQ(a->kind, STM_EXTENT_KIND_COLD);
    STM_ASSERT(a->len > STM_FS_RECORDSIZE_MAX);
    return f;
}

/* A 10-byte buffered write near the end of the big record on a fragmented
 * pool: the drain's promote writes the record back in pieces, the commit
 * succeeds, and another file's write commits after it. `pend`: blocks a
 * commit freed wait to be swept, so a failing flush would reclaim. In a
 * home the logout after it locks the home. */
static void r4_frag_edge(bool home, bool pend)
{
    seal_pool sp;
    const char *tag = home ? "r4fragh" : (pend ? "r4fragp" : "r4frag");
    if (!seal_pool_open_sz(&sp, tag, UINT64_C(1) << 30, UINT64_C(128) << 20))
        return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t ds = home ? sp.home.ds : sp.sib.ds;
    const size_t LEN = (size_t)64 << 20;
    uint8_t *all = malloc(LEN);
    STM_ASSERT(all != NULL);
    if (!all) { seal_pool_close(&sp); return; }
    stm_extent_record a;
    uint64_t f = r4_big_file(&sp, ds, home, all, LEN, &a);
    r4_fragment(sync);
    if (pend) {
        uint64_t p = 0;
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, ds, 1, (const uint8_t *)"p", 1,
                                         0600, 1000, 1000, &p));
        static uint8_t pb[256u << 10];
        memset(pb, 'p', sizeof pb);
        STM_ASSERT_OK(stm_fs_write(sp.fs, ds, p, 0, pb, sizeof pb));
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
        STM_ASSERT_OK(stm_fs_write(sp.fs, ds, p, 0, pb, sizeof pb));
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
        STM_ASSERT(stm_sync_pending_free_blocks(sync) > 0u);
    }
    const uint64_t at = a.off + a.len - 100u;
    STM_ASSERT_OK(stm_fs_write(sp.fs, ds, f, at, "wwwwwwwwww", 10));
    memcpy(all + at, "wwwwwwwwww", 10);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_fs_stats fst;
    memset(&fst, 0, sizeof fst);
    STM_ASSERT_OK(stm_fs_stats_get(sp.fs, &fst));
    STM_ASSERT(!fst.wedged);
    /* Back as HOT records, more than the two parts a run would hold. */
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    unsigned n = 0;
    for (uint64_t o = a.off; o < a.off + a.len; ) {
        stm_extent_record e;
        memset(&e, 0, sizeof e);
        STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, f, o, &e));
        STM_ASSERT_EQ(e.kind, STM_EXTENT_KIND_HOT);
        if (e.len == 0u) break;
        o = e.off + e.len;
        n++;
    }
    STM_ASSERT(n > 2u);
    uint8_t *got = malloc((size_t)a.len);
    STM_ASSERT(got != NULL);
    if (got) {
        r3_read_all(sp.fs, ds, f, a.off, got, (size_t)a.len);
        STM_ASSERT(memcmp(got, all + a.off, (size_t)a.len) == 0);
        free(got);
    }
    if (home) {
        STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, ds));
        STM_ASSERT(stm_fs_dataset_locked(sp.fs, ds));
        uint8_t b[16];
        size_t nb = 0;
        STM_ASSERT_ERR(stm_fs_read(sp.fs, ds, f, 0, b, sizeof b, &nb),
                       STM_ELOCKED);
    } else {
        uint64_t g = 0;
        STM_ASSERT_OK(stm_fs_create_file(sp.fs, ds, 1, (const uint8_t *)"g", 1,
                                         0600, 1000, 1000, &g));
        STM_ASSERT_OK(stm_fs_write(sp.fs, ds, g, 0, "other", 5));
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
    }
    free(all);
    seal_pool_close(&sp);
}

STM_TEST(corvus_write_into_a_big_cold_record_on_a_fragmented_pool_commits) {
    r4_frag_edge(false, false);
}

STM_TEST(corvus_write_into_a_big_cold_record_on_a_fragmented_pool_with_frees_pending_commits) {
    r4_frag_edge(false, true);
}

STM_TEST(corvus_logout_after_a_write_into_a_big_cold_record_on_a_fragmented_pool_locks_the_home) {
    r4_frag_edge(true, false);
}

/* A login pass on a fragmented pool moves a file of an older pool's big
 * COLD record and the file of small records after it. */
STM_TEST(corvus_login_promote_on_a_fragmented_pool_moves_a_big_record_and_what_follows) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r4starve", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t ds = sp.home.ds;
    const size_t LEN = (size_t)64 << 20;
    uint8_t *all = malloc(LEN);
    STM_ASSERT(all != NULL);
    if (!all) { seal_pool_close(&sp); return; }
    stm_extent_record a;
    uint64_t big = r4_big_file(&sp, ds, true, all, LEN, &a);
    free(all);
    uint64_t small = seal_sparse_cold_file(sp.fs, ds, "r4small", 4,
                                           (size_t)256 << 10, 0x61);
    STM_ASSERT(big < small);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    r4_fragment(sync);
    stm_fs_promote_policy_stats st;
    memset(&st, 0, sizeof st);
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, ds, (uint64_t)128 << 20, &st));
    STM_ASSERT_EQ(st.last_err, STM_OK);
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    stm_extent_record e;
    memset(&e, 0, sizeof e);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, big, a.off, &e));
    STM_ASSERT_EQ(e.kind, STM_EXTENT_KIND_HOT);
    memset(&e, 0, sizeof e);
    STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, small, 0, &e));
    STM_ASSERT_EQ(e.kind, STM_EXTENT_KIND_HOT);
    seal_pool_close(&sp);
}

/* A pass the pool stops in a file (here its raw drain's STM_ENOSPC) starts
 * the next pass in that file, not past it. */
STM_TEST(corvus_login_promote_resumes_in_the_file_a_pool_error_stopped_it_in) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "r4stop", UINT64_C(256) << 20,
                           UINT64_C(64) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t ds = sp.home.ds;
    const size_t P = (size_t)256 << 10;
    uint64_t fa = seal_sparse_cold_file(sp.fs, ds, "ra", 4, P, 0x61);
    uint64_t fb = seal_sparse_cold_file(sp.fs, ds, "rb", 4, P, 0x62);
    STM_ASSERT(fa < fb);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    STM_ASSERT_OK(stm_fs_write(sp.fs, ds, fa, 10, "dirty", 5));
    stm_fs_fail_drains_for_test(sp.fs, STM_ENOSPC);
    stm_fs_promote_policy_stats st;
    memset(&st, 0, sizeof st);
    STM_ASSERT_ERR(stm_fs_promote_sealed_cold(sp.fs, ds, 4u * P, &st),
                   STM_ENOSPC);
    STM_ASSERT_EQ(st.bytes_promoted, 0u);
    stm_fs_fail_drains_for_test(sp.fs, STM_OK);
    memset(&st, 0, sizeof st);
    STM_ASSERT_OK(stm_fs_promote_sealed_cold(sp.fs, ds, 4u * P, &st));
    stm_extent_index *eidx = stm_sync_extent_index(sync);
    for (unsigned k = 0; k < 4u; k++) {
        stm_extent_record e;
        memset(&e, 0, sizeof e);
        uint64_t o = (uint64_t)k * 2u * P;
        if (stm_extent_lookup_at(eidx, ds, fa, o, &e) != STM_OK) {
            o = (uint64_t)k * P;
            STM_ASSERT_OK(stm_extent_lookup_at(eidx, ds, fa, o, &e));
        }
        STM_ASSERT_EQ(e.kind, STM_EXTENT_KIND_HOT);
    }
    (void)fb;
    seal_pool_close(&sp);
}

/* A logout inside stm_send_init, after the key capture and before the
 * split: the init unwraps none of the home's long cold chunks (the hook
 * arms the next device read to fail, and none fires), and the stream
 * answers STM_ELOCKED from its first record. The control, one variable
 * away (no logout): that armed read is the split's, and the init fails. */
static stm_fs *g_x5r_fs;
static uint64_t g_x5r_ds;
static int g_x5r_logout, g_x5r_fired;
static stm_status g_x5r_out;

static void x5r_hook(void *ctx, int stage)
{
    (void)ctx;
    if (stage != STM_SEND_INIT_HOOK_BEFORE_PINS || g_x5r_fired) return;
    g_x5r_fired = 1;
    g_x5r_out = g_x5r_logout ? stm_fs_evict_dek(g_x5r_fs, g_x5r_ds) : STM_OK;
    stm_bdev_inject_read_fail_after(stm_fs_bdev_for_test(g_x5r_fs), 1);
}

static void x5r_case(int logout)
{
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, logout ? "x5rlo" : "x5rct", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)24 << 20;
    uint8_t *all = malloc(LEN);
    STM_ASSERT(all != NULL);
    if (!all) { seal_pool_close(&sp); return; }
    r3_noise17(all, LEN);
    uint64_t f = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, sp.home.ds, 1, (const uint8_t *)"x5",
                                     2, 0600, 1000, 1000, &f));
    for (size_t k = 0; k < LEN; k += (size_t)4 << 20)
        STM_ASSERT_OK(stm_fs_write(sp.fs, sp.home.ds, f, k, all + k,
                                   (size_t)4 << 20));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_sync_set_cold_chunks_uncapped_for_test(sync, true);
    stm_sync_set_cas_admits_sealed_for_test(sync, true);
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, sp.home.ds, f));
    stm_sync_set_cas_admits_sealed_for_test(sync, false);
    stm_sync_set_cold_chunks_uncapped_for_test(sync, false);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    stm_extent_record a;
    memset(&a, 0, sizeof a);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(sync), sp.home.ds,
                                       f, 0, &a));
    STM_ASSERT(a.len > STM_SEND_CHUNK_PLAIN_MAX);

    g_x5r_fs = sp.fs;
    g_x5r_ds = sp.home.ds;
    g_x5r_logout = logout;
    g_x5r_fired = 0;
    g_x5r_out = STM_EINVAL;
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    uint32_t fired0 = stm_bdev_inject_read_fired_count(d);
    stm_send_set_init_hook_for_test(x5r_hook, NULL);
    stm_send_handle *h = NULL;
    stm_status ir = stm_send_init(sync, sp.home.ds, 0, 0, &h);
    stm_send_set_init_hook_for_test(NULL, NULL);
    stm_bdev_inject_read_fail_after(d, 0);
    uint32_t fired = stm_bdev_inject_read_fired_count(d) - fired0;
    stm_test_info("x5r logout=%d: init %d, evict %d, injected reads fired %u",
                  logout, (int)ir, (int)g_x5r_out, fired);
    STM_ASSERT_EQ(g_x5r_fired, 1);
    STM_ASSERT_OK(g_x5r_out);
    if (logout) {
        STM_ASSERT_OK(ir);
        STM_ASSERT_EQ(fired, 0u);
        STM_ASSERT(h != NULL);
    } else {
        STM_ASSERT_ERR(ir, STM_EIO);
        STM_ASSERT_EQ(fired, 1u);
        STM_ASSERT(h == NULL);
    }
    if (h) {
        size_t cap = STM_SEND_RECORD_MAX_LEN, n = 0, need = 0;
        uint8_t *buf = malloc(cap);
        stm_status r = buf ? stm_send_next(h, buf, cap, &n, &need) : STM_ENOMEM;
        STM_ASSERT_ERR(r, STM_ELOCKED);
        STM_ASSERT(!stm_send_parent_held_for_test(h));
        free(buf);
        stm_send_close(h);
    }
    if (logout)
        STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    free(all);
    seal_pool_close(&sp);
}

STM_TEST(corvus_a_logout_inside_the_send_init_unwraps_no_long_cold_chunk) {
    x5r_case(1);
    x5r_case(0);
}


/* ========================================================================= */
/* A big COLD record the drain's promote cannot read (O1, round 5 F1).        */
/* ========================================================================= */

/* The chunk of COLD record c on every replica: its device bytes faulted
 * `times` reads each (every one when < 0), EIO or read with a byte
 * flipped. */
static void o1_fault_chunk(seal_pool *sp, const stm_extent_record *c,
                           int64_t times, bool flip)
{
    stm_sync *sync = stm_fs_sync(sp->fs);
    stm_cas_record cr;
    memset(&cr, 0, sizeof cr);
    STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(sync), c->content_hash, &cr));
    struct stm_bdev *d = stm_fs_bdev_for_test(sp->fs);
    for (uint8_t i = 0; i < cr.n_replicas && i < 4u; i++) {
        uint64_t lo = stm_paddr_offset(cr.paddrs[i]) * 4096u;
        stm_bdev_inject_read_range(d, lo, lo + cr.length, times,
                                   flip ? STM_OK : STM_EIO);
    }
    stm_sync_dcache_drain_for_test(sync);
}

/* c's content entry dereferenced and collected; put back with length
 * c->len + delta when delta is not 0. */
static void o1_take_chunk(seal_pool *sp, const stm_extent_record *c,
                          uint64_t delta)
{
    stm_sync *sync = stm_fs_sync(sp->fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    stm_cas_record cr;
    memset(&cr, 0, sizeof cr);
    STM_ASSERT_OK(stm_cas_lookup(cas, c->content_hash, &cr));
    for (uint32_t k = 0; k < cr.refcount; k++)
        STM_ASSERT_OK(stm_cas_deref(cas, c->content_hash));
    uint64_t pads[8];
    size_t np = 0;
    STM_ASSERT_OK(stm_cas_gc(cas, c->content_hash, pads, 8, &np));
    if (delta != 0u)
        STM_ASSERT_OK(stm_cas_insert(cas, c->content_hash, cr.paddrs,
                                     cr.n_replicas, cr.length + delta, cr.gen));
    stm_sync_dcache_drain_for_test(sync);
}

enum o1_big_damage {
    O1_TAG_ALWAYS, O1_EIO_ALWAYS, O1_TAG_ONCE, O1_EIO_ONCE, O1_NO_ENTRY,
    O1_ENTRY_LEN
};

/* A 10-byte buffered write near the end of an older pool's big COLD record
 * damaged as `dmg` says: the drain's lower widening meets the record and
 * its promote is the first to read it. A damage that stays drops the run
 * (f's fsync answers EIO once) and the pool commits another file; one that
 * clears on the promote's re-read costs nothing, and the write is there. */
static void o1_big_case(const char *tag, enum o1_big_damage dmg)
{
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, tag, UINT64_C(1) << 30, UINT64_C(128) << 20))
        return;
    const uint64_t ds = sp.sib.ds;
    const size_t LEN = (size_t)64 << 20;
    uint8_t *all = malloc(LEN);
    STM_ASSERT(all != NULL);
    if (!all) { seal_pool_close(&sp); return; }
    stm_extent_record a;
    uint64_t f = r4_big_file(&sp, ds, false, all, LEN, &a);
    free(all);
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    stm_cas_record cr;
    memset(&cr, 0, sizeof cr);
    STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(stm_fs_sync(sp.fs)),
                                 a.content_hash, &cr));
    const bool clears = (dmg == O1_TAG_ONCE || dmg == O1_EIO_ONCE);
    switch (dmg) {
    case O1_TAG_ALWAYS: o1_fault_chunk(&sp, &a, -1, true);  break;
    case O1_EIO_ALWAYS: o1_fault_chunk(&sp, &a, -1, false); break;
    case O1_TAG_ONCE:   o1_fault_chunk(&sp, &a, 1, true);   break;
    case O1_EIO_ONCE:   o1_fault_chunk(&sp, &a, 1, false);  break;
    case O1_NO_ENTRY:   o1_take_chunk(&sp, &a, 0u);         break;
    case O1_ENTRY_LEN:  o1_take_chunk(&sp, &a, 4096u);      break;
    }
    const uint64_t at = a.off + a.len - 100u;
    STM_ASSERT_OK(stm_fs_write(sp.fs, ds, f, at, "wwwwwwwwww", 10));
    stm_status c1 = stm_fs_commit(sp.fs);
    uint32_t fired = stm_bdev_inject_read_range_fired(d);
    stm_bdev_inject_read_range_clear(d);
    uint64_t g = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, ds, 1, (const uint8_t *)"g", 1,
                                     0600, 1000, 1000, &g));
    STM_ASSERT_OK(stm_fs_write(sp.fs, ds, g, 0, "other", 5));
    stm_status c2 = stm_fs_commit(sp.fs);
    stm_status fy = stm_fs_fsync(sp.fs, ds, f, NULL);
    fprintf(stderr, "  info: o1 big %s: commit %d, faulted reads %u (replicas "
            "%u), other commit %d, fsync %d\n", tag, (int)c1, (unsigned)fired,
            (unsigned)cr.n_replicas, (int)c2, (int)fy);
    STM_ASSERT_OK(c1);
    STM_ASSERT_OK(c2);
    if (clears) {
        STM_ASSERT(fired == cr.n_replicas);
        STM_ASSERT_OK(fy);
        uint8_t b[10];
        size_t got = 0;
        memset(b, 0, sizeof b);
        STM_ASSERT_OK(stm_fs_read(sp.fs, ds, f, at, b, sizeof b, &got));
        STM_ASSERT(got == sizeof b && memcmp(b, "wwwwwwwwww", 10) == 0);
    } else {
        if (dmg == O1_TAG_ALWAYS || dmg == O1_EIO_ALWAYS)
            STM_ASSERT(fired >= 2u * cr.n_replicas);
        STM_ASSERT_ERR(fy, STM_EIO);
        STM_ASSERT_OK(stm_fs_fsync(sp.fs, ds, f, NULL));
    }
    if (c1 != STM_OK || c2 != STM_OK) {
        stm_status u = stm_fs_unmount(sp.fs);
        fprintf(stderr, "  info: o1 big %s: unmount %d\n", tag, (int)u);
        sp.fs = NULL;
    }
    seal_pool_close(&sp);
}

STM_TEST(corvus_a_drain_promote_of_a_damaged_big_cold_record_drops_the_run) {
    o1_big_case("o1btag", O1_TAG_ALWAYS);
}

STM_TEST(corvus_a_bad_sector_under_a_big_cold_record_drops_the_run) {
    o1_big_case("o1beio", O1_EIO_ALWAYS);
}

STM_TEST(corvus_a_tag_failure_that_clears_on_the_promotes_re_read_costs_no_write) {
    o1_big_case("o1btag1", O1_TAG_ONCE);
}

STM_TEST(corvus_a_read_error_that_clears_on_the_promotes_re_read_costs_no_write) {
    o1_big_case("o1beio1", O1_EIO_ONCE);
}

STM_TEST(corvus_a_write_into_a_big_cold_record_with_no_content_entry_is_dropped) {
    o1_big_case("o1bgone", O1_NO_ENTRY);
}

STM_TEST(corvus_a_write_into_a_big_cold_record_its_content_entry_disowns_is_dropped) {
    o1_big_case("o1blen", O1_ENTRY_LEN);
}


/* A direct write (over 1 MiB) starting at an older pool's big COLD record
 * whose chunk answers EIO on every read: the direct write promotes the
 * record first, a reader that drops nothing, so it reads each replica
 * once and answers the EIO to its caller; nothing is dropped. */
STM_TEST(corvus_a_direct_write_into_a_big_cold_record_reads_a_bad_sector_once) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "o1bdirect", UINT64_C(1) << 30,
                           UINT64_C(128) << 20))
        return;
    const uint64_t ds = sp.sib.ds;
    const size_t LEN = (size_t)64 << 20;
    uint8_t *all = malloc(LEN);
    STM_ASSERT(all != NULL);
    if (!all) { seal_pool_close(&sp); return; }
    stm_extent_record a;
    uint64_t f = r4_big_file(&sp, ds, false, all, LEN, &a);
    free(all);
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    stm_cas_record cr;
    memset(&cr, 0, sizeof cr);
    STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(stm_fs_sync(sp.fs)),
                                 a.content_hash, &cr));
    STM_ASSERT(a.len > (uint64_t)STM_FS_RECORDSIZE_MAX);
    o1_fault_chunk(&sp, &a, -1, false);
    const size_t WL = (size_t)STM_FS_RECORDSIZE_MAX + 4096u;
    uint8_t *w = malloc(WL);
    STM_ASSERT(w != NULL);
    if (!w) { seal_pool_close(&sp); return; }
    memset(w, 'v', WL);
    const uint32_t f0 = stm_bdev_inject_read_range_fired(d);
    stm_status ws = stm_fs_write(sp.fs, ds, f, a.off, w, WL);
    const uint32_t fired = stm_bdev_inject_read_range_fired(d) - f0;
    stm_bdev_inject_read_range_clear(d);
    free(w);
    fprintf(stderr, "  info: direct write %d, faulted reads %u (replicas %u)\n",
            (int)ws, (unsigned)fired, (unsigned)cr.n_replicas);
    STM_ASSERT_ERR(ws, STM_EIO);
    STM_ASSERT_EQ(fired, (uint32_t)cr.n_replicas);
    STM_ASSERT_OK(stm_fs_fsync(sp.fs, ds, f, NULL));
    seal_pool_close(&sp);
}


/* ========================================================================= */
/* The promote writes with s->lock free (o1b, x6 round 5 F3).                 */
/* ========================================================================= */

enum { O1B_NOTE, O1B_REPLACE, O1B_PRUNE, O1B_WEDGE, O1B_COMMIT };

typedef struct {
    seal_pool      *sp;
    int             mode;
    int             calls;      /* every hook call */
    int             lock_free;  /* calls that found s->lock free */
    int             fired;      /* the first call acted */
    uint64_t        ds, ino;
    const uint8_t  *repl;       /* O1B_REPLACE: written over the record */
    size_t          len;
    size_t          pruned;     /* O1B_PRUNE: keys the sweep took */
    uint64_t        gen0, gen1; /* the pool's gen before, after the act */
    stm_hybrid_keys wk;
} o1b_hook;

static void o1b_hook_fn(void *arg)
{
    o1b_hook *h = arg;
    stm_sync *sync = stm_fs_sync(h->sp->fs);
    h->calls++;
    if (stm_sync_lock_is_free_for_test(sync)) h->lock_free++;
    /* NOTE only notes: under the old locked promote this runs under
     * s->lock, which stm_sync_current_gen takes. */
    if (h->mode == O1B_NOTE || h->fired) return;
    h->fired = 1;
    h->gen0 = stm_sync_current_gen(sync);
    uint64_t nk = 0, ok_ = 0;
    switch (h->mode) {
    case O1B_REPLACE:
        /* The record's place gets another COLD record of its length:
         * the same bytes overwritten, then moved to the cold tier. */
        STM_ASSERT_OK(stm_fs_write(h->sp->fs, h->ds, h->ino, 0, h->repl,
                                   h->len));
        STM_ASSERT_OK(stm_fs_migrate_to_cold(h->sp->fs, h->ds, h->ino));
        break;
    case O1B_PRUNE:
        /* The promote's key, CURRENT with no record yet, retires and
         * goes in the sweep. */
        STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, h->ds, &h->wk, NULL,
                                                  &nk, &ok_));
        STM_ASSERT_OK(stm_sync_keyschema_sweep(sync, h->ds, &h->pruned));
        break;
    case O1B_WEDGE:
        stm_sync_mark_wedged(sync);
        break;
    case O1B_COMMIT:
        STM_ASSERT_OK(stm_fs_commit(h->sp->fs));
        break;
    default:
        break;
    }
    h->gen1 = stm_sync_current_gen(sync);
}

/* A file of `len` incompressible bytes moved to the cold tier as one
 * record at 0; *out its record. Returns the bytes; the caller frees. */
static uint8_t *o1b_cold_file(seal_pool *sp, uint64_t ds, const char *name,
                              size_t len, uint64_t seed, uint64_t *ino,
                              stm_extent_record *out)
{
    uint8_t *b = malloc(len);
    STM_ASSERT(b != NULL);
    if (!b) return NULL;
    seal_noise(&seed, b, len);
    STM_ASSERT_OK(stm_fs_create_file(sp->fs, ds, 1, (const uint8_t *)name,
                                     (uint8_t)strlen(name), 0600, 1000, 1000,
                                     ino));
    STM_ASSERT_OK(stm_fs_write(sp->fs, ds, *ino, 0, b, len));
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(sp->fs, ds, *ino));
    STM_ASSERT_OK(stm_fs_commit(sp->fs));
    seal_ext_sum e = seal_extents(sp->fs, ds, *ino);
    STM_ASSERT_EQ(e.n, 1);
    STM_ASSERT_EQ(e.cold, 1);
    STM_ASSERT_EQ(e.big_len, (uint64_t)len);
    memset(out, 0, sizeof *out);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(stm_fs_sync(sp->fs)),
                                       ds, *ino, 0, out));
    return b;
}

static stm_extent_record o1b_rec_at0(seal_pool *sp, uint64_t ds, uint64_t ino)
{
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    STM_ASSERT_OK(stm_extent_lookup_at(stm_sync_extent_index(stm_fs_sync(sp->fs)),
                                       ds, ino, 0, &r));
    return r;
}

typedef struct { stm_sync *s; int seen; } o1b_probe;

static void o1b_probe_held_hook(void *arg)
{
    o1b_probe *p = arg;
    p->seen = stm_sync_lock_is_free_for_test(p->s) ? 2 : 1;
}

/* The device I/O a promote does, each op with whether it found s->lock
 * free (stm_sync_lock_is_free_for_test answers held to the holder too). */
#define O1B_IO_MAX 4096
typedef struct {
    stm_sync  *s;
    atomic_int n;
    struct { bool w, lock_free; uint64_t off; size_t len; } op[O1B_IO_MAX];
} o1b_io_log;

static void o1b_io_fn(void *ctx, bool is_write, uint64_t off, size_t len)
{
    o1b_io_log *l = ctx;
    int i = atomic_fetch_add(&l->n, 1);
    if (i >= O1B_IO_MAX) return;
    l->op[i].w = is_write;
    l->op[i].off = off;
    l->op[i].len = len;
    l->op[i].lock_free = stm_sync_lock_is_free_for_test(l->s);
}

/* A file's records' device bytes on device 0: each COLD record's chunk
 * (cold), or each HOT record's replicas (!cold). */
#define O1B_SPANS_MAX 256
typedef struct {
    stm_sync *s;
    bool      cold;
    int       n;
    uint64_t  lo[O1B_SPANS_MAX], hi[O1B_SPANS_MAX];
} o1b_spans;

static void o1b_span_add(o1b_spans *v, uint64_t paddr, uint64_t len)
{
    if (stm_paddr_device(paddr) != 0u) return;
    STM_ASSERT(v->n < O1B_SPANS_MAX);
    if (v->n >= O1B_SPANS_MAX) return;
    uint64_t lo = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    v->lo[v->n] = lo;
    v->hi[v->n] = lo + len + stm_aead_tag_len(STM_AEAD_AEGIS256);
    v->n++;
}

static bool o1b_span_cb(const stm_extent_record *e, void *cx)
{
    o1b_spans *v = cx;
    if (v->cold && e->kind == STM_EXTENT_KIND_COLD) {
        stm_cas_record cr;
        memset(&cr, 0, sizeof cr);
        STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(v->s),
                                     e->content_hash, &cr));
        for (uint8_t i = 0; i < cr.n_replicas; i++)
            o1b_span_add(v, cr.paddrs[i], cr.length);
    } else if (!v->cold && e->kind == STM_EXTENT_KIND_HOT) {
        for (uint8_t i = 0; i < e->n_replicas; i++)
            o1b_span_add(v, e->paddrs[i], e->len);
    }
    return true;
}

static o1b_spans o1b_spans_of(stm_sync *s, uint64_t ds, uint64_t ino,
                              bool cold)
{
    o1b_spans v;
    memset(&v, 0, sizeof v);
    v.s = s;
    v.cold = cold;
    STM_ASSERT_OK(stm_extent_iter(stm_sync_extent_index(s), ds, ino,
                                  o1b_span_cb, &v));
    return v;
}

static bool o1b_in(const o1b_spans *v, uint64_t off, size_t len)
{
    for (int k = 0; k < v->n; k++)
        if (off < v->hi[k] && off + len > v->lo[k]) return true;
    return false;
}

/* The logged ops on the chunks' and the pieces' bytes: chunk reads, piece
 * writes, and how many of all of them found s->lock held and free. */
typedef struct { int reads, writes, held, unheld; } o1b_io_tally;

static o1b_io_tally o1b_tally(o1b_io_log *l, const o1b_spans *cold,
                              const o1b_spans *hot)
{
    o1b_io_tally t = { 0, 0, 0, 0 };
    int n = atomic_load(&l->n);
    STM_ASSERT(n <= O1B_IO_MAX);
    if (n > O1B_IO_MAX) n = O1B_IO_MAX;
    for (int i = 0; i < n; i++) {
        bool c = o1b_in(cold, l->op[i].off, l->op[i].len);
        bool h = o1b_in(hot, l->op[i].off, l->op[i].len);
        if (!c && !h) continue;
        if (!l->op[i].w && c) t.reads++;
        if (l->op[i].w && h) t.writes++;
        if (l->op[i].lock_free) t.unheld++;
        else t.held++;
    }
    return t;
}

/* One record's HOT blocks on a one-device pool: ceil((len + tag) / UB). */
static uint64_t o1b_blocks(size_t len)
{
    size_t tag = stm_aead_tag_len(STM_AEAD_AEGIS256);
    return (uint64_t)((len + tag + STM_UB_SIZE - 1u) / STM_UB_SIZE);
}

static void o1b_alloc_counts(stm_sync *sync, uint64_t *alloc, uint64_t *pend)
{
    stm_alloc_stats st;
    memset(&st, 0, sizeof st);
    STM_ASSERT_OK(stm_alloc_stats_get(stm_sync_alloc(sync, 0), &st));
    *alloc = st.data_allocated_blocks;
    *pend  = st.data_pending_blocks;
}

/* The lowest and highest gen and link_gen of a file's HOT records. */
typedef struct { uint64_t lo, hi; bool any; } o1b_gens;

static bool o1b_gens_cb(const stm_extent_record *e, void *cx)
{
    o1b_gens *v = cx;
    if (e->kind != STM_EXTENT_KIND_HOT) return true;
    uint64_t lo = e->gen < e->link_gen ? e->gen : e->link_gen;
    uint64_t hi = e->gen > e->link_gen ? e->gen : e->link_gen;
    if (!v->any || lo < v->lo) v->lo = lo;
    if (!v->any || hi > v->hi) v->hi = hi;
    v->any = true;
    return true;
}

static o1b_gens o1b_gens_of(stm_sync *s, uint64_t ds, uint64_t ino)
{
    o1b_gens v = { 0, 0, false };
    STM_ASSERT_OK(stm_extent_iter(stm_sync_extent_index(s), ds, ino,
                                  o1b_gens_cb, &v));
    return v;
}

/* Each COLD record's chunk is read, and each HOT piece written, with
 * s->lock free: an observer on the pool's device logs every read and write
 * with whether s->lock was free, and every op on the chunks' and the
 * pieces' bytes found it free (and the promote's seam, once a record). The
 * file reads its bytes, HOT, before and after a remount. Controls: from
 * the evict's seam, under s->lock, the probe answers held; through the
 * same observer, the fully locked promote (stm_sync_promote_cold_at, the
 * drain's covering write) of another file does its chunk read and piece
 * writes with the lock held. */
STM_TEST(corvus_promote_writes_its_records_with_the_sync_lock_free) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "o1blk", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    o1b_probe pr = { .s = sync, .seen = 0 };
    stm_sync_set_evict_published_hook_for_test(sync, o1b_probe_held_hook, &pr);
    STM_ASSERT_OK(stm_fs_evict_dek(sp.fs, sp.home.ds));
    stm_sync_set_evict_published_hook_for_test(sync, NULL, NULL);
    STM_ASSERT_OK(stm_fs_install_dek(sp.fs, sp.home.ds, &sp.cc));
    STM_ASSERT_EQ(pr.seen, 1);                 /* held, seen as held */
    STM_ASSERT(stm_sync_lock_is_free_for_test(sync));

    o1b_io_log *l = calloc(1, sizeof *l);
    STM_ASSERT(l != NULL);
    if (!l) { seal_pool_close(&sp); return; }
    l->s = sync;
    stm_bdev_io_observer ob = { .fn = o1b_io_fn, .ctx = l };

    const size_t LEN = (size_t)256 << 10;
    uint64_t k = 0;
    stm_extent_record kc;
    uint8_t *kwant = o1b_cold_file(&sp, sp.sib.ds, "lk", LEN, 0x1c1c3d3dull,
                                   &k, &kc);
    if (!kwant) { free(l); seal_pool_close(&sp); return; }
    o1b_spans kcold = o1b_spans_of(sync, sp.sib.ds, k, true);
    atomic_store(&l->n, 0);
    stm_bdev_set_io_observer_for_test(d, &ob);
    STM_ASSERT_OK(stm_sync_promote_cold_at(sync, sp.sib.ds, k, 0, NULL));
    stm_bdev_set_io_observer_for_test(d, NULL);
    o1b_spans khot = o1b_spans_of(sync, sp.sib.ds, k, false);
    o1b_io_tally kt = o1b_tally(l, &kcold, &khot);
    printf("    locked: %d chunk reads, %d piece writes; %d held, %d free\n",
           kt.reads, kt.writes, kt.held, kt.unheld);
    STM_ASSERT(kcold.n >= 1 && khot.n >= 1);
    STM_ASSERT(kt.reads >= 1);
    STM_ASSERT(kt.writes >= 1);
    STM_ASSERT_EQ(kt.unheld, 0);

    uint64_t g = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.sib.ds, "b24", true, &g);
    if (!want) { free(kwant); free(l); seal_pool_close(&sp); return; }
    seal_ext_sum e = seal_extents(sp.fs, sp.sib.ds, g);
    STM_ASSERT_EQ(e.cold, e.n);
    STM_ASSERT(e.max_len > (uint64_t)STM_FS_RECORDSIZE_MAX);
    o1b_spans gcold = o1b_spans_of(sync, sp.sib.ds, g, true);
    o1b_hook h = { .sp = &sp, .mode = O1B_NOTE };
    atomic_store(&l->n, 0);
    stm_bdev_set_io_observer_for_test(d, &ob);
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_hook_fn, &h);
    STM_ASSERT_OK(stm_sync_promote_to_hot(sync, sp.sib.ds, g));
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    stm_bdev_set_io_observer_for_test(d, NULL);
    seal_ext_sum a = seal_extents(sp.fs, sp.sib.ds, g);
    o1b_spans ghot = o1b_spans_of(sync, sp.sib.ds, g, false);
    o1b_io_tally t = o1b_tally(l, &gcold, &ghot);
    printf("    %d cold records -> %d HOT: %d chunk reads, %d piece writes; "
           "%d held, %d free; %d hook calls, %d with the lock free\n",
           e.n, a.n, t.reads, t.writes, t.held, t.unheld, h.calls,
           h.lock_free);
    STM_ASSERT(t.reads >= e.n);
    STM_ASSERT(t.writes >= a.n);
    STM_ASSERT_EQ(t.held, 0);
    STM_ASSERT_EQ(h.calls, e.n);
    STM_ASSERT_EQ(h.lock_free, e.n);
    STM_ASSERT_EQ(a.cold, 0);
    STM_ASSERT(a.max_len <= (uint64_t)STM_FS_RECORDSIZE_MAX);
    STM_ASSERT_EQ(a.sum, (uint64_t)SEAL_BIG_LEN);
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, g, 0, want, SEAL_BIG_LEN);
    seal_read_eq(sp.fs, sp.sib.ds, k, 0, kwant, LEN);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (seal_pool_remount_session(&sp))
        seal_read_eq(sp.fs, sp.sib.ds, g, 0, want, SEAL_BIG_LEN);
    free(want);
    free(kwant);
    free(l);
    seal_pool_close(&sp);
}

/* A record overwritten and moved to the cold tier again while the promote
 * wrote, the same length at the same place, is left as it now is: the file
 * reads the new bytes, from a COLD record, and the bounded step counts it
 * tried, not moved. One variable away, with nothing landing in the window,
 * the record is promoted, counted moved, and reads its own. */
static void o1b_replace_case(bool act)
{
    seal_pool sp;
    if (!seal_pool_open(&sp, act ? "o1brp" : "o1brq")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *old = o1b_cold_file(&sp, sp.sib.ds, "r", LEN, 0x5151a1a1ull,
                                 &f, &c);
    uint8_t *nw = malloc(LEN);
    STM_ASSERT(old != NULL && nw != NULL);
    if (!old || !nw) { free(old); free(nw); seal_pool_close(&sp); return; }
    uint64_t seed = 0x7272b2b2ull;
    seal_noise(&seed, nw, LEN);
    o1b_hook h = { .sp = &sp, .mode = act ? O1B_REPLACE : O1B_NOTE,
                   .ds = sp.sib.ds, .ino = f, .repl = nw, .len = LEN };
    stm_sync_promote_step st;
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_hook_fn, &h);
    STM_ASSERT_OK(stm_sync_promote_to_hot_bounded(sync, sp.sib.ds, f, 0,
                                                  4u * LEN, &st));
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    STM_ASSERT_EQ(h.calls, 1);
    if (act) STM_ASSERT_EQ(h.gen1, h.gen0);   /* no commit: the identity */
    STM_ASSERT_EQ(st.tried, (uint64_t)LEN);
    STM_ASSERT_EQ(st.bytes, act ? 0u : (uint64_t)LEN);   /* moved */
    stm_extent_record r = o1b_rec_at0(&sp, sp.sib.ds, f);
    STM_ASSERT_EQ(r.len, (uint64_t)LEN);
    stm_sync_dcache_drain_for_test(sync);
    if (act) {
        STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_COLD);
        STM_ASSERT(memcmp(r.content_hash, c.content_hash,
                          STM_EXTENT_HASH_LEN) != 0);
        seal_read_eq(sp.fs, sp.sib.ds, f, 0, nw, LEN);
    } else {
        STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_HOT);
        seal_read_eq(sp.fs, sp.sib.ds, f, 0, old, LEN);
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (seal_pool_remount(&sp))
        seal_read_eq(sp.fs, sp.sib.ds, f, 0, act ? nw : old, LEN);
    free(old);
    free(nw);
    seal_pool_close(&sp);
}

STM_TEST(corvus_promote_leaves_a_record_changed_while_it_wrote) {
    o1b_replace_case(true);
    o1b_replace_case(false);
}

/* A commit while the promote wrote closes the gen its parts were
 * encrypted in: that record goes again with fresh blocks (one hook call
 * more), so every HOT record is indexed in the gen it was written in, the
 * one open at its swap (gen = link_gen = the gen now), and the file reads
 * its bytes before and after a remount. */
STM_TEST(corvus_promote_goes_again_when_a_commit_closes_its_gen) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "o1bgn", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint64_t g = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.sib.ds, "b24", true, &g);
    if (!want) { seal_pool_close(&sp); return; }
    seal_ext_sum e = seal_extents(sp.fs, sp.sib.ds, g);
    o1b_hook h = { .sp = &sp, .mode = O1B_COMMIT };
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_hook_fn, &h);
    STM_ASSERT_OK(stm_sync_promote_to_hot(sync, sp.sib.ds, g));
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    STM_ASSERT_EQ(h.fired, 1);
    STM_ASSERT(h.gen1 > h.gen0);               /* the commit moved it */
    STM_ASSERT_EQ(h.calls, e.n + 1);
    seal_ext_sum a = seal_extents(sp.fs, sp.sib.ds, g);
    STM_ASSERT_EQ(a.cold, 0);
    o1b_gens gg = o1b_gens_of(sync, sp.sib.ds, g);
    STM_ASSERT(gg.any);
    STM_ASSERT_EQ(gg.lo, stm_sync_current_gen(sync));
    STM_ASSERT_EQ(gg.hi, stm_sync_current_gen(sync));
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, g, 0, want, SEAL_BIG_LEN);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (seal_pool_remount(&sp))
        seal_read_eq(sp.fs, sp.sib.ds, g, 0, want, SEAL_BIG_LEN);
    free(want);
    seal_pool_close(&sp);
}

/* The promote's key, CURRENT and not yet named by any record, is retired
 * and pruned while the promote wrote: the promote goes again under the new
 * key (a second hook call), and the file reads its bytes. */
STM_TEST(corvus_promote_goes_again_when_its_key_is_pruned_under_it) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "o1bpr")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *want = o1b_cold_file(&sp, sp.sib.ds, "k", LEN, 0x3434c4c4ull,
                                  &f, &c);
    if (!want) { seal_pool_close(&sp); return; }
    o1b_hook h = { .sp = &sp, .mode = O1B_PRUNE, .ds = sp.sib.ds };
    STM_ASSERT_OK(stm_keyfile_load(sp.key_path, &h.wk));
    uint64_t nk = 0, ok_ = 0;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, sp.sib.ds, &h.wk, NULL,
                                              &nk, &ok_));
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_hook_fn, &h);
    STM_ASSERT_OK(stm_sync_promote_to_hot(sync, sp.sib.ds, f));
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    STM_ASSERT_EQ(h.pruned, 1u);
    STM_ASSERT_EQ(h.gen1, h.gen0);             /* no commit: the key */
    STM_ASSERT_EQ(h.calls, 2);
    stm_extent_record r = o1b_rec_at0(&sp, sp.sib.ds, f);
    STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_HOT);
    STM_ASSERT(r.key_id != nk);
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, f, 0, want, LEN);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (seal_pool_remount(&sp))
        seal_read_eq(sp.fs, sp.sib.ds, f, 0, want, LEN);
    free(want);
    seal_pool_close(&sp);
}

/* A wedge while the promote wrote: STM_EWEDGED, the record is still the
 * COLD one it was, and the parts' blocks went back (PENDING), none kept. */
STM_TEST(corvus_promote_swaps_nothing_once_the_handle_wedged) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "o1bwg")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *want = o1b_cold_file(&sp, sp.sib.ds, "w", LEN, 0x9a9a1b1bull,
                                  &f, &c);
    if (!want) { seal_pool_close(&sp); return; }
    o1b_hook h = { .sp = &sp, .mode = O1B_WEDGE };
    uint64_t a0 = 0, p0 = 0, a1 = 0, p1 = 0;
    o1b_alloc_counts(sync, &a0, &p0);
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_hook_fn, &h);
    STM_ASSERT_ERR(stm_sync_promote_to_hot(sync, sp.sib.ds, f), STM_EWEDGED);
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    o1b_alloc_counts(sync, &a1, &p1);
    printf("    allocated %+lld, pending %+lld (one record = %llu blocks)\n",
           (long long)(a1 - a0), (long long)(p1 - p0),
           (unsigned long long)o1b_blocks(LEN));
    STM_ASSERT_EQ(a1, a0);
    STM_ASSERT(p1 >= p0 + o1b_blocks(LEN));
    STM_ASSERT_EQ(h.calls, 1);
    stm_extent_record r = o1b_rec_at0(&sp, sp.sib.ds, f);
    STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_COLD);
    STM_ASSERT_MEM_EQ(r.content_hash, c.content_hash, STM_EXTENT_HASH_LEN);
    (void)stm_fs_unmount(sp.fs);
    sp.fs = NULL;
    free(want);
    seal_pool_close(&sp);
}

/* The chunk's first read fails while s->lock is free: the locked body reads
 * it again, and its answer is the promote's. Once (`times` 1), the second
 * read succeeds and the record moves, with no hook call (the unlocked try
 * stopped before it); every read failing (`times` 2), the record stays
 * COLD and the promote answers the read's error. */
static void o1b_read_case(int64_t times)
{
    seal_pool sp;
    if (!seal_pool_open(&sp, times == 1 ? "o1brd" : "o1bre")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *want = o1b_cold_file(&sp, sp.sib.ds, "e", LEN, 0x6e6e2f2full,
                                  &f, &c);
    if (!want) { seal_pool_close(&sp); return; }
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    stm_cas_record cr;
    memset(&cr, 0, sizeof cr);
    STM_ASSERT_OK(stm_cas_lookup(stm_sync_cas_index(sync), c.content_hash, &cr));
    STM_ASSERT_EQ(cr.n_replicas, 1u);
    o1_fault_chunk(&sp, &c, times, false);
    o1b_hook h = { .sp = &sp, .mode = O1B_NOTE };
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_hook_fn, &h);
    const uint32_t f0 = stm_bdev_inject_read_range_fired(d);
    stm_status rc = stm_sync_promote_to_hot(sync, sp.sib.ds, f);
    const uint32_t fired = stm_bdev_inject_read_range_fired(d) - f0;
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    stm_bdev_inject_read_range_clear(d);
    STM_ASSERT_EQ(fired, (uint32_t)times);
    STM_ASSERT_EQ(h.calls, 0);
    stm_extent_record r = o1b_rec_at0(&sp, sp.sib.ds, f);
    if (times == 1) {
        STM_ASSERT_OK(rc);
        STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_HOT);
    } else {
        STM_ASSERT_ERR(rc, STM_EIO);
        STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_COLD);
    }
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, f, 0, want, LEN);
    free(want);
    seal_pool_close(&sp);
}

STM_TEST(corvus_promote_reads_a_failed_chunk_again_under_the_lock) {
    o1b_read_case(1);
    o1b_read_case(2);
}

/* The key pruned under every unlocked try: four tries roll back, then the
 * fully locked body runs (no hook call) and promotes under the key CURRENT
 * at its end. The hook stops pruning past six calls, so a promote that
 * does not stop trying ends with more calls than four rather than hangs. */
typedef struct {
    seal_pool      *sp;
    uint64_t        ds;
    int             calls;
    size_t          pruned;
    uint64_t        last_new;
    stm_hybrid_keys wk;
} o1b_prune_all;

static void o1b_prune_all_fn(void *arg)
{
    o1b_prune_all *h = arg;
    stm_sync *sync = stm_fs_sync(h->sp->fs);
    uint64_t nk = 0, ok_ = 0;
    size_t n = 0;
    if (++h->calls > 6) return;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, h->ds, &h->wk, NULL,
                                              &nk, &ok_));
    STM_ASSERT_OK(stm_sync_keyschema_sweep(sync, h->ds, &n));
    h->pruned += n;
    h->last_new = nk;
}

STM_TEST(corvus_promote_runs_fully_locked_once_every_try_lost_its_key) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "o1bex")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *want = o1b_cold_file(&sp, sp.sib.ds, "k4", LEN, 0x4545d5d5ull,
                                  &f, &c);
    if (!want) { seal_pool_close(&sp); return; }
    o1b_prune_all h;
    memset(&h, 0, sizeof h);
    h.sp = &sp;
    h.ds = sp.sib.ds;
    STM_ASSERT_OK(stm_keyfile_load(sp.key_path, &h.wk));
    uint64_t nk = 0, ok_ = 0;
    STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, sp.sib.ds, &h.wk, NULL,
                                              &nk, &ok_));
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_prune_all_fn, &h);
    stm_status rc = stm_sync_promote_to_hot(sync, sp.sib.ds, f);
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    printf("    rc %d, hook calls %d, pruned %zu\n", (int)rc, h.calls,
           h.pruned);
    STM_ASSERT_OK(rc);
    STM_ASSERT_EQ(h.calls, 4);
    STM_ASSERT_EQ(h.pruned, (size_t)4);
    stm_extent_record r = o1b_rec_at0(&sp, sp.sib.ds, f);
    STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_HOT);
    STM_ASSERT_EQ(r.key_id, h.last_new);
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, f, 0, want, LEN);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (seal_pool_remount(&sp))
        seal_read_eq(sp.fs, sp.sib.ds, f, 0, want, LEN);
    stm_hybrid_keys_wipe(&h.wk);
    free(want);
    seal_pool_close(&sp);
}

/* What the unlocked promote reserved and did not index goes back: the
 * allocator's data blocks counted across the promote, no commit between.
 *   DROP : the record truncated away in the window (changed)
 *          -> allocated unchanged, pending up a record.
 *   PRUNE: the key pruned once (a try lost, then a swap)
 *          -> allocated up a record, pending up a record.
 *   STORE: the promote's first device write fails
 *          -> allocated unchanged, pending up a record, STM_EIO.
 *   COMMIT: a commit in the window (a try lost, then a swap)
 *          -> allocated up a record (the commit moves the pending ones).
 * A reservation may take a block more than asked (the allocator's spare
 * fit), so these are bounds. */
enum { O1B_ACCT_DROP, O1B_ACCT_PRUNE, O1B_ACCT_STORE, O1B_ACCT_COMMIT };

typedef struct {
    seal_pool      *sp;
    int             mode;
    int             calls;
    uint64_t        ds, ino;
    uint64_t        gen0, gen1;
    stm_hybrid_keys wk;
} o1b_acct;

static void o1b_acct_fn(void *arg)
{
    o1b_acct *h = arg;
    stm_sync *sync = stm_fs_sync(h->sp->fs);
    if (h->calls++) return;
    uint64_t nk = 0, ok_ = 0;
    size_t n = 0;
    h->gen0 = stm_sync_current_gen(sync);
    switch (h->mode) {
    case O1B_ACCT_DROP:
        STM_ASSERT_OK(stm_sync_truncate(sync, h->ds, h->ino, 0, NULL));
        break;
    case O1B_ACCT_PRUNE:
        STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, h->ds, &h->wk, NULL,
                                                  &nk, &ok_));
        STM_ASSERT_OK(stm_sync_keyschema_sweep(sync, h->ds, &n));
        STM_ASSERT_EQ(n, (size_t)1);
        break;
    case O1B_ACCT_COMMIT:
        STM_ASSERT_OK(stm_fs_commit(h->sp->fs));
        break;
    default:
        break;
    }
    h->gen1 = stm_sync_current_gen(sync);
}

static void o1b_acct_case(int mode)
{
    seal_pool sp;
    const char *tag = mode == O1B_ACCT_DROP ? "o1bad" :
                      mode == O1B_ACCT_PRUNE ? "o1bap" :
                      mode == O1B_ACCT_STORE ? "o1bas" : "o1bac";
    if (!seal_pool_open(&sp, tag)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    const uint64_t NB = o1b_blocks(LEN);
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *want = o1b_cold_file(&sp, sp.sib.ds, "a", LEN, 0x5a5a6b6bull,
                                  &f, &c);
    if (!want) { seal_pool_close(&sp); return; }
    o1b_acct h;
    memset(&h, 0, sizeof h);
    h.sp = &sp;
    h.mode = mode;
    h.ds = sp.sib.ds;
    h.ino = f;
    if (mode == O1B_ACCT_PRUNE) {
        uint64_t nk = 0, ok_ = 0;
        STM_ASSERT_OK(stm_keyfile_load(sp.key_path, &h.wk));
        STM_ASSERT_OK(stm_sync_rotate_dataset_key(sync, sp.sib.ds, &h.wk,
                                                  NULL, &nk, &ok_));
    }
    uint64_t a0 = 0, p0 = 0, a1 = 0, p1 = 0;
    o1b_alloc_counts(sync, &a0, &p0);
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    if (mode == O1B_ACCT_STORE) stm_bdev_inject_fail_after(d, 1);
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_acct_fn, &h);
    stm_status rc = stm_sync_promote_to_hot(sync, sp.sib.ds, f);
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    if (mode == O1B_ACCT_STORE) stm_bdev_inject_fail_after(d, 0);
    o1b_alloc_counts(sync, &a1, &p1);
    printf("    mode %d: rc %d, calls %d, allocated %+lld, pending %+lld "
           "(one record = %llu blocks)\n", mode, (int)rc, h.calls,
           (long long)(a1 - a0), (long long)(p1 - p0),
           (unsigned long long)NB);
    switch (mode) {
    case O1B_ACCT_DROP:
        STM_ASSERT_OK(rc);
        STM_ASSERT_EQ(h.calls, 1);
        STM_ASSERT_EQ(h.gen1, h.gen0);
        STM_ASSERT_EQ(a1, a0);                       /* nothing kept */
        STM_ASSERT(p1 >= p0 + NB);                   /* rolled back */
        break;
    case O1B_ACCT_PRUNE:
        STM_ASSERT_OK(rc);
        STM_ASSERT_EQ(h.calls, 2);
        STM_ASSERT_EQ(h.gen1, h.gen0);
        STM_ASSERT(a1 >= a0 + NB && a1 <= a0 + NB + 1u);  /* one record */
        STM_ASSERT(p1 >= p0 + NB);                   /* try 1 rolled back */
        break;
    case O1B_ACCT_COMMIT:
        STM_ASSERT_OK(rc);
        STM_ASSERT_EQ(h.calls, 2);
        STM_ASSERT(h.gen1 > h.gen0);
        STM_ASSERT(a1 >= a0 + NB && a1 <= a0 + NB + 1u);  /* one record */
        break;
    default:
        STM_ASSERT_ERR(rc, STM_EIO);
        STM_ASSERT_EQ(h.calls, 0);
        STM_ASSERT_EQ(a1, a0);
        STM_ASSERT(p1 >= p0 + NB);
        break;
    }
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    if (mode == O1B_ACCT_PRUNE) stm_hybrid_keys_wipe(&h.wk);
    free(want);
    seal_pool_close(&sp);
}

STM_TEST(corvus_promote_gives_back_every_block_it_did_not_index) {
    o1b_acct_case(O1B_ACCT_DROP);
    o1b_acct_case(O1B_ACCT_PRUNE);
    o1b_acct_case(O1B_ACCT_STORE);
    o1b_acct_case(O1B_ACCT_COMMIT);
}

/* A snapshot taken (with its commit) while the promote wrote: the record
 * goes again in the new gen, so the HOT record is not older than the
 * snapshot, and an overwrite after it frees the HOT block rather than put
 * it on the snapshot's dead list (the snapshot never had it: it held the
 * COLD record). */
typedef struct {
    seal_pool *sp;
    uint64_t   ds;
    int        calls;
    uint64_t   snap;
} o1b_snap;

static void o1b_snap_fn(void *arg)
{
    o1b_snap *h = arg;
    if (h->calls++) return;
    STM_ASSERT_OK(stm_fs_create_snapshot(h->sp->fs, h->ds, "w", 1, &h->snap));
}

STM_TEST(corvus_promote_across_a_snapshot_lists_no_block_the_snapshot_never_had) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "o1bsn")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *old = o1b_cold_file(&sp, sp.sib.ds, "s", LEN, 0x1b1b2c2cull,
                                 &f, &c);
    uint8_t *nw = malloc(LEN);
    STM_ASSERT(old != NULL && nw != NULL);
    if (!old || !nw) { free(old); free(nw); seal_pool_close(&sp); return; }
    uint64_t seed = 0x3d3d4e4eull;
    seal_noise(&seed, nw, LEN);
    o1b_snap h = { .sp = &sp, .ds = sp.sib.ds };
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_snap_fn, &h);
    STM_ASSERT_OK(stm_sync_promote_to_hot(sync, sp.sib.ds, f));
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    STM_ASSERT_EQ(h.calls, 2);
    stm_extent_record r = o1b_rec_at0(&sp, sp.sib.ds, f);
    STM_ASSERT_EQ(r.kind, STM_EXTENT_KIND_HOT);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    stm_snapshot_entry se;
    memset(&se, 0, sizeof se);
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, h.snap, &se));
    printf("    HOT gen %llu link_gen %llu, snapshot extent_txg %llu\n",
           (unsigned long long)r.gen, (unsigned long long)r.link_gen,
           (unsigned long long)se.extent_txg);
    STM_ASSERT(r.gen >= se.extent_txg);
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, f, 0, nw, LEN));
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    uint64_t *dead = NULL;
    size_t nd = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_get(sidx, h.snap, &dead, &nd));
    bool listed = false;
    for (size_t k = 0; k < nd; k++)
        if (dead[k] == r.paddrs[0]) listed = true;
    printf("    snapshot dead list %zu entries; the promote's block %s\n",
           nd, listed ? "LISTED" : "not listed");
    free(dead);
    STM_ASSERT(!listed);
    free(old);
    free(nw);
    seal_pool_close(&sp);
}

/* The fs promote holds a txn span across each record's sync promote, so
 * the ENOSPC reclaim, which commits under fs->global SH, waits for it
 * rather than persist blocks it reserved and no record names yet. From the
 * promote's first seam a second thread preallocates another file whose
 * drain answers ENOSPC (injected; the reclaim's own drain lands), so its
 * reclaim comes to the txn lock (seen there in the window): it must not
 * take it while the promote is in its unlocked span, and takes it once
 * the record is done. Through stm_fs_promote_to_hot (a sibling's file)
 * and the login promote (a home's legacy cold file, a step at a time);
 * over a file of several records stm_fs_promote_to_hot lets the reclaim in
 * between two of them, so it has committed by the second record's seam.
 * Every seam runs inside exactly one span, and none is left after. The
 * controls need a txn lock that prefers writers (macOS; glibc with the
 * attribute): on musl's a queued writer is not seen, nor let in. */
typedef struct {
    seal_pool      *sp;
    uint64_t        ds, x;
    pthread_t       tb;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             calls, started, trying, locked;
    int             trying_in_window, locked_in_window, locked_by_second;
    int             unspanned, queued_in_window;
    stm_status      b_rc;
} o1b_rc;

static void o1b_rc_reclaim_hook(bool locked, void *arg)
{
    o1b_rc *r = arg;
    pthread_mutex_lock(&r->mu);
    if (locked) {
        r->locked = 1;
    } else {
        r->trying = 1;
        stm_fs_fail_drains_for_test(r->sp->fs, STM_OK);
    }
    pthread_cond_broadcast(&r->cv);
    pthread_mutex_unlock(&r->mu);
}

static void *o1b_rc_thread(void *arg)
{
    o1b_rc *r = arg;
    stm_fs_fail_drains_for_test(r->sp->fs, STM_ENOSPC);
    r->b_rc = stm_fs_fallocate(r->sp->fs, r->ds, r->x, 0, 4096, 0);
    stm_fs_fail_drains_for_test(r->sp->fs, STM_OK);
    return NULL;
}

static void o1b_rc_after(struct timespec *t, long ms)
{
    clock_gettime(CLOCK_REALTIME, t);
    t->tv_sec += ms / 1000;
    t->tv_nsec += (ms % 1000) * 1000000L;
    if (t->tv_nsec >= 1000000000L) {
        t->tv_sec++;
        t->tv_nsec -= 1000000000L;
    }
}

static void o1b_rc_seam(void *arg)
{
    o1b_rc *r = arg;
    if (stm_fs_txn_depth_for_test() != 1u) r->unspanned++;
    if (r->calls++) {
        if (r->calls == 2) {
            pthread_mutex_lock(&r->mu);
            r->locked_by_second = r->locked;
            pthread_mutex_unlock(&r->mu);
        }
        return;
    }
    if (pthread_create(&r->tb, NULL, o1b_rc_thread, r) != 0) return;
    r->started = 1;
    struct timespec until;
    pthread_mutex_lock(&r->mu);
    o1b_rc_after(&until, 10000);
    while (!r->trying &&
           pthread_cond_timedwait(&r->cv, &r->mu, &until) == 0) {
    }
    if (r->trying) {
        /* queued at the txn lock, not just come to the hook before it */
        for (int k = 0; k < 10000 && !r->locked &&
                        !stm_fs_txn_writer_waiting_for_test(r->sp->fs); k++) {
            pthread_mutex_unlock(&r->mu);
            usleep(1000);
            pthread_mutex_lock(&r->mu);
        }
        r->queued_in_window = !r->locked &&
                              stm_fs_txn_writer_waiting_for_test(r->sp->fs);
        o1b_rc_after(&until, 300);
        while (!r->locked &&
               pthread_cond_timedwait(&r->cv, &r->mu, &until) == 0) {
        }
    }
    r->trying_in_window = r->trying;
    r->locked_in_window = r->locked;
    pthread_mutex_unlock(&r->mu);
}

enum { O1B_RC_WHOLE, O1B_RC_LOGIN, O1B_RC_RECORDS };

static void o1b_rc_case(int leg)
{
    const bool login = leg == O1B_RC_LOGIN, many = leg == O1B_RC_RECORDS;
    seal_pool sp;
    if (many ? !seal_pool_open_sz(&sp, "o1brm", UINT64_C(1) << 30,
                                  UINT64_C(128) << 20)
             : !seal_pool_open(&sp, login ? "o1brl" : "o1brh")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const uint64_t ds = login ? sp.home.ds : sp.sib.ds;
    uint64_t y = login ? sp.home.big : sp.sib.big;
    uint8_t *want = NULL;
    if (many) {
        want = seal_big_cold_file(sp.fs, ds, "m24", true, &y);
        if (!want) { seal_pool_close(&sp); return; }
    } else {
        if (login) stm_sync_set_cas_admits_sealed_for_test(sync, true);
        STM_ASSERT_OK(stm_fs_migrate_to_cold(sp.fs, ds, y));
        if (login) stm_sync_set_cas_admits_sealed_for_test(sync, false);
        STM_ASSERT_OK(stm_fs_commit(sp.fs));
    }
    const seal_ext_sum e = seal_extents(sp.fs, ds, y);
    STM_ASSERT_EQ(e.cold, e.n);
    STM_ASSERT(many ? e.n >= 2 : e.n == 1);
    uint64_t x = 0;
    STM_ASSERT_OK(stm_fs_create_file(sp.fs, sp.sib.ds, 1,
                                     (const uint8_t *)"x", 1, 0600, 1000,
                                     1000, &x));
    const size_t XL = (size_t)64 << 10;
    uint8_t *xb = malloc(XL);
    STM_ASSERT(xb != NULL);
    if (!xb) { free(want); seal_pool_close(&sp); return; }
    memset(xb, 0x78, XL);
    STM_ASSERT_OK(stm_fs_write(sp.fs, sp.sib.ds, x, 0, xb, XL));
    free(xb);
    STM_ASSERT(stm_sync_pending_free_blocks(sync) > 0u);  /* the reclaim's gate */
    o1b_rc r;
    memset(&r, 0, sizeof r);
    r.sp = &sp;
    r.ds = sp.sib.ds;
    r.x = x;
    pthread_mutex_init(&r.mu, NULL);
    pthread_cond_init(&r.cv, NULL);
    stm_fs_set_reclaim_hook_for_test(sp.fs, o1b_rc_reclaim_hook, &r);
    stm_sync_set_promote_phase2_hook_for_test(sync, o1b_rc_seam, &r);
    stm_status rc;
    if (login) {
        stm_fs_promote_policy_stats st;
        memset(&st, 0, sizeof st);
        rc = stm_fs_promote_sealed_cold(sp.fs, ds, UINT64_C(1) << 20, &st);
    } else {
        rc = stm_fs_promote_to_hot(sp.fs, ds, y);
    }
    stm_sync_set_promote_phase2_hook_for_test(sync, NULL, NULL);
    const unsigned depth_after = stm_fs_txn_depth_for_test();
    if (r.started) pthread_join(r.tb, NULL);
    stm_fs_set_reclaim_hook_for_test(sp.fs, NULL, NULL);
    stm_fs_fail_drains_for_test(sp.fs, STM_OK);
    printf("    %s: rc %d, records %d, seam calls %d, reclaim at the lock "
           "in the window %d, queued there %d, inside it %d, by the second "
           "seam %d, at all %d/%d, its op rc %d; seams outside one span %d, "
           "spans left %u\n",
           login ? "login" : many ? "records" : "whole", (int)rc, e.n,
           r.calls, r.trying_in_window, r.queued_in_window,
           r.locked_in_window, r.locked_by_second, r.trying, r.locked,
           (int)r.b_rc, r.unspanned, depth_after);
    STM_ASSERT_OK(rc);
    STM_ASSERT_EQ(r.started, 1);
    STM_ASSERT_EQ(r.trying_in_window, 1);    /* at the lock in the window */
    STM_ASSERT_EQ(r.queued_in_window, 1);    /* queued there, not just near */
    STM_ASSERT_EQ(r.locked_in_window, 0);    /* not inside the promote */
    STM_ASSERT_EQ(r.unspanned, 0);           /* every seam in one span */
    STM_ASSERT_EQ(depth_after, 0u);          /* every span ended once */
    STM_ASSERT_EQ(r.trying, 1);
    STM_ASSERT_EQ(r.locked, 1);              /* once the record was done */
    STM_ASSERT_EQ(r.calls, e.n);             /* no record went again */
    if (many) STM_ASSERT_EQ(r.locked_by_second, 1);  /* between records */
    STM_ASSERT_OK(r.b_rc);
    const seal_ext_sum a = seal_extents(sp.fs, ds, y);
    STM_ASSERT_EQ(a.cold, 0);
    if (many) {
        stm_sync_dcache_drain_for_test(sync);
        seal_read_eq(sp.fs, ds, y, 0, want, SEAL_BIG_LEN);
    }
    free(want);
    STM_ASSERT_OK(stm_fs_commit(sp.fs));
    pthread_cond_destroy(&r.cv);
    pthread_mutex_destroy(&r.mu);
    seal_pool_close(&sp);
}

STM_TEST(corvus_promote_through_the_fs_holds_off_a_reclaims_commit) {
    o1b_rc_case(O1B_RC_WHOLE);
    o1b_rc_case(O1B_RC_LOGIN);
}

STM_TEST(corvus_promote_through_the_fs_lets_a_reclaim_in_between_records) {
    o1b_rc_case(O1B_RC_RECORDS);
}

/* `between` runs with no sync or pool lock held and every block the
 * records before it reserved indexed or given back: the data blocks
 * allocated since the promote began are the file's HOT blocks so far
 * (each piece may take one spare). Sync-direct, then through
 * stm_fs_promote_to_hot, whose yield ends its span before it takes the
 * next (no order violation, no span left). */
typedef struct {
    stm_sync *s;
    stm_pool *pool;
    uint64_t  ds, ino, a0;
    int       calls, held, pool_held, outstanding;
} o1b_between;

static bool o1b_between_hot_cb(const stm_extent_record *e, void *cx)
{
    uint64_t *v = cx;
    if (e->kind == STM_EXTENT_KIND_HOT) {
        v[0] += o1b_blocks((size_t)e->len);
        v[1]++;
    }
    return true;
}

static void o1b_between_fn(void *arg)
{
    o1b_between *b = arg;
    b->calls++;
    if (!stm_sync_lock_is_free_for_test(b->s)) {
        b->held++;
        return;
    }
    if (!stm_pool_lock_is_free_for_test(b->pool)) b->pool_held++;
    uint64_t a = 0, p = 0, hot[2] = { 0, 0 };
    o1b_alloc_counts(b->s, &a, &p);
    STM_ASSERT_OK(stm_extent_iter(stm_sync_extent_index(b->s), b->ds, b->ino,
                                  o1b_between_hot_cb, hot));
    if (a < b->a0 + hot[0] || a > b->a0 + hot[0] + hot[1]) b->outstanding++;
}

STM_TEST(corvus_promote_yields_with_no_lock_held_and_nothing_outstanding) {
    seal_pool sp;
    if (!seal_pool_open_sz(&sp, "o1bbt", UINT64_C(1) << 30,
                           UINT64_C(128) << 20)) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    uint64_t g = 0;
    uint8_t *want = seal_big_cold_file(sp.fs, sp.sib.ds, "b24", true, &g);
    if (!want) { seal_pool_close(&sp); return; }
    const seal_ext_sum e = seal_extents(sp.fs, sp.sib.ds, g);
    STM_ASSERT(e.n >= 2);
    o1b_between b = { .s = sync, .pool = stm_sync_pool(sync),
                      .ds = sp.sib.ds, .ino = g };
    uint64_t p0 = 0;
    o1b_alloc_counts(sync, &b.a0, &p0);
    STM_ASSERT_OK(stm_sync_promote_to_hot_yielding(sync, sp.sib.ds, g,
                                                   o1b_between_fn, &b));
    printf("    records %d, between calls %d, held %d, pool held %d, "
           "outstanding %d\n", e.n, b.calls, b.held, b.pool_held,
           b.outstanding);
    STM_ASSERT_EQ(b.calls, e.n - 1);
    STM_ASSERT_EQ(b.held, 0);
    STM_ASSERT_EQ(b.pool_held, 0);
    STM_ASSERT_EQ(b.outstanding, 0);
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, g, 0, want, SEAL_BIG_LEN);
    free(want);
    uint64_t h = 0;
    want = seal_big_cold_file(sp.fs, sp.sib.ds, "c24", true, &h);
    if (!want) { seal_pool_close(&sp); return; }
    STM_ASSERT(seal_extents(sp.fs, sp.sib.ds, h).n >= 2);
    const unsigned viol0 = stm_fs_txn_order_violations_for_test();
    STM_ASSERT_OK(stm_fs_promote_to_hot(sp.fs, sp.sib.ds, h));
    const unsigned viol1 = stm_fs_txn_order_violations_for_test();
    printf("    through the fs: order violations %u -> %u, spans left %u\n",
           viol0, viol1, stm_fs_txn_depth_for_test());
    STM_ASSERT_EQ(viol1, viol0);
    STM_ASSERT_EQ(stm_fs_txn_depth_for_test(), 0u);
    STM_ASSERT_EQ(seal_extents(sp.fs, sp.sib.ds, h).cold, 0);
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, h, 0, want, SEAL_BIG_LEN);
    free(want);
    seal_pool_close(&sp);
}

/* A failed unlocked chunk read gives back the blocks its try reserved
 * (the allocator's data blocks around the promote, no commit between).
 * One failure: that try's record goes to pending and the locked body
 * reads the chunk again and swaps (allocated up a record). Every read
 * failing: the locked body reads before it reserves, so only the unlocked
 * try's record reaches pending and allocated is unchanged. */
static void o1b_read_acct_case(int64_t times)
{
    seal_pool sp;
    if (!seal_pool_open(&sp, times == 1 ? "o1bq1" : "o1bq2")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    const size_t LEN = (size_t)256 << 10;
    const uint64_t NB = o1b_blocks(LEN);
    uint64_t f = 0;
    stm_extent_record c;
    uint8_t *want = o1b_cold_file(&sp, sp.sib.ds, "q", LEN, 0x2f2f6e6eull,
                                  &f, &c);
    if (!want) { seal_pool_close(&sp); return; }
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    o1_fault_chunk(&sp, &c, times, false);
    uint64_t a0 = 0, p0 = 0, a1 = 0, p1 = 0;
    o1b_alloc_counts(sync, &a0, &p0);
    stm_status rc = stm_sync_promote_to_hot(sync, sp.sib.ds, f);
    o1b_alloc_counts(sync, &a1, &p1);
    stm_bdev_inject_read_range_clear(d);
    printf("    times %lld: rc %d, allocated %+lld, pending %+lld "
           "(one record = %llu blocks)\n", (long long)times, (int)rc,
           (long long)(a1 - a0), (long long)(p1 - p0),
           (unsigned long long)NB);
    if (times == 1) {
        STM_ASSERT_OK(rc);
        STM_ASSERT(a1 >= a0 + NB && a1 <= a0 + NB + 1u);
        STM_ASSERT(p1 >= p0 + NB);
        STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.sib.ds, f),
                      STM_EXTENT_KIND_HOT);
    } else {
        STM_ASSERT_ERR(rc, STM_EIO);
        STM_ASSERT_EQ(a1, a0);
        STM_ASSERT(p1 >= p0 + NB);
        STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.sib.ds, f),
                      STM_EXTENT_KIND_COLD);
    }
    free(want);
    seal_pool_close(&sp);
}

STM_TEST(corvus_promote_gives_back_its_blocks_when_the_unlocked_read_fails) {
    o1b_read_acct_case(1);
    o1b_read_acct_case(2);
}

/* The unlocked chunk read runs under the pool's shared lock, which keeps
 * the chunk's devices. Controls: the probe answers held under a shared
 * hold and free without one, and the fully locked body (whose devices
 * s->lock keeps) reads with the pool lock free. */
#define O1B_POOL_IO_MAX 4096
typedef struct {
    stm_pool  *pool;     /* resolved before arming: stm_sync_pool takes s->lock */
    atomic_int n;
    struct { bool w, pool_free; uint64_t off; size_t len; } op[O1B_POOL_IO_MAX];
} o1b_pool_log;

static void o1b_pool_fn(void *ctx, bool is_write, uint64_t off, size_t len)
{
    o1b_pool_log *l = ctx;
    int i = atomic_fetch_add(&l->n, 1);
    if (i >= O1B_POOL_IO_MAX) return;
    l->op[i].w = is_write;
    l->op[i].off = off;
    l->op[i].len = len;
    l->op[i].pool_free = stm_pool_lock_is_free_for_test(l->pool);
}

static void o1b_pool_tally(o1b_pool_log *l, const o1b_spans *cold,
                           int *reads, int *free_reads)
{
    *reads = *free_reads = 0;
    int n = atomic_load(&l->n);
    if (n > O1B_POOL_IO_MAX) n = O1B_POOL_IO_MAX;
    for (int i = 0; i < n; i++) {
        if (l->op[i].w || !o1b_in(cold, l->op[i].off, l->op[i].len)) continue;
        (*reads)++;
        if (l->op[i].pool_free) (*free_reads)++;
    }
}

STM_TEST(corvus_promote_reads_its_chunk_under_the_pool_lock) {
    seal_pool sp;
    if (!seal_pool_open(&sp, "o1bpl")) return;
    stm_sync *sync = stm_fs_sync(sp.fs);
    stm_pool *pool = stm_sync_pool(sync);
    struct stm_bdev *d = stm_fs_bdev_for_test(sp.fs);
    STM_ASSERT(stm_pool_lock_is_free_for_test(pool));
    stm_pool_lock_shared(pool);
    STM_ASSERT(!stm_pool_lock_is_free_for_test(pool));
    stm_pool_unlock_shared(pool);
    o1b_pool_log *l = calloc(1, sizeof *l);
    STM_ASSERT(l != NULL);
    if (!l) { seal_pool_close(&sp); return; }
    l->pool = pool;
    stm_bdev_io_observer ob = { .fn = o1b_pool_fn, .ctx = l };
    const size_t LEN = (size_t)256 << 10;
    uint64_t k = 0;
    stm_extent_record kc;
    uint8_t *kwant = o1b_cold_file(&sp, sp.sib.ds, "pk", LEN, 0x6a6a7b7bull,
                                   &k, &kc);
    uint64_t g = 0;
    stm_extent_record gc;
    uint8_t *gwant = o1b_cold_file(&sp, sp.sib.ds, "pg", LEN, 0x7b7b8c8cull,
                                   &g, &gc);
    if (!kwant || !gwant) {
        free(kwant); free(gwant); free(l); seal_pool_close(&sp); return;
    }
    o1b_spans kcold = o1b_spans_of(sync, sp.sib.ds, k, true);
    o1b_spans gcold = o1b_spans_of(sync, sp.sib.ds, g, true);
    atomic_store(&l->n, 0);
    stm_bdev_set_io_observer_for_test(d, &ob);
    STM_ASSERT_OK(stm_sync_promote_cold_at(sync, sp.sib.ds, k, 0, NULL));
    stm_bdev_set_io_observer_for_test(d, NULL);
    int kr = 0, kfree = 0;
    o1b_pool_tally(l, &kcold, &kr, &kfree);
    atomic_store(&l->n, 0);
    stm_bdev_set_io_observer_for_test(d, &ob);
    STM_ASSERT_OK(stm_sync_promote_to_hot(sync, sp.sib.ds, g));
    stm_bdev_set_io_observer_for_test(d, NULL);
    int gr = 0, gfree = 0;
    o1b_pool_tally(l, &gcold, &gr, &gfree);
    printf("    locked body: %d chunk reads, %d with the pool lock free; "
           "unlocked: %d chunk reads, %d free\n", kr, kfree, gr, gfree);
    STM_ASSERT(kr >= 1);
    STM_ASSERT_EQ(kfree, kr);            /* the probe can answer free */
    STM_ASSERT(gr >= 1);
    STM_ASSERT_EQ(gfree, 0);             /* every unlocked read: held */
    STM_ASSERT_EQ(seal_extent_kind(sp.fs, sp.sib.ds, g), STM_EXTENT_KIND_HOT);
    stm_sync_dcache_drain_for_test(sync);
    seal_read_eq(sp.fs, sp.sib.ds, g, 0, gwant, LEN);
    free(kwant);
    free(gwant);
    free(l);
    seal_pool_close(&sp);
}
