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
#include <stratum/pool.h>
#include <stratum/scrub.h>
#include <stratum/send_recv.h>
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

static bool seal_pool_open(seal_pool *sp, const char *tag)
{
    memset(sp, 0, sizeof *sp);
    make_tmp(tag);
    snprintf(sp->key_path, sizeof sp->key_path, "%s.key", g_tmp_path);
    unlink(sp->key_path);
    STM_ASSERT_OK(stm_keyfile_generate(sp->key_path));
    stm_fs_format_opts fo = {
        .device_size_bytes = TEST_DEVICE_BYTES,
        .bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES,
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
    /* An empty inline file's first block: the inline -> extent step
     * buffers it. */
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
