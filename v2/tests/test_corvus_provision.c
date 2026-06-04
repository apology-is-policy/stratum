/* SPDX-License-Identifier: ISC */
/*
 * test_corvus_provision — TLY-A3-keyslot-wrap chunk 5b: the operator
 * surface for provisioning a corvus-encrypted dataset.
 *
 * Two surfaces under test:
 *   - stm_fs_create_dataset_corvus — the fs-layer wrapper that
 *     composes dataset-table creation + corvus WRAP key provisioning,
 *     with rollback on WRAP failure.
 *   - stm_stratumd_run's one-shot `provision_corvus` mode — mount,
 *     create the corvus dataset, init its root, unmount.
 *
 * The fake corvus is a verb-aware toy seal/unseal pair (same shape as
 * test_corvus_mount.c): WRAP seals a DEK as MAGIC || dek; UNWRAP reads
 * it back. A non-OK fc->status drives the WRAP-rejected path.
 */

#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/corvus_client.h>
#include <stratum/ctl.h>
#include <stratum/dataset.h>
#include <stratum/fs.h>
#include <stratum/inode.h>
#include <stratum/lp9.h>
#include <stratum/stratumd.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Verb-aware fake corvus — toy seal/unseal pair (lifted from            */
/* test_corvus_mount.c). WRAP: envelope = MAGIC(8) || dek(32). UNWRAP:    */
/* recognizes that shape + hands the DEK back. A non-OK fc->status        */
/* drives the error frame for either verb.                                */
/* ────────────────────────────────────────────────────────────────────── */

static const uint8_t FAKE_ENVELOPE_MAGIC[8] = {
    'F','A','K','E','W','R','A','P',
};
#define FAKE_ENVELOPE_LEN  (8u + 32u)

typedef struct {
    int               listen_fd;
    char              sock_path[128];
    pthread_t         thread;
    bool              thread_started;
    stm_corvus_status status;       /* status byte to return */
} fake_corvus;

static void *fake_corvus_thread(void *arg)
{
    fake_corvus *fc = arg;
    for (;;) {
        int cfd = accept(fc->listen_fd, NULL, NULL);
        if (cfd < 0) return NULL;   /* listen fd shut down → exit */

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
                    memcpy(resp + 3, wrapped + 8, 32);
                    resp[1] = 32u;
                    resp_len = 3u + 32u;
                }
                /* else: malformed envelope — status-only frame. */
            }
        }
        (void)write(cfd, resp, resp_len);
        close(cfd);
    }
}

static void fake_corvus_start(fake_corvus *fc, const char *tag,
                                stm_corvus_status status)
{
    memset(fc, 0, sizeof *fc);
    fc->status = status;
    snprintf(fc->sock_path, sizeof fc->sock_path,
             "/tmp/stm_cvprov_%d_%s.sock", (int)getpid(), tag);
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

/* A fixed 33-byte session token. The fake corvus does not inspect it. */
static const uint8_t TEST_TOKEN[STM_CORVUS_TOKEN_LEN] = {
    's',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
    '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f',
};

/* Write the 33-byte token to a per-pid file; returns the path in
 * `out` (caller-sized buffer). stm_corvus_load_token requires an
 * exact-33-byte regular file. */
static void write_token_file(char *out, size_t out_cap, const char *tag)
{
    snprintf(out, out_cap, "/tmp/stm_cvprov_token_%d_%s.bin",
             (int)getpid(), tag);
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    STM_ASSERT(fd >= 0);
    ssize_t w = write(fd, TEST_TOKEN, STM_CORVUS_TOKEN_LEN);
    STM_ASSERT_EQ((long long)w, (long long)STM_CORVUS_TOKEN_LEN);
    close(fd);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Test 1: the full stratumd one-shot provisioning e2e.                   */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(provision_via_stratumd_run) {
    make_tmp("provrun");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    char token_path[256];
    write_token_file(token_path, sizeof token_path, "provrun");

    /* One verb-aware fake corvus serves the provisioning WRAP and the
     * verification-remount UNWRAP. */
    fake_corvus fc;
    fake_corvus_start(&fc, "provrun", STM_CORVUS_STATUS_OK);

    /* --- Provision via the stratumd one-shot mode. --- */
    stm_stratumd_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.fs_path                   = g_tmp_path;
    opts.keyfile_path              = g_key_path;
    opts.socket_path               = "/tmp/stm_cvprov_unused.sock";
    opts.corvus_unwrap_socket      = fc.sock_path;
    opts.corvus_session_token_file = token_path;
    opts.provision_corvus          = true;
    opts.provision_dataset_name    = "alice";
    opts.provision_corvus_path     = "users/alice";
    opts.provision_parent          = 1u;
    STM_ASSERT_OK(stm_stratumd_run(&opts));

    /* --- Verify: a normal remount WITH corvus resolves the new
     *     dataset's CURRENT CORVUS keyslot (mount fail-fast doctrine —
     *     a CURRENT corvus slot that won't UNWRAP aborts the mount, so
     *     a successful mount IS the proof the slot resolves). --- */
    {
        stm_fs_mount_opts mopts = rw_mount_opts();
        mopts.corvus_socket             = fc.sock_path;
        mopts.corvus_session_token_file = token_path;
        stm_fs *fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        STM_ASSERT_OK(stm_fs_unmount(fs));
    }

    /* --- Verify: a remount WITHOUT corvus now SUCCEEDS (TLY-A5b
     *     deferred-unwrap soft-skip) -- the system coordinator boots with
     *     alice's user-sealed dataset present-but-LOCKED. The provisioned
     *     slot is genuine, not a no-op: a write into ds=2 resolves the
     *     CURRENT CORVUS slot, finds no installed DEK, and returns the
     *     distinct STM_ELOCKED (a no-op provision would leave no slot, so
     *     the write would lookup_current-miss with STM_ENOENT instead).
     *     The locked-read posture is also unit-tested in
     *     test_corvus_mount::corvus_mount_soft_skips_locked_user_dataset. --- */
    {
        stm_fs_mount_opts mopts = rw_mount_opts();
        /* no corvus_socket / corvus_session_token_file */
        stm_fs *fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        STM_ASSERT(fs != NULL);

        uint8_t buf[4096];   /* one STM_UB_SIZE block */
        memset(buf, 0x5A, sizeof buf);
        STM_ASSERT_ERR(stm_fs_write(fs, /*dataset_id=*/2u, /*ino=*/1u,
                                      /*off=*/0u, buf, sizeof buf),
                         STM_ELOCKED);

        STM_ASSERT_OK(stm_fs_unmount(fs));
    }

    fake_corvus_stop(&fc);
    (void)unlink(token_path);
    (void)unlink(g_tmp_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Test 2: stratumd provision-mode argument refusals.                     */
/* Each refusal fires inside stratumd_run_provision BEFORE any mount, so  */
/* fs_path need only be non-NULL (never opened).                           */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(provision_refuses_bad_args) {
    /* Baseline well-formed provision opts; each case below mutates one
     * field to an invalid shape. */
    stm_stratumd_opts base;
    memset(&base, 0, sizeof base);
    base.fs_path                   = "/tmp/stm_cvprov_norun.bin";
    base.keyfile_path              = "/tmp/stm_cvprov_nokey.bin";
    base.socket_path               = "/tmp/stm_cvprov_unused.sock";
    base.corvus_unwrap_socket      = "/tmp/stm_cvprov_nocorvus.sock";
    base.corvus_session_token_file = "/tmp/stm_cvprov_notoken.bin";
    base.provision_corvus          = true;
    base.provision_dataset_name    = "alice";
    base.provision_corvus_path     = "users/alice";

    /* Missing --corvus-dataset-path. */
    {
        stm_stratumd_opts o = base;
        o.provision_corvus_path = NULL;
        STM_ASSERT_EQ((int)stm_stratumd_run(&o), (int)STM_EINVAL);
    }
    /* Missing --corvus-session-token-file (a WRAP needs a token). */
    {
        stm_stratumd_opts o = base;
        o.corvus_session_token_file = NULL;
        STM_ASSERT_EQ((int)stm_stratumd_run(&o), (int)STM_EINVAL);
    }
    /* Empty dataset name. */
    {
        stm_stratumd_opts o = base;
        o.provision_dataset_name = "";
        STM_ASSERT_EQ((int)stm_stratumd_run(&o), (int)STM_EINVAL);
    }
    /* --read-only is incompatible with provisioning. */
    {
        stm_stratumd_opts o = base;
        o.read_only = true;
        STM_ASSERT_EQ((int)stm_stratumd_run(&o), (int)STM_EINVAL);
    }
    /* --ctl-listen is rejected in one-shot mode. */
    {
        stm_stratumd_opts o = base;
        o.ctl_socket_path = "/tmp/stm_cvprov_ctl.sock";
        STM_ASSERT_EQ((int)stm_stratumd_run(&o), (int)STM_EINVAL);
    }
    /* Control byte in the corvus dataset path (line-injection
     * defense — R99 doctrine). */
    {
        stm_stratumd_opts o = base;
        /* split literal: \x01 would otherwise greedily consume the
         * "bad" hex digits into one out-of-range escape. */
        o.provision_corvus_path = "users/\x01" "bad";
        STM_ASSERT_EQ((int)stm_stratumd_run(&o), (int)STM_EINVAL);
    }
}

/* ────────────────────────────────────────────────────────────────────── */
/* Test 3: stm_fs_create_dataset_corvus rolls back the dataset entry on   */
/* a corvus WRAP failure — the index is never left with an orphan.        */
/* ────────────────────────────────────────────────────────────────────── */

STM_TEST(provision_create_dataset_corvus_rollback) {
    make_tmp("rollback");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    /* Fake corvus that REJECTS every WRAP with a fatal status. */
    fake_corvus fc;
    fake_corvus_start(&fc, "rollback", STM_CORVUS_STATUS_BAD_AUTH);

    /* Fresh pool has only LEGACY slots — the mount itself needs no
     * corvus. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_corvus_mount_cfg cc = {
        .socket_path   = fc.sock_path,
        .session_token = TEST_TOKEN,
        .n_retries     = 0,
    };

    /* The corvus WRAP fails (BAD_AUTH) → stm_fs_create_dataset_corvus
     * must roll back the dataset_create_child and surface the typed
     * corvus error. */
    uint64_t id = 999;
    STM_ASSERT_EQ((int)stm_fs_create_dataset_corvus(
                        fs, 1u, "alice", "users/alice",
                        strlen("users/alice"), &cc, &id),
                  (int)STM_ECORVUSAUTH);

    /* The rollback freed the name: a subsequent create with the SAME
     * name under the SAME parent must succeed (it would refuse
     * STM_EEXIST if an orphan dataset had been left behind). The
     * legacy create wraps under the mount keyfile — no corvus. */
    uint64_t id2 = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1u, "alice", &id2));
    STM_ASSERT(id2 >= 2u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    fake_corvus_stop(&fc);
    (void)unlink(g_tmp_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* TLY-A5b: the /ctl install-dek / evict-dek control surface + F7          */
/* connection-binding, driven directly through the ctl vops over an fs     */
/* with a soft-skipped (LOCKED) corvus dataset.                            */
/* ────────────────────────────────────────────────────────────────────── */

/* The A-5b login coordinator runs as PRINCIPAL_SYSTEM (= the A-3 host-bake
 * owner uid). Any non-system uid must be denied the DEK verbs. */
#define SYS_UID    ((uid_t)4294967294u)   /* PRINCIPAL_SYSTEM */
#define SYS_GID    ((gid_t)4294967294u)
#define OTHER_UID  ((uid_t)1234u)
#define OTHER_GID  ((gid_t)1234u)

/* Walk /datasets/<dsid>/<verb> and return the leaf qid (walk is never
 * gated -- only Tlopen is; so this succeeds for any caller). */
static uint64_t ctl_walk_verb(const stm_lp9_vops *v, stm_ctl_conn *cn,
                                uint64_t root, uint64_t dsid, const char *verb)
{
    stm_lp9_qid q;
    STM_ASSERT_OK(v->walk(cn, root, "datasets", 8, &q));
    char dsbuf[24];
    int n = snprintf(dsbuf, sizeof dsbuf, "%llu", (unsigned long long)dsid);
    STM_ASSERT(n > 0 && n < (int)sizeof dsbuf);
    STM_ASSERT_OK(v->walk(cn, q.path, dsbuf, (size_t)n, &q));
    STM_ASSERT_OK(v->walk(cn, q.path, verb, strlen(verb), &q));
    return q.path;
}

/* Drive install-dek: walk + Tlopen(WRONLY) + Twrite(token). Returns the
 * lopen rc if it fails (the SYSTEM gate), else the write rc. Clunks the
 * fid whenever the open succeeded. */
static stm_status ctl_drive_install(const stm_lp9_vops *v, stm_ctl_conn *cn,
                                      uint64_t root, uint64_t dsid,
                                      const uint8_t *token, uint32_t tok_len,
                                      uint32_t fid)
{
    uint64_t q = ctl_walk_verb(v, cn, root, dsid, "install-dek");
    stm_status rc = v->lopen(cn, fid, q, STM_LP9_O_WRONLY);
    if (rc != STM_OK) return rc;
    uint32_t written = 0;
    rc = v->write(cn, fid, q, 0, token, tok_len, &written);
    v->clunk(cn, fid, q);
    return rc;
}

/* Drive evict-dek: a single trigger byte (content ignored). */
static stm_status ctl_drive_evict(const stm_lp9_vops *v, stm_ctl_conn *cn,
                                    uint64_t root, uint64_t dsid, uint32_t fid)
{
    uint64_t q = ctl_walk_verb(v, cn, root, dsid, "evict-dek");
    stm_status rc = v->lopen(cn, fid, q, STM_LP9_O_WRONLY);
    if (rc != STM_OK) return rc;
    uint32_t written = 0;
    uint8_t  trig = 'x';
    rc = v->write(cn, fid, q, 0, &trig, 1u, &written);
    v->clunk(cn, fid, q);
    return rc;
}

/* Provision alice (ds=2) via the stratumd one-shot, then remount WITHOUT
 * corvus so ds=2 is soft-skipped LOCKED. `fc` must already be running and
 * stays the corvus the ctl install verb later UNWRAPs over. */
static stm_fs *provision_and_remount_locked(fake_corvus *fc, const char *tag,
                                              const char *token_path)
{
    stm_stratumd_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.fs_path                   = g_tmp_path;
    opts.keyfile_path              = g_key_path;
    opts.socket_path               = "/tmp/stm_dekctl_unused.sock";
    opts.corvus_unwrap_socket      = fc->sock_path;
    opts.corvus_session_token_file = token_path;
    opts.provision_corvus          = true;
    opts.provision_dataset_name    = "alice";
    opts.provision_corvus_path     = "users/alice";
    opts.provision_parent          = 1u;
    STM_ASSERT_OK(stm_stratumd_run(&opts));
    (void)tag;

    stm_fs_mount_opts mopts = rw_mount_opts();   /* no corvus → soft-skip */
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    return fs;
}

STM_TEST(dek_install_evict_via_ctl) {
    make_tmp("dekctl");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    char token_path[256];
    write_token_file(token_path, sizeof token_path, "dekctl");

    fake_corvus fc;
    fake_corvus_start(&fc, "dekctl", STM_CORVUS_STATUS_OK);
    stm_fs *fs = provision_and_remount_locked(&fc, "dekctl", token_path);
    stm_sync *sync = stm_fs_sync(fs);

    uint8_t dek[32];
    /* Soft-skipped: ds=2 present-but-LOCKED (no DEK in the map). */
    STM_ASSERT_ERR(stm_sync_get_dek(sync, 2u, 0u, dek), STM_ENOENT);

    stm_ctl *ctl = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &ctl));
    STM_ASSERT_OK(stm_ctl_set_system_uid(ctl, SYS_UID));
    STM_ASSERT_OK(stm_ctl_set_corvus_socket(ctl, fc.sock_path, 0, 0, 0));
    uint64_t root = stm_ctl_root(ctl);
    const stm_lp9_vops *v = stm_ctl_vops();
    stm_ctl_conn *cn = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(ctl, SYS_UID, SYS_GID, &cn));

    /* install-dek → the DEK lands (LOCKED lifts). */
    STM_ASSERT_OK(ctl_drive_install(v, cn, root, 2u,
                                      TEST_TOKEN, STM_CORVUS_TOKEN_LEN, 1u));
    STM_ASSERT_OK(stm_sync_get_dek(sync, 2u, 0u, dek));

    /* Idempotent re-install from the owning conn. */
    STM_ASSERT_OK(ctl_drive_install(v, cn, root, 2u,
                                      TEST_TOKEN, STM_CORVUS_TOKEN_LEN, 2u));
    STM_ASSERT_OK(stm_sync_get_dek(sync, 2u, 0u, dek));

    /* evict-dek → back to LOCKED. */
    STM_ASSERT_OK(ctl_drive_evict(v, cn, root, 2u, 3u));
    STM_ASSERT_ERR(stm_sync_get_dek(sync, 2u, 0u, dek), STM_ENOENT);

    /* Idempotent evict (no lease) → STM_OK no-op. */
    STM_ASSERT_OK(ctl_drive_evict(v, cn, root, 2u, 4u));

    /* Re-install, then a conn drop AUTO-EVICTS (F7). */
    STM_ASSERT_OK(ctl_drive_install(v, cn, root, 2u,
                                      TEST_TOKEN, STM_CORVUS_TOKEN_LEN, 5u));
    STM_ASSERT_OK(stm_sync_get_dek(sync, 2u, 0u, dek));
    stm_ctl_conn_destroy(cn);
    STM_ASSERT_ERR(stm_sync_get_dek(sync, 2u, 0u, dek), STM_ENOENT);

    stm_ctl_destroy(ctl);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fake_corvus_stop(&fc);
    (void)unlink(token_path);
    (void)unlink(g_tmp_path);
}

STM_TEST(dek_ctl_authz) {
    make_tmp("dekauthz");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    char token_path[256];
    write_token_file(token_path, sizeof token_path, "dekauthz");

    fake_corvus fc;
    fake_corvus_start(&fc, "dekauthz", STM_CORVUS_STATUS_OK);
    stm_fs *fs = provision_and_remount_locked(&fc, "dekauthz", token_path);
    stm_sync *sync = stm_fs_sync(fs);
    uint8_t dek[32];

    stm_ctl *ctl = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &ctl));
    STM_ASSERT_OK(stm_ctl_set_system_uid(ctl, SYS_UID));
    STM_ASSERT_OK(stm_ctl_set_corvus_socket(ctl, fc.sock_path, 0, 0, 0));
    uint64_t root = stm_ctl_root(ctl);
    const stm_lp9_vops *v = stm_ctl_vops();

    /* (1) A non-SYSTEM caller is refused at Tlopen (the gate is system-
     *     only -- NOT admin/root). The walk itself still succeeds. */
    stm_ctl_conn *other = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(ctl, OTHER_UID, OTHER_GID, &other));
    {
        uint64_t q = ctl_walk_verb(v, other, root, 2u, "install-dek");
        STM_ASSERT_ERR(v->lopen(other, 1u, q, STM_LP9_O_WRONLY), STM_EACCES);
    }

    stm_ctl_conn *sysA = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(ctl, SYS_UID, SYS_GID, &sysA));

    /* (2) SYSTEM caller, wrong token length → EINVAL; stays LOCKED. */
    STM_ASSERT_ERR(ctl_drive_install(v, sysA, root, 2u,
                                       TEST_TOKEN, 32u, 2u), STM_EINVAL);
    STM_ASSERT_ERR(stm_sync_get_dek(sync, 2u, 0u, dek), STM_ENOENT);

    /* (3) sysA installs → lease owned by sysA; DEK present. */
    STM_ASSERT_OK(ctl_drive_install(v, sysA, root, 2u,
                                      TEST_TOKEN, STM_CORVUS_TOKEN_LEN, 3u));
    STM_ASSERT_OK(stm_sync_get_dek(sync, 2u, 0u, dek));

    /* (4) A DIFFERENT SYSTEM conn cannot install (cross-conn) nor evict
     *     (non-owning) the leased dataset → EACCES; DEK stays sysA's. */
    stm_ctl_conn *sysB = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(ctl, SYS_UID, SYS_GID, &sysB));
    STM_ASSERT_ERR(ctl_drive_install(v, sysB, root, 2u,
                                       TEST_TOKEN, STM_CORVUS_TOKEN_LEN, 4u),
                     STM_EACCES);
    STM_ASSERT_ERR(ctl_drive_evict(v, sysB, root, 2u, 5u), STM_EACCES);
    STM_ASSERT_OK(stm_sync_get_dek(sync, 2u, 0u, dek));

    /* (5) The owning conn evicts cleanly. */
    STM_ASSERT_OK(ctl_drive_evict(v, sysA, root, 2u, 6u));
    STM_ASSERT_ERR(stm_sync_get_dek(sync, 2u, 0u, dek), STM_ENOENT);

    stm_ctl_conn_destroy(other);
    stm_ctl_conn_destroy(sysA);
    stm_ctl_conn_destroy(sysB);
    stm_ctl_destroy(ctl);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fake_corvus_stop(&fc);
    (void)unlink(token_path);
    (void)unlink(g_tmp_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* TLY-A5b #826c: the datasets-LEVEL provision-dek control surface, driven  */
/* directly through the ctl vops. Mints a user's encrypted home at runtime  */
/* (create + corvus WRAP + root-init 0700 + commit), idempotent, SYSTEM-    */
/* gated. The first-login coordinator path -- login drives this, then       */
/* install-dek per session.                                                 */
/* ────────────────────────────────────────────────────────────────────── */

/* Serialize a provision-dek payload into `out` (>= 9+namelen+pathlen+33).
 * Layout: owner_uid(LE32) owner_gid(LE32) name_len(u8) name path_len(u8)
 * path token[33]. Returns the encoded length. */
static uint32_t build_provision_payload(uint8_t *out,
                                          uint32_t owner_uid, uint32_t owner_gid,
                                          const char *name, const char *path,
                                          const uint8_t *token)
{
    uint32_t n = 0;
    out[n++] = (uint8_t)(owner_uid & 0xFFu);
    out[n++] = (uint8_t)((owner_uid >> 8) & 0xFFu);
    out[n++] = (uint8_t)((owner_uid >> 16) & 0xFFu);
    out[n++] = (uint8_t)((owner_uid >> 24) & 0xFFu);
    out[n++] = (uint8_t)(owner_gid & 0xFFu);
    out[n++] = (uint8_t)((owner_gid >> 8) & 0xFFu);
    out[n++] = (uint8_t)((owner_gid >> 16) & 0xFFu);
    out[n++] = (uint8_t)((owner_gid >> 24) & 0xFFu);
    size_t nl = strlen(name);
    out[n++] = (uint8_t)nl;
    memcpy(out + n, name, nl); n += (uint32_t)nl;
    size_t pl = strlen(path);
    out[n++] = (uint8_t)pl;
    memcpy(out + n, path, pl); n += (uint32_t)pl;
    memcpy(out + n, token, STM_CORVUS_TOKEN_LEN);
    n += STM_CORVUS_TOKEN_LEN;
    return n;
}

/* Walk /datasets/provision-dek + Tlopen(WRONLY) + Twrite(payload). Returns
 * the lopen rc if it fails (the SYSTEM gate), else the write rc. */
static stm_status ctl_drive_provision(const stm_lp9_vops *v, stm_ctl_conn *cn,
                                        uint64_t root, const uint8_t *payload,
                                        uint32_t plen, uint32_t fid)
{
    stm_lp9_qid q;
    STM_ASSERT_OK(v->walk(cn, root, "datasets", 8, &q));
    STM_ASSERT_OK(v->walk(cn, q.path, "provision-dek",
                            strlen("provision-dek"), &q));
    stm_status rc = v->lopen(cn, fid, q.path, STM_LP9_O_WRONLY);
    if (rc != STM_OK) return rc;
    uint32_t written = 0;
    rc = v->write(cn, fid, q.path, 0, payload, plen, &written);
    v->clunk(cn, fid, q.path);
    return rc;
}

STM_TEST(provision_via_ctl) {
    make_tmp("provctl");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    char token_path[256];
    write_token_file(token_path, sizeof token_path, "provctl");

    fake_corvus fc;
    fake_corvus_start(&fc, "provctl", STM_CORVUS_STATUS_OK);

    /* A fresh pool has only LEGACY slots -> mounts with no corvus. The
     * runtime coordinator then provisions the user's home over /ctl. */
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    stm_sync *sync = stm_fs_sync(fs);

    stm_ctl *ctl = NULL;
    STM_ASSERT_OK(stm_ctl_create(fs, &ctl));
    STM_ASSERT_OK(stm_ctl_set_system_uid(ctl, SYS_UID));
    STM_ASSERT_OK(stm_ctl_set_corvus_socket(ctl, fc.sock_path, 0, 0, 0));
    uint64_t root = stm_ctl_root(ctl);
    const stm_lp9_vops *v = stm_ctl_vops();

    uint8_t payload[600];
    uint32_t plen = build_provision_payload(payload, OTHER_UID, OTHER_GID,
                                              "alice", "users/alice",
                                              TEST_TOKEN);

    /* (1) A non-SYSTEM caller is refused at Tlopen (walk still succeeds). */
    stm_ctl_conn *other = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(ctl, OTHER_UID, OTHER_GID, &other));
    {
        stm_lp9_qid q;
        STM_ASSERT_OK(v->walk(other, root, "datasets", 8, &q));
        STM_ASSERT_OK(v->walk(other, q.path, "provision-dek",
                                strlen("provision-dek"), &q));
        STM_ASSERT_ERR(v->lopen(other, 1u, q.path, STM_LP9_O_WRONLY),
                         STM_EACCES);
    }

    stm_ctl_conn *sys = NULL;
    STM_ASSERT_OK(stm_ctl_conn_create(ctl, SYS_UID, SYS_GID, &sys));

    /* (2) A truncated payload is refused with EINVAL; nothing is created. */
    STM_ASSERT_ERR(ctl_drive_provision(v, sys, root, payload, 8u, 2u),
                     STM_EINVAL);
    {
        stm_dataset_entry e;
        STM_ASSERT_ERR(stm_fs_dataset_lookup(fs, 2u, &e), STM_ENOENT);
    }

    /* (3) SYSTEM provisions alice (the first child -> ds=2). */
    STM_ASSERT_OK(ctl_drive_provision(v, sys, root, payload, plen, 3u));

    /* The dataset exists, its CURRENT corvus keyslot resolved (the WRAP
     * installs the minted DEK into the live map), and its root inode is
     * born user-owned 0700 (the F1 isolation property). */
    {
        stm_dataset_entry e;
        STM_ASSERT_OK(stm_fs_dataset_lookup(fs, 2u, &e));
        uint8_t dek[32];
        STM_ASSERT_OK(stm_sync_get_dek(sync, 2u, 0u, dek));
        struct stm_inode_value iv;
        STM_ASSERT_OK(stm_fs_stat(fs, 2u, 1u, &iv));
        STM_ASSERT_EQ(stm_load_le32(iv.si_uid), (uint32_t)OTHER_UID);
        STM_ASSERT_EQ(stm_load_le32(iv.si_gid), (uint32_t)OTHER_GID);
        STM_ASSERT_EQ(stm_load_le32(iv.si_mode) & 0777u, 0700u);
    }

    /* (4) Idempotent: a returning user re-provisions -> name collision maps
     *     to OK; no NEW dataset (ds=3 must not exist) and the DEK is
     *     unchanged (never re-minted). */
    STM_ASSERT_OK(ctl_drive_provision(v, sys, root, payload, plen, 4u));
    {
        stm_dataset_entry e;
        STM_ASSERT_ERR(stm_fs_dataset_lookup(fs, 3u, &e), STM_ENOENT);
    }

    stm_ctl_conn_destroy(other);
    stm_ctl_conn_destroy(sys);
    stm_ctl_destroy(ctl);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fake_corvus_stop(&fc);
    (void)unlink(token_path);
    (void)unlink(g_tmp_path);
}

/* ────────────────────────────────────────────────────────────────────── */
/* TLY-A5b #827a-login: the three SYSTEM-gated DEK trigger nodes report      */
/* uid/gid == system_uid via getattr, so a remote Thylacine kernel's         */
/* owner-first rwx check on the /ctl dev9p attach (A-3) is COHERENT with     */
/* this server's own SYSTEM gate -- the login coordinator runs as            */
/* PRINCIPAL_SYSTEM and must OWN the 0200 (owner-write-only) nodes to write  */
/* them. World-readable nodes (0444/0555) stay uid/gid 0: `other` carries    */
/* them, so their owner is immaterial to the kernel check.                   */
/* ────────────────────────────────────────────────────────────────────── */
STM_TEST(dek_nodes_report_system_owner) {
    make_tmp("dekowner");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    char token_path[256];
    write_token_file(token_path, sizeof token_path, "dekowner");

    fake_corvus fc;
    fake_corvus_start(&fc, "dekowner", STM_CORVUS_STATUS_OK);
    stm_fs *fs = provision_and_remount_locked(&fc, "dekowner", token_path); /* ds=2 alice */

    const stm_lp9_vops *v = stm_ctl_vops();
    stm_lp9_attr a;

    /* (1) system_uid configured -> the three DEK verbs are SYSTEM-owned. */
    {
        stm_ctl *ctl = NULL;
        STM_ASSERT_OK(stm_ctl_create(fs, &ctl));
        STM_ASSERT_OK(stm_ctl_set_system_uid(ctl, SYS_UID));
        uint64_t root = stm_ctl_root(ctl);
        stm_ctl_conn *cn = NULL;
        STM_ASSERT_OK(stm_ctl_conn_create(ctl, SYS_UID, SYS_GID, &cn));

        /* datasets-level provision-dek */
        stm_lp9_qid q;
        STM_ASSERT_OK(v->walk(cn, root, "datasets", 8, &q));
        STM_ASSERT_OK(v->walk(cn, q.path, "provision-dek",
                                strlen("provision-dek"), &q));
        STM_ASSERT_OK(v->getattr(cn, q.path, STM_LP9_GETATTR_BASIC, &a));
        STM_ASSERT_EQ(a.uid, (uint32_t)SYS_UID);
        STM_ASSERT_EQ(a.gid, (uint32_t)SYS_UID);

        /* per-dataset install-dek + evict-dek (ds=2) */
        STM_ASSERT_OK(v->getattr(cn, ctl_walk_verb(v, cn, root, 2u, "install-dek"),
                                   STM_LP9_GETATTR_BASIC, &a));
        STM_ASSERT_EQ(a.uid, (uint32_t)SYS_UID);
        STM_ASSERT_EQ(a.gid, (uint32_t)SYS_UID);
        STM_ASSERT_OK(v->getattr(cn, ctl_walk_verb(v, cn, root, 2u, "evict-dek"),
                                   STM_LP9_GETATTR_BASIC, &a));
        STM_ASSERT_EQ(a.uid, (uint32_t)SYS_UID);

        /* world-readable properties keeps uid/gid 0 (other-r carries it). */
        STM_ASSERT_OK(v->getattr(cn, ctl_walk_verb(v, cn, root, 2u, "properties"),
                                   STM_LP9_GETATTR_BASIC, &a));
        STM_ASSERT_EQ(a.uid, 0u);
        STM_ASSERT_EQ(a.gid, 0u);

        stm_ctl_conn_destroy(cn);
        stm_ctl_destroy(ctl);
    }

    /* (2) system_uid UNCONFIGURED -> provision-dek owned by the invalid
     *     sentinel ((uid_t)-1): a real principal never matches it, so the
     *     kernel rwx check fail-closes, mirroring ctl_caller_is_system. */
    {
        stm_ctl *ctl = NULL;
        STM_ASSERT_OK(stm_ctl_create(fs, &ctl));   /* no set_system_uid */
        uint64_t root = stm_ctl_root(ctl);
        stm_ctl_conn *cn = NULL;
        STM_ASSERT_OK(stm_ctl_conn_create(ctl, SYS_UID, SYS_GID, &cn));
        stm_lp9_qid q;
        STM_ASSERT_OK(v->walk(cn, root, "datasets", 8, &q));
        STM_ASSERT_OK(v->walk(cn, q.path, "provision-dek",
                                strlen("provision-dek"), &q));
        STM_ASSERT_OK(v->getattr(cn, q.path, STM_LP9_GETATTR_BASIC, &a));
        STM_ASSERT_EQ(a.uid, (uint32_t)(uid_t)-1);
        stm_ctl_conn_destroy(cn);
        stm_ctl_destroy(ctl);
    }

    STM_ASSERT_OK(stm_fs_unmount(fs));
    fake_corvus_stop(&fc);
    (void)unlink(token_path);
    (void)unlink(g_tmp_path);
}

STM_TEST_MAIN("corvus_provision")
