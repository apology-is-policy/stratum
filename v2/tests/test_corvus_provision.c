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
#include <stratum/fs.h>
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

    /* --- Verify: a remount WITHOUT corvus FAILS — confirms the
     *     provisioned slot is a genuine CURRENT CORVUS slot, not a
     *     no-op. --- */
    {
        stm_fs_mount_opts mopts = rw_mount_opts();
        /* no corvus_socket / corvus_session_token_file */
        stm_fs *fs = NULL;
        STM_ASSERT(stm_fs_mount(g_tmp_path, &mopts, &fs) != STM_OK);
        STM_ASSERT(fs == NULL);
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

STM_TEST_MAIN("corvus_provision")
