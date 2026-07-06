/* SPDX-License-Identifier: ISC */
/*
 * Shared test scaffold for stm_fs test suites — implementations.
 * See tests/test_fs_common.h for the rationale.
 */
#include "test_fs_common.h"
#include "tharness.h"

#include <stratum/keyfile.h>

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const uint64_t POOL_UUID[2]   = { 0xAA11, 0xBB22 };
static const uint64_t DEVICE_UUID[2] = { 0xCC33, 0xDD44 };

char g_tmp_path[256];
char g_key_path[256];

/* CF-2e (#57, the 32 GB stale-fixture leak): make_tmp unlinks a
 * fixture only at the NEXT test's start, and the names are per-PID —
 * so every binary's last fixture persisted forever, and killed or
 * crashed runs leaked everything they had created. Two sweeps close
 * the class:
 *
 *   - at process exit, unlink every /tmp/stm_v2_* file carrying THIS
 *     pid ("_<pid>." infix) — the clean-exit half;
 *   - once per process (first make_tmp), unlink every /tmp/stm_v2_*
 *     file older than 6 hours — the crashed/killed-run half. The age
 *     gate makes it safe under parallel ctest (no live run holds a
 *     fixture for hours; deliberate crash-inject children run
 *     seconds).
 */
#define SWEEP_PREFIX      "stm_v2_"
#define SWEEP_STALE_SECS  (6 * 60 * 60)

static void sweep_dir(bool stale_only)
{
    char pid_infix[32];
    snprintf(pid_infix, sizeof pid_infix, "_%d.", (int)getpid());

    DIR *d = opendir("/tmp");
    if (!d) return;

    time_t now = time(NULL);
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strncmp(de->d_name, SWEEP_PREFIX, sizeof SWEEP_PREFIX - 1) != 0)
            continue;
        char path[512];
        snprintf(path, sizeof path, "/tmp/%s", de->d_name);
        if (stale_only) {
            struct stat st;
            if (lstat(path, &st) != 0) continue;
            if (!S_ISREG(st.st_mode)) continue;
            if (now - st.st_mtime < SWEEP_STALE_SECS) continue;
        } else {
            if (!strstr(de->d_name, pid_infix)) continue;
        }
        (void)unlink(path);
    }
    closedir(d);
}

static void sweep_own_at_exit(void)  { sweep_dir(/*stale_only=*/false); }
static void sweep_once_init(void)
{
    sweep_dir(/*stale_only=*/true);
    (void)atexit(sweep_own_at_exit);
}

static pthread_once_t g_sweep_once = PTHREAD_ONCE_INIT;

void make_tmp(const char *tag)
{
    (void)pthread_once(&g_sweep_once, sweep_once_init);

    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_fs_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
    snprintf(g_key_path, sizeof g_key_path, "/tmp/stm_v2_fs_%s_%d.key",
             tag, (int)getpid());
    unlink(g_key_path);
    STM_ASSERT_OK(stm_keyfile_generate(g_key_path));
}

stm_fs_format_opts default_format_opts(void)
{
    return (stm_fs_format_opts){
        .device_size_bytes    = TEST_DEVICE_BYTES,
        .bootstrap_size_bytes = TEST_BOOTSTRAP_BYTES,
        .pool_uuid            = { POOL_UUID[0], POOL_UUID[1] },
        .device_uuid          = { DEVICE_UUID[0], DEVICE_UUID[1] },
        .keyfile_path         = g_key_path,
    };
}

stm_fs_mount_opts rw_mount_opts(void)
{
    return (stm_fs_mount_opts){
        .read_only    = false,
        .keyfile_path = g_key_path,
    };
}
