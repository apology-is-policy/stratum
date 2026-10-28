/* SPDX-License-Identifier: ISC */
/*
 * Shared test scaffold for stm_fs test suites.
 *
 * Originally living inline in tests/test_fs.c. Extracted because that
 * file grew past 13k lines + 320+ tests. Split tests/test_fs_phase8.c
 * (P8-POSIX-* surface) reuses the same lifecycle helpers; both link
 * against tests/test_fs_common.c.
 *
 * Each test executable runs as its own process — globals
 * (g_tmp_path / g_key_path) are per-process state; make_tmp()
 * refreshes them per-test.
 */
#ifndef STRATUM_V2_TEST_FS_COMMON_H
#define STRATUM_V2_TEST_FS_COMMON_H

#include <stratum/fs.h>

#include <stdint.h>

#define TEST_DEVICE_BYTES     (UINT64_C(16) * 1024u * 1024u)
#define TEST_BOOTSTRAP_BYTES  (UINT64_C(8)  * 1024u * 1024u)

extern char g_tmp_path[256];
extern char g_key_path[256];

/*
 * make_tmp: refresh g_tmp_path / g_key_path with a unique
 * "/tmp/stm_v2_fs_<tag>_<pid>.bin" pair + regenerate the
 * keyfile. MUST be called at the top of every test that uses
 * stm_fs_format / stm_fs_mount.
 */
void make_tmp(const char *tag);

/*
 * default_format_opts / rw_mount_opts: helpers wrapping the
 * canonical opts struct. POOL_UUID + DEVICE_UUID are module-
 * private constants; keyfile_path points at g_key_path (refreshed
 * by make_tmp).
 */
stm_fs_format_opts default_format_opts(void);
stm_fs_mount_opts  rw_mount_opts(void);

/*
 * reuse_fs / reuse_fs_done: a freshly formatted and mounted pool with an
 * unnamed directory inode in dataset 1, and its unmount.
 */
stm_fs *reuse_fs(const char *name, uint64_t *out_dir);
void    reuse_fs_done(stm_fs *fs);

/* Test-only CDC params override: avg=8 KiB / min=2 KiB / max=32 KiB.
 * stm_cdc_make_params clamps min to avg/4. After round_chunk_boundaries
 * the per-chunk minimum is STM_UB_SIZE (4 KiB). 64 KiB / max=32 KiB
 * forces at least 2 chunks via the loose-region cutoff. */
stm_status mtc4b_install_test_params(stm_fs *fs);

/* Synth-ino encoding constants -- keep in sync with fs.c FS_SYNTH_* macros.
 * Used by the fs tests; not exported from fs.h. */
#define TFS_SYNTH_TAG          (1ULL << 63)
#define TFS_SNAPS_PARENT_INO   TFS_SYNTH_TAG

static inline uint64_t tfs_synth_encode(uint64_t snap_id, uint64_t frozen_ino) {
    return TFS_SYNTH_TAG | (snap_id << 32) | (frozen_ino & 0xFFFFFFFFu);
}

#define LATE_WRITE_BYTES (1024u * 1024u)

#endif /* STRATUM_V2_TEST_FS_COMMON_H */
