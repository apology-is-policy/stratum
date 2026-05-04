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

#endif /* STRATUM_V2_TEST_FS_COMMON_H */
