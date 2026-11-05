/* SPDX-License-Identifier: ISC */
/*
 * test_pleiades -- Stratum Stabilization Area S correctness stress.
 *
 * The many-small-files surface the existing suite under-covered: test_dirent
 * maxed at 32 names, bench_concurrent_write at 8 files. The go-build creates
 * thousands of small files in nested dirs, so this pins the create/dirent/
 * inline path AT SCALE:
 *
 *   - 2000 files in one directory: every create succeeds (no spurious
 *     STM_ENOSPC from the 64-probe open-addressing cap), readdir enumerates
 *     EXACTLY the set, and every name resolves by lookup (probe walk at depth).
 *   - chain integrity at N=1000 (the test_dirent property, scaled): unlink
 *     half, the surviving half stays reachable, the removed half is ENOENT.
 *   - churn: create N, unlink N, recreate the SAME names (tombstone reuse) --
 *     the realistic rebuild-overwrites-object-files pattern.
 *   - the inline<->extent boundary (STM_INODE_INLINE_MAX = 100): write 99 /
 *     100 / 101 bytes, read back byte-exact (101 triggers the inline->extent
 *     transition, which must not lose or zero the tail).
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/fs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PLEIADES_DEVICE_BYTES   (UINT64_C(64) * 1024u * 1024u)

/* Mount a fresh 64 MiB fs with one dataset; return the dataset id + root ino
 * (always 1). The caller unmounts + unlinks. */
static stm_fs *pleiades_mount(const char *tag, uint64_t *out_ds)
{
    make_tmp(tag);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = PLEIADES_DEVICE_BYTES;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));

    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint64_t ds = 0;
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1, "pl_ds", &ds));
    uint64_t root = 0;
    STM_ASSERT_OK(stm_fs_init_dataset_root(fs, ds, 0755u, 0, 0, &root));
    *out_ds = ds;
    return fs;
}

static void pleiades_teardown(stm_fs *fs)
{
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Drain readdir into `seen[]` (indexed by the integer suffix of an "f%u"
 * name), counting stored entries. Asserts no entry is returned twice and
 * every name parses. Returns the count. */
static size_t drain_readdir_fset(stm_fs *fs, uint64_t ds, uint64_t dir, unsigned n, bool *seen)
{
    memset(seen, 0, (size_t)n * sizeof *seen);
    uint64_t cursor = 0;
    size_t total = 0;
    stm_fs_dirent_entry ents[64];
    for (unsigned guard = 0; guard < n + 16u; guard++) {
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_readdir(fs, ds, dir, dir,
                                        STM_FS_READDIR_FLAG_NO_DOTS,
                                        &cursor, ents, 64u, &got));
        if (got == 0) break;
        for (size_t e = 0; e < got; e++) {
            char nm[40];
            STM_ASSERT(ents[e].name_len < sizeof nm);
            memcpy(nm, ents[e].name, ents[e].name_len);
            nm[ents[e].name_len] = '\0';
            STM_ASSERT_EQ(nm[0], 'f');
            unsigned idx = (unsigned)strtoul(nm + 1, NULL, 10);
            STM_ASSERT(idx < n);
            STM_ASSERT_EQ(seen[idx], false);   /* never returned twice */
            seen[idx] = true;
            total++;
        }
    }
    return total;
}

/* 2000 files in one dir: all create, readdir enumerates exactly them, every
 * name resolves. */
STM_TEST(pleiades_2000_in_one_dir) {
    enum { N = 2000u };
    uint64_t ds = 0;
    stm_fs *fs = pleiades_mount("pl2000", &ds);

    uint64_t *inos = malloc(N * sizeof *inos);
    STM_ASSERT(inos != NULL);
    for (unsigned i = 0; i < N; i++) {
        char nm[40];
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)nm,
                                            (uint8_t)nl, 0100644u, 0, 0, &inos[i]));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));

    bool *seen = malloc(N * sizeof *seen);
    STM_ASSERT(seen != NULL);
    size_t cnt = drain_readdir_fset(fs, ds, 1, N, seen);
    STM_ASSERT_EQ(cnt, (size_t)N);
    for (unsigned i = 0; i < N; i++) STM_ASSERT_EQ(seen[i], true);

    /* Every name resolves to the ino we created (probe walk at depth). */
    for (unsigned i = 0; i < N; i++) {
        char nm[40];
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t got = 0;
        STM_ASSERT_OK(stm_fs_lookup(fs, ds, 1, (const uint8_t *)nm, (uint8_t)nl, &got));
        STM_ASSERT_EQ(got, inos[i]);
    }

    free(seen);
    free(inos);
    pleiades_teardown(fs);
}

/* Chain integrity scaled to N=1000: unlink even names, odd survive, even are
 * ENOENT, readdir shows exactly the 500 survivors. (test_dirent's N=32
 * property at 30x.) */
STM_TEST(pleiades_unlink_half_preserves_chain) {
    enum { N = 1000u };
    uint64_t ds = 0;
    stm_fs *fs = pleiades_mount("plhalf", &ds);

    for (unsigned i = 0; i < N; i++) {
        char nm[40];
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)nm,
                                            (uint8_t)nl, 0100644u, 0, 0, &ino));
    }
    for (unsigned i = 0; i < N; i += 2u) {
        char nm[40];
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        STM_ASSERT_OK(stm_fs_unlink(fs, ds, 1, (const uint8_t *)nm, (uint8_t)nl));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));

    for (unsigned i = 1; i < N; i += 2u) {
        char nm[40];
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t got = 0;
        STM_ASSERT_OK(stm_fs_lookup(fs, ds, 1, (const uint8_t *)nm, (uint8_t)nl, &got));
    }
    for (unsigned i = 0; i < N; i += 2u) {
        char nm[40];
        int nl = snprintf(nm, sizeof nm, "f%u", i);
        uint64_t got = 0;
        STM_ASSERT_ERR(stm_fs_lookup(fs, ds, 1, (const uint8_t *)nm, (uint8_t)nl, &got),
                       STM_ENOENT);
    }

    bool *seen = malloc(N * sizeof *seen);
    STM_ASSERT(seen != NULL);
    size_t cnt = drain_readdir_fset(fs, ds, 1, N, seen);
    STM_ASSERT_EQ(cnt, (size_t)(N / 2u));
    for (unsigned i = 1; i < N; i += 2u) STM_ASSERT_EQ(seen[i], true);

    free(seen);
    pleiades_teardown(fs);
}

/* Churn: create N, unlink N, recreate the SAME N names. The recreate must
 * reuse tombstone slots and resolve correctly (rebuild-overwrites pattern). */
STM_TEST(pleiades_churn_recreate_same_names) {
    enum { N = 800u };
    uint64_t ds = 0;
    stm_fs *fs = pleiades_mount("plchurn", &ds);

    for (unsigned round = 0; round < 2u; round++) {
        for (unsigned i = 0; i < N; i++) {
            char nm[40];
            int nl = snprintf(nm, sizeof nm, "f%u", i);
            uint64_t ino = 0;
            STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)nm,
                                                (uint8_t)nl, 0100644u, 0, 0, &ino));
        }
        STM_ASSERT_OK(stm_fs_commit(fs));

        bool *seen = malloc(N * sizeof *seen);
        STM_ASSERT(seen != NULL);
        size_t cnt = drain_readdir_fset(fs, ds, 1, N, seen);
        STM_ASSERT_EQ(cnt, (size_t)N);
        free(seen);

        if (round == 0u) {
            for (unsigned i = 0; i < N; i++) {
                char nm[40];
                int nl = snprintf(nm, sizeof nm, "f%u", i);
                STM_ASSERT_OK(stm_fs_unlink(fs, ds, 1, (const uint8_t *)nm, (uint8_t)nl));
            }
            STM_ASSERT_OK(stm_fs_commit(fs));
        }
    }

    pleiades_teardown(fs);
}

/* The inline<->extent boundary (STM_INODE_INLINE_MAX = 100): 99/100 stay
 * inline, 101 transitions to a single extent. Each must read back byte-exact
 * (the transition must not zero or lose the tail). */
STM_TEST(pleiades_inline_boundary_roundtrip) {
    uint64_t ds = 0;
    stm_fs *fs = pleiades_mount("plinline", &ds);

    const unsigned sizes[] = { 99u, 100u, 101u };
    for (unsigned s = 0; s < 3u; s++) {
        unsigned len = sizes[s];
        char nm[16];
        int nl = snprintf(nm, sizeof nm, "i%u", len);
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_create_file(fs, ds, 1, (const uint8_t *)nm,
                                            (uint8_t)nl, 0100644u, 0, 0, &ino));

        uint8_t wbuf[256];
        for (unsigned i = 0; i < len; i++) wbuf[i] = (uint8_t)(i * 17u + s * 3u + 1u);
        STM_ASSERT_OK(stm_fs_write(fs, ds, ino, 0, wbuf, len));

        uint8_t rbuf[256];
        memset(rbuf, 0xAB, sizeof rbuf);
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(fs, ds, ino, 0, rbuf, len, &got));
        STM_ASSERT_EQ(got, (size_t)len);
        STM_ASSERT(memcmp(rbuf, wbuf, len) == 0);
    }

    /* Survives a commit + re-read (the transition's durable state). */
    STM_ASSERT_OK(stm_fs_commit(fs));
    {
        uint64_t ino = 0;
        STM_ASSERT_OK(stm_fs_lookup(fs, ds, 1, (const uint8_t *)"i101", 4u, &ino));
        uint8_t rbuf[256];
        memset(rbuf, 0xAB, sizeof rbuf);
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(fs, ds, ino, 0, rbuf, 101u, &got));
        STM_ASSERT_EQ(got, (size_t)101u);
        for (unsigned i = 0; i < 101u; i++)
            STM_ASSERT_EQ(rbuf[i], (uint8_t)(i * 17u + 2u * 3u + 1u));
    }

    pleiades_teardown(fs);
}

STM_TEST_MAIN("pleiades")
