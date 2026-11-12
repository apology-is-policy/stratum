/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * fs tests of a snapshot's capacity: a drop born after the snapshot spends no list
 * entry, and past a list what the snapshot may name stays allocated, so no list
 * ever costs a write its answer or the snapshot its view.
 */

#include "tharness.h"
#include "test_fs_common.h"
#include <sys/stat.h>

#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/inode.h>
#include <stratum/snapshot.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CAP_MIB (UINT64_C(1024) * 1024u)

static void capacity_root(stm_fs *fs, uint64_t *out_root)
{
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_TRUE(iidx != NULL);
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  out_root));
}

static void capacity_read(stm_fs *fs, uint64_t f, uint8_t *out, size_t len)
{
    size_t got = 0;
    while (got < len) {
        size_t n = 0;
        stm_status rs = stm_fs_read(fs, 1, f, got, out + got, len - got, &n);
        STM_ASSERT_OK(rs);
        STM_ASSERT_TRUE(n > 0);
        if (rs != STM_OK || n == 0) return;
        got += n;
    }
}

static stm_fs *capacity_pool(const char *name, uint64_t device_bytes,
                             uint64_t bootstrap_bytes, stm_fs_mount_opts *mopts)
{
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = device_bytes;
    fopts.bootstrap_size_bytes = bootstrap_bytes;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    *mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, mopts, &fs));
    return fs;
}

static void capacity_done(stm_fs *fs)
{
    if (fs) STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* One block rewritten across commits drops only what the last commit wrote, born
 * after the snapshot: freed, no entry spent, and the pool does not shrink under
 * it. The list holds the extent the first rewrite replaced and little more. */
STM_TEST(fs_a_block_rewritten_under_a_snapshot_spends_no_entries) {
    static uint8_t data[64u * 1024u], next[4096], out[64u * 1024u];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 3u + 1u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = capacity_pool("snapcap_hot", (uint64_t)64u * CAP_MIB,
                               (uint64_t)16u * CAP_MIB, &mopts);
    if (!fs) return;
    uint64_t root = 0, f = 0, snap = 0;
    capacity_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, data, sizeof data));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    stm_snapshot_index *idx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_TRUE(idx != NULL);
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t avail = st.data_avail_blocks;

    enum { REWRITES = 2u * STM_SNAP_DEAD_LIST_MAX };
    stm_status last = STM_OK;
    unsigned written = 0;
    for (unsigned i = 0; i < REWRITES && last == STM_OK; i++) {
        memset(next, (int)(i % 251u + 1u), sizeof next);
        last = stm_fs_write(fs, 1, f, 0, next, sizeof next);
        if (last == STM_OK) last = stm_fs_commit(fs);
        if (last == STM_OK) written++;
    }
    size_t dead = 0;
    uint64_t kept = 99u;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, snap, &dead));
    stm_snapshot_index_retained(idx, &kept, NULL);
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    fprintf(stderr, "snapcap hot: written=%u dead=%zu kept=%llu avail %llu -> %llu "
            "last=%d (%s)\n", written, dead, (unsigned long long)kept,
            (unsigned long long)avail, (unsigned long long)st.data_avail_blocks,
            (int)last, stm_strerror(last));
    STM_ASSERT_OK(last);
    STM_ASSERT_EQ(written, (unsigned)REWRITES);
    STM_ASSERT_EQ(dead, (size_t)1);
    STM_ASSERT_EQ(kept, (uint64_t)0);
    /* far under one block per rewrite, what keeping each would cost */
    STM_ASSERT_TRUE(st.data_avail_blocks + 64u >= avail);
    STM_ASSERT_FALSE(st.wedged);
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    memset(out, 0xa5, sizeof out);
    capacity_read(fs, f, out, sizeof data);
    STM_ASSERT_MEM_EQ(data, out, sizeof data);
    capacity_done(fs);
}

/* Every file's blocks are older than the snapshot, so each overwrite's drop is in
 * its view, past the list's cap. Each is answered, each block stays allocated
 * whether the list took it or not, and none is offered to the allocator: pool
 * pressure afterwards reuses nothing the snapshot reads. */
STM_TEST(fs_overwrites_past_a_snapshots_dead_list_keep_every_block) {
    enum { FILES = STM_SNAP_DEAD_LIST_MAX + 44u, BATCH = 8 };
    enum { FILE_BYTES = 16u * 1024u, FILE_BLOCKS = FILE_BYTES / 4096u };
    static uint64_t inos[FILES];
    static uint8_t b[FILE_BYTES], out[FILE_BYTES], want[FILE_BYTES];
    static uint8_t chunk[64u * 1024u];
    stm_fs_mount_opts mopts;
    stm_fs *fs = capacity_pool("snapcap_keep", (uint64_t)32u * CAP_MIB,
                               (uint64_t)8u * CAP_MIB, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *idx = stm_sync_snapshot_index(sync);
    uint64_t root = 0, g = 0, snap = 0;
    capacity_root(fs, &root);
    for (unsigned i = 0; i < FILES; i++) {
        char name[32];
        int n = snprintf(name, sizeof name, "f%u", i);
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)name,
                                         (uint8_t)n, 0644u, 0, 0, &inos[i]));
        memset(b, (int)(i % 251u + 1u), sizeof b);
        STM_ASSERT_OK(stm_fs_write(fs, 1, inos[i], 0, b, sizeof b));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t avail = st.data_avail_blocks;

    stm_status last = STM_OK;
    unsigned written = 0;
    memset(b, 0xee, sizeof b);
    for (unsigned i = 0; i < FILES && last == STM_OK; i++) {
        last = stm_fs_write(fs, 1, inos[i], 0, b, sizeof b);
        if (last == STM_OK && (i + 1u) % BATCH == 0u) last = stm_fs_commit(fs);
        if (last == STM_OK) written++;
    }
    if (last == STM_OK) last = stm_fs_commit(fs);
    size_t dead = 0;
    uint64_t kept = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, snap, &dead));
    stm_snapshot_index_retained(idx, &kept, NULL);
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    fprintf(stderr, "snapcap keep: written=%u dead=%zu kept=%llu avail %llu -> %llu "
            "last=%d (%s) wedged=%d\n", written, dead, (unsigned long long)kept,
            (unsigned long long)avail, (unsigned long long)st.data_avail_blocks,
            (int)last, stm_strerror(last), (int)st.wedged);
    STM_ASSERT_OK(last);
    STM_ASSERT_EQ(written, (unsigned)FILES);
    /* premise: the list filled and the overwrites ran past it */
    STM_ASSERT_EQ(dead, (size_t)STM_SNAP_DEAD_LIST_MAX);
    STM_ASSERT_TRUE(kept >= (uint64_t)(FILES - STM_SNAP_DEAD_LIST_MAX));
    STM_ASSERT_FALSE(st.wedged);
    /* The space stays spent: the new copies, each with its tag's block, and nothing of
     * the old back. */
    STM_ASSERT_TRUE(avail >= st.data_avail_blocks +
                             (uint64_t)FILES * (FILE_BLOCKS + 1u));

    /* Reuse whatever was wrongly handed back: each round frees the last round's blocks,
     * born after the snapshot, and first fit keeps returning to the lowest gaps, which
     * is where the old copies, the first blocks written, are. */
    memset(chunk, 0x33, sizeof chunk);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"g", 1,
                                     0644u, 0, 0, &g));
    for (unsigned round = 0; round < 128u; round++) {
        for (uint64_t off = 0; off < CAP_MIB; off += sizeof chunk)
            STM_ASSERT_OK(stm_fs_write(fs, 1, g, off, chunk, sizeof chunk));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    for (int round = 0; fs && round < 2; round++) {
        size_t bad = 0;
        for (unsigned i = 0; i < FILES; i++) {
            memset(want, (int)(i % 251u + 1u), sizeof want);
            memset(out, 0xa5, sizeof out);
            capacity_read(fs, inos[i], out, sizeof out);
            if (memcmp(want, out, sizeof out) != 0) bad++;
        }
        STM_ASSERT_EQ(bad, (size_t)0);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    }
    capacity_done(fs);
}

/* Commits that churn one file copy nodes born after the snapshot, which spend no
 * entry. A sweep over every older file copies nodes the snapshot's tree names, far
 * past the list, and each stays allocated; new names force allocations that would
 * reuse a node handed back. The snapshot stays whole. */
STM_TEST(fs_a_snapshot_keeps_its_tree_past_its_node_dead_list) {
    enum { OLD_FILES = 16000, SWEEP_BATCH = 16, CHURN = 300, NEW_COMMITS = 512 };
    static uint64_t olds[OLD_FILES];
    static uint8_t data[64u * 1024u], out[64u * 1024u];
    for (size_t i = 0; i < sizeof data; i++) data[i] = (uint8_t)(i * 7u + 3u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = capacity_pool("snapcap_boot", (uint64_t)256u * CAP_MIB,
                               (uint64_t)128u * CAP_MIB, &mopts);
    if (!fs) return;
    uint64_t root = 0, f = 0, snap = 0;
    capacity_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, data, sizeof data));
    for (unsigned i = 0; i < OLD_FILES; i++) {
        char name[32];
        int n = snprintf(name, sizeof name, "old%u", i);
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)name,
                                         (uint8_t)n, 0644u, 0, 0, &olds[i]));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    stm_snapshot_index *idx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_TRUE(idx != NULL);

    stm_status last = STM_OK;
    for (unsigned i = 0; i < CHURN && last == STM_OK; i++) {
        last = stm_fs_chmod(fs, 1, olds[0], i % 2u ? 0644u : 0640u);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    STM_ASSERT_OK(last);
    size_t nodes = 0;
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(idx, snap, &nodes));
    fprintf(stderr, "snapcap boot: churn left nodes=%zu\n", nodes);
    /* a chain's worth from the first commit, and then nothing per commit */
    STM_ASSERT_TRUE(nodes <= 16u);

    for (unsigned i = 1; last == STM_OK && i < OLD_FILES; i++) {
        last = stm_fs_chmod(fs, 1, olds[i], 0600u);
        if (last == STM_OK && i % SWEEP_BATCH == 0) last = stm_fs_commit(fs);
    }
    for (unsigned i = 0; last == STM_OK && i < NEW_COMMITS; i++) {
        char name[32];
        int n = snprintf(name, sizeof name, "new%u", i);
        uint64_t ino = 0;
        last = stm_fs_create_file(fs, 1, root, (const uint8_t *)name,
                                  (uint8_t)n, 0644u, 0, 0, &ino);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    uint64_t kept = 0;
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(idx, snap, &nodes));
    stm_snapshot_index_retained(idx, NULL, &kept);
    fprintf(stderr, "snapcap boot: nodes=%zu kept=%llu last=%d (%s)\n", nodes,
            (unsigned long long)kept, (int)last, stm_strerror(last));
    STM_ASSERT_OK(last);
    /* premise: the list filled, and the sweep ran past it */
    STM_ASSERT_EQ(nodes, (size_t)STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX);
    STM_ASSERT_TRUE(kept > 0u);

    stm_status rb = stm_fs_rollback_snapshot(fs, 1, snap, false);
    fprintf(stderr, "snapcap boot: rollback=%d (%s)\n", (int)rb, stm_strerror(rb));
    STM_ASSERT_OK(rb);
    for (int round = 0; rb == STM_OK && round < 2; round++) {
        unsigned bad = 0;
        stm_status first = STM_OK;
        for (unsigned i = 1; i < OLD_FILES; i++) {
            struct stm_inode_value v = {0};
            stm_status ss = stm_fs_stat(fs, 1, olds[i], &v);
            if (ss != STM_OK || (stm_load_le32(v.si_mode) & 0777u) != 0644u) {
                if (bad++ == 0) first = ss;
            }
        }
        fprintf(stderr, "snapcap boot: round %d: bad stats=%u first=%d (%s)\n",
                round, bad, (int)first, stm_strerror(first));
        STM_ASSERT_EQ(bad, 0u);
        memset(out, 0xa5, sizeof out);
        capacity_read(fs, f, out, sizeof data);
        STM_ASSERT_MEM_EQ(data, out, sizeof data);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        if (!fs) return;
    }
    capacity_done(fs);
}

STM_TEST_MAIN("fs_snapshot_capacity")
