/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * fs tests of what a snapshot's lists must keep: across a delete of its newer
 * neighbour, a promote, a cold list at its cap, and a clone that shares the
 * snapshot's blocks with its origin.
 */

#include "tharness.h"
#include "test_fs_common.h"
#include <fcntl.h>
#include <sys/stat.h>

#include <stratum/alloc.h>
#include <stratum/alloc_testing.h>
#include <stratum/bootstrap.h>
#include <stratum/dataset.h>
#include <stratum/cas.h>
#include <stratum/extent.h>
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

#define LISTS_MIB (UINT64_C(1024) * 1024u)

/* Varied by seed and offset, so the chunker cuts and no two files dedup. */
static uint8_t lists_pat(uint64_t seed, uint64_t i)
{
    uint32_t v = (uint32_t)(i + seed * 2147483647u) * 2654435761u + 0x9e3779b9u;
    v ^= v >> 15;
    v *= 2246822519u;
    v ^= v >> 13;
    return (uint8_t)(v >> 24);
}

static void lists_fill(uint8_t *b, size_t len, uint64_t seed)
{
    for (size_t i = 0; i < len; i++) b[i] = lists_pat(seed, i);
}

static stm_fs *lists_mount(const char *name, uint64_t device_bytes,
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

static void lists_root(stm_fs *fs, uint64_t *out_root)
{
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_TRUE(iidx != NULL);
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  out_root));
}

static void lists_read(stm_fs *fs, uint64_t ds, uint64_t f, uint8_t *out,
                       size_t len)
{
    size_t got = 0;
    while (got < len) {
        size_t n = 0;
        stm_status rs = stm_fs_read(fs, ds, f, got, out + got, len - got, &n);
        STM_ASSERT_OK(rs);
        STM_ASSERT_TRUE(n > 0);
        if (rs != STM_OK || n == 0) return;
        got += n;
    }
}

static void lists_done(stm_fs *fs)
{
    if (fs) STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
    unlink(g_key_path);
}

/* Writes over a run wrongly handed back: a read of it cannot tell before that. Each round
 * frees the last round's blocks, born after every snapshot here. The allocator is first fit
 * and a drop is swept a commit later, so this cycles the lowest few gaps that fit a chunk
 * and reaches nothing above them: the block at risk has to be the oldest written. A fill
 * to ENOSPC cannot do this: it stops on reservations, short of a run behind its
 * placements. */
#define LISTS_CHURN_INO UINT64_C(77)

static void lists_reuse_lowest_runs(stm_fs *fs, uint64_t device_bytes)
{
    static uint8_t chunk[LISTS_MIB];
    lists_fill(chunk, sizeof chunk, 3u);
    unsigned rounds = 0, want = (unsigned)(4u * device_bytes / LISTS_MIB);
    stm_status last = STM_OK;
    for (; last == STM_OK && rounds < want; rounds++) {
        last = stm_fs_write(fs, 1, LISTS_CHURN_INO, 0, chunk, sizeof chunk);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    fprintf(stderr, "reuse lowest runs: %u rounds of %u, last=%d (%s)\n", rounds, want,
            (int)last, stm_strerror(last));
    STM_ASSERT_OK(last);
}

/* Two snapshots name a block; an overwrite puts it on the newer's list. The older
 * still names it, so deleting the newer frees nothing and the older's list takes
 * it. */
STM_TEST(fs_deleting_a_newer_snapshot_leaves_the_older_whole) {
    static uint8_t data[LISTS_MIB], next[LISTS_MIB], out[LISTS_MIB];
    lists_fill(data, sizeof data, 1u);
    lists_fill(next, sizeof next, 2u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_del", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *idx = stm_sync_snapshot_index(sync);
    uint64_t root = 0, f = 0, s1 = 0, s2 = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, data, sizeof data));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, next, sizeof next));
    STM_ASSERT_OK(stm_fs_commit(fs));

    size_t on_newer = 0, on_older = 99u, freed = 99u;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s2, &on_newer));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s1, &on_older));
    STM_ASSERT_TRUE(on_newer >= 1u);
    STM_ASSERT_EQ(on_older, (size_t)0);
    uint64_t pending = stm_sync_pending_free_blocks(sync);
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s2, &freed));
    fprintf(stderr, "snaplist del: newer=%zu freed=%zu pending %llu -> %llu\n",
            on_newer, freed, (unsigned long long)pending,
            (unsigned long long)stm_sync_pending_free_blocks(sync));
    STM_ASSERT_EQ(freed, (size_t)0);
    STM_ASSERT_EQ(stm_sync_pending_free_blocks(sync), pending);
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s1, &on_older));
    STM_ASSERT_EQ(on_older, on_newer);

    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    lists_reuse_lowest_runs(fs, TEST_DEVICE_BYTES);
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s1, false));
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, f, out, sizeof out);
    STM_ASSERT_MEM_EQ(data, out, sizeof out);
    lists_done(fs);
}

/* A rollback past a newer snapshot brings back what that snapshot's list held. The
 * block is live again, so no list may keep it: the target's later delete would free
 * it under the live file. */
STM_TEST(fs_a_rollback_past_a_newer_snapshot_keeps_what_it_brings_back) {
    static uint8_t data[LISTS_MIB], next[LISTS_MIB], out[LISTS_MIB];
    lists_fill(data, sizeof data, 22u);
    lists_fill(next, sizeof next, 23u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_back", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_snapshot_index *idx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    uint64_t root = 0, f = 0, s1 = 0, s2 = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, data, sizeof data));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, next, sizeof next));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t on_newer = 0, on_target = 99u, freed = 99u;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s2, &on_newer));
    STM_ASSERT_TRUE(on_newer >= 1u);

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s1, false));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s1, &on_target));
    fprintf(stderr, "snaplist back: on_newer=%zu on_target=%zu\n", on_newer, on_target);
    STM_ASSERT_EQ(on_target, (size_t)0);
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s1, &freed));
    STM_ASSERT_EQ(freed, (size_t)0);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    lists_reuse_lowest_runs(fs, TEST_DEVICE_BYTES);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, f, out, sizeof out);
    STM_ASSERT_MEM_EQ(data, out, sizeof out);
    lists_done(fs);
}

/* A full pool has to be able to let go: a file's whole delete needs no new block. */
STM_TEST(fs_a_full_pool_can_let_go) {
    static uint8_t chunk[64u * 1024u];
    lists_fill(chunk, sizeof chunk, 24u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_full", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t root = 0, f = 0, off = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    stm_status last = STM_OK;
    while (last == STM_OK && off < TEST_DEVICE_BYTES) {
        last = stm_fs_write(fs, 1, f, off, chunk, sizeof chunk);
        if (last != STM_OK) break;
        off += sizeof chunk;
        if (off % LISTS_MIB == 0u) last = stm_fs_commit(fs);
    }
    /* premise: the pool filled */
    STM_ASSERT_EQ((int)last, (int)STM_ENOSPC);
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status part = stm_fs_truncate(fs, 1, f, off - LISTS_MIB + 1u);
    stm_status whole = stm_fs_truncate(fs, 1, f, 0u);
    fprintf(stderr, "snaplist full: filled %llu, part truncate %d (%s), whole %d (%s)\n",
            (unsigned long long)off, (int)part, stm_strerror(part), (int)whole,
            stm_strerror(whole));
    STM_ASSERT_OK(whole);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, chunk, sizeof chunk));
    STM_ASSERT_OK(stm_fs_commit(fs));
    lists_done(fs);
}

/* Under a snapshot the same delete frees nothing, and still needs no new block. Past
 * the list it keeps what it drops, and the snapshot reads what it took. */
STM_TEST(fs_a_full_pool_under_a_snapshot_can_let_go) {
    static uint8_t chunk[64u * 1024u], out[64u * 1024u];
    lists_fill(chunk, sizeof chunk, 38u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_full_snap", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t root = 0, f = 0, off = 0, snap = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    stm_status last = STM_OK;
    while (last == STM_OK && off < TEST_DEVICE_BYTES) {
        last = stm_fs_write(fs, 1, f, off, chunk, sizeof chunk);
        if (last != STM_OK) break;
        off += sizeof chunk;
        if (off % LISTS_MIB == 0u) last = stm_fs_commit(fs);
    }
    /* premise: the pool filled */
    STM_ASSERT_EQ((int)last, (int)STM_ENOSPC);
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status made = stm_fs_create_snapshot(fs, 1, "s", 1, &snap);
    stm_status whole = stm_fs_truncate(fs, 1, f, 0u);
    stm_status com = stm_fs_commit(fs);
    fprintf(stderr, "snaplist full snap: filled %llu, snapshot %d (%s), truncate %d (%s), "
            "commit %d (%s)\n", (unsigned long long)off, (int)made, stm_strerror(made),
            (int)whole, stm_strerror(whole), (int)com, stm_strerror(com));
    STM_ASSERT_OK(made);
    STM_ASSERT_OK(whole);
    STM_ASSERT_OK(com);
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, f, out, sizeof out);
    STM_ASSERT_MEM_EQ(chunk, out, sizeof out);
    lists_done(fs);
}

/* The other half of the move: the oldest snapshot's delete frees what it took,
 * so a block only a deleted snapshot named costs space only until then. */
STM_TEST(fs_the_oldest_snapshots_delete_frees_what_the_newer_left) {
    static uint8_t data[LISTS_MIB], next[LISTS_MIB], out[LISTS_MIB];
    lists_fill(data, sizeof data, 4u);
    lists_fill(next, sizeof next, 5u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_old", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    uint64_t root = 0, f = 0, s1 = 0, s2 = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, data, sizeof data));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, next, sizeof next));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t on_newer = 0, freed = 0;
    STM_ASSERT_OK(stm_snapshot_dead_list_count(stm_sync_snapshot_index(sync),
                                               s2, &on_newer));
    STM_ASSERT_TRUE(on_newer >= 1u);
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s2, &freed));
    uint64_t pending = stm_sync_pending_free_blocks(sync);
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s1, &freed));
    STM_ASSERT_TRUE(freed >= on_newer);
    STM_ASSERT_TRUE(stm_sync_pending_free_blocks(sync) > pending);
    STM_ASSERT_OK(stm_fs_commit(fs));
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, f, out, sizeof out);
    STM_ASSERT_MEM_EQ(next, out, sizeof out);
    lists_done(fs);
}

/* A promote drops the cold record a snapshot's view names, and the view's only
 * reference to the chunk is that record's: the chunk stays until the snapshot
 * lets go. A cold record born after the snapshot is in no view, and its chunk
 * goes as it would with no snapshot at all. */
STM_TEST(fs_a_promote_under_a_snapshot_keeps_its_chunk) {
    static uint8_t data[64u * 1024u], other[64u * 1024u], out[64u * 1024u];
    lists_fill(data, sizeof data, 6u);
    lists_fill(other, sizeof other, 7u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_promote", (uint64_t)64u * LISTS_MIB,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    uint64_t root = 0, f = 0, h = 0, snap = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, data, sizeof data));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, f));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t chunks = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &chunks));
    STM_ASSERT_TRUE(chunks >= 1u);
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));

    STM_ASSERT_OK(stm_fs_promote_to_hot(fs, 1, f));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t now = 0, listed = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &now));
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(idx, snap, &listed));
    fprintf(stderr, "snaplist promote: chunks %zu -> %zu listed=%zu\n", chunks,
            now, listed);
    STM_ASSERT_EQ(now, chunks);
    STM_ASSERT_EQ(listed, chunks);

    /* The control: born after the snapshot, so it spends no entry. */
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"h", 1,
                                     0644u, 0, 0, &h));
    STM_ASSERT_OK(stm_fs_write(fs, 1, h, 0, other, sizeof other));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, h));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &now));
    STM_ASSERT_TRUE(now > chunks);
    STM_ASSERT_OK(stm_fs_promote_to_hot(fs, 1, h));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &now));
    STM_ASSERT_EQ(now, chunks);
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(idx, snap, &listed));
    STM_ASSERT_EQ(listed, chunks);

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, f, out, sizeof out);
    STM_ASSERT_MEM_EQ(data, out, sizeof out);
    lists_done(fs);
}

/* Every file's one cold record is overwritten under a snapshot, past the cold
 * list's cap. Each overwrite is answered, whichever road its bytes take, and the
 * fs never wedges; the snapshot keeps every chunk, list or no list. */
static void cold_past_the_list(const char *name, size_t write_len)
{
    enum { FILES = STM_SNAP_COLD_DEAD_LIST_MAX + 44u, BATCH = 8 };
    enum { FILE_BYTES = 16u * 1024u };
    static uint64_t inos[FILES];
    static uint8_t b[FILE_BYTES], out[FILE_BYTES], want[FILE_BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount(name, (uint64_t)256u * LISTS_MIB,
                             (uint64_t)32u * LISTS_MIB, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *idx = stm_sync_snapshot_index(sync);
    uint64_t root = 0, snap = 0;
    lists_root(fs, &root);
    for (unsigned i = 0; i < FILES; i++) {
        char fname[32];
        int n = snprintf(fname, sizeof fname, "f%u", i);
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)fname,
                                         (uint8_t)n, 0644u, 0, 0, &inos[i]));
        lists_fill(b, sizeof b, (uint64_t)i + 100u);
        STM_ASSERT_OK(stm_fs_write(fs, 1, inos[i], 0, b, sizeof b));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, inos[i]));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t chunks = 0;
    STM_ASSERT_OK(stm_cas_count(stm_sync_cas_index(sync), &chunks));
    /* premise: every file went cold */
    STM_ASSERT_TRUE(chunks >= FILES);
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));

    stm_status last = STM_OK;
    unsigned written = 0;
    memset(b, 0x77, sizeof b);
    for (unsigned i = 0; i < FILES && last == STM_OK; i++) {
        last = stm_fs_write(fs, 1, inos[i], 0, b, write_len);
        if (last == STM_OK && (i + 1u) % BATCH == 0u) last = stm_fs_commit(fs);
        if (last == STM_OK) written++;
    }
    if (last == STM_OK) last = stm_fs_commit(fs);
    size_t listed = 0;
    (void)stm_snapshot_cold_dead_list_count(idx, snap, &listed);
    stm_fs_stats st = {0};
    (void)stm_fs_stats_get(fs, &st);
    fprintf(stderr, "%s: written=%u listed=%zu chunks=%zu last=%d (%s) wedged=%d\n",
            name, written, listed, chunks, (int)last, stm_strerror(last),
            (int)st.wedged);
    STM_ASSERT_OK(last);
    STM_ASSERT_FALSE(st.wedged);
    STM_ASSERT_EQ(written, (unsigned)FILES);
    /* premise: the list filled and the overwrites ran past it */
    STM_ASSERT_EQ(listed, (size_t)STM_SNAP_COLD_DEAD_LIST_MAX);

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    for (int round = 0; fs && round < 2; round++) {
        size_t bad = 0;
        for (unsigned i = 0; i < FILES; i++) {
            lists_fill(want, sizeof want, (uint64_t)i + 100u);
            memset(out, 0xa5, sizeof out);
            lists_read(fs, 1, inos[i], out, sizeof out);
            if (memcmp(want, out, sizeof out) != 0) bad++;
        }
        STM_ASSERT_EQ(bad, (size_t)0);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    }
    lists_done(fs);
}

STM_TEST(fs_whole_overwrites_past_a_cold_list_are_answered) {
    cold_past_the_list("snaplist_cold_whole", (size_t)16u * 1024u);
}

STM_TEST(fs_partial_overwrites_past_a_cold_list_are_answered) {
    cold_past_the_list("snaplist_cold_part", (size_t)100u);
}

/* A clone and its origin share what their snapshot names, so each overwrites the
 * same block once. Neither answer may be a wedge, and each keeps its own bytes. */
static void clone_and_origin(const char *name, bool clone_first)
{
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], o[BYTES], c[BYTES], out[BYTES];
    lists_fill(x, sizeof x, 8u);
    lists_fill(o, sizeof o, 9u);
    lists_fill(c, sizeof c, 10u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount(name, TEST_DEVICE_BYTES, TEST_BOOTSTRAP_BYTES,
                             &mopts);
    if (!fs) return;
    uint64_t snap = 0, clone = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap, &clone));
    STM_ASSERT_OK(stm_fs_commit(fs));

    uint64_t first = clone_first ? clone : 1u, then = clone_first ? 1u : clone;
    STM_ASSERT_OK(stm_fs_write(fs, first, 1, 0, clone_first ? c : o, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status last = stm_fs_write(fs, then, 1, 0, clone_first ? o : c, sizeof c);
    if (last == STM_OK) last = stm_fs_commit(fs);
    stm_fs_stats st = {0};
    (void)stm_fs_stats_get(fs, &st);
    fprintf(stderr, "%s: second overwrite last=%d (%s) wedged=%d\n", name,
            (int)last, stm_strerror(last), (int)st.wedged);
    STM_ASSERT_OK(last);
    STM_ASSERT_FALSE(st.wedged);
    if (last != STM_OK) {
        lists_done(fs);
        return;
    }
    for (int round = 0; fs && round < 2; round++) {
        memset(out, 0xa5, sizeof out);
        lists_read(fs, 1, 1, out, sizeof out);
        STM_ASSERT_MEM_EQ(o, out, sizeof out);
        memset(out, 0xa5, sizeof out);
        lists_read(fs, clone, 1, out, sizeof out);
        STM_ASSERT_MEM_EQ(c, out, sizeof out);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    }
    lists_done(fs);
}

STM_TEST(fs_a_clone_then_its_origin_overwrite_a_shared_block) {
    clone_and_origin("snaplist_clone_a", true);
}

STM_TEST(fs_an_origin_then_its_clone_overwrite_a_shared_block) {
    clone_and_origin("snaplist_clone_b", false);
}

/* An origin's two records share one block, so they hold two counts. A clone inherits
 * both records and neither count: its overwrite takes nothing, and the origin's two
 * drops each find theirs. */
STM_TEST(fs_a_clones_overwrite_takes_no_count_from_its_origin) {
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], o[BYTES], o2[BYTES], c[BYTES], out[BYTES];
    lists_fill(x, sizeof x, 11u);
    lists_fill(o, sizeof o, 12u);
    lists_fill(o2, sizeof o2, 13u);
    lists_fill(c, sizeof c, 14u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rc_a", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0, clone = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap, &clone));
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_fs_write(fs, clone, 1, 0, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, o, sizeof o));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status last = stm_fs_write(fs, 1, 2, 0, o2, sizeof o2);
    if (last == STM_OK) last = stm_fs_commit(fs);
    stm_fs_stats st = {0};
    (void)stm_fs_stats_get(fs, &st);
    fprintf(stderr, "snaplist rc a: origin's second drop last=%d (%s) wedged=%d\n",
            (int)last, stm_strerror(last), (int)st.wedged);
    STM_ASSERT_OK(last);
    STM_ASSERT_FALSE(st.wedged);
    if (last != STM_OK) {
        lists_done(fs);
        return;
    }
    for (int round = 0; fs && round < 2; round++) {
        lists_read(fs, 1, 1, out, sizeof out);
        STM_ASSERT_MEM_EQ(o, out, sizeof out);
        lists_read(fs, 1, 2, out, sizeof out);
        STM_ASSERT_MEM_EQ(o2, out, sizeof out);
        lists_read(fs, clone, 1, out, sizeof out);
        STM_ASSERT_MEM_EQ(c, out, sizeof out);
        lists_read(fs, clone, 2, out, sizeof out);
        STM_ASSERT_MEM_EQ(x, out, sizeof out);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    }
    lists_done(fs);
}

/* A clone's reflink of a block its snapshot names takes no count: the snapshot holds
 * the block while the clone stands. So the origin's drop finds its count the last and
 * lists the block on the newest view naming it, where a rollback to a newer snapshot,
 * whose view does not, leaves it alone. */
STM_TEST(fs_a_clones_reflink_takes_no_count_of_a_snapshots_block) {
    static uint8_t x[LISTS_MIB], o[LISTS_MIB], c[LISTS_MIB], out[LISTS_MIB];
    lists_fill(x, sizeof x, 15u);
    lists_fill(o, sizeof o, 16u);
    lists_fill(c, sizeof c, 17u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rc_b", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_snapshot_index *idx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    uint64_t s1 = 0, s2 = 0, clone = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", s1, &clone));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_reflink(fs, clone, 1, clone, 2));
    STM_ASSERT_OK(stm_fs_commit(fs));

    size_t on_older = 99u, on_newer = 99u;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, o, sizeof o));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s1, &on_older));
    STM_ASSERT_EQ(on_older, (size_t)1);

    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT_OK(stm_fs_write(fs, clone, 2, 0, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s1, &on_older));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, s2, &on_newer));
    fprintf(stderr, "snaplist rc b: older=%zu newer=%zu\n", on_older, on_newer);
    STM_ASSERT_EQ(on_older, (size_t)1);
    STM_ASSERT_EQ(on_newer, (size_t)0);

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s2, false));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    lists_reuse_lowest_runs(fs, TEST_DEVICE_BYTES);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, clone, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof out);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, clone, 2, out, sizeof out);
    STM_ASSERT_MEM_EQ(c, out, sizeof out);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(o, out, sizeof out);
    lists_done(fs);
}

/* A reflink pair both dropped under a snapshot, then a rollback: both records are back,
 * and each must hold a count, or the first one's next drop frees the block under the
 * second. */
STM_TEST(fs_a_rollback_gives_a_reflink_pair_its_counts_back) {
    static uint8_t x[LISTS_MIB], a[LISTS_MIB], out[LISTS_MIB];
    lists_fill(x, sizeof x, 26u);
    lists_fill(a, sizeof a, 27u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rb_rc", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0;
    size_t freed = 99u;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap, &freed));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    lists_reuse_lowest_runs(fs, TEST_DEVICE_BYTES);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, 2, out, sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof out);
    lists_done(fs);
}

typedef struct {
    uint64_t ino;
    uint64_t off;
    uint64_t paddr;
} lists_record_query;

static bool lists_record_cb(const stm_extent_record *e, void *ctx)
{
    lists_record_query *q = ctx;
    if (e->ino == q->ino && e->off == q->off && e->kind == STM_EXTENT_KIND_HOT)
        q->paddr = e->paddrs[0];
    return true;
}

/* The allocator's count on the block the live record at (ino, off) names. */
static uint32_t lists_count_at(stm_fs *fs, uint64_t ds, uint64_t ino, uint64_t off)
{
    stm_sync *sync = stm_fs_sync_for_test(fs);
    lists_record_query q = { ino, off, 0 };
    STM_ASSERT_OK(stm_extent_iter_ds(stm_sync_extent_index(sync), ds, lists_record_cb, &q));
    STM_ASSERT(q.paddr != 0);
    if (q.paddr == 0) return 0;
    stm_alloc *a = stm_sync_alloc(sync, stm_paddr_device(q.paddr));
    uint64_t len = 0;
    uint32_t rc = 0;
    STM_ASSERT_OK(stm_alloc_lookup(a, q.paddr, &len, &rc));
    return rc;
}

/* A clone's failed reflink gives back the counts it took and no others: its inherited
 * record took none, and a count given back there is the snapshot's block let go. The
 * inherited record comes first, so an undo that does not skip it spends the bump there. */
STM_TEST(fs_a_clones_failed_reflink_gives_back_only_what_it_took) {
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], c[BYTES], out[BYTES];
    lists_fill(x, sizeof x, 41u);
    lists_fill(c, sizeof c, 42u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rc_undo", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0, clone = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap, &clone));
    STM_ASSERT_OK(stm_fs_write(fs, clone, 1, BYTES, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_write(fs, clone, 1, 2u * BYTES, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, 0), 1u);
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, BYTES), 1u);
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, 2u * BYTES), 1u);
    stm_alloc *a = stm_sync_alloc(stm_fs_sync_for_test(fs), 0);
    stm_alloc_fail_next_ref_for_test(a, 2u, STM_ENOMEM);
    stm_status rs = stm_fs_reflink(fs, clone, 1, clone, 2);
    stm_alloc_fail_next_ref_for_test(a, 0u, STM_OK);
    /* premise: it was the second bump that failed, so one came before it */
    STM_ASSERT_EQ(rs, STM_ENOMEM);
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, 0), 1u);
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, BYTES), 1u);
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, 2u * BYTES), 1u);
    /* the control: the same reflink with nothing failing bumps the clone's own only */
    STM_ASSERT_OK(stm_fs_reflink(fs, clone, 1, clone, 2));
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, 0), 1u);
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, BYTES), 2u);
    STM_ASSERT_EQ(lists_count_at(fs, clone, 1, 2u * BYTES), 2u);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof out);
    lists_done(fs);
}

/* A rollback that cannot give a view's block its counts must not commit: the pair would
 * come back on one count. It wedges with the pool as it was before, and the rollback
 * can be asked for again. */
STM_TEST(fs_a_rollback_that_cannot_set_a_count_commits_nothing) {
    static uint8_t x[LISTS_MIB], a[LISTS_MIB], out[LISTS_MIB];
    lists_fill(x, sizeof x, 43u);
    lists_fill(a, sizeof a, 44u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rb_wedge", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 1, 1, 2));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 2, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_alloc *al = stm_sync_alloc(stm_fs_sync_for_test(fs), 0);
    stm_alloc_fail_next_ref_for_test(al, 1u, STM_ENOMEM);
    stm_status rs = stm_fs_rollback_snapshot(fs, 1, snap, false);
    stm_alloc_fail_next_ref_for_test(al, 0u, STM_OK);
    STM_ASSERT_EQ(rs, STM_ENOMEM);
    STM_ASSERT_ERR(stm_fs_commit(fs), STM_EWEDGED);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(a, out, sizeof out);
    /* the control: asked again with nothing failing, the pair comes back on two counts */
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_EQ(lists_count_at(fs, 1, 1, 0), 2u);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, 2, out, sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof out);
    lists_done(fs);
}

/* A reflink pair born after the snapshot goes with the rollback, both counts. */
STM_TEST(fs_a_rollback_frees_every_count_it_drops) {
    static uint8_t x[LISTS_MIB];
    lists_fill(x, sizeof x, 28u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rb_all", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    stm_fs_stats st = {0};
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    uint64_t avail = st.data_avail_blocks;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 5, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_reflink(fs, 1, 5, 1, 6));
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* premise: the pair is holding space, or coming back proves nothing */
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    STM_ASSERT_TRUE(st.data_avail_blocks + 64u < avail);
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_stats_get(fs, &st));
    fprintf(stderr, "snaplist rb all: avail %llu -> %llu\n", (unsigned long long)avail,
            (unsigned long long)st.data_avail_blocks);
    STM_ASSERT_TRUE(st.data_avail_blocks + 16u >= avail);
    lists_done(fs);
}

/* A cold record a clone made took a reference of its own, however old its bytes: the
 * clone's overwrite lets it go, and no list takes it. */
STM_TEST(fs_a_clones_own_cold_record_lets_its_chunk_go) {
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], c[BYTES], out[BYTES];
    lists_fill(x, sizeof x, 18u);
    lists_fill(c, sizeof c, 19u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rc_c", (uint64_t)64u * LISTS_MIB,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    uint64_t snap = 0, clone = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap, &clone));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t none = 99u, made = 0, after = 99u, listed = 99u;
    STM_ASSERT_OK(stm_cas_count(cas, &none));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, clone, 1));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &made));
    /* premise: the clone's migrate made a chunk */
    STM_ASSERT_TRUE(made > none);
    STM_ASSERT_OK(stm_fs_write(fs, clone, 1, 0, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &after));
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(stm_sync_snapshot_index(sync),
                                                    snap, &listed));
    fprintf(stderr, "snaplist rc c: chunks %zu -> %zu -> %zu listed=%zu\n", none,
            made, after, listed);
    STM_ASSERT_EQ(after, none);
    STM_ASSERT_EQ(listed, (size_t)0);
    lists_read(fs, clone, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(c, out, sizeof out);
    lists_read(fs, 1, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof out);
    lists_done(fs);
}

/* A cold record made after a snapshot is in no view, however old its bytes: the view
 * reads the hot blocks the migrate listed, and the record's reference goes with no
 * entry. */
STM_TEST(fs_a_cold_record_made_after_a_snapshot_spends_no_entry) {
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], n[BYTES], out[BYTES];
    lists_fill(x, sizeof x, 20u);
    lists_fill(n, sizeof n, 21u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_cold_new", (uint64_t)64u * LISTS_MIB,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *idx = stm_sync_snapshot_index(sync);
    stm_cas_index *cas = stm_sync_cas_index(sync);
    uint64_t root = 0, f = 0, snap = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, f));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t made = 0, after = 99u, listed = 99u, hot = 0;
    STM_ASSERT_OK(stm_cas_count(cas, &made));
    STM_ASSERT_OK(stm_snapshot_dead_list_count(idx, snap, &hot));
    /* premise: the migrate made a chunk, and listed the blocks the view reads */
    STM_ASSERT_TRUE(made >= 1u);
    STM_ASSERT_TRUE(hot >= 1u);
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, n, sizeof n));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &after));
    STM_ASSERT_OK(stm_snapshot_cold_dead_list_count(idx, snap, &listed));
    fprintf(stderr, "snaplist cold new: chunks %zu -> %zu listed=%zu hot=%zu\n",
            made, after, listed, hot);
    STM_ASSERT_EQ(after, (size_t)0);
    STM_ASSERT_EQ(listed, (size_t)0);
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, f, out, sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof out);
    lists_done(fs);
}

/* What a clone writes is its own, from the first gen after its snapshot's capture:
 * a rewrite frees it, and rewriting forever costs nothing. The small pool's data and
 * node space would both run out on any leak. */
STM_TEST(fs_a_clones_own_blocks_go_back) {
    static uint8_t b[LISTS_MIB], out[LISTS_MIB];
    lists_fill(b, sizeof b, 25u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_own", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync_for_test(fs);
    uint64_t snap = 0, clone = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, 4096u));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap, &clone));
    STM_ASSERT_OK(stm_fs_write(fs, clone, 5, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    uint64_t pending = stm_sync_pending_free_blocks(sync);
    STM_ASSERT_OK(stm_fs_write(fs, clone, 5, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    uint64_t now = stm_sync_pending_free_blocks(sync);
    fprintf(stderr, "snaplist own: pending %llu -> %llu\n", (unsigned long long)pending,
            (unsigned long long)now);
    STM_ASSERT_TRUE(now >= pending + LISTS_MIB / 4096u);

    stm_status last = STM_OK;
    unsigned rounds = 0;
    for (; last == STM_OK && rounds < 64u; rounds++) {
        last = stm_fs_write(fs, clone, 5, 0, b, sizeof b);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    for (unsigned small = 0; last == STM_OK && small < 1200u; small++) {
        last = stm_fs_write(fs, clone, 6, 0, b, 4096u);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    fprintf(stderr, "snaplist own: %u data rounds, last=%d (%s)\n", rounds, (int)last,
            stm_strerror(last));
    STM_ASSERT_OK(last);
    lists_read(fs, clone, 5, out, sizeof out);
    STM_ASSERT_MEM_EQ(b, out, sizeof out);
    lists_done(fs);
}

/* A clone's rewrite copies the nodes it shares with its origin, and those stay: the
 * origin reads through them. The churn hands out whatever was wrongly freed, and the
 * remount leaves no node cached to hide it. */
STM_TEST(fs_a_clones_rewrite_leaves_the_origins_nodes) {
    enum { FILES = 400, BYTES = 4096 };
    static uint8_t b[BYTES], out[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_nodes", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0, clone = 0;
    for (unsigned i = 0; i < FILES; i++) {
        lists_fill(b, sizeof b, (uint64_t)i + 1000u);
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap, &clone));
    STM_ASSERT_OK(stm_fs_commit(fs));
    memset(b, 0x5a, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, clone, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status last = STM_OK;
    for (unsigned round = 0; last == STM_OK && round < 400u; round++) {
        last = stm_fs_write(fs, clone, (uint64_t)(round % 8u) + 100u, 0, b, sizeof b);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    STM_ASSERT_OK(last);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    size_t bad = 0;
    for (unsigned i = 0; i < FILES; i++) {
        lists_fill(b, sizeof b, (uint64_t)i + 1000u);
        size_t n = 0;
        memset(out, 0xa5, sizeof out);
        stm_status rs = stm_fs_read(fs, 1, (uint64_t)i + 100u, 0, out, sizeof out, &n);
        if (rs != STM_OK || n != sizeof out || memcmp(b, out, sizeof out) != 0) bad++;
    }
    fprintf(stderr, "snaplist nodes: %zu of %u origin files unreadable\n", bad,
            (unsigned)FILES);
    STM_ASSERT_EQ(bad, (size_t)0);
    lists_done(fs);
}

/* Absent snapshots are not written out, so a delete re-points the next snapshot's
 * link past the deleted one: a link to an absent snapshot once failed every later
 * mount. */
STM_TEST(fs_a_pool_mounts_after_a_delete_with_a_newer_snapshot) {
    enum { BYTES = 64u * 1024u };
    static uint8_t a[BYTES], b[BYTES], c[BYTES], out[BYTES];
    lists_fill(a, sizeof a, 30u);
    lists_fill(b, sizeof b, 31u);
    lists_fill(c, sizeof c, 32u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_mount", TEST_DEVICE_BYTES, TEST_BOOTSTRAP_BYTES,
                             &mopts);
    if (!fs) return;
    uint64_t s1 = 0, s2 = 0, s3 = 0;
    size_t freed = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, a, sizeof a));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, c, sizeof c));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s3", 2, &s3));

    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s2, &freed));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    stm_status m = stm_fs_mount(g_tmp_path, &mopts, &fs);
    fprintf(stderr, "snaplist mount: after the middle delete %d (%s)\n", (int)m,
            stm_strerror(m));
    STM_ASSERT_OK(m);
    if (!fs) {
        lists_done(NULL);
        return;
    }
    stm_snapshot_entry e;
    memset(&e, 0, sizeof e);
    STM_ASSERT_OK(stm_snapshot_lookup(stm_sync_snapshot_index(stm_fs_sync_for_test(fs)),
                                      s3, &e));
    STM_ASSERT_EQ(e.prev_snap_id, s1);

    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s1, &freed));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    STM_ASSERT_OK(stm_snapshot_lookup(stm_sync_snapshot_index(stm_fs_sync_for_test(fs)),
                                      s3, &e));
    STM_ASSERT_EQ(e.prev_snap_id, STM_SNAP_NO_PREV);
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s3, false));
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(c, out, sizeof out);
    lists_done(fs);
}

/* Reads a file back twice, the second time past a remount, and takes the fs. */
static void lists_read_past_a_remount(stm_fs *fs, stm_fs_mount_opts *mopts, uint64_t f,
                                      uint64_t off, const uint8_t *want, size_t len)
{
    static uint8_t got[LISTS_MIB];
    for (int round = 0; fs && round < 2; round++) {
        memset(got, 0xa5, len);
        size_t have = 0;
        while (have < len) {
            size_t n = 0;
            stm_status rs = stm_fs_read(fs, 1, f, off + have, got + have, len - have, &n);
            STM_ASSERT_OK(rs);
            if (rs != STM_OK || n == 0) break;
            have += n;
        }
        STM_ASSERT_EQ(have, len);
        STM_ASSERT_MEM_EQ(want, got, len);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, mopts, &fs));
    }
    lists_done(fs);
}

/* A rollback with no commit since the overwrite: the drain drops the view's cold
 * record, which pays with a list entry, so the rollback may not count the record as
 * still held and spend the entry on the view's reference. */
STM_TEST(fs_a_rollback_with_no_commit_keeps_a_cold_view) {
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], n[BYTES];
    lists_fill(x, sizeof x, 33u);
    lists_fill(n, sizeof n, 34u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_nc", (uint64_t)64u * LISTS_MIB,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_cas_index *cas = stm_sync_cas_index(stm_fs_sync_for_test(fs));
    uint64_t root = 0, f = 0, snap = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, f));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t chunks = 0, now = 99u;
    STM_ASSERT_OK(stm_cas_count(cas, &chunks));
    STM_ASSERT_TRUE(chunks >= 1u);
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));

    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, n, sizeof n));
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &now));
    fprintf(stderr, "snaplist nc: chunks %zu -> %zu\n", chunks, now);
    STM_ASSERT_EQ(now, chunks);
    lists_read_past_a_remount(fs, &mopts, f, 0, x, sizeof x);
}

/* A cold record made after the snapshot shares the view's chunk. Its drop derefs at
 * once, so with no commit since, the rollback must not find it in the old tree and
 * deref it again: that reference is the view's. */
STM_TEST(fs_a_rollback_with_no_commit_keeps_what_a_new_cold_record_shares) {
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], n[BYTES];
    lists_fill(x, sizeof x, 35u);
    lists_fill(n, sizeof n, 36u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_nc2", (uint64_t)64u * LISTS_MIB,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    stm_cas_index *cas = stm_sync_cas_index(stm_fs_sync_for_test(fs));
    uint64_t root = 0, f = 0, g = 0, snap = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, f));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t chunks = 0, now = 99u;
    STM_ASSERT_OK(stm_cas_count(cas, &chunks));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));

    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"g", 1,
                                     0644u, 0, 0, &g));
    STM_ASSERT_OK(stm_fs_write(fs, 1, g, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, g));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &now));
    /* premise: g's record shares f's chunks */
    STM_ASSERT_EQ(now, chunks);
    STM_ASSERT_OK(stm_fs_write(fs, 1, g, 0, n, sizeof n));
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &now));
    fprintf(stderr, "snaplist nc2: chunks %zu -> %zu\n", chunks, now);
    STM_ASSERT_EQ(now, chunks);
    lists_read_past_a_remount(fs, &mopts, f, 0, x, sizeof x);
}

/* COLLAPSE and INSERT move a record's key and keep the record, and its reference. A
 * rollback that matched by key would take it for one made since and deref the view's
 * only reference. */
static void cold_record_moved(const char *name, uint64_t data_off, uint64_t move_off,
                              uint32_t flag)
{
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES];
    lists_fill(x, sizeof x, 37u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount(name, (uint64_t)64u * LISTS_MIB, TEST_BOOTSTRAP_BYTES,
                             &mopts);
    if (!fs) return;
    stm_cas_index *cas = stm_sync_cas_index(stm_fs_sync_for_test(fs));
    uint64_t root = 0, f = 0, snap = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"f", 1,
                                     0644u, 0, 0, &f));
    STM_ASSERT_OK(stm_fs_write(fs, 1, f, data_off, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_migrate_to_cold(fs, 1, f));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t chunks = 0, now = 99u;
    STM_ASSERT_OK(stm_cas_count(cas, &chunks));
    STM_ASSERT_TRUE(chunks >= 1u);
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_fallocate(fs, 1, f, move_off, 4096u, flag));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, snap, false));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_cas_count(cas, &now));
    fprintf(stderr, "%s: chunks %zu -> %zu\n", name, chunks, now);
    STM_ASSERT_EQ(now, chunks);
    lists_read_past_a_remount(fs, &mopts, f, data_off, x, sizeof x);
}

STM_TEST(fs_a_rollback_keeps_a_cold_record_an_insert_moved) {
    cold_record_moved("snaplist_insert", 0, 0, STM_FS_FALLOC_FL_INSERT_RANGE);
}

STM_TEST(fs_a_rollback_keeps_a_cold_record_a_collapse_moved) {
    cold_record_moved("snaplist_collapse", 4096u, 0, STM_FS_FALLOC_FL_COLLAPSE_RANGE);
}

/* A list entry stays allocated across a mount, in a view or not. A mount that sweeps one
 * reissues it to a live tree, and the snapshot's delete then frees it from under that
 * tree. With no delete every entry here is in the older view, whose walk marks it: only
 * the moved case tells that the list itself is marked. */
static void nodes_on_a_list(const char *name, bool moved_by_a_delete)
{
    enum { FILES = 400, BYTES = 4096 };
    static uint8_t b[BYTES], out[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount(name, (uint64_t)64u * LISTS_MIB, TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t older = 0, newer = 0;
    size_t on_list = 0, freed = 0;
    memset(b, 0x11, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &older));
    memset(b, 0x22, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    if (moved_by_a_delete)
        STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &newer));
    memset(b, 0x33, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    size_t before_delete = 0;
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, older, &before_delete));
    if (moved_by_a_delete) STM_ASSERT_OK(stm_fs_delete_snapshot(fs, newer, &freed));
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, older, &on_list));
    /* premise: the list holds nodes, and the delete moved some onto it */
    STM_ASSERT_TRUE(on_list >= 1u);
    if (moved_by_a_delete) STM_ASSERT_TRUE(on_list > before_delete);
    STM_ASSERT_OK(stm_fs_commit(fs));
    uint64_t *listed = NULL;
    size_t n_listed = 0;
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_get(sidx, older, &listed, &n_listed));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        free(listed);
        lists_done(NULL);
        return;
    }
    stm_bootstrap *boot = stm_alloc_bootstrap(stm_sync_alloc(stm_fs_sync_for_test(fs), 0));
    size_t gone = 0;
    for (size_t i = 0; i < n_listed; i++) {
        bool allocated = false;
        STM_ASSERT_OK(stm_bootstrap_is_allocated(boot, listed[i], &allocated));
        if (!allocated) gone++;
    }
    free(listed);
    fprintf(stderr, "%s: on_list=%zu, %zu swept\n", name, on_list, gone);
    STM_ASSERT_EQ(gone, (size_t)0);

    memset(b, 0x44, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, older, &freed));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status last = STM_OK;
    for (unsigned round = 0; last == STM_OK && round < 400u; round++) {
        last = stm_fs_write(fs, 1, (uint64_t)(round % 8u) + 100u, 0, b, sizeof b);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    STM_ASSERT_OK(last);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    size_t bad = 0;
    for (unsigned i = 0; i < FILES; i++) {
        size_t n = 0;
        memset(out, 0xa5, sizeof out);
        stm_status rs = stm_fs_read(fs, 1, (uint64_t)i + 100u, 0, out, sizeof out, &n);
        if (rs != STM_OK || n != sizeof out || memcmp(b, out, sizeof out) != 0) bad++;
    }
    fprintf(stderr, "%s: %zu of %u files unreadable\n", name, bad, (unsigned)FILES);
    STM_ASSERT_EQ(bad, (size_t)0);
    lists_done(fs);
}

STM_TEST(fs_a_mount_keeps_a_node_a_list_holds) {
    nodes_on_a_list("snaplist_mark", false);
}

STM_TEST(fs_a_mount_keeps_a_node_a_delete_moved_out_of_its_view) {
    nodes_on_a_list("snaplist_mark_moved", true);
}

/* A pool an older mount swept has entries naming a node gone free, or reissued to a live
 * tree. Either is nothing the snapshot may free: this mount lets go of them, and keeps
 * the entries that do hold a node. */
STM_TEST(fs_a_mount_lets_go_of_a_list_entry_an_older_mount_swept) {
    enum { FILES = 400, BYTES = 4096 };
    static uint8_t b[BYTES], out[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_stale", TEST_DEVICE_BYTES, TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0;
    size_t freed = 0, real = 0, after = 0;
    memset(b, 0x11, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    memset(b, 0x22, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    stm_bootstrap *boot = stm_alloc_bootstrap(stm_sync_alloc(sync, 0));

    /* A node gone free: swept by a later dirty commit, and it may be reissued, which is
     * stale all the same. */
    uint64_t free_node = 0;
    STM_ASSERT_OK(stm_bootstrap_reserve(boot, STM_BOOTSTRAP_NODE_BLOCKS, 0, &free_node));
    STM_ASSERT_OK(stm_bootstrap_free(boot, free_node, STM_BOOTSTRAP_NODE_BLOCKS,
                                     stm_sync_current_gen(sync)));
    STM_ASSERT_OK(stm_fs_commit(fs));
    for (unsigned i = 0; i < 2u; i++) {
        STM_ASSERT_OK(stm_fs_write(fs, 1, 99, 0, b, sizeof b));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, snap, &real));
    /* premise: real entries to keep, or a mount dropping the lot would pass */
    STM_ASSERT_TRUE(real >= 1u);

    /* A live tree's node: the root, born after the capture, so no view names it. */
    stm_dataset_entry de;
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(sync), 1, &de));
    uint64_t live_node = de.di_tree_root;
    bool should_free = false;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_bootstrap_block(sidx, 1, free_node, &should_free));
    STM_ASSERT_OK(stm_snapshot_index_overwrite_bootstrap_block(sidx, 1, live_node, &should_free));
    size_t planted = 0;
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, snap, &planted));
    STM_ASSERT_EQ(planted, real + 2u);
    STM_ASSERT_OK(stm_fs_commit(fs));
    /* premise: that commit wrote the index and left the tree, so the root is still live */
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(sync), 1, &de));
    STM_ASSERT_EQ(de.di_tree_root, live_node);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;

    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    sync = stm_fs_sync_for_test(fs);
    sidx = stm_sync_snapshot_index(sync);
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, snap, &after));
    fprintf(stderr, "snaplist stale: real=%zu planted=%zu after=%zu\n", real, planted, after);
    STM_ASSERT_EQ(after, real);

    /* The delete frees what is left, and the live tree still reads. */
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap, &freed));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status last = STM_OK;
    memset(b, 0x33, sizeof b);
    for (unsigned round = 0; last == STM_OK && round < 400u; round++) {
        last = stm_fs_write(fs, 1, (uint64_t)(round % 8u) + 100u, 0, b, sizeof b);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    STM_ASSERT_OK(last);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    memset(b, 0x22, sizeof b);
    size_t bad = 0;
    for (unsigned i = 8; i < FILES; i++) {
        size_t n = 0;
        memset(out, 0xa5, sizeof out);
        stm_status rs = stm_fs_read(fs, 1, (uint64_t)i + 100u, 0, out, sizeof out, &n);
        if (rs != STM_OK || n != sizeof out || memcmp(b, out, sizeof out) != 0) bad++;
    }
    STM_ASSERT_EQ(bad, (size_t)0);
    lists_done(fs);
}

/* A clone's live tree reaches what its snapshot names: a list entry in that view is not
 * stale for being live, and stays across a mount. */
STM_TEST(fs_a_mount_keeps_a_list_entry_a_clone_reaches_through_the_view) {
    enum { FILES = 400, BYTES = 4096 };
    static uint8_t b[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_stale_clone", TEST_DEVICE_BYTES, TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t snap = 0, clone = 0;
    size_t before = 0, after = 0;
    memset(b, 0x11, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap));
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap, &clone));
    memset(b, 0x22, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, snap, &before));
    STM_ASSERT_TRUE(before >= 1u);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    sidx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, snap, &after));
    fprintf(stderr, "snaplist stale clone: before=%zu after=%zu\n", before, after);
    STM_ASSERT_EQ(after, before);
    lists_done(fs);
}

/* A view naming a free block is one no rollback can bring back. It refuses before the
 * drain, a true no-op, and a rollback to an undamaged older snapshot still works. */
STM_TEST(fs_a_rollback_refuses_a_view_naming_a_free_block) {
    enum { BYTES = 64u * 1024u };
    static uint8_t x[BYTES], z[BYTES], y[BYTES], out[BYTES];
    lists_fill(x, sizeof x, 45u);
    lists_fill(z, sizeof z, 46u);
    lists_fill(y, sizeof y, 47u);
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_rb_free", TEST_DEVICE_BYTES,
                             TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    /* The inode allocator starts at 1 and knows nothing of a raw ino, so the file below
     * would land on a low one, and writing it back would free the block freed here again. */
    enum { RAW_X = 101, RAW_Z = 102 };
    uint64_t s1 = 0, s2 = 0;
    STM_ASSERT_OK(stm_fs_write(fs, 1, RAW_X, 0, x, sizeof x));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, RAW_Z, 0, z, sizeof z));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));

    stm_sync *sync = stm_fs_sync_for_test(fs);
    lists_record_query q = { RAW_Z, 0, 0 };
    STM_ASSERT_OK(stm_extent_iter_ds(stm_sync_extent_index(sync), 1, lists_record_cb, &q));
    STM_ASSERT_TRUE(q.paddr != 0);
    stm_alloc *a = stm_sync_alloc(sync, stm_paddr_device(q.paddr));
    STM_ASSERT_OK(stm_alloc_free(a, q.paddr, stm_sync_current_gen(sync)));

    /* a dirty buffer the refusal must not touch, and no commit: a drain or a commit
     * before the refusal would read back the same. A raw ino writes straight through, so
     * this is a file. */
    uint64_t root = 0, yf = 0;
    lists_root(fs, &root);
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, root, (const uint8_t *)"y", 1, 0644u, 0, 0, &yf));
    STM_ASSERT_TRUE(root != RAW_X && root != RAW_Z && yf != RAW_X && yf != RAW_Z);
    STM_ASSERT_OK(stm_fs_write(fs, 1, yf, 0, y, sizeof y));
    stm_fs_stats before, refused;
    STM_ASSERT_OK(stm_fs_stats_get(fs, &before));
    uint64_t gen = stm_sync_current_gen(sync);
    STM_ASSERT_TRUE(before.data_dirty_reserved_blocks != 0u);
    STM_ASSERT_ERR(stm_fs_rollback_snapshot(fs, 1, s2, false), STM_ECORRUPT);
    STM_ASSERT_OK(stm_fs_stats_get(fs, &refused));
    STM_ASSERT_EQ(refused.data_dirty_reserved_blocks, before.data_dirty_reserved_blocks);
    STM_ASSERT_EQ(stm_sync_current_gen(sync), gen);
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, yf, out, sizeof out);
    STM_ASSERT_MEM_EQ(y, out, sizeof out);
    STM_ASSERT_OK(stm_fs_commit(fs));

    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s1, false));
    memset(out, 0xa5, sizeof out);
    lists_read(fs, 1, RAW_X, out, sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof out);
    lists_done(fs);
}

/* An older mount swept a node off a list, a live tree got it back, and a newer snapshot
 * captured it. The entry holds nothing, and it goes; freed by its delete, the node would
 * go from under that view and that tree. */
STM_TEST(fs_a_mount_lets_go_of_a_list_entry_a_newer_view_captured) {
    enum { FILES = 400, BYTES = 4096 };
    static uint8_t b[BYTES], out[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_newer", (uint64_t)64u * LISTS_MIB, TEST_BOOTSTRAP_BYTES,
                             &mopts);
    if (!fs) return;
    uint64_t s1 = 0, s2 = 0;
    size_t freed = 0, real = 0, planted = 0, after = 0;
    memset(b, 0x11, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    memset(b, 0x22, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, s1, &real));
    /* premise: real entries to keep, or a mount dropping the lot would pass */
    STM_ASSERT_TRUE(real >= 1u);
    stm_dataset_entry de;
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(sync), 1, &de));
    bool should_free = false;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_bootstrap_block(sidx, 1, de.di_tree_root,
                                                               &should_free));
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, s1, &planted));
    STM_ASSERT_EQ(planted, real + 1u);
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    /* premise: the newer view names the node the entry does */
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s2, &e));
    STM_ASSERT_EQ(e.tree_root_paddr, de.di_tree_root);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;

    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    sidx = stm_sync_snapshot_index(stm_fs_sync_for_test(fs));
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_count(sidx, s1, &after));
    fprintf(stderr, "snaplist newer: real=%zu after=%zu\n", real, after);
    STM_ASSERT_EQ(after, real);

    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s1, &freed));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_status last = STM_OK;
    memset(b, 0x33, sizeof b);
    for (unsigned round = 0; last == STM_OK && round < 400u; round++) {
        last = stm_fs_write(fs, 1, (uint64_t)(round % 8u) + 100u, 0, b, sizeof b);
        if (last == STM_OK) last = stm_fs_commit(fs);
    }
    STM_ASSERT_OK(last);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s2, false));
    memset(b, 0x22, sizeof b);
    size_t bad = 0;
    for (unsigned i = 0; i < FILES; i++) {
        size_t n = 0;
        memset(out, 0xa5, sizeof out);
        stm_status rs = stm_fs_read(fs, 1, (uint64_t)i + 100u, 0, out, sizeof out, &n);
        if (rs != STM_OK || n != sizeof out || memcmp(b, out, sizeof out) != 0) bad++;
    }
    fprintf(stderr, "snaplist newer: %zu of %u unreadable in the view\n", bad, (unsigned)FILES);
    STM_ASSERT_EQ(bad, (size_t)0);
    lists_done(fs);
}

/* A tree of its own that nothing here writes again: its root stands in for a node reissued
 * to something else. */
static uint64_t lists_other_tree_root(stm_fs *fs, const char *name, const uint8_t *b, size_t n,
                                      uint64_t *out_ds)
{
    uint64_t ds = 0;
    stm_dataset_entry de;
    memset(&de, 0, sizeof de);
    STM_ASSERT_OK(stm_fs_create_dataset(fs, 1u, name, &ds));
    STM_ASSERT_OK(stm_fs_write(fs, ds, 1, 0, b, n));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(stm_fs_sync_for_test(fs)), ds, &de));
    STM_ASSERT_TRUE(de.di_tree_root != 0);
    *out_ds = ds;
    return de.di_tree_root;
}

/* lists_unchecked's other half, one variable away: on a mount that finished, what a snapshot
 * lets go of comes back. Nothing else tells "frees nothing on an unchecked mount" from "frees
 * nothing". */
enum lists_letgo { LETGO_DELETE, LETGO_CASCADE, LETGO_MOVED };

static void lists_checked_frees(const char *name, enum lists_letgo how)
{
    enum { FILES = 400, BYTES = 4096 };
    static uint8_t b[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount(name, (uint64_t)64u * LISTS_MIB, TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t s1 = 0, s2 = 0;
    size_t freed = 0;
    memset(b, 0x11, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    memset(b, 0x22, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    if (how != LETGO_DELETE)
        STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    memset(b, 0x33, sizeof b);
    for (unsigned i = 0; i < FILES; i++)
        STM_ASSERT_OK(stm_fs_write(fs, 1, (uint64_t)i + 100u, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    if (how == LETGO_MOVED) {
        STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s2, &freed));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    stm_bootstrap *boot = stm_alloc_bootstrap(stm_sync_alloc(sync, 0));
    stm_bootstrap_stats bs;
    STM_ASSERT_OK(stm_bootstrap_stats_get(boot, &bs));
    /* premises: the pass finished, and on a healthy pool it has nothing to take back */
    STM_ASSERT_TRUE(!stm_snapshot_index_boot_lists_unverified(sidx));
    STM_ASSERT_EQ(bs.restored_nodes, 0u);
    uint64_t *listed = NULL;
    size_t n_listed = 0;
    STM_ASSERT_OK(stm_snapshot_bootstrap_dead_list_get(sidx, how == LETGO_CASCADE ? s2 : s1,
                                                       &listed, &n_listed));
    STM_ASSERT_TRUE(n_listed >= 1u);
    if (how == LETGO_DELETE) {
        STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s1, &freed));
    } else {
        STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s1, false));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    size_t gone = 0;
    for (size_t i = 0; i < n_listed; i++) {
        bool allocated = false;
        STM_ASSERT_OK(stm_bootstrap_is_allocated(boot, listed[i], &allocated));
        if (!allocated) gone++;
    }
    free(listed);
    fprintf(stderr, "%s: listed=%zu gone=%zu\n", name, n_listed, gone);
    STM_ASSERT_TRUE(gone >= 1u);
    lists_done(fs);
}

STM_TEST(fs_a_delete_frees_a_node_off_a_list_a_mount_checked) {
    lists_checked_frees("snaplist_chk_del", LETGO_DELETE);
}

STM_TEST(fs_a_rollback_frees_a_node_only_a_newer_snapshot_held) {
    lists_checked_frees("snaplist_chk_cascade", LETGO_CASCADE);
}

STM_TEST(fs_a_rollback_frees_a_node_a_delete_moved_onto_its_list) {
    lists_checked_frees("snaplist_chk_moved", LETGO_MOVED);
}

/* What an older mount's sweep and an older delete could leave: a tree on a free node, whole
 * until the allocator comes round to it. A mount takes it back. */
STM_TEST(fs_a_mount_takes_back_a_free_node_a_tree_names) {
    enum { BYTES = 4096 };
    static uint8_t b[BYTES], out[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount("snaplist_restore", TEST_DEVICE_BYTES, TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    uint64_t ds = 0;
    memset(b, 0x44, sizeof b);
    uint64_t root = lists_other_tree_root(fs, "ta", b, sizeof b, &ds);
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_bootstrap *boot = stm_alloc_bootstrap(stm_sync_alloc(sync, 0));
    STM_ASSERT_OK(stm_bootstrap_free(boot, root, STM_BOOTSTRAP_NODE_BLOCKS,
                                     stm_sync_current_gen(sync)));
    /* A deferred free lands past its generation, and only with commits that do work. */
    memset(out, 0x55, sizeof out);
    for (unsigned round = 0; round < 3u; round++) {
        STM_ASSERT_OK(stm_fs_write(fs, 1, 99, 0, out, sizeof out));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    bool held = true;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(boot, root, &held));
    /* premise: the tree stands on a free node */
    STM_ASSERT_TRUE(!held);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    sync = stm_fs_sync_for_test(fs);
    boot = stm_alloc_bootstrap(stm_sync_alloc(sync, 0));
    stm_bootstrap_stats bs;
    STM_ASSERT_OK(stm_bootstrap_stats_get(boot, &bs));
    STM_ASSERT_EQ(bs.restored_nodes, 1u);
    STM_ASSERT_OK(stm_bootstrap_is_allocated(boot, root, &held));
    STM_ASSERT_TRUE(held);
    memset(out, 0x55, sizeof out);
    for (unsigned round = 0; round < 64u; round++) {
        STM_ASSERT_OK(stm_fs_write(fs, 1, 99, 0, out, sizeof out));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    memset(out, 0xa5, sizeof out);
    lists_read(fs, ds, 1, out, sizeof out);
    STM_ASSERT_MEM_EQ(b, out, sizeof out);
    lists_done(fs);
}

/* A mount that cannot read a view cannot tell a stale entry from a real one, and deleting a
 * snapshot is what one does with a damaged pool. Nothing frees a node off a list then. */
static void lists_unchecked(const char *name, bool rollback)
{
    enum { BYTES = 4096 };
    static const uint8_t junk[BYTES] = { 0x5a };
    static uint8_t b[BYTES], first[BYTES], out[BYTES];
    stm_fs_mount_opts mopts;
    stm_fs *fs = lists_mount(name, TEST_DEVICE_BYTES, TEST_BOOTSTRAP_BYTES, &mopts);
    if (!fs) return;
    memset(b, 0x11, sizeof b);
    memcpy(first, b, sizeof first);
    uint64_t s1 = 0, s2 = 0, ds_a = 0, ds_b = 0;
    uint64_t on_s1 = lists_other_tree_root(fs, "ta", b, sizeof b, &ds_a);
    uint64_t on_s2 = lists_other_tree_root(fs, "tb", b, sizeof b, &ds_b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 100, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    stm_sync *sync = stm_fs_sync_for_test(fs);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    bool should_free = false;
    STM_ASSERT_OK(stm_snapshot_index_overwrite_bootstrap_block(sidx, 1, on_s1, &should_free));
    memset(b, 0x22, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 100, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s2, &e));
    STM_ASSERT_OK(stm_snapshot_index_overwrite_bootstrap_block(sidx, 1, on_s2, &should_free));
    memset(b, 0x33, sizeof b);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 100, 0, b, sizeof b));
    STM_ASSERT_OK(stm_fs_commit(fs));
    stm_dataset_entry de;
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(sync), 1, &de));
    /* premise: only the view stands on the node about to be damaged */
    STM_ASSERT_TRUE(e.tree_root_paddr != 0 && de.di_tree_root != e.tree_root_paddr);
    /* premise: the planted entries still root their trees, or the read below says nothing */
    stm_dataset_entry planted;
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(sync), ds_a, &planted));
    STM_ASSERT_EQ(planted.di_tree_root, on_s1);
    STM_ASSERT_OK(stm_dataset_lookup(stm_sync_dataset_index(sync), ds_b, &planted));
    STM_ASSERT_EQ(planted.di_tree_root, on_s2);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;

    int fd = open(g_tmp_path, O_WRONLY);
    STM_ASSERT_TRUE(fd >= 0);
    if (fd >= 0) {
        ssize_t wrote = pwrite(fd, junk, sizeof junk,
                               (off_t)(stm_paddr_offset(e.tree_root_paddr) * 4096u));
        STM_ASSERT_TRUE(wrote == (ssize_t)sizeof junk);
        close(fd);
    }
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    sync = stm_fs_sync_for_test(fs);
    sidx = stm_sync_snapshot_index(sync);
    /* premise: the pass did not finish */
    STM_ASSERT_TRUE(stm_snapshot_index_boot_lists_unverified(sidx));
    size_t freed = 0;
    if (rollback) {
        STM_ASSERT_OK(stm_fs_rollback_snapshot(fs, 1, s1, false));
    } else {
        STM_ASSERT_OK(stm_fs_delete_snapshot(fs, s1, &freed));
    }
    for (unsigned round = 0; round < 64u; round++) {
        STM_ASSERT_OK(stm_fs_write(fs, 1, 99, 0, b, sizeof b));
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    stm_bootstrap *boot = stm_alloc_bootstrap(stm_sync_alloc(sync, 0));
    bool held_s1 = false, held_s2 = false;
    STM_ASSERT_OK(stm_bootstrap_is_allocated(boot, on_s1, &held_s1));
    STM_ASSERT_OK(stm_bootstrap_is_allocated(boot, on_s2, &held_s2));
    STM_ASSERT_TRUE(held_s1);
    STM_ASSERT_TRUE(held_s2);
    /* A bit proves little: a freed node reissued has it set again. Its tree's read from a
     * fresh mount cannot be satisfied by that. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) {
        lists_done(NULL);
        return;
    }
    uint64_t trees[2] = { ds_a, ds_b };
    size_t bad = 0;
    for (unsigned i = 0; i < 2u; i++) {
        size_t n = 0;
        memset(out, 0xa5, sizeof out);
        stm_status rs = stm_fs_read(fs, trees[i], 1, 0, out, sizeof out, &n);
        if (rs != STM_OK || n != sizeof out || memcmp(first, out, sizeof out) != 0) bad++;
    }
    fprintf(stderr, "%s: %zu of 2 trees unreadable\n", name, bad);
    STM_ASSERT_EQ(bad, (size_t)0);
    lists_done(fs);
}

STM_TEST(fs_a_delete_frees_no_node_off_a_list_no_mount_could_check) {
    lists_unchecked("snaplist_unchk_del", false);
}

STM_TEST(fs_a_rollback_frees_no_node_off_a_list_no_mount_could_check) {
    lists_unchecked("snaplist_unchk_rb", true);
}

STM_TEST_MAIN("fs_snapshot_lists")
