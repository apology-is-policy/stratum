/* SPDX-License-Identifier: ISC */
/*
 * fs tests on a fragmented pool: a write no free run holds goes in
 * pieces. Their fixture fills and punches a whole pool, so they run in a
 * binary of their own.
 */

#include "tharness.h"
#include "test_fs_common.h"

#include <sys/stat.h>

#include <stratum/alloc.h>
#include <stratum/extent.h>
#include <stratum/fs.h>
#include <stratum/inode.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Bytes that differ from block to block and within one. */
static uint8_t frag_pat(uint64_t i)
{
    uint32_t v = (uint32_t)i * 2654435761u + 0x9e3779b9u;
    v ^= v >> 15;
    v *= 2246822519u;
    v ^= v >> 13;
    return (uint8_t)(v >> 24);
}

/* A 24 MiB pool with files x, y and z (z if out_z). With `fill`, its free
 * space is all 2-block holes but for the slop: x holds a 4 KiB extent (2
 * blocks with its tag) at every 8 KiB until the pool is full, and every
 * second one is punched. */
static stm_fs *frag_pool(const char *name, bool fill, uint64_t *out_x,
                         uint64_t *out_y, uint64_t *out_z)
{
    const uint64_t K = 4096u, MIB = 1024u * 1024u;
    make_tmp(name);
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes = 24u * MIB;
    fopts.bootstrap_size_bytes = 8u * MIB;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return NULL;
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u, 0, 0,
                                  &dir));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"x", 1,
                                     0644u, 0, 0, out_x));
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"y", 1,
                                     0644u, 0, 0, out_y));
    if (out_z)
        STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"z", 1,
                                         0644u, 0, 0, out_z));
    if (!fill) return fs;
    uint8_t b[4096];
    memset(b, 0x5A, sizeof b);
    uint64_t n = 0;
    bool refused = false;
    for (;;) {
        stm_status ws = stm_fs_write(fs, 1, *out_x, n * 2u * K, b, sizeof b);
        if (ws == STM_OK) {
            refused = false;
            if (++n % 256u == 0u) STM_ASSERT_OK(stm_fs_commit(fs));
            continue;
        }
        STM_ASSERT_ERR(ws, STM_ENOSPC);
        if (refused) break;
        refused = true;
        STM_ASSERT_OK(stm_fs_commit(fs));
    }
    STM_ASSERT_OK(stm_fs_commit(fs));
    for (uint64_t i = 1; i < n; i += 2u)
        STM_ASSERT_OK(stm_fs_fallocate(fs, 1, *out_x, i * 2u * K, K,
                                       STM_FS_FALLOC_FL_PUNCH_HOLE |
                                       STM_FS_FALLOC_FL_KEEP_SIZE));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    return fs;
}

/* The file's first MiB reads back as frag_pat (a read may stop at a
 * record). */
static void frag_check(stm_fs *fs, uint64_t y)
{
    const uint64_t MIB = 1024u * 1024u;
    uint8_t *b = malloc((size_t)MIB);
    size_t got = 0, bad = 0;
    while (got < MIB) {
        size_t n = 0;
        STM_ASSERT_OK(stm_fs_read(fs, 1, y, got, b + got, (size_t)MIB - got,
                                  &n));
        if (n == 0) break;
        got += n;
    }
    STM_ASSERT_EQ(got, (size_t)MIB);
    for (size_t i = 0; i < got; i++) bad += b[i] != frag_pat(i);
    STM_ASSERT_EQ(bad, (size_t)0);
    free(b);
}

/* On a pool with the blocks free but no run long enough for a MiB (257
 * blocks with its tag), a MiB written direct (y) and a MiB of acknowledged
 * buffered 4 KiB writes, which drain as one covering write (z), both go in
 * pieces: the commit succeeds, each file holds several records, and both
 * read back before and after a remount. On a pool with room each is one
 * record. */
STM_TEST(fs_a_write_no_free_run_holds_is_written_in_pieces) {
    const uint64_t K = 4096u, MIB = 1024u * 1024u;
    uint8_t *b = malloc((size_t)MIB);
    for (uint64_t i = 0; i < MIB; i++) b[i] = frag_pat(i);
    for (int frag = 0; frag < 2; frag++) {
        uint64_t x = 0, f[2] = { 0, 0 };
        stm_fs *fs = frag_pool(frag ? "frag_pieces" : "frag_control",
                               frag != 0, &x, &f[0], &f[1]);
        if (!fs) break;
        stm_sync *sync = stm_fs_sync(fs);
        if (frag) {
            /* The premise: the blocks are free, a 257-block run is not. */
            stm_alloc *a = stm_sync_alloc(sync, 0);
            STM_ASSERT_TRUE(stm_alloc_data_free_blocks(a) >= 3u * 257u);
            uint64_t pa = 0;
            STM_ASSERT_ERR(stm_alloc_reserve(a, 257u, 0, &pa), STM_ENOSPC);
        }
        STM_ASSERT_OK(stm_fs_write(fs, 1, f[0], 0, b, (size_t)MIB));
        for (uint64_t off = 0; off < MIB; off += K)
            STM_ASSERT_OK(stm_fs_write(fs, 1, f[1], off, b + off, (size_t)K));
        STM_ASSERT_OK(stm_fs_commit(fs));
        for (int k = 0; k < 2; k++) {
            size_t n_rec = 0;
            STM_ASSERT_OK(stm_extent_count_for_ino(stm_sync_extent_index(sync),
                                                   1, f[k], &n_rec));
            if (frag) STM_ASSERT_TRUE(n_rec > 1u);
            else      STM_ASSERT_EQ(n_rec, (size_t)1);
            frag_check(fs, f[k]);
        }
        STM_ASSERT_OK(stm_fs_unmount(fs));
        stm_fs_mount_opts mopts = rw_mount_opts();
        fs = NULL;
        STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
        if (!fs) break;
        frag_check(fs, f[0]);
        frag_check(fs, f[1]);
        STM_ASSERT_OK(stm_fs_unmount(fs));
        unlink(g_tmp_path); unlink(g_key_path);
    }
    free(b);
}

/* A write the room cannot hold even in one piece is refused at once: its
 * pieces would need more, and reserving them would leave their blocks
 * PENDING until the next commit. The control: a write the room holds but
 * no free run does goes in pieces. */
STM_TEST(fs_a_write_refused_for_room_takes_no_piece) {
    const uint64_t K = 4096u;
    uint64_t x = 0, y = 0;
    stm_fs *fs = frag_pool("frag_room", true, &x, &y, NULL);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync(fs);
    stm_alloc *a = stm_sync_alloc(sync, 0);
    const uint64_t room = stm_alloc_avail_blocks(a), q = room / 4u;
    STM_ASSERT_TRUE(room >= 8u);
    STM_ASSERT_TRUE(room * K <= STM_FS_RECORDSIZE_MAX);
    uint64_t pa = 0;
    STM_ASSERT_ERR(stm_alloc_reserve(a, q + 1u, 0, &pa), STM_ENOSPC);
    uint8_t *b = calloc((size_t)room, (size_t)K);
    const uint64_t free0 = stm_alloc_data_free_blocks(a);
    const uint64_t pend0 = stm_alloc_pending_blocks(a);
    /* room blocks of data take room + 1 with the tag */
    STM_ASSERT_ERR(stm_sync_write_extent(sync, 1, y, 0, b, (size_t)(room * K)),
                   STM_ENOSPC);
    STM_ASSERT_EQ(stm_alloc_data_free_blocks(a), free0);
    STM_ASSERT_EQ(stm_alloc_pending_blocks(a), pend0);
    STM_ASSERT_OK(stm_sync_write_extent(sync, 1, y, 0, b, (size_t)(q * K)));
    size_t n_rec = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(stm_sync_extent_index(sync), 1, y,
                                           &n_rec));
    STM_ASSERT_TRUE(n_rec > 1u);
    free(b);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST_MAIN("fs_frag")
