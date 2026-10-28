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

/* A 24 MiB pool with files x, y and z (z if out_z). With `run` blocks, its
 * free space is all (run + 1)-block holes but for the slop: x holds an
 * extent of `run` blocks of data (run + 1 with its tag) at every 2 * run
 * blocks until the pool is full, and every second one is punched. */
static stm_fs *gap_pool(const char *name, uint64_t run, uint64_t *out_x,
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
    if (run == 0u) return fs;
    const uint64_t L = run * K;
    uint8_t *b = malloc((size_t)L);
    memset(b, 0x5A, (size_t)L);
    uint64_t n = 0;
    bool refused = false;
    for (;;) {
        stm_status ws = stm_fs_write(fs, 1, *out_x, n * 2u * L, b, (size_t)L);
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
    free(b);
    STM_ASSERT_OK(stm_fs_commit(fs));
    for (uint64_t i = 1; i < n; i += 2u)
        STM_ASSERT_OK(stm_fs_fallocate(fs, 1, *out_x, i * 2u * L, L,
                                       STM_FS_FALLOC_FL_PUNCH_HOLE |
                                       STM_FS_FALLOC_FL_KEEP_SIZE));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_OK(stm_fs_commit(fs));
    return fs;
}

/* gap_pool with 2-block holes (with `fill`) or none. */
static stm_fs *frag_pool(const char *name, bool fill, uint64_t *out_x,
                         uint64_t *out_y, uint64_t *out_z)
{
    return gap_pool(name, fill ? 1u : 0u, out_x, out_y, out_z);
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

/* Bytes of [off, off + L) that do not read back as frag_pat from `seed`
 * (a read may stop at a record). */
static size_t range_bad(stm_fs *fs, uint64_t y, uint64_t off, uint64_t L,
                        uint64_t seed)
{
    uint8_t *b = malloc((size_t)L);
    size_t got = 0, bad = 0;
    while (got < L) {
        size_t n = 0;
        if (stm_fs_read(fs, 1, y, off + got, b + got, (size_t)L - got, &n)
                != STM_OK || n == 0)
            break;
        got += n;
    }
    bad += (size_t)L - got;
    for (size_t i = 0; i < got; i++) bad += b[i] != frag_pat(seed + i);
    free(b);
    return bad;
}

/* Bytes of nk writes of L that do not read back: write k at k * 2 MiB,
 * frag_pat from k MiB. */
static size_t acked_bad(stm_fs *fs, uint64_t y, uint64_t nk, uint64_t L)
{
    const uint64_t MIB = 1024u * 1024u;
    size_t bad = 0;
    for (uint64_t k = 0; k < nk; k++)
        bad += range_bad(fs, y, k * 2u * MIB, L, k * MIB);
    return bad;
}

/* Every buffered write the pool acknowledges commits, however its free
 * space lies. On a pool whose free runs are all 2 blocks, a write of just
 * under the direct threshold drains at 2 blocks per block of data, each
 * piece with its own tag; it is charged that, so the pool refuses a write
 * it could not drain rather than losing it at the commit. */
STM_TEST(fs_every_acknowledged_buffered_write_commits) {
    const uint64_t K = 4096u, MIB = 1024u * 1024u, L = MIB - 4u * K;
    uint64_t x = 0, y = 0;
    stm_fs *fs = frag_pool("frag_acked", true, &x, &y, NULL);
    if (!fs) return;
    stm_alloc *a = stm_sync_alloc(stm_fs_sync(fs), 0);
    uint64_t pa = 0;
    STM_ASSERT_ERR(stm_alloc_reserve(a, L / K + 1u, 0, &pa), STM_ENOSPC);
    uint8_t *b = malloc((size_t)L);
    uint64_t nk = 0;
    STM_ASSERT_EQ(stm_alloc_pending_blocks(a), (uint64_t)0);
    for (uint64_t k = 0; k < 8u; k++) {
        for (uint64_t i = 0; i < L; i++) b[i] = frag_pat(k * MIB + i);
        stm_status ws = stm_fs_write(fs, 1, y, k * 2u * MIB, b, (size_t)L);
        /* a refusal leaves nothing behind, not even PENDING */
        STM_ASSERT_EQ(stm_alloc_pending_blocks(a), (uint64_t)0);
        if (ws == STM_ENOSPC) break;
        STM_ASSERT_OK(ws);
        if (ws != STM_OK) break;
        nk++;
    }
    free(b);
    STM_ASSERT_TRUE(nk >= 2u);
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_EQ(acked_bad(fs, y, nk, L), (size_t)0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    stm_fs_mount_opts mopts = rw_mount_opts();
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(acked_bad(fs, y, nk, L), (size_t)0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

/* A piece takes a whole free run, so a write spends at most 2 blocks per
 * block of data, plus 1: what its buffered form is charged. On a pool of
 * 3-block holes, D blocks of data go in pieces of 2 and take 3D/2. Pieces
 * cut by halving instead reach 1 block of data, which takes a whole
 * 3-block hole: 3 per block. */
STM_TEST(fs_a_write_in_pieces_spends_at_most_twice_its_blocks_and_one) {
    const uint64_t K = 4096u, D = 200u;
    uint64_t x = 0, y = 0;
    stm_fs *fs = gap_pool("frag_runs", 2u, &x, &y, NULL);
    if (!fs) return;
    stm_sync *sync = stm_fs_sync(fs);
    stm_alloc *a = stm_sync_alloc(sync, 0);
    STM_ASSERT_TRUE(stm_alloc_avail_blocks(a) >= 3u * D);
    uint8_t *b = malloc((size_t)(D * K));
    for (uint64_t i = 0; i < D * K; i++) b[i] = frag_pat(i);
    const uint64_t free0 = stm_alloc_data_free_blocks(a);
    STM_ASSERT_OK(stm_sync_write_extent(sync, 1, y, 0, b, (size_t)(D * K)));
    const uint64_t spent = free0 - stm_alloc_data_free_blocks(a);
    STM_ASSERT_TRUE(spent <= 2u * D + 1u);
    size_t n_rec = 0;
    STM_ASSERT_OK(stm_extent_count_for_ino(stm_sync_extent_index(sync), 1, y,
                                           &n_rec));
    STM_ASSERT_TRUE(n_rec > 1u);
    size_t got = 0, bad = 0;
    while (got < D * K) {
        size_t n = 0;
        STM_ASSERT_OK(stm_sync_read_extent(sync, 1, y, got, b + got,
                                           (size_t)(D * K) - got, &n));
        if (n == 0) break;
        got += n;
    }
    STM_ASSERT_EQ(got, (size_t)(D * K));
    for (size_t i = 0; i < got; i++) bad += b[i] != frag_pat(i);
    STM_ASSERT_EQ(bad, (size_t)0);
    free(b);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

/* A buffered write is charged 2 blocks for every block its drain writes,
 * and a block for each record: a 4 KiB write into a hole 3, one inside a
 * 64-block extent, which its drain rewrites whole, 2 for each block of
 * that extent, 1 for its own record and 2 for the extent's. */
STM_TEST(fs_a_buffered_write_is_charged_its_worst_case) {
    const uint64_t K = 4096u;
    uint64_t x = 0, y = 0;
    stm_fs *fs = frag_pool("frag_charge", false, &x, &y, NULL);
    if (!fs) return;
    stm_alloc *a = stm_sync_alloc(stm_fs_sync(fs), 0);
    uint8_t *b = calloc(64u, (size_t)K);
    STM_ASSERT_OK(stm_fs_write(fs, 1, y, 0, b, (size_t)(64u * K)));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_EQ(stm_alloc_dirty_reserved(a), (uint64_t)0);
    STM_ASSERT_OK(stm_fs_write(fs, 1, y, 1024u * K, b, (size_t)K));
    STM_ASSERT_EQ(stm_alloc_dirty_reserved(a), (uint64_t)3);
    STM_ASSERT_OK(stm_fs_write(fs, 1, y, 10u * K, b, (size_t)K));
    STM_ASSERT_EQ(stm_alloc_dirty_reserved(a),
                  (uint64_t)(3u + 2u * 64u + 1u + 2u));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_EQ(stm_alloc_dirty_reserved(a), (uint64_t)0);
    free(b);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

/* A write the charge refuses, on a pool that still holds what it takes,
 * is written direct: 252 blocks of data are charged 505, and take 253
 * of the 400 the pool has. */
STM_TEST(fs_a_write_its_charge_refuses_is_written_direct) {
    const uint64_t K = 4096u, MIB = 1024u * 1024u, L = MIB - 4u * K;
    uint64_t x = 0, y = 0;
    stm_fs *fs = frag_pool("frag_direct", false, &x, &y, NULL);
    if (!fs) return;
    stm_alloc *a = stm_sync_alloc(stm_fs_sync(fs), 0);
    uint8_t *b = malloc((size_t)L);
    memset(b, 0, (size_t)K);
    STM_ASSERT_OK(stm_fs_write(fs, 1, y, 0, b, (size_t)K));
    STM_ASSERT_OK(stm_fs_commit(fs));
    const uint64_t avail = stm_alloc_avail_blocks(a);
    uint64_t pa = 0;
    STM_ASSERT_TRUE(avail > 1000u);
    STM_ASSERT_OK(stm_alloc_reserve(a, avail - 400u, 0, &pa));
    STM_ASSERT_EQ(stm_alloc_avail_blocks(a), (uint64_t)400);
    for (uint64_t i = 0; i < L; i++) b[i] = frag_pat(MIB + i);
    STM_ASSERT_OK(stm_fs_write(fs, 1, y, 2u * MIB, b, (size_t)L));
    STM_ASSERT_OK(stm_fs_commit(fs));
    STM_ASSERT_TRUE(stm_alloc_avail_blocks(a) + 253u <= 400u);
    free(b);
    STM_ASSERT_EQ(range_bad(fs, y, 2u * MIB, L, MIB), (size_t)0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    stm_fs_mount_opts mopts = rw_mount_opts();
    fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    if (!fs) return;
    STM_ASSERT_EQ(range_bad(fs, y, 2u * MIB, L, MIB), (size_t)0);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path); unlink(g_key_path);
}

STM_TEST_MAIN("fs_frag")
