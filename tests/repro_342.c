/* SPDX-License-Identifier: ISC */
/*
 * repro_342 — host-side replay of the Thylacine #342 on-disk zeros corruption.
 *
 * In-guest ground truth (dev9p crc trace + linker parse trace + forensic hex,
 * 2026-07-03): cmd/go's b001/_pkg_.a is written by the traced sequence below;
 * after the two 41-byte updateBuildID in-place stamps, the region starting at
 * file offset 3176 (the byte after the last backfill write's end, and the
 * start of the 186-byte write extent [3176,3362)) reads back as ZEROS on
 * every subsequent read, durably. The stamp at 3306 lands INSIDE that extent.
 *
 * This replays the exact (off,len) write sequence against libstm_fs with a
 * byte-exact shadow buffer and reports every divergent run on read-back.
 * Not a ctest — a hunt tool; the confirmed mechanism lands as a proper
 * regression test with the fix.
 */
#include "test_fs_common.h"
#include "tharness.h"

#include <sys/stat.h>
#include <stratum/fs.h>
#include <stratum/inode.h>
#include <stratum/sync.h>
#include <stratum/types.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define FILE_SIZE 48676u

struct wop { uint64_t off; uint32_t len; };

/* Phase 1: the compile's writes (bufio flushes + ar-header backfills). */
static const struct wop phase1[] = {
    {0, 68}, {68, 3048}, {8, 60}, {3116, 60}, {3176, 186},
    {3362, 4096}, {7458, 4096}, {11554, 4096}, {15650, 4096}, {19746, 4096},
    {23842, 4096}, {27938, 4096}, {32034, 4096}, {36130, 4096}, {40226, 4096},
    {44322, 4096}, {48418, 258},
    {3362, 96}, {3116, 60},
};

/* Phase 2: updateBuildID's two in-place stamps (the corruption trigger). */
static const struct wop phase2[] = {
    {198, 41}, {3306, 41},
};

static uint8_t shadow[FILE_SIZE];
static uint8_t rbuf[FILE_SIZE];
static uint64_t g_file_size = FILE_SIZE;   /* per-variant logical size */

static void fill_pattern(uint8_t *dst, uint64_t off, uint32_t len, int salt)
{
    for (uint32_t i = 0; i < len; i++)
        dst[i] = (uint8_t)(1 + ((off + i + (uint64_t)salt * 7) % 251));
}

static int check(stm_fs *fs, uint64_t ino, const char *tag, int windowed)
{
    memset(rbuf, 0xEE, sizeof rbuf);
    if (windowed) {
        /* mirror the guest's <=4096-byte read granularity */
        for (uint64_t o = 0; o < g_file_size; ) {
            size_t want = g_file_size - o;
            if (want > 4096) want = 4096;
            size_t got = 0;
            STM_ASSERT_OK(stm_fs_read(fs, 1, ino, o, rbuf + o, want, &got));
            if (got == 0) { printf("  [%s] EOF short at %llu\n", tag,
                                   (unsigned long long)o); break; }
            o += got;
        }
    } else {
        size_t got = 0;
        STM_ASSERT_OK(stm_fs_read(fs, 1, ino, 0, rbuf,
                                  (size_t)g_file_size, &got));
        if (got != g_file_size)
            printf("  [%s] whole-read short: %zu\n", tag, got);
    }
    int bad = 0;
    uint64_t i = 0;
    while (i < g_file_size) {
        if (rbuf[i] == shadow[i]) { i++; continue; }
        uint64_t start = i;
        int allzero = 1;
        while (i < g_file_size && rbuf[i] != shadow[i]) {
            if (rbuf[i] != 0) allzero = 0;
            i++;
        }
        printf("  [%s] DIVERGE [%llu,%llu) len=%llu %s (got[%llu]=0x%02x "
               "want 0x%02x)\n",
               tag, (unsigned long long)start, (unsigned long long)i,
               (unsigned long long)(i - start),
               allzero ? "ALL-ZEROS" : "nonzero-garbage",
               (unsigned long long)start, rbuf[start], shadow[start]);
        bad = 1;
    }
    if (!bad) printf("  [%s] clean (%llu bytes match)\n", tag,
                     (unsigned long long)g_file_size);
    return bad;
}

/* Minimization variants (argv[1]): each is (phase1 set, phase2 set).
 * full  : the traced sequence (default)
 * nobf  : phase 1 without the two backfills
 * head5 : phase 1 truncated after W(3176,186); stamp 3306 only
 * lone  : W(3176,186) alone (hole before); stamp 3306
 * dense : W(0,186) + W(186,4096); stamp W(50,41)
 * backf : W(0,186) + W(186,4096); then W(186,96) (the backfill shape)
 * safe  : full phase 1; stamp 198 only (the observed-safe control)
 */
static const struct wop p1_nobf[] = {
    {0, 68}, {68, 3048}, {8, 60}, {3116, 60}, {3176, 186},
    {3362, 4096}, {7458, 4096}, {11554, 4096}, {15650, 4096}, {19746, 4096},
    {23842, 4096}, {27938, 4096}, {32034, 4096}, {36130, 4096}, {40226, 4096},
    {44322, 4096}, {48418, 258},
};
static const struct wop p1_head5[] = {
    {0, 68}, {68, 3048}, {8, 60}, {3116, 60}, {3176, 186},
};
static const struct wop p1_lone[]  = { {3176, 186} };
static const struct wop p1_dense[] = { {0, 186}, {186, 4096} };
static const struct wop p2_3306[]  = { {3306, 41} };
static const struct wop p2_50[]    = { {50, 41} };
static const struct wop p2_b96[]   = { {186, 96} };
static const struct wop p2_198[]   = { {198, 41} };

static uint64_t max_end(const struct wop *w, size_t n)
{
    uint64_t m = 0;
    for (size_t i = 0; i < n; i++)
        if (w[i].off + w[i].len > m) m = w[i].off + w[i].len;
    return m;
}

static int run_variant(const char *variant);
static int run_space_probe(void);
static int wedge_load(stm_fs *fs, uint64_t dir);
static int run_wedge_probe(void);
static int run_baked_probe(const char *pool_path, const char *key_path);
static int run_getattr46_probe(const char *pool_path, const char *key_path);

int main(int argc, char **argv)
{
    if (argc > 1) {
        if (!strcmp(argv[1], "space")) return run_space_probe();
        if (!strcmp(argv[1], "wedge")) return run_wedge_probe();
        if (!strcmp(argv[1], "baked") && argc == 4)
            return run_baked_probe(argv[2], argv[3]);
        if (!strcmp(argv[1], "getattr46") && argc == 4)
            return run_getattr46_probe(argv[2], argv[3]);
        return run_variant(argv[1]);
    }
    /* ctest mode: every variant must be clean. */
    static const char *all[] = { "full", "safe", "nobf", "head5",
                                 "lone", "dense", "backf" };
    int bad = 0;
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        bad |= run_variant(all[i]);
    printf(bad ? "repro_342: FAIL\n" : "repro_342: ALL VARIANTS CLEAN\n");
    return bad;
}

static int run_variant(const char *variant)
{
    const struct wop *w1 = phase1; size_t n1 = sizeof(phase1)/sizeof(phase1[0]);
    const struct wop *w2 = phase2; size_t n2 = sizeof(phase2)/sizeof(phase2[0]);
    if (!strcmp(variant, "nobf"))  { w1 = p1_nobf;  n1 = sizeof(p1_nobf)/sizeof(p1_nobf[0]); w2 = p2_3306; n2 = 1; }
    if (!strcmp(variant, "head5")) { w1 = p1_head5; n1 = sizeof(p1_head5)/sizeof(p1_head5[0]); w2 = p2_3306; n2 = 1; }
    if (!strcmp(variant, "lone"))  { w1 = p1_lone;  n1 = 1; w2 = p2_3306; n2 = 1; }
    if (!strcmp(variant, "dense")) { w1 = p1_dense; n1 = 2; w2 = p2_50;   n2 = 1; }
    if (!strcmp(variant, "backf")) { w1 = p1_dense; n1 = 2; w2 = p2_b96;  n2 = 1; }
    if (!strcmp(variant, "safe"))  { w2 = p2_198; n2 = 1; }
    uint64_t fsz1 = max_end(w1, n1), fsz2 = max_end(w2, n2);
    g_file_size = (fsz1 > fsz2) ? fsz1 : fsz2;
    memset(shadow, 0, sizeof shadow);
    printf("repro_342 variant=%s size=%llu\n", variant,
           (unsigned long long)g_file_size);

    make_tmp("repro342");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs *fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* A real S_IFREG under a real dir so writes take the buffered
     * fs_write_regular_locked path (the on-device 9P Tlcreate'd file). */
    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                  0, 0, &dir));
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1, dir, (const uint8_t *)"_pkg_.a", 7,
                                     0644, 0, 0, &ino));

    uint8_t wbuf[4096];
    for (size_t w = 0; w < n1; w++) {
        fill_pattern(wbuf, w1[w].off, w1[w].len, (int)w);
        memcpy(shadow + w1[w].off, wbuf, w1[w].len);
        STM_ASSERT_OK(stm_fs_write(fs, 1, ino, w1[w].off, wbuf, w1[w].len));
    }
    int bad = 0;
    bad |= check(fs, ino, "post-phase1-whole", 0);
    bad |= check(fs, ino, "post-phase1-windowed", 1); /* FindAndHash analog */

    for (size_t w = 0; w < n2; w++) {
        fill_pattern(wbuf, w2[w].off, w2[w].len, 100 + (int)w);
        memcpy(shadow + w2[w].off, wbuf, w2[w].len);
        STM_ASSERT_OK(stm_fs_write(fs, 1, ino, w2[w].off, wbuf, w2[w].len));
    }
    bad |= check(fs, ino, "post-stamps-whole", 0);
    bad |= check(fs, ino, "post-stamps-windowed", 1);

    /* durability angle: remount and re-read */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));
    bad |= check(fs, ino, "post-remount-whole", 0);
    STM_ASSERT_OK(stm_fs_unmount(fs));

    printf(bad ? "repro_342: REPRODUCED (divergence above)\n"
               : "repro_342: clean -- no divergence on this tier\n");
    return bad ? 1 : 0;
}

/* space: amplification probe (task #39 hunt tool, NOT part of the ctest
 * run). Writes the traced go-archive pattern file-after-file with NO
 * commit until the first ENOSPC, then commits and writes a second wave.
 * At ~1x amplification the 16 MiB test pool (8 MiB bootstrap) holds
 * ~150 files of 48,676 B. A much earlier ENOSPC = space consumed above
 * the logical bytes; second-wave success after the commit = the excess
 * was uncommitted-CoW/PENDING garbage a commit sweeps (the fix then is
 * commit-on-allocation-pressure); second-wave ENOSPC = a real leak. */
static int run_space_probe(void)
{
    make_tmp("repro342sp");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs *fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                  0, 0, &dir));

    uint8_t wbuf[4096];
    int wave1 = 0, wave2 = 0;
    stm_status rc = STM_OK;
    for (int f = 0; f < 4000 && rc == STM_OK; f++) {
        char nm[16];
        int nl = snprintf(nm, sizeof nm, "f%04d", f);
        uint64_t ino = 0;
        rc = stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm,
                                (uint8_t)nl, 0644, 0, 0, &ino);
        if (rc != STM_OK) break;
        for (size_t w = 0; w < sizeof(phase1)/sizeof(phase1[0]) && rc == STM_OK; w++) {
            fill_pattern(wbuf, phase1[w].off, phase1[w].len, (int)w);
            rc = stm_fs_write(fs, 1, ino, phase1[w].off, wbuf, phase1[w].len);
        }
        for (size_t w = 0; w < sizeof(phase2)/sizeof(phase2[0]) && rc == STM_OK; w++) {
            fill_pattern(wbuf, phase2[w].off, phase2[w].len, 100 + (int)w);
            rc = stm_fs_write(fs, 1, ino, phase2[w].off, wbuf, phase2[w].len);
        }
        if (rc == STM_OK) wave1++;
    }
    printf("space: wave1 files=%d logical=%.1f MiB before rc=%d "
           "(pool 16 MiB, 8 MiB bootstrap)\n",
           wave1, wave1 * (double)FILE_SIZE / (1024.0 * 1024.0), (int)rc);

    stm_status crc_ = stm_fs_commit(fs);
    printf("space: commit rc=%d\n", (int)crc_);

    rc = STM_OK;
    for (int f = 0; f < 4000 && rc == STM_OK; f++) {
        char nm[16];
        int nl = snprintf(nm, sizeof nm, "g%04d", f);
        uint64_t ino = 0;
        rc = stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm,
                                (uint8_t)nl, 0644, 0, 0, &ino);
        if (rc != STM_OK) break;
        for (size_t w = 0; w < sizeof(phase1)/sizeof(phase1[0]) && rc == STM_OK; w++) {
            fill_pattern(wbuf, phase1[w].off, phase1[w].len, (int)w);
            rc = stm_fs_write(fs, 1, ino, phase1[w].off, wbuf, phase1[w].len);
        }
        if (rc == STM_OK) wave2++;
    }
    printf("space: wave2 (post-commit) files=%d logical=%.1f MiB rc=%d\n",
           wave2, wave2 * (double)FILE_SIZE / (1024.0 * 1024.0), (int)rc);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    return 0;
}

/* --- #35 fsync-cascade probes (wedge / baked) ------------------------- */

/* The go-build-shaped load, shared by the empty-pool (`wedge`) and the
 * baked-pool (`baked`) probes: buffered smalls + DIRECT bigs (>= the
 * 1 MiB flush threshold -> immediate uncommitted extents) + buffered
 * stamps ONTO those extents + an unlink storm of files-with-extents
 * (reclaim commits fire mid-load), x3 cycles, then the fsync-equivalent
 * stm_fs_commit + a post cascade probe. Prints every failing rc; the
 * in-guest cascade is EVERY extent write failing STM_ECORRUPT(-200)
 * from the $WORK-cleanup window onward. Returns nonzero if dirty. */
static int wedge_load(stm_fs *fs, uint64_t dir)
{
    size_t big_len = 2u * 1024u * 1024u;
    uint8_t *big = malloc(big_len);
    STM_ASSERT(big != NULL);
    for (size_t i = 0; i < big_len; i++) big[i] = (uint8_t)(i * 131u + 7u);
    uint8_t wbuf[4096];

    stm_status rc = STM_OK;
    int cycle = 0, smalls = 0, bigs = 0, unlinks = 0;
    const char *died = NULL;

    for (cycle = 0; cycle < 3 && rc == STM_OK; cycle++) {
        for (int f = 0; f < 300 && rc == STM_OK; f++) {
            char nm[24];
            int nl = snprintf(nm, sizeof nm, "c%d-s%04d", cycle, f);
            uint64_t ino = 0;
            rc = stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm,
                                    (uint8_t)nl, 0644, 0, 0, &ino);
            if (rc != STM_OK) { died = "small-create"; break; }
            for (size_t w = 0; w < sizeof(phase1)/sizeof(phase1[0]); w++) {
                fill_pattern(wbuf, phase1[w].off, phase1[w].len, (int)w);
                rc = stm_fs_write(fs, 1, ino, phase1[w].off, wbuf,
                                  phase1[w].len);
                if (rc != STM_OK) { died = "small-write"; break; }
            }
            if (rc == STM_OK) smalls++;
        }

        for (int f = 0; f < 8 && rc == STM_OK; f++) {
            char nm[24];
            int nl = snprintf(nm, sizeof nm, "c%d-b%02d", cycle, f);
            uint64_t ino = 0;
            rc = stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm,
                                    (uint8_t)nl, 0644, 0, 0, &ino);
            if (rc != STM_OK) { died = "big-create"; break; }
            rc = stm_fs_write(fs, 1, ino, 0, big, big_len);
            if (rc != STM_OK) { died = "big-direct-write"; break; }
            fill_pattern(wbuf, 3176, 186, 42);
            rc = stm_fs_write(fs, 1, ino, 3176, wbuf, 186);
            if (rc != STM_OK) { died = "stamp1"; break; }
            fill_pattern(wbuf, 3306, 41, 43);
            rc = stm_fs_write(fs, 1, ino, 3306, wbuf, 41);
            if (rc != STM_OK) { died = "stamp2"; break; }
            bigs++;
        }

        for (int f = 0; f < 300 && rc == STM_OK; f += 2) {
            char nm[24];
            int nl = snprintf(nm, sizeof nm, "c%d-s%04d", cycle, f);
            rc = stm_fs_unlink(fs, 1, dir, (const uint8_t *)nm, (uint8_t)nl);
            if (rc != STM_OK) { died = "small-unlink"; break; }
            unlinks++;
        }
        for (int f = 0; f < 8 && rc == STM_OK; f += 2) {
            char nm[24];
            int nl = snprintf(nm, sizeof nm, "c%d-b%02d", cycle, f);
            rc = stm_fs_unlink(fs, 1, dir, (const uint8_t *)nm, (uint8_t)nl);
            if (rc != STM_OK) { died = "big-unlink"; break; }
            unlinks++;
        }
        printf("wedge: cycle %d done smalls=%d bigs=%d unlinks=%d rc=%d\n",
               cycle, smalls, bigs, unlinks, (int)rc);
    }

    if (rc != STM_OK)
        printf("wedge: FIRST FAILURE at %s rc=%d (cycle %d)\n",
               died ? died : "?", (int)rc, cycle);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    stm_status crc_ = stm_fs_commit(fs);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ms = (double)(t1.tv_sec - t0.tv_sec) * 1e3
              + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("wedge: commit rc=%d in %.0f ms\n", (int)crc_, ms);

    uint64_t ino2 = 0;
    stm_status c2 = stm_fs_create_file(fs, 1, dir, (const uint8_t *)"after", 5,
                                       0644, 0, 0, &ino2);
    stm_status w2 = STM_EINVAL;
    if (c2 == STM_OK) {
        fill_pattern(wbuf, 0, 4096, 7);
        w2 = stm_fs_write(fs, 1, ino2, 0, wbuf, 4096);
    }
    stm_status s2 = stm_fs_commit(fs);
    printf("wedge: post create rc=%d write rc=%d commit2 rc=%d\n",
           (int)c2, (int)w2, (int)s2);

    free(big);
    int bad = (rc != STM_OK) || (crc_ != STM_OK) || (c2 != STM_OK) ||
              (w2 != STM_OK) || (s2 != STM_OK);
    printf(bad ? "wedge: DIRTY\n" : "wedge: CLEAN\n");
    return bad;
}

static int run_wedge_probe(void)
{
    make_tmp("repro342w");
    stm_fs_format_opts fopts = default_format_opts();
    fopts.device_size_bytes    = UINT64_C(4) * 1024 * 1024 * 1024;
    fopts.bootstrap_size_bytes = UINT64_C(16) * 1024 * 1024;
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs *fs = NULL;
    stm_fs_mount_opts mopts = rw_mount_opts();
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                  0, 0, &dir));

    int bad = wedge_load(fs, dir);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    return bad;
}

/* baked: the wedge load against a COPY of the REAL baked GOROOT pool
 * (build/fixtures/pool.img.baked-snapshot + system.key.baked-snapshot)
 * -- the guest-fidelity delta the empty-pool wedge lacks: the committed
 * bake tree (extent/alloc/Merkle state at real depth) that the guest
 * then mutates. argv: repro_342 baked <pool-copy> <keyfile>. The pool
 * file IS MUTATED -- pass a throwaway copy, never the snapshot. */
static int run_baked_probe(const char *pool_path, const char *key_path)
{
    stm_fs *fs = NULL;
    stm_fs_mount_opts mopts = {
        .read_only    = false,
        .keyfile_path = key_path,
    };
    stm_status mrc = stm_fs_mount(pool_path, &mopts, &fs);
    printf("baked: mount rc=%d (%s)\n", (int)mrc, pool_path);
    if (mrc != STM_OK) return 2;
    printf("baked: verify-at-mount rc=%d\n", (int)stm_fs_verify(fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                  0, 0, &dir));

    int bad = wedge_load(fs, dir);
    printf("baked: verify-post-load rc=%d\n", (int)stm_fs_verify(fs));
    STM_ASSERT_OK(stm_fs_unmount(fs));
    return bad;
}

/* getattr46 (#46 / the Thylacine go-cache layer-4 residue): the cmd/go
 * putIndexEntry shape against a COPY of the REAL baked pool. Per
 * iteration: a chunked buffered "-d output" write (cmd/go copyFile's
 * chunking -- 40 x 64 KiB buffered inserts, enough dirty-buffer pressure
 * to trip mid-run flushes), then a FRESH 66-char "-a" index entry:
 * create -> write(175) -> IMMEDIATE stm_fs_stat with NO fsync/commit --
 * asserting si_size == 175 (the port Ftruncate no-op gate). ZERO commits
 * across the load (the on-device go build issues none). argv:
 * repro_342 getattr46 <pool-copy> <keyfile>. Pool file IS MUTATED. */
static int run_getattr46_probe(const char *pool_path, const char *key_path)
{
    stm_fs *fs = NULL;
    stm_fs_mount_opts mopts = {
        .read_only    = false,
        .keyfile_path = key_path,
    };
    stm_status mrc = stm_fs_mount(pool_path, &mopts, &fs);
    printf("getattr46: mount rc=%d (%s)\n", (int)mrc, pool_path);
    if (mrc != STM_OK) return 2;

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t dir = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1, (uint32_t)S_IFDIR | 0755u,
                                  0, 0, &dir));

    const size_t chunk_len = 64u * 1024u;
    uint8_t *chunk = malloc(chunk_len);
    STM_ASSERT(chunk != NULL);
    uint8_t entry[175];
    int bad = 0;

    for (int it = 0; it < 40 && !bad; it++) {
        char nm[80];
        /* The -d output file: chunked buffered writes. */
        int nl = snprintf(nm, sizeof nm, "%02x%062d-d", it & 0xff, it);
        uint64_t dino = 0;
        stm_status rc = stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm,
                                           (uint8_t)nl, 0644, 0, 0, &dino);
        if (rc != STM_OK) {
            printf("getattr46: it=%d -d create rc=%d\n", it, (int)rc);
            bad = 1; break;
        }
        for (int c = 0; c < 40 && rc == STM_OK; c++) {
            for (size_t i = 0; i < chunk_len; i++)
                chunk[i] = (uint8_t)(i * 31u + (size_t)c + (size_t)it);
            rc = stm_fs_write(fs, 1, dino, (uint64_t)c * chunk_len,
                              chunk, chunk_len);
        }
        if (rc != STM_OK) {
            printf("getattr46: it=%d -d write rc=%d\n", it, (int)rc);
            bad = 1; break;
        }

        /* The -a index entry: create -> write(175) -> stat, no fsync. */
        nl = snprintf(nm, sizeof nm, "%02x%062d-a", it & 0xff, it);
        uint64_t aino = 0;
        rc = stm_fs_create_file(fs, 1, dir, (const uint8_t *)nm,
                                (uint8_t)nl, 0644, 0, 0, &aino);
        if (rc != STM_OK) {
            printf("getattr46: it=%d -a create rc=%d\n", it, (int)rc);
            bad = 1; break;
        }
        for (size_t i = 0; i < sizeof entry; i++)
            entry[i] = (uint8_t)('A' + ((i + (size_t)it) % 26u));
        rc = stm_fs_write(fs, 1, aino, 0, entry, sizeof entry);
        if (rc != STM_OK) {
            printf("getattr46: it=%d -a write rc=%d\n", it, (int)rc);
            bad = 1; break;
        }

        struct stm_inode_value iv;
        rc = stm_fs_stat(fs, 1, aino, &iv);
        uint64_t sz = (rc == STM_OK) ? stm_load_le64(iv.si_size) : 0u;
        if (rc != STM_OK || sz != sizeof entry) {
            printf("getattr46: it=%d STALE -a stat rc=%d size=%llu (want %zu)\n",
                   it, (int)rc, (unsigned long long)sz, sizeof entry);
            bad = 1;
        }
        /* The -d inode too (cmd/go's Get trusts its size on every hit). */
        rc = stm_fs_stat(fs, 1, dino, &iv);
        sz = (rc == STM_OK) ? stm_load_le64(iv.si_size) : 0u;
        if (rc != STM_OK || sz != (uint64_t)(40u * chunk_len)) {
            printf("getattr46: it=%d STALE -d stat rc=%d size=%llu (want %llu)\n",
                   it, (int)rc, (unsigned long long)sz,
                   (unsigned long long)(40u * chunk_len));
            bad = 1;
        }
    }

    free(chunk);
    printf(bad ? "getattr46: STALE/DIRTY\n" : "getattr46: CLEAN\n");
    STM_ASSERT_OK(stm_fs_unmount(fs));
    return bad;
}
