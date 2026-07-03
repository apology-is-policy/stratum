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

int main(int argc, char **argv)
{
    if (argc > 1) return run_variant(argv[1]);
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
