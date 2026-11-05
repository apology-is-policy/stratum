/* SPDX-License-Identifier: ISC */
/*
 * Synchronous block-device tests over a loopback file.
 */
#include "tharness.h"
#include <stratum/block.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char g_tmp_path[256];

static void make_tmp(const char *tag)
{
    snprintf(g_tmp_path, sizeof g_tmp_path, "/tmp/stm_v2_bdev_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_tmp_path);
}

STM_TEST(bdev_open_close) {
    make_tmp("ok");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT(d != NULL);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_grow_and_write_read_roundtrip) {
    make_tmp("rw");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));

    const size_t N = 4096;
    uint8_t *wbuf = malloc(N);
    uint8_t *rbuf = malloc(N);
    STM_ASSERT(wbuf && rbuf);
    stm_prop_seed(1);
    stm_prop_fill(wbuf, N);

    STM_ASSERT_OK(stm_bdev_resize(d, 1024 * 1024));
    STM_ASSERT_OK(stm_bdev_write(d, 0, wbuf, N));
    STM_ASSERT_OK(stm_bdev_fsync(d));
    STM_ASSERT_OK(stm_bdev_read(d, 0, rbuf, N));
    STM_ASSERT_MEM_EQ(wbuf, rbuf, N);

    free(wbuf); free(rbuf);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_multiple_offsets) {
    make_tmp("offs");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 1024 * 1024));

    for (int i = 0; i < 16; i++) {
        uint8_t buf[64];
        stm_prop_seed((uint64_t)i * 7 + 3);
        stm_prop_fill(buf, sizeof buf);
        uint64_t off = (uint64_t)i * 8192;
        STM_ASSERT_OK(stm_bdev_write(d, off, buf, sizeof buf));
    }
    STM_ASSERT_OK(stm_bdev_fsync(d));

    for (int i = 0; i < 16; i++) {
        uint8_t expected[64];
        stm_prop_seed((uint64_t)i * 7 + 3);
        stm_prop_fill(expected, sizeof expected);

        uint8_t got[64];
        uint64_t off = (uint64_t)i * 8192;
        STM_ASSERT_OK(stm_bdev_read(d, off, got, sizeof got));
        STM_ASSERT_MEM_EQ(expected, got, sizeof got);
    }

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_readonly_blocks_writes) {
    make_tmp("ro");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 65536));
    uint8_t zero[4096] = { 0 };
    STM_ASSERT_OK(stm_bdev_write(d, 0, zero, sizeof zero));
    stm_bdev_close(d);

    opts = stm_bdev_open_opts_default();
    opts.read_only = true;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    uint8_t data[4096];
    stm_prop_fill(data, sizeof data);
    STM_ASSERT_ERR(stm_bdev_write(d, 0, data, sizeof data), STM_EROFS);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_caps_populated) {
    make_tmp("caps");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 4096 * 1024));

    const stm_bdev_caps *c = stm_bdev_caps_of(d);
    STM_ASSERT(c != NULL);
    STM_ASSERT(c->size_bytes >= 4096 * 1024);
    STM_ASSERT(c->block_size >= 512);
    STM_ASSERT(c->queue_depth >= 1);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

/* R0-P1-1 regression: sync read past EOF must return STM_EIO, not silently
 * succeed with partial data. Both backends must agree on this contract. */
STM_TEST(bdev_sync_read_past_eof_is_eio) {
    make_tmp("eof");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 4096));

    uint8_t buf[4096];
    /* Read crossing the EOF boundary at offset 2048 for 4096 bytes. */
    STM_ASSERT_ERR(stm_bdev_read(d, 2048, buf, sizeof buf), STM_EIO);

    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST(bdev_resize_grow_only) {
    make_tmp("resz");
    stm_bdev_open_opts opts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_tmp_path, &opts, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, 1 << 20));
    STM_ASSERT_OK(stm_bdev_resize(d, 2 << 20));          /* grow: ok */
    STM_ASSERT_ERR(stm_bdev_resize(d, 1 << 20),          /* shrink: EINVAL */
                   STM_EINVAL);
    stm_bdev_close(d);
    unlink(g_tmp_path);
}

STM_TEST_MAIN("bdev")
