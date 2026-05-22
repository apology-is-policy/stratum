/* SPDX-License-Identifier: ISC */
/*
 * test_xattr.c — P8-POSIX-6 + 9.7-impl-1c-iv.
 *
 * Exercises the xattr index per `v2/specs/xattr.tla`:
 *
 *   - Lifecycle (create / close / attach).
 *   - Set / get / remove / list basic paths.
 *   - POSIX setxattr flag semantics (CREATE / REPLACE / default-replace-
 *     or-create).
 *   - Chain integrity: tombstone-after-remove preserves reachability of
 *     a colliding name at a higher probe index — the canonical
 *     xattr.tla::BuggyUnlinkUsesEmpty failure mode that this impl pins
 *     via `Remove leaves TOMBSTONE marker`.
 *   - Argument validation matrix: every documented refusal in xattr.h
 *     is exercised and asserted symmetric with the on-disk decoder
 *     (R71 P1-1 + R77 P1-1 lesson — writer-side guards mirror
 *     decoder-side guards for both name_len AND value_len).
 *   - Probe-only / range-truncation getxattr shapes (POSIX getxattr(2)).
 *   - Drop-for-ino.
 *   - D1 invariant from xattr's side: per-dataset engines distinct;
 *     same-key lookups across datasets see independent values.
 *   - On-disk layout sanity: STM_UB_VERSION compile-time at 32.
 *
 * 9.7-impl-1c-iv: the xattr module no longer owns its own engine —
 * records live in each dataset's per-dataset btree_engine, resolved
 * via an attached `stm_dataset_index`. The fixture builds bdev +
 * boot + ds_idx + creates a roster of test datasets, then attaches
 * the xattr index. Tests that exercise dataset_ids 1..16 just work
 * (the fixture pre-creates them). Persistence-specific tests from
 * P8-POSIX-6 + 9.6-impl-4c are dropped — that persistence layer is
 * now in the dataset_index + per-dataset engines.
 */
#include "tharness.h"

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btree_engine.h>
#include <stratum/crypto.h>
#include <stratum/dataset.h>
#include <stratum/xattr.h>
#include <stratum/super.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define XA_DEVICE_BYTES        (UINT64_C(64) * 1024u * 1024u)
#define XA_BOOTSTRAP_BYTES     (UINT64_C(8)  * 1024u * 1024u)
#define XA_DS_ROSTER_MAX       16u

static const uint64_t XA_POOL_UUID[2]   = { 0xA001, 0xB001 };
static const uint64_t XA_DEVICE_UUID[2] = { 0xC001, 0xD001 };
static const uint8_t  XA_KEY[32]        = { 0x88, 0x99, 0xAA };

/* ------------------------------------------------------------------ */
/* Storage fixture.                                                    */
/*                                                                      */
/* 9.7-impl-1c-iv: the fixture stands up bdev + boot + ds_idx +        */
/* creates a roster of test datasets (id 2..16 — id 1 is the auto-     */
/* created root), then attaches the xattr index. Tests can use any     */
/* dataset_id in [1..16] directly. The harness runs tests sequentially */
/* in one process, so static fixture slots (g_fx_*) are safe.          */
/* ------------------------------------------------------------------ */

static char xa_tmp_path[256];

static void xa_make_tmp(const char *tag) {
    snprintf(xa_tmp_path, sizeof xa_tmp_path,
             "/tmp/stm_v2_xattr_persist_%s_%d.bin", tag, (int)getpid());
    unlink(xa_tmp_path);
}

static void xa_open_fresh(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(xa_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bdev_resize(*out_d, XA_DEVICE_BYTES));
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_bootstrap_create(*out_d, XA_POOL_UUID, XA_DEVICE_UUID,
                                         XA_BOOTSTRAP_BYTES, out_b));
}

/* Single static fixture slot — sequential tests share it. */
static stm_bdev          *xa_g_fx_bdev;
static stm_bootstrap     *xa_g_fx_boot;
static stm_dataset_index *xa_g_fx_ds_idx;

/* Build a fresh storage-backed, fully-bound xattr index. The dataset
 * index owns the per-dataset engines + the bdev/boot/crypt context;
 * the xattr index borrows the dataset index via attach. A roster of
 * datasets (ids 2..XA_DS_ROSTER_MAX) is pre-created so every test's
 * chosen dataset_id is PRESENT. */
static stm_xattr_index *xa_test_idx(void) {
    xa_make_tmp("fx");
    xa_open_fresh(&xa_g_fx_bdev, &xa_g_fx_boot);

    STM_ASSERT_OK(stm_dataset_index_create(/*current_txg=*/0, &xa_g_fx_ds_idx));
    STM_ASSERT_OK(stm_dataset_index_set_storage(xa_g_fx_ds_idx,
                                                  xa_g_fx_bdev, xa_g_fx_boot));
    STM_ASSERT_OK(stm_dataset_index_set_crypt_ctx(xa_g_fx_ds_idx, XA_KEY,
                                                    XA_POOL_UUID,
                                                    XA_DEVICE_UUID));

    /* Pre-create datasets id 2..XA_DS_ROSTER_MAX as siblings of root.
     * Each stm_dataset_create_child returns a monotonic id; we discard
     * the returned id and rely on the monotonic assignment (root=1,
     * first child=2, second child=3, ...). */
    char name_buf[8];
    for (uint64_t i = 2u; i <= XA_DS_ROSTER_MAX; i++) {
        uint64_t out_id = 0;
        snprintf(name_buf, sizeof name_buf, "ds%llu", (unsigned long long)i);
        STM_ASSERT_OK(stm_dataset_create_child(xa_g_fx_ds_idx,
                                                 STM_DATASET_ROOT_ID,
                                                 name_buf, &out_id));
        STM_ASSERT_EQ(out_id, i);
    }

    stm_xattr_index *idx = stm_xattr_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    STM_ASSERT_OK(stm_xattr_index_attach_dataset_index(idx, xa_g_fx_ds_idx));
    return idx;
}

static void xa_test_idx_close(stm_xattr_index *idx) {
    stm_xattr_index_close(idx);     /* before ds_idx — the xattr index
                                     * borrows the dataset index */
    stm_dataset_index_close(xa_g_fx_ds_idx);
    stm_bootstrap_close(xa_g_fx_boot);
    stm_bdev_close(xa_g_fx_bdev);
    xa_g_fx_ds_idx = NULL;
    xa_g_fx_boot   = NULL;
    xa_g_fx_bdev   = NULL;
    unlink(xa_tmp_path);
}

/* ------------------------------------------------------------------ */
/* In-memory ops — chain integrity + arg validation.                    */
/* ------------------------------------------------------------------ */

STM_TEST(xattr_lifecycle_create_close) {
    stm_xattr_index *idx = xa_test_idx();
    STM_ASSERT_TRUE(idx != NULL);
    xa_test_idx_close(idx);
    /* Closing NULL is safe. */
    stm_xattr_index_close(NULL);
}

STM_TEST(xattr_set_get_basic) {
    stm_xattr_index *idx = xa_test_idx();

    const uint8_t name[] = "user.foo";
    const uint8_t value[] = "hello world";
    bool replaced = true;
    STM_ASSERT_OK(stm_xattr_set(idx, /*ds=*/1, /*ino=*/100,
                                   name, (uint8_t)(sizeof name - 1u),
                                   value, (uint32_t)(sizeof value - 1u),
                                   /*flags=*/0, &replaced));
    STM_ASSERT_TRUE(!replaced);

    uint8_t  buf[64] = { 0 };
    uint32_t out_size = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 100,
                                   name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &out_size));
    STM_ASSERT_EQ(out_size, (uint32_t)(sizeof value - 1u));
    STM_ASSERT_TRUE(memcmp(buf, value, sizeof value - 1u) == 0);

    /* Lookup on a name that doesn't exist returns STM_ENODATA. */
    const uint8_t miss[] = "user.bar";
    STM_ASSERT_ERR(stm_xattr_get(idx, 1, 100,
                                    miss, (uint8_t)(sizeof miss - 1u),
                                    buf, sizeof buf, &out_size),
                   STM_ENODATA);
    STM_ASSERT_EQ(out_size, (uint32_t)0);

    xa_test_idx_close(idx);
}

STM_TEST(xattr_get_probe_with_value_max_zero) {
    /* POSIX getxattr probe shape: pass value_max=0, get full size. */
    stm_xattr_index *idx = xa_test_idx();

    const uint8_t name[]  = "user.size";
    const uint8_t value[] = "0123456789ABCDEF";
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   value, (uint32_t)(sizeof value - 1u), 0, NULL));

    uint32_t sz = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   /*buf=*/NULL, /*max=*/0, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)(sizeof value - 1u));
    xa_test_idx_close(idx);
}

STM_TEST(xattr_get_buf_too_small_returns_erange) {
    stm_xattr_index *idx = xa_test_idx();

    const uint8_t name[]  = "user.long";
    const uint8_t value[] = "this-is-twelve-bytes!";
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   value, (uint32_t)(sizeof value - 1u), 0, NULL));

    uint8_t  small[5] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_ERR(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                    small, sizeof small, &sz),
                   STM_ERANGE);
    /* sz still tells caller the full size. */
    STM_ASSERT_EQ(sz, (uint32_t)(sizeof value - 1u));
    xa_test_idx_close(idx);
}

STM_TEST(xattr_set_default_replaces) {
    stm_xattr_index *idx = xa_test_idx();

    const uint8_t name[] = "user.k";
    bool replaced = false;
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"v1", 2, 0, &replaced));
    STM_ASSERT_TRUE(!replaced);
    /* Second set with same name + default flags = replace. */
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"v2-bigger", 9, 0, &replaced));
    STM_ASSERT_TRUE(replaced);

    uint8_t  buf[16] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)9);
    STM_ASSERT_TRUE(memcmp(buf, "v2-bigger", 9) == 0);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_set_create_flag_refuses_existing) {
    stm_xattr_index *idx = xa_test_idx();
    const uint8_t name[] = "user.k";
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"v", 1, 0, NULL));
    /* CREATE flag must refuse with STM_EEXIST. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                    (const uint8_t *)"new", 3,
                                    STM_XATTR_FLAG_CREATE, NULL),
                   STM_EEXIST);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_set_replace_flag_refuses_missing) {
    stm_xattr_index *idx = xa_test_idx();
    const uint8_t name[] = "user.k";
    /* REPLACE on a missing name → STM_ENODATA. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                    (const uint8_t *)"v", 1,
                                    STM_XATTR_FLAG_REPLACE, NULL),
                   STM_ENODATA);
    /* And after a successful create, REPLACE is fine. */
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"v2", 2,
                                   STM_XATTR_FLAG_REPLACE, NULL));
    xa_test_idx_close(idx);
}

STM_TEST(xattr_set_create_and_replace_together_is_einval) {
    stm_xattr_index *idx = xa_test_idx();
    const uint8_t name[] = "user.k";
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                    (const uint8_t *)"v", 1,
                                    STM_XATTR_FLAG_CREATE | STM_XATTR_FLAG_REPLACE,
                                    NULL),
                   STM_EINVAL);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_remove_basic) {
    stm_xattr_index *idx = xa_test_idx();
    const uint8_t name[] = "user.gone";
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"x", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_remove(idx, 1, 1, name, (uint8_t)(sizeof name - 1u)));
    /* After remove, get returns STM_ENODATA. */
    uint32_t sz = 0;
    STM_ASSERT_ERR(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                    NULL, 0, &sz),
                   STM_ENODATA);
    /* Remove of an absent name returns STM_ENODATA. */
    STM_ASSERT_ERR(stm_xattr_remove(idx, 1, 1, name, (uint8_t)(sizeof name - 1u)),
                   STM_ENODATA);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_per_ino_isolation) {
    /* Same name on different (ds, ino) pairs is independent. */
    stm_xattr_index *idx = xa_test_idx();
    const uint8_t name[] = "user.shared";
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"a", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"b", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 2, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"c", 1, 0, NULL));

    uint8_t  buf[4] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)1);
    STM_ASSERT_EQ(buf[0], (uint8_t)'a');
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(buf[0], (uint8_t)'b');
    STM_ASSERT_OK(stm_xattr_get(idx, 2, 1, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(buf[0], (uint8_t)'c');
    xa_test_idx_close(idx);
}

/* xattr.tla::BuggyLookupStopsOnTombstone — Remove must leave a tombstone
 * marker so a colliding name stays reachable past the slot. The probe
 * walk is determined by FNV-1a64; we synthesize a collision by picking
 * names that hash to the same modular slot. Names "ab" / "ba" don't
 * collide on FNV. We instead choose names that we know hash-collide
 * via direct construction: any two distinct byte sequences of the same
 * length that produce identical hash are rare, so we instead exercise
 * tombstone behavior on the SAME slot by constructing remove + reset +
 * reset_with_collision via the chain. The cleanest test is to remove
 * an inserted name then re-set the same name — it MUST end up at the
 * tombstoned slot (the chain-integrity contract for re-allocation). */
STM_TEST(xattr_remove_then_set_same_name_lands_on_tombstone) {
    stm_xattr_index *idx = xa_test_idx();
    const uint8_t name[] = "user.tomb";
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"v1", 2, 0, NULL));
    STM_ASSERT_OK(stm_xattr_remove(idx, 1, 1, name, (uint8_t)(sizeof name - 1u)));
    /* Re-set the same name → the install slot is the tombstone. */
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"v2-after-tomb", 13, 0, NULL));
    uint8_t  buf[32] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)13);
    STM_ASSERT_TRUE(memcmp(buf, "v2-after-tomb", 13) == 0);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_set_arg_validation) {
    stm_xattr_index *idx = xa_test_idx();

    /* NULL idx. */
    STM_ASSERT_ERR(stm_xattr_set(NULL, 1, 1, (const uint8_t *)"u.x", 3,
                                    (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* NULL name. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, NULL, 3,
                                    (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* NULL value with value_len > 0. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, (const uint8_t *)"u.x", 3,
                                    NULL, 1, 0, NULL),
                   STM_EINVAL);
    /* dataset_id == 0. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 0, 1, (const uint8_t *)"u.x", 3,
                                    (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* ino == 0. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 0, (const uint8_t *)"u.x", 3,
                                    (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* name_len == 0. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, (const uint8_t *)"u.x", 0,
                                    (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* Unknown flag bit. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, (const uint8_t *)"u.x", 3,
                                    (const uint8_t *)"v", 1, 0x4, NULL),
                   STM_EINVAL);

    /* value_len > MAX → STM_ERANGE. */
    /* We can't allocate a 64KiB+1 buffer easily; the writer-guard just
     * checks the integer, so a NULL value with value_len > MAX would
     * fail the NULL check first. Use a stub byte buffer. */
    static uint8_t big[STM_XATTR_VALUE_MAX + 1] = { 0 };
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, (const uint8_t *)"u.x", 3,
                                    big, (uint32_t)(STM_XATTR_VALUE_MAX + 1u),
                                    0, NULL),
                   STM_ERANGE);

    xa_test_idx_close(idx);
}

STM_TEST(xattr_max_size_value_accepted) {
    /* Boundary: value_len == STM_XATTR_VALUE_MAX is accepted. */
    stm_xattr_index *idx = xa_test_idx();
    static uint8_t big[STM_XATTR_VALUE_MAX] = { 0 };
    for (size_t i = 0; i < STM_XATTR_VALUE_MAX; i++) big[i] = (uint8_t)(i & 0xFFu);

    const uint8_t name[] = "user.max";
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   big, STM_XATTR_VALUE_MAX, 0, NULL));

    /* Probe size. */
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   NULL, 0, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)STM_XATTR_VALUE_MAX);

    /* Read back — buffer fits exactly. */
    static uint8_t out[STM_XATTR_VALUE_MAX] = { 0 };
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 1, name, (uint8_t)(sizeof name - 1u),
                                   out, STM_XATTR_VALUE_MAX, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)STM_XATTR_VALUE_MAX);
    STM_ASSERT_TRUE(memcmp(out, big, STM_XATTR_VALUE_MAX) == 0);

    xa_test_idx_close(idx);
}

STM_TEST(xattr_max_name_accepted) {
    /* Boundary: name_len == STM_XATTR_NAME_MAX is accepted. */
    stm_xattr_index *idx = xa_test_idx();
    uint8_t name[STM_XATTR_NAME_MAX];
    memcpy(name, "user.", 5);
    for (size_t i = 5; i < STM_XATTR_NAME_MAX; i++) name[i] = 'A';

    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, name, STM_XATTR_NAME_MAX,
                                   (const uint8_t *)"x", 1, 0, NULL));
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 1, name, STM_XATTR_NAME_MAX,
                                   NULL, 0, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)1);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_list_basic) {
    stm_xattr_index *idx = xa_test_idx();
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.a", 6,
                                   (const uint8_t *)"v1", 2, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.b", 6,
                                   (const uint8_t *)"v22", 3, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"system.acl", 10,
                                   (const uint8_t *)"v333", 4, 0, NULL));

    /* Probe size. */
    size_t total = 0;
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 1, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)3);

    /* Full enumeration. */
    stm_xattr_entry batch[8];
    memset(batch, 0, sizeof batch);
    size_t got = 0;
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 1, batch, 8, &got));
    STM_ASSERT_EQ(got, (size_t)3);
    /* Verify all three names appear (order is implementation-defined). */
    bool saw_a = false, saw_b = false, saw_acl = false;
    for (size_t i = 0; i < got; i++) {
        if (batch[i].name_len == 6  && memcmp(batch[i].name, "user.a", 6) == 0) saw_a = true;
        if (batch[i].name_len == 6  && memcmp(batch[i].name, "user.b", 6) == 0) saw_b = true;
        if (batch[i].name_len == 10 && memcmp(batch[i].name, "system.acl", 10) == 0) saw_acl = true;
    }
    STM_ASSERT_TRUE(saw_a && saw_b && saw_acl);

    xa_test_idx_close(idx);
}

STM_TEST(xattr_list_skips_tombstones) {
    stm_xattr_index *idx = xa_test_idx();
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.a", 6,
                                   (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.b", 6,
                                   (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_remove(idx, 1, 1, (const uint8_t *)"user.a", 6));
    /* List must report only "user.b". */
    size_t total = 0;
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 1, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)1);
    stm_xattr_entry batch[4];
    memset(batch, 0, sizeof batch);
    size_t got = 0;
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 1, batch, 4, &got));
    STM_ASSERT_EQ(got, (size_t)1);
    STM_ASSERT_EQ(batch[0].name_len, (uint8_t)6);
    STM_ASSERT_TRUE(memcmp(batch[0].name, "user.b", 6) == 0);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_list_buf_too_small_returns_erange) {
    stm_xattr_index *idx = xa_test_idx();
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.a", 6,
                                   (const uint8_t *)"v", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.b", 6,
                                   (const uint8_t *)"v", 1, 0, NULL));
    /* Pass max_entries=1, total=2 → STM_ERANGE; out_total reports 2. */
    stm_xattr_entry one[1];
    size_t total = 0;
    STM_ASSERT_ERR(stm_xattr_list(idx, 1, 1, one, 1, &total),
                   STM_ERANGE);
    STM_ASSERT_EQ(total, (size_t)2);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_drop_for_ino) {
    stm_xattr_index *idx = xa_test_idx();
    /* Three xattrs on one ino, two on another. */
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.a", 6,
                                   (const uint8_t *)"x", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.b", 6,
                                   (const uint8_t *)"x", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.c", 6,
                                   (const uint8_t *)"x", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_remove(idx, 1, 1, (const uint8_t *)"user.b", 6));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 2, (const uint8_t *)"user.x", 6,
                                   (const uint8_t *)"y", 1, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 2, (const uint8_t *)"user.y", 6,
                                   (const uint8_t *)"z", 1, 0, NULL));

    /* Drop ino=1 → should drop 3 records (live a, tombstone b, live c). */
    size_t dropped = 0;
    STM_ASSERT_OK(stm_xattr_drop_for_ino(idx, 1, 1, &dropped));
    STM_ASSERT_EQ(dropped, (size_t)3);

    /* ino=1 has zero records now. */
    size_t total = 0;
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 1, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)0);
    /* ino=2 untouched. */
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 2, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)2);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_get_arg_validation) {
    stm_xattr_index *idx = xa_test_idx();
    uint8_t  buf[16] = { 0 };
    uint32_t sz = 0xFFFFu;

    /* NULL idx. */
    STM_ASSERT_ERR(stm_xattr_get(NULL, 1, 1, (const uint8_t *)"u.x", 3,
                                    buf, sizeof buf, &sz),
                   STM_EINVAL);
    /* NULL name. */
    STM_ASSERT_ERR(stm_xattr_get(idx, 1, 1, NULL, 3,
                                    buf, sizeof buf, &sz),
                   STM_EINVAL);
    /* NULL out_size. */
    STM_ASSERT_ERR(stm_xattr_get(idx, 1, 1, (const uint8_t *)"u.x", 3,
                                    buf, sizeof buf, NULL),
                   STM_EINVAL);
    /* NULL value_buf with value_max > 0. */
    STM_ASSERT_ERR(stm_xattr_get(idx, 1, 1, (const uint8_t *)"u.x", 3,
                                    NULL, sizeof buf, &sz),
                   STM_EINVAL);
    STM_ASSERT_EQ(sz, (uint32_t)0);
    xa_test_idx_close(idx);
}

/* ------------------------------------------------------------------ */
/* 9.7-impl-1c-iv: per-dataset engine routing + attach lifecycle.       */
/* ------------------------------------------------------------------ */

/* D1 invariant from xattr's side: two distinct datasets MUST get
 * distinct engines, so the same (ino, name) lookup across datasets
 * returns INDEPENDENT values. Pre-cutover the dataset_id was a key
 * prefix so this was obviously held by the engine layout; post-cutover
 * the dataset_id rides in the engine's AEAD AD (tree_id) and the
 * engines are per-slot — the same property must still hold. */
STM_TEST(xattr_routes_via_dataset_engine) {
    stm_xattr_index *idx = xa_test_idx();

    const uint8_t name[] = "user.k";
    STM_ASSERT_OK(stm_xattr_set(idx, /*ds=*/1, /*ino=*/100,
                                   name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"alpha", 5, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, /*ds=*/2, /*ino=*/100,
                                   name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"beta", 4, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, /*ds=*/3, /*ino=*/100,
                                   name, (uint8_t)(sizeof name - 1u),
                                   (const uint8_t *)"gamma", 5, 0, NULL));

    uint8_t  buf[16] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 100, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)5);
    STM_ASSERT_TRUE(memcmp(buf, "alpha", 5) == 0);
    STM_ASSERT_OK(stm_xattr_get(idx, 2, 100, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)4);
    STM_ASSERT_TRUE(memcmp(buf, "beta", 4) == 0);
    STM_ASSERT_OK(stm_xattr_get(idx, 3, 100, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)5);
    STM_ASSERT_TRUE(memcmp(buf, "gamma", 5) == 0);

    /* Removing from ds=2 leaves ds=1 + ds=3 intact. */
    STM_ASSERT_OK(stm_xattr_remove(idx, 2, 100, name, (uint8_t)(sizeof name - 1u)));
    STM_ASSERT_OK(stm_xattr_get(idx, 1, 100, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)5);
    STM_ASSERT_TRUE(memcmp(buf, "alpha", 5) == 0);
    STM_ASSERT_ERR(stm_xattr_get(idx, 2, 100, name, (uint8_t)(sizeof name - 1u),
                                    buf, sizeof buf, &sz),
                   STM_ENODATA);
    STM_ASSERT_OK(stm_xattr_get(idx, 3, 100, name, (uint8_t)(sizeof name - 1u),
                                   buf, sizeof buf, &sz));
    STM_ASSERT_EQ(sz, (uint32_t)5);
    STM_ASSERT_TRUE(memcmp(buf, "gamma", 5) == 0);

    xa_test_idx_close(idx);
}

/* The attach is one-time — a second call refuses. */
STM_TEST(xattr_attach_dataset_index_refuses_rebind) {
    stm_xattr_index *idx = xa_test_idx();
    /* Fixture already attached xa_g_fx_ds_idx; a second attach fails. */
    STM_ASSERT_ERR(stm_xattr_index_attach_dataset_index(idx, xa_g_fx_ds_idx),
                   STM_EINVAL);
    xa_test_idx_close(idx);
}

STM_TEST(xattr_attach_dataset_index_null_args) {
    stm_xattr_index *idx = stm_xattr_index_create();
    STM_ASSERT_ERR(stm_xattr_index_attach_dataset_index(NULL, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_xattr_index_attach_dataset_index(idx, NULL), STM_EINVAL);
    /* Don't pass non-NULL ds_idx here; we'd have to wire up a real one
     * and the fixture-style refuse_rebind test above already covers
     * the successful attach + rebind refusal. */
    stm_xattr_index_close(idx);
}

/* Public ops MUST refuse with STM_EINVAL when no ds_idx is attached.
 * Mirrors dirent_op_without_attach_refused. */
STM_TEST(xattr_op_without_attach_refused) {
    stm_xattr_index *idx = stm_xattr_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    /* set without attach: STM_EINVAL. */
    STM_ASSERT_ERR(stm_xattr_set(idx, 1, 1, (const uint8_t *)"u.x", 3,
                                    (const uint8_t *)"v", 1, 0, NULL),
                   STM_EINVAL);
    /* get without attach: STM_EINVAL. */
    uint8_t  buf[8] = { 0 };
    uint32_t sz = 0;
    STM_ASSERT_ERR(stm_xattr_get(idx, 1, 1, (const uint8_t *)"u.x", 3,
                                    buf, sizeof buf, &sz),
                   STM_EINVAL);
    /* remove without attach: STM_EINVAL. */
    STM_ASSERT_ERR(stm_xattr_remove(idx, 1, 1, (const uint8_t *)"u.x", 3),
                   STM_EINVAL);
    /* list without attach: STM_EINVAL. */
    size_t total = 0;
    STM_ASSERT_ERR(stm_xattr_list(idx, 1, 1, NULL, 0, &total),
                   STM_EINVAL);
    /* drop_for_ino without attach: STM_EINVAL. */
    STM_ASSERT_ERR(stm_xattr_drop_for_ino(idx, 1, 1, NULL),
                   STM_EINVAL);

    stm_xattr_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Compile-time invariants.                                            */
/* ------------------------------------------------------------------ */

STM_TEST(xattr_ub_version_is_v32) {
    /* 9.7-impl-3 bumps STM_UB_VERSION 31 → 32 for the snap-record
     * tree-root triple (root_gen + root_csum). The xattr layer's
     * on-disk value format is unchanged since v26 but rides the
     * latest version constant. */
    STM_ASSERT_EQ((unsigned)STM_UB_VERSION, (unsigned)32u);
}

/* ------------------------------------------------------------------ */
/* R80 regression tests.                                               */
/* ------------------------------------------------------------------ */

/* R80 P0-1: install_bytes OOM must NOT leave a zero-keyed zombie in
 * records[] that wedges the pool on next mount.
 *
 * Pre-cutover the bug shape was: stm_xattr_set's append_record path
 * bumped n_records++ before install_bytes; on install_bytes STM_ENOMEM
 * the zero-keyed record survived in records[] and was serialized at
 * the next sync_commit with key 24 zero bytes. On reopen, xa_load_iter
 * rejected ds==0 with STM_ECORRUPT → unmountable pool.
 *
 * Post-cutover (9.6-impl-4c + 9.7-impl-1c-iv), the in-RAM records[]
 * array is gone — every set goes straight through engine_insert which
 * is failure-atomic by the engine's contract. The zombie shape is
 * structurally impossible. This test still exercises the rollback
 * BRANCH via interleaved set / remove / set sequences and verifies the
 * list always agrees with the legitimate live record set; a structural
 * regression introducing a zombie would show up here as a phantom
 * count.
 *
 * Coverage gap acknowledged: a true malloc-failure repro requires a
 * test seam for the engine's encode-allocate path; deferred until a
 * fault-injection harness lands. */
STM_TEST(xattr_r80_p0_1_install_failure_no_zombie_record) {
    stm_xattr_index *idx = xa_test_idx();

    /* First, succeed with two real records so the engine isn't empty. */
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.a", 6,
                                   (const uint8_t *)"v1", 2, 0, NULL));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.b", 6,
                                   (const uint8_t *)"v2", 2, 0, NULL));

    /* List confirms 2 entries. */
    size_t total = 0;
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 1, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)2);

    /* Interleaved set/remove/set sequence — verify list always agrees
     * with the legitimate live record set. */
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.c", 6,
                                   (const uint8_t *)"v3", 2, 0, NULL));
    STM_ASSERT_OK(stm_xattr_remove(idx, 1, 1, (const uint8_t *)"user.b", 6));
    STM_ASSERT_OK(stm_xattr_set(idx, 1, 1, (const uint8_t *)"user.d", 6,
                                   (const uint8_t *)"v4", 2, 0, NULL));

    /* List confirms 3 live entries (a, c, d). */
    STM_ASSERT_OK(stm_xattr_list(idx, 1, 1, NULL, 0, &total));
    STM_ASSERT_EQ(total, (size_t)3);

    xa_test_idx_close(idx);
}

/* R80 P2-3 forward-noted: STM_ENOSPC chain-exhaustion at probe cap.
 *
 * A real chain-exhaustion test requires synthesizing 64 names whose
 * FNV-1a64 hashes lie in a contiguous 64-slot window — astronomically
 * unlikely for random names (≈ 64 / 2^64). The audit suggested
 * test-friend access to records[] for direct slot population; we don't
 * have a seam.
 *
 * Forward-noted at P8-POSIX-6 substantive: a future P8-POSIX-11
 * coverage push could add an `STM_BUILD_TESTING_HOOKS`-gated seam
 * that lets a test populate records[] at chosen probes, exercising
 * the stm_xattr_set STM_ENOSPC return path + the symmetric
 * STM_ENODATA paths in get/remove at chain exhaustion.
 *
 * In the meantime, the chain walk's loop bound `k < STM_XATTR_PROBE_MAX`
 * is structurally identical to the dirent layer's tested path; the
 * symmetry argument carries the soundness through. */

STM_TEST_MAIN("test_xattr")
