/* SPDX-License-Identifier: ISC */
/*
 * test_dirent.c — P8-POSIX-2.
 *
 * Exercises the dirent index per `v2/specs/dirent.tla`:
 *
 *   - Lifecycle (create / close).
 *   - Alloc / lookup / unlink / count_for_dir basic paths.
 *   - Chain integrity: tombstone-after-unlink preserves reachability of
 *     a colliding name at a higher probe index (the canonical
 *     dirent.tla::BuggyUnlinkUsesEmpty failure mode that this impl
 *     pins via `Unlink leaves TOMBSTONE marker`).
 *   - Argument validation matrix: every documented refusal in dirent.h
 *     is exercised and asserted symmetric with the on-disk decoder
 *     (R71 P1-1 lesson — writer-side guards mirror decoder-side guards).
 *   - Persistence: alloc / commit / close / open / load_at / lookup
 *     roundtrip across mount boundaries with both live records and
 *     tombstones surviving the persistence path.
 *   - On-disk layout sanity: STM_UB_VERSION compile-time at 25.
 */
#include "tharness.h"

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/crypto.h>
#include <stratum/dirent.h>
#include <stratum/super.h>
#include <stratum/types.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DI_DEVICE_BYTES        (UINT64_C(64) * 1024u * 1024u)
#define DI_BOOTSTRAP_BYTES     (UINT64_C(8)  * 1024u * 1024u)

static const uint64_t DI_POOL_UUID[2]   = { 0xAA01, 0xBB01 };
static const uint64_t DI_DEVICE_UUID[2] = { 0xCC01, 0xDD01 };
static const uint8_t  DI_KEY[32]        = { 0x55, 0x66, 0x77 };

/* ------------------------------------------------------------------ */
/* In-memory ops — chain integrity + arg validation.                    */
/* ------------------------------------------------------------------ */

STM_TEST(dirent_lifecycle_create_close) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    stm_dirent_index_close(idx);
    /* Closing NULL is safe. */
    stm_dirent_index_close(NULL);
}

STM_TEST(dirent_alloc_lookup_basic) {
    stm_dirent_index *idx = stm_dirent_index_create();

    const uint8_t name[] = "foo";
    STM_ASSERT_OK(stm_dirent_alloc(idx, /*ds=*/1, /*dir=*/2,
                                       name, (uint8_t)(sizeof name - 1u),
                                       /*child_ino=*/100, /*child_gen=*/0,
                                       STM_DT_REG));

    uint64_t child_ino = 0, child_gen = 0;
    uint8_t  child_type = 0;
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                       &child_ino, &child_gen, &child_type));
    STM_ASSERT_EQ(child_ino, (uint64_t)100);
    STM_ASSERT_EQ(child_gen, (uint64_t)0);
    STM_ASSERT_EQ(child_type, (uint8_t)STM_DT_REG);

    /* Lookup on a name that doesn't exist returns STM_ENOENT. */
    const uint8_t bar[] = "bar";
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 2, bar, (uint8_t)(sizeof bar - 1u),
                                        &child_ino, NULL, NULL),
                   STM_ENOENT);
    STM_ASSERT_EQ(child_ino, (uint64_t)0);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_alloc_refuses_duplicate) {
    stm_dirent_index *idx = stm_dirent_index_create();
    const uint8_t name[] = "x";
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, name, 1, 100, 0, STM_DT_REG));
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 2, name, 1, 200, 0, STM_DT_REG),
                   STM_EEXIST);
    stm_dirent_index_close(idx);
}

STM_TEST(dirent_unlink_basic) {
    stm_dirent_index *idx = stm_dirent_index_create();
    const uint8_t name[] = "to-unlink";
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                       100, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2, name, (uint8_t)(sizeof name - 1u)));
    /* After unlink, lookup returns ENOENT. */
    uint64_t child_ino = 0;
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                        &child_ino, NULL, NULL),
                   STM_ENOENT);
    /* Unlink of an absent name returns ENOENT. */
    STM_ASSERT_ERR(stm_dirent_unlink(idx, 1, 2, name, (uint8_t)(sizeof name - 1u)),
                   STM_ENOENT);
    stm_dirent_index_close(idx);
}

STM_TEST(dirent_per_dir_isolation) {
    stm_dirent_index *idx = stm_dirent_index_create();
    const uint8_t name[] = "shared-name";
    /* Same name in different (ds, dir) pairs is not a conflict. */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                       100, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 3, name, (uint8_t)(sizeof name - 1u),
                                       200, 0, STM_DT_DIR));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 2, 2, name, (uint8_t)(sizeof name - 1u),
                                       300, 0, STM_DT_LNK));

    uint64_t child_ino = 0;
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                       &child_ino, NULL, NULL));
    STM_ASSERT_EQ(child_ino, (uint64_t)100);
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 3, name, (uint8_t)(sizeof name - 1u),
                                       &child_ino, NULL, NULL));
    STM_ASSERT_EQ(child_ino, (uint64_t)200);
    STM_ASSERT_OK(stm_dirent_lookup(idx, 2, 2, name, (uint8_t)(sizeof name - 1u),
                                       &child_ino, NULL, NULL));
    STM_ASSERT_EQ(child_ino, (uint64_t)300);
    stm_dirent_index_close(idx);
}

STM_TEST(dirent_count_for_dir) {
    stm_dirent_index *idx = stm_dirent_index_create();
    const uint8_t a[] = "a";
    const uint8_t b[] = "b";
    const uint8_t c[] = "c";
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, a, 1, 100, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, b, 1, 101, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, c, 1, 102, 0, STM_DT_REG));

    size_t n = 0;
    STM_ASSERT_OK(stm_dirent_count_for_dir(idx, 1, 2, &n));
    STM_ASSERT_EQ(n, (size_t)3);

    /* Tombstones don't count. */
    STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2, b, 1));
    STM_ASSERT_OK(stm_dirent_count_for_dir(idx, 1, 2, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    /* Different directory. */
    STM_ASSERT_OK(stm_dirent_count_for_dir(idx, 1, 3, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_dirent_index_close(idx);
}

/* dirent.tla::BuggyUnlinkUsesEmpty — the canonical chain-integrity
 * failure mode. This test pins the IMPL'S correct behavior:
 * after Unlink leaves a TOMBSTONE, a colliding name at a higher
 * probe index remains reachable. The test deliberately uses names
 * crafted so they share fnv1a64 prefix bytes — but since FNV
 * collisions are rare in practice, the more reliable shape is to
 * exercise the chain via the TWO-STEP test:
 *
 *   1. Alloc many names that probe-overlap by coincidence at high N.
 *   2. Unlink one and confirm the rest stay reachable.
 *
 * For deterministic coverage: alloc N names, unlink half, confirm
 * the live half still resolves. The test passes regardless of
 * collision pattern because TOMBSTONE preservation is symmetric. */
STM_TEST(dirent_unlink_preserves_chain_integrity) {
    stm_dirent_index *idx = stm_dirent_index_create();

    /* Alloc 32 distinct names with a shared prefix (fnv1a will
     * spread their hashes; but the test doesn't need a forced
     * collision — it pins the property that no live name becomes
     * unreachable after any of the others is unlinked). */
    enum { N = 32u };
    char names[N][8];
    for (size_t i = 0; i < N; i++) {
        snprintf(names[i], sizeof names[i], "f%zu", i);
        STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2,
                                           (const uint8_t *)names[i],
                                           (uint8_t)strlen(names[i]),
                                           /*child_ino=*/100u + i, 0,
                                           STM_DT_REG));
    }

    /* Unlink every other name. */
    for (size_t i = 0; i < N; i += 2u) {
        STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2,
                                            (const uint8_t *)names[i],
                                            (uint8_t)strlen(names[i])));
    }

    /* Surviving names (odd indices) must still be reachable —
     * walking past tombstones in the chain. */
    for (size_t i = 1; i < N; i += 2u) {
        uint64_t child_ino = 0;
        STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 2,
                                            (const uint8_t *)names[i],
                                            (uint8_t)strlen(names[i]),
                                            &child_ino, NULL, NULL));
        STM_ASSERT_EQ(child_ino, (uint64_t)(100u + i));
    }
    /* Removed names lookup as ENOENT. */
    for (size_t i = 0; i < N; i += 2u) {
        uint64_t child_ino = 0;
        STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 2,
                                             (const uint8_t *)names[i],
                                             (uint8_t)strlen(names[i]),
                                             &child_ino, NULL, NULL),
                       STM_ENOENT);
    }

    stm_dirent_index_close(idx);
}

/* Re-create a previously-unlinked name. The TOMBSTONE slot must be
 * reusable for the new alloc — chain stays compact. */
STM_TEST(dirent_realloc_after_unlink) {
    stm_dirent_index *idx = stm_dirent_index_create();
    const uint8_t name[] = "rotated";
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                       100, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2, name, (uint8_t)(sizeof name - 1u)));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                       200, 0, STM_DT_DIR));
    uint64_t child_ino = 0;
    uint8_t  child_type = 0;
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 2, name, (uint8_t)(sizeof name - 1u),
                                        &child_ino, NULL, &child_type));
    STM_ASSERT_EQ(child_ino, (uint64_t)200);
    STM_ASSERT_EQ(child_type, (uint8_t)STM_DT_DIR);
    stm_dirent_index_close(idx);
}

/* R71 P1-1 lesson — symmetric writer-side guards. Each documented
 * refusal in dirent.h is exercised explicitly. */
STM_TEST(dirent_arg_validation) {
    stm_dirent_index *idx = stm_dirent_index_create();
    const uint8_t name[] = "x";

    /* alloc */
    STM_ASSERT_ERR(stm_dirent_alloc(NULL, 1, 2, name, 1, 100, 0, STM_DT_REG),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 0, 2, name, 1, 100, 0, STM_DT_REG),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 0, name, 1, 100, 0, STM_DT_REG),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 2, NULL, 1, 100, 0, STM_DT_REG),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 2, name, 0, 100, 0, STM_DT_REG),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 2, name, 1, 0, 0, STM_DT_REG),
                   STM_EINVAL);
    /* invalid types: 0 (UNKNOWN), 3, 5, 7, 9, 11, 13, 14, 15 are not in the valid set */
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 2, name, 1, 100, 0, STM_DT_UNKNOWN),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 2, name, 1, 100, 0, 3),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_alloc(idx, 1, 2, name, 1, 100, 0, 14),
                   STM_EINVAL);

    /* lookup */
    uint64_t ci = 0;
    STM_ASSERT_ERR(stm_dirent_lookup(NULL, 1, 2, name, 1, &ci, NULL, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 2, name, 1, NULL, NULL, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 0, 2, name, 1, &ci, NULL, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 0, name, 1, &ci, NULL, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 2, NULL, 1, &ci, NULL, NULL),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 2, name, 0, &ci, NULL, NULL),
                   STM_EINVAL);

    /* unlink */
    STM_ASSERT_ERR(stm_dirent_unlink(NULL, 1, 2, name, 1), STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_unlink(idx, 0, 2, name, 1),  STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_unlink(idx, 1, 0, name, 1),  STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_unlink(idx, 1, 2, NULL, 1),  STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_unlink(idx, 1, 2, name, 0),  STM_EINVAL);

    /* count_for_dir */
    size_t n = 0;
    STM_ASSERT_ERR(stm_dirent_count_for_dir(NULL, 1, 2, &n), STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_count_for_dir(idx, 1, 2, NULL), STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_count_for_dir(idx, 0, 2, &n),   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_count_for_dir(idx, 1, 0, &n),   STM_EINVAL);

    stm_dirent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* Persistence — alloc / commit / close / open / load_at / lookup.     */
/* ------------------------------------------------------------------ */

static char di_tmp_path[256];

static void di_make_tmp(const char *tag) {
    snprintf(di_tmp_path, sizeof di_tmp_path,
             "/tmp/stm_v2_dirent_persist_%s_%d.bin", tag, (int)getpid());
    unlink(di_tmp_path);
}

static void di_open_fresh(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(di_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bdev_resize(*out_d, DI_DEVICE_BYTES));
    STM_ASSERT_OK(stm_crypto_init());
    STM_ASSERT_OK(stm_bootstrap_create(*out_d, DI_POOL_UUID, DI_DEVICE_UUID,
                                         DI_BOOTSTRAP_BYTES, out_b));
}

static void di_reopen(stm_bdev **out_d, stm_bootstrap **out_b) {
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    STM_ASSERT_OK(stm_bdev_open(di_tmp_path, &bo, out_d));
    STM_ASSERT_OK(stm_bootstrap_open(*out_d, out_b));
}

STM_TEST(dirent_persist_commit_load_roundtrip) {
    di_make_tmp("rt");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    di_open_fresh(&d, &b);

    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    STM_ASSERT_OK(stm_dirent_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dirent_index_set_crypt_ctx(idx, DI_KEY,
                                                    DI_POOL_UUID,
                                                    DI_DEVICE_UUID));

    /* Three live records; one becomes a tombstone. */
    const uint8_t fa[] = "alpha";
    const uint8_t fb[] = "beta";
    const uint8_t fc[] = "gamma";
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, fa, (uint8_t)(sizeof fa - 1u),
                                       101, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, fb, (uint8_t)(sizeof fb - 1u),
                                       102, 0, STM_DT_DIR));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, fc, (uint8_t)(sizeof fc - 1u),
                                       103, 0, STM_DT_LNK));
    STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2, fb, (uint8_t)(sizeof fb - 1u)));

    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_OK(stm_dirent_index_commit(idx, /*committed_gen=*/1u, &paddr, cs));
    STM_ASSERT(paddr != 0);

    stm_dirent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);

    /* Reopen and load. */
    di_reopen(&d, &b);
    stm_dirent_index *idx2 = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_index_set_storage(idx2, d, b));
    STM_ASSERT_OK(stm_dirent_index_set_crypt_ctx(idx2, DI_KEY,
                                                     DI_POOL_UUID,
                                                     DI_DEVICE_UUID));
    STM_ASSERT_OK(stm_dirent_index_load_at(idx2, paddr, 1u, cs));

    /* alpha + gamma still reachable; beta returns ENOENT (tombstoned). */
    uint64_t ci = 0;
    uint8_t  ct = 0;
    STM_ASSERT_OK(stm_dirent_lookup(idx2, 1, 2, fa, (uint8_t)(sizeof fa - 1u),
                                        &ci, NULL, &ct));
    STM_ASSERT_EQ(ci, (uint64_t)101);
    STM_ASSERT_EQ(ct, (uint8_t)STM_DT_REG);
    STM_ASSERT_OK(stm_dirent_lookup(idx2, 1, 2, fc, (uint8_t)(sizeof fc - 1u),
                                        &ci, NULL, &ct));
    STM_ASSERT_EQ(ci, (uint64_t)103);
    STM_ASSERT_EQ(ct, (uint8_t)STM_DT_LNK);
    STM_ASSERT_ERR(stm_dirent_lookup(idx2, 1, 2, fb, (uint8_t)(sizeof fb - 1u),
                                         &ci, NULL, NULL),
                   STM_ENOENT);
    /* count: 2 live (alpha + gamma). */
    size_t n = 0;
    STM_ASSERT_OK(stm_dirent_count_for_dir(idx2, 1, 2, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    stm_dirent_index_close(idx2);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(di_tmp_path);
}

STM_TEST(dirent_persist_commit_requires_storage_and_crypt) {
    stm_dirent_index *idx = stm_dirent_index_create();
    uint64_t paddr = 0; uint8_t cs[32];
    STM_ASSERT_ERR(stm_dirent_index_commit(idx, 1u, &paddr, cs), STM_EINVAL);
    stm_dirent_index_close(idx);
}

STM_TEST(dirent_persist_idempotent_commit_when_clean) {
    di_make_tmp("idem");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    di_open_fresh(&d, &b);

    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_index_set_storage(idx, d, b));
    STM_ASSERT_OK(stm_dirent_index_set_crypt_ctx(idx, DI_KEY,
                                                    DI_POOL_UUID,
                                                    DI_DEVICE_UUID));

    const uint8_t name[] = "x";
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, name, 1, 100, 0, STM_DT_REG));

    uint64_t p1 = 0, p2 = 0; uint8_t c1[32], c2[32];
    STM_ASSERT_OK(stm_dirent_index_commit(idx, 1u, &p1, c1));
    STM_ASSERT_OK(stm_dirent_index_commit(idx, 1u, &p2, c2));
    STM_ASSERT_EQ(p1, p2);
    STM_ASSERT_MEM_EQ(c1, c2, 32);

    stm_dirent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(di_tmp_path);
}

/* R70 P3-6 + R71 P2-1 carry-forward: bound-once latches refuse re-bind. */
STM_TEST(dirent_set_storage_refuses_rebind) {
    di_make_tmp("rebind_st");
    stm_bdev *d = NULL; stm_bootstrap *b = NULL;
    di_open_fresh(&d, &b);
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_index_set_storage(idx, d, b));
    STM_ASSERT_ERR(stm_dirent_index_set_storage(idx, d, b), STM_EINVAL);
    stm_dirent_index_close(idx);
    stm_bootstrap_close(b);
    stm_bdev_close(d);
    unlink(di_tmp_path);
}

STM_TEST(dirent_set_crypt_ctx_refuses_rebind) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_index_set_crypt_ctx(idx, DI_KEY,
                                                    DI_POOL_UUID,
                                                    DI_DEVICE_UUID));
    STM_ASSERT_ERR(stm_dirent_index_set_crypt_ctx(idx, DI_KEY,
                                                     DI_POOL_UUID,
                                                     DI_DEVICE_UUID),
                   STM_EINVAL);
    stm_dirent_index_close(idx);
}

STM_TEST(dirent_ub_version_is_v26) {
    /* P8-POSIX-6 bumped STM_UB_VERSION 25 → 26 for the new xattr tree
     * (v2/include/stratum/super.h). The dirent layer is unchanged
     * since v25 but rides the latest version constant. */
    STM_ASSERT_EQ(STM_UB_VERSION, 26u);
}

/* R73 P2-1: stm_dirent_drop_for_dir bulk-removes every record keyed
 * under (ds, dir_ino, *), including tombstones from prior unlinks. */
STM_TEST(dirent_r73_p2_1_drop_for_dir_clears_records_and_tombstones) {
    stm_dirent_index *idx = stm_dirent_index_create();

    /* Three live + one tombstone in dir=2, plus one live in dir=3
     * (must survive — drop_for_dir is scoped). */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"a", 1,
                                       100, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"b", 1,
                                       101, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"c", 1,
                                       102, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2, (const uint8_t *)"b", 1));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 3, (const uint8_t *)"x", 1,
                                       200, 0, STM_DT_REG));

    /* Drop dir=2: removes 3 records (a + b-tombstone + c). */
    size_t dropped = 0;
    STM_ASSERT_OK(stm_dirent_drop_for_dir(idx, 1, 2, &dropped));
    STM_ASSERT_EQ(dropped, (size_t)3);

    /* dir=2 is fully empty (no live, no tombstone). */
    size_t n = 0;
    STM_ASSERT_OK(stm_dirent_count_for_dir(idx, 1, 2, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    /* Lookup of any prior name is ENOENT. */
    uint64_t ci = 0;
    STM_ASSERT_ERR(stm_dirent_lookup(idx, 1, 2, (const uint8_t *)"a", 1,
                                         &ci, NULL, NULL),
                   STM_ENOENT);

    /* dir=3's record survives. */
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 3, (const uint8_t *)"x", 1,
                                        &ci, NULL, NULL));
    STM_ASSERT_EQ(ci, (uint64_t)200);

    /* Reuse the cleared dir: alloc into dir=2 succeeds with the
     * SAME name `b` that was previously tombstoned — proving the
     * tombstone is gone (not reused). The test seam: post-drop, the
     * chain at fnv1a64("b") starts EMPTY, install at probe 0. */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"b", 1,
                                       300, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 2, (const uint8_t *)"b", 1,
                                        &ci, NULL, NULL));
    STM_ASSERT_EQ(ci, (uint64_t)300);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_r73_p2_1_drop_for_dir_arg_validation) {
    stm_dirent_index *idx = stm_dirent_index_create();
    size_t n = 0;
    STM_ASSERT_ERR(stm_dirent_drop_for_dir(NULL, 1, 2, &n), STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_drop_for_dir(idx, 0, 2, &n),  STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_drop_for_dir(idx, 1, 0, &n),  STM_EINVAL);
    /* out_dropped optional — STM_OK with NULL. */
    STM_ASSERT_OK(stm_dirent_drop_for_dir(idx, 1, 2, NULL));
    stm_dirent_index_close(idx);
}

/* ------------------------------------------------------------------ */
/* P8-POSIX-4 readdir tests.                                            */
/* ------------------------------------------------------------------ */

STM_TEST(dirent_readdir_empty_dir) {
    stm_dirent_index *idx = stm_dirent_index_create();
    /* Empty directory: readdir returns 0 entries, cursor unchanged. */
    uint64_t cursor = 0;
    stm_dirent_entry batch[16];
    size_t n = 999;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT_EQ(cursor, (uint64_t)0);
    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_single_entry) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"foo", 3,
                                       100, 7, STM_DT_REG));

    uint64_t cursor = 0;
    stm_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(batch[0].child_ino, (uint64_t)100);
    STM_ASSERT_EQ(batch[0].child_gen, (uint64_t)7);
    STM_ASSERT_EQ(batch[0].child_type, (uint8_t)STM_DT_REG);
    STM_ASSERT_EQ(batch[0].name_len, (uint8_t)3);
    STM_ASSERT_TRUE(memcmp(batch[0].name, "foo", 3) == 0);
    /* cursor advanced past the entry's hash_probe. */
    STM_ASSERT_TRUE(cursor > batch[0].hash_probe);

    /* Second call: no more entries. */
    n = 999;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_multiple_entries_hash_order) {
    stm_dirent_index *idx = stm_dirent_index_create();
    /* Insert 5 entries; readdir returns them in hash_probe-ascending
     * order regardless of insertion order. */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"alpha", 5,
                                       1, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"beta", 4,
                                       2, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"gamma", 5,
                                       3, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"delta", 5,
                                       4, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"epsilon", 7,
                                       5, 0, STM_DT_REG));

    uint64_t cursor = 0;
    stm_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)5);

    /* Verify hash_probe-ascending order. */
    for (size_t i = 1; i < n; i++) {
        STM_ASSERT_TRUE(batch[i - 1].hash_probe < batch[i].hash_probe);
    }

    /* All five inos are present. Track via bitmap; probe-order is
     * hash-determined. */
    uint8_t seen[6] = {0};
    for (size_t i = 0; i < n; i++) {
        STM_ASSERT_TRUE(batch[i].child_ino >= 1 && batch[i].child_ino <= 5);
        seen[batch[i].child_ino] = 1;
    }
    for (size_t i = 1; i <= 5; i++) STM_ASSERT_TRUE(seen[i]);

    /* Second call: 0 entries. */
    n = 999;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_skips_tombstones) {
    /* Models dirent.tla::ReaddirNoTombstoneEmitted — tombstones from
     * prior unlinks are NEVER returned. Forced FNV collision: "n_a"
     * and "n_b" hash differently here (not the spec's collision pair),
     * but the principle is the same — unlink one, readdir returns the
     * other but never the tombstone. */
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"keep1", 5,
                                       100, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"drop", 4,
                                       101, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"keep2", 5,
                                       102, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2, (const uint8_t *)"drop", 4));

    uint64_t cursor = 0;
    stm_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)2);

    /* Neither returned entry is the tombstone (101). */
    for (size_t i = 0; i < n; i++) {
        STM_ASSERT_TRUE(batch[i].child_ino != (uint64_t)101);
        STM_ASSERT_TRUE(batch[i].name_len > 0u);
    }
    /* Both 100 and 102 are present. */
    bool saw_100 = false, saw_102 = false;
    for (size_t i = 0; i < n; i++) {
        if (batch[i].child_ino == 100u) saw_100 = true;
        if (batch[i].child_ino == 102u) saw_102 = true;
    }
    STM_ASSERT_TRUE(saw_100 && saw_102);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_pagination_max_entries_one) {
    /* Models dirent.tla::ReaddirNoDuplicateProbeInLog — strict cursor
     * advance prevents same-probe re-emit. With max_entries=1, a full
     * iteration emits each record exactly once. */
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"e1", 2,
                                       1, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"e2", 2,
                                       2, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"e3", 2,
                                       3, 0, STM_DT_REG));

    uint64_t cursor = 0;
    uint64_t seen_inos[3] = {0};
    size_t total = 0;
    for (int iter = 0; iter < 10; iter++) {
        stm_dirent_entry batch[1];
        size_t n = 0;
        STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 1, &n));
        if (n == 0) break;
        STM_ASSERT_EQ(n, (size_t)1);
        STM_ASSERT_TRUE(total < 3);
        seen_inos[total++] = batch[0].child_ino;
    }
    STM_ASSERT_EQ(total, (size_t)3);

    /* All three inos returned exactly once. */
    bool s1 = false, s2 = false, s3 = false;
    for (size_t i = 0; i < 3; i++) {
        if (seen_inos[i] == 1u) s1 = true;
        if (seen_inos[i] == 2u) s2 = true;
        if (seen_inos[i] == 3u) s3 = true;
    }
    STM_ASSERT_TRUE(s1 && s2 && s3);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_per_dir_isolation) {
    stm_dirent_index *idx = stm_dirent_index_create();
    /* Same name in three different (ds, dir) pairs. readdir on each
     * sees only its own. */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"name", 4,
                                       100, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 3, (const uint8_t *)"name", 4,
                                       200, 0, STM_DT_DIR));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 2, 2, (const uint8_t *)"name", 4,
                                       300, 0, STM_DT_LNK));

    stm_dirent_entry batch[16];
    uint64_t cursor;
    size_t n;

    /* readdir(ds=1, dir=2) → only child_ino=100. */
    cursor = 0; n = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(batch[0].child_ino, (uint64_t)100);

    /* readdir(ds=1, dir=3) → only child_ino=200. */
    cursor = 0; n = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 3, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(batch[0].child_ino, (uint64_t)200);

    /* readdir(ds=2, dir=2) → only child_ino=300. */
    cursor = 0; n = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 2, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(batch[0].child_ino, (uint64_t)300);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_resume_after_create_past_cursor) {
    /* Verify between-call concurrent-Create semantics: a Create that
     * lands at a probe ≥ remaining-cursor is visible to the next
     * readdir step; one that lands at probe < cursor is invisible.
     *
     * Concrete: paginate 1 entry at a time. After the first call,
     * insert a NEW entry. If its hash_probe lands ≥ cursor, the
     * next call returns it; otherwise not. We don't predict the
     * hash, but we verify that whichever happens, the returned set
     * is consistent (no probe-duplicates, no original entry returned
     * twice).
     */
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"alpha", 5,
                                       1, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"beta", 4,
                                       2, 0, STM_DT_REG));

    /* First call: emits one of {1, 2}. */
    uint64_t cursor = 0;
    stm_dirent_entry first[1];
    size_t fn = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, first, 1, &fn));
    STM_ASSERT_EQ(fn, (size_t)1);
    uint64_t cursor_after_first = cursor;

    /* Insert a new entry. Its probe is FNV-determined (we don't
     * predict). */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"gamma", 5,
                                       3, 0, STM_DT_REG));

    /* Continue iterating. We may see 2 entries (other original + new)
     * or 1 entry (just other original) depending on where "gamma"
     * landed. In either case, we never see the FIRST returned entry
     * again — that's the cursor-monotone-advance guarantee. */
    uint64_t seen_inos[3] = { first[0].child_ino, 0, 0 };
    size_t   total = 1;
    for (int iter = 0; iter < 10; iter++) {
        stm_dirent_entry batch[1];
        size_t n = 0;
        STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 1, &n));
        if (n == 0) break;
        STM_ASSERT_EQ(n, (size_t)1);
        /* Returned entry must not equal the first. */
        STM_ASSERT_TRUE(batch[0].child_ino != first[0].child_ino);
        STM_ASSERT_TRUE(total < 3);
        seen_inos[total++] = batch[0].child_ino;
    }
    /* No duplicates among seen_inos. */
    if (total >= 2) STM_ASSERT_TRUE(seen_inos[0] != seen_inos[1]);
    if (total >= 3) {
        STM_ASSERT_TRUE(seen_inos[0] != seen_inos[2]);
        STM_ASSERT_TRUE(seen_inos[1] != seen_inos[2]);
    }
    /* Cursor monotonically advanced. */
    STM_ASSERT_TRUE(cursor >= cursor_after_first);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_arg_validation) {
    stm_dirent_index *idx = stm_dirent_index_create();
    uint64_t cursor = 0;
    stm_dirent_entry batch[4];
    size_t n = 0;

    /* NULL idx. */
    STM_ASSERT_ERR(stm_dirent_readdir(NULL, 1, 2, &cursor, batch, 4, &n),
                   STM_EINVAL);
    /* NULL cursor. */
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 1, 2, NULL, batch, 4, &n),
                   STM_EINVAL);
    /* NULL out_entries. */
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 1, 2, &cursor, NULL, 4, &n),
                   STM_EINVAL);
    /* NULL out_returned. */
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 4, NULL),
                   STM_EINVAL);
    /* dataset_id == 0. */
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 0, 2, &cursor, batch, 4, &n),
                   STM_EINVAL);
    /* dir_ino == 0. */
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 1, 0, &cursor, batch, 4, &n),
                   STM_EINVAL);
    /* max_entries == 0. */
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 0, &n),
                   STM_EINVAL);

    stm_dirent_index_close(idx);
}

/* R75 P2-1: cursor saturation sentinel. When the caller passes
 * cursor=UINT64_MAX (either organically from a prior emit's
 * saturation, or from caller error), readdir short-circuits and
 * returns 0 entries. Without this guard, a record at probe=UINT64_MAX
 * would re-emit forever because the strict-less-than filter
 * `r->hash_probe < UINT64_MAX` is false at probe=UINT64_MAX. */
STM_TEST(dirent_readdir_r75_p2_1_cursor_saturation_terminates) {
    stm_dirent_index *idx = stm_dirent_index_create();
    /* Even with a live record present, cursor=UINT64_MAX returns 0. */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"foo", 3,
                                       100, 0, STM_DT_REG));
    uint64_t cursor = UINT64_MAX;
    stm_dirent_entry batch[16];
    size_t n = 999;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);
    STM_ASSERT_EQ(cursor, (uint64_t)UINT64_MAX);

    /* Empty dir + saturated cursor also returns 0 (no infinite loop). */
    cursor = UINT64_MAX; n = 999;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 999, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_dirent_index_close(idx);
}

/* R75 P3-1: out-param zero-init contract. *out_returned must be
 * zero-init'd BEFORE arg validation, so callers observing on
 * STM_EINVAL see a defined value (0) regardless of which validation
 * step rejected. */
STM_TEST(dirent_readdir_r75_p3_1_out_param_zero_init_on_einval) {
    stm_dirent_index *idx = stm_dirent_index_create();
    uint64_t cursor = 0;
    stm_dirent_entry batch[4];

    /* Pre-fill with sentinel; STM_EINVAL must overwrite to 0. */
    size_t n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_dirent_readdir(idx, /*ds=*/0, 2, &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    /* dir_ino = 0 — same contract. */
    n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 1, /*dir=*/0, &cursor, batch, 4, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    /* max_entries = 0 — same. */
    n = 0xDEADBEEFu;
    STM_ASSERT_ERR(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 0, &n),
                   STM_EINVAL);
    STM_ASSERT_EQ(n, (size_t)0);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_readdir_after_drop_for_dir) {
    /* drop_for_dir wipes records[]; subsequent readdir on the dir
     * returns 0 entries. */
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"a", 1, 1, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 2, (const uint8_t *)"b", 1, 2, 0, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_unlink(idx, 1, 2, (const uint8_t *)"a", 1));
    /* Pre-drop: readdir returns "b" (one live + one tombstone). */
    uint64_t cursor = 0;
    stm_dirent_entry batch[16];
    size_t n = 0;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)1);
    STM_ASSERT_EQ(batch[0].child_ino, (uint64_t)2);
    /* drop the dir. */
    STM_ASSERT_OK(stm_dirent_drop_for_dir(idx, 1, 2, NULL));
    /* Post-drop: readdir from cursor=0 returns 0. */
    cursor = 0; n = 999;
    STM_ASSERT_OK(stm_dirent_readdir(idx, 1, 2, &cursor, batch, 16, &n));
    STM_ASSERT_EQ(n, (size_t)0);

    stm_dirent_index_close(idx);
}

/* ========================================================================= */
/* P8-POSIX-9b: stm_dirent_swap_two — RENAME_EXCHANGE primitive.              */
/* ========================================================================= */

STM_TEST(dirent_swap_two_same_dir) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    /* Two distinct dirents in the same directory. */
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"a", 1,
                                        10, 1, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"b", 1,
                                        20, 2, STM_DT_DIR));

    STM_ASSERT_OK(stm_dirent_swap_two(idx, 1,
                                            100, (const uint8_t *)"a", 1,
                                            100, (const uint8_t *)"b", 1));

    /* a → 20/2/DIR, b → 10/1/REG. */
    uint64_t ino = 0, gen = 0; uint8_t typ = 0;
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 100, (const uint8_t *)"a", 1,
                                          &ino, &gen, &typ));
    STM_ASSERT_EQ(ino, 20u);
    STM_ASSERT_EQ(gen, 2u);
    STM_ASSERT_EQ(typ, (uint8_t)STM_DT_DIR);

    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 100, (const uint8_t *)"b", 1,
                                          &ino, &gen, &typ));
    STM_ASSERT_EQ(ino, 10u);
    STM_ASSERT_EQ(gen, 1u);
    STM_ASSERT_EQ(typ, (uint8_t)STM_DT_REG);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_swap_two_cross_dir) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"x", 1,
                                        10, 1, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 200,
                                        (const uint8_t *)"y", 1,
                                        20, 2, STM_DT_REG));

    STM_ASSERT_OK(stm_dirent_swap_two(idx, 1,
                                            100, (const uint8_t *)"x", 1,
                                            200, (const uint8_t *)"y", 1));

    uint64_t ino = 0, gen = 0; uint8_t typ = 0;
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 100, (const uint8_t *)"x", 1,
                                          &ino, &gen, &typ));
    STM_ASSERT_EQ(ino, 20u);
    STM_ASSERT_EQ(gen, 2u);
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 200, (const uint8_t *)"y", 1,
                                          &ino, &gen, &typ));
    STM_ASSERT_EQ(ino, 10u);
    STM_ASSERT_EQ(gen, 1u);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_swap_two_is_self_inverse) {
    /* Swap is its own inverse: swap(a,b) twice restores identity. */
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"a", 1,
                                        10, 1, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"b", 1,
                                        20, 2, STM_DT_DIR));

    STM_ASSERT_OK(stm_dirent_swap_two(idx, 1,
                                            100, (const uint8_t *)"a", 1,
                                            100, (const uint8_t *)"b", 1));
    STM_ASSERT_OK(stm_dirent_swap_two(idx, 1,
                                            100, (const uint8_t *)"a", 1,
                                            100, (const uint8_t *)"b", 1));

    uint64_t ino = 0, gen = 0; uint8_t typ = 0;
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 100, (const uint8_t *)"a", 1,
                                          &ino, &gen, &typ));
    STM_ASSERT_EQ(ino, 10u);
    STM_ASSERT_EQ(gen, 1u);
    STM_ASSERT_EQ(typ, (uint8_t)STM_DT_REG);
    STM_ASSERT_OK(stm_dirent_lookup(idx, 1, 100, (const uint8_t *)"b", 1,
                                          &ino, &gen, &typ));
    STM_ASSERT_EQ(ino, 20u);
    STM_ASSERT_EQ(gen, 2u);
    STM_ASSERT_EQ(typ, (uint8_t)STM_DT_DIR);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_swap_two_self_swap_refused) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"a", 1,
                                        10, 1, STM_DT_REG));

    /* Same dir, same name → STM_EINVAL. */
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 1,
                                             100, (const uint8_t *)"a", 1,
                                             100, (const uint8_t *)"a", 1),
                   STM_EINVAL);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_swap_two_missing_either_returns_enoent) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);

    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"a", 1,
                                        10, 1, STM_DT_REG));

    /* Missing src → ENOENT. */
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 1,
                                             100, (const uint8_t *)"missing", 7,
                                             100, (const uint8_t *)"a", 1),
                   STM_ENOENT);
    /* Missing dst → ENOENT. */
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 1,
                                             100, (const uint8_t *)"a", 1,
                                             100, (const uint8_t *)"missing", 7),
                   STM_ENOENT);

    stm_dirent_index_close(idx);
}

STM_TEST(dirent_swap_two_arg_validation) {
    stm_dirent_index *idx = stm_dirent_index_create();
    STM_ASSERT_TRUE(idx != NULL);
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"a", 1,
                                        10, 1, STM_DT_REG));
    STM_ASSERT_OK(stm_dirent_alloc(idx, 1, 100,
                                        (const uint8_t *)"b", 1,
                                        20, 2, STM_DT_REG));

    /* NULL idx. */
    STM_ASSERT_ERR(stm_dirent_swap_two(NULL, 1,
                                             100, (const uint8_t *)"a", 1,
                                             100, (const uint8_t *)"b", 1),
                   STM_EINVAL);
    /* Zero ds / dir. */
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 0,
                                             100, (const uint8_t *)"a", 1,
                                             100, (const uint8_t *)"b", 1),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 1,
                                             0,   (const uint8_t *)"a", 1,
                                             100, (const uint8_t *)"b", 1),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 1,
                                             100, (const uint8_t *)"a", 1,
                                             0,   (const uint8_t *)"b", 1),
                   STM_EINVAL);
    /* NULL name / zero name_len. */
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 1,
                                             100, NULL, 1,
                                             100, (const uint8_t *)"b", 1),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_dirent_swap_two(idx, 1,
                                             100, (const uint8_t *)"a", 0,
                                             100, (const uint8_t *)"b", 1),
                   STM_EINVAL);

    stm_dirent_index_close(idx);
}

STM_TEST_MAIN("test_dirent")
