/* SPDX-License-Identifier: ISC */
/*
 * 9.7-impl-6f: integration tests for the v1.0 clone surface.
 *
 * Pins the share-root mechanism + every refusal case introduced by
 * the impl-6a..6e plumbing:
 *   - stm_fs_create_clone composes set_engine_root + snapshot_hold +
 *     add_dataset_key under fs->global EX.
 *   - The clone's (di_tree_root, di_root_gen, di_root_csum) is a
 *     verbatim copy of the origin snap's triple (phase-9.7-design.md
 *     §9.1.2).
 *   - The shared root makes clone reads return the origin's frozen
 *     bytes until a clone-side COW write diverges the clone's tree.
 *   - Snap-of-clone is refused STM_ENOTSUPPORTED before any
 *     destructive step (R160 P1-1).
 *   - The sync.c-installed clone_check_cb refuses delete-origin-snap
 *     with STM_EBUSY while any clone references the snap.
 *   - The rollback cascade pre-validate refuses STM_EBUSY when any
 *     newer snap of the dataset has clones (§9.1.6 / R165 P2-1).
 *   - stm_fs_promote_clone refuses STM_ENOTSUPPORTED at v1.0.
 */
#include "tharness.h"
#include "test_fs_common.h"

#include <stratum/dataset.h>
#include <stratum/fs.h>
#include <stratum/snapshot.h>
#include <stratum/sync.h>
#include <stratum/types.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ========================================================================= */
/* Test 1: clone_create_basic — the share-root triple round-trip.            */
/* ========================================================================= */

STM_TEST(fs_clone_create_basic) {
    make_tmp("clone_basic");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Write so dataset 1's engine root is non-zero — gives the snap a
     * REAL triple to capture (not the empty-dataset sentinel). */
    uint8_t plain[4096];
    memset(plain, 0xA5, sizeof plain);
    STM_ASSERT_OK(stm_fs_write(fs, /*ds=*/1, /*ino=*/1, /*off=*/0,
                                  plain, sizeof plain));

    /* Snap-create flushes + commits internally, then captures the
     * dataset's freshly-committed (di_tree_root, di_root_gen,
     * di_root_csum) triple verbatim. */
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "snap1", 5, &snap_id));
    STM_ASSERT(snap_id != 0);

    /* Create the clone under root (parent_id=1) with origin = snap_id. */
    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, /*parent_id=*/1, "myclone",
                                         snap_id, &clone_id));
    STM_ASSERT(clone_id != 0);
    STM_ASSERT_NE(clone_id, (uint64_t)1);     /* not the root */
    STM_ASSERT_NE(clone_id, snap_id);          /* not the snap id either */

    /* Verbatim-copy invariant: clone's triple == origin snap's triple. */
    stm_sync *sync = stm_fs_sync(fs);
    STM_ASSERT(sync != NULL);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(sync);
    stm_dataset_index  *didx = stm_sync_dataset_index(sync);
    STM_ASSERT(sidx != NULL && didx != NULL);

    stm_snapshot_entry snap;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, snap_id, &snap));
    stm_dataset_entry  clone_de;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &clone_de));

    STM_ASSERT_EQ(clone_de.di_tree_root, snap.tree_root_paddr);
    STM_ASSERT_EQ(clone_de.di_root_gen,  snap.root_gen);
    STM_ASSERT_EQ(memcmp(clone_de.di_root_csum, snap.root_csum, 32), 0);

    /* Clone records its origin back-reference. */
    STM_ASSERT_EQ(clone_de.origin_snap_id, snap_id);
    STM_ASSERT_EQ(clone_de.parent_id, (uint64_t)1);

    /* impl-6e takes a snap-hold for the clone's lifetime — the snap
     * entry we just fetched is post-clone, so hold_count is ≥ 1. */
    STM_ASSERT(snap.hold_count >= 1u);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Test 2: clone_share_root_reads — clone reads return the snap's bytes.     */
/* ========================================================================= */

STM_TEST(fs_clone_share_root_reads) {
    make_tmp("clone_share");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Distinct sentinel pattern so a "wrong-extent" decode would
     * surface as a memcmp diff. */
    uint8_t src[4096];
    for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)(0x40u + (i % 17u));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, src, sizeof src));

    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "share", 5, &snap_id));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c_share", snap_id, &clone_id));

    /* Read from the CLONE — the read traverses the clone's engine,
     * which opened at the snap's captured triple. The extent record
     * encodes (origin_dataset_id, key_id) so the per-extent crypto
     * dispatch resolves the origin's DEK transparently. */
    uint8_t out[4096];
    memset(out, 0, sizeof out);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, clone_id, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(src, out, sizeof src);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Test 3: clone_cow_divergence — clone writes COW to fresh paddrs and       */
/* leave the origin's view unchanged.                                        */
/* ========================================================================= */

STM_TEST(fs_clone_cow_divergence) {
    make_tmp("clone_cow");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* X = the snap's frozen content. Y = the clone's post-divergence
     * content. */
    uint8_t x[4096], y[4096], out[4096];
    memset(x, 0xA1, sizeof x);
    memset(y, 0xB2, sizeof y);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, x, sizeof x));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "snap", 4, &snap_id));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c_cow", snap_id, &clone_id));

    /* Pre-divergence: clone reads X. */
    memset(out, 0, sizeof out);
    size_t got = 0;
    STM_ASSERT_OK(stm_fs_read(fs, clone_id, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof x);

    /* Divergence: write Y to clone — 6c/6d's clone-routing routes the
     * superseded extent paddrs to snap's dead-list rather than the
     * allocator (preserves AEAD `(paddr, write_gen)` uniqueness across
     * a future origin read of the still-shared extent). */
    STM_ASSERT_OK(stm_fs_write(fs, clone_id, 1, 0, y, sizeof y));

    /* Clone reads Y now. */
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, clone_id, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(y, out, sizeof y);

    /* The origin dataset's live tree is UNCHANGED — its own root
     * didn't move when the clone wrote (the clone has its own engine
     * with its own root triple after divergence). */
    memset(out, 0, sizeof out);
    STM_ASSERT_OK(stm_fs_read(fs, 1, 1, 0, out, sizeof out, &got));
    STM_ASSERT_EQ(got, (size_t)sizeof out);
    STM_ASSERT_MEM_EQ(x, out, sizeof x);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Test 4: clone_create_arg_validation — refusal matrix.                     */
/* ========================================================================= */

STM_TEST(fs_clone_create_arg_validation) {
    make_tmp("clone_args");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Set up a valid snap so we can isolate-test the bad-arg branches. */
    uint8_t buf[4096];
    memset(buf, 0xC3, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "valid", 5, &snap_id));

    uint64_t out = 0;

    /* NULL fs. */
    STM_ASSERT_ERR(stm_fs_create_clone(NULL, 1, "c", snap_id, &out),
                       STM_EINVAL);

    /* NULL name. */
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, NULL, snap_id, &out),
                       STM_EINVAL);

    /* NULL out. */
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, "c", snap_id, NULL),
                       STM_EINVAL);

    /* Zero parent_id. */
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 0, "c", snap_id, &out),
                       STM_EINVAL);

    /* Zero origin_snap_id — the "use create_child for non-clones"
     * refusal from the dataset layer. */
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, "c", 0, &out),
                       STM_EINVAL);

    /* Parent dataset not present. */
    STM_ASSERT_ERR(stm_fs_create_clone(fs, /*missing=*/9999, "c",
                                          snap_id, &out),
                       STM_ENOENT);

    /* Origin snap not present. */
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, "c", /*missing=*/9999, &out),
                       STM_ENOENT);

    /* Sibling-name collision: first create a clone called "dup", then
     * try a second clone with the same name + same parent. */
    uint64_t first_clone = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "dup", snap_id, &first_clone));
    STM_ASSERT(first_clone != 0);
    STM_ASSERT_ERR(stm_fs_create_clone(fs, 1, "dup", snap_id, &out),
                       STM_EEXIST);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Test 5: snap_of_clone_refused — STM_ENOTSUPPORTED + no side effect.       */
/* ========================================================================= */

STM_TEST(fs_clone_snap_of_clone_refused) {
    make_tmp("snap_of_clone");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096];
    memset(buf, 0x44, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "origin", 6, &snap_id));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "the_clone", snap_id, &clone_id));

    /* Capture pre-attempt state — clone entry + snap entry shouldn't
     * move during the failed snap attempt. */
    stm_dataset_index *didx = stm_sync_dataset_index(stm_fs_sync(fs));
    stm_dataset_entry clone_de_before;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &clone_de_before));

    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    size_t snap_count_before = 0;
    STM_ASSERT_OK(stm_snapshot_count(sidx, &snap_count_before));

    /* The refusal fires BEFORE stm_sync_commit (R160 P1-1 doctrine
     * carry), so this is a true no-op. */
    uint64_t bad_snap = 0;
    STM_ASSERT_ERR(stm_fs_create_snapshot(fs, clone_id, "fail", 4,
                                             &bad_snap),
                       STM_ENOTSUPPORTED);
    STM_ASSERT_EQ(bad_snap, (uint64_t)0);

    /* No new snap created. */
    size_t snap_count_after = 0;
    STM_ASSERT_OK(stm_snapshot_count(sidx, &snap_count_after));
    STM_ASSERT_EQ(snap_count_after, snap_count_before);

    /* Clone entry's triple is unchanged. */
    stm_dataset_entry clone_de_after;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &clone_de_after));
    STM_ASSERT_EQ(clone_de_after.di_tree_root, clone_de_before.di_tree_root);
    STM_ASSERT_EQ(clone_de_after.di_root_gen,  clone_de_before.di_root_gen);
    STM_ASSERT_EQ(memcmp(clone_de_after.di_root_csum,
                          clone_de_before.di_root_csum, 32), 0);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Test 6: origin_snap_undeletable_with_clone — clone-check cb fires.        */
/* ========================================================================= */

STM_TEST(fs_clone_origin_snap_undeletable_with_clone) {
    make_tmp("origin_undel");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096];
    memset(buf, 0x55, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "origin", 6, &snap_id));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap_id, &clone_id));

    /* Delete refused — the sync.c-installed clone_check_cb sees
     * `stm_dataset_clones_count_for_snap(snap_id) > 0` and short-
     * circuits the delete via STM_EBUSY. */
    size_t freed = 0;
    STM_ASSERT_ERR(stm_fs_delete_snapshot(fs, snap_id, &freed),
                       STM_EBUSY);

    /* The snap is still present. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    stm_snapshot_entry snap;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, snap_id, &snap));

    /* Drop the clone (no public fs-level destroy at v1.0; use the
     * index API directly — same posture as the test-only seam used
     * elsewhere in the suite). Also release the hold impl-6e took on
     * the snap so the only remaining gate is the clone-count. */
    stm_dataset_index *didx = stm_sync_dataset_index(stm_fs_sync(fs));
    STM_ASSERT_OK(stm_dataset_destroy(didx, clone_id));
    STM_ASSERT_OK(stm_fs_release_snapshot(fs, snap_id));

    /* Delete now succeeds — clones_count_for_snap returns 0 AND
     * hold_count went back to 0. */
    freed = 0;
    STM_ASSERT_OK(stm_fs_delete_snapshot(fs, snap_id, &freed));
    STM_ASSERT_ERR(stm_snapshot_lookup(sidx, snap_id, &snap), STM_ENOENT);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Test 7: rollback_refused_with_clone_on_newer_snap — cascade gate.         */
/* ========================================================================= */

STM_TEST(fs_clone_rollback_refused_with_clone_on_newer_snap) {
    make_tmp("rb_clone");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Two snapshots — S1 then S2 (newer). */
    uint8_t d1[4096], d2[4096];
    memset(d1, 0x11, sizeof d1);
    memset(d2, 0x22, sizeof d2);

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, d1, sizeof d1));
    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));

    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, d2, sizeof d2));
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT(s2 > s1);

    /* Clone of the NEWER snap (S2). */
    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "rbc", s2, &clone_id));

    /* Rollback to S1 — the cascade pre-validate (§9.1.6) refuses
     * because S2 (the newer snap that the cascade would destroy)
     * carries a clone. Refusal fires BEFORE the destructive drain. */
    STM_ASSERT_ERR(stm_fs_rollback_snapshot(fs, 1, s1, /*force=*/false),
                       STM_EBUSY);

    /* Verify no destructive step taken: both snaps still present;
     * clone still present. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s1, &e));
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s2, &e));
    stm_dataset_index *didx = stm_sync_dataset_index(stm_fs_sync(fs));
    stm_dataset_entry clone_de;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &clone_de));
    STM_ASSERT_EQ(clone_de.origin_snap_id, s2);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* Test 8: promote_clone_refused_v1 — STM_ENOTSUPPORTED stub at v1.0.        */
/* ========================================================================= */

STM_TEST(fs_clone_promote_clone_refused_v1) {
    make_tmp("promote_v1");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096];
    memset(buf, 0x77, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s", 1, &snap_id));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "c", snap_id, &clone_id));

    /* Arg-shape refusals fire upfront. */
    STM_ASSERT_ERR(stm_fs_promote_clone(NULL, clone_id), STM_EINVAL);
    STM_ASSERT_ERR(stm_fs_promote_clone(fs,   0),         STM_EINVAL);

    /* The mechanism stub itself: every other input is STM_ENOTSUPPORTED
     * (forward-defined for v1.x; phase-9.7-design.md §9.1.4). */
    STM_ASSERT_ERR(stm_fs_promote_clone(fs, clone_id), STM_ENOTSUPPORTED);

    /* The clone's origin link is UNCHANGED — the stub didn't mutate
     * anything. */
    stm_dataset_index *didx = stm_sync_dataset_index(stm_fs_sync(fs));
    stm_dataset_entry  de;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &de));
    STM_ASSERT_EQ(de.origin_snap_id, snap_id);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* R168-close regression tests (P1-1 + P2-1 + P2-2 + P2-4).                  */
/* ========================================================================= */

/* R168 P1-1 / P2-4: remount round-trip for a clone whose dataset_id
 * coincides numerically with its origin_snap_id. The 6f close commit
 * removed the namespace-confused self-reference check at the create
 * site (`stm_dataset_create_clone`) but missed the identical flawed
 * check at the load-time validator (`ds_validate_shadow` at
 * dataset.c:2293). Pre-fix this test fails STM_ECORRUPT on the
 * remount; post-fix the remount succeeds + the clone entry survives
 * with its triple intact. */
STM_TEST(fs_clone_remount_with_id_equals_origin_snap_id) {
    make_tmp("clone_remount");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Construct the id-collision scenario: two snapshots of root +
     * a clone of s2 yields clone_id == origin_snap_id == 2 (root=1
     * used the dataset slot 1, so next_dataset_id starts at 2;
     * snap_idx counter advances 1→2 across two snaps). */
    uint8_t buf[4096];
    memset(buf, 0x99, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));
    STM_ASSERT_EQ(s2, (uint64_t)2);

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "rmt", s2, &clone_id));
    STM_ASSERT_EQ(clone_id, (uint64_t)2);
    STM_ASSERT_EQ(clone_id, s2);  /* the bug-triggering coincidence */

    /* Capture the clone's triple BEFORE unmount for round-trip
     * verification. */
    stm_dataset_index *didx = stm_sync_dataset_index(stm_fs_sync(fs));
    stm_dataset_entry de_before;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &de_before));

    /* Unmount → the dirty dataset_idx persists the clone slot. */
    STM_ASSERT_OK(stm_fs_unmount(fs));
    fs = NULL;

    /* Remount — pre-fix this returns STM_ECORRUPT from
     * `ds_validate_shadow`. Post-fix it succeeds. */
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    /* Clone entry survives with the same triple. */
    didx = stm_sync_dataset_index(stm_fs_sync(fs));
    stm_dataset_entry de_after;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &de_after));
    STM_ASSERT_EQ(de_after.origin_snap_id, de_before.origin_snap_id);
    STM_ASSERT_EQ(de_after.di_tree_root,   de_before.di_tree_root);
    STM_ASSERT_EQ(de_after.di_root_gen,    de_before.di_root_gen);
    STM_ASSERT_EQ(memcmp(de_after.di_root_csum, de_before.di_root_csum, 32), 0);
    STM_ASSERT_EQ(de_after.parent_id, (uint64_t)1);

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R168 P2-1: the impl-6e clone-count gate at `stm_fs_rollback_snapshot`'s
 * newer-snap pre-validate is masked by the pre-existing `hold_count > 0`
 * check (impl-6e takes a snap hold at clone-create, so a clone-of-newer-
 * snap rollback hits the hold gate first). Test 7 verifies the COMPOSITE
 * STM_EBUSY refusal but cannot distinguish which gate fired. This variant
 * drops the hold first so the clone-count gate is the LOAD-BEARING
 * refusal. A future regression that broke ONLY the clone-count gate
 * would silently pass test 7; this variant catches it. */
STM_TEST(fs_clone_rollback_clone_count_gate_alone) {
    make_tmp("rb_gate_alone");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096];
    memset(buf, 0x11, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t s1 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s1", 2, &s1));
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t s2 = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "s2", 2, &s2));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "rbg", s2, &clone_id));

    /* Drop the snap-hold impl-6e took at create_clone time. After this:
     *   s2.hold_count = 0          (hold gate would NOT fire)
     *   clones_count_for_snap(s2) = 1  (clone-count gate WILL fire)
     * The rollback's newer-snap loop now demonstrates the new gate in
     * isolation. */
    STM_ASSERT_OK(stm_fs_release_snapshot(fs, s2));

    /* Pre-validate: hold_count check passes (0); clone-count check
     * fires (1 clone). STM_EBUSY refusal — true no-op. */
    STM_ASSERT_ERR(stm_fs_rollback_snapshot(fs, 1, s1, /*force=*/false),
                       STM_EBUSY);

    /* Verify no destructive step taken: both snaps + clone still
     * present. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s1, &e));
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, s2, &e));
    stm_dataset_index *didx = stm_sync_dataset_index(stm_fs_sync(fs));
    stm_dataset_entry de;
    STM_ASSERT_OK(stm_dataset_lookup(didx, clone_id, &de));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* R168 P2-2: the sync.c-installed clone_check_cb at `stm_snapshot_delete`
 * is masked by the pre-existing `hold_count > 0` check (test 6's first
 * delete attempt has hold_count=1 from create_clone's hold). Test 6
 * verifies the COMPOSITE STM_EBUSY refusal but cannot distinguish which
 * gate fired. This variant drops the hold first so the cb is the
 * LOAD-BEARING refusal. A future regression that broke ONLY the cb
 * registration / body would silently pass test 6; this variant catches
 * it. */
STM_TEST(fs_clone_origin_snap_undeletable_clone_check_cb_alone) {
    make_tmp("undel_cb_alone");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    uint8_t buf[4096];
    memset(buf, 0x22, sizeof buf);
    STM_ASSERT_OK(stm_fs_write(fs, 1, 1, 0, buf, sizeof buf));
    uint64_t snap_id = 0;
    STM_ASSERT_OK(stm_fs_create_snapshot(fs, 1, "cb", 2, &snap_id));

    uint64_t clone_id = 0;
    STM_ASSERT_OK(stm_fs_create_clone(fs, 1, "cb_c", snap_id, &clone_id));

    /* Drop the snap-hold impl-6e took at create_clone time. After
     * this: snap.hold_count = 0; clone is still PRESENT and still
     * references the snap. The clone_check_cb is the SOLE remaining
     * gate. */
    STM_ASSERT_OK(stm_fs_release_snapshot(fs, snap_id));

    /* Delete refused via clone_check_cb only. */
    size_t freed = 0;
    STM_ASSERT_ERR(stm_fs_delete_snapshot(fs, snap_id, &freed),
                       STM_EBUSY);

    /* Snap still present after the refused delete. */
    stm_snapshot_index *sidx = stm_sync_snapshot_index(stm_fs_sync(fs));
    stm_snapshot_entry e;
    STM_ASSERT_OK(stm_snapshot_lookup(sidx, snap_id, &e));

    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */

STM_TEST_MAIN("test_fs_clone")
