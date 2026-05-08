# ---------------------------------------------------------------------------
# Test harness library (stm_testlib) shared by every test binary.
# ---------------------------------------------------------------------------

add_library(stm_testlib STATIC
    tharness.c)

target_include_directories(stm_testlib PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_testlib
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stratum)

# ---------------------------------------------------------------------------
# A tiny macro to declare a test and register with ctest.
# ---------------------------------------------------------------------------

function(stm_add_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE stm_testlib stratum
                                          stm_warnings stm_sanitize stm_coverage)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT 60)
endfunction()

# Special timeout for test_btree_lf — the long-stress test can run for
# a user-configurable duration via STM_BT_LF_LONG_SEC (default 2s).
# Operators running 1h+ sustained passes should override ctest timeout
# with --timeout=0 or set a large value; the CMakeLists default here
# only needs to accommodate the short default run path.

# ---------------------------------------------------------------------------
# Individual test binaries.
# ---------------------------------------------------------------------------

stm_add_test(test_types      test_types.c)
stm_add_test(test_hash       test_hash.c)
stm_add_test(test_crypto     test_crypto.c)
stm_add_test(test_hybrid     test_hybrid.c)
stm_add_test(test_bdev       test_bdev.c)
stm_add_test(test_bdev_async test_bdev_async.c)
stm_add_test(test_ebr        test_ebr.c)
stm_add_test(test_btree      test_btree.c)
stm_add_test(test_btree_mt   test_btree_mt.c)
stm_add_test(test_btree_lf   test_btree_lf.c)
stm_add_test(test_sb         test_sb.c)
stm_add_test(test_bootstrap  test_bootstrap.c)
stm_add_test(test_btnode     test_btnode.c)
stm_add_test(test_btree_store test_btree_store.c)
stm_add_test(test_alloc      test_alloc.c)
stm_add_test(test_alloc_roots test_alloc_roots.c)
stm_add_test(test_sync       test_sync.c)
stm_add_test(test_fs         test_fs.c       test_fs_common.c)
stm_add_test(test_fs_phase8  test_fs_phase8.c test_fs_common.c)
stm_add_test(test_sdarray    test_sdarray.c)
stm_add_test(test_xor_filter test_xor_filter.c)
stm_add_test(test_crash_inject test_crash_inject.c)
stm_add_test(test_extent     test_extent.c)
stm_add_test(test_extent_index test_extent_index.c)
stm_add_test(test_cas_index    test_cas_index.c)
stm_add_test(test_p9         test_p9.c)
stm_add_test(test_janus      test_janus.c)
stm_add_test(test_keyschema_rotate test_keyschema_rotate.c)
stm_add_test(test_keyfile_passphrase test_keyfile_passphrase.c)
stm_add_test(test_pool       test_pool.c)
stm_add_test(test_sync_multi test_sync_multi.c)
stm_add_test(test_scrub      test_scrub.c)
stm_add_test(test_cdc        test_cdc.c)
stm_add_test(test_dataset    test_dataset.c)
stm_add_test(test_snapshot   test_snapshot.c)
stm_add_test(test_send_recv  test_send_recv.c)
stm_add_test(test_repair_log test_repair_log.c)
stm_add_test(test_inode      test_inode.c)
stm_add_test(test_dirent     test_dirent.c)
stm_add_test(test_xattr      test_xattr.c)
stm_add_test(test_locks      test_locks.c)
stm_add_test(test_9p         test_9p.c       test_fs_common.c)
stm_add_test(test_9p_socket  test_9p_socket.c test_fs_common.c)
target_link_libraries(test_9p_socket PRIVATE stm_stratumd)
stm_add_test(test_9p_client  test_9p_client.c test_fs_common.c)
target_link_libraries(test_9p_client PRIVATE stm_stratumd stm_9p_client)
stm_add_test(test_ctl        test_ctl.c      test_fs_common.c)
target_link_libraries(test_ctl PRIVATE stm_lp9)
stm_add_test(test_lp9        test_lp9.c)
target_link_libraries(test_lp9 PRIVATE stm_lp9)
stm_add_test(test_stratum_fs test_stratum_fs.c test_fs_common.c)
target_link_libraries(test_stratum_fs PRIVATE stm_stratumd)
stm_add_test(test_stratumd_ctl test_stratumd_ctl.c test_fs_common.c)
target_link_libraries(test_stratumd_ctl PRIVATE stm_stratumd stm_9p_client stm_lp9)
stm_add_test(test_slate test_slate.c)
target_link_libraries(test_slate PRIVATE stm_slate stm_lp9)
stm_add_test(test_slate_socket test_slate_socket.c)
target_link_libraries(test_slate_socket PRIVATE stm_slate stm_lp9 stm_stratumd stm_9p_client)
# stratum-fs binary path passed in via env so the test can fork/exec it.
set_tests_properties(test_stratum_fs PROPERTIES
    ENVIRONMENT "STM_STRATUM_FS_BIN=$<TARGET_FILE:stratum-fs>"
    TIMEOUT 120)

# test_stratumd_ctl forks a worker thread to serve /ctl/ over a Unix
# socket and runs ~8 retry-dial-bounded sub-tests. Solo runs finish in
# < 1 s, but under heavy parallel ctest load (slate's 2-slate e2e
# fixture pumps the same /tmp socket-allocation path) the cumulative
# retry-dial wait can push the run past the default 60 s. Bumping to
# 180 s matches test_fs's discipline for stratumd-style integration
# tests.
set_tests_properties(test_stratumd_ctl PROPERTIES TIMEOUT 180)
# test_slate_socket spawns multiple slate instances in the SLATE-2
# e2e attach test (one foreground + one backend), each with its own
# accept thread and per-connection worker pool. Bump for parallel
# resilience.
set_tests_properties(test_slate_socket PROPERTIES TIMEOUT 120)

# The crash-injection fuzzer runs ~168 independent format+mount+unmount
# cycles. Original default budget was ~25 s on default, ~42 s under
# ASan/TSan; subsequent chunks (P7-3 extent index, P7-15 repair-log)
# added per-cycle metadata-tree commits that compound under TSan's
# mutex instrumentation. Pre-P7-15 the TSan run was ~120 s; P7-15
# pushed it past the 180 s cap on contention-heavy CI runs. Bumped to
# 300 s to give comfortable headroom; the underlying test work hasn't
# regressed in correctness, just runtime under instrumentation.
set_tests_properties(test_crash_inject PROPERTIES TIMEOUT 300)

# test_fs + test_fs_phase8 each format/mount/unmount per test
# (~150ms wall under -j2 with ASan/TSan). Pre-split, the combined
# 322-test test_fs took ~80s. Post-split: ~150-test test_fs (Phase
# 1-7) ~40s; ~170-test test_fs_phase8 ~50s. Bump both to 180s
# (1.5x headroom for parallel pressure / sanitizer slowdown).
set_tests_properties(test_fs        PROPERTIES TIMEOUT 180)
set_tests_properties(test_fs_phase8 PROPERTIES TIMEOUT 180)
