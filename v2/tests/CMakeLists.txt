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
stm_add_test(test_alloc      test_alloc.c)
