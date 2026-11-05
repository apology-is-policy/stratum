add_library(stm_snapshot STATIC
    snapshot.c)

target_include_directories(stm_snapshot PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_snapshot
    PRIVATE stm_warnings stm_sanitize stm_coverage)

# R46 P2-1: gate stm_snapshot_create_for_test (the chain-ordering
# bypass used by the on-disk validator regression test) behind a
# compile-time flag. Default ON to keep the test-tree build flowing;
# production builds opt out with `-DSTRATUM_BUILD_TESTING_HOOKS=OFF`
# at configure time. PUBLIC so consumers (test_snapshot, test_fs)
# see the prototype in <stratum/snapshot_testing.h> and the symbol
# exists in the archive they link.
if(STRATUM_BUILD_TESTING_HOOKS)
    target_compile_definitions(stm_snapshot PUBLIC STRATUM_BUILD_TESTING_HOOKS)
endif()
