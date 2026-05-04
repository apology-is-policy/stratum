add_library(stm_dirent STATIC dirent.c)

target_include_directories(stm_dirent PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_dirent
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_block stm_bootstrap stm_btree stm_btree_store
            stm_sb Threads::Threads)

# P8-POSIX-9b R88 P2-1: gate stm_dirent_install_at_probe_for_test (the
# probe-bypass used by the whiteout-preservation regression test)
# behind a compile-time flag. Same pattern as stm_snapshot_create_for_test
# (R46 P2-1). Default ON to keep the test-tree build flowing; production
# builds opt out with `-DSTRATUM_BUILD_TESTING_HOOKS=OFF` at configure
# time. PUBLIC so test_dirent + test_fs_phase8 see the prototype in
# <stratum/dirent_testing.h> and the symbol exists in the linked
# archive.
if(STRATUM_BUILD_TESTING_HOOKS)
    target_compile_definitions(stm_dirent PUBLIC STRATUM_BUILD_TESTING_HOOKS)
endif()
