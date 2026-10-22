add_library(stm_dataset STATIC
    dataset.c)

target_include_directories(stm_dataset PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_dataset
    PUBLIC  stm_btree_engine
            stm_engine_store
            stm_ebr
    PRIVATE stm_warnings stm_sanitize stm_coverage)

# Gate stm_dataset_index_lock_for_test / _unlock_for_test behind the same
# flag as stm_dirent_install_at_probe_for_test. PUBLIC so test_dataset sees
# the prototypes in <stratum/dataset_testing.h> and the symbols exist in
# the linked archive.
if(STRATUM_BUILD_TESTING_HOOKS)
    target_compile_definitions(stm_dataset PUBLIC STRATUM_BUILD_TESTING_HOOKS)
endif()
