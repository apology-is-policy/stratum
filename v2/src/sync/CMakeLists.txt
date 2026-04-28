add_library(stm_sync STATIC
    sync.c)

target_include_directories(stm_sync PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_sync
    PRIVATE stm_warnings stm_sanitize stm_coverage Threads::Threads
    PUBLIC  stm_sb stm_alloc stm_alloc_roots stm_block stm_hash stm_crypto
            stm_cdc stm_keyschema stm_keyfile stm_janus stm_pool)

# P7-CAS-4b: gate stm_sync_set_cdc_params_for_test (the FastCDC params
# override used by chunked-migrate tests) behind STRATUM_BUILD_TESTING_HOOKS,
# matching the snapshot_create_for_test pattern (R46 P2-1). Production
# builds opt out via -DSTRATUM_BUILD_TESTING_HOOKS=OFF; the symbol is
# absent from the archive in that mode.
if(STRATUM_BUILD_TESTING_HOOKS)
    target_compile_definitions(stm_sync PUBLIC STRATUM_BUILD_TESTING_HOOKS)
endif()
