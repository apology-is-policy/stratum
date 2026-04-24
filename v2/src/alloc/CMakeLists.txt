add_library(stm_alloc STATIC
    alloc.c)

target_include_directories(stm_alloc PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_alloc
    PRIVATE stm_warnings stm_sanitize stm_coverage Threads::Threads
    PUBLIC  stm_bootstrap stm_btree stm_btnode stm_btree_store stm_block
            stm_pool stm_sdarray stm_xor_filter)

# Succinct in-RAM acceleration (Phase 3 chunk 4c). Standalone
# data-structure library with no deps beyond libc + types.h. Integration
# with stm_alloc's query path lives with chunk 4e / a followup.
add_library(stm_sdarray STATIC
    sdarray.c)

target_include_directories(stm_sdarray PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_sdarray
    PRIVATE stm_warnings stm_sanitize stm_coverage)

# xor8 filter (Phase 3 chunk 4d). Standalone membership-accelerator
# library; same packaging as stm_sdarray.
add_library(stm_xor_filter STATIC
    xor_filter.c)

target_include_directories(stm_xor_filter PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_xor_filter
    PRIVATE stm_warnings stm_sanitize stm_coverage)
