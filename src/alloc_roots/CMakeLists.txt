add_library(stm_alloc_roots STATIC
    alloc_roots.c)

target_include_directories(stm_alloc_roots PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_alloc_roots
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_btree stm_btree_store stm_btnode stm_bootstrap
            stm_block stm_sb stm_pool)
