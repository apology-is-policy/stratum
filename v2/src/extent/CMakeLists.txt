add_library(stm_extent STATIC
    extent.c
    extent_index.c)

target_include_directories(stm_extent PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_extent
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_crypto stm_block stm_bootstrap stm_btree stm_btree_store
            stm_btree_engine stm_engine_store
            Threads::Threads)
