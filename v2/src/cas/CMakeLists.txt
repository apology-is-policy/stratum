add_library(stm_cas STATIC
    cas_index.c)

target_include_directories(stm_cas PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_cas
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_crypto stm_btree_store stm_block stm_bootstrap
            Threads::Threads)
