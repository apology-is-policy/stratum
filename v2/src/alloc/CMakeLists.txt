add_library(stm_alloc STATIC
    alloc.c)

target_include_directories(stm_alloc PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_alloc
    PRIVATE stm_warnings stm_sanitize stm_coverage Threads::Threads
    PUBLIC  stm_bootstrap stm_btree stm_btnode stm_btree_store stm_block)
