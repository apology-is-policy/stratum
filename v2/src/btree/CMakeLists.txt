add_library(stm_btree STATIC
    node.c
    btree.c
    btree_mt.c)

target_include_directories(stm_btree PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_btree
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util stm_hash stm_ebr)
