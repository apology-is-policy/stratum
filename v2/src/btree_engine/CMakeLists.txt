add_library(stm_btree_engine STATIC
    node.c
    node_cache.c
    btnode_io.c
    engine.c)

target_include_directories(stm_btree_engine PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_btree_engine
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_btnode stm_btree_store stm_hash)
