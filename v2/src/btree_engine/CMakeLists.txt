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

# Phase 9.6-impl-4b: the production storage vtable binding the engine to
# stm_bootstrap + stm_bdev. A separate library so stm_btree_engine itself
# stays allocator-agnostic (the engine + its test exercise an in-RAM
# vtable); only the cutover modules — inode / dirent / xattr / extent —
# link this. See v2/docs/phase-9.6-impl-4b-sync-wiring-design.md §2.
add_library(stm_engine_store STATIC
    engine_store.c)

target_include_directories(stm_engine_store PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_engine_store
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_btree_store stm_bootstrap stm_block)
