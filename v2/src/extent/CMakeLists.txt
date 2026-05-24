add_library(stm_extent STATIC
    extent.c
    extent_index.c)

target_include_directories(stm_extent PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_extent
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_crypto stm_block stm_bootstrap
            stm_btree_engine stm_metakey stm_dataset stm_ebr
            Threads::Threads)
# 9.7-impl-1c-v: stm_engine_store no longer needed (engine create / open
# is now driven from stm_dataset_index's per-slot engine cache). Added
# stm_metakey (key encoding via stm_metakey_compose / parse) + stm_dataset
# (per-dataset engine resolution via stm_dataset_index_get_engine). The
# pool-global engine + its storage-binder APIs are RETIRED — see
# extent_index.c header comment.
