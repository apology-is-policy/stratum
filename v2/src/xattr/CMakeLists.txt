add_library(stm_xattr STATIC xattr.c)

target_include_directories(stm_xattr PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_xattr
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_block stm_bootstrap stm_btree stm_btree_store
            stm_btree_engine stm_engine_store stm_metakey stm_dataset
            stm_sb Threads::Threads)
