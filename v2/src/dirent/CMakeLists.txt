add_library(stm_dirent STATIC dirent.c)

target_include_directories(stm_dirent PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_dirent
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_block stm_bootstrap stm_btree stm_btree_store
            stm_sb Threads::Threads)
