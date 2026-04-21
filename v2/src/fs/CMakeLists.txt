add_library(stm_fs STATIC
    fs.c)

target_include_directories(stm_fs PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_fs
    PRIVATE stm_warnings stm_sanitize stm_coverage Threads::Threads
    PUBLIC  stm_sync stm_alloc stm_bootstrap stm_block stm_keyfile stm_janus stm_pool stm_sb)
