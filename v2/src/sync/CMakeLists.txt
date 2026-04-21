add_library(stm_sync STATIC
    sync.c)

target_include_directories(stm_sync PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_sync
    PRIVATE stm_warnings stm_sanitize stm_coverage Threads::Threads
    PUBLIC  stm_sb stm_alloc stm_block stm_hash stm_crypto
            stm_keyschema stm_keyfile)
