add_library(stm_bootstrap STATIC
    pool.c)

target_include_directories(stm_bootstrap PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_bootstrap
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_hash stm_block stm_sb)
