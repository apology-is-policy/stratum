add_library(stm_pool STATIC
    pool.c)

target_include_directories(stm_pool PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_pool
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_block stm_hash stm_util)
