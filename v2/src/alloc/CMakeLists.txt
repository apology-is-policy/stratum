add_library(stm_alloc STATIC
    bootstrap.c)

target_include_directories(stm_alloc PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_alloc
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_hash stm_block stm_sb)
