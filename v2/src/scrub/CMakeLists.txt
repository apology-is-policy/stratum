add_library(stm_scrub STATIC
    scrub.c)

target_include_directories(stm_scrub PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_scrub
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_alloc stm_block stm_pool stm_sync stm_util)
