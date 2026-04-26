add_library(stm_extent STATIC
    extent.c
    extent_index.c)

target_include_directories(stm_extent PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_extent
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_crypto Threads::Threads)
