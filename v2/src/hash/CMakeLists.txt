add_library(stm_hash STATIC
    blake3_wrap.c
    xxhash_wrap.c)

target_include_directories(stm_hash PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_hash
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PRIVATE blake3 xxhash
    PUBLIC  stm_util)
