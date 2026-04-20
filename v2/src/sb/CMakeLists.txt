add_library(stm_sb STATIC
    uberblock.c
    label.c)

target_include_directories(stm_sb PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_sb
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_hash)
