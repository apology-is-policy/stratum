add_library(stm_p9 STATIC
    server.c)

target_include_directories(stm_p9 PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_p9
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util)
