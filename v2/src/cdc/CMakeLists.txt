add_library(stm_cdc STATIC
    cdc.c)

target_include_directories(stm_cdc PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_cdc
    PRIVATE stm_warnings stm_sanitize stm_coverage)
