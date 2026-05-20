add_library(stm_metakey STATIC
    metakey.c)

target_include_directories(stm_metakey PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_metakey
    PRIVATE stm_warnings stm_sanitize stm_coverage)
