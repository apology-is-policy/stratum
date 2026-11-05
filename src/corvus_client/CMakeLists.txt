# TLY-A3-impl-1: corvus key-agent client library.

add_library(stm_corvus_client STATIC
    corvus_client.c)

target_include_directories(stm_corvus_client PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_corvus_client
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util)
