add_library(stm_9p_client STATIC
    9p_client.c)

target_include_directories(stm_9p_client PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_9p_client
    PRIVATE stm_warnings stm_sanitize stm_coverage)
