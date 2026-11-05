add_library(stm_util STATIC
    status.c)

target_include_directories(stm_util PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_util
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  Threads::Threads)
