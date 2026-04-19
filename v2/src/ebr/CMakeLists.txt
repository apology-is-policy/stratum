add_library(stm_ebr STATIC
    ebr.c)

target_include_directories(stm_ebr PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_ebr
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util Threads::Threads)
