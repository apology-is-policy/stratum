add_library(stm_locks STATIC locks.c)

target_include_directories(stm_locks PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_locks
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  Threads::Threads)
