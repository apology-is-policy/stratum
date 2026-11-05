add_library(stm_dirty_buffer STATIC dirty_buffer.c)

target_include_directories(stm_dirty_buffer PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_dirty_buffer
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  Threads::Threads)
