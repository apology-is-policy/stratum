add_library(stm_9p STATIC
    server.c)

target_include_directories(stm_9p PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_9p
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util stm_fs stm_inode)

find_package(Threads REQUIRED)
target_link_libraries(stm_9p PUBLIC Threads::Threads)
