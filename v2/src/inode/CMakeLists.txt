add_library(stm_inode STATIC inode.c)

target_include_directories(stm_inode PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_inode
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  Threads::Threads)
