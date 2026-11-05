add_library(stm_send_recv STATIC
    send.c
    recv.c)

target_include_directories(stm_send_recv PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_send_recv
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_crypto stm_hash stm_block Threads::Threads)
