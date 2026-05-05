# P9-9P-4: stratumd Unix-socket transport.
#
# Two artifacts:
#   - stm_stratumd: static library exporting the daemon machinery
#                   (listen_unix, serve_client, accept_loop, run).
#                   Tests link against this directly.
#   - stratumd:     the daemon binary itself, a thin main.c around
#                   stm_stratumd_run.

add_library(stm_stratumd STATIC
    serve.c)

target_include_directories(stm_stratumd PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_stratumd
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util stm_fs stm_9p)

find_package(Threads REQUIRED)
target_link_libraries(stm_stratumd PUBLIC Threads::Threads)

# Daemon binary.
add_executable(stratumd
    main.c)

target_link_libraries(stratumd
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stm_stratumd stratum)
