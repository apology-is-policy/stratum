# host_fs — POSIX-as-9P read-only server (SWISS-2).
# Used by `stratum host-fs` subcommand to mount a host directory tree
# as a 9P backend the slate TUI can attach to.

add_library(stm_host_fs STATIC host_fs.c)

target_include_directories(stm_host_fs PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

find_package(Threads REQUIRED)
target_link_libraries(stm_host_fs
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  Threads::Threads stm_lp9)
