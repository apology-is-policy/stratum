# P9-CLI-1 (FS-only): stratum-fs CLI.
#
# Thin wrapper over libstratum-9p exposing common POSIX file ops as
# subcommands against a stratumd Unix socket. /ctl/-using subcommands
# (pool / dataset / snapshot / scrub) deferred until /ctl/-on-stratumd
# integration lands.

add_executable(stratum-fs
    main.c)

target_include_directories(stratum-fs PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stratum-fs
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stm_9p_client stratum)
