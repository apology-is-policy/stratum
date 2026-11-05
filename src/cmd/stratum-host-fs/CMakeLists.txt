# stratum-host-fs: SWISS-2 host-fs daemon binary.
#
# Two artifacts:
#   - stm_cmd_host_fs: argv-driven CLI lifecycle as a static library
#                       (FFI'd by the swiss-army `stratum` binary).
#   - stratum-host-fs: standalone binary (thin main.c).

add_library(stm_cmd_host_fs STATIC
    run.c)

target_include_directories(stm_cmd_host_fs PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_cmd_host_fs
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_host_fs stm_lp9 stm_stratumd stratum)

add_executable(stratum-host-fs
    main.c)

target_link_libraries(stratum-host-fs
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stm_cmd_host_fs)
