# stratum-mkfs: small CLI wrapper around stm_fs_format + dataset-root
# init. Lets users `stratum-mkfs vol.stm` and immediately point
# stratumd at the resulting image.

add_library(stm_cmd_mkfs STATIC
    run.c)

target_include_directories(stm_cmd_mkfs PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_cmd_mkfs
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stratum)

add_executable(stratum-mkfs
    main.c)

target_link_libraries(stratum-mkfs
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stm_cmd_mkfs)
