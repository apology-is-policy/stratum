# stratum-mkfs: small CLI wrapper around stm_fs_format + dataset-root
# init. Lets users `stratum-mkfs vol.stm` and immediately point
# stratumd at the resulting image.

add_executable(stratum-mkfs
    main.c)

target_include_directories(stratum-mkfs PRIVATE
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stratum-mkfs
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stratum)
