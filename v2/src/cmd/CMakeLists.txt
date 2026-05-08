# Command-line binaries built on top of the stratum library.

# SWISS-4m: shared passphrase-reader for mkfs / stratumd. Static lib
# so each consumer pulls only the small footprint they need.
add_library(stm_cli_passphrase STATIC
    cli_passphrase.c)
target_include_directories(stm_cli_passphrase PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(stm_cli_passphrase
    PRIVATE stm_warnings stm_sanitize stm_coverage)

add_subdirectory(stratumd)
add_subdirectory(stratum-fs)
add_subdirectory(stratum-mkfs)
add_subdirectory(stratum-slate)
add_subdirectory(stratum-host-fs)
