add_library(stm_janus STATIC
    synfs.c
    backend_file.c
    backend_passphrase.c
    client.c
    daemon.c)

target_include_directories(stm_janus
    PUBLIC  ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(stm_janus
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_p9 stm_crypto stm_keyfile)

add_executable(janus janusd.c)
target_include_directories(janus PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(janus
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stm_janus)
