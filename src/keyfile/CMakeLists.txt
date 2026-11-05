add_library(stm_keyfile STATIC
    keyfile.c)

target_include_directories(stm_keyfile PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_keyfile
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_crypto)
