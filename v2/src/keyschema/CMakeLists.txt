add_library(stm_keyschema STATIC
    keyschema.c)

target_include_directories(stm_keyschema PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_keyschema
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_btnode stm_bootstrap stm_block stm_sb)
