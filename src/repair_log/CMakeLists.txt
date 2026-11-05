add_library(stm_repair_log STATIC
    repair_log.c)

target_include_directories(stm_repair_log PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_repair_log
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_block stm_bootstrap stm_btnode stm_crypto stm_sb)
