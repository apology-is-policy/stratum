# P9-SLATE-1: stratum-slate daemon binary.

# Run-main lib: argv-driven CLI lifecycle (accept loop + worker pool +
# signal handlers). Factored out of main.c so the swiss-army `stratum`
# Rust binary can FFI-dispatch into it.
add_library(stm_cmd_slate STATIC
    run.c)

target_include_directories(stm_cmd_slate PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_cmd_slate
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_slate stm_stratumd stratum)

add_executable(stratum-slate main.c)

target_link_libraries(stratum-slate
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stm_cmd_slate)
