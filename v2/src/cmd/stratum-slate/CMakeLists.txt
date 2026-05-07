# P9-SLATE-1: stratum-slate daemon binary.

add_executable(stratum-slate main.c)

target_link_libraries(stratum-slate
    PRIVATE stm_warnings stm_sanitize stm_coverage
            stm_slate stm_stratumd stratum)
