# lp9: generic 9P2000.L server, vops-extensible.
#
# Sibling to src/p9/ (9P2000) and src/9p/ (FS-bound .L). v1.0 shipped
# for /ctl/ migration (P9-CTL-2b) and slate (P9-SLATE-*).

add_library(stm_lp9 STATIC
    server.c)

target_include_directories(stm_lp9 PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_lp9
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util)
