# P9-SLATE-1: slate daemon's per-process UI state + lp9 vops backend.

add_library(stm_slate STATIC slate.c)

target_include_directories(stm_slate PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_slate
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_lp9)

find_package(Threads REQUIRED)
target_link_libraries(stm_slate PUBLIC Threads::Threads)
