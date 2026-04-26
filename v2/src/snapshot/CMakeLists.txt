add_library(stm_snapshot STATIC
    snapshot.c)

target_include_directories(stm_snapshot PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_snapshot
    PRIVATE stm_warnings stm_sanitize stm_coverage)
