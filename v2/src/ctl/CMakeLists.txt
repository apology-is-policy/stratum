add_library(stm_ctl STATIC
    synfs.c)

target_include_directories(stm_ctl
    PUBLIC  ${CMAKE_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(stm_ctl
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_p9 stm_fs)
