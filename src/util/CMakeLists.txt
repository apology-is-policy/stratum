add_library(stm_util STATIC
    status.c
    listen.c
    takename.c)

target_include_directories(stm_util PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

if(STRATUM_BUILD_TESTING_HOOKS)
    target_compile_definitions(stm_util PUBLIC STRATUM_BUILD_TESTING_HOOKS)
endif()

target_link_libraries(stm_util
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  Threads::Threads)
