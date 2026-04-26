add_library(stm_dataset STATIC
    dataset.c)

target_include_directories(stm_dataset PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_dataset
    PRIVATE stm_warnings stm_sanitize stm_coverage)
