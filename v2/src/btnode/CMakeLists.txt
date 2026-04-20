add_library(stm_btnode STATIC
    leaf.c)

target_include_directories(stm_btnode PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_btnode
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_hash)
