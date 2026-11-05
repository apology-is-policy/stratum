add_library(stm_btree_store STATIC
    serialize.c
    crypt.c)

target_include_directories(stm_btree_store PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_btree_store
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_btnode stm_btree stm_crypto)
