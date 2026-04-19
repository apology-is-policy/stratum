add_library(stratum-lib STATIC
    block/block.c
    block/file_backend.c
    btree/btree.c
    btree/node.c
    btree/msg.c
    btree/cache.c
    alloc/alloc.c
    alloc/space_map.c
    alloc/space_log.c
    cow/cow.c
    fs/fs.c
    snap/snap.c
    crypto/crypto.c
    compress/compress.c
    p9/p9.c
)

target_include_directories(stratum-lib PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

target_include_directories(stratum-lib PRIVATE
    ${PROJECT_SOURCE_DIR}/src
)

if(STM_HAVE_LZ4)
    target_include_directories(stratum-lib PUBLIC ${LZ4_INCLUDE_DIR})
    target_link_libraries(stratum-lib PUBLIC ${LZ4_LIBRARY})
endif()

if(STM_HAVE_CRYPTO)
    target_include_directories(stratum-lib PUBLIC ${SODIUM_INCLUDE_DIR})
    target_link_libraries(stratum-lib PUBLIC ${SODIUM_LIBRARY})
endif()

if(STM_HAVE_ZSTD)
    target_include_directories(stratum-lib PUBLIC ${ZSTD_INCLUDE_DIR})
    target_link_libraries(stratum-lib PUBLIC ${ZSTD_LIBRARY})
endif()

if(STM_HAVE_XXHASH)
    target_include_directories(stratum-lib PUBLIC ${XXHASH_INCLUDE_DIR})
    target_link_libraries(stratum-lib PUBLIC ${XXHASH_LIBRARY})
endif()
