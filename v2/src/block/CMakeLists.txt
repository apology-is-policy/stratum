set(STM_BLOCK_SRCS
    bdev.c)

if(STM_PLATFORM_THYLACINE)
    # Thylacine arm: in-process virtio-blk driver replaces the POSIX
    # backend. pouch's musl lacks pread/pwrite/fsync at v1.0 so the
    # POSIX arm would be a runtime hazard (ENOSYS via the 0xFFFF
    # sentinel). See src/block/bdev_thylacine.c.
    list(APPEND STM_BLOCK_SRCS bdev_thylacine.c)
else()
    list(APPEND STM_BLOCK_SRCS posix.c)
endif()

if(STM_ENABLE_IOURING)
    list(APPEND STM_BLOCK_SRCS iouring.c)
endif()

add_library(stm_block STATIC ${STM_BLOCK_SRCS})

target_include_directories(stm_block PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_block
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PUBLIC  stm_util Threads::Threads)

if(STM_ENABLE_IOURING)
    target_compile_definitions(stm_block PRIVATE STM_HAVE_IOURING=1)
    target_link_libraries(stm_block PRIVATE PkgConfig::LIBURING)
else()
    target_compile_definitions(stm_block PRIVATE STM_HAVE_IOURING=0)
endif()
