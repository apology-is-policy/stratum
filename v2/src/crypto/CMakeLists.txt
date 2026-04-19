set(STM_CRYPTO_SRCS
    init.c
    random.c
    ct.c
    aead_aegis256.c
    aead_xchacha20_siv.c
    aead.c
    hkdf.c
    argon2.c
    x25519.c
    mlkem768.c
    hybrid_wrap.c)

add_library(stm_crypto STATIC ${STM_CRYPTO_SRCS})

target_include_directories(stm_crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(stm_crypto
    PRIVATE stm_warnings stm_sanitize stm_coverage
    PRIVATE PkgConfig::LIBSODIUM
    PUBLIC  stm_util)

if(STM_ENABLE_PQ)
    target_compile_definitions(stm_crypto PRIVATE STM_HAVE_LIBOQS=1)
    if(TARGET liboqs::oqs)
        target_link_libraries(stm_crypto PRIVATE liboqs::oqs)
    elseif(TARGET PkgConfig::LIBOQS)
        target_link_libraries(stm_crypto PRIVATE PkgConfig::LIBOQS)
    endif()
else()
    target_compile_definitions(stm_crypto PRIVATE STM_HAVE_LIBOQS=0)
endif()
