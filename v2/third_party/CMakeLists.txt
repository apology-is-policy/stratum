# ---------------------------------------------------------------------------
# BLAKE3 reference implementation (vendored at v1.5.4).
#
# Stabilization Area E re-enabled the SIMD path the original wiring deferred
# ("re-enable once benchmarks justify"): the crypto bench measured the portable
# path leaving ~2.3x on the integrity layer (Merkle/CAS hashing), so NEON --
# baseline on ARMv8, the Thylacine target -- is now compiled there. x86 SIMD
# stays off (no runtime-dispatch hassle); portable elsewhere. BLAKE3 SIMD is
# bit-for-bit the portable hash, so on-disk Merkle/CAS values are unchanged.
# ---------------------------------------------------------------------------

if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(BLAKE3_ARCH_SRC BLAKE3_src/c/blake3_neon.c)
    set(BLAKE3_NEON_DEF BLAKE3_USE_NEON=1)
else()
    set(BLAKE3_ARCH_SRC)
    set(BLAKE3_NEON_DEF BLAKE3_USE_NEON=0)
endif()

add_library(blake3 STATIC
    BLAKE3_src/c/blake3.c
    BLAKE3_src/c/blake3_dispatch.c
    BLAKE3_src/c/blake3_portable.c
    ${BLAKE3_ARCH_SRC})

target_include_directories(blake3 PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/BLAKE3_src/c)

# x86 SIMD stays off; NEON gated on the ARM target (above).
target_compile_definitions(blake3 PRIVATE
    BLAKE3_NO_SSE2
    BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2
    BLAKE3_NO_AVX512
    ${BLAKE3_NEON_DEF})

target_compile_options(blake3 PRIVATE
    -Wno-unused-function -Wno-unused-parameter)

set_target_properties(blake3 PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ---------------------------------------------------------------------------
# xxHash (vendored at v0.8.2) — build as static library with dispatcher.
# ---------------------------------------------------------------------------

add_library(xxhash STATIC
    xxHash_src/xxhash.c)

target_include_directories(xxhash PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/xxHash_src)

target_compile_definitions(xxhash PUBLIC
    XXH_STATIC_LINKING_ONLY)

target_compile_options(xxhash PRIVATE
    -Wno-unused-function -Wno-unused-parameter -Wno-macro-redefined)

set_target_properties(xxhash PROPERTIES POSITION_INDEPENDENT_CODE ON)
