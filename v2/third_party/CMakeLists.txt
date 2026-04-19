# ---------------------------------------------------------------------------
# BLAKE3 reference implementation (vendored at v1.5.4).
#
# Include only the portable C implementation + dispatch. SIMD variants are
# available via the reference CMake but the portable path is sufficient for
# Phase 1 and saves assembly portability hassle. We can re-enable SIMD paths
# in Phase 9 once benchmarks justify.
# ---------------------------------------------------------------------------

add_library(blake3 STATIC
    BLAKE3_src/c/blake3.c
    BLAKE3_src/c/blake3_dispatch.c
    BLAKE3_src/c/blake3_portable.c)

target_include_directories(blake3 PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/BLAKE3_src/c)

# Disable SIMD paths — portable only for now.
target_compile_definitions(blake3 PRIVATE
    BLAKE3_NO_SSE2
    BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2
    BLAKE3_NO_AVX512
    BLAKE3_USE_NEON=0)

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
    -Wno-unused-function -Wno-unused-parameter)

set_target_properties(xxhash PROPERTIES POSITION_INDEPENDENT_CODE ON)
