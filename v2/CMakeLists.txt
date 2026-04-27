cmake_minimum_required(VERSION 3.24)
project(stratum-v2
    VERSION 2.0.0
    DESCRIPTION "Stratum v2 — copy-on-write filesystem, PQ-encrypted, lock-free"
    LANGUAGES C)

# ---------------------------------------------------------------------------
# Language level, warnings.
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

# ---------------------------------------------------------------------------
# Options.
# ---------------------------------------------------------------------------
set(STM_SANITIZE "off" CACHE STRING
    "Sanitizer build: off | asan | tsan | msan | ubsan")
set_property(CACHE STM_SANITIZE PROPERTY STRINGS off asan tsan msan ubsan)

option(STM_ENABLE_IOURING "Enable io_uring backend (Linux only)" ON)
option(STM_ENABLE_LIBAIO  "Enable libaio backend (pre-5.1 Linux)" OFF)
option(STM_ENABLE_PQ      "Enable liboqs ML-KEM-768 hybrid wrap"  ON)
option(STM_BUILD_TESTS    "Build tests"                           ON)
option(STM_BUILD_FUZZERS  "Build libFuzzer targets (clang only)"  OFF)
option(STM_COVERAGE       "Enable gcov/lcov coverage"             OFF)
option(STM_WERROR         "Treat warnings as errors"              ON)

set(STM_AEAD_DEFAULT "auto" CACHE STRING
    "Default AEAD: aegis256 | xchacha20-siv | auto")
set_property(CACHE STM_AEAD_DEFAULT PROPERTY STRINGS aegis256 xchacha20-siv auto)

# ---------------------------------------------------------------------------
# Platform detection — must run before warnings/sanitizer setup so feature-
# test macros and fortify gating can consult STM_PLATFORM_*.
# ---------------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(STM_PLATFORM_LINUX TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(STM_PLATFORM_DARWIN TRUE)
endif()

# io_uring only on Linux.
if(STM_ENABLE_IOURING AND NOT STM_PLATFORM_LINUX)
    message(STATUS "io_uring disabled (not Linux)")
    set(STM_ENABLE_IOURING OFF)
endif()

# ---------------------------------------------------------------------------
# Warnings + sanitizers.
# ---------------------------------------------------------------------------
add_library(stm_warnings INTERFACE)
target_compile_options(stm_warnings INTERFACE
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wno-sign-conversion
    -Wstrict-prototypes -Wmissing-prototypes
    -Wformat=2 -Wnull-dereference
    -fno-common
    -fstack-protector-strong)

# Feature-test macros for POSIX + GNU APIs under -std=c17.
#
# Linux + glibc hides pread/pwrite, posix_memalign, fdatasync, ftruncate,
# S_IFMT/S_IFBLK/S_IFREG, ioctl, BLKDISCARD, fallocate, etc. behind feature-
# test macros when -std=c17 is in effect (which sets __STRICT_ANSI__ and
# disables _DEFAULT_SOURCE-by-default). We need all of POSIX 2008 +
# XOpen 7 + GNU extensions.
#
# macOS exposes most of these by default; setting _POSIX_C_SOURCE there
# would HIDE macOS-specific symbols (F_FULLFSYNC, _SC_NPROCESSORS_ONLN). So
# we gate per-platform.
if(STM_PLATFORM_LINUX)
    target_compile_definitions(stm_warnings INTERFACE
        _POSIX_C_SOURCE=200809L
        _XOPEN_SOURCE=700
        _GNU_SOURCE
        _DEFAULT_SOURCE)
endif()

# _FORTIFY_SOURCE is useful but platforms disagree on when it's safe to set.
# - Linux: glibc wants it at -O1+ and never under sanitizers (conflicts with
#   ASan's interceptors).
# - macOS: Clang on recent SDKs already defines _FORTIFY_SOURCE via system
#   headers; setting it here triggers -Wmacro-redefined.
# Gate on platform + sanitizer.
if(NOT STM_PLATFORM_DARWIN AND STM_SANITIZE STREQUAL "off")
    target_compile_options(stm_warnings INTERFACE -D_FORTIFY_SOURCE=2)
endif()
if(STM_WERROR)
    target_compile_options(stm_warnings INTERFACE -Werror)
endif()

add_library(stm_sanitize INTERFACE)
if(STM_SANITIZE STREQUAL "asan")
    target_compile_options(stm_sanitize INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options   (stm_sanitize INTERFACE -fsanitize=address,undefined)
elseif(STM_SANITIZE STREQUAL "tsan")
    target_compile_options(stm_sanitize INTERFACE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options   (stm_sanitize INTERFACE -fsanitize=thread)
elseif(STM_SANITIZE STREQUAL "msan")
    target_compile_options(stm_sanitize INTERFACE -fsanitize=memory -fno-omit-frame-pointer -fno-optimize-sibling-calls)
    target_link_options   (stm_sanitize INTERFACE -fsanitize=memory)
elseif(STM_SANITIZE STREQUAL "ubsan")
    target_compile_options(stm_sanitize INTERFACE -fsanitize=undefined -fno-omit-frame-pointer)
    target_link_options   (stm_sanitize INTERFACE -fsanitize=undefined)
endif()

add_library(stm_coverage INTERFACE)
if(STM_COVERAGE)
    target_compile_options(stm_coverage INTERFACE --coverage -O0 -g)
    target_link_options   (stm_coverage INTERFACE --coverage)
endif()

# ---------------------------------------------------------------------------
# Dependencies.
# ---------------------------------------------------------------------------
find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBSODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.19)

if(STM_ENABLE_IOURING)
    pkg_check_modules(LIBURING REQUIRED IMPORTED_TARGET liburing>=2.3)
endif()

if(STM_ENABLE_LIBAIO)
    pkg_check_modules(LIBAIO REQUIRED IMPORTED_TARGET libaio>=0.3)
endif()

if(STM_ENABLE_PQ)
    # liboqs ships a CMake config package (0.11+) AND a pkg-config file.
    # Prefer pkg-config because the CMake-exported target name has
    # changed across versions (OQS::oqs in 0.12, liboqs::oqs in earlier
    # variants) and pkg-config gives us a stable PkgConfig::LIBOQS.
    pkg_check_modules(LIBOQS IMPORTED_TARGET liboqs>=0.9.0)
    if(NOT LIBOQS_FOUND)
        find_package(liboqs QUIET)
        if(NOT liboqs_FOUND)
            message(WARNING "liboqs not found; PQ hybrid wrap disabled. "
                            "Set STM_ENABLE_PQ=OFF to silence, or install liboqs.")
            set(STM_ENABLE_PQ OFF)
        endif()
    endif()
endif()

# ---------------------------------------------------------------------------
# Vendored third-party.
# ---------------------------------------------------------------------------
add_subdirectory(third_party)

# ---------------------------------------------------------------------------
# Core subsystems.
# ---------------------------------------------------------------------------
add_subdirectory(src/util)
add_subdirectory(src/hash)
add_subdirectory(src/crypto)
add_subdirectory(src/block)
add_subdirectory(src/ebr)
add_subdirectory(src/btree)
add_subdirectory(src/sb)
add_subdirectory(src/bootstrap)
add_subdirectory(src/btnode)
add_subdirectory(src/btree_store)
add_subdirectory(src/alloc)
add_subdirectory(src/alloc_roots)
add_subdirectory(src/keyfile)
add_subdirectory(src/keyschema)
add_subdirectory(src/p9)
add_subdirectory(src/janus)
add_subdirectory(src/pool)
add_subdirectory(src/sync)
add_subdirectory(src/scrub)
add_subdirectory(src/fs)
add_subdirectory(src/extent)
add_subdirectory(src/cdc)
add_subdirectory(src/dataset)
add_subdirectory(src/snapshot)
add_subdirectory(src/send_recv)

# ---------------------------------------------------------------------------
# Public aggregate library.
# ---------------------------------------------------------------------------
add_library(stratum INTERFACE)
target_link_libraries(stratum INTERFACE
    stm_util
    stm_hash
    stm_crypto
    stm_block
    stm_ebr
    stm_btree
    stm_sb
    stm_bootstrap
    stm_btnode
    stm_btree_store
    stm_alloc
    stm_alloc_roots
    stm_sdarray
    stm_xor_filter
    stm_keyfile
    stm_keyschema
    stm_p9
    stm_janus
    stm_pool
    stm_sync
    stm_scrub
    stm_fs
    stm_extent
    stm_cdc
    stm_dataset
    stm_snapshot
    stm_send_recv)
target_include_directories(stratum INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/include)

# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------
if(STM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(STM_BUILD_BENCHES)
    add_subdirectory(bench)
endif()

# ---------------------------------------------------------------------------
# Configuration summary.
# ---------------------------------------------------------------------------
message(STATUS "")
message(STATUS "Stratum v2 configuration")
message(STATUS "  Platform       : ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Build type     : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Sanitizer      : ${STM_SANITIZE}")
message(STATUS "  io_uring       : ${STM_ENABLE_IOURING}")
message(STATUS "  libaio         : ${STM_ENABLE_LIBAIO}")
message(STATUS "  PQ (liboqs)    : ${STM_ENABLE_PQ}")
message(STATUS "  AEAD default   : ${STM_AEAD_DEFAULT}")
message(STATUS "  Coverage       : ${STM_COVERAGE}")
message(STATUS "  Werror         : ${STM_WERROR}")
message(STATUS "  Tests          : ${STM_BUILD_TESTS}")
message(STATUS "  Fuzzers        : ${STM_BUILD_FUZZERS}")
message(STATUS "")
