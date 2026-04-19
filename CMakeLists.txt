cmake_minimum_required(VERSION 3.20)
project(stratum VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_options(
    -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes
    -Wno-unused-parameter
    -fno-strict-aliasing
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(STM_ARCH_ARM64 ON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(STM_ARCH_X86_64 ON)
endif()

if(APPLE)
    set(STM_PLATFORM_MACOS ON)
elseif(UNIX)
    set(STM_PLATFORM_LINUX ON)
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)

# Compression libraries (optional)
find_path(LZ4_INCLUDE_DIR lz4.h)
find_library(LZ4_LIBRARY NAMES lz4)
if(LZ4_INCLUDE_DIR AND LZ4_LIBRARY)
    set(STM_HAVE_LZ4 ON)
    add_compile_definitions(STM_HAVE_LZ4=1)
    message(STATUS "Found LZ4: ${LZ4_LIBRARY}")
endif()

find_path(ZSTD_INCLUDE_DIR zstd.h)
find_library(ZSTD_LIBRARY NAMES zstd)
if(ZSTD_INCLUDE_DIR AND ZSTD_LIBRARY)
    set(STM_HAVE_ZSTD ON)
    add_compile_definitions(STM_HAVE_ZSTD=1)
    message(STATUS "Found ZSTD: ${ZSTD_LIBRARY}")
endif()

# Integrity checksums (xxHash3-128 for SB + btree nodes; xxHash3-64 for
# per-extent integrity). CMake still allows building without — the stubs
# in include/stratum/csum.h return 0/pass — but that disables *all*
# integrity detection, so emit a loud WARNING rather than silently ship
# an insecure build. Production packagers should treat this as an error.
find_path(XXHASH_INCLUDE_DIR xxhash.h)
find_library(XXHASH_LIBRARY NAMES xxhash)
if(XXHASH_INCLUDE_DIR AND XXHASH_LIBRARY)
    set(STM_HAVE_XXHASH ON)
    add_compile_definitions(STM_HAVE_XXHASH=1)
    message(STATUS "Found xxHash: ${XXHASH_LIBRARY}")
else()
    message(WARNING
        "xxHash not found — building WITHOUT integrity checksums. "
        "SB/node/extent corruption will not be detected. "
        "Install xxhash (apt install libxxhash-dev, brew install xxhash) "
        "and reconfigure for a production build.")
endif()

# Encryption (optional)
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium)
if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
    set(STM_HAVE_CRYPTO ON)
    add_compile_definitions(STM_HAVE_CRYPTO=1)
    message(STATUS "Found libsodium: ${SODIUM_LIBRARY}")
endif()

add_subdirectory(src)

# CLI executable
add_executable(stratum src/cmd/stratum.c src/cmd/check.c src/cmd/scrub.c src/cmd/cli_common.c)
target_link_libraries(stratum PRIVATE stratum-lib)
# rename to avoid collision with the library target
set_target_properties(stratum PROPERTIES OUTPUT_NAME stratum)

# FUSE executable — built only if libfuse3 is available. On Linux install
# libfuse3-dev (Debian/Ubuntu) or fuse3-devel (Fedora). On macOS install
# macFUSE (which provides fuse3). If not found, the rest of the build
# succeeds; users can still use the 9P server + TUI.
find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
    pkg_check_modules(FUSE3 IMPORTED_TARGET fuse3)
endif()
if (FUSE3_FOUND)
    add_executable(stratum-fuse src/cmd/fuse.c src/cmd/cli_common.c)
    target_link_libraries(stratum-fuse PRIVATE stratum-lib PkgConfig::FUSE3)
    # macFUSE's fuse_lowlevel.h uses `typeof` (a GNU extension) to route
    # Darwin-specific extended signatures. Relax the C standard for this
    # one target so the header compiles. libfuse3 on Linux doesn't need
    # this but the flag is harmless.
    target_compile_options(stratum-fuse PRIVATE -std=gnu99)
    message(STATUS "Found libfuse3: building stratum-fuse")
else()
    message(STATUS "libfuse3 not found: stratum-fuse will be skipped "
                   "(install libfuse3-dev / macFUSE to enable)")
endif()

enable_testing()
add_subdirectory(tests)
