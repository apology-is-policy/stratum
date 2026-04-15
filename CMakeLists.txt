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
add_executable(stratum src/cmd/stratum.c)
target_link_libraries(stratum PRIVATE stratum-lib)
# rename to avoid collision with the library target
set_target_properties(stratum PROPERTIES OUTPUT_NAME stratum)

enable_testing()
add_subdirectory(tests)
