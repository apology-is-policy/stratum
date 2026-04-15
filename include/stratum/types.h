#ifndef STM_TYPES_H
#define STM_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * On-disk integer types — little-endian.
 *
 * Wrapped in structs so the compiler rejects implicit conversions
 * between host-endian and disk-endian values. Same approach as
 * Linux's __le64/__le32/__le16.
 */

typedef struct { uint64_t _v; } __attribute__((packed)) le64;
typedef struct { uint32_t _v; } __attribute__((packed)) le32;
typedef struct { uint16_t _v; } __attribute__((packed)) le16;

/* Byte-swap primitives */
#if defined(__APPLE__)
  #include <libkern/OSByteOrder.h>
  #define stm_bswap16(x) OSSwapInt16(x)
  #define stm_bswap32(x) OSSwapInt32(x)
  #define stm_bswap64(x) OSSwapInt64(x)
#elif defined(__linux__)
  #include <byteswap.h>
  #define stm_bswap16(x) bswap_16(x)
  #define stm_bswap32(x) bswap_32(x)
  #define stm_bswap64(x) bswap_64(x)
#else
  #define stm_bswap16(x) __builtin_bswap16(x)
  #define stm_bswap32(x) __builtin_bswap32(x)
  #define stm_bswap64(x) __builtin_bswap64(x)
#endif

/* Compile-time endianness detection */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  #define STM_LITTLE_ENDIAN 1
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
  #define STM_BIG_ENDIAN 1
#else
  #error "Cannot determine endianness"
#endif

static inline le64 cpu_to_le64(uint64_t v) {
#ifdef STM_BIG_ENDIAN
    v = stm_bswap64(v);
#endif
    return (le64){ ._v = v };
}

static inline uint64_t le64_to_cpu(le64 x) {
#ifdef STM_BIG_ENDIAN
    return stm_bswap64(x._v);
#else
    return x._v;
#endif
}

static inline le32 cpu_to_le32(uint32_t v) {
#ifdef STM_BIG_ENDIAN
    v = stm_bswap32(v);
#endif
    return (le32){ ._v = v };
}

static inline uint32_t le32_to_cpu(le32 x) {
#ifdef STM_BIG_ENDIAN
    return stm_bswap32(x._v);
#else
    return x._v;
#endif
}

static inline le16 cpu_to_le16(uint16_t v) {
#ifdef STM_BIG_ENDIAN
    v = stm_bswap16(v);
#endif
    return (le16){ ._v = v };
}

static inline uint16_t le16_to_cpu(le16 x) {
#ifdef STM_BIG_ENDIAN
    return stm_bswap16(x._v);
#else
    return x._v;
#endif
}

/* BLAKE3 digest length */
#define STM_BLAKE3_LEN  32

/* Magic: "STRATUM\0" as little-endian uint64 */
#define STM_MAGIC       UINT64_C(0x004d555441525453)

/* Block size: 4 KiB (for superblocks, space map entries) */
#define STM_BLOCK_SHIFT   12
#define STM_BLOCK_SIZE    (1U << STM_BLOCK_SHIFT)

/* Node size: 128 KiB (for Bε-tree nodes) */
#define STM_NODE_SHIFT    17
#define STM_NODE_SIZE     (1U << STM_NODE_SHIFT)

/* Invalid block address sentinel */
#define STM_BADDR_NONE    UINT64_C(0xFFFFFFFFFFFFFFFF)

/* C99-compatible static assertion */
#define STM_STATIC_ASSERT(cond, msg) \
    typedef char static_assert_##msg[(cond) ? 1 : -1]

#endif /* STM_TYPES_H */
