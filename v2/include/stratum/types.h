/* SPDX-License-Identifier: ISC */
/*
 * Basic fixed-width types, endian helpers, and the error enum shared by every
 * Stratum v2 subsystem. Deliberately small — only things that every file needs.
 */
#ifndef STRATUM_V2_TYPES_H
#define STRATUM_V2_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Fixed-width little-endian types.                                           */
/*                                                                            */
/* On-disk and on-wire numbers are little-endian. Accessors convert. Never    */
/* dereference these as native ints — always go through stm_{load,store}_*.  */
/* ------------------------------------------------------------------------- */

typedef struct { uint8_t  v[2];  } le16;
typedef struct { uint8_t  v[4];  } le32;
typedef struct { uint8_t  v[8];  } le64;
typedef struct { uint8_t  v[16]; } le128;

static inline uint16_t stm_load_le16(le16 x) {
    return (uint16_t)((uint16_t)x.v[0] | ((uint16_t)x.v[1] << 8));
}
static inline uint32_t stm_load_le32(le32 x) {
    return (uint32_t)x.v[0]        | ((uint32_t)x.v[1] << 8) |
           ((uint32_t)x.v[2] << 16) | ((uint32_t)x.v[3] << 24);
}
static inline uint64_t stm_load_le64(le64 x) {
    return (uint64_t)stm_load_le32((le32){{x.v[0], x.v[1], x.v[2], x.v[3]}}) |
           ((uint64_t)stm_load_le32((le32){{x.v[4], x.v[5], x.v[6], x.v[7]}}) << 32);
}

static inline le16 stm_store_le16(uint16_t n) {
    return (le16){{(uint8_t)n, (uint8_t)(n >> 8)}};
}
static inline le32 stm_store_le32(uint32_t n) {
    return (le32){{(uint8_t)n, (uint8_t)(n >> 8),
                   (uint8_t)(n >> 16), (uint8_t)(n >> 24)}};
}
static inline le64 stm_store_le64(uint64_t n) {
    return (le64){{(uint8_t)n,         (uint8_t)(n >> 8),
                   (uint8_t)(n >> 16), (uint8_t)(n >> 24),
                   (uint8_t)(n >> 32), (uint8_t)(n >> 40),
                   (uint8_t)(n >> 48), (uint8_t)(n >> 56)}};
}

/* ------------------------------------------------------------------------- */
/* Error codes. Negative for errors, 0 for success. Kept sparse on purpose — */
/* callers should treat any negative return as failure; specific codes are   */
/* for diagnostics, not flow control.                                        */
/* ------------------------------------------------------------------------- */

typedef enum {
    STM_OK              =    0,

    /* Caller errors. */
    STM_EINVAL          =  -22,   /* matches POSIX EINVAL for familiarity */
    STM_ENOMEM          =  -12,
    STM_ENOSPC          =  -28,
    STM_EOVERFLOW       =  -75,
    STM_ERANGE          =  -34,

    /* I/O and device errors. */
    STM_EIO             =   -5,
    STM_ENOENT          =   -2,
    STM_EEXIST          =  -17,
    STM_EACCES          =  -13,
    STM_EBUSY           =  -16,
    STM_EAGAIN          =  -11,
    STM_ENODEV          =  -19,
    STM_EROFS           =  -30,
    STM_EXDEV           =  -18,   /* cross-device link/reflink refused      */

    /* Stratum-specific. */
    STM_ECORRUPT        = -200,   /* on-disk data failed integrity check   */
    STM_EBADTAG         = -201,   /* AEAD tag verification failed          */
    STM_EBADVERSION     = -202,   /* format version unsupported            */
    STM_EBADFEATURE     = -203,   /* required feature flag unknown         */
    STM_EWEDGED         = -204,   /* filesystem in wedged state            */
    STM_ENOTSUPPORTED   = -205,
    STM_EPROTOCOL       = -206,   /* protocol / wire-format violation      */
    STM_EBACKEND        = -207,   /* backend reported an opaque failure    */
    STM_EQUORUM         = -208,   /* multi-device commit/mount lacked quorum confirmations */

    /* P8-POSIX-2b: dirent / directory-shape errors. POSIX-aligned values
     * (matches Linux errno.h) so callers can interpret without translation. */
    STM_ENOTDIR         =  -20,   /* entry isn't a directory but should be */
    STM_EISDIR          =  -21,   /* entry is a directory but shouldn't be */
    STM_ENOTEMPTY       =  -39,   /* directory non-empty                   */
    STM_ENAMETOOLONG    =  -36,   /* path / symlink target / name exceeds bound */

    /* P8-POSIX-6: xattr / extended-attribute errors. POSIX-aligned values
     * (matches Linux errno.h on most systems; also returned for
     * getxattr/removexattr "no such attribute" per Linux man getxattr(2)). */
    STM_ENODATA         =  -61,   /* xattr name not present                */

    /* P8-POSIX-7a-seals: file-seal violations. Linux memfd_create's
     * F_ADD_SEALS / F_GET_SEALS surface returns EPERM on every seal-rule
     * violation (write into SEAL_WRITE'd file; truncate-up into
     * SEAL_GROW'd; truncate-down into SEAL_SHRINK'd; F_ADD_SEALS into a
     * SEAL_SEAL'd inode). POSIX-aligned (`EPERM = 1`); kept distinct
     * from STM_EACCES (mode-permission denial) and STM_EROFS (mount-
     * level read-only) so callers can route the seal-rejection branch
     * separately. */
    STM_EPERM           =   -1,   /* operation not permitted (sealed)      */
} stm_status;

const char *stm_strerror(stm_status s);

/* ------------------------------------------------------------------------- */
/* Slices: pointer + length, immutable and mutable variants. The output      */
/* type convention for "caller provides buffer, callee fills in" is          */
/*   `stm_mut_slice buf` + `size_t *out_written`.                            */
/* ------------------------------------------------------------------------- */

typedef struct {
    const uint8_t *data;
    size_t         len;
} stm_slice;

typedef struct {
    uint8_t *data;
    size_t   len;
} stm_mut_slice;

static inline stm_slice stm_slice_from(const void *p, size_t n) {
    return (stm_slice){ .data = (const uint8_t *)p, .len = n };
}
static inline stm_mut_slice stm_mut_slice_from(void *p, size_t n) {
    return (stm_mut_slice){ .data = (uint8_t *)p, .len = n };
}

/* ------------------------------------------------------------------------- */
/* Misc compile-time helpers.                                                */
/* ------------------------------------------------------------------------- */

#define STM_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define STM_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

#ifdef __GNUC__
#  define STM_MUST_USE   __attribute__((warn_unused_result))
#  define STM_PACKED     __attribute__((packed))
#  define STM_UNUSED     __attribute__((unused))
#  define STM_LIKELY(x)   __builtin_expect(!!(x), 1)
#  define STM_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#  define STM_MUST_USE
#  define STM_PACKED
#  define STM_UNUSED
#  define STM_LIKELY(x)   (x)
#  define STM_UNLIKELY(x) (x)
#endif

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_TYPES_H */
