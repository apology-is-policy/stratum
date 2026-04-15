#include "stratum/compress.h"
#include "stratum/bptr.h"

#include <string.h>
#include <errno.h>

#ifdef STM_HAVE_LZ4
#include <lz4.h>
#endif

#ifdef STM_HAVE_ZSTD
#include <zstd.h>
#endif

int stm_compress(uint8_t algo, const void *src, uint32_t src_len,
                 void *dst, uint32_t *dst_len)
{
    switch (algo) {
    case STM_COMP_NONE:
        if (*dst_len < src_len) return -EIO;
        memcpy(dst, src, src_len);
        *dst_len = src_len;
        return 0;

#ifdef STM_HAVE_LZ4
    case STM_COMP_LZ4: {
        int rc = LZ4_compress_default((const char *)src, (char *)dst,
                                      (int)src_len, (int)*dst_len);
        if (rc <= 0) return -EIO;
        *dst_len = (uint32_t)rc;
        return 0;
    }
#endif

#ifdef STM_HAVE_ZSTD
    case STM_COMP_ZSTD: {
        size_t rc = ZSTD_compress(dst, *dst_len, src, src_len, 3);
        if (ZSTD_isError(rc)) return -EIO;
        *dst_len = (uint32_t)rc;
        return 0;
    }
#endif

    default:
        return -EINVAL;
    }
}

int stm_decompress(uint8_t algo, const void *src, uint32_t src_len,
                   void *dst, uint32_t dst_len)
{
    switch (algo) {
    case STM_COMP_NONE:
        if (src_len > dst_len) return -EIO;
        memcpy(dst, src, src_len);
        return 0;

#ifdef STM_HAVE_LZ4
    case STM_COMP_LZ4: {
        int rc = LZ4_decompress_safe((const char *)src, (char *)dst,
                                     (int)src_len, (int)dst_len);
        if (rc < 0) return -EIO;
        return 0;
    }
#endif

#ifdef STM_HAVE_ZSTD
    case STM_COMP_ZSTD: {
        size_t rc = ZSTD_decompress(dst, dst_len, src, src_len);
        if (ZSTD_isError(rc)) return -EIO;
        return 0;
    }
#endif

    default:
        return -EINVAL;
    }
}

uint32_t stm_compress_bound(uint8_t algo, uint32_t src_len)
{
    switch (algo) {
    case STM_COMP_NONE:
        return src_len;

#ifdef STM_HAVE_LZ4
    case STM_COMP_LZ4:
        return (uint32_t)LZ4_compressBound((int)src_len);
#endif

#ifdef STM_HAVE_ZSTD
    case STM_COMP_ZSTD:
        return (uint32_t)ZSTD_compressBound((size_t)src_len);
#endif

    default:
        return src_len;
    }
}
