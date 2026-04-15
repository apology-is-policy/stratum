#ifndef STM_COMPRESS_H
#define STM_COMPRESS_H

#include "stratum/types.h"

/* Compress src_len bytes from src into dst.
 * *dst_len is the buffer capacity on entry, compressed size on return.
 * Returns 0 on success, -EIO on failure, -EINVAL for unknown algo. */
int stm_compress(uint8_t algo, const void *src, uint32_t src_len,
                 void *dst, uint32_t *dst_len);

/* Decompress src_len bytes from src into dst of capacity dst_len.
 * Returns 0 on success, -EIO on failure, -EINVAL for unknown algo. */
int stm_decompress(uint8_t algo, const void *src, uint32_t src_len,
                   void *dst, uint32_t dst_len);

/* Maximum compressed size for a given input length. */
uint32_t stm_compress_bound(uint8_t algo, uint32_t src_len);

#endif /* STM_COMPRESS_H */
