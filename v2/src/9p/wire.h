/* SPDX-License-Identifier: ISC */
/*
 * Private wire helpers for the filesystem 9P2000.L server. Little-
 * endian packers and bounds-checked unpackers. 9P is little-endian
 * on the wire.
 *
 * Mirrors `src/p9/wire.h` (janus's codec). Kept as a separate copy
 * to keep the audit-trigger surface boundaries clean — every change
 * to either codec is independently auditable.
 */
#ifndef STRATUM_V2_9P_WIRE_H
#define STRATUM_V2_9P_WIRE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint8_t  p9l_g8 (const uint8_t *p) { return p[0]; }
static inline uint16_t p9l_g16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t p9l_g32(const uint8_t *p) {
    return (uint32_t)p[0]        | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint64_t p9l_g64(const uint8_t *p) {
    return (uint64_t)p9l_g32(p) | ((uint64_t)p9l_g32(p + 4) << 32);
}
static inline void p9l_p8 (uint8_t *p, uint8_t  v) { p[0] = v; }
static inline void p9l_p16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static inline void p9l_p32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static inline void p9l_p64(uint8_t *p, uint64_t v) {
    p9l_p32(p,     (uint32_t)v);
    p9l_p32(p + 4, (uint32_t)(v >> 32));
}

/* Write a 9P string [u16 len][data] and advance *pp. Caller MUST have
 * reserved at least 2 + len bytes. */
static inline void p9l_pstr(uint8_t **pp, const char *s, uint16_t len) {
    p9l_p16(*pp, len); *pp += 2;
    if (len) { memcpy(*pp, s, len); *pp += len; }
}

/* Read a bounds-checked 9P string from *pp, not past `end`. On success
 * returns the pointer into the wire buffer (NOT NUL-terminated) and
 * advances *pp. On truncation returns NULL and leaves *pp untouched. */
static inline const char *p9l_gstr(const uint8_t **pp, const uint8_t *end,
                                       uint16_t *out_len)
{
    const uint8_t *p = *pp;
    if (end - p < 2) { *out_len = 0; return NULL; }
    uint16_t len = p9l_g16(p);
    if ((size_t)(end - p - 2) < (size_t)len) { *out_len = 0; return NULL; }
    *pp = p + 2 + len;
    *out_len = len;
    return (const char *)(p + 2);
}

/* Pack a 13-byte qid: [u8 type][u32 version][u64 path]. */
static inline void p9l_pqid(uint8_t *p, uint8_t type, uint32_t vers,
                                uint64_t path) {
    p[0] = type; p9l_p32(p + 1, vers); p9l_p64(p + 5, path);
}

#endif /* STRATUM_V2_9P_WIRE_H */
