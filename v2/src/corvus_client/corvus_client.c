/* SPDX-License-Identifier: ISC */
/*
 * corvus_client — TLY-A3-impl-1 codec + token loader.
 *
 * See <stratum/corvus_client.h> for the public surface + wire-format
 * description. R111 doctrine carry — every length parsed off the
 * wire is bound-checked before use; strict-equality on payload_len
 * vs trailing buffer length; caller-cap on every server-supplied
 * count.
 */

#include <stratum/corvus_client.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Little-endian byte writers/readers.                                    */
/* ────────────────────────────────────────────────────────────────────── */

static void store_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void store_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xFFu);
}

static uint16_t load_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ────────────────────────────────────────────────────────────────────── */
/* UNWRAP encode.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

size_t stm_corvus_encode_unwrap_size(size_t dataset_len, size_t wrapped_len)
{
    if (dataset_len > STM_CORVUS_DATASET_MAX) return 0;
    if (wrapped_len > STM_CORVUS_WRAPPED_MAX) return 0;
    /* 4 (header: verb + ver + payload_len) + 33 (token) + 1 (ds_len)
     * + dataset_len + 8 (key_id) + 2 (wrapped_len) + wrapped_len. */
    return 4u + STM_CORVUS_TOKEN_LEN + 1u + dataset_len
         + 8u + 2u + wrapped_len;
}

stm_status stm_corvus_encode_unwrap(const uint8_t token[STM_CORVUS_TOKEN_LEN],
                                       const char *dataset,
                                       size_t dataset_len,
                                       uint64_t key_id,
                                       const uint8_t *wrapped,
                                       size_t wrapped_len,
                                       uint8_t *out_buf,
                                       size_t out_cap,
                                       size_t *out_len)
{
    if (!token || (!dataset && dataset_len > 0) || (!wrapped && wrapped_len > 0)
        || !out_buf || !out_len) return STM_EINVAL;
    if (dataset_len > STM_CORVUS_DATASET_MAX) return STM_EINVAL;
    if (wrapped_len > STM_CORVUS_WRAPPED_MAX) return STM_EINVAL;

    size_t total = stm_corvus_encode_unwrap_size(dataset_len, wrapped_len);
    if (total == 0) return STM_EINVAL; /* defense-in-depth */
    if (out_cap < total) return STM_ENOSPC;

    /* payload_len counts the bytes AFTER the 4-byte header
     * (verb_id + protocol_version + payload_len LE). The wire spec
     * §5.2 isn't explicit on this question; we adopt the natural
     * reading: payload_len = (frame total) - 4. */
    size_t payload_len = total - 4u;
    if (payload_len > UINT16_MAX) return STM_EINVAL; /* unreachable
                                                     * under the caps
                                                     * above but pin
                                                     * the invariant. */

    uint8_t *p = out_buf;
    *p++ = STM_CORVUS_VERB_UNWRAP;
    *p++ = STM_CORVUS_PROTO_V1;
    store_le16(p, (uint16_t)payload_len);
    p += 2;
    memcpy(p, token, STM_CORVUS_TOKEN_LEN);
    p += STM_CORVUS_TOKEN_LEN;
    *p++ = (uint8_t)dataset_len;
    if (dataset_len > 0) {
        memcpy(p, dataset, dataset_len);
        p += dataset_len;
    }
    store_le64(p, key_id);
    p += 8;
    store_le16(p, (uint16_t)wrapped_len);
    p += 2;
    if (wrapped_len > 0) {
        memcpy(p, wrapped, wrapped_len);
        p += wrapped_len;
    }

    *out_len = (size_t)(p - out_buf);
    /* Defense-in-depth: the computed length matches the predicted
     * total. If not, we wrote off-by-one bytes that would surface
     * as a corvus BadFormat on the wire. */
    if (*out_len != total) return STM_EBACKEND;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* UNWRAP decode.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_corvus_decode_response(const uint8_t *buf, size_t len,
                                          stm_corvus_status *out_status,
                                          uint8_t *out_dek,
                                          size_t out_dek_cap)
{
    if (!buf || !out_status) return STM_EINVAL;
    /* Sentinel out-of-enum value for the failure path. */
    const stm_corvus_status SENTINEL =
        (stm_corvus_status)(STM_CORVUS_STATUS_INTERNAL_ERROR + 1);
    *out_status = SENTINEL;

    if (len < 3u) return STM_EPROTOCOL;

    uint8_t  status_byte = buf[0];
    uint16_t payload_len = load_le16(buf + 1);

    /* Strict-equality on framing (R111 P3 F-10 carry): the buffer's
     * trailing length MUST equal payload_len. Truncated AND
     * oversize-trailing-bytes both refused. */
    if ((size_t)payload_len != len - 3u) return STM_EPROTOCOL;

    /* Validate status byte is a known value. */
    switch (status_byte) {
    case STM_CORVUS_STATUS_OK:
    case STM_CORVUS_STATUS_BAD_AUTH:
    case STM_CORVUS_STATUS_PERM_DENIED:
    case STM_CORVUS_STATUS_NOT_FOUND:
    case STM_CORVUS_STATUS_RATE_LIMITED:
    case STM_CORVUS_STATUS_BAD_FORMAT:
    case STM_CORVUS_STATUS_INTERNAL_ERROR:
        break;
    default:
        return STM_EPROTOCOL;
    }

    /* Status-payload discipline: status=OK → payload must be
     * exactly 32 bytes (the DEK). All other statuses → payload
     * must be exactly 0 bytes. Any disagreement is a frame from a
     * non-conforming peer; refuse. */
    if (status_byte == STM_CORVUS_STATUS_OK) {
        if (payload_len != STM_CORVUS_DEK_LEN) return STM_EPROTOCOL;
        if (out_dek) {
            if (out_dek_cap < STM_CORVUS_DEK_LEN) return STM_ENOSPC;
            memcpy(out_dek, buf + 3, STM_CORVUS_DEK_LEN);
        }
    } else {
        if (payload_len != 0u) return STM_EPROTOCOL;
    }

    *out_status = (stm_corvus_status)status_byte;
    return STM_OK;
}

stm_status stm_corvus_status_to_stm(stm_corvus_status s)
{
    switch (s) {
    case STM_CORVUS_STATUS_OK:             return STM_OK;
    case STM_CORVUS_STATUS_BAD_AUTH:       return STM_ECORVUSAUTH;
    case STM_CORVUS_STATUS_PERM_DENIED:    return STM_ECORVUSPERM;
    case STM_CORVUS_STATUS_NOT_FOUND:      return STM_ECORVUSNOTFOUND;
    case STM_CORVUS_STATUS_RATE_LIMITED:   return STM_ECORVUSRATELIMITED;
    case STM_CORVUS_STATUS_BAD_FORMAT:     return STM_ECORVUSBADFORMAT;
    case STM_CORVUS_STATUS_INTERNAL_ERROR: return STM_ECORVUSINTERNAL;
    }
    return STM_EPROTOCOL;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Session token loader.                                                   */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_corvus_load_token(const char *path,
                                     uint8_t out_token[STM_CORVUS_TOKEN_LEN])
{
    if (!path || !out_token) return STM_EINVAL;

    /* O_CLOEXEC: never leak the token fd to fork+exec'd children. */
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags);
    if (fd < 0) {
        if (errno == ENOENT) return STM_ENOENT;
        return STM_EIO;
    }

    /* fstat: verify regular file + exact length. The mode-bits
     * check is deferred to the caller (stratumd's CLI/run.c is
     * the right place to enforce 0400/0600). */
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return STM_EIO;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return STM_ENOENT;
    }
    if ((uintmax_t)st.st_size != (uintmax_t)STM_CORVUS_TOKEN_LEN) {
        close(fd);
        return STM_ERANGE;
    }

    /* Best-effort mlock + MADV_DONTDUMP on the destination buffer.
     * mlock is best-effort because the caller's buffer may already
     * be mlock'd, or the process may lack CAP_IPC_LOCK; either way
     * we don't fail the load on mlock failure. */
    (void)mlock(out_token, STM_CORVUS_TOKEN_LEN);
#if defined(__linux__) && defined(MADV_DONTDUMP)
    (void)madvise(out_token, STM_CORVUS_TOKEN_LEN, MADV_DONTDUMP);
#endif

    /* Read exactly STM_CORVUS_TOKEN_LEN bytes. Loop on EINTR;
     * partial-read short of the bound is fatal. */
    size_t done = 0;
    while (done < STM_CORVUS_TOKEN_LEN) {
        ssize_t n = read(fd, out_token + done, STM_CORVUS_TOKEN_LEN - done);
        if (n == 0) {
            close(fd);
            return STM_ERANGE; /* EOF before 33 bytes — shouldn't
                                * happen post-fstat but defense. */
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return STM_EIO;
        }
        done += (size_t)n;
    }

    /* Defensive trailing-byte check: stat said size == 33, but a
     * concurrent writer could have appended between stat + read.
     * A 34th byte at this point means the file changed underfoot. */
    uint8_t extra;
    ssize_t n_extra = read(fd, &extra, 1);
    close(fd);
    if (n_extra > 0) return STM_ERANGE;

    return STM_OK;
}
