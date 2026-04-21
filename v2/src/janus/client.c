/* SPDX-License-Identifier: ISC */
/*
 * janus client — used by the FS to unwrap DEKs via the daemon.
 *
 * The connection is short-lived from the FS's perspective: one
 * `stm_janus_client_connect` + at least one `stm_janus_client_unwrap`
 * (typically at `stm_fs_mount`) + `stm_janus_client_disconnect`.
 * The raw DEK enters FS RAM briefly, gets handed to
 * `stm_alloc_set_crypt_ctx`, and the client handle is torn down.
 *
 * Wire protocol: 9P2000 over Unix socket. Each unwrap is:
 *     Twalk / Topen / Twrite / Tread / Tclunk
 * over a fresh fid. The connection's root fid lives for the client's
 * lifetime.
 *
 * Framing note: 9P messages begin with a 4-byte LE size field that
 * covers the whole message (size itself included). We use that to
 * drive read-exactly, so a short read never leaves us mid-message.
 */

#include <stratum/crypto.h>
#include <stratum/janus.h>
#include <stratum/p9.h>
#include <stratum/types.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define ROOT_FID   1u
#define CLIENT_MSIZE 65536u

struct stm_janus_client {
    int      fd;
    uint32_t msize;
    uint32_t next_fid;
    uint16_t next_tag;
    uint8_t *iobuf;
};

/* ── little-endian helpers ──────────────────────────────────────────── */

static void pack_u16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}
static void pack_u32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void pack_u64(uint8_t *p, uint64_t v) {
    pack_u32(p, (uint32_t)v); pack_u32(p + 4, (uint32_t)(v >> 32));
}
static uint32_t load_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t load_u16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* ── socket I/O ─────────────────────────────────────────────────────── */

static stm_status write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return STM_EIO;
        }
        if (n == 0) return STM_EIO;
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return STM_OK;
}

static stm_status read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return STM_EIO;
        }
        if (n == 0) return STM_EIO;   /* peer closed */
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return STM_OK;
}

/* Read one complete 9P message into client->iobuf. Returns the full
 * message size (including the 4-byte size prefix). Validates type +
 * tag; on Rerror, returns STM_EACCES and copies the error into the
 * caller's optional buffer. */
static stm_status read_one(stm_janus_client *c, uint8_t expected_type,
                             uint16_t expected_tag,
                             uint32_t *out_msg_len)
{
    stm_status rc = read_all(c->fd, c->iobuf, 4);
    if (rc != STM_OK) return rc;
    uint32_t msg_len = load_u32(c->iobuf);
    if (msg_len < STM_P9_HDR_SIZE || msg_len > c->msize) return STM_EPROTOCOL;
    rc = read_all(c->fd, c->iobuf + 4, msg_len - 4);
    if (rc != STM_OK) return rc;
    uint8_t type = c->iobuf[4];
    uint16_t tag = load_u16(c->iobuf + 5);
    if (tag != expected_tag) return STM_EPROTOCOL;
    if (type == STM_P9_RERROR) {
        /* Not logging the text yet; return a mappable error. */
        return STM_EACCES;
    }
    if (type != expected_type) return STM_EPROTOCOL;
    *out_msg_len = msg_len;
    return STM_OK;
}

/* ── handshake ──────────────────────────────────────────────────────── */

static stm_status do_version(stm_janus_client *c)
{
    uint8_t *p = c->iobuf + 7;
    pack_u32(p, CLIENT_MSIZE); p += 4;
    pack_u16(p, 6); p += 2; memcpy(p, "9P2000", 6); p += 6;
    uint32_t msg_len = (uint32_t)(p - c->iobuf);
    pack_u32(c->iobuf, msg_len);
    c->iobuf[4] = STM_P9_TVERSION;
    pack_u16(c->iobuf + 5, STM_P9_NOTAG);

    stm_status rc = write_all(c->fd, c->iobuf, msg_len);
    if (rc != STM_OK) return rc;

    rc = read_one(c, STM_P9_RVERSION, STM_P9_NOTAG, &msg_len);
    if (rc != STM_OK) return rc;
    uint32_t neg = load_u32(c->iobuf + 7);
    if (neg < 1024u || neg > CLIENT_MSIZE) return STM_EPROTOCOL;
    uint16_t vlen = load_u16(c->iobuf + 11);
    if (vlen < 6 || memcmp(c->iobuf + 13, "9P2000", 6) != 0) return STM_EPROTOCOL;
    c->msize = neg;
    return STM_OK;
}

static stm_status do_attach(stm_janus_client *c)
{
    uint8_t *p = c->iobuf + 7;
    pack_u32(p, ROOT_FID);         p += 4;
    pack_u32(p, STM_P9_NOFID);     p += 4;
    pack_u16(p, 0); p += 2;        /* uname */
    pack_u16(p, 0); p += 2;        /* aname */
    uint32_t msg_len = (uint32_t)(p - c->iobuf);
    pack_u32(c->iobuf, msg_len);
    c->iobuf[4] = STM_P9_TATTACH;
    uint16_t tag = c->next_tag++;
    pack_u16(c->iobuf + 5, tag);

    stm_status rc = write_all(c->fd, c->iobuf, msg_len);
    if (rc != STM_OK) return rc;
    return read_one(c, STM_P9_RATTACH, tag, &msg_len);
}

/* ── unwrap flow ────────────────────────────────────────────────────── */

static stm_status do_walk(stm_janus_client *c, uint32_t newfid,
                            uint16_t n_names, const char **names,
                            const uint16_t *name_lens)
{
    uint8_t *p = c->iobuf + 7;
    pack_u32(p, ROOT_FID);  p += 4;
    pack_u32(p, newfid);    p += 4;
    pack_u16(p, n_names);   p += 2;
    for (uint16_t i = 0; i < n_names; i++) {
        uint16_t nl = name_lens[i];
        pack_u16(p, nl); p += 2;
        memcpy(p, names[i], nl);
        p += nl;
    }
    uint32_t msg_len = (uint32_t)(p - c->iobuf);
    pack_u32(c->iobuf, msg_len);
    c->iobuf[4] = STM_P9_TWALK;
    uint16_t tag = c->next_tag++;
    pack_u16(c->iobuf + 5, tag);

    stm_status rc = write_all(c->fd, c->iobuf, msg_len);
    if (rc != STM_OK) return rc;
    rc = read_one(c, STM_P9_RWALK, tag, &msg_len);
    if (rc != STM_OK) return rc;
    uint16_t nw = load_u16(c->iobuf + 7);
    if (nw != n_names) return STM_ENOENT;
    return STM_OK;
}

static stm_status do_open(stm_janus_client *c, uint32_t fid, uint8_t mode)
{
    uint8_t *p = c->iobuf + 7;
    pack_u32(p, fid); p += 4;
    *p++ = mode;
    uint32_t msg_len = (uint32_t)(p - c->iobuf);
    pack_u32(c->iobuf, msg_len);
    c->iobuf[4] = STM_P9_TOPEN;
    uint16_t tag = c->next_tag++;
    pack_u16(c->iobuf + 5, tag);

    stm_status rc = write_all(c->fd, c->iobuf, msg_len);
    if (rc != STM_OK) return rc;
    return read_one(c, STM_P9_ROPEN, tag, &msg_len);
}

static stm_status do_write(stm_janus_client *c, uint32_t fid,
                             uint64_t offset, const uint8_t *data,
                             uint32_t len, uint32_t *out_written)
{
    if (len + STM_P9_HDR_SIZE + 4 + 8 + 4 > c->msize) return STM_ERANGE;
    uint8_t *p = c->iobuf + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, len);    p += 4;
    memcpy(p, data, len); p += len;
    uint32_t msg_len = (uint32_t)(p - c->iobuf);
    pack_u32(c->iobuf, msg_len);
    c->iobuf[4] = STM_P9_TWRITE;
    uint16_t tag = c->next_tag++;
    pack_u16(c->iobuf + 5, tag);

    stm_status rc = write_all(c->fd, c->iobuf, msg_len);
    if (rc != STM_OK) return rc;
    rc = read_one(c, STM_P9_RWRITE, tag, &msg_len);
    if (rc != STM_OK) return rc;
    *out_written = load_u32(c->iobuf + 7);
    return STM_OK;
}

static stm_status do_read(stm_janus_client *c, uint32_t fid, uint64_t offset,
                            uint32_t want, uint8_t *out, uint32_t *got)
{
    uint8_t *p = c->iobuf + 7;
    pack_u32(p, fid);    p += 4;
    pack_u64(p, offset); p += 8;
    pack_u32(p, want);   p += 4;
    uint32_t msg_len = (uint32_t)(p - c->iobuf);
    pack_u32(c->iobuf, msg_len);
    c->iobuf[4] = STM_P9_TREAD;
    uint16_t tag = c->next_tag++;
    pack_u16(c->iobuf + 5, tag);

    stm_status rc = write_all(c->fd, c->iobuf, msg_len);
    if (rc != STM_OK) return rc;
    rc = read_one(c, STM_P9_RREAD, tag, &msg_len);
    if (rc != STM_OK) return rc;
    /* R11 P2-1: underflow-safe bounds check. Rread's body is
     * count(4) + data[count]; the full message is thus at least
     * STM_P9_HDR_SIZE(7) + 4 = 11 bytes. A malicious daemon returning
     * msg_len in [7,10] would otherwise make `msg_len - 11` wrap to a
     * huge u32 and the subsequent `count > that` check pass for any
     * count. */
    if (msg_len < 11u) return STM_EPROTOCOL;
    uint32_t count = load_u32(c->iobuf + 7);
    if (count > msg_len - 11u) return STM_EPROTOCOL;
    if (count > want) return STM_EPROTOCOL;
    memcpy(out, c->iobuf + 11, count);
    /* R11 P3-5: wipe the copy left in iobuf. DEK bytes in the
     * client's scratch buffer otherwise live until disconnect; a
     * long-lived connection (P4-4c) would widen that exposure. */
    stm_ct_memzero(c->iobuf + 11, count);
    *got = count;
    return STM_OK;
}

static stm_status do_clunk(stm_janus_client *c, uint32_t fid)
{
    uint8_t *p = c->iobuf + 7;
    pack_u32(p, fid); p += 4;
    uint32_t msg_len = (uint32_t)(p - c->iobuf);
    pack_u32(c->iobuf, msg_len);
    c->iobuf[4] = STM_P9_TCLUNK;
    uint16_t tag = c->next_tag++;
    pack_u16(c->iobuf + 5, tag);

    stm_status rc = write_all(c->fd, c->iobuf, msg_len);
    if (rc != STM_OK) return rc;
    return read_one(c, STM_P9_RCLUNK, tag, &msg_len);
}

/* ── public API ─────────────────────────────────────────────────────── */

stm_status stm_janus_client_connect(const char *socket_path,
                                      stm_janus_client **out)
{
    if (!socket_path || !out) return STM_EINVAL;
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    size_t plen = strlen(socket_path);
    if (plen >= sizeof sa.sun_path) return STM_EINVAL;
    memcpy(sa.sun_path, socket_path, plen + 1);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return STM_EIO;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return (errno == EACCES) ? STM_EACCES : STM_EIO;
    }

    stm_janus_client *c = calloc(1, sizeof *c);
    if (!c) { close(fd); return STM_ENOMEM; }
    c->iobuf = calloc(1, CLIENT_MSIZE);
    if (!c->iobuf) { free(c); close(fd); return STM_ENOMEM; }
    c->fd = fd;
    c->msize = CLIENT_MSIZE;
    c->next_fid = ROOT_FID + 1;
    c->next_tag = 0;

    stm_status rc = do_version(c);
    if (rc != STM_OK) goto fail;
    rc = do_attach(c);
    if (rc != STM_OK) goto fail;

    *out = c;
    return STM_OK;
fail:
    close(c->fd);
    stm_ct_memzero(c->iobuf, CLIENT_MSIZE);
    free(c->iobuf);
    free(c);
    return rc;
}

static void uuid_to_hex(const uint8_t uuid[16], char out[37])
{
    static const char hex[] = "0123456789abcdef";
    size_t p = 0;
    for (size_t i = 0; i < 16; i++) {
        out[p++] = hex[uuid[i] >> 4];
        out[p++] = hex[uuid[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) out[p++] = '-';
    }
    out[p] = '\0';
}

stm_status stm_janus_client_unwrap(stm_janus_client *c,
                                     const uint8_t pool_uuid[16],
                                     uint64_t dataset_id,
                                     uint64_t key_id,
                                     const void *wrapped,
                                     size_t wrapped_len,
                                     void *out_dek,
                                     size_t *inout_dek_len)
{
    if (!c || !pool_uuid || !wrapped || !out_dek || !inout_dek_len)
        return STM_EINVAL;
    if (wrapped_len <= STM_HYBRID_WRAP_OVERHEAD) return STM_EINVAL;
    size_t expect_dek = wrapped_len - STM_HYBRID_WRAP_OVERHEAD;
    if (*inout_dek_len < expect_dek) return STM_ERANGE;

    /* Build walk path: ["pools", "<uuid>", "datasets", "<ds>", "unwrap"]. */
    char uuid_s[37];
    uuid_to_hex(pool_uuid, uuid_s);
    char ds_s[21];
    int ds_len = snprintf(ds_s, sizeof ds_s, "%llu", (unsigned long long)dataset_id);
    if (ds_len < 0) return STM_EINVAL;
    const char *names[5] = { "pools", uuid_s, "datasets", ds_s, "unwrap" };
    uint16_t lens[5] = { 5, 36, 8, (uint16_t)ds_len, 6 };

    uint32_t unwrap_fid = c->next_fid++;
    stm_status rc = do_walk(c, unwrap_fid, 5, names, lens);
    if (rc != STM_OK) return rc;
    rc = do_open(c, unwrap_fid, STM_P9_ORDWR);
    if (rc != STM_OK) { (void)do_clunk(c, unwrap_fid); return rc; }

    /* Write: key_id (8 LE) + wrapped bytes. */
    uint8_t hdr[STM_JANUS_UNWRAP_REQ_HDR];
    for (size_t i = 0; i < 8; i++) hdr[i] = (uint8_t)(key_id >> (i * 8));

    uint64_t offset = 0;
    uint32_t written = 0;
    rc = do_write(c, unwrap_fid, offset, hdr, sizeof hdr, &written);
    if (rc != STM_OK) goto done;
    if (written != sizeof hdr) { rc = STM_EIO; goto done; }
    offset += written;

    /* Write wrapped in one shot — wrapped_len is ~1200 bytes, well
     * under msize. */
    if (wrapped_len + STM_P9_HDR_SIZE + 4 + 8 + 4 > c->msize) {
        rc = STM_ERANGE;
        goto done;
    }
    rc = do_write(c, unwrap_fid, offset, wrapped, (uint32_t)wrapped_len, &written);
    if (rc != STM_OK) goto done;
    if ((size_t)written != wrapped_len) { rc = STM_EIO; goto done; }

    /* Read the DEK in chunks. */
    size_t read_off = 0;
    uint32_t avail_max = c->msize - STM_P9_HDR_SIZE - 4u;
    while (read_off < expect_dek) {
        uint32_t want = (expect_dek - read_off > avail_max)
                          ? avail_max : (uint32_t)(expect_dek - read_off);
        uint32_t got = 0;
        rc = do_read(c, unwrap_fid, read_off, want,
                       (uint8_t *)out_dek + read_off, &got);
        if (rc != STM_OK) goto done;
        if (got == 0) { rc = STM_EBADTAG; goto done; }  /* short response */
        read_off += got;
    }
    *inout_dek_len = read_off;
    rc = STM_OK;

done: {
    stm_status rc2 = do_clunk(c, unwrap_fid);
    if (rc == STM_OK && rc2 != STM_OK) rc = rc2;
    return rc;
}
}

stm_status stm_janus_client_rotate(stm_janus_client *c,
                                     const uint8_t pool_uuid[16],
                                     uint64_t dataset_id,
                                     uint64_t new_key_id,
                                     void *out_dek, size_t *inout_dek_len,
                                     void *out_wrapped, size_t *inout_wrapped_len)
{
    if (!c || !pool_uuid || !out_dek || !inout_dek_len
            || !out_wrapped || !inout_wrapped_len) return STM_EINVAL;
    const size_t dek_len     = 32u;
    const size_t wrapped_len = dek_len + STM_HYBRID_WRAP_OVERHEAD;
    if (*inout_dek_len     < dek_len)     return STM_ERANGE;
    if (*inout_wrapped_len < wrapped_len) return STM_ERANGE;

    /* Walk /pools/<uuid>/datasets/<N>/rotate. */
    char uuid_s[37];
    uuid_to_hex(pool_uuid, uuid_s);
    char ds_s[21];
    int ds_len = snprintf(ds_s, sizeof ds_s, "%llu",
                          (unsigned long long)dataset_id);
    if (ds_len < 0) return STM_EINVAL;
    const char *names[5] = { "pools", uuid_s, "datasets", ds_s, "rotate" };
    uint16_t lens[5] = { 5, 36, 8, (uint16_t)ds_len, 6 };

    uint32_t fid = c->next_fid++;
    stm_status rc = do_walk(c, fid, 5, names, lens);
    if (rc != STM_OK) return rc;
    rc = do_open(c, fid, STM_P9_ORDWR);
    if (rc != STM_OK) { (void)do_clunk(c, fid); return rc; }

    /* Write new_key_id as 8 LE bytes. */
    uint8_t hdr[STM_JANUS_ROTATE_REQ_HDR];
    for (size_t i = 0; i < 8; i++)
        hdr[i] = (uint8_t)(new_key_id >> (i * 8));
    uint32_t written = 0;
    rc = do_write(c, fid, 0, hdr, sizeof hdr, &written);
    if (rc != STM_OK) goto done;
    if (written != sizeof hdr) { rc = STM_EIO; goto done; }

    /* Read back dek(32) || wrapped(dek_len + OVERHEAD) in chunks. The
     * daemon lays them out contiguously in resp_buf. */
    uint8_t   *cursor       = NULL;
    size_t     want_total   = dek_len + wrapped_len;
    uint8_t   *composite    = calloc(1, want_total);
    if (!composite) { rc = STM_ENOMEM; goto done; }

    size_t read_off = 0;
    uint32_t avail_max = c->msize - STM_P9_HDR_SIZE - 4u;
    while (read_off < want_total) {
        uint32_t want = (want_total - read_off > avail_max)
                          ? avail_max : (uint32_t)(want_total - read_off);
        uint32_t got = 0;
        rc = do_read(c, fid, read_off, want, composite + read_off, &got);
        if (rc != STM_OK) {
            stm_ct_memzero(composite, want_total);
            free(composite);
            goto done;
        }
        if (got == 0) {
            /* Short response — daemon produced fewer bytes than
             * expected; tag the result as truncated to make this
             * observable at the call site. R11 P2-1 guards against
             * malformed frames; this guards against a well-framed
             * but under-sized response. */
            stm_ct_memzero(composite, want_total);
            free(composite);
            rc = STM_EBADTAG;
            goto done;
        }
        read_off += got;
    }
    cursor = composite;
    memcpy(out_dek,     cursor,           dek_len);
    memcpy(out_wrapped, cursor + dek_len, wrapped_len);
    *inout_dek_len     = dek_len;
    *inout_wrapped_len = wrapped_len;
    stm_ct_memzero(composite, want_total);
    free(composite);
    rc = STM_OK;

done: {
    stm_status rc2 = do_clunk(c, fid);
    if (rc == STM_OK && rc2 != STM_OK) rc = rc2;
    return rc;
}
}

void stm_janus_client_disconnect(stm_janus_client *c)
{
    if (!c) return;
    if (c->fd >= 0) {
        (void)do_clunk(c, ROOT_FID);
        close(c->fd);
    }
    if (c->iobuf) {
        stm_ct_memzero(c->iobuf, CLIENT_MSIZE);
        free(c->iobuf);
    }
    free(c);
}
