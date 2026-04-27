/* SPDX-License-Identifier: ISC */
/*
 * Recv — point-in-time dataset replication consumer.
 *
 *   see include/stratum/send_recv.h — surface + wire format.
 *
 * Recv is a strict state-machine over the wire format:
 *
 *   STATE_AWAIT_HEADER → STATE_BODY → STATE_DONE
 *
 * The first record MUST be HEADER. Subsequent EXTENT records are
 * dispatched to stm_sync_write_extent on the target dataset (which
 * re-encrypts under the receiver pool's metadata_key with fresh paddrs
 * — no nonce reuse hazard across pools). The final END record carries
 * a BLAKE3 csum over every prior record's framing+body bytes; recv
 * computes its own running hash and rejects on mismatch.
 *
 * Errors are sticky: once recv enters STATE_FAILED, all subsequent
 * apply / finish calls return STM_EPROTOCOL.
 */

#include <stratum/send_recv.h>

#include <stratum/hash.h>
#include <stratum/sync.h>

#include <stdlib.h>
#include <string.h>

typedef enum {
    RECV_AWAIT_HEADER = 0,
    RECV_BODY,
    RECV_DONE,
    RECV_FAILED,
} recv_state;

struct stm_recv_handle {
    stm_sync       *sync;             /* borrowed; must outlive handle */
    uint64_t        target_dataset_id;
    recv_state      state;
    stm_blake3_ctx *hasher;           /* running over emitted records */
    /* Stats / debugging. */
    uint64_t        n_extents_applied;
};

/* ------------------------------------------------------------------ */
/* Wire deserialization helpers.                                       */
/* ------------------------------------------------------------------ */

static uint32_t get_le32(const uint8_t *p) {
    le32 le; memcpy(le.v, p, 4);
    return stm_load_le32(le);
}

static uint64_t get_le64(const uint8_t *p) {
    le64 le; memcpy(le.v, p, 8);
    return stm_load_le64(le);
}

/* Parse a record's framing header. Returns the body length on
 * success; returns SIZE_MAX on malformed framing (caller treats as
 * STM_ECORRUPT). Output: *out_type set to the record type. */
static stm_status parse_record_hdr(const uint8_t *bytes, size_t total_len,
                                      uint32_t *out_type,
                                      uint64_t *out_body_len)
{
    if (total_len < STM_SEND_RECORD_HDR_LEN) return STM_ECORRUPT;
    *out_type     = get_le32(bytes + 0);
    /* flags @ +4 reserved; ignore */
    *out_body_len = get_le64(bytes + 8);
    if (*out_body_len > SIZE_MAX - STM_SEND_RECORD_HDR_LEN) return STM_ECORRUPT;
    if ((size_t)(*out_body_len) + STM_SEND_RECORD_HDR_LEN != total_len)
        return STM_ECORRUPT;
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Init / close.                                                       */
/* ------------------------------------------------------------------ */

stm_status stm_recv_init(stm_sync *sync,
                            uint64_t target_dataset_id,
                            stm_recv_handle **out_handle)
{
    if (!sync || !out_handle) return STM_EINVAL;
    if (target_dataset_id == 0) return STM_EINVAL;
    *out_handle = NULL;

    stm_recv_handle *h = calloc(1, sizeof(*h));
    if (!h) return STM_ENOMEM;
    h->sync              = sync;
    h->target_dataset_id = target_dataset_id;
    h->state             = RECV_AWAIT_HEADER;
    h->hasher            = stm_blake3_new();
    if (!h->hasher) { free(h); return STM_ENOMEM; }

    *out_handle = h;
    return STM_OK;
}

void stm_recv_close(stm_recv_handle *h)
{
    if (!h) return;
    if (h->hasher) stm_blake3_free(h->hasher);
    free(h);
}

/* ------------------------------------------------------------------ */
/* Apply: dispatch by record type.                                     */
/* ------------------------------------------------------------------ */

static stm_status apply_header(stm_recv_handle *h,
                                  const uint8_t *body, uint64_t body_len)
{
    (void)h;  /* recv side is permissive about source pool/ds — see docstring. */
    if (body_len != STM_SEND_HEADER_BODY_LEN) return STM_ECORRUPT;
    /* Magic + version. */
    uint32_t magic = get_le32(body + 0);
    uint32_t ver   = get_le32(body + 4);
    if (magic != STM_SEND_MAGIC) return STM_EBADVERSION;
    if (ver   != STM_SEND_VERSION) return STM_EBADVERSION;
    /* pool_uuid + dataset_id + from/to/txg are advisory at recv —
     * recv writes into target_dataset_id regardless of source's
     * dataset_id (the caller chose to map the stream onto a target). */
    return STM_OK;
}

static stm_status apply_extent(stm_recv_handle *h,
                                  const uint8_t *body, uint64_t body_len)
{
    if (body_len < STM_SEND_EXTENT_META_LEN) return STM_ECORRUPT;
    uint64_t ino = get_le64(body + 0);
    uint64_t off = get_le64(body + 8);
    uint64_t len = get_le64(body + 16);
    /* gen @ +24 advisory; recv re-stamps with its own current_gen */
    if (ino == 0)  return STM_ECORRUPT;
    if (len == 0)  return STM_ECORRUPT;
    if (body_len != STM_SEND_EXTENT_META_LEN + len) return STM_ECORRUPT;

    const uint8_t *plain = body + STM_SEND_EXTENT_META_LEN;

    /* Apply via stm_sync_write_extent — handles fan-out to N replicas
     * + AEAD encrypt under recv's pool key + extent index update. */
    stm_status ws = stm_sync_write_extent(h->sync,
                                             h->target_dataset_id, ino,
                                             off, plain, (size_t)len);
    if (ws != STM_OK) return ws;

    h->n_extents_applied++;
    return STM_OK;
}

static stm_status apply_end(stm_recv_handle *h,
                               const uint8_t *body, uint64_t body_len)
{
    if (body_len != STM_SEND_END_BODY_LEN) return STM_ECORRUPT;

    /* Compute our running BLAKE3 over all PRIOR records (header, extents)
     * and compare to the END's body. The END's framing header is NOT in
     * the hash domain — see send.c::emit_end_locked for the symmetric
     * exclusion. */
    uint8_t our_csum[STM_SEND_END_BODY_LEN];
    stm_blake3_final(h->hasher, our_csum, sizeof our_csum);

    if (memcmp(our_csum, body, STM_SEND_END_BODY_LEN) != 0)
        return STM_EBADTAG;
    return STM_OK;
}

stm_status stm_recv_apply(stm_recv_handle *h,
                             const void *record_bytes,
                             size_t record_len)
{
    if (!h || !record_bytes || record_len == 0) return STM_EINVAL;
    if (h->state == RECV_FAILED || h->state == RECV_DONE) return STM_EPROTOCOL;

    const uint8_t *p = record_bytes;
    uint32_t type = 0;
    uint64_t body_len = 0;
    stm_status ps = parse_record_hdr(p, record_len, &type, &body_len);
    if (ps != STM_OK) { h->state = RECV_FAILED; return ps; }

    const uint8_t *body = p + STM_SEND_RECORD_HDR_LEN;

    switch (type) {
    case STM_SEND_REC_HEADER: {
        if (h->state != RECV_AWAIT_HEADER) {
            h->state = RECV_FAILED;
            return STM_ECORRUPT;
        }
        stm_status as = apply_header(h, body, body_len);
        if (as != STM_OK) { h->state = RECV_FAILED; return as; }
        /* Hash AFTER successful validation so a rejected header
         * doesn't poison the running csum. */
        stm_blake3_update(h->hasher, p, record_len);
        h->state = RECV_BODY;
        return STM_OK;
    }
    case STM_SEND_REC_EXTENT: {
        if (h->state != RECV_BODY) {
            h->state = RECV_FAILED;
            return STM_ECORRUPT;
        }
        stm_status as = apply_extent(h, body, body_len);
        if (as != STM_OK) { h->state = RECV_FAILED; return as; }
        stm_blake3_update(h->hasher, p, record_len);
        return STM_OK;
    }
    case STM_SEND_REC_END: {
        if (h->state != RECV_BODY) {
            h->state = RECV_FAILED;
            return STM_ECORRUPT;
        }
        /* csum compares against running hash over PRIOR records only
         * — must NOT update hasher with END's bytes first. */
        stm_status as = apply_end(h, body, body_len);
        if (as != STM_OK) { h->state = RECV_FAILED; return as; }
        h->state = RECV_DONE;
        return STM_OK;
    }
    default:
        h->state = RECV_FAILED;
        return STM_ECORRUPT;
    }
}

stm_status stm_recv_finish(stm_recv_handle *h)
{
    if (!h) return STM_EINVAL;
    if (h->state == RECV_DONE) return STM_OK;
    return STM_EPROTOCOL;
}
