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
 * The first record MUST be HEADER. Subsequent CHUNK / EXTENT records
 * are dispatched to the sync layer:
 *   - CHUNK → stm_sync_recv_cold_chunk (BLAKE3-verify + intern into
 *     CAS); add hash to per-stream chunks_seen.
 *   - HOT EXTENT → stm_sync_write_extent (P7-10: re-encrypts under
 *     the receiver pool's CURRENT DEK for the target dataset_id —
 *     fresh paddrs + receiver-side key_id; no nonce reuse hazard
 *     across pools, no key sharing across pools).
 *   - COLD EXTENT (P7-CAS-10) → stm_sync_recv_cold_extent_ref. The
 *     wire body carries only ino/off/len/gen + content_hash; the
 *     chunk's bytes were already received via a prior CHUNK record
 *     (sender enforces this; recv enforces it via chunks_seen
 *     membership check).
 *
 * The final END record carries a BLAKE3 csum over every prior
 * record's framing + body bytes; recv computes its own running hash
 * and rejects on mismatch.
 *
 * P7-CAS-10 lifecycle: every successful CHUNK record bumps the
 * target's CAS refcount by 1 (intern's MISS-insert at 1 or HIT-bump
 * += 1). The recv handle's chunks_seen tracks each interned hash.
 * recv_close iterates chunks_seen and calls
 * stm_sync_recv_cold_chunk_release for each, undoing the per-CHUNK
 * intern bump. Net result: refcount = (number of COLD EXTENTs in
 * this stream that referenced the hash) + (any pre-existing
 * receiver-side refcount). Same final-state invariant as
 * stm_sync_recv_cold_extent's atomic intern+write-extent path.
 *
 * Operator preconditions for receive: the target_dataset_id MUST
 * already have a CURRENT DEK in the receiver's keyschema. The root
 * dataset (id=1) is provisioned at sync_create; other datasets need
 * the operator to call stm_sync_add_dataset_key before stm_recv_init.
 * Without that, stm_sync_write_extent returns STM_ENOENT for every
 * EXTENT record and recv reports STM_ENOENT to the caller.
 *
 * Errors are sticky: once recv enters STATE_FAILED, all subsequent
 * apply / finish calls return STM_EPROTOCOL. recv_close still drains
 * chunks_seen on FAILED — orphan refs would otherwise survive the
 * next commit and pin the chunk indefinitely.
 */

#include <stratum/send_recv.h>

#include <stratum/hash.h>
#include <stratum/sync.h>

#include <stdlib.h>
#include <string.h>

#define RECV_CHUNK_HASH_LEN 32u

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
    /* P7-CAS-10: per-stream tracking of hashes interned via CHUNK
     * records. Each entry is one BLAKE3-256 (32 bytes). recv_close
     * drains this set via stm_sync_recv_cold_chunk_release calls.
     * Linear-scan membership (O(K)); upgrade to hash-table when
     * stream sizes routinely exceed ~10k unique chunks. */
    uint8_t        *chunks_seen;      /* len n_chunks_seen × 32 bytes */
    size_t          n_chunks_seen;
    size_t          cap_chunks_seen;
    /* Stats / debugging. */
    uint64_t        n_extents_applied;
    uint64_t        n_chunks_applied;
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
 * STM_ECORRUPT). Output: *out_type, *out_flags, *out_body_len. */
static stm_status parse_record_hdr(const uint8_t *bytes, size_t total_len,
                                      uint32_t *out_type,
                                      uint32_t *out_flags,
                                      uint64_t *out_body_len)
{
    if (total_len < STM_SEND_RECORD_HDR_LEN) return STM_ECORRUPT;
    *out_type     = get_le32(bytes + 0);
    *out_flags    = get_le32(bytes + 4);
    *out_body_len = get_le64(bytes + 8);
    if (*out_body_len > SIZE_MAX - STM_SEND_RECORD_HDR_LEN) return STM_ECORRUPT;
    if ((size_t)(*out_body_len) + STM_SEND_RECORD_HDR_LEN != total_len)
        return STM_ECORRUPT;
    /* P7-CAS-9: refuse unknown flag bits — protocol-evolution
     * discipline. A future flag bit (e.g. compression, larger
     * record) shipped by a newer sender to an older receiver
     * deserves a hard refusal rather than silent ignore. */
    if ((*out_flags & ~STM_SEND_FLAG_KNOWN_MASK) != 0u) return STM_ECORRUPT;
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

/* P7-CAS-10: drain chunks_seen via stm_sync_recv_cold_chunk_release
 * one entry at a time. Errors are logged-and-ignored — under sound
 * recv state every refcount in chunks_seen was bumped by an earlier
 * intern in this handle, so a deref MUST succeed; if it doesn't, the
 * cas_idx is in an unexpected state but proceeding to the next deref
 * is the only forward move (a wedged sync is fine: the deref is
 * idempotent on the in-RAM cas shadow and the next commit either
 * persists or doesn't, but in either case we want EVERY chunk to be
 * touched lest one slip through). */
static void recv_drain_chunks_seen(stm_recv_handle *h)
{
    if (!h->chunks_seen) return;
    for (size_t i = 0; i < h->n_chunks_seen; i++) {
        const uint8_t *hash = h->chunks_seen + (i * RECV_CHUNK_HASH_LEN);
        (void)stm_sync_recv_cold_chunk_release(h->sync, hash);
    }
    free(h->chunks_seen);
    h->chunks_seen      = NULL;
    h->n_chunks_seen    = 0;
    h->cap_chunks_seen  = 0;
}

void stm_recv_close(stm_recv_handle *h)
{
    if (!h) return;
    /* Drain chunks_seen ON ALL paths (success / failure / done) so
     * the cas_idx is left in a consistent refcount state. Without
     * this drain, any CHUNKs interned in this stream would persist
     * with refcount = (extent refs) + (per-CHUNK intern bump) — the
     * +1 leak. */
    recv_drain_chunks_seen(h);
    if (h->hasher) stm_blake3_free(h->hasher);
    free(h);
}

/* Return true if `hash` is already in chunks_seen. Linear scan. */
static bool chunks_seen_contains(const stm_recv_handle *h,
                                    const uint8_t hash[RECV_CHUNK_HASH_LEN])
{
    for (size_t i = 0; i < h->n_chunks_seen; i++) {
        const uint8_t *e = h->chunks_seen + (i * RECV_CHUNK_HASH_LEN);
        if (memcmp(e, hash, RECV_CHUNK_HASH_LEN) == 0) return true;
    }
    return false;
}

/* Append `hash` to chunks_seen. Caller MUST verify chunks_seen_contains
 * is false beforehand (duplicate CHUNK record in a stream is a
 * protocol violation — caught at apply_chunk). */
static stm_status chunks_seen_add(stm_recv_handle *h,
                                     const uint8_t hash[RECV_CHUNK_HASH_LEN])
{
    if (h->n_chunks_seen == h->cap_chunks_seen) {
        size_t new_cap = h->cap_chunks_seen == 0 ? 8 : h->cap_chunks_seen * 2;
        uint8_t *grown = realloc(h->chunks_seen,
                                    new_cap * RECV_CHUNK_HASH_LEN);
        if (!grown) return STM_ENOMEM;
        h->chunks_seen     = grown;
        h->cap_chunks_seen = new_cap;
    }
    memcpy(h->chunks_seen + (h->n_chunks_seen * RECV_CHUNK_HASH_LEN),
              hash, RECV_CHUNK_HASH_LEN);
    h->n_chunks_seen++;
    return STM_OK;
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
                                  const uint8_t *body, uint64_t body_len,
                                  uint32_t flags)
{
    if (body_len < STM_SEND_EXTENT_META_LEN) return STM_ECORRUPT;
    uint64_t ino = get_le64(body + 0);
    uint64_t off = get_le64(body + 8);
    uint64_t len = get_le64(body + 16);
    /* gen @ +24 advisory; recv re-stamps with its own current_gen */
    if (ino == 0)  return STM_ECORRUPT;
    if (len == 0)  return STM_ECORRUPT;

    bool is_cold = (flags & STM_SEND_FLAG_COLD) != 0u;
    if (is_cold) {
        /* P7-CAS-10: COLD extent body is FIXED at 64 bytes (32B meta +
         * 32B content_hash); no plaintext follows. The chunk's bytes
         * were received via a prior STM_SEND_REC_CHUNK record. */
        if (body_len != STM_SEND_COLD_EXTENT_BODY_LEN) return STM_ECORRUPT;
        const uint8_t *claimed_hash = body + STM_SEND_EXTENT_META_LEN;

        /* Stream-ordering invariant: the hash MUST be in chunks_seen
         * (i.e. an earlier CHUNK record in this stream interned it).
         * Without this check, a sender could emit COLD EXTENTs
         * referencing hashes the receiver doesn't have a stream-bound
         * deref obligation for, leaking refs at recv_close. */
        if (!chunks_seen_contains(h, claimed_hash)) return STM_ECORRUPT;

        stm_status rs = stm_sync_recv_cold_extent_ref(h->sync,
                                                        h->target_dataset_id,
                                                        ino, off, len,
                                                        claimed_hash);
        if (rs != STM_OK) return rs;
    } else {
        if (body_len != STM_SEND_EXTENT_META_LEN + len) return STM_ECORRUPT;
        const uint8_t *plain = body + STM_SEND_EXTENT_META_LEN;
        /* Apply via stm_sync_write_extent — handles fan-out to N
         * replicas + AEAD encrypt under recv's pool key + extent
         * index update. */
        stm_status ws = stm_sync_write_extent(h->sync,
                                                 h->target_dataset_id, ino,
                                                 off, plain, (size_t)len);
        if (ws != STM_OK) return ws;
    }

    h->n_extents_applied++;
    return STM_OK;
}

/* P7-CAS-10: apply a STM_SEND_REC_CHUNK record. Body shape:
 *   0..32: BLAKE3-256 content_hash (claimed by the sender)
 *   32..32+len: plaintext (raw bytes)
 *
 * The receiver:
 *   1. Validates body_len >= 32 (hash prefix).
 *   2. Refuses duplicate CHUNK in the same stream (sender bug).
 *   3. Calls stm_sync_recv_cold_chunk which BLAKE3-verifies
 *      plaintext-vs-claimed-hash AND interns the chunk into the
 *      target's CAS index (refcount += 1).
 *   4. Tracks the hash in chunks_seen so recv_close can drain. */
static stm_status apply_chunk(stm_recv_handle *h,
                                 const uint8_t *body, uint64_t body_len)
{
    if (body_len < STM_SEND_CHUNK_HASH_LEN) return STM_ECORRUPT;
    size_t plain_len = (size_t)(body_len - STM_SEND_CHUNK_HASH_LEN);
    if (plain_len == 0u || plain_len > STM_SEND_CHUNK_PLAIN_MAX) return STM_ECORRUPT;

    const uint8_t *claimed_hash = body;
    const uint8_t *plain        = body + STM_SEND_CHUNK_HASH_LEN;

    /* Duplicate CHUNK in the same stream is a sender bug — at v1 the
     * sender dedupes by hash and emits each unique chunk once. */
    if (chunks_seen_contains(h, claimed_hash)) return STM_ECORRUPT;

    /* Reserve chunks_seen slot BEFORE the sync call so a successful
     * intern has a place to land; a failed intern means we don't
     * commit to the slot. */
    if (h->n_chunks_seen == h->cap_chunks_seen) {
        size_t new_cap = h->cap_chunks_seen == 0 ? 8 : h->cap_chunks_seen * 2;
        uint8_t *grown = realloc(h->chunks_seen,
                                    new_cap * RECV_CHUNK_HASH_LEN);
        if (!grown) return STM_ENOMEM;
        h->chunks_seen     = grown;
        h->cap_chunks_seen = new_cap;
    }

    stm_status cs = stm_sync_recv_cold_chunk(h->sync,
                                                claimed_hash,
                                                plain, plain_len);
    if (cs != STM_OK) return cs;

    /* Commit to the chunks_seen slot AFTER the intern succeeded. */
    stm_status as = chunks_seen_add(h, claimed_hash);
    if (as != STM_OK) {
        /* R61 P3-2: this rollback is intentional defense-in-depth.
         * Today `chunks_seen_add` can only fail with STM_ENOMEM, AND
         * the pre-grow above synchronizes capacity so the inner
         * realloc is a no-op; in this configuration the rollback is
         * dead code. DO NOT REMOVE: if a future refactor folds the
         * pre-grow into chunks_seen_add itself (single-source the
         * capacity check) the realloc moves back inside add, and an
         * OOM there leaves the cas_idx with a +1 intern bump that
         * MUST be balanced here lest the chunk leak at refcount=1
         * (auto_gc only reclaims refcount=0). */
        (void)stm_sync_recv_cold_chunk_release(h->sync, claimed_hash);
        return as;
    }

    h->n_chunks_applied++;
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
    /* R39 P2-3: cap the maximum record size up front. Any legitimate
     * record is ≤ STM_SEND_RECORD_MAX_LEN (16-byte framing + 32-byte
     * extent meta + STM_SEND_CHUNK_PLAIN_MAX plaintext; at v3 / UB v23
     * the plaintext cap is 8 MiB so the total max is 8388656 bytes —
     * see send_recv.h's STM_SEND_RECORD_MAX_LEN definition for the
     * lockstep with STM_FS_RECORDSIZE_MAX). A larger record indicates
     * either caller framing error or a hostile stream; refuse before
     * any per-type dispatch so callers can't be DOS'd into buffering
     * arbitrarily large blobs. */
    if (record_len > STM_SEND_RECORD_MAX_LEN) {
        h->state = RECV_FAILED;
        return STM_ECORRUPT;
    }
    if (h->state == RECV_FAILED || h->state == RECV_DONE) return STM_EPROTOCOL;

    const uint8_t *p = record_bytes;
    uint32_t type = 0;
    uint32_t flags = 0;
    uint64_t body_len = 0;
    stm_status ps = parse_record_hdr(p, record_len, &type, &flags, &body_len);
    if (ps != STM_OK) { h->state = RECV_FAILED; return ps; }

    const uint8_t *body = p + STM_SEND_RECORD_HDR_LEN;

    switch (type) {
    case STM_SEND_REC_HEADER: {
        if (h->state != RECV_AWAIT_HEADER) {
            h->state = RECV_FAILED;
            return STM_ECORRUPT;
        }
        /* HEADER flags reserved zero. */
        if (flags != 0u) { h->state = RECV_FAILED; return STM_ECORRUPT; }
        stm_status as = apply_header(h, body, body_len);
        if (as != STM_OK) { h->state = RECV_FAILED; return as; }
        /* Hash AFTER successful validation so a rejected header
         * doesn't poison the running csum. */
        stm_blake3_update(h->hasher, p, record_len);
        h->state = RECV_BODY;
        return STM_OK;
    }
    case STM_SEND_REC_CHUNK: {
        /* P7-CAS-10: out-of-band chunk store record; valid only in
         * the BODY state (HEADER must have been applied first). */
        if (h->state != RECV_BODY) {
            h->state = RECV_FAILED;
            return STM_ECORRUPT;
        }
        /* CHUNK flags reserved zero (no flag bits defined for CHUNK). */
        if (flags != 0u) { h->state = RECV_FAILED; return STM_ECORRUPT; }
        stm_status as = apply_chunk(h, body, body_len);
        if (as != STM_OK) { h->state = RECV_FAILED; return as; }
        stm_blake3_update(h->hasher, p, record_len);
        return STM_OK;
    }
    case STM_SEND_REC_EXTENT: {
        if (h->state != RECV_BODY) {
            h->state = RECV_FAILED;
            return STM_ECORRUPT;
        }
        stm_status as = apply_extent(h, body, body_len, flags);
        if (as != STM_OK) { h->state = RECV_FAILED; return as; }
        stm_blake3_update(h->hasher, p, record_len);
        return STM_OK;
    }
    case STM_SEND_REC_END: {
        if (h->state != RECV_BODY) {
            h->state = RECV_FAILED;
            return STM_ECORRUPT;
        }
        /* END flags reserved zero. */
        if (flags != 0u) { h->state = RECV_FAILED; return STM_ECORRUPT; }
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
