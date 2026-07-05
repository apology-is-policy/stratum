/* SPDX-License-Identifier: ISC */
/*
 * stm_btnode — internal (branch) node encode/decode (Phase 3 chunk 5b;
 * message buffer 9.8-BE-format).
 *
 *   see v2/include/stratum/btnode.h for the format spec.
 *
 * Internal-node payload layout (packed):
 *
 *   pivots (N variable-length):  le32 key_len || key bytes
 *   children (N+1 fixed size):   64 opaque bytes each
 *   messages (n_buffer_used bytes; 9.8-BE-format):
 *       [op:1][reserved:1][seq:6 LE][key_len:2 LE][value_len:4 LE][key][value]
 *
 * `n_payload_used` covers the whole payload; `n_buffer_used` the
 * trailing message region only, so the pivot/child prefix is
 * (payload_used − buffer_used) bytes. A node with n_buffer_used == 0
 * is byte-identical to the pre-9.8 encoding.
 *
 * The same 128-byte header + trailing BLAKE3 csum as the leaf encoding
 * (see leaf.c). Only the payload format differs. The node size is a
 * per-call parameter (`buf_size`) since 9.6-impl-1b.
 *
 * Trees that never buffer (btree_store's flush-before-serialize
 * contract) use the legacy stm_btnode_internal_decode, which REJECTS a
 * nonzero n_buffer_used — fail-closed against a buffered node reaching
 * a reader that would silently ignore its messages (stale reads).
 */

#include <stratum/btnode.h>

#include "btnode_common.h"

#include <string.h>

/* Header + csum helpers consolidated into common.c (R7c P2-4). */

/* ========================================================================= */
/* Message-region helpers (9.8-BE-format).                                    */
/* ========================================================================= */

size_t stm_btnode_msgs_encoded_bytes(const stm_btnode_msg *msgs,
                                       uint32_t n_msgs)
{
    size_t total = 0;
    if (msgs) {
        for (uint32_t i = 0; i < n_msgs; i++) {
            total += STM_BTNODE_MSG_HDR_SIZE
                   + msgs[i].key_len + msgs[i].value_len;
        }
    }
    return total;
}

/* Validate one caller-supplied message for encode. Caller-bad-args are
 * STM_EINVAL; over-bound sizes are STM_ERANGE (mirrors the pivot
 * discipline: shape errors EINVAL, capacity errors ERANGE). */
static stm_status msg_validate_for_encode(const stm_btnode_msg *m)
{
    if (m->op != STM_BTNODE_MSG_INSERT &&
        m->op != STM_BTNODE_MSG_DELETE)
        return STM_EINVAL;
    if (m->op == STM_BTNODE_MSG_DELETE && m->value_len != 0)
        return STM_EINVAL;                 /* tombstones carry no value */
    if (m->seq > STM_BTNODE_MSG_SEQ_MAX) return STM_ERANGE;
    if (m->key_len > STM_BTNODE_MSG_KEY_MAX) return STM_ERANGE;
    if (m->key_len > 0 && !m->key) return STM_EINVAL;
    if (m->value_len > 0 && !m->value) return STM_EINVAL;
    /* value_len is bounded structurally by the region cap at the
     * caller-level total; the engine's inline-value cap is the tree
     * layer's bound, not the codec's. */
    return STM_OK;
}

/* ========================================================================= */
/* Public: internal encode / decode.                                          */
/* ========================================================================= */

size_t stm_btnode_internal_encoded_bytes(const stm_btnode_pivot *pivots,
                                          uint32_t n_pivots)
{
    size_t total = 0;
    if (pivots) {
        for (uint32_t i = 0; i < n_pivots; i++) {
            total += 4u + pivots[i].key_len;
        }
    }
    total += ((size_t)n_pivots + 1u) * STM_BTNODE_CHILD_BPTR_SIZE;
    return total;
}

stm_status stm_btnode_internal_encode_msgs(const stm_btnode_pivot *pivots,
                                             uint32_t n_pivots,
                                             const uint8_t *children,
                                             size_t children_len,
                                             const stm_btnode_msg *msgs,
                                             uint32_t n_msgs,
                                             uint64_t gen, uint64_t tree_id,
                                             void *buf, size_t buf_size)
{
    if (!buf) return STM_EINVAL;
    if (buf_size < STM_BTNODE_MIN_SIZE) return STM_ERANGE;
    if (n_pivots > 0 && !pivots) return STM_EINVAL;
    if (!children) return STM_EINVAL;
    if (n_msgs > 0 && !msgs) return STM_EINVAL;

    /* N+1 children exactly (overflow-safe multiply: n_pivots is u32;
     * n_pivots + 1 can't overflow u32 unless n_pivots == UINT32_MAX,
     * which is rejected below by the payload-fit check anyway). */
    size_t expected_children =
        ((size_t)n_pivots + 1u) * STM_BTNODE_CHILD_BPTR_SIZE;
    if (children_len != expected_children) return STM_EINVAL;

    /* Message-region validation. */
    for (uint32_t i = 0; i < n_msgs; i++) {
        stm_status ms = msg_validate_for_encode(&msgs[i]);
        if (ms != STM_OK) return ms;
    }
    size_t msg_bytes = stm_btnode_msgs_encoded_bytes(msgs, n_msgs);
    if (msg_bytes > STM_BTNODE_BUFFER_REGION_MAX(buf_size))
        return STM_ERANGE;

    size_t pc_bytes = stm_btnode_internal_encoded_bytes(pivots, n_pivots);
    size_t payload_bytes = pc_bytes + msg_bytes;
    if (payload_bytes > STM_BTNODE_PAYLOAD_CAP(buf_size)) return STM_ERANGE;
    if (payload_bytes > UINT32_MAX) return STM_ERANGE;   /* le32 fields */

    uint8_t *out = (uint8_t *)buf;
    memset(out, 0, buf_size);

    btnode_hdr_write(out, STM_BTNODE_KIND_INTERNAL,
                     n_pivots, (uint32_t)msg_bytes,
                     (uint32_t)payload_bytes, gen, tree_id);

    uint8_t *p = out + STM_BTNODE_HDR_SIZE;

    /* Pivots. */
    for (uint32_t i = 0; i < n_pivots; i++) {
        const stm_btnode_pivot *pv = &pivots[i];
        if (pv->key_len > UINT32_MAX) return STM_ERANGE;
        if (pv->key_len > 0 && !pv->key) return STM_EINVAL;

        le32 kl = stm_store_le32((uint32_t)pv->key_len);
        memcpy(p, kl.v, 4); p += 4;
        if (pv->key_len) memcpy(p, pv->key, pv->key_len);
        p += pv->key_len;
    }

    /* Children blob. */
    memcpy(p, children, expected_children);
    p += expected_children;

    /* Messages (9.8-BE-format). Order preserved verbatim — the caller
     * supplies (target_child, seq) order; routing lives tree-side. */
    for (uint32_t i = 0; i < n_msgs; i++) {
        const stm_btnode_msg *m = &msgs[i];
        *p++ = m->op;
        *p++ = 0;                                   /* reserved — zero */
        for (int b = 0; b < 6; b++)                 /* seq, 48-bit LE */
            *p++ = (uint8_t)((m->seq >> (8 * b)) & 0xffu);
        le16 kl = stm_store_le16((uint16_t)m->key_len);
        memcpy(p, kl.v, 2); p += 2;
        le32 vl = stm_store_le32((uint32_t)m->value_len);
        memcpy(p, vl.v, 4); p += 4;
        if (m->key_len)   { memcpy(p, m->key, m->key_len);     p += m->key_len; }
        if (m->value_len) { memcpy(p, m->value, m->value_len); p += m->value_len; }
    }
    (void)p;   /* padding to csum is already zero from memset */

    /* Trailing csum. */
    uint8_t csum[STM_BTNODE_CSUM_SIZE];
    btnode_compute_csum(out, buf_size, csum);
    memcpy(out + BTNODE_CSUM_OFFSET(buf_size), csum, STM_BTNODE_CSUM_SIZE);

    return STM_OK;
}

stm_status stm_btnode_internal_encode(const stm_btnode_pivot *pivots,
                                        uint32_t n_pivots,
                                        const uint8_t *children,
                                        size_t children_len,
                                        uint64_t gen, uint64_t tree_id,
                                        void *buf, size_t buf_size)
{
    return stm_btnode_internal_encode_msgs(pivots, n_pivots,
                                           children, children_len,
                                           NULL, 0,
                                           gen, tree_id, buf, buf_size);
}

stm_status stm_btnode_internal_decode_msgs(const void *buf, size_t buf_size,
                                             stm_btnode_info *out_info,
                                             stm_btnode_pivot_cb pivot_cb,
                                             stm_btnode_child_cb child_cb,
                                             stm_btnode_msg_cb msg_cb,
                                             void *ctx)
{
    if (!buf) return STM_EINVAL;
    if (buf_size < STM_BTNODE_MIN_SIZE) return STM_ERANGE;

    const uint8_t *in = (const uint8_t *)buf;

    stm_btnode_info info;
    stm_status s = btnode_hdr_read(in, buf_size, &info);
    if (s != STM_OK) return s;

    /* R7c P2-3: wrong on-disk kind → STM_ECORRUPT, not STM_EINVAL. */
    if (info.kind != STM_BTNODE_KIND_INTERNAL) return STM_ECORRUPT;

    s = btnode_verify_csum(in, buf_size);
    if (s != STM_OK) return s;

    if (out_info) *out_info = info;

    /* Walk payload: N pivots (variable), then (N+1) × 64 children,
     * then buffer_used bytes of messages (9.8-BE-format). */
    if (info.payload_used > STM_BTNODE_PAYLOAD_CAP(buf_size))
        return STM_ECORRUPT;
    if (info.buffer_used > info.payload_used) return STM_ECORRUPT;
    if (info.buffer_used > STM_BTNODE_BUFFER_REGION_MAX(buf_size))
        return STM_ECORRUPT;

    const uint8_t *p      = in + STM_BTNODE_HDR_SIZE;
    const uint8_t *end    = p + info.payload_used;
    const uint8_t *pc_end = end - info.buffer_used;   /* pivots+children */

    /* Check we can fit N+1 children's worth at the pivot/child tail. */
    size_t expected_children =
        ((size_t)info.n_entries + 1u) * STM_BTNODE_CHILD_BPTR_SIZE;
    if ((size_t)(pc_end - p) < expected_children) return STM_ECORRUPT;

    /* Pivots phase: walk info.n_entries keys. */
    for (uint32_t i = 0; i < info.n_entries; i++) {
        if ((size_t)(pc_end - p) < 4u) return STM_ECORRUPT;
        le32 kl_le;
        memcpy(kl_le.v, p, 4);
        uint32_t key_len = stm_load_le32(kl_le);
        p += 4;

        if ((size_t)(pc_end - p) < key_len) return STM_ECORRUPT;
        const uint8_t *key_ptr = p;
        p += key_len;

        if (pivot_cb) {
            int rc = pivot_cb(key_ptr, key_len, i, ctx);
            if (rc != 0) return STM_OK;
        }
    }

    /* Children phase: next N+1 × 64 bytes. The remaining pivot/child
     * slack must exactly equal expected_children. */
    if ((size_t)(pc_end - p) != expected_children) return STM_ECORRUPT;

    for (uint32_t i = 0; i <= info.n_entries; i++) {
        const uint8_t *child_ptr = p;
        p += STM_BTNODE_CHILD_BPTR_SIZE;
        if (child_cb) {
            int rc = child_cb(child_ptr, i, ctx);
            if (rc != 0) return STM_OK;
        }
    }

    /* Message phase: exactly buffer_used bytes of whole messages. The
     * region is ALWAYS validated (msg_cb may be NULL to skip
     * enumeration only). A partial trailing message, a foreign op, a
     * nonzero reserved byte, a valued tombstone, or an over-bound key
     * is corruption. */
    for (uint32_t idx = 0; p != end; idx++) {
        if ((size_t)(end - p) < STM_BTNODE_MSG_HDR_SIZE) return STM_ECORRUPT;

        uint8_t op       = p[0];
        uint8_t reserved = p[1];
        uint64_t seq = 0;
        for (int b = 0; b < 6; b++)
            seq |= (uint64_t)p[2 + b] << (8 * b);
        le16 kl_le; memcpy(kl_le.v, p + 8, 2);
        le32 vl_le; memcpy(vl_le.v, p + 10, 4);
        uint32_t key_len   = stm_load_le16(kl_le);
        uint32_t value_len = stm_load_le32(vl_le);
        p += STM_BTNODE_MSG_HDR_SIZE;

        if (op != STM_BTNODE_MSG_INSERT && op != STM_BTNODE_MSG_DELETE)
            return STM_ECORRUPT;
        if (reserved != 0) return STM_ECORRUPT;
        if (op == STM_BTNODE_MSG_DELETE && value_len != 0)
            return STM_ECORRUPT;
        if (key_len > STM_BTNODE_MSG_KEY_MAX) return STM_ECORRUPT;

        if ((size_t)(end - p) < key_len) return STM_ECORRUPT;
        const uint8_t *key_ptr = p;
        p += key_len;
        if ((size_t)(end - p) < value_len) return STM_ECORRUPT;
        const uint8_t *val_ptr = p;
        p += value_len;

        if (msg_cb) {
            int rc = msg_cb(op, seq,
                            key_len ? key_ptr : NULL, key_len,
                            value_len ? val_ptr : NULL, value_len,
                            idx, ctx);
            if (rc != 0) return STM_OK;
        }
    }

    return STM_OK;
}

stm_status stm_btnode_internal_decode(const void *buf, size_t buf_size,
                                        stm_btnode_info *out_info,
                                        stm_btnode_pivot_cb pivot_cb,
                                        stm_btnode_child_cb child_cb,
                                        void *ctx)
{
    if (!buf) return STM_EINVAL;
    if (buf_size < STM_BTNODE_MIN_SIZE) return STM_ERANGE;

    /* Fail-closed for buffer-unaware trees: a nonzero n_buffer_used
     * would mean silently unseen messages (stale reads) — reject it
     * BEFORE any callback fires. Header-only peek; the full csum +
     * structure validation runs in the _msgs body below. */
    stm_btnode_info peek;
    stm_status s = btnode_hdr_read((const uint8_t *)buf, buf_size, &peek);
    if (s != STM_OK) return s;
    if (peek.kind == STM_BTNODE_KIND_INTERNAL && peek.buffer_used != 0)
        return STM_ECORRUPT;

    return stm_btnode_internal_decode_msgs(buf, buf_size, out_info,
                                           pivot_cb, child_cb,
                                           NULL, ctx);
}
