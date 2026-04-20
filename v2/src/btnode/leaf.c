/* SPDX-License-Identifier: ISC */
/*
 * stm_btnode — leaf node encode/decode (Phase 3 chunk 5a).
 *
 *   see v2/include/stratum/btnode.h for the format spec.
 *
 * The node layout is a fixed 128 KiB block with three regions:
 *
 *   [0, 128)          header       (stm_btnode_hdr)
 *   [128, 131040)     payload      (leaf entries)
 *   [131040, 131072)  csum         (BLAKE3-256 over [0, 131040) with
 *                                   the csum region zeroed)
 *
 * Each leaf entry is packed as:
 *
 *   le32 key_len
 *   le32 value_len
 *   key bytes
 *   value bytes
 *
 * No inter-entry alignment padding. Entries pack byte-tight; callers
 * that need alignment should embed it in the value encoding.
 *
 * The encoder does NOT verify sort order (caller responsibility,
 * documented in btnode.h). The decoder does not re-sort either — it
 * walks in the order written. A future hardening pass could add sort-
 * order verification to the decoder as a corruption check.
 */

#include <stratum/btnode.h>

#include "btnode_common.h"

#include <string.h>

/* ========================================================================= */
/* Public: peek / verify. Both shared helpers live in common.c now (P2-4).    */
/* ========================================================================= */

stm_status stm_btnode_peek(const void *buf, size_t buf_size,
                            stm_btnode_info *out_info)
{
    if (!buf || !out_info) return STM_EINVAL;
    return btnode_hdr_read((const uint8_t *)buf, buf_size, out_info);
}

stm_status stm_btnode_verify(const void *buf, size_t buf_size)
{
    if (!buf) return STM_EINVAL;
    if (buf_size < STM_BTNODE_SIZE) return STM_ERANGE;

    stm_btnode_info info;
    stm_status s = btnode_hdr_read((const uint8_t *)buf, buf_size, &info);
    if (s != STM_OK) return s;

    return btnode_verify_csum((const uint8_t *)buf);
}

/* ========================================================================= */
/* Public: leaf encode / decode.                                              */
/* ========================================================================= */

size_t stm_btnode_leaf_encoded_bytes(const stm_btnode_entry *entries,
                                      uint32_t n_entries)
{
    if (!entries || n_entries == 0) return 0;
    size_t total = 0;
    for (uint32_t i = 0; i < n_entries; i++) {
        total += STM_BTNODE_ENTRY_HDR_SIZE +
                 entries[i].key_len + entries[i].value_len;
    }
    return total;
}

stm_status stm_btnode_leaf_encode(const stm_btnode_entry *entries,
                                   uint32_t n_entries,
                                   uint64_t gen, uint64_t tree_id,
                                   void *buf, size_t buf_size)
{
    if (!buf) return STM_EINVAL;
    if (buf_size < STM_BTNODE_SIZE) return STM_ERANGE;
    if (n_entries > 0 && !entries) return STM_EINVAL;

    /* Size check first — bail before touching buf if we can't fit. */
    size_t payload_bytes = stm_btnode_leaf_encoded_bytes(entries, n_entries);
    if (payload_bytes > STM_BTNODE_PAYLOAD_MAX) return STM_ERANGE;

    uint8_t *out = (uint8_t *)buf;

    /* Zero the entire node so padding + csum region + reserved bytes
     * start clean. */
    memset(out, 0, STM_BTNODE_SIZE);

    /* Header. payload_used = total bytes from offset 128 onward that
     * carry valid entry data. */
    btnode_hdr_write(out, STM_BTNODE_KIND_LEAF, n_entries, /*buffer_used=*/0,
                     (uint32_t)payload_bytes, gen, tree_id);

    /* Entries. */
    uint8_t *p = out + STM_BTNODE_HDR_SIZE;
    for (uint32_t i = 0; i < n_entries; i++) {
        const stm_btnode_entry *e = &entries[i];
        /* Reject oversized entries early — u32 length fields. */
        if (e->key_len > UINT32_MAX || e->value_len > UINT32_MAX)
            return STM_ERANGE;
        if ((e->key_len > 0 && !e->key) ||
            (e->value_len > 0 && !e->value)) return STM_EINVAL;

        le32 kl = stm_store_le32((uint32_t)e->key_len);
        le32 vl = stm_store_le32((uint32_t)e->value_len);
        memcpy(p, kl.v, 4); p += 4;
        memcpy(p, vl.v, 4); p += 4;
        if (e->key_len)   memcpy(p, e->key,   e->key_len);   p += e->key_len;
        if (e->value_len) memcpy(p, e->value, e->value_len); p += e->value_len;
    }

    /* Trailing csum. */
    uint8_t csum[STM_BTNODE_CSUM_SIZE];
    btnode_compute_csum(out, csum);
    memcpy(out + BTNODE_CSUM_OFFSET, csum, STM_BTNODE_CSUM_SIZE);

    return STM_OK;
}

stm_status stm_btnode_leaf_decode(const void *buf, size_t buf_size,
                                   stm_btnode_info *out_info,
                                   stm_btnode_entry_cb cb, void *ctx)
{
    if (!buf || !cb) return STM_EINVAL;
    if (buf_size < STM_BTNODE_SIZE) return STM_ERANGE;

    const uint8_t *in = (const uint8_t *)buf;

    stm_btnode_info info;
    stm_status s = btnode_hdr_read(in, buf_size, &info);
    if (s != STM_OK) return s;

    /* R7c P2-3: wrong on-disk kind is a data-integrity failure, not a
     * caller-bad-arg. Surface as STM_ECORRUPT. */
    if (info.kind != STM_BTNODE_KIND_LEAF) return STM_ECORRUPT;

    /* Verify csum before trusting any payload bytes. */
    s = btnode_verify_csum(in);
    if (s != STM_OK) return s;

    if (out_info) *out_info = info;

    /* Walk payload. Boundaries:
     *   payload_used must fit in [0, STM_BTNODE_PAYLOAD_MAX].
     *   Each entry must fit entirely within payload_used.
     *   n_entries must match the walk count. */
    if (info.payload_used > STM_BTNODE_PAYLOAD_MAX) return STM_ECORRUPT;

    const uint8_t *p   = in + STM_BTNODE_HDR_SIZE;
    const uint8_t *end = p + info.payload_used;

    for (uint32_t i = 0; i < info.n_entries; i++) {
        /* Header bytes for this entry must be readable. */
        if ((size_t)(end - p) < STM_BTNODE_ENTRY_HDR_SIZE)
            return STM_ECORRUPT;

        le32 kl_le, vl_le;
        memcpy(kl_le.v, p,     4);
        memcpy(vl_le.v, p + 4, 4);
        uint32_t key_len   = stm_load_le32(kl_le);
        uint32_t value_len = stm_load_le32(vl_le);
        p += STM_BTNODE_ENTRY_HDR_SIZE;

        /* Whole key + value body must fit. Use subtraction to avoid
         * overflow in the bounds check. */
        if ((size_t)(end - p) < key_len) return STM_ECORRUPT;
        const uint8_t *key_ptr = p;
        p += key_len;
        if ((size_t)(end - p) < value_len) return STM_ECORRUPT;
        const uint8_t *value_ptr = p;
        p += value_len;

        int rc = cb(key_ptr, key_len, value_ptr, value_len, ctx);
        if (rc != 0) return STM_OK;   /* early stop */
    }

    /* After walking exactly n_entries, we must have consumed exactly
     * payload_used bytes. Slack would mean a trailing garbage region
     * that validates under csum but isn't part of the logical data —
     * surface as corruption. */
    if (p != end) return STM_ECORRUPT;
    return STM_OK;
}
