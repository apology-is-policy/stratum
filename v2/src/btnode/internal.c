/* SPDX-License-Identifier: ISC */
/*
 * stm_btnode — internal (branch) node encode/decode (Phase 3 chunk 5b).
 *
 *   see v2/include/stratum/btnode.h for the format spec.
 *
 * Internal-node payload layout (packed):
 *
 *   pivots (N variable-length):  le32 key_len || key bytes
 *   children (N+1 fixed size):   64 opaque bytes each
 *
 * The same 128-byte header + trailing BLAKE3 csum as the leaf encoding
 * (see leaf.c). Only the payload format differs.
 *
 * Chunk 5b does not yet serialize message buffers (the ε part of the
 * Bε-tree). Callers must flush pending messages before serializing.
 * A future chunk can add a messages region after the children table.
 */

#include <stratum/btnode.h>
#include <stratum/hash.h>

#include <string.h>

/* Shared constants with leaf.c. Duplicated locally to keep the two
 * translation units decoupled — consolidation comes after chunk 5c
 * when the common write/verify helpers want to live in one place. */
#define CSUM_OFFSET   (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE)

/* ========================================================================= */
/* Internal helpers mirroring leaf.c (header + csum).                         */
/* ========================================================================= */

static void hdr_write_internal(uint8_t *buf,
                                 uint32_t n_pivots,
                                 uint32_t payload_used,
                                 uint64_t gen, uint64_t tree_id)
{
    memset(buf, 0, STM_BTNODE_HDR_SIZE);

    stm_btnode_hdr hdr = { 0 };
    hdr.n_magic        = stm_store_le64(STM_BTNODE_MAGIC);
    hdr.n_version      = stm_store_le32(STM_BTNODE_VERSION);
    hdr.n_flags        = stm_store_le32(0);
    hdr.n_kind         = (uint8_t)STM_BTNODE_KIND_INTERNAL;
    hdr.n_n_entries    = stm_store_le32(n_pivots);
    hdr.n_buffer_used  = stm_store_le32(0);        /* messages deferred */
    hdr.n_payload_used = stm_store_le32(payload_used);
    hdr.n_gen          = stm_store_le64(gen);
    hdr.n_tree_id      = stm_store_le64(tree_id);

    memcpy(buf, &hdr, sizeof hdr);
}

static stm_status hdr_read_internal(const uint8_t *buf, size_t buf_size,
                                      stm_btnode_info *out)
{
    if (buf_size < STM_BTNODE_SIZE) return STM_ERANGE;

    const stm_btnode_hdr *hdr = (const stm_btnode_hdr *)buf;
    if (stm_load_le64(hdr->n_magic) != STM_BTNODE_MAGIC)
        return STM_EBADVERSION;
    if (stm_load_le32(hdr->n_version) != STM_BTNODE_VERSION)
        return STM_EBADVERSION;

    uint8_t kind = hdr->n_kind;
    if (kind != STM_BTNODE_KIND_LEAF && kind != STM_BTNODE_KIND_INTERNAL)
        return STM_ECORRUPT;

    out->kind         = (stm_btnode_kind)kind;
    out->n_entries    = stm_load_le32(hdr->n_n_entries);
    out->buffer_used  = stm_load_le32(hdr->n_buffer_used);
    out->payload_used = stm_load_le32(hdr->n_payload_used);
    out->gen          = stm_load_le64(hdr->n_gen);
    out->tree_id      = stm_load_le64(hdr->n_tree_id);
    return STM_OK;
}

static void compute_csum_internal(uint8_t *buf, uint8_t out[STM_BTNODE_CSUM_SIZE])
{
    memset(buf + CSUM_OFFSET, 0, STM_BTNODE_CSUM_SIZE);
    stm_blake3_hash h;
    stm_blake3(buf, CSUM_OFFSET, &h);
    memcpy(out, h.bytes, STM_BTNODE_CSUM_SIZE);
}

static stm_status verify_csum_internal(const uint8_t *buf)
{
    uint8_t staged[STM_BTNODE_SIZE];
    memcpy(staged, buf, STM_BTNODE_SIZE);
    memset(staged + CSUM_OFFSET, 0, STM_BTNODE_CSUM_SIZE);

    stm_blake3_hash h;
    stm_blake3(staged, CSUM_OFFSET, &h);
    const uint8_t *stored = buf + CSUM_OFFSET;
    uint8_t diff = 0;
    for (size_t i = 0; i < STM_BTNODE_CSUM_SIZE; i++) {
        diff |= (uint8_t)(stored[i] ^ h.bytes[i]);
    }
    return diff == 0 ? STM_OK : STM_ECORRUPT;
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

stm_status stm_btnode_internal_encode(const stm_btnode_pivot *pivots,
                                        uint32_t n_pivots,
                                        const uint8_t *children,
                                        size_t children_len,
                                        uint64_t gen, uint64_t tree_id,
                                        void *buf, size_t buf_size)
{
    if (!buf) return STM_EINVAL;
    if (buf_size < STM_BTNODE_SIZE) return STM_ERANGE;
    if (n_pivots > 0 && !pivots) return STM_EINVAL;
    if (!children) return STM_EINVAL;

    /* N+1 children exactly (overflow-safe multiply: n_pivots is u32;
     * n_pivots + 1 can't overflow u32 unless n_pivots == UINT32_MAX,
     * which is rejected below by the payload-fit check anyway). */
    size_t expected_children =
        ((size_t)n_pivots + 1u) * STM_BTNODE_CHILD_BPTR_SIZE;
    if (children_len != expected_children) return STM_EINVAL;

    size_t payload_bytes = stm_btnode_internal_encoded_bytes(pivots, n_pivots);
    if (payload_bytes > STM_BTNODE_PAYLOAD_MAX) return STM_ERANGE;

    uint8_t *out = (uint8_t *)buf;
    memset(out, 0, STM_BTNODE_SIZE);

    hdr_write_internal(out, n_pivots, (uint32_t)payload_bytes, gen, tree_id);

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
    (void)p;   /* padding to csum is already zero from memset */

    /* Trailing csum. */
    uint8_t csum[STM_BTNODE_CSUM_SIZE];
    compute_csum_internal(out, csum);
    memcpy(out + CSUM_OFFSET, csum, STM_BTNODE_CSUM_SIZE);

    return STM_OK;
}

stm_status stm_btnode_internal_decode(const void *buf, size_t buf_size,
                                        stm_btnode_info *out_info,
                                        stm_btnode_pivot_cb pivot_cb,
                                        stm_btnode_child_cb child_cb,
                                        void *ctx)
{
    if (!buf) return STM_EINVAL;
    if (buf_size < STM_BTNODE_SIZE) return STM_ERANGE;

    const uint8_t *in = (const uint8_t *)buf;

    stm_btnode_info info;
    stm_status s = hdr_read_internal(in, buf_size, &info);
    if (s != STM_OK) return s;

    if (info.kind != STM_BTNODE_KIND_INTERNAL) return STM_EINVAL;

    s = verify_csum_internal(in);
    if (s != STM_OK) return s;

    if (out_info) *out_info = info;

    /* Walk payload. N pivots (variable), then (N+1) × 64 children. */
    if (info.payload_used > STM_BTNODE_PAYLOAD_MAX) return STM_ECORRUPT;

    const uint8_t *p   = in + STM_BTNODE_HDR_SIZE;
    const uint8_t *end = p + info.payload_used;

    /* Check we can fit N+1 children's worth at the tail. */
    size_t expected_children =
        ((size_t)info.n_entries + 1u) * STM_BTNODE_CHILD_BPTR_SIZE;
    if (info.payload_used < expected_children) return STM_ECORRUPT;

    /* Pivots phase: walk info.n_entries keys. */
    for (uint32_t i = 0; i < info.n_entries; i++) {
        if ((size_t)(end - p) < 4u) return STM_ECORRUPT;
        le32 kl_le;
        memcpy(kl_le.v, p, 4);
        uint32_t key_len = stm_load_le32(kl_le);
        p += 4;

        if ((size_t)(end - p) < key_len) return STM_ECORRUPT;
        const uint8_t *key_ptr = p;
        p += key_len;

        if (pivot_cb) {
            int rc = pivot_cb(key_ptr, key_len, i, ctx);
            if (rc != 0) return STM_OK;
        }
    }

    /* Children phase: next N+1 × 64 bytes. The remaining slack must
     * exactly equal expected_children (so (end - p) == expected). */
    if ((size_t)(end - p) != expected_children) return STM_ECORRUPT;

    for (uint32_t i = 0; i <= info.n_entries; i++) {
        const uint8_t *child_ptr = p;
        p += STM_BTNODE_CHILD_BPTR_SIZE;
        if (child_cb) {
            int rc = child_cb(child_ptr, i, ctx);
            if (rc != 0) return STM_OK;
        }
    }

    if (p != end) return STM_ECORRUPT;   /* should not happen given the
                                            exact check above */
    return STM_OK;
}
