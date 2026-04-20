/* SPDX-License-Identifier: ISC */
/*
 * Shared header/csum helpers for stm_btnode's leaf and internal
 * codecs (R7c P2-4 consolidation).
 */

#include "btnode_common.h"

#include <stratum/hash.h>

#include <string.h>

void btnode_hdr_write(uint8_t *buf,
                       stm_btnode_kind kind,
                       uint32_t n_entries,
                       uint32_t buffer_used,
                       uint32_t payload_used,
                       uint64_t gen, uint64_t tree_id)
{
    memset(buf, 0, STM_BTNODE_HDR_SIZE);

    stm_btnode_hdr hdr = { 0 };
    hdr.n_magic        = stm_store_le64(STM_BTNODE_MAGIC);
    hdr.n_version      = stm_store_le32(STM_BTNODE_VERSION);
    hdr.n_flags        = stm_store_le32(0);
    hdr.n_kind         = (uint8_t)kind;
    hdr.n_n_entries    = stm_store_le32(n_entries);
    hdr.n_buffer_used  = stm_store_le32(buffer_used);
    hdr.n_payload_used = stm_store_le32(payload_used);
    hdr.n_gen          = stm_store_le64(gen);
    hdr.n_tree_id      = stm_store_le64(tree_id);
    /* n_merkle left zero — chunk 7 will populate. */

    memcpy(buf, &hdr, sizeof hdr);
}

stm_status btnode_hdr_read(const uint8_t *buf, size_t buf_size,
                            stm_btnode_info *out)
{
    if (buf_size < STM_BTNODE_SIZE) return STM_ERANGE;

    const stm_btnode_hdr *hdr = (const stm_btnode_hdr *)buf;
    if (stm_load_le64(hdr->n_magic)   != STM_BTNODE_MAGIC)
        return STM_EBADVERSION;
    if (stm_load_le32(hdr->n_version) != STM_BTNODE_VERSION)
        return STM_EBADVERSION;

    uint8_t kind = hdr->n_kind;
    if (kind != STM_BTNODE_KIND_LEAF && kind != STM_BTNODE_KIND_INTERNAL)
        return STM_ECORRUPT;

    uint32_t n_entries    = stm_load_le32(hdr->n_n_entries);
    uint32_t buffer_used  = stm_load_le32(hdr->n_buffer_used);
    uint32_t payload_used = stm_load_le32(hdr->n_payload_used);

    /* R7c P2-1: cap n_entries to prevent DoS on 32-bit size_t from
     * attacker-controlled values approaching UINT32_MAX. */
    if (n_entries > BTNODE_MAX_N_ENTRIES) return STM_ECORRUPT;
    if (payload_used > STM_BTNODE_PAYLOAD_MAX) return STM_ECORRUPT;
    if (buffer_used  > STM_BTNODE_PAYLOAD_MAX) return STM_ECORRUPT;

    out->kind         = (stm_btnode_kind)kind;
    out->n_entries    = n_entries;
    out->buffer_used  = buffer_used;
    out->payload_used = payload_used;
    out->gen          = stm_load_le64(hdr->n_gen);
    out->tree_id      = stm_load_le64(hdr->n_tree_id);
    return STM_OK;
}

void btnode_compute_csum(uint8_t *buf,
                          uint8_t out[STM_BTNODE_CSUM_SIZE])
{
    memset(buf + BTNODE_CSUM_OFFSET, 0, STM_BTNODE_CSUM_SIZE);
    stm_blake3_hash h;
    stm_blake3(buf, BTNODE_CSUM_OFFSET, &h);
    memcpy(out, h.bytes, STM_BTNODE_CSUM_SIZE);
}

stm_status btnode_verify_csum(const uint8_t *buf)
{
    uint8_t staged[STM_BTNODE_SIZE];
    memcpy(staged, buf, STM_BTNODE_SIZE);
    memset(staged + BTNODE_CSUM_OFFSET, 0, STM_BTNODE_CSUM_SIZE);

    stm_blake3_hash h;
    stm_blake3(staged, BTNODE_CSUM_OFFSET, &h);
    const uint8_t *stored = buf + BTNODE_CSUM_OFFSET;
    uint8_t diff = 0;
    for (size_t i = 0; i < STM_BTNODE_CSUM_SIZE; i++) {
        diff |= (uint8_t)(stored[i] ^ h.bytes[i]);
    }
    return diff == 0 ? STM_OK : STM_ECORRUPT;
}
