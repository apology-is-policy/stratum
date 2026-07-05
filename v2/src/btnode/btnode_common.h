/* SPDX-License-Identifier: ISC */
/*
 * Private header shared between leaf.c and internal.c. Not exposed
 * outside the stm_btnode module — see include/stratum/btnode.h for
 * the public surface.
 *
 * R7c P2-4 consolidated the header-encode, header-decode, and csum
 * helpers here: they were duplicated verbatim across leaf.c +
 * internal.c, a drift hazard the code itself flagged.
 *
 * 9.6-impl-1b: the node size is a per-call parameter (`node_size`), not
 * the fixed STM_BTNODE_SIZE — the COW B+tree engine encodes ~16 KiB
 * nodes, the legacy metadata path 128 KiB. The format is identical at
 * every size; only the total length and the trailing-csum offset vary.
 */
#ifndef STM_V2_BTNODE_COMMON_H
#define STM_V2_BTNODE_COMMON_H

#include <stratum/btnode.h>

/* Byte offset of the trailing csum within a node of size `node_size`. */
#define BTNODE_CSUM_OFFSET(node_size)   ((node_size) - STM_BTNODE_CSUM_SIZE)

/*
 * R7c P2-1: upper bound on n_entries for a well-formed node. Each
 * meaningful entry / pivot consumes at least 4 bytes (a length field
 * alone — even with empty key/value). Cap n_entries by this bound to
 * shut down adversarial UINT32_MAX DoS on 32-bit size_t. The cap scales
 * with node_size via STM_BTNODE_PAYLOAD_CAP.
 */
#define BTNODE_MAX_N_ENTRIES(node_size) (STM_BTNODE_PAYLOAD_CAP(node_size) / 4u)

/*
 * Write a header. kind must be a valid stm_btnode_kind. Zeros reserved
 * regions; caller fills payload AFTER STM_BTNODE_HDR_SIZE. Node-size
 * independent — the header is a fixed 128 bytes at offset 0. `seq_hw`
 * is the message-seq high water (9.8-BE-prepend; 0 when the node
 * carries no seq bookkeeping — every leaf, every pre-9.8 writer).
 */
void btnode_hdr_write(uint8_t *buf,
                       stm_btnode_kind kind,
                       uint32_t n_entries,
                       uint32_t buffer_used,
                       uint32_t payload_used,
                       uint64_t gen, uint64_t tree_id,
                       uint64_t seq_hw);

/*
 * Read + validate a header for a node of size `node_size`. Returns:
 *   STM_OK          — valid header, out filled
 *   STM_ERANGE      — node_size < STM_BTNODE_MIN_SIZE
 *   STM_EBADVERSION — magic or version mismatch
 *   STM_ECORRUPT    — kind out of range, or n_entries / payload_used /
 *                     buffer_used exceed the node_size-derived bound
 *
 * Caller still needs to validate csum via btnode_verify_csum before
 * trusting the payload.
 */
STM_MUST_USE
stm_status btnode_hdr_read(const uint8_t *buf, size_t node_size,
                            stm_btnode_info *out);

/*
 * Compute BLAKE3-256 over bytes [0, node_size - STM_BTNODE_CSUM_SIZE)
 * and write the 32-byte digest into `out`. The hashed region is exactly
 * the header + payload; it never overlaps the trailing csum slot, so no
 * staging copy is needed. Caller copies `out` into buf's csum slot.
 */
void btnode_compute_csum(const uint8_t *buf, size_t node_size,
                          uint8_t out[STM_BTNODE_CSUM_SIZE]);

/* Verify the trailing csum of a node of size `node_size`. Returns
 * STM_OK or STM_ECORRUPT. Does NOT modify `buf`. */
STM_MUST_USE
stm_status btnode_verify_csum(const uint8_t *buf, size_t node_size);

#endif /* STM_V2_BTNODE_COMMON_H */
