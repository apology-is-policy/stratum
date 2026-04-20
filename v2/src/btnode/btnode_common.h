/* SPDX-License-Identifier: ISC */
/*
 * Private header shared between leaf.c and internal.c. Not exposed
 * outside the stm_btnode module — see include/stratum/btnode.h for
 * the public surface.
 *
 * R7c P2-4 consolidated the header-encode, header-decode, and csum
 * helpers here: they were duplicated verbatim across leaf.c +
 * internal.c, a drift hazard the code itself flagged.
 */
#ifndef STM_V2_BTNODE_COMMON_H
#define STM_V2_BTNODE_COMMON_H

#include <stratum/btnode.h>

/* Byte offset of the trailing csum within a node. */
#define BTNODE_CSUM_OFFSET   (STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE)

/*
 * R7c P2-1: upper bound on n_entries for a well-formed node. Each
 * meaningful entry / pivot consumes at least 4 bytes (a length field
 * alone — even with empty key/value). Cap n_entries by this bound to
 * shut down adversarial UINT32_MAX DoS on 32-bit size_t.
 *
 * PAYLOAD_MAX / 4 = 130912 / 4 = 32728. Real trees are orders of
 * magnitude below this, so false positives are impossible.
 */
#define BTNODE_MAX_N_ENTRIES   (STM_BTNODE_PAYLOAD_MAX / 4u)

/*
 * Write a header. kind must be a valid stm_btnode_kind. Zeros reserved
 * regions; caller fills payload AFTER STM_BTNODE_HDR_SIZE.
 */
void btnode_hdr_write(uint8_t *buf,
                       stm_btnode_kind kind,
                       uint32_t n_entries,
                       uint32_t buffer_used,
                       uint32_t payload_used,
                       uint64_t gen, uint64_t tree_id);

/*
 * Read + validate a header. Returns:
 *   STM_OK          — valid header, out filled
 *   STM_ERANGE      — buf_size < STM_BTNODE_SIZE
 *   STM_EBADVERSION — magic or version mismatch
 *   STM_ECORRUPT    — kind out of range, or n_entries > BTNODE_MAX_N_ENTRIES
 *
 * Caller still needs to validate csum via btnode_verify_csum before
 * trusting the payload.
 */
STM_MUST_USE
stm_status btnode_hdr_read(const uint8_t *buf, size_t buf_size,
                            stm_btnode_info *out);

/* Compute BLAKE3-256 over bytes [0, CSUM_OFFSET) with the csum region
 * zeroed, and write the 32-byte digest into `out`. Caller then copies
 * `out` into buf[CSUM_OFFSET..]. */
void btnode_compute_csum(uint8_t *buf,
                          uint8_t out[STM_BTNODE_CSUM_SIZE]);

/* Verify the trailing csum against a staged re-hash. Returns STM_OK
 * or STM_ECORRUPT. Does NOT modify `buf`. */
STM_MUST_USE
stm_status btnode_verify_csum(const uint8_t *buf);

#endif /* STM_V2_BTNODE_COMMON_H */
