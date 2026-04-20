/* SPDX-License-Identifier: ISC */
/*
 * On-disk Bε-tree node format (Phase 3 chunk 5).
 *
 *   see ARCHITECTURE §3 (Bε-tree model), §5.4 (bptr), §6.3 (allocator
 *        tree), §7.11 (Merkle integration — chunk 7 wires the Merkle
 *        hash field).
 *
 * This module defines the persistent encoding of a single Bε-tree node.
 * It does NOT implement tree-level ops (split, merge, flush) — those
 * live in the Bε-tree layer (stm_btree and friends). `stm_btnode` is
 * the serialization primitive that both the allocator-tree (chunk 4)
 * and the main fs tree (future) share.
 *
 * Node size is fixed at 128 KiB — one STM_BOOTSTRAP_UNIT (32 blocks
 * × 4 KiB) per ARCH §6.3.1. A fixed size keeps the bootstrap-pool
 * bitmap math trivial: each allocated unit is exactly one node.
 *
 * Layout (131072 bytes total):
 *
 *   offset 0       header (128 bytes)  — see struct stm_btnode_hdr
 *   offset 128     payload (up to 130912 bytes)
 *   offset 131040  csum (32 bytes) — BLAKE3-256 over bytes [0, 131040)
 *                                    with the csum field zeroed
 *
 * Keys and values are opaque byte strings; comparison is lexicographic.
 * This matches stm_btree's external contract.
 *
 * Leaf payload format:
 *
 *   Each entry: le32 key_len + le32 value_len + key bytes + value bytes.
 *   Entries are sorted ascending by key (lex).
 *   n_entries in the header gives the count; payload_used gives the
 *   byte offset of the end of the valid data (= header + all entries).
 *
 * Internal payload format (chunk 5b): pivot keys + child bptrs +
 * optional message buffer. Deferred to 5b.
 *
 * Integrity model (chunk 5 MVP):
 *
 *   - BLAKE3-256 csum over bytes [0, 131040), with the csum field
 *     zeroed for hashing. Self-verifying: a node that hashes to its
 *     own csum is structurally valid.
 *   - The 32-byte Merkle hash field (reserved_b[0..32)) is populated
 *     by chunk 7's integrity layer. Chunk 5 leaves it zero.
 *
 * The node format carries neither paddr (it's self-describing; the
 * paddr is in the parent's bptr) nor tree-id-affinity (it's reusable
 * across trees; the parent decides what the key/value schema means).
 */
#ifndef STRATUM_V2_BTNODE_H
#define STRATUM_V2_BTNODE_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Constants.                                                                 */
/* ========================================================================= */

/* Fixed node size: 128 KiB. Matches STM_BOOTSTRAP_UNIT_BLOCKS × 4 KiB
 * so each allocator-tree node maps 1:1 to a bootstrap-pool unit. */
#define STM_BTNODE_SIZE          (128u * 1024u)

/* Header size (bytes). */
#define STM_BTNODE_HDR_SIZE      128u

/* Checksum size (bytes). BLAKE3-256 output. */
#define STM_BTNODE_CSUM_SIZE     32u

/* Maximum payload bytes available between the header and the trailing
 * csum. Any encoding that produces more than this will error with
 * STM_ERANGE. */
#define STM_BTNODE_PAYLOAD_MAX   \
    (STM_BTNODE_SIZE - STM_BTNODE_HDR_SIZE - STM_BTNODE_CSUM_SIZE)

/* 8-byte magic at the head of every node. ASCII "STBTNODE" read as
 * little-endian uint64: byte 0 = 'S', byte 7 = 'E'. Chosen distinct
 * from STM_UB_MAGIC and STM_BOOTSTRAP_HDR_MAGIC so misplaced bytes
 * surface via magic mismatch. */
#define STM_BTNODE_MAGIC         UINT64_C(0x45444F4E54425453) /* "STBTNODE" */

/* Format version. Bumped on incompatible layout changes. */
#define STM_BTNODE_VERSION       1u

/* Node kinds. */
typedef enum {
    STM_BTNODE_KIND_LEAF     = 0,
    STM_BTNODE_KIND_INTERNAL = 1,    /* Phase 3 chunk 5b */
} stm_btnode_kind;

/* Per-entry overhead in the leaf payload: 2 × le32 (key_len + value_len). */
#define STM_BTNODE_ENTRY_HDR_SIZE    8u

/* ========================================================================= */
/* Header (on-disk, 128 bytes).                                               */
/* ========================================================================= */

typedef struct {
    le64    n_magic;                /*   0 :  8 — STM_BTNODE_MAGIC        */
    le32    n_version;              /*   8 :  4 — STM_BTNODE_VERSION      */
    le32    n_flags;                /*  12 :  4                           */
    uint8_t n_kind;                 /*  16 :  1 — stm_btnode_kind         */
    uint8_t n_reserved_a[3];        /*  17 :  3 — align to 20             */
    le32    n_n_entries;            /*  20 :  4 — entries (leaf) or
                                     *            pivots (internal)        */
    le32    n_buffer_used;          /*  24 :  4 — message-buffer bytes
                                     *            (internal; 0 for leaf)   */
    le32    n_payload_used;         /*  28 :  4 — total payload bytes
                                     *            consumed                 */
    le64    n_gen;                  /*  32 :  8 — creation gen (MVCC)     */
    le64    n_tree_id;              /*  40 :  8 — future: multi-tree pool */
    uint8_t n_merkle[32];           /*  48 : 32 — Merkle hash (chunk 7)   */
    uint8_t n_reserved_b[48];       /*  80 : 48 — align to 128            */
} stm_btnode_hdr;

_Static_assert(sizeof(stm_btnode_hdr) == STM_BTNODE_HDR_SIZE,
               "stm_btnode_hdr must be 128 bytes");

/* ========================================================================= */
/* Leaf entry input (caller-owned pointers; not packed).                      */
/* ========================================================================= */

typedef struct {
    const void *key;
    size_t      key_len;
    const void *value;
    size_t      value_len;
} stm_btnode_entry;

/* ========================================================================= */
/* Header peek (without decoding payload).                                    */
/* ========================================================================= */

typedef struct {
    stm_btnode_kind kind;
    uint32_t         n_entries;
    uint32_t         buffer_used;
    uint32_t         payload_used;
    uint64_t         gen;
    uint64_t         tree_id;
} stm_btnode_info;

/* Validate + decode only the header. Does NOT validate csum — use
 * stm_btnode_verify for that. Returns STM_EBADVERSION on magic/version
 * mismatch, STM_ECORRUPT on a kind outside the known range. */
STM_MUST_USE
stm_status stm_btnode_peek(const void *buf, size_t buf_size,
                            stm_btnode_info *out_info);

/* Verify the full node: magic + version + kind + csum. Returns
 * STM_ECORRUPT if any check fails. */
STM_MUST_USE
stm_status stm_btnode_verify(const void *buf, size_t buf_size);

/* ========================================================================= */
/* Leaf encode / decode.                                                      */
/* ========================================================================= */

/*
 * Encode a leaf node into `buf` (must be at least STM_BTNODE_SIZE
 * bytes). The entries must be sorted ascending by key (lex); the
 * encoder asserts this in debug builds via a softer check that's
 * documented below but not enforced at runtime in release — caller
 * responsibility.
 *
 * `gen` is the creation generation (commit-txg); written verbatim into
 * the header for MVCC snapshot routing. The Merkle hash field is
 * zeroed (chunk 7 will populate it post-encode).
 *
 * Returns STM_ERANGE if the encoded entries exceed
 * STM_BTNODE_PAYLOAD_MAX bytes (caller must split the leaf before
 * retrying).
 */
STM_MUST_USE
stm_status stm_btnode_leaf_encode(
    const stm_btnode_entry *entries, uint32_t n_entries,
    uint64_t gen, uint64_t tree_id,
    void *buf, size_t buf_size);

/* Per-entry callback invoked by decode. Pointers are valid only for
 * the duration of the call (they point into `buf`). Return 0 to
 * continue, nonzero to stop. */
typedef int (*stm_btnode_entry_cb)(
    const void *key, size_t key_len,
    const void *value, size_t value_len,
    void *ctx);

/*
 * Decode a leaf node. Validates magic + version + kind + csum. If kind
 * is not LEAF returns STM_EINVAL (wrong kind for this function).
 *
 * Invokes `cb` once per entry in key order. `cb` returning nonzero
 * stops enumeration and the call returns STM_OK (early stop is not an
 * error). `out_info` (if non-NULL) is populated with the header info
 * before enumeration starts.
 *
 * Returns STM_ECORRUPT on checksum or entry-boundary violations
 * (e.g. an entry whose length would exceed the payload region).
 */
STM_MUST_USE
stm_status stm_btnode_leaf_decode(
    const void *buf, size_t buf_size,
    stm_btnode_info *out_info,
    stm_btnode_entry_cb cb, void *ctx);

/*
 * Given an array of prospective entries, compute the total payload
 * bytes they would occupy in a leaf encoding. Does NOT require a
 * buffer — useful for callers deciding whether to split.
 */
size_t stm_btnode_leaf_encoded_bytes(
    const stm_btnode_entry *entries, uint32_t n_entries);

/* ========================================================================= */
/* Internal (branch) node encode / decode (chunk 5b).                         */
/* ========================================================================= */

/*
 * Internal nodes route lookups to children. An internal with N pivots
 * has N+1 children; pivot[i] is the smallest key reachable through
 * children[i+1]. Pivots are sorted ascending lex, same comparison as
 * leaves.
 *
 * Payload layout (packed, no inter-slot padding):
 *
 *   [pivot 0: le32 key_len | key bytes]
 *   [pivot 1: le32 key_len | key bytes]
 *   ...
 *   [pivot N-1]
 *   [child 0: 64 byte bptr opaque blob]
 *   [child 1: 64 byte bptr opaque blob]
 *   ...
 *   [child N: 64 byte bptr opaque blob]
 *
 * Message-buffer serialization is deferred: callers must drain pending
 * messages to leaves before serializing (quiescent state). Chunk 5c's
 * serializer will call the tree layer's flush-all before encoding.
 *
 * The 64-byte child blobs are opaque to this module — stm_btree layer
 * fills them in with encoded stm_bptr bytes. Decoding gives the bytes
 * back to the caller who knows how to reinterpret.
 */

/* One child bptr's worth of opaque bytes. Matches stm_bptr size in
 * super.h but kept here as a value to avoid pulling super.h into
 * btnode.h. */
#define STM_BTNODE_CHILD_BPTR_SIZE    64u

typedef struct {
    const void *key;
    size_t      key_len;
} stm_btnode_pivot;

/*
 * Encode an internal node. Caller supplies N pivots (must be sorted
 * ascending) and a flat array of (N+1) × 64 child bptr bytes. A tree
 * with an internal node and no children is not representable (N=0 is
 * allowed and produces a node with exactly one child and zero pivots —
 * degenerate but valid; useful during single-child-promotion).
 *
 * Returns STM_ERANGE if the encoding exceeds STM_BTNODE_PAYLOAD_MAX.
 */
STM_MUST_USE
stm_status stm_btnode_internal_encode(
    const stm_btnode_pivot *pivots, uint32_t n_pivots,
    const uint8_t *children, size_t children_len,
    uint64_t gen, uint64_t tree_id,
    void *buf, size_t buf_size);

typedef int (*stm_btnode_pivot_cb)(const void *key, size_t key_len,
                                     uint32_t pivot_index, void *ctx);
typedef int (*stm_btnode_child_cb)(const uint8_t bptr[STM_BTNODE_CHILD_BPTR_SIZE],
                                     uint32_t child_index, void *ctx);

/*
 * Decode an internal node. Validates csum + kind. Invokes `pivot_cb`
 * for each of the N pivots in order, then `child_cb` for each of the
 * N+1 children in order. Either callback may be NULL to skip that
 * phase. Return nonzero from either callback to stop; the decode then
 * returns STM_OK immediately.
 *
 * Returns STM_EINVAL if the node's kind is not INTERNAL, STM_ECORRUPT
 * on csum / boundary violations.
 */
STM_MUST_USE
stm_status stm_btnode_internal_decode(
    const void *buf, size_t buf_size,
    stm_btnode_info *out_info,
    stm_btnode_pivot_cb pivot_cb,
    stm_btnode_child_cb child_cb,
    void *ctx);

/*
 * Predict the encoded size of an internal node with the given pivots
 * + N+1 children.
 */
size_t stm_btnode_internal_encoded_bytes(
    const stm_btnode_pivot *pivots, uint32_t n_pivots);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BTNODE_H */
