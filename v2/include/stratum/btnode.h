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
 * Node size is a per-call parameter (`buf_size`), not a fixed constant
 * (9.6-impl-1b). The legacy metadata path (allocator tree, keyschema,
 * repair_log) uses STM_BTNODE_SIZE = 128 KiB; the Phase 9.6 COW B+tree
 * engine uses a smaller node (~16 KiB) to cut copy-on-write
 * amplification. The format below is identical at every size — only the
 * total length and the trailing-csum offset scale with `buf_size`, which
 * must be at least STM_BTNODE_MIN_SIZE (header + csum, no payload).
 *
 * Layout (buf_size bytes total):
 *
 *   offset 0                header (128 bytes) — see struct stm_btnode_hdr
 *   offset 128              payload (up to buf_size - 160 bytes)
 *   offset buf_size - 32    csum (32 bytes) — BLAKE3-256 over
 *                           bytes [0, buf_size - 32)
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

/* The legacy metadata node size: 128 KiB = one STM_BOOTSTRAP_UNIT_BLOCKS
 * run (8 × 16-KiB bootstrap nodes). The codec is node-size-parameterized
 * (9.6-impl-1b); keyschema / repair_log / btree_store encode at this
 * size, the COW B+tree engine at a smaller one. NOT a fixed format
 * constant — pass the chosen size as `buf_size` to every codec call. */
#define STM_BTNODE_SIZE          (128u * 1024u)

/* Header size (bytes). */
#define STM_BTNODE_HDR_SIZE      128u

/* Checksum size (bytes). BLAKE3-256 output. */
#define STM_BTNODE_CSUM_SIZE     32u

/* Minimum node size: a header plus a trailing csum, zero payload.
 * Every codec function rejects buf_size < this with STM_ERANGE. */
#define STM_BTNODE_MIN_SIZE   \
    (STM_BTNODE_HDR_SIZE + STM_BTNODE_CSUM_SIZE)

/* Payload bytes available in a node of size `node_size` — the region
 * between the header and the trailing csum. An encoding that produces
 * more than this errors with STM_ERANGE. */
#define STM_BTNODE_PAYLOAD_CAP(node_size)   \
    ((node_size) - STM_BTNODE_HDR_SIZE - STM_BTNODE_CSUM_SIZE)

/* Payload cap for the legacy 128-KiB node (STM_BTNODE_SIZE). */
#define STM_BTNODE_PAYLOAD_MAX   STM_BTNODE_PAYLOAD_CAP(STM_BTNODE_SIZE)

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
    le64    n_seq_hw;               /*  80 :  8 — message-seq high water
                                     *            (9.8-BE-prepend; root-
                                     *            meaningful, see below)   */
    uint8_t n_reserved_b[40];       /*  88 : 40 — align to 128            */
} stm_btnode_hdr;

/*
 * n_seq_hw (9.8-BE-prepend, chunk 9): an upper bound on every message
 * seq buffered anywhere in the subtree rooted at this node AT THE TIME
 * THE NODE WAS WRITTEN. Load-bearing only at a tree ROOT: the engine
 * seeds its per-engine delta-seq counter from the root's value at
 * open/load, so seqs minted after a restart stay strictly above every
 * persisted message and per-key newest-wins ordering never inverts
 * across process lifetimes. Written by the engine commit path (the
 * root is rewritten by any commit that minted new seqs); zero on leaf
 * nodes, on pre-9.8 pools, and on internal nodes never carrying
 * messages — a zero seed is correct for all three. Best-effort
 * metadata, not a validated invariant: the verify path checks per-node
 * message ORDER (R172 F2), not seq-vs-hw.
 */

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
    uint64_t         seq_hw;       /* n_seq_hw — 0 on pre-9.8 nodes */
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
 * Encode a leaf node into `buf`, a buffer of exactly `buf_size` bytes
 * (the node size; ≥ STM_BTNODE_MIN_SIZE). The entries must be sorted
 * ascending by key (lex) — caller responsibility, not enforced.
 *
 * `gen` is the creation generation (commit-txg); written verbatim into
 * the header for MVCC snapshot routing. The Merkle hash field is
 * zeroed (chunk 7 will populate it post-encode).
 *
 * Returns STM_ERANGE if the encoded entries exceed the node's payload
 * cap, STM_BTNODE_PAYLOAD_CAP(buf_size) (caller must split the leaf
 * before retrying), or if buf_size < STM_BTNODE_MIN_SIZE.
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

/* ========================================================================= */
/* Internal-node message buffer (9.8-BE-format).                              */
/* ========================================================================= */

/*
 * Phase 9.8-BE: an internal node may carry a region of buffered Bε
 * messages after the children table:
 *
 *   payload = [pivots ‖ children ‖ messages]
 *
 * `n_payload_used` counts the WHOLE payload (pivots + children +
 * messages); `n_buffer_used` counts the trailing message region only,
 * so the pivot/child prefix is (payload_used − buffer_used) bytes.
 * A node with `n_buffer_used == 0` is byte-identical to the pre-9.8
 * encoding — the extension is strictly additive (phase-9.8-design.md
 * §3.1).
 *
 * Each message on the wire:
 *
 *   [op:1][reserved:1][seq:6 LE][key_len:2 LE][value_len:4 LE][key][value]
 *
 * The region holds whole messages only (a partial trailing message is
 * corruption). Messages are ordered (target_child, seq) by the WRITER
 * (the flush's per-child linear-sweep precondition); target_child is
 * not stored — it derives from routing the key through the pivots, so
 * ORDER validation is the tree layer's job (it owns routing), while
 * this codec validates structure: op range, tombstone-has-no-value,
 * key bound, exact region consumption, region caps.
 *
 * The engine additionally bounds a buffered value to its inline cap
 * (larger values bypass the buffer and go direct-to-leaf); that bound
 * is the tree layer's, not this codec's — the codec's structural bound
 * is the region itself.
 */

/* Message ops. Foreign values on disk are corruption (R71 P1-1
 * doctrine). 0x03 RANGE_DELETE is reserved for a future phase. */
#define STM_BTNODE_MSG_INSERT      0x01u
#define STM_BTNODE_MSG_DELETE      0x02u

/* Fixed per-message wire header:
 * op(1) + reserved(1) + seq(6) + key_len(2) + value_len(4). */
#define STM_BTNODE_MSG_HDR_SIZE    14u

/* seq is 48-bit on the wire. Encode rejects larger with STM_ERANGE. */
#define STM_BTNODE_MSG_SEQ_MAX     ((UINT64_C(1) << 48) - 1u)

/* Buffered-message key bound. Mirrors the metakey bound (design §3.1:
 * key_len <= STM_METAKEY_MAX == 256); kept as a local constant so the
 * codec stays self-contained. */
#define STM_BTNODE_MSG_KEY_MAX     256u

/* The Bε buffer region cap: ε = 1/4 of the payload budget
 * (phase-9.8-design.md §5.3). The pivot/child budget is the remaining
 * 3/4 — enforced by the TREE layer's capacity checks, not here: the
 * codec accepts any [pivots ‖ children ‖ messages] mix that fits the
 * payload cap, because pre-9.8 pools may legitimately carry internal
 * nodes whose pivot/child bytes exceed the 3/4 carve (they split on
 * their next mutation). */
#define STM_BTNODE_BUFFER_REGION_MAX(node_size) \
    (STM_BTNODE_PAYLOAD_CAP(node_size) / 4u)

typedef struct {
    uint8_t     op;          /* STM_BTNODE_MSG_INSERT / _DELETE */
    uint64_t    seq;         /* <= STM_BTNODE_MSG_SEQ_MAX */
    const void *key;
    size_t      key_len;     /* <= STM_BTNODE_MSG_KEY_MAX */
    const void *value;       /* INSERT only; DELETE carries none */
    size_t      value_len;
} stm_btnode_msg;

typedef int (*stm_btnode_msg_cb)(uint8_t op, uint64_t seq,
                                   const void *key, size_t key_len,
                                   const void *value, size_t value_len,
                                   uint32_t msg_index, void *ctx);

/* Predict the encoded byte size of a message array. */
size_t stm_btnode_msgs_encoded_bytes(const stm_btnode_msg *msgs,
                                       uint32_t n_msgs);

/*
 * Encode an internal node WITH a message buffer. `msgs == NULL` /
 * `n_msgs == 0` produces bytes identical to stm_btnode_internal_encode
 * (which is now a thin wrapper over this). Message order is preserved
 * verbatim — the caller supplies (target_child, seq) order.
 *
 * `seq_hw` lands in the header's n_seq_hw field (see the header
 * comment); pass 0 for a node that carries no seq bookkeeping (the
 * thin wrapper does).
 *
 * Returns STM_ERANGE if the message region exceeds
 * STM_BTNODE_BUFFER_REGION_MAX(buf_size), if any key exceeds
 * STM_BTNODE_MSG_KEY_MAX, if any seq exceeds STM_BTNODE_MSG_SEQ_MAX,
 * or if the total payload exceeds the payload cap. STM_EINVAL on a
 * foreign op, a DELETE carrying a value, or NULL key/value pointers
 * with nonzero lengths.
 */
STM_MUST_USE
stm_status stm_btnode_internal_encode_msgs(
    const stm_btnode_pivot *pivots, uint32_t n_pivots,
    const uint8_t *children, size_t children_len,
    const stm_btnode_msg *msgs, uint32_t n_msgs,
    uint64_t gen, uint64_t tree_id, uint64_t seq_hw,
    void *buf, size_t buf_size);

/*
 * Decode an internal node, message-buffer-aware. Enumerates pivots,
 * then children, then messages (msg_cb may be NULL to skip
 * enumeration — the message region is STILL fully validated). The
 * legacy stm_btnode_internal_decode instead REJECTS a nonzero
 * n_buffer_used with STM_ECORRUPT (fail-closed: trees that never
 * write buffers — btree_store's flush-before-serialize contract —
 * must treat a buffered node as corruption).
 *
 * Structural validation of the message region (all STM_ECORRUPT):
 * buffer_used <= payload_used, buffer_used <=
 * STM_BTNODE_BUFFER_REGION_MAX(buf_size), whole messages only with
 * exact region consumption, op in {INSERT, DELETE}, DELETE with
 * value_len != 0 rejected, key_len <= STM_BTNODE_MSG_KEY_MAX.
 */
STM_MUST_USE
stm_status stm_btnode_internal_decode_msgs(
    const void *buf, size_t buf_size,
    stm_btnode_info *out_info,
    stm_btnode_pivot_cb pivot_cb,
    stm_btnode_child_cb child_cb,
    stm_btnode_msg_cb msg_cb,
    void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BTNODE_H */
