/* SPDX-License-Identifier: ISC */
/*
 * Private structures shared inside the btree_engine module — see
 * include/stratum/btree_engine.h for the public surface and
 * v2/docs/reference/24-btree-engine.md for the as-built reference.
 *
 * Not exposed outside the module.
 */
#ifndef STM_V2_BTREE_ENGINE_INTERNAL_H
#define STM_V2_BTREE_ENGINE_INTERNAL_H

#include <stratum/btree_engine.h>
#include <stratum/btree_store.h>
#include <stratum/btnode.h>

#include <pthread.h>
#include <stdatomic.h>

/* Payload bytes available in one engine node — between the 128-byte
 * header and the trailing 32-byte csum slot. */
#define ENG_PAYLOAD_CAP   STM_BTNODE_PAYLOAD_CAP(STM_BTREE_ENGINE_NODE_SIZE)

/* Largest single (key + value) entry the impl-1b engine accepts,
 * counting the 8-byte leaf-entry header. == STM_BTREE_ENGINE_MAX_ENTRY_BYTES.
 * Bounding it at a third of the payload guarantees a 2-way node split
 * always produces two well-formed (<= cap, non-degenerate) nodes — see
 * node.c eng_split_leaf / eng_split_internal. */
#define ENG_MAX_ITEM_BYTES   STM_BTREE_ENGINE_MAX_ENTRY_BYTES

/* Descent / recursion depth cap. A real metadata tree is depth < 10;
 * 32 is generous headroom and a hard stop against a corrupt on-disk
 * tree whose nodes form a cycle. */
#define ENG_MAX_DEPTH   32u

/* ========================================================================= */
/* Large-value spill (9.6-impl-3).                                             */
/* ========================================================================= */

/*
 * A leaf value too large to sit inline — counting the 1-byte on-disk
 * value tag, 8 + key_len + 1 + value_len > ENG_MAX_ITEM_BYTES — is
 * stored out-of-line in a chain of spill blocks; the leaf entry holds a
 * fixed indirection record in place of the value. See
 * v2/docs/phase-9.6-impl-3-spill-design.md.
 *
 * Every engine leaf value is stored on disk as [tag : 1][payload]:
 *   ENG_VAL_INLINE  — payload is the value bytes verbatim.
 *   ENG_VAL_SPILLED — payload is the 72-byte indirection record:
 *                     real_value_len (le64) || head bptr (64 bytes).
 * The tag keeps the spill discriminator inside the engine's opaque
 * value bytes — the shared btnode codec is untouched.
 */
#define ENG_VAL_TAG_SIZE          1u
#define ENG_VAL_INLINE            0u
#define ENG_VAL_SPILLED           1u

/* The indirection record: 8-byte real length + a 64-byte bptr to spill
 * block 0. */
#define ENG_SPILL_INDIRECT_SIZE   (8u + STM_BTNODE_CHILD_BPTR_SIZE)   /* 72 */

/*
 * A spill block is one 16-KiB engine-node region, AEGIS-256 encrypted
 * (ciphertext [0, NODE_SIZE-32), tag in the trailing 32) and Merkle-
 * csummed exactly as a tree node — but its plaintext is an engine-owned
 * format, NOT a btnode:
 *   [0,8)    magic      ENG_SPILL_MAGIC (le64)
 *   [8,12)   chunk_len  le32 — value bytes carried by this block
 *   [12,16)  flags      le32 — bit 0 = HAS_NEXT
 *   [16,80)  next bptr  64 bytes — to the next block (valid iff HAS_NEXT)
 *   [80, NODE_SIZE-32) value chunk — up to ENG_SPILL_CHUNK_CAP bytes
 */
#define ENG_SPILL_MAGIC           UINT64_C(0x314C4C4950535453) /* "STSPILL1" */
#define ENG_SPILL_HDR_SIZE        (8u + 4u + 4u + STM_BTNODE_CHILD_BPTR_SIZE)
#define ENG_SPILL_CT_LEN          (STM_BTREE_ENGINE_NODE_SIZE - STM_BTNODE_CSUM_SIZE)
#define ENG_SPILL_CHUNK_CAP       (ENG_SPILL_CT_LEN - ENG_SPILL_HDR_SIZE)
#define ENG_SPILL_FLAG_HAS_NEXT   0x1u

/* The `kind` byte stamped into a spill chain's next / head bptr.
 * Distinct from STM_BPTR_KIND_LEAF / INTERNAL; not load-bearing (the
 * spill block's magic + the Merkle csum are the integrity gates) —
 * carried only so the bptr is self-describing. */
#define ENG_SPILL_BPTR_KIND       3u

/* Most spill blocks a value at the value-size cap could occupy — a
 * chain longer than this, decoded from disk, is corrupt. */
#define ENG_SPILL_MAX_BLOCKS   \
    ((STM_BTREE_ENGINE_MAX_VALUE_BYTES + ENG_SPILL_CHUNK_CAP - 1u) /   \
     ENG_SPILL_CHUNK_CAP)

typedef struct eng_node eng_node;

/* ========================================================================= */
/* Bw-tree-shaped delta chain (9.8-LF-1).                                      */
/* ========================================================================= */

/*
 * Per-node in-memory message buffer — Bε in motion. Every non-leaf root
 * and every node can carry a LIFO chain of pending mutations that
 * readers must walk newest-first BEFORE consulting the base node;
 * consolidation (commit time, 9.8-LF-2+) drains the chain into the
 * base node's sorted entries (leaf) or the sorted on-disk buffer
 * region (internal — 9.8-BE-format).
 *
 * LF-1 ships the structure + the reader-side walk (`chain_resolve` in
 * engine.c). No code path PREPENDS yet — the writer-side CAS-prepend
 * is 9.8-BE-prepend. So at LF-1 the chain is always empty; the
 * `_concurrent` lookup walks an empty chain in O(1) and falls through
 * to the existing single-threaded descent.
 *
 * Spec composition: realizes the message-resolution side of
 * v2/specs/bepsilon.tla::PerKeyNewestWins (the reader sees the newest
 * applicable message); `next` pointers stable for the EBR epoch
 * duration realizes concurrency_mvcc.tla::ReaderObservesCoherentTree.
 *
 * Ownership: every delta owns its `key` + `value` heap; freed once
 * the delta is past EBR retire grace at LF-2.
 */
typedef enum {
    ENG_DELTA_INSERT = 1,           /* upsert (key, value) */
    ENG_DELTA_DELETE = 2,           /* remove key — tombstone */
} eng_delta_op;

typedef struct eng_delta eng_delta;
struct eng_delta {
    eng_delta_op  op;
    uint64_t      seq;              /* monotonic per engine — total order */
    uint8_t      *key;              /* owned; NULL iff key_len == 0 */
    uint32_t      key_len;
    uint8_t      *value;            /* owned; INSERT only; NULL iff val_len == 0 */
    uint32_t      value_len;
    eng_delta    *next;             /* LIFO — newest at chain head */
};

/* ========================================================================= */
/* Decoded on-disk message buffer (9.8-BE-format, chunk 7b).                   */
/* ========================================================================= */

/*
 * The materialised form of an internal node's persisted Bε message
 * region (design §3.1/§5.2). DISTINCT from the delta chain: the chain
 * is RAM-only pending mutations (seqs strictly greater than every
 * buffered seq by construction); this array mirrors the on-disk
 * region — committed messages not yet flushed to children.
 *
 * Order invariant: ascending (target_child, seq), seq strictly
 * increasing within one child. Target child is NOT stored — it derives
 * from routing `key` through the node's pivots — so the order can rot
 * IN MEMORY when a pivot splice re-routes targets. The discipline:
 *   - eng_split_internal PARTITIONS messages across the two sides by
 *     the separator (a message on the wrong SIDE mis-routes forever —
 *     the #35 internal_split lesson applied preemptively);
 *   - eng_node_write NORMALISES (stable-sorts by current routing)
 *     before encoding (design §5.2 flush step 2's sort);
 *   - eng_node_read VALIDATES the order (the trust boundary; disorder
 *     on disk is STM_ECORRUPT).
 *
 * Ownership: key/value heap owned by the message; freed by
 * eng_msg_array_free from eng_node_free (and the btnode_io read
 * failure paths).
 */
typedef struct {
    uint8_t   op;               /* the ENG_DELTA_* vocabulary (== wire) */
    uint64_t  seq;              /* <= STM_BTNODE_MSG_SEQ_MAX */
    uint8_t  *key;              /* owned; NULL iff key_len == 0 */
    uint32_t  key_len;
    uint8_t  *value;            /* owned; INSERT only */
    uint32_t  value_len;
} eng_msg;

_Static_assert(ENG_DELTA_INSERT == STM_BTNODE_MSG_INSERT,
               "eng_msg op vocabulary must match the wire");
_Static_assert(ENG_DELTA_DELETE == STM_BTNODE_MSG_DELETE,
               "eng_msg op vocabulary must match the wire");

void eng_msg_array_free(eng_msg *msgs, uint32_t n);

/* The ε = 1/4 capacity carve (design §5.3): an internal node's
 * pivot/child bytes are budgeted against the NON-buffer 3/4 of the
 * payload, so a full buffer can never displace the split-bound
 * proofs' pivot capacity. Nodes from pre-9.8 pools may exceed this
 * (they packed to the full cap); they split on their next mutation. */
#define ENG_BUFFER_REGION_MAX \
    STM_BTNODE_BUFFER_REGION_MAX(STM_BTREE_ENGINE_NODE_SIZE)
#define ENG_INTERNAL_PC_CAP   (ENG_PAYLOAD_CAP - ENG_BUFFER_REGION_MAX)

/* Bε flush recursion cap (design §3.4): a flush cascade descends at
 * most one tree level per recursion, so real depth is bounded by the
 * tree height; the cap (== ENG_MAX_DEPTH) is a hard stop against a
 * corrupt shape stalling a commit. Exceeding it is STM_ECORRUPT. */
#define ENG_FLUSH_MAX_RECURSION   32u

/*
 * Siblings peeled off one node by a flush (9.8-BE-flush, chunk 8).
 *
 * A flush can grow a node past ENG_INTERNAL_PC_CAP more than once
 * (leaf-split splices + child-flush splices), so a single
 * split_result cannot carry the peels: the flush splits EAGERLY —
 * immediately after the splice that crossed the cap, while the total
 * is still within the §Split chooser's proven <= 4/3 × PC_CAP
 * envelope (R172 F4) — and accumulates each (separator, right) here.
 * Entries hold DISJOINT key ranges at the flushed node's level:
 * entry i covers [sep_i, next-higher sep); the flushed node keeps
 * (-inf, min sep). The caller either splices them into the parent
 * (the absorb step) or grows the root around them.
 *
 * Ownership: sep_key + right are owned by the vec until spliced;
 * eng_split_vec_free_deep frees any still-owned remainder (error
 * paths — the peels are not reachable from the tree root, so
 * invalidate_memtree alone would leak them).
 */
typedef struct {
    uint8_t  *sep_key;
    uint32_t  sep_len;
    eng_node *right;
} eng_split_ent;

typedef struct {
    eng_split_ent *v;
    uint32_t       n;
    uint32_t       cap;
} eng_split_vec;

void eng_split_vec_free_deep(eng_split_vec *vec);

/* Encoded byte size of a message array (mirrors the codec:
 * Σ per-message header + key + value). The flush trigger compares
 * this against ENG_BUFFER_REGION_MAX. */
size_t eng_msgs_region_bytes(const eng_msg *msgs, uint32_t n);

/*
 * Deterministic allocation-failure injection for the buffer machinery
 * (R172 F5). -1 = disabled (production steady state; one relaxed load
 * on cold paths). A test stores N >= 0: the (N+1)-th allocation
 * through eng_buf_alloc / eng_buf_realloc returns NULL. Hooked sites
 * are ONLY the Bε buffer machinery (split partition, flush append) —
 * this is not a general malloc shim.
 */
extern _Atomic(int) eng_test_oom_countdown;
void *eng_buf_alloc(size_t sz);
void *eng_buf_realloc(void *p, size_t sz);

/*
 * Out-of-line state for a spilled leaf value. NULL on an eng_entry
 * whose value fits inline. `eng_entry.val` ALWAYS holds the full
 * materialized value (inline or spilled) — spill is purely an on-disk
 * representation, and this struct just tracks the on-disk chain.
 *
 *   dirty   — the on-disk chain is stale vs `val` (the value was set /
 *             replaced since the last write of this leaf). commit frees
 *             the old chain and writes a fresh one. A never-yet-written
 *             chain is dirty with blocks == NULL.
 *   blocks  — paddrs of the on-disk chain, head (blocks[0]) .. tail;
 *             cached so a superseded chain frees with no I/O.
 *   head_gen / head_csum — block 0's gen + ciphertext csum: the bptr
 *             the leaf indirection record stores.
 */
typedef struct {
    bool      dirty;
    uint64_t *blocks;
    uint32_t  n_blocks;
    uint64_t  head_gen;
    uint8_t   head_csum[STM_BTNODE_CSUM_SIZE];
} eng_spill;

/* A leaf entry. `key` / `val` are owned (malloc'd); a zero-length
 * key or value is stored as a NULL pointer. `val` is the full
 * materialized value even when spilled; `spill` is non-NULL iff the
 * value has (or had) an on-disk spill chain. */
typedef struct {
    uint8_t   *key;
    uint32_t   key_len;
    uint8_t   *val;
    uint32_t   val_len;
    eng_spill *spill;
} eng_entry;

/* An internal node's pivot. `key` owned; zero-length stored NULL. */
typedef struct {
    uint8_t  *key;
    uint32_t  key_len;
} eng_pivot;

/*
 * An internal node's child slot. Carries no owned heap — `mem` is a
 * borrowed pointer into the tree (freed via the recursive tree walk),
 * `csum` is inline — so eng_child structs are trivially memcpy-able
 * during a split.
 *
 *   mem      — the loaded child node, or NULL if the child is still
 *              purely on-disk.
 *   paddr    — the child's durable paddr (0 if never written).
 *   gen      — the gen the child was last written at; the AEAD-nonce
 *              input needed to decrypt it. Under incremental COW every
 *              node has its own birth-gen (design §3.9), so the gen is
 *              carried per-child in the parent's on-disk bptr.
 *   csum     — BLAKE3 of the child's ciphertext (the Merkle link).
 *   is_leaf  — the child node's kind.
 */
typedef struct {
    eng_node *mem;
    uint64_t  paddr;
    uint64_t  gen;
    uint8_t   csum[STM_BTNODE_CSUM_SIZE];
    bool      is_leaf;
} eng_child;

/*
 * One in-memory metadata-tree node.
 *
 *   dirty — mutated since it was last written; commit assigns it a
 *           fresh paddr. A node freshly created in RAM is dirty with
 *           paddr == 0. A clean node has a valid paddr / gen / csum
 *           and matches what is on disk.
 *
 * Invariant maintained by node.c: the encoded payload of every node
 * is <= ENG_PAYLOAD_CAP at all times (a mutation that would overflow
 * triggers a split before returning). An ENOMEM mid-split is the one
 * documented exception — see the reference doc §"Failure atomicity".
 */
struct eng_node {
    bool      is_leaf;
    bool      dirty;
    uint64_t  paddr;
    uint64_t  gen;
    uint8_t   csum[STM_BTNODE_CSUM_SIZE];   /* valid when !dirty */

    /* Leaf payload — entries sorted ascending by key (lex). */
    eng_entry *entries;
    uint32_t   n_entries;
    uint32_t   entries_cap;

    /* Internal payload — n_pivots pivots + (n_pivots + 1) children.
     * pivots sorted ascending; child[i] covers keys in
     * [pivot[i-1], pivot[i]) with pivot[-1] = -inf, pivot[n] = +inf. */
    eng_pivot *pivots;
    uint32_t   n_pivots;
    uint32_t   pivots_cap;
    eng_child *children;
    uint32_t   children_cap;

    /* 9.8-LF-1: in-memory Bε delta chain (RAM-only; never persisted).
     *
     * `chain_head` is CAS-prepended by the writer and atomically loaded
     * by the reader. Walked newest-first; consolidation at commit time
     * (9.8-LF-2+) drains it. NULL means an empty chain — the steady
     * state at LF-1 where no prepend path exists yet.
     *
     * `flush_mu` serialises future per-node consolidation (the commit
     * thread acquires it before draining `chain_head`); readers don't
     * touch it. `chain_depth` is observability — atomically incremented
     * on prepend, decremented on drain; used by flush triggers and
     * tests. Both reserved at LF-1; first writer at 9.8-BE-prepend.
     */
    _Atomic(eng_delta *)  chain_head;
    pthread_mutex_t       flush_mu;
    _Atomic(uint32_t)     chain_depth;

    /* 9.8-BE-format (chunk 7b): the decoded on-disk message buffer
     * (internal nodes only; see the eng_msg block above). Owned by the
     * node; freed by eng_node_free. Empty (NULL/0) on every node until
     * a flush (chunk 8) or a buffered read materialises one. */
    eng_msg  *buf_msgs;
    uint32_t  buf_count;
};

/* ========================================================================= */
/* Node cache — paddr-keyed, non-owning (node_cache.c).                        */
/* ========================================================================= */

/*
 * Maps a clean node's paddr -> its in-memory eng_node. Populated when
 * a node is read from disk; consulted by a descent that has not yet
 * loaded a child.
 *
 * Non-owning: the cache never frees a node. Node lifetime is the tree
 * (every loaded node is linked as some parent's child.mem); the engine
 * frees the whole tree by a recursive walk at destroy, then tears the
 * cache table down. impl-1b never frees a node mid-life (no delete /
 * merge), so the cache needs no entry removal.
 *
 * In impl-1b — one live tree, no snapshots — every node has exactly
 * one parent, so a descent hits the parent's child.mem pointer and the
 * paddr index is rarely consulted. It becomes load-bearing at
 * 9.6-impl-2, when incremental COW shares clean subtrees between the
 * superseded and the current root; it is built now so impl-2 layers
 * onto a ready substrate.
 */
#define ENG_CACHE_BITS      10u
#define ENG_CACHE_BUCKETS   (1u << ENG_CACHE_BITS)

typedef struct eng_cache_ent {
    uint64_t              paddr;
    eng_node             *node;
    struct eng_cache_ent *next;
} eng_cache_ent;

typedef struct {
    eng_cache_ent *buckets[ENG_CACHE_BUCKETS];
    size_t         n_entries;
} eng_cache;

void       eng_cache_init(eng_cache *c);
void       eng_cache_destroy(eng_cache *c);   /* frees entries, NOT nodes */
eng_node  *eng_cache_get(const eng_cache *c, uint64_t paddr);
stm_status eng_cache_put(eng_cache *c, uint64_t paddr, eng_node *node);

/* ========================================================================= */
/* Pending commit — the flush -> finalize / abort window (engine.c).           */
/* ========================================================================= */

/*
 * A growable paddr list — the commit superseded / fresh sets. impl-2
 * pre-sized these from a dirty-node count; 9.6-impl-3 spill makes the
 * per-commit paddr count variable (a leaf can write a multi-block spill
 * chain), so they are doubling vectors. `count_dirty` survives as the
 * initial-capacity hint. A push can STM_ENOMEM — that surfaces as a
 * flush failure through the existing failed-flush revert path.
 */
typedef struct {
    uint64_t *v;
    uint32_t  n;
    uint32_t  cap;
} paddr_vec;

/* paddr_vec helpers — defined in engine.c, shared with btnode_io.c's
 * spill-chain writer. `reserve` ensures room for `additional` more
 * entries (call it before an irreversible device write so the push
 * that records the result cannot fail); `push` appends, growing on
 * demand. */
STM_MUST_USE stm_status paddr_vec_reserve(paddr_vec *v, uint32_t additional);
STM_MUST_USE stm_status paddr_vec_push(paddr_vec *v, uint64_t p);
void                    paddr_vec_free(paddr_vec *v);

/*
 * A commit that has been FLUSHED (every dirty node written to a fresh
 * paddr) but not yet FINALIZED publishes nothing durable — the engine's
 * durable root triple still names the prior tree. `eng_pending` records
 * what the flush did so the matching close-out can run:
 *
 *   stm_btree_engine_commit_finalize — adopt new_root_* as the durable
 *     root and hand the `superseded` paddrs back to the allocator
 *     (deferred-free, stamped `gen`); the spec's FinalCommit.
 *   stm_btree_engine_commit_abort — discard the flush: hand the `fresh`
 *     paddrs back (written but never durably rooted) and drop the
 *     in-memory tree so the next access reloads the prior durable
 *     root; the spec's Crash.
 *
 * `superseded` collects the prior paddrs of every rewritten node AND
 * every superseded spill-chain block; `fresh` collects every paddr the
 * flush wrote — nodes and fresh spill-chain blocks alike.
 *
 * Models the in-flight `commit` record of v2/specs/btree.tla.
 */
typedef struct {
    bool      active;          /* a flushed-but-unfinalized commit exists  */
    uint64_t  gen;             /* the write gen of the flushed commit      */
    uint64_t  new_root_paddr;  /* prospective durable root — published by  */
    uint64_t  new_root_gen;    /*   finalize, discarded by abort           */
    uint8_t   new_root_csum[STM_BTNODE_CSUM_SIZE];
    paddr_vec superseded;      /* prior paddrs of rewritten nodes + chains */
    paddr_vec fresh;           /* paddrs the flush wrote this commit       */
} eng_pending;

/* ========================================================================= */
/* The engine handle.                                                         */
/* ========================================================================= */

struct stm_btree_engine {
    const stm_btree_store_vtable *vt;       /* borrowed */
    void                         *vt_ctx;
    stm_btree_crypt_ctx           cx;       /* copied; metadata_key borrowed */
    uint64_t                      tree_id;

    /* The live tree. root is the in-memory root, or NULL when the tree
     * was opened and not yet descended (root still purely on-disk), or
     * after a commit_abort / failed flush dropped the in-memory tree. */
    eng_node *root;
    uint64_t  root_paddr;
    uint64_t  root_gen;
    uint8_t   root_csum[STM_BTNODE_CSUM_SIZE];
    bool      has_durable_root;             /* false for a fresh tree */

    eng_cache   cache;
    eng_pending pending;                    /* the flush -> finalize window */

    /* Spill chains orphaned by stm_btree_engine_delete since the last
     * commit — on-disk block paddrs awaiting supersede. commit_flush
     * drains this into pending.superseded (so finalize deferred-frees
     * them); invalidate_memtree clears it (a delete is reverted with
     * the dropped in-memory tree); destroy frees the backing store. */
    paddr_vec   orphaned_spill_blocks;

    /* 9.8-LF-1 / 9.8-LF-2: lock-free concurrency substrate.
     *
     * `commit_mu` serialises engine-internal commits (one in-flight
     * three-phase commit per engine). LF-2 takes it in the slow-warm
     * path of `stm_btree_engine_lookup_concurrent` to serialise
     * multiple concurrent readers' first-descent load_root calls
     * against each other (double-checked locking). LF-2 commits
     * themselves still rely on atomic-store-release alone (the
     * production caller's fs->global EX serialises commits). When
     * LF-BE-prepend's consolidator becomes commit-concurrent with
     * writes, finalize/abort/flush will all acquire this mutex.
     *
     * Lock order (R170 P3-2): `commit_mu` sits ABOVE the engine's
     * store-vtable I/O (`vt->reserve` / `vt->write` / `vt->read` /
     * `vt->free`) — the slow-warm path holds commit_mu across the
     * load_root disk-read it triggers. Any future code that takes
     * commit_mu AND a store-vtable lock MUST preserve this order
     * (commit_mu outer, vtable inner) — reversal risks deadlock if
     * a future caller takes the vtable lock then upcalls into a
     * function that would acquire commit_mu. The bootstrap allocator
     * is the production vtable (`STM_ENGINE_STORE_VT`); it holds NO
     * internal lock -- its mutating callbacks (`reserve` / `free` /
     * `write`) are race-free only because they are reached EXCLUSIVELY
     * from the commit path, which runs under `fs->global` EX (NOT
     * because of any vtable-internal lock). The serial-path engine ops
     * under serial_mu drive only `vt->read` (via load_root), never the
     * mutating callbacks.
     *
     * `next_delta_seq` is the engine-wide monotonic source for
     * `eng_delta::seq` — gives every prepended message a total order
     * across nodes (used by the future consolidator to merge LIFO
     * chains from sibling pivots into a single timeline). Atomic
     * fetch-add at the prepend site. LF-1 reserves it.
     *
     * 9.8-LF-2: `mvcc_root` is the atomically-published in-memory
     * root pointer for concurrent readers. Acquire-loaded by every
     * `stm_btree_engine_lookup_concurrent` call; release-stored
     * whenever `eng->root` is set (every `load_root` materialisation
     * + `commit_finalize`'s republish) and release-stored to NULL
     * BEFORE every in-memory-tree teardown (`invalidate_memtree`).
     *
     * The 9.6 codebase mutates eng->root nodes in place during
     * commit (paddr/gen/csum/dirty updates) — the root POINTER value
     * stays the same across commits, so at LF-2 the republished
     * value is typically identical to the pre-publish value, and
     * there is no superseded root pointer to EBR-retire. LF-BE-prepend
     * lifts this: the consolidator will COW the dirty path,
     * producing a fresh root, and at that point the publish becomes
     * a true pointer swap + EBR-retire of the old root + every
     * COW'd-superseded eng_node struct.
     *
     * Spec composition (concurrency_mvcc.tla):
     *   - RootAlwaysReachable: every published root is a coherent
     *     tree at the moment of publish; in-place mutation is
     *     reader-invisible because resident readers traverse via
     *     `entries[] / pivots[] / children[].mem`, none of which
     *     commit_node mutates.
     *   - ReaderObservesCoherentTree: at LF-2 the trivial case —
     *     there are no retired nodes because nothing is yet COW'd.
     *     LF-BE-prepend exercises this invariant for real.
     */
    pthread_mutex_t       commit_mu;

    /* P9.5-PARALLEL-3 fix: serialises the SERIAL-PATH tree ops
     * (insert / delete / lookup / scan / scan_range / stats_get) against
     * each other. The engine mutates `root` and its nodes IN PLACE on a
     * plain (non-atomic) pointer; the LF-2 substrate publishes `mvcc_root`
     * only for the wait-free `*_concurrent` readers. The original design
     * relied on the production caller holding `fs->global` EX to give the
     * serial path a single writer (see the commit_mu note above). Once the
     * fs layer ported its compound mutators to `fs->global` SH + per-inode
     * pins, two ops reaching the SAME per-dataset engine through DIFFERENT
     * index locks (inode / dirent / extent / xattr each carry their own
     * private idx->lock, but all four share one engine per dataset) raced
     * on `root`/the nodes -> btree corruption (spurious STM_EEXIST on a
     * torn dirent probe chain, STM_ECORRUPT on a torn node). `serial_mu`
     * restores the single-serial-op-at-a-time invariant inside the engine,
     * independent of which caller-side lock was held. The `*_concurrent`
     * EBR readers DO NOT take it (they stay wait-free via mvcc_root); the
     * commit path does not take it either (it runs under `fs->global` EX).
     * Lock order: serial_mu and commit_mu are currently NEVER co-held -- the
     * serial-path load_root runs OUTSIDE commit_mu (commit_mu is taken only by
     * the `*_concurrent` EBR slow-warm path, which does not take serial_mu).
     * The required discipline for any FUTURE code that would hold both (e.g.
     * the BE-prepend commit-concurrent consolidator) is serial_mu OUTER ->
     * commit_mu INNER; never the reverse. */
    pthread_mutex_t       serial_mu;

    _Atomic(uint64_t)     next_delta_seq;
    _Atomic(eng_node *)   mvcc_root;
};

/* ========================================================================= */
/* node.c — in-memory node primitives.                                        */
/* ========================================================================= */

/* Lexicographic unsigned-byte compare; shorter is less. Returns < 0,
 * 0, > 0. NULL is valid for a zero-length operand. */
int eng_key_cmp(const void *a, size_t alen, const void *b, size_t blen);

eng_node  *eng_node_new_leaf(void);
eng_node  *eng_node_new_internal(void);
/* New internal node with capacity for >= np pivots + nc children. */
eng_node  *eng_node_new_internal_sized(uint32_t np, uint32_t nc);
void       eng_node_free(eng_node *n);            /* one node only */
void       eng_node_free_recursive(eng_node *n);  /* node + in-memory subtree */

/* 9.8-LF-1: free a single delta (key/value heap + the record). NULL-safe.
 * Used (a) by node.c at node-destroy time to drain any residual chain,
 * and (b) at 9.8-LF-2 as the EBR retire destructor for consolidated
 * deltas. */
void       eng_delta_free(eng_delta *d);

/* Lower-bound index of `key` among a leaf's entries; *out_found set
 * TRUE iff an exact match sits at that index. */
uint32_t   eng_leaf_lower_bound(const eng_node *n,
                                 const void *key, size_t key_len,
                                 bool *out_found);
/* The child index a descent for `key` should follow. */
uint32_t   eng_pivot_child_for(const eng_node *n,
                                const void *key, size_t key_len);

/* Encoded-payload byte size of a node (matches the codec). For a leaf
 * this counts each value's ON-DISK footprint — inline, or the small
 * spill indirection record when the value spills. */
size_t     eng_leaf_payload_bytes(const eng_node *n);
size_t     eng_internal_payload_bytes(const eng_node *n);

/* Does a leaf value of (key_len, val_len) spill out-of-line? True iff
 * the inline entry — 8-byte btnode hdr + key + 1-byte tag + value —
 * exceeds ENG_MAX_ITEM_BYTES. The single source of the spill decision,
 * shared by node.c sizing and engine.c's leaf_sync_spill. */
bool       eng_value_spills(size_t key_len, size_t val_len);

/* Insert / upsert a pre-size-validated entry into a leaf. Fully
 * transactional: on STM_ENOMEM the leaf is unchanged. */
STM_MUST_USE
stm_status eng_leaf_put(eng_node *n,
                         const void *key, size_t key_len,
                         const void *val, size_t val_len);

/* Append an entry to a leaf's tail (in-order node load only). */
STM_MUST_USE
stm_status eng_leaf_append(eng_node *n,
                            const void *key, size_t key_len,
                            const void *val, size_t val_len);

/* Remove leaf entry `idx` (9.6-impl-4a). When the entry's value was
 * stored out-of-line, the paddrs of its on-disk spill chain are
 * appended to `orphan_sink` so the next commit supersedes them. The
 * append is the only fallible step and it reserves before it mutates,
 * so on STM_ENOMEM the leaf is left unchanged. The leaf is NOT merged
 * or rebalanced — it may be left empty. */
STM_MUST_USE
stm_status eng_leaf_remove(eng_node *n, uint32_t idx, paddr_vec *orphan_sink);

/* Set pivot `idx` of an internal node (in-order node load only;
 * pivots array pre-sized by eng_node_new_internal_sized). */
STM_MUST_USE
stm_status eng_internal_set_pivot(eng_node *n, uint32_t idx,
                                   const void *key, size_t key_len);

/* Ensure an internal node can absorb one more (pivot, child) without
 * a further allocation — call before descending so the post-descent
 * splice is infallible. */
STM_MUST_USE
stm_status eng_internal_reserve_splice(eng_node *n);

/* Splice (sep_key, right_child) into internal node `n` at pivot index
 * `at` (child index at+1). `sep_key` ownership transfers to `n`.
 * Infallible — eng_internal_reserve_splice must have been called. */
void eng_internal_splice(eng_node *n, uint32_t at,
                          uint8_t *sep_key, uint32_t sep_len,
                          eng_node *right_child);

/* Split an over-cap node into itself (left) + a fresh right sibling,
 * yielding the separator key (malloc'd; ownership to caller). On
 * STM_ENOMEM the node is left intact (over-cap but complete). */
STM_MUST_USE
stm_status eng_split_leaf(eng_node *n, eng_node **out_right,
                           uint8_t **out_sep_key, uint32_t *out_sep_len);
STM_MUST_USE
stm_status eng_split_internal(eng_node *n, eng_node **out_right,
                               uint8_t **out_sep_key, uint32_t *out_sep_len);

/*
 * Bε flush of one internal node's message buffer (9.8-BE-flush,
 * chunk 8; engine.c). Detaches the node's ENTIRE buffer and delivers
 * every message one tree level down in ascending-seq order: an
 * internal child receives the message into its own buffer (recursing
 * when that buffer crosses ENG_BUFFER_REGION_MAX); a leaf child has
 * the message APPLIED (INSERT = upsert, DELETE = remove-if-present,
 * orphaned spill chains routed to eng->orphaned_spill_blocks). Leaf
 * and self splits are handled eagerly; peeled siblings accumulate in
 * *vec (see eng_split_vec) for the caller to splice or root-grow.
 *
 * R172 F1 (BINDING): this MUTATES buf_msgs — the flushed node's, its
 * children's — and node entries/pivots/children. It may only run on
 * a subtree no wait-free reader can be traversing: reader safety is
 * COW, never writer exclusion. At chunk 8 its only production caller
 * is the commit path under the LF-2 regime (fs->global EX writers;
 * production buffers empty until chunk 9); chunk 9's consolidator
 * MUST route it through unpublished COW copies before populating
 * buffers on live mvcc-reachable nodes.
 *
 * Failure contract: on any error the memtree is mid-flush-mutated and
 * MUST be dropped by the caller (invalidate_memtree) — the durable
 * tree still holds every message (nothing was written), so no message
 * is lost or duplicated. *vec may hold peels on error; the caller
 * frees them (eng_split_vec_free_deep) — they are NOT tree-reachable.
 */
STM_MUST_USE
stm_status eng_flush_node(stm_btree_engine *eng, eng_node *node,
                           uint32_t depth, eng_split_vec *vec);

/* ========================================================================= */
/* btnode_io.c — per-node device I/O (encode/encrypt/write, read/decrypt).     */
/* ========================================================================= */

/* Reserve a fresh paddr, encode + AEAD-encrypt + Merkle-csum `n`, and
 * write it. On success n->paddr / n->gen / n->csum are updated and
 * n->dirty is cleared. For an internal node, every child slot's
 * paddr / gen / csum / is_leaf must already be current. */
STM_MUST_USE
stm_status eng_node_write(stm_btree_engine *eng, eng_node *n, uint64_t gen);

/* Read the node at `paddr`: Merkle-check against `expected_csum`,
 * AEAD-decrypt under (paddr, gen), decode into a fresh clean eng_node
 * returned via *out_node. */
STM_MUST_USE
stm_status eng_node_read(stm_btree_engine *eng,
                          uint64_t paddr, uint64_t gen,
                          const uint8_t expected_csum[STM_BTNODE_CSUM_SIZE],
                          eng_node **out_node);

/* Verify the on-disk subtree rooted at (paddr, gen, expected_csum):
 * Merkle + AEAD at every node, recursing through internal nodes and
 * through every spilled leaf value's spill chain. */
STM_MUST_USE
stm_status eng_verify_subtree(stm_btree_engine *eng,
                               uint64_t paddr, uint64_t gen,
                               const uint8_t expected_csum[STM_BTNODE_CSUM_SIZE],
                               uint32_t depth);

/* ========================================================================= */
/* btnode_io.c — spill-block chain I/O (9.6-impl-3).                           */
/* ========================================================================= */

/*
 * Write `val` (val_len bytes) as a fresh forward-linked chain of spill
 * blocks at gen `gen`. On success fills `sp` — blocks[] (newly
 * malloc'd, head..tail), n_blocks, head_gen, head_csum — and clears
 * sp->dirty. Every reserved block paddr is pushed into `fresh` BEFORE
 * its block is written, so a mid-chain failure still leaves every
 * reserved paddr reclaimable by the caller's failed-flush handler.
 * `sp->blocks` must be NULL on entry (the caller frees / supersedes any
 * prior chain first). Returns STM_ENOMEM / STM_ERANGE / device errors.
 */
STM_MUST_USE
stm_status eng_spill_chain_write(stm_btree_engine *eng,
                                  const uint8_t *val, uint32_t val_len,
                                  uint64_t gen, eng_spill *sp,
                                  paddr_vec *fresh);

/*
 * Read the spill chain rooted at (head_paddr, head_gen, head_csum),
 * Merkle + AEAD checking every block, into a freshly malloc'd *out_val
 * of exactly `total_len` bytes. *out_blocks (freshly malloc'd) gets the
 * chain's block paddrs head..tail, *out_n_blocks the count. `total_len`
 * must be in (0, STM_BTREE_ENGINE_MAX_VALUE_BYTES]. Returns STM_ECORRUPT
 * on a magic / Merkle / length / chain-shape violation, STM_EBADTAG on
 * AEAD failure, STM_ENOMEM / device errors.
 */
STM_MUST_USE
stm_status eng_spill_chain_read(stm_btree_engine *eng,
                                 uint64_t head_paddr, uint64_t head_gen,
                                 const uint8_t head_csum[STM_BTNODE_CSUM_SIZE],
                                 uint64_t total_len,
                                 uint8_t **out_val, uint64_t **out_blocks,
                                 uint32_t *out_n_blocks);

/*
 * Verify the spill chain rooted at (head_paddr, head_gen, head_csum):
 * Merkle + AEAD at every block, magic + chain shape, total chunk bytes
 * == total_len. Reads nothing back. Returns STM_ECORRUPT / STM_EBADTAG.
 */
STM_MUST_USE
stm_status eng_spill_chain_verify(stm_btree_engine *eng,
                                   uint64_t head_paddr, uint64_t head_gen,
                                   const uint8_t head_csum[STM_BTNODE_CSUM_SIZE],
                                   uint64_t total_len);

#endif /* STM_V2_BTREE_ENGINE_INTERNAL_H */
