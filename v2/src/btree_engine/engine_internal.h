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

typedef struct eng_node eng_node;

/* A leaf entry. `key` / `val` are owned (malloc'd); a zero-length
 * key or value is stored as a NULL pointer. */
typedef struct {
    uint8_t  *key;
    uint32_t  key_len;
    uint8_t  *val;
    uint32_t  val_len;
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
 * `superseded` / `fresh` are pre-sized from a dirty-node count pass
 * (commit_flush) so the flush walk's appends are infallible — ENOMEM
 * can only surface at the one upfront allocation. Both arrays hold at
 * most `cap` (= dirty-node count) entries: one `fresh` paddr per
 * rewritten node, one `superseded` paddr per rewritten node that had a
 * prior on-disk paddr (a RAM-fresh node — a split product, a grown
 * root — has none, so superseded <= fresh = cap).
 *
 * Models the in-flight `commit` record of v2/specs/btree.tla.
 */
typedef struct {
    bool      active;          /* a flushed-but-unfinalized commit exists  */
    uint64_t  gen;             /* the write gen of the flushed commit      */
    uint64_t  new_root_paddr;  /* prospective durable root — published by  */
    uint64_t  new_root_gen;    /*   finalize, discarded by abort           */
    uint8_t   new_root_csum[STM_BTNODE_CSUM_SIZE];
    uint64_t *superseded;      /* prior paddrs of rewritten nodes          */
    uint32_t  n_superseded;
    uint64_t *fresh;           /* paddrs the flush wrote this commit       */
    uint32_t  n_fresh;
    uint32_t  cap;             /* capacity of superseded[] AND fresh[]     */
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

/* Lower-bound index of `key` among a leaf's entries; *out_found set
 * TRUE iff an exact match sits at that index. */
uint32_t   eng_leaf_lower_bound(const eng_node *n,
                                 const void *key, size_t key_len,
                                 bool *out_found);
/* The child index a descent for `key` should follow. */
uint32_t   eng_pivot_child_for(const eng_node *n,
                                const void *key, size_t key_len);

/* Encoded-payload byte size of a node (matches the codec). */
size_t     eng_leaf_payload_bytes(const eng_node *n);
size_t     eng_internal_payload_bytes(const eng_node *n);

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
 * Merkle + AEAD at every node, recursing through internal nodes. */
STM_MUST_USE
stm_status eng_verify_subtree(stm_btree_engine *eng,
                               uint64_t paddr, uint64_t gen,
                               const uint8_t expected_csum[STM_BTNODE_CSUM_SIZE],
                               uint32_t depth);

#endif /* STM_V2_BTREE_ENGINE_INTERNAL_H */
