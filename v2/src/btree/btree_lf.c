/* SPDX-License-Identifier: ISC */
/*
 * Lock-free Bw-tree — Phase 2, tasks #171, #172, #176.
 *
 * See ARCHITECTURE §3.4, v2/docs/phase2-bw-tree-design.md, and
 * v2/docs/phase2-status.md for the model. This TU implements the
 * internal-routing variant: a balanced B+tree where the root is a
 * BASE_INTERNAL delta holding a pivot array routing to leaf children.
 * Task #176 (this extension) is spec-led by v2/specs/balanced.tla,
 * which proves LookupCorrectness across the three-step leaf-split
 * protocol (InstallSibling + PostSplit + UpdateParent).
 *
 * Data structure
 * --------------
 *
 * A physical node in the tree is one of:
 *   - BASE_LEAF      — owns a consolidated stm_bt_node holding sorted
 *                      (key, value) entries. Forms the tail of every
 *                      leaf's delta chain.
 *   - BASE_INTERNAL  — owns a stm_bt_lf_internal holding
 *                        leftmost_child + sorted pivot array
 *                        (sep_key → right_child). Published atomically
 *                        on parent updates. No deltas are prepended
 *                        above a BASE_INTERNAL in this MVP.
 *   - INSERT         — one pending upsert (key, value) on a leaf.
 *   - DELETE         — one pending tombstone for a key on a leaf.
 *   - SPLIT          — redirect hint: keys >= sep_key route to
 *                      sibling_id. Prepended on a leaf's chain as
 *                      part of PostSplit; preserved across leaf
 *                      consolidation so stale parent-pivot readers
 *                      remain correct.
 *
 * The page table maps a node_id to the CURRENT HEAD of that node's
 * chain via an atomic slot. For internal nodes the head is a
 * BASE_INTERNAL (no deltas above). For leaves it can be:
 *
 *     slots[leaf_id] -> INSERT -> DELETE -> ... -> SPLIT -> SPLIT -> BASE_LEAF
 *                        newest-first; INSERT/DELETE above SPLITs above BASE
 *
 * Leaves can carry multiple SPLITs (one per split this leaf has
 * undergone). Their seps are monotonically increasing newest-first
 * (each new split partitions a shrinking range, so new sep < older
 * sep). The chain walk picks the SPLIT with the LARGEST sep <= key:
 * that is the correct sibling for `key`.
 *
 * Traversal
 * ---------
 *
 * From root:
 *   - BASE_INTERNAL → binary-search pivots, recurse into matching child.
 *   - SPLIT on an internal node → not used in this MVP (internal nodes
 *     are atomic-replaced, never delta-prepended).
 *
 * At a leaf:
 *   - Walk chain newest-first. INSERT/DELETE for the target key wins
 *     if encountered (they sit above any SPLIT, and by invariant only
 *     reference keys in the leaf's current range).
 *   - For SPLITs, find the one with the largest sep <= key. If such
 *     a SPLIT exists, redirect to its sibling and traverse there.
 *   - Otherwise fall through to BASE_LEAF and do a sorted-array lookup.
 *
 * Writes
 * ------
 *
 * Writers traverse to the correct leaf (following BASE_INTERNAL pivots
 * and any applicable SPLIT redirects) and CAS-prepend an INSERT/DELETE
 * at that leaf's slot. On CAS failure they retry from the root, which
 * handles the rare races where a SPLIT landed on our target slot
 * between walk and CAS.
 *
 * Consolidation
 * -------------
 *
 * When a writer's prepend leaves chain_depth >= CONSOLIDATE_THRESHOLD,
 * it attempts a consolidation. The consolidator is serialized
 * tree-wide through t->consolidating: the first writer past the
 * threshold wins and does the work; others bail. The winner:
 *
 *   1. Reads the leaf's current chain head.
 *   2. Builds a new BASE_LEAF by cloning the old base and replaying
 *      INSERT/DELETE deltas in oldest-first order. All SPLIT deltas
 *      are preserved in order on the new chain head:
 *
 *          new head = [SPLIT_newest, ..., SPLIT_oldest, BASE_LEAF']
 *
 *   3. CAS the slot from old head to new head. On failure, retry.
 *   4. If the new base overflows target_entries AND we haven't
 *      already split, transition into commit_split instead (see
 *      below).
 *
 * Split (spec-aligned with balanced.tla)
 * --------------------------------------
 *
 * commit_split implements the three-step protocol:
 *
 *   1. InstallSibling — allocate a fresh slot upper_id, atomic_store
 *      a BASE_LEAF(upper-half keys) there. The sibling is unreachable
 *      until step 2 publishes a redirect or step 3 publishes a pivot.
 *
 *   2. PostSplit on the leaf — CAS the leaf's slot from old_head to
 *      a new chain head SPLIT(sep, upper_id) over BASE_LEAF(lower)
 *      (preserving any pre-existing SPLITs above the old BASE).
 *      Readers arriving at this leaf for keys >= sep redirect to the
 *      new sibling.
 *
 *   3. UpdateParent — CAS the parent's BASE_INTERNAL with a clone
 *      that adds a pivot (sep, upper_id). After this, parent routes
 *      keys >= sep directly to upper_id; the leaf's SPLIT becomes
 *      redundant-but-harmless (preserved for stale-pivot readers).
 *
 * All three steps occur under t->consolidating, so no other splitter
 * races us. The CAS events are individually seq_cst; the ordering is
 * what balanced.tla verifies: every reader at every intermediate
 * phase observes a correct answer.
 *
 * Memory reclamation
 * ------------------
 *
 * Each retired delta record goes through stm_ebr_retire with a
 * destructor (delta_destroy) that frees key/value buffers and, for
 * BASE / BASE_INTERNAL, the owned node/internal struct. EBR ensures
 * no reader holding an older epoch is still looking at the record.
 *
 * Limitations (this MVP)
 * ----------------------
 *
 *   - Two-level tree: root is BASE_INTERNAL, children are leaves.
 *     Internal-node splits (the three-level+ case) are follow-up
 *     work; the 65536-slot page table caps the tree at roughly
 *     65536 * target_entries keys, which is ample for tests.
 *   - MERGE is not implemented (see phase2-status.md option A).
 *   - Leaf SPLITs are preserved across consolidations forever.
 *     Under many repeated splits of the same leaf the SPLIT count on
 *     its chain grows; walk cost grows linearly. A future
 *     EBR-aware purge (drop SPLITs no reader could still need) is
 *     on the roadmap.
 */

#include <stratum/btree.h>
#include <stratum/ebr.h>

#include "node.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define STM_BT_LF_CONSOLIDATE_THRESHOLD 4u

/* The consolidator retries a bounded number of times when its CAS
 * loses to a concurrent prepender. Each retry re-reads the chain head
 * so we always consolidate the latest state we can see. */
#define STM_BT_LF_CONSOLIDATE_RETRIES 8u

/* Sanity cap on how deep a leaf chain can grow before we refuse to
 * consolidate (heap blow-up guard). Under normal operation chain
 * depth stays within a small multiple of the threshold. */
#define STM_BT_LF_MAX_CHAIN 4096u

/* Max SPLITs a single leaf can accumulate during consolidation. In
 * practice one per split this leaf has undergone; far below this cap. */
#define STM_BT_LF_MAX_SPLITS 256u

typedef enum {
    STM_BT_LF_DELTA_INSERT        = 1,
    STM_BT_LF_DELTA_DELETE        = 2,
    STM_BT_LF_DELTA_BASE          = 3,  /* BASE_LEAF */
    STM_BT_LF_DELTA_SPLIT         = 4,
    STM_BT_LF_DELTA_BASE_INTERNAL = 5,
    /* Terminal marker on a leaf's slot after MERGE: the leaf has been
     * reabsorbed into forward_id. Readers arriving here follow the
     * forward; writers retraverse from root. Once installed, the SEAL
     * head is never replaced — the slot becomes permanently forwarded.
     * Spec: v2/specs/merge.tla. */
    STM_BT_LF_DELTA_SEALED        = 6,
} stm_bt_lf_delta_kind;

/* (sep_key, right_child) pivot in a BASE_INTERNAL. Sorted ascending
 * by sep_key within the enclosing stm_bt_lf_internal. */
typedef struct {
    uint8_t *sep_key;
    uint32_t sep_key_len;
    uint64_t right_child;
} stm_bt_lf_pivot;

/* The content of a BASE_INTERNAL delta. Owned by the delta; freed by
 * internal_free when the delta is destroyed.
 *
 * Routing:
 *   key < pivots[0].sep_key                          → leftmost_child
 *   pivots[i].sep_key <= key < pivots[i+1].sep_key   → pivots[i].right_child
 *   key >= pivots[npivots-1].sep_key                 → pivots[npivots-1].right_child
 */
typedef struct {
    uint64_t         leftmost_child;
    uint32_t         npivots;
    stm_bt_lf_pivot *pivots;
} stm_bt_lf_internal;

typedef struct stm_bt_lf_delta stm_bt_lf_delta;
struct stm_bt_lf_delta {
    stm_bt_lf_delta_kind kind;
    _Atomic uint32_t chain_depth;          /* 0 for BASE*; N for Nth delta above */
    _Atomic(stm_bt_lf_delta *) next;
    union {
        struct { uint8_t *key; uint32_t key_len;
                 uint8_t *val; uint32_t val_len; } upsert;
        struct { uint8_t *key; uint32_t key_len; } del;
        struct { stm_bt_node *node; }      base;
        struct { uint8_t *sep_key; uint32_t sep_key_len;
                 uint64_t sibling_id; } split;
        struct { stm_bt_lf_internal *internal; } base_internal;
        struct { uint64_t forward_id; } sealed;
    } u;
};

/* Page table entries are zero-initialized; slot IDs start from 0. */
#define STM_BT_LF_NO_REDIRECT ((uint64_t)UINT64_MAX)

typedef struct stm_bt_page_table {
    _Atomic(stm_bt_lf_delta *) *slots;
    _Atomic uint64_t            next_id;
    size_t                      capacity;
} stm_bt_page_table;

struct stm_btree_lf {
    stm_bt_page_table *pt;
    _Atomic uint64_t   root_id;
    stm_btree_opts     opts;
    /* Single-consolidator / single-splitter gate. Every split and
     * every parent-update goes through this. Writers past the chain
     * threshold attempt try_acquire; the winner does the work and the
     * rest bail to their insert/delete fast path. force_consolidate
     * (test-only) takes this blocking. */
    _Atomic bool       consolidating;
};

/* ------------------------------------------------------------------------- */
/* Internal-node helpers.                                                     */
/* ------------------------------------------------------------------------- */

static stm_bt_lf_internal *internal_new(uint64_t leftmost_child)
{
    stm_bt_lf_internal *i = calloc(1, sizeof *i);
    if (!i) return NULL;
    i->leftmost_child = leftmost_child;
    i->npivots = 0;
    i->pivots = NULL;
    return i;
}

static void internal_free(stm_bt_lf_internal *i)
{
    if (!i) return;
    for (uint32_t j = 0; j < i->npivots; j++) {
        free(i->pivots[j].sep_key);
    }
    free(i->pivots);
    free(i);
}

/* Build a new internal with one more pivot inserted (sorted). Deep-copies
 * all sep_keys including the new one; caller owns their sep_key buffer
 * and may free it afterwards. */
static stm_bt_lf_internal *
internal_clone_with_pivot(const stm_bt_lf_internal *old,
                          const void *sep_key, uint32_t sep_key_len,
                          uint64_t right_child)
{
    uint32_t idx = 0;
    while (idx < old->npivots &&
           stm_bt_key_cmp(old->pivots[idx].sep_key,
                          old->pivots[idx].sep_key_len,
                          sep_key, sep_key_len) < 0) {
        idx++;
    }

    stm_bt_lf_internal *neu = calloc(1, sizeof *neu);
    if (!neu) return NULL;
    neu->leftmost_child = old->leftmost_child;
    neu->npivots = old->npivots + 1;
    neu->pivots  = calloc(neu->npivots, sizeof *neu->pivots);
    if (!neu->pivots) { free(neu); return NULL; }

    for (uint32_t j = 0; j < idx; j++) {
        uint8_t *nk = stm_bt_dup_bytes(old->pivots[j].sep_key,
                                         old->pivots[j].sep_key_len);
        if (!nk && old->pivots[j].sep_key_len > 0) goto oom;
        neu->pivots[j].sep_key     = nk;
        neu->pivots[j].sep_key_len = old->pivots[j].sep_key_len;
        neu->pivots[j].right_child = old->pivots[j].right_child;
    }

    {
        uint8_t *nk = stm_bt_dup_bytes(sep_key, sep_key_len);
        if (!nk && sep_key_len > 0) goto oom;
        neu->pivots[idx].sep_key     = nk;
        neu->pivots[idx].sep_key_len = sep_key_len;
        neu->pivots[idx].right_child = right_child;
    }

    for (uint32_t j = idx; j < old->npivots; j++) {
        uint8_t *nk = stm_bt_dup_bytes(old->pivots[j].sep_key,
                                         old->pivots[j].sep_key_len);
        if (!nk && old->pivots[j].sep_key_len > 0) goto oom;
        neu->pivots[j + 1].sep_key     = nk;
        neu->pivots[j + 1].sep_key_len = old->pivots[j].sep_key_len;
        neu->pivots[j + 1].right_child = old->pivots[j].right_child;
    }

    return neu;

oom:
    internal_free(neu);
    return NULL;
}

/* Build a new internal with the pivot at `drop_idx` removed. leftmost_child
 * is preserved; the pivot at drop_idx's right_child is effectively merged
 * INTO the child at drop_idx-1 (or leftmost_child if drop_idx==0), since
 * the routing range formerly covered by the dropped pivot now extends the
 * neighboring child's range rightward.
 *
 * Caller must ensure drop_idx < old->npivots. Deep-copies all retained
 * sep_keys; on OOM returns NULL and leaves old untouched. */
static stm_bt_lf_internal *
internal_clone_without_pivot(const stm_bt_lf_internal *old, uint32_t drop_idx)
{
    if (drop_idx >= old->npivots) return NULL;

    stm_bt_lf_internal *neu = calloc(1, sizeof *neu);
    if (!neu) return NULL;
    neu->leftmost_child = old->leftmost_child;
    neu->npivots = old->npivots - 1;
    neu->pivots  = neu->npivots
        ? calloc(neu->npivots, sizeof *neu->pivots)
        : NULL;
    if (neu->npivots > 0 && !neu->pivots) { free(neu); return NULL; }

    uint32_t j = 0;
    for (uint32_t i = 0; i < old->npivots; i++) {
        if (i == drop_idx) continue;
        uint8_t *nk = stm_bt_dup_bytes(old->pivots[i].sep_key,
                                         old->pivots[i].sep_key_len);
        if (!nk && old->pivots[i].sep_key_len > 0) {
            internal_free(neu);
            return NULL;
        }
        neu->pivots[j].sep_key     = nk;
        neu->pivots[j].sep_key_len = old->pivots[i].sep_key_len;
        neu->pivots[j].right_child = old->pivots[i].right_child;
        j++;
    }
    return neu;
}

/* Route a key through an internal node: return the child_id to recurse
 * into. Linear scan — pivot arrays stay small in this MVP. */
static uint64_t internal_route(const stm_bt_lf_internal *i,
                                const void *key, size_t key_len)
{
    uint64_t result = i->leftmost_child;
    for (uint32_t j = 0; j < i->npivots; j++) {
        int cmp = stm_bt_key_cmp(key, key_len,
                                  i->pivots[j].sep_key,
                                  i->pivots[j].sep_key_len);
        if (cmp >= 0) {
            result = i->pivots[j].right_child;
        } else {
            break;              /* pivots sorted; no further matches */
        }
    }
    return result;
}

/* ------------------------------------------------------------------------- */
/* Delta allocation + destruction.                                            */
/* ------------------------------------------------------------------------- */

static void delta_destroy(void *p)
{
    stm_bt_lf_delta *d = (stm_bt_lf_delta *)p;
    switch (d->kind) {
    case STM_BT_LF_DELTA_INSERT:
        free(d->u.upsert.key);
        free(d->u.upsert.val);
        break;
    case STM_BT_LF_DELTA_DELETE:
        free(d->u.del.key);
        break;
    case STM_BT_LF_DELTA_BASE:
        stm_bt_node_free(d->u.base.node);
        break;
    case STM_BT_LF_DELTA_SPLIT:
        free(d->u.split.sep_key);
        break;
    case STM_BT_LF_DELTA_BASE_INTERNAL:
        internal_free(d->u.base_internal.internal);
        break;
    case STM_BT_LF_DELTA_SEALED:
        /* No heap-owned state — forward_id is scalar. */
        break;
    }
    free(d);
}

static stm_bt_lf_delta *alloc_base_delta(stm_bt_node *node)
{
    stm_bt_lf_delta *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->kind = STM_BT_LF_DELTA_BASE;
    atomic_init(&d->next, NULL);
    atomic_init(&d->chain_depth, 0u);
    d->u.base.node = node;
    return d;
}

static stm_bt_lf_delta *alloc_internal_delta(stm_bt_lf_internal *internal)
{
    stm_bt_lf_delta *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->kind = STM_BT_LF_DELTA_BASE_INTERNAL;
    atomic_init(&d->next, NULL);
    atomic_init(&d->chain_depth, 0u);
    d->u.base_internal.internal = internal;
    return d;
}

static stm_bt_lf_delta *alloc_insert_delta(const void *key, size_t key_len,
                                            const void *val, size_t val_len)
{
    stm_bt_lf_delta *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->kind = STM_BT_LF_DELTA_INSERT;
    atomic_init(&d->next, NULL);
    atomic_init(&d->chain_depth, 0u);

    uint8_t *k = stm_bt_dup_bytes(key, key_len);
    uint8_t *v = stm_bt_dup_bytes(val, val_len);
    if ((!k && key_len > 0) || (!v && val_len > 0)) {
        free(k); free(v); free(d);
        return NULL;
    }
    d->u.upsert.key     = k;
    d->u.upsert.key_len = (uint32_t)key_len;
    d->u.upsert.val     = v;
    d->u.upsert.val_len = (uint32_t)val_len;
    return d;
}

static stm_bt_lf_delta *alloc_delete_delta(const void *key, size_t key_len)
{
    stm_bt_lf_delta *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->kind = STM_BT_LF_DELTA_DELETE;
    atomic_init(&d->next, NULL);
    atomic_init(&d->chain_depth, 0u);

    uint8_t *k = stm_bt_dup_bytes(key, key_len);
    if (!k && key_len > 0) { free(d); return NULL; }
    d->u.del.key     = k;
    d->u.del.key_len = (uint32_t)key_len;
    return d;
}

/* Build a SEAL delta for MERGE. No owned heap data. */
static stm_bt_lf_delta *alloc_sealed_delta(uint64_t forward_id)
{
    stm_bt_lf_delta *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->kind = STM_BT_LF_DELTA_SEALED;
    atomic_init(&d->next, NULL);
    atomic_init(&d->chain_depth, 0u);
    d->u.sealed.forward_id = forward_id;
    return d;
}

/* Build a SPLIT delta. Takes ownership of the sep_key buffer. */
static stm_bt_lf_delta *alloc_split_delta(uint8_t *sep_key, uint32_t sep_key_len,
                                           uint64_t sibling_id)
{
    stm_bt_lf_delta *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->kind = STM_BT_LF_DELTA_SPLIT;
    atomic_init(&d->next, NULL);
    atomic_init(&d->chain_depth, 0u);
    d->u.split.sep_key     = sep_key;
    d->u.split.sep_key_len = sep_key_len;
    d->u.split.sibling_id  = sibling_id;
    return d;
}

/* ------------------------------------------------------------------------- */
/* Page table.                                                                */
/* ------------------------------------------------------------------------- */

static stm_bt_page_table *page_table_new(size_t capacity)
{
    if (capacity == 0) return NULL;
    stm_bt_page_table *pt = calloc(1, sizeof *pt);
    if (!pt) return NULL;
    pt->slots = calloc(capacity, sizeof *pt->slots);
    if (!pt->slots) { free(pt); return NULL; }
    atomic_init(&pt->next_id, 0);
    pt->capacity = capacity;
    return pt;
}

static void page_table_free(stm_bt_page_table *pt)
{
    if (!pt) return;
    for (size_t i = 0; i < pt->capacity; i++) {
        stm_bt_lf_delta *d = atomic_load_explicit(&pt->slots[i],
                                                   memory_order_relaxed);
        while (d) {
            stm_bt_lf_delta *next = atomic_load_explicit(&d->next,
                                                           memory_order_relaxed);
            delta_destroy(d);
            d = next;
        }
    }
    free(pt->slots);
    free(pt);
}

static uint64_t page_table_allocate_id(stm_bt_page_table *pt)
{
    return atomic_fetch_add(&pt->next_id, 1);
}

/* ------------------------------------------------------------------------- */
/* Tree construction / destruction.                                           */
/* ------------------------------------------------------------------------- */

stm_status stm_btree_lf_new(const stm_btree_opts *opts, stm_btree_lf **out)
{
    if (!out) return STM_EINVAL;

    stm_status s = stm_ebr_init();
    if (s != STM_OK) return s;

    stm_btree_lf *t = calloc(1, sizeof *t);
    if (!t) return STM_ENOMEM;
    atomic_init(&t->consolidating, false);
    t->opts = opts ? *opts : stm_btree_opts_default();
    if (t->opts.target_entries  < 4) t->opts.target_entries  = 4;
    if (t->opts.target_messages < 1) t->opts.target_messages = 1;

    /* 65536 slots — ample for two-level trees (one root internal +
     * up to 65535 leaves). Three-level support is a future task. */
    t->pt = page_table_new(65536);
    if (!t->pt) { free(t); return STM_ENOMEM; }

    /* Allocate: leaf L0 (slot 0), root internal (slot 1). The root
     * routes every key to leftmost_child = L0 until the first split
     * adds a pivot. */
    stm_bt_node *leaf = stm_bt_node_new_leaf(t->opts.target_entries,
                                              t->opts.target_messages);
    if (!leaf) { page_table_free(t->pt); free(t); return STM_ENOMEM; }

    stm_bt_lf_delta *leaf_base = alloc_base_delta(leaf);
    if (!leaf_base) {
        stm_bt_node_free(leaf);
        page_table_free(t->pt); free(t);
        return STM_ENOMEM;
    }

    uint64_t l0_id = page_table_allocate_id(t->pt);          /* 0 */

    stm_bt_lf_internal *root_internal = internal_new(l0_id);
    if (!root_internal) {
        delta_destroy(leaf_base);
        page_table_free(t->pt); free(t);
        return STM_ENOMEM;
    }

    stm_bt_lf_delta *root_base = alloc_internal_delta(root_internal);
    if (!root_base) {
        internal_free(root_internal);
        delta_destroy(leaf_base);
        page_table_free(t->pt); free(t);
        return STM_ENOMEM;
    }

    uint64_t root_id = page_table_allocate_id(t->pt);        /* 1 */

    atomic_store(&t->pt->slots[l0_id],   leaf_base);
    atomic_store(&t->pt->slots[root_id], root_base);
    atomic_store(&t->root_id, root_id);

    *out = t;
    return STM_OK;
}

void stm_btree_lf_free(stm_btree_lf *t)
{
    if (!t) return;
    page_table_free(t->pt);
    free(t);
}

/* ------------------------------------------------------------------------- */
/* Chain walk at a leaf — multi-SPLIT aware.                                  */
/* ------------------------------------------------------------------------- */

/* Walk a leaf's chain newest-first, deciding among:
 *
 *   - INSERT/DELETE matching the key → `*out_match` is the delta, return OK.
 *   - Needs redirect (SPLIT(s) with s <= key → pick largest s) → `*out_redirect`
 *     holds sibling_id, return OK with *out_match = NULL.
 *   - BASE_LEAF reached without match or redirect → *out_base is set.
 *
 * Exactly one of *out_match, *out_redirect != NO_REDIRECT, or *out_base
 * will be populated on STM_OK. A malformed chain (no BASE reached)
 * returns STM_ECORRUPT with all outs NULL.
 *
 * Multi-SPLIT rule: leaves can carry multiple SPLITs, their seps
 * monotonically increasing newest-first. A reader picks the SPLIT with
 * the LARGEST sep <= key because that is the one whose sibling holds
 * `key`'s current range. Reasoning:
 *
 *   chain newest-first: SPLIT(s_0) SPLIT(s_1) ... SPLIT(s_m) BASE
 *                       with s_0 < s_1 < ... < s_m
 *
 * Each SPLIT(s_i) routes [s_i, s_{i-1}) (or [s_m, ∞) for the oldest)
 * to its sibling. To find the right sibling for key k, take the
 * LARGEST s_i with s_i <= k.
 *
 * Walking newest-first, we upgrade the candidate as we see larger
 * seps. The first SPLIT with s > k lets us break: older SPLITs have
 * even larger seps, none of which can match. */
static stm_status resolve_leaf_chain(stm_bt_lf_delta *head,
                                      const void *key, size_t key_len,
                                      stm_bt_lf_delta **out_match,
                                      uint64_t *out_redirect,
                                      stm_bt_lf_delta **out_base)
{
    *out_match    = NULL;
    *out_redirect = STM_BT_LF_NO_REDIRECT;
    *out_base     = NULL;

    /* SEAL head: defensive forward. Callers (lookup, traverse) should
     * intercept SEAL before calling this, but treat it correctly if it
     * slips through. */
    if (head && head->kind == STM_BT_LF_DELTA_SEALED) {
        *out_redirect = head->u.sealed.forward_id;
        return STM_OK;
    }

    uint64_t candidate_sibling = 0;
    bool     has_candidate     = false;

    for (stm_bt_lf_delta *d = head; d; d = atomic_load(&d->next)) {
        switch (d->kind) {
        case STM_BT_LF_DELTA_INSERT:
            if (stm_bt_key_cmp(d->u.upsert.key, d->u.upsert.key_len,
                               key, key_len) == 0) {
                *out_match = d;
                return STM_OK;
            }
            break;
        case STM_BT_LF_DELTA_DELETE:
            if (stm_bt_key_cmp(d->u.del.key, d->u.del.key_len,
                               key, key_len) == 0) {
                *out_match = d;
                return STM_OK;
            }
            break;
        case STM_BT_LF_DELTA_SPLIT: {
            int cmp = stm_bt_key_cmp(key, key_len,
                                      d->u.split.sep_key,
                                      d->u.split.sep_key_len);
            if (cmp >= 0) {
                /* key >= sep; candidate. Keep looking for a larger
                 * sep (older SPLIT) that also matches. */
                candidate_sibling = d->u.split.sibling_id;
                has_candidate     = true;
            } else {
                /* sep > key; older SPLITs have even larger seps. No
                 * more candidates possible. Break to finalize. */
                if (has_candidate) {
                    *out_redirect = candidate_sibling;
                    return STM_OK;
                }
                goto scan_base;
            }
            break;
        }
        case STM_BT_LF_DELTA_BASE:
            if (has_candidate) {
                *out_redirect = candidate_sibling;
                return STM_OK;
            }
            *out_base = d;
            return STM_OK;
        case STM_BT_LF_DELTA_BASE_INTERNAL:
            /* A leaf chain should never contain BASE_INTERNAL. */
            return STM_ECORRUPT;
        case STM_BT_LF_DELTA_SEALED:
            /* SEAL only valid at head; intercepted above. Mid-chain
             * SEAL is a corruption signal. */
            return STM_ECORRUPT;
        }
    }

    return STM_ECORRUPT;

scan_base:
    /* Found a SPLIT with sep > key without prior candidate: the key
     * is below all SPLITs. Continue walking to find BASE; no more
     * candidate possible. INSERT/DELETE above wouldn't have been
     * encountered yet (we hit SPLIT first and returned). */
    for (stm_bt_lf_delta *d = head; d; d = atomic_load(&d->next)) {
        if (d->kind == STM_BT_LF_DELTA_BASE) {
            *out_base = d;
            return STM_OK;
        }
    }
    return STM_ECORRUPT;
}

/* ------------------------------------------------------------------------- */
/* Lookup.                                                                    */
/* ------------------------------------------------------------------------- */

stm_status stm_btree_lf_lookup(const stm_btree_lf *t, stm_ebr_thread *ebr,
                                const void *key, size_t key_len,
                                void *buf, size_t buf_cap,
                                size_t *out_value_len)
{
    if (!t || !ebr || !key) return STM_EINVAL;

    stm_ebr_enter(ebr);

    uint64_t nid = atomic_load(&t->root_id);
    stm_status result = STM_ECORRUPT;

    for (uint32_t hops = 0; hops < 64; hops++) {
        if (nid >= t->pt->capacity) { result = STM_ECORRUPT; goto out; }
        stm_bt_lf_delta *head = atomic_load(&t->pt->slots[nid]);
        if (!head) { result = STM_ECORRUPT; goto out; }

        /* At an internal node, route via the pivot array and recurse. */
        if (head->kind == STM_BT_LF_DELTA_BASE_INTERNAL) {
            nid = internal_route(head->u.base_internal.internal,
                                  key, key_len);
            continue;
        }

        /* SEAL'd leaf: the leaf has been merged away. Follow the
         * forward to the sibling that absorbed its range. Only reachable
         * by stale-pivot readers whose parent snapshot predates the
         * UpdateParent of the MERGE protocol; fresh readers don't route
         * here because parent no longer has this leaf's pivot. */
        if (head->kind == STM_BT_LF_DELTA_SEALED) {
            nid = head->u.sealed.forward_id;
            continue;
        }

        /* At a leaf, walk the chain. */
        stm_bt_lf_delta *match = NULL, *base = NULL;
        uint64_t redirect = STM_BT_LF_NO_REDIRECT;
        stm_status rc = resolve_leaf_chain(head, key, key_len,
                                            &match, &redirect, &base);
        if (rc != STM_OK) { result = rc; goto out; }

        if (redirect != STM_BT_LF_NO_REDIRECT) {
            nid = redirect;
            continue;
        }

        if (match) {
            if (match->kind == STM_BT_LF_DELTA_INSERT) {
                uint32_t vl = match->u.upsert.val_len;
                if (out_value_len) *out_value_len = vl;
                if (buf == NULL || buf_cap == 0) { result = STM_OK; goto out; }
                if (vl > buf_cap) { result = STM_ERANGE; goto out; }
                memcpy(buf, match->u.upsert.val, vl);
                result = STM_OK;
                goto out;
            }
            /* DELETE */
            result = STM_ENOENT;
            goto out;
        }

        /* Fell through to BASE. */
        stm_bt_node *node = base->u.base.node;
        bool found;
        uint32_t idx = stm_bt_entry_lower_bound(node->entries, node->nentries,
                                                 key, key_len, &found);
        if (!found) { result = STM_ENOENT; goto out; }
        const stm_bt_entry *e = &node->entries[idx];
        if (out_value_len) *out_value_len = e->value_len;
        if (buf == NULL || buf_cap == 0) { result = STM_OK; goto out; }
        if (e->value_len > buf_cap) { result = STM_ERANGE; goto out; }
        memcpy(buf, e->value, e->value_len);
        result = STM_OK;
        goto out;
    }

    /* Hops exhausted. Malformed tree or cycle. */
    result = STM_ECORRUPT;

out:
    stm_ebr_exit(ebr);
    return result;
}

/* ------------------------------------------------------------------------- */
/* Consolidation.                                                             */
/* ------------------------------------------------------------------------- */

/* Apply one INSERT delta to a partially-constructed leaf. */
static stm_status apply_insert_to_leaf(stm_bt_node *leaf,
                                        const stm_bt_lf_delta *d)
{
    bool found;
    uint32_t idx = stm_bt_entry_lower_bound(leaf->entries, leaf->nentries,
                                             d->u.upsert.key,
                                             d->u.upsert.key_len,
                                             &found);
    if (found) {
        uint8_t *nv = stm_bt_dup_bytes(d->u.upsert.val, d->u.upsert.val_len);
        if (!nv && d->u.upsert.val_len > 0) return STM_ENOMEM;
        free(leaf->entries[idx].value);
        leaf->entries[idx].value     = nv;
        leaf->entries[idx].value_len = d->u.upsert.val_len;
        return STM_OK;
    }

    stm_status s = stm_bt_node_grow_entries(leaf, leaf->nentries + 1);
    if (s != STM_OK) return s;

    memmove(&leaf->entries[idx + 1], &leaf->entries[idx],
            (leaf->nentries - idx) * sizeof(stm_bt_entry));

    uint8_t *nk = stm_bt_dup_bytes(d->u.upsert.key, d->u.upsert.key_len);
    uint8_t *nv = stm_bt_dup_bytes(d->u.upsert.val, d->u.upsert.val_len);
    if ((!nk && d->u.upsert.key_len > 0) ||
        (!nv && d->u.upsert.val_len > 0)) {
        free(nk); free(nv);
        memmove(&leaf->entries[idx], &leaf->entries[idx + 1],
                (leaf->nentries - idx) * sizeof(stm_bt_entry));
        return STM_ENOMEM;
    }
    leaf->entries[idx] = (stm_bt_entry){
        .key = nk, .key_len = d->u.upsert.key_len,
        .value = nv, .value_len = d->u.upsert.val_len,
    };
    leaf->nentries++;
    return STM_OK;
}

static void apply_delete_to_leaf(stm_bt_node *leaf, const stm_bt_lf_delta *d)
{
    bool found;
    uint32_t idx = stm_bt_entry_lower_bound(leaf->entries, leaf->nentries,
                                             d->u.del.key, d->u.del.key_len,
                                             &found);
    if (!found) return;

    free(leaf->entries[idx].key);
    free(leaf->entries[idx].value);
    memmove(&leaf->entries[idx], &leaf->entries[idx + 1],
            (leaf->nentries - idx - 1) * sizeof(stm_bt_entry));
    leaf->nentries--;
}

/* All SPLIT deltas extracted from a chain during consolidation,
 * preserved for the new chain head. Caller owns the sep_key buffers —
 * they transfer into new SPLIT deltas when the new chain is built,
 * or are freed if the caller bails. Stored newest-first (same order
 * as the chain). */
typedef struct {
    uint32_t n;
    struct {
        uint8_t *sep_key;
        uint32_t sep_key_len;
        uint64_t sibling_id;
    } splits[STM_BT_LF_MAX_SPLITS];
} stm_bt_lf_preserved_splits;

static void preserved_splits_free(stm_bt_lf_preserved_splits *p)
{
    for (uint32_t i = 0; i < p->n; i++) {
        free(p->splits[i].sep_key);
        p->splits[i].sep_key = NULL;
    }
    p->n = 0;
}

/* Build a fresh base by cloning the BASE node in `head`'s chain and
 * applying the INSERT/DELETE deltas oldest-first. SPLIT deltas are
 * extracted into `*out_splits` in newest-first order. On success the
 * caller owns the returned leaf node AND the sep_key buffers in
 * out_splits. On failure, returns NULL and frees any sep_keys. */
static stm_bt_node *build_consolidated_leaf(stm_bt_lf_delta *head,
                                             stm_btree_opts opts,
                                             stm_bt_lf_preserved_splits *out)
{
    stm_bt_lf_delta *stack[STM_BT_LF_MAX_CHAIN];
    size_t sp = 0;
    stm_bt_lf_delta *base_delta = NULL;

    out->n = 0;

    for (stm_bt_lf_delta *d = head; d; d = atomic_load(&d->next)) {
        if (d->kind == STM_BT_LF_DELTA_BASE) { base_delta = d; break; }
        if (d->kind == STM_BT_LF_DELTA_BASE_INTERNAL) return NULL;
        if (sp >= STM_BT_LF_MAX_CHAIN) return NULL;
        stack[sp++] = d;
    }
    if (!base_delta) return NULL;

    stm_bt_node *new_leaf = stm_bt_node_new_leaf(opts.target_entries,
                                                  opts.target_messages);
    if (!new_leaf) return NULL;

    /* Clone the old base entries into the new leaf. */
    stm_bt_node *old = base_delta->u.base.node;
    if (old->nentries > 0) {
        stm_status s = stm_bt_node_grow_entries(new_leaf, old->nentries);
        if (s != STM_OK) { stm_bt_node_free(new_leaf); return NULL; }
        for (uint32_t i = 0; i < old->nentries; i++) {
            uint8_t *nk = stm_bt_dup_bytes(old->entries[i].key,
                                             old->entries[i].key_len);
            uint8_t *nv = stm_bt_dup_bytes(old->entries[i].value,
                                             old->entries[i].value_len);
            if ((!nk && old->entries[i].key_len > 0) ||
                (!nv && old->entries[i].value_len > 0)) {
                free(nk); free(nv);
                stm_bt_node_free(new_leaf);
                return NULL;
            }
            new_leaf->entries[i] = (stm_bt_entry){
                .key = nk, .key_len = old->entries[i].key_len,
                .value = nv, .value_len = old->entries[i].value_len,
            };
            new_leaf->nentries++;
        }
    }

    /* Replay deltas oldest-first (stack was filled newest-first).
     * SPLITs are extracted to preserved splits — they need to be
     * carried onto the new chain head, but they don't modify the
     * base. */
    while (sp > 0) {
        stm_bt_lf_delta *d = stack[--sp];
        switch (d->kind) {
        case STM_BT_LF_DELTA_INSERT: {
            stm_status s = apply_insert_to_leaf(new_leaf, d);
            if (s != STM_OK) {
                preserved_splits_free(out);
                stm_bt_node_free(new_leaf);
                return NULL;
            }
            break;
        }
        case STM_BT_LF_DELTA_DELETE:
            apply_delete_to_leaf(new_leaf, d);
            break;
        case STM_BT_LF_DELTA_SPLIT: {
            /* Preserved newest-first. We're walking oldest-first here,
             * so insert at the head of the preserved list (index 0)
             * by shifting. Simpler: collect oldest-first then reverse.
             * Here we put newer SPLITs AFTER older ones, then reverse.
             * But we're walking oldest-first from stack, meaning the
             * earliest SPLIT we encounter during replay is the OLDEST
             * in the chain. To preserve newest-first order (smallest
             * sep first), we need to insert into the preserved list
             * at position 0 and shift. */
            if (out->n >= STM_BT_LF_MAX_SPLITS) {
                preserved_splits_free(out);
                stm_bt_node_free(new_leaf);
                return NULL;
            }
            uint8_t *nk = stm_bt_dup_bytes(d->u.split.sep_key,
                                             d->u.split.sep_key_len);
            if (!nk && d->u.split.sep_key_len > 0) {
                preserved_splits_free(out);
                stm_bt_node_free(new_leaf);
                return NULL;
            }
            /* Shift existing splits up by 1 and put new at [0] so
             * preserved is newest-first (smallest sep first). */
            memmove(&out->splits[1], &out->splits[0],
                    out->n * sizeof out->splits[0]);
            out->splits[0].sep_key     = nk;
            out->splits[0].sep_key_len = d->u.split.sep_key_len;
            out->splits[0].sibling_id  = d->u.split.sibling_id;
            out->n++;
            break;
        }
        case STM_BT_LF_DELTA_BASE:
        case STM_BT_LF_DELTA_BASE_INTERNAL:
        case STM_BT_LF_DELTA_SEALED:
            /* SEAL should be intercepted before consolidation (the
             * slot's head is checked in consolidate_or_split). Seeing
             * one here is a corruption signal. */
            preserved_splits_free(out);
            stm_bt_node_free(new_leaf);
            return NULL;
        }
    }

    return new_leaf;
}

/* Wait — the newest-first ordering I claimed above is backwards.
 *
 * Chain order (memory): [INSERT_newest, ..., SPLIT_newest, ..., SPLIT_oldest, BASE].
 * Newest SPLIT (smallest sep) is closer to head; oldest SPLIT (largest sep) is
 * closer to BASE.
 *
 * Walking d = head; d = d->next; we visit newest-first. So SPLITs in
 * the order (d->next traversal): smallest sep first (newest), largest
 * sep last (oldest).
 *
 * But build_consolidated_leaf walks the chain forward (newest-first)
 * to populate the stack, then pops LIFO => oldest-first on replay.
 * That means during replay we see SPLITs oldest-first (largest sep
 * first), newest last (smallest sep last).
 *
 * To rebuild preserved[] in newest-first order (smallest sep first,
 * matching the chain layout), we insert each replayed SPLIT at
 * preserved[0] and shift — which is what the memmove above does. The
 * LAST SPLIT we see during replay (the newest, smallest sep) ends up
 * at preserved[0]. Correct. */

/* Retire each delta in a chain through EBR. Walks d->next until NULL. */
static void retire_chain(stm_bt_lf_delta *head)
{
    stm_bt_lf_delta *d = head;
    while (d) {
        stm_bt_lf_delta *next = atomic_load(&d->next);
        stm_status s = stm_ebr_retire(d, delta_destroy);
        if (s != STM_OK) {
            /* Retire failed (OOM in EBR). Best effort: accept the
             * leak. Freeing d directly would be unsafe if a pinned
             * reader is still traversing. */
        }
        d = next;
    }
}

/* Build a chain head of [SPLIT_n, ..., SPLIT_0, BASE_LEAF(leaf)] where
 * SPLITs come from `preserved` (in the same newest-first order).
 *
 * Contract: on SUCCESS the returned chain owns `leaf` + all sep_key
 * buffers in `preserved` (which is left with n=0). On FAILURE returns
 * NULL AND the caller retains ownership of `leaf` (must free) AND any
 * sep_key buffers in preserved that weren't transferred (those remain
 * with sep_key != NULL; transferred slots are set to NULL). */
static stm_bt_lf_delta *build_leaf_chain(stm_bt_node *leaf,
                                           stm_bt_lf_preserved_splits *preserved)
{
    stm_bt_lf_delta *base = alloc_base_delta(leaf);
    if (!base) return NULL;  /* leaf retained by caller */

    stm_bt_lf_delta *cur = base;
    uint32_t depth = 0;

    /* Preserved[] is newest-first (index 0 = smallest sep). Walk it
     * backwards (n-1 → 0) so each prepend yields the correct order. */
    for (uint32_t i = preserved->n; i > 0; ) {
        i--;
        stm_bt_lf_delta *sd = alloc_split_delta(preserved->splits[i].sep_key,
                                                 preserved->splits[i].sep_key_len,
                                                 preserved->splits[i].sibling_id);
        if (!sd) {
            /* Destroy SPLITs prepended above base, but preserve
             * base's leaf — detach it and caller will reclaim. */
            while (cur != base) {
                stm_bt_lf_delta *nx =
                    atomic_load_explicit(&cur->next, memory_order_relaxed);
                delta_destroy(cur);
                cur = nx;
            }
            base->u.base.node = NULL;   /* detach so delta_destroy
                                           doesn't free leaf */
            delta_destroy(base);
            return NULL;
        }
        preserved->splits[i].sep_key = NULL;   /* transferred to sd */
        atomic_store_explicit(&sd->next, cur, memory_order_relaxed);
        depth++;
        atomic_store_explicit(&sd->chain_depth, depth, memory_order_relaxed);
        cur = sd;
    }

    preserved->n = 0;                          /* all transferred */
    return cur;
}

/* Split `full_base` into lower + upper halves. Installs upper at a
 * fresh sibling slot (Step 1 InstallSibling), PostSplit's the leaf
 * slot at `nid` (Step 2), then UpdateParent's the parent slot at
 * `parent_nid` with a new pivot (Step 3). All three under
 * t->consolidating (enforced by caller).
 *
 * On entry: full_base owns its entries; will be consumed regardless
 * of outcome. old_head is the expected current chain head at `nid`
 * (for CAS). preserved carries the SPLIT redirects that need to be
 * preserved above the new BASE on `nid`'s chain.
 *
 * Spec: balanced.tla Phase_Installed_X → Phase_PostSplit →
 * Phase_ParentUpd. */
static stm_status commit_split(stm_btree_lf *t, uint64_t nid,
                                 uint64_t parent_nid,
                                 stm_bt_lf_delta *old_head,
                                 stm_bt_node *full_base,
                                 stm_bt_lf_preserved_splits *preserved)
{
    stm_bt_node             *upper                 = NULL;
    uint8_t                 *sep_key               = NULL;
    uint32_t                 sep_len               = 0;
    uint64_t                 upper_id              = 0;
    bool                     upper_installed       = false;
    stm_bt_lf_delta         *upper_base            = NULL;
    stm_bt_lf_delta         *lower_head            = NULL;  /* whole new chain head for nid */
    stm_bt_lf_internal      *new_parent_internal   = NULL;
    stm_bt_lf_delta         *new_parent_delta      = NULL;
    stm_status               rc                    = STM_OK;

    if (full_base->nentries < 2) { rc = STM_EINVAL; goto cleanup; }

    uint32_t mid = full_base->nentries / 2;
    uint32_t upper_count = full_base->nentries - mid;

    upper = stm_bt_node_new_leaf(t->opts.target_entries,
                                  t->opts.target_messages);
    if (!upper) { rc = STM_ENOMEM; goto cleanup; }

    rc = stm_bt_node_grow_entries(upper, upper_count);
    if (rc != STM_OK) goto cleanup;

    /* Move entries[mid..] to upper — byte copies remain, we rehome
     * the pointers. */
    memcpy(upper->entries, &full_base->entries[mid],
           upper_count * sizeof(stm_bt_entry));
    upper->nentries = upper_count;
    memset(&full_base->entries[mid], 0, upper_count * sizeof(stm_bt_entry));
    full_base->nentries = mid;

    sep_key = stm_bt_dup_bytes(upper->entries[0].key,
                                upper->entries[0].key_len);
    sep_len = upper->entries[0].key_len;
    if (!sep_key && sep_len > 0) { rc = STM_ENOMEM; goto cleanup; }

    upper_id = page_table_allocate_id(t->pt);
    if (upper_id >= t->pt->capacity) { rc = STM_EOVERFLOW; goto cleanup; }

    upper_base = alloc_base_delta(upper);
    if (!upper_base) { rc = STM_ENOMEM; goto cleanup; }
    upper = NULL;                               /* owned by upper_base */

    /* Step 1 — InstallSibling. The slot was zero-initialized; nobody
     * can observe upper_id yet (no pivot routes there, no SPLIT
     * redirects there). A relaxed store is enough. */
    atomic_store(&t->pt->slots[upper_id], upper_base);
    upper_installed = true;
    upper_base = NULL;                          /* owned by slot now */

    /* Build the new chain head for nid: [SPLIT(sep, upper_id),
     * preserved SPLITs..., BASE(lower)]. alloc_split_delta takes
     * ownership of sep_key on success. */
    {
        stm_bt_lf_delta *base_delta = alloc_base_delta(full_base);
        if (!base_delta) { rc = STM_ENOMEM; goto cleanup; }
        full_base = NULL;                       /* owned by base_delta */

        /* Prepend preserved SPLITs oldest-first onto base. */
        stm_bt_lf_delta *cur = base_delta;
        uint32_t depth = 0;
        for (uint32_t i = preserved->n; i > 0; ) {
            i--;
            stm_bt_lf_delta *sd =
                alloc_split_delta(preserved->splits[i].sep_key,
                                  preserved->splits[i].sep_key_len,
                                  preserved->splits[i].sibling_id);
            if (!sd) {
                /* Unwind partial chain: free everything we built.
                 * Transferred sep_keys (indices > i) were NULL'd in
                 * their own iteration below and freed via the
                 * delta_destroy; untransferred indices [0, i] remain
                 * in preserved for caller cleanup. */
                while (cur) {
                    stm_bt_lf_delta *nx = atomic_load_explicit(
                        &cur->next, memory_order_relaxed);
                    delta_destroy(cur);
                    cur = nx;
                }
                rc = STM_ENOMEM;
                goto cleanup;
            }
            preserved->splits[i].sep_key = NULL;
            atomic_store_explicit(&sd->next, cur, memory_order_relaxed);
            depth++;
            atomic_store_explicit(&sd->chain_depth, depth,
                                   memory_order_relaxed);
            cur = sd;
        }
        preserved->n = 0;

        /* Now prepend the new SPLIT(sep, upper_id) as the head.
         * alloc_split_delta takes ownership of sep_key on success
         * only; on failure the caller retains (cleanup will free). */
        stm_bt_lf_delta *new_split = alloc_split_delta(sep_key, sep_len, upper_id);
        if (!new_split) {
            while (cur) {
                stm_bt_lf_delta *nx = atomic_load_explicit(
                    &cur->next, memory_order_relaxed);
                delta_destroy(cur);
                cur = nx;
            }
            rc = STM_ENOMEM;
            goto cleanup;
        }
        sep_key = NULL;  /* transferred to new_split */
        atomic_store_explicit(&new_split->next, cur, memory_order_relaxed);
        depth++;
        atomic_store_explicit(&new_split->chain_depth, depth,
                               memory_order_relaxed);
        lower_head = new_split;
    }

    /* Step 2 — PostSplit. CAS the leaf's slot. */
    if (!atomic_compare_exchange_strong(&t->pt->slots[nid],
                                         &old_head, lower_head)) {
        /* Raced. Abort the split. The slot now holds someone else's
         * chain (probably a new INSERT/DELETE prepended on the
         * original old_head). upper_id is installed but unreachable;
         * we clean it up and release the sibling. */
        goto cleanup;
    }

    /* Step 3 — UpdateParent. Clone the parent's BASE_INTERNAL with
     * the new pivot added. */
    {
        stm_bt_lf_delta *parent_head = atomic_load(&t->pt->slots[parent_nid]);
        if (!parent_head ||
            parent_head->kind != STM_BT_LF_DELTA_BASE_INTERNAL) {
            /* Corrupt tree state. We've already committed steps 1+2;
             * abandon the parent update. Readers still get correct
             * answers via the SPLIT redirect on nid. */
            rc = STM_ECORRUPT;
            /* Do NOT retire old_head on the corruption path — we're
             * bailing. Actually step 2 succeeded so old_head is
             * unreferenced; retire it. The leaf slot is committed. */
            retire_chain(old_head);
            return rc;
        }
        new_parent_internal = internal_clone_with_pivot(
            parent_head->u.base_internal.internal,
            lower_head->u.split.sep_key,
            lower_head->u.split.sep_key_len,
            upper_id);
        if (!new_parent_internal) {
            /* Allocation failure on parent rebuild. The leaf has been
             * committed with its SPLIT redirect; readers are still
             * correct via the redirect. We just leave the parent as-
             * is and return OK. A later split or force_consolidate
             * can retry the parent update when memory permits. */
            retire_chain(old_head);
            return STM_OK;
        }
        new_parent_delta = alloc_internal_delta(new_parent_internal);
        if (!new_parent_delta) {
            internal_free(new_parent_internal);
            retire_chain(old_head);
            return STM_OK;
        }
        new_parent_internal = NULL;  /* owned by delta */

        if (!atomic_compare_exchange_strong(&t->pt->slots[parent_nid],
                                             &parent_head, new_parent_delta)) {
            /* CAS failed. Under t->consolidating the parent slot
             * shouldn't be changing; if it did something is wrong.
             * Accept the pivot loss — readers are still correct via
             * SPLIT redirect. */
            delta_destroy(new_parent_delta);
            retire_chain(old_head);
            return STM_OK;
        }

        /* Retire the old parent head. */
        retire_chain(parent_head);
    }

    retire_chain(old_head);
    return STM_OK;

cleanup:
    /* Phase-A cleanup (pre-PostSplit). Step 2 either hasn't fired or
     * failed its CAS. upper_id might be installed but unreachable. */
    if (upper_installed) {
        /* Uninstall the sibling and free its BASE_LEAF delta. No
         * reader can hold a reference — no pivot and no SPLIT
         * redirect points at upper_id yet, so direct destroy is safe. */
        stm_bt_lf_delta *installed =
            atomic_exchange(&t->pt->slots[upper_id], NULL);
        if (installed) delta_destroy(installed);
    }
    if (lower_head) {
        /* Walk and free the whole built chain [new_split,
         * preserved_splits..., base]. */
        stm_bt_lf_delta *cur = lower_head;
        while (cur) {
            stm_bt_lf_delta *nx = atomic_load_explicit(&cur->next,
                                                         memory_order_relaxed);
            delta_destroy(cur);
            cur = nx;
        }
        full_base = NULL;                 /* freed via base_delta above */
        sep_key   = NULL;                 /* freed via new_split above */
    }
    if (upper_base) delta_destroy(upper_base);
    else if (upper) stm_bt_node_free(upper);
    if (full_base)  stm_bt_node_free(full_base);
    if (sep_key)    free(sep_key);
    return rc;
}

/* Search the tree for the parent_nid of `leaf_nid`. In the two-level
 * MVP the parent is always the root. */
static uint64_t find_parent(stm_btree_lf *t, uint64_t leaf_nid)
{
    uint64_t root_id = atomic_load(&t->root_id);
    if (root_id == leaf_nid) return STM_BT_LF_NO_REDIRECT;
    return root_id;
}

/* Find the index k such that internal->pivots[k].right_child == child_nid.
 * Returns k on success, -1 if child_nid is the leftmost_child (leftmost
 * merges are unsupported in this MVP) or not found. */
static int32_t find_pivot_index(const stm_bt_lf_internal *internal,
                                  uint64_t child_nid)
{
    if (internal->leftmost_child == child_nid) return -1;
    for (uint32_t k = 0; k < internal->npivots; k++) {
        if (internal->pivots[k].right_child == child_nid) return (int32_t)k;
    }
    return -1;
}

/* Rebuild L's slot head without its SPLIT(*, r_nid) entry. When R was
 * carved out of L by an earlier split, L's chain acquired a SPLIT that
 * redirects k >= sep to R. Merging R back into L without dropping that
 * SPLIT would create a bounce: reader arrives at L, sees SPLIT, goes to
 * R, finds SEAL, forwards back to L, re-sees SPLIT, loops.
 *
 * This is step 0 of the MERGE protocol (a precondition that merge.tla's
 * three-step spec implicitly assumes — its scenario models L1 as
 * [BASE_LEAF(L1_initial)] with no SPLIT).
 *
 * Consolidates L's chain (extracting BASE + preserved SPLITs), drops the
 * preserved SPLIT pointing at r_nid, rebuilds the chain, and CASes L's
 * slot. On CAS failure from a racing writer, retries; on exhaustion
 * returns OK (the merge attempt will skip this round). Caller holds
 * t->consolidating so no other structural op races.
 */
static stm_status purge_split_on_l(stm_btree_lf *t, uint64_t l_nid,
                                     uint64_t r_nid)
{
    for (uint32_t attempt = 0; attempt < STM_BT_LF_CONSOLIDATE_RETRIES; attempt++) {
        stm_bt_lf_delta *old_head = atomic_load(&t->pt->slots[l_nid]);
        if (!old_head) return STM_ECORRUPT;
        if (old_head->kind == STM_BT_LF_DELTA_BASE_INTERNAL ||
            old_head->kind == STM_BT_LF_DELTA_SEALED) return STM_OK;

        stm_bt_lf_preserved_splits preserved = { .n = 0 };
        stm_bt_node *new_base =
            build_consolidated_leaf(old_head, t->opts, &preserved);
        if (!new_base) return STM_ENOMEM;

        /* L overflowing during a merge of R is unusual — defer merge. */
        if (new_base->nentries > t->opts.target_entries) {
            stm_bt_node_free(new_base);
            preserved_splits_free(&preserved);
            return STM_OK;
        }

        /* Drop any SPLIT whose sibling is r_nid. In practice there is
         * exactly one (from when R was split off L), but be permissive. */
        bool removed = false;
        for (uint32_t i = 0; i < preserved.n; ) {
            if (preserved.splits[i].sibling_id == r_nid) {
                free(preserved.splits[i].sep_key);
                memmove(&preserved.splits[i], &preserved.splits[i + 1],
                        (preserved.n - i - 1) * sizeof preserved.splits[0]);
                preserved.n--;
                removed = true;
            } else {
                i++;
            }
        }

        if (!removed) {
            /* L already carries no SPLIT(*, R). Maybe a previous purge
             * succeeded but SealR aborted; retry paths land here. No-op
             * and let the caller proceed. */
            stm_bt_node_free(new_base);
            preserved_splits_free(&preserved);
            return STM_OK;
        }

        stm_bt_lf_delta *new_head = build_leaf_chain(new_base, &preserved);
        if (!new_head) {
            stm_bt_node_free(new_base);
            preserved_splits_free(&preserved);
            return STM_ENOMEM;
        }

        if (atomic_compare_exchange_strong(&t->pt->slots[l_nid],
                                            &old_head, new_head)) {
            retire_chain(old_head);
            return STM_OK;
        }
        /* Concurrent writer prepended; free new_head (walk + destroy)
         * and retry with fresh old_head. */
        stm_bt_lf_delta *cur = new_head;
        while (cur) {
            stm_bt_lf_delta *nx = atomic_load_explicit(&cur->next,
                                                         memory_order_relaxed);
            delta_destroy(cur);
            cur = nx;
        }
    }
    return STM_OK;
}

/* Implements the four-step MERGE protocol. merge.tla models steps 1-3
 * (SealR, UpdateParent, RetireR); step 0 (PurgeSplitOnL) is a
 * precondition establishing the spec's scenario (L without SPLIT to R).
 *
 *   0. PurgeSplitOnL — CAS L's slot to a chain without SPLIT(*, R).
 *                      Prevents reader/writer bounce between L and
 *                      SEAL(forward=L).
 *   1. SealR        — CAS R's slot from expected_head to SEAL(forward).
 *   2. UpdateParent — CAS parent's BASE_INTERNAL to drop pivot at
 *                     `pivot_index`. Serialized by t->consolidating.
 *   3. RetireR      — EBR-retire expected_head (R's pre-SEAL chain).
 *                     SEAL itself persists in R's slot (no slot
 *                     reclamation in this MVP; matches burned-ID
 *                     policy in phase2-status.md).
 *
 * Caller must hold t->consolidating. expected_head must be a
 * BASE_LEAF with zero entries and no SPLIT deltas above it
 * (eligibility checked by try_merge).
 *
 * Failure modes:
 *   - PurgeSplitOnL returns ENOMEM: propagate; merge deferred.
 *   - SealR CAS fails (writer raced an INSERT into the "empty" leaf):
 *     abort, leaf reverts to its correct non-empty state. L's purge
 *     has already landed but is harmless (just one fewer redundant
 *     redirect).
 *   - UpdateParent CAS fails: shouldn't happen under t->consolidating;
 *     defensive accept — SEAL on R still forwards correctly so
 *     readers remain correct. Pivot leak (minor, bounded by merge
 *     count in this MVP).
 */
static stm_status commit_merge(stm_btree_lf *t, uint64_t r_nid,
                                 uint64_t parent_nid,
                                 stm_bt_lf_delta *expected_head,
                                 uint32_t pivot_index)
{
    stm_bt_lf_delta *parent_head = atomic_load(&t->pt->slots[parent_nid]);
    if (!parent_head || parent_head->kind != STM_BT_LF_DELTA_BASE_INTERNAL)
        return STM_ECORRUPT;
    const stm_bt_lf_internal *cur = parent_head->u.base_internal.internal;
    if (pivot_index >= cur->npivots) return STM_ECORRUPT;
    if (cur->pivots[pivot_index].right_child != r_nid) return STM_ECORRUPT;

    /* Forward target: left neighbor in the pivot array. */
    uint64_t forward_id = (pivot_index == 0)
        ? cur->leftmost_child
        : cur->pivots[pivot_index - 1].right_child;

    /* Build the post-merge parent internal (drops pivot_index). */
    stm_bt_lf_internal *new_internal =
        internal_clone_without_pivot(cur, pivot_index);
    if (!new_internal) return STM_ENOMEM;

    stm_bt_lf_delta *new_parent_delta = alloc_internal_delta(new_internal);
    if (!new_parent_delta) {
        internal_free(new_internal);
        return STM_ENOMEM;
    }

    /* Build SEAL delta. */
    stm_bt_lf_delta *sealed = alloc_sealed_delta(forward_id);
    if (!sealed) {
        delta_destroy(new_parent_delta);
        return STM_ENOMEM;
    }

    /* Step 0 — PurgeSplitOnL. Remove the stale SPLIT on L's chain
     * that points back to R. Without this, readers arriving at L via
     * SEAL(forward=L) would re-redirect to R and bounce. See the
     * purge_split_on_l header for the reasoning. */
    stm_status purge_rc = purge_split_on_l(t, forward_id, r_nid);
    if (purge_rc != STM_OK) {
        delta_destroy(sealed);
        delta_destroy(new_parent_delta);
        return purge_rc;
    }

    /* Step 1 — SealR. CAS expects exactly expected_head; if a writer
     * prepended an INSERT/DELETE since consolidation, CAS fails and we
     * abort the merge. Under t->consolidating the consolidator is the
     * only structural-op thread, but writer INSERTs/DELETEs on a
     * pre-merge empty leaf can still race the SEAL CAS. */
    if (!atomic_compare_exchange_strong(&t->pt->slots[r_nid],
                                         &expected_head, sealed)) {
        delta_destroy(sealed);
        delta_destroy(new_parent_delta);
        return STM_OK;   /* merge abandoned; leaf is fine as-is.
                          * L's purge has landed and is harmless. */
    }

    /* Step 2 — UpdateParent. */
    if (!atomic_compare_exchange_strong(&t->pt->slots[parent_nid],
                                         &parent_head, new_parent_delta)) {
        /* Shouldn't happen: parent is only mutated under
         * t->consolidating (which we hold) and the rwlock variant
         * lives on a separate tree. Accept the pivot leak: SEAL on R
         * still forwards correctly, readers remain correct. */
        delta_destroy(new_parent_delta);
        retire_chain(expected_head);
        return STM_OK;
    }

    /* Step 3 — EBR-retire R's old chain and the old parent head. SEAL
     * stays at R's slot indefinitely so stale-pivot readers can still
     * forward. */
    retire_chain(expected_head);
    retire_chain(parent_head);
    return STM_OK;
}

/* Merge eligibility + dispatch helper.
 *
 * Eligibility (MVP):
 *   - R's current slot head is `expected_head` of kind BASE_LEAF with
 *     zero entries.
 *   - No SPLIT or INSERT/DELETE deltas above the BASE (caller ensures
 *     by passing a freshly-consolidated head).
 *   - R has a parent (not root itself).
 *   - R is not the leftmost child of its parent (leftmost-merge would
 *     require a different forward direction and isn't modeled by
 *     merge.tla).
 */
static stm_status try_merge(stm_btree_lf *t, uint64_t r_nid,
                              stm_bt_lf_delta *expected_head)
{
    uint64_t parent_nid = find_parent(t, r_nid);
    if (parent_nid == STM_BT_LF_NO_REDIRECT) return STM_OK;

    stm_bt_lf_delta *parent_head = atomic_load(&t->pt->slots[parent_nid]);
    if (!parent_head || parent_head->kind != STM_BT_LF_DELTA_BASE_INTERNAL)
        return STM_OK;

    int32_t idx = find_pivot_index(parent_head->u.base_internal.internal,
                                     r_nid);
    if (idx < 0) return STM_OK;    /* leftmost or unreachable — skip */

    return commit_merge(t, r_nid, parent_nid, expected_head, (uint32_t)idx);
}

/* One-shot consolidation attempt for a leaf at `nid`. Either flattens
 * the chain via CAS of a fresh [preserved SPLITs..., BASE] head, or
 * transitions into a split if the consolidated base overflows.
 * Caller must hold t->consolidating. */
static stm_status consolidate_or_split(stm_btree_lf *t, uint64_t nid,
                                         bool bypass_threshold)
{
    for (uint32_t attempt = 0; attempt < STM_BT_LF_CONSOLIDATE_RETRIES; attempt++) {
        stm_bt_lf_delta *old_head = atomic_load(&t->pt->slots[nid]);
        if (!old_head) return STM_OK;
        /* Root (internal) has no deltas; skip. */
        if (old_head->kind == STM_BT_LF_DELTA_BASE_INTERNAL) return STM_OK;
        /* Already merged — nothing to do. */
        if (old_head->kind == STM_BT_LF_DELTA_SEALED) return STM_OK;

        uint32_t depth = atomic_load_explicit(&old_head->chain_depth,
                                               memory_order_relaxed);
        if (!bypass_threshold && depth < STM_BT_LF_CONSOLIDATE_THRESHOLD)
            return STM_OK;

        /* Merge fast-path: if bypass and the chain is already a lone
         * empty BASE_LEAF (depth 0, nentries 0, no SPLITs), try to
         * reabsorb this leaf into its left neighbor. consolidate_or_split
         * would otherwise bail here without doing anything. */
        if (bypass_threshold && depth == 0) {
            if (old_head->kind == STM_BT_LF_DELTA_BASE &&
                old_head->u.base.node->nentries == 0) {
                return try_merge(t, nid, old_head);
            }
            return STM_OK;
        }

        stm_bt_lf_preserved_splits preserved = { .n = 0 };
        stm_bt_node *new_base_node = build_consolidated_leaf(old_head, t->opts,
                                                               &preserved);
        if (!new_base_node) return STM_ENOMEM;

        if (new_base_node->nentries > t->opts.target_entries) {
            /* Split path. commit_split consumes new_base_node + preserved. */
            uint64_t parent_nid = find_parent(t, nid);
            if (parent_nid == STM_BT_LF_NO_REDIRECT) {
                /* Leaf is root — shouldn't happen in the internal-
                 * routing MVP (root is always BASE_INTERNAL). */
                preserved_splits_free(&preserved);
                stm_bt_node_free(new_base_node);
                return STM_ECORRUPT;
            }
            stm_status rc = commit_split(t, nid, parent_nid, old_head,
                                           new_base_node, &preserved);
            /* Free any preserved sep_keys commit_split didn't take. */
            preserved_splits_free(&preserved);
            return rc;
        }

        /* No-split path: build new head and CAS. */
        stm_bt_lf_delta *new_head = build_leaf_chain(new_base_node, &preserved);
        if (!new_head) {
            preserved_splits_free(&preserved);
            stm_bt_node_free(new_base_node);
            return STM_ENOMEM;
        }
        /* new_head owns new_base_node and all preserved sep_keys now. */

        if (atomic_compare_exchange_strong(&t->pt->slots[nid],
                                            &old_head, new_head)) {
            retire_chain(old_head);
            /* Post-consolidation merge check: if the new base is empty
             * AND there are no preserved SPLITs above it (i.e., the
             * chain is a lone BASE_LEAF(empty)), reabsorb this leaf
             * into its left neighbor. new_head is still the current
             * slot head (writers may prepend concurrently; commit_merge
             * CAS will re-check). */
            if (new_base_node->nentries == 0 &&
                new_head->kind == STM_BT_LF_DELTA_BASE) {
                return try_merge(t, nid, new_head);
            }
            return STM_OK;
        }
        /* Prepender beat us. Free the new head (walk and destroy) and
         * retry. */
        stm_bt_lf_delta *cur = new_head;
        while (cur) {
            stm_bt_lf_delta *nx = atomic_load_explicit(&cur->next,
                                                         memory_order_relaxed);
            delta_destroy(cur);
            cur = nx;
        }
    }
    return STM_OK;
}

/* Consolidating-flag helpers. */
static bool try_acquire_consolidate(stm_btree_lf *t)
{
    bool expected = false;
    return atomic_compare_exchange_strong(&t->consolidating, &expected, true);
}

static void acquire_consolidate_blocking(stm_btree_lf *t)
{
    bool expected = false;
    while (!atomic_compare_exchange_weak(&t->consolidating, &expected, true)) {
        expected = false;
    }
}

static void release_consolidate(stm_btree_lf *t)
{
    atomic_store(&t->consolidating, false);
}

/* Contended-but-non-blocking consolidate; called by writers past the
 * threshold. */
static stm_status try_consolidate(stm_btree_lf *t, uint64_t nid)
{
    if (!try_acquire_consolidate(t)) return STM_OK;
    stm_status rc = consolidate_or_split(t, nid, false);
    release_consolidate(t);
    return rc;
}

/* Collect all leaf slot IDs reachable from root. Two-level MVP: root's
 * BASE_INTERNAL lists them directly. Heap-allocates *out (caller must
 * free); returns count. Returns 0 and leaves *out NULL if the root is
 * empty / not BASE_INTERNAL / OOM. */
static uint32_t enumerate_leaves(stm_btree_lf *t, uint64_t **out)
{
    *out = NULL;
    uint64_t root_id = atomic_load(&t->root_id);
    stm_bt_lf_delta *root_head = atomic_load(&t->pt->slots[root_id]);
    if (!root_head || root_head->kind != STM_BT_LF_DELTA_BASE_INTERNAL)
        return 0;
    stm_bt_lf_internal *internal = root_head->u.base_internal.internal;
    uint32_t count = internal->npivots + 1u;
    uint64_t *arr = malloc(count * sizeof *arr);
    if (!arr) return 0;
    arr[0] = internal->leftmost_child;
    for (uint32_t i = 0; i < internal->npivots; i++) {
        arr[i + 1] = internal->pivots[i].right_child;
    }
    *out = arr;
    return count;
}

stm_status stm_btree_lf_force_consolidate(stm_btree_lf *t, stm_ebr_thread *ebr)
{
    if (!t || !ebr) return STM_EINVAL;
    stm_ebr_enter(ebr);
    acquire_consolidate_blocking(t);

    stm_status rc = STM_OK;
    for (uint32_t iter = 0; iter < 16; iter++) {
        uint64_t *leaves = NULL;
        uint32_t n = enumerate_leaves(t, &leaves);
        bool any_work = false;

        for (uint32_t i = 0; i < n; i++) {
            stm_bt_lf_delta *head = atomic_load(&t->pt->slots[leaves[i]]);
            if (!head) continue;
            uint32_t d_before = atomic_load_explicit(&head->chain_depth,
                                                      memory_order_relaxed);
            if (d_before == 0) continue;
            stm_status s = consolidate_or_split(t, leaves[i], true);
            if (s != STM_OK) { free(leaves); rc = s; goto out; }
            /* P3-1: only mark any_work if we actually reduced depth.
             * Otherwise the outer loop thrashes on leaves whose chain
             * is all preserved SPLITs (no INSERTs/DELETEs to merge). */
            stm_bt_lf_delta *after = atomic_load(&t->pt->slots[leaves[i]]);
            uint32_t d_after = after
                ? atomic_load_explicit(&after->chain_depth,
                                        memory_order_relaxed)
                : 0u;
            if (d_after < d_before) any_work = true;
        }
        free(leaves);
        if (!any_work) break;
    }

out:
    release_consolidate(t);
    stm_ebr_exit(ebr);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Insert / delete.                                                           */
/* ------------------------------------------------------------------------- */

/* Traverse from root following BASE_INTERNAL pivots and leaf SPLIT
 * redirects. CAS-prepend `d` on the final leaf. On CAS failure,
 * retry the whole traversal.
 *
 * *out_final_nid gets the leaf nid; *out_depth gets the depth of the
 * newly-installed delta. */
static stm_status traverse_and_prepend(stm_btree_lf *t,
                                        stm_bt_lf_delta *d,
                                        const void *key, size_t key_len,
                                        uint64_t *out_final_nid,
                                        uint32_t *out_depth)
{
    for (uint32_t attempts = 0; attempts < 256; attempts++) {
        uint64_t nid = atomic_load(&t->root_id);
        /* Traverse to the target leaf. */
        uint32_t hops = 0;
        for (;;) {
            if (hops++ > 128) return STM_ECORRUPT;
            if (nid >= t->pt->capacity) return STM_ECORRUPT;

            stm_bt_lf_delta *head = atomic_load(&t->pt->slots[nid]);
            if (!head) return STM_ECORRUPT;

            if (head->kind == STM_BT_LF_DELTA_BASE_INTERNAL) {
                nid = internal_route(head->u.base_internal.internal,
                                      key, key_len);
                continue;
            }

            /* SEAL'd leaf: forward to the absorbing sibling and keep
             * walking. Writers with stale parent pivots may arrive here;
             * they continue to the forward target rather than retraverse
             * from root (retraversal is also correct but risks a retry
             * loop if parent's UpdateParent is still pending). */
            if (head->kind == STM_BT_LF_DELTA_SEALED) {
                nid = head->u.sealed.forward_id;
                continue;
            }

            /* Leaf. Determine: prepend here, or redirect via SPLIT? */
            uint64_t candidate = 0;
            bool     has_candidate = false;
            for (stm_bt_lf_delta *w = head; w; w = atomic_load(&w->next)) {
                if (w->kind == STM_BT_LF_DELTA_SPLIT) {
                    int cmp = stm_bt_key_cmp(key, key_len,
                                              w->u.split.sep_key,
                                              w->u.split.sep_key_len);
                    if (cmp >= 0) {
                        candidate     = w->u.split.sibling_id;
                        has_candidate = true;
                    } else {
                        break;          /* older SPLITs have larger seps */
                    }
                } else if (w->kind == STM_BT_LF_DELTA_BASE) {
                    break;
                }
            }
            if (has_candidate) { nid = candidate; continue; }

            /* Prepend at nid. */
            atomic_store_explicit(&d->next, head, memory_order_relaxed);
            uint32_t base_depth = head
                ? atomic_load_explicit(&head->chain_depth,
                                        memory_order_relaxed)
                : 0u;
            atomic_store_explicit(&d->chain_depth, base_depth + 1u,
                                   memory_order_relaxed);
            if (atomic_compare_exchange_weak(&t->pt->slots[nid], &head, d)) {
                *out_final_nid = nid;
                *out_depth     = base_depth + 1u;
                return STM_OK;
            }
            /* CAS failed — restart whole traversal (a SPLIT may have
             * landed here since we decided to prepend). */
            break;
        }
    }
    return STM_ECORRUPT;
}

stm_status stm_btree_lf_insert(stm_btree_lf *t, stm_ebr_thread *ebr,
                                const void *key, size_t key_len,
                                const void *value, size_t value_len)
{
    if (!t || !ebr || !key) return STM_EINVAL;

    stm_bt_lf_delta *d = alloc_insert_delta(key, key_len, value, value_len);
    if (!d) return STM_ENOMEM;

    stm_ebr_enter(ebr);

    uint64_t final_nid = 0;
    uint32_t depth_after = 0;
    stm_status rc = traverse_and_prepend(t, d, key, key_len,
                                           &final_nid, &depth_after);
    if (rc != STM_OK) {
        stm_ebr_exit(ebr);
        delta_destroy(d);
        return rc;
    }

    if (depth_after >= STM_BT_LF_CONSOLIDATE_THRESHOLD) {
        (void)try_consolidate(t, final_nid);
    }

    stm_ebr_exit(ebr);
    (void)stm_ebr_try_advance();
    return STM_OK;
}

stm_status stm_btree_lf_delete(stm_btree_lf *t, stm_ebr_thread *ebr,
                                const void *key, size_t key_len)
{
    if (!t || !ebr || !key) return STM_EINVAL;

    size_t dummy_len = 0;
    stm_status ls = stm_btree_lf_lookup(t, ebr, key, key_len,
                                         NULL, 0, &dummy_len);
    if (ls == STM_ENOENT) return STM_ENOENT;
    if (ls != STM_OK)     return ls;

    stm_bt_lf_delta *d = alloc_delete_delta(key, key_len);
    if (!d) return STM_ENOMEM;

    stm_ebr_enter(ebr);

    uint64_t final_nid = 0;
    uint32_t depth_after = 0;
    stm_status rc = traverse_and_prepend(t, d, key, key_len,
                                           &final_nid, &depth_after);
    if (rc != STM_OK) {
        stm_ebr_exit(ebr);
        delta_destroy(d);
        return rc;
    }

    if (depth_after >= STM_BT_LF_CONSOLIDATE_THRESHOLD) {
        (void)try_consolidate(t, final_nid);
    }

    stm_ebr_exit(ebr);
    (void)stm_ebr_try_advance();
    return STM_OK;
}

/* ------------------------------------------------------------------------- */
/* Observability.                                                             */
/* ------------------------------------------------------------------------- */

/* Returns the MAX chain_depth across all leaves. Root's own chain is
 * always 0 in this MVP (BASE_INTERNAL with no deltas above). */
uint32_t stm_btree_lf_chain_depth(const stm_btree_lf *t, stm_ebr_thread *ebr)
{
    if (!t || !ebr) return 0;
    stm_ebr_enter(ebr);
    uint64_t root_id = atomic_load(&t->root_id);
    stm_bt_lf_delta *root_head = atomic_load(&t->pt->slots[root_id]);

    uint32_t max_depth = 0;
    if (root_head && root_head->kind == STM_BT_LF_DELTA_BASE_INTERNAL) {
        stm_bt_lf_internal *internal = root_head->u.base_internal.internal;
        uint32_t count = internal->npivots + 1u;
        uint64_t *nids = malloc(count * sizeof *nids);
        if (nids) {
            nids[0] = internal->leftmost_child;
            for (uint32_t i = 0; i < internal->npivots; i++) {
                nids[i + 1] = internal->pivots[i].right_child;
            }
            for (uint32_t i = 0; i < count; i++) {
                stm_bt_lf_delta *h = atomic_load(&t->pt->slots[nids[i]]);
                if (!h) continue;
                uint32_t d = atomic_load_explicit(&h->chain_depth,
                                                    memory_order_relaxed);
                if (d > max_depth) max_depth = d;
            }
            free(nids);
        }
    } else if (root_head) {
        /* Legacy fallback: root directly holds a leaf chain. Only
         * possible if the tree was constructed before this MVP; keep
         * for safety. */
        max_depth = atomic_load_explicit(&root_head->chain_depth,
                                           memory_order_relaxed);
    }
    stm_ebr_exit(ebr);
    return max_depth;
}

uint32_t stm_btree_lf_leaf_count(const stm_btree_lf *t, stm_ebr_thread *ebr)
{
    if (!t || !ebr) return 0;
    stm_ebr_enter(ebr);
    uint64_t root_id = atomic_load(&t->root_id);
    stm_bt_lf_delta *root_head = atomic_load(&t->pt->slots[root_id]);
    uint32_t count = 0;
    if (root_head && root_head->kind == STM_BT_LF_DELTA_BASE_INTERNAL) {
        count = root_head->u.base_internal.internal->npivots + 1u;
    }
    stm_ebr_exit(ebr);
    return count;
}
