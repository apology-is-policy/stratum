/* SPDX-License-Identifier: ISC */
/*
 * Lock-free Bw-tree — Phase 2, task #171.
 *
 * See ARCHITECTURE §3.4 and v2/docs/phase2-bw-tree-design.md for the full
 * model. This TU implements the MVP: a single logical node addressed
 * through a page-table slot, with a CAS-prepended delta chain and a
 * helping-pattern consolidation.
 *
 * Data structure
 * --------------
 *
 * A physical node in the tree is one of:
 *   - BASE   — owns a consolidated stm_bt_node (reused from the single-
 *              threaded core). Forms the tail of every delta chain.
 *   - INSERT — one pending upsert (key, value).
 *   - DELETE — one pending tombstone for a key.
 *
 * The page table maps a node_id to the CURRENT HEAD of that node's delta
 * chain, via an atomic slot:
 *
 *     slots[id] -> delta_n -> delta_{n-1} -> ... -> delta_1 -> BASE
 *                  (newest at head; LIFO)
 *
 * Reads
 *   Readers load the slot, walk the chain newest-first, return at the
 *   first INSERT or DELETE for the target key, or fall through to the
 *   BASE and do an ordinary sorted-array lookup. The walk is pinned by
 *   EBR so no node the reader dereferences can be reclaimed.
 *
 * Writes
 *   Writers allocate a new delta, set its `next` to the current head,
 *   and CAS the slot from old head to the new delta. On contention, the
 *   CAS retries with a fresh head.
 *
 * Consolidation
 *   When a writer's prepend leaves `chain_depth >= CONSOLIDATE_THRESHOLD`,
 *   it attempts a consolidation: walk the chain, apply the accumulated
 *   INSERT/DELETE ops to a copy of the base node to produce a new base,
 *   wrap it as a BASE delta, CAS the slot from old head to new head. The
 *   winner retires the entire old chain via EBR; losers abandon their
 *   attempt and free the wasted allocations.
 *
 * Memory reclamation
 *   Each retired delta record goes through stm_ebr_retire with a
 *   destructor (delta_destroy) that frees key/value buffers and, for
 *   BASE deltas, the owned stm_bt_node. EBR ensures no reader holding an
 *   older epoch is still looking at the record when its destructor fires.
 *
 * Current scope (MVP for #171)
 * ----------------------------
 *   - Single node. No SPLIT / MERGE deltas, no internal routing.
 *   - Tree capacity bounded by leaf target_entries.
 *
 * Next chunk (task #172)
 * ----------------------
 *   - SPLIT / MERGE delta kinds, page-table resize, internal-node
 *     routing with lazy parent updates.
 */

#include <stratum/btree.h>
#include <stratum/ebr.h>

#include "node.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define STM_BT_LF_CONSOLIDATE_THRESHOLD 4u

/* The consolidator retries a bounded number of times when its CAS loses
 * to a concurrent prepender. Beyond this, we yield to the next
 * threshold-hitter. Each retry re-reads the chain head, so we always
 * consolidate the latest state we can see. */
#define STM_BT_LF_CONSOLIDATE_RETRIES 8u

/* Sanity cap on how deep the chain can grow before we refuse to
 * consolidate (heap blow-up guard). Under normal operation chain depth
 * stays within a small multiple of the threshold under contention. */
#define STM_BT_LF_MAX_CHAIN 4096u

typedef enum {
    STM_BT_LF_DELTA_INSERT = 1,
    STM_BT_LF_DELTA_DELETE = 2,
    STM_BT_LF_DELTA_BASE   = 3,
    STM_BT_LF_DELTA_SPLIT  = 4,
} stm_bt_lf_delta_kind;

typedef struct stm_bt_lf_delta stm_bt_lf_delta;
struct stm_bt_lf_delta {
    stm_bt_lf_delta_kind kind;
    _Atomic uint32_t chain_depth;          /* 0 for BASE, N for the Nth delta above */
    _Atomic(stm_bt_lf_delta *) next;
    union {
        struct { uint8_t *key; uint32_t key_len;
                 uint8_t *val; uint32_t val_len; } upsert;
        struct { uint8_t *key; uint32_t key_len; } del;
        struct { stm_bt_node *node; }      base;
        /* SPLIT delta: keys >= sep_key should redirect to sibling_id.
         * sep_key is owned by this record; freed in delta_destroy. */
        struct { uint8_t *sep_key; uint32_t sep_key_len;
                 uint64_t sibling_id; } split;
    } u;
};

/* Page table entries are zero-initialized, so slot IDs start from 0.
 * We reserve 0 as the root ID (allocated first in stm_btree_lf_new)
 * and use UINT64_MAX as an "no-redirect" sentinel internally. */
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
    /* Single-consolidator gate. Under N-way writer contention the
     * thundering-herd of "every writer past threshold tries to
     * consolidate" produces mostly-failed CAS attempts and an unbounded
     * chain. We serialize consolidations through this flag: the first
     * writer past the threshold wins and does the work; others bail out
     * to the insert path and let the winner handle it. */
    _Atomic bool       consolidating;
};

/* ------------------------------------------------------------------------- */
/* Delta allocation + destruction.                                            */
/* ------------------------------------------------------------------------- */

/* Destructor for EBR and for direct (shutdown-path) free. Handles every
 * kind uniformly; BASE deltas own their stm_bt_node. */
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

/* Build a SPLIT delta. Takes ownership of the passed-in sep_key buffer
 * (caller transfers; sep_key must be heap-allocated from stm_bt_dup_bytes
 * or similar). On failure, the caller still owns sep_key. */
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

/* Walk every slot, directly free the current chain. Caller must ensure
 * no other thread is touching this page table. */
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

    /* Fixed-capacity page table. 65536 slots gives enough headroom for
     * a deep right-chain of splits plus defensive margin for IDs burned
     * when a commit_split CAS loses its race to a concurrent prepender
     * (see audit R2-1). A runtime grow-with-CoW and/or freed-id pool
     * are follow-up work. */
    t->pt = page_table_new(65536);
    if (!t->pt) { free(t); return STM_ENOMEM; }

    stm_bt_node *leaf = stm_bt_node_new_leaf(t->opts.target_entries,
                                              t->opts.target_messages);
    if (!leaf) {
        page_table_free(t->pt); free(t);
        return STM_ENOMEM;
    }

    stm_bt_lf_delta *base = alloc_base_delta(leaf);
    if (!base) {
        stm_bt_node_free(leaf);
        page_table_free(t->pt); free(t);
        return STM_ENOMEM;
    }

    uint64_t rid = page_table_allocate_id(t->pt);   /* == 0 */
    atomic_store(&t->pt->slots[rid], base);
    atomic_store(&t->root_id, rid);

    *out = t;
    return STM_OK;
}

void stm_btree_lf_free(stm_btree_lf *t)
{
    if (!t) return;
    /* Caller promises no thread is still inside a lookup / insert / delete
     * on this tree. Retired deltas (if any) remain in EBR; they will be
     * reclaimed by a later try_advance or by stm_ebr_shutdown. */
    page_table_free(t->pt);
    free(t);
}

/* ------------------------------------------------------------------------- */
/* Lookup.                                                                    */
/* ------------------------------------------------------------------------- */

/* Chain walk for lookup:
 *
 *   - INSERT/DELETE delta matching the key: returns that delta (hit).
 *   - SPLIT delta with key >= sep: sets *redirect_nid, returns NULL.
 *   - BASE delta: returns that delta (hit, caller searches its leaf).
 *   - no base reached: returns NULL and leaves *redirect_nid at
 *     STM_BT_LF_NO_REDIRECT (malformed chain; caller should return
 *     STM_ECORRUPT).
 */
static stm_bt_lf_delta *resolve_chain(stm_bt_lf_delta *head,
                                       const void *key, size_t key_len,
                                       uint64_t *redirect_nid)
{
    *redirect_nid = STM_BT_LF_NO_REDIRECT;
    for (stm_bt_lf_delta *d = head; d; d = atomic_load(&d->next)) {
        switch (d->kind) {
        case STM_BT_LF_DELTA_INSERT:
            if (stm_bt_key_cmp(d->u.upsert.key, d->u.upsert.key_len,
                               key, key_len) == 0) return d;
            break;
        case STM_BT_LF_DELTA_DELETE:
            if (stm_bt_key_cmp(d->u.del.key, d->u.del.key_len,
                               key, key_len) == 0) return d;
            break;
        case STM_BT_LF_DELTA_SPLIT:
            if (stm_bt_key_cmp(key, key_len,
                               d->u.split.sep_key,
                               d->u.split.sep_key_len) >= 0) {
                *redirect_nid = d->u.split.sibling_id;
                return NULL;
            }
            break;
        case STM_BT_LF_DELTA_BASE:
            return d;
        }
    }
    return NULL;
}

stm_status stm_btree_lf_lookup(const stm_btree_lf *t, stm_ebr_thread *ebr,
                                const void *key, size_t key_len,
                                void *buf, size_t buf_cap,
                                size_t *out_value_len)
{
    if (!t || !ebr || !key) return STM_EINVAL;

    stm_ebr_enter(ebr);

    uint64_t nid = atomic_load(&t->root_id);
    stm_status result;
    for (;;) {
        if (nid >= t->pt->capacity) { result = STM_ECORRUPT; goto out; }
        stm_bt_lf_delta *head = atomic_load(&t->pt->slots[nid]);
        uint64_t redirect = STM_BT_LF_NO_REDIRECT;
        stm_bt_lf_delta *hit = resolve_chain(head, key, key_len, &redirect);
        if (redirect != STM_BT_LF_NO_REDIRECT) {
            nid = redirect;
            continue;               /* follow SPLIT */
        }
        if (!hit) { result = STM_ECORRUPT; goto out; }

        switch (hit->kind) {
        case STM_BT_LF_DELTA_INSERT: {
            uint32_t vl = hit->u.upsert.val_len;
            if (out_value_len) *out_value_len = vl;
            if (buf == NULL || buf_cap == 0) { result = STM_OK; break; }
            if (vl > buf_cap) { result = STM_ERANGE; break; }
            memcpy(buf, hit->u.upsert.val, vl);
            result = STM_OK;
            break;
        }
        case STM_BT_LF_DELTA_DELETE:
            result = STM_ENOENT;
            break;
        case STM_BT_LF_DELTA_BASE: {
            stm_bt_node *node = hit->u.base.node;
            bool found;
            uint32_t idx = stm_bt_entry_lower_bound(node->entries,
                                                     node->nentries,
                                                     key, key_len, &found);
            if (!found) { result = STM_ENOENT; break; }
            const stm_bt_entry *e = &node->entries[idx];
            if (out_value_len) *out_value_len = e->value_len;
            if (buf == NULL || buf_cap == 0) { result = STM_OK; break; }
            if (e->value_len > buf_cap) { result = STM_ERANGE; break; }
            memcpy(buf, e->value, e->value_len);
            result = STM_OK;
            break;
        }
        default:
            result = STM_ECORRUPT;
            break;
        }
        break;                       /* decision made */
    }

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
        /* Undo shift. */
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

/* Apply one DELETE delta to the working leaf. No-op if key absent. */
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

/* Extracted SPLIT info, preserved across consolidation so the post-
 * consolidated chain still redirects upper-range keys to the sibling.
 * `present` is TRUE iff `out_split` below was populated by the walk.
 * `sep_key` is a heap copy the caller OWNS (freed by caller if unused,
 * transferred into a freshly allocated SPLIT delta otherwise). */
typedef struct {
    bool     present;
    uint8_t *sep_key;
    uint32_t sep_key_len;
    uint64_t sibling_id;
} stm_bt_lf_preserved_split;

/* Build a fresh base by cloning the BASE node in `head`'s chain and
 * applying the chain's INSERT/DELETE deltas in OLDEST-FIRST order.
 * SPLIT deltas encountered on the chain are extracted into
 * `*out_split` (most-recent-wins, matching replay semantics); callers
 * must preserve them in the new chain or free the sep_key copy.
 * Returns NULL on OOM or malformed chain. */
static stm_bt_node *build_consolidated_base(stm_bt_lf_delta *head,
                                              stm_btree_opts opts,
                                              stm_bt_lf_preserved_split *out_split)
{
    stm_bt_lf_delta *stack[STM_BT_LF_MAX_CHAIN];
    size_t sp = 0;
    stm_bt_lf_delta *base_delta = NULL;

    out_split->present     = false;
    out_split->sep_key     = NULL;
    out_split->sep_key_len = 0;
    out_split->sibling_id  = 0;

    for (stm_bt_lf_delta *d = head; d; d = atomic_load(&d->next)) {
        if (d->kind == STM_BT_LF_DELTA_BASE) { base_delta = d; break; }
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

    /* Replay deltas oldest-first (stack was filled newest-first). */
    while (sp > 0) {
        stm_bt_lf_delta *d = stack[--sp];
        switch (d->kind) {
        case STM_BT_LF_DELTA_INSERT: {
            stm_status s = apply_insert_to_leaf(new_leaf, d);
            if (s != STM_OK) {
                free(out_split->sep_key);
                out_split->present = false;
                stm_bt_node_free(new_leaf);
                return NULL;
            }
            break;
        }
        case STM_BT_LF_DELTA_DELETE:
            apply_delete_to_leaf(new_leaf, d);
            break;
        case STM_BT_LF_DELTA_SPLIT: {
            /* Preserve the most recent SPLIT (replay is oldest-first
             * so each successive SPLIT overwrites the previous). */
            uint8_t *nk = stm_bt_dup_bytes(d->u.split.sep_key,
                                             d->u.split.sep_key_len);
            if (!nk && d->u.split.sep_key_len > 0) {
                stm_bt_node_free(new_leaf);
                return NULL;
            }
            free(out_split->sep_key);
            out_split->present     = true;
            out_split->sep_key     = nk;
            out_split->sep_key_len = d->u.split.sep_key_len;
            out_split->sibling_id  = d->u.split.sibling_id;
            break;
        }
        case STM_BT_LF_DELTA_BASE:
            /* Should never occur mid-chain. */
            free(out_split->sep_key);
            out_split->present = false;
            stm_bt_node_free(new_leaf);
            return NULL;
        }
    }

    return new_leaf;
}

/* Retire each delta in the chain [old_head, ..., BASE] through EBR. */
static void retire_old_chain(stm_bt_lf_delta *old_head)
{
    stm_bt_lf_delta *d = old_head;
    while (d) {
        stm_bt_lf_delta *next = atomic_load(&d->next);
        stm_status s = stm_ebr_retire(d, delta_destroy);
        if (s != STM_OK) {
            /* Fallback: if EBR retire fails we would leak. Best effort:
             * free immediately, knowing no concurrent reader should still
             * be looking at this exact record (the consolidate CAS has
             * already unpublished it). This is not strictly safe — a
             * reader who loaded the old slot before our CAS might still
             * be dereferencing. To play safe we must accept the leak. */
            /* leak d */
        }
        d = next;
    }
}

/* Split `full_base` in place into a lower and upper half. Allocates a
 * fresh sibling node_id, installs upper's chain at that slot, and CAS-
 * swaps the splitting slot's chain from `old_head` to a new chain of
 * [SPLIT delta, BASE(lower)]. On success, retires the old chain.
 *
 * Ownership on entry: `full_base` is owned by this function; it will
 * be consumed regardless of outcome. `old_head` is the expected current
 * chain head; if another thread CASed the slot between the caller's
 * sampling and this call, the CAS here will fail and we roll back.
 *
 * `inherited` (optional): when the old chain already carried a SPLIT
 * delta (meaning the node had previously split and its chain redirects
 * keys >= inherited.sep_key to inherited.sibling_id), the NEW sibling
 * we're creating must also redirect those keys — otherwise a reader
 * who lands on the new sibling would lookup keys outside its range in
 * its local base. To preserve linearizability the new sibling's chain
 * becomes [SPLIT(inherited), BASE(upper)] instead of just [BASE(upper)],
 * and we take ownership of inherited->sep_key iff we succeed in
 * building the split_delta. If `inherited` is NULL or has
 * present == FALSE, the new sibling gets a plain [BASE(upper)] chain
 * (the first-split case covered by structural.tla).
 *
 * On CAS failure (race), we uninstall the upper slot and release all
 * new allocations. The old chain stays untouched.
 *
 * Matches structural.tla's two-step protocol: InstallSibling (step 1)
 * is the atomic_store on the fresh upper slot; PostSplit (step 2) is
 * the CAS that publishes the new (SPLIT | BASE(lower)) chain. Chain
 * inheritance generalizes the spec inductively — each level is itself
 * a well-formed two-step split, with the inherited SPLIT flowing into
 * the new sibling rather than staying on the splitting node. */
static stm_status commit_split(stm_btree_lf *t, uint64_t nid,
                                 stm_bt_lf_delta *old_head,
                                 stm_bt_node *full_base,
                                 stm_bt_lf_preserved_split *inherited)
{
    stm_bt_node     *upper            = NULL;
    uint8_t         *sep_key          = NULL;
    uint32_t         sep_len          = 0;
    uint64_t         upper_id         = 0;
    bool             upper_installed  = false;
    stm_bt_lf_delta *upper_base       = NULL;
    stm_bt_lf_delta *inherited_delta  = NULL;
    stm_bt_lf_delta *upper_head       = NULL;
    stm_bt_lf_delta *lower_base       = NULL;
    stm_bt_lf_delta *split_delta      = NULL;
    stm_status       rc               = STM_OK;

    if (full_base->nentries < 2) { rc = STM_EINVAL; goto cleanup; }

    uint32_t mid = full_base->nentries / 2;

    upper = stm_bt_node_new_leaf(t->opts.target_entries,
                                  t->opts.target_messages);
    if (!upper) { rc = STM_ENOMEM; goto cleanup; }

    uint32_t upper_count = full_base->nentries - mid;
    rc = stm_bt_node_grow_entries(upper, upper_count);
    if (rc != STM_OK) goto cleanup;

    /* Transfer ownership of entries[mid..] from full_base into upper —
     * the byte copies already exist, we just re-home the pointers. */
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

    upper_head = upper_base;
    if (inherited && inherited->present) {
        /* Chain inheritance: upper's chain must keep the redirect to
         * the existing sibling so keys >= inherited.sep_key still
         * resolve correctly from the new sibling. */
        inherited_delta = alloc_split_delta(inherited->sep_key,
                                              inherited->sep_key_len,
                                              inherited->sibling_id);
        if (!inherited_delta) { rc = STM_ENOMEM; goto cleanup; }
        inherited->sep_key = NULL;               /* owned by inherited_delta */
        atomic_store_explicit(&inherited_delta->next, upper_base,
                              memory_order_relaxed);
        atomic_store_explicit(&inherited_delta->chain_depth, 1u,
                              memory_order_relaxed);
        upper_head = inherited_delta;
    }

    /* Step 1 — InstallSibling. The slot was zero-initialized and has
     * never been published; a relaxed store is sufficient. */
    atomic_store(&t->pt->slots[upper_id], upper_head);
    upper_installed = true;

    lower_base = alloc_base_delta(full_base);
    if (!lower_base) { rc = STM_ENOMEM; goto cleanup; }
    full_base = NULL;                           /* owned by lower_base */

    split_delta = alloc_split_delta(sep_key, sep_len, upper_id);
    if (!split_delta) { rc = STM_ENOMEM; goto cleanup; }
    sep_key = NULL;                             /* owned by split_delta */
    atomic_store_explicit(&split_delta->next, lower_base,
                          memory_order_relaxed);
    atomic_store_explicit(&split_delta->chain_depth, 1u,
                          memory_order_relaxed);

    /* Step 2 — PostSplit. Publish the new chain atomically. */
    if (!atomic_compare_exchange_strong(&t->pt->slots[nid],
                                         &old_head, split_delta)) {
        /* Lost the race. Cleanup below. */
        goto cleanup;
    }

    retire_old_chain(old_head);
    return STM_OK;

cleanup:
    if (upper_installed) {
        atomic_store(&t->pt->slots[upper_id], NULL);
    }
    if (split_delta)     delta_destroy(split_delta);
    else if (sep_key)    free(sep_key);
    if (lower_base)      delta_destroy(lower_base);
    else if (full_base)  stm_bt_node_free(full_base);
    if (inherited_delta) delta_destroy(inherited_delta);
    if (upper_base)      delta_destroy(upper_base);
    else if (upper)      stm_bt_node_free(upper);
    if (inherited && inherited->sep_key) {
        /* inherited ownership wasn't transferred to inherited_delta. */
        free(inherited->sep_key);
        inherited->sep_key = NULL;
    }
    return rc;
}

/* One-shot consolidation attempt for slot `nid`. Either consolidates
 * the chain in-place (preserving any SPLIT delta above a fresh base)
 * or, when the consolidated leaf overflows AND no SPLIT is already
 * present, transitions into a split via commit_split. The caller must
 * hold t->consolidating and be inside EBR. When called by
 * try_consolidate, `bypass_threshold` is FALSE so the function no-ops
 * on sub-threshold chains; force_consolidate passes TRUE to attempt
 * the collapse regardless. */
static stm_status consolidate_or_split(stm_btree_lf *t, uint64_t nid,
                                         bool bypass_threshold)
{
    for (uint32_t attempt = 0; attempt < STM_BT_LF_CONSOLIDATE_RETRIES; attempt++) {
        stm_bt_lf_delta *old_head = atomic_load(&t->pt->slots[nid]);
        if (!old_head) return STM_OK;
        uint32_t depth = atomic_load_explicit(&old_head->chain_depth,
                                               memory_order_relaxed);
        if (!bypass_threshold && depth < STM_BT_LF_CONSOLIDATE_THRESHOLD)
            return STM_OK;
        if (bypass_threshold && depth == 0) return STM_OK;

        stm_bt_lf_preserved_split preserved;
        stm_bt_node *new_base_node = build_consolidated_base(old_head, t->opts,
                                                               &preserved);
        if (!new_base_node) return STM_ENOMEM;

        /* Split decision: the consolidated leaf overflows. Chain
         * inheritance — if the old chain already carried a SPLIT, the
         * new sibling we're creating must also carry that SPLIT (via
         * commit_split's `inherited` argument) so its upper-range keys
         * still route correctly. commit_split takes ownership of the
         * inherited sep_key buffer on success; on cleanup it returns
         * ownership through preserved.sep_key. */
        if (new_base_node->nentries > t->opts.target_entries) {
            stm_bt_lf_preserved_split *inherit_arg =
                preserved.present ? &preserved : NULL;
            stm_status split_rc = commit_split(t, nid, old_head,
                                                 new_base_node, inherit_arg);
            /* If commit_split's cleanup returned the sep_key to us,
             * free it — we won't reuse it. */
            if (preserved.sep_key) { free(preserved.sep_key); preserved.sep_key = NULL; }
            return split_rc;
        }

        stm_bt_lf_delta *new_base_delta = alloc_base_delta(new_base_node);
        if (!new_base_delta) {
            stm_bt_node_free(new_base_node);
            free(preserved.sep_key);
            return STM_ENOMEM;
        }

        stm_bt_lf_delta *new_head = new_base_delta;
        if (preserved.present) {
            stm_bt_lf_delta *split_clone = alloc_split_delta(preserved.sep_key,
                                                               preserved.sep_key_len,
                                                               preserved.sibling_id);
            if (!split_clone) {
                delta_destroy(new_base_delta);
                free(preserved.sep_key);
                return STM_ENOMEM;
            }
            preserved.sep_key = NULL;       /* owned by split_clone */
            atomic_store_explicit(&split_clone->next, new_base_delta,
                                  memory_order_relaxed);
            atomic_store_explicit(&split_clone->chain_depth, 1u,
                                  memory_order_relaxed);
            new_head = split_clone;
        }

        if (atomic_compare_exchange_strong(&t->pt->slots[nid],
                                            &old_head, new_head)) {
            retire_old_chain(old_head);
            return STM_OK;
        }
        /* A prepender beat us. Discard and retry with fresh head. */
        if (new_head != new_base_delta) delta_destroy(new_head);
        delta_destroy(new_base_delta);
    }
    return STM_OK;   /* retries exhausted; give way to the next caller */
}

/* Acquire the consolidating flag. try_consolidate bails if contended
 * (lets the winner handle the work); force_consolidate spin-waits
 * (it's test-only, so blocking is acceptable). */
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

/* Attempt consolidation of node `nid`. Called inside the caller's EBR
 * epoch, so any chain we walk is alive for our whole visit. Serialized
 * through t->consolidating — the first writer past the threshold takes
 * the flag, later writers bail immediately and leave the work to the
 * winner. If consolidation's result overflows target_entries AND this
 * node doesn't already carry a SPLIT delta, the consolidator transitions
 * into a split (commit_split). */
static stm_status try_consolidate(stm_btree_lf *t, uint64_t nid)
{
    if (!try_acquire_consolidate(t)) return STM_OK;
    stm_status rc = consolidate_or_split(t, nid, false);
    release_consolidate(t);
    return rc;
}

stm_status stm_btree_lf_force_consolidate(stm_btree_lf *t, stm_ebr_thread *ebr)
{
    if (!t || !ebr) return STM_EINVAL;
    stm_ebr_enter(ebr);
    /* Block until exclusive — force_consolidate is a test-only oracle
     * and concurrent try_consolidate would race on commit_split's CAS,
     * burning page-table IDs (see audit R2-3). Serializing through the
     * same flag is the safe fix. */
    acquire_consolidate_blocking(t);
    uint64_t nid = atomic_load(&t->root_id);
    stm_status rc = consolidate_or_split(t, nid, true);
    release_consolidate(t);
    stm_ebr_exit(ebr);
    return rc;
}

/* ------------------------------------------------------------------------- */
/* Insert / delete.                                                           */
/* ------------------------------------------------------------------------- */

/* Traverse the tree from root, following any SPLIT redirects that
 * apply to `key`, and CAS-prepend `d` at the target leaf. Assumes the
 * caller is inside EBR. On CAS failure we reload and re-walk — this
 * handles both the common insert-vs-insert race AND the rarer race
 * where a SPLIT landed on our target slot between our walk and CAS.
 * *out_final_nid gets the nid where the prepend landed; *out_depth
 * gets the chain_depth of the newly published delta. */
static void traverse_and_prepend(stm_btree_lf *t,
                                   stm_bt_lf_delta *d,
                                   const void *key, size_t key_len,
                                   uint64_t *out_final_nid,
                                   uint32_t *out_depth)
{
    uint64_t nid = atomic_load(&t->root_id);
    for (;;) {
        stm_bt_lf_delta *head = atomic_load(&t->pt->slots[nid]);
        /* Walk the chain and decide: follow a SPLIT, or prepend here. */
        uint64_t redirect = STM_BT_LF_NO_REDIRECT;
        for (stm_bt_lf_delta *w = head; w; w = atomic_load(&w->next)) {
            if (w->kind == STM_BT_LF_DELTA_SPLIT) {
                if (stm_bt_key_cmp(key, key_len,
                                   w->u.split.sep_key,
                                   w->u.split.sep_key_len) >= 0) {
                    redirect = w->u.split.sibling_id;
                    break;
                }
            } else if (w->kind == STM_BT_LF_DELTA_BASE) {
                break;
            }
            /* INSERT/DELETE deltas don't change the routing decision. */
        }
        if (redirect != STM_BT_LF_NO_REDIRECT) {
            nid = redirect;
            continue;
        }

        /* Prepend at `nid`. */
        atomic_store_explicit(&d->next, head, memory_order_relaxed);
        uint32_t base_depth = head
            ? atomic_load_explicit(&head->chain_depth, memory_order_relaxed)
            : 0u;
        atomic_store_explicit(&d->chain_depth, base_depth + 1u,
                              memory_order_relaxed);
        if (atomic_compare_exchange_weak(&t->pt->slots[nid], &head, d)) {
            *out_final_nid = nid;
            *out_depth     = base_depth + 1u;
            return;
        }
        /* CAS failed. Re-walk at this nid — if a SPLIT now applies to
         * our key the next iteration follows it. */
    }
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
    traverse_and_prepend(t, d, key, key_len, &final_nid, &depth_after);

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

    /* Report ENOENT if the key isn't currently present. This is a
     * best-effort check: a concurrent insert between the lookup and the
     * prepend would cause a false ENOENT, but the caller may retry. A
     * DELETE delta on an absent key is idempotent during consolidation. */
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
    traverse_and_prepend(t, d, key, key_len, &final_nid, &depth_after);

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

/* Must pin an EBR epoch to safely dereference the head — a concurrent
 * consolidator may have retired the head pointer. Caller provides the
 * per-thread handle. */
uint32_t stm_btree_lf_chain_depth(const stm_btree_lf *t, stm_ebr_thread *ebr)
{
    if (!t || !ebr) return 0;
    stm_ebr_enter(ebr);
    uint64_t nid = atomic_load(&t->root_id);
    stm_bt_lf_delta *head = atomic_load(&t->pt->slots[nid]);
    uint32_t depth = head
        ? atomic_load_explicit(&head->chain_depth, memory_order_relaxed)
        : 0u;
    stm_ebr_exit(ebr);
    return depth;
}
