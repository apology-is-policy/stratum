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
    } u;
};

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
    }
    free(d);
}

static stm_bt_lf_delta *alloc_base_delta(stm_bt_node *node)
{
    stm_bt_lf_delta *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->kind = STM_BT_LF_DELTA_BASE;
    atomic_init(&d->next, NULL);
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

    uint8_t *k = stm_bt_dup_bytes(key, key_len);
    if (!k && key_len > 0) { free(d); return NULL; }
    d->u.del.key     = k;
    d->u.del.key_len = (uint32_t)key_len;
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

    /* MVP: single-slot page table. */
    t->pt = page_table_new(1);
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

/* Walk the chain newest-first, stopping at the first decisive event. */
static stm_bt_lf_delta *resolve_chain(stm_bt_lf_delta *head,
                                       const void *key, size_t key_len)
{
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
        case STM_BT_LF_DELTA_BASE:
            return d;
        }
    }
    return NULL;   /* malformed chain — no base reached */
}

stm_status stm_btree_lf_lookup(const stm_btree_lf *t, stm_ebr_thread *ebr,
                                const void *key, size_t key_len,
                                void *buf, size_t buf_cap,
                                size_t *out_value_len)
{
    if (!t || !ebr || !key) return STM_EINVAL;

    stm_ebr_enter(ebr);

    uint64_t nid = atomic_load(&t->root_id);
    stm_bt_lf_delta *head = atomic_load(&t->pt->slots[nid]);
    stm_bt_lf_delta *hit  = resolve_chain(head, key, key_len);

    stm_status result;
    if (!hit) {
        result = STM_ECORRUPT;
        goto out;
    }

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
        uint32_t idx = stm_bt_entry_lower_bound(node->entries, node->nentries,
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

/* Build a fresh base by cloning the BASE node in `head`'s chain and
 * applying the chain's deltas in OLDEST-FIRST order. Returns NULL on OOM
 * or on malformed / over-deep chain. */
static stm_bt_node *build_consolidated_base(stm_bt_lf_delta *head,
                                              stm_btree_opts opts)
{
    stm_bt_lf_delta *stack[STM_BT_LF_MAX_CHAIN];
    size_t sp = 0;
    stm_bt_lf_delta *base_delta = NULL;

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
            if (s != STM_OK) { stm_bt_node_free(new_leaf); return NULL; }
            break;
        }
        case STM_BT_LF_DELTA_DELETE:
            apply_delete_to_leaf(new_leaf, d);
            break;
        case STM_BT_LF_DELTA_BASE:
            /* Should never occur mid-chain. */
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

/* Attempt consolidation of node `nid`. Called inside the caller's EBR
 * epoch, so any chain we walk is alive for our whole visit. Serialized
 * through t->consolidating — the first writer past the threshold takes
 * the flag, later writers bail immediately and leave the work to the
 * winner. */
static stm_status try_consolidate(stm_btree_lf *t, uint64_t nid)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&t->consolidating, &expected, true)) {
        return STM_OK;   /* another thread is consolidating */
    }

    stm_status rc = STM_OK;
    for (uint32_t attempt = 0; attempt < STM_BT_LF_CONSOLIDATE_RETRIES; attempt++) {
        stm_bt_lf_delta *old_head = atomic_load(&t->pt->slots[nid]);
        if (!old_head) break;
        if (atomic_load_explicit(&old_head->chain_depth, memory_order_relaxed)
            < STM_BT_LF_CONSOLIDATE_THRESHOLD) break;   /* nothing to do */

        stm_bt_node *new_base_node = build_consolidated_base(old_head, t->opts);
        if (!new_base_node) { rc = STM_ENOMEM; break; }

        stm_bt_lf_delta *new_head = alloc_base_delta(new_base_node);
        if (!new_head) {
            stm_bt_node_free(new_base_node);
            rc = STM_ENOMEM;
            break;
        }
        atomic_store_explicit(&new_head->chain_depth, 0u,
                              memory_order_relaxed);

        if (atomic_compare_exchange_strong(&t->pt->slots[nid],
                                            &old_head, new_head)) {
            retire_old_chain(old_head);
            break;                          /* success */
        }
        /* A prepender beat us. Discard and retry with fresh head. */
        delta_destroy(new_head);
    }

    atomic_store(&t->consolidating, false);
    return rc;
}

stm_status stm_btree_lf_force_consolidate(stm_btree_lf *t, stm_ebr_thread *ebr)
{
    if (!t || !ebr) return STM_EINVAL;
    stm_ebr_enter(ebr);
    /* Bypass the chain-depth check: always try. */
    uint64_t nid = atomic_load(&t->root_id);
    stm_bt_lf_delta *old_head = atomic_load(&t->pt->slots[nid]);
    stm_status s = STM_OK;

    if (old_head &&
        atomic_load_explicit(&old_head->chain_depth, memory_order_relaxed) > 0) {
        stm_bt_node *new_base_node = build_consolidated_base(old_head, t->opts);
        if (!new_base_node) { s = STM_ENOMEM; goto out; }

        stm_bt_lf_delta *new_head = alloc_base_delta(new_base_node);
        if (!new_head) {
            stm_bt_node_free(new_base_node);
            s = STM_ENOMEM;
            goto out;
        }
        atomic_store_explicit(&new_head->chain_depth, 0u, memory_order_relaxed);

        if (atomic_compare_exchange_strong(&t->pt->slots[nid], &old_head, new_head)) {
            retire_old_chain(old_head);
        } else {
            delta_destroy(new_head);
        }
    }

out:
    stm_ebr_exit(ebr);
    return s;
}

/* ------------------------------------------------------------------------- */
/* Insert / delete.                                                           */
/* ------------------------------------------------------------------------- */

/* CAS-prepend `d` onto the chain at slot `nid`, setting d->next and
 * d->chain_depth in the process. Assumes the caller is inside EBR. */
static void cas_prepend(stm_btree_lf *t, uint64_t nid, stm_bt_lf_delta *d)
{
    stm_bt_lf_delta *head;
    do {
        head = atomic_load(&t->pt->slots[nid]);
        atomic_store_explicit(&d->next, head, memory_order_relaxed);
        uint32_t base_depth = head
            ? atomic_load_explicit(&head->chain_depth, memory_order_relaxed)
            : 0u;
        atomic_store_explicit(&d->chain_depth, base_depth + 1u,
                              memory_order_relaxed);
    } while (!atomic_compare_exchange_weak(&t->pt->slots[nid], &head, d));
}

stm_status stm_btree_lf_insert(stm_btree_lf *t, stm_ebr_thread *ebr,
                                const void *key, size_t key_len,
                                const void *value, size_t value_len)
{
    if (!t || !ebr || !key) return STM_EINVAL;

    stm_bt_lf_delta *d = alloc_insert_delta(key, key_len, value, value_len);
    if (!d) return STM_ENOMEM;

    stm_ebr_enter(ebr);

    uint64_t nid = atomic_load(&t->root_id);
    cas_prepend(t, nid, d);
    uint32_t depth_after = atomic_load_explicit(&d->chain_depth,
                                                 memory_order_relaxed);

    if (depth_after >= STM_BT_LF_CONSOLIDATE_THRESHOLD) {
        (void)try_consolidate(t, nid);
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

    uint64_t nid = atomic_load(&t->root_id);
    cas_prepend(t, nid, d);
    uint32_t depth_after = atomic_load_explicit(&d->chain_depth,
                                                 memory_order_relaxed);

    if (depth_after >= STM_BT_LF_CONSOLIDATE_THRESHOLD) {
        (void)try_consolidate(t, nid);
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
