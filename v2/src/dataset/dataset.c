/* SPDX-License-Identifier: ISC */
/*
 * Pool-wide dataset hierarchy + index.
 *
 *   see include/stratum/dataset.h — public API + invariants.
 *   see v2/specs/dataset.tla — formal model.
 *
 * In-RAM linear-array implementation: each dataset gets a slot in a
 * dynamic array. Slots are append-only — Destroy marks ABSENT, the slot
 * stays. Lookup is O(n); fine for the MVP scale (a typical pool has
 * < 1000 datasets). Persistent storage is a follow-on chunk.
 *
 * Threading: pthread_mutex_t guards the array + counters. Every public
 * API takes the lock for the duration of the call. The cycle-prevention
 * walk in Move and the sibling-uniqueness scan in Create/Rename/Move are
 * all O(n) under the lock.
 */
#include <stratum/dataset.h>

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/btree.h>
#include <stratum/btree_store.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdatomic.h>      /* P7-CAS-14 prop_mutation_gen */
#include <stdlib.h>
#include <string.h>

/*
 * R29 self-audit P1 (carries back to R28 / dataset module): ERRORCHECK
 * pthread mutex returns EDEADLK on reentry-from-same-thread, but if
 * the caller doesn't check the return code the inner lock call
 * proceeds unsafely AND the inner unlock releases the OUTER's lock
 * claim — exposing state to concurrent writers. We use ERRORCHECK to
 * surface contract violations (e.g., iter callback re-entering a
 * public API) as a hard abort rather than a silent race.
 */
static inline void must_lock(pthread_mutex_t *m) {
    int rc = pthread_mutex_lock(m);
    if (rc != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    int rc = pthread_mutex_unlock(m);
    if (rc != 0) abort();
}

/*
 * Per-slot record. The public stm_dataset_entry plus a "present" flag
 * (PRESENT vs ABSENT/destroyed) plus per-property local state.
 *
 * local_set[p] is TRUE iff the dataset has a locally-set value for
 * property p; local_value[p] is that value (only meaningful when
 * local_set[p] is TRUE — otherwise the slot is "inherit / default").
 */
typedef struct {
    stm_dataset_entry e;
    bool              present;
    bool              local_set[STM_PROP_COUNT];
    uint64_t          local_value[STM_PROP_COUNT];
} dataset_slot;

struct stm_dataset_index {
    pthread_mutex_t lock;
    dataset_slot   *slots;        /* dynamic array indexed by slot index */
    size_t          slots_len;    /* count of allocated slots */
    size_t          slots_cap;    /* capacity */
    uint64_t        next_id;      /* next id to assign — monotonic */
    uint64_t        current_txg;
    uint64_t        pool_default[STM_PROP_COUNT];  /* per-property default */

    /* ----- Persistence (P6-persist) ----- */
    stm_bdev       *bdev;         /* borrowed — device 0; NULL until set_storage */
    stm_bootstrap  *boot;         /* borrowed — device 0's bootstrap */
    const uint8_t  *metadata_key; /* borrowed (32 bytes); NULL until set_crypt_ctx */
    uint64_t        pool_uuid[2];
    uint64_t        device_uuid[2];
    bool            crypt_set;

    /* Durable root state (last persisted or last loaded). All zero
     * before any commit/load. */
    uint64_t        root_paddr;
    uint64_t        root_gen;
    uint8_t         root_csum[32];

    /* R7c P2-5 / R14b parallel idempotency flag. True iff in-RAM state
     * has diverged from the durably-persisted root. Fresh handles start
     * dirty (no durable state yet); load_at clears; mutation sets;
     * commit clears on success.
     *
     * Why load-bearing: sync_commit retries on STM_EQUORUM must produce
     * byte-identical UB bytes across every device per
     * quorum.tla::ContentQuorumAtGen. A non-idempotent commit would
     * allocate a fresh paddr on each call and diverge. */
    bool            dirty;

    /* P7-CAS-14: monotonic counter bumped on every property-state
     * mutation (set_property + clear_property + set_pool_default +
     * move). Read by the sync layer's per-COLD-read property cache
     * to detect when its cached effective values are stale. The
     * counter is _Atomic so the read side (sync layer at the bump
     * call site, holding sync->lock but NOT this idx's lock) sees a
     * coherent value without contending on dataset_idx->lock.
     *
     * Bumped under dataset_idx->lock at each mutation site; read with
     * relaxed ordering since the cache is best-effort + race-tolerant
     * (a stale window value yields a stale heuristic decision, not a
     * soundness violation per R62 + R63 audits). */
    _Atomic uint64_t prop_mutation_gen;
};

/*
 * R28 P3-2: cast away the const on idx->lock for pthread_mutex_*.
 * The mutex is logically a distinct state component from idx's
 * data; const-qualified API callers (lookup, count, iter) treat the
 * data as read-only but still need exclusive access to serialize
 * with concurrent writers. POSIX permits this pattern.
 */
static inline pthread_mutex_t *dataset_lock(const stm_dataset_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* Internal helpers (caller must hold idx->lock).                     */
/* ------------------------------------------------------------------ */

/*
 * Find the slot for id, returning the slot index or SIZE_MAX if id is
 * not allocated. Linear scan is acceptable for MVP scale.
 *
 * Note: an "allocated" slot may be PRESENT or ABSENT; lookup callers
 * should additionally check slot->present for PRESENT semantics.
 */
static size_t find_slot_locked(const stm_dataset_index *idx, uint64_t id) {
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].e.id == id) return i;
    }
    return (size_t)-1;
}

/*
 * Is id PRESENT? (Allocated AND not destroyed.) Used by the public-API
 * preconditions and by the cycle-prevention walk.
 */
static bool is_present_locked(const stm_dataset_index *idx, uint64_t id) {
    if (id == STM_DATASET_NO_PARENT) return false;
    size_t s = find_slot_locked(idx, id);
    return s != (size_t)-1 && idx->slots[s].present;
}

/*
 * Sibling-name-uniqueness check: is `name` already used by a PRESENT
 * sibling of parent_id (excluding `exclude_id` if non-zero — used by
 * Rename / Move when checking against the moving dataset's own slot)?
 */
static bool sibling_name_taken_locked(const stm_dataset_index *idx,
                                        uint64_t parent_id,
                                        const uint8_t *name, uint32_t name_len,
                                        uint64_t exclude_id) {
    for (size_t i = 0; i < idx->slots_len; i++) {
        const dataset_slot *s = &idx->slots[i];
        if (!s->present) continue;
        if (s->e.id == exclude_id) continue;
        if (s->e.parent_id != parent_id) continue;
        if (s->e.name_len != name_len) continue;
        if (memcmp(s->e.name, name, name_len) == 0) return true;
    }
    return false;
}

/*
 * Cycle-prevention helper for Move: is `candidate` a descendant of
 * `ancestor` (or equal to `ancestor`) along the present-parent chain?
 *
 * Walks candidate → parent[candidate] → ... up to MaxDatasets steps.
 * Bounded by slot count to defend against a hypothetical malformed
 * chain. If we encounter an ABSENT parent or hit RootId without
 * finding ancestor, we return false; if we encounter ancestor on the
 * walk, we return true.
 */
static bool is_descendant_or_self_locked(const stm_dataset_index *idx,
                                            uint64_t candidate,
                                            uint64_t ancestor) {
    uint64_t cur = candidate;
    /* Defensive bound: walk at most slots_len + 1 steps. Any longer
     * means a cycle in parent_ids — which the impl should never
     * produce, but the bound keeps us safe under malformed state. */
    for (size_t hops = 0; hops <= idx->slots_len; hops++) {
        if (cur == ancestor) return true;
        if (cur == STM_DATASET_NO_PARENT) return false;
        size_t s = find_slot_locked(idx, cur);
        if (s == (size_t)-1) return false;        /* unallocated id */
        cur = idx->slots[s].e.parent_id;
    }
    return false;  /* exceeded bound — treat as no path */
}

/*
 * Has dataset `id` any PRESENT children?
 */
static bool has_children_locked(const stm_dataset_index *idx, uint64_t id) {
    for (size_t i = 0; i < idx->slots_len; i++) {
        const dataset_slot *s = &idx->slots[i];
        if (s->present && s->e.parent_id == id) return true;
    }
    return false;
}

/*
 * Append a new dataset_slot. Grows the array if needed (doubling).
 * Returns the new slot's index, or SIZE_MAX on allocation failure.
 */
static size_t append_slot_locked(stm_dataset_index *idx) {
    if (idx->slots_len == idx->slots_cap) {
        size_t new_cap = idx->slots_cap == 0 ? 8 : idx->slots_cap * 2;
        dataset_slot *new_slots = realloc(idx->slots,
                                            new_cap * sizeof(dataset_slot));
        if (!new_slots) return (size_t)-1;
        idx->slots = new_slots;
        idx->slots_cap = new_cap;
    }
    size_t new_idx = idx->slots_len++;
    memset(&idx->slots[new_idx], 0, sizeof(dataset_slot));
    return new_idx;
}

/* ------------------------------------------------------------------ */
/* Public API.                                                         */
/* ------------------------------------------------------------------ */

stm_status stm_dataset_index_create(uint64_t current_txg,
                                      stm_dataset_index **out) {
    if (!out) return STM_EINVAL;
    *out = NULL;

    stm_dataset_index *idx = calloc(1, sizeof(*idx));
    if (!idx) return STM_ENOMEM;

    /* R28 P3-4: ERRORCHECK mutex — callback re-entry from
     * stm_dataset_iter (forbidden per public API contract) returns
     * EDEADLK on the inner lock instead of hanging silently. Cost:
     * trivial. Benefit: contract violations surface visibly. */
    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        free(idx);
        return STM_ENOMEM;
    }
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    int mr = pthread_mutex_init(&idx->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    if (mr != 0) {
        free(idx);
        return STM_ENOMEM;
    }

    /* Allocate root slot (id = STM_DATASET_ROOT_ID = 1).
     *
     * R28 P3-1: dataset.tla's Init sets root.name = sentinel "_ROOT_"
     * to keep the abstract name set disjoint from real children's
     * names. The C impl stores name_len = 0 / empty string instead
     * because (a) the path-prefix is the pool name (e.g., "tank"),
     * not stored per-dataset; (b) root has no siblings (parent = 0),
     * so SiblingNameUnique is vacuous; (c) name "" can never collide
     * with a real child name (the empty string is rejected by Create's
     * name_len > 0 check). Semantically equivalent to the spec
     * sentinel. */
    size_t root_slot = append_slot_locked(idx);
    if (root_slot == (size_t)-1) {
        pthread_mutex_destroy(&idx->lock);
        free(idx);
        return STM_ENOMEM;
    }
    idx->slots[root_slot].e.id          = STM_DATASET_ROOT_ID;
    idx->slots[root_slot].e.parent_id   = STM_DATASET_NO_PARENT;
    idx->slots[root_slot].e.name_len    = 0;
    idx->slots[root_slot].e.name[0]     = '\0';
    idx->slots[root_slot].e.created_txg = current_txg;
    idx->slots[root_slot].e.flags       = 0;
    idx->slots[root_slot].e.next_ino    = 0;
    idx->slots[root_slot].present       = true;

    idx->next_id     = 2;  /* root = 1 used; next allocation starts at 2 */
    idx->current_txg = current_txg;
    idx->dirty       = true;  /* fresh state — needs first persist */

    *out = idx;
    return STM_OK;
}

void stm_dataset_index_close(stm_dataset_index *idx) {
    if (!idx) return;
    pthread_mutex_destroy(&idx->lock);
    free(idx->slots);
    free(idx);
}

stm_status stm_dataset_index_advance_txg(stm_dataset_index *idx,
                                           uint64_t new_txg) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    /* R28 P3-3: equal value is a no-op (not a regression) — the spec's
     * BirthTxgMonotonic invariant only forbids strictly-decreasing
     * advance. Same-value advance is the legitimate "external txg
     * source agrees with internal counter" path. */
    if (new_txg < idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->current_txg = new_txg;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_index_current_txg(const stm_dataset_index *idx,
                                            uint64_t *out_txg) {
    if (!idx || !out_txg) return STM_EINVAL;
    /* Cast away const for pthread API; semantically read-only. */
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    *out_txg = idx->current_txg;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_dataset_create_child(stm_dataset_index *idx,
                                       uint64_t parent_id,
                                       const char *name,
                                       uint64_t *out_id) {
    if (!idx || !name || !out_id) return STM_EINVAL;
    *out_id = 0;
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > STM_DATASET_NAME_MAX) return STM_EINVAL;

    must_lock(&idx->lock);

    /* R29 P3-1 (carry-over): defensive saturation on the monotonic
     * counters. Under realistic workloads UINT64_MAX is millennia
     * away; refuse cleanly rather than wrap into an id collision
     * or a backwards txg under a hostile / buggy caller. */
    if (idx->next_id == UINT64_MAX || idx->current_txg == UINT64_MAX) {
        must_unlock(&idx->lock);
        return STM_EOVERFLOW;
    }

    if (!is_present_locked(idx, parent_id)) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (sibling_name_taken_locked(idx, parent_id,
                                    (const uint8_t *)name, (uint32_t)name_len,
                                    0)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    /* Allocate the new slot. */
    size_t new_slot = append_slot_locked(idx);
    if (new_slot == (size_t)-1) {
        must_unlock(&idx->lock);
        return STM_ENOMEM;
    }

    /* Spec semantics: each Create bumps current_txg and stamps the
     * new dataset's created_txg = (post-bump) current_txg. */
    idx->current_txg += 1;

    uint64_t id = idx->next_id++;
    dataset_slot *s = &idx->slots[new_slot];
    s->e.id              = id;
    s->e.parent_id       = parent_id;
    s->e.name_len        = (uint32_t)name_len;
    memcpy(s->e.name, name, name_len);
    s->e.name[name_len] = '\0';
    s->e.created_txg     = idx->current_txg;
    s->e.flags           = 0;
    s->e.next_ino        = 0;
    s->e.origin_snap_id  = STM_DATASET_NO_ORIGIN;  /* not a clone */
    s->present           = true;

    *out_id = id;
    idx->dirty = true;

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_destroy(stm_dataset_index *idx, uint64_t id) {
    if (!idx) return STM_EINVAL;
    if (id == STM_DATASET_ROOT_ID) return STM_EINVAL;

    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (has_children_locked(idx, id)) {
        must_unlock(&idx->lock);
        return STM_EBUSY;
    }
    idx->slots[s].present = false;
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_rename(stm_dataset_index *idx, uint64_t id,
                                const char *new_name) {
    if (!idx || !new_name) return STM_EINVAL;
    if (id == STM_DATASET_ROOT_ID) return STM_EINVAL;
    size_t name_len = strlen(new_name);
    if (name_len == 0 || name_len > STM_DATASET_NAME_MAX) return STM_EINVAL;

    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    uint64_t parent_id = idx->slots[s].e.parent_id;
    if (sibling_name_taken_locked(idx, parent_id,
                                    (const uint8_t *)new_name,
                                    (uint32_t)name_len, id)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }
    /* R31 P3-2: no-op rename (same name) shouldn't dirty the handle —
     * matches set_pool_default's idempotency guard. */
    if (idx->slots[s].e.name_len == name_len &&
        memcmp(idx->slots[s].e.name, new_name, name_len) == 0) {
        must_unlock(&idx->lock);
        return STM_OK;
    }
    idx->slots[s].e.name_len = (uint32_t)name_len;
    memcpy(idx->slots[s].e.name, new_name, name_len);
    idx->slots[s].e.name[name_len] = '\0';
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

uint64_t stm_dataset_index_property_mutation_gen(
        const stm_dataset_index *idx) {
    if (!idx) return 0;
    return atomic_load_explicit(&idx->prop_mutation_gen,
                                   memory_order_relaxed);
}

stm_status stm_dataset_move(stm_dataset_index *idx, uint64_t id,
                              uint64_t new_parent_id) {
    if (!idx) return STM_EINVAL;
    if (id == STM_DATASET_ROOT_ID) return STM_EINVAL;
    if (id == new_parent_id) return STM_EINVAL;

    must_lock(&idx->lock);

    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (!is_present_locked(idx, new_parent_id)) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    /* Cycle prevention: new_parent_id must NOT be a descendant of id
     * (or id itself — covered by id != new_parent_id above). */
    if (is_descendant_or_self_locked(idx, new_parent_id, id)) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    /* Sibling-name uniqueness in the new parent's children. */
    if (sibling_name_taken_locked(idx, new_parent_id,
                                    idx->slots[s].e.name,
                                    idx->slots[s].e.name_len, id)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }
    idx->slots[s].e.parent_id = new_parent_id;
    idx->dirty = true;
    /* P7-CAS-14: a Move changes the moved dataset's parent chain →
     * effective INHERITABLE values change for the dataset and every
     * descendant. Bump the property-mutation gen so any sync-side
     * cache observes its entries as stale and recomputes. */
    atomic_fetch_add_explicit(&idx->prop_mutation_gen, 1u,
                                 memory_order_relaxed);
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_lookup(const stm_dataset_index *idx, uint64_t id,
                                stm_dataset_entry *out) {
    if (!idx || !out) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(lock);
        return STM_ENOENT;
    }
    *out = idx->slots[s].e;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_dataset_count(const stm_dataset_index *idx,
                                size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    size_t n = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].present) n++;
    }
    *out_count = n;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_dataset_children_count(const stm_dataset_index *idx,
                                         uint64_t parent_id,
                                         size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    if (!is_present_locked(idx, parent_id)) {
        must_unlock(lock);
        return STM_ENOENT;
    }
    size_t n = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].present && idx->slots[i].e.parent_id == parent_id) n++;
    }
    *out_count = n;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_dataset_iter(const stm_dataset_index *idx,
                              stm_dataset_iter_cb cb, void *ctx) {
    if (!idx || !cb) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    /* Iterate by id-ascending. Slots are appended in id-ascending order
     * (next_id is monotonic), so a linear walk over slots[] is already
     * id-ordered. */
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (!idx->slots[i].present) continue;
        if (!cb(&idx->slots[i].e, ctx)) break;
    }
    must_unlock(lock);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Property API.                                                       */
/* ------------------------------------------------------------------ */

stm_property_kind stm_property_kind_of(stm_property p) {
    switch (p) {
    case STM_PROP_COMPRESS:                return STM_PROP_KIND_INHERITABLE;
    case STM_PROP_QUOTA:                   return STM_PROP_KIND_NONINHERITABLE;
    case STM_PROP_ENCRYPTION:              return STM_PROP_KIND_IMMUTABLE;
    case STM_PROP_TIERING:                 return STM_PROP_KIND_INHERITABLE;
    case STM_PROP_PROMOTE_DECAY_WINDOW:    return STM_PROP_KIND_INHERITABLE;
    case STM_PROP_COUNT:                   break;
    }
    /* R30 P3-4: STM_PROP_COUNT is the count sentinel — out-of-range
     * values should never reach this function (every public API
     * filters via prop_in_range first). Default-treat unknown values
     * as inheritable so future enum extensions get a safe default. */
    return STM_PROP_KIND_INHERITABLE;
}

static bool prop_in_range(stm_property p) {
    return (unsigned)p < (unsigned)STM_PROP_COUNT;
}

/*
 * Walk d's chain looking for the nearest dataset with `p` locally set.
 * For NONINHERITABLE properties, only d's own slot counts (no walk).
 * Returns the local value if found; otherwise returns the pool default.
 *
 * Caller must hold idx->lock.
 */
static uint64_t effective_property_locked(const stm_dataset_index *idx,
                                              uint64_t id, stm_property p) {
    stm_property_kind kind = stm_property_kind_of(p);

    /* Bounded walk: at most slots_len + 1 steps to defend against any
     * malformed parent chain.
     *
     * R30 P3-1: an ABSENT intermediate parent on the chain of a
     * PRESENT dataset would indicate corruption (Destroy refuses
     * non-leaf, so this state should be unreachable from the public
     * API). The break + fall-through to pool_default below is
     * defensive — it returns a safe value rather than crashing under
     * malformed state. A future debug-only assert could promote this
     * to a hard fail; for now the silent fallback is preferred to
     * keep effective_property crash-free even on hostile inputs. */
    uint64_t cur = id;
    for (size_t hops = 0; hops <= idx->slots_len; hops++) {
        size_t s = find_slot_locked(idx, cur);
        if (s == (size_t)-1 || !idx->slots[s].present) break;
        if (idx->slots[s].local_set[p]) {
            return idx->slots[s].local_value[p];
        }
        /* Non-inheritable: short-circuit to pool default once we've
         * checked d's own slot (no parent walk).
         * property.tla::NonInheritableNoWalk. */
        if (kind == STM_PROP_KIND_NONINHERITABLE) break;
        /* Inheritable / Immutable: walk to parent. (Immutable is
         * inherited if not locally set — see ARCH §8.4.2 encryption
         * "can be inherited from parent or declared at creation".) */
        uint64_t parent = idx->slots[s].e.parent_id;
        if (parent == STM_DATASET_NO_PARENT) break;
        cur = parent;
    }
    return idx->pool_default[p];
}

stm_status stm_dataset_set_pool_default(stm_dataset_index *idx,
                                           stm_property p, uint64_t value) {
    if (!idx) return STM_EINVAL;
    if (!prop_in_range(p)) return STM_EINVAL;
    must_lock(&idx->lock);
    if (idx->pool_default[p] != value) {
        idx->pool_default[p] = value;
        idx->dirty = true;
        /* P7-CAS-14: bump the property-mutation gen so any sync-side
         * cache observes a stale window value as out-of-date and
         * recomputes on next access. */
        atomic_fetch_add_explicit(&idx->prop_mutation_gen, 1u,
                                     memory_order_relaxed);
    }
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_set_property(stm_dataset_index *idx, uint64_t id,
                                       stm_property p, uint64_t value) {
    if (!idx) return STM_EINVAL;
    if (!prop_in_range(p)) return STM_EINVAL;
    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    /* property.tla::ImmutableEncryption: an IMMUTABLE property is
     * write-once per dataset. Once locally set, refuse subsequent
     * Set / Clear. The spec models this via the
     * `immutable_was_mutated` ghost flag and BuggyMutateEncryption
     * gate; the impl rejects at the action's enabling condition. */
    if (stm_property_kind_of(p) == STM_PROP_KIND_IMMUTABLE
        && idx->slots[s].local_set[p]) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->slots[s].local_set[p]   = true;
    idx->slots[s].local_value[p] = value;
    idx->dirty = true;
    /* P7-CAS-14: bump the property-mutation gen (see set_pool_default). */
    atomic_fetch_add_explicit(&idx->prop_mutation_gen, 1u,
                                 memory_order_relaxed);
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_clear_property(stm_dataset_index *idx, uint64_t id,
                                         stm_property p) {
    if (!idx) return STM_EINVAL;
    if (!prop_in_range(p)) return STM_EINVAL;
    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    /* R30 P2-2: clearing an IMMUTABLE property is unconditionally
     * refused — even on a slot that was never locally set. This
     * tightens the contract to match the dataset.h docstring
     * ("clearing an IMMUTABLE property always refused"). The previous
     * behavior was to no-op-succeed when local_set was already FALSE,
     * which was a contract drift. */
    if (stm_property_kind_of(p) == STM_PROP_KIND_IMMUTABLE) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (idx->slots[s].local_set[p]) {
        idx->slots[s].local_set[p] = false;
        /* Leave local_value[p] in place; it's not observed when
         * local_set[p] is FALSE. */
        idx->dirty = true;
        /* P7-CAS-14: bump the property-mutation gen (see set_pool_default). */
        atomic_fetch_add_explicit(&idx->prop_mutation_gen, 1u,
                                     memory_order_relaxed);
    }
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_effective_property(const stm_dataset_index *idx,
                                              uint64_t id, stm_property p,
                                              uint64_t *out_value) {
    if (!idx || !out_value) return STM_EINVAL;
    if (!prop_in_range(p)) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(lock);
        return STM_ENOENT;
    }
    *out_value = effective_property_locked(idx, id, p);
    must_unlock(lock);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Clone API (P6-clone).                                              */
/* ------------------------------------------------------------------ */

stm_status stm_dataset_create_clone(stm_dataset_index *idx,
                                       uint64_t parent_id,
                                       const char *name,
                                       uint64_t origin_snap_id,
                                       uint64_t *out_id) {
    if (!idx || !name || !out_id) return STM_EINVAL;
    *out_id = 0;
    if (origin_snap_id == STM_DATASET_NO_ORIGIN) return STM_EINVAL;
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > STM_DATASET_NAME_MAX) return STM_EINVAL;

    must_lock(&idx->lock);

    if (idx->next_id == UINT64_MAX || idx->current_txg == UINT64_MAX) {
        must_unlock(&idx->lock);
        return STM_EOVERFLOW;
    }

    /* R32 P2-2: check self-reference BEFORE counter advances. The
     * about-to-be-allocated id is `idx->next_id`; rejecting here
     * leaves all in-RAM counters untouched, so we don't need a
     * rollback path on this branch. */
    if (origin_snap_id == idx->next_id) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (!is_present_locked(idx, parent_id)) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (sibling_name_taken_locked(idx, parent_id,
                                    (const uint8_t *)name, (uint32_t)name_len,
                                    0)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    size_t new_slot = append_slot_locked(idx);
    if (new_slot == (size_t)-1) {
        must_unlock(&idx->lock);
        return STM_ENOMEM;
    }

    /* Same txg-bump-then-stamp as create_child. */
    idx->current_txg += 1;

    uint64_t id = idx->next_id++;
    dataset_slot *s = &idx->slots[new_slot];
    s->e.id              = id;
    s->e.parent_id       = parent_id;
    s->e.name_len        = (uint32_t)name_len;
    memcpy(s->e.name, name, name_len);
    s->e.name[name_len] = '\0';
    s->e.created_txg     = idx->current_txg;
    s->e.flags           = 0;
    s->e.next_ino        = 0;
    s->e.origin_snap_id  = origin_snap_id;
    s->present           = true;

    *out_id = id;
    idx->dirty = true;

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_promote(stm_dataset_index *idx, uint64_t id) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    /* clone.tla::Promote precondition: dataset must be a clone. */
    if (idx->slots[s].e.origin_snap_id == STM_DATASET_NO_ORIGIN) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->slots[s].e.origin_snap_id = STM_DATASET_NO_ORIGIN;
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_clones_count_for_snap(const stm_dataset_index *idx,
                                                uint64_t snapshot_id,
                                                size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    *out_count = 0;
    if (snapshot_id == STM_DATASET_NO_ORIGIN) {
        /* The sentinel never matches a real clone reference; fast-path
         * short-circuit so a caller scanning for "any clones?" doesn't
         * walk the array uselessly. */
        return STM_OK;
    }
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    size_t n = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        const dataset_slot *s = &idx->slots[i];
        if (!s->present) continue;
        if (s->e.origin_snap_id == snapshot_id) n++;
    }
    *out_count = n;
    must_unlock(lock);
    return STM_OK;
}

/* =========================================================================
 * Persistence (P6-persist).
 *
 * The dataset index is persisted as a single btree_store-encoded tree
 * under ub_main_root. Keyspace:
 *   - le64 0   → pool-property defaults  (value: 8 * STM_PROP_COUNT bytes;
 *                v22 = 40, v20 = 32, v19 = 24).
 *   - le64 ≥1  → packed dataset entry
 *                  (value: DS_VAL_FIXED + name_len bytes;
 *                   v22 = 80 + name_len, v20 = 72 + name_len,
 *                   v19 = 64 + name_len).
 *
 * Implementation mirrors src/alloc_roots/alloc_roots.c — same vtable shape,
 * same dirty-flag idempotency, same Merkle + AEAD chain via btree_store.
 *
 * Format-break history:
 *   v10: introduced origin_snap_id at offset 56 (P6-clone).
 *   v20: STM_PROP_COUNT 3 → 4 (P7-CAS-8 STM_PROP_TIERING). local_value
 *        grows from 24 to 32 bytes; origin_snap_id moves from offset
 *        56 to offset 64; DS_VAL_FIXED grows from 64 to 72. v19 pools
 *        refused at v20 mount via uniform STM_EBADVERSION (no in-place
 *        forward-compat at the value layer — same posture as v17→v18
 *        and v18→v19 bumps).
 *   v22: STM_PROP_COUNT 4 → 5 (P7-CAS-12 STM_PROP_PROMOTE_DECAY_WINDOW).
 *        local_value grows from 32 to 40 bytes; origin_snap_id moves
 *        from offset 64 to offset 72; DS_VAL_FIXED grows from 72 to 80.
 *        v21 pools refused at v22 mount via uniform STM_EBADVERSION.
 * ========================================================================= */

#define DS_KEY_LEN              8u
/* v22: 32 bytes fixed prefix + 40 bytes local_value (5 × le64) + 8 bytes
 * origin_snap_id = 80 fixed bytes. */
#define DS_VAL_FIXED            80u
#define DS_VAL_MAX              (DS_VAL_FIXED + STM_DATASET_NAME_MAX)
#define DS_POOL_DEFAULTS_KEY    UINT64_C(0)
#define DS_POOL_DEFAULTS_VAL_LEN  (8u * STM_PROP_COUNT)

/* DS_VAL_MAX = 319 bytes, well under any btnode-leaf cap; if a future
 * STM_DATASET_NAME_MAX bump pushes past one leaf, the encode would
 * fail at stm_btree_mt_insert with STM_ERANGE. Keeping the math here
 * as a comment for reviewers. */

/* R63 P3-3: the on-disk local_set_bitmap is encoded as a uint16_t
 * (le16 at offset 28). The encoder/decoder construct the validation
 * mask as `(uint16_t)((1u << STM_PROP_COUNT) - 1u)` — at
 * STM_PROP_COUNT > 16 the cast silently truncates and the
 * anti-tamper check on bitmap bits beyond `STM_PROP_COUNT - 1`
 * regresses. A future STM_PROP_COUNT bump that exceeds 16 must
 * also widen the bitmap to le32 (or split into multiple le16s) +
 * bump STM_UB_VERSION accordingly. Defense-in-depth: fail the
 * compile loudly so the bump that breaks this gets surfaced
 * before runtime. */
_Static_assert(STM_PROP_COUNT <= 16,
               "DS local_set_bitmap is le16; STM_PROP_COUNT must fit. "
               "Widen the on-disk bitmap field before bumping past 16.");

/* ---- key + value codec (caller must hold idx->lock for slot reads) ---- */

static void ds_encode_key(uint64_t key_val, uint8_t out[DS_KEY_LEN]) {
    le64 k = stm_store_le64(key_val);
    memcpy(out, k.v, DS_KEY_LEN);
}

static uint64_t ds_decode_key(const uint8_t in[DS_KEY_LEN]) {
    le64 k;
    memcpy(k.v, in, DS_KEY_LEN);
    return stm_load_le64(k);
}

/* Encode a present dataset slot. Returns the byte count written.
 * Caller ensures out_cap >= DS_VAL_FIXED + slot->e.name_len. */
static size_t ds_encode_dataset_value(const dataset_slot *s,
                                          uint8_t *out, size_t out_cap) {
    size_t need = DS_VAL_FIXED + s->e.name_len;
    if (out_cap < need) return 0;

    le64 parent = stm_store_le64(s->e.parent_id);
    le64 ctxg   = stm_store_le64(s->e.created_txg);
    le64 nino   = stm_store_le64(s->e.next_ino);
    le32 flags  = stm_store_le32(s->e.flags);

    uint16_t bitmap = 0;
    for (unsigned p = 0; p < STM_PROP_COUNT; p++) {
        if (s->local_set[p]) bitmap |= (uint16_t)(1u << p);
    }
    le16 lsb    = stm_store_le16(bitmap);
    le16 nlen   = stm_store_le16((uint16_t)s->e.name_len);
    le64 origin = stm_store_le64(s->e.origin_snap_id);

    memcpy(out + 0,  parent.v, 8);
    memcpy(out + 8,  ctxg.v,   8);
    memcpy(out + 16, nino.v,   8);
    memcpy(out + 24, flags.v,  4);
    memcpy(out + 28, lsb.v,    2);
    memcpy(out + 30, nlen.v,   2);
    for (unsigned p = 0; p < STM_PROP_COUNT; p++) {
        le64 v = stm_store_le64(s->local_value[p]);
        memcpy(out + 32u + p * 8u, v.v, 8);
    }
    /* v22: origin_snap_id at offset 32 + 8*STM_PROP_COUNT
     * (= 72 at STM_PROP_COUNT=5). Was at offset 56 pre-v20, 64 at v20. */
    memcpy(out + 32u + 8u * STM_PROP_COUNT, origin.v, 8);
    if (s->e.name_len > 0) {
        memcpy(out + DS_VAL_FIXED, s->e.name, s->e.name_len);
    }
    return need;
}

/* Decode a dataset entry value into out_slot (with id supplied separately
 * from the key). out_slot is fully populated (present=true). */
static stm_status ds_decode_dataset_value(uint64_t id, const uint8_t *in,
                                             size_t in_len,
                                             dataset_slot *out_slot) {
    if (in_len < DS_VAL_FIXED) return STM_ECORRUPT;

    le64 parent, ctxg, nino;
    le32 flags;
    le16 lsb, nlen;
    memcpy(parent.v, in + 0,  8);
    memcpy(ctxg.v,   in + 8,  8);
    memcpy(nino.v,   in + 16, 8);
    memcpy(flags.v,  in + 24, 4);
    memcpy(lsb.v,    in + 28, 2);
    memcpy(nlen.v,   in + 30, 2);

    uint16_t name_len = stm_load_le16(nlen);
    if (name_len > STM_DATASET_NAME_MAX) return STM_ECORRUPT;
    if (in_len != (size_t)DS_VAL_FIXED + name_len) return STM_ECORRUPT;

    uint16_t bitmap = stm_load_le16(lsb);
    /* Bits beyond STM_PROP_COUNT signal an encode from a future
     * STM_PROP_COUNT — refuse to mount partially-decoded state. A
     * version bump should accompany any STM_PROP_COUNT growth. */
    uint16_t bitmap_mask = (uint16_t)((1u << STM_PROP_COUNT) - 1u);
    if (bitmap & ~bitmap_mask) return STM_ECORRUPT;

    memset(out_slot, 0, sizeof *out_slot);
    out_slot->present     = true;
    out_slot->e.id        = id;
    out_slot->e.parent_id = stm_load_le64(parent);
    out_slot->e.created_txg = stm_load_le64(ctxg);
    out_slot->e.next_ino  = stm_load_le64(nino);
    out_slot->e.flags     = stm_load_le32(flags);
    out_slot->e.name_len  = name_len;
    for (unsigned p = 0; p < STM_PROP_COUNT; p++) {
        le64 v;
        memcpy(v.v, in + 32u + p * 8u, 8);
        out_slot->local_value[p] = stm_load_le64(v);
        out_slot->local_set[p]   = (bitmap & (uint16_t)(1u << p)) != 0;
    }
    le64 origin;
    /* v22: origin_snap_id at 32 + 8*STM_PROP_COUNT (= 72 at
     * STM_PROP_COUNT=5). Mirror of the encode offset. */
    memcpy(origin.v, in + 32u + 8u * STM_PROP_COUNT, 8);
    out_slot->e.origin_snap_id = stm_load_le64(origin);
    if (name_len > 0) {
        memcpy(out_slot->e.name, in + DS_VAL_FIXED, name_len);
    }
    out_slot->e.name[name_len] = '\0';
    return STM_OK;
}

static void ds_encode_pool_defaults(const uint64_t pd[STM_PROP_COUNT],
                                       uint8_t out[DS_POOL_DEFAULTS_VAL_LEN]) {
    for (unsigned p = 0; p < STM_PROP_COUNT; p++) {
        le64 v = stm_store_le64(pd[p]);
        memcpy(out + p * 8u, v.v, 8);
    }
}

static stm_status ds_decode_pool_defaults(const uint8_t *in, size_t in_len,
                                              uint64_t out_pd[STM_PROP_COUNT]) {
    if (in_len != DS_POOL_DEFAULTS_VAL_LEN) return STM_ECORRUPT;
    for (unsigned p = 0; p < STM_PROP_COUNT; p++) {
        le64 v;
        memcpy(v.v, in + p * 8u, 8);
        out_pd[p] = stm_load_le64(v);
    }
    return STM_OK;
}

/* ---- btree_store vtable: bridge to bootstrap + bdev on device 0. ---- */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} ds_store_ctx;

static stm_status ds_store_reserve(void *ctx_, uint64_t *out_paddr) {
    ds_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status ds_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen) {
    ds_store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status ds_store_write(void *ctx_, uint64_t paddr,
                                    const void *buf, size_t len) {
    ds_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status ds_store_read(void *ctx_, uint64_t paddr,
                                   void *buf, size_t len) {
    ds_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable DS_STORE_VT = {
    .reserve = ds_store_reserve,
    .free    = ds_store_free,
    .write   = ds_store_write,
    .read    = ds_store_read,
};

static inline ds_store_ctx ds_make_store_ctx(stm_dataset_index *idx) {
    ds_store_ctx c = { .boot = idx->boot, .bdev = idx->bdev };
    return c;
}

static inline stm_btree_crypt_ctx ds_make_crypt_ctx(const stm_dataset_index *idx) {
    stm_btree_crypt_ctx cx = { .metadata_key = idx->metadata_key };
    cx.pool_uuid[0]   = idx->pool_uuid[0];
    cx.pool_uuid[1]   = idx->pool_uuid[1];
    cx.device_uuid[0] = idx->device_uuid[0];
    cx.device_uuid[1] = idx->device_uuid[1];
    return cx;
}

/* ---- Public persistence API. ---- */

stm_status stm_dataset_index_set_storage(stm_dataset_index *idx,
                                            stm_bdev *bdev_0,
                                            stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(&idx->lock);
    idx->bdev = bdev_0;
    idx->boot = boot_0;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_index_set_crypt_ctx(stm_dataset_index *idx,
                                              const uint8_t *metadata_key,
                                              const uint64_t pool_uuid[2],
                                              const uint64_t device_uuid_0[2]) {
    if (!idx || !metadata_key || !pool_uuid || !device_uuid_0) return STM_EINVAL;
    must_lock(&idx->lock);
    idx->metadata_key   = metadata_key;
    idx->pool_uuid[0]   = pool_uuid[0];
    idx->pool_uuid[1]   = pool_uuid[1];
    idx->device_uuid[0] = device_uuid_0[0];
    idx->device_uuid[1] = device_uuid_0[1];
    idx->crypt_set      = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_index_get_root(const stm_dataset_index *idx,
                                         uint64_t *out_root_paddr,
                                         uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    *out_root_paddr = idx->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, idx->root_csum, 32);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_dataset_index_get_gen(const stm_dataset_index *idx,
                                        uint64_t *out_root_gen) {
    if (!idx || !out_root_gen) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    *out_root_gen = idx->root_gen;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_dataset_index_get_next_id(const stm_dataset_index *idx,
                                            uint64_t *out_next_id) {
    if (!idx || !out_next_id) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    *out_next_id = idx->next_id;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_dataset_index_set_next_id(stm_dataset_index *idx,
                                            uint64_t next_id) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    /* Refuse to push next_id below any present id + 1 — would break
     * IdMonotonic on subsequent creates. Equal-or-greater advance is OK. */
    uint64_t max_present = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (!idx->slots[i].present) continue;
        if (idx->slots[i].e.id > max_present) max_present = idx->slots[i].e.id;
    }
    if (next_id <= max_present) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (next_id != idx->next_id) {
        idx->next_id = next_id;
        /* No dirty flip: next_id is sourced from the UB, not persisted
         * in our btree. The caller (sync.c) round-trips it via
         * ub_next_dataset_id. */
    }
    must_unlock(&idx->lock);
    return STM_OK;
}

/* Build a fresh stm_btree_mt from the in-RAM slots[] + pool_default[].
 * Caller (commit) takes ownership; on error returns NULL with status set. */
static stm_status ds_build_btree_locked(const stm_dataset_index *idx,
                                            stm_btree_mt **out_tree) {
    stm_btree_opts opts = stm_btree_opts_default();
    /* Dataset entries are ~60..310 bytes each; with a 128 KiB leaf and
     * ~280 byte average we can fit ~460 entries per leaf. Bump
     * target_entries to ~512 to stay single-leaf for typical pool
     * populations (< 500 datasets) — internal-node splits then only
     * fire for genuinely large pools. */
    if (opts.target_entries < 512u) opts.target_entries = 512u;

    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) return ts;

    /* Pool defaults: key = le64 0, value = 24 bytes. */
    uint8_t pdkey[DS_KEY_LEN];
    uint8_t pdval[DS_POOL_DEFAULTS_VAL_LEN];
    ds_encode_key(DS_POOL_DEFAULTS_KEY, pdkey);
    ds_encode_pool_defaults(idx->pool_default, pdval);
    stm_status ins = stm_btree_mt_insert(t, pdkey, DS_KEY_LEN,
                                            pdval, sizeof pdval);
    if (ins != STM_OK) { stm_btree_mt_free(t); return ins; }

    /* Each PRESENT slot. */
    uint8_t key[DS_KEY_LEN];
    uint8_t val[DS_VAL_MAX];
    for (size_t i = 0; i < idx->slots_len; i++) {
        const dataset_slot *s = &idx->slots[i];
        if (!s->present) continue;
        ds_encode_key(s->e.id, key);
        size_t vlen = ds_encode_dataset_value(s, val, sizeof val);
        if (vlen == 0) { stm_btree_mt_free(t); return STM_ERANGE; }
        stm_status is = stm_btree_mt_insert(t, key, DS_KEY_LEN, val, vlen);
        if (is != STM_OK) { stm_btree_mt_free(t); return is; }
    }

    *out_tree = t;
    return STM_OK;
}

stm_status stm_dataset_index_commit(stm_dataset_index *idx,
                                       uint64_t committed_gen,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    must_lock(&idx->lock);

    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* R7c P2-5 / R14b idempotency: clean handle with prior persist
     * returns cached values. Critical for quorum.tla::ContentQuorumAtGen
     * under retry. */
    if (!idx->dirty && idx->root_paddr != 0) {
        *out_root_paddr = idx->root_paddr;
        memcpy(out_root_csum, idx->root_csum, 32);
        must_unlock(&idx->lock);
        return STM_OK;
    }

    /* Materialize a btree from current slots + pool_defaults. */
    stm_btree_mt *t = NULL;
    stm_status bs = ds_build_btree_locked(idx, &t);
    if (bs != STM_OK) {
        must_unlock(&idx->lock);
        return bs;
    }

    ds_store_ctx       sc = ds_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = ds_make_crypt_ctx(idx);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(t, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &DS_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    /* The materialized btree is no longer needed once serialized;
     * btree_store has copied bytes into the on-disk nodes. */
    stm_btree_mt_free(t);
    if (ss != STM_OK) {
        must_unlock(&idx->lock);
        return ss;
    }

    /* R15 F2 P1 parallel: rollback helper for failure paths after a
     * successful reserve+write but before commit completes. Symmetric
     * to alloc_roots's AR_ROLLBACK_RESERVE. */
    #define DS_ROLLBACK_RESERVE() \
        do { (void)stm_btree_store_free_tree(new_paddr, committed_gen,  \
                                                committed_gen, new_csum, \
                                                &DS_STORE_VT, &sc, &cx); \
        } while (0)

    /* Defer-free the prior root's nodes. */
    if (idx->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(idx->root_paddr,
                                                     idx->root_gen,
                                                     committed_gen,
                                                     idx->root_csum,
                                                     &DS_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            DS_ROLLBACK_RESERVE();
            must_unlock(&idx->lock);
            return fs;
        }
    }

    /* Bootstrap commit so our reserve + free are durable. Idempotent
     * at the same gen — symmetric to alloc_roots_commit. */
    stm_status bsc = stm_bootstrap_commit(idx->boot, committed_gen);
    if (bsc != STM_OK) {
        DS_ROLLBACK_RESERVE();
        must_unlock(&idx->lock);
        return bsc;
    }
    #undef DS_ROLLBACK_RESERVE

    idx->root_paddr = new_paddr;
    idx->root_gen   = committed_gen;
    memcpy(idx->root_csum, new_csum, 32);
    idx->dirty      = false;

    *out_root_paddr = new_paddr;
    memcpy(out_root_csum, new_csum, 32);
    must_unlock(&idx->lock);
    return STM_OK;
}

/* ---- load_at: hydrate from on-disk root.
 *
 * Atomic swap discipline: we build a shadow slots[] + shadow
 * pool_default[] from the on-disk btree first, validate it (root
 * present, no decode failures), and only then swap into idx. Any
 * failure mid-iteration leaves idx unchanged so the caller (sync_open)
 * can propagate STM_ECORRUPT / STM_ENOMEM up without leaving the
 * index in a half-loaded state.
 * ---- */

typedef struct {
    /* Shadow buffers (we own them until swap). */
    dataset_slot *shadow_slots;
    size_t        shadow_len;
    size_t        shadow_cap;
    uint64_t      shadow_pool_default[STM_PROP_COUNT];
    bool          saw_pool_defaults;
    bool          saw_root;
    uint64_t      max_present_id;
    /* R31 P2-1: ceiling for post-load current_txg. Walking the loaded
     * slots gives max(created_txg). idx->current_txg must be bumped to
     * at least that, else a post-mount Create stamps a created_txg LESS
     * than persisted slots, violating dataset.tla::BirthTxgMonotonic. */
    uint64_t      max_created_txg;
    stm_status    err;
} ds_load_ctx;

static stm_status ds_shadow_append(ds_load_ctx *lc, const dataset_slot *src) {
    if (lc->shadow_len == lc->shadow_cap) {
        size_t new_cap = lc->shadow_cap == 0 ? 8 : lc->shadow_cap * 2;
        dataset_slot *new_buf = realloc(lc->shadow_slots,
                                          new_cap * sizeof(dataset_slot));
        if (!new_buf) return STM_ENOMEM;
        lc->shadow_slots = new_buf;
        lc->shadow_cap = new_cap;
    }
    lc->shadow_slots[lc->shadow_len++] = *src;
    return STM_OK;
}

static int ds_load_iter(const void *k, size_t klen,
                          const void *v, size_t vlen, void *ctx_) {
    ds_load_ctx *lc = ctx_;
    if (klen != DS_KEY_LEN) {
        lc->err = STM_ECORRUPT;
        return 1;
    }
    uint64_t key = ds_decode_key(k);
    if (key == DS_POOL_DEFAULTS_KEY) {
        if (lc->saw_pool_defaults) {
            lc->err = STM_ECORRUPT;
            return 1;
        }
        stm_status pds = ds_decode_pool_defaults(v, vlen,
                                                    lc->shadow_pool_default);
        if (pds != STM_OK) { lc->err = pds; return 1; }
        lc->saw_pool_defaults = true;
        return 0;
    }
    dataset_slot tmp;
    stm_status dr = ds_decode_dataset_value(key, v, vlen, &tmp);
    if (dr != STM_OK) { lc->err = dr; return 1; }
    if (key == STM_DATASET_ROOT_ID) lc->saw_root = true;
    if (key > lc->max_present_id) lc->max_present_id = key;
    if (tmp.e.created_txg > lc->max_created_txg) {
        lc->max_created_txg = tmp.e.created_txg;
    }
    stm_status as = ds_shadow_append(lc, &tmp);
    if (as != STM_OK) { lc->err = as; return 1; }
    return 0;
}

/* R31 P2-2 + P2-3: structural validation of the load-at shadow.
 * Catches trees that decode byte-clean but violate dataset.tla
 * invariants — orphan parent, sibling-name collision, cycle in parent
 * chain, root with non-zero parent_id. Returns STM_ECORRUPT on any
 * violation; STM_OK if every present slot honors ForestStructure +
 * SiblingNameUnique + RootInvariant. O(N²); fine for MVP scale. */
static stm_status ds_validate_shadow(const ds_load_ctx *lc) {
    /* Pass 1: per-slot local checks. */
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const dataset_slot *si = &lc->shadow_slots[i];
        if (!si->present) continue;

        if (si->e.id == STM_DATASET_ROOT_ID) {
            /* Root must have NO_PARENT; corrupt otherwise. */
            if (si->e.parent_id != STM_DATASET_NO_PARENT) return STM_ECORRUPT;
            /* P6-clone: root is never a clone (clone.tla::RootInvariant). */
            if (si->e.origin_snap_id != STM_DATASET_NO_ORIGIN)
                return STM_ECORRUPT;
            continue;
        }
        /* Non-root: parent_id must be set and must NOT equal own id. */
        if (si->e.parent_id == STM_DATASET_NO_PARENT) return STM_ECORRUPT;
        if (si->e.parent_id == si->e.id) return STM_ECORRUPT;
        /* P6-clone: a clone's origin_snap_id cannot equal its own id
         * (datasets and snapshots use disjoint id-spaces in the spec
         * but the impl shares the type — so origin == own_id is a
         * malformed reference). The cross-module "snap exists"
         * invariant (CloneOriginPresent) is enforced at delete time
         * via the snapshot module's clone-check cb, not here. */
        if (si->e.origin_snap_id == si->e.id) return STM_ECORRUPT;
        /* Parent must reference an existing shadow slot. */
        bool parent_found = false;
        for (size_t j = 0; j < lc->shadow_len; j++) {
            if (lc->shadow_slots[j].e.id == si->e.parent_id) {
                parent_found = true;
                break;
            }
        }
        if (!parent_found) return STM_ECORRUPT;
    }

    /* Pass 2: cycle detection — every present slot's parent chain must
     * reach root within ≤ shadow_len steps. */
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const dataset_slot *si = &lc->shadow_slots[i];
        if (!si->present) continue;
        uint64_t cur = si->e.id;
        bool reached_root = false;
        for (size_t hops = 0; hops <= lc->shadow_len; hops++) {
            if (cur == STM_DATASET_ROOT_ID) { reached_root = true; break; }
            if (cur == STM_DATASET_NO_PARENT) return STM_ECORRUPT;
            bool found = false;
            for (size_t j = 0; j < lc->shadow_len; j++) {
                if (lc->shadow_slots[j].e.id == cur) {
                    cur = lc->shadow_slots[j].e.parent_id;
                    found = true;
                    break;
                }
            }
            if (!found) return STM_ECORRUPT;
        }
        if (!reached_root) return STM_ECORRUPT;  /* cycle */
    }

    /* Pass 3: sibling-name uniqueness (per parent_id). */
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const dataset_slot *si = &lc->shadow_slots[i];
        if (!si->present) continue;
        for (size_t j = i + 1; j < lc->shadow_len; j++) {
            const dataset_slot *sj = &lc->shadow_slots[j];
            if (!sj->present) continue;
            if (si->e.parent_id != sj->e.parent_id) continue;
            if (si->e.name_len != sj->e.name_len) continue;
            if (memcmp(si->e.name, sj->e.name, si->e.name_len) == 0)
                return STM_ECORRUPT;
        }
    }

    return STM_OK;
}

stm_status stm_dataset_index_load_at(stm_dataset_index *idx,
                                        uint64_t root_paddr, uint64_t root_gen,
                                        const uint8_t expected_csum[32]) {
    if (!idx || !expected_csum) return STM_EINVAL;
    if (root_paddr == 0) return STM_EINVAL;
    must_lock(&idx->lock);
    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;
    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) {
        must_unlock(&idx->lock);
        return ts;
    }

    ds_store_ctx       sc = ds_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = ds_make_crypt_ctx(idx);

    stm_status ds = stm_btree_store_deserialize(t, root_paddr, root_gen,
                                                   expected_csum,
                                                   &DS_STORE_VT, &sc, &cx);
    if (ds != STM_OK) {
        stm_btree_mt_free(t);
        must_unlock(&idx->lock);
        return ds;
    }

    ds_load_ctx lc = {0};
    stm_status sr = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                         ds_load_iter, &lc);
    stm_btree_mt_free(t);

    if (sr != STM_OK) {
        free(lc.shadow_slots);
        must_unlock(&idx->lock);
        return sr;
    }
    if (lc.err != STM_OK) {
        free(lc.shadow_slots);
        must_unlock(&idx->lock);
        return lc.err;
    }
    /* Every legitimate persisted index includes id=1. Missing root =
     * corruption / tamper; refusing here keeps post-load_at invariants
     * identical to fresh-create. */
    if (!lc.saw_root) {
        free(lc.shadow_slots);
        must_unlock(&idx->lock);
        return STM_ECORRUPT;
    }

    /* R31 P2-2 + P2-3: full structural validation against dataset.tla
     * invariants before committing to in-RAM state. */
    stm_status vs = ds_validate_shadow(&lc);
    if (vs != STM_OK) {
        free(lc.shadow_slots);
        must_unlock(&idx->lock);
        return vs;
    }

    /* Atomic swap: replace in-RAM slots[] with the validated shadow. */
    free(idx->slots);
    idx->slots     = lc.shadow_slots;
    idx->slots_len = lc.shadow_len;
    idx->slots_cap = lc.shadow_cap;
    memcpy(idx->pool_default, lc.shadow_pool_default,
           sizeof idx->pool_default);

    /* Seed next_id past the highest decoded id; sync.c may further
     * advance via stm_dataset_index_set_next_id from ub_next_dataset_id
     * (which can be ahead if a Destroy happened post-Create-with-skip). */
    if (lc.max_present_id < UINT64_MAX) {
        idx->next_id = lc.max_present_id + 1;
    }

    /* R31 P2-1: keep current_txg ≥ max(created_txg) so post-mount
     * Create's created_txg = current_txg + 1 stamps a value strictly
     * greater than every loaded slot's created_txg
     * (dataset.tla::BirthTxgMonotonic). */
    if (lc.max_created_txg > idx->current_txg) {
        idx->current_txg = lc.max_created_txg;
    }

    idx->root_paddr = root_paddr;
    idx->root_gen   = root_gen;
    memcpy(idx->root_csum, expected_csum, 32);
    idx->dirty = false;

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_dataset_index_verify(const stm_dataset_index *idx) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_t *lock = dataset_lock(idx);
    must_lock(lock);
    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    if (idx->root_paddr == 0) {
        must_unlock(lock);
        return STM_OK;   /* no commit yet */
    }
    /* The store-context structs aren't const-friendly; we hold the lock
     * for the duration so the cast is benign. */
    ds_store_ctx       sc = ds_make_store_ctx((stm_dataset_index *)idx);
    stm_btree_crypt_ctx cx = ds_make_crypt_ctx(idx);
    stm_status vs = stm_btree_store_verify(idx->root_paddr, idx->root_gen,
                                              idx->root_csum,
                                              &DS_STORE_VT, &sc, &cx);
    must_unlock(lock);
    return vs;
}
