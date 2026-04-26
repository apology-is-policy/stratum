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

#include <pthread.h>
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
    s->e.id          = id;
    s->e.parent_id   = parent_id;
    s->e.name_len    = (uint32_t)name_len;
    memcpy(s->e.name, name, name_len);
    s->e.name[name_len] = '\0';
    s->e.created_txg = idx->current_txg;
    s->e.flags       = 0;
    s->e.next_ino    = 0;
    s->present       = true;

    *out_id = id;

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
    idx->slots[s].e.name_len = (uint32_t)name_len;
    memcpy(idx->slots[s].e.name, new_name, name_len);
    idx->slots[s].e.name[name_len] = '\0';
    must_unlock(&idx->lock);
    return STM_OK;
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
    case STM_PROP_COMPRESS:    return STM_PROP_KIND_INHERITABLE;
    case STM_PROP_QUOTA:       return STM_PROP_KIND_NONINHERITABLE;
    case STM_PROP_ENCRYPTION:  return STM_PROP_KIND_IMMUTABLE;
    case STM_PROP_COUNT:       break;
    }
    /* Default-treat unknown / future properties as inheritable. */
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
     * malformed parent chain. */
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
    idx->pool_default[p] = value;
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
    /* IMMUTABLE properties cannot be cleared after Create. */
    if (stm_property_kind_of(p) == STM_PROP_KIND_IMMUTABLE
        && idx->slots[s].local_set[p]) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->slots[s].local_set[p] = false;
    /* Leave local_value[p] in place; it's not observed when
     * local_set[p] is FALSE. */
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
