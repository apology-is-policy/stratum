/* SPDX-License-Identifier: ISC */
/*
 * Per-dataset snapshot index.
 *
 *   see include/stratum/snapshot.h — public API + invariants.
 *   see v2/specs/snapshot.tla — formal model.
 *
 * In-RAM linear-array implementation analogous to src/dataset/dataset.c.
 * Slots are append-only — Delete marks ABSENT, the slot stays.
 * Persistent storage (ub_snap_root + btree_store) is a follow-on chunk.
 */
#include <stratum/snapshot.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    stm_snapshot_entry e;
    bool               present;
} snapshot_slot;

struct stm_snapshot_index {
    pthread_mutex_t lock;
    snapshot_slot  *slots;
    size_t          slots_len;
    size_t          slots_cap;
    uint64_t        next_id;       /* monotonic; starts at 1 */
    uint64_t        current_txg;
};

/*
 * Cast away const on idx->lock for pthread_mutex_*. Safe per POSIX —
 * mutex is logically a separate state component from the data, and
 * read-only API methods (lookup/count/iter) still need exclusive
 * access to serialize against concurrent writers.
 */
static inline pthread_mutex_t *snap_lock(const stm_snapshot_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* Internal helpers (caller must hold idx->lock).                     */
/* ------------------------------------------------------------------ */

static size_t find_slot_locked(const stm_snapshot_index *idx,
                                  uint64_t snap_id) {
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].e.snapshot_id == snap_id) return i;
    }
    return (size_t)-1;
}

/*
 * Sibling-name uniqueness: for snapshots, "sibling" means same
 * dataset_id. Two PRESENT snapshots of the same dataset cannot share
 * a name. Across-dataset name reuse is permitted (each dataset's
 * snapshot namespace is independent).
 */
static bool name_taken_in_dataset_locked(const stm_snapshot_index *idx,
                                            uint64_t dataset_id,
                                            const uint8_t *name,
                                            uint32_t name_len,
                                            uint64_t exclude_id) {
    for (size_t i = 0; i < idx->slots_len; i++) {
        const snapshot_slot *s = &idx->slots[i];
        if (!s->present) continue;
        if (s->e.snapshot_id == exclude_id) continue;
        if (s->e.dataset_id != dataset_id) continue;
        if (s->e.name_len != name_len) continue;
        if (memcmp(s->e.name, name, name_len) == 0) return true;
    }
    return false;
}

/*
 * Find the highest-id PRESENT snapshot for a dataset. Walks the
 * slots array; since slots are append-only and id-ascending, the
 * most-recent is the last PRESENT slot with matching dataset_id.
 * Returns STM_SNAP_NO_PREV if none.
 */
static uint64_t most_recent_locked(const stm_snapshot_index *idx,
                                       uint64_t dataset_id) {
    uint64_t best = STM_SNAP_NO_PREV;
    for (size_t i = 0; i < idx->slots_len; i++) {
        const snapshot_slot *s = &idx->slots[i];
        if (!s->present) continue;
        if (s->e.dataset_id != dataset_id) continue;
        if (s->e.snapshot_id > best) best = s->e.snapshot_id;
    }
    return best;
}

static size_t append_slot_locked(stm_snapshot_index *idx) {
    if (idx->slots_len == idx->slots_cap) {
        size_t new_cap = idx->slots_cap == 0 ? 8 : idx->slots_cap * 2;
        snapshot_slot *new_slots = realloc(idx->slots,
                                              new_cap * sizeof(snapshot_slot));
        if (!new_slots) return (size_t)-1;
        idx->slots = new_slots;
        idx->slots_cap = new_cap;
    }
    size_t new_idx = idx->slots_len++;
    memset(&idx->slots[new_idx], 0, sizeof(snapshot_slot));
    return new_idx;
}

/* ------------------------------------------------------------------ */
/* Public API.                                                        */
/* ------------------------------------------------------------------ */

stm_status stm_snapshot_index_create(uint64_t current_txg,
                                       stm_snapshot_index **out) {
    if (!out) return STM_EINVAL;
    *out = NULL;

    stm_snapshot_index *idx = calloc(1, sizeof(*idx));
    if (!idx) return STM_ENOMEM;

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

    idx->next_id     = 1;
    idx->current_txg = current_txg;

    *out = idx;
    return STM_OK;
}

void stm_snapshot_index_close(stm_snapshot_index *idx) {
    if (!idx) return;
    pthread_mutex_destroy(&idx->lock);
    free(idx->slots);
    free(idx);
}

stm_status stm_snapshot_index_advance_txg(stm_snapshot_index *idx,
                                            uint64_t new_txg) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_lock(&idx->lock);
    /* Equal value is no-op; only strict regression refused. */
    if (new_txg < idx->current_txg) {
        pthread_mutex_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->current_txg = new_txg;
    pthread_mutex_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_index_current_txg(const stm_snapshot_index *idx,
                                             uint64_t *out_txg) {
    if (!idx || !out_txg) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    pthread_mutex_lock(lock);
    *out_txg = idx->current_txg;
    pthread_mutex_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_create(stm_snapshot_index *idx,
                                 uint64_t dataset_id,
                                 const char *name,
                                 uint64_t tree_root_paddr,
                                 uint64_t *out_id) {
    if (!idx || !name || !out_id) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;
    *out_id = 0;
    size_t name_len = strlen(name);
    if (name_len == 0 || name_len > STM_SNAP_NAME_MAX) return STM_EINVAL;

    pthread_mutex_lock(&idx->lock);

    if (name_taken_in_dataset_locked(idx, dataset_id,
                                       (const uint8_t *)name,
                                       (uint32_t)name_len, 0)) {
        pthread_mutex_unlock(&idx->lock);
        return STM_EEXIST;
    }

    uint64_t prev_snap = most_recent_locked(idx, dataset_id);

    size_t new_slot = append_slot_locked(idx);
    if (new_slot == (size_t)-1) {
        pthread_mutex_unlock(&idx->lock);
        return STM_ENOMEM;
    }

    /* Spec: each Create bumps current_txg + stamps the new snap's
     * created_txg = post-bump current_txg. */
    idx->current_txg += 1;

    uint64_t id = idx->next_id++;
    snapshot_slot *s = &idx->slots[new_slot];
    s->e.snapshot_id     = id;
    s->e.dataset_id      = dataset_id;
    s->e.name_len        = (uint32_t)name_len;
    memcpy(s->e.name, name, name_len);
    s->e.name[name_len]  = '\0';
    s->e.tree_root_paddr = tree_root_paddr;
    s->e.created_txg     = idx->current_txg;
    s->e.prev_snap_id    = prev_snap;
    s->e.hold_count      = 0;
    s->e.flags           = 0;
    s->present           = true;

    *out_id = id;

    pthread_mutex_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_delete(stm_snapshot_index *idx,
                                 uint64_t snapshot_id) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_lock(&idx->lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        pthread_mutex_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (idx->slots[s].e.hold_count > 0) {
        pthread_mutex_unlock(&idx->lock);
        return STM_EBUSY;
    }
    idx->slots[s].present = false;
    pthread_mutex_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_hold(stm_snapshot_index *idx,
                               uint64_t snapshot_id) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_lock(&idx->lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        pthread_mutex_unlock(&idx->lock);
        return STM_ENOENT;
    }
    /* hold_count is uint32_t; saturate at UINT32_MAX rather than wrap.
     * Realistic deployments will never approach 4B holds; guard
     * against a hostile caller anyway. */
    if (idx->slots[s].e.hold_count == UINT32_MAX) {
        pthread_mutex_unlock(&idx->lock);
        return STM_EOVERFLOW;
    }
    idx->slots[s].e.hold_count++;
    pthread_mutex_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_release(stm_snapshot_index *idx,
                                  uint64_t snapshot_id) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_lock(&idx->lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        pthread_mutex_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (idx->slots[s].e.hold_count == 0) {
        pthread_mutex_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->slots[s].e.hold_count--;
    pthread_mutex_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_lookup(const stm_snapshot_index *idx,
                                 uint64_t snapshot_id,
                                 stm_snapshot_entry *out) {
    if (!idx || !out) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    pthread_mutex_lock(lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        pthread_mutex_unlock(lock);
        return STM_ENOENT;
    }
    *out = idx->slots[s].e;
    pthread_mutex_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_count(const stm_snapshot_index *idx,
                                size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    pthread_mutex_lock(lock);
    size_t n = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].present) n++;
    }
    *out_count = n;
    pthread_mutex_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_dataset_count(const stm_snapshot_index *idx,
                                         uint64_t dataset_id,
                                         size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    pthread_mutex_lock(lock);
    size_t n = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].present && idx->slots[i].e.dataset_id == dataset_id)
            n++;
    }
    *out_count = n;
    pthread_mutex_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_most_recent(const stm_snapshot_index *idx,
                                       uint64_t dataset_id,
                                       uint64_t *out_id) {
    if (!idx || !out_id) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    pthread_mutex_lock(lock);
    *out_id = most_recent_locked(idx, dataset_id);
    pthread_mutex_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_iter(const stm_snapshot_index *idx,
                               stm_snapshot_iter_cb cb, void *ctx) {
    if (!idx || !cb) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    pthread_mutex_lock(lock);
    /* Slots are appended in id-ascending order; linear walk is
     * already id-ordered. */
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (!idx->slots[i].present) continue;
        if (!cb(&idx->slots[i].e, ctx)) break;
    }
    pthread_mutex_unlock(lock);
    return STM_OK;
}
