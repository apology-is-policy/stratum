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

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/btree.h>
#include <stratum/btree_store.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/*
 * R29 self-audit P1 (also affects dataset module): ERRORCHECK pthread
 * mutex returns EDEADLK on reentry-from-same-thread, but if the
 * caller doesn't check the return code the inner lock call proceeds
 * unsafely AND the inner unlock releases the OUTER's lock claim,
 * exposing state to concurrent writers. We use ERRORCHECK to surface
 * contract violations (iter callback re-entering a public API) as
 * a hard abort rather than a silent race or silent hang.
 */
static inline void must_lock(pthread_mutex_t *m) {
    int rc = pthread_mutex_lock(m);
    if (rc != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    int rc = pthread_mutex_unlock(m);
    if (rc != 0) abort();
}

typedef struct {
    stm_snapshot_entry e;
    bool               present;

    /* P6-deadlist: per-snapshot incremental dead-list (dead_list.tla).
     * Owned by the slot; freed in close + load_at + delete (transferred
     * to caller). dead_count <= dead_capacity <= STM_SNAP_DEAD_LIST_MAX.
     * NULL/0 for slots with no overwrites. */
    uint64_t          *dead_list;
    size_t             dead_count;
    size_t             dead_capacity;
} snapshot_slot;

struct stm_snapshot_index {
    pthread_mutex_t lock;
    snapshot_slot  *slots;
    size_t          slots_len;
    size_t          slots_cap;
    uint64_t        next_id;       /* monotonic; starts at 1 */
    uint64_t        current_txg;

    /* ----- Persistence (P6-persist), mirrors stm_dataset_index. ----- */
    stm_bdev       *bdev;
    stm_bootstrap  *boot;
    const uint8_t  *metadata_key;
    uint64_t        pool_uuid[2];
    uint64_t        device_uuid[2];
    bool            crypt_set;
    uint64_t        root_paddr;
    uint64_t        root_gen;
    uint8_t         root_csum[32];
    bool            dirty;

    /* ----- Clone-dependency hook (P6-clone). ----- */
    stm_snapshot_clone_check_cb clone_check_cb;
    void                       *clone_check_ctx;
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
 *
 * R29 P2-1: divergence from snapshot.tla. The spec persists a single
 * `most_recent_snap` variable past Delete (so a subsequent Create
 * gets `prev_snap_id = <ABSENT snap id>` and the chain walk filters
 * ABSENT links). The C impl computes most_recent dynamically and
 * skips ABSENT — so a subsequent Create gets a TIGHTER chain
 * (`prev_snap_id = previous PRESENT snap`). Both shapes satisfy
 * snapshot.tla::ChainTxgOrdered; the impl's variant produces a
 * cleaner chain with no dangling ABSENT links. The spec text could
 * be relaxed to match; deferred since safety is preserved either way.
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
    idx->dirty       = true;  /* fresh state — needs first persist */

    *out = idx;
    return STM_OK;
}

void stm_snapshot_index_close(stm_snapshot_index *idx) {
    if (!idx) return;
    pthread_mutex_destroy(&idx->lock);
    /* P6-deadlist: free per-slot dead_list arrays. */
    for (size_t i = 0; i < idx->slots_len; i++) {
        free(idx->slots[i].dead_list);
    }
    free(idx->slots);
    free(idx);
}

stm_status stm_snapshot_index_advance_txg(stm_snapshot_index *idx,
                                            uint64_t new_txg) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    /* Equal value is no-op; only strict regression refused. */
    if (new_txg < idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->current_txg = new_txg;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_index_current_txg(const stm_snapshot_index *idx,
                                             uint64_t *out_txg) {
    if (!idx || !out_txg) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    *out_txg = idx->current_txg;
    must_unlock(lock);
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

    must_lock(&idx->lock);

    /* R29 P3-1: defensive saturation on the monotonic counters.
     * UINT64_MAX is millennia away under realistic workloads, but
     * a hostile / buggy caller could push us there. Refuse cleanly
     * rather than wrap into an id collision or a backwards txg. */
    if (idx->next_id == UINT64_MAX || idx->current_txg == UINT64_MAX) {
        must_unlock(&idx->lock);
        return STM_EOVERFLOW;
    }

    if (name_taken_in_dataset_locked(idx, dataset_id,
                                       (const uint8_t *)name,
                                       (uint32_t)name_len, 0)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    uint64_t prev_snap = most_recent_locked(idx, dataset_id);

    size_t new_slot = append_slot_locked(idx);
    if (new_slot == (size_t)-1) {
        must_unlock(&idx->lock);
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
    idx->dirty = true;

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_delete(stm_snapshot_index *idx,
                                 uint64_t snapshot_id,
                                 uint64_t **out_freed_paddrs,
                                 size_t *out_freed_count) {
    if (!idx || !out_freed_paddrs || !out_freed_count) return STM_EINVAL;
    *out_freed_paddrs = NULL;
    *out_freed_count  = 0;
    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (idx->slots[s].e.hold_count > 0) {
        must_unlock(&idx->lock);
        return STM_EBUSY;
    }
    /* P6-clone: clone.tla::SnapWithClonesUndeletable. If a clone-check
     * cb is registered, refuse delete when any clone references this
     * snap. Cb runs while we hold idx->lock; cb is contract-bound NOT
     * to call back into stm_snapshot_* — it queries other modules
     * (typically the dataset index) with their own locks. */
    if (idx->clone_check_cb &&
        idx->clone_check_cb(snapshot_id, idx->clone_check_ctx)) {
        must_unlock(&idx->lock);
        return STM_EBUSY;
    }
    /* P6-deadlist: transfer the dead_list to the caller. In dead_list.tla's
     * single-ownership model, all entries are unique-and-freed; the
     * predecessor-merge step is empty so we just hand off the full list
     * for caller-side reclaim. After the transfer, the slot's dead_list
     * is NULL/0 — safe to mark ABSENT and leave to the next persist /
     * close.
     *
     * Note: we do this AFTER all the refusal checks above (hold, clone-
     * cb), so a refused delete leaves the dead_list intact. */
    snapshot_slot *slot = &idx->slots[s];
    *out_freed_paddrs   = slot->dead_list;
    *out_freed_count    = slot->dead_count;
    slot->dead_list     = NULL;
    slot->dead_count    = 0;
    slot->dead_capacity = 0;

    slot->present = false;
    idx->dirty    = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_index_overwrite_block(stm_snapshot_index *idx,
                                                 uint64_t dataset_id,
                                                 uint64_t paddr,
                                                 bool *out_should_free) {
    if (!idx || !out_should_free) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;
    if (paddr == 0) return STM_EINVAL;  /* paddr=0 reserved sentinel */
    *out_should_free = false;

    must_lock(&idx->lock);

    uint64_t mr = most_recent_locked(idx, dataset_id);
    if (mr == STM_SNAP_NO_PREV) {
        /* No PRESENT snap holds this paddr — caller frees directly per
         * dead_list.tla::OverwriteBlock with most_recent_snap = 0. */
        *out_should_free = true;
        must_unlock(&idx->lock);
        return STM_OK;
    }

    size_t s = find_slot_locked(idx, mr);
    /* most_recent_locked returns only PRESENT slots; missing ⇒ corruption. */
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ECORRUPT;
    }

    snapshot_slot *slot = &idx->slots[s];

    /* R33 P2: single-ownership defense-in-depth. dead_list.tla
     * requires that a paddr appears in at most one PRESENT snap's
     * dead_list at any time. The alloc layer's live-tracking is the
     * de-jure prevention (the same paddr is never re-issued while it
     * remains on a dead-list); this scan catches caller bugs upstream
     * before they corrupt the in-RAM index and surface only at the
     * next mount via sp_validate_shadow. Bounded by total live dead
     * entries (≤ STM_SNAP_DEAD_LIST_MAX × n_snaps). */
    for (size_t k = 0; k < idx->slots_len; k++) {
        const snapshot_slot *sk = &idx->slots[k];
        if (!sk->present) continue;
        for (size_t j = 0; j < sk->dead_count; j++) {
            if (sk->dead_list[j] == paddr) {
                must_unlock(&idx->lock);
                return STM_EINVAL;
            }
        }
    }

    if (slot->dead_count >= STM_SNAP_DEAD_LIST_MAX) {
        must_unlock(&idx->lock);
        return STM_ENOSPC;
    }

    if (slot->dead_count == slot->dead_capacity) {
        size_t new_cap = slot->dead_capacity == 0 ? 8u : slot->dead_capacity * 2u;
        if (new_cap > STM_SNAP_DEAD_LIST_MAX) new_cap = STM_SNAP_DEAD_LIST_MAX;
        uint64_t *new_buf = realloc(slot->dead_list,
                                       new_cap * sizeof(uint64_t));
        if (!new_buf) {
            must_unlock(&idx->lock);
            return STM_ENOMEM;
        }
        slot->dead_list     = new_buf;
        slot->dead_capacity = new_cap;
    }

    slot->dead_list[slot->dead_count++] = paddr;
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_dead_list_count(const stm_snapshot_index *idx,
                                           uint64_t snapshot_id,
                                           size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(lock);
        return STM_ENOENT;
    }
    *out_count = idx->slots[s].dead_count;
    must_unlock(lock);
    return STM_OK;
}

void stm_snapshot_index_set_clone_check_cb(stm_snapshot_index *idx,
                                              stm_snapshot_clone_check_cb cb,
                                              void *ctx) {
    if (!idx) return;
    must_lock(&idx->lock);
    idx->clone_check_cb  = cb;
    idx->clone_check_ctx = ctx;
    must_unlock(&idx->lock);
}

stm_status stm_snapshot_hold(stm_snapshot_index *idx,
                               uint64_t snapshot_id) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    /* hold_count is uint32_t; saturate at UINT32_MAX rather than wrap.
     * Realistic deployments will never approach 4B holds; guard
     * against a hostile caller anyway. */
    if (idx->slots[s].e.hold_count == UINT32_MAX) {
        must_unlock(&idx->lock);
        return STM_EOVERFLOW;
    }
    idx->slots[s].e.hold_count++;
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_release(stm_snapshot_index *idx,
                                  uint64_t snapshot_id) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (idx->slots[s].e.hold_count == 0) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->slots[s].e.hold_count--;
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_lookup(const stm_snapshot_index *idx,
                                 uint64_t snapshot_id,
                                 stm_snapshot_entry *out) {
    if (!idx || !out) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    size_t s = find_slot_locked(idx, snapshot_id);
    if (s == (size_t)-1 || !idx->slots[s].present) {
        must_unlock(lock);
        return STM_ENOENT;
    }
    *out = idx->slots[s].e;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_count(const stm_snapshot_index *idx,
                                size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    size_t n = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].present) n++;
    }
    *out_count = n;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_dataset_count(const stm_snapshot_index *idx,
                                         uint64_t dataset_id,
                                         size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    size_t n = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (idx->slots[i].present && idx->slots[i].e.dataset_id == dataset_id)
            n++;
    }
    *out_count = n;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_most_recent(const stm_snapshot_index *idx,
                                       uint64_t dataset_id,
                                       uint64_t *out_id) {
    if (!idx || !out_id) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    *out_id = most_recent_locked(idx, dataset_id);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_iter(const stm_snapshot_index *idx,
                               stm_snapshot_iter_cb cb, void *ctx) {
    if (!idx || !cb) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    /* Slots are appended in id-ascending order; linear walk is
     * already id-ordered. */
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (!idx->slots[i].present) continue;
        if (!cb(&idx->slots[i].e, ctx)) break;
    }
    must_unlock(lock);
    return STM_OK;
}

/* =========================================================================
 * Persistence (P6-persist).
 *
 * Mirrors src/dataset/dataset.c's persistence. Snapshot index has no
 * pool-level defaults so the keyspace is just le64 snapshot_id (≥ 1).
 * ========================================================================= */

#define SP_KEY_LEN              8u
#define SP_VAL_FIXED            44u                          /* before name[] */
#define SP_DEAD_TAIL_FIXED      4u                            /* le32 dead_count */
#define SP_DEAD_PADDR_BYTES     8u                            /* le64 paddr */
#define SP_VAL_MAX              (SP_VAL_FIXED + STM_SNAP_NAME_MAX \
                                  + SP_DEAD_TAIL_FIXED \
                                  + STM_SNAP_DEAD_LIST_MAX * SP_DEAD_PADDR_BYTES)

static void sp_encode_key(uint64_t id, uint8_t out[SP_KEY_LEN]) {
    le64 k = stm_store_le64(id);
    memcpy(out, k.v, SP_KEY_LEN);
}

static uint64_t sp_decode_key(const uint8_t in[SP_KEY_LEN]) {
    le64 k;
    memcpy(k.v, in, SP_KEY_LEN);
    return stm_load_le64(k);
}

static size_t sp_encode_value(const snapshot_slot *s,
                                 uint8_t *out, size_t out_cap) {
    size_t need = (size_t)SP_VAL_FIXED + s->e.name_len
                + SP_DEAD_TAIL_FIXED
                + (size_t)s->dead_count * SP_DEAD_PADDR_BYTES;
    if (out_cap < need) return 0;

    le64 ds   = stm_store_le64(s->e.dataset_id);
    le64 trp  = stm_store_le64(s->e.tree_root_paddr);
    le64 ctxg = stm_store_le64(s->e.created_txg);
    le64 prev = stm_store_le64(s->e.prev_snap_id);
    le32 hc   = stm_store_le32(s->e.hold_count);
    le32 fl   = stm_store_le32(s->e.flags);
    le16 nl   = stm_store_le16((uint16_t)s->e.name_len);

    memcpy(out + 0,  ds.v,   8);
    memcpy(out + 8,  trp.v,  8);
    memcpy(out + 16, ctxg.v, 8);
    memcpy(out + 24, prev.v, 8);
    memcpy(out + 32, hc.v,   4);
    memcpy(out + 36, fl.v,   4);
    memcpy(out + 40, nl.v,   2);
    /* out[42..44) is pad; zero. */
    out[42] = 0; out[43] = 0;
    if (s->e.name_len > 0) {
        memcpy(out + SP_VAL_FIXED, s->e.name, s->e.name_len);
    }

    /* P6-deadlist tail: dead_count then dead_paddrs[]. */
    size_t tail_off = (size_t)SP_VAL_FIXED + s->e.name_len;
    le32 dc = stm_store_le32((uint32_t)s->dead_count);
    memcpy(out + tail_off, dc.v, 4);
    tail_off += SP_DEAD_TAIL_FIXED;
    for (size_t i = 0; i < s->dead_count; i++) {
        le64 p = stm_store_le64(s->dead_list[i]);
        memcpy(out + tail_off, p.v, 8);
        tail_off += SP_DEAD_PADDR_BYTES;
    }
    return need;
}

static stm_status sp_decode_value(uint64_t id, const uint8_t *in,
                                     size_t in_len, snapshot_slot *out_slot) {
    if (in_len < SP_VAL_FIXED) return STM_ECORRUPT;

    le64 ds, trp, ctxg, prev;
    le32 hc, fl;
    le16 nl;
    memcpy(ds.v,   in + 0,  8);
    memcpy(trp.v,  in + 8,  8);
    memcpy(ctxg.v, in + 16, 8);
    memcpy(prev.v, in + 24, 8);
    memcpy(hc.v,   in + 32, 4);
    memcpy(fl.v,   in + 36, 4);
    memcpy(nl.v,   in + 40, 2);

    uint16_t name_len = stm_load_le16(nl);
    if (name_len > STM_SNAP_NAME_MAX) return STM_ECORRUPT;

    /* P6-deadlist: read dead_count + paddrs[] from the tail. */
    size_t tail_off = (size_t)SP_VAL_FIXED + name_len;
    if (in_len < tail_off + SP_DEAD_TAIL_FIXED) return STM_ECORRUPT;
    le32 dc;
    memcpy(dc.v, in + tail_off, 4);
    uint32_t dead_count = stm_load_le32(dc);
    if (dead_count > STM_SNAP_DEAD_LIST_MAX) return STM_ECORRUPT;
    size_t expected = tail_off + SP_DEAD_TAIL_FIXED
                    + (size_t)dead_count * SP_DEAD_PADDR_BYTES;
    if (in_len != expected) return STM_ECORRUPT;

    memset(out_slot, 0, sizeof *out_slot);
    out_slot->present              = true;
    out_slot->e.snapshot_id        = id;
    out_slot->e.dataset_id         = stm_load_le64(ds);
    out_slot->e.tree_root_paddr    = stm_load_le64(trp);
    out_slot->e.created_txg        = stm_load_le64(ctxg);
    out_slot->e.prev_snap_id       = stm_load_le64(prev);
    out_slot->e.hold_count         = stm_load_le32(hc);
    out_slot->e.flags              = stm_load_le32(fl);
    out_slot->e.name_len           = name_len;
    if (name_len > 0) {
        memcpy(out_slot->e.name, in + SP_VAL_FIXED, name_len);
    }
    out_slot->e.name[name_len] = '\0';

    if (dead_count > 0) {
        /* R33 P3-2: zero-initialized so a partial-paddr-decode error
         * leaves the buffer free of stale or partial entries that a
         * future caller might inadvertently read. */
        out_slot->dead_list = calloc((size_t)dead_count, sizeof(uint64_t));
        if (!out_slot->dead_list) return STM_ENOMEM;
        out_slot->dead_capacity = dead_count;
        out_slot->dead_count    = dead_count;
        size_t off = tail_off + SP_DEAD_TAIL_FIXED;
        for (size_t i = 0; i < dead_count; i++) {
            le64 p;
            memcpy(p.v, in + off + i * SP_DEAD_PADDR_BYTES, 8);
            out_slot->dead_list[i] = stm_load_le64(p);
            if (out_slot->dead_list[i] == 0) {
                /* paddr=0 reserved sentinel — refuse on decode. */
                free(out_slot->dead_list);
                out_slot->dead_list     = NULL;
                out_slot->dead_count    = 0;
                out_slot->dead_capacity = 0;
                return STM_ECORRUPT;
            }
        }
    }
    return STM_OK;
}

/* ---- btree_store vtable ---- */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} sp_store_ctx;

static stm_status sp_store_reserve(void *ctx_, uint64_t *out_paddr) {
    sp_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status sp_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen) {
    sp_store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status sp_store_write(void *ctx_, uint64_t paddr,
                                    const void *buf, size_t len) {
    sp_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status sp_store_read(void *ctx_, uint64_t paddr,
                                   void *buf, size_t len) {
    sp_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable SP_STORE_VT = {
    .reserve = sp_store_reserve,
    .free    = sp_store_free,
    .write   = sp_store_write,
    .read    = sp_store_read,
};

static inline sp_store_ctx sp_make_store_ctx(stm_snapshot_index *idx) {
    sp_store_ctx c = { .boot = idx->boot, .bdev = idx->bdev };
    return c;
}

static inline stm_btree_crypt_ctx sp_make_crypt_ctx(const stm_snapshot_index *idx) {
    stm_btree_crypt_ctx cx = { .metadata_key = idx->metadata_key };
    cx.pool_uuid[0]   = idx->pool_uuid[0];
    cx.pool_uuid[1]   = idx->pool_uuid[1];
    cx.device_uuid[0] = idx->device_uuid[0];
    cx.device_uuid[1] = idx->device_uuid[1];
    return cx;
}

/* ---- Public persistence API. ---- */

stm_status stm_snapshot_index_set_storage(stm_snapshot_index *idx,
                                             stm_bdev *bdev_0,
                                             stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(&idx->lock);
    idx->bdev = bdev_0;
    idx->boot = boot_0;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_snapshot_index_set_crypt_ctx(stm_snapshot_index *idx,
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

stm_status stm_snapshot_index_get_root(const stm_snapshot_index *idx,
                                          uint64_t *out_root_paddr,
                                          uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    *out_root_paddr = idx->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, idx->root_csum, 32);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_index_get_gen(const stm_snapshot_index *idx,
                                         uint64_t *out_root_gen) {
    if (!idx || !out_root_gen) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    *out_root_gen = idx->root_gen;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_index_get_next_id(const stm_snapshot_index *idx,
                                             uint64_t *out_next_id) {
    if (!idx || !out_next_id) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    *out_next_id = idx->next_id;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_snapshot_index_set_next_id(stm_snapshot_index *idx,
                                             uint64_t next_id) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    uint64_t max_present = 0;
    for (size_t i = 0; i < idx->slots_len; i++) {
        if (!idx->slots[i].present) continue;
        if (idx->slots[i].e.snapshot_id > max_present)
            max_present = idx->slots[i].e.snapshot_id;
    }
    if (next_id <= max_present) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (next_id != idx->next_id) {
        idx->next_id = next_id;
        /* No dirty flip — sourced from UB. */
    }
    must_unlock(&idx->lock);
    return STM_OK;
}

static stm_status sp_build_btree_locked(const stm_snapshot_index *idx,
                                            stm_btree_mt **out_tree) {
    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;

    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) return ts;

    uint8_t key[SP_KEY_LEN];
    uint8_t val[SP_VAL_MAX];
    for (size_t i = 0; i < idx->slots_len; i++) {
        const snapshot_slot *s = &idx->slots[i];
        if (!s->present) continue;
        sp_encode_key(s->e.snapshot_id, key);
        size_t vlen = sp_encode_value(s, val, sizeof val);
        if (vlen == 0) { stm_btree_mt_free(t); return STM_ERANGE; }
        stm_status is = stm_btree_mt_insert(t, key, SP_KEY_LEN, val, vlen);
        if (is != STM_OK) { stm_btree_mt_free(t); return is; }
    }

    *out_tree = t;
    return STM_OK;
}

stm_status stm_snapshot_index_commit(stm_snapshot_index *idx,
                                        uint64_t committed_gen,
                                        uint64_t *out_root_paddr,
                                        uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    must_lock(&idx->lock);

    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (!idx->dirty && idx->root_paddr != 0) {
        *out_root_paddr = idx->root_paddr;
        memcpy(out_root_csum, idx->root_csum, 32);
        must_unlock(&idx->lock);
        return STM_OK;
    }

    stm_btree_mt *t = NULL;
    stm_status bs = sp_build_btree_locked(idx, &t);
    if (bs != STM_OK) {
        must_unlock(&idx->lock);
        return bs;
    }

    sp_store_ctx       sc = sp_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = sp_make_crypt_ctx(idx);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(t, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &SP_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    stm_btree_mt_free(t);
    if (ss != STM_OK) {
        must_unlock(&idx->lock);
        return ss;
    }

    #define SP_ROLLBACK_RESERVE() \
        do { (void)stm_btree_store_free_tree(new_paddr, committed_gen,  \
                                                committed_gen, new_csum, \
                                                &SP_STORE_VT, &sc, &cx); \
        } while (0)

    if (idx->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(idx->root_paddr,
                                                     idx->root_gen,
                                                     committed_gen,
                                                     idx->root_csum,
                                                     &SP_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            SP_ROLLBACK_RESERVE();
            must_unlock(&idx->lock);
            return fs;
        }
    }

    stm_status bsc = stm_bootstrap_commit(idx->boot, committed_gen);
    if (bsc != STM_OK) {
        SP_ROLLBACK_RESERVE();
        must_unlock(&idx->lock);
        return bsc;
    }
    #undef SP_ROLLBACK_RESERVE

    idx->root_paddr = new_paddr;
    idx->root_gen   = committed_gen;
    memcpy(idx->root_csum, new_csum, 32);
    idx->dirty      = false;

    *out_root_paddr = new_paddr;
    memcpy(out_root_csum, new_csum, 32);
    must_unlock(&idx->lock);
    return STM_OK;
}

/* load_at — atomic shadow swap. */

typedef struct {
    snapshot_slot *shadow_slots;
    size_t         shadow_len;
    size_t         shadow_cap;
    uint64_t       max_present_id;
    /* R31 P2-1: ceiling for post-load current_txg, mirroring dataset's
     * fix. Without this, a post-mount Create stamps created_txg less
     * than persisted snaps, violating snapshot.tla::BirthTxgMonotonic. */
    uint64_t       max_created_txg;
    stm_status     err;
} sp_load_ctx;

static stm_status sp_shadow_append(sp_load_ctx *lc, const snapshot_slot *src) {
    if (lc->shadow_len == lc->shadow_cap) {
        size_t new_cap = lc->shadow_cap == 0 ? 8 : lc->shadow_cap * 2;
        snapshot_slot *new_buf = realloc(lc->shadow_slots,
                                            new_cap * sizeof(snapshot_slot));
        if (!new_buf) return STM_ENOMEM;
        lc->shadow_slots = new_buf;
        lc->shadow_cap = new_cap;
    }
    /* Shallow-copy the slot — dead_list ownership transfers from src
     * (the local in sp_load_iter) to shadow_slots[i]. Caller MUST NOT
     * free src->dead_list after this call. */
    lc->shadow_slots[lc->shadow_len++] = *src;
    return STM_OK;
}

/* P6-deadlist: free shadow_slots' per-slot dead_list arrays + the
 * shadow_slots itself. Used on every load_at error path (each shadow
 * slot owns its dead_list malloc'd by sp_decode_value). */
static void sp_shadow_free(sp_load_ctx *lc) {
    if (!lc->shadow_slots) return;
    for (size_t i = 0; i < lc->shadow_len; i++) {
        free(lc->shadow_slots[i].dead_list);
    }
    free(lc->shadow_slots);
    lc->shadow_slots = NULL;
    lc->shadow_len   = 0;
    lc->shadow_cap   = 0;
}

static int sp_load_iter(const void *k, size_t klen,
                          const void *v, size_t vlen, void *ctx_) {
    sp_load_ctx *lc = ctx_;
    if (klen != SP_KEY_LEN) {
        lc->err = STM_ECORRUPT;
        return 1;
    }
    uint64_t key = sp_decode_key(k);
    if (key == 0) {
        /* snapshot_id=0 is reserved (STM_SNAP_NO_PREV sentinel) — never
         * emitted by encode. Refuse to load such a tree. */
        lc->err = STM_ECORRUPT;
        return 1;
    }
    snapshot_slot tmp;
    stm_status dr = sp_decode_value(key, v, vlen, &tmp);
    if (dr != STM_OK) { lc->err = dr; return 1; }
    if (key > lc->max_present_id) lc->max_present_id = key;
    if (tmp.e.created_txg > lc->max_created_txg) {
        lc->max_created_txg = tmp.e.created_txg;
    }
    stm_status as = sp_shadow_append(lc, &tmp);
    if (as != STM_OK) {
        /* Append failed; ownership of tmp.dead_list never transferred,
         * so we own it and must free here. */
        free(tmp.dead_list);
        lc->err = as;
        return 1;
    }
    return 0;
}

/* R31 P2-2: structural validation of the load-at shadow. Catches
 * snapshot trees that decode byte-clean but violate snapshot.tla /
 * dead_list.tla invariants — zero ids, prev_snap_id pointing forward
 * or to wrong dataset, sibling-name collision within a dataset, or a
 * paddr appearing in two snaps' dead_lists (single-ownership
 * violation). Returns STM_ECORRUPT on any violation. */
static stm_status sp_validate_shadow(const sp_load_ctx *lc) {
    /* Per-slot checks. */
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const snapshot_slot *si = &lc->shadow_slots[i];
        if (!si->present) continue;
        if (si->e.snapshot_id == 0) return STM_ECORRUPT;
        if (si->e.dataset_id == 0)  return STM_ECORRUPT;
        if (si->e.prev_snap_id != STM_SNAP_NO_PREV) {
            /* prev must point backward (< own id) by SnapIdMonotonic
             * + ChainTxgOrdered. Forward links indicate corruption. */
            if (si->e.prev_snap_id >= si->e.snapshot_id) return STM_ECORRUPT;
            /* prev must reference a PRESENT slot of the SAME dataset.
             * (Spec allows prev to reach an ABSENT link, but we don't
             * encode ABSENT slots so a present prev_snap_id MUST resolve
             * within the shadow.) */
            bool found = false;
            for (size_t j = 0; j < lc->shadow_len; j++) {
                const snapshot_slot *sj = &lc->shadow_slots[j];
                if (sj->e.snapshot_id != si->e.prev_snap_id) continue;
                if (!sj->present) return STM_ECORRUPT;  /* shouldn't happen */
                if (sj->e.dataset_id != si->e.dataset_id) return STM_ECORRUPT;
                found = true;
                break;
            }
            if (!found) return STM_ECORRUPT;
        }
    }

    /* Sibling-name uniqueness within each dataset. */
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const snapshot_slot *si = &lc->shadow_slots[i];
        if (!si->present) continue;
        for (size_t j = i + 1; j < lc->shadow_len; j++) {
            const snapshot_slot *sj = &lc->shadow_slots[j];
            if (!sj->present) continue;
            if (si->e.dataset_id != sj->e.dataset_id) continue;
            if (si->e.name_len != sj->e.name_len) continue;
            if (memcmp(si->e.name, sj->e.name, si->e.name_len) == 0)
                return STM_ECORRUPT;
        }
    }

    /* P6-deadlist single-ownership: a paddr appears in at most one
     * snap's dead_list. Bounded by STM_SNAP_DEAD_LIST_MAX × n_snaps,
     * the O(N²) walk is fine for any plausible mount. R33 P3-4:
     * production-grade chunked dead-list (deferred) needs a sorted-
     * merge or hash-set replacement here to avoid mount-time DoS on
     * crafted-but-byte-clean trees with very-long dead-lists. */
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const snapshot_slot *si = &lc->shadow_slots[i];
        if (!si->present) continue;
        for (size_t ip = 0; ip < si->dead_count; ip++) {
            uint64_t p = si->dead_list[ip];
            for (size_t j = i; j < lc->shadow_len; j++) {
                const snapshot_slot *sj = &lc->shadow_slots[j];
                if (!sj->present) continue;
                size_t jp_start = (j == i) ? (ip + 1) : 0;
                for (size_t jp = jp_start; jp < sj->dead_count; jp++) {
                    if (sj->dead_list[jp] == p) return STM_ECORRUPT;
                }
            }
        }
    }

    return STM_OK;
}

stm_status stm_snapshot_index_load_at(stm_snapshot_index *idx,
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

    sp_store_ctx       sc = sp_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = sp_make_crypt_ctx(idx);

    stm_status ds = stm_btree_store_deserialize(t, root_paddr, root_gen,
                                                   expected_csum,
                                                   &SP_STORE_VT, &sc, &cx);
    if (ds != STM_OK) {
        stm_btree_mt_free(t);
        must_unlock(&idx->lock);
        return ds;
    }

    sp_load_ctx lc = {0};
    stm_status sr = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                         sp_load_iter, &lc);
    stm_btree_mt_free(t);

    if (sr != STM_OK) {
        sp_shadow_free(&lc);
        must_unlock(&idx->lock);
        return sr;
    }
    if (lc.err != STM_OK) {
        sp_shadow_free(&lc);
        must_unlock(&idx->lock);
        return lc.err;
    }
    /* R31 P2-2: structural validation. */
    stm_status vs = sp_validate_shadow(&lc);
    if (vs != STM_OK) {
        sp_shadow_free(&lc);
        must_unlock(&idx->lock);
        return vs;
    }

    /* Atomic swap. P6-deadlist: free OLD slots' dead_list arrays before
     * dropping the OLD slots[] backing store. */
    for (size_t i = 0; i < idx->slots_len; i++) {
        free(idx->slots[i].dead_list);
    }
    free(idx->slots);
    idx->slots     = lc.shadow_slots;
    idx->slots_len = lc.shadow_len;
    idx->slots_cap = lc.shadow_cap;

    if (lc.max_present_id < UINT64_MAX) {
        idx->next_id = lc.max_present_id + 1;
    }

    /* R31 P2-1: keep current_txg ≥ max(created_txg) per
     * snapshot.tla::BirthTxgMonotonic. */
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

stm_status stm_snapshot_index_verify(const stm_snapshot_index *idx) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_t *lock = snap_lock(idx);
    must_lock(lock);
    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    if (idx->root_paddr == 0) {
        must_unlock(lock);
        return STM_OK;
    }
    sp_store_ctx       sc = sp_make_store_ctx((stm_snapshot_index *)idx);
    stm_btree_crypt_ctx cx = sp_make_crypt_ctx(idx);
    stm_status vs = stm_btree_store_verify(idx->root_paddr, idx->root_gen,
                                              idx->root_csum,
                                              &SP_STORE_VT, &sc, &cx);
    must_unlock(lock);
    return vs;
}
