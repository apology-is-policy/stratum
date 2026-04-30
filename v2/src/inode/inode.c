/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — inode index implementation (P8-POSIX-1).
 *
 * In-memory inode allocator + value store. Spec: v2/specs/inode.tla.
 *
 * MVP — alloc-fresh-only:
 *   - stm_inode_alloc returns next_ino[dataset_id]++; gen=0 always.
 *   - stm_inode_free flips state to FREED; record retained (preserves
 *     gen for a future P8-POSIX-1b AllocReused path).
 *   - No reuse of FREED inos in this chunk. The (ino, gen)
 *     uniqueness invariant from inode.tla holds trivially because
 *     no AllocReused path exists yet.
 *
 * Concurrency: a single mutex guards the records + next_ino arrays.
 * Ordering: this layer takes its own lock only — no cross-layer lock
 * dependencies from inode.c. The caller must not hold any other
 * inode-lock-comparable lock when calling these APIs (no current
 * candidates in the v2 tree; sync.c does not hold inode-related
 * locks at this stage).
 */
#include <stratum/inode.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Lock helpers — match the snapshot.c / extent_index.c convention:    */
/* abort on lock-misuse rather than mask a silent race.                */
/* ------------------------------------------------------------------ */

static inline void must_lock(pthread_mutex_t *m) {
    int rc = pthread_mutex_lock(m);
    if (rc != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    int rc = pthread_mutex_unlock(m);
    if (rc != 0) abort();
}

/* ------------------------------------------------------------------ */
/* Internal record / index types.                                      */
/* ------------------------------------------------------------------ */

#define STM_INODE_STATE_ALLOCATED  1u
#define STM_INODE_STATE_FREED      2u

typedef struct {
    uint64_t                 dataset_id;
    uint64_t                 ino;
    uint8_t                  state;       /* STM_INODE_STATE_* */
    struct stm_inode_value   value;
} stm_inode_record;

typedef struct {
    uint64_t dataset_id;
    uint64_t next_ino;       /* high-water mark; alloc returns this then bumps */
} stm_inode_dsstate;

struct stm_inode_index {
    pthread_mutex_t     lock;
    stm_inode_record   *records;
    size_t              n_records;
    size_t              cap_records;
    stm_inode_dsstate  *dsstate;
    size_t              n_datasets;
    size_t              cap_datasets;
};

static inline pthread_mutex_t *idx_lock(const stm_inode_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* Internal helpers (caller holds idx->lock).                          */
/* ------------------------------------------------------------------ */

/* Linear scan for a record matching (dataset_id, ino). NULL on miss. */
static stm_inode_record *find_record(stm_inode_index *idx,
                                          uint64_t dataset_id, uint64_t ino) {
    for (size_t i = 0; i < idx->n_records; i++) {
        stm_inode_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id && r->ino == ino) return r;
    }
    return NULL;
}

/* Const variant for read-only callers. */
static const stm_inode_record *find_record_c(const stm_inode_index *idx,
                                                  uint64_t dataset_id,
                                                  uint64_t ino) {
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_inode_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id && r->ino == ino) return r;
    }
    return NULL;
}

/* Linear scan for the per-dataset state. NULL on miss. */
static stm_inode_dsstate *find_dsstate(stm_inode_index *idx,
                                            uint64_t dataset_id) {
    for (size_t i = 0; i < idx->n_datasets; i++) {
        if (idx->dsstate[i].dataset_id == dataset_id) return &idx->dsstate[i];
    }
    return NULL;
}

static const stm_inode_dsstate *find_dsstate_c(const stm_inode_index *idx,
                                                    uint64_t dataset_id) {
    for (size_t i = 0; i < idx->n_datasets; i++) {
        if (idx->dsstate[i].dataset_id == dataset_id) return &idx->dsstate[i];
    }
    return NULL;
}

/* Return the dsstate slot for `dataset_id`, allocating a fresh entry
 * with next_ino=1 if absent. Returns NULL only on STM_ENOMEM. */
static stm_inode_dsstate *get_or_create_dsstate(stm_inode_index *idx,
                                                     uint64_t dataset_id) {
    stm_inode_dsstate *s = find_dsstate(idx, dataset_id);
    if (s) return s;

    if (idx->n_datasets == idx->cap_datasets) {
        size_t new_cap = idx->cap_datasets ? idx->cap_datasets * 2u : 4u;
        stm_inode_dsstate *new_arr =
                realloc(idx->dsstate, new_cap * sizeof *new_arr);
        if (!new_arr) return NULL;
        idx->dsstate     = new_arr;
        idx->cap_datasets = new_cap;
    }
    s = &idx->dsstate[idx->n_datasets++];
    s->dataset_id = dataset_id;
    s->next_ino   = 1u;          /* ino 0 reserved as "invalid" sentinel */
    return s;
}

/* Append a fresh record. Returns NULL only on STM_ENOMEM. */
static stm_inode_record *append_record(stm_inode_index *idx) {
    if (idx->n_records == idx->cap_records) {
        size_t new_cap = idx->cap_records ? idx->cap_records * 2u : 8u;
        stm_inode_record *new_arr =
                realloc(idx->records, new_cap * sizeof *new_arr);
        if (!new_arr) return NULL;
        idx->records     = new_arr;
        idx->cap_records = new_cap;
    }
    stm_inode_record *r = &idx->records[idx->n_records++];
    memset(r, 0, sizeof *r);
    return r;
}

/* ------------------------------------------------------------------ */
/* Public API.                                                         */
/* ------------------------------------------------------------------ */

stm_inode_index *stm_inode_index_create(void) {
    stm_inode_index *idx = calloc(1, sizeof *idx);
    if (!idx) return NULL;

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        free(idx);
        return NULL;
    }
    /* ERRORCHECK: surface lock-misuse as abort, not silent UB. */
    (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    int rc = pthread_mutex_init(&idx->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    if (rc != 0) {
        free(idx);
        return NULL;
    }
    return idx;
}

void stm_inode_index_close(stm_inode_index *idx) {
    if (!idx) return;
    pthread_mutex_destroy(&idx->lock);
    free(idx->records);
    free(idx->dsstate);
    free(idx);
}

stm_status stm_inode_alloc(stm_inode_index *idx, uint64_t dataset_id,
                              uint32_t mode, uint32_t uid, uint32_t gid,
                              uint64_t *out_ino) {
    if (!idx || !out_ino) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;
    if (mode == 0) return STM_EINVAL;

    *out_ino = 0;

    must_lock(idx_lock(idx));

    stm_inode_dsstate *s = get_or_create_dsstate(idx, dataset_id);
    if (!s) {
        must_unlock(idx_lock(idx));
        return STM_ENOMEM;
    }

    /* AllocFresh path: pick next_ino, bump. UINT64 overflow guard:
     * a 64-bit ino space is too large to overflow in practice but
     * fail-loud if it ever does. */
    uint64_t fresh_ino = s->next_ino;
    if (fresh_ino == UINT64_MAX) {
        must_unlock(idx_lock(idx));
        return STM_ENOSPC;
    }

    stm_inode_record *r = append_record(idx);
    if (!r) {
        must_unlock(idx_lock(idx));
        return STM_ENOMEM;
    }
    r->dataset_id = dataset_id;
    r->ino        = fresh_ino;
    r->state      = STM_INODE_STATE_ALLOCATED;
    /* Initialize the inode value. Caller is expected to stamp
     * timestamps + populate identity-specific fields via stm_inode_set
     * after alloc returns. */
    r->value.si_ino        = stm_store_le64(fresh_ino);
    r->value.si_dataset_id = stm_store_le64(dataset_id);
    r->value.si_gen        = stm_store_le64(0);             /* P8-POSIX-1: gen=0 always */
    r->value.si_mode       = stm_store_le32(mode);
    r->value.si_uid        = stm_store_le32(uid);
    r->value.si_gid        = stm_store_le32(gid);
    r->value.si_nlink      = stm_store_le32(1);
    r->value.si_data_kind  = STM_DATA_INLINE;
    r->value.si_data_len   = 0;

    s->next_ino  = fresh_ino + 1u;
    *out_ino     = fresh_ino;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_free(stm_inode_index *idx, uint64_t dataset_id,
                             uint64_t ino) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));

    stm_inode_record *r = find_record(idx, dataset_id, ino);
    if (!r || r->state != STM_INODE_STATE_ALLOCATED) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    r->state = STM_INODE_STATE_FREED;
    /* gen is preserved in r->value.si_gen so a future
     * AllocReused (P8-POSIX-1b) can bump it for the (ino, gen)
     * uniqueness invariant. */

    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_lookup(const stm_inode_index *idx,
                               uint64_t dataset_id, uint64_t ino,
                               struct stm_inode_value *out_value) {
    if (!idx || !out_value) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));

    const stm_inode_record *r = find_record_c(idx, dataset_id, ino);
    if (!r || r->state != STM_INODE_STATE_ALLOCATED) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    *out_value = r->value;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_set(stm_inode_index *idx, uint64_t dataset_id,
                            uint64_t ino,
                            const struct stm_inode_value *in_value) {
    if (!idx || !in_value) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));

    stm_inode_record *r = find_record(idx, dataset_id, ino);
    if (!r || r->state != STM_INODE_STATE_ALLOCATED) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    /* Caller-provided identity must match the record's lookup key. */
    if (stm_load_le64(in_value->si_ino) != ino) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    if (stm_load_le64(in_value->si_dataset_id) != dataset_id) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    /* Protect the (ino, gen) tuple uniqueness invariant: callers
     * cannot rewrite gen via Set. The allocator is the only path
     * that updates gen. */
    if (stm_load_le64(in_value->si_gen) != stm_load_le64(r->value.si_gen)) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    r->value = *in_value;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_count_for_ds(const stm_inode_index *idx,
                                     uint64_t dataset_id,
                                     size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;

    *out_count = 0;
    must_lock(idx_lock(idx));

    size_t count = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_inode_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id &&
            r->state == STM_INODE_STATE_ALLOCATED) count++;
    }
    *out_count = count;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_next_ino(const stm_inode_index *idx,
                                 uint64_t dataset_id,
                                 uint64_t *out_next) {
    if (!idx || !out_next) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));

    const stm_inode_dsstate *s = find_dsstate_c(idx, dataset_id);
    *out_next = s ? s->next_ino : 0u;

    must_unlock(idx_lock(idx));
    return STM_OK;
}
