/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — advisory lock table (P8-POSIX-7d).
 *
 * Spec: v2/specs/locks.tla. NON-BLOCKING acquire only —
 * `stm_lock_acquire` returns STM_EAGAIN on conflict; callers
 * loop or give up. Blocking F_SETLKW + deadlock detection are
 * deferred to a future sub-chunk.
 *
 * Concurrency: a single mutex serializes every operation on
 * the table. The records[] linear scan is acceptable for the
 * common case (small per-inode lock count); a future
 * optimization would index by (ds, ino).
 *
 * Audit-trigger surface: this module joins CLAUDE.md's trigger
 * list with this commit (P8-POSIX-7d substantive).
 */
#include <stratum/locks.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t dataset_id;
    uint64_t ino;
    uint64_t owner_id;
    uint8_t  type;        /* STM_LOCK_SHARED or STM_LOCK_EXCLUSIVE */
    uint64_t off;
    uint64_t end;         /* off + len normalized; UINT64_MAX for "to EOF" */
} lock_record;

struct stm_lock_table {
    pthread_mutex_t lock;
    lock_record    *records;
    size_t          n_records;
    size_t          cap_records;
};

static inline pthread_mutex_t *tbl_lock(const stm_lock_table *t) {
    return (pthread_mutex_t *)&t->lock;
}

static inline void must_lock(pthread_mutex_t *m) {
    int rc = pthread_mutex_lock(m);
    if (rc != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    int rc = pthread_mutex_unlock(m);
    if (rc != 0) abort();
}

/* Two byte-ranges [a_off, a_end) and [b_off, b_end) overlap iff
 * a_off < b_end AND b_off < a_end. */
static inline bool ranges_overlap(uint64_t a_off, uint64_t a_end,
                                       uint64_t b_off, uint64_t b_end) {
    return a_off < b_end && b_off < a_end;
}

stm_lock_table *stm_lock_table_create(void) {
    stm_lock_table *t = calloc(1, sizeof *t);
    if (!t) return NULL;

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        free(t);
        return NULL;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        pthread_mutexattr_destroy(&attr);
        free(t);
        return NULL;
    }
    int rc = pthread_mutex_init(&t->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    if (rc != 0) {
        free(t);
        return NULL;
    }
    return t;
}

void stm_lock_table_close(stm_lock_table *t) {
    if (!t) return;
    pthread_mutex_destroy(&t->lock);
    free(t->records);
    free(t);
}

/* Validate args + normalize len=0 → end=UINT64_MAX. Returns the
 * normalized end via *out_end. */
static stm_status normalize_range(uint64_t off, uint64_t len,
                                       uint64_t *out_end) {
    if (len == 0u) {
        *out_end = UINT64_MAX;
        return STM_OK;
    }
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;
    *out_end = off + len;
    return STM_OK;
}

/* Check whether `cand` conflicts with `other` per the locks.tla
 * Conflicts predicate. Healthy: overlap AND different owner AND
 * at-least-one-exclusive. Same-owner overlap is always admitted
 * (POSIX upgrade/downgrade/stack). */
static bool conflicts(const lock_record *cand, const lock_record *other) {
    if (cand->dataset_id != other->dataset_id) return false;
    if (cand->ino        != other->ino)        return false;
    if (!ranges_overlap(cand->off, cand->end, other->off, other->end))
        return false;
    if (cand->owner_id == other->owner_id) return false;
    if (cand->type != STM_LOCK_EXCLUSIVE &&
        other->type != STM_LOCK_EXCLUSIVE) return false;
    return true;
}

/* Append (caller holds lock). Returns NULL on STM_ENOMEM. */
static lock_record *append_record(stm_lock_table *t) {
    if (t->n_records == t->cap_records) {
        if (t->cap_records > (SIZE_MAX / sizeof *t->records) / 2u)
            return NULL;
        size_t new_cap = t->cap_records ? t->cap_records * 2u : 8u;
        lock_record *grown = realloc(t->records, new_cap * sizeof *grown);
        if (!grown) return NULL;
        t->records     = grown;
        t->cap_records = new_cap;
    }
    lock_record *r = &t->records[t->n_records++];
    memset(r, 0, sizeof *r);
    return r;
}

stm_status stm_lock_acquire(stm_lock_table *t,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t owner_id, uint8_t type,
                                  uint64_t off, uint64_t len) {
    if (!t) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u || owner_id == 0u) return STM_EINVAL;
    if (type != STM_LOCK_SHARED && type != STM_LOCK_EXCLUSIVE)
        return STM_EINVAL;
    uint64_t end = 0;
    stm_status ns = normalize_range(off, len, &end);
    if (ns != STM_OK) return ns;

    must_lock(tbl_lock(t));

    lock_record cand = {
        .dataset_id = dataset_id, .ino = ino,
        .owner_id = owner_id, .type = type,
        .off = off, .end = end,
    };

    /* Conflict scan. */
    for (size_t i = 0; i < t->n_records; i++) {
        if (conflicts(&cand, &t->records[i])) {
            must_unlock(tbl_lock(t));
            return STM_EAGAIN;
        }
    }

    lock_record *r = append_record(t);
    if (!r) {
        must_unlock(tbl_lock(t));
        return STM_ENOMEM;
    }
    *r = cand;

    must_unlock(tbl_lock(t));
    return STM_OK;
}

stm_status stm_lock_release(stm_lock_table *t,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t owner_id,
                                  uint64_t off, uint64_t len) {
    if (!t) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u || owner_id == 0u) return STM_EINVAL;
    uint64_t end = 0;
    stm_status ns = normalize_range(off, len, &end);
    if (ns != STM_OK) return ns;

    must_lock(tbl_lock(t));

    /* Compact-in-place: shift surviving records down. */
    size_t kept = 0;
    for (size_t i = 0; i < t->n_records; i++) {
        const lock_record *r = &t->records[i];
        bool drop = (r->dataset_id == dataset_id &&
                     r->ino == ino &&
                     r->owner_id == owner_id &&
                     r->off == off &&
                     r->end == end);
        if (!drop) {
            if (kept != i) t->records[kept] = *r;
            kept++;
        }
    }
    t->n_records = kept;

    must_unlock(tbl_lock(t));
    return STM_OK;
}

stm_status stm_lock_test(const stm_lock_table *t,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t owner_id, uint8_t type,
                              uint64_t off, uint64_t len,
                              bool *out_would_grant,
                              uint64_t *out_conflicting_owner) {
    if (out_would_grant) *out_would_grant = false;
    if (out_conflicting_owner) *out_conflicting_owner = 0;
    if (!t || !out_would_grant) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u || owner_id == 0u) return STM_EINVAL;
    if (type != STM_LOCK_SHARED && type != STM_LOCK_EXCLUSIVE)
        return STM_EINVAL;
    uint64_t end = 0;
    stm_status ns = normalize_range(off, len, &end);
    if (ns != STM_OK) return ns;

    must_lock(tbl_lock(t));

    lock_record cand = {
        .dataset_id = dataset_id, .ino = ino,
        .owner_id = owner_id, .type = type,
        .off = off, .end = end,
    };

    for (size_t i = 0; i < t->n_records; i++) {
        if (conflicts(&cand, &t->records[i])) {
            *out_would_grant = false;
            if (out_conflicting_owner)
                *out_conflicting_owner = t->records[i].owner_id;
            must_unlock(tbl_lock(t));
            return STM_OK;
        }
    }

    *out_would_grant = true;
    must_unlock(tbl_lock(t));
    return STM_OK;
}

stm_status stm_lock_release_owner(stm_lock_table *t, uint64_t owner_id) {
    if (!t) return STM_EINVAL;
    if (owner_id == 0u) return STM_EINVAL;

    must_lock(tbl_lock(t));

    size_t kept = 0;
    for (size_t i = 0; i < t->n_records; i++) {
        if (t->records[i].owner_id == owner_id) continue;
        if (kept != i) t->records[kept] = t->records[i];
        kept++;
    }
    t->n_records = kept;

    must_unlock(tbl_lock(t));
    return STM_OK;
}

stm_status stm_lock_count(const stm_lock_table *t, size_t *out_count) {
    if (!t || !out_count) return STM_EINVAL;
    must_lock(tbl_lock(t));
    *out_count = t->n_records;
    must_unlock(tbl_lock(t));
    return STM_OK;
}
