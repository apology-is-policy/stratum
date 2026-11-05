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
    uint64_t gen;         /* the inode incarnation the lock is on */
    uint64_t owner_id;
    uint64_t client;      /* whose share it counts against; 0 = no one's */
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
        /* R90 P3-8: refuse the degenerate empty range [UINT64_MAX,
         * UINT64_MAX) — Linux fcntl returns EINVAL for
         * `l_start=UINT64_MAX, l_len=0`. */
        if (off == UINT64_MAX) return STM_EINVAL;
        *out_end = UINT64_MAX;
        return STM_OK;
    }
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;
    *out_end = off + len;
    return STM_OK;
}

/* Check whether `cand` conflicts with `other` per the locks.tla
 * Conflicts predicate: overlap AND different owner AND at-least-one-
 * exclusive. Same-owner overlap never conflicts: the owner's own
 * request replaces what it held there. */
static bool conflicts(const lock_record *cand, const lock_record *other) {
    if (cand->dataset_id != other->dataset_id) return false;
    if (cand->ino        != other->ino)        return false;
    if (cand->gen        != other->gen)        return false;
    if (!ranges_overlap(cand->off, cand->end, other->off, other->end))
        return false;
    if (cand->owner_id == other->owner_id) return false;
    if (cand->type != STM_LOCK_EXCLUSIVE &&
        other->type != STM_LOCK_EXCLUSIVE) return false;
    return true;
}

/* Grow records[] so `extra` more records fit without another
 * allocation, so a request that passed its checks cannot fail half
 * done (caller holds lock). */
static stm_status reserve_records(stm_lock_table *t, size_t extra) {
    if (t->n_records + extra <= t->cap_records) return STM_OK;
    size_t want = t->cap_records ? t->cap_records : 8u;
    while (want < t->n_records + extra) {
        if (want > (SIZE_MAX / sizeof *t->records) / 2u) return STM_ENOMEM;
        want *= 2u;
    }
    lock_record *grown = realloc(t->records, want * sizeof *grown);
    if (!grown) return STM_ENOMEM;
    t->records     = grown;
    t->cap_records = want;
    return STM_OK;
}

/* Drop every record marked dead (owner_id 0, never a live owner:
 * acquire and release refuse it), keeping the survivors' order. */
static void compact_dead(stm_lock_table *t) {
    size_t kept = 0;
    for (size_t i = 0; i < t->n_records; i++) {
        if (t->records[i].owner_id == 0u) continue;
        if (kept != i) t->records[kept] = t->records[i];
        kept++;
    }
    t->n_records = kept;
}

/* The bound check both mutators share: `owner_n` records held by the
 * owner now, and a request that adds `added` and removes `removed`. */
static stm_status within_bounds(const stm_lock_table *t, size_t owner_n,
                                size_t added, size_t removed) {
    if (added <= removed) return STM_OK;
    size_t grow = added - removed;
    if (owner_n + grow > STM_LOCK_MAX_PER_OWNER) return STM_ENOLCK;
    if (t->n_records + grow > STM_LOCK_MAX_RECORDS) return STM_ENOLCK;
    return STM_OK;
}

/* The same for a client's share: `client_n` records of its now, and a request
 * that writes `added` for it and removes `removed` of its own. */
static stm_status within_client_bound(uint64_t client, size_t client_n,
                                      size_t added, size_t removed) {
    if (client == 0u || added <= removed) return STM_OK;
    if (client_n + (added - removed) > STM_LOCK_MAX_PER_CLIENT)
        return STM_ENOLCK;
    return STM_OK;
}

stm_status stm_lock_acquire(stm_lock_table *t,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t gen,
                                  uint64_t owner_id, uint8_t type,
                                  uint64_t off, uint64_t len) {
    return stm_lock_acquire_as(t, dataset_id, ino, gen, owner_id, 0u, type,
                               off, len);
}

stm_status stm_lock_acquire_as(stm_lock_table *t,
                                     uint64_t dataset_id, uint64_t ino,
                                     uint64_t gen,
                                     uint64_t owner_id, uint64_t client,
                                     uint8_t type,
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
        .dataset_id = dataset_id, .ino = ino, .gen = gen,
        .owner_id = owner_id, .client = client, .type = type,
        .off = off, .end = end,
    };

    /* Conflict scan, then the plan. The owner's records on one file
     * never overlap (every mutation keeps them disjoint), so a record of
     * the other type that overlaps the request leaves at most a piece on
     * each side, and only the record that crosses `off` (or `end`) can
     * leave one there. A record of the same type that overlaps or abuts
     * the request merges into it. */
    size_t owner_n = 0, removed = 0, added = 1;
    size_t client_n = 0, client_removed = 0;
    bool held = false;
    for (size_t i = 0; i < t->n_records; i++) {
        const lock_record *r = &t->records[i];
        if (conflicts(&cand, r)) {
            must_unlock(tbl_lock(t));
            return STM_EAGAIN;
        }
        if (r->client == client) client_n++;
        if (r->owner_id != owner_id) continue;
        owner_n++;
        if (r->dataset_id != dataset_id || r->ino != ino || r->gen != gen)
            continue;
        if (r->type == type) {
            if (r->off <= off && end <= r->end) held = true;
            if (r->off <= end && off <= r->end) {
                removed++;
                if (r->client == client) client_removed++;
            }
        } else if (ranges_overlap(r->off, r->end, off, end)) {
            removed++;
            if (r->client == client) client_removed++;
            if (r->off < off) added++;
            if (r->end > end) added++;
        }
    }
    /* Every byte asked for is held at that type: the request writes nothing, so
     * no bound applies, and the record keeps the client that paid for it. */
    if (held) {
        must_unlock(tbl_lock(t));
        return STM_OK;
    }
    stm_status s = within_bounds(t, owner_n, added, removed);
    if (s == STM_OK)
        s = within_client_bound(client, client_n, added, client_removed);
    if (s == STM_OK) s = reserve_records(t, added);
    if (s != STM_OK) {
        must_unlock(tbl_lock(t));
        return s;
    }

    /* Apply. Pieces append past n0, so the scan below never meets them;
     * the replaced records are marked dead and compacted after. */
    size_t n0 = t->n_records;
    for (size_t i = 0; i < n0; i++) {
        lock_record *r = &t->records[i];
        if (r->owner_id != owner_id || r->dataset_id != dataset_id ||
            r->ino != ino || r->gen != gen)
            continue;
        if (r->type == type) {
            if (!(r->off <= end && off <= r->end)) continue;
            if (r->off < cand.off) cand.off = r->off;
            if (r->end > cand.end) cand.end = r->end;
        } else {
            if (!ranges_overlap(r->off, r->end, off, end)) continue;
            if (r->off < off) {
                lock_record left = *r;
                left.end = off;
                left.client = client;
                t->records[t->n_records++] = left;
            }
            if (r->end > end) {
                lock_record right = *r;
                right.off = end;
                right.client = client;
                t->records[t->n_records++] = right;
            }
        }
        r->owner_id = 0u;
    }
    t->records[t->n_records++] = cand;
    compact_dead(t);

    must_unlock(tbl_lock(t));
    return STM_OK;
}

/* A release's pieces keep their record's client, so only a record spanning the
 * range grows a client's share, by one piece. A release reaches every incarnation
 * and an owner's records are disjoint on one only, so several can span. */
static stm_status spans_within_client_bounds(const stm_lock_table *t,
                                             uint64_t dataset_id, uint64_t ino,
                                             uint64_t owner_id,
                                             uint64_t off, uint64_t end) {
    for (size_t i = 0; i < t->n_records; i++) {
        const lock_record *r = &t->records[i];
        if (r->owner_id != owner_id || r->dataset_id != dataset_id ||
            r->ino != ino || !(r->off < off && r->end > end))
            continue;
        size_t client_n = 0, spans = 0;
        for (size_t j = 0; j < t->n_records; j++) {
            const lock_record *q = &t->records[j];
            if (q->client != r->client) continue;
            client_n++;
            if (q->owner_id == owner_id && q->dataset_id == dataset_id &&
                q->ino == ino && q->off < off && q->end > end)
                spans++;
        }
        stm_status s = within_client_bound(r->client, client_n, 2u * spans, spans);
        if (s != STM_OK) return s;
    }
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

    /* Every incarnation: a release asks no identity (the 9P UNLCK path). */
    size_t owner_n = 0, removed = 0, added = 0;
    bool spanned = false;
    for (size_t i = 0; i < t->n_records; i++) {
        const lock_record *r = &t->records[i];
        if (r->owner_id != owner_id) continue;
        owner_n++;
        if (r->dataset_id != dataset_id || r->ino != ino) continue;
        if (!ranges_overlap(r->off, r->end, off, end)) continue;
        removed++;
        if (r->off < off) added++;
        if (r->end > end) added++;
        if (r->off < off && r->end > end) spanned = true;
    }
    stm_status s = within_bounds(t, owner_n, added, removed);
    if (s == STM_OK && spanned)
        s = spans_within_client_bounds(t, dataset_id, ino, owner_id, off, end);
    if (s == STM_OK) s = reserve_records(t, added);
    if (s != STM_OK) {
        must_unlock(tbl_lock(t));
        return s;
    }

    size_t n0 = t->n_records;
    for (size_t i = 0; i < n0; i++) {
        lock_record *r = &t->records[i];
        if (r->owner_id != owner_id || r->dataset_id != dataset_id ||
            r->ino != ino || !ranges_overlap(r->off, r->end, off, end))
            continue;
        if (r->off < off) {
            lock_record left = *r;
            left.end = off;
            t->records[t->n_records++] = left;
        }
        if (r->end > end) {
            lock_record right = *r;
            right.off = end;
            t->records[t->n_records++] = right;
        }
        r->owner_id = 0u;
    }
    compact_dead(t);

    must_unlock(tbl_lock(t));
    return STM_OK;
}

stm_status stm_lock_test(const stm_lock_table *t,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t gen,
                              uint64_t owner_id, uint8_t type,
                              uint64_t off, uint64_t len,
                              bool *out_would_grant,
                              stm_lock_conflict *out_conflict) {
    if (out_would_grant) *out_would_grant = false;
    if (out_conflict) memset(out_conflict, 0, sizeof *out_conflict);
    if (!t || !out_would_grant) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u || owner_id == 0u) return STM_EINVAL;
    if (type != STM_LOCK_SHARED && type != STM_LOCK_EXCLUSIVE)
        return STM_EINVAL;
    uint64_t end = 0;
    stm_status ns = normalize_range(off, len, &end);
    if (ns != STM_OK) return ns;

    must_lock(tbl_lock(t));

    lock_record cand = {
        .dataset_id = dataset_id, .ino = ino, .gen = gen,
        .owner_id = owner_id, .type = type,
        .off = off, .end = end,
    };

    for (size_t i = 0; i < t->n_records; i++) {
        const lock_record *r = &t->records[i];
        if (conflicts(&cand, r)) {
            *out_would_grant = false;
            if (out_conflict) {
                out_conflict->owner_id = r->owner_id;
                out_conflict->type     = r->type;
                out_conflict->off      = r->off;
                out_conflict->end      = r->end;
            }
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

stm_status stm_lock_release_ino(stm_lock_table *t, uint64_t dataset_id,
                                uint64_t ino) {
    if (!t) return STM_EINVAL;

    must_lock(tbl_lock(t));

    size_t kept = 0;
    for (size_t i = 0; i < t->n_records; i++) {
        if (t->records[i].dataset_id == dataset_id &&
            t->records[i].ino == ino) continue;
        if (kept != i) t->records[kept] = t->records[i];
        kept++;
    }
    t->n_records = kept;

    must_unlock(tbl_lock(t));
    return STM_OK;
}

stm_status stm_lock_count(const stm_lock_table *t, size_t *out_count) {
    /* R90 P3-1: uniform out-param zero-init contract — set
     * `*out_count = 0` BEFORE arg validation so callers observing
     * on STM_EINVAL see a defined value (R57 P3-5 / R58 P3-1
     * pattern). The fs-level wrapper already does this; the
     * underlying primitive should match. */
    if (out_count) *out_count = 0;
    if (!t || !out_count) return STM_EINVAL;
    must_lock(tbl_lock(t));
    *out_count = t->n_records;
    must_unlock(tbl_lock(t));
    return STM_OK;
}

stm_status stm_lock_snapshot(const stm_lock_table *t,
                             stm_lock_record_view *out, size_t cap,
                             size_t *out_n) {
    if (out_n) *out_n = 0;
    if (!t || !out_n || (cap && !out)) return STM_EINVAL;
    must_lock(tbl_lock(t));
    for (size_t i = 0; i < t->n_records && i < cap; i++) {
        const lock_record *r = &t->records[i];
        out[i] = (stm_lock_record_view){
            .dataset_id = r->dataset_id, .ino = r->ino, .gen = r->gen,
            .owner_id = r->owner_id, .type = r->type,
            .off = r->off, .end = r->end, .client = r->client,
        };
    }
    *out_n = t->n_records;
    must_unlock(tbl_lock(t));
    return STM_OK;
}
