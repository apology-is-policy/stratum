/* SPDX-License-Identifier: ISC */
/*
 * Per-pool extent index — in-RAM MVP (P7-2).
 *
 *   see include/stratum/extent.h — public API + invariants.
 *   see v2/specs/extent.tla — formal model.
 *
 * Linear-array implementation analogous to src/dataset/dataset.c.
 * Records are stored in a single dynamic array; Overwrite / Truncate /
 * DeleteFile compact the array in place. Persistent storage (per-inode
 * Bε-tree under ub_extent_root) is a follow-on chunk (P7-3).
 *
 * SPEC-TO-CODE mapping:
 *
 *   extent.tla::Init               → stm_extent_index_create
 *   extent.tla::Write              → stm_extent_write
 *   extent.tla::Overwrite          → stm_extent_overwrite
 *   extent.tla::Truncate           → stm_extent_truncate
 *   extent.tla::DeleteFile         → stm_extent_delete_file
 *   extent.tla::AdvanceTxg         → stm_extent_index_advance_txg
 *
 *   extent.tla::TypeOK             → field types in stm_extent_record
 *   extent.tla::NoOverlapWithinIno → overlap-scan in _write / _overwrite
 *   extent.tla::LengthPositive     → len ≥ 1 check in _write / _overwrite
 *   extent.tla::BirthTxgBound      → write_gen ≤ current_txg check
 *   extent.tla::AllExtentsInBounds → off + len overflow check
 *   extent.tla::PaddrFreshness     → paddr_in_use_locked scan (live-paddr
 *                                       interpretation; see header preamble)
 */
#include <stratum/extent.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Match snapshot.c's must_lock / must_unlock pattern for ERRORCHECK
 * mutex contract enforcement. Surface lock-misuse as abort, not silent
 * race. */
static inline void must_lock(pthread_mutex_t *m) {
    int rc = pthread_mutex_lock(m);
    if (rc != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    int rc = pthread_mutex_unlock(m);
    if (rc != 0) abort();
}

struct stm_extent_index {
    pthread_mutex_t       lock;
    stm_extent_record    *records;
    size_t                n_records;
    size_t                cap_records;
    uint64_t              current_txg;
};

static inline pthread_mutex_t *ex_lock(const stm_extent_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* Internal helpers (caller holds idx->lock).                         */
/* ------------------------------------------------------------------ */

/* Two byte-ranges [a_off, a_off+a_len) and [b_off, b_off+b_len) overlap
 * iff a_off < b_off+b_len AND b_off < a_off+a_len. Caller MUST have
 * validated that both ranges do not overflow uint64. */
static inline bool ranges_overlap(uint64_t a_off, uint64_t a_len,
                                     uint64_t b_off, uint64_t b_len) {
    if (a_len == 0 || b_len == 0) return false;
    return a_off < b_off + b_len && b_off < a_off + a_len;
}

static bool paddr_in_use_locked(const stm_extent_index *idx, uint64_t paddr) {
    for (size_t i = 0; i < idx->n_records; i++) {
        if (idx->records[i].paddr == paddr) return true;
    }
    return false;
}

static bool overlap_in_ino_locked(const stm_extent_index *idx,
                                     uint64_t ds, uint64_t ino,
                                     uint64_t off, uint64_t len) {
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != ds || e->ino != ino) continue;
        if (ranges_overlap(e->off, e->len, off, len)) return true;
    }
    return false;
}

/* Grow the records array if needed and append `rec`. Returns STM_OK
 * on success or STM_ENOMEM. */
static stm_status append_record_locked(stm_extent_index *idx,
                                          const stm_extent_record *rec) {
    if (idx->n_records == idx->cap_records) {
        size_t new_cap = idx->cap_records == 0 ? 8u : idx->cap_records * 2u;
        stm_extent_record *new_buf = realloc(idx->records,
                                                new_cap * sizeof(stm_extent_record));
        if (!new_buf) return STM_ENOMEM;
        idx->records     = new_buf;
        idx->cap_records = new_cap;
    }
    idx->records[idx->n_records++] = *rec;
    return STM_OK;
}

/*
 * Compact records: collect each record's paddr into out_paddrs if its
 * index appears in `drop_indices` (sorted ascending), and remove those
 * records from the array. Caller owns out_paddrs (already malloc'd of
 * size n_drops).
 */
static void remove_indices_locked(stm_extent_index *idx,
                                     const size_t *drop_indices, size_t n_drops,
                                     uint64_t *out_paddrs) {
    /* Collect dropped paddrs in input order. */
    for (size_t i = 0; i < n_drops; i++) {
        out_paddrs[i] = idx->records[drop_indices[i]].paddr;
    }

    /* Two-finger compact: skip indices in drop_indices, copy survivors
     * forward. drop_indices is sorted ascending by construction. */
    size_t write_idx = 0;
    size_t drop_cursor = 0;
    for (size_t read_idx = 0; read_idx < idx->n_records; read_idx++) {
        if (drop_cursor < n_drops && drop_indices[drop_cursor] == read_idx) {
            drop_cursor++;
            continue;
        }
        if (write_idx != read_idx) {
            idx->records[write_idx] = idx->records[read_idx];
        }
        write_idx++;
    }
    idx->n_records = write_idx;
}

/* ------------------------------------------------------------------ */
/* Lifecycle.                                                          */
/* ------------------------------------------------------------------ */

stm_status stm_extent_index_create(uint64_t current_txg,
                                      stm_extent_index **out) {
    if (!out) return STM_EINVAL;
    *out = NULL;

    stm_extent_index *idx = calloc(1, sizeof(*idx));
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

    idx->current_txg = current_txg;
    *out = idx;
    return STM_OK;
}

void stm_extent_index_close(stm_extent_index *idx) {
    if (!idx) return;
    pthread_mutex_destroy(&idx->lock);
    free(idx->records);
    free(idx);
}

stm_status stm_extent_index_current_txg(const stm_extent_index *idx,
                                           uint64_t *out_txg) {
    if (!idx || !out_txg) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    *out_txg = idx->current_txg;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_extent_index_advance_txg(stm_extent_index *idx,
                                           uint64_t new_txg) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    if (new_txg < idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->current_txg = new_txg;
    must_unlock(&idx->lock);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Mutators: Write / Overwrite / Truncate / DeleteFile.                */
/* ------------------------------------------------------------------ */

stm_status stm_extent_write(stm_extent_index *idx,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t off, uint64_t len,
                              uint64_t paddr, uint64_t write_gen) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;            /* LengthPositive */
    if (paddr == 0) return STM_EINVAL;           /* sentinel */
    /* off + len overflow guard (AllExtentsInBounds — bounds the end). */
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;                       /* BirthTxgBound */
    }
    if (paddr_in_use_locked(idx, paddr)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;                       /* PaddrFreshness */
    }
    if (overlap_in_ino_locked(idx, dataset_id, ino, off, len)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;                       /* NoOverlapWithinIno */
    }

    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .paddr = paddr, .gen = write_gen,
    };
    stm_status as = append_record_locked(idx, &rec);
    must_unlock(&idx->lock);
    return as;
}

stm_status stm_extent_overwrite(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  uint64_t new_paddr, uint64_t write_gen,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped) {
    if (!idx || !out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (new_paddr == 0) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* First pass: collect indices of overlapping extents in (ds, ino).
     * Cycle check: new_paddr must NOT match any extent we're about to
     * drop (caller bug — overwrite can't reuse the same paddr it's
     * dropping, since the allocator's NoReuseInSameGen forbids it). */
    size_t *drop_idx = NULL;
    size_t  n_drops  = 0;
    size_t  cap      = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != dataset_id || e->ino != ino) continue;
        if (!ranges_overlap(e->off, e->len, off, len)) continue;
        if (e->paddr == new_paddr) {
            free(drop_idx);
            must_unlock(&idx->lock);
            return STM_EINVAL;                   /* cycle */
        }
        if (n_drops == cap) {
            size_t new_cap = cap == 0 ? 4u : cap * 2u;
            size_t *grown = realloc(drop_idx, new_cap * sizeof(size_t));
            if (!grown) {
                free(drop_idx);
                must_unlock(&idx->lock);
                return STM_ENOMEM;
            }
            drop_idx = grown;
            cap = new_cap;
        }
        drop_idx[n_drops++] = i;
    }

    /* PaddrFreshness on new_paddr: must not collide with any LIVE
     * extent. (We've already checked it's not in the drop set, so a
     * non-dropped match is a true conflict.) */
    if (paddr_in_use_locked(idx, new_paddr)) {
        free(drop_idx);
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    /* Allocate the dropped-paddr buffer (if any drops). */
    uint64_t *out_buf = NULL;
    if (n_drops > 0) {
        out_buf = calloc(n_drops, sizeof(uint64_t));
        if (!out_buf) {
            free(drop_idx);
            must_unlock(&idx->lock);
            return STM_ENOMEM;
        }
    }

    /* Reserve append space BEFORE compacting so post-drop append never
     * fails (would leave dropped extents removed without the new one
     * inserted — atomicity violation). */
    if (idx->n_records - n_drops + 1 > idx->cap_records) {
        size_t new_cap = idx->cap_records == 0 ? 8u : idx->cap_records * 2u;
        while (new_cap < idx->n_records - n_drops + 1) new_cap *= 2u;
        stm_extent_record *grown = realloc(idx->records,
                                              new_cap * sizeof(stm_extent_record));
        if (!grown) {
            free(out_buf);
            free(drop_idx);
            must_unlock(&idx->lock);
            return STM_ENOMEM;
        }
        idx->records     = grown;
        idx->cap_records = new_cap;
    }

    /* Compact + emit dropped paddrs. */
    if (n_drops > 0) {
        remove_indices_locked(idx, drop_idx, n_drops, out_buf);
    }
    free(drop_idx);

    /* Append the new extent. Capacity reserved above so this can't
     * fail. */
    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .paddr = new_paddr, .gen = write_gen,
    };
    idx->records[idx->n_records++] = rec;

    *out_dropped_paddrs = out_buf;
    *out_n_dropped      = n_drops;
    must_unlock(&idx->lock);
    return STM_OK;
}

/* Common driver for Truncate / DeleteFile: collect drops by predicate,
 * compact, emit paddrs to caller. `keep_at_or_below` semantics:
 *   - For Truncate(new_size): drop extents with off ≥ new_size.
 *   - For DeleteFile: drop all extents (predicate matches everything in
 *     (ds, ino)).
 *
 * The predicate is encoded by the boolean `delete_all`; if not set,
 * threshold is the truncation off cutoff. Caller already validated
 * args.
 */
static stm_status drop_by_predicate_locked(stm_extent_index *idx,
                                              uint64_t ds, uint64_t ino,
                                              bool delete_all,
                                              uint64_t threshold,
                                              uint64_t **out_paddrs,
                                              size_t *out_n) {
    *out_paddrs = NULL;
    *out_n      = 0;

    size_t *drop_idx = NULL;
    size_t  n_drops  = 0;
    size_t  cap      = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != ds || e->ino != ino) continue;
        if (!delete_all && e->off < threshold) continue;
        if (n_drops == cap) {
            size_t new_cap = cap == 0 ? 4u : cap * 2u;
            size_t *grown = realloc(drop_idx, new_cap * sizeof(size_t));
            if (!grown) {
                free(drop_idx);
                return STM_ENOMEM;
            }
            drop_idx = grown;
            cap = new_cap;
        }
        drop_idx[n_drops++] = i;
    }

    if (n_drops == 0) {
        free(drop_idx);
        return STM_OK;
    }

    uint64_t *paddrs = calloc(n_drops, sizeof(uint64_t));
    if (!paddrs) {
        free(drop_idx);
        return STM_ENOMEM;
    }

    remove_indices_locked(idx, drop_idx, n_drops, paddrs);
    free(drop_idx);

    *out_paddrs = paddrs;
    *out_n      = n_drops;
    return STM_OK;
}

stm_status stm_extent_truncate(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t new_size,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped) {
    if (!idx || !out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino,
                                                /*delete_all=*/false,
                                                /*threshold=*/new_size,
                                                out_dropped_paddrs,
                                                out_n_dropped);
    must_unlock(&idx->lock);
    return rs;
}

stm_status stm_extent_delete_file(stm_extent_index *idx,
                                    uint64_t dataset_id, uint64_t ino,
                                    uint64_t **out_dropped_paddrs,
                                    size_t *out_n_dropped) {
    if (!idx || !out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino,
                                                /*delete_all=*/true,
                                                /*threshold=*/0,
                                                out_dropped_paddrs,
                                                out_n_dropped);
    must_unlock(&idx->lock);
    return rs;
}

/* ------------------------------------------------------------------ */
/* Read paths.                                                         */
/* ------------------------------------------------------------------ */

stm_status stm_extent_lookup_at(const stm_extent_index *idx,
                                   uint64_t dataset_id, uint64_t ino,
                                   uint64_t off,
                                   stm_extent_record *out_extent) {
    if (!idx || !out_extent) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    /* NoOverlapWithinIno guarantees at most one extent matches; first
     * match suffices. */
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != dataset_id || e->ino != ino) continue;
        if (off < e->off) continue;
        if (off >= e->off + e->len) continue;
        *out_extent = *e;
        must_unlock(lock);
        return STM_OK;
    }
    must_unlock(lock);
    return STM_ENOENT;
}

stm_status stm_extent_iter(const stm_extent_index *idx,
                              uint64_t dataset_id, uint64_t ino,
                              stm_extent_iter_cb cb, void *ctx) {
    if (!idx || !cb) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);

    /* Linear scan is unsorted by off; we need off-ascending. The MVP
     * builds a tiny index of matching records, sorts by off, then
     * invokes cb in order. For typical n_extents per file (small),
     * O(n log n) sort is cheap. */
    size_t  cap = 0;
    size_t  n   = 0;
    size_t *order = NULL;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != dataset_id || e->ino != ino) continue;
        if (n == cap) {
            size_t new_cap = cap == 0 ? 8u : cap * 2u;
            size_t *grown = realloc(order, new_cap * sizeof(size_t));
            if (!grown) {
                free(order);
                must_unlock(lock);
                return STM_ENOMEM;
            }
            order = grown;
            cap = new_cap;
        }
        order[n++] = i;
    }

    /* Insertion sort — n is small in the MVP (typical files: tens of
     * extents). Bounded by NoOverlap so no equality issues. */
    for (size_t i = 1; i < n; i++) {
        size_t key = order[i];
        uint64_t key_off = idx->records[key].off;
        size_t j = i;
        while (j > 0 && idx->records[order[j - 1]].off > key_off) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = key;
    }

    for (size_t i = 0; i < n; i++) {
        if (!cb(&idx->records[order[i]], ctx)) break;
    }
    free(order);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_extent_count(const stm_extent_index *idx,
                               size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    *out_count = idx->n_records;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_extent_count_for_ino(const stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    size_t n = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id == dataset_id && e->ino == ino) n++;
    }
    *out_count = n;
    must_unlock(lock);
    return STM_OK;
}
