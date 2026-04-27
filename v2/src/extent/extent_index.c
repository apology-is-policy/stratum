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

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/btree.h>
#include <stratum/btree_store.h>
#include <stratum/super.h>

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

    /* ----- Persistence (P7-3), mirrors stm_dataset_index. ----- */
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

/* True if `paddr` appears in any live extent's replica set. */
static bool paddr_in_use_locked(const stm_extent_index *idx, uint64_t paddr) {
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        for (uint8_t r = 0; r < e->n_replicas; r++) {
            if (e->paddrs[r] == paddr) return true;
        }
    }
    return false;
}

/* True if any paddr in `paddrs[0..n)` is already in some live extent's
 * replica set. P7-6 / extent.tla::LiveReplicasDisjoint. */
static bool any_paddr_in_use_locked(const stm_extent_index *idx,
                                       const uint64_t *paddrs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (paddr_in_use_locked(idx, paddrs[i])) return true;
    }
    return false;
}

/* True iff `paddrs[0..n)` are pairwise distinct and none are zero.
 * Used as the per-Write/Overwrite within-set sanity check. */
static bool replica_set_is_valid(const uint64_t *paddrs, size_t n) {
    if (n < 1 || n > STM_EXTENT_MAX_REPLICAS) return false;
    for (size_t i = 0; i < n; i++) {
        if (paddrs[i] == 0) return false;
        for (size_t j = i + 1; j < n; j++) {
            if (paddrs[i] == paddrs[j]) return false;
        }
    }
    return true;
}

/* Sum of n_replicas over the given record indices. */
static size_t total_replicas_in_drop_set(const stm_extent_index *idx,
                                            const size_t *drop_indices,
                                            size_t n_drops) {
    size_t total = 0;
    for (size_t i = 0; i < n_drops; i++) {
        total += idx->records[drop_indices[i]].n_replicas;
    }
    return total;
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
 * Compact records: flatten every dropped record's replica set into
 * out_paddrs (size = sum of n_replicas across dropped records), then
 * remove those records. drop_indices is sorted ascending. Caller owns
 * out_paddrs (already malloc'd of total-replica size).
 *
 * Returns the count written to out_paddrs.
 */
static size_t remove_indices_locked(stm_extent_index *idx,
                                       const size_t *drop_indices, size_t n_drops,
                                       uint64_t *out_paddrs) {
    /* Flatten dropped paddrs. Each dropped extent contributes
     * n_replicas paddrs, in slot-index order. */
    size_t out_idx = 0;
    for (size_t i = 0; i < n_drops; i++) {
        const stm_extent_record *e = &idx->records[drop_indices[i]];
        for (uint8_t r = 0; r < e->n_replicas; r++) {
            out_paddrs[out_idx++] = e->paddrs[r];
        }
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
    return out_idx;
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
    /* Mark dirty so the first commit persists even when no extents
     * have been written — matches the dataset / snapshot pattern.
     * The empty btree write makes ub_extent_root non-zero. */
    idx->dirty       = true;
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
    /* Equal value is no-op; only strict regression refused.
     * current_txg is NOT persisted as a standalone field — load_at
     * recomputes it from max(write_gen) — so advance_txg doesn't
     * flip dirty. Matches snapshot.c's pattern. */
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
                              const uint64_t *paddrs, size_t n_paddrs,
                              uint64_t write_gen, uint64_t key_id) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;            /* LengthPositive */
    if (!paddrs) return STM_EINVAL;
    if (!replica_set_is_valid(paddrs, n_paddrs)) return STM_EINVAL;
    /* off + len overflow guard (AllExtentsInBounds — bounds the end). */
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;                       /* BirthTxgBound */
    }
    if (any_paddr_in_use_locked(idx, paddrs, n_paddrs)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;                       /* LiveReplicasDisjoint */
    }
    if (overlap_in_ino_locked(idx, dataset_id, ino, off, len)) {
        must_unlock(&idx->lock);
        return STM_EEXIST;                       /* NoOverlapWithinIno */
    }

    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .n_replicas = (uint8_t)n_paddrs,
        .gen = write_gen,
        .key_id = key_id,
    };
    for (size_t i = 0; i < n_paddrs; i++) rec.paddrs[i] = paddrs[i];
    stm_status as = append_record_locked(idx, &rec);
    if (as == STM_OK) idx->dirty = true;
    must_unlock(&idx->lock);
    return as;
}

stm_status stm_extent_overwrite(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  const uint64_t *new_paddrs,
                                  size_t n_new_paddrs,
                                  uint64_t write_gen, uint64_t key_id,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped) {
    /* R34 P2-1: zero out-args before any early return so the header
     * "On failure, *out_dropped_paddrs is NULL and *out_n_dropped is
     * 0" contract holds even when idx==NULL but the out-arg pointers
     * are valid. */
    if (!out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (!new_paddrs) return STM_EINVAL;
    if (!replica_set_is_valid(new_paddrs, n_new_paddrs)) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* First pass: collect indices of overlapping extents in (ds, ino).
     * Cycle check: no new replica paddr may match any paddr in any
     * to-be-dropped extent's replica set (caller bug — overwrite
     * can't reuse a paddr it's dropping; allocator.tla::
     * NoReuseInSameGen forbids it for the alloc-issuance side). */
    size_t *drop_idx = NULL;
    size_t  n_drops  = 0;
    size_t  cap      = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != dataset_id || e->ino != ino) continue;
        if (!ranges_overlap(e->off, e->len, off, len)) continue;
        for (size_t k = 0; k < n_new_paddrs; k++) {
            for (uint8_t r = 0; r < e->n_replicas; r++) {
                if (e->paddrs[r] == new_paddrs[k]) {
                    free(drop_idx);
                    must_unlock(&idx->lock);
                    return STM_EINVAL;           /* cycle */
                }
            }
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

    /* LiveReplicasDisjoint on new_paddrs: none may collide with any
     * surviving (non-dropped) live extent's replica set. The drop set
     * is already cycle-checked above. */
    for (size_t k = 0; k < n_new_paddrs; k++) {
        bool in_drop = false;
        for (size_t i = 0; i < n_drops && !in_drop; i++) {
            const stm_extent_record *e = &idx->records[drop_idx[i]];
            for (uint8_t r = 0; r < e->n_replicas; r++) {
                if (e->paddrs[r] == new_paddrs[k]) { in_drop = true; break; }
            }
        }
        if (!in_drop && paddr_in_use_locked(idx, new_paddrs[k])) {
            free(drop_idx);
            must_unlock(&idx->lock);
            return STM_EEXIST;
        }
    }

    /* Total replicas across dropped extents — buffer size for the
     * flattened drop set. */
    size_t total_drops = total_replicas_in_drop_set(idx, drop_idx, n_drops);

    /* Allocate the dropped-paddr buffer (if any drops). */
    uint64_t *out_buf = NULL;
    if (total_drops > 0) {
        out_buf = calloc(total_drops, sizeof(uint64_t));
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

    /* Compact + emit dropped paddrs (flattened across replicas). */
    size_t emitted = 0;
    if (n_drops > 0) {
        emitted = remove_indices_locked(idx, drop_idx, n_drops, out_buf);
    }
    free(drop_idx);

    /* Append the new extent. Capacity reserved above so this can't
     * fail. */
    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .n_replicas = (uint8_t)n_new_paddrs,
        .gen = write_gen,
        .key_id = key_id,
    };
    for (size_t i = 0; i < n_new_paddrs; i++) rec.paddrs[i] = new_paddrs[i];
    idx->records[idx->n_records++] = rec;

    *out_dropped_paddrs = out_buf;
    *out_n_dropped      = emitted;
    idx->dirty = true;
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
 *
 * P7-6: dropped paddrs are flattened across each dropped extent's
 * full replica set.
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

    size_t total_drops = total_replicas_in_drop_set(idx, drop_idx, n_drops);
    uint64_t *paddrs = calloc(total_drops, sizeof(uint64_t));
    if (!paddrs) {
        free(drop_idx);
        return STM_ENOMEM;
    }

    size_t emitted = remove_indices_locked(idx, drop_idx, n_drops, paddrs);
    free(drop_idx);

    *out_paddrs = paddrs;
    *out_n      = emitted;
    return STM_OK;
}

stm_status stm_extent_truncate(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t new_size,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped) {
    /* R34 P2-1: zero out-args before any early return. */
    if (!out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino,
                                                /*delete_all=*/false,
                                                /*threshold=*/new_size,
                                                out_dropped_paddrs,
                                                out_n_dropped);
    if (rs == STM_OK && *out_n_dropped > 0) idx->dirty = true;
    must_unlock(&idx->lock);
    return rs;
}

/* P7-12: peek-only count of past-truncation extents + replicas. */
stm_status stm_extent_truncate_peek(const stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t new_size,
                                       size_t *out_n_extents,
                                       size_t *out_n_replicas_total) {
    if (!idx || !out_n_extents || !out_n_replicas_total) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    *out_n_extents        = 0;
    *out_n_replicas_total = 0;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != dataset_id || e->ino != ino) continue;
        if (e->off < new_size) continue;
        (*out_n_extents)++;
        *out_n_replicas_total += e->n_replicas;
    }
    must_unlock(lock);
    return STM_OK;
}

/* P7-12: drop_by_predicate variant that uses caller-provided
 * pre-allocated buffers and never allocates. Returns STM_ERANGE if
 * either cap is insufficient (atomic — index unchanged on ERANGE).
 *
 * Caller already holds idx->lock. */
static stm_status drop_by_predicate_into_locked(stm_extent_index *idx,
                                                  uint64_t ds, uint64_t ino,
                                                  bool delete_all,
                                                  uint64_t threshold,
                                                  size_t *drop_idx_buf,
                                                  size_t drop_idx_cap,
                                                  uint64_t *paddrs_buf,
                                                  size_t paddrs_cap,
                                                  size_t *out_n_dropped) {
    *out_n_dropped = 0;

    /* First pass: collect drop indices into the caller-provided
     * scratch buffer. STM_ERANGE if cap is too small — index
     * unchanged. */
    size_t n_drops = 0;
    size_t n_replicas_needed = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != ds || e->ino != ino) continue;
        if (!delete_all && e->off < threshold) continue;
        if (n_drops >= drop_idx_cap) return STM_ERANGE;
        drop_idx_buf[n_drops++] = i;
        n_replicas_needed += e->n_replicas;
    }

    if (n_replicas_needed > paddrs_cap) return STM_ERANGE;

    if (n_drops == 0) return STM_OK;

    /* Second phase: compact + emit paddrs. Reuses the existing
     * helper. The helper expects out_paddrs sized to the total
     * replicas — verified above. */
    size_t emitted = remove_indices_locked(idx, drop_idx_buf, n_drops,
                                              paddrs_buf);
    *out_n_dropped = emitted;
    return STM_OK;
}

stm_status stm_extent_truncate_into(stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t new_size,
                                       size_t *drop_idx_buf, size_t drop_idx_cap,
                                       uint64_t *paddrs_buf, size_t paddrs_cap,
                                       size_t *out_n_dropped) {
    if (!out_n_dropped) return STM_EINVAL;
    *out_n_dropped = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    /* drop_idx_buf / paddrs_buf may be NULL only when their cap is 0
     * AND no drops are expected; otherwise we'd dereference null.
     * Allow NULL+0 so a caller that peeked zero can pass NULL safely. */
    if (drop_idx_cap > 0 && !drop_idx_buf) return STM_EINVAL;
    if (paddrs_cap   > 0 && !paddrs_buf)   return STM_EINVAL;

    must_lock(&idx->lock);
    stm_status rs = drop_by_predicate_into_locked(idx, dataset_id, ino,
                                                     /*delete_all=*/false,
                                                     /*threshold=*/new_size,
                                                     drop_idx_buf, drop_idx_cap,
                                                     paddrs_buf, paddrs_cap,
                                                     out_n_dropped);
    if (rs == STM_OK && *out_n_dropped > 0) idx->dirty = true;
    must_unlock(&idx->lock);
    return rs;
}

stm_status stm_extent_delete_file(stm_extent_index *idx,
                                    uint64_t dataset_id, uint64_t ino,
                                    uint64_t **out_dropped_paddrs,
                                    size_t *out_n_dropped) {
    /* R34 P2-1: zero out-args before any early return. */
    if (!out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino,
                                                /*delete_all=*/true,
                                                /*threshold=*/0,
                                                out_dropped_paddrs,
                                                out_n_dropped);
    if (rs == STM_OK && *out_n_dropped > 0) idx->dirty = true;
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

stm_status stm_extent_lookup_by_paddr(const stm_extent_index *idx,
                                          uint64_t paddr,
                                          stm_extent_record *out_extent) {
    if (!idx || !out_extent) return STM_EINVAL;
    if (paddr == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    /* P7-6: scan each extent's replica set. extent.tla::
     * LiveReplicasDisjoint guarantees no paddr appears in two live
     * extents' replicas, so first match suffices. */
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        for (uint8_t r = 0; r < e->n_replicas; r++) {
            if (e->paddrs[r] == paddr) {
                *out_extent = *e;
                must_unlock(lock);
                return STM_OK;
            }
        }
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

stm_status stm_extent_iter_ds(const stm_extent_index *idx,
                                  uint64_t dataset_id,
                                  stm_extent_iter_cb cb, void *ctx) {
    if (!idx || !cb) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);

    /* Collect every extent matching ds, then sort by (ino, off). */
    size_t  cap = 0;
    size_t  n   = 0;
    size_t *order = NULL;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *e = &idx->records[i];
        if (e->dataset_id != dataset_id) continue;
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

    /* Insertion sort by (ino, off). */
    for (size_t i = 1; i < n; i++) {
        size_t key = order[i];
        uint64_t k_ino = idx->records[key].ino;
        uint64_t k_off = idx->records[key].off;
        size_t j = i;
        while (j > 0) {
            uint64_t p_ino = idx->records[order[j - 1]].ino;
            uint64_t p_off = idx->records[order[j - 1]].off;
            bool greater = (p_ino > k_ino) ||
                           (p_ino == k_ino && p_off > k_off);
            if (!greater) break;
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

/* =========================================================================
 * Persistence (P7-3, v12; extended for replicas in P7-6, v13).
 *
 * Mirrors src/snapshot/snapshot.c's persistence section. Same envelope:
 * btree_store-encoded, AEAD-encrypted Bε-tree on device 0, with nonce
 * paddr‖gen‖pool_uuid + AD pool_uuid‖device_uuid_0. Idempotent commit
 * via internal dirty flag; atomic shadow swap on load_at; structural
 * validator on the loaded shadow before swap.
 *
 * P7-10 / v15 value layout (64 bytes):
 *
 *   off  size  field
 *     0    1   n_replicas       (u8; 1..STM_EXTENT_MAX_REPLICAS=4)
 *     1    7   reserved         (zero)
 *     8    8   paddr_0          (le64; always non-zero)
 *    16    8   paddr_1          (le64; 0 if n_replicas < 2)
 *    24    8   paddr_2          (le64; 0 if n_replicas < 3)
 *    32    8   paddr_3          (le64; 0 if n_replicas < 4)
 *    40    8   write_gen        (le64)
 *    48    4   dlen             (le32; logical byte length)
 *    52    4   clen_and_comp    (le32; low 24: stored len; high 8: comp)
 *    56    8   key_id           (le64; per-dataset DEK key_id; was xxh
 *                                  in v13/v14 — always 0 there since AEAD
 *                                  tag is integrity. The v15 decode
 *                                  treats the bytes as key_id; v14 pools
 *                                  fail at uberblock version check before
 *                                  this layer is reached.)
 * ========================================================================= */

#define EX_KEY_LEN              24u                          /* ds + ino + off */
#define EX_VAL_LEN              64u                          /* P7-6 / v13     */
/* MVP cap: 24-bit length so dlen + clen_and_comp.clen both fit without
 * compression. Production extends with chunking / per-extent integrity. */
#define EX_LEN_MAX_24BIT        UINT32_C(0x00FFFFFF)

static void ex_encode_key(uint64_t ds, uint64_t ino, uint64_t off,
                             uint8_t out[EX_KEY_LEN]) {
    le64 d = stm_store_le64(ds);
    le64 i = stm_store_le64(ino);
    le64 o = stm_store_le64(off);
    memcpy(out + 0,  d.v, 8);
    memcpy(out + 8,  i.v, 8);
    memcpy(out + 16, o.v, 8);
}

static stm_status ex_decode_key(const uint8_t *in, size_t in_len,
                                   uint64_t *ds, uint64_t *ino, uint64_t *off) {
    if (in_len != EX_KEY_LEN) return STM_ECORRUPT;
    le64 d, i, o;
    memcpy(d.v, in + 0,  8);
    memcpy(i.v, in + 8,  8);
    memcpy(o.v, in + 16, 8);
    *ds  = stm_load_le64(d);
    *ino = stm_load_le64(i);
    *off = stm_load_le64(o);
    return STM_OK;
}

static stm_status ex_encode_value(const stm_extent_record *r,
                                     uint8_t out[EX_VAL_LEN]) {
    /* MVP cap on length. dlen and clen both equal r->len — extent
     * records track LOGICAL plaintext length; AEAD tag overhead lives
     * with the allocator's per-range size tracking (stm_alloc_free
     * uses paddr alone, allocator knows the run length internally). */
    if (r->len > EX_LEN_MAX_24BIT) return STM_ERANGE;
    if (r->n_replicas < 1 || r->n_replicas > STM_EXTENT_MAX_REPLICAS)
        return STM_ECORRUPT;

    /* Zero entire buffer first so unused replica slots + reserved
     * bytes are deterministic-zero. */
    memset(out, 0, EX_VAL_LEN);

    out[0] = r->n_replicas;
    /* bytes [1..7] reserved (zero, already zeroed above). */
    for (uint8_t i = 0; i < r->n_replicas; i++) {
        if (r->paddrs[i] == 0) return STM_ECORRUPT; /* sentinel guard */
        le64 p = stm_store_le64(r->paddrs[i]);
        memcpy(out + 8 + (size_t)i * 8, p.v, 8);
    }
    /* Trailing replica slots already zero from memset. */

    le64 write_gen = stm_store_le64(r->gen);
    le32 dlen      = stm_store_le32((uint32_t)r->len);
    uint32_t clen_and_comp = (uint32_t)r->len & 0x00FFFFFFu;
    le32 cac        = stm_store_le32(clen_and_comp);
    le64 key_id_le  = stm_store_le64(r->key_id);

    memcpy(out + 40, write_gen.v, 8);
    memcpy(out + 48, dlen.v,      4);
    memcpy(out + 52, cac.v,       4);
    memcpy(out + 56, key_id_le.v, 8);
    return STM_OK;
}

static stm_status ex_decode_value(const uint8_t *in, size_t in_len,
                                     uint64_t ds, uint64_t ino, uint64_t off,
                                     stm_extent_record *out_rec) {
    if (in_len != EX_VAL_LEN) return STM_ECORRUPT;

    uint8_t n_replicas = in[0];
    if (n_replicas < 1 || n_replicas > STM_EXTENT_MAX_REPLICAS)
        return STM_ECORRUPT;
    /* bytes [1..7] reserved — must be zero (anti-tamper). */
    for (size_t i = 1; i < 8; i++) if (in[i] != 0) return STM_ECORRUPT;

    /* Decode all 4 replica slots; verify trailing slots are zero. */
    uint64_t paddrs[STM_EXTENT_MAX_REPLICAS];
    for (uint8_t i = 0; i < STM_EXTENT_MAX_REPLICAS; i++) {
        le64 p_le;
        memcpy(p_le.v, in + 8 + (size_t)i * 8, 8);
        paddrs[i] = stm_load_le64(p_le);
        if (i < n_replicas) {
            if (paddrs[i] == 0) return STM_ECORRUPT;  /* must be set */
        } else {
            if (paddrs[i] != 0) return STM_ECORRUPT;  /* must be zero */
        }
    }
    /* Within-set distinctness — no replica paddr appears twice. */
    for (uint8_t i = 0; i < n_replicas; i++) {
        for (uint8_t j = (uint8_t)(i + 1); j < n_replicas; j++) {
            if (paddrs[i] == paddrs[j]) return STM_ECORRUPT;
        }
    }

    le64 write_gen_le, key_id_le;
    le32 dlen_le, cac_le;
    memcpy(write_gen_le.v, in + 40, 8);
    memcpy(dlen_le.v,      in + 48, 4);
    memcpy(cac_le.v,       in + 52, 4);
    memcpy(key_id_le.v,    in + 56, 8);

    uint32_t dlen = stm_load_le32(dlen_le);
    uint32_t cac  = stm_load_le32(cac_le);
    uint32_t clen = cac & 0x00FFFFFFu;
    uint32_t comp = (cac >> 24) & 0xFFu;
    /* MVP: refuse non-zero comp (no compression supported). */
    if (comp != 0) return STM_ECORRUPT;
    /* MVP: clen must equal dlen (no compression). */
    if (clen != dlen) return STM_ECORRUPT;
    /* dlen must be positive (LengthPositive). */
    if (dlen == 0) return STM_ECORRUPT;

    out_rec->dataset_id = ds;
    out_rec->ino        = ino;
    out_rec->off        = off;
    out_rec->len        = (uint64_t)dlen;
    out_rec->n_replicas = n_replicas;
    for (uint8_t i = 0; i < STM_EXTENT_MAX_REPLICAS; i++) {
        out_rec->paddrs[i] = paddrs[i];
    }
    out_rec->gen        = stm_load_le64(write_gen_le);
    out_rec->key_id     = stm_load_le64(key_id_le);

    return STM_OK;
}

/* ---- btree_store vtable ---- */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} ex_store_ctx;

static stm_status ex_store_reserve(void *ctx_, uint64_t *out_paddr) {
    ex_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status ex_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen) {
    ex_store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status ex_store_write(void *ctx_, uint64_t paddr,
                                    const void *buf, size_t len) {
    ex_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status ex_store_read(void *ctx_, uint64_t paddr,
                                   void *buf, size_t len) {
    ex_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable EX_STORE_VT = {
    .reserve = ex_store_reserve,
    .free    = ex_store_free,
    .write   = ex_store_write,
    .read    = ex_store_read,
};

static inline ex_store_ctx ex_make_store_ctx(stm_extent_index *idx) {
    ex_store_ctx c = { .boot = idx->boot, .bdev = idx->bdev };
    return c;
}

static inline stm_btree_crypt_ctx ex_make_crypt_ctx(const stm_extent_index *idx) {
    stm_btree_crypt_ctx cx = { .metadata_key = idx->metadata_key };
    cx.pool_uuid[0]   = idx->pool_uuid[0];
    cx.pool_uuid[1]   = idx->pool_uuid[1];
    cx.device_uuid[0] = idx->device_uuid[0];
    cx.device_uuid[1] = idx->device_uuid[1];
    return cx;
}

/* ---- Public persistence API. ---- */

stm_status stm_extent_index_set_storage(stm_extent_index *idx,
                                           stm_bdev *bdev_0,
                                           stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(&idx->lock);
    idx->bdev = bdev_0;
    idx->boot = boot_0;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_index_set_crypt_ctx(stm_extent_index *idx,
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

stm_status stm_extent_index_get_root(const stm_extent_index *idx,
                                        uint64_t *out_root_paddr,
                                        uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    *out_root_paddr = idx->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, idx->root_csum, 32);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_extent_index_get_gen(const stm_extent_index *idx,
                                       uint64_t *out_root_gen) {
    if (!idx || !out_root_gen) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    *out_root_gen = idx->root_gen;
    must_unlock(lock);
    return STM_OK;
}

static stm_status ex_build_btree_locked(const stm_extent_index *idx,
                                           stm_btree_mt **out_tree) {
    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;

    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) return ts;

    uint8_t key[EX_KEY_LEN];
    uint8_t val[EX_VAL_LEN];
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_extent_record *r = &idx->records[i];
        ex_encode_key(r->dataset_id, r->ino, r->off, key);
        stm_status es = ex_encode_value(r, val);
        if (es != STM_OK) { stm_btree_mt_free(t); return es; }
        stm_status is = stm_btree_mt_insert(t, key, EX_KEY_LEN, val, EX_VAL_LEN);
        if (is != STM_OK) { stm_btree_mt_free(t); return is; }
    }

    *out_tree = t;
    return STM_OK;
}

stm_status stm_extent_index_commit(stm_extent_index *idx,
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
    stm_status bs = ex_build_btree_locked(idx, &t);
    if (bs != STM_OK) {
        must_unlock(&idx->lock);
        return bs;
    }

    ex_store_ctx       sc = ex_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = ex_make_crypt_ctx(idx);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(t, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &EX_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    stm_btree_mt_free(t);
    if (ss != STM_OK) {
        must_unlock(&idx->lock);
        return ss;
    }

    #define EX_ROLLBACK_RESERVE() \
        do { (void)stm_btree_store_free_tree(new_paddr, committed_gen,  \
                                                committed_gen, new_csum, \
                                                &EX_STORE_VT, &sc, &cx); \
        } while (0)

    if (idx->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(idx->root_paddr,
                                                     idx->root_gen,
                                                     committed_gen,
                                                     idx->root_csum,
                                                     &EX_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            EX_ROLLBACK_RESERVE();
            must_unlock(&idx->lock);
            return fs;
        }
    }

    stm_status bsc = stm_bootstrap_commit(idx->boot, committed_gen);
    if (bsc != STM_OK) {
        EX_ROLLBACK_RESERVE();
        must_unlock(&idx->lock);
        return bsc;
    }
    #undef EX_ROLLBACK_RESERVE

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
    stm_extent_record *shadow_records;
    size_t             shadow_len;
    size_t             shadow_cap;
    uint64_t           max_write_gen;
    stm_status         err;
} ex_load_ctx;

static stm_status ex_shadow_append(ex_load_ctx *lc,
                                      const stm_extent_record *r) {
    if (lc->shadow_len == lc->shadow_cap) {
        size_t new_cap = lc->shadow_cap == 0 ? 8 : lc->shadow_cap * 2;
        stm_extent_record *new_buf = realloc(lc->shadow_records,
                                                new_cap * sizeof(stm_extent_record));
        if (!new_buf) return STM_ENOMEM;
        lc->shadow_records = new_buf;
        lc->shadow_cap = new_cap;
    }
    lc->shadow_records[lc->shadow_len++] = *r;
    return STM_OK;
}

static int ex_load_iter(const void *k, size_t klen,
                          const void *v, size_t vlen, void *ctx_) {
    ex_load_ctx *lc = ctx_;
    uint64_t ds, ino, off;
    stm_status ks = ex_decode_key(k, klen, &ds, &ino, &off);
    if (ks != STM_OK) { lc->err = ks; return 1; }
    /* Zero ds / ino are reserved sentinels — refuse on decode. */
    if (ds == 0 || ino == 0) { lc->err = STM_ECORRUPT; return 1; }

    stm_extent_record r;
    stm_status vs = ex_decode_value(v, vlen, ds, ino, off, &r);
    if (vs != STM_OK) { lc->err = vs; return 1; }

    if (r.gen > lc->max_write_gen) lc->max_write_gen = r.gen;

    /* off + len overflow guard (AllExtentsInBounds). */
    if (r.off > UINT64_MAX - r.len) { lc->err = STM_ECORRUPT; return 1; }

    stm_status as = ex_shadow_append(lc, &r);
    if (as != STM_OK) { lc->err = as; return 1; }
    return 0;
}

/* Structural validator on the loaded shadow. Catches extents that
 * decode byte-clean but violate extent.tla invariants:
 *   - NoOverlapWithinIno: pairwise overlap check within each (ds, ino).
 *   - LiveReplicasDisjoint (P7-6): no paddr appears in two records'
 *     replica sets.
 * O(N² · K²) where K = STM_EXTENT_MAX_REPLICAS — fine for any plausible
 * mount. Production-grade persistence (chunked / per-inode trees)
 * revisits this with a sorted-merge strategy.
 */
static stm_status ex_validate_shadow(const ex_load_ctx *lc) {
    /* NoOverlapWithinIno + LengthPositive (already enforced at decode). */
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const stm_extent_record *a = &lc->shadow_records[i];
        for (size_t j = i + 1; j < lc->shadow_len; j++) {
            const stm_extent_record *b = &lc->shadow_records[j];
            if (a->dataset_id == b->dataset_id && a->ino == b->ino) {
                if (ranges_overlap(a->off, a->len, b->off, b->len)) {
                    return STM_ECORRUPT;
                }
            }
            /* Cross-record replica-set disjointness. */
            for (uint8_t ai = 0; ai < a->n_replicas; ai++) {
                for (uint8_t bi = 0; bi < b->n_replicas; bi++) {
                    if (a->paddrs[ai] == b->paddrs[bi]) return STM_ECORRUPT;
                }
            }
        }
    }
    return STM_OK;
}

stm_status stm_extent_index_load_at(stm_extent_index *idx,
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

    ex_store_ctx       sc = ex_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = ex_make_crypt_ctx(idx);

    stm_status ds = stm_btree_store_deserialize(t, root_paddr, root_gen,
                                                   expected_csum,
                                                   &EX_STORE_VT, &sc, &cx);
    if (ds != STM_OK) {
        stm_btree_mt_free(t);
        must_unlock(&idx->lock);
        return ds;
    }

    ex_load_ctx lc = {0};
    stm_status sr = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                         ex_load_iter, &lc);
    stm_btree_mt_free(t);

    if (sr != STM_OK) {
        free(lc.shadow_records);
        must_unlock(&idx->lock);
        return sr;
    }
    if (lc.err != STM_OK) {
        free(lc.shadow_records);
        must_unlock(&idx->lock);
        return lc.err;
    }
    stm_status vs = ex_validate_shadow(&lc);
    if (vs != STM_OK) {
        free(lc.shadow_records);
        must_unlock(&idx->lock);
        return vs;
    }

    /* Atomic swap. */
    free(idx->records);
    idx->records      = lc.shadow_records;
    idx->n_records    = lc.shadow_len;
    idx->cap_records  = lc.shadow_cap;

    /* Bump current_txg ≥ max(write_gen) per extent.tla::BirthTxgBound. */
    if (lc.max_write_gen > idx->current_txg) {
        idx->current_txg = lc.max_write_gen;
    }

    idx->root_paddr = root_paddr;
    idx->root_gen   = root_gen;
    memcpy(idx->root_csum, expected_csum, 32);
    idx->dirty = false;

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_index_verify(const stm_extent_index *idx) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    if (idx->root_paddr == 0) {
        must_unlock(lock);
        return STM_OK;
    }
    ex_store_ctx       sc = ex_make_store_ctx((stm_extent_index *)idx);
    stm_btree_crypt_ctx cx = ex_make_crypt_ctx(idx);
    stm_status vs = stm_btree_store_verify(idx->root_paddr, idx->root_gen,
                                              idx->root_csum,
                                              &EX_STORE_VT, &sc, &cx);
    must_unlock(lock);
    return vs;
}
