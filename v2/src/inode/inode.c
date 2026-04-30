/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — inode index implementation (P8-POSIX-1 + P8-POSIX-1b).
 *
 * Spec: v2/specs/inode.tla.
 *
 * P8-POSIX-1 landed the in-memory allocator (alloc-fresh-only). This
 * file extends that with:
 *
 *   - AllocReused path (P8-POSIX-1b): stm_inode_alloc prefers a
 *     FREED ino over fresh allocation, bumping si_gen by 1 on
 *     reuse. Models inode.tla's AllocReused action.
 *
 *   - On-disk persistence (P8-POSIX-1b, UB v24): per-pool inode
 *     tree backed by btree_store. Mirrors stm_extent_index's
 *     set_storage / set_crypt_ctx / load_at / commit lifecycle.
 *
 * On-disk encoding:
 *   - Key (16 bytes): le64 dataset_id || le64 ino.
 *   - Value (256 bytes): full struct stm_inode_value as defined in
 *     inode.h. FREED state is encoded inline via STM_INO_FLAG_FREED
 *     in si_flags — no separate state byte. next_ino is reconstructed
 *     at load_at time as max(ino) + 1 per dataset.
 *
 * Concurrency: a single mutex guards the records + dsstate + persistence
 * fields. Lock posture: this layer takes its own lock only — no cross-
 * layer lock dependencies. The caller (sync.c) MUST not hold any other
 * inode-comparable lock when invoking these APIs; sync.c does not.
 */
#include <stratum/inode.h>
#include <stratum/types.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btree.h>
#include <stratum/btree_store.h>
#include <stratum/super.h>

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
    uint8_t                  state;       /* STM_INODE_STATE_* (mirrors si_flags FREED bit) */
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

    /* ----- Persistence (P8-POSIX-1b, mirrors stm_extent_index). ----- */
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

/* Scan records[] for a FREED slot in dataset_id. NULL on miss. */
static stm_inode_record *find_freed_record(stm_inode_index *idx,
                                                 uint64_t dataset_id) {
    for (size_t i = 0; i < idx->n_records; i++) {
        stm_inode_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id && r->state == STM_INODE_STATE_FREED) {
            return r;
        }
    }
    return NULL;
}

/* Return the dsstate slot for `dataset_id`, allocating a fresh entry
 * with next_ino=1 if absent. Returns NULL only on STM_ENOMEM.
 *
 * realloc is called under idx->lock (R69 P3-4 acknowledged + P3-5
 * cap-doubling overflow guard). */
static stm_inode_dsstate *get_or_create_dsstate(stm_inode_index *idx,
                                                     uint64_t dataset_id) {
    stm_inode_dsstate *s = find_dsstate(idx, dataset_id);
    if (s) return s;

    if (idx->n_datasets == idx->cap_datasets) {
        if (idx->cap_datasets > SIZE_MAX / 2u) return NULL;
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
        if (idx->cap_records > SIZE_MAX / 2u) return NULL;
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
/* On-disk key/value encoding.                                         */
/*                                                                      */
/* Key: 16 bytes (le64 dataset_id || le64 ino).                        */
/* Value: 256 bytes (struct stm_inode_value).                          */
/* ------------------------------------------------------------------ */

#define IN_KEY_LEN  16u
#define IN_VAL_LEN  STM_INODE_SIZE_BYTES

static void in_encode_key(uint64_t ds, uint64_t ino, uint8_t out[IN_KEY_LEN]) {
    le64 ds_le  = stm_store_le64(ds);
    le64 ino_le = stm_store_le64(ino);
    memcpy(out + 0, &ds_le, 8);
    memcpy(out + 8, &ino_le, 8);
}

static stm_status in_decode_key(const void *in, size_t in_len,
                                    uint64_t *out_ds, uint64_t *out_ino) {
    if (in_len != IN_KEY_LEN) return STM_ECORRUPT;
    le64 ds_le, ino_le;
    memcpy(&ds_le,  (const uint8_t *)in + 0, 8);
    memcpy(&ino_le, (const uint8_t *)in + 8, 8);
    *out_ds  = stm_load_le64(ds_le);
    *out_ino = stm_load_le64(ino_le);
    return STM_OK;
}

/* Value encoding: just the 256-byte struct. The struct is already
 * packed-LE per its field types, so memcpy is a structural identity. */
static void in_encode_value(const struct stm_inode_value *v,
                                uint8_t out[IN_VAL_LEN]) {
    memcpy(out, v, IN_VAL_LEN);
}

/* Decode validates the value's identity (ino, dataset_id match the
 * key) and the FREED-flag/state contract. */
static stm_status in_decode_value(const void *in, size_t in_len,
                                      uint64_t expected_ds,
                                      uint64_t expected_ino,
                                      stm_inode_record *out) {
    if (in_len != IN_VAL_LEN) return STM_ECORRUPT;
    memcpy(&out->value, in, IN_VAL_LEN);

    /* Identity must match the key. */
    if (stm_load_le64(out->value.si_ino) != expected_ino) return STM_ECORRUPT;
    if (stm_load_le64(out->value.si_dataset_id) != expected_ds) return STM_ECORRUPT;

    /* data_kind must be one of the four known variants. */
    switch (out->value.si_data_kind) {
        case STM_DATA_EXTENT:
        case STM_DATA_INLINE:
        case STM_DATA_SYMLINK:
        case STM_DATA_DEVICE:
            break;
        default:
            return STM_ECORRUPT;
    }

    /* Reconstruct state from the FREED flag. */
    uint32_t flags = stm_load_le32(out->value.si_flags);
    out->state = (flags & STM_INO_FLAG_FREED)
            ? STM_INODE_STATE_FREED
            : STM_INODE_STATE_ALLOCATED;

    out->dataset_id = expected_ds;
    out->ino        = expected_ino;
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* btree_store vtable — same shape as extent_index's.                   */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} in_store_ctx;

static stm_status in_store_reserve(void *ctx_, uint64_t *out_paddr) {
    in_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status in_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen) {
    in_store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status in_store_write(void *ctx_, uint64_t paddr,
                                     const void *buf, size_t len) {
    in_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status in_store_read(void *ctx_, uint64_t paddr,
                                    void *buf, size_t len) {
    in_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable IN_STORE_VT = {
    .reserve = in_store_reserve,
    .free    = in_store_free,
    .write   = in_store_write,
    .read    = in_store_read,
};

static inline in_store_ctx in_make_store_ctx(stm_inode_index *idx) {
    in_store_ctx c = { .boot = idx->boot, .bdev = idx->bdev };
    return c;
}

static inline stm_btree_crypt_ctx in_make_crypt_ctx(const stm_inode_index *idx) {
    stm_btree_crypt_ctx cx = { .metadata_key = idx->metadata_key };
    cx.pool_uuid[0]   = idx->pool_uuid[0];
    cx.pool_uuid[1]   = idx->pool_uuid[1];
    cx.device_uuid[0] = idx->device_uuid[0];
    cx.device_uuid[1] = idx->device_uuid[1];
    return cx;
}

/* ------------------------------------------------------------------ */
/* Public API — lifecycle.                                             */
/* ------------------------------------------------------------------ */

stm_inode_index *stm_inode_index_create(void) {
    stm_inode_index *idx = calloc(1, sizeof *idx);
    if (!idx) return NULL;

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        free(idx);
        return NULL;
    }
    /* ERRORCHECK: surface lock-misuse as abort, not silent UB.
     * R69 P3-6: settype's failure is treated as init failure. */
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        pthread_mutexattr_destroy(&attr);
        free(idx);
        return NULL;
    }
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

/* ------------------------------------------------------------------ */
/* Public API — alloc / free / lookup / set / count / next_ino.        */
/* ------------------------------------------------------------------ */

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

    /* AllocReused path (preferred): pick a FREED record, bump gen
     * by 1, mark ALLOCATED. Models inode.tla's AllocReused action.
     * The bump preserves the (ino, gen) tuple-uniqueness invariant
     * — every distinct allocation at this ino has a strictly
     * greater gen than any prior allocation at the same ino. */
    stm_inode_record *r = find_freed_record(idx, dataset_id);
    uint64_t fresh_ino = 0;
    if (r) {
        uint64_t prior_gen = stm_load_le64(r->value.si_gen);
        if (prior_gen == UINT64_MAX) {
            /* gen would wrap on bump — refuse this slot. Fall through
             * to AllocFresh by wiping the FREED flag is unsafe (would
             * leak the slot); instead, leave it FREED and try fresh. */
            r = NULL;
        } else {
            uint64_t new_gen = prior_gen + 1u;
            /* Re-init the value: identity preserved (ino, dataset_id),
             * gen bumped, all other fields restored to alloc-fresh
             * defaults. The ino number is preserved (this IS the
             * point of reuse). */
            uint64_t reused_ino = r->ino;
            memset(&r->value, 0, sizeof r->value);
            r->state             = STM_INODE_STATE_ALLOCATED;
            r->value.si_ino      = stm_store_le64(reused_ino);
            r->value.si_dataset_id = stm_store_le64(dataset_id);
            r->value.si_gen      = stm_store_le64(new_gen);
            r->value.si_mode     = stm_store_le32(mode);
            r->value.si_uid      = stm_store_le32(uid);
            r->value.si_gid      = stm_store_le32(gid);
            r->value.si_nlink    = stm_store_le32(1);
            r->value.si_data_kind = STM_DATA_INLINE;
            r->value.si_data_len = 0;
            *out_ino             = reused_ino;
            idx->dirty           = true;
            must_unlock(idx_lock(idx));
            return STM_OK;
        }
    }

    /* AllocFresh path: ino = next_ino[ds], bump.
     * UINT64 saturation guard; UINT64_MAX is reserved as the
     * saturation sentinel per inode.h R69 P3-1 docstring. */
    fresh_ino = s->next_ino;
    if (fresh_ino == UINT64_MAX) {
        must_unlock(idx_lock(idx));
        return STM_ENOSPC;
    }

    r = append_record(idx);
    if (!r) {
        must_unlock(idx_lock(idx));
        return STM_ENOMEM;
    }
    r->dataset_id = dataset_id;
    r->ino        = fresh_ino;
    r->state      = STM_INODE_STATE_ALLOCATED;
    r->value.si_ino        = stm_store_le64(fresh_ino);
    r->value.si_dataset_id = stm_store_le64(dataset_id);
    r->value.si_gen        = stm_store_le64(0);
    r->value.si_mode       = stm_store_le32(mode);
    r->value.si_uid        = stm_store_le32(uid);
    r->value.si_gid        = stm_store_le32(gid);
    r->value.si_nlink      = stm_store_le32(1);
    r->value.si_data_kind  = STM_DATA_INLINE;
    r->value.si_data_len   = 0;

    s->next_ino  = fresh_ino + 1u;
    *out_ino     = fresh_ino;
    idx->dirty   = true;

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
    /* Encode FREED state in si_flags so the on-disk record carries
     * the lifecycle bit. Clear nlink as well (POSIX-shape: a freed
     * inode has zero links). gen is preserved for the next
     * AllocReused's bump. */
    uint32_t flags = stm_load_le32(r->value.si_flags);
    r->value.si_flags = stm_store_le32(flags | STM_INO_FLAG_FREED);
    r->value.si_nlink = stm_store_le32(0);
    idx->dirty = true;

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
    /* R69 P3-3: reject unknown si_data_kind. */
    switch (in_value->si_data_kind) {
        case STM_DATA_EXTENT:
        case STM_DATA_INLINE:
        case STM_DATA_SYMLINK:
        case STM_DATA_DEVICE:
            break;
        default:
            must_unlock(idx_lock(idx));
            return STM_EINVAL;
    }
    /* Reject Set with the FREED bit set in si_flags — that bit is
     * the allocator's internal lifecycle marker; callers reach FREED
     * via stm_inode_free, not by writing the flag. */
    {
        uint32_t flags = stm_load_le32(in_value->si_flags);
        if (flags & STM_INO_FLAG_FREED) {
            must_unlock(idx_lock(idx));
            return STM_EINVAL;
        }
    }
    r->value = *in_value;
    /* R69 P3-2: zero `si_reserved` on every Set. */
    memset(r->value.si_reserved, 0, sizeof r->value.si_reserved);
    idx->dirty = true;

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

/* ------------------------------------------------------------------ */
/* Public API — persistence (P8-POSIX-1b).                             */
/* ------------------------------------------------------------------ */

stm_status stm_inode_index_set_storage(stm_inode_index *idx,
                                          stm_bdev *bdev_0,
                                          stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(&idx->lock);
    idx->bdev = bdev_0;
    idx->boot = boot_0;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_inode_index_set_crypt_ctx(stm_inode_index *idx,
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

stm_status stm_inode_index_get_root(const stm_inode_index *idx,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr) return STM_EINVAL;
    pthread_mutex_t *lock = idx_lock(idx);
    must_lock(lock);
    *out_root_paddr = idx->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, idx->root_csum, 32);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_inode_index_get_gen(const stm_inode_index *idx,
                                      uint64_t *out_root_gen) {
    if (!idx || !out_root_gen) return STM_EINVAL;
    pthread_mutex_t *lock = idx_lock(idx);
    must_lock(lock);
    *out_root_gen = idx->root_gen;
    must_unlock(lock);
    return STM_OK;
}

/* Build a btree from records[] for serialization. */
static stm_status in_build_btree_locked(const stm_inode_index *idx,
                                            stm_btree_mt **out_tree) {
    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;

    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) return ts;

    uint8_t key[IN_KEY_LEN];
    uint8_t val[IN_VAL_LEN];
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_inode_record *r = &idx->records[i];
        in_encode_key(r->dataset_id, r->ino, key);
        in_encode_value(&r->value, val);
        stm_status is = stm_btree_mt_insert(t, key, IN_KEY_LEN, val, IN_VAL_LEN);
        if (is != STM_OK) { stm_btree_mt_free(t); return is; }
    }

    *out_tree = t;
    return STM_OK;
}

stm_status stm_inode_index_commit(stm_inode_index *idx,
                                     uint64_t committed_gen,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    must_lock(&idx->lock);

    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* Clean + already-committed: idempotent return of the existing root. */
    if (!idx->dirty && idx->root_paddr != 0) {
        *out_root_paddr = idx->root_paddr;
        memcpy(out_root_csum, idx->root_csum, 32);
        must_unlock(&idx->lock);
        return STM_OK;
    }

    stm_btree_mt *t = NULL;
    stm_status bs = in_build_btree_locked(idx, &t);
    if (bs != STM_OK) {
        must_unlock(&idx->lock);
        return bs;
    }

    in_store_ctx        sc = in_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = in_make_crypt_ctx(idx);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(t, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &IN_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    stm_btree_mt_free(t);
    if (ss != STM_OK) {
        must_unlock(&idx->lock);
        return ss;
    }

    /* Rollback the freshly-serialized tree if any subsequent step fails. */
    #define IN_ROLLBACK_RESERVE() \
        do { (void)stm_btree_store_free_tree(new_paddr, committed_gen,  \
                                                committed_gen, new_csum, \
                                                &IN_STORE_VT, &sc, &cx); \
        } while (0)

    if (idx->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(idx->root_paddr,
                                                     idx->root_gen,
                                                     committed_gen,
                                                     idx->root_csum,
                                                     &IN_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            IN_ROLLBACK_RESERVE();
            must_unlock(&idx->lock);
            return fs;
        }
    }

    stm_status bsc = stm_bootstrap_commit(idx->boot, committed_gen);
    if (bsc != STM_OK) {
        IN_ROLLBACK_RESERVE();
        must_unlock(&idx->lock);
        return bsc;
    }
    #undef IN_ROLLBACK_RESERVE

    idx->root_paddr = new_paddr;
    idx->root_gen   = committed_gen;
    memcpy(idx->root_csum, new_csum, 32);
    idx->dirty      = false;

    *out_root_paddr = new_paddr;
    memcpy(out_root_csum, new_csum, 32);
    must_unlock(&idx->lock);
    return STM_OK;
}

/* load_at — atomic shadow swap. Walks the deserialized tree, builds
 * a fresh records[] + dsstate[], swaps into idx atomically. */

typedef struct {
    stm_inode_record *shadow_records;
    size_t            shadow_len;
    size_t            shadow_cap;
    stm_status        err;
} in_load_ctx;

static stm_status in_shadow_append(in_load_ctx *lc,
                                       const stm_inode_record *r) {
    if (lc->shadow_len == lc->shadow_cap) {
        if (lc->shadow_cap > SIZE_MAX / 2u) return STM_ENOMEM;
        size_t new_cap = lc->shadow_cap == 0 ? 8u : lc->shadow_cap * 2u;
        stm_inode_record *new_buf = realloc(lc->shadow_records,
                                                 new_cap * sizeof *new_buf);
        if (!new_buf) return STM_ENOMEM;
        lc->shadow_records = new_buf;
        lc->shadow_cap     = new_cap;
    }
    lc->shadow_records[lc->shadow_len++] = *r;
    return STM_OK;
}

static int in_load_iter(const void *k, size_t klen,
                            const void *v, size_t vlen, void *ctx_) {
    in_load_ctx *lc = ctx_;
    uint64_t ds = 0, ino = 0;
    stm_status ks = in_decode_key(k, klen, &ds, &ino);
    if (ks != STM_OK) { lc->err = ks; return 1; }
    if (ds == 0 || ino == 0) { lc->err = STM_ECORRUPT; return 1; }

    stm_inode_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = in_decode_value(v, vlen, ds, ino, &r);
    if (vs != STM_OK) { lc->err = vs; return 1; }

    stm_status as = in_shadow_append(lc, &r);
    if (as != STM_OK) { lc->err = as; return 1; }
    return 0;
}

/* Reconstruct dsstate[] from the loaded records (max(ino) + 1
 * per dataset). Returns NULL on malloc failure; caller frees. */
static stm_status in_rebuild_dsstate_from_records(
        const stm_inode_record *records, size_t n_records,
        stm_inode_dsstate **out_arr, size_t *out_n, size_t *out_cap) {
    *out_arr = NULL; *out_n = 0; *out_cap = 0;
    for (size_t i = 0; i < n_records; i++) {
        const stm_inode_record *r = &records[i];
        /* find or create dsstate slot */
        stm_inode_dsstate *s = NULL;
        for (size_t j = 0; j < *out_n; j++) {
            if ((*out_arr)[j].dataset_id == r->dataset_id) {
                s = &(*out_arr)[j];
                break;
            }
        }
        if (!s) {
            if (*out_n == *out_cap) {
                if (*out_cap > SIZE_MAX / 2u) {
                    free(*out_arr);
                    *out_arr = NULL; *out_n = 0; *out_cap = 0;
                    return STM_ENOMEM;
                }
                size_t new_cap = *out_cap == 0 ? 4u : *out_cap * 2u;
                stm_inode_dsstate *new_arr =
                        realloc(*out_arr, new_cap * sizeof *new_arr);
                if (!new_arr) {
                    free(*out_arr);
                    *out_arr = NULL; *out_n = 0; *out_cap = 0;
                    return STM_ENOMEM;
                }
                *out_arr = new_arr;
                *out_cap = new_cap;
            }
            s = &(*out_arr)[(*out_n)++];
            s->dataset_id = r->dataset_id;
            s->next_ino   = 0u;
        }
        if (r->ino + 1u > s->next_ino) s->next_ino = r->ino + 1u;
    }
    return STM_OK;
}

stm_status stm_inode_index_load_at(stm_inode_index *idx,
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

    in_store_ctx        sc = in_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = in_make_crypt_ctx(idx);

    stm_status ds = stm_btree_store_deserialize(t, root_paddr, root_gen,
                                                   expected_csum,
                                                   &IN_STORE_VT, &sc, &cx);
    if (ds != STM_OK) {
        stm_btree_mt_free(t);
        must_unlock(&idx->lock);
        return ds;
    }

    in_load_ctx lc = {0};
    stm_status sr = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                         in_load_iter, &lc);
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

    /* Reconstruct dsstate[] from loaded records. */
    stm_inode_dsstate *new_dsstate = NULL;
    size_t             new_n_ds = 0, new_cap_ds = 0;
    stm_status rs = in_rebuild_dsstate_from_records(lc.shadow_records,
                                                          lc.shadow_len,
                                                          &new_dsstate,
                                                          &new_n_ds,
                                                          &new_cap_ds);
    if (rs != STM_OK) {
        free(lc.shadow_records);
        must_unlock(&idx->lock);
        return rs;
    }

    /* Atomic swap: free the old, install the new. */
    free(idx->records);
    free(idx->dsstate);
    idx->records      = lc.shadow_records;
    idx->n_records    = lc.shadow_len;
    idx->cap_records  = lc.shadow_cap;
    idx->dsstate      = new_dsstate;
    idx->n_datasets   = new_n_ds;
    idx->cap_datasets = new_cap_ds;

    idx->root_paddr = root_paddr;
    idx->root_gen   = root_gen;
    memcpy(idx->root_csum, expected_csum, 32);
    idx->dirty      = false;

    must_unlock(&idx->lock);
    return STM_OK;
}
