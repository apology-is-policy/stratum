/* SPDX-License-Identifier: ISC */
/*
 * Content-addressed cold-tier index (P7-CAS, v18).
 *
 *   see include/stratum/cas.h — public API + invariants.
 *   see v2/specs/cas.tla — formal model.
 *
 * Mirrors src/extent/extent_index.c — linear-array in-RAM map +
 * btree_store-backed persistence on device 0 under STM_BPTR_KIND_CAS.
 * The bp_kind constant was carved out at v3 and is used for the first
 * time here (see include/stratum/super.h).
 *
 * SPEC-TO-CODE mapping:
 *
 *   cas.tla::Init               → stm_cas_index_create
 *   cas.tla::WriteHot           → (extent layer; not modeled here)
 *   cas.tla::MigrateToCold (CAS-miss)
 *                                → stm_cas_insert
 *   cas.tla::MigrateToCold (CAS-hit) / Reflink-touches-cold
 *                                → stm_cas_ref
 *   cas.tla::RehydrateOnWrite (per-hash deref)
 *   cas.tla::DeleteFile (per-hash deref)
 *                                → stm_cas_deref
 *   cas.tla::GC                 → stm_cas_gc
 *   cas.tla::AdvanceTxg         → stm_cas_index_advance_txg
 *
 *   cas.tla::TypeOK             → field types in stm_cas_record
 *   cas.tla::CASIndexUnique     → upsert-by-hash (insert refuses dup)
 *   cas.tla::LengthPositive     → length ≥ 1 check in _insert
 *   cas.tla::BirthTxgBound      → gen ≤ current_txg check in _insert
 *   cas.tla::PaddrFreshness     → paddr-distinct invariant in
 *                                   _insert (within-set + cross-set)
 *   cas.tla::CASReplicasDisjoint
 *                                → cross-set paddr scan in _insert
 *   cas.tla::RefcountConsistent → refcount field updated by _ref /
 *                                   _deref; refcount=0 is a precondition
 *                                   for _gc.
 */
#include <stratum/cas.h>

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/btree.h>
#include <stratum/btree_store.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Match snapshot.c / extent_index.c's must_lock / must_unlock pattern. */
static inline void must_lock(pthread_mutex_t *m) {
    int rc = pthread_mutex_lock(m);
    if (rc != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    int rc = pthread_mutex_unlock(m);
    if (rc != 0) abort();
}

struct stm_cas_index {
    pthread_mutex_t   lock;
    stm_cas_record   *records;
    size_t            n_records;
    size_t            cap_records;
    uint64_t          current_txg;

    /* Persistence (mirrors stm_extent_index). */
    stm_bdev         *bdev;
    stm_bootstrap    *boot;
    const uint8_t    *metadata_key;
    uint64_t          pool_uuid[2];
    uint64_t          device_uuid[2];
    bool              crypt_set;
    uint64_t          root_paddr;
    uint64_t          root_gen;
    uint8_t           root_csum[32];
    bool              dirty;
};

static inline pthread_mutex_t *cas_lock(const stm_cas_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* AD packing (ARCH §7.6.3).                                          */
/* ------------------------------------------------------------------ */

void stm_ad_cas_pack(const stm_ad_cas *ad,
                     uint8_t out[STM_AD_CAS_PACKED_LEN])
{
    le32 magic   = stm_store_le32(ad->magic);
    le32 version = stm_store_le32(ad->version);
    le64 pu0     = stm_store_le64(ad->pool_uuid[0]);
    le64 pu1     = stm_store_le64(ad->pool_uuid[1]);

    size_t o = 0;
    memcpy(out + o, magic.v,   4); o += 4;
    memcpy(out + o, version.v, 4); o += 4;
    memcpy(out + o, pu0.v,     8); o += 8;
    memcpy(out + o, pu1.v,     8); o += 8;
    memcpy(out + o, ad->content_hash, STM_CAS_HASH_LEN); o += STM_CAS_HASH_LEN;
    /* 4+4+8+8+32 = 56 bytes. */
    (void)o;
}

/* ------------------------------------------------------------------ */
/* Internal helpers (caller holds idx->lock).                         */
/* ------------------------------------------------------------------ */

/* Look up a record by hash. Returns the index in idx->records or -1. */
static ptrdiff_t find_by_hash_locked(const stm_cas_index *idx,
                                        const uint8_t hash[STM_CAS_HASH_LEN])
{
    for (size_t i = 0; i < idx->n_records; i++) {
        if (memcmp(idx->records[i].content_hash, hash,
                    STM_CAS_HASH_LEN) == 0) {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

/* True iff `paddr` appears in any live entry's replica set. */
static bool paddr_in_use_locked(const stm_cas_index *idx, uint64_t paddr) {
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_cas_record *r = &idx->records[i];
        for (uint8_t k = 0; k < r->n_replicas; k++) {
            if (r->paddrs[k] == paddr) return true;
        }
    }
    return false;
}

/* True iff `paddrs[0..n)` are pairwise distinct, all non-zero, and
 * within bounds. */
static bool replica_set_is_valid(const uint64_t *paddrs, size_t n) {
    if (n < 1 || n > STM_CAS_MAX_REPLICAS) return false;
    for (size_t i = 0; i < n; i++) {
        if (paddrs[i] == 0) return false;
        for (size_t j = i + 1; j < n; j++) {
            if (paddrs[i] == paddrs[j]) return false;
        }
    }
    return true;
}

/* True iff `hash` is all-zero (reserved sentinel — invalid in production). */
static bool hash_is_zero(const uint8_t hash[STM_CAS_HASH_LEN]) {
    for (size_t i = 0; i < STM_CAS_HASH_LEN; i++) if (hash[i] != 0) return false;
    return true;
}

/* Append a record to the records array. Caller holds the lock. */
static stm_status records_append(stm_cas_index *idx, const stm_cas_record *r) {
    if (idx->n_records == idx->cap_records) {
        size_t new_cap = idx->cap_records == 0 ? 8u : idx->cap_records * 2u;
        stm_cas_record *grown = realloc(idx->records,
                                         new_cap * sizeof(stm_cas_record));
        if (!grown) return STM_ENOMEM;
        idx->records = grown;
        idx->cap_records = new_cap;
    }
    idx->records[idx->n_records++] = *r;
    return STM_OK;
}

/* Remove the i-th record by swap-and-pop. */
static void records_remove_at(stm_cas_index *idx, size_t i) {
    if (i + 1 < idx->n_records) {
        idx->records[i] = idx->records[idx->n_records - 1];
    }
    idx->n_records--;
}

/* ========================================================================= */
/* Lifecycle.                                                                  */
/* ========================================================================= */

stm_status stm_cas_index_create(uint64_t current_txg,
                                  stm_cas_index **out) {
    if (!out) return STM_EINVAL;

    stm_cas_index *idx = calloc(1, sizeof(*idx));
    if (!idx) return STM_ENOMEM;

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) { free(idx); return STM_ENOMEM; }
    (void)pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    int rc = pthread_mutex_init(&idx->lock, &attr);
    pthread_mutexattr_destroy(&attr);
    if (rc != 0) { free(idx); return STM_ENOMEM; }

    idx->records     = NULL;
    idx->n_records   = 0;
    idx->cap_records = 0;
    idx->current_txg = current_txg;

    *out = idx;
    return STM_OK;
}

void stm_cas_index_close(stm_cas_index *idx) {
    if (!idx) return;
    free(idx->records);
    pthread_mutex_destroy(&idx->lock);
    free(idx);
}

stm_status stm_cas_index_current_txg(const stm_cas_index *idx,
                                       uint64_t *out_txg) {
    if (!idx || !out_txg) return STM_EINVAL;
    pthread_mutex_t *lock = cas_lock(idx);
    must_lock(lock);
    *out_txg = idx->current_txg;
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_cas_index_advance_txg(stm_cas_index *idx,
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

/* ========================================================================= */
/* Mutations.                                                                  */
/* ========================================================================= */

stm_status stm_cas_insert(stm_cas_index *idx,
                            const uint8_t content_hash[STM_CAS_HASH_LEN],
                            const uint64_t *paddrs, size_t n_paddrs,
                            uint64_t length, uint64_t gen) {
    if (!idx || !content_hash || !paddrs) return STM_EINVAL;
    if (length == 0) return STM_EINVAL;
    if (!replica_set_is_valid(paddrs, n_paddrs)) return STM_EINVAL;
    if (hash_is_zero(content_hash)) return STM_EINVAL;

    must_lock(&idx->lock);

    if (gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (find_by_hash_locked(idx, content_hash) >= 0) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    /* CASReplicasDisjoint: every paddr must be fresh from any live
     * CAS entry's replica set. (Hot-vs-CAS disjointness — cas.tla::
     * HotColdReplicasDisjoint — is enforced by the caller, who allocates
     * fresh paddrs from the allocator's hot-side fresh pool before
     * invoking us.) */
    for (size_t i = 0; i < n_paddrs; i++) {
        if (paddr_in_use_locked(idx, paddrs[i])) {
            must_unlock(&idx->lock);
            return STM_EEXIST;
        }
    }

    stm_cas_record r;
    memcpy(r.content_hash, content_hash, STM_CAS_HASH_LEN);
    r.n_replicas = (uint8_t)n_paddrs;
    for (size_t i = 0; i < STM_CAS_MAX_REPLICAS; i++) {
        r.paddrs[i] = (i < n_paddrs) ? paddrs[i] : 0u;
    }
    r.refcount = 1u;
    r.length   = length;
    r.gen      = gen;

    stm_status as = records_append(idx, &r);
    if (as != STM_OK) {
        must_unlock(&idx->lock);
        return as;
    }

    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_cas_ref(stm_cas_index *idx,
                        const uint8_t content_hash[STM_CAS_HASH_LEN]) {
    if (!idx || !content_hash) return STM_EINVAL;

    must_lock(&idx->lock);
    ptrdiff_t i = find_by_hash_locked(idx, content_hash);
    if (i < 0) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (idx->records[i].refcount == UINT32_MAX) {
        must_unlock(&idx->lock);
        return STM_EOVERFLOW;
    }
    idx->records[i].refcount += 1u;
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_cas_deref(stm_cas_index *idx,
                          const uint8_t content_hash[STM_CAS_HASH_LEN]) {
    if (!idx || !content_hash) return STM_EINVAL;

    must_lock(&idx->lock);
    ptrdiff_t i = find_by_hash_locked(idx, content_hash);
    if (i < 0) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (idx->records[i].refcount == 0u) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->records[i].refcount -= 1u;
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_cas_gc(stm_cas_index *idx,
                        const uint8_t content_hash[STM_CAS_HASH_LEN],
                        uint64_t *out_paddrs, size_t paddrs_cap,
                        size_t *out_n_paddrs) {
    if (!idx || !content_hash || !out_paddrs || !out_n_paddrs) return STM_EINVAL;

    must_lock(&idx->lock);
    ptrdiff_t i = find_by_hash_locked(idx, content_hash);
    if (i < 0) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (idx->records[i].refcount > 0u) {
        must_unlock(&idx->lock);
        return STM_EBUSY;
    }
    if (paddrs_cap < (size_t)idx->records[i].n_replicas) {
        must_unlock(&idx->lock);
        return STM_ERANGE;
    }

    *out_n_paddrs = (size_t)idx->records[i].n_replicas;
    for (size_t k = 0; k < *out_n_paddrs; k++) {
        out_paddrs[k] = idx->records[i].paddrs[k];
    }

    records_remove_at(idx, (size_t)i);
    idx->dirty = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

/* ========================================================================= */
/* Lookup + iteration.                                                         */
/* ========================================================================= */

stm_status stm_cas_lookup(const stm_cas_index *idx,
                            const uint8_t content_hash[STM_CAS_HASH_LEN],
                            stm_cas_record *out_record) {
    if (!idx || !content_hash || !out_record) return STM_EINVAL;
    pthread_mutex_t *lock = cas_lock(idx);
    must_lock(lock);
    ptrdiff_t i = find_by_hash_locked(idx, content_hash);
    if (i < 0) {
        must_unlock(lock);
        return STM_ENOENT;
    }
    *out_record = idx->records[i];
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_cas_iter(const stm_cas_index *idx,
                          stm_cas_iter_cb cb, void *ctx) {
    if (!idx || !cb) return STM_EINVAL;

    pthread_mutex_t *lock = cas_lock(idx);
    must_lock(lock);

    /* Sort by hash for deterministic iteration. Insertion sort over a
     * small index — typical n is small. */
    if (idx->n_records == 0) {
        must_unlock(lock);
        return STM_OK;
    }

    size_t *order = malloc(idx->n_records * sizeof(size_t));
    if (!order) {
        must_unlock(lock);
        return STM_ENOMEM;
    }
    for (size_t i = 0; i < idx->n_records; i++) order[i] = i;

    for (size_t i = 1; i < idx->n_records; i++) {
        size_t key = order[i];
        const uint8_t *kh = idx->records[key].content_hash;
        size_t j = i;
        while (j > 0) {
            const uint8_t *ph = idx->records[order[j - 1]].content_hash;
            if (memcmp(ph, kh, STM_CAS_HASH_LEN) <= 0) break;
            order[j] = order[j - 1];
            j--;
        }
        order[j] = key;
    }

    for (size_t i = 0; i < idx->n_records; i++) {
        if (!cb(&idx->records[order[i]], ctx)) break;
    }
    free(order);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_cas_count(const stm_cas_index *idx, size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    pthread_mutex_t *lock = cas_lock(idx);
    must_lock(lock);
    *out_count = idx->n_records;
    must_unlock(lock);
    return STM_OK;
}

/* =========================================================================
 * Persistence (P7-CAS, v18). Mirrors src/extent/extent_index.c §Persistence.
 *
 * Key (32 bytes):  content_hash (BLAKE3-256, big-endian as bytes).
 * Value (64 bytes):
 *
 *   off  size  field
 *     0    1   n_replicas (u8; 1..STM_CAS_MAX_REPLICAS=4)
 *     1    7   reserved (zero — anti-tamper)
 *     8   32   paddrs[STM_CAS_MAX_REPLICAS=4] (le64 each)
 *    40    8   refcount (le64; clamped at UINT32_MAX semantically)
 *    48    8   length (le64; chunk plaintext bytes)
 *    56    8   gen (le64; AEAD nonce gen of the stored chunk)
 *
 * The CAS index tree's bp_kind is STM_BPTR_KIND_CAS (= 6, allocated at
 * v3 in include/stratum/super.h).
 * ========================================================================= */

#define CAS_KEY_LEN    STM_CAS_HASH_LEN          /* 32 */
#define CAS_VAL_LEN    64u

static void cas_encode_key(const uint8_t hash[STM_CAS_HASH_LEN],
                            uint8_t out[CAS_KEY_LEN]) {
    memcpy(out, hash, STM_CAS_HASH_LEN);
}

static stm_status cas_decode_key(const uint8_t *in, size_t in_len,
                                    uint8_t out_hash[STM_CAS_HASH_LEN]) {
    if (in_len != CAS_KEY_LEN) return STM_ECORRUPT;
    memcpy(out_hash, in, STM_CAS_HASH_LEN);
    return STM_OK;
}

static stm_status cas_encode_value(const stm_cas_record *r,
                                      uint8_t out[CAS_VAL_LEN]) {
    if (r->n_replicas < 1 || r->n_replicas > STM_CAS_MAX_REPLICAS) {
        return STM_ECORRUPT;
    }

    memset(out, 0, CAS_VAL_LEN);
    out[0] = r->n_replicas;
    /* bytes [1..7] reserved (zero, already zeroed). */
    for (uint8_t i = 0; i < r->n_replicas; i++) {
        if (r->paddrs[i] == 0) return STM_ECORRUPT;
        le64 p = stm_store_le64(r->paddrs[i]);
        memcpy(out + 8 + (size_t)i * 8, p.v, 8);
    }
    /* Trailing replica slots zero (memset already). */

    le64 refc = stm_store_le64((uint64_t)r->refcount);
    le64 len  = stm_store_le64(r->length);
    le64 gen  = stm_store_le64(r->gen);
    memcpy(out + 40, refc.v, 8);
    memcpy(out + 48, len.v,  8);
    memcpy(out + 56, gen.v,  8);
    return STM_OK;
}

static stm_status cas_decode_value(const uint8_t *in, size_t in_len,
                                      const uint8_t hash[STM_CAS_HASH_LEN],
                                      stm_cas_record *out_rec) {
    if (in_len != CAS_VAL_LEN) return STM_ECORRUPT;
    uint8_t n_replicas = in[0];
    if (n_replicas < 1 || n_replicas > STM_CAS_MAX_REPLICAS) return STM_ECORRUPT;
    /* bytes [1..7] reserved — must be zero (anti-tamper). */
    for (size_t i = 1; i < 8; i++) if (in[i] != 0) return STM_ECORRUPT;

    uint64_t paddrs[STM_CAS_MAX_REPLICAS];
    for (uint8_t i = 0; i < STM_CAS_MAX_REPLICAS; i++) {
        le64 p_le;
        memcpy(p_le.v, in + 8 + (size_t)i * 8, 8);
        paddrs[i] = stm_load_le64(p_le);
    }
    /* Slots [n_replicas..STM_CAS_MAX_REPLICAS) MUST be zero. */
    for (uint8_t i = n_replicas; i < STM_CAS_MAX_REPLICAS; i++) {
        if (paddrs[i] != 0) return STM_ECORRUPT;
    }
    /* Active slots must be non-zero + pairwise distinct. */
    for (uint8_t i = 0; i < n_replicas; i++) {
        if (paddrs[i] == 0) return STM_ECORRUPT;
        for (uint8_t j = (uint8_t)(i + 1); j < n_replicas; j++) {
            if (paddrs[i] == paddrs[j]) return STM_ECORRUPT;
        }
    }

    le64 refc_le, len_le, gen_le;
    memcpy(refc_le.v, in + 40, 8);
    memcpy(len_le.v,  in + 48, 8);
    memcpy(gen_le.v,  in + 56, 8);

    uint64_t refc = stm_load_le64(refc_le);
    uint64_t len  = stm_load_le64(len_le);
    uint64_t gen  = stm_load_le64(gen_le);

    if (refc > (uint64_t)UINT32_MAX) return STM_ECORRUPT;
    if (len == 0u) return STM_ECORRUPT;
    if (refc == 0u) return STM_ECORRUPT; /* refcount=0 is GC-pending; not persisted */

    memcpy(out_rec->content_hash, hash, STM_CAS_HASH_LEN);
    out_rec->n_replicas = n_replicas;
    for (uint8_t i = 0; i < STM_CAS_MAX_REPLICAS; i++) {
        out_rec->paddrs[i] = paddrs[i];
    }
    out_rec->refcount = (uint32_t)refc;
    out_rec->length   = len;
    out_rec->gen      = gen;
    return STM_OK;
}

/* ---- btree_store vtable ---- */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} cas_store_ctx;

static stm_status cas_store_reserve(void *ctx_, uint64_t *out_paddr) {
    cas_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status cas_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen) {
    cas_store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status cas_store_write(void *ctx_, uint64_t paddr,
                                     const void *buf, size_t len) {
    cas_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status cas_store_read(void *ctx_, uint64_t paddr,
                                    void *buf, size_t len) {
    cas_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable CAS_STORE_VT = {
    .reserve = cas_store_reserve,
    .free    = cas_store_free,
    .write   = cas_store_write,
    .read    = cas_store_read,
};

static inline cas_store_ctx cas_make_store_ctx(stm_cas_index *idx) {
    cas_store_ctx c = { .boot = idx->boot, .bdev = idx->bdev };
    return c;
}

static inline stm_btree_crypt_ctx cas_make_crypt_ctx(const stm_cas_index *idx) {
    stm_btree_crypt_ctx cx = { .metadata_key = idx->metadata_key };
    cx.pool_uuid[0]   = idx->pool_uuid[0];
    cx.pool_uuid[1]   = idx->pool_uuid[1];
    cx.device_uuid[0] = idx->device_uuid[0];
    cx.device_uuid[1] = idx->device_uuid[1];
    return cx;
}

/* ---- Public persistence API. ---- */

stm_status stm_cas_index_set_storage(stm_cas_index *idx,
                                        stm_bdev *bdev_0,
                                        stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(&idx->lock);
    idx->bdev = bdev_0;
    idx->boot = boot_0;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_cas_index_set_crypt_ctx(stm_cas_index *idx,
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

stm_status stm_cas_index_get_root(const stm_cas_index *idx,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr) return STM_EINVAL;
    pthread_mutex_t *lock = cas_lock(idx);
    must_lock(lock);
    *out_root_paddr = idx->root_paddr;
    if (out_root_csum) memcpy(out_root_csum, idx->root_csum, 32);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_cas_index_get_gen(const stm_cas_index *idx,
                                    uint64_t *out_root_gen) {
    if (!idx || !out_root_gen) return STM_EINVAL;
    pthread_mutex_t *lock = cas_lock(idx);
    must_lock(lock);
    *out_root_gen = idx->root_gen;
    must_unlock(lock);
    return STM_OK;
}

static stm_status cas_build_btree_locked(const stm_cas_index *idx,
                                            stm_btree_mt **out_tree) {
    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;

    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) return ts;

    uint8_t key[CAS_KEY_LEN];
    uint8_t val[CAS_VAL_LEN];
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_cas_record *r = &idx->records[i];
        /* refcount=0 entries are GC-pending; commit excludes them so a
         * post-commit GC walker can reclaim by iterating the in-RAM
         * shadow but the persistent state never carries refcount=0
         * entries. (Mirrors cas.tla: GC removes refcount=0 entries from
         * cas_entries; the persistent on-disk state is the post-GC
         * subset.) */
        if (r->refcount == 0u) continue;
        cas_encode_key(r->content_hash, key);
        stm_status es = cas_encode_value(r, val);
        if (es != STM_OK) { stm_btree_mt_free(t); return es; }
        stm_status is = stm_btree_mt_insert(t, key, CAS_KEY_LEN, val, CAS_VAL_LEN);
        if (is != STM_OK) { stm_btree_mt_free(t); return is; }
    }

    *out_tree = t;
    return STM_OK;
}

stm_status stm_cas_index_commit(stm_cas_index *idx,
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
    stm_status bs = cas_build_btree_locked(idx, &t);
    if (bs != STM_OK) {
        must_unlock(&idx->lock);
        return bs;
    }

    cas_store_ctx       sc = cas_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = cas_make_crypt_ctx(idx);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(t, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &CAS_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    stm_btree_mt_free(t);
    if (ss != STM_OK) {
        must_unlock(&idx->lock);
        return ss;
    }

    #define CAS_ROLLBACK_RESERVE() \
        do { (void)stm_btree_store_free_tree(new_paddr, committed_gen,  \
                                                committed_gen, new_csum, \
                                                &CAS_STORE_VT, &sc, &cx); \
        } while (0)

    if (idx->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(idx->root_paddr,
                                                     idx->root_gen,
                                                     committed_gen,
                                                     idx->root_csum,
                                                     &CAS_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            CAS_ROLLBACK_RESERVE();
            must_unlock(&idx->lock);
            return fs;
        }
    }

    stm_status bsc = stm_bootstrap_commit(idx->boot, committed_gen);
    if (bsc != STM_OK) {
        CAS_ROLLBACK_RESERVE();
        must_unlock(&idx->lock);
        return bsc;
    }
    #undef CAS_ROLLBACK_RESERVE

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
    stm_cas_record *shadow;
    size_t          shadow_len;
    size_t          shadow_cap;
    uint64_t        max_gen;
    stm_status      err;
} cas_load_ctx;

static stm_status cas_shadow_append(cas_load_ctx *lc,
                                       const stm_cas_record *r) {
    if (lc->shadow_len == lc->shadow_cap) {
        size_t new_cap = lc->shadow_cap == 0 ? 8 : lc->shadow_cap * 2;
        stm_cas_record *new_buf = realloc(lc->shadow,
                                            new_cap * sizeof(stm_cas_record));
        if (!new_buf) return STM_ENOMEM;
        lc->shadow     = new_buf;
        lc->shadow_cap = new_cap;
    }
    lc->shadow[lc->shadow_len++] = *r;
    return STM_OK;
}

static int cas_load_iter(const void *k, size_t klen,
                            const void *v, size_t vlen, void *ctx_) {
    cas_load_ctx *lc = ctx_;
    uint8_t hash[STM_CAS_HASH_LEN];
    stm_status ks = cas_decode_key(k, klen, hash);
    if (ks != STM_OK) { lc->err = ks; return 1; }
    if (hash_is_zero(hash)) { lc->err = STM_ECORRUPT; return 1; }

    stm_cas_record r;
    stm_status vs = cas_decode_value(v, vlen, hash, &r);
    if (vs != STM_OK) { lc->err = vs; return 1; }

    if (r.gen > lc->max_gen) lc->max_gen = r.gen;

    stm_status as = cas_shadow_append(lc, &r);
    if (as != STM_OK) { lc->err = as; return 1; }
    return 0;
}

/* Structural validator on the loaded shadow. Catches:
 *   - Duplicate hash (CASIndexUnique violation).
 *   - Cross-record paddr collision (CASReplicasDisjoint violation).
 * O(N²·K²) where K = STM_CAS_MAX_REPLICAS — fine for any plausible mount.
 */
static stm_status cas_validate_shadow(const cas_load_ctx *lc) {
    for (size_t i = 0; i < lc->shadow_len; i++) {
        const stm_cas_record *a = &lc->shadow[i];
        for (size_t j = i + 1; j < lc->shadow_len; j++) {
            const stm_cas_record *b = &lc->shadow[j];
            if (memcmp(a->content_hash, b->content_hash,
                        STM_CAS_HASH_LEN) == 0) {
                return STM_ECORRUPT;   /* duplicate hash */
            }
            for (uint8_t ai = 0; ai < a->n_replicas; ai++) {
                for (uint8_t bi = 0; bi < b->n_replicas; bi++) {
                    if (a->paddrs[ai] == b->paddrs[bi]) {
                        return STM_ECORRUPT; /* paddr collision */
                    }
                }
            }
        }
    }
    return STM_OK;
}

stm_status stm_cas_index_load_at(stm_cas_index *idx,
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

    cas_store_ctx       sc = cas_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = cas_make_crypt_ctx(idx);

    stm_status ds = stm_btree_store_deserialize(t, root_paddr, root_gen,
                                                   expected_csum,
                                                   &CAS_STORE_VT, &sc, &cx);
    if (ds != STM_OK) {
        stm_btree_mt_free(t);
        must_unlock(&idx->lock);
        return ds;
    }

    cas_load_ctx lc = {0};
    stm_status sr = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                         cas_load_iter, &lc);
    stm_btree_mt_free(t);

    if (sr != STM_OK) {
        free(lc.shadow);
        must_unlock(&idx->lock);
        return sr;
    }
    if (lc.err != STM_OK) {
        free(lc.shadow);
        must_unlock(&idx->lock);
        return lc.err;
    }
    stm_status vs = cas_validate_shadow(&lc);
    if (vs != STM_OK) {
        free(lc.shadow);
        must_unlock(&idx->lock);
        return vs;
    }

    /* Atomic swap. */
    free(idx->records);
    idx->records      = lc.shadow;
    idx->n_records    = lc.shadow_len;
    idx->cap_records  = lc.shadow_cap;

    if (lc.max_gen > idx->current_txg) {
        idx->current_txg = lc.max_gen;
    }

    idx->root_paddr = root_paddr;
    idx->root_gen   = root_gen;
    memcpy(idx->root_csum, expected_csum, 32);
    idx->dirty = false;

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_cas_index_verify(const stm_cas_index *idx) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_t *lock = cas_lock(idx);
    must_lock(lock);
    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    if (idx->root_paddr == 0) {
        must_unlock(lock);
        return STM_OK;
    }
    cas_store_ctx       sc = cas_make_store_ctx((stm_cas_index *)idx);
    stm_btree_crypt_ctx cx = cas_make_crypt_ctx(idx);
    stm_status vs = stm_btree_store_verify(idx->root_paddr, idx->root_gen,
                                              idx->root_csum,
                                              &CAS_STORE_VT, &sc, &cx);
    must_unlock(lock);
    return vs;
}
