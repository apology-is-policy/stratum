/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — inode index implementation
 * (P8-POSIX-1 + P8-POSIX-1b + 9.6-impl-4b-ii).
 *
 * Spec: v2/specs/inode.tla.
 *
 * 9.6-impl-4b-ii — the inode cutover. The module no longer keeps an
 * in-RAM `records[]` array serialized whole on every commit: the
 * btree_engine COW B+tree (Phase 9.6) IS the inode store. Every public
 * op maps onto the engine —
 *
 *   lookup            -> engine_lookup
 *   set               -> engine_lookup, then engine_insert (upsert)
 *   alloc / alloc_anon -> pick the ino, then engine_insert
 *   free / link / unlink / materialize
 *                     -> engine_lookup, mutate the value, engine_insert
 *   count_for_ds      -> engine_scan_range
 *
 * inode.tla's allocator state machine — alloc / free / link / unlink /
 * materialize, the (ino, si_gen) tuple-uniqueness invariant — is
 * UNCHANGED; only the storage under it swapped from btree_store's
 * whole-tree-rebuild MVP to btree_engine's incremental COW B+tree. A
 * FREED record is an UPSERT of a FREED-flagged value, never an engine
 * delete: a FREED record must persist so AllocReused can re-issue the
 * ino with a bumped gen (cutover doc §3.1).
 *
 * On-disk encoding (unchanged from P8-POSIX-1b):
 *   - Key (16 bytes): le64 dataset_id || le64 ino.
 *   - Value (256 bytes): the full struct stm_inode_value. FREED state
 *     is encoded inline via STM_INO_FLAG_FREED in si_flags.
 *
 * Engine lifecycle. stm_btree_engine_create needs the storage vtable
 * context (bdev + bootstrap) AND the AEAD crypt context — set by
 * stm_inode_index_set_storage / _set_crypt_ctx, which the sole caller
 * (sync.c) issues after stm_inode_index_create. So the engine cannot
 * exist at create time. It is created by whichever of the two binders
 * runs SECOND (the first one with both contexts now populated); the
 * mount path's load_at then destroys that fresh engine and opens the
 * on-disk one. `next_ino` per dataset stays in RAM (dsstate[]),
 * reconstructed at mount from a one-time engine_scan.
 *
 * Concurrency: a single mutex (idx->lock) guards dsstate + the
 * persistence fields AND every engine call — the btree_engine is
 * single-threaded (one handle, one thread at a time), and idx->lock IS
 * that serialization. No btree_engine API is ever touched without
 * idx->lock held. The per-inode lock pool (handle_buckets[]) is
 * independent of the index state and untouched by the cutover.
 */
#include <stratum/inode.h>
#include <stratum/types.h>
#include <stratum/bootstrap.h>
#include <stratum/btree_engine.h>
#include <stratum/engine_store.h>

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
/* Internal types.                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t dataset_id;
    uint64_t next_ino;       /* high-water mark; alloc returns this then bumps */
} stm_inode_dsstate;

/* P9.5-PARALLEL-3 impl-1: per-inode lock slot. Refcounted; lives in a
 * fixed-bucket hash chain owned by stm_inode_index. The slot's `mu`
 * is the per-inode mutex that stm_inode_pin / stm_inode_unpin lock /
 * unlock; the slot itself is heap-allocated and stable for the
 * lifetime of any non-zero refcount, so the handle pointer remains
 * valid across realloc of unrelated index state.
 *
 * Spec composition: realizes the `inode_lock_holder[i] = w` action of
 * compound_ops_per_inode.tla. Independent of the inode store — the
 * 9.6-impl-4b-ii cutover does not touch it. */
struct stm_inode_handle {
    uint64_t                  dataset_id;
    uint64_t                  ino;
    uint32_t                  refcount;     /* under idx->lock */
    pthread_mutex_t           mu;           /* the per-inode lock */
    struct stm_inode_handle  *next;         /* hash-chain link, under idx->lock */
};

#define STM_INODE_HANDLE_BUCKETS  256u

struct stm_inode_index {
    pthread_mutex_t     lock;

    /* Per-dataset next_ino high-water marks. Small (not file-count-
     * scaling); kept in RAM, reconstructed at mount from a one-time
     * engine_scan (see stm_inode_index_load_at). */
    stm_inode_dsstate  *dsstate;
    size_t              n_datasets;
    size_t              cap_datasets;

    /* P9.5-PARALLEL-3 impl-1: per-inode lock-slot pool. Hash chains keyed
     * by mix(dataset_id, ino) % STM_INODE_HANDLE_BUCKETS. Each bucket
     * head is a linked list of stm_inode_handle. The chain head pointer
     * AND each handle's refcount live under idx->lock; the handle's
     * `mu` is independent of idx->lock. */
    struct stm_inode_handle *handle_buckets[STM_INODE_HANDLE_BUCKETS];

    /* ----- Persistence (9.6-impl-4b-ii: btree_engine-backed). ----- */
    bool                  storage_set;   /* R70 P3-6: latched on first
                                           * successful set_storage. */
    bool                  crypt_set;     /* R70 P3-6: latched on first
                                           * successful set_crypt_ctx. */
    stm_engine_store_ctx  store_ctx;     /* { boot, bdev } — the engine's
                                           * vt_ctx. Populated by set_storage;
                                           * a stable member so the engine's
                                           * borrowed vt_ctx pointer stays
                                           * valid for idx's lifetime. */
    stm_btree_crypt_ctx   crypt_ctx;     /* metadata_key + uuids — the
                                           * engine's cx. Populated by
                                           * set_crypt_ctx; a stable member. */
    stm_btree_engine     *eng;           /* the inode store. Created once
                                           * BOTH contexts are bound (see
                                           * in_engine_create_locked /
                                           * the two binders), or by load_at
                                           * on the mount path. */
    /* Last durably-committed root triple — mirrored for the sync layer's
     * uberblock stamping (stm_inode_index_get_root / _get_gen). */
    uint64_t            root_paddr;
    uint64_t            root_gen;
    uint8_t             root_csum[32];
};

static inline pthread_mutex_t *idx_lock(const stm_inode_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* dsstate helpers (caller holds idx->lock).                           */
/* ------------------------------------------------------------------ */

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
 * with next_ino=1 if absent. Returns NULL only on STM_ENOMEM.
 *
 * realloc is called under idx->lock (R69 P3-4 acknowledged + P3-5
 * cap-doubling overflow guard + R71b P3-1 size-multiplication guard). */
static stm_inode_dsstate *get_or_create_dsstate(stm_inode_index *idx,
                                                     uint64_t dataset_id) {
    stm_inode_dsstate *s = find_dsstate(idx, dataset_id);
    if (s) return s;

    if (idx->n_datasets == idx->cap_datasets) {
        if (idx->cap_datasets > (SIZE_MAX / sizeof *idx->dsstate) / 2u)
            return NULL;
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

/* ------------------------------------------------------------------ */
/* On-disk key/value encoding.                                         */
/*                                                                      */
/* Key: 16 bytes (le64 dataset_id || le64 ino).                        */
/* Value: 256 bytes (struct stm_inode_value).                          */
/*                                                                      */
/* The btree_engine compares keys bytewise (eng_key_cmp -> memcmp).    */
/* For a fixed dataset every key shares the same 8-byte dataset prefix; */
/* the [ds||0 .. ds||UINT64_MAX] scan_range bounds therefore bracket    */
/* EXACTLY that dataset's keys (the all-zero / all-FF ino suffixes are  */
/* the bytewise extremes), regardless of the little-endian ino field's  */
/* numeric scramble. The two scan_range callers (AllocReused FREED-scan */
/* + count_for_ds) need range membership, not numeric ordering, so the  */
/* LE encoding is sound. Point engine_lookup works under any consistent */
/* comparator.                                                          */
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

/* ------------------------------------------------------------------ */
/* Engine glue.                                                         */
/* ------------------------------------------------------------------ */

/*
 * Full structural validation of a 256-byte on-disk inode value against
 * the (dataset_id, ino) key it was stored under. Run on EVERY value
 * read back from the engine (in_engine_get) and on every value the
 * mount scan walks — a corrupt record is refused before any caller
 * trusts it. Carries the R69/R70/R71/R77/R85 decoder-side guards
 * verbatim from the retired in_decode_value.
 *
 * The AEAD tag + Merkle chain on the enclosing engine node already
 * defend against offline tamper; this is the SEMANTIC layer on top —
 * it catches a record a buggy writer (or a future format skew) stored
 * inconsistently. The R77 P1-1 si_data_len bound is load-bearing for
 * memory safety: fs.c memcpy's si_data_len bytes out of the 100-byte
 * inline/symlink union slot, so an over-long value would OOB-read.
 */
static stm_status in_validate_value(const struct stm_inode_value *v,
                                    uint64_t expected_ds,
                                    uint64_t expected_ino) {
    /* Identity must match the key. */
    if (stm_load_le64(v->si_ino) != expected_ino) return STM_ECORRUPT;
    if (stm_load_le64(v->si_dataset_id) != expected_ds) return STM_ECORRUPT;

    /* data_kind must be one of the four known variants. */
    switch (v->si_data_kind) {
        case STM_DATA_EXTENT:
        case STM_DATA_INLINE:
        case STM_DATA_SYMLINK:
        case STM_DATA_DEVICE:
            break;
        default:
            return STM_ECORRUPT;
    }

    /* R77 P1-1: bound si_data_len by STM_INODE_INLINE_MAX for INLINE
     * and SYMLINK kinds — the union slot is exactly that many bytes. */
    if (v->si_data_kind == STM_DATA_INLINE ||
        v->si_data_kind == STM_DATA_SYMLINK) {
        if (v->si_data_len > STM_INODE_INLINE_MAX) return STM_ECORRUPT;
    }

    /* R70 P3-3 + P8-POSIX-7a-anon: the FREED / ORPHAN / nlink
     * invariants. FREED <=> nlink=0; ALLOCATED non-orphan => nlink>=1;
     * ORPHAN => nlink=0; ORPHAN => ALLOCATED. */
    uint32_t flags = stm_load_le32(v->si_flags);
    uint32_t nlink = stm_load_le32(v->si_nlink);
    bool is_freed  = (flags & STM_INO_FLAG_FREED) != 0;
    bool is_orphan = (flags & STM_INO_FLAG_ORPHAN) != 0;
    if (is_freed && nlink != 0) return STM_ECORRUPT;
    if (!is_freed && nlink == 0 && !is_orphan) return STM_ECORRUPT;
    if (is_orphan && nlink != 0) return STM_ECORRUPT;
    if (is_orphan && is_freed) return STM_ECORRUPT;
    return STM_OK;
}

/* Build an alloc-fresh inode value (regular: nlink=1, flags=0; anon:
 * nlink=0, flags=STM_INO_FLAG_ORPHAN). All other fields zero — caller
 * stamps timestamps on the next set; data_kind = INLINE, len 0. */
static void in_init_value(struct stm_inode_value *v,
                          uint64_t ds, uint64_t ino, uint64_t gen,
                          uint32_t mode, uint32_t uid, uint32_t gid,
                          uint32_t nlink, uint32_t flags) {
    memset(v, 0, sizeof *v);
    v->si_ino        = stm_store_le64(ino);
    v->si_dataset_id = stm_store_le64(ds);
    v->si_gen        = stm_store_le64(gen);
    v->si_mode       = stm_store_le32(mode);
    v->si_uid        = stm_store_le32(uid);
    v->si_gid        = stm_store_le32(gid);
    v->si_nlink      = stm_store_le32(nlink);
    v->si_flags      = stm_store_le32(flags);
    v->si_data_kind  = STM_DATA_INLINE;
    v->si_data_len   = 0;
}

/*
 * engine_lookup + validate. Caller holds idx->lock. On STM_OK:
 * *out_found is set; if true, *out holds the validated 256-byte value
 * (FREED or not — the caller applies the FREED filter). A device /
 * engine / corruption error propagates verbatim.
 */
static stm_status in_engine_get(const stm_inode_index *idx,
                                uint64_t ds, uint64_t ino,
                                struct stm_inode_value *out,
                                bool *out_found) {
    *out_found = false;
    uint8_t key[IN_KEY_LEN];
    in_encode_key(ds, ino, key);

    bool found = false;
    void *vbuf = NULL;
    size_t vlen = 0;
    stm_status ls = stm_btree_engine_lookup(idx->eng, key, IN_KEY_LEN,
                                            &found, &vbuf, &vlen);
    if (ls != STM_OK) return ls;
    if (!found) return STM_OK;                  /* *out_found stays false */
    /* An inode value is always exactly 256 bytes — a short / NULL / over
     * read-back is structural corruption. */
    if (vlen != IN_VAL_LEN || !vbuf) {
        free(vbuf);
        return STM_ECORRUPT;
    }
    struct stm_inode_value v;
    memcpy(&v, vbuf, IN_VAL_LEN);
    free(vbuf);
    stm_status vs = in_validate_value(&v, ds, ino);
    if (vs != STM_OK) return vs;
    *out = v;
    *out_found = true;
    return STM_OK;
}

/* Encode + engine_insert (upsert). Caller holds idx->lock. The engine's
 * insert is failure-atomic — a failed put never loses the prior value
 * at this key. */
static stm_status in_engine_put(stm_inode_index *idx,
                                uint64_t ds, uint64_t ino,
                                const struct stm_inode_value *v) {
    uint8_t key[IN_KEY_LEN];
    uint8_t val[IN_VAL_LEN];
    in_encode_key(ds, ino, key);
    memcpy(val, v, IN_VAL_LEN);
    return stm_btree_engine_insert(idx->eng, key, IN_KEY_LEN,
                                   val, IN_VAL_LEN);
}

/*
 * AllocReused FREED-ino scan (inode.tla AllocReused). scan_range over
 * [ds||0 .. ds||UINT64_MAX] early-stops at the first FREED record whose
 * prior gen is not UINT64_MAX (a UINT64_MAX-gen slot would wrap on the
 * +1 bump, silently violating the (ino, gen) tuple-uniqueness invariant
 * — R70 P3-1). "First" is bytewise-key order, which is sufficient: any
 * FREED slot is an equally valid reuse target.
 */
typedef struct {
    uint64_t   ds;
    bool       found;
    uint64_t   ino;
    uint64_t   prior_gen;
    stm_status err;
} in_freed_ctx;

static int in_freed_cb(const void *k, size_t klen,
                       const void *v, size_t vlen, void *ctx_) {
    in_freed_ctx *c = ctx_;
    uint64_t ds = 0, ino = 0;
    if (in_decode_key(k, klen, &ds, &ino) != STM_OK) {
        c->err = STM_ECORRUPT;
        return 1;
    }
    if (ds != c->ds) return 0;            /* defense-in-depth — the range
                                           * already isolates the dataset */
    if (vlen != IN_VAL_LEN) {
        c->err = STM_ECORRUPT;
        return 1;
    }
    struct stm_inode_value val;
    memcpy(&val, v, IN_VAL_LEN);
    uint32_t flags = stm_load_le32(val.si_flags);
    if (!(flags & STM_INO_FLAG_FREED)) return 0;         /* ALLOCATED — skip */
    uint64_t prior_gen = stm_load_le64(val.si_gen);
    if (prior_gen == UINT64_MAX) return 0;               /* would wrap — skip */
    c->found     = true;
    c->ino       = ino;
    c->prior_gen = prior_gen;
    return 1;                                            /* first FREED wins */
}

/* Caller holds idx->lock. */
static stm_status in_find_freed(stm_inode_index *idx, uint64_t ds,
                                bool *out_found, uint64_t *out_ino,
                                uint64_t *out_prior_gen) {
    *out_found     = false;
    *out_ino       = 0;
    *out_prior_gen = 0;
    uint8_t lo[IN_KEY_LEN], hi[IN_KEY_LEN];
    in_encode_key(ds, 0u,         lo);
    in_encode_key(ds, UINT64_MAX, hi);
    in_freed_ctx c = { .ds = ds, .found = false, .ino = 0,
                       .prior_gen = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(idx->eng, lo, IN_KEY_LEN,
                                                hi, IN_KEY_LEN,
                                                in_freed_cb, &c);
    if (ss != STM_OK) return ss;
    if (c.err != STM_OK) return c.err;
    *out_found     = c.found;
    *out_ino       = c.ino;
    *out_prior_gen = c.prior_gen;
    return STM_OK;
}

/* count_for_ds: scan_range over a dataset, count non-FREED records. */
typedef struct {
    size_t     count;
    stm_status err;
} in_count_ctx;

static int in_count_cb(const void *k, size_t klen,
                       const void *v, size_t vlen, void *ctx_) {
    (void)k; (void)klen;
    in_count_ctx *c = ctx_;
    if (vlen != IN_VAL_LEN) {
        c->err = STM_ECORRUPT;
        return 1;
    }
    struct stm_inode_value val;
    memcpy(&val, v, IN_VAL_LEN);
    if (!(stm_load_le32(val.si_flags) & STM_INO_FLAG_FREED)) c->count++;
    return 0;
}

/* Stand up the btree_engine from the (now both populated) store + crypt
 * contexts. Caller holds idx->lock, has verified BOTH contexts are
 * bound and idx->eng is NULL. The engine borrows &idx->store_ctx (its
 * vt_ctx) and &idx->crypt_ctx (its cx) — both stable members, alive for
 * idx's lifetime. */
static stm_status in_engine_create_locked(stm_inode_index *idx) {
    return stm_btree_engine_create(&STM_ENGINE_STORE_VT, &idx->store_ctx,
                                   &idx->crypt_ctx, /*tree_id=*/0u,
                                   &idx->eng);
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
    int rc = pthread_mutex_init(idx_lock(idx), &attr);
    pthread_mutexattr_destroy(&attr);
    if (rc != 0) {
        free(idx);
        return NULL;
    }
    return idx;
}

void stm_inode_index_close(stm_inode_index *idx) {
    if (!idx) return;
    /* P9.5-PARALLEL-3 impl-1: drain any leftover handle slots. In a well-
     * formed shutdown every pin has a matching unpin so the buckets are
     * empty; the drain is defense-in-depth against leaks. We destroy
     * each slot's mutex unconditionally — at this point no other thread
     * can hold it (close is the last call). */
    for (size_t b = 0; b < STM_INODE_HANDLE_BUCKETS; b++) {
        struct stm_inode_handle *h = idx->handle_buckets[b];
        while (h) {
            struct stm_inode_handle *next = h->next;
            pthread_mutex_destroy(&h->mu);
            free(h);
            h = next;
        }
    }
    pthread_mutex_destroy(idx_lock(idx));
    /* NULL-safe; an un-finalized flush is implicitly aborted (the
     * flushed-but-unrooted paddrs are handed back to the allocator).
     * stm_inode_index_commit uses the single-shot commit so no pending
     * window is ever left open in practice. */
    stm_btree_engine_destroy(idx->eng);
    free(idx->dsstate);
    free(idx);
}

/* ------------------------------------------------------------------ */
/* Public API — alloc / free / lookup / set / count / next_ino.        */
/* ------------------------------------------------------------------ */

/* Shared body of stm_inode_alloc (anon=false) + stm_inode_alloc_anon
 * (anon=true). Models inode.tla's AllocReused -> AllocFresh fallback;
 * the anon variant is the AllocAnon action (nlink=0 + ORPHAN). */
static stm_status in_alloc_common(stm_inode_index *idx, uint64_t dataset_id,
                                  uint32_t mode, uint32_t uid, uint32_t gid,
                                  bool anon, uint64_t *out_ino) {
    if (!idx || !out_ino) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;
    if (mode == 0) return STM_EINVAL;

    *out_ino = 0;

    must_lock(idx_lock(idx));
    if (!idx->eng) {                       /* storage / crypt not bound */
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    stm_inode_dsstate *s = get_or_create_dsstate(idx, dataset_id);
    if (!s) {
        must_unlock(idx_lock(idx));
        return STM_ENOMEM;
    }

    /* AllocReused path (preferred): reuse a FREED ino with si_gen += 1.
     * The bump preserves the (ino, gen) tuple-uniqueness invariant. */
    bool     freed = false;
    uint64_t freed_ino = 0, freed_prior_gen = 0;
    stm_status fs = in_find_freed(idx, dataset_id, &freed, &freed_ino,
                                  &freed_prior_gen);
    if (fs != STM_OK) {
        must_unlock(idx_lock(idx));
        return fs;
    }

    uint32_t nlink = anon ? 0u : 1u;
    uint32_t flags = anon ? (uint32_t)STM_INO_FLAG_ORPHAN : 0u;
    struct stm_inode_value v;
    uint64_t chosen;

    if (freed) {
        chosen = freed_ino;
        in_init_value(&v, dataset_id, chosen, freed_prior_gen + 1u,
                      mode, uid, gid, nlink, flags);
    } else {
        /* AllocFresh path: ino = next_ino[ds]. UINT64_MAX is reserved
         * as the saturation sentinel (inode.h R69 P3-1). */
        if (s->next_ino == UINT64_MAX) {
            must_unlock(idx_lock(idx));
            return STM_ENOSPC;
        }
        chosen = s->next_ino;
        in_init_value(&v, dataset_id, chosen, /*gen=*/0u,
                      mode, uid, gid, nlink, flags);
    }

    stm_status ps = in_engine_put(idx, dataset_id, chosen, &v);
    if (ps != STM_OK) {
        /* Engine insert is failure-atomic: on the AllocReused path the
         * FREED record is untouched; on the AllocFresh path no key was
         * inserted and next_ino is not bumped. */
        must_unlock(idx_lock(idx));
        return ps;
    }
    if (!freed) s->next_ino = chosen + 1u;    /* bump only on the fresh
                                               * path, only after success */
    *out_ino = chosen;
    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_alloc(stm_inode_index *idx, uint64_t dataset_id,
                              uint32_t mode, uint32_t uid, uint32_t gid,
                              uint64_t *out_ino) {
    return in_alloc_common(idx, dataset_id, mode, uid, gid,
                           /*anon=*/false, out_ino);
}

/* P8-POSIX-7a-anon: alloc_anon — same allocation policy as
 * stm_inode_alloc but produces an orphan inode (nlink=0 +
 * STM_INO_FLAG_ORPHAN set). Models inode.tla's AllocAnon. */
stm_status stm_inode_alloc_anon(stm_inode_index *idx, uint64_t dataset_id,
                                   uint32_t mode, uint32_t uid, uint32_t gid,
                                   uint64_t *out_ino) {
    return in_alloc_common(idx, dataset_id, mode, uid, gid,
                           /*anon=*/true, out_ino);
}

/* P8-POSIX-7a-anon: materialize — flip an orphan inode to linked.
 * Models inode.tla's Materialize action. */
stm_status stm_inode_materialize(stm_inode_index *idx, uint64_t dataset_id,
                                    uint64_t ino) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (!idx->eng) { must_unlock(idx_lock(idx)); return STM_EINVAL; }

    struct stm_inode_value v;
    bool found = false;
    stm_status gs = in_engine_get(idx, dataset_id, ino, &v, &found);
    if (gs != STM_OK) { must_unlock(idx_lock(idx)); return gs; }
    if (!found || (stm_load_le32(v.si_flags) & STM_INO_FLAG_FREED)) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }

    /* Must be in orphan state: ORPHAN flag set + nlink == 0. */
    uint32_t flags = stm_load_le32(v.si_flags);
    uint32_t nlink = stm_load_le32(v.si_nlink);
    if (!(flags & STM_INO_FLAG_ORPHAN) || nlink != 0) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    /* Flip: clear ORPHAN, set nlink=1. si_gen preserved
     * (TupleUniqueAllTime — handle stability across materialization). */
    v.si_flags = stm_store_le32(flags & ~(uint32_t)STM_INO_FLAG_ORPHAN);
    v.si_nlink = stm_store_le32(1u);
    stm_status ps = in_engine_put(idx, dataset_id, ino, &v);
    must_unlock(idx_lock(idx));
    return ps;
}

stm_status stm_inode_free(stm_inode_index *idx, uint64_t dataset_id,
                             uint64_t ino) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (!idx->eng) { must_unlock(idx_lock(idx)); return STM_EINVAL; }

    struct stm_inode_value v;
    bool found = false;
    stm_status gs = in_engine_get(idx, dataset_id, ino, &v, &found);
    if (gs != STM_OK) { must_unlock(idx_lock(idx)); return gs; }
    uint32_t flags = stm_load_le32(v.si_flags);
    if (!found || (flags & STM_INO_FLAG_FREED)) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }

    /* Encode FREED state in si_flags so the on-disk record carries
     * the lifecycle bit. Clear nlink (a freed inode has zero links);
     * gen is preserved for the next AllocReused's bump.
     *
     * R85 P0-1: ALSO clear STM_INO_FLAG_ORPHAN — the decoder enforces
     * FREED+ORPHAN as structurally inconsistent (orphans are an
     * ALLOCATED intermediate; freeing one extinguishes the orphan
     * property). Leaving both bits set would wedge the next mount's
     * scan with STM_ECORRUPT. */
    flags = (flags | (uint32_t)STM_INO_FLAG_FREED) &
            ~(uint32_t)STM_INO_FLAG_ORPHAN;
    v.si_flags = stm_store_le32(flags);
    v.si_nlink = stm_store_le32(0u);
    stm_status ps = in_engine_put(idx, dataset_id, ino, &v);
    must_unlock(idx_lock(idx));
    return ps;
}

/* P8-POSIX-3: nlink-aware Link. Models inode.tla's Link action. */
stm_status stm_inode_link(stm_inode_index *idx, uint64_t dataset_id,
                              uint64_t ino) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (!idx->eng) { must_unlock(idx_lock(idx)); return STM_EINVAL; }

    struct stm_inode_value v;
    bool found = false;
    stm_status gs = in_engine_get(idx, dataset_id, ino, &v, &found);
    if (gs != STM_OK) { must_unlock(idx_lock(idx)); return gs; }
    uint32_t flags = stm_load_le32(v.si_flags);
    if (!found || (flags & STM_INO_FLAG_FREED)) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    /* P8-POSIX-7a-anon: orphan inodes must go through stm_inode_materialize
     * for the first link — refuse explicitly so a buggy wrapper can't
     * bump nlink past 0 while leaving the ORPHAN flag set. */
    if (flags & STM_INO_FLAG_ORPHAN) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    uint32_t cur_nlink = stm_load_le32(v.si_nlink);
    if (cur_nlink == UINT32_MAX) {
        must_unlock(idx_lock(idx));
        return STM_EOVERFLOW;
    }
    v.si_nlink = stm_store_le32(cur_nlink + 1u);
    stm_status ps = in_engine_put(idx, dataset_id, ino, &v);
    must_unlock(idx_lock(idx));
    return ps;
}

stm_status stm_inode_unlink(stm_inode_index *idx, uint64_t dataset_id,
                                uint64_t ino, bool *out_freed) {
    if (out_freed) *out_freed = false;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (!idx->eng) { must_unlock(idx_lock(idx)); return STM_EINVAL; }

    struct stm_inode_value v;
    bool found = false;
    stm_status gs = in_engine_get(idx, dataset_id, ino, &v, &found);
    if (gs != STM_OK) { must_unlock(idx_lock(idx)); return gs; }
    uint32_t flags = stm_load_le32(v.si_flags);
    if (!found || (flags & STM_INO_FLAG_FREED)) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    /* P8-POSIX-7a-anon: orphan inodes aren't linked to any dirent —
     * caller must use stm_inode_free (via stm_fs_unlink_anon). */
    if (flags & STM_INO_FLAG_ORPHAN) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    uint32_t cur_nlink = stm_load_le32(v.si_nlink);
    if (cur_nlink == 0u) {
        /* ALLOCATED + nlink=0 + non-orphan is the corrupt-record shape
         * inode.tla::LinkedAllocatedHasPositiveNlink pins against. */
        must_unlock(idx_lock(idx));
        return STM_ECORRUPT;
    }
    uint32_t new_nlink = cur_nlink - 1u;
    bool cascade = (new_nlink == 0u);
    if (cascade) {
        /* Cascade-free per inode.tla::Unlink: atomically transition to
         * FREED + zero nlink + set FREED flag. gen preserved. R85 P3-1
         * (defense-in-depth): also clear ORPHAN — today unreachable
         * (orphan inputs refused above) but the right hygiene. */
        flags = (flags | (uint32_t)STM_INO_FLAG_FREED) &
                ~(uint32_t)STM_INO_FLAG_ORPHAN;
        v.si_flags = stm_store_le32(flags);
        v.si_nlink = stm_store_le32(0u);
    } else {
        v.si_nlink = stm_store_le32(new_nlink);
    }
    stm_status ps = in_engine_put(idx, dataset_id, ino, &v);
    if (ps == STM_OK && out_freed) *out_freed = cascade;
    must_unlock(idx_lock(idx));
    return ps;
}

stm_status stm_inode_lookup(const stm_inode_index *idx,
                               uint64_t dataset_id, uint64_t ino,
                               struct stm_inode_value *out_value) {
    if (!idx || !out_value) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (!idx->eng) { must_unlock(idx_lock(idx)); return STM_EINVAL; }

    struct stm_inode_value v;
    bool found = false;
    stm_status gs = in_engine_get(idx, dataset_id, ino, &v, &found);
    if (gs != STM_OK) { must_unlock(idx_lock(idx)); return gs; }
    if (!found || (stm_load_le32(v.si_flags) & STM_INO_FLAG_FREED)) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    *out_value = v;
    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_set(stm_inode_index *idx, uint64_t dataset_id,
                            uint64_t ino,
                            const struct stm_inode_value *in_value) {
    if (!idx || !in_value) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (!idx->eng) { must_unlock(idx_lock(idx)); return STM_EINVAL; }

    stm_status rc = STM_OK;

    struct stm_inode_value cur;
    bool found = false;
    stm_status gs = in_engine_get(idx, dataset_id, ino, &cur, &found);
    if (gs != STM_OK) { rc = gs; goto out; }
    if (!found || (stm_load_le32(cur.si_flags) & STM_INO_FLAG_FREED)) {
        rc = STM_ENOENT;
        goto out;
    }

    /* Identity must match the lookup key. */
    if (stm_load_le64(in_value->si_ino) != ino) { rc = STM_EINVAL; goto out; }
    if (stm_load_le64(in_value->si_dataset_id) != dataset_id) {
        rc = STM_EINVAL;
        goto out;
    }
    /* Protect the (ino, gen) tuple uniqueness invariant: callers cannot
     * rewrite gen via Set. The allocator owns gen. */
    if (stm_load_le64(in_value->si_gen) != stm_load_le64(cur.si_gen)) {
        rc = STM_EINVAL;
        goto out;
    }
    /* R69 P3-3: reject unknown si_data_kind. */
    switch (in_value->si_data_kind) {
        case STM_DATA_EXTENT:
        case STM_DATA_INLINE:
        case STM_DATA_SYMLINK:
        case STM_DATA_DEVICE:
            break;
        default:
            rc = STM_EINVAL;
            goto out;
    }
    /* R77 P1-1: bound si_data_len for INLINE / SYMLINK kinds — symmetric
     * with the decoder-side guard so a hostile or buggy caller can't
     * commit a record that would OOB-read downstream. */
    if (in_value->si_data_kind == STM_DATA_INLINE ||
        in_value->si_data_kind == STM_DATA_SYMLINK) {
        if (in_value->si_data_len > STM_INODE_INLINE_MAX) {
            rc = STM_EINVAL;
            goto out;
        }
    }
    /* The FREED bit is the allocator's internal lifecycle marker —
     * callers reach FREED via stm_inode_free, not by writing the flag.
     * P8-POSIX-7a-anon: the ORPHAN bit likewise — Set must not toggle
     * it (orphan-state transitions go through alloc_anon / materialize). */
    {
        uint32_t flags     = stm_load_le32(in_value->si_flags);
        uint32_t cur_flags = stm_load_le32(cur.si_flags);
        if (flags & STM_INO_FLAG_FREED) { rc = STM_EINVAL; goto out; }
        bool in_orphan  = (flags     & STM_INO_FLAG_ORPHAN) != 0;
        bool cur_orphan = (cur_flags & STM_INO_FLAG_ORPHAN) != 0;
        if (in_orphan != cur_orphan) { rc = STM_EINVAL; goto out; }
    }
    /* R71 P1-1: pin the FREED <=> nlink>=1 invariant on the WRITE side.
     * P8-POSIX-7a-anon: orphan inodes legitimately have nlink=0; the
     * dual invariant (ORPHAN => nlink=0) is enforced symmetrically. */
    {
        uint32_t in_flags = stm_load_le32(in_value->si_flags);
        bool in_orphan = (in_flags & STM_INO_FLAG_ORPHAN) != 0;
        uint32_t in_nlink = stm_load_le32(in_value->si_nlink);
        if (!in_orphan && in_nlink == 0) { rc = STM_EINVAL; goto out; }
        if (in_orphan && in_nlink != 0)  { rc = STM_EINVAL; goto out; }
    }
    /* R82 P2-2: pin the seal-stickiness invariant on the writer side —
     * a write that clears a previously-set seal bit is rejected. */
    {
        uint32_t in_seals  = stm_load_le32(in_value->si_flags) &
                             (uint32_t)STM_INO_FLAG_SEAL_MASK;
        uint32_t cur_seals = stm_load_le32(cur.si_flags) &
                             (uint32_t)STM_INO_FLAG_SEAL_MASK;
        if (cur_seals & ~in_seals) { rc = STM_EINVAL; goto out; }
    }

    /* R70 P3-4 + R69 P3-2: build the canonical post-write candidate
     * (caller's value with si_reserved zeroed) and skip the engine
     * write when the candidate is byte-identical to the current
     * record — avoids re-COWing a root-to-leaf path for a no-op Set. */
    {
        struct stm_inode_value candidate = *in_value;
        memset(candidate.si_reserved, 0, sizeof candidate.si_reserved);
        if (memcmp(&candidate, &cur, sizeof candidate) == 0) {
            rc = STM_OK;
            goto out;
        }
        rc = in_engine_put(idx, dataset_id, ino, &candidate);
    }

out:
    must_unlock(idx_lock(idx));
    return rc;
}

stm_status stm_inode_count_for_ds(const stm_inode_index *idx,
                                     uint64_t dataset_id,
                                     size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;

    *out_count = 0;
    must_lock(idx_lock(idx));
    if (!idx->eng) { must_unlock(idx_lock(idx)); return STM_EINVAL; }

    uint8_t lo[IN_KEY_LEN], hi[IN_KEY_LEN];
    in_encode_key(dataset_id, 0u,         lo);
    in_encode_key(dataset_id, UINT64_MAX, hi);
    in_count_ctx c = { .count = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(idx->eng, lo, IN_KEY_LEN,
                                                hi, IN_KEY_LEN,
                                                in_count_cb, &c);
    must_unlock(idx_lock(idx));
    if (ss != STM_OK) return ss;
    if (c.err != STM_OK) return c.err;
    *out_count = c.count;
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
/* Public API — persistence (P8-POSIX-1b + 9.6-impl-4b-ii).            */
/* ------------------------------------------------------------------ */

stm_status stm_inode_index_set_storage(stm_inode_index *idx,
                                          stm_bdev *bdev_0,
                                          stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(idx_lock(idx));
    /* R70 P3-6: refuse re-binding once latched. */
    if (idx->storage_set) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    idx->store_ctx.bdev = bdev_0;
    idx->store_ctx.boot = boot_0;
    /* If crypt is already bound this is the SECOND bind — both the
     * engine's vt_ctx (&store_ctx) and cx (&crypt_ctx) are now
     * populated, so stand the engine up. A create failure leaves
     * storage_set false so the caller may retry. */
    if (idx->crypt_set && !idx->eng) {
        stm_status es = in_engine_create_locked(idx);
        if (es != STM_OK) {
            must_unlock(idx_lock(idx));
            return es;
        }
    }
    idx->storage_set = true;
    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_inode_index_set_crypt_ctx(stm_inode_index *idx,
                                            const uint8_t *metadata_key,
                                            const uint64_t pool_uuid[2],
                                            const uint64_t device_uuid_0[2]) {
    if (!idx || !metadata_key || !pool_uuid || !device_uuid_0) return STM_EINVAL;
    must_lock(idx_lock(idx));
    /* R70 P3-6: refuse re-binding once latched. */
    if (idx->crypt_set) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    idx->crypt_ctx.metadata_key   = metadata_key;
    idx->crypt_ctx.pool_uuid[0]   = pool_uuid[0];
    idx->crypt_ctx.pool_uuid[1]   = pool_uuid[1];
    idx->crypt_ctx.device_uuid[0] = device_uuid_0[0];
    idx->crypt_ctx.device_uuid[1] = device_uuid_0[1];
    /* Second-bind: stand the engine up (see set_storage). */
    if (idx->storage_set && !idx->eng) {
        stm_status es = in_engine_create_locked(idx);
        if (es != STM_OK) {
            must_unlock(idx_lock(idx));
            return es;
        }
    }
    idx->crypt_set = true;
    must_unlock(idx_lock(idx));
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

stm_status stm_inode_index_commit(stm_inode_index *idx,
                                     uint64_t committed_gen,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    must_lock(idx_lock(idx));

    if (!idx->storage_set || !idx->crypt_set || !idx->eng) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    /* Single-shot incremental-COW commit: flush the dirty root-to-leaf
     * paths + finalize, no pending window left open. A clean tree's
     * commit is a cheap no-op (the engine subsumes the old explicit
     * !dirty short-circuit). committed_gen is stm_sync_commit's
     * target_gen — strictly increasing across commits, so the engine's
     * monotonic-gen guard never fires. */
    uint64_t cp = 0;
    uint8_t  cc[32];
    stm_status cs = stm_btree_engine_commit(idx->eng, committed_gen, &cp, cc);
    if (cs != STM_OK) {
        /* A failed commit self-reverts — the engine drops the in-memory
         * tree, leaves no pending window, and the durable root still
         * names the previous tree. 9.6-impl-4b design §5.5: a failed
         * stm_sync_commit is crash-equivalent; the caller wedges the fs. */
        must_unlock(idx_lock(idx));
        return cs;
    }

    /* Read back the authoritative durable triple. A no-op clean commit
     * keeps the root's PRIOR write gen — that, not committed_gen, is the
     * gen the uberblock must record + the gen a future mount opens at. */
    uint64_t rp = 0, rg = 0;
    uint8_t  rc[32];
    stm_status gs = stm_btree_engine_get_root(idx->eng, &rp, &rg, rc);
    if (gs != STM_OK) {
        must_unlock(idx_lock(idx));
        return gs;
    }

    /* Make the bootstrap bitmap durable — the engine's vt->reserve set
     * node bits in RAM; this fsyncs them. 9.6-impl-4b-ii keeps this
     * call inside the inode commit (the exact monolithic btree_store
     * shape, so stm_sync_commit is unchanged). 4b-iii relocates it into
     * stm_sync_commit, strictly before the uberblock write — the
     * crash-safe order (4b design note §5). On failure the fs wedges +
     * remounts off the previous (still-consistent) uberblock; no
     * rollback is needed here. */
    stm_status bs = stm_bootstrap_commit(idx->store_ctx.boot, committed_gen);
    if (bs != STM_OK) {
        must_unlock(idx_lock(idx));
        return bs;
    }

    idx->root_paddr = rp;
    idx->root_gen   = rg;
    memcpy(idx->root_csum, rc, 32);

    *out_root_paddr = rp;
    memcpy(out_root_csum, rc, 32);
    must_unlock(idx_lock(idx));
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* load_at — open the on-disk engine + rebuild dsstate from a scan.    */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_inode_dsstate *arr;
    size_t             n;
    size_t             cap;
    stm_status         err;
} in_mount_ctx;

/* find-or-grow a dsstate slot in the mount scratch; NULL on STM_ENOMEM.
 * A fresh slot starts at next_ino=0; the walk raises it to max(ino)+1. */
static stm_inode_dsstate *in_mount_dsstate(in_mount_ctx *c, uint64_t ds) {
    for (size_t i = 0; i < c->n; i++) {
        if (c->arr[i].dataset_id == ds) return &c->arr[i];
    }
    if (c->n == c->cap) {
        if (c->cap > (SIZE_MAX / sizeof *c->arr) / 2u) return NULL;
        size_t nc = c->cap == 0 ? 4u : c->cap * 2u;
        stm_inode_dsstate *na = realloc(c->arr, nc * sizeof *na);
        if (!na) return NULL;
        c->arr = na;
        c->cap = nc;
    }
    stm_inode_dsstate *s = &c->arr[c->n++];
    s->dataset_id = ds;
    s->next_ino   = 0u;
    return s;
}

/* Per-record mount-scan callback: validate the record (a corrupt tree
 * fails the mount HERE — parity with the retired btree_store load_at's
 * deserialize+validate) and raise the per-dataset next_ino high-water
 * mark. */
static int in_mount_cb(const void *k, size_t klen,
                       const void *v, size_t vlen, void *ctx_) {
    in_mount_ctx *c = ctx_;
    uint64_t ds = 0, ino = 0;
    stm_status ks = in_decode_key(k, klen, &ds, &ino);
    if (ks != STM_OK) { c->err = ks; return 1; }
    /* R70 P3-2: ino == UINT64_MAX would wrap the next_ino raise below;
     * ds / ino == 0 are reserved sentinels. */
    if (ds == 0 || ino == 0 || ino == UINT64_MAX) {
        c->err = STM_ECORRUPT;
        return 1;
    }
    if (vlen != IN_VAL_LEN) { c->err = STM_ECORRUPT; return 1; }
    struct stm_inode_value val;
    memcpy(&val, v, IN_VAL_LEN);
    stm_status vs = in_validate_value(&val, ds, ino);
    if (vs != STM_OK) { c->err = vs; return 1; }

    stm_inode_dsstate *s = in_mount_dsstate(c, ds);
    if (!s) { c->err = STM_ENOMEM; return 1; }
    if (ino + 1u > s->next_ino) s->next_ino = ino + 1u;
    return 0;
}

stm_status stm_inode_index_load_at(stm_inode_index *idx,
                                      uint64_t root_paddr, uint64_t root_gen,
                                      const uint8_t expected_csum[32]) {
    if (!idx || !expected_csum) return STM_EINVAL;
    if (root_paddr == 0) return STM_EINVAL;
    must_lock(idx_lock(idx));
    if (!idx->storage_set || !idx->crypt_set) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    /* Open the on-disk tree (lazy — no device I/O until the scan
     * descends). */
    stm_btree_engine *opened = NULL;
    stm_status os = stm_btree_engine_open(&STM_ENGINE_STORE_VT,
                                          &idx->store_ctx, &idx->crypt_ctx,
                                          /*tree_id=*/0u,
                                          root_paddr, root_gen, expected_csum,
                                          &opened);
    if (os != STM_OK) {
        must_unlock(idx_lock(idx));
        return os;
    }

    /* Walk every record into a scratch dsstate: validate it + raise
     * next_ino = max(ino)+1 per dataset. The walk reads + AEAD/Merkle-
     * verifies every node; in_validate_value adds the semantic layer. */
    in_mount_ctx mc = { .arr = NULL, .n = 0, .cap = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan(opened, in_mount_cb, &mc);
    if (ss != STM_OK || mc.err != STM_OK) {
        free(mc.arr);
        stm_btree_engine_destroy(opened);
        must_unlock(idx_lock(idx));
        return ss != STM_OK ? ss : mc.err;
    }

    /* Atomic install: drop the prior engine (the fresh one stood up by
     * the second binder, or a previously-loaded one) + dsstate, adopt
     * the opened tree. */
    stm_btree_engine_destroy(idx->eng);
    idx->eng          = opened;
    free(idx->dsstate);
    idx->dsstate      = mc.arr;
    idx->n_datasets   = mc.n;
    idx->cap_datasets = mc.cap;

    idx->root_paddr = root_paddr;
    idx->root_gen   = root_gen;
    memcpy(idx->root_csum, expected_csum, 32);

    must_unlock(idx_lock(idx));
    return STM_OK;
}

/* ====================================================================== */
/* Per-inode locks (P9.5-PARALLEL-3 impl-1).                              */
/*                                                                          */
/* The hash mixes dataset_id and ino into a 256-bucket fixed-size table.   */
/* Distinct inodes within the same dataset typically have low ino values,  */
/* so we fold the high bits via a multiply-and-xor mix that spreads bits   */
/* across all 8 output bits. Collisions are handled by linear chain walk   */
/* under idx->lock. Striping is forward-noted: bucket head reads/writes   */
/* serialize on idx->lock today; a finer-grained per-bucket mutex is a    */
/* future optimization if pin contention becomes load-bearing.            */
/*                                                                          */
/* The pool is independent of the inode store — the 9.6-impl-4b-ii cutover */
/* changes only stm_inode_pin's existence pre-check (find_record ->        */
/* in_engine_get); everything else here is verbatim.                       */
/* ====================================================================== */

/* xxhash-style mix → 8-bit bucket index. */
static inline size_t handle_bucket(uint64_t dataset_id, uint64_t ino) {
    uint64_t h = dataset_id;
    h ^= ino + 0x9e3779b97f4a7c15ull;
    h ^= (h >> 33);
    h *= 0xff51afd7ed558ccdull;
    h ^= (h >> 33);
    h *= 0xc4ceb9fe1a85ec53ull;
    h ^= (h >> 33);
    return (size_t)(h & (uint64_t)(STM_INODE_HANDLE_BUCKETS - 1u));
}

/* Find or allocate the lock slot for (dataset_id, ino). Bumps refcount
 * on success. Caller holds idx->lock. Returns NULL on STM_ENOMEM (init
 * of the per-slot mutex failed). */
static struct stm_inode_handle *
handle_get_or_alloc_locked(stm_inode_index *idx,
                              uint64_t dataset_id, uint64_t ino) {
    size_t b = handle_bucket(dataset_id, ino);
    for (struct stm_inode_handle *h = idx->handle_buckets[b]; h; h = h->next) {
        if (h->dataset_id == dataset_id && h->ino == ino) {
            h->refcount++;
            return h;
        }
    }
    struct stm_inode_handle *h = malloc(sizeof *h);
    if (!h) return NULL;
    h->dataset_id = dataset_id;
    h->ino        = ino;
    h->refcount   = 1u;
    h->next       = idx->handle_buckets[b];

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        free(h);
        return NULL;
    }
    /* ERRORCHECK: a buggy double-pin from the same thread aborts here
     * rather than silently allowing a recursive lock — matches the
     * spec's WriterAtomicPerInode posture (at most one writer per
     * inode at any time). */
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        pthread_mutexattr_destroy(&attr);
        free(h);
        return NULL;
    }
    int rc = pthread_mutex_init(&h->mu, &attr);
    pthread_mutexattr_destroy(&attr);
    if (rc != 0) {
        free(h);
        return NULL;
    }
    idx->handle_buckets[b] = h;
    return h;
}

/* Decrement refcount on the slot; if 0, remove from bucket chain +
 * free. Caller holds idx->lock. */
static void handle_release_locked(stm_inode_index *idx,
                                       struct stm_inode_handle *h) {
    if (h->refcount > 1u) {
        h->refcount--;
        return;
    }
    size_t b = handle_bucket(h->dataset_id, h->ino);
    struct stm_inode_handle **pp = &idx->handle_buckets[b];
    while (*pp && *pp != h) pp = &(*pp)->next;
    /* If the slot is unlinked while still referenced, that's a leak we
     * surface loudly rather than mask. Reachability is theoretical
     * (handle_get_or_alloc_locked is the only inserter). */
    if (*pp != h) abort();
    *pp = h->next;
    pthread_mutex_destroy(&h->mu);
    free(h);
}

stm_status stm_inode_pin(stm_inode_index *idx, uint64_t dataset_id,
                            uint64_t ino, stm_inode_handle **out_handle) {
    if (!idx || !out_handle) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    /* Validate the record exists + is allocated BEFORE taking the
     * per-inode mutex. This pre-check avoids alloc-then-fail thrash
     * for the common missing-inode case. */
    must_lock(idx_lock(idx));
    if (!idx->eng) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    struct stm_inode_value v;
    bool found = false;
    stm_status gs = in_engine_get(idx, dataset_id, ino, &v, &found);
    if (gs != STM_OK) {
        must_unlock(idx_lock(idx));
        return gs;
    }
    if (!found || (stm_load_le32(v.si_flags) & STM_INO_FLAG_FREED)) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    struct stm_inode_handle *h = handle_get_or_alloc_locked(idx,
                                                                  dataset_id, ino);
    if (!h) {
        must_unlock(idx_lock(idx));
        return STM_ENOMEM;
    }
    must_unlock(idx_lock(idx));

    /* Acquire the per-inode mutex; may block on a concurrent holder.
     * The slot remains live (refcount >= 1 thanks to our bump) for
     * the duration of this wait. */
    if (pthread_mutex_lock(&h->mu) != 0) {
        must_lock(idx_lock(idx));
        handle_release_locked(idx, h);
        must_unlock(idx_lock(idx));
        return STM_EBACKEND;
    }

    /* TOCTOU re-validate: between the pre-check and acquiring h->mu,
     * the holding writer may have freed the inode. Re-check under
     * both locks. */
    must_lock(idx_lock(idx));
    found = false;
    gs = in_engine_get(idx, dataset_id, ino, &v, &found);
    if (gs != STM_OK || !found ||
        (stm_load_le32(v.si_flags) & STM_INO_FLAG_FREED)) {
        stm_status rc = (gs != STM_OK) ? gs : STM_ENOENT;
        must_unlock(idx_lock(idx));
        pthread_mutex_unlock(&h->mu);
        must_lock(idx_lock(idx));
        handle_release_locked(idx, h);
        must_unlock(idx_lock(idx));
        return rc;
    }
    must_unlock(idx_lock(idx));

    *out_handle = h;
    return STM_OK;
}

void stm_inode_unpin(stm_inode_index *idx, stm_inode_handle *handle) {
    if (!idx || !handle) return;
    pthread_mutex_unlock(&handle->mu);
    must_lock(idx_lock(idx));
    handle_release_locked(idx, handle);
    must_unlock(idx_lock(idx));
}

/* P9.5-PARALLEL-3 impl-2: pin two inodes in canonical ascending
 * (dataset_id, ino) order. The caller passes them in arbitrary order;
 * the helper sorts internally, pins the lower one first, then the
 * higher. Returns handles in CALLER-SPECIFIED slot order — `*out_a`
 * corresponds to `(ds_a, ino_a)` regardless of which one got pinned
 * first.
 *
 * On second-pin failure, the first pin is rolled back so the caller
 * sees an atomic success/fail. */
stm_status stm_inode_pin_two(stm_inode_index *idx,
                                uint64_t ds_a, uint64_t ino_a,
                                uint64_t ds_b, uint64_t ino_b,
                                stm_inode_handle **out_a,
                                stm_inode_handle **out_b) {
    if (!idx || !out_a || !out_b) return STM_EINVAL;
    if (ds_a == 0u || ino_a == 0u) return STM_EINVAL;
    if (ds_b == 0u || ino_b == 0u) return STM_EINVAL;
    if (ds_a == ds_b && ino_a == ino_b) return STM_EINVAL;

    *out_a = NULL;
    *out_b = NULL;

    /* Determine ascending order on (dataset_id, ino) lex key. */
    bool a_first = (ds_a < ds_b) || (ds_a == ds_b && ino_a < ino_b);

    uint64_t ds_lo, ino_lo, ds_hi, ino_hi;
    if (a_first) {
        ds_lo = ds_a; ino_lo = ino_a;
        ds_hi = ds_b; ino_hi = ino_b;
    } else {
        ds_lo = ds_b; ino_lo = ino_b;
        ds_hi = ds_a; ino_hi = ino_a;
    }

    stm_inode_handle *h_lo = NULL;
    stm_status sl = stm_inode_pin(idx, ds_lo, ino_lo, &h_lo);
    if (sl != STM_OK) return sl;

    stm_inode_handle *h_hi = NULL;
    stm_status sh = stm_inode_pin(idx, ds_hi, ino_hi, &h_hi);
    if (sh != STM_OK) {
        stm_inode_unpin(idx, h_lo);
        return sh;
    }

    /* Distribute handles back to caller's slot order. */
    if (a_first) {
        *out_a = h_lo;
        *out_b = h_hi;
    } else {
        *out_a = h_hi;
        *out_b = h_lo;
    }
    return STM_OK;
}

/*
 * stm_inode_pin_many — generalised pin_two for N up to
 * STM_INODE_PIN_MANY_MAX (16).
 *
 * Algorithm:
 *   1. Validate args + bounds.
 *   2. Build a permutation `order[0..n-1]` such that
 *      `(requests[order[k]].dataset_id, requests[order[k]].ino)` is
 *      strictly ascending in `k`.
 *   3. Refuse if any two adjacent entries in the sorted order have
 *      the same (ds, ino) pair (duplicate detection).
 *   4. Pin in sorted order. On any pin failure, release all
 *      previously-acquired pins (in reverse order — doesn't matter
 *      semantically but matches conventional unwinding).
 *   5. Map handles back into caller slot order via the inverse
 *      permutation.
 *
 * N is small (≤ 16) so an O(N²) selection sort is fine and avoids
 * heap allocation. Stack-only.
 */
stm_status stm_inode_pin_many(stm_inode_index *idx,
                                 const struct stm_inode_pin_request *requests,
                                 size_t n,
                                 stm_inode_handle **out_handles) {
    if (!idx || !requests || !out_handles) return STM_EINVAL;
    if (n == 0u || n > STM_INODE_PIN_MANY_MAX) return STM_EINVAL;
    for (size_t k = 0u; k < n; k++) {
        if (requests[k].dataset_id == 0u || requests[k].ino == 0u) {
            return STM_EINVAL;
        }
    }

    /* Zero all output slots up front. */
    for (size_t k = 0u; k < n; k++) {
        out_handles[k] = NULL;
    }

    /* order[k] = index into requests[] for the k-th element in ascending
     * (ds, ino) order. Initialize identity, then selection-sort. */
    size_t order[STM_INODE_PIN_MANY_MAX];
    for (size_t k = 0u; k < n; k++) order[k] = k;

    /* Selection sort on order[] by (requests[order[k]].dataset_id,
     * requests[order[k]].ino) ascending. O(N²) but N ≤ 16. */
    for (size_t i = 0u; i + 1u < n; i++) {
        size_t min_pos = i;
        for (size_t j = i + 1u; j < n; j++) {
            const struct stm_inode_pin_request *a = &requests[order[min_pos]];
            const struct stm_inode_pin_request *b = &requests[order[j]];
            if (b->dataset_id < a->dataset_id ||
                (b->dataset_id == a->dataset_id && b->ino < a->ino)) {
                min_pos = j;
            }
        }
        if (min_pos != i) {
            size_t tmp = order[i];
            order[i] = order[min_pos];
            order[min_pos] = tmp;
        }
    }

    /* Duplicate detection on the sorted run: adjacent entries with
     * equal (ds, ino) → STM_EINVAL. Pinning a duplicate would deadlock
     * on the per-slot ERRORCHECK mutex. */
    for (size_t k = 1u; k < n; k++) {
        const struct stm_inode_pin_request *prev = &requests[order[k - 1u]];
        const struct stm_inode_pin_request *curr = &requests[order[k]];
        if (prev->dataset_id == curr->dataset_id && prev->ino == curr->ino) {
            return STM_EINVAL;
        }
    }

    /* Pin in ascending order. handles_sorted[k] receives the handle
     * for requests[order[k]]; we map back to caller slot order at the
     * end. */
    stm_inode_handle *handles_sorted[STM_INODE_PIN_MANY_MAX] = {0};
    for (size_t k = 0u; k < n; k++) {
        const struct stm_inode_pin_request *req = &requests[order[k]];
        stm_status ps = stm_inode_pin(idx, req->dataset_id, req->ino,
                                          &handles_sorted[k]);
        if (ps != STM_OK) {
            /* Roll back every previously-acquired pin (sorted order
             * 0..k-1; unpin order is conventionally reverse). */
            for (size_t j = k; j > 0u; j--) {
                stm_inode_unpin(idx, handles_sorted[j - 1u]);
            }
            return ps;
        }
    }

    /* Map handles back into caller slot order:
     * out_handles[order[k]] = handles_sorted[k]. */
    for (size_t k = 0u; k < n; k++) {
        out_handles[order[k]] = handles_sorted[k];
    }
    return STM_OK;
}
