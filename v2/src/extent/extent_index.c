/* SPDX-License-Identifier: ISC */
/*
 * Per-dataset extent index — btree_engine-backed via an attached
 * stm_dataset_index (P7-2 → 9.6-impl-4d → 9.7-impl-1c-v).
 *
 *   see include/stratum/extent.h — public API + invariants.
 *   see v2/specs/extent.tla — formal model.
 *   see v2/docs/phase-9.7-design.md §2 — per-dataset metadata trees.
 *
 * 9.7-impl-1c-v — the extent cutover. The module no longer owns its
 * own btree_engine. Each dataset's extent records live in that
 * dataset's per-dataset engine (the substrate from 9.7-impl-1c-i),
 * resolved via an attached borrowed `stm_dataset_index *`. Every
 * public op resolves the dataset's engine on entry, atomically with
 * the extent index's own lock, and routes its lookup / scan / insert
 * / delete through that engine.
 *
 * Keys (17 bytes): `stm_metakey_compose(STM_METAKEY_KIND_EXTENT,
 *                  body, 16)` where body = `le64 ino || le64
 *                  file_offset`.
 *
 * The previous 24-byte `(le64 dataset_id || le64 ino || le64 off)`
 * form is retired — the dataset id is now woven into the engine's
 * AEAD additional-data via `tree_id = dataset_id`, so a cross-dataset
 * substitution attack fails decrypt rather than relying on the key
 * prefix.
 *
 * Values (108 bytes): kind-discriminated (HOT vs COLD); same byte
 * layout as 9.6-impl-4d (P7-CAS / v18 + P7-CAS-11 / v21 tail).
 * Unchanged from the pre-cutover encoding.
 *
 * Engine ops:
 *   write/overwrite/reflink   -> engine_lookup / scan_range to
 *                                check overlap + cohabit + paddr-
 *                                freshness, then engine_insert.
 *   truncate / delete_file /
 *   punch_range               -> scan_range over (ino, *), filter
 *                                by predicate, engine_delete each
 *                                matching key.
 *   migrate_to_cold /
 *   promote_swap_to_hot       -> upsert at same (ino, off) key.
 *   migrate_to_cold_chunked   -> upsert at src key + engine_insert
 *                                at each chunk's (ino, off).
 *   migrate_whole_ino_to_cold -> engine_delete every HOT under
 *                                (ino, *) + engine_insert every
 *                                COLD chunk.
 *   read_hit                  -> upsert at (ino, off).
 *
 * Cross-pool scans (paddr-in-use / cohabit / lookup_by_paddr /
 * count / mount_validate) walk every PRESENT dataset's engine over
 * its EXTENT subspace via `ex_global_walk_locked`. The walk is
 * 2-phase: phase 1 collects PRESENT dataset ids inside
 * `stm_dataset_iter` (the iter holds dataset_idx's internal mutex
 * for its callback; we CANNOT call `stm_dataset_index_get_engine`
 * from within because the engine resolver would re-enter that same
 * mutex and EDEADLK abort). Phase 2 walks the collected id buffer
 * and resolves + scans each engine. Bounded by N_datasets ×
 * extents-per-dataset; acceptable at small-N. A paddr→extent
 * in-RAM index is a forward-noted perf optimisation; deferred until
 * data motivates.
 *
 * extent.tla's invariants are UNCHANGED; only the storage under
 * them swapped from the pool-global engine to the per-dataset
 * engines. NoOverlapWithinIno, BirthTxgBound, LiveReplicasDisjoint,
 * SharedReplicasAreCohabit, OriginConsistentInBounds all preserved
 * verbatim — the writer-side checks now consult one engine per
 * dataset rather than the single pool-global engine.
 *
 * Concurrency: a single mutex (idx->lock) guards the ds_idx
 * pointer AND every engine call — the btree_engine is single-
 * threaded (one handle, one thread at a time), and idx->lock IS
 * that serialization. The engine handle is BORROWED from the
 * dataset index per call; lifetime is safe because the fs.c layer
 * holds fs->global SH/EX across every extent op, and
 * `stm_dataset_destroy` takes fs->global EX (so a slot's engine
 * cannot be closed mid-op).
 *
 * Audit-trigger surface: this module is on CLAUDE.md's trigger list.
 *
 * SPEC-TO-CODE mapping (unchanged from pre-cutover MVP):
 *
 *   extent.tla::Init               → stm_extent_index_create
 *   extent.tla::Write              → stm_extent_write
 *   extent.tla::Overwrite          → stm_extent_overwrite
 *   extent.tla::Truncate           → stm_extent_truncate
 *   extent.tla::Truncate (peek)    → stm_extent_truncate_peek
 *   extent.tla::Truncate (into)    → stm_extent_truncate_into
 *   extent.tla::DeleteFile         → stm_extent_delete_file
 *   extent.tla::AdvanceTxg         → stm_extent_index_advance_txg
 *   extent.tla::Reflink            → stm_extent_reflink
 *   extent.tla::TypeOK             → field types in stm_extent_record
 *   extent.tla::NoOverlapWithinIno → engine_scan_range per (ds, ino)
 *                                       at every write/overwrite/reflink
 *   extent.tla::LengthPositive     → len ≥ 1 check
 *   extent.tla::BirthTxgBound      → write_gen ≤ current_txg check
 *   extent.tla::AllExtentsInBounds → off + len overflow check
 *   extent.tla::PaddrFreshness     → ex_global_walk + allocator.tla
 *                                       ::NoReuseInSameGen
 *   extent.tla::SharedReplicasAreCohabit
 *                                   → cohabit_check via ex_global_walk
 *   extent.tla::OriginConsistentInBounds
 *                                   → encoder + decoder checks.
 */
#include <stratum/extent.h>
#include <stratum/cas.h>
#include <stratum/dataset.h>
#include <stratum/btree_engine.h>
#include <stratum/metakey.h>
#include <stratum/super.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* R53 P3-5: extent's content_hash field and CAS's hash key MUST share
 * the same byte length — chunked migrate copies between them via
 * memcpy(STM_EXTENT_HASH_LEN). If a future revision widens one without
 * the other, the copy would short-fill or buffer-overflow. */
_Static_assert(STM_EXTENT_HASH_LEN == STM_CAS_HASH_LEN,
               "extent + CAS hash lengths must agree (cross-index memcpy)");

/* MVP on-disk encoding cap: 24-bit length so `dlen` (le32 at offset 48)
 * and `clen_and_comp.clen` (low 24 bits of le32 at offset 52) both fit
 * the same value (no compression). */
#define EX_LEN_MAX_24BIT        UINT32_C(0x00FFFFFF)

/* Match snapshot.c's must_lock / must_unlock pattern. */
static inline void must_lock(pthread_mutex_t *m) {
    int rc = pthread_mutex_lock(m);
    if (rc != 0) abort();
}
static inline void must_unlock(pthread_mutex_t *m) {
    int rc = pthread_mutex_unlock(m);
    if (rc != 0) abort();
}

/* On-disk key/value lengths. */
#define EX_KEY_BODY_LEN         16u                          /* ino + off */
#define EX_KEY_LEN              (1u + EX_KEY_BODY_LEN)       /* 17 */
#define EX_VAL_LEN              108u                         /* P7-CAS-11 / v21 */

struct stm_extent_index {
    pthread_mutex_t       lock;
    uint64_t              current_txg;

    /* 9.7-impl-1c-v: borrowed dataset index. Set once by
     * stm_extent_index_attach_dataset_index; alive for the extent
     * index's lifetime. NULL pre-attach — every op refuses with
     * STM_EINVAL. */
    stm_dataset_index    *ds_idx;
};

static inline pthread_mutex_t *ex_lock(const stm_extent_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* Encoding (forward decls — definitions further down).                */
/* ------------------------------------------------------------------ */

static stm_status ex_encode_key(uint64_t ino, uint64_t off,
                                uint8_t out[EX_KEY_LEN]);
static stm_status ex_decode_key(const void *in, size_t in_len,
                                uint64_t *out_ino, uint64_t *out_off);
static stm_status ex_encode_value(const stm_extent_record *r,
                                  uint8_t out[EX_VAL_LEN]);
static stm_status ex_decode_value(const void *in, size_t in_len,
                                  uint64_t ds, uint64_t ino, uint64_t off,
                                  stm_extent_record *out_rec);

/* ------------------------------------------------------------------ */
/* Common helpers.                                                      */
/* ------------------------------------------------------------------ */

static inline bool ranges_overlap(uint64_t a_off, uint64_t a_len,
                                  uint64_t b_off, uint64_t b_len) {
    if (a_len == 0 || b_len == 0) return false;
    return a_off < b_off + b_len && b_off < a_off + a_len;
}

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

/* ------------------------------------------------------------------ */
/* Engine glue. All ops are caller-holds-idx->lock.                     */
/* ------------------------------------------------------------------ */

/*
 * Resolve the dataset's per-dataset engine handle. Caller holds
 * idx->lock.
 *
 * Returns STM_OK with *out_eng set on success. Common failures:
 *   - STM_EINVAL: ds_idx unbound (attach not called).
 *   - STM_ENOENT: dataset not PRESENT (destroyed or never created).
 *   - Engine create / open errors propagated verbatim.
 */
static stm_status ex_get_engine_locked(stm_extent_index *idx,
                                        uint64_t dataset_id,
                                        stm_btree_engine **out_eng) {
    *out_eng = NULL;
    if (idx->ds_idx == NULL) return STM_EINVAL;
    return stm_dataset_index_get_engine(idx->ds_idx, dataset_id, out_eng);
}

/* engine_lookup + decode at exact (ds, ino, off). On STM_OK: *out_found
 * is set; if true, *out holds the validated decoded record. The
 * (dataset_id, ino, off) fields are stamped from the caller's triple,
 * NOT from the value bytes. A dataset-not-present resolves as
 * not-found rather than STM_ENOENT — the engine simply has no records
 * for it. */
static stm_status ex_engine_get(stm_extent_index *idx,
                                uint64_t ds, uint64_t ino, uint64_t off,
                                stm_extent_record *out, bool *out_found) {
    *out_found = false;

    stm_btree_engine *eng = NULL;
    stm_status es = ex_get_engine_locked(idx, ds, &eng);
    if (es == STM_ENOENT) return STM_OK;        /* dataset not present */
    if (es != STM_OK) return es;

    uint8_t key[EX_KEY_LEN];
    stm_status ks = ex_encode_key(ino, off, key);
    if (ks != STM_OK) return ks;

    bool found = false;
    void *vbuf = NULL;
    size_t vlen = 0;
    stm_status ls = stm_btree_engine_lookup(eng, key, EX_KEY_LEN,
                                            &found, &vbuf, &vlen);
    if (ls != STM_OK) return ls;
    if (!found) return STM_OK;                  /* *out_found stays false */

    if (vlen != EX_VAL_LEN || !vbuf) {
        free(vbuf);
        return STM_ECORRUPT;
    }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(vbuf, vlen, ds, ino, off, &r);
    free(vbuf);
    if (vs != STM_OK) return vs;
    *out = r;
    *out_found = true;
    return STM_OK;
}

/* Encode + engine_insert (upsert). The engine's insert is failure-
 * atomic — a failed put never loses the prior value at this key. */
static stm_status ex_engine_put(stm_extent_index *idx,
                                const stm_extent_record *r) {
    stm_btree_engine *eng = NULL;
    stm_status es = ex_get_engine_locked(idx, r->dataset_id, &eng);
    if (es != STM_OK) return es;

    uint8_t key[EX_KEY_LEN];
    uint8_t val[EX_VAL_LEN];
    stm_status ks = ex_encode_key(r->ino, r->off, key);
    if (ks != STM_OK) return ks;
    stm_status vs = ex_encode_value(r, val);
    if (vs != STM_OK) return vs;
    return stm_btree_engine_insert(eng, key, EX_KEY_LEN, val, EX_VAL_LEN);
}

/* engine_delete at exact (ds, ino, off). Unlike dirent/xattr (where
 * Remove writes a TOMBSTONE via engine_insert), extent uses
 * engine_delete in the normal write-path: truncate / delete_file /
 * overwrite / punch_range / migrate_to_cold_chunked / shift_range_keys
 * all need STRUCTURAL removal (extent.tla doesn't model tombstone
 * slots; a stale extent record left in the tree would read back at
 * mount as a live extent → data corruption). */
static stm_status ex_engine_del(stm_extent_index *idx,
                                uint64_t ds, uint64_t ino, uint64_t off) {
    stm_btree_engine *eng = NULL;
    stm_status es = ex_get_engine_locked(idx, ds, &eng);
    if (es != STM_OK) return es;

    uint8_t key[EX_KEY_LEN];
    stm_status ks = ex_encode_key(ino, off, key);
    if (ks != STM_OK) return ks;
    return stm_btree_engine_delete(eng, key, EX_KEY_LEN, NULL);
}

/* ------------------------------------------------------------------ */
/* (ds, ino) prefix iteration — extent's NoOverlapWithinIno checks +    */
/* iter / truncate / punch_range / shift_range_keys all bracket the    */
/* engine at the (ino, *) prefix WITHIN a single dataset's engine.     */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t            ds;        /* stamped on every record by caller */
    stm_extent_record  *records;
    uint64_t           *offs;      /* parallel array of key.off */
    size_t              n;
    size_t              cap;
    stm_status          err;
} ex_collect_ctx;

static int ex_collect_cb(const void *k, size_t klen,
                         const void *v, size_t vlen, void *ctx_) {
    ex_collect_ctx *c = ctx_;
    uint64_t ino = 0, off = 0;
    stm_status ks = ex_decode_key(k, klen, &ino, &off);
    if (ks != STM_OK) { c->err = ks; return 1; }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, c->ds, ino, off, &r);
    if (vs != STM_OK) { c->err = vs; return 1; }

    if (c->n == c->cap) {
        if (c->cap > (SIZE_MAX / sizeof *c->records) / 2u) {
            c->err = STM_ENOMEM;
            return 1;
        }
        size_t new_cap = c->cap == 0 ? 8u : c->cap * 2u;
        stm_extent_record *nr = realloc(c->records,
                                            new_cap * sizeof *c->records);
        if (!nr) { c->err = STM_ENOMEM; return 1; }
        c->records = nr;
        uint64_t *no = realloc(c->offs, new_cap * sizeof *c->offs);
        if (!no) { c->err = STM_ENOMEM; return 1; }
        c->offs = no;
        c->cap = new_cap;
    }
    c->records[c->n] = r;
    c->offs[c->n]    = off;
    c->n++;
    return 0;
}

/* Collect every record under (ds, ino) into out_ctx. Caller holds
 * idx->lock. */
static stm_status ex_collect_in_ino_locked(stm_extent_index *idx,
                                            uint64_t ds, uint64_t ino,
                                            ex_collect_ctx *out_ctx) {
    memset(out_ctx, 0, sizeof *out_ctx);
    out_ctx->ds = ds;

    stm_btree_engine *eng = NULL;
    stm_status es = ex_get_engine_locked(idx, ds, &eng);
    if (es == STM_ENOENT) return STM_OK;        /* empty — no records */
    if (es != STM_OK) return es;

    uint8_t lo[EX_KEY_LEN], hi[EX_KEY_LEN];
    stm_status k1 = ex_encode_key(ino, 0u,         lo);
    stm_status k2 = ex_encode_key(ino, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        return k1 != STM_OK ? k1 : k2;
    }
    stm_status ss = stm_btree_engine_scan_range(eng, lo, EX_KEY_LEN,
                                                hi, EX_KEY_LEN,
                                                ex_collect_cb, out_ctx);
    if (ss != STM_OK) {
        free(out_ctx->records);
        free(out_ctx->offs);
        memset(out_ctx, 0, sizeof *out_ctx);
        return ss;
    }
    if (out_ctx->err != STM_OK) {
        stm_status err = out_ctx->err;
        free(out_ctx->records);
        free(out_ctx->offs);
        memset(out_ctx, 0, sizeof *out_ctx);
        return err;
    }
    return STM_OK;
}

static void ex_collect_free(ex_collect_ctx *c) {
    free(c->records);
    free(c->offs);
    memset(c, 0, sizeof *c);
}

/* Within (ds, ino) — does any existing extent overlap [off, off+len)?
 * Caller holds idx->lock. */
static stm_status overlap_in_ino_locked(stm_extent_index *idx,
                                        uint64_t ds, uint64_t ino,
                                        uint64_t off, uint64_t len,
                                        bool *out_overlap) {
    *out_overlap = false;
    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, ds, ino, &c);
    if (cs != STM_OK) return cs;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (ranges_overlap(e->off, e->len, off, len)) {
            *out_overlap = true;
            break;
        }
    }
    ex_collect_free(&c);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Cross-pool walk over every PRESENT dataset's EXTENT subspace.        */
/*                                                                      */
/* Two-phase pattern (the LOAD-BEARING discipline of the per-dataset    */
/* port): phase 1 collects PRESENT dataset_ids inside                  */
/* stm_dataset_iter's callback (the iter holds dataset_idx's mutex     */
/* during the callback — calling stm_dataset_index_get_engine from     */
/* inside would re-enter the same mutex and EDEADLK abort under the    */
/* ERRORCHECK mutexattr). Phase 2 iterates the collected id buffer +    */
/* resolves + scans each engine.                                       */
/*                                                                      */
/* The walk's user callback is invoked per (ds, ino, off, decoded      */
/* record) tuple in dataset-id-ascending order, with the records       */
/* within each dataset in bytewise-key order. Returning non-zero from  */
/* the user cb terminates the walk early; the per-engine scan_range    */
/* also returns immediately on user-cb signal.                         */
/* ------------------------------------------------------------------ */

typedef int (*ex_global_record_cb)(uint64_t ds, uint64_t ino,
                                       uint64_t off,
                                       const stm_extent_record *r,
                                       void *ctx);

typedef struct {
    uint64_t *ids;
    size_t    n;
    size_t    cap;
    stm_status err;
} ex_ds_collect_ctx;

static bool ex_ds_collect_cb(const stm_dataset_entry *entry, void *ctx_) {
    ex_ds_collect_ctx *c = ctx_;
    if (entry == NULL) return true;
    if (c->n == c->cap) {
        if (c->cap > (SIZE_MAX / sizeof *c->ids) / 2u) {
            c->err = STM_ENOMEM;
            return false;
        }
        size_t new_cap = c->cap == 0 ? 8u : c->cap * 2u;
        uint64_t *na = realloc(c->ids, new_cap * sizeof *c->ids);
        if (!na) { c->err = STM_ENOMEM; return false; }
        c->ids = na;
        c->cap = new_cap;
    }
    c->ids[c->n++] = entry->id;
    return true;
}

typedef struct {
    ex_global_record_cb user_cb;
    void               *user_ctx;
    uint64_t            ds;            /* current engine's dataset id */
    int                 user_signal;   /* set if user cb returned non-zero */
    stm_status          err;
} ex_global_scan_ctx;

static int ex_global_scan_adapter(const void *k, size_t klen,
                                      const void *v, size_t vlen,
                                      void *ctx_) {
    ex_global_scan_ctx *gc = ctx_;
    uint64_t ino = 0, off = 0;
    stm_status ks = ex_decode_key(k, klen, &ino, &off);
    if (ks != STM_OK) { gc->err = ks; return 1; }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, gc->ds, ino, off, &r);
    if (vs != STM_OK) { gc->err = vs; return 1; }
    int rc = gc->user_cb(gc->ds, ino, off, &r, gc->user_ctx);
    if (rc != 0) {
        gc->user_signal = rc;
        return 1;            /* propagate stop to engine scanner */
    }
    return 0;
}

/* Walk every PRESENT dataset's engine over the EXTENT subspace
 * [tag||0||0 .. tag||MAX||MAX]. Caller holds idx->lock. */
static stm_status ex_global_walk_locked(stm_extent_index *idx,
                                            ex_global_record_cb cb,
                                            void *ctx) {
    if (idx->ds_idx == NULL) return STM_EINVAL;

    /* Phase 1: collect PRESENT dataset ids. */
    ex_ds_collect_ctx dc = { .ids = NULL, .n = 0, .cap = 0, .err = STM_OK };
    stm_status is = stm_dataset_iter(idx->ds_idx, ex_ds_collect_cb, &dc);
    if (is != STM_OK || dc.err != STM_OK) {
        free(dc.ids);
        return is != STM_OK ? is : dc.err;
    }

    /* Phase 2: per-id resolve engine + scan_range over EXTENT subspace. */
    uint8_t lo[EX_KEY_LEN], hi[EX_KEY_LEN];
    stm_status k1 = ex_encode_key(0u,         0u,         lo);
    stm_status k2 = ex_encode_key(UINT64_MAX, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        free(dc.ids);
        return k1 != STM_OK ? k1 : k2;
    }

    for (size_t i = 0; i < dc.n; i++) {
        uint64_t ds = dc.ids[i];
        stm_btree_engine *eng = NULL;
        stm_status es = ex_get_engine_locked(idx, ds, &eng);
        if (es == STM_ENOENT) continue;        /* concurrent destroy; skip */
        if (es != STM_OK) { free(dc.ids); return es; }

        ex_global_scan_ctx gc = { .user_cb = cb, .user_ctx = ctx,
                                    .ds = ds, .user_signal = 0,
                                    .err = STM_OK };
        stm_status ss = stm_btree_engine_scan_range(eng, lo, EX_KEY_LEN,
                                                    hi, EX_KEY_LEN,
                                                    ex_global_scan_adapter,
                                                    &gc);
        if (ss != STM_OK || gc.err != STM_OK) {
            free(dc.ids);
            return ss != STM_OK ? ss : gc.err;
        }
        if (gc.user_signal != 0) break;        /* user requested stop */
    }

    free(dc.ids);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Whole-pool paddr / cohabit / lookup_by_paddr helpers built on the   */
/* cross-pool walk.                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    /* paddr-uniqueness probe. */
    const uint64_t  *probe_paddrs;
    size_t           n_probe;
    /* Skip-record set: triples (ds, ino, off). The records being
     * dropped are excluded — overwrite may legitimately reuse a paddr
     * a to-be-dropped record holds because that paddr is queued for
     * return-to-allocator. NULL/0 means no skip set. */
    const uint64_t  *skip_keys;
    size_t           n_skip;
    bool             collision;
    /* cohabit probe: candidate tuple. */
    bool             cohabit_active;
    const uint64_t  *cand_paddrs;
    size_t           n_cand;
    uint64_t         cand_gen;
    uint64_t         cand_key_id;
    uint64_t         cand_origin_ds;
    uint64_t         cand_origin_ino;
    uint64_t         cand_origin_off;
    bool             cohabit_ok;
} ex_check_ctx;

static int ex_check_record_cb(uint64_t ds, uint64_t ino, uint64_t off,
                                  const stm_extent_record *r, void *ctx_) {
    ex_check_ctx *gc = ctx_;

    /* Check skip set. */
    bool skipped = false;
    if (gc->skip_keys && gc->n_skip > 0) {
        for (size_t si = 0; si < gc->n_skip; si++) {
            if (gc->skip_keys[si * 3 + 0] == ds &&
                gc->skip_keys[si * 3 + 1] == ino &&
                gc->skip_keys[si * 3 + 2] == off) {
                skipped = true;
                break;
            }
        }
    }

    /* Paddr-uniqueness probe (LiveReplicasDisjoint). */
    if (gc->probe_paddrs && !skipped) {
        for (uint8_t i = 0; i < r->n_replicas && !gc->collision; i++) {
            for (size_t k = 0; k < gc->n_probe; k++) {
                if (r->paddrs[i] == gc->probe_paddrs[k]) {
                    gc->collision = true;
                    break;
                }
            }
        }
    }

    /* Cohabit probe (SharedReplicasAreCohabit). */
    if (gc->cohabit_active && gc->cohabit_ok && !skipped) {
        bool any_share = false;
        for (uint8_t i = 0; i < r->n_replicas && !any_share; i++) {
            for (size_t k = 0; k < gc->n_cand; k++) {
                if (r->paddrs[i] == gc->cand_paddrs[k]) {
                    any_share = true;
                    break;
                }
            }
        }
        if (any_share) {
            if (r->n_replicas != (uint8_t)gc->n_cand) {
                gc->cohabit_ok = false;
            } else {
                bool whole_match = true;
                for (uint8_t i = 0; i < r->n_replicas && whole_match; i++) {
                    bool found = false;
                    for (size_t k = 0; k < gc->n_cand; k++) {
                        if (r->paddrs[i] == gc->cand_paddrs[k]) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) whole_match = false;
                }
                if (!whole_match) gc->cohabit_ok = false;
                else if (r->gen != gc->cand_gen) gc->cohabit_ok = false;
                else if (r->key_id != gc->cand_key_id) gc->cohabit_ok = false;
                else if (r->origin_dataset_id != gc->cand_origin_ds)  gc->cohabit_ok = false;
                else if (r->origin_ino        != gc->cand_origin_ino) gc->cohabit_ok = false;
                else if (r->origin_off        != gc->cand_origin_off) gc->cohabit_ok = false;
            }
        }
    }
    return 0;
}

/* Cross-pool paddr-uniqueness scan. Caller holds idx->lock. */
static stm_status any_paddr_in_use_global_locked(stm_extent_index *idx,
                                                  const uint64_t *paddrs,
                                                  size_t n,
                                                  const uint64_t *skip_keys,
                                                  size_t n_skip,
                                                  bool *out_collision) {
    *out_collision = false;
    ex_check_ctx gc = {0};
    gc.probe_paddrs = paddrs;
    gc.n_probe      = n;
    gc.skip_keys    = skip_keys;
    gc.n_skip       = n_skip;
    gc.cohabit_ok   = true;
    stm_status ss = ex_global_walk_locked(idx, ex_check_record_cb, &gc);
    if (ss != STM_OK) return ss;
    *out_collision = gc.collision;
    return STM_OK;
}

/* Cross-pool cohabit check. Caller holds idx->lock. */
static stm_status cohabit_check_global_locked(stm_extent_index *idx,
                                              const uint64_t *paddrs,
                                              size_t n_paddrs,
                                              uint64_t gen, uint64_t key_id,
                                              uint64_t origin_ds,
                                              uint64_t origin_ino,
                                              uint64_t origin_off,
                                              bool *out_ok) {
    *out_ok = true;
    ex_check_ctx gc = {0};
    gc.cohabit_active     = true;
    gc.cand_paddrs        = paddrs;
    gc.n_cand             = n_paddrs;
    gc.cand_gen           = gen;
    gc.cand_key_id        = key_id;
    gc.cand_origin_ds     = origin_ds;
    gc.cand_origin_ino    = origin_ino;
    gc.cand_origin_off    = origin_off;
    gc.cohabit_ok         = true;
    stm_status ss = ex_global_walk_locked(idx, ex_check_record_cb, &gc);
    if (ss != STM_OK) return ss;
    *out_ok = gc.cohabit_ok;
    return STM_OK;
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
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK) != 0) {
        pthread_mutexattr_destroy(&attr);
        free(idx);
        return STM_ENOMEM;
    }
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
    /* 9.7-impl-1c-v: the per-dataset engines aren't ours to close —
     * they live on the borrowed ds_idx and are closed by
     * stm_dataset_index_close at its lifecycle end. We just drop the
     * borrowed pointer. */
    free(idx);
}

stm_status stm_extent_index_attach_dataset_index(stm_extent_index *idx,
                                                  stm_dataset_index *ds_idx) {
    if (!idx || !ds_idx) return STM_EINVAL;
    must_lock(ex_lock(idx));
    if (idx->ds_idx != NULL) {
        must_unlock(ex_lock(idx));
        return STM_EINVAL;
    }
    idx->ds_idx = ds_idx;
    must_unlock(ex_lock(idx));
    return STM_OK;
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
/* Writes — fresh extent / overwrite (drop overlap, insert new).        */
/* ------------------------------------------------------------------ */

stm_status stm_extent_write(stm_extent_index *idx,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t off, uint64_t len,
                              const uint64_t *paddrs, size_t n_paddrs,
                              uint64_t write_gen, uint64_t key_id) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (!paddrs) return STM_EINVAL;
    if (!replica_set_is_valid(paddrs, n_paddrs)) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    bool collision = false;
    stm_status ps = any_paddr_in_use_global_locked(idx, paddrs, n_paddrs,
                                                    NULL, 0, &collision);
    if (ps != STM_OK) {
        must_unlock(&idx->lock);
        return ps;
    }
    if (collision) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    bool overlap = false;
    stm_status os = overlap_in_ino_locked(idx, dataset_id, ino, off, len,
                                            &overlap);
    if (os != STM_OK) {
        must_unlock(&idx->lock);
        return os;
    }
    if (overlap) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .kind       = STM_EXTENT_KIND_HOT,
        .n_replicas = (uint8_t)n_paddrs,
        .gen = write_gen,
        .key_id = key_id,
        .origin_dataset_id = dataset_id,
        .origin_ino        = ino,
        .origin_off        = off,
        .link_gen          = write_gen,
    };
    for (size_t i = 0; i < n_paddrs; i++) rec.paddrs[i] = paddrs[i];
    stm_status pr = ex_engine_put(idx, &rec);
    must_unlock(&idx->lock);
    return pr;
}

stm_status stm_extent_overwrite(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  const uint64_t *new_paddrs,
                                  size_t n_new_paddrs,
                                  uint64_t write_gen, uint64_t key_id,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped) {
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
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }

    /* Cycle check: no new paddr may equal any paddr in any to-be-
     * dropped record's replica set. */
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (!ranges_overlap(e->off, e->len, off, len)) continue;
        for (size_t k = 0; k < n_new_paddrs; k++) {
            for (uint8_t r = 0; r < e->n_replicas; r++) {
                if (e->paddrs[r] == new_paddrs[k]) {
                    ex_collect_free(&c);
                    must_unlock(&idx->lock);
                    return STM_EINVAL;
                }
            }
        }
    }

    /* Build (ds, ino, off) skip-set for the cross-pool paddr check. */
    size_t total_drops = 0;
    size_t n_drops     = 0;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (!ranges_overlap(e->off, e->len, off, len)) continue;
        total_drops += e->n_replicas;
        n_drops++;
    }
    uint64_t *skip_keys = NULL;
    if (n_drops > 0) {
        skip_keys = malloc(n_drops * 3 * sizeof *skip_keys);
        if (!skip_keys) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ENOMEM;
        }
        size_t ski = 0;
        for (size_t i = 0; i < c.n; i++) {
            const stm_extent_record *e = &c.records[i];
            if (!ranges_overlap(e->off, e->len, off, len)) continue;
            skip_keys[ski * 3 + 0] = e->dataset_id;
            skip_keys[ski * 3 + 1] = e->ino;
            skip_keys[ski * 3 + 2] = e->off;
            ski++;
        }
    }

    /* Cross-pool paddr-uniqueness scan with skip set. */
    bool collision = false;
    stm_status ps = any_paddr_in_use_global_locked(idx, new_paddrs,
                                                    n_new_paddrs,
                                                    skip_keys, n_drops,
                                                    &collision);
    if (ps != STM_OK || collision) {
        free(skip_keys);
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        if (ps != STM_OK) return ps;
        return STM_EEXIST;
    }
    free(skip_keys);

    uint64_t *out_buf = NULL;
    if (total_drops > 0) {
        out_buf = calloc(total_drops, sizeof(uint64_t));
        if (!out_buf) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ENOMEM;
        }
    }

    size_t out_idx = 0;
    size_t *drop_offs_idx = NULL;
    if (n_drops > 0) {
        drop_offs_idx = malloc(n_drops * sizeof *drop_offs_idx);
        if (!drop_offs_idx) {
            free(out_buf);
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ENOMEM;
        }
    }
    size_t drop_cursor = 0;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (!ranges_overlap(e->off, e->len, off, len)) continue;
        drop_offs_idx[drop_cursor++] = i;
        for (uint8_t r = 0; r < e->n_replicas; r++) {
            out_buf[out_idx++] = e->paddrs[r];
        }
    }

    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .kind       = STM_EXTENT_KIND_HOT,
        .n_replicas = (uint8_t)n_new_paddrs,
        .gen = write_gen,
        .key_id = key_id,
        .origin_dataset_id = dataset_id,
        .origin_ino        = ino,
        .origin_off        = off,
        .link_gen          = write_gen,
    };
    for (size_t i = 0; i < n_new_paddrs; i++) rec.paddrs[i] = new_paddrs[i];

    stm_status pr = ex_engine_put(idx, &rec);
    if (pr != STM_OK) {
        free(out_buf);
        free(drop_offs_idx);
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return pr;
    }

    /* Delete drops whose key.off differs from the new record's off. */
    stm_status last_ds = STM_OK;
    for (size_t i = 0; i < n_drops; i++) {
        const stm_extent_record *e = &c.records[drop_offs_idx[i]];
        if (e->off == off) continue;
        stm_status ds = ex_engine_del(idx, e->dataset_id, e->ino, e->off);
        if (ds != STM_OK) last_ds = ds;
    }
    free(drop_offs_idx);
    ex_collect_free(&c);

    /* R156 P2-1 carry: out-args contract "NULL on failure". */
    if (last_ds != STM_OK) {
        free(out_buf);
        must_unlock(&idx->lock);
        return last_ds;
    }
    *out_dropped_paddrs = out_buf;
    *out_n_dropped      = out_idx;
    must_unlock(&idx->lock);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Predicate-drop driver — shared by truncate / delete_file /          */
/* truncate_into / punch_range.                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    bool       have_delete_all;
    uint64_t   threshold;        /* drop off ≥ threshold */
    bool       have_punch_range;
    uint64_t   punch_off;
    uint64_t   punch_end;
} ex_drop_pred;

static bool ex_drop_pred_matches(const ex_drop_pred *p,
                                  const stm_extent_record *e) {
    if (p->have_delete_all) return true;
    if (p->have_punch_range) {
        uint64_t e_end = e->off + e->len;
        return (e->off >= p->punch_off && e_end <= p->punch_end);
    }
    return e->off >= p->threshold;
}

static stm_status drop_by_predicate_locked(stm_extent_index *idx,
                                              uint64_t ds, uint64_t ino,
                                              const ex_drop_pred *pred,
                                              uint64_t **out_paddrs,
                                              size_t *out_n) {
    *out_paddrs = NULL;
    *out_n      = 0;

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, ds, ino, &c);
    if (cs != STM_OK) return cs;

    size_t n_drops = 0;
    size_t total_replicas = 0;
    for (size_t i = 0; i < c.n; i++) {
        if (!ex_drop_pred_matches(pred, &c.records[i])) continue;
        n_drops++;
        total_replicas += c.records[i].n_replicas;
    }
    if (n_drops == 0) {
        ex_collect_free(&c);
        return STM_OK;
    }

    uint64_t *paddrs = NULL;
    if (total_replicas > 0) {
        paddrs = calloc(total_replicas, sizeof(uint64_t));
        if (!paddrs) {
            ex_collect_free(&c);
            return STM_ENOMEM;
        }
    }

    size_t pidx = 0;
    stm_status last_ds = STM_OK;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (!ex_drop_pred_matches(pred, e)) continue;
        for (uint8_t r = 0; r < e->n_replicas; r++) {
            paddrs[pidx++] = e->paddrs[r];
        }
        stm_status ds_ = ex_engine_del(idx, e->dataset_id, e->ino, e->off);
        if (ds_ != STM_OK) last_ds = ds_;
    }
    ex_collect_free(&c);

    /* R156 P2-1 carry: out-args contract "NULL on failure". */
    if (last_ds != STM_OK) {
        free(paddrs);
        return last_ds;
    }
    *out_paddrs = paddrs;
    *out_n      = pidx;
    return STM_OK;
}

static stm_status drop_by_predicate_into_locked(stm_extent_index *idx,
                                                  uint64_t ds, uint64_t ino,
                                                  const ex_drop_pred *pred,
                                                  size_t *drop_idx_buf,
                                                  size_t drop_idx_cap,
                                                  uint64_t *paddrs_buf,
                                                  size_t paddrs_cap,
                                                  size_t *out_n_dropped) {
    *out_n_dropped = 0;

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, ds, ino, &c);
    if (cs != STM_OK) return cs;

    size_t n_drops = 0;
    size_t total_replicas = 0;
    for (size_t i = 0; i < c.n; i++) {
        if (!ex_drop_pred_matches(pred, &c.records[i])) continue;
        if (n_drops >= drop_idx_cap) { ex_collect_free(&c); return STM_ERANGE; }
        drop_idx_buf[n_drops++] = i;
        total_replicas += c.records[i].n_replicas;
    }
    if (total_replicas > paddrs_cap) {
        ex_collect_free(&c);
        return STM_ERANGE;
    }
    if (n_drops == 0) {
        ex_collect_free(&c);
        return STM_OK;
    }

    size_t pidx = 0;
    stm_status last_ds = STM_OK;
    for (size_t i = 0; i < n_drops; i++) {
        const stm_extent_record *e = &c.records[drop_idx_buf[i]];
        for (uint8_t r = 0; r < e->n_replicas; r++) {
            paddrs_buf[pidx++] = e->paddrs[r];
        }
        stm_status ds_ = ex_engine_del(idx, e->dataset_id, e->ino, e->off);
        if (ds_ != STM_OK) last_ds = ds_;
    }
    ex_collect_free(&c);
    *out_n_dropped = pidx;
    return last_ds;
}

stm_status stm_extent_truncate(stm_extent_index *idx,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t new_size,
                                  uint64_t **out_dropped_paddrs,
                                  size_t *out_n_dropped) {
    if (!out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    ex_drop_pred pred = { .have_delete_all = false, .threshold = new_size,
                            .have_punch_range = false,
                            .punch_off = 0, .punch_end = 0 };
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino, &pred,
                                                out_dropped_paddrs,
                                                out_n_dropped);
    must_unlock(&idx->lock);
    return rs;
}

stm_status stm_extent_truncate_peek(const stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t new_size,
                                       size_t *out_n_extents,
                                       size_t *out_n_replicas_total) {
    if (!out_n_extents || !out_n_replicas_total) return STM_EINVAL;
    *out_n_extents        = 0;
    *out_n_replicas_total = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(m, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(lock);
        return cs;
    }
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (e->off < new_size) continue;
        (*out_n_extents)++;
        *out_n_replicas_total += e->n_replicas;
    }
    ex_collect_free(&c);
    must_unlock(lock);
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
    if (drop_idx_cap > 0 && !drop_idx_buf) return STM_EINVAL;
    if (paddrs_cap   > 0 && !paddrs_buf)   return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    ex_drop_pred pred = { .have_delete_all = false, .threshold = new_size,
                            .have_punch_range = false,
                            .punch_off = 0, .punch_end = 0 };
    stm_status rs = drop_by_predicate_into_locked(idx, dataset_id, ino, &pred,
                                                     drop_idx_buf, drop_idx_cap,
                                                     paddrs_buf, paddrs_cap,
                                                     out_n_dropped);
    must_unlock(&idx->lock);
    return rs;
}

stm_status stm_extent_delete_file(stm_extent_index *idx,
                                    uint64_t dataset_id, uint64_t ino,
                                    uint64_t **out_dropped_paddrs,
                                    size_t *out_n_dropped) {
    if (!out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    ex_drop_pred pred = { .have_delete_all = true, .threshold = 0,
                            .have_punch_range = false,
                            .punch_off = 0, .punch_end = 0 };
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino, &pred,
                                                out_dropped_paddrs,
                                                out_n_dropped);
    must_unlock(&idx->lock);
    return rs;
}

stm_status stm_extent_punch_range(stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t off, uint64_t len,
                                       uint64_t **out_dropped_paddrs,
                                       size_t *out_n_dropped_paddrs) {
    if (out_dropped_paddrs) *out_dropped_paddrs = NULL;
    if (out_n_dropped_paddrs) *out_n_dropped_paddrs = 0;
    if (!idx || !out_dropped_paddrs || !out_n_dropped_paddrs)
        return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (len == 0u) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    uint64_t r_end = off + len;
    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        uint64_t e_end = e->off + e->len;
        bool overlaps = (e->off < r_end && e_end > off);
        if (!overlaps) continue;
        bool fully_in = (e->off >= off && e_end <= r_end);
        if (!fully_in) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ENOTSUPPORTED;
        }
    }
    ex_collect_free(&c);

    ex_drop_pred pred = { .have_delete_all = false, .threshold = 0,
                            .have_punch_range = true,
                            .punch_off = off, .punch_end = r_end };
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino, &pred,
                                                out_dropped_paddrs,
                                                out_n_dropped_paddrs);
    must_unlock(&idx->lock);
    return rs;
}

stm_status stm_extent_shift_range_keys(stm_extent_index *idx,
                                            uint64_t dataset_id, uint64_t ino,
                                            uint64_t cutoff,
                                            int64_t  delta) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (delta == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }

    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        uint64_t e_end = e->off + e->len;

        if (delta < 0) {
            uint64_t adelta = (uint64_t)(-delta);
            if (cutoff < adelta) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_EINVAL;
            }
            uint64_t hole_start = cutoff - adelta;
            if (e->off < cutoff && e_end > hole_start) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_ENOTSUPPORTED;
            }
            if (e->off >= cutoff && e->off < adelta) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_EINVAL;
            }
        } else {
            uint64_t adelta = (uint64_t)delta;
            if (e->off < cutoff && e_end > cutoff) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_ENOTSUPPORTED;
            }
            if (e->off >= cutoff && e->off > UINT64_MAX - adelta) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_EOVERFLOW;
            }
            if (e->off >= cutoff && e_end > UINT64_MAX - adelta) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_EOVERFLOW;
            }
        }
    }

    stm_status last_status = STM_OK;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (e->off < cutoff) continue;
        stm_status ds_ = ex_engine_del(idx, e->dataset_id, e->ino, e->off);
        if (ds_ != STM_OK) { last_status = ds_; continue; }
        stm_extent_record nr = *e;
        if (delta < 0) {
            uint64_t adelta = (uint64_t)(-delta);
            nr.off = e->off - adelta;
        } else {
            nr.off = e->off + (uint64_t)delta;
        }
        stm_status ps = ex_engine_put(idx, &nr);
        if (ps != STM_OK) last_status = ps;
    }
    ex_collect_free(&c);
    must_unlock(&idx->lock);
    return last_status;
}

stm_status stm_extent_reflink(stm_extent_index *idx,
                                uint64_t dst_dataset_id, uint64_t dst_ino,
                                uint64_t dst_off, uint64_t len,
                                const uint64_t *paddrs, size_t n_paddrs,
                                uint64_t gen, uint64_t key_id,
                                uint64_t origin_dataset_id,
                                uint64_t origin_ino,
                                uint64_t origin_off,
                                uint64_t link_gen) {
    if (!idx) return STM_EINVAL;
    if (dst_dataset_id == 0 || dst_ino == 0) return STM_EINVAL;
    if (origin_dataset_id == 0 || origin_ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (!paddrs) return STM_EINVAL;
    if (!replica_set_is_valid(paddrs, n_paddrs)) return STM_EINVAL;
    if (dst_off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (link_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    bool overlap = false;
    stm_status os = overlap_in_ino_locked(idx, dst_dataset_id, dst_ino,
                                            dst_off, len, &overlap);
    if (os != STM_OK) {
        must_unlock(&idx->lock);
        return os;
    }
    if (overlap) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }
    bool cohabit_ok = true;
    stm_status hs = cohabit_check_global_locked(idx, paddrs, n_paddrs,
                                                  gen, key_id,
                                                  origin_dataset_id, origin_ino,
                                                  origin_off, &cohabit_ok);
    if (hs != STM_OK) {
        must_unlock(&idx->lock);
        return hs;
    }
    if (!cohabit_ok) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    stm_extent_record rec = {
        .dataset_id = dst_dataset_id, .ino = dst_ino,
        .off = dst_off, .len = len,
        .kind       = STM_EXTENT_KIND_HOT,
        .n_replicas = (uint8_t)n_paddrs,
        .gen = gen,
        .key_id = key_id,
        .origin_dataset_id = origin_dataset_id,
        .origin_ino        = origin_ino,
        .origin_off        = origin_off,
        .link_gen          = link_gen,
    };
    for (size_t i = 0; i < n_paddrs; i++) rec.paddrs[i] = paddrs[i];
    stm_status as = ex_engine_put(idx, &rec);
    must_unlock(&idx->lock);
    return as;
}

stm_status stm_extent_write_cold(stm_extent_index *idx,
                                    uint64_t dataset_id, uint64_t ino,
                                    uint64_t off, uint64_t len,
                                    const uint8_t content_hash[STM_EXTENT_HASH_LEN],
                                    uint64_t gen, uint64_t key_id,
                                    uint64_t origin_dataset_id,
                                    uint64_t origin_ino,
                                    uint64_t origin_off,
                                    uint64_t link_gen) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (origin_dataset_id == 0 || origin_ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (!content_hash) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;
    bool any_nonzero = false;
    for (size_t i = 0; i < STM_EXTENT_HASH_LEN; i++) {
        if (content_hash[i] != 0) { any_nonzero = true; break; }
    }
    if (!any_nonzero) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (gen > idx->current_txg)         { must_unlock(&idx->lock); return STM_EINVAL; }
    if (link_gen > idx->current_txg)    { must_unlock(&idx->lock); return STM_EINVAL; }
    if (origin_off > UINT64_MAX - len)  { must_unlock(&idx->lock); return STM_EINVAL; }

    bool overlap = false;
    stm_status os = overlap_in_ino_locked(idx, dataset_id, ino, off, len,
                                            &overlap);
    if (os != STM_OK) {
        must_unlock(&idx->lock);
        return os;
    }
    if (overlap) {
        must_unlock(&idx->lock);
        return STM_EEXIST;
    }

    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .kind       = STM_EXTENT_KIND_COLD,
        .n_replicas = 0u,
        .gen        = gen,
        .key_id     = key_id,
        .origin_dataset_id = origin_dataset_id,
        .origin_ino        = origin_ino,
        .origin_off        = origin_off,
        .link_gen          = link_gen,
    };
    memcpy(rec.content_hash, content_hash, STM_EXTENT_HASH_LEN);

    stm_status as = ex_engine_put(idx, &rec);
    must_unlock(&idx->lock);
    return as;
}

stm_status stm_extent_migrate_to_cold(stm_extent_index *idx,
                                         uint64_t dataset_id, uint64_t ino,
                                         uint64_t off, uint64_t len,
                                         const uint8_t content_hash[STM_EXTENT_HASH_LEN],
                                         uint64_t gen, uint64_t key_id,
                                         uint64_t origin_dataset_id,
                                         uint64_t origin_ino,
                                         uint64_t origin_off,
                                         uint64_t link_gen,
                                         uint64_t out_paddrs[STM_EXTENT_MAX_REPLICAS],
                                         uint8_t  *out_n_replicas) {
    if (!out_paddrs || !out_n_replicas) return STM_EINVAL;
    *out_n_replicas = 0;
    for (size_t k = 0; k < STM_EXTENT_MAX_REPLICAS; k++) out_paddrs[k] = 0;

    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (origin_dataset_id == 0 || origin_ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (!content_hash) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;
    if (origin_off > UINT64_MAX - len) return STM_EINVAL;
    bool any_nonzero = false;
    for (size_t i = 0; i < STM_EXTENT_HASH_LEN; i++) {
        if (content_hash[i] != 0) { any_nonzero = true; break; }
    }
    if (!any_nonzero) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (gen > idx->current_txg)      { must_unlock(&idx->lock); return STM_EINVAL; }
    if (link_gen > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }

    stm_extent_record src;
    bool found = false;
    stm_status gs = ex_engine_get(idx, dataset_id, ino, off, &src, &found);
    if (gs != STM_OK) { must_unlock(&idx->lock); return gs; }
    if (!found) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (src.len != len) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (src.kind != STM_EXTENT_KIND_HOT) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (src.n_replicas < 1 || src.n_replicas > STM_EXTENT_MAX_REPLICAS) {
        must_unlock(&idx->lock);
        return STM_ECORRUPT;
    }

    *out_n_replicas = src.n_replicas;
    for (uint8_t r = 0; r < src.n_replicas; r++) {
        out_paddrs[r] = src.paddrs[r];
    }

    stm_extent_record cold_rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .kind       = STM_EXTENT_KIND_COLD,
        .n_replicas = 0u,
        .gen        = gen,
        .key_id     = key_id,
        .origin_dataset_id = origin_dataset_id,
        .origin_ino        = origin_ino,
        .origin_off        = origin_off,
        .link_gen          = link_gen,
    };
    memcpy(cold_rec.content_hash, content_hash, STM_EXTENT_HASH_LEN);

    stm_status ps = ex_engine_put(idx, &cold_rec);
    must_unlock(&idx->lock);
    return ps;
}

stm_status stm_extent_migrate_to_cold_chunked(
        stm_extent_index *idx,
        uint64_t dataset_id, uint64_t ino,
        uint64_t src_off, uint64_t src_len,
        const stm_extent_cold_chunk *chunks, size_t n_chunks,
        uint64_t src_gen, uint64_t src_key_id,
        uint64_t src_origin_dataset_id,
        uint64_t src_origin_ino,
        uint64_t src_origin_off,
        uint64_t link_gen,
        uint64_t out_paddrs[STM_EXTENT_MAX_REPLICAS],
        uint8_t  *out_n_replicas) {
    if (!out_paddrs || !out_n_replicas) return STM_EINVAL;
    *out_n_replicas = 0;
    for (size_t k = 0; k < STM_EXTENT_MAX_REPLICAS; k++) out_paddrs[k] = 0;

    if (!idx || !chunks) return STM_EINVAL;
    if (n_chunks == 0) return STM_EINVAL;
    if (n_chunks == 1) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (src_origin_dataset_id == 0 || src_origin_ino == 0) return STM_EINVAL;
    if (src_len == 0) return STM_EINVAL;
    if (src_off > UINT64_MAX - src_len) return STM_EOVERFLOW;
    if (src_origin_off > UINT64_MAX - src_len) return STM_EINVAL;

    uint64_t cursor = src_off;
    for (size_t i = 0; i < n_chunks; i++) {
        const stm_extent_cold_chunk *c = &chunks[i];
        if (c->len == 0) return STM_EINVAL;
        if (c->off != cursor) return STM_EINVAL;
        if (c->off > UINT64_MAX - c->len) return STM_EOVERFLOW;
        bool any_nonzero = false;
        for (size_t k = 0; k < STM_EXTENT_HASH_LEN; k++) {
            if (c->content_hash[k] != 0) { any_nonzero = true; break; }
        }
        if (!any_nonzero) return STM_EINVAL;
        cursor = c->off + c->len;
    }
    if (cursor != src_off + src_len) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (src_gen  > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }
    if (link_gen > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }

    stm_extent_record src;
    bool found = false;
    stm_status gs = ex_engine_get(idx, dataset_id, ino, src_off, &src, &found);
    if (gs != STM_OK) { must_unlock(&idx->lock); return gs; }
    if (!found) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (src.len != src_len) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (src.kind != STM_EXTENT_KIND_HOT) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (src.n_replicas < 1 || src.n_replicas > STM_EXTENT_MAX_REPLICAS) {
        must_unlock(&idx->lock);
        return STM_ECORRUPT;
    }

    *out_n_replicas = src.n_replicas;
    for (uint8_t r = 0; r < src.n_replicas; r++) {
        out_paddrs[r] = src.paddrs[r];
    }

    #define BUILD_COLD(i_)                                                     \
        ((stm_extent_record){                                                  \
            .dataset_id        = dataset_id,                                   \
            .ino               = ino,                                          \
            .off               = chunks[(i_)].off,                             \
            .len               = chunks[(i_)].len,                             \
            .kind              = STM_EXTENT_KIND_COLD,                         \
            .n_replicas        = 0u,                                           \
            .gen               = src_gen,                                      \
            .key_id            = src_key_id,                                   \
            .origin_dataset_id = src_origin_dataset_id,                        \
            .origin_ino        = src_origin_ino,                               \
            .origin_off        = src_origin_off + (chunks[(i_)].off - src_off),\
            .link_gen          = link_gen,                                     \
            .paddrs            = {0},                                          \
            .content_hash      = {0},                                          \
        })

    for (size_t i = 0; i < n_chunks; i++) {
        stm_extent_record ci = BUILD_COLD(i);
        memcpy(ci.content_hash, chunks[i].content_hash, STM_EXTENT_HASH_LEN);
        stm_status ps = ex_engine_put(idx, &ci);
        if (ps != STM_OK) {
            must_unlock(&idx->lock);
            return ps;
        }
    }
    #undef BUILD_COLD

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_migrate_whole_ino_to_cold(
        stm_extent_index *idx,
        uint64_t dataset_id, uint64_t ino,
        const stm_extent_cold_chunk *chunks, size_t n_chunks,
        uint64_t key_id,
        uint64_t link_gen,
        uint64_t **out_dropped_paddrs,
        size_t *out_n_dropped_paddrs) {
    if (out_dropped_paddrs)   *out_dropped_paddrs = NULL;
    if (out_n_dropped_paddrs) *out_n_dropped_paddrs = 0;

    if (!idx || !chunks || !out_dropped_paddrs || !out_n_dropped_paddrs)
        return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (n_chunks == 0) return STM_EINVAL;
    if (link_gen == 0) return STM_EINVAL;

    for (size_t i = 0; i < n_chunks; i++) {
        const stm_extent_cold_chunk *c = &chunks[i];
        if (c->len == 0) return STM_EINVAL;
        if (c->len > EX_LEN_MAX_24BIT) return STM_ERANGE;
        if (c->len % STM_UB_SIZE != 0) return STM_EINVAL;
        if (c->off > UINT64_MAX - c->len) return STM_EOVERFLOW;
        bool any_nonzero = false;
        for (size_t k = 0; k < STM_EXTENT_HASH_LEN; k++) {
            if (c->content_hash[k] != 0) { any_nonzero = true; break; }
        }
        if (!any_nonzero) return STM_EINVAL;
    }
    for (size_t i = 1; i < n_chunks; i++) {
        if (chunks[i].off != chunks[i - 1].off + chunks[i - 1].len)
            return STM_EINVAL;
    }

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (link_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }

    uint64_t src_gen   = 0;
    uint64_t src_key_id = 0;
    uint64_t src_origin_ds  = 0;
    uint64_t src_origin_ino = 0;
    uint64_t first_off = 0;
    bool     first_off_set = false;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *r = &c.records[i];
        if (r->kind == STM_EXTENT_KIND_COLD) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ENOTSUPPORTED;
        }
        if (r->kind != STM_EXTENT_KIND_HOT) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ECORRUPT;
        }
        if (r->n_replicas < 1 || r->n_replicas > STM_EXTENT_MAX_REPLICAS) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ECORRUPT;
        }
        if (!first_off_set || r->off < first_off) {
            first_off = r->off;
            first_off_set = true;
            src_gen        = r->gen;
            src_key_id     = r->key_id;
            src_origin_ds  = r->origin_dataset_id;
            src_origin_ino = r->origin_ino;
        }
    }
    if (c.n == 0) {
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *r = &c.records[i];
        if (r->gen != src_gen) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
        if (r->key_id != src_key_id) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
        if (r->origin_dataset_id != src_origin_ds) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
        if (r->origin_ino != src_origin_ino) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
    }

    /* Insertion-sort by off. */
    for (size_t i = 1; i < c.n; i++) {
        stm_extent_record key = c.records[i];
        uint64_t key_off_v   = c.offs[i];
        size_t j = i;
        while (j > 0 && c.offs[j - 1] > key_off_v) {
            c.records[j] = c.records[j - 1];
            c.offs[j]    = c.offs[j - 1];
            j--;
        }
        c.records[j] = key;
        c.offs[j]    = key_off_v;
    }
    first_off = c.records[0].off;

    uint64_t cumulative = first_off;
    for (size_t i = 0; i < c.n; i++) {
        if (c.records[i].off != cumulative) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ENOTSUPPORTED;
        }
        if (cumulative > UINT64_MAX - c.records[i].len) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_EOVERFLOW;
        }
        cumulative += c.records[i].len;
    }
    uint64_t total_len = cumulative - first_off;

    if (chunks[0].off != first_off) {
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    uint64_t chunks_end = chunks[n_chunks - 1].off + chunks[n_chunks - 1].len;
    if (chunks_end != first_off + total_len) {
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    size_t paddrs_n = 0;
    for (size_t i = 0; i < c.n; i++) paddrs_n += c.records[i].n_replicas;
    uint64_t *dropped = malloc(paddrs_n * sizeof(uint64_t));
    if (!dropped) {
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return STM_ENOMEM;
    }
    {
        size_t pi = 0;
        for (size_t i = 0; i < c.n; i++) {
            const stm_extent_record *r = &c.records[i];
            for (uint8_t k = 0; k < r->n_replicas; k++) {
                dropped[pi++] = r->paddrs[k];
            }
        }
    }

    stm_status last_status = STM_OK;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *r = &c.records[i];
        stm_status ds_ = ex_engine_del(idx, r->dataset_id, r->ino, r->off);
        if (ds_ != STM_OK) last_status = ds_;
    }

    for (size_t i = 0; i < n_chunks; i++) {
        stm_extent_record cold_rec;
        memset(&cold_rec, 0, sizeof cold_rec);
        cold_rec.dataset_id        = dataset_id;
        cold_rec.ino               = ino;
        cold_rec.off               = chunks[i].off;
        cold_rec.len               = chunks[i].len;
        cold_rec.kind              = STM_EXTENT_KIND_COLD;
        cold_rec.n_replicas        = 0;
        memcpy(cold_rec.content_hash, chunks[i].content_hash, STM_EXTENT_HASH_LEN);
        cold_rec.gen               = src_gen;
        cold_rec.key_id            = key_id;
        cold_rec.origin_dataset_id = dataset_id;
        cold_rec.origin_ino        = ino;
        cold_rec.origin_off        = chunks[i].off;
        cold_rec.link_gen          = link_gen;
        cold_rec.read_count        = 0;
        cold_rec.last_read_gen     = 0;
        stm_status ps = ex_engine_put(idx, &cold_rec);
        if (ps != STM_OK) last_status = ps;
    }

    ex_collect_free(&c);
    must_unlock(&idx->lock);

    *out_dropped_paddrs   = dropped;
    *out_n_dropped_paddrs = paddrs_n;
    return last_status;
}

stm_status stm_extent_promote_swap_to_hot(stm_extent_index *idx,
                                            uint64_t dataset_id, uint64_t ino,
                                            uint64_t off, uint64_t len,
                                            const uint64_t *new_paddrs,
                                            uint8_t n_replicas,
                                            uint64_t gen, uint64_t key_id,
                                            uint64_t origin_dataset_id,
                                            uint64_t origin_ino,
                                            uint64_t origin_off,
                                            uint64_t link_gen,
                                            uint8_t out_content_hash[STM_EXTENT_HASH_LEN])
{
    if (!out_content_hash) return STM_EINVAL;
    memset(out_content_hash, 0, STM_EXTENT_HASH_LEN);

    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (origin_dataset_id == 0 || origin_ino == 0) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    if (!new_paddrs) return STM_EINVAL;
    if (n_replicas < 1 || n_replicas > STM_EXTENT_MAX_REPLICAS) return STM_EINVAL;
    for (uint8_t i = 0; i < n_replicas; i++) {
        if (new_paddrs[i] == 0) return STM_EINVAL;
        for (uint8_t j = (uint8_t)(i + 1); j < n_replicas; j++) {
            if (new_paddrs[i] == new_paddrs[j]) return STM_EINVAL;
        }
    }
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;
    if (origin_off > UINT64_MAX - len) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (gen > idx->current_txg)      { must_unlock(&idx->lock); return STM_EINVAL; }
    if (link_gen > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }

    stm_extent_record src;
    bool found = false;
    stm_status gs = ex_engine_get(idx, dataset_id, ino, off, &src, &found);
    if (gs != STM_OK) { must_unlock(&idx->lock); return gs; }
    if (!found) {
        must_unlock(&idx->lock);
        return STM_ENOENT;
    }
    if (src.len != len) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    if (src.kind != STM_EXTENT_KIND_COLD) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    memcpy(out_content_hash, src.content_hash, STM_EXTENT_HASH_LEN);

    stm_extent_record hot_rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .kind       = STM_EXTENT_KIND_HOT,
        .n_replicas = n_replicas,
        .gen        = gen,
        .key_id     = key_id,
        .origin_dataset_id = origin_dataset_id,
        .origin_ino        = origin_ino,
        .origin_off        = origin_off,
        .link_gen          = link_gen,
    };
    for (uint8_t r = 0; r < n_replicas; r++) {
        hot_rec.paddrs[r] = new_paddrs[r];
    }

    stm_status ps = ex_engine_put(idx, &hot_rec);
    must_unlock(&idx->lock);
    return ps;
}

stm_status stm_extent_record_promote_read_hit(stm_extent_index *idx,
                                                uint64_t dataset_id,
                                                uint64_t ino,
                                                uint64_t off,
                                                uint64_t current_gen,
                                                uint64_t decay_window)
{
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (current_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }

    ptrdiff_t found_idx = -1;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (off < e->off) continue;
        if (off >= e->off + e->len) continue;
        found_idx = (ptrdiff_t)i;
        break;
    }
    if (found_idx < 0) {
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return STM_OK;
    }
    stm_extent_record rec = c.records[found_idx];
    ex_collect_free(&c);

    if (rec.kind != STM_EXTENT_KIND_COLD) {
        must_unlock(&idx->lock);
        return STM_OK;
    }

    bool reset = false;
    if (rec.last_read_gen == 0u) {
        reset = true;
    } else if (current_gen < rec.last_read_gen) {
        reset = true;
    } else {
        uint64_t age = current_gen - rec.last_read_gen;
        if (age > decay_window) reset = true;
    }
    if (reset) {
        rec.read_count = 1u;
    } else if (rec.read_count < UINT32_MAX) {
        rec.read_count++;
    }
    rec.last_read_gen = current_gen;

    stm_status ps = ex_engine_put(idx, &rec);
    must_unlock(&idx->lock);
    return ps;
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
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(m, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(lock);
        return cs;
    }
    bool got = false;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (off < e->off) continue;
        if (off >= e->off + e->len) continue;
        *out_extent = *e;
        got = true;
        break;
    }
    ex_collect_free(&c);
    must_unlock(lock);
    return got ? STM_OK : STM_ENOENT;
}

typedef struct {
    uint64_t           probe;
    stm_extent_record  hit;
    bool               found;
} ex_paddr_lookup_ctx;

static int ex_paddr_lookup_cb(uint64_t ds, uint64_t ino, uint64_t off,
                                const stm_extent_record *r, void *ctx_) {
    (void)ds; (void)ino; (void)off;
    ex_paddr_lookup_ctx *p = ctx_;
    for (uint8_t i = 0; i < r->n_replicas; i++) {
        if (r->paddrs[i] == p->probe) {
            p->hit = *r;
            p->found = true;
            return 1;        /* stop */
        }
    }
    return 0;
}

stm_status stm_extent_lookup_by_paddr(const stm_extent_index *idx,
                                          uint64_t paddr,
                                          stm_extent_record *out_extent) {
    if (!idx || !out_extent) return STM_EINVAL;
    if (paddr == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    ex_paddr_lookup_ctx lc = { .probe = paddr, .hit = {0}, .found = false };
    stm_status ss = ex_global_walk_locked(m, ex_paddr_lookup_cb, &lc);
    must_unlock(lock);
    if (ss != STM_OK) return ss;
    if (!lc.found) return STM_ENOENT;
    *out_extent = lc.hit;
    return STM_OK;
}

stm_status stm_extent_iter(const stm_extent_index *idx,
                              uint64_t dataset_id, uint64_t ino,
                              stm_extent_iter_cb cb, void *ctx) {
    if (!idx || !cb) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(m, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(lock);
        return cs;
    }
    /* Sort by off. */
    for (size_t i = 1; i < c.n; i++) {
        stm_extent_record key = c.records[i];
        uint64_t key_off_v   = c.offs[i];
        size_t j = i;
        while (j > 0 && c.offs[j - 1] > key_off_v) {
            c.records[j] = c.records[j - 1];
            c.offs[j]    = c.offs[j - 1];
            j--;
        }
        c.records[j] = key;
        c.offs[j]    = key_off_v;
    }
    for (size_t i = 0; i < c.n; i++) {
        if (!cb(&c.records[i], ctx)) break;
    }
    ex_collect_free(&c);
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
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    /* Scan the dataset's engine over the entire EXTENT subspace. */
    stm_btree_engine *eng = NULL;
    stm_status es = ex_get_engine_locked(m, dataset_id, &eng);
    if (es == STM_ENOENT) {
        must_unlock(lock);
        return STM_OK;          /* no records */
    }
    if (es != STM_OK) {
        must_unlock(lock);
        return es;
    }

    uint8_t lo[EX_KEY_LEN], hi[EX_KEY_LEN];
    stm_status k1 = ex_encode_key(0u,         0u,         lo);
    stm_status k2 = ex_encode_key(UINT64_MAX, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        must_unlock(lock);
        return k1 != STM_OK ? k1 : k2;
    }

    /* Collect via the existing in-ino ctx but ignore the ino field —
     * we'll filter to records under (dataset_id, *) via the range
     * bracket. Use ex_collect_ctx but stamped with this dataset_id. */
    ex_collect_ctx c;
    memset(&c, 0, sizeof c);
    c.ds = dataset_id;
    stm_status ss = stm_btree_engine_scan_range(eng, lo, EX_KEY_LEN,
                                                hi, EX_KEY_LEN,
                                                ex_collect_cb, &c);
    if (ss != STM_OK || c.err != STM_OK) {
        free(c.records);
        free(c.offs);
        must_unlock(lock);
        return ss != STM_OK ? ss : c.err;
    }

    /* Sort by (ino, off). */
    for (size_t i = 1; i < c.n; i++) {
        stm_extent_record key = c.records[i];
        size_t j = i;
        while (j > 0) {
            bool greater = (c.records[j - 1].ino > key.ino) ||
                            (c.records[j - 1].ino == key.ino && c.records[j - 1].off > key.off);
            if (!greater) break;
            c.records[j] = c.records[j - 1];
            j--;
        }
        c.records[j] = key;
    }
    for (size_t i = 0; i < c.n; i++) {
        if (!cb(&c.records[i], ctx)) break;
    }
    free(c.records);
    free(c.offs);
    must_unlock(lock);
    return STM_OK;
}

typedef struct {
    size_t n;
} ex_count_ctx;

static int ex_count_cb_g(uint64_t ds, uint64_t ino, uint64_t off,
                          const stm_extent_record *r, void *ctx_) {
    (void)ds; (void)ino; (void)off; (void)r;
    ex_count_ctx *cx = ctx_;
    cx->n++;
    return 0;
}

stm_status stm_extent_count(const stm_extent_index *idx,
                               size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    *out_count = 0;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    ex_count_ctx cc = { .n = 0 };
    stm_status ss = ex_global_walk_locked(m, ex_count_cb_g, &cc);
    must_unlock(lock);
    if (ss != STM_OK) return ss;
    *out_count = cc.n;
    return STM_OK;
}

stm_status stm_extent_count_for_ino(const stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    *out_count = 0;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(m, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(lock);
        return cs;
    }
    *out_count = c.n;
    ex_collect_free(&c);
    must_unlock(lock);
    return STM_OK;
}

/* =========================================================================
 * Persistence — per-dataset btree_engine via attached stm_dataset_index.
 *
 * 9.7-impl-1c-v: the extent module owns NO engines. Persistence is
 * provided by each dataset's per-dataset engine; the M-engine cascade in
 * stm_sync_commit drives commit / finalize / abort for every PRESENT
 * dataset's engine. The only "persistence-shaped" entry point retained
 * here is the mount-time validator, which runs AFTER the dataset_index
 * has opened every per-dataset engine and walks every record to:
 *
 *   - raise current_txg to max(write_gen) (extent.tla::BirthTxgBound);
 *   - validate NoOverlapWithinIno across all (ds, ino);
 *   - validate SharedReplicasAreCohabit across all replica-set shares;
 *   - validate per-record invariants (encoder/decoder symmetry).
 *
 * Value layout (108 bytes, P7-CAS-11 / v21 — UNCHANGED from 9.6-impl-4d):
 *
 *   off  size  field
 *     0    1   kind             (u8; 0x01 = HOT, 0x02 = COLD)
 *
 *   HOT (kind=0x01) — bytes 1..95:
 *     1    1   n_replicas       (u8; 1..STM_EXTENT_MAX_REPLICAS=4)
 *     2    6   reserved         (zero)
 *     8   32   paddrs[4]        (le64 each; valid 0..n_replicas-1, zero rest)
 *    40    8   write_gen        (le64) — AEAD gen for nonce construction
 *    48    4   dlen             (le32; logical byte length)
 *    52    4   clen_and_comp    (le32; low 24: stored len; high 8: comp)
 *    56    8   key_id           (le64; per-dataset DEK key_id)
 *    64    8   origin_dataset_id (le64; AEAD-AD identity binding)
 *    72    8   origin_ino       (le64; AEAD-AD identity binding)
 *    80    8   origin_off       (le64; AEAD-AD identity binding)
 *    88    8   link_gen         (le64) — R48 P0-1.
 *
 *   COLD (kind=0x02) — bytes 1..95:
 *     1    7   reserved         (zero — 1-byte padding + 6-byte gap pre-hash)
 *     8   32   content_hash     (BLAKE3-256; names a CAS index entry)
 *    40   56   <same as HOT bytes 40..95>
 *
 *   Trailing tail (bytes 96..107) for both kinds:
 *    96    4   read_count       (le32) — saturating counter; HOT must be 0
 *   100    8   last_read_gen    (le64) — HOT must be 0
 *
 * Key layout (17 bytes, 9.7-impl-1c-v):
 *
 *   off  size  field                       contract
 *    0     1   u8   STM_METAKEY_KIND_EXTENT  metakey tag (=0x04)
 *    1     8   le64 ino                     non-zero
 *    9     8   le64 file_offset             byte offset within file
 *
 * The dataset_id prefix is retired; cross-dataset substitution
 * defense lives in the engine layer via `tree_id = dataset_id` in
 * AEAD AD. R71 P1-1 doctrine: writer-side and decoder-side bounds
 * checks SYMMETRIC at the tag byte (stm_metakey_compose /
 * stm_metakey_parse pin the tag chokepoint) AND at the body
 * (the per-module decoder enforces the 16-byte body length on every
 * read-back).
 * ========================================================================= */

static stm_status ex_encode_key(uint64_t ino, uint64_t off,
                                  uint8_t out[EX_KEY_LEN]) {
    uint8_t body[EX_KEY_BODY_LEN];
    le64 i = stm_store_le64(ino);
    le64 o = stm_store_le64(off);
    memcpy(body + 0, i.v, 8);
    memcpy(body + 8, o.v, 8);
    size_t out_len = 0;
    return stm_metakey_compose(STM_METAKEY_KIND_EXTENT,
                                body, EX_KEY_BODY_LEN,
                                out, EX_KEY_LEN, &out_len);
}

static stm_status ex_decode_key(const void *in, size_t in_len,
                                  uint64_t *out_ino, uint64_t *out_off) {
    stm_metakey_kind kind;
    const uint8_t *body = NULL;
    size_t body_len = 0;
    stm_status rc = stm_metakey_parse(in, in_len, &kind, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (kind != STM_METAKEY_KIND_EXTENT) return STM_ECORRUPT;
    if (body_len != EX_KEY_BODY_LEN) return STM_ECORRUPT;
    le64 i_le, o_le;
    memcpy(i_le.v, body + 0, 8);
    memcpy(o_le.v, body + 8, 8);
    *out_ino = stm_load_le64(i_le);
    *out_off = stm_load_le64(o_le);
    return STM_OK;
}

static stm_status ex_encode_value(const stm_extent_record *r,
                                     uint8_t out[EX_VAL_LEN]) {
    if (r->len > EX_LEN_MAX_24BIT) return STM_ERANGE;

    memset(out, 0, EX_VAL_LEN);

    /* R156 P3-1 carry: encoder-side mirrors of decoder-side guards. */
    if (r->origin_dataset_id == 0 || r->origin_ino == 0) return STM_ECORRUPT;
    if (r->origin_off > UINT64_MAX - r->len) return STM_ECORRUPT;

    if (r->kind == STM_EXTENT_KIND_HOT) {
        if (r->n_replicas < 1 || r->n_replicas > STM_EXTENT_MAX_REPLICAS) {
            return STM_ECORRUPT;
        }
        for (uint8_t i = 0; i < r->n_replicas; i++) {
            for (uint8_t j = (uint8_t)(i + 1); j < r->n_replicas; j++) {
                if (r->paddrs[i] == r->paddrs[j]) return STM_ECORRUPT;
            }
        }
        out[0] = (uint8_t)STM_EXTENT_KIND_HOT;
        out[1] = r->n_replicas;
        for (uint8_t i = 0; i < r->n_replicas; i++) {
            if (r->paddrs[i] == 0) return STM_ECORRUPT;
            le64 p = stm_store_le64(r->paddrs[i]);
            memcpy(out + 8 + (size_t)i * 8, p.v, 8);
        }
    } else if (r->kind == STM_EXTENT_KIND_COLD) {
        if (r->n_replicas != 0u) return STM_ECORRUPT;
        out[0] = (uint8_t)STM_EXTENT_KIND_COLD;
        bool any_nonzero = false;
        for (size_t i = 0; i < STM_EXTENT_HASH_LEN; i++) {
            if (r->content_hash[i] != 0) { any_nonzero = true; break; }
        }
        if (!any_nonzero) return STM_ECORRUPT;
        memcpy(out + 8, r->content_hash, STM_EXTENT_HASH_LEN);
    } else {
        return STM_ECORRUPT;
    }

    le64 write_gen = stm_store_le64(r->gen);
    le32 dlen      = stm_store_le32((uint32_t)r->len);
    uint32_t clen_and_comp = (uint32_t)r->len & 0x00FFFFFFu;
    le32 cac        = stm_store_le32(clen_and_comp);
    le64 key_id_le  = stm_store_le64(r->key_id);

    memcpy(out + 40, write_gen.v, 8);
    memcpy(out + 48, dlen.v,      4);
    memcpy(out + 52, cac.v,       4);
    memcpy(out + 56, key_id_le.v, 8);

    le64 origin_ds  = stm_store_le64(r->origin_dataset_id);
    le64 origin_ino_le = stm_store_le64(r->origin_ino);
    le64 origin_off = stm_store_le64(r->origin_off);
    memcpy(out + 64, origin_ds.v,  8);
    memcpy(out + 72, origin_ino_le.v, 8);
    memcpy(out + 80, origin_off.v, 8);
    le64 link_gen_le = stm_store_le64(r->link_gen);
    memcpy(out + 88, link_gen_le.v, 8);

    if (r->kind == STM_EXTENT_KIND_HOT) {
        if (r->read_count != 0u || r->last_read_gen != 0u) return STM_ECORRUPT;
    }
    le32 rc_le  = stm_store_le32(r->read_count);
    le64 lrg_le = stm_store_le64(r->last_read_gen);
    memcpy(out + 96,  rc_le.v,  4);
    memcpy(out + 100, lrg_le.v, 8);
    return STM_OK;
}

static stm_status ex_decode_value(const void *in, size_t in_len,
                                     uint64_t ds, uint64_t ino, uint64_t off,
                                     stm_extent_record *out_rec) {
    if (in_len != EX_VAL_LEN) return STM_ECORRUPT;
    const uint8_t *b = in;

    uint8_t kind_byte = b[0];
    uint8_t n_replicas = 0;
    uint64_t paddrs[STM_EXTENT_MAX_REPLICAS] = {0};
    uint8_t  content_hash[STM_EXTENT_HASH_LEN] = {0};

    if (kind_byte == (uint8_t)STM_EXTENT_KIND_HOT) {
        n_replicas = b[1];
        if (n_replicas < 1 || n_replicas > STM_EXTENT_MAX_REPLICAS)
            return STM_ECORRUPT;
        for (size_t i = 2; i < 8; i++) if (b[i] != 0) return STM_ECORRUPT;

        for (uint8_t i = 0; i < STM_EXTENT_MAX_REPLICAS; i++) {
            le64 p_le;
            memcpy(p_le.v, b + 8 + (size_t)i * 8, 8);
            paddrs[i] = stm_load_le64(p_le);
            if (i < n_replicas) {
                if (paddrs[i] == 0) return STM_ECORRUPT;
            } else {
                if (paddrs[i] != 0) return STM_ECORRUPT;
            }
        }
        for (uint8_t i = 0; i < n_replicas; i++) {
            for (uint8_t j = (uint8_t)(i + 1); j < n_replicas; j++) {
                if (paddrs[i] == paddrs[j]) return STM_ECORRUPT;
            }
        }
    } else if (kind_byte == (uint8_t)STM_EXTENT_KIND_COLD) {
        for (size_t i = 1; i < 8; i++) if (b[i] != 0) return STM_ECORRUPT;
        memcpy(content_hash, b + 8, STM_EXTENT_HASH_LEN);
        bool any_nonzero = false;
        for (size_t i = 0; i < STM_EXTENT_HASH_LEN; i++) {
            if (content_hash[i] != 0) { any_nonzero = true; break; }
        }
        if (!any_nonzero) return STM_ECORRUPT;
    } else {
        return STM_ECORRUPT;
    }

    le64 write_gen_le, key_id_le;
    le32 dlen_le, cac_le;
    memcpy(write_gen_le.v, b + 40, 8);
    memcpy(dlen_le.v,      b + 48, 4);
    memcpy(cac_le.v,       b + 52, 4);
    memcpy(key_id_le.v,    b + 56, 8);

    le64 origin_ds_le, origin_ino_le, origin_off_le;
    memcpy(origin_ds_le.v,  b + 64, 8);
    memcpy(origin_ino_le.v, b + 72, 8);
    memcpy(origin_off_le.v, b + 80, 8);
    le64 link_gen_le;
    memcpy(link_gen_le.v, b + 88, 8);

    uint32_t dlen = stm_load_le32(dlen_le);
    uint32_t cac  = stm_load_le32(cac_le);
    uint32_t clen = cac & 0x00FFFFFFu;
    uint32_t comp = (cac >> 24) & 0xFFu;
    if (comp != 0) return STM_ECORRUPT;
    if (clen != dlen) return STM_ECORRUPT;
    if (dlen == 0) return STM_ECORRUPT;

    uint64_t origin_ds_v  = stm_load_le64(origin_ds_le);
    uint64_t origin_ino_v = stm_load_le64(origin_ino_le);
    uint64_t origin_off_v = stm_load_le64(origin_off_le);
    if (origin_ds_v == 0 || origin_ino_v == 0) return STM_ECORRUPT;
    if (origin_off_v > UINT64_MAX - (uint64_t)dlen) return STM_ECORRUPT;
    uint64_t link_gen_v = stm_load_le64(link_gen_le);

    le32 rc_le; le64 lrg_le;
    memcpy(rc_le.v,  b + 96,  4);
    memcpy(lrg_le.v, b + 100, 8);
    uint32_t read_count_v   = stm_load_le32(rc_le);
    uint64_t last_read_gen_v = stm_load_le64(lrg_le);
    if (kind_byte == (uint8_t)STM_EXTENT_KIND_HOT) {
        if (read_count_v != 0u || last_read_gen_v != 0u) return STM_ECORRUPT;
    }

    /* off + len overflow guard. */
    if (off > UINT64_MAX - (uint64_t)dlen) return STM_ECORRUPT;

    out_rec->dataset_id = ds;
    out_rec->ino        = ino;
    out_rec->off        = off;
    out_rec->len        = (uint64_t)dlen;
    out_rec->kind       = (kind_byte == (uint8_t)STM_EXTENT_KIND_HOT)
                           ? STM_EXTENT_KIND_HOT
                           : STM_EXTENT_KIND_COLD;
    out_rec->n_replicas = n_replicas;
    for (uint8_t i = 0; i < STM_EXTENT_MAX_REPLICAS; i++) {
        out_rec->paddrs[i] = paddrs[i];
    }
    memcpy(out_rec->content_hash, content_hash, STM_EXTENT_HASH_LEN);
    out_rec->gen        = stm_load_le64(write_gen_le);
    out_rec->key_id     = stm_load_le64(key_id_le);
    out_rec->origin_dataset_id = origin_ds_v;
    out_rec->origin_ino        = origin_ino_v;
    out_rec->origin_off        = origin_off_v;
    out_rec->link_gen          = link_gen_v;
    out_rec->read_count        = read_count_v;
    out_rec->last_read_gen     = last_read_gen_v;

    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Mount-time validator + on-demand verify.                            */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_extent_record *records;
    size_t             n;
    size_t             cap;
    uint64_t           max_write_gen;
    stm_status         err;
} ex_validate_ctx;

static int ex_validate_collect_cb(uint64_t ds, uint64_t ino, uint64_t off,
                                    const stm_extent_record *r, void *ctx_) {
    (void)ds; (void)ino; (void)off;
    ex_validate_ctx *m = ctx_;
    if (r->gen > m->max_write_gen) m->max_write_gen = r->gen;
    if (m->n == m->cap) {
        if (m->cap > (SIZE_MAX / sizeof *m->records) / 2u) {
            m->err = STM_ENOMEM;
            return 1;
        }
        size_t new_cap = m->cap == 0 ? 16u : m->cap * 2u;
        stm_extent_record *nr = realloc(m->records,
                                            new_cap * sizeof *m->records);
        if (!nr) { m->err = STM_ENOMEM; return 1; }
        m->records = nr;
        m->cap = new_cap;
    }
    m->records[m->n++] = *r;
    return 0;
}

static stm_status ex_validate_cross_records(const ex_validate_ctx *m) {
    /* O(N²·K²) pairwise — fine for any plausible mount.
     * Production-grade per-file trees revisits with sorted-merge. */
    for (size_t i = 0; i < m->n; i++) {
        const stm_extent_record *a = &m->records[i];
        for (size_t j = i + 1; j < m->n; j++) {
            const stm_extent_record *b = &m->records[j];
            if (a->dataset_id == b->dataset_id && a->ino == b->ino) {
                if (ranges_overlap(a->off, a->len, b->off, b->len)) {
                    return STM_ECORRUPT;
                }
            }
            bool any_share = false;
            for (uint8_t ai = 0; ai < a->n_replicas && !any_share; ai++) {
                for (uint8_t bi = 0; bi < b->n_replicas; bi++) {
                    if (a->paddrs[ai] == b->paddrs[bi]) { any_share = true; break; }
                }
            }
            if (!any_share) continue;
            if (a->n_replicas != b->n_replicas) return STM_ECORRUPT;
            for (uint8_t ai = 0; ai < a->n_replicas; ai++) {
                bool found = false;
                for (uint8_t bi = 0; bi < b->n_replicas; bi++) {
                    if (a->paddrs[ai] == b->paddrs[bi]) { found = true; break; }
                }
                if (!found) return STM_ECORRUPT;
            }
            if (a->gen        != b->gen)        return STM_ECORRUPT;
            if (a->key_id     != b->key_id)     return STM_ECORRUPT;
            if (a->origin_dataset_id != b->origin_dataset_id) return STM_ECORRUPT;
            if (a->origin_ino        != b->origin_ino)        return STM_ECORRUPT;
            if (a->origin_off        != b->origin_off)        return STM_ECORRUPT;
        }
    }
    return STM_OK;
}

stm_status stm_extent_index_mount_validate(stm_extent_index *idx) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    if (idx->ds_idx == NULL) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    ex_validate_ctx m = { .records = NULL, .n = 0, .cap = 0,
                            .max_write_gen = 0, .err = STM_OK };
    stm_status ws = ex_global_walk_locked(idx, ex_validate_collect_cb, &m);
    if (ws != STM_OK || m.err != STM_OK) {
        free(m.records);
        must_unlock(&idx->lock);
        return ws != STM_OK ? ws : m.err;
    }
    stm_status vs = ex_validate_cross_records(&m);
    free(m.records);
    if (vs != STM_OK) {
        must_unlock(&idx->lock);
        return vs;
    }

    if (m.max_write_gen > idx->current_txg) {
        idx->current_txg = m.max_write_gen;
    }
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_index_verify(const stm_extent_index *idx) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    stm_extent_index *m = (stm_extent_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    ex_validate_ctx ctx = { .records = NULL, .n = 0, .cap = 0,
                              .max_write_gen = 0, .err = STM_OK };
    stm_status ws = ex_global_walk_locked(m, ex_validate_collect_cb, &ctx);
    if (ws != STM_OK || ctx.err != STM_OK) {
        free(ctx.records);
        must_unlock(lock);
        return ws != STM_OK ? ws : ctx.err;
    }
    stm_status vs = ex_validate_cross_records(&ctx);
    free(ctx.records);
    must_unlock(lock);
    return vs;
}

/* ------------------------------------------------------------------ */
/* 9.7-impl-4c: rollback DATA-extent (stm_alloc tier) reclamation —    */
/* enumerate every HOT replica paddr of a frozen tree.                 */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_extent_paddr_cb user_cb;
    void               *user_ctx;
    uint64_t            ds;            /* the tree's dataset id        */
    stm_status          err;
} ex_collect_data_ctx;

/* stm_btree_engine_iter_cb — decode one extent value, emit its HOT
 * replica paddrs. A decode failure aborts the scan via gc->err. A
 * nonzero user-cb return halts the scan with no error (the user cb
 * surfaces its own state through user_ctx — there is no per-dataset
 * loop above this to break, unlike ex_global_scan_adapter). COLD
 * records are decoded + validated (so a corrupt COLD value still
 * aborts the scan) but contribute no paddr — the CAS tier is reclaimed
 * separately (9.7-impl-4c-ii). */
static int ex_collect_data_adapter(const void *k, size_t klen,
                                      const void *v, size_t vlen,
                                      void *ctx_) {
    ex_collect_data_ctx *gc = ctx_;
    uint64_t ino = 0, off = 0;
    stm_status ks = ex_decode_key(k, klen, &ino, &off);
    if (ks != STM_OK) { gc->err = ks; return 1; }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, gc->ds, ino, off, &r);
    if (vs != STM_OK) { gc->err = vs; return 1; }
    if (r.kind == STM_EXTENT_KIND_HOT) {
        for (uint8_t i = 0; i < r.n_replicas; i++) {
            if (gc->user_cb(r.paddrs[i], gc->user_ctx) != 0)
                return 1;          /* user cb halted the scan */
        }
    }
    return 0;
}

stm_status stm_extent_index_collect_engine_data_paddrs_at(
        stm_extent_index *idx, uint64_t dataset_id,
        uint64_t root_paddr, uint64_t root_gen, const uint8_t root_csum[32],
        stm_extent_paddr_cb cb, void *cb_ctx) {
    if (!idx || !cb) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    if (idx->ds_idx == NULL) {
        must_unlock(lock);
        return STM_EINVAL;
    }

    /* EXTENT subspace bounds: [tag||0||0 .. tag||MAX||MAX] — the same
     * inclusive prefix range ex_global_walk_locked scans. */
    uint8_t lo[EX_KEY_LEN], hi[EX_KEY_LEN];
    stm_status k1 = ex_encode_key(0u,         0u,         lo);
    stm_status k2 = ex_encode_key(UINT64_MAX, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        must_unlock(lock);
        return k1 != STM_OK ? k1 : k2;
    }

    ex_collect_data_ctx gc = { .user_cb = cb, .user_ctx = cb_ctx,
                                 .ds = dataset_id, .err = STM_OK };
    /* Delegate the throwaway-engine open + bounded scan to the dataset
     * index. Lock order: extent idx->lock (held) -> dataset idx->lock
     * (taken inside) — the same order ex_global_walk_locked uses. */
    stm_status rc = stm_dataset_index_scan_engine_range_at(
            idx->ds_idx, dataset_id, root_paddr, root_gen, root_csum,
            lo, EX_KEY_LEN, hi, EX_KEY_LEN,
            ex_collect_data_adapter, &gc);
    must_unlock(lock);
    if (rc != STM_OK) return rc;
    return gc.err;   /* a per-value decode failure inside the adapter */
}
