/* SPDX-License-Identifier: ISC */
/*
 * Per-pool extent index — btree_engine-backed (9.6-impl-4d).
 *
 *   see include/stratum/extent.h — public API + invariants.
 *   see v2/specs/extent.tla — formal model.
 *   see v2/docs/phase-9.6-impl-4-cutover-design.md — engine cutover rationale.
 *
 * Persistence is incremental-COW B+tree via stm_btree_engine — the same
 * substrate the inode / dirent / xattr indices use as of 9.6-impl-4b/c.
 * The retired pre-4d implementation held records[] in RAM, rebuilt the
 * whole tree on every stm_extent_index_commit, and validated cross-record
 * invariants on every load. The post-cutover impl:
 *
 *   - reads records on demand via stm_btree_engine_lookup + scan_range
 *     over the (dataset_id, ino) prefix;
 *   - mutates via stm_btree_engine_insert (upsert) + _delete;
 *   - commits via the three-phase _commit_flush / _finalize / _abort
 *     that stm_sync_commit drives (parallel to inode/dirent/xattr);
 *   - mount-scans every record into a transient ctx that raises
 *     current_txg = max(write_gen) and cross-validates cohabit
 *     (extent.tla::SharedReplicasAreCohabit) BEFORE swapping the engine
 *     in. The mount-time scan is the load-bearing validator for
 *     paddr-uniqueness across the entire pool (the runtime check
 *     defaults to allocator.tla::NoReuseInSameGen + a (ds, ino)-scoped
 *     scan; the global engine-scan-per-write is too expensive).
 *
 * The (ds, ino, off) on-disk key + 108-byte value layout (v18 + v21
 * tail) are UNCHANGED. STM_UB_VERSION 28→29 at the 4d-bump commits the
 * cutover: v28 pools (whole-tree-rebuild btree_store) are unreadable by
 * v29 code; v29 mounts open the engine via stm_btree_engine_open and
 * the layout-on-disk semantics (16 KiB nodes, AEAD-encrypted, per-node
 * BLAKE3 Merkle csum) come from the engine.
 *
 * SPEC-TO-CODE mapping (unchanged from pre-4d MVP):
 *
 *   extent.tla::Init               → stm_extent_index_create
 *   extent.tla::Write              → stm_extent_write
 *   extent.tla::Overwrite          → stm_extent_overwrite
 *   extent.tla::Truncate           → stm_extent_truncate
 *   extent.tla::Truncate (refinement: pure-read peek pair)
 *                                   → stm_extent_truncate_peek    (P7-12)
 *   extent.tla::Truncate (refinement: pre-allocated _into)
 *                                   → stm_extent_truncate_into    (P7-12)
 *   extent.tla::DeleteFile         → stm_extent_delete_file
 *   extent.tla::AdvanceTxg         → stm_extent_index_advance_txg
 *   extent.tla::Reflink            → stm_extent_reflink            (P7-16)
 *
 *   extent.tla::TypeOK             → field types in stm_extent_record
 *   extent.tla::NoOverlapWithinIno → engine_scan_range over (ds, ino)
 *                                       at every write/overwrite/reflink
 *   extent.tla::LengthPositive     → len ≥ 1 check
 *   extent.tla::BirthTxgBound      → write_gen ≤ current_txg check
 *   extent.tla::AllExtentsInBounds → off + len overflow check
 *   extent.tla::PaddrFreshness     → allocator.tla::NoReuseInSameGen
 *                                       (the runtime in-ino scan is
 *                                       defense-in-depth — see notes
 *                                       at any_paddr_in_ino_locked).
 *   extent.tla::SharedReplicasAreCohabit
 *                                   → cohabit_check_in_locked at insert
 *                                       (P7-16); cross-pool variant runs
 *                                       at mount via ex_mount_validate
 *                                       (replaces ex_validate_shadow).
 *   extent.tla::OriginConsistentInBounds
 *                                   → origin = (dataset_id, ino, off) at
 *                                       fresh write / overwrite / truncate;
 *                                       origin = src.origin at reflink;
 *                                       on-disk decode pins origin_ds > 0
 *                                       AND origin_ino > 0 (P7-16).
 */
#include <stratum/extent.h>
#include <stratum/cas.h>

/* R53 P3-5: extent's content_hash field and CAS's hash key MUST share
 * the same byte length — chunked migrate copies between them via
 * memcpy(STM_EXTENT_HASH_LEN). If a future revision widens one without
 * the other, the copy would short-fill or buffer-overflow. */
_Static_assert(STM_EXTENT_HASH_LEN == STM_CAS_HASH_LEN,
               "extent + CAS hash lengths must agree (cross-index memcpy)");

/* MVP on-disk encoding cap: 24-bit length so `dlen` (le32 at offset 48)
 * and `clen_and_comp.clen` (low 24 bits of le32 at offset 52) both fit
 * the same value (no compression). Hoisted to file scope so callers in
 * this TU can validate against it without forward-declaration; canonical
 * encoding-section reference at ex_encode_value.
 *
 * P7-CAS-17 `stm_extent_migrate_whole_ino_to_cold` validates chunk lens
 * against this cap. */
#define EX_LEN_MAX_24BIT        UINT32_C(0x00FFFFFF)

#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/btnode.h>
#include <stratum/btree.h>
#include <stratum/btree_engine.h>
#include <stratum/engine_store.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdint.h>
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

/* On-disk key/value lengths — defined here so the struct + the engine
 * glue below can refer to them. The encoding routines live further down
 * in this TU (the canonical encoding-section is unchanged from pre-4d). */
#define EX_KEY_LEN              24u                          /* ds + ino + off */
#define EX_VAL_LEN              108u                         /* P7-CAS-11 / v21 */

struct stm_extent_index {
    pthread_mutex_t       lock;
    uint64_t              current_txg;

    /* ----- Persistence (9.6-impl-4d: btree_engine-backed). ----- */
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
    stm_btree_engine     *eng;           /* the extent store. Created once
                                           * BOTH contexts are bound (see
                                           * ex_engine_create_locked /
                                           * the two binders), or by load_at
                                           * on the mount path. */
    /* Last durably-committed root triple — mirrored for the sync layer's
     * uberblock stamping (stm_extent_index_get_root / _get_gen). */
    uint64_t              root_paddr;
    uint64_t              root_gen;
    uint8_t               root_csum[32];
};

static inline pthread_mutex_t *ex_lock(const stm_extent_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

/* ------------------------------------------------------------------ */
/* Forward decls for encode/decode (defined in the encoding section).   */
/* ------------------------------------------------------------------ */

static void       ex_encode_key(uint64_t ds, uint64_t ino, uint64_t off,
                                 uint8_t out[EX_KEY_LEN]);
static stm_status ex_decode_key(const uint8_t *in, size_t in_len,
                                   uint64_t *ds, uint64_t *ino, uint64_t *off);
static stm_status ex_encode_value(const stm_extent_record *r,
                                     uint8_t out[EX_VAL_LEN]);
static stm_status ex_decode_value(const uint8_t *in, size_t in_len,
                                     uint64_t ds, uint64_t ino, uint64_t off,
                                     stm_extent_record *out_rec);

/* ------------------------------------------------------------------ */
/* Common helpers.                                                      */
/* ------------------------------------------------------------------ */

/* Two byte-ranges [a_off, a_off+a_len) and [b_off, b_off+b_len) overlap
 * iff a_off < b_off+b_len AND b_off < a_off+a_len. Caller MUST have
 * validated that both ranges do not overflow uint64. */
static inline bool ranges_overlap(uint64_t a_off, uint64_t a_len,
                                     uint64_t b_off, uint64_t b_len) {
    if (a_len == 0 || b_len == 0) return false;
    return a_off < b_off + b_len && b_off < a_off + a_len;
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

/* ------------------------------------------------------------------ */
/* Engine glue. All ops are caller-holds-idx->lock.                     */
/* ------------------------------------------------------------------ */

/* engine_lookup + decode at exact (ds, ino, off). On STM_OK: *out_found
 * is set; if true, *out holds the validated decoded record. The
 * dataset_id / ino / off fields are stamped from the key triple, NOT
 * trusted from the value bytes — the value carries the kind, replicas,
 * gen, key_id, origin_*, link_gen, read_count, last_read_gen. */
static stm_status ex_engine_get(stm_extent_index *idx,
                                uint64_t ds, uint64_t ino, uint64_t off,
                                stm_extent_record *out, bool *out_found) {
    *out_found = false;
    uint8_t key[EX_KEY_LEN];
    ex_encode_key(ds, ino, off, key);

    bool found = false;
    void *vbuf = NULL;
    size_t vlen = 0;
    stm_status ls = stm_btree_engine_lookup(idx->eng, key, EX_KEY_LEN,
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

/* Encode + engine_insert (upsert). The engine's insert is failure-atomic —
 * a failed put never loses the prior value at this key. */
static stm_status ex_engine_put(stm_extent_index *idx,
                                const stm_extent_record *r) {
    uint8_t key[EX_KEY_LEN];
    uint8_t val[EX_VAL_LEN];
    ex_encode_key(r->dataset_id, r->ino, r->off, key);
    stm_status es = ex_encode_value(r, val);
    if (es != STM_OK) return es;
    return stm_btree_engine_insert(idx->eng, key, EX_KEY_LEN, val, EX_VAL_LEN);
}

/* engine_delete at exact (ds, ino, off). Unlike dirent (where Unlink
 * writes a TOMBSTONE via engine_insert), extent is the only metadata
 * index that uses engine_delete in the normal write-path: truncate /
 * delete_file / overwrite / punch_range / migrate_to_cold_chunked /
 * shift_range_keys all need STRUCTURAL removal (extent.tla doesn't
 * model tombstone slots; a stale extent record left in the tree would
 * read back at mount as a live extent → data corruption). The 9.6-
 * impl-4 design doc §3.1 added stm_btree_engine_delete specifically
 * for this use case. */
static stm_status ex_engine_del(stm_extent_index *idx,
                                uint64_t ds, uint64_t ino, uint64_t off) {
    uint8_t key[EX_KEY_LEN];
    ex_encode_key(ds, ino, off, key);
    return stm_btree_engine_delete(idx->eng, key, EX_KEY_LEN, NULL);
}

/* Stand up the btree_engine from the (now both populated) store + crypt
 * contexts. Caller holds idx->lock, has verified BOTH contexts are
 * bound and idx->eng is NULL. The engine borrows &idx->store_ctx (its
 * vt_ctx) and &idx->crypt_ctx (its cx) — both stable members, alive for
 * idx's lifetime. */
static stm_status ex_engine_create_locked(stm_extent_index *idx) {
    return stm_btree_engine_create(&STM_ENGINE_STORE_VT, &idx->store_ctx,
                                   &idx->crypt_ctx, /*tree_id=*/0u,
                                   &idx->eng);
}

/* ------------------------------------------------------------------ */
/* (ds, ino) prefix iteration — extent's NoOverlapWithinIno checks +    */
/* iter / truncate / punch_range / shift_range_keys / cohabit-check    */
/* all bracket the engine at the (ds, ino) prefix.                     */
/*                                                                      */
/* The on-disk key is le64(ds) ‖ le64(ino) ‖ le64(off). The engine     */
/* compares keys bytewise (memcmp). Within a fixed (ds, ino) prefix,   */
/* every key shares the same 16-byte prefix; the                       */
/* [ds‖ino‖0 .. ds‖ino‖UINT64_MAX] scan_range bounds therefore bracket */
/* exactly that (ds, ino)'s keys regardless of the LE off-field        */
/* numeric scramble. The two pre-4d scan-style ops (paddr-in-use +     */
/* iter) already had to handle unsorted iteration, so the bytewise-not-*/
/* numeric ordering is a no-op semantic change.                        */
/* ------------------------------------------------------------------ */

typedef struct {
    /* In-ino collected records, sorted later if the caller wants. */
    stm_extent_record  *records;
    uint64_t           *offs;   /* parallel array of key.off for filter */
    size_t              n;
    size_t              cap;
    stm_status          err;
} ex_collect_ctx;

static int ex_collect_cb(const void *k, size_t klen,
                         const void *v, size_t vlen, void *ctx_) {
    ex_collect_ctx *c = ctx_;
    uint64_t ds = 0, ino = 0, off = 0;
    stm_status ks = ex_decode_key(k, klen, &ds, &ino, &off);
    if (ks != STM_OK) { c->err = ks; return 1; }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, ds, ino, off, &r);
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
 * idx->lock. *out_ctx is owned by the caller, free'd via
 * ex_collect_free. NULL out_ctx->records on n==0 (and cap==0). */
static stm_status ex_collect_in_ino_locked(stm_extent_index *idx,
                                           uint64_t ds, uint64_t ino,
                                           ex_collect_ctx *out_ctx) {
    memset(out_ctx, 0, sizeof *out_ctx);
    uint8_t lo[EX_KEY_LEN], hi[EX_KEY_LEN];
    ex_encode_key(ds, ino, 0u,         lo);
    ex_encode_key(ds, ino, UINT64_MAX, hi);
    stm_status ss = stm_btree_engine_scan_range(idx->eng, lo, EX_KEY_LEN,
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

/* Whole-tree paddr / cohabit context. Used by the global scans below
 * to validate paddr-uniqueness + extent.tla::SharedReplicasAreCohabit
 * at insert time across the entire pool.
 *
 * NOTE: pre-4d these checks ran against an in-RAM records[] (cheap).
 * Post-4d they engine_scan the entire tree (decrypts every node). For
 * typical extents this is acceptable; for high-frequency writes on a
 * large pool this is a known perf degradation. Forward-noted at the
 * impl-5+ chunks: a paddr→extent map (in-RAM index keyed by paddr,
 * rebuilt at mount + maintained at every write/delete) would restore
 * O(1) lookup. The MVP defers that optimisation; correctness wins. */
typedef struct {
    /* paddr-uniqueness probe. */
    const uint64_t  *probe_paddrs;
    size_t           n_probe;
    /* Skip-record set: by (ds, ino, off) triples. Used by stm_extent_overwrite
     * to exclude the records that are being dropped (their paddrs are
     * about to be freed, so the new candidate may legitimately reuse them
     * within the same call). NULL/0 means no skip set. */
    const uint64_t  *skip_keys;    /* triples [ds0, ino0, off0, ds1, ino1, off1, ...] */
    size_t           n_skip;       /* number of triples */
    bool             collision;
    /* cohabit probe: candidate tuple. */
    bool             cohabit_active;       /* gate the check off when unused */
    const uint64_t  *cand_paddrs;
    size_t           n_cand;
    uint64_t         cand_gen;
    uint64_t         cand_key_id;
    uint64_t         cand_origin_ds;
    uint64_t         cand_origin_ino;
    uint64_t         cand_origin_off;
    bool             cohabit_ok;
    stm_status       err;
} ex_global_check_ctx;

static int ex_global_check_cb(const void *k, size_t klen,
                              const void *v, size_t vlen, void *ctx_) {
    ex_global_check_ctx *gc = ctx_;
    uint64_t ds = 0, ino = 0, off = 0;
    stm_status ks = ex_decode_key(k, klen, &ds, &ino, &off);
    if (ks != STM_OK) { gc->err = ks; return 1; }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, ds, ino, off, &r);
    if (vs != STM_OK) { gc->err = vs; return 1; }

    /* Check skip set: if THIS record's key is in the skip list, don't
     * count its paddrs against the candidate (overwrite is dropping
     * this record; its paddrs are about to be freed). */
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

    /* Paddr-uniqueness probe (LiveReplicasDisjoint). Any share fires
     * collision; we DON'T early-exit because the cohabit probe may
     * still want to run on later records. (In practice the callers
     * activate at most ONE probe at a time, so the optimisation
     * doesn't pay; preserving generality.) */
    if (gc->probe_paddrs && !skipped) {
        for (uint8_t i = 0; i < r.n_replicas && !gc->collision; i++) {
            for (size_t k_ = 0; k_ < gc->n_probe; k_++) {
                if (r.paddrs[i] == gc->probe_paddrs[k_]) {
                    gc->collision = true;
                    break;
                }
            }
        }
    }

    /* Cohabit probe (SharedReplicasAreCohabit). */
    if (gc->cohabit_active && gc->cohabit_ok) {
        bool any_share = false;
        for (uint8_t i = 0; i < r.n_replicas && !any_share; i++) {
            for (size_t k_ = 0; k_ < gc->n_cand; k_++) {
                if (r.paddrs[i] == gc->cand_paddrs[k_]) {
                    any_share = true;
                    break;
                }
            }
        }
        if (any_share) {
            /* Whole-set match required. */
            if (r.n_replicas != (uint8_t)gc->n_cand) {
                gc->cohabit_ok = false;
            } else {
                bool whole_match = true;
                for (uint8_t i = 0; i < r.n_replicas && whole_match; i++) {
                    bool found = false;
                    for (size_t k_ = 0; k_ < gc->n_cand; k_++) {
                        if (r.paddrs[i] == gc->cand_paddrs[k_]) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) whole_match = false;
                }
                if (!whole_match) gc->cohabit_ok = false;
                else if (r.gen != gc->cand_gen) gc->cohabit_ok = false;
                else if (r.key_id != gc->cand_key_id) gc->cohabit_ok = false;
                else if (r.origin_dataset_id != gc->cand_origin_ds)  gc->cohabit_ok = false;
                else if (r.origin_ino        != gc->cand_origin_ino) gc->cohabit_ok = false;
                else if (r.origin_off        != gc->cand_origin_off) gc->cohabit_ok = false;
            }
        }
    }
    return 0;
}

/* Cross-(ds, ino) paddr-uniqueness scan. Caller holds idx->lock. */
static stm_status any_paddr_in_use_global_locked(stm_extent_index *idx,
                                                  const uint64_t *paddrs, size_t n,
                                                  bool *out_collision) {
    *out_collision = false;
    ex_global_check_ctx gc = {0};
    gc.probe_paddrs = paddrs;
    gc.n_probe      = n;
    gc.cohabit_ok   = true;
    stm_status ss = stm_btree_engine_scan(idx->eng, ex_global_check_cb, &gc);
    if (ss != STM_OK) return ss;
    if (gc.err != STM_OK) return gc.err;
    *out_collision = gc.collision;
    return STM_OK;
}

/* P7-16: validate extent.tla::SharedReplicasAreCohabit at insert time.
 * Given a candidate (paddrs, gen, key_id, origin_*) tuple about to be
 * inserted, checks EVERY existing extent record in the pool. If any
 * existing record shares a paddr but disagrees on (replicas, gen,
 * key_id, origin_*), the cohabit invariant would be violated — return
 * false (refuse). If sharing is consistent (whole-extent inheritance),
 * or no sharing exists, return true.
 *
 * Three-state classification of an existing record `e` vs candidate:
 *   - No overlap: e.replicas ∩ candidate.paddrs = ∅. OK.
 *   - Whole-set match + matching tuple: cohabit-OK. Multiple reflink-
 *     siblings can coexist; any number is fine.
 *   - Partial overlap OR whole-match-but-tuple-mismatch: refuse.
 *
 * Whole-set check: same n_replicas AND each paddr in e.paddrs is in
 * candidate.paddrs (their replica sets are equal as sets).
 *
 * NOTE: cross-(ds, ino) global scan. See ex_global_check_ctx for the
 * perf rationale. */
static stm_status cohabit_check_global_locked(stm_extent_index *idx,
                                              const uint64_t *paddrs, size_t n_paddrs,
                                              uint64_t gen, uint64_t key_id,
                                              uint64_t origin_ds, uint64_t origin_ino,
                                              uint64_t origin_off,
                                              bool *out_ok) {
    *out_ok = true;
    ex_global_check_ctx gc = {0};
    gc.cohabit_active     = true;
    gc.cand_paddrs        = paddrs;
    gc.n_cand             = n_paddrs;
    gc.cand_gen           = gen;
    gc.cand_key_id        = key_id;
    gc.cand_origin_ds     = origin_ds;
    gc.cand_origin_ino    = origin_ino;
    gc.cand_origin_off    = origin_off;
    gc.cohabit_ok         = true;
    stm_status ss = stm_btree_engine_scan(idx->eng, ex_global_check_cb, &gc);
    if (ss != STM_OK) return ss;
    if (gc.err != STM_OK) return gc.err;
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
    /* NULL-safe; an un-finalized flush is implicitly aborted (the
     * flushed-but-unrooted paddrs are handed back to the allocator).
     * The monolithic stm_extent_index_commit uses the single-shot engine
     * commit (no pending window); the three-phase _commit_flush /
     * _finalize / _abort trio pairs every flush with a finalize-or-abort
     * in stm_sync_commit. The implicit abort here is defense-in-depth
     * for a destroy that races a buggy mid-flush caller. */
    stm_btree_engine_destroy(idx->eng);
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
     * need to dirty the engine. */
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
    if (len == 0) return STM_EINVAL;            /* LengthPositive */
    if (!paddrs) return STM_EINVAL;
    if (!replica_set_is_valid(paddrs, n_paddrs)) return STM_EINVAL;
    /* off + len overflow guard (AllExtentsInBounds — bounds the end). */
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;                       /* BirthTxgBound */
    }

    /* LiveReplicasDisjoint (cross-(ds, ino) global scan).
     * extent.tla guarantees PaddrFreshness across the entire pool; we
     * mirror that at the runtime check site. */
    bool collision = false;
    stm_status ps = any_paddr_in_use_global_locked(idx, paddrs, n_paddrs,
                                                     &collision);
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
        return STM_EEXIST;                       /* NoOverlapWithinIno */
    }

    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .kind       = STM_EXTENT_KIND_HOT,    /* P7-CAS: fresh writes are HOT */
        .n_replicas = (uint8_t)n_paddrs,
        .gen = write_gen,
        .key_id = key_id,
        /* P7-16: fresh write — origin = (dataset_id, ino, off). */
        .origin_dataset_id = dataset_id,
        .origin_ino        = ino,
        .origin_off        = off,
        /* R48 P0-1: fresh write — link_gen == write_gen. */
        .link_gen          = write_gen,
    };
    for (size_t i = 0; i < n_paddrs; i++) rec.paddrs[i] = paddrs[i];
    /* P7-CAS: content_hash zeroed by initializer for HOT extents. */
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
    /* R34 P2-1: zero out-args before any early return. */
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
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (write_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* Collect every record under (ds, ino). Single scan_range — we then
     * partition into drop-set (overlapping with [off, off+len)) and
     * survivor-set. */
    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }

    /* First pass: validate the drop set + check for paddr cycle. */
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (!ranges_overlap(e->off, e->len, off, len)) continue;
        /* Cycle check: no new replica paddr may match any paddr in any
         * to-be-dropped extent's replica set (caller bug — overwrite
         * can't reuse a paddr it's dropping; allocator.tla::
         * NoReuseInSameGen forbids it for the alloc-issuance side). */
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

    /* Build the (ds, ino, off) skip-set: the to-be-dropped records'
     * keys. LiveReplicasDisjoint runs as a global scan that EXCLUDES
     * these (their paddrs are about to be freed, so the candidate may
     * legitimately reuse a paddr they hold). */
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

    /* Global scan: collision iff any new_paddr is in an existing
     * extent's replica set AND that extent is not in the skip set. */
    ex_global_check_ctx gc = {0};
    gc.probe_paddrs = new_paddrs;
    gc.n_probe      = n_new_paddrs;
    gc.skip_keys    = skip_keys;
    gc.n_skip       = n_drops;
    gc.cohabit_ok   = true;
    stm_status gss = stm_btree_engine_scan(idx->eng, ex_global_check_cb, &gc);
    if (gss != STM_OK || gc.err != STM_OK || gc.collision) {
        free(skip_keys);
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        if (gss != STM_OK)    return gss;
        if (gc.err != STM_OK) return gc.err;
        return STM_EEXIST;
    }
    free(skip_keys);

    /* Allocate the dropped-paddr buffer (if any drops). */
    uint64_t *out_buf = NULL;
    if (total_drops > 0) {
        out_buf = calloc(total_drops, sizeof(uint64_t));
        if (!out_buf) {
            ex_collect_free(&c);
            must_unlock(&idx->lock);
            return STM_ENOMEM;
        }
    }

    /* Capture drop indices + flattened paddrs from the snapshot. */
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

    /* Engine mutation. Insert the new record FIRST — if any old key
     * happens to equal the new (off), upsert replaces it (no need to
     * delete that one separately). Then delete remaining drops whose
     * keys differ from the new record's (off).
     *
     * If the engine_insert fails: nothing was committed; abort with
     * the failure status. The snapshot is freed; the engine remains
     * exactly as it was. */
    stm_extent_record rec = {
        .dataset_id = dataset_id, .ino = ino,
        .off = off, .len = len,
        .kind       = STM_EXTENT_KIND_HOT,    /* P7-CAS: COW always HOT */
        .n_replicas = (uint8_t)n_new_paddrs,
        .gen = write_gen,
        .key_id = key_id,
        /* P7-16: COW Overwrite resets origin = current — the new
         * ciphertext was AEAD-encrypted under (dataset_id, ino, off). */
        .origin_dataset_id = dataset_id,
        .origin_ino        = ino,
        .origin_off        = off,
        /* R48 P0-1: fresh ciphertext — link_gen == write_gen. */
        .link_gen          = write_gen,
    };
    for (size_t i = 0; i < n_new_paddrs; i++) rec.paddrs[i] = new_paddrs[i];

    stm_status ps = ex_engine_put(idx, &rec);
    if (ps != STM_OK) {
        free(out_buf);
        free(drop_offs_idx);
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return ps;
    }

    /* Delete drops whose key.off differs from the new record's off (the
     * same-off drop was replaced by the upsert above). On engine_delete
     * failure we have torn state — pre-4d the in-RAM impl couldn't fail
     * here either; post-4d the failure surface is STM_EBUSY (pending-
     * commit window — never happens under the FS lock discipline) /
     * STM_ENOMEM (defensive). Return the status verbatim; stm_sync_commit
     * will wedge on the next commit attempt if the engine state is
     * inconsistent. */
    stm_status last_ds = STM_OK;
    for (size_t i = 0; i < n_drops; i++) {
        const stm_extent_record *e = &c.records[drop_offs_idx[i]];
        if (e->off == off) continue;            /* upsert already handled */
        stm_status ds = ex_engine_del(idx, e->dataset_id, e->ino, e->off);
        if (ds != STM_OK) last_ds = ds;
    }
    free(drop_offs_idx);
    ex_collect_free(&c);

    *out_dropped_paddrs = out_buf;
    *out_n_dropped      = out_idx;
    must_unlock(&idx->lock);
    return last_ds;
}

/* ------------------------------------------------------------------ */
/* Predicate-drop driver — shared by truncate / delete_file /          */
/* truncate_into / punch_range.                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    bool       have_delete_all;
    uint64_t   threshold;        /* drop records whose off ≥ threshold */
    bool       have_punch_range; /* drop records FULLY inside [off, off+len) */
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
    /* default: truncate(threshold) — drop off ≥ threshold */
    return e->off >= p->threshold;
}

/* Caller holds idx->lock. Collects every (ds, ino) record into a
 * snapshot, picks the ones matching `pred`, deletes them from the
 * engine, returns the flattened replica paddrs to the caller.
 *
 * Allocates *out_paddrs if total > 0. *out_n is the count of paddrs
 * written. */
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

    *out_paddrs = paddrs;
    *out_n      = pidx;
    return last_ds;
}

/* Predicate-drop variant for stm_extent_truncate_into — uses caller-
 * provided pre-allocated buffers and never allocates. Returns STM_ERANGE
 * if either cap is insufficient (atomic — index unchanged on ERANGE). */
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
        drop_idx_buf[n_drops++] = i;          /* indices into c.records */
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
    /* R34 P2-1: zero out-args before any early return. */
    if (!out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    if (!idx->eng) {
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

/* P7-12: peek-only count of past-truncation extents + replicas. */
stm_status stm_extent_truncate_peek(const stm_extent_index *idx,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t new_size,
                                       size_t *out_n_extents,
                                       size_t *out_n_replicas_total) {
    /* R44 P3-4: zero out-args before any early return. */
    if (!out_n_extents || !out_n_replicas_total) return STM_EINVAL;
    *out_n_extents        = 0;
    *out_n_replicas_total = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    if (!idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked((stm_extent_index *)idx,
                                              dataset_id, ino, &c);
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
    /* drop_idx_buf / paddrs_buf may be NULL only when their cap is 0
     * AND no drops are expected; otherwise we'd dereference null.
     * Allow NULL+0 so a caller that peeked zero can pass NULL safely. */
    if (drop_idx_cap > 0 && !drop_idx_buf) return STM_EINVAL;
    if (paddrs_cap   > 0 && !paddrs_buf)   return STM_EINVAL;

    must_lock(&idx->lock);
    if (!idx->eng) {
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
    /* R34 P2-1: zero out-args before any early return. */
    if (!out_dropped_paddrs || !out_n_dropped) return STM_EINVAL;
    *out_dropped_paddrs = NULL;
    *out_n_dropped      = 0;
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    if (!idx->eng) {
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

/* P8-POSIX-7b PUNCH_HOLE: drop every extent at (ds, ino) fully
 * contained in [off, off+len). Refuse if any extent crosses a
 * boundary. */
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
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* Pre-check: refuse if any extent crosses either boundary. */
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

    /* Pre-check passed — delegate to the predicate-drop driver with
     * punch_range semantics. */
    ex_drop_pred pred = { .have_delete_all = false, .threshold = 0,
                            .have_punch_range = true,
                            .punch_off = off, .punch_end = r_end };
    stm_status rs = drop_by_predicate_locked(idx, dataset_id, ino, &pred,
                                                out_dropped_paddrs,
                                                out_n_dropped_paddrs);
    must_unlock(&idx->lock);
    return rs;
}

/* P8-POSIX-7b COLLAPSE_RANGE / INSERT_RANGE: shift extent keys at
 * off >= cutoff by the signed `delta`.
 *
 * Engine-backed posture: scan + collect every (ds, ino) record, validate
 * preconditions, then for each shifted record: delete-old + insert-new.
 * If delete fails mid-loop, we accept torn state (matches the pre-4d
 * in-place pointer-walk's implicit atomicity — neither impl rolls back
 * on a mid-shift failure). The engine_insert is failure-atomic per the
 * engine contract, and the delete failure surface is STM_EBUSY (never
 * fires under FS lock discipline) / STM_ENOMEM.
 *
 * Order: we must delete BEFORE insert when shifting up (positive delta)
 * because the new key may collide with a yet-to-be-shifted record;
 * conversely we must delete BEFORE insert when shifting down as well
 * (otherwise the new key may collide with a yet-to-be-shifted record
 * higher in the chain). Simplest: collect → delete every shifted
 * record → insert at new offset. */
stm_status stm_extent_shift_range_keys(stm_extent_index *idx,
                                            uint64_t dataset_id, uint64_t ino,
                                            uint64_t cutoff,
                                            int64_t  delta) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (delta == 0) return STM_EINVAL;

    must_lock(&idx->lock);
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }

    /* Validate preconditions across all (ds, ino) extents BEFORE
     * mutating anything. */
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        uint64_t e_end = e->off + e->len;

        if (delta < 0) {
            uint64_t adelta = (uint64_t)(-delta);
            /* COLLAPSE: cutoff is the END of the punched range; the
             * range [cutoff - adelta, cutoff) must be empty (already
             * punched). Equivalently, no extent may overlap that
             * range. */
            if (cutoff < adelta) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_EINVAL;
            }
            uint64_t hole_start = cutoff - adelta;
            if (e->off < cutoff && e_end > hole_start) {
                /* Extent overlaps the hole — caller must clear it
                 * (e.g., via stm_extent_punch_range) before shifting. */
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_ENOTSUPPORTED;
            }
            /* Below the hole: untouched. Above cutoff: shift down by
             * adelta. Range underflow guard. */
            if (e->off >= cutoff && e->off < adelta) {
                ex_collect_free(&c);
                must_unlock(&idx->lock);
                return STM_EINVAL;
            }
        } else {
            uint64_t adelta = (uint64_t)delta;
            /* INSERT: no extent may cross the cutoff. Below cutoff:
             * untouched. At/above cutoff: shift up by adelta —
             * shifted end MUST NOT overflow uint64_t. */
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

    /* Apply shift: for each record at off ≥ cutoff, delete old key +
     * insert at shifted offset. Records below cutoff are untouched. */
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
    if (len == 0) return STM_EINVAL;            /* LengthPositive */
    if (!paddrs) return STM_EINVAL;
    if (!replica_set_is_valid(paddrs, n_paddrs)) return STM_EINVAL;
    if (dst_off > UINT64_MAX - len) return STM_EOVERFLOW;

    must_lock(&idx->lock);
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;                       /* BirthTxgBound */
    }
    /* R48 P0-1: link_gen also bounded by current_txg (BirthTxgBound
     * applies to the link gen as well — the record can't be linked at
     * a future gen). */
    if (link_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    /* P7-16: dst-overlap check (NoOverlapWithinIno). */
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
    /* P7-16: SharedReplicasAreCohabit. Reuse of any paddr is permitted
     * ONLY when the existing extent's (replicas, gen, key_id, origin_*)
     * tuple matches the candidate. Catches the partial-overlap and
     * different-origin buggy patterns. link_gen is excluded from the
     * cohabit check — siblings created at different gens still share
     * legitimately. Cross-(ds, ino) global scan. */
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
        .kind       = STM_EXTENT_KIND_HOT,    /* P7-CAS: reflinks share HOT replicas */
        .n_replicas = (uint8_t)n_paddrs,
        .gen = gen,
        .key_id = key_id,
        .origin_dataset_id = origin_dataset_id,
        .origin_ino        = origin_ino,
        .origin_off        = origin_off,
        .link_gen          = link_gen,
    };
    for (size_t i = 0; i < n_paddrs; i++) rec.paddrs[i] = paddrs[i];
    /* P7-CAS: content_hash zeroed by initializer for HOT extents. */
    stm_status as = ex_engine_put(idx, &rec);
    must_unlock(&idx->lock);
    return as;
}

/* P7-CAS: insert a COLD extent record. Caller has already inserted /
 * ref-bumped the CAS index entry and the extent record's content_hash
 * names that entry. */
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
    /* Hash all-zero is reserved sentinel. */
    bool any_nonzero = false;
    for (size_t i = 0; i < STM_EXTENT_HASH_LEN; i++) {
        if (content_hash[i] != 0) { any_nonzero = true; break; }
    }
    if (!any_nonzero) return STM_EINVAL;

    must_lock(&idx->lock);
    if (!idx->eng) {
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
    /* paddrs[] zeroed by initializer; content_hash copied in. */
    memcpy(rec.content_hash, content_hash, STM_EXTENT_HASH_LEN);

    stm_status as = ex_engine_put(idx, &rec);
    must_unlock(&idx->lock);
    return as;
}

/* P7-CAS-2: atomic hot→cold swap. See header for full contract. The
 * (ds, ino, off) key is unchanged — the swap is an UPSERT replacing the
 * HOT value with a COLD value at the same key. */
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
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (gen > idx->current_txg)      { must_unlock(&idx->lock); return STM_EINVAL; }
    if (link_gen > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }

    /* Find the matching HOT extent at (ds, ino, off). */
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
        return STM_EINVAL;            /* partial migrate not modeled */
    }
    if (src.kind != STM_EXTENT_KIND_HOT) {
        must_unlock(&idx->lock);
        return STM_EINVAL;            /* COLD already; caller bug */
    }
    if (src.n_replicas < 1 || src.n_replicas > STM_EXTENT_MAX_REPLICAS) {
        must_unlock(&idx->lock);
        return STM_ECORRUPT;
    }

    /* Capture dropped HOT replicas FIRST so the upsert below cannot
     * lose them. */
    *out_n_replicas = src.n_replicas;
    for (uint8_t r = 0; r < src.n_replicas; r++) {
        out_paddrs[r] = src.paddrs[r];
    }

    /* Build the COLD replacement and upsert at the same key. */
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
    /* paddrs[] zeroed by initializer. */
    memcpy(cold_rec.content_hash, content_hash, STM_EXTENT_HASH_LEN);

    stm_status ps = ex_engine_put(idx, &cold_rec);
    must_unlock(&idx->lock);
    return ps;
}

/* P7-CAS-4b: 1-hot-to-N-cold chunked migrate. See header for full
 * contract. */
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
    if (n_chunks == 1) return STM_EINVAL;       /* K=1 → use single migrate */
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (src_origin_dataset_id == 0 || src_origin_ino == 0) return STM_EINVAL;
    if (src_len == 0) return STM_EINVAL;
    if (src_off > UINT64_MAX - src_len) return STM_EOVERFLOW;
    if (src_origin_off > UINT64_MAX - src_len) return STM_EINVAL;

    /* Pre-validate the tile: chunks contiguous, lens > 0, hashes nonzero,
     * total spans [src_off, src_off+src_len). */
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
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (src_gen  > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }
    if (link_gen > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }

    /* Find the matching HOT extent at (ds, ino, src_off). */
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
        return STM_EINVAL;            /* partial migrate not modeled */
    }
    if (src.kind != STM_EXTENT_KIND_HOT) {
        must_unlock(&idx->lock);
        return STM_EINVAL;            /* COLD already; caller bug */
    }
    if (src.n_replicas < 1 || src.n_replicas > STM_EXTENT_MAX_REPLICAS) {
        must_unlock(&idx->lock);
        return STM_ECORRUPT;
    }

    /* Capture dropped HOT replicas FIRST so the upserts below cannot
     * lose them. */
    *out_n_replicas = src.n_replicas;
    for (uint8_t r = 0; r < src.n_replicas; r++) {
        out_paddrs[r] = src.paddrs[r];
    }

    /* Chunk 0 takes the dropped src slot (upsert at src_off REPLACES
     * the HOT record at the same key). Chunks 1..N-1 are fresh keys
     * (their off is strictly greater than src_off — no key conflict
     * with any existing record at (ds, ino) because the source HOT
     * extent OCCUPIED the entire [src_off, src_off+src_len) range so
     * no other (ds, ino) record can overlap it by NoOverlapWithinIno). */
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

/* P7-CAS-17: cross-extent FastCDC at migrate. Atomically replace ALL HOT
 * extents at (ds, ino) with N' COLD chunks tiling the same range. */
stm_status stm_extent_migrate_whole_ino_to_cold(
        stm_extent_index *idx,
        uint64_t dataset_id, uint64_t ino,
        const stm_extent_cold_chunk *chunks, size_t n_chunks,
        uint64_t key_id,
        uint64_t link_gen,
        uint64_t **out_dropped_paddrs,
        size_t *out_n_dropped_paddrs) {
    /* Uniform out-param zero-init contract (R57 P3-5 + R58 P3-1 + R64 P2-1). */
    if (out_dropped_paddrs)   *out_dropped_paddrs = NULL;
    if (out_n_dropped_paddrs) *out_n_dropped_paddrs = 0;

    if (!idx || !chunks || !out_dropped_paddrs || !out_n_dropped_paddrs)
        return STM_EINVAL;
    if (dataset_id == 0 || ino == 0) return STM_EINVAL;
    if (n_chunks == 0) return STM_EINVAL;
    if (link_gen == 0) return STM_EINVAL;

    /* Validate chunks: each has non-zero len bounded by 24-bit, alignment
     * to STM_UB_SIZE, non-zero hash. Validate tile contiguity. */
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
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (link_gen > idx->current_txg) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* Phase 1: collect every (ds, ino) record. Refuse on COLD/corrupt;
     * gather HOT records. */
    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(idx, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(&idx->lock);
        return cs;
    }

    /* Validate the collected records — every record must be HOT with a
     * legal replica count. */
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
            /* All HOT records under the same (ds, ino) created by the
             * compound write path share gen/key_id/origin_* tuples
             * (extent.tla::OriginConsistentInBounds + R48 P0-1
             * link_gen). Capture from the first encountered record;
             * defense-in-depth equality check follows below. */
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
    /* Defense-in-depth: every collected HOT record shares (gen, key_id,
     * origin_ds, origin_ino). If a buggy producer broke that invariant
     * we'd see a divergent record here. */
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *r = &c.records[i];
        if (r->gen != src_gen) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
        if (r->key_id != src_key_id) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
        if (r->origin_dataset_id != src_origin_ds) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
        if (r->origin_ino != src_origin_ino) { ex_collect_free(&c); must_unlock(&idx->lock); return STM_ECORRUPT; }
    }

    /* Phase 2: sort by off (small N typical; insertion-sort acceptable). */
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
    /* After sort, first_off = c.records[0].off. */
    first_off = c.records[0].off;

    /* Phase 3: validate contiguity. */
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

    /* Phase 4: validate chunks tile [first_off, first_off + total_len). */
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

    /* Phase 5: capture all dropped HOT replica paddrs. */
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

    /* Phase 6: delete every HOT record from the engine FIRST, then
     * insert every COLD chunk. Pre-4d this was a swap-erase + append
     * in-place. The engine has no such conflated op — clearing the
     * range before inserts is the cleanest way to avoid same-key
     * upserts colliding with not-yet-deleted HOT records. */
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

/* P7-CAS-11: atomic per-extent COLD→HOT swap. Drops the COLD record at
 * (ds, ino, off) + inserts a HOT record at the same coords. Returns the
 * dropped COLD's content_hash via out_content_hash. */
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
    /* Within-set distinctness + non-zero. */
    for (uint8_t i = 0; i < n_replicas; i++) {
        if (new_paddrs[i] == 0) return STM_EINVAL;
        for (uint8_t j = (uint8_t)(i + 1); j < n_replicas; j++) {
            if (new_paddrs[i] == new_paddrs[j]) return STM_EINVAL;
        }
    }
    if (off > UINT64_MAX - len) return STM_EOVERFLOW;
    if (origin_off > UINT64_MAX - len) return STM_EINVAL;

    must_lock(&idx->lock);
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    if (gen > idx->current_txg)      { must_unlock(&idx->lock); return STM_EINVAL; }
    if (link_gen > idx->current_txg) { must_unlock(&idx->lock); return STM_EINVAL; }

    /* Find the matching extent at (ds, ino, off). */
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
        return STM_EINVAL;            /* partial promote not modeled */
    }
    if (src.kind != STM_EXTENT_KIND_COLD) {
        must_unlock(&idx->lock);
        return STM_EINVAL;            /* HOT already; caller bug */
    }

    /* Capture dropped COLD's content_hash FIRST so the upsert cannot
     * lose it (caller routes the hash through stm_cas_deref AFTER
     * this returns OK). */
    memcpy(out_content_hash, src.content_hash, STM_EXTENT_HASH_LEN);

    /* Build the new HOT record. */
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
    /* content_hash[] zeroed by initializer for HOT extents. */

    stm_status ps = ex_engine_put(idx, &hot_rec);
    must_unlock(&idx->lock);
    return ps;
}

/* P7-CAS-11: bump the read counter on the COLD extent at (ds, ino, off).
 * Windowed-count semantics (see header). HOT records are no-op. Race-
 * tolerant on missing record (returns STM_OK).
 *
 * Engine-backed: this op MAY need to find a record whose off is the
 * GREATEST off ≤ probe_off whose extent covers probe_off. We scan the
 * (ds, ino) range and pick the one covering. */
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
    if (!idx->eng) {
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

    /* Find the extent covering `off`. */
    ptrdiff_t found_idx = -1;
    for (size_t i = 0; i < c.n; i++) {
        const stm_extent_record *e = &c.records[i];
        if (off < e->off) continue;
        if (off >= e->off + e->len) continue;
        found_idx = (ptrdiff_t)i;
        break;
    }
    if (found_idx < 0) {
        /* Race-tolerant: no-op + STM_OK. */
        ex_collect_free(&c);
        must_unlock(&idx->lock);
        return STM_OK;
    }
    stm_extent_record rec = c.records[found_idx];
    ex_collect_free(&c);

    if (rec.kind != STM_EXTENT_KIND_COLD) {
        /* HOT records have no counter; no-op. */
        must_unlock(&idx->lock);
        return STM_OK;
    }

    /* Windowed-count update.
     *   - last_read_gen == 0: never observed → reset to 1.
     *   - current_gen < last_read_gen: clock-rewind (shouldn't happen;
     *     defensive — treat as old + reset).
     *   - age > decay_window: out of window → reset to 1.
     *   - else: saturating-increment count. */
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
    if (!idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    stm_extent_index *m = (stm_extent_index *)idx;

    /* The MVP "first match" semantic: find any extent whose off-range
     * covers `off`. With the engine, we scan_range over (ds, ino) and
     * pick the first covering. */
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

/* ------------------------------------------------------------------ */
/* Engine_scan / scan_range callbacks for stm_extent_lookup_by_paddr / */
/* stm_extent_iter_ds / stm_extent_count{,_for_ino}. Hoisted to file   */
/* scope because C99 has no nested functions or block lambdas.         */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t           probe;
    stm_extent_record  hit;
    bool               found;
    stm_status         err;
} ex_paddr_lookup_ctx;

static int ex_paddr_lookup_cb(const void *k, size_t klen,
                              const void *v, size_t vlen, void *ctx_) {
    ex_paddr_lookup_ctx *p = ctx_;
    uint64_t ds = 0, ino_ = 0, off = 0;
    stm_status ks = ex_decode_key(k, klen, &ds, &ino_, &off);
    if (ks != STM_OK) { p->err = ks; return 1; }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, ds, ino_, off, &r);
    if (vs != STM_OK) { p->err = vs; return 1; }
    for (uint8_t i = 0; i < r.n_replicas; i++) {
        if (r.paddrs[i] == p->probe) {
            p->hit = r;
            p->found = true;
            return 1;        /* stop */
        }
    }
    return 0;
}

typedef struct {
    stm_extent_record *arr;
    size_t             n;
    size_t             cap;
    stm_status         err;
} ex_iter_ds_ctx;

static int ex_iter_ds_collect_cb(const void *k, size_t klen,
                                  const void *v, size_t vlen, void *ctx_) {
    ex_iter_ds_ctx *d = ctx_;
    uint64_t ds_ = 0, ino_ = 0, off_ = 0;
    stm_status ks = ex_decode_key(k, klen, &ds_, &ino_, &off_);
    if (ks != STM_OK) { d->err = ks; return 1; }
    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, ds_, ino_, off_, &r);
    if (vs != STM_OK) { d->err = vs; return 1; }
    if (d->n == d->cap) {
        if (d->cap > (SIZE_MAX / sizeof *d->arr) / 2u) {
            d->err = STM_ENOMEM;
            return 1;
        }
        size_t new_cap = d->cap == 0 ? 8u : d->cap * 2u;
        stm_extent_record *na = realloc(d->arr,
                                            new_cap * sizeof *d->arr);
        if (!na) { d->err = STM_ENOMEM; return 1; }
        d->arr = na;
        d->cap = new_cap;
    }
    d->arr[d->n++] = r;
    return 0;
}

typedef struct {
    size_t     n;
    stm_status err;
} ex_count_ctx;

static int ex_count_cb(const void *k, size_t klen,
                       const void *v, size_t vlen, void *ctx_) {
    (void)k; (void)klen; (void)v; (void)vlen;
    ex_count_ctx *cx = ctx_;
    cx->n++;
    return 0;
}

stm_status stm_extent_lookup_by_paddr(const stm_extent_index *idx,
                                          uint64_t paddr,
                                          stm_extent_record *out_extent) {
    if (!idx || !out_extent) return STM_EINVAL;
    if (paddr == 0) return STM_EINVAL;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    if (!idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    stm_extent_index *m = (stm_extent_index *)idx;

    /* P7-6 / P7-16: scan each extent's replica set. Cross-(ds, ino)
     * scan — the only true full-engine-scan in the read path. Used by
     * the production scrub β cb's lookup-by-paddr; under typical
     * workloads scrub runs at low frequency so the O(N) cost is
     * tolerable. */
    ex_paddr_lookup_ctx lc = { .probe = paddr, .hit = {0}, .found = false,
                                 .err = STM_OK };
    stm_status ss = stm_btree_engine_scan(m->eng, ex_paddr_lookup_cb, &lc);
    must_unlock(lock);
    if (ss != STM_OK) return ss;
    if (lc.err != STM_OK) return lc.err;
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
    if (!idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    stm_extent_index *m = (stm_extent_index *)idx;

    /* Collect every (ds, ino) record, sort by off, invoke cb in order. */
    ex_collect_ctx c;
    stm_status cs = ex_collect_in_ino_locked(m, dataset_id, ino, &c);
    if (cs != STM_OK) {
        must_unlock(lock);
        return cs;
    }
    /* Insertion-sort (small N typical for a file's extents). */
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
    if (!idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    stm_extent_index *m = (stm_extent_index *)idx;

    /* scan_range over the dataset prefix. The keys come back in bytewise
     * (le64-scrambled) order; we collect + sort by (ino, off) before
     * invoking cb. */
    uint8_t lo[EX_KEY_LEN], hi[EX_KEY_LEN];
    ex_encode_key(dataset_id, 0u,         0u,        lo);
    ex_encode_key(dataset_id, UINT64_MAX, UINT64_MAX, hi);

    ex_iter_ds_ctx dc = { .arr = NULL, .n = 0, .cap = 0, .err = STM_OK };

    stm_status ss = stm_btree_engine_scan_range(m->eng, lo, EX_KEY_LEN,
                                                hi, EX_KEY_LEN,
                                                ex_iter_ds_collect_cb, &dc);
    if (ss != STM_OK || dc.err != STM_OK) {
        free(dc.arr);
        must_unlock(lock);
        return ss != STM_OK ? ss : dc.err;
    }

    /* Sort by (ino, off). */
    for (size_t i = 1; i < dc.n; i++) {
        stm_extent_record key = dc.arr[i];
        size_t j = i;
        while (j > 0) {
            bool greater = (dc.arr[j - 1].ino > key.ino) ||
                            (dc.arr[j - 1].ino == key.ino && dc.arr[j - 1].off > key.off);
            if (!greater) break;
            dc.arr[j] = dc.arr[j - 1];
            j--;
        }
        dc.arr[j] = key;
    }
    for (size_t i = 0; i < dc.n; i++) {
        if (!cb(&dc.arr[i], ctx)) break;
    }
    free(dc.arr);
    must_unlock(lock);
    return STM_OK;
}

stm_status stm_extent_count(const stm_extent_index *idx,
                               size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    *out_count = 0;

    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    if (!idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    stm_extent_index *m = (stm_extent_index *)idx;

    ex_count_ctx cc = { .n = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan(m->eng, ex_count_cb, &cc);
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
    if (!idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    stm_extent_index *m = (stm_extent_index *)idx;

    uint8_t lo[EX_KEY_LEN], hi[EX_KEY_LEN];
    ex_encode_key(dataset_id, ino, 0u,         lo);
    ex_encode_key(dataset_id, ino, UINT64_MAX, hi);

    ex_count_ctx cc = { .n = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(m->eng, lo, EX_KEY_LEN,
                                                hi, EX_KEY_LEN,
                                                ex_count_cb, &cc);
    must_unlock(lock);
    if (ss != STM_OK) return ss;
    *out_count = cc.n;
    return STM_OK;
}

/* =========================================================================
 * Persistence (9.6-impl-4d, btree_engine-backed).
 *
 * On-disk key + value layout UNCHANGED from pre-4d. STM_UB_VERSION 28→29
 * commits the cutover: a v28 pool's extent tree is written through
 * btree_store; v29 mounts it through btree_engine. No semantic on-disk
 * change — both stores produce structurally-identical 16 KiB AEAD-
 * encrypted btree nodes — but the v28 tree's root_paddr+csum is a
 * btree_store header, not an engine root, so the version gate is
 * mandatory.
 *
 * P7-16 / v17 value layout (96 bytes):
 *
 *   off  size  field
 * P7-CAS / v18 value layout (96 bytes, kind-discriminated):
 *
 *   off  size  field
 *     0    1   kind             (u8; 0x01 = HOT, 0x02 = COLD; v18)
 *
 *   HOT (kind=0x01) — bytes 1..95:
 *     1    1   n_replicas       (u8; 1..STM_EXTENT_MAX_REPLICAS=4)
 *     2    6   reserved         (zero)
 *     8   32   paddrs[4]        (le64 each; valid 0..n_replicas-1, zero rest)
 *    40    8   write_gen        (le64) — AEAD gen for nonce
 *                                          construction; inherited from
 *                                          src on Reflink.
 *    48    4   dlen             (le32; logical byte length)
 *    52    4   clen_and_comp    (le32; low 24: stored len; high 8: comp)
 *    56    8   key_id           (le64; per-dataset DEK key_id)
 *    64    8   origin_dataset_id (le64; AEAD-AD identity binding —
 *                                  P7-16 reflinks; for non-reflinked
 *                                  extents equals dataset_id at offset 0
 *                                  of the encoded key.)
 *    72    8   origin_ino       (le64; AEAD-AD identity binding)
 *    80    8   origin_off       (le64; AEAD-AD identity binding)
 *    88    8   link_gen         (le64) — R48 P0-1.
 *
 *   COLD (kind=0x02) — bytes 1..95:
 *     1    7   reserved         (zero — 1-byte padding + 6-byte gap pre-hash)
 *     8   32   content_hash     (BLAKE3-256; names a CAS index entry)
 *    40   56   <same as HOT bytes 40..95>
 *
 * P7-CAS-11 / v21 — extent record value layout grows 96 → 108. The new
 * tail tracks per-COLD-extent read-frequency for the promotion
 * heuristic:
 *
 *   off  size  field
 *    96    4   read_count       (le32) — saturating counter of COLD reads
 *                                 since last_read_gen. HOT extents have
 *                                 this == 0 (decoder anti-tamper).
 *   100    8   last_read_gen    (le64) — gen at which read_count was last
 *                                 incremented. HOT extents have this ==
 *                                 0 (decoder anti-tamper).
 *
 * Format breaks: 18, 21. v29 (impl-4d) reformats the engine's root
 * envelope but does NOT change the key/value layout above.
 * ========================================================================= */

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

    /* Zero entire buffer first so unused replica slots + reserved
     * bytes are deterministic-zero. */
    memset(out, 0, EX_VAL_LEN);

    /* P7-CAS / v18: byte 0 = kind discriminator. */
    if (r->kind == STM_EXTENT_KIND_HOT) {
        if (r->n_replicas < 1 || r->n_replicas > STM_EXTENT_MAX_REPLICAS) {
            return STM_ECORRUPT;
        }
        out[0] = (uint8_t)STM_EXTENT_KIND_HOT;
        out[1] = r->n_replicas;
        /* bytes [2..7] reserved (zero, already zeroed above). */
        for (uint8_t i = 0; i < r->n_replicas; i++) {
            if (r->paddrs[i] == 0) return STM_ECORRUPT; /* sentinel guard */
            le64 p = stm_store_le64(r->paddrs[i]);
            memcpy(out + 8 + (size_t)i * 8, p.v, 8);
        }
        /* Trailing replica slots already zero from memset. */
    } else if (r->kind == STM_EXTENT_KIND_COLD) {
        if (r->n_replicas != 0u) return STM_ECORRUPT;  /* COLD has no replicas */
        out[0] = (uint8_t)STM_EXTENT_KIND_COLD;
        /* bytes [1..7] reserved (zero, already zeroed above). */
        bool any_nonzero = false;
        for (size_t i = 0; i < STM_EXTENT_HASH_LEN; i++) {
            if (r->content_hash[i] != 0) { any_nonzero = true; break; }
        }
        if (!any_nonzero) return STM_ECORRUPT;  /* hash-zero is sentinel */
        memcpy(out + 8, r->content_hash, STM_EXTENT_HASH_LEN);
    } else {
        return STM_ECORRUPT;
    }

    /* Bytes 40..95 are kind-independent. */
    le64 write_gen = stm_store_le64(r->gen);
    le32 dlen      = stm_store_le32((uint32_t)r->len);
    uint32_t clen_and_comp = (uint32_t)r->len & 0x00FFFFFFu;
    le32 cac        = stm_store_le32(clen_and_comp);
    le64 key_id_le  = stm_store_le64(r->key_id);

    memcpy(out + 40, write_gen.v, 8);
    memcpy(out + 48, dlen.v,      4);
    memcpy(out + 52, cac.v,       4);
    memcpy(out + 56, key_id_le.v, 8);

    /* P7-16: origin (dataset_id, ino, offset) at v17 offsets 64..87. */
    le64 origin_ds  = stm_store_le64(r->origin_dataset_id);
    le64 origin_ino_le = stm_store_le64(r->origin_ino);
    le64 origin_off = stm_store_le64(r->origin_off);
    memcpy(out + 64, origin_ds.v,  8);
    memcpy(out + 72, origin_ino_le.v, 8);
    memcpy(out + 80, origin_off.v, 8);
    /* R48 P0-1: link_gen at v17 offset 88..95. */
    le64 link_gen_le = stm_store_le64(r->link_gen);
    memcpy(out + 88, link_gen_le.v, 8);

    /* P7-CAS-11 / v21: read_count + last_read_gen at offsets 96..108.
     * HOT extents must have both == 0; COLD extents carry the counter.
     * This is enforced at encode time so any in-RAM stm_extent_record
     * with kind=HOT and non-zero counters fails-fast rather than
     * silently persisting bogus state. */
    if (r->kind == STM_EXTENT_KIND_HOT) {
        if (r->read_count != 0u || r->last_read_gen != 0u) return STM_ECORRUPT;
    }
    le32 rc_le  = stm_store_le32(r->read_count);
    le64 lrg_le = stm_store_le64(r->last_read_gen);
    memcpy(out + 96,  rc_le.v,  4);
    memcpy(out + 100, lrg_le.v, 8);
    return STM_OK;
}

static stm_status ex_decode_value(const uint8_t *in, size_t in_len,
                                     uint64_t ds, uint64_t ino, uint64_t off,
                                     stm_extent_record *out_rec) {
    if (in_len != EX_VAL_LEN) return STM_ECORRUPT;

    /* P7-CAS / v18: byte 0 = kind discriminator. */
    uint8_t kind_byte = in[0];
    uint8_t n_replicas = 0;
    uint64_t paddrs[STM_EXTENT_MAX_REPLICAS] = {0};
    uint8_t  content_hash[STM_EXTENT_HASH_LEN] = {0};

    if (kind_byte == (uint8_t)STM_EXTENT_KIND_HOT) {
        n_replicas = in[1];
        if (n_replicas < 1 || n_replicas > STM_EXTENT_MAX_REPLICAS)
            return STM_ECORRUPT;
        /* bytes [2..7] reserved — must be zero (anti-tamper). */
        for (size_t i = 2; i < 8; i++) if (in[i] != 0) return STM_ECORRUPT;

        /* Decode all 4 replica slots; verify trailing slots are zero. */
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
        /* Within-set distinctness. */
        for (uint8_t i = 0; i < n_replicas; i++) {
            for (uint8_t j = (uint8_t)(i + 1); j < n_replicas; j++) {
                if (paddrs[i] == paddrs[j]) return STM_ECORRUPT;
            }
        }
    } else if (kind_byte == (uint8_t)STM_EXTENT_KIND_COLD) {
        /* bytes [1..7] reserved — must be zero (anti-tamper). */
        for (size_t i = 1; i < 8; i++) if (in[i] != 0) return STM_ECORRUPT;
        memcpy(content_hash, in + 8, STM_EXTENT_HASH_LEN);
        /* Hash-all-zero is the sentinel — refuse on decode. */
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
    memcpy(write_gen_le.v, in + 40, 8);
    memcpy(dlen_le.v,      in + 48, 4);
    memcpy(cac_le.v,       in + 52, 4);
    memcpy(key_id_le.v,    in + 56, 8);

    /* P7-16 / v17: origin (dataset_id, ino, offset) at offsets 64..87. */
    le64 origin_ds_le, origin_ino_le, origin_off_le;
    memcpy(origin_ds_le.v,  in + 64, 8);
    memcpy(origin_ino_le.v, in + 72, 8);
    memcpy(origin_off_le.v, in + 80, 8);
    /* R48 P0-1: link_gen at offsets 88..95 (le64). */
    le64 link_gen_le;
    memcpy(link_gen_le.v, in + 88, 8);

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

    /* P7-16: origin must satisfy basic typing. dataset_id and ino must
     * be > 0 (sentinels reserved). R48 P2-2 also pins
     * extent.tla::OriginConsistentInBounds: origin_off + dlen must
     * not overflow (extents past origin's file size cap don't have
     * legitimate ciphertext). */
    uint64_t origin_ds  = stm_load_le64(origin_ds_le);
    uint64_t origin_ino_v = stm_load_le64(origin_ino_le);
    uint64_t origin_off = stm_load_le64(origin_off_le);
    if (origin_ds == 0 || origin_ino_v == 0) return STM_ECORRUPT;
    if (origin_off > UINT64_MAX - (uint64_t)dlen) return STM_ECORRUPT;
    uint64_t link_gen_v = stm_load_le64(link_gen_le);

    /* P7-CAS-11 / v21: read_count + last_read_gen at offsets 96..108.
     * HOT extents must have both == 0 (anti-tamper); COLD extents carry
     * the windowed-count fields. */
    le32 rc_le; le64 lrg_le;
    memcpy(rc_le.v,  in + 96,  4);
    memcpy(lrg_le.v, in + 100, 8);
    uint32_t read_count_v   = stm_load_le32(rc_le);
    uint64_t last_read_gen_v = stm_load_le64(lrg_le);
    if (kind_byte == (uint8_t)STM_EXTENT_KIND_HOT) {
        if (read_count_v != 0u || last_read_gen_v != 0u) return STM_ECORRUPT;
    }

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
    out_rec->origin_dataset_id = origin_ds;
    out_rec->origin_ino        = origin_ino_v;
    out_rec->origin_off        = origin_off;
    out_rec->link_gen          = link_gen_v;
    out_rec->read_count        = read_count_v;
    out_rec->last_read_gen     = last_read_gen_v;

    return STM_OK;
}

/* ---- Public persistence API. ---- */

stm_status stm_extent_index_set_storage(stm_extent_index *idx,
                                           stm_bdev *bdev_0,
                                           stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(&idx->lock);
    /* R70 P3-6: refuse re-binding once latched. */
    if (idx->storage_set) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->store_ctx.bdev = bdev_0;
    idx->store_ctx.boot = boot_0;
    /* Second-bind: stand the engine up. */
    if (idx->crypt_set && !idx->eng) {
        stm_status es = ex_engine_create_locked(idx);
        if (es != STM_OK) {
            must_unlock(&idx->lock);
            return es;
        }
    }
    idx->storage_set = true;
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_index_set_crypt_ctx(stm_extent_index *idx,
                                             const uint8_t *metadata_key,
                                             const uint64_t pool_uuid[2],
                                             const uint64_t device_uuid_0[2]) {
    if (!idx || !metadata_key || !pool_uuid || !device_uuid_0) return STM_EINVAL;
    must_lock(&idx->lock);
    /* R70 P3-6: refuse re-binding once latched. */
    if (idx->crypt_set) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }
    idx->crypt_ctx.metadata_key   = metadata_key;
    idx->crypt_ctx.pool_uuid[0]   = pool_uuid[0];
    idx->crypt_ctx.pool_uuid[1]   = pool_uuid[1];
    idx->crypt_ctx.device_uuid[0] = device_uuid_0[0];
    idx->crypt_ctx.device_uuid[1] = device_uuid_0[1];
    if (idx->storage_set && !idx->eng) {
        stm_status es = ex_engine_create_locked(idx);
        if (es != STM_OK) {
            must_unlock(&idx->lock);
            return es;
        }
    }
    idx->crypt_set = true;
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

stm_status stm_extent_index_commit(stm_extent_index *idx,
                                      uint64_t committed_gen,
                                      uint64_t *out_root_paddr,
                                      uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    must_lock(&idx->lock);

    if (!idx->storage_set || !idx->crypt_set || !idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* Single-shot incremental-COW commit. Engine subsumes the pre-4d
     * !dirty short-circuit (clean tree → cheap no-op). */
    uint64_t cp = 0;
    uint8_t  cc[32];
    stm_status cs = stm_btree_engine_commit(idx->eng, committed_gen, &cp, cc);
    if (cs != STM_OK) {
        /* A failed commit self-reverts — the engine drops the in-memory
         * tree, leaves no pending window, and the durable root still
         * names the previous tree. 9.6-impl-4b design §5.5: a failed
         * stm_sync_commit is crash-equivalent; the caller wedges. */
        must_unlock(&idx->lock);
        return cs;
    }

    /* Read back the authoritative durable triple. */
    uint64_t rp = 0, rg = 0;
    uint8_t  rc[32];
    stm_status gs = stm_btree_engine_get_root(idx->eng, &rp, &rg, rc);
    if (gs != STM_OK) {
        must_unlock(&idx->lock);
        return gs;
    }

    /* Make the bootstrap bitmap durable — the engine's vt->reserve set
     * node bits in RAM; this fsyncs them. The monolithic _commit keeps
     * this call inside the index commit for use by non-sync callers
     * (unit tests). stm_sync_commit relocates this barrier (4b-iii) so
     * its three-phase trio doesn't double-commit. */
    stm_status bs = stm_bootstrap_commit(idx->store_ctx.boot, committed_gen);
    if (bs != STM_OK) {
        must_unlock(&idx->lock);
        return bs;
    }

    idx->root_paddr = rp;
    idx->root_gen   = rg;
    memcpy(idx->root_csum, rc, 32);

    *out_root_paddr = rp;
    memcpy(out_root_csum, rc, 32);
    must_unlock(&idx->lock);
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Three-phase commit — flush / finalize / abort (9.6-impl-4d).         */
/*                                                                      */
/* The form stm_sync_commit drives. Each is a thin wrapper over the     */
/* btree_engine's commit_flush / _finalize / _abort, under idx->lock.   */
/* NONE of them calls stm_bootstrap_commit — the sync layer runs that   */
/* single explicit durable-bitmap barrier after every index flush,      */
/* strictly before the uberblock write (4b-iii doctrine carry).         */
/* ------------------------------------------------------------------ */

stm_status stm_extent_index_commit_flush(stm_extent_index *idx,
                                           uint64_t committed_gen,
                                           uint64_t *out_root_paddr,
                                           uint64_t *out_root_gen,
                                           uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr || !out_root_gen || !out_root_csum)
        return STM_EINVAL;
    must_lock(&idx->lock);

    if (!idx->storage_set || !idx->crypt_set || !idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    uint64_t cp = 0, cg = 0;
    uint8_t  cc[32];
    stm_status cs = stm_btree_engine_commit_flush(idx->eng, committed_gen,
                                                  &cp, &cg, cc);
    if (cs != STM_OK) {
        /* A failed flush self-reverts: NO pending window opened, the
         * in-memory tree dropped, the durable root still names the
         * previous tree. The caller MUST NOT _commit_abort. 4b design
         * §5.5: a failed stm_sync_commit is crash-equivalent — the
         * caller wedges the fs. */
        must_unlock(&idx->lock);
        return cs;
    }

    *out_root_paddr = cp;
    *out_root_gen   = cg;
    memcpy(out_root_csum, cc, 32);
    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_index_commit_finalize(stm_extent_index *idx) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* Adopt the flushed root + deferred-free the superseded paddrs.
     * After a successful commit_flush this is infallible (btree_engine.h
     * contract); the STM_EINVAL exit is a no-pending-flush sequencing
     * bug. */
    stm_status fs = stm_btree_engine_commit_finalize(idx->eng);
    if (fs != STM_OK) {
        must_unlock(&idx->lock);
        return fs;
    }

    /* Mirror the now-durable triple into idx->root_*. */
    uint64_t rp = 0, rg = 0;
    uint8_t  rc[32];
    stm_status gs = stm_btree_engine_get_root(idx->eng, &rp, &rg, rc);
    if (gs != STM_OK) {
        must_unlock(&idx->lock);
        return gs;
    }
    idx->root_paddr = rp;
    idx->root_gen   = rg;
    memcpy(idx->root_csum, rc, 32);

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_index_commit_abort(stm_extent_index *idx) {
    if (!idx) return STM_EINVAL;
    must_lock(&idx->lock);
    if (!idx->eng) {
        must_unlock(&idx->lock);
        return STM_EINVAL;
    }

    /* Discard the flushed root: deferred-free the freshly-written
     * paddrs + drop the in-memory tree. idx->root_* is deliberately
     * NOT touched — the durable root still names the previous tree. */
    stm_status as = stm_btree_engine_commit_abort(idx->eng);
    must_unlock(&idx->lock);
    return as;
}

/* ------------------------------------------------------------------ */
/* load_at — open the on-disk engine + reconstruct current_txg.         */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t  *paddrs;       /* dynamic — collected for SharedReplicasAreCohabit
                              * cross-record validation; one element per
                              * (extent, replica-slot) pair. */
    size_t     n_paddrs;
    size_t     cap_paddrs;
    /* Per-extent snapshot for cross-record overlap + cohabit checks. */
    stm_extent_record *records;
    size_t             n_records;
    size_t             cap_records;
    uint64_t  max_write_gen;
    stm_status err;
} ex_mount_ctx;

static stm_status ex_mount_grow_paddrs(ex_mount_ctx *m, size_t added) {
    if (m->n_paddrs + added > m->cap_paddrs) {
        size_t new_cap = m->cap_paddrs == 0 ? 32u : m->cap_paddrs;
        while (new_cap < m->n_paddrs + added) {
            if (new_cap > (SIZE_MAX / sizeof *m->paddrs) / 2u) return STM_ENOMEM;
            new_cap *= 2u;
        }
        uint64_t *np = realloc(m->paddrs, new_cap * sizeof *m->paddrs);
        if (!np) return STM_ENOMEM;
        m->paddrs = np;
        m->cap_paddrs = new_cap;
    }
    return STM_OK;
}

static stm_status ex_mount_grow_records(ex_mount_ctx *m) {
    if (m->n_records == m->cap_records) {
        size_t new_cap = m->cap_records == 0 ? 16u : m->cap_records * 2u;
        if (new_cap > (SIZE_MAX / sizeof *m->records)) return STM_ENOMEM;
        stm_extent_record *nr = realloc(m->records,
                                            new_cap * sizeof *m->records);
        if (!nr) return STM_ENOMEM;
        m->records = nr;
        m->cap_records = new_cap;
    }
    return STM_OK;
}

static int ex_mount_cb(const void *k, size_t klen,
                       const void *v, size_t vlen, void *ctx_) {
    ex_mount_ctx *m = ctx_;
    uint64_t ds = 0, ino = 0, off = 0;
    stm_status ks = ex_decode_key(k, klen, &ds, &ino, &off);
    if (ks != STM_OK) { m->err = ks; return 1; }
    if (ds == 0 || ino == 0) { m->err = STM_ECORRUPT; return 1; }

    stm_extent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = ex_decode_value(v, vlen, ds, ino, off, &r);
    if (vs != STM_OK) { m->err = vs; return 1; }

    if (r.gen > m->max_write_gen) m->max_write_gen = r.gen;

    /* off + len overflow guard (AllExtentsInBounds). */
    if (r.off > UINT64_MAX - r.len) { m->err = STM_ECORRUPT; return 1; }

    stm_status gs = ex_mount_grow_records(m);
    if (gs != STM_OK) { m->err = gs; return 1; }
    m->records[m->n_records++] = r;

    if (r.n_replicas > 0) {
        stm_status gp = ex_mount_grow_paddrs(m, r.n_replicas);
        if (gp != STM_OK) { m->err = gp; return 1; }
        for (uint8_t i = 0; i < r.n_replicas; i++) {
            m->paddrs[m->n_paddrs++] = r.paddrs[i];
        }
    }
    return 0;
}

/* Structural validator on the loaded extent tree. Mount-time check —
 * runs once at load_at, after the engine has been opened + every
 * record has been collected via engine_scan. The cross-record overlap
 * + SharedReplicasAreCohabit checks are O(N²·K²) where N is the total
 * extent count + K = STM_EXTENT_MAX_REPLICAS — fine for any plausible
 * mount; production-grade persistence (chunked / per-inode trees)
 * revisits with a sorted-merge strategy. */
static stm_status ex_mount_validate(const ex_mount_ctx *m) {
    /* NoOverlapWithinIno + LengthPositive (already enforced at decode). */
    for (size_t i = 0; i < m->n_records; i++) {
        const stm_extent_record *a = &m->records[i];
        for (size_t j = i + 1; j < m->n_records; j++) {
            const stm_extent_record *b = &m->records[j];
            if (a->dataset_id == b->dataset_id && a->ino == b->ino) {
                if (ranges_overlap(a->off, a->len, b->off, b->len)) {
                    return STM_ECORRUPT;
                }
            }
            /* Replica-set classification: detect any paddr share. */
            bool any_share = false;
            for (uint8_t ai = 0; ai < a->n_replicas && !any_share; ai++) {
                for (uint8_t bi = 0; bi < b->n_replicas; bi++) {
                    if (a->paddrs[ai] == b->paddrs[bi]) { any_share = true; break; }
                }
            }
            if (!any_share) continue;
            /* Whole-set match required when sharing. */
            if (a->n_replicas != b->n_replicas) return STM_ECORRUPT;
            for (uint8_t ai = 0; ai < a->n_replicas; ai++) {
                bool found = false;
                for (uint8_t bi = 0; bi < b->n_replicas; bi++) {
                    if (a->paddrs[ai] == b->paddrs[bi]) { found = true; break; }
                }
                if (!found) return STM_ECORRUPT;
            }
            /* Matching (gen, key_id, origin_*) required when sharing. */
            if (a->gen        != b->gen)        return STM_ECORRUPT;
            if (a->key_id     != b->key_id)     return STM_ECORRUPT;
            if (a->origin_dataset_id != b->origin_dataset_id) return STM_ECORRUPT;
            if (a->origin_ino        != b->origin_ino)        return STM_ECORRUPT;
            if (a->origin_off        != b->origin_off)        return STM_ECORRUPT;
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
    if (!idx->storage_set || !idx->crypt_set) {
        must_unlock(&idx->lock);
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
        must_unlock(&idx->lock);
        return os;
    }

    /* Walk every record into a mount scratch ctx: validate it +
     * raise current_txg = max(write_gen) + collect for cross-record
     * cohabit validation. The walk reads + AEAD/Merkle-verifies every
     * node; ex_decode_value adds the per-record semantic layer. */
    ex_mount_ctx mc = { .paddrs = NULL, .n_paddrs = 0, .cap_paddrs = 0,
                          .records = NULL, .n_records = 0, .cap_records = 0,
                          .max_write_gen = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan(opened, ex_mount_cb, &mc);
    if (ss != STM_OK || mc.err != STM_OK) {
        free(mc.paddrs);
        free(mc.records);
        stm_btree_engine_destroy(opened);
        must_unlock(&idx->lock);
        return ss != STM_OK ? ss : mc.err;
    }
    /* Cross-record cohabit + overlap validation. */
    stm_status vs = ex_mount_validate(&mc);
    if (vs != STM_OK) {
        free(mc.paddrs);
        free(mc.records);
        stm_btree_engine_destroy(opened);
        must_unlock(&idx->lock);
        return vs;
    }
    free(mc.paddrs);
    free(mc.records);

    /* Atomic install. */
    stm_btree_engine_destroy(idx->eng);
    idx->eng = opened;

    /* Bump current_txg ≥ max(write_gen) per extent.tla::BirthTxgBound. */
    if (mc.max_write_gen > idx->current_txg) {
        idx->current_txg = mc.max_write_gen;
    }

    idx->root_paddr = root_paddr;
    idx->root_gen   = root_gen;
    memcpy(idx->root_csum, expected_csum, 32);

    must_unlock(&idx->lock);
    return STM_OK;
}

stm_status stm_extent_index_verify(const stm_extent_index *idx) {
    if (!idx) return STM_EINVAL;
    pthread_mutex_t *lock = ex_lock(idx);
    must_lock(lock);
    if (!idx->storage_set || !idx->crypt_set || !idx->eng) {
        must_unlock(lock);
        return STM_EINVAL;
    }
    if (idx->root_paddr == 0) {
        must_unlock(lock);
        return STM_OK;
    }
    /* Engine-backed: a re-scan via engine_scan re-decrypts every node
     * (AEAD verifies tags + Merkle ladders ensure linkage). Each
     * decoded record is structurally checked via ex_decode_value. */
    ex_mount_ctx mc = { .paddrs = NULL, .n_paddrs = 0, .cap_paddrs = 0,
                          .records = NULL, .n_records = 0, .cap_records = 0,
                          .max_write_gen = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan(((stm_extent_index *)idx)->eng,
                                          ex_mount_cb, &mc);
    if (ss != STM_OK || mc.err != STM_OK) {
        free(mc.paddrs);
        free(mc.records);
        must_unlock(lock);
        return ss != STM_OK ? ss : mc.err;
    }
    stm_status vs = ex_mount_validate(&mc);
    free(mc.paddrs);
    free(mc.records);
    must_unlock(lock);
    return vs;
}
