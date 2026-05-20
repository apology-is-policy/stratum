/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — dirent index implementation
 * (P8-POSIX-2 + 9.6-impl-4c + 9.7-impl-1c-iii).
 *
 * Spec: v2/specs/dirent.tla. Models open-addressing chain integrity
 * for directory entries keyed by `(dataset_id, dir_ino, hash_probe)`
 * where `hash_probe = fnv1a64(name) + probe_offset`. Per ARCH §11.4.
 *
 * 9.6-impl-4c — the dirent module was cut to btree_engine; the
 * in-RAM records[] array was retired in favour of an incremental-COW
 * B+tree as the canonical store.
 *
 * 9.7-impl-1c-iii — the dirent cutover. The module no longer owns
 * its own btree_engine. Each dataset's dirent records live in that
 * dataset's per-dataset engine (the substrate from 9.7-impl-1c-i),
 * resolved via an attached borrowed `stm_dataset_index *`. Every
 * public op resolves the dataset's engine on entry, atomically with
 * the dirent index's own lock, and routes its lookup / scan / insert
 * / delete through that engine.
 *
 * Keys (17 bytes): `stm_metakey_compose(STM_METAKEY_KIND_DIRENT,
 *                  body, 16)` where body = `le64 dir_ino || le64
 *                  hash_probe`.
 *
 * The previous 24-byte `(le64 dataset_id || le64 dir_ino || le64
 * hash_probe)` form is retired — the dataset id is now woven into
 * the engine's AEAD additional-data via `tree_id = dataset_id`, so
 * a cross-dataset substitution attack fails decrypt rather than
 * relying on the key prefix.
 *
 * Values (32 + name_len bytes, tombstones 32 bytes): unchanged
 * from 4c — see dirent.h for the full byte-level layout.
 *
 * Engine ops:
 *   alloc          -> chain-walk via engine_lookup per probe,
 *                     engine_insert at the chosen probe (upsert
 *                     overwrites a tombstone or same-name whiteout)
 *   lookup         -> chain-walk via engine_lookup per probe
 *   unlink         -> chain-walk + engine_insert (tombstone-flavored)
 *   whiteout       -> chain-walk + engine_insert (whiteout-flavored)
 *   swap_two       -> two chain-walks + two engine_inserts (atomic
 *                     under idx->lock — single critical section)
 *   count_for_dir  -> engine_scan_range over the (dir, *) prefix,
 *                     count live records (not tombstones/whiteouts)
 *   readdir        -> engine_scan_range over the (dir, *) range,
 *                     collect into a buffer, sort by hash_probe,
 *                     emit prefix
 *   drop_for_dir   -> engine_scan_range to collect keys, then
 *                     engine_delete each
 *
 * dirent.tla's chain-integrity invariants are UNCHANGED; only the
 * storage under it swapped from the pool-global engine to a per-
 * dataset engine. Tombstones + whiteouts remain reachable as
 * engine_inserted records (no engine_delete is issued for an Unlink
 * — the slot must persist so a colliding name at a higher probe
 * stays reachable per dirent.tla::BuggyUnlinkUsesEmpty).
 * engine_delete is only used by drop_for_dir's bulk cleanup.
 *
 * Concurrency: a single mutex (idx->lock) guards dsstate AND every
 * engine call — the btree_engine is single-threaded (one handle,
 * one thread at a time), and idx->lock IS that serialization. The
 * engine handle is BORROWED from the dataset index per call;
 * lifetime is safe because the fs.c layer holds fs->global SH/EX
 * across every dirent op, and `stm_dataset_destroy` takes
 * fs->global EX (so a slot's engine cannot be closed mid-op).
 *
 * Audit-trigger surface: this module is on CLAUDE.md's trigger list.
 */
#include <stratum/dirent.h>
#include <stratum/dirent_testing.h>
#include <stratum/dataset.h>
#include <stratum/btree_engine.h>
#include <stratum/metakey.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Lock helpers — abort on misuse (snapshot.c / inode.c convention).   */
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
/* On-disk layout constants.                                            */
/* ------------------------------------------------------------------ */

/* Key: 1-byte STM_METAKEY_KIND_DIRENT tag + 8-byte le64 dir_ino +
 * 8-byte le64 hash_probe = 17 bytes total. */
#define DI_KEY_BODY_LEN         16u
#define DI_KEY_LEN              (1u + DI_KEY_BODY_LEN)        /* 17 */

#define DI_VAL_FIXED            32u
#define DI_VAL_MAX              (DI_VAL_FIXED + STM_DIRENT_NAME_MAX)

/* Reserved-bytes window inside the value (offset 19..32). */
#define DI_VAL_RESERVED_OFF     19u
#define DI_VAL_RESERVED_LEN     13u

/* ------------------------------------------------------------------ */
/* Internal record + index types.                                      */
/* ------------------------------------------------------------------ */

/* In-memory decoded record. The engine stores key + value as opaque
 * bytes; this is the structured shape every chain helper + public op
 * operates on. Decoded from engine_lookup and re-encoded for
 * engine_insert. Per-call stack allocation — no heap, no persistence;
 * the dataset_id / dir_ino / hash_probe fields are STAMPED from the
 * key triple (NOT from the value bytes) so a buggy writer can't
 * tamper cross-key references.
 *
 * The dataset_id is conceptual (it comes from the engine handle's
 * tree_id, not the on-disk key body) but we record it on the
 * decoded record so swap_two + readdir emit it through the public
 * stm_dirent_entry shape. */
typedef struct {
    uint64_t dataset_id;
    uint64_t dir_ino;
    uint64_t hash_probe;
    uint64_t child_ino;
    uint64_t child_gen;
    uint8_t  child_type;
    uint8_t  name_len;
    uint8_t  flags;          /* STM_DIRENT_FLAG_TOMBSTONE / _WHITEOUT */
    uint8_t  name[STM_DIRENT_NAME_MAX];
} stm_dirent_record;

struct stm_dirent_index {
    pthread_mutex_t      lock;

    /* 9.7-impl-1c-iii: borrowed dataset index. Set once by
     * stm_dirent_index_attach_dataset_index; alive for the dirent
     * index's lifetime. NULL pre-attach — every op refuses with
     * STM_EINVAL. */
    stm_dataset_index   *ds_idx;
};

static inline pthread_mutex_t *idx_lock(const stm_dirent_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

static inline bool record_is_tombstone(const stm_dirent_record *r) {
    return (r->flags & STM_DIRENT_FLAG_TOMBSTONE) != 0u;
}

/* P8-POSIX-9b: a slot is a whiteout iff the WHITEOUT flag bit is
 * set. Whiteouts and tombstones are mutually exclusive (the
 * decoder rejects flags with both bits set; the writer never
 * encodes both simultaneously). */
static inline bool record_is_whiteout(const stm_dirent_record *r) {
    return (r->flags & STM_DIRENT_FLAG_WHITEOUT) != 0u;
}

/* A slot is "live" iff it's neither a tombstone nor a whiteout —
 * i.e., it actually carries an addressable child_ino. */
static inline bool record_is_live(const stm_dirent_record *r) {
    return !record_is_tombstone(r) && !record_is_whiteout(r);
}

static inline bool record_name_eq(const stm_dirent_record *r,
                                       const uint8_t *name, uint8_t name_len) {
    return r->name_len == name_len &&
           memcmp(r->name, name, name_len) == 0;
}

/* ------------------------------------------------------------------ */
/* FNV-1a 64-bit hash (ARCH §11.4 — used to compute hash_probe).       */
/* ------------------------------------------------------------------ */

static uint64_t fnv1a64(const uint8_t *data, size_t len) {
    uint64_t h = 0xCBF29CE484222325ull;        /* offset basis */
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= 0x100000001B3ull;                  /* FNV prime */
    }
    return h;
}

/* ------------------------------------------------------------------ */
/* On-disk key/value encoding.                                         */
/*                                                                      */
/* Key: 17 bytes — STM_METAKEY_KIND_DIRENT tag || le64 dir_ino ||      */
/*                  le64 hash_probe.                                    */
/* Value: 32 + name_len bytes (tombstone 32, whiteout 32+name_len,     */
/*        live record 32+name_len). See dirent.h.                       */
/*                                                                      */
/* The dataset id is woven into the engine's AEAD additional-data via   */
/* tree_id = dataset_id at engine create / open time (the substrate     */
/* from 9.7-impl-1c-i). Cross-dataset substitution defense lives in the */
/* engine layer, not the key prefix.                                    */
/*                                                                      */
/* R71 P1-1 doctrine: stm_metakey_compose tags + stm_metakey_parse      */
/* decoder-side tag check are symmetric. The body length (16 bytes)     */
/* is re-validated on every decode in di_decode_key.                    */
/* ------------------------------------------------------------------ */

static stm_status di_encode_key(uint64_t dir_ino, uint64_t hash_probe,
                                uint8_t out[DI_KEY_LEN]) {
    uint8_t body[DI_KEY_BODY_LEN];
    le64 di = stm_store_le64(dir_ino);
    le64 hp = stm_store_le64(hash_probe);
    memcpy(body + 0, di.v, 8);
    memcpy(body + 8, hp.v, 8);
    size_t out_len = 0;
    return stm_metakey_compose(STM_METAKEY_KIND_DIRENT,
                                body, DI_KEY_BODY_LEN,
                                out, DI_KEY_LEN, &out_len);
}

static stm_status di_decode_key(const void *in, size_t in_len,
                                    uint64_t *out_dir, uint64_t *out_probe) {
    stm_metakey_kind kind;
    const uint8_t *body = NULL;
    size_t body_len = 0;
    stm_status rc = stm_metakey_parse(in, in_len, &kind, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (kind != STM_METAKEY_KIND_DIRENT) return STM_ECORRUPT;
    if (body_len != DI_KEY_BODY_LEN) return STM_ECORRUPT;
    le64 di_le, hp_le;
    memcpy(di_le.v, body + 0, 8);
    memcpy(hp_le.v, body + 8, 8);
    *out_dir   = stm_load_le64(di_le);
    *out_probe = stm_load_le64(hp_le);
    return STM_OK;
}

static void di_encode_value(const stm_dirent_record *r,
                                uint8_t out[DI_VAL_MAX], size_t *out_len) {
    le64 ci = stm_store_le64(r->child_ino);
    le64 cg = stm_store_le64(r->child_gen);
    memcpy(out + 0,  ci.v, 8);
    memcpy(out + 8,  cg.v, 8);
    out[16] = r->child_type;
    out[17] = r->name_len;
    out[18] = r->flags;
    memset(out + DI_VAL_RESERVED_OFF, 0, DI_VAL_RESERVED_LEN);
    if (r->name_len > 0u) memcpy(out + DI_VAL_FIXED, r->name, r->name_len);
    *out_len = (size_t)DI_VAL_FIXED + (size_t)r->name_len;
}

/* Decode + validate. Pins the on-disk invariants per dirent.h's
 * value-layout contract:
 *
 *   - value length matches the encoded name_len;
 *   - reserved bytes are zero;
 *   - tombstone iff (flags & TOMBSTONE) iff (name_len == 0);
 *   - live records: child_ino != 0, name_len in [1, 255], child_type
 *     in the valid POSIX-shape DT_* set.
 *
 * These must be SYMMETRIC with the writer-side guards in
 * stm_dirent_alloc (R71 P1-1 lesson). */
static stm_status di_decode_value(const void *in, size_t in_len,
                                       stm_dirent_record *out) {
    if (in_len < DI_VAL_FIXED || in_len > DI_VAL_MAX) return STM_ECORRUPT;
    const uint8_t *b = in;

    le64 ci_le, cg_le;
    memcpy(ci_le.v, b + 0, 8);
    memcpy(cg_le.v, b + 8, 8);
    out->child_ino  = stm_load_le64(ci_le);
    out->child_gen  = stm_load_le64(cg_le);
    out->child_type = b[16];
    out->name_len   = b[17];
    out->flags      = b[18];

    /* Reserved bytes 19..32 must be zero. */
    for (size_t i = 0; i < DI_VAL_RESERVED_LEN; i++) {
        if (b[DI_VAL_RESERVED_OFF + i] != 0u) return STM_ECORRUPT;
    }

    /* Length matches name_len. */
    if (in_len != (size_t)DI_VAL_FIXED + (size_t)out->name_len)
        return STM_ECORRUPT;

    bool is_tomb  = record_is_tombstone(out);
    bool is_white = record_is_whiteout(out);

    /* Mutually exclusive: a slot is exactly one of {tombstone,
     * whiteout, live record}. The decoder refuses any record with
     * both bits set as STM_ECORRUPT (writer-side guards in
     * stm_dirent_unlink + stm_dirent_whiteout never encode both
     * simultaneously — R71 P1-1 lesson). */
    if (is_tomb && is_white) return STM_ECORRUPT;

    if (is_tomb) {
        if (out->child_ino  != 0u)   return STM_ECORRUPT;
        if (out->child_gen  != 0u)   return STM_ECORRUPT;
        if (out->child_type != 0u)   return STM_ECORRUPT;
        if (out->name_len   != 0u)   return STM_ECORRUPT;
        /* Other flag bits beyond TOMBSTONE are reserved zero. */
        if ((out->flags & ~(uint8_t)STM_DIRENT_FLAG_TOMBSTONE) != 0u)
            return STM_ECORRUPT;
    } else if (is_white) {
        /* Whiteout shape: child_ino == 0, child_gen == 0,
         * child_type == STM_DT_WHITEOUT, name preserved. Other flag
         * bits beyond WHITEOUT are reserved zero. */
        if (out->child_ino  != 0u)               return STM_ECORRUPT;
        if (out->child_gen  != 0u)               return STM_ECORRUPT;
        if (out->child_type != STM_DT_WHITEOUT)  return STM_ECORRUPT;
        if (out->name_len == 0u ||
            out->name_len > STM_DIRENT_NAME_MAX) return STM_ECORRUPT;
        if ((out->flags & ~(uint8_t)STM_DIRENT_FLAG_WHITEOUT) != 0u)
            return STM_ECORRUPT;
        memcpy(out->name, b + DI_VAL_FIXED, out->name_len);
    } else {
        /* Live record: child_ino non-zero, name_len in [1, 255],
         * child_type in the valid POSIX-shape DT_* set EXCLUDING
         * STM_DT_WHITEOUT (whiteouts are flag-bit-encoded, not
         * type-encoded — a record claiming type=WHITEOUT but no
         * WHITEOUT flag bit is malformed). */
        if (out->child_ino == 0u)    return STM_ECORRUPT;
        if (out->name_len == 0u || out->name_len > STM_DIRENT_NAME_MAX)
            return STM_ECORRUPT;
        switch (out->child_type) {
            case STM_DT_FIFO:
            case STM_DT_CHR:
            case STM_DT_DIR:
            case STM_DT_BLK:
            case STM_DT_REG:
            case STM_DT_LNK:
            case STM_DT_SOCK:
                break;
            default:
                return STM_ECORRUPT;
        }
        if (out->flags != 0u) return STM_ECORRUPT;
        memcpy(out->name, b + DI_VAL_FIXED, out->name_len);
    }
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Engine glue.                                                         */
/* ------------------------------------------------------------------ */

/*
 * Resolve the dataset's per-dataset engine handle. Caller holds idx->lock.
 *
 * Returns STM_OK with *out_eng set on success. Common failures:
 *   - STM_EINVAL: ds_idx unbound (attach not called).
 *   - STM_ENOENT: dataset not PRESENT (destroyed or never created).
 *   - Engine create / open errors propagated verbatim.
 */
static stm_status di_get_engine_locked(stm_dirent_index *idx,
                                       uint64_t dataset_id,
                                       stm_btree_engine **out_eng) {
    *out_eng = NULL;
    if (idx->ds_idx == NULL) return STM_EINVAL;
    return stm_dataset_index_get_engine(idx->ds_idx, dataset_id, out_eng);
}

/* engine_lookup + decode + validate at exact (ds, dir, probe). Caller
 * holds idx->lock. On STM_OK: *out_found is set; if true, *out holds
 * the validated decoded record (live, tombstone, or whiteout). The
 * dataset_id / dir_ino / hash_probe fields are STAMPED from the
 * (ds, dir, probe) triple, NOT trusted from the value bytes — the
 * value carries only (child_ino, child_gen, child_type, name_len,
 * flags, name). */
static stm_status di_engine_get(stm_dirent_index *idx,
                                uint64_t ds, uint64_t dir, uint64_t probe,
                                stm_dirent_record *out, bool *out_found) {
    *out_found = false;
    stm_btree_engine *eng = NULL;
    stm_status es = di_get_engine_locked(idx, ds, &eng);
    if (es != STM_OK) return es;

    uint8_t key[DI_KEY_LEN];
    stm_status ks = di_encode_key(dir, probe, key);
    if (ks != STM_OK) return ks;

    bool found = false;
    void *vbuf = NULL;
    size_t vlen = 0;
    stm_status ls = stm_btree_engine_lookup(eng, key, DI_KEY_LEN,
                                            &found, &vbuf, &vlen);
    if (ls != STM_OK) return ls;
    if (!found) return STM_OK;                  /* *out_found stays false */

    memset(out, 0, sizeof *out);
    stm_status vs = di_decode_value(vbuf, vlen, out);
    free(vbuf);
    if (vs != STM_OK) return vs;
    out->dataset_id = ds;
    out->dir_ino    = dir;
    out->hash_probe = probe;
    *out_found      = true;
    return STM_OK;
}

/* Encode + engine_insert (upsert). Caller holds idx->lock. The
 * engine's insert is failure-atomic — a failed put never loses the
 * prior value at this key. */
static stm_status di_engine_put(stm_dirent_index *idx,
                                const stm_dirent_record *r) {
    stm_btree_engine *eng = NULL;
    stm_status es = di_get_engine_locked(idx, r->dataset_id, &eng);
    if (es != STM_OK) return es;

    uint8_t key[DI_KEY_LEN];
    uint8_t val[DI_VAL_MAX];
    size_t  vlen = 0;
    stm_status ks = di_encode_key(r->dir_ino, r->hash_probe, key);
    if (ks != STM_OK) return ks;
    di_encode_value(r, val, &vlen);
    return stm_btree_engine_insert(eng, key, DI_KEY_LEN, val, vlen);
}

/* engine_delete at exact (ds, dir, probe). Caller holds idx->lock.
 * Used ONLY by drop_for_dir's bulk cleanup; Unlink does NOT delete —
 * it engine_inserts a tombstone (chain integrity per dirent.tla). */
static stm_status di_engine_del(stm_dirent_index *idx,
                                uint64_t ds, uint64_t dir, uint64_t probe) {
    stm_btree_engine *eng = NULL;
    stm_status es = di_get_engine_locked(idx, ds, &eng);
    if (es != STM_OK) return es;

    uint8_t key[DI_KEY_LEN];
    stm_status ks = di_encode_key(dir, probe, key);
    if (ks != STM_OK) return ks;
    return stm_btree_engine_delete(eng, key, DI_KEY_LEN, NULL);
}

/* ------------------------------------------------------------------ */
/* Public API — lifecycle.                                             */
/* ------------------------------------------------------------------ */

stm_dirent_index *stm_dirent_index_create(void) {
    stm_dirent_index *idx = calloc(1, sizeof *idx);
    if (!idx) return NULL;

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) {
        free(idx);
        return NULL;
    }
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

void stm_dirent_index_close(stm_dirent_index *idx) {
    if (!idx) return;
    pthread_mutex_destroy(&idx->lock);
    /* 9.7-impl-1c-iii: the engine isn't ours to close — the per-dataset
     * engines live on the borrowed ds_idx and are closed by
     * stm_dataset_index_close at its lifecycle end. We just drop the
     * borrowed pointer. */
    free(idx);
}

stm_status stm_dirent_index_attach_dataset_index(stm_dirent_index *idx,
                                                 stm_dataset_index *ds_idx) {
    if (!idx || !ds_idx) return STM_EINVAL;
    must_lock(idx_lock(idx));
    if (idx->ds_idx != NULL) {
        /* Re-attach refused — borrow lifetime is fixed at attach. */
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    idx->ds_idx = ds_idx;
    must_unlock(idx_lock(idx));
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Public API — chain operations (alloc / lookup / unlink / count).    */
/* ------------------------------------------------------------------ */

/* Argument-validation helper — refuses every shape the on-disk
 * decoder would refuse, plus the trivial NULL/zero cases. SYMMETRIC
 * with di_decode_value's live-record invariants per R71 P1-1. */
static stm_status alloc_validate_args(uint64_t dataset_id, uint64_t dir_ino,
                                            const uint8_t *name, uint8_t name_len,
                                            uint64_t child_ino,
                                            uint8_t child_type) {
    if (!name) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u || child_ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;
    switch (child_type) {
        case STM_DT_FIFO:
        case STM_DT_CHR:
        case STM_DT_DIR:
        case STM_DT_BLK:
        case STM_DT_REG:
        case STM_DT_LNK:
        case STM_DT_SOCK:
            return STM_OK;
        default:
            return STM_EINVAL;
    }
}

stm_status stm_dirent_alloc(stm_dirent_index *idx,
                                uint64_t dataset_id, uint64_t dir_ino,
                                const uint8_t *name, uint8_t name_len,
                                uint64_t child_ino, uint64_t child_gen,
                                uint8_t child_type) {
    if (!idx) return STM_EINVAL;
    stm_status av = alloc_validate_args(dataset_id, dir_ino, name, name_len,
                                          child_ino, child_type);
    if (av != STM_OK) return av;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    /* Walk the chain. Track the FIRST install-eligible slot (EMPTY,
     * TOMBSTONE, or SAME-NAME WHITEOUT) but keep walking to verify
     * the name isn't already linked further in the chain (would be
     * EEXIST).
     *
     * P8-POSIX-9b: WHITEOUT slots are install candidates ONLY when
     * the whiteout's name matches the name being installed
     * (overlayfs's "promote NAME from lower to upper layer"
     * semantic). A DIFFERENT-named whiteout in the chain MUST be
     * preserved — otherwise an unrelated colliding-named create
     * would silently destroy the whiteout marker, breaking
     * RENAME_WHITEOUT's contract that whiteouts persist across
     * other dir ops (R88 P2-1). Walking past a non-matching
     * whiteout treats it as a chain-occupying slot (like a
     * different-named live record) — chain integrity preserved. */
    bool     have_install_slot = false;
    uint64_t install_probe     = 0;

    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_dirent_record r;
        bool found = false;
        stm_status gs = di_engine_get(idx, dataset_id, dir_ino, probe,
                                      &r, &found);
        if (gs != STM_OK) {
            must_unlock(idx_lock(idx));
            return gs;
        }
        if (!found) {
            /* EMPTY — chain ends here. Install at first install slot
             * (this EMPTY if none earlier was found). */
            if (!have_install_slot) {
                install_probe     = probe;
                have_install_slot = true;
            }
            break;
        }
        if (record_is_tombstone(&r)) {
            if (!have_install_slot) {
                install_probe     = probe;
                have_install_slot = true;
            }
            continue;
        }
        if (record_is_whiteout(&r)) {
            /* SAME-NAME whiteout: install candidate (overlayfs
             * "promote name" — overwrites the whiteout with a
             * fresh live record at the same name). DIFFERENT-NAME
             * whiteout: MUST be preserved to honor RENAME_WHITEOUT's
             * persistence contract — walk past it as an occupying
             * slot. (R88 P2-1) */
            if (record_name_eq(&r, name, name_len)) {
                if (!have_install_slot) {
                    install_probe     = probe;
                    have_install_slot = true;
                }
            }
            continue;
        }
        if (record_name_eq(&r, name, name_len)) {
            must_unlock(idx_lock(idx));
            return STM_EEXIST;
        }
        /* Different live name → continue probing. */
    }

    if (!have_install_slot) {
        must_unlock(idx_lock(idx));
        return STM_ENOSPC;
    }

    /* engine_insert (upsert) the fresh live record at install_probe.
     * If the slot was previously a tombstone or same-name whiteout,
     * the upsert overwrites it; if EMPTY, this is a fresh insert.
     * Failure-atomic — engine_insert never loses an already-present
     * value on failure. */
    stm_dirent_record r;
    memset(&r, 0, sizeof r);
    r.dataset_id = dataset_id;
    r.dir_ino    = dir_ino;
    r.hash_probe = install_probe;
    r.child_ino  = child_ino;
    r.child_gen  = child_gen;
    r.child_type = child_type;
    r.name_len   = name_len;
    r.flags      = 0u;
    memcpy(r.name, name, name_len);

    stm_status ps = di_engine_put(idx, &r);
    must_unlock(idx_lock(idx));
    return ps;
}

stm_status stm_dirent_lookup(const stm_dirent_index *idx,
                                 uint64_t dataset_id, uint64_t dir_ino,
                                 const uint8_t *name, uint8_t name_len,
                                 uint64_t *out_child_ino,
                                 uint64_t *out_child_gen,
                                 uint8_t *out_child_type) {
    if (!idx || !name || !out_child_ino) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;

    *out_child_ino = 0;
    if (out_child_gen)  *out_child_gen  = 0;
    if (out_child_type) *out_child_type = 0;

    stm_dirent_index *m = (stm_dirent_index *)idx;
    pthread_mutex_t *lk = idx_lock(idx);
    must_lock(lk);
    if (m->ds_idx == NULL) {
        must_unlock(lk);
        return STM_EINVAL;
    }

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_dirent_record r;
        bool found = false;
        stm_status gs = di_engine_get(m, dataset_id, dir_ino, probe,
                                      &r, &found);
        if (gs != STM_OK) {
            must_unlock(lk);
            return gs;
        }
        if (!found) {
            /* EMPTY — chain ends. */
            must_unlock(lk);
            return STM_ENOENT;
        }
        if (record_is_tombstone(&r)) continue;
        if (record_is_whiteout(&r)) {
            /* P8-POSIX-9b: a matching whiteout HIDES the name from
             * lookup view (overlayfs interprets via readdir).
             * Non-matching whiteout slots preserve chain integrity
             * for colliding names — continue probing past them. */
            if (record_name_eq(&r, name, name_len)) {
                must_unlock(lk);
                return STM_ENOENT;
            }
            continue;
        }
        if (record_name_eq(&r, name, name_len)) {
            *out_child_ino = r.child_ino;
            if (out_child_gen)  *out_child_gen  = r.child_gen;
            if (out_child_type) *out_child_type = r.child_type;
            must_unlock(lk);
            return STM_OK;
        }
    }

    must_unlock(lk);
    return STM_ENOENT;
}

stm_status stm_dirent_unlink(stm_dirent_index *idx,
                                 uint64_t dataset_id, uint64_t dir_ino,
                                 const uint8_t *name, uint8_t name_len) {
    if (!idx || !name) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_dirent_record r;
        bool found = false;
        stm_status gs = di_engine_get(idx, dataset_id, dir_ino, probe,
                                      &r, &found);
        if (gs != STM_OK) {
            must_unlock(idx_lock(idx));
            return gs;
        }
        if (!found) {
            must_unlock(idx_lock(idx));
            return STM_ENOENT;
        }
        if (record_is_tombstone(&r)) continue;
        if (record_is_whiteout(&r)) {
            /* P8-POSIX-9b: a matching whiteout name has no live
             * record to unlink — return ENOENT. Non-matching
             * whiteouts preserve chain integrity (continue probing). */
            if (record_name_eq(&r, name, name_len)) {
                must_unlock(idx_lock(idx));
                return STM_ENOENT;
            }
            continue;
        }
        if (record_name_eq(&r, name, name_len)) {
            /* Replace with TOMBSTONE via engine_insert — preserves
             * chain integrity for colliding names at higher probe
             * indices (dirent.tla::BuggyUnlinkUsesEmpty). The slot
             * is NOT engine_deleted; the tombstone IS the marker. */
            stm_dirent_record tomb;
            memset(&tomb, 0, sizeof tomb);
            tomb.dataset_id = dataset_id;
            tomb.dir_ino    = dir_ino;
            tomb.hash_probe = probe;
            tomb.flags      = STM_DIRENT_FLAG_TOMBSTONE;
            /* child_ino / child_gen / child_type / name_len / name all
             * zero — matches the decoder's tombstone invariants. */
            stm_status ps = di_engine_put(idx, &tomb);
            must_unlock(idx_lock(idx));
            return ps;
        }
    }

    must_unlock(idx_lock(idx));
    return STM_ENOENT;
}

/* P8-POSIX-9b: helper that walks the chain to locate the live
 * record at (dataset_id, dir_ino, name). Returns STM_OK with
 * `*out_found = true` AND the decoded record on hit; STM_OK with
 * `*out_found = false` if not found OR the chain runs into EMPTY
 * before the name appears OR a matching whiteout hides the name.
 * Non-matching whiteouts preserve chain integrity (continue
 * probing). Engine I/O errors propagate verbatim. Caller MUST
 * hold the index mutex. */
static stm_status find_live_record(stm_dirent_index *idx,
                                   uint64_t dataset_id, uint64_t dir_ino,
                                   const uint8_t *name, uint8_t name_len,
                                   stm_dirent_record *out, bool *out_found) {
    *out_found = false;
    uint64_t hash_base = fnv1a64(name, (size_t)name_len);
    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_dirent_record r;
        bool found = false;
        stm_status gs = di_engine_get(idx, dataset_id, dir_ino, probe,
                                      &r, &found);
        if (gs != STM_OK) return gs;
        if (!found) return STM_OK;          /* EMPTY — chain ends */
        if (record_is_tombstone(&r)) continue;
        if (record_is_whiteout(&r)) {
            if (record_name_eq(&r, name, name_len)) return STM_OK;
            continue;
        }
        if (record_name_eq(&r, name, name_len)) {
            *out = r;
            *out_found = true;
            return STM_OK;
        }
    }
    return STM_OK;
}

stm_status stm_dirent_swap_two(stm_dirent_index *idx,
                                   uint64_t dataset_id,
                                   uint64_t dir1_ino,
                                   const uint8_t *name1, uint8_t name1_len,
                                   uint64_t dir2_ino,
                                   const uint8_t *name2, uint8_t name2_len) {
    if (!idx || !name1 || !name2) return STM_EINVAL;
    if (dataset_id == 0u || dir1_ino == 0u || dir2_ino == 0u) return STM_EINVAL;
    if (name1_len == 0u || name1_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;
    if (name2_len == 0u || name2_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;
    /* Self-swap forbidden — same-dir + same-name is a no-op the
     * caller should have rejected upstream. dirent.tla::Swap
     * mirrors this precondition. */
    if (dir1_ino == dir2_ino &&
        name1_len == name2_len &&
        memcmp(name1, name2, name1_len) == 0) {
        return STM_EINVAL;
    }

    /* R86 P3-1: spec-impl gap note — dirent.tla::Swap requires
     * `~iter_active[d1]` and `~iter_active[d2]`. The C impl doesn't
     * carry an explicit iter_active flag; the index mutex held
     * across the entire swap window substitutes for the spec's
     * stable-iteration guard (readdir at the C layer also takes
     * this same mutex). */
    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    stm_dirent_record r1, r2;
    bool found1 = false, found2 = false;
    stm_status fs1 = find_live_record(idx, dataset_id, dir1_ino,
                                      name1, name1_len, &r1, &found1);
    if (fs1 != STM_OK) {
        must_unlock(idx_lock(idx));
        return fs1;
    }
    if (!found1) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    stm_status fs2 = find_live_record(idx, dataset_id, dir2_ino,
                                      name2, name2_len, &r2, &found2);
    if (fs2 != STM_OK) {
        must_unlock(idx_lock(idx));
        return fs2;
    }
    if (!found2) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }

    /* Swap (child_ino, child_gen, child_type) in the decoded records.
     * Slot positions (hash_probe + key) + names + flags + name_len
     * UNCHANGED — chain integrity by construction. Two engine_inserts
     * land in this critical section so no observer can see a
     * half-swapped state. The engine_insert is failure-atomic: a
     * mid-swap failure on the second put leaves the first put's
     * upsert in place (a partial swap). We accept this trade-off:
     * the partial swap is a self-consistent dirent state (one valid
     * live record replaces another), and the caller wedges the fs
     * on any sync error (R154 doctrine), which forces the next mount
     * to reload from the previous uberblock's pre-swap state. */
    uint64_t c_ino  = r1.child_ino;
    uint64_t c_gen  = r1.child_gen;
    uint8_t  c_type = r1.child_type;
    r1.child_ino  = r2.child_ino;
    r1.child_gen  = r2.child_gen;
    r1.child_type = r2.child_type;
    r2.child_ino  = c_ino;
    r2.child_gen  = c_gen;
    r2.child_type = c_type;

    stm_status p1 = di_engine_put(idx, &r1);
    if (p1 != STM_OK) {
        must_unlock(idx_lock(idx));
        return p1;
    }
    stm_status p2 = di_engine_put(idx, &r2);
    must_unlock(idx_lock(idx));
    return p2;
}

/* P8-POSIX-9b: convert a live record at (ds, dir_ino, name) to a
 * WHITEOUT marker. Models dirent.tla::Whiteout. */
stm_status stm_dirent_whiteout(stm_dirent_index *idx,
                                   uint64_t dataset_id, uint64_t dir_ino,
                                   const uint8_t *name, uint8_t name_len) {
    if (!idx || !name) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    stm_dirent_record r;
    bool found = false;
    stm_status fs = find_live_record(idx, dataset_id, dir_ino,
                                     name, name_len, &r, &found);
    if (fs != STM_OK) {
        must_unlock(idx_lock(idx));
        return fs;
    }
    if (!found) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }

    /* Convert the live record to a WHITEOUT slot in place. Slot
     * position (hash_probe + key) UNCHANGED — chain integrity
     * preserved by construction. The name field is PRESERVED (so
     * readdir can emit the marker). child_ino / child_gen are
     * CLEARED. child_type is reassigned to STM_DT_WHITEOUT (Linux
     * DT_WHT). The flags byte holds ONLY the WHITEOUT bit (mutually
     * exclusive with TOMBSTONE per the decoder). */
    r.child_ino  = 0;
    r.child_gen  = 0;
    r.child_type = STM_DT_WHITEOUT;
    r.flags      = STM_DIRENT_FLAG_WHITEOUT;
    /* name + name_len UNCHANGED. */

    stm_status ps = di_engine_put(idx, &r);
    must_unlock(idx_lock(idx));
    return ps;
}

/* count_for_dir: scan_range over [tag||dir||0 .. tag||dir||UINT64_MAX]
 * within the dataset's engine and count live records (not tombstones,
 * not whiteouts). Range membership is correct under bytewise key
 * order regardless of the little-endian hash_probe encoding's
 * numeric scramble (the all-zero / all-FF probe suffixes are the
 * bytewise extremes within the fixed-prefix scan). */
typedef struct {
    size_t     count;
    stm_status err;
} di_count_ctx;

static int di_count_cb(const void *k, size_t klen,
                       const void *v, size_t vlen, void *ctx_) {
    (void)k;                                /* range bracket pins (ds, dir) */
    (void)klen;
    di_count_ctx *c = ctx_;
    stm_dirent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = di_decode_value(v, vlen, &r);
    if (vs != STM_OK) { c->err = vs; return 1; }
    if (record_is_live(&r)) c->count++;
    return 0;
}

stm_status stm_dirent_count_for_dir(const stm_dirent_index *idx,
                                        uint64_t dataset_id, uint64_t dir_ino,
                                        size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;

    *out_count = 0;
    stm_dirent_index *m = (stm_dirent_index *)idx;
    pthread_mutex_t *lk = idx_lock(idx);
    must_lock(lk);
    if (m->ds_idx == NULL) {
        must_unlock(lk);
        return STM_EINVAL;
    }

    stm_btree_engine *eng = NULL;
    stm_status es = di_get_engine_locked(m, dataset_id, &eng);
    if (es != STM_OK) {
        must_unlock(lk);
        /* STM_ENOENT (dataset not present) maps to count=0 — mirrors
         * the count-on-empty-dir pre-cutover behavior; the dir simply
         * has no records. Every other engine-resolve error propagates. */
        if (es == STM_ENOENT) {
            *out_count = 0;
            return STM_OK;
        }
        return es;
    }

    uint8_t lo[DI_KEY_LEN], hi[DI_KEY_LEN];
    stm_status k1 = di_encode_key(dir_ino, 0u,         lo);
    stm_status k2 = di_encode_key(dir_ino, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        must_unlock(lk);
        return k1 != STM_OK ? k1 : k2;
    }
    di_count_ctx c = { .count = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(eng, lo, DI_KEY_LEN,
                                                hi, DI_KEY_LEN,
                                                di_count_cb, &c);
    must_unlock(lk);
    if (ss != STM_OK) return ss;
    if (c.err != STM_OK) return c.err;
    *out_count = c.count;
    return STM_OK;
}

/* P8-POSIX-4 readdir: emits live + whiteout records under (ds, dir_ino)
 * in hash_probe-ascending order, starting at *cursor.
 *
 * Implementation: scan_range over the (dir, *) prefix to collect all
 * matches into a heap buffer, sort by hash_probe (NOT bytewise — the
 * LE encoding scrambles numeric order), then apply cursor filter and
 * emit prefix. Memory cost: one heap entry per record under (ds, dir).
 * For a directory with N total records (live + tomb + whiteout) this
 * is O(N) memory + O(N log N) time per call.
 *
 * Forward-note (deferred): switching hash_probe to big-endian in the
 * on-disk key would make scan_range yield numeric ascending order
 * natively, letting readdir drop the qsort + serve a window
 * (cursor..cursor+max_entries) directly. Same algorithmic cost as
 * today; same forward-note from 4c. */
typedef struct {
    uint64_t          hash_probe;
    stm_dirent_record r;
} di_readdir_match;

typedef struct {
    di_readdir_match *arr;
    size_t            n;
    size_t            cap;
    stm_status        err;
} di_readdir_ctx;

static int di_readdir_match_cmp(const void *a, const void *b) {
    const di_readdir_match *pa = a, *pb = b;
    if (pa->hash_probe < pb->hash_probe) return -1;
    if (pa->hash_probe > pb->hash_probe) return  1;
    return 0;
}

static int di_readdir_cb(const void *k, size_t klen,
                         const void *v, size_t vlen, void *ctx_) {
    di_readdir_ctx *c = ctx_;
    uint64_t dir = 0, probe = 0;
    stm_status ks = di_decode_key(k, klen, &dir, &probe);
    if (ks != STM_OK) { c->err = ks; return 1; }
    stm_dirent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = di_decode_value(v, vlen, &r);
    if (vs != STM_OK) { c->err = vs; return 1; }
    if (record_is_tombstone(&r)) return 0;     /* never emit tombstones */
    /* dataset_id stamped by the caller (it's the engine handle's
     * tree_id, not on-disk); dir + probe from the decoded key. */
    r.dir_ino    = dir;
    r.hash_probe = probe;

    if (c->n == c->cap) {
        if (c->cap > (SIZE_MAX / sizeof *c->arr) / 2u) {
            c->err = STM_ENOMEM;
            return 1;
        }
        size_t new_cap = c->cap == 0 ? 16u : c->cap * 2u;
        di_readdir_match *na = realloc(c->arr, new_cap * sizeof *na);
        if (!na) { c->err = STM_ENOMEM; return 1; }
        c->arr = na;
        c->cap = new_cap;
    }
    c->arr[c->n].hash_probe = probe;
    c->arr[c->n].r          = r;
    c->n++;
    return 0;
}

stm_status stm_dirent_readdir(const stm_dirent_index *idx,
                                  uint64_t dataset_id, uint64_t dir_ino,
                                  uint64_t *cursor,
                                  stm_dirent_entry *out_entries,
                                  size_t max_entries,
                                  size_t *out_returned)
{
    /* R75 P3-1: zero-init out-param BEFORE arg validation so callers
     * observing on STM_EINVAL see defined values regardless of which
     * validation step rejected. */
    if (out_returned) *out_returned = 0;

    if (!idx || !cursor || !out_entries || !out_returned) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;
    if (max_entries == 0u) return STM_EINVAL;

    /* R75 P2-1: cursor saturation sentinel. Once the prior call's
     * cursor advance hit UINT64_MAX, iteration is done — short-
     * circuit. */
    if (*cursor == UINT64_MAX) return STM_OK;

    stm_dirent_index *m = (stm_dirent_index *)idx;
    pthread_mutex_t *lk = idx_lock(idx);
    must_lock(lk);
    if (m->ds_idx == NULL) {
        must_unlock(lk);
        return STM_EINVAL;
    }

    stm_btree_engine *eng = NULL;
    stm_status es = di_get_engine_locked(m, dataset_id, &eng);
    if (es != STM_OK) {
        must_unlock(lk);
        /* Dataset not present → empty readdir. */
        if (es == STM_ENOENT) return STM_OK;
        return es;
    }

    /* Collect every non-tombstone match under (ds, dir) into a heap
     * buffer via scan_range. The range bracket pins the prefix; we
     * filter the cursor in the post-sort emit step. */
    uint8_t lo[DI_KEY_LEN], hi[DI_KEY_LEN];
    stm_status k1 = di_encode_key(dir_ino, 0u,         lo);
    stm_status k2 = di_encode_key(dir_ino, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        must_unlock(lk);
        return k1 != STM_OK ? k1 : k2;
    }

    di_readdir_ctx c = { .arr = NULL, .n = 0, .cap = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(eng, lo, DI_KEY_LEN,
                                                hi, DI_KEY_LEN,
                                                di_readdir_cb, &c);
    if (ss != STM_OK || c.err != STM_OK) {
        free(c.arr);
        must_unlock(lk);
        return ss != STM_OK ? ss : c.err;
    }
    if (c.n == 0) {
        free(c.arr);
        must_unlock(lk);
        return STM_OK;
    }

    qsort(c.arr, c.n, sizeof *c.arr, di_readdir_match_cmp);

    /* Apply cursor filter: skip records with hash_probe < cursor. */
    size_t start = 0;
    while (start < c.n && c.arr[start].hash_probe < *cursor) start++;
    if (start == c.n) {
        free(c.arr);
        must_unlock(lk);
        return STM_OK;
    }

    /* Emit prefix. */
    size_t avail = c.n - start;
    size_t emit  = (max_entries < avail) ? max_entries : avail;
    for (size_t k = 0; k < emit; k++) {
        const stm_dirent_record *r = &c.arr[start + k].r;
        out_entries[k].child_ino  = r->child_ino;
        out_entries[k].child_gen  = r->child_gen;
        out_entries[k].hash_probe = r->hash_probe;
        out_entries[k].child_type = r->child_type;
        out_entries[k].name_len   = r->name_len;
        memset(out_entries[k].name, 0, sizeof out_entries[k].name);
        if (r->name_len > 0u)
            memcpy(out_entries[k].name, r->name, r->name_len);
    }

    /* Advance cursor to (last_returned_probe + 1), saturating at
     * UINT64_MAX. */
    uint64_t last_probe = c.arr[start + emit - 1].hash_probe;
    *cursor = (last_probe == UINT64_MAX) ? UINT64_MAX : (last_probe + 1u);
    *out_returned = emit;

    free(c.arr);
    must_unlock(lk);
    return STM_OK;
}

/* P8-POSIX-2b R73 P2-1: bulk-drop every record (live + tombstone +
 * whiteout) keyed at (ds, dir_ino, *). Two-phase: scan_range
 * collects every probe under the prefix into a heap buffer, then a
 * second pass engine_deletes each key. The two-phase pattern avoids
 * mutating the engine during scan_range traversal — which is the
 * safe-by-contract pattern (engine_delete during a callback is
 * undefined). */
typedef struct {
    uint64_t  *probes;
    size_t     n;
    size_t     cap;
    stm_status err;
} di_drop_ctx;

static int di_drop_cb(const void *k, size_t klen,
                      const void *v, size_t vlen, void *ctx_) {
    (void)v;                                /* drop reads keys only */
    (void)vlen;
    di_drop_ctx *c = ctx_;
    uint64_t dir = 0, probe = 0;
    stm_status ks = di_decode_key(k, klen, &dir, &probe);
    if (ks != STM_OK) { c->err = ks; return 1; }

    if (c->n == c->cap) {
        if (c->cap > (SIZE_MAX / sizeof *c->probes) / 2u) {
            c->err = STM_ENOMEM;
            return 1;
        }
        size_t new_cap = c->cap == 0 ? 16u : c->cap * 2u;
        uint64_t *na = realloc(c->probes, new_cap * sizeof *na);
        if (!na) { c->err = STM_ENOMEM; return 1; }
        c->probes = na;
        c->cap    = new_cap;
    }
    c->probes[c->n++] = probe;
    return 0;
}

stm_status stm_dirent_drop_for_dir(stm_dirent_index *idx,
                                       uint64_t dataset_id, uint64_t dir_ino,
                                       size_t *out_dropped) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    stm_btree_engine *eng = NULL;
    stm_status es = di_get_engine_locked(idx, dataset_id, &eng);
    if (es != STM_OK) {
        must_unlock(idx_lock(idx));
        /* Dataset not present → nothing to drop. */
        if (es == STM_ENOENT) {
            if (out_dropped) *out_dropped = 0;
            return STM_OK;
        }
        return es;
    }

    uint8_t lo[DI_KEY_LEN], hi[DI_KEY_LEN];
    stm_status k1 = di_encode_key(dir_ino, 0u,         lo);
    stm_status k2 = di_encode_key(dir_ino, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        must_unlock(idx_lock(idx));
        return k1 != STM_OK ? k1 : k2;
    }

    di_drop_ctx c = { .probes = NULL, .n = 0, .cap = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(eng, lo, DI_KEY_LEN,
                                                hi, DI_KEY_LEN,
                                                di_drop_cb, &c);
    if (ss != STM_OK || c.err != STM_OK) {
        free(c.probes);
        must_unlock(idx_lock(idx));
        return ss != STM_OK ? ss : c.err;
    }

    /* Phase 2: engine_delete each collected probe. On the first
     * failure we stop + return the error code; previously-deleted
     * probes stay deleted (engine_delete is failure-atomic; partial
     * progress is durable from the engine's view, retried at the
     * next sync). The caller wedges the fs on any sync error
     * (R154 doctrine), preserving consistency. */
    for (size_t i = 0; i < c.n; i++) {
        stm_status ds = di_engine_del(idx, dataset_id, dir_ino, c.probes[i]);
        if (ds != STM_OK) {
            free(c.probes);
            must_unlock(idx_lock(idx));
            return ds;
        }
    }

    size_t dropped = c.n;
    free(c.probes);
    if (out_dropped) *out_dropped = dropped;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* P8-POSIX-9b R88 P2-1 testing hooks (gated by                        */
/* STRATUM_BUILD_TESTING_HOOKS).                                       */
/* ------------------------------------------------------------------ */

#ifdef STRATUM_BUILD_TESTING_HOOKS
/* Production callers MUST NOT use these. See <stratum/dirent_testing.h>
 * for rationale. */

stm_status stm_dirent_install_at_probe_for_test(
        stm_dirent_index *idx,
        uint64_t dataset_id, uint64_t dir_ino, uint64_t hash_probe,
        const uint8_t *name, uint8_t name_len,
        uint64_t child_ino, uint64_t child_gen,
        uint8_t child_type, uint8_t flags)
{
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;
    if (name_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    /* Construct the in-memory record + engine_insert (upsert). Tests
     * use this to set up specific chain layouts (whiteouts with
     * controlled hash_probes, etc); we bypass alloc's chain-walk +
     * accept whatever (probably-malformed) flags + payload the test
     * specifies, but the engine's KEY-side encoding still applies. */
    stm_dirent_record r;
    memset(&r, 0, sizeof r);
    r.dataset_id = dataset_id;
    r.dir_ino    = dir_ino;
    r.hash_probe = hash_probe;
    r.child_ino  = child_ino;
    r.child_gen  = child_gen;
    r.child_type = child_type;
    r.name_len   = name_len;
    r.flags      = flags;
    if (name && name_len > 0u) memcpy(r.name, name, name_len);

    stm_status ps = di_engine_put(idx, &r);
    must_unlock(idx_lock(idx));
    return ps;
}

uint64_t stm_dirent_fnv1a64_for_test(const uint8_t *name, size_t len) {
    return fnv1a64(name, len);
}
#endif /* STRATUM_BUILD_TESTING_HOOKS */
