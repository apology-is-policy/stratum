/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — xattr index implementation
 * (P8-POSIX-6 + 9.6-impl-4c + 9.7-impl-1c-iv).
 *
 * Spec: v2/specs/xattr.tla. Models open-addressing chain integrity
 * for extended attributes keyed by `(dataset_id, ino, hash_probe)`
 * where `hash_probe = fnv1a64(name) + probe_offset`. Per ARCH §11.5.
 *
 * Structurally isomorphic to dirent.c (P8-POSIX-2): same probe-walk,
 * same tombstone-leaves-on-Remove, same writer/decoder symmetric
 * guards (R71 P1-1 + R77 P1-1 lessons). Differences:
 *   - Keyed at `ino` instead of `dir_ino` (a dir is just a special
 *     inode at the namespace layer; the key field is the same shape).
 *   - Variable-length VALUE field (up to STM_XATTR_VALUE_MAX = 64 KiB)
 *     — engine_insert / engine_lookup serialise the full value bytes
 *     per record; 9.6-impl-3's spill mechanism handles values past
 *     the inline-leaf cap automatically.
 *   - POSIX setxattr flags (CREATE / REPLACE) layered atop the
 *     spec's basic Set action.
 *
 * 9.6-impl-4c — the xattr module was cut to btree_engine; the
 * in-RAM `records[]` array was retired in favour of an
 * incremental-COW B+tree as the canonical store.
 *
 * 9.7-impl-1c-iv — the xattr cutover. The module no longer owns
 * its own btree_engine. Each dataset's xattr records live in that
 * dataset's per-dataset engine (the substrate from 9.7-impl-1c-i),
 * resolved via an attached borrowed `stm_dataset_index *`. Every
 * public op resolves the dataset's engine on entry, atomically with
 * the xattr index's own lock, and routes its lookup / scan / insert
 * / delete through that engine.
 *
 * Keys (17 bytes): `stm_metakey_compose(STM_METAKEY_KIND_XATTR,
 *                  body, 16)` where body = `le64 ino || le64
 *                  hash_probe`.
 *
 * The previous 24-byte `(le64 dataset_id || le64 ino || le64
 * hash_probe)` form is retired — the dataset id is now woven into
 * the engine's AEAD additional-data via `tree_id = dataset_id`, so
 * a cross-dataset substitution attack fails decrypt rather than
 * relying on the key prefix.
 *
 * Values (16 + name_len + value_len bytes, tombstones 16 bytes):
 * unchanged from 4c — see xattr.h for the full byte-level layout.
 *
 * Engine ops:
 *   set            -> chain-walk via engine_lookup per probe, install
 *                     via engine_insert (upsert overwrites a
 *                     tombstone OR a same-name live record per POSIX
 *                     setxattr default semantics)
 *   get            -> chain-walk via engine_lookup per probe
 *   remove         -> chain-walk + engine_insert (tombstone-flavored)
 *   list           -> engine_scan_range over the (ino, *) prefix,
 *                     count + copy out live records (no sort —
 *                     POSIX listxattr doesn't promise order)
 *   drop_for_ino   -> engine_scan_range collects keys, then
 *                     engine_delete each
 *
 * xattr.tla's chain-integrity invariants are UNCHANGED; only the
 * storage under it swapped from the pool-global engine to a per-
 * dataset engine. Tombstones remain reachable as engine_inserted
 * records (no engine_delete is issued for a Remove — the slot must
 * persist so a colliding name at a higher probe stays reachable
 * per xattr.tla's tombstone-leaves-on-Remove invariant).
 * engine_delete is only used by drop_for_ino's bulk cleanup.
 *
 * Concurrency: a single mutex (idx->lock) guards the ds_idx pointer
 * AND every engine call — the btree_engine is single-threaded (one
 * handle, one thread at a time), and idx->lock IS that
 * serialization. The engine handle is BORROWED from the dataset
 * index per call; lifetime is safe because the fs.c layer holds
 * fs->global SH/EX across every xattr op, and `stm_dataset_destroy`
 * takes fs->global EX (so a slot's engine cannot be closed mid-op).
 *
 * Audit-trigger surface: this module is on CLAUDE.md's trigger list.
 */
#include <stratum/xattr.h>
#include <stratum/dataset.h>
#include <stratum/btree_engine.h>
#include <stratum/ebr.h>              /* 9.8-LF-3: stm_xattr_get_concurrent */
#include <stratum/metakey.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Lock helpers — abort on misuse (dirent.c / inode.c convention).     */
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

/* Key: 1-byte STM_METAKEY_KIND_XATTR tag + 8-byte le64 ino + 8-byte
 * le64 hash_probe = 17 bytes total. */
#define XA_KEY_BODY_LEN         16u
#define XA_KEY_LEN              (1u + XA_KEY_BODY_LEN)        /* 17 */

#define XA_VAL_FIXED            16u

/* Max possible on-disk value length (live record): fixed header +
 * max name + max value. Used to size temporary encode buffers. */
#define XA_VAL_MAX              (XA_VAL_FIXED + STM_XATTR_NAME_MAX + STM_XATTR_VALUE_MAX)

/* Reserved-bytes window inside the value (offset 6..16). */
#define XA_VAL_RESERVED_OFF      6u
#define XA_VAL_RESERVED_LEN     10u

/* ------------------------------------------------------------------ */
/* Internal record + index types.                                      */
/* ------------------------------------------------------------------ */

/* In-memory decoded record. The engine stores key + value as opaque
 * bytes; this is the structured shape every chain helper + public op
 * operates on. Decoded from engine_lookup and re-encoded for
 * engine_insert. The dataset_id / ino / hash_probe fields are STAMPED
 * from the (caller, key) triple (NOT from the value bytes) so a buggy
 * writer can't tamper cross-key references.
 *
 * `value` is heap-allocated when value_len > 0; the caller MUST free
 * it after every use. This struct is per-call stack-allocated; there
 * is no in-RAM cache of records.
 *
 * The dataset_id is conceptual (it comes from the engine handle's
 * tree_id, not the on-disk key body) but we record it on the
 * decoded record for caller-side symmetry with the pre-cutover shape. */
typedef struct {
    uint64_t dataset_id;
    uint64_t ino;
    uint64_t hash_probe;
    uint8_t  name_len;
    uint8_t  flags;          /* STM_XATTR_FLAG_TOMBSTONE on tombstone */
    uint8_t  name[STM_XATTR_NAME_MAX];
    uint32_t value_len;
    uint8_t *value;
} stm_xattr_record;

struct stm_xattr_index {
    pthread_mutex_t      lock;

    /* 9.7-impl-1c-iv: borrowed dataset index. Set once by
     * stm_xattr_index_attach_dataset_index; alive for the xattr
     * index's lifetime. NULL pre-attach — every op refuses with
     * STM_EINVAL. */
    stm_dataset_index   *ds_idx;
};

static inline pthread_mutex_t *idx_lock(const stm_xattr_index *idx) {
    return (pthread_mutex_t *)&idx->lock;
}

static inline bool record_is_tombstone(const stm_xattr_record *r) {
    return (r->flags & STM_XATTR_FLAG_TOMBSTONE) != 0u;
}

static inline bool record_name_eq(const stm_xattr_record *r,
                                       const uint8_t *name, uint8_t name_len) {
    return r->name_len == name_len &&
           memcmp(r->name, name, name_len) == 0;
}

/* Free a record's value buffer + clear value_len. */
static void record_clear_value(stm_xattr_record *r) {
    if (r->value) {
        /* Not stm_ct_memzero — xattr values are user-controlled but not
         * key material. */
        free(r->value);
        r->value = NULL;
    }
    r->value_len = 0u;
}

/* ------------------------------------------------------------------ */
/* FNV-1a 64-bit hash (ARCH §11.5 — used to compute hash_probe).       */
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
/* Key: 17 bytes — STM_METAKEY_KIND_XATTR tag || le64 ino ||           */
/*                  le64 hash_probe.                                    */
/* Value: 16 + name_len + value_len bytes (tombstone: 16 bytes).        */
/* See xattr.h.                                                         */
/*                                                                      */
/* The dataset id is woven into the engine's AEAD additional-data via   */
/* tree_id = dataset_id at engine create / open time (the substrate     */
/* from 9.7-impl-1c-i). Cross-dataset substitution defense lives in the */
/* engine layer, not the key prefix.                                    */
/*                                                                      */
/* R71 P1-1 doctrine: stm_metakey_compose tags + stm_metakey_parse      */
/* decoder-side tag check are symmetric. The body length (16 bytes)     */
/* is re-validated on every decode in xa_decode_key.                    */
/* ------------------------------------------------------------------ */

static stm_status xa_encode_key(uint64_t ino, uint64_t hash_probe,
                                uint8_t out[XA_KEY_LEN]) {
    uint8_t body[XA_KEY_BODY_LEN];
    le64 in = stm_store_le64(ino);
    le64 hp = stm_store_le64(hash_probe);
    memcpy(body + 0, in.v, 8);
    memcpy(body + 8, hp.v, 8);
    size_t out_len = 0;
    return stm_metakey_compose(STM_METAKEY_KIND_XATTR,
                                body, XA_KEY_BODY_LEN,
                                out, XA_KEY_LEN, &out_len);
}

static stm_status xa_decode_key(const void *in, size_t in_len,
                                    uint64_t *out_ino, uint64_t *out_probe) {
    stm_metakey_kind kind;
    const uint8_t *body = NULL;
    size_t body_len = 0;
    stm_status rc = stm_metakey_parse(in, in_len, &kind, &body, &body_len);
    if (rc != STM_OK) return rc;
    if (kind != STM_METAKEY_KIND_XATTR) return STM_ECORRUPT;
    if (body_len != XA_KEY_BODY_LEN) return STM_ECORRUPT;
    le64 in_le, hp_le;
    memcpy(in_le.v, body + 0, 8);
    memcpy(hp_le.v, body + 8, 8);
    *out_ino   = stm_load_le64(in_le);
    *out_probe = stm_load_le64(hp_le);
    return STM_OK;
}

/* Encode a record into out[]; out must be ≥ XA_VAL_FIXED + r->name_len
 * + r->value_len bytes (the caller passes XA_VAL_MAX-sized buffers). */
static void xa_encode_value(const stm_xattr_record *r,
                                uint8_t *out, size_t *out_len) {
    le32 vl = stm_store_le32(r->value_len);
    memcpy(out + 0, vl.v, 4);
    out[4] = r->name_len;
    out[5] = r->flags;
    memset(out + XA_VAL_RESERVED_OFF, 0, XA_VAL_RESERVED_LEN);
    if (r->name_len > 0u) {
        memcpy(out + XA_VAL_FIXED, r->name, r->name_len);
    }
    /* R80 P3-4: encode invariant — value_len > 0 ⇒ value != NULL.
     * The `else` branch zero-fills any value_len bytes if the upstream
     * invariant is violated (defense-in-depth) so we never disclose
     * heap content via an unset value pointer. */
    if (r->value_len > 0u) {
        if (r->value) {
            memcpy(out + XA_VAL_FIXED + r->name_len, r->value, r->value_len);
        } else {
            memset(out + XA_VAL_FIXED + r->name_len, 0, r->value_len);
        }
    }
    *out_len = (size_t)XA_VAL_FIXED
                + (size_t)r->name_len
                + (size_t)r->value_len;
}

/* Decode + validate. Pins the on-disk invariants per xattr.h's
 * value-layout contract:
 *
 *   - value length matches the encoded name_len + value_len;
 *   - reserved bytes are zero;
 *   - tombstone iff (flags & TOMBSTONE) iff (name_len == 0 AND
 *     value_len == 0);
 *   - live records: name_len in [1, 255], value_len in [0,
 *     STM_XATTR_VALUE_MAX].
 *
 * These must be SYMMETRIC with the writer-side guards in
 * stm_xattr_set (R71 P1-1 + R77 P1-1 lesson — the OOB-read shape
 * extends from inline data to xattr value records).
 *
 * On success, copies the name into `out->name[0..name_len)` and
 * heap-allocates a fresh `out->value` buffer if value_len > 0
 * (caller takes ownership; freed via record_clear_value or free()).
 * The dataset_id / ino / hash_probe fields are NOT set here — caller
 * stamps from the (caller, on-disk key) triple. */
static stm_status xa_decode_value(const void *in, size_t in_len,
                                       stm_xattr_record *out) {
    if (in_len < XA_VAL_FIXED) return STM_ECORRUPT;
    const uint8_t *b = in;

    le32 vl_le;
    memcpy(vl_le.v, b + 0, 4);
    uint32_t value_len = stm_load_le32(vl_le);
    uint8_t  name_len  = b[4];
    uint8_t  flags     = b[5];

    /* Reserved bytes 6..16 must be zero. */
    for (size_t i = 0; i < XA_VAL_RESERVED_LEN; i++) {
        if (b[XA_VAL_RESERVED_OFF + i] != 0u) return STM_ECORRUPT;
    }

    /* Length matches name_len + value_len. */
    if (in_len != (size_t)XA_VAL_FIXED
                    + (size_t)name_len
                    + (size_t)value_len) {
        return STM_ECORRUPT;
    }

    bool is_tomb = (flags & STM_XATTR_FLAG_TOMBSTONE) != 0u;

    /* R80 P3-6: zero-init key fields explicitly so the contract is
     * "xa_decode_value fully initializes out except for caller-
     * supplied (dataset_id, ino, hash_probe) which the caller fills
     * post-call from the (caller, on-disk key) triple". */
    out->dataset_id = 0u;
    out->ino        = 0u;
    out->hash_probe = 0u;

    /* Tombstone vs live invariants. */
    if (is_tomb) {
        if (name_len  != 0u)  return STM_ECORRUPT;
        if (value_len != 0u)  return STM_ECORRUPT;
        /* Other flag bits beyond TOMBSTONE are reserved zero. */
        if ((flags & ~(uint8_t)STM_XATTR_FLAG_TOMBSTONE) != 0u)
            return STM_ECORRUPT;
        out->name_len  = 0u;
        out->value_len = 0u;
        out->flags     = flags;
        out->value     = NULL;
        memset(out->name, 0, sizeof out->name);
    } else {
        if (name_len == 0u || name_len > STM_XATTR_NAME_MAX)
            return STM_ECORRUPT;
        if (value_len > STM_XATTR_VALUE_MAX)
            return STM_ECORRUPT;
        if (flags != 0u) return STM_ECORRUPT;

        out->name_len  = name_len;
        out->value_len = value_len;
        out->flags     = 0u;
        memset(out->name, 0, sizeof out->name);
        memcpy(out->name, b + XA_VAL_FIXED, name_len);

        if (value_len > 0u) {
            out->value = malloc(value_len);
            if (!out->value) return STM_ENOMEM;
            memcpy(out->value, b + XA_VAL_FIXED + name_len, value_len);
        } else {
            out->value = NULL;
        }
    }
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Engine glue.                                                         */
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
static stm_status xa_get_engine_locked(stm_xattr_index *idx,
                                       uint64_t dataset_id,
                                       stm_btree_engine **out_eng) {
    *out_eng = NULL;
    if (idx->ds_idx == NULL) return STM_EINVAL;
    return stm_dataset_index_get_engine(idx->ds_idx, dataset_id, out_eng);
}

/* engine_lookup + decode + validate at exact (ds, ino, probe). Caller
 * holds idx->lock. On STM_OK with *out_found = true, *out holds the
 * validated decoded record (live or tombstone); if value_len > 0 the
 * caller MUST free out->value (or call record_clear_value). The
 * dataset_id / ino / hash_probe fields are STAMPED from the (caller,
 * key) triple. On STM_OK with *out_found = false, *out is left in a
 * cleared state (no heap to free). */
static stm_status xa_engine_get(stm_xattr_index *idx,
                                uint64_t ds, uint64_t ino, uint64_t probe,
                                stm_xattr_record *out, bool *out_found) {
    *out_found = false;
    memset(out, 0, sizeof *out);

    stm_btree_engine *eng = NULL;
    stm_status es = xa_get_engine_locked(idx, ds, &eng);
    if (es != STM_OK) return es;

    uint8_t key[XA_KEY_LEN];
    stm_status ks = xa_encode_key(ino, probe, key);
    if (ks != STM_OK) return ks;

    /* 9.8-BE-fs-port (chunk 10): chain-aware _concurrent lookup + a
     * self-entered EBR pin (value copied out under the pin).
     * Non-reentrant caller contract -- see inode.c in_engine_get. */
    stm_ebr_thread *ebr = stm_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;

    bool found = false;
    void *vbuf = NULL;
    size_t vlen = 0;
    stm_ebr_enter(ebr);
    stm_status ls = stm_btree_engine_lookup_concurrent(eng, ebr, key,
                                                       XA_KEY_LEN,
                                                       &found, &vbuf, &vlen);
    stm_ebr_exit(ebr);
    if (ls != STM_OK) return ls;
    if (!found) return STM_OK;                  /* *out_found stays false */

    stm_status vs = xa_decode_value(vbuf, vlen, out);
    free(vbuf);
    if (vs != STM_OK) {
        /* xa_decode_value may have heap-allocated out->value before
         * hitting an error code path; in practice it returns the
         * heap allocation only on STM_OK. Defense-in-depth: free if
         * non-NULL. */
        if (out->value) {
            free(out->value);
            out->value = NULL;
        }
        return vs;
    }
    out->dataset_id = ds;
    out->ino        = ino;
    out->hash_probe = probe;
    *out_found      = true;
    return STM_OK;
}

/* Encode + engine_insert (upsert). Caller holds idx->lock. The engine's
 * insert is failure-atomic — a failed put never loses the prior value
 * at this key. The encoded value buffer is allocated on the heap
 * (worst-case 16 + 255 + 65536 ≈ 64 KiB — too big for the stack). */
static stm_status xa_engine_put(stm_xattr_index *idx,
                                const stm_xattr_record *r) {
    stm_btree_engine *eng = NULL;
    stm_status es = xa_get_engine_locked(idx, r->dataset_id, &eng);
    if (es != STM_OK) return es;

    uint8_t key[XA_KEY_LEN];
    stm_status ks = xa_encode_key(r->ino, r->hash_probe, key);
    if (ks != STM_OK) return ks;

    uint8_t *val = malloc(XA_VAL_MAX);
    if (!val) return STM_ENOMEM;
    size_t vlen = 0;
    xa_encode_value(r, val, &vlen);

    /* 9.8-BE-fs-port (chunk 10): CAS-prepend via _concurrent insert;
     * self-entered EBR pin; non-reentrant caller contract. */
    stm_ebr_thread *ebr = stm_ebr_thread_current();
    if (!ebr) { free(val); return STM_ENOMEM; }
    stm_ebr_enter(ebr);
    stm_status is = stm_btree_engine_insert_concurrent(eng, ebr, key,
                                                       XA_KEY_LEN, val, vlen);
    stm_ebr_exit(ebr);
    free(val);
    return is;
}

/* engine_delete at exact (ds, ino, probe). Caller holds idx->lock.
 * Used ONLY by drop_for_ino's bulk cleanup; Remove does NOT delete —
 * it engine_inserts a tombstone (chain integrity per xattr.tla). */
static stm_status xa_engine_del(stm_xattr_index *idx,
                                uint64_t ds, uint64_t ino, uint64_t probe) {
    stm_btree_engine *eng = NULL;
    stm_status es = xa_get_engine_locked(idx, ds, &eng);
    if (es != STM_OK) return es;

    uint8_t key[XA_KEY_LEN];
    stm_status ks = xa_encode_key(ino, probe, key);
    if (ks != STM_OK) return ks;

    /* 9.8-BE-fs-port (chunk 10): CAS-prepend a DELETE delta via
     * _concurrent delete; self-entered EBR pin; non-reentrant caller
     * contract. */
    stm_ebr_thread *ebr = stm_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;
    stm_ebr_enter(ebr);
    stm_status rc = stm_btree_engine_delete_concurrent(eng, ebr, key,
                                                       XA_KEY_LEN);
    stm_ebr_exit(ebr);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Public API — lifecycle.                                             */
/* ------------------------------------------------------------------ */

stm_xattr_index *stm_xattr_index_create(void) {
    stm_xattr_index *idx = calloc(1, sizeof *idx);
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

void stm_xattr_index_close(stm_xattr_index *idx) {
    if (!idx) return;
    pthread_mutex_destroy(&idx->lock);
    /* 9.7-impl-1c-iv: the engine isn't ours to close — the per-dataset
     * engines live on the borrowed ds_idx and are closed by
     * stm_dataset_index_close at its lifecycle end. We just drop the
     * borrowed pointer. */
    free(idx);
}

stm_status stm_xattr_index_attach_dataset_index(stm_xattr_index *idx,
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
/* Public API — chain operations.                                      */
/* ------------------------------------------------------------------ */

/* Argument-validation helper — refuses every shape the on-disk
 * decoder would refuse, plus the trivial NULL/zero cases. SYMMETRIC
 * with xa_decode_value's live-record invariants per R71 P1-1 + R77
 * P1-1. */
static stm_status set_validate_args(uint64_t dataset_id, uint64_t ino,
                                          const uint8_t *name, uint8_t name_len,
                                          const uint8_t *value, uint32_t value_len,
                                          uint32_t flags) {
    if (!name) return STM_EINVAL;
    if (value_len > 0u && !value) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_XATTR_NAME_MAX) return STM_EINVAL;
    if (value_len > STM_XATTR_VALUE_MAX) return STM_ERANGE;
    /* flags must be a subset of {CREATE, REPLACE} and not both. */
    uint32_t known = STM_XATTR_FLAG_CREATE | STM_XATTR_FLAG_REPLACE;
    if ((flags & ~known) != 0u) return STM_EINVAL;
    if ((flags & STM_XATTR_FLAG_CREATE) &&
        (flags & STM_XATTR_FLAG_REPLACE)) return STM_EINVAL;
    return STM_OK;
}

stm_status stm_xattr_set(stm_xattr_index *idx,
                            uint64_t dataset_id, uint64_t ino,
                            const uint8_t *name, uint8_t name_len,
                            const uint8_t *value, uint32_t value_len,
                            uint32_t flags,
                            bool *out_replaced) {
    if (out_replaced) *out_replaced = false;
    if (!idx) return STM_EINVAL;
    stm_status av = set_validate_args(dataset_id, ino, name, name_len,
                                         value, value_len, flags);
    if (av != STM_OK) return av;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    /* Walk the chain. Track the FIRST install-eligible slot (EMPTY or
     * TOMBSTONE) but keep walking to verify whether the name is
     * already linked further in the chain. If it is, we replace
     * in-place at that slot (POSIX setxattr default semantics). */
    bool     have_install_slot = false;
    uint64_t install_probe     = 0;
    bool     existing_found    = false;
    uint64_t existing_probe    = 0;

    for (uint32_t k = 0; k < STM_XATTR_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_xattr_record r;
        bool found = false;
        stm_status gs = xa_engine_get(idx, dataset_id, ino, probe,
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
            /* tombstone has no heap value to free */
            continue;
        }
        if (record_name_eq(&r, name, name_len)) {
            /* Found a live match at this probe. Free the heap value
             * we just allocated in xa_engine_get and remember the
             * probe to replace at. */
            record_clear_value(&r);
            existing_found = true;
            existing_probe = probe;
            break;
        }
        /* Different live name → continue probing. Free the heap value
         * before the next iteration. */
        record_clear_value(&r);
    }

    /* Apply POSIX setxattr flag semantics. */
    if (existing_found) {
        if (flags & STM_XATTR_FLAG_CREATE) {
            must_unlock(idx_lock(idx));
            return STM_EEXIST;
        }
        /* REPLACE or default: rewrite the existing record. Construct
         * the new value via engine_insert (upsert) at the same probe. */
        stm_xattr_record nr;
        memset(&nr, 0, sizeof nr);
        nr.dataset_id = dataset_id;
        nr.ino        = ino;
        nr.hash_probe = existing_probe;
        nr.name_len   = name_len;
        nr.flags      = 0u;
        memcpy(nr.name, name, name_len);
        nr.value_len  = value_len;
        nr.value      = (uint8_t *)value;   /* borrowed for encode only */

        stm_status ps = xa_engine_put(idx, &nr);
        /* xa_engine_put doesn't free nr.value (it's borrowed); we
         * also do nothing because the caller owns the original
         * buffer. */
        if (ps != STM_OK) {
            must_unlock(idx_lock(idx));
            return ps;
        }
        if (out_replaced) *out_replaced = true;
        must_unlock(idx_lock(idx));
        return STM_OK;
    }

    /* No existing live record. */
    if (flags & STM_XATTR_FLAG_REPLACE) {
        must_unlock(idx_lock(idx));
        return STM_ENODATA;
    }
    if (!have_install_slot) {
        must_unlock(idx_lock(idx));
        return STM_ENOSPC;
    }

    /* Install at install_probe via engine_insert (upsert overwrites
     * a tombstone if present, fresh insert at EMPTY). */
    stm_xattr_record nr;
    memset(&nr, 0, sizeof nr);
    nr.dataset_id = dataset_id;
    nr.ino        = ino;
    nr.hash_probe = install_probe;
    nr.name_len   = name_len;
    nr.flags      = 0u;
    memcpy(nr.name, name, name_len);
    nr.value_len  = value_len;
    nr.value      = (uint8_t *)value;   /* borrowed for encode only */

    stm_status ps = xa_engine_put(idx, &nr);
    must_unlock(idx_lock(idx));
    return ps;
}

stm_status stm_xattr_get(const stm_xattr_index *idx,
                            uint64_t dataset_id, uint64_t ino,
                            const uint8_t *name, uint8_t name_len,
                            uint8_t *value_buf, uint32_t value_max,
                            uint32_t *out_size) {
    /* R75 P3-1-style zero-init: out_size BEFORE arg validation so
     * callers observing on STM_EINVAL see defined values regardless
     * of which validation step rejected. */
    if (out_size) *out_size = 0;

    if (!idx || !name || !out_size) return STM_EINVAL;
    if (value_max > 0u && !value_buf) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_XATTR_NAME_MAX) return STM_EINVAL;

    pthread_mutex_t *lk = idx_lock(idx);
    must_lock(lk);

    /* Cast away const for the engine_lookup call. */
    stm_xattr_index *m = (stm_xattr_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lk);
        return STM_EINVAL;
    }

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_XATTR_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_xattr_record r;
        bool found = false;
        stm_status gs = xa_engine_get(m, dataset_id, ino, probe,
                                      &r, &found);
        if (gs != STM_OK) {
            must_unlock(lk);
            /* Dataset not present → no record. POSIX getxattr maps
             * to ENODATA. */
            if (gs == STM_ENOENT) return STM_ENODATA;
            return gs;
        }
        if (!found) {
            /* EMPTY — chain ends. */
            must_unlock(lk);
            return STM_ENODATA;
        }
        if (record_is_tombstone(&r)) {
            /* No heap value on a tombstone — no-op free. */
            continue;
        }
        if (record_name_eq(&r, name, name_len)) {
            /* R77 P1-1 defense-in-depth: re-cap value_len. */
            if (r.value_len > STM_XATTR_VALUE_MAX) {
                record_clear_value(&r);
                must_unlock(lk);
                return STM_ECORRUPT;
            }
            *out_size = r.value_len;
            if (value_max == 0u) {
                /* Probe-only call; no copy. */
                record_clear_value(&r);
                must_unlock(lk);
                return STM_OK;
            }
            if (value_max < r.value_len) {
                record_clear_value(&r);
                must_unlock(lk);
                return STM_ERANGE;
            }
            if (r.value_len > 0u && r.value) {
                memcpy(value_buf, r.value, r.value_len);
            }
            record_clear_value(&r);
            must_unlock(lk);
            return STM_OK;
        }
        /* Different live name → free the heap value, continue. */
        record_clear_value(&r);
    }

    must_unlock(lk);
    return STM_ENODATA;
}

/*
 * 9.8-LF-3: wait-free sibling of stm_xattr_get. See xattr.h for the
 * contract.
 *
 * Same reader-vs-writer caveat as stm_inode_lookup_concurrent: a
 * same-engine concurrent writer's stm_btree_engine_insert can tear
 * the per-probe descent at LF-2; BE-prepend lifts that.
 *
 * No xattr-index mutex is taken; the descent uses the per-probe
 * engine_lookup_concurrent which pins each visited node under the
 * caller's EBR handle.
 */
stm_status stm_xattr_get_concurrent(const stm_xattr_index *idx,
                                       stm_ebr_thread *ebr,
                                       uint64_t dataset_id, uint64_t ino,
                                       const uint8_t *name, uint8_t name_len,
                                       uint8_t *value_buf, uint32_t value_max,
                                       uint32_t *out_size) {
    /* Match stm_xattr_get's R75 P3-1 zero-init posture. */
    if (out_size) *out_size = 0;

    if (!idx || !ebr || !name || !out_size) return STM_EINVAL;
    if (value_max > 0u && !value_buf) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_XATTR_NAME_MAX) return STM_EINVAL;

    stm_xattr_index *m = (stm_xattr_index *)idx;
    if (m->ds_idx == NULL) return STM_EINVAL;

    stm_btree_engine *eng = NULL;
    stm_status es = stm_dataset_index_get_engine(m->ds_idx, dataset_id, &eng);
    if (es != STM_OK) {
        /* Dataset not present → POSIX getxattr maps to ENODATA. */
        if (es == STM_ENOENT) return STM_ENODATA;
        return es;
    }

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_XATTR_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;

        uint8_t key[XA_KEY_LEN];
        stm_status ks = xa_encode_key(ino, probe, key);
        if (ks != STM_OK) return ks;

        bool found = false;
        void *vbuf = NULL;
        size_t vlen = 0;
        stm_status ls = stm_btree_engine_lookup_concurrent(
                              eng, ebr, key, XA_KEY_LEN,
                              &found, &vbuf, &vlen);
        if (ls != STM_OK) return ls;
        if (!found) return STM_ENODATA;

        stm_xattr_record r;
        memset(&r, 0, sizeof r);
        stm_status vs = xa_decode_value(vbuf, vlen, &r);
        free(vbuf);
        if (vs != STM_OK) return vs;

        if (record_is_tombstone(&r)) {
            /* Tombstone — no heap allocated by decoder. Continue. */
            continue;
        }
        if (record_name_eq(&r, name, name_len)) {
            /* R77 P1-1 defense-in-depth: re-cap value_len. */
            if (r.value_len > STM_XATTR_VALUE_MAX) {
                record_clear_value(&r);
                return STM_ECORRUPT;
            }
            *out_size = r.value_len;
            if (value_max == 0u) {
                record_clear_value(&r);
                return STM_OK;
            }
            if (value_max < r.value_len) {
                record_clear_value(&r);
                return STM_ERANGE;
            }
            if (r.value_len > 0u && r.value) {
                memcpy(value_buf, r.value, r.value_len);
            }
            record_clear_value(&r);
            return STM_OK;
        }
        /* Different live name → free the heap value, continue. */
        record_clear_value(&r);
    }

    return STM_ENODATA;
}

stm_status stm_xattr_remove(stm_xattr_index *idx,
                               uint64_t dataset_id, uint64_t ino,
                               const uint8_t *name, uint8_t name_len) {
    if (!idx || !name) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_XATTR_NAME_MAX) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_XATTR_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_xattr_record r;
        bool found = false;
        stm_status gs = xa_engine_get(idx, dataset_id, ino, probe,
                                      &r, &found);
        if (gs != STM_OK) {
            must_unlock(idx_lock(idx));
            /* Dataset not present → nothing to remove. POSIX
             * removexattr maps to ENODATA. */
            if (gs == STM_ENOENT) return STM_ENODATA;
            return gs;
        }
        if (!found) {
            must_unlock(idx_lock(idx));
            return STM_ENODATA;
        }
        if (record_is_tombstone(&r)) continue;     /* no heap to free */
        if (record_name_eq(&r, name, name_len)) {
            /* Free the live record's heap value before constructing
             * the tombstone (tombstones have no value). */
            record_clear_value(&r);
            /* Replace with TOMBSTONE via engine_insert — preserves
             * chain integrity for colliding names at higher probe
             * indices. */
            stm_xattr_record tomb;
            memset(&tomb, 0, sizeof tomb);
            tomb.dataset_id = dataset_id;
            tomb.ino        = ino;
            tomb.hash_probe = probe;
            tomb.flags      = STM_XATTR_FLAG_TOMBSTONE;
            /* name_len / name / value_len / value all zero. */
            stm_status ps = xa_engine_put(idx, &tomb);
            must_unlock(idx_lock(idx));
            return ps;
        }
        /* Different live name → continue, free heap value. */
        record_clear_value(&r);
    }

    must_unlock(idx_lock(idx));
    return STM_ENODATA;
}

/* listxattr: scan_range over [tag||ino||0 .. tag||ino||UINT64_MAX]
 * within the dataset's engine and emit live records into out_entries.
 * POSIX listxattr doesn't promise any order, so we emit in scan_range's
 * bytewise-key order. *out_total is the count of live records under
 * (ds, ino), regardless of how many were copied.
 *
 * Two-pass not strictly required (we know cap from caller), but we
 * still need to count live records first to refuse with STM_ERANGE
 * when max_entries < n_total. We collect into a heap buffer of
 * caller_max entries during the scan, also incrementing n_total for
 * every live match — early-stop the scan once n_total exceeds
 * max_entries IF we don't need precise counts. We don't early-stop
 * because the POSIX semantics expose the count via *out_total. */
typedef struct {
    stm_xattr_entry  *out;
    size_t            out_cap;            /* caller's max_entries */
    size_t            out_n;              /* number copied so far */
    size_t            n_total;            /* total live records seen */
    stm_status        err;
} xa_list_ctx;

static int xa_list_cb(const void *k, size_t klen,
                      const void *v, size_t vlen, void *ctx_) {
    xa_list_ctx *c = ctx_;
    uint64_t ino = 0, probe = 0;
    stm_status ks = xa_decode_key(k, klen, &ino, &probe);
    if (ks != STM_OK) { c->err = ks; return 1; }
    (void)ino;                          /* range bracket pins ino */

    stm_xattr_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = xa_decode_value(v, vlen, &r);
    if (vs != STM_OK) { c->err = vs; return 1; }
    if (record_is_tombstone(&r)) {
        /* Tombstones aren't live records; don't count. No heap. */
        return 0;
    }
    /* Live record — count + maybe copy. Free the heap value we just
     * allocated in xa_decode_value; we only need name + value_len for
     * the listxattr entry shape. */
    c->n_total++;
    if (c->out && c->out_n < c->out_cap) {
        c->out[c->out_n].hash_probe = probe;
        c->out[c->out_n].name_len   = r.name_len;
        memset(c->out[c->out_n].name, 0, sizeof c->out[c->out_n].name);
        if (r.name_len > 0u) {
            memcpy(c->out[c->out_n].name, r.name, r.name_len);
        }
        c->out[c->out_n].value_len = r.value_len;
        c->out_n++;
    }
    record_clear_value(&r);
    return 0;
}

stm_status stm_xattr_list(const stm_xattr_index *idx,
                             uint64_t dataset_id, uint64_t ino,
                             stm_xattr_entry *out_entries,
                             size_t max_entries,
                             size_t *out_total) {
    if (out_total) *out_total = 0;

    if (!idx || !out_total) return STM_EINVAL;
    if (max_entries > 0u && !out_entries) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_mutex_t *lk = idx_lock(idx);
    must_lock(lk);

    /* Cast away const for the engine_scan_range call. */
    stm_xattr_index *m = (stm_xattr_index *)idx;
    if (m->ds_idx == NULL) {
        must_unlock(lk);
        return STM_EINVAL;
    }

    stm_btree_engine *eng = NULL;
    stm_status es = xa_get_engine_locked(m, dataset_id, &eng);
    if (es != STM_OK) {
        must_unlock(lk);
        /* Dataset not present → empty listing. */
        if (es == STM_ENOENT) return STM_OK;
        return es;
    }

    uint8_t lo[XA_KEY_LEN], hi[XA_KEY_LEN];
    stm_status k1 = xa_encode_key(ino, 0u,         lo);
    stm_status k2 = xa_encode_key(ino, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        must_unlock(lk);
        return k1 != STM_OK ? k1 : k2;
    }

    xa_list_ctx c = { .out = out_entries, .out_cap = max_entries,
                       .out_n = 0, .n_total = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(eng, lo, XA_KEY_LEN,
                                                hi, XA_KEY_LEN,
                                                xa_list_cb, &c);
    if (ss != STM_OK || c.err != STM_OK) {
        must_unlock(lk);
        return ss != STM_OK ? ss : c.err;
    }
    *out_total = c.n_total;
    if (max_entries == 0u) {
        /* Probe-only: report the count, copied 0. */
        must_unlock(lk);
        return STM_OK;
    }
    if (max_entries < c.n_total) {
        /* Caller's buffer is too small for the full listing. POSIX
         * listxattr returns ERANGE; out_total has the required size. */
        must_unlock(lk);
        return STM_ERANGE;
    }
    must_unlock(lk);
    return STM_OK;
}

/* 9.8-LF-3b: concurrent (EBR-pinned) listxattr.
 *
 * Same shape as stm_xattr_list — same xa_list_cb, same lo/hi bracket,
 * same STM_ERANGE / *out_total post-scan handling — but the engine is
 * materialised through stm_dataset_index_get_engine (which takes
 * dataset_index's internal mutex) instead of this module's lock, and
 * the scan runs via stm_btree_engine_scan_range_concurrent under the
 * caller's EBR pin. */
stm_status stm_xattr_list_concurrent(const stm_xattr_index *idx,
                                        stm_ebr_thread *ebr,
                                        uint64_t dataset_id, uint64_t ino,
                                        stm_xattr_entry *out_entries,
                                        size_t max_entries,
                                        size_t *out_total) {
    if (out_total) *out_total = 0;

    if (!idx || !ebr || !out_total) return STM_EINVAL;
    if (max_entries > 0u && !out_entries) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    stm_xattr_index *m = (stm_xattr_index *)idx;
    if (m->ds_idx == NULL) return STM_EINVAL;

    stm_btree_engine *eng = NULL;
    stm_status es = stm_dataset_index_get_engine(m->ds_idx, dataset_id, &eng);
    if (es != STM_OK) {
        /* Dataset not present → empty listing (matches serial path). */
        if (es == STM_ENOENT) return STM_OK;
        return es;
    }

    uint8_t lo[XA_KEY_LEN], hi[XA_KEY_LEN];
    stm_status k1 = xa_encode_key(ino, 0u,         lo);
    stm_status k2 = xa_encode_key(ino, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK)
        return k1 != STM_OK ? k1 : k2;

    xa_list_ctx c = { .out = out_entries, .out_cap = max_entries,
                       .out_n = 0, .n_total = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range_concurrent(
        eng, ebr, lo, XA_KEY_LEN, hi, XA_KEY_LEN, xa_list_cb, &c);
    if (ss != STM_OK || c.err != STM_OK)
        return ss != STM_OK ? ss : c.err;

    *out_total = c.n_total;
    if (max_entries == 0u) return STM_OK;          /* probe-only */
    if (max_entries < c.n_total) return STM_ERANGE;
    return STM_OK;
}

/* drop_for_ino: bulk-drop every record (live + tombstone) keyed at
 * (ds, ino, *). Two-phase: scan_range collects every probe under the
 * prefix into a heap buffer, then a second pass engine_deletes each
 * key. The two-phase pattern avoids mutating the engine during
 * scan_range traversal — safe-by-contract. */
typedef struct {
    uint64_t  *probes;
    size_t     n;
    size_t     cap;
    stm_status err;
} xa_drop_ctx;

static int xa_drop_cb(const void *k, size_t klen,
                      const void *v, size_t vlen, void *ctx_) {
    (void)v;                                /* drop reads keys only */
    (void)vlen;
    xa_drop_ctx *c = ctx_;
    uint64_t ino = 0, probe = 0;
    stm_status ks = xa_decode_key(k, klen, &ino, &probe);
    if (ks != STM_OK) { c->err = ks; return 1; }
    (void)ino;                          /* range bracket pins ino */

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

stm_status stm_xattr_drop_for_ino(stm_xattr_index *idx,
                                     uint64_t dataset_id, uint64_t ino,
                                     size_t *out_dropped) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    must_lock(idx_lock(idx));
    if (idx->ds_idx == NULL) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    stm_btree_engine *eng = NULL;
    stm_status es = xa_get_engine_locked(idx, dataset_id, &eng);
    if (es != STM_OK) {
        must_unlock(idx_lock(idx));
        /* Dataset not present → nothing to drop. */
        if (es == STM_ENOENT) {
            if (out_dropped) *out_dropped = 0;
            return STM_OK;
        }
        return es;
    }

    uint8_t lo[XA_KEY_LEN], hi[XA_KEY_LEN];
    stm_status k1 = xa_encode_key(ino, 0u,         lo);
    stm_status k2 = xa_encode_key(ino, UINT64_MAX, hi);
    if (k1 != STM_OK || k2 != STM_OK) {
        must_unlock(idx_lock(idx));
        return k1 != STM_OK ? k1 : k2;
    }

    xa_drop_ctx c = { .probes = NULL, .n = 0, .cap = 0, .err = STM_OK };
    stm_status ss = stm_btree_engine_scan_range(eng, lo, XA_KEY_LEN,
                                                hi, XA_KEY_LEN,
                                                xa_drop_cb, &c);
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
        stm_status ds = xa_engine_del(idx, dataset_id, ino, c.probes[i]);
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
