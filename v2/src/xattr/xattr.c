/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — xattr index implementation (P8-POSIX-6).
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
 *   - Variable-length VALUE field heap-allocated per record (up to
 *     STM_XATTR_VALUE_MAX = 64 KiB) rather than fixed-size embedded
 *     bytes — keeps the records[] array compact for inodes with many
 *     small xattrs.
 *   - POSIX setxattr flags (CREATE / REPLACE) layered atop the
 *     spec's basic Set action.
 *
 * On-disk encoding:
 *   - Key (24 bytes): le64 dataset_id || le64 ino || le64 hash_probe.
 *   - Value (16 + name_len + value_len bytes, tombstones 16 bytes):
 *     see xattr.h for the full byte-level layout.
 *
 * Concurrency: a single mutex guards records[] + persistence fields.
 * Lock posture: this layer takes its own lock only — no cross-layer
 * lock dependencies. The caller (sync.c) MUST not hold any other
 * xattr-comparable lock when invoking these APIs; sync.c does not.
 *
 * Audit-trigger surface: this module joins CLAUDE.md's trigger list
 * with this commit (P8-POSIX-6 substantive).
 */
#include <stratum/xattr.h>
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
/* Lock helpers — abort on misuse (dirent.c convention).               */
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

#define XA_KEY_LEN              24u
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

typedef struct {
    uint64_t dataset_id;
    uint64_t ino;
    uint64_t hash_probe;
    uint8_t  name_len;
    uint8_t  flags;          /* STM_XATTR_FLAG_TOMBSTONE on tombstone */
    uint8_t  name[STM_XATTR_NAME_MAX];
    uint32_t value_len;
    /* Heap-allocated value buffer (NULL iff value_len == 0). The
     * pointer is valid across records[] realloc (it points off-heap;
     * realloc relocates the array of structs but not the bytes
     * referenced by struct fields). Freed on Remove, replace, drop
     * for ino, load_at shadow-swap, and close. */
    uint8_t *value;
} stm_xattr_record;

struct stm_xattr_index {
    pthread_mutex_t      lock;
    stm_xattr_record    *records;
    size_t               n_records;
    size_t               cap_records;

    /* Persistence (mirrors stm_dirent_index, with R70 P3-6 latches). */
    stm_bdev       *bdev;
    stm_bootstrap  *boot;
    const uint8_t  *metadata_key;
    uint64_t        pool_uuid[2];
    uint64_t        device_uuid[2];
    bool            crypt_set;       /* latched on first set_crypt_ctx */
    bool            storage_set;     /* latched on first set_storage */
    uint64_t        root_paddr;
    uint64_t        root_gen;
    uint8_t         root_csum[32];
    bool            dirty;
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

/* Free a record's value buffer + clear its header to a tombstone-shaped
 * zero state (caller may then set TOMBSTONE flag if applicable, or
 * leave the slot for compaction). */
static void record_clear_value(stm_xattr_record *r) {
    if (r->value) {
        /* Note: not stm_ct_memzero — xattr values are user-controlled
         * but not key material. dirent's record_clear is similar. */
        free(r->value);
        r->value = NULL;
    }
    r->value_len = 0u;
}

/* ------------------------------------------------------------------ */
/* FNV-1a 64-bit hash (ARCH §11.5 — used to compute hash_probe).       */
/* Identical to dirent.c's fnv1a64; same offset basis + prime so the   */
/* hash function is the standard one. */
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
/* Internal helpers (caller holds idx->lock).                          */
/* ------------------------------------------------------------------ */

/* Linear scan for a record at exact key (ds, ino, probe). NULL on
 * miss. Used by the chain walkers as the per-step "is there a record
 * at probe k?" check — semantic equivalent to "slot[k] EMPTY iff
 * find returns NULL". */
static stm_xattr_record *find_record_at_probe(stm_xattr_index *idx,
                                                    uint64_t dataset_id,
                                                    uint64_t ino,
                                                    uint64_t hash_probe) {
    for (size_t i = 0; i < idx->n_records; i++) {
        stm_xattr_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id &&
            r->ino        == ino &&
            r->hash_probe == hash_probe) return r;
    }
    return NULL;
}

static const stm_xattr_record *find_record_at_probe_c(
        const stm_xattr_index *idx,
        uint64_t dataset_id, uint64_t ino, uint64_t hash_probe) {
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_xattr_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id &&
            r->ino        == ino &&
            r->hash_probe == hash_probe) return r;
    }
    return NULL;
}

/* Append a fresh record. Returns NULL only on STM_ENOMEM.
 * R71b P3-1: cap-doubling guard tightened to bound the
 * `* sizeof` multiplication. */
static stm_xattr_record *append_record(stm_xattr_index *idx) {
    if (idx->n_records == idx->cap_records) {
        if (idx->cap_records > (SIZE_MAX / sizeof *idx->records) / 2u)
            return NULL;
        size_t new_cap = idx->cap_records ? idx->cap_records * 2u : 8u;
        stm_xattr_record *new_arr =
                realloc(idx->records, new_cap * sizeof *new_arr);
        if (!new_arr) return NULL;
        idx->records     = new_arr;
        idx->cap_records = new_cap;
    }
    stm_xattr_record *r = &idx->records[idx->n_records++];
    memset(r, 0, sizeof *r);
    return r;
}

/* ------------------------------------------------------------------ */
/* On-disk key/value encoding.                                         */
/* ------------------------------------------------------------------ */

static void xa_encode_key(uint64_t dataset_id, uint64_t ino,
                              uint64_t hash_probe, uint8_t out[XA_KEY_LEN]) {
    le64 ds = stm_store_le64(dataset_id);
    le64 in = stm_store_le64(ino);
    le64 hp = stm_store_le64(hash_probe);
    memcpy(out + 0,  ds.v, 8);
    memcpy(out + 8,  in.v, 8);
    memcpy(out + 16, hp.v, 8);
}

static stm_status xa_decode_key(const void *in, size_t in_len,
                                    uint64_t *out_ds, uint64_t *out_ino,
                                    uint64_t *out_probe) {
    if (in_len != XA_KEY_LEN) return STM_ECORRUPT;
    le64 ds_le, in_le, hp_le;
    memcpy(ds_le.v, (const uint8_t *)in + 0,  8);
    memcpy(in_le.v, (const uint8_t *)in + 8,  8);
    memcpy(hp_le.v, (const uint8_t *)in + 16, 8);
    *out_ds    = stm_load_le64(ds_le);
    *out_ino   = stm_load_le64(in_le);
    *out_probe = stm_load_le64(hp_le);
    return STM_OK;
}

/* Encode a record into out[]; out must be ≥ XA_VAL_FIXED + r->name_len
 * + r->value_len bytes. Caller writes the result via btree_mt_insert
 * with the returned length. */
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
    if (r->value_len > 0u && r->value) {
        memcpy(out + XA_VAL_FIXED + r->name_len, r->value, r->value_len);
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
 * (caller takes ownership; freed via record_clear_value on
 * subsequent Remove/replace/drop_for_ino/close). */
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
/* btree_store vtable — same shape as dirent_index's.                   */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} xa_store_ctx;

static stm_status xa_store_reserve(void *ctx_, uint64_t *out_paddr) {
    xa_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status xa_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen) {
    xa_store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status xa_store_write(void *ctx_, uint64_t paddr,
                                     const void *buf, size_t len) {
    xa_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status xa_store_read(void *ctx_, uint64_t paddr,
                                    void *buf, size_t len) {
    xa_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable XA_STORE_VT = {
    .reserve = xa_store_reserve,
    .free    = xa_store_free,
    .write   = xa_store_write,
    .read    = xa_store_read,
};

static inline xa_store_ctx xa_make_store_ctx(stm_xattr_index *idx) {
    xa_store_ctx c = { .boot = idx->boot, .bdev = idx->bdev };
    return c;
}

static inline stm_btree_crypt_ctx xa_make_crypt_ctx(const stm_xattr_index *idx) {
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
    /* Free every record's heap-allocated value before freeing the
     * records[] array itself. */
    for (size_t i = 0; i < idx->n_records; i++) {
        record_clear_value(&idx->records[i]);
    }
    free(idx->records);
    free(idx);
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

/* Helper: install bytes into target's (name, value) slot. Frees any
 * existing value (POSIX setxattr replace-or-create). Allocates new
 * buffer for value if value_len > 0. Returns STM_ENOMEM if the new
 * value buffer can't be allocated. On STM_ENOMEM, target's prior
 * state is preserved (we malloc a fresh buffer BEFORE freeing the
 * old one). */
static stm_status install_bytes(stm_xattr_record *target,
                                      uint64_t dataset_id, uint64_t ino,
                                      uint64_t hash_probe,
                                      const uint8_t *name, uint8_t name_len,
                                      const uint8_t *value, uint32_t value_len) {
    uint8_t *new_value = NULL;
    if (value_len > 0u) {
        new_value = malloc(value_len);
        if (!new_value) return STM_ENOMEM;
        memcpy(new_value, value, value_len);
    }
    /* Now safe to free old. */
    if (target->value) {
        free(target->value);
        target->value = NULL;
    }
    target->dataset_id = dataset_id;
    target->ino        = ino;
    target->hash_probe = hash_probe;
    target->name_len   = name_len;
    target->flags      = 0u;
    memset(target->name, 0, sizeof target->name);
    memcpy(target->name, name, name_len);
    target->value_len  = value_len;
    target->value      = new_value;
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

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    /* Walk the chain. Track the FIRST install-eligible slot (EMPTY or
     * TOMBSTONE) but keep walking to verify whether the name is
     * already linked further in the chain. If it is, we replace
     * in-place at that slot (POSIX setxattr default semantics). */
    bool     have_install_slot = false;
    uint64_t install_probe     = 0;
    stm_xattr_record *install_tomb = NULL;  /* non-NULL iff install_probe is a TOMBSTONE */
    stm_xattr_record *existing    = NULL;
    uint64_t existing_probe       = 0;

    for (uint32_t k = 0; k < STM_XATTR_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_xattr_record *r =
                find_record_at_probe(idx, dataset_id, ino, probe);
        if (!r) {
            /* EMPTY — chain ends here. Install at first install slot
             * (this EMPTY if none earlier was found). */
            if (!have_install_slot) {
                install_probe     = probe;
                install_tomb      = NULL;
                have_install_slot = true;
            }
            break;
        }
        if (record_is_tombstone(r)) {
            if (!have_install_slot) {
                install_probe     = probe;
                install_tomb      = r;
                have_install_slot = true;
            }
            continue;
        }
        if (record_name_eq(r, name, name_len)) {
            existing       = r;
            existing_probe = probe;
            break;
        }
        /* Different live name → continue probing. */
    }

    /* Apply POSIX setxattr flag semantics. */
    if (existing) {
        if (flags & STM_XATTR_FLAG_CREATE) {
            must_unlock(idx_lock(idx));
            return STM_EEXIST;
        }
        /* REPLACE or default: rewrite the existing record. */
        stm_status is = install_bytes(existing, dataset_id, ino,
                                            existing_probe,
                                            name, name_len,
                                            value, value_len);
        if (is != STM_OK) {
            must_unlock(idx_lock(idx));
            return is;
        }
        idx->dirty = true;
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

    /* Install at install_probe. */
    stm_xattr_record *target;
    if (install_tomb) {
        target = install_tomb;
    } else {
        target = append_record(idx);
        if (!target) {
            must_unlock(idx_lock(idx));
            return STM_ENOMEM;
        }
    }
    stm_status is = install_bytes(target, dataset_id, ino, install_probe,
                                        name, name_len, value, value_len);
    if (is != STM_OK) {
        /* Note: target may be a freshly-appended record on STM_ENOMEM.
         * Leaving it in records[] with all-zero header (memset by
         * append_record) is safe — find_record_at_probe matches by
         * (ds, ino, hash_probe), and zero ds rejects every future
         * lookup. The next append_record reuses; cap-doubling not
         * triggered. Bookkeeping cost is one zero record per OOM,
         * bounded by the OOM rate; tolerable. */
        must_unlock(idx_lock(idx));
        return is;
    }
    idx->dirty = true;

    must_unlock(idx_lock(idx));
    return STM_OK;
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

    must_lock(idx_lock(idx));

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_XATTR_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        const stm_xattr_record *r =
                find_record_at_probe_c(idx, dataset_id, ino, probe);
        if (!r) {
            /* EMPTY — chain ends. */
            must_unlock(idx_lock(idx));
            return STM_ENODATA;
        }
        if (record_is_tombstone(r)) continue;
        if (record_name_eq(r, name, name_len)) {
            /* R77 P1-1 defense-in-depth: re-cap value_len before any
             * memcpy. The decoder + writer both bound value_len ≤
             * STM_XATTR_VALUE_MAX, so a record exceeding the cap is
             * unreachable through legitimate paths — but the explicit
             * cap here closes any future-bypass surface. */
            if (r->value_len > STM_XATTR_VALUE_MAX) {
                must_unlock(idx_lock(idx));
                return STM_ECORRUPT;
            }
            *out_size = r->value_len;
            if (value_max == 0u) {
                /* Probe-only call; no copy. */
                must_unlock(idx_lock(idx));
                return STM_OK;
            }
            if (value_max < r->value_len) {
                must_unlock(idx_lock(idx));
                return STM_ERANGE;
            }
            if (r->value_len > 0u && r->value) {
                memcpy(value_buf, r->value, r->value_len);
            }
            must_unlock(idx_lock(idx));
            return STM_OK;
        }
    }

    must_unlock(idx_lock(idx));
    return STM_ENODATA;
}

stm_status stm_xattr_remove(stm_xattr_index *idx,
                               uint64_t dataset_id, uint64_t ino,
                               const uint8_t *name, uint8_t name_len) {
    if (!idx || !name) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_XATTR_NAME_MAX) return STM_EINVAL;

    must_lock(idx_lock(idx));

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_XATTR_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_xattr_record *r =
                find_record_at_probe(idx, dataset_id, ino, probe);
        if (!r) {
            must_unlock(idx_lock(idx));
            return STM_ENODATA;
        }
        if (record_is_tombstone(r)) continue;
        if (record_name_eq(r, name, name_len)) {
            /* Replace with TOMBSTONE — preserves chain integrity for
             * colliding names at higher probe indices. Free the
             * value bytes; clear the name buffer; keep ds/ino/probe
             * for the chain walk, set tombstone flag. */
            record_clear_value(r);
            r->name_len = 0;
            r->flags    = STM_XATTR_FLAG_TOMBSTONE;
            memset(r->name, 0, sizeof r->name);
            idx->dirty = true;
            must_unlock(idx_lock(idx));
            return STM_OK;
        }
    }

    must_unlock(idx_lock(idx));
    return STM_ENODATA;
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

    must_lock(idx_lock(idx));

    /* Pass 1: count live matches. */
    size_t n_total = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_xattr_record *r = &idx->records[i];
        if (r->dataset_id != dataset_id) continue;
        if (r->ino        != ino)        continue;
        if (record_is_tombstone(r))      continue;
        n_total++;
    }
    *out_total = n_total;

    if (max_entries == 0u) {
        must_unlock(idx_lock(idx));
        return STM_OK;
    }

    if (max_entries < n_total) {
        must_unlock(idx_lock(idx));
        return STM_ERANGE;
    }

    /* Pass 2: copy out. Order is records[]'s natural order — we don't
     * sort by hash_probe here because POSIX listxattr doesn't promise
     * any order, and tests can compute a stable order by pairing
     * names. */
    size_t j = 0;
    for (size_t i = 0; i < idx->n_records && j < n_total; i++) {
        const stm_xattr_record *r = &idx->records[i];
        if (r->dataset_id != dataset_id) continue;
        if (r->ino        != ino)        continue;
        if (record_is_tombstone(r))      continue;
        out_entries[j].hash_probe = r->hash_probe;
        out_entries[j].name_len   = r->name_len;
        memset(out_entries[j].name, 0, sizeof out_entries[j].name);
        if (r->name_len > 0u) {
            memcpy(out_entries[j].name, r->name, r->name_len);
        }
        out_entries[j].value_len = r->value_len;
        j++;
    }

    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_xattr_drop_for_ino(stm_xattr_index *idx,
                                     uint64_t dataset_id, uint64_t ino,
                                     size_t *out_dropped) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    must_lock(idx_lock(idx));

    size_t kept = 0;
    size_t dropped = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        stm_xattr_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id && r->ino == ino) {
            /* Free heap value before dropping. */
            record_clear_value(r);
            dropped++;
            continue;
        }
        if (kept != i) {
            idx->records[kept] = *r;
            /* The struct copy transferred the (uint8_t *)value
             * pointer from the source. The source slot is being
             * abandoned (i > kept means src at i is one being
             * compacted out, dst at kept is one being preserved).
             * We must NOT double-free or leak. The source pointer
             * is now solely owned by records[kept]; clear records[i]
             * to avoid confusion at the next iteration if i happens
             * to be re-read. */
            r->value = NULL;
            r->value_len = 0;
        }
        kept++;
    }
    idx->n_records = kept;
    if (dropped > 0u) idx->dirty = true;
    if (out_dropped) *out_dropped = dropped;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

/* ------------------------------------------------------------------ */
/* Public API — persistence (mirrors stm_dirent_index).                 */
/* ------------------------------------------------------------------ */

stm_status stm_xattr_index_set_storage(stm_xattr_index *idx,
                                          stm_bdev *bdev_0,
                                          stm_bootstrap *boot_0) {
    if (!idx || !bdev_0 || !boot_0) return STM_EINVAL;
    must_lock(idx_lock(idx));
    if (idx->storage_set) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    idx->bdev = bdev_0;
    idx->boot = boot_0;
    idx->storage_set = true;
    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_xattr_index_set_crypt_ctx(stm_xattr_index *idx,
                                            const uint8_t *metadata_key,
                                            const uint64_t pool_uuid[2],
                                            const uint64_t device_uuid_0[2]) {
    if (!idx || !metadata_key || !pool_uuid || !device_uuid_0) return STM_EINVAL;
    must_lock(idx_lock(idx));
    if (idx->crypt_set) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }
    idx->metadata_key   = metadata_key;
    idx->pool_uuid[0]   = pool_uuid[0];
    idx->pool_uuid[1]   = pool_uuid[1];
    idx->device_uuid[0] = device_uuid_0[0];
    idx->device_uuid[1] = device_uuid_0[1];
    idx->crypt_set      = true;
    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_xattr_index_get_root(const stm_xattr_index *idx,
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

stm_status stm_xattr_index_get_gen(const stm_xattr_index *idx,
                                      uint64_t *out_root_gen) {
    if (!idx || !out_root_gen) return STM_EINVAL;
    pthread_mutex_t *lock = idx_lock(idx);
    must_lock(lock);
    *out_root_gen = idx->root_gen;
    must_unlock(lock);
    return STM_OK;
}

/* Build a btree from records[] for serialization. */
static stm_status xa_build_btree_locked(const stm_xattr_index *idx,
                                              stm_btree_mt **out_tree) {
    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;

    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) return ts;

    uint8_t key[XA_KEY_LEN];
    /* Variable-length value: allocate the worst-case buffer once and
     * reuse. XA_VAL_MAX (16 + 255 + 65536 = 65807 bytes) on the heap
     * to avoid stack pressure. */
    uint8_t *val = malloc(XA_VAL_MAX);
    if (!val) {
        stm_btree_mt_free(t);
        return STM_ENOMEM;
    }
    size_t  vlen;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_xattr_record *r = &idx->records[i];
        xa_encode_key(r->dataset_id, r->ino, r->hash_probe, key);
        xa_encode_value(r, val, &vlen);
        stm_status is = stm_btree_mt_insert(t, key, XA_KEY_LEN, val, vlen);
        if (is != STM_OK) { free(val); stm_btree_mt_free(t); return is; }
    }

    free(val);
    *out_tree = t;
    return STM_OK;
}

stm_status stm_xattr_index_commit(stm_xattr_index *idx,
                                     uint64_t committed_gen,
                                     uint64_t *out_root_paddr,
                                     uint8_t out_root_csum[32]) {
    if (!idx || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    must_lock(idx_lock(idx));

    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    /* Clean + already-committed: idempotent return of the existing root. */
    if (!idx->dirty && idx->root_paddr != 0) {
        *out_root_paddr = idx->root_paddr;
        memcpy(out_root_csum, idx->root_csum, 32);
        must_unlock(idx_lock(idx));
        return STM_OK;
    }

    stm_btree_mt *t = NULL;
    stm_status bs = xa_build_btree_locked(idx, &t);
    if (bs != STM_OK) {
        must_unlock(idx_lock(idx));
        return bs;
    }

    xa_store_ctx        sc = xa_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = xa_make_crypt_ctx(idx);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(t, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &XA_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    stm_btree_mt_free(t);
    if (ss != STM_OK) {
        must_unlock(idx_lock(idx));
        return ss;
    }

    #define XA_ROLLBACK_RESERVE() \
        do { (void)stm_btree_store_free_tree(new_paddr, committed_gen,  \
                                                committed_gen, new_csum, \
                                                &XA_STORE_VT, &sc, &cx); \
        } while (0)

    if (idx->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(idx->root_paddr,
                                                     idx->root_gen,
                                                     committed_gen,
                                                     idx->root_csum,
                                                     &XA_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            XA_ROLLBACK_RESERVE();
            must_unlock(idx_lock(idx));
            return fs;
        }
    }

    stm_status bsc = stm_bootstrap_commit(idx->boot, committed_gen);
    if (bsc != STM_OK) {
        XA_ROLLBACK_RESERVE();
        must_unlock(idx_lock(idx));
        return bsc;
    }
    #undef XA_ROLLBACK_RESERVE

    idx->root_paddr = new_paddr;
    idx->root_gen   = committed_gen;
    memcpy(idx->root_csum, new_csum, 32);
    idx->dirty      = false;

    *out_root_paddr = new_paddr;
    memcpy(out_root_csum, new_csum, 32);
    must_unlock(idx_lock(idx));
    return STM_OK;
}

/* load_at — atomic shadow swap. */

typedef struct {
    stm_xattr_record  *shadow;
    size_t             shadow_len;
    size_t             shadow_cap;
    stm_status         err;
} xa_load_ctx;

static stm_status xa_shadow_append(xa_load_ctx *lc,
                                       const stm_xattr_record *r) {
    if (lc->shadow_len == lc->shadow_cap) {
        if (lc->shadow_cap > (SIZE_MAX / sizeof *lc->shadow) / 2u) return STM_ENOMEM;
        size_t new_cap = lc->shadow_cap == 0 ? 8u : lc->shadow_cap * 2u;
        stm_xattr_record *new_buf = realloc(lc->shadow,
                                                 new_cap * sizeof *new_buf);
        if (!new_buf) return STM_ENOMEM;
        lc->shadow     = new_buf;
        lc->shadow_cap = new_cap;
    }
    lc->shadow[lc->shadow_len++] = *r;
    /* Caller's `r` continues to own the value pointer until we assume
     * ownership here. The struct-copy transferred the pointer; caller
     * MUST NOT free it. We document this contract in xa_load_iter. */
    return STM_OK;
}

static int xa_load_iter(const void *k, size_t klen,
                            const void *v, size_t vlen, void *ctx_) {
    xa_load_ctx *lc = ctx_;
    uint64_t ds = 0, ino = 0, probe = 0;
    stm_status ks = xa_decode_key(k, klen, &ds, &ino, &probe);
    if (ks != STM_OK) { lc->err = ks; return 1; }
    if (ds == 0u || ino == 0u) { lc->err = STM_ECORRUPT; return 1; }

    stm_xattr_record r;
    memset(&r, 0, sizeof r);
    /* xa_decode_value heap-allocates r.value if value_len > 0. The
     * shadow_append below transfers ownership to the shadow buffer.
     * On error before append we must free r.value. */
    stm_status vs = xa_decode_value(v, vlen, &r);
    if (vs != STM_OK) { lc->err = vs; return 1; }

    r.dataset_id = ds;
    r.ino        = ino;
    r.hash_probe = probe;

    stm_status as = xa_shadow_append(lc, &r);
    if (as != STM_OK) {
        /* Append failed; free our heap value before returning so it
         * doesn't leak. */
        if (r.value) free(r.value);
        lc->err = as;
        return 1;
    }
    return 0;
}

stm_status stm_xattr_index_load_at(stm_xattr_index *idx,
                                      uint64_t root_paddr,
                                      uint64_t root_gen,
                                      const uint8_t expected_csum[32]) {
    if (!idx || !expected_csum) return STM_EINVAL;
    if (root_paddr == 0u) return STM_EINVAL;
    must_lock(idx_lock(idx));
    if (!idx->crypt_set || !idx->bdev || !idx->boot) {
        must_unlock(idx_lock(idx));
        return STM_EINVAL;
    }

    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;
    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) {
        must_unlock(idx_lock(idx));
        return ts;
    }

    xa_store_ctx        sc = xa_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = xa_make_crypt_ctx(idx);

    stm_status ds = stm_btree_store_deserialize(t, root_paddr, root_gen,
                                                   expected_csum,
                                                   &XA_STORE_VT, &sc, &cx);
    if (ds != STM_OK) {
        stm_btree_mt_free(t);
        must_unlock(idx_lock(idx));
        return ds;
    }

    xa_load_ctx lc = { .err = STM_OK };
    stm_status sr = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                         xa_load_iter, &lc);
    stm_btree_mt_free(t);
    if (sr != STM_OK) {
        /* Free any heap values inside the partially-built shadow
         * before discarding it. */
        for (size_t i = 0; i < lc.shadow_len; i++) {
            if (lc.shadow[i].value) free(lc.shadow[i].value);
        }
        free(lc.shadow);
        must_unlock(idx_lock(idx));
        return sr;
    }
    if (lc.err != STM_OK) {
        for (size_t i = 0; i < lc.shadow_len; i++) {
            if (lc.shadow[i].value) free(lc.shadow[i].value);
        }
        free(lc.shadow);
        must_unlock(idx_lock(idx));
        return lc.err;
    }

    /* Atomic shadow swap. Free old records' heap values + the records[]
     * array, then swap in shadow. */
    for (size_t i = 0; i < idx->n_records; i++) {
        record_clear_value(&idx->records[i]);
    }
    free(idx->records);
    idx->records     = lc.shadow;
    idx->n_records   = lc.shadow_len;
    idx->cap_records = lc.shadow_cap;
    idx->root_paddr  = root_paddr;
    idx->root_gen    = root_gen;
    memcpy(idx->root_csum, expected_csum, 32);
    idx->dirty       = false;

    must_unlock(idx_lock(idx));
    return STM_OK;
}
