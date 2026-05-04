/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — dirent index implementation (P8-POSIX-2).
 *
 * Spec: v2/specs/dirent.tla. Models open-addressing chain integrity
 * for directory entries keyed by `(dataset_id, dir_ino, hash_probe)`
 * where `hash_probe = fnv1a64(name) + probe_offset`. Per ARCH §11.4.
 *
 * On-disk encoding:
 *   - Key (24 bytes): le64 dataset_id || le64 dir_ino || le64 hash_probe.
 *   - Value (32 + name_len bytes, tombstones 32 bytes): see dirent.h
 *     for the full byte-level layout.
 *
 * Concurrency: a single mutex guards records[] + persistence fields.
 * Lock posture: this layer takes its own lock only — no cross-layer
 * lock dependencies. The caller (sync.c) MUST not hold any other
 * dirent-comparable lock when invoking these APIs; sync.c does not.
 *
 * Audit-trigger surface: this module joins CLAUDE.md's trigger list
 * with this commit (P8-POSIX-2 substantive).
 */
#include <stratum/dirent.h>
#include <stratum/dirent_testing.h>
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

#define DI_KEY_LEN              24u
#define DI_VAL_FIXED            32u
#define DI_VAL_MAX              (DI_VAL_FIXED + STM_DIRENT_NAME_MAX)

/* Reserved-bytes window inside the value (offset 19..32). */
#define DI_VAL_RESERVED_OFF     19u
#define DI_VAL_RESERVED_LEN     13u

/* ------------------------------------------------------------------ */
/* Internal record + index types.                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t dataset_id;
    uint64_t dir_ino;
    uint64_t hash_probe;
    uint64_t child_ino;
    uint64_t child_gen;
    uint8_t  child_type;
    uint8_t  name_len;
    uint8_t  flags;          /* STM_DIRENT_FLAG_TOMBSTONE on tombstone */
    uint8_t  name[STM_DIRENT_NAME_MAX];
} stm_dirent_record;

struct stm_dirent_index {
    pthread_mutex_t      lock;
    stm_dirent_record   *records;
    size_t               n_records;
    size_t               cap_records;

    /* Persistence (mirrors stm_inode_index, with R70 P3-6 latches). */
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
/* Internal helpers (caller holds idx->lock).                          */
/* ------------------------------------------------------------------ */

/* Linear scan for a record at exact key (ds, dir_ino, probe). NULL on
 * miss. Used by the chain walkers as the per-step "is there a record
 * at probe k?" check — semantic equivalent to "slot[k] EMPTY iff
 * find returns NULL". */
static stm_dirent_record *find_record_at_probe(stm_dirent_index *idx,
                                                    uint64_t dataset_id,
                                                    uint64_t dir_ino,
                                                    uint64_t hash_probe) {
    for (size_t i = 0; i < idx->n_records; i++) {
        stm_dirent_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id &&
            r->dir_ino    == dir_ino &&
            r->hash_probe == hash_probe) return r;
    }
    return NULL;
}

static const stm_dirent_record *find_record_at_probe_c(
        const stm_dirent_index *idx,
        uint64_t dataset_id, uint64_t dir_ino, uint64_t hash_probe) {
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_dirent_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id &&
            r->dir_ino    == dir_ino &&
            r->hash_probe == hash_probe) return r;
    }
    return NULL;
}

/* Append a fresh record. Returns NULL only on STM_ENOMEM.
 * R71b P3-1: cap-doubling guard tightened to bound the
 * `* sizeof` multiplication. */
static stm_dirent_record *append_record(stm_dirent_index *idx) {
    if (idx->n_records == idx->cap_records) {
        if (idx->cap_records > (SIZE_MAX / sizeof *idx->records) / 2u)
            return NULL;
        size_t new_cap = idx->cap_records ? idx->cap_records * 2u : 8u;
        stm_dirent_record *new_arr =
                realloc(idx->records, new_cap * sizeof *new_arr);
        if (!new_arr) return NULL;
        idx->records     = new_arr;
        idx->cap_records = new_cap;
    }
    stm_dirent_record *r = &idx->records[idx->n_records++];
    memset(r, 0, sizeof *r);
    return r;
}

/* ------------------------------------------------------------------ */
/* On-disk key/value encoding.                                         */
/* ------------------------------------------------------------------ */

static void di_encode_key(uint64_t dataset_id, uint64_t dir_ino,
                              uint64_t hash_probe, uint8_t out[DI_KEY_LEN]) {
    le64 ds = stm_store_le64(dataset_id);
    le64 di = stm_store_le64(dir_ino);
    le64 hp = stm_store_le64(hash_probe);
    memcpy(out + 0,  ds.v, 8);
    memcpy(out + 8,  di.v, 8);
    memcpy(out + 16, hp.v, 8);
}

static stm_status di_decode_key(const void *in, size_t in_len,
                                    uint64_t *out_ds, uint64_t *out_dir,
                                    uint64_t *out_probe) {
    if (in_len != DI_KEY_LEN) return STM_ECORRUPT;
    le64 ds_le, di_le, hp_le;
    memcpy(ds_le.v, (const uint8_t *)in + 0,  8);
    memcpy(di_le.v, (const uint8_t *)in + 8,  8);
    memcpy(hp_le.v, (const uint8_t *)in + 16, 8);
    *out_ds    = stm_load_le64(ds_le);
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
/* btree_store vtable — same shape as inode_index's.                   */
/* ------------------------------------------------------------------ */

typedef struct {
    stm_bootstrap *boot;
    stm_bdev      *bdev;
} di_store_ctx;

static stm_status di_store_reserve(void *ctx_, uint64_t *out_paddr) {
    di_store_ctx *ctx = ctx_;
    return stm_bootstrap_reserve(ctx->boot, STM_BOOTSTRAP_UNIT_BLOCKS,
                                   /*hint_paddr=*/0, out_paddr);
}

static stm_status di_store_free(void *ctx_, uint64_t paddr, uint64_t free_gen) {
    di_store_ctx *ctx = ctx_;
    return stm_bootstrap_free(ctx->boot, paddr, STM_BOOTSTRAP_UNIT_BLOCKS,
                                free_gen);
}

static stm_status di_store_write(void *ctx_, uint64_t paddr,
                                     const void *buf, size_t len) {
    di_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_write(ctx->bdev, byte_offset, buf, len);
}

static stm_status di_store_read(void *ctx_, uint64_t paddr,
                                    void *buf, size_t len) {
    di_store_ctx *ctx = ctx_;
    if (stm_paddr_device(paddr) != 0) return STM_EINVAL;
    uint64_t byte_offset = stm_paddr_offset(paddr) * (uint64_t)STM_UB_SIZE;
    return stm_bdev_read(ctx->bdev, byte_offset, buf, len);
}

static const stm_btree_store_vtable DI_STORE_VT = {
    .reserve = di_store_reserve,
    .free    = di_store_free,
    .write   = di_store_write,
    .read    = di_store_read,
};

static inline di_store_ctx di_make_store_ctx(stm_dirent_index *idx) {
    di_store_ctx c = { .boot = idx->boot, .bdev = idx->bdev };
    return c;
}

static inline stm_btree_crypt_ctx di_make_crypt_ctx(const stm_dirent_index *idx) {
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
    free(idx->records);
    free(idx);
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
     * different-named live record) — chain integrity preserved.
     * Whiteout-overwrite semantics are tested in test_dirent.c's
     * dirent_whiteout_then_create_overwrites_slot;
     * whiteout-preservation under hash collision is tested by
     * dirent_whiteout_preserved_under_hash_collision. */
    bool     have_install_slot = false;
    uint64_t install_probe     = 0;
    stm_dirent_record *install_existing = NULL;  /* tombstone or same-name whiteout to overwrite */

    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_dirent_record *r =
                find_record_at_probe(idx, dataset_id, dir_ino, probe);
        if (!r) {
            /* EMPTY — chain ends here. Install at first install slot
             * (this EMPTY if none earlier was found). */
            if (!have_install_slot) {
                install_probe     = probe;
                install_existing  = NULL;
                have_install_slot = true;
            }
            break;
        }
        if (record_is_tombstone(r)) {
            if (!have_install_slot) {
                install_probe     = probe;
                install_existing  = r;
                have_install_slot = true;
            }
            continue;
        }
        if (record_is_whiteout(r)) {
            /* SAME-NAME whiteout: install candidate (overlayfs
             * "promote name" — overwrites the whiteout with a
             * fresh live record at the same name). DIFFERENT-NAME
             * whiteout: MUST be preserved to honor RENAME_WHITEOUT's
             * persistence contract — walk past it as an occupying
             * slot. (R88 P2-1) */
            if (record_name_eq(r, name, name_len)) {
                if (!have_install_slot) {
                    install_probe     = probe;
                    install_existing  = r;
                    have_install_slot = true;
                }
            }
            continue;
        }
        if (record_name_eq(r, name, name_len)) {
            must_unlock(idx_lock(idx));
            return STM_EEXIST;
        }
        /* Different live name → continue probing. */
    }

    if (!have_install_slot) {
        must_unlock(idx_lock(idx));
        return STM_ENOSPC;
    }

    /* Install at install_probe. */
    stm_dirent_record *target;
    if (install_existing) {
        target = install_existing;
    } else {
        target = append_record(idx);
        if (!target) {
            must_unlock(idx_lock(idx));
            return STM_ENOMEM;
        }
    }
    target->dataset_id = dataset_id;
    target->dir_ino    = dir_ino;
    target->hash_probe = install_probe;
    target->child_ino  = child_ino;
    target->child_gen  = child_gen;
    target->child_type = child_type;
    target->name_len   = name_len;
    target->flags      = 0u;
    memset(target->name, 0, sizeof target->name);
    memcpy(target->name, name, name_len);
    idx->dirty = true;

    must_unlock(idx_lock(idx));
    return STM_OK;
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

    must_lock(idx_lock(idx));

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        const stm_dirent_record *r =
                find_record_at_probe_c(idx, dataset_id, dir_ino, probe);
        if (!r) {
            /* EMPTY — chain ends. */
            must_unlock(idx_lock(idx));
            return STM_ENOENT;
        }
        if (record_is_tombstone(r)) continue;
        if (record_is_whiteout(r)) {
            /* P8-POSIX-9b: a matching whiteout HIDES the name from
             * lookup view (overlayfs interprets via readdir).
             * Non-matching whiteout slots preserve chain integrity
             * for colliding names — continue probing past them. */
            if (record_name_eq(r, name, name_len)) {
                must_unlock(idx_lock(idx));
                return STM_ENOENT;
            }
            continue;
        }
        if (record_name_eq(r, name, name_len)) {
            *out_child_ino = r->child_ino;
            if (out_child_gen)  *out_child_gen  = r->child_gen;
            if (out_child_type) *out_child_type = r->child_type;
            must_unlock(idx_lock(idx));
            return STM_OK;
        }
    }

    must_unlock(idx_lock(idx));
    return STM_ENOENT;
}

stm_status stm_dirent_unlink(stm_dirent_index *idx,
                                 uint64_t dataset_id, uint64_t dir_ino,
                                 const uint8_t *name, uint8_t name_len) {
    if (!idx || !name) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_DIRENT_NAME_MAX) return STM_EINVAL;

    must_lock(idx_lock(idx));

    uint64_t hash_base = fnv1a64(name, (size_t)name_len);

    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_dirent_record *r =
                find_record_at_probe(idx, dataset_id, dir_ino, probe);
        if (!r) {
            must_unlock(idx_lock(idx));
            return STM_ENOENT;
        }
        if (record_is_tombstone(r)) continue;
        if (record_is_whiteout(r)) {
            /* P8-POSIX-9b: a matching whiteout name has no live
             * record to unlink — return ENOENT. Non-matching
             * whiteouts preserve chain integrity (continue probing). */
            if (record_name_eq(r, name, name_len)) {
                must_unlock(idx_lock(idx));
                return STM_ENOENT;
            }
            continue;
        }
        if (record_name_eq(r, name, name_len)) {
            /* Replace with TOMBSTONE — preserves chain integrity for
             * colliding names at higher probe indices. */
            r->child_ino  = 0;
            r->child_gen  = 0;
            r->child_type = 0;
            r->name_len   = 0;
            r->flags      = STM_DIRENT_FLAG_TOMBSTONE;
            memset(r->name, 0, sizeof r->name);
            idx->dirty = true;
            must_unlock(idx_lock(idx));
            return STM_OK;
        }
    }

    must_unlock(idx_lock(idx));
    return STM_ENOENT;
}

/* P8-POSIX-9b: helper that walks the chain to locate the live
 * record at (dataset_id, dir_ino, name). Returns NULL if not
 * found OR if the chain runs into EMPTY before the name appears.
 * Whiteouts are NOT live records — a matching whiteout returns
 * NULL (caller sees this as ENOENT). Non-matching whiteouts
 * preserve chain integrity (continue probing). Caller MUST
 * hold the index mutex. */
static stm_dirent_record *
find_live_record(stm_dirent_index *idx, uint64_t dataset_id,
                      uint64_t dir_ino,
                      const uint8_t *name, uint8_t name_len)
{
    uint64_t hash_base = fnv1a64(name, (size_t)name_len);
    for (uint32_t k = 0; k < STM_DIRENT_PROBE_MAX; k++) {
        uint64_t probe = hash_base + (uint64_t)k;
        stm_dirent_record *r =
                find_record_at_probe(idx, dataset_id, dir_ino, probe);
        if (!r) return NULL;   /* EMPTY — chain ends */
        if (record_is_tombstone(r)) continue;
        if (record_is_whiteout(r)) {
            if (record_name_eq(r, name, name_len)) return NULL;
            continue;
        }
        if (record_name_eq(r, name, name_len)) return r;
    }
    return NULL;
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
     * this same mutex). Don't introduce a separate iter_active
     * flag without simultaneously redesigning readdir to release
     * the mutex between cursor steps; today both serialize through
     * the same lock and the spec precondition is satisfied de facto. */
    must_lock(idx_lock(idx));

    stm_dirent_record *r1 =
            find_live_record(idx, dataset_id, dir1_ino, name1, name1_len);
    if (!r1) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }
    stm_dirent_record *r2 =
            find_live_record(idx, dataset_id, dir2_ino, name2, name2_len);
    if (!r2) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }

    /* Swap (child_ino, child_gen, child_type). Slot positions +
     * names + flags + name_len UNCHANGED — chain integrity by
     * construction. */
    uint64_t c_ino  = r1->child_ino;
    uint64_t c_gen  = r1->child_gen;
    uint8_t  c_type = r1->child_type;
    r1->child_ino  = r2->child_ino;
    r1->child_gen  = r2->child_gen;
    r1->child_type = r2->child_type;
    r2->child_ino  = c_ino;
    r2->child_gen  = c_gen;
    r2->child_type = c_type;
    idx->dirty = true;

    must_unlock(idx_lock(idx));
    return STM_OK;
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

    stm_dirent_record *r =
            find_live_record(idx, dataset_id, dir_ino, name, name_len);
    if (!r) {
        must_unlock(idx_lock(idx));
        return STM_ENOENT;
    }

    /* Convert the live record to a WHITEOUT slot in place. Slot
     * position (hash_probe + array index) UNCHANGED — chain
     * integrity preserved by construction. The name field is
     * PRESERVED (so readdir can emit the marker). child_ino /
     * child_gen are CLEARED. child_type is reassigned to
     * STM_DT_WHITEOUT (Linux DT_WHT). The flags byte holds ONLY
     * the WHITEOUT bit (mutually exclusive with TOMBSTONE per
     * the decoder). */
    r->child_ino  = 0;
    r->child_gen  = 0;
    r->child_type = STM_DT_WHITEOUT;
    r->flags      = STM_DIRENT_FLAG_WHITEOUT;
    /* name + name_len UNCHANGED. */
    idx->dirty = true;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

stm_status stm_dirent_count_for_dir(const stm_dirent_index *idx,
                                        uint64_t dataset_id, uint64_t dir_ino,
                                        size_t *out_count) {
    if (!idx || !out_count) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;

    *out_count = 0;
    must_lock(idx_lock(idx));

    /* P8-POSIX-9b: only LIVE records count toward the directory's
     * link count. Tombstones (invisible) and whiteouts (visible-
     * to-readdir markers but no addressable child_ino) do not
     * contribute to nlink/empty-check semantics. A directory with
     * only whiteouts is empty for rmdir purposes (POSIX:
     * whiteouts shouldn't block rmdir per overlayfs semantics). */
    size_t count = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_dirent_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id &&
            r->dir_ino    == dir_ino &&
            record_is_live(r)) count++;
    }
    *out_count = count;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

/* P8-POSIX-4 readdir: emits live records under (ds, dir_ino) in
 * hash_probe-ascending order, starting at *cursor. Models dirent.tla's
 * ReaddirReset/Step/End cycle.
 *
 * Implementation: filter records[] for matches (ds, dir_ino, hp >=
 * cursor, !tombstone), copy match indices + probes into a temp buffer,
 * qsort by hash_probe, emit up to max_entries. Memory cost: one
 * malloc'd `(uint64_t hp, size_t idx)` pair per match. For a directory
 * with N total records, this is O(N) memory + O(N log N) time per
 * call. Future optimization (when xfstests stresses 1M-entry dirs):
 * top-K heap select with O(max_entries) memory + O(N log K) time.
 */
typedef struct {
    uint64_t hash_probe;
    size_t   record_idx;
} di_readdir_match;

static int di_readdir_match_cmp(const void *a, const void *b) {
    const di_readdir_match *pa = a, *pb = b;
    if (pa->hash_probe < pb->hash_probe) return -1;
    if (pa->hash_probe > pb->hash_probe) return  1;
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
     * validation step rejected. Mirrors the R57 P3-5 / R58 P3-1
     * uniform out-param contract used elsewhere in the codebase. */
    if (out_returned) *out_returned = 0;

    if (!idx || !cursor || !out_entries || !out_returned) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;
    if (max_entries == 0u) return STM_EINVAL;

    /* R75 P2-1: cursor saturation sentinel. Once the prior call's
     * cursor advance hit UINT64_MAX (either from `last_probe + 1`
     * saturation or because the highest live probe was UINT64_MAX
     * itself), iteration is done — short-circuit before the filter
     * loop. Without this guard, a record at probe=UINT64_MAX would
     * get re-emitted forever because the strict-less-than filter
     * `r->hash_probe < UINT64_MAX` is false at probe=UINT64_MAX. */
    if (*cursor == UINT64_MAX) return STM_OK;

    /* Cast away const for lock acquisition; idx is logically read-only
     * across this call but we need write access to its mutex. Mirrors
     * the const-cast in find_record_at_probe_c's lock pattern. */
    pthread_mutex_t *lk = idx_lock(idx);
    must_lock(lk);

    /* Pass 1: count matches.
     *
     * "Match" = same dataset_id + dir_ino + (live record OR whiteout)
     * + probe ≥ cursor. Tombstones are NEVER emitted (they're internal
     * chain-integrity markers). Whiteouts ARE emitted (P8-POSIX-9b —
     * Linux DT_WHT semantics; overlayfs userspace interprets the
     * marker). We allocate enough space for all matches even if many
     * exceed max_entries — the post-sort prefix gives the smallest
     * max_entries by probe, which is what readdir needs. */
    size_t n_match = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_dirent_record *r = &idx->records[i];
        if (r->dataset_id != dataset_id) continue;
        if (r->dir_ino    != dir_ino)    continue;
        if (record_is_tombstone(r))      continue;
        if (r->hash_probe < *cursor)     continue;
        n_match++;
    }
    if (n_match == 0) {
        /* No matches: leave *cursor unchanged, *out_returned = 0. */
        must_unlock(lk);
        return STM_OK;
    }

    /* Bounded multiplication: SIZE_MAX / sizeof guarantees no overflow. */
    if (n_match > SIZE_MAX / sizeof(di_readdir_match)) {
        must_unlock(lk);
        return STM_ENOMEM;
    }
    di_readdir_match *matches = malloc(n_match * sizeof *matches);
    if (!matches) {
        must_unlock(lk);
        return STM_ENOMEM;
    }

    /* Pass 2: collect matches. */
    size_t j = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_dirent_record *r = &idx->records[i];
        if (r->dataset_id != dataset_id) continue;
        if (r->dir_ino    != dir_ino)    continue;
        if (record_is_tombstone(r))      continue;
        if (r->hash_probe < *cursor)     continue;
        matches[j].hash_probe = r->hash_probe;
        matches[j].record_idx = i;
        j++;
    }
    /* j must equal n_match — both passes use identical filter. */

    qsort(matches, n_match, sizeof *matches, di_readdir_match_cmp);

    /* Emit prefix. */
    size_t emit = (max_entries < n_match) ? max_entries : n_match;
    for (size_t k = 0; k < emit; k++) {
        const stm_dirent_record *r = &idx->records[matches[k].record_idx];
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
     * UINT64_MAX so caller-side arithmetic doesn't wrap. The next
     * call resumes at this cursor; matches with probe < cursor are
     * filtered out, ensuring strict monotone advance per
     * dirent.tla::ReaddirCursorMonotonicEmits. */
    uint64_t last_probe = matches[emit - 1].hash_probe;
    *cursor = (last_probe == UINT64_MAX) ? UINT64_MAX : (last_probe + 1u);
    *out_returned = emit;

    free(matches);
    must_unlock(lk);
    return STM_OK;
}

/* P8-POSIX-2b R73 P2-1: bulk-drop every record keyed at (ds, dir_ino,
 * *). Walks records[] once, compacts in place. After this returns the
 * dirent btree on the next sync_commit will not encode any record at
 * that (ds, dir_ino) prefix — including tombstones from prior unlinks. */
stm_status stm_dirent_drop_for_dir(stm_dirent_index *idx,
                                       uint64_t dataset_id, uint64_t dir_ino,
                                       size_t *out_dropped) {
    if (!idx) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u) return STM_EINVAL;

    must_lock(idx_lock(idx));

    size_t kept = 0;
    size_t dropped = 0;
    for (size_t i = 0; i < idx->n_records; i++) {
        stm_dirent_record *r = &idx->records[i];
        if (r->dataset_id == dataset_id && r->dir_ino == dir_ino) {
            dropped++;
            continue;
        }
        if (kept != i) {
            idx->records[kept] = *r;
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
/* Public API — persistence (mirrors stm_inode_index).                  */
/* ------------------------------------------------------------------ */

stm_status stm_dirent_index_set_storage(stm_dirent_index *idx,
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

stm_status stm_dirent_index_set_crypt_ctx(stm_dirent_index *idx,
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

stm_status stm_dirent_index_get_root(const stm_dirent_index *idx,
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

stm_status stm_dirent_index_get_gen(const stm_dirent_index *idx,
                                        uint64_t *out_root_gen) {
    if (!idx || !out_root_gen) return STM_EINVAL;
    pthread_mutex_t *lock = idx_lock(idx);
    must_lock(lock);
    *out_root_gen = idx->root_gen;
    must_unlock(lock);
    return STM_OK;
}

/* Build a btree from records[] for serialization. */
static stm_status di_build_btree_locked(const stm_dirent_index *idx,
                                              stm_btree_mt **out_tree) {
    stm_btree_opts opts = stm_btree_opts_default();
    if (opts.target_entries < 512u) opts.target_entries = 512u;

    stm_btree_mt *t = NULL;
    stm_status ts = stm_btree_mt_new(&opts, &t);
    if (ts != STM_OK) return ts;

    uint8_t key[DI_KEY_LEN];
    uint8_t val[DI_VAL_MAX];
    size_t  vlen;
    for (size_t i = 0; i < idx->n_records; i++) {
        const stm_dirent_record *r = &idx->records[i];
        di_encode_key(r->dataset_id, r->dir_ino, r->hash_probe, key);
        di_encode_value(r, val, &vlen);
        stm_status is = stm_btree_mt_insert(t, key, DI_KEY_LEN, val, vlen);
        if (is != STM_OK) { stm_btree_mt_free(t); return is; }
    }

    *out_tree = t;
    return STM_OK;
}

stm_status stm_dirent_index_commit(stm_dirent_index *idx,
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
    stm_status bs = di_build_btree_locked(idx, &t);
    if (bs != STM_OK) {
        must_unlock(idx_lock(idx));
        return bs;
    }

    di_store_ctx        sc = di_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = di_make_crypt_ctx(idx);

    uint64_t new_paddr = 0;
    uint8_t  new_csum[32];
    stm_status ss = stm_btree_store_serialize(t, committed_gen,
                                                 /*tree_id=*/0u,
                                                 &DI_STORE_VT, &sc, &cx,
                                                 &new_paddr, new_csum);
    stm_btree_mt_free(t);
    if (ss != STM_OK) {
        must_unlock(idx_lock(idx));
        return ss;
    }

    #define DI_ROLLBACK_RESERVE() \
        do { (void)stm_btree_store_free_tree(new_paddr, committed_gen,  \
                                                committed_gen, new_csum, \
                                                &DI_STORE_VT, &sc, &cx); \
        } while (0)

    if (idx->root_paddr != 0) {
        stm_status fs = stm_btree_store_free_tree(idx->root_paddr,
                                                     idx->root_gen,
                                                     committed_gen,
                                                     idx->root_csum,
                                                     &DI_STORE_VT, &sc, &cx);
        if (fs != STM_OK) {
            DI_ROLLBACK_RESERVE();
            must_unlock(idx_lock(idx));
            return fs;
        }
    }

    stm_status bsc = stm_bootstrap_commit(idx->boot, committed_gen);
    if (bsc != STM_OK) {
        DI_ROLLBACK_RESERVE();
        must_unlock(idx_lock(idx));
        return bsc;
    }
    #undef DI_ROLLBACK_RESERVE

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
    stm_dirent_record *shadow;
    size_t             shadow_len;
    size_t             shadow_cap;
    stm_status         err;
} di_load_ctx;

static stm_status di_shadow_append(di_load_ctx *lc,
                                       const stm_dirent_record *r) {
    if (lc->shadow_len == lc->shadow_cap) {
        if (lc->shadow_cap > (SIZE_MAX / sizeof *lc->shadow) / 2u) return STM_ENOMEM;
        size_t new_cap = lc->shadow_cap == 0 ? 8u : lc->shadow_cap * 2u;
        stm_dirent_record *new_buf = realloc(lc->shadow,
                                                 new_cap * sizeof *new_buf);
        if (!new_buf) return STM_ENOMEM;
        lc->shadow     = new_buf;
        lc->shadow_cap = new_cap;
    }
    lc->shadow[lc->shadow_len++] = *r;
    return STM_OK;
}

static int di_load_iter(const void *k, size_t klen,
                            const void *v, size_t vlen, void *ctx_) {
    di_load_ctx *lc = ctx_;
    uint64_t ds = 0, dir = 0, probe = 0;
    stm_status ks = di_decode_key(k, klen, &ds, &dir, &probe);
    if (ks != STM_OK) { lc->err = ks; return 1; }
    if (ds == 0u || dir == 0u) { lc->err = STM_ECORRUPT; return 1; }

    stm_dirent_record r;
    memset(&r, 0, sizeof r);
    stm_status vs = di_decode_value(v, vlen, &r);
    if (vs != STM_OK) { lc->err = vs; return 1; }

    r.dataset_id = ds;
    r.dir_ino    = dir;
    r.hash_probe = probe;

    stm_status as = di_shadow_append(lc, &r);
    if (as != STM_OK) { lc->err = as; return 1; }
    return 0;
}

stm_status stm_dirent_index_load_at(stm_dirent_index *idx,
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

    di_store_ctx        sc = di_make_store_ctx(idx);
    stm_btree_crypt_ctx cx = di_make_crypt_ctx(idx);

    stm_status ds = stm_btree_store_deserialize(t, root_paddr, root_gen,
                                                   expected_csum,
                                                   &DI_STORE_VT, &sc, &cx);
    if (ds != STM_OK) {
        stm_btree_mt_free(t);
        must_unlock(idx_lock(idx));
        return ds;
    }

    di_load_ctx lc = { .err = STM_OK };
    stm_status sr = stm_btree_mt_scan(t, NULL, 0, NULL, 0,
                                         di_load_iter, &lc);
    stm_btree_mt_free(t);
    if (sr != STM_OK) {
        free(lc.shadow);
        must_unlock(idx_lock(idx));
        return sr;
    }
    if (lc.err != STM_OK) {
        free(lc.shadow);
        must_unlock(idx_lock(idx));
        return lc.err;
    }

    /* Atomic shadow swap. */
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

    stm_dirent_record *target =
            find_record_at_probe(idx, dataset_id, dir_ino, hash_probe);
    if (!target) {
        target = append_record(idx);
        if (!target) {
            must_unlock(idx_lock(idx));
            return STM_ENOMEM;
        }
    }
    target->dataset_id = dataset_id;
    target->dir_ino    = dir_ino;
    target->hash_probe = hash_probe;
    target->child_ino  = child_ino;
    target->child_gen  = child_gen;
    target->child_type = child_type;
    target->name_len   = name_len;
    target->flags      = flags;
    memset(target->name, 0, sizeof target->name);
    if (name && name_len > 0u) memcpy(target->name, name, name_len);
    idx->dirty = true;

    must_unlock(idx_lock(idx));
    return STM_OK;
}

uint64_t stm_dirent_fnv1a64_for_test(const uint8_t *name, size_t len) {
    return fnv1a64(name, len);
}
#endif /* STRATUM_BUILD_TESTING_HOOKS */
