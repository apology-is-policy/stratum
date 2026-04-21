/* SPDX-License-Identifier: ISC */
/*
 * synfs — janus's synthetic 9P filesystem.
 *
 * Structure:
 *   - `janus_synfs` holds a list of registered pools plus the audit
 *     log buffer.
 *   - qid_path packs (kind:8 | pool_idx:28 | dataset_idx:28). Every
 *     file kind is a distinct tag; the server's opaque u64 round-
 *     trips identity back to us.
 *   - Per-fid session state (for stateful files like `unwrap`) lives
 *     in a small fixed-size array indexed by (fid, kind).
 *
 * Concurrency: synfs is shared across 9P server instances if the
 * daemon accepts multiple clients. All mutation (audit log append,
 * session state) is guarded by a single mutex — acceptable for
 * janus's request rate (human-scale unwrap ops).
 */

#include "synfs.h"
#include "backend.h"

#include <stratum/crypto.h>
#include <stratum/janus.h>
#include <stratum/p9.h>
#include <stratum/types.h>

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── qid_path encoding ──────────────────────────────────────────────── */

enum {
    KIND_ROOT          = 0,
    KIND_POOLS_DIR     = 1,
    KIND_POOL_DIR      = 2,
    KIND_WRAP_KEY_INFO = 3,
    KIND_DATASETS_DIR  = 4,
    KIND_DATASET_DIR   = 5,
    KIND_UNWRAP        = 6,
    KIND_AUDIT_LOG     = 7,
    KIND_ROTATE        = 8,
};

/* qid_path layout: kind(8) || pool_idx(28) || dataset_id(28). P4-4c
 * widens the dataset field from a pool-local INDEX (always 0) to the
 * actual dataset_id, capped at 2^28-1. Pools with more datasets than
 * that would need a qid scheme bump; realistic counts stay in the
 * thousands. */
#define POOL_IDX_MASK    0x0FFFFFFFu
#define DATASET_ID_MASK  0x0FFFFFFFu

static uint64_t qid_of(uint8_t kind, uint32_t pool_idx, uint64_t dataset_id)
{
    return ((uint64_t)kind << 56)
         | ((uint64_t)(pool_idx & POOL_IDX_MASK) << 28)
         | (dataset_id & DATASET_ID_MASK);
}

static uint8_t  qid_kind    (uint64_t q) { return (uint8_t)(q >> 56); }
static uint32_t qid_pool    (uint64_t q) { return (uint32_t)((q >> 28) & POOL_IDX_MASK); }
static uint64_t qid_dataset (uint64_t q) { return q & DATASET_ID_MASK; }

/* ── pool + session records ─────────────────────────────────────────── */

#define JANUS_MAX_POOLS        16u

typedef struct pool_rec {
    int      active;
    uint8_t  pool_uuid[16];
    janus_backend backend;
} pool_rec;

#define JANUS_MAX_SESSIONS     32u
#define JANUS_SESSION_MAX_REQ  (STM_HYBRID_WRAP_OVERHEAD + 4096u + STM_JANUS_UNWRAP_REQ_HDR)
/* Rotate's response = dek(32) || wrapped(dek_len + OVERHEAD). Unwrap's
 * response = dek(= wrapped_len - OVERHEAD). Both must fit JANUS_SESSION_MAX_RESP. */
#define JANUS_SESSION_MAX_RESP 4096u

/* R11 P2-3: pin the size invariant statically. `stm_hybrid_unwrap`
 * writes `wrapped_len - STM_HYBRID_WRAP_OVERHEAD` bytes into the DEK
 * buffer; that MUST fit in resp_buf for every wrapped blob the
 * session accepts via Twrite. `JANUS_SESSION_MAX_REQ = OVERHEAD +
 * 4096 + HDR` sets the upper bound on wrapped_len as 4096 + OVERHEAD,
 * so the DEK output is at most 4096. If any of these three constants
 * ever drifts, builds break here rather than at a runtime OOB write. */
_Static_assert(JANUS_SESSION_MAX_REQ
                  >= STM_HYBRID_WRAP_OVERHEAD
                   + JANUS_SESSION_MAX_RESP
                   + STM_JANUS_UNWRAP_REQ_HDR,
               "unwrap DEK output can exceed resp_buf");
/* Rotate's response = 32B DEK + (32 + OVERHEAD) wrapped bytes = 64 +
 * OVERHEAD, and OVERHEAD is ~1160 under PQ-hybrid. Plenty of headroom
 * in JANUS_SESSION_MAX_RESP, but pin the invariant so a future enlarged
 * DEK or OVERHEAD can't silently overflow. */
#define JANUS_ROTATE_DEK_LEN       32u
#define JANUS_ROTATE_WRAPPED_LEN   (JANUS_ROTATE_DEK_LEN + STM_HYBRID_WRAP_OVERHEAD)
_Static_assert(JANUS_ROTATE_DEK_LEN + JANUS_ROTATE_WRAPPED_LEN <= JANUS_SESSION_MAX_RESP,
               "rotate response (dek || wrapped) must fit resp_buf");

typedef enum {
    SESSION_UNWRAP = 1,
    SESSION_ROTATE = 2,
} session_kind;

typedef struct rw_session {
    int            active;
    session_kind   kind;
    uint32_t       fid;
    uint32_t       pool_idx;
    uint64_t       dataset_id;
    uint8_t       *req_buf;
    size_t         req_len;
    size_t         req_cap;
    uint8_t       *resp_buf;
    size_t         resp_len;
    int            materialized;   /* response built, ready for Tread */
} rw_session;

struct janus_synfs {
    pthread_mutex_t mu;           /* guards pools + sessions */
    pthread_mutex_t audit_mu;     /* guards the audit log (separate to
                                     avoid reentrance when a handler
                                     logs from under `mu`) */
    pool_rec         pools[JANUS_MAX_POOLS];
    uint32_t         n_pools;

    rw_session       sessions[JANUS_MAX_SESSIONS];

    /* Audit log — contiguous byte buffer, grown by the factor of 2. */
    uint8_t  *audit_buf;
    size_t    audit_len;
    size_t    audit_cap;
};

/* ── helpers ────────────────────────────────────────────────────────── */

static void uuid_hex(const uint8_t uuid[16], char out[37])
{
    static const char hex[] = "0123456789abcdef";
    size_t p = 0;
    for (size_t i = 0; i < 16; i++) {
        out[p++] = hex[uuid[i] >> 4];
        out[p++] = hex[uuid[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) out[p++] = '-';
    }
    out[p] = '\0';
}

static int uuid_from_hex(const char *s, size_t len, uint8_t out[16])
{
    if (len != 36) return -1;
    size_t hi = 0;
    uint8_t acc = 0;
    int nib = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '-') {
            if (i != 8 && i != 13 && i != 18 && i != 23) return -1;
            continue;
        }
        uint8_t v;
        if      (c >= '0' && c <= '9') v = (uint8_t)(c - '0');
        else if (c >= 'a' && c <= 'f') v = (uint8_t)(10 + c - 'a');
        else if (c >= 'A' && c <= 'F') v = (uint8_t)(10 + c - 'A');
        else return -1;
        acc = (uint8_t)((acc << 4) | v);
        nib++;
        if (nib == 2) {
            if (hi >= 16) return -1;
            out[hi++] = acc;
            acc = 0;
            nib = 0;
        }
    }
    return hi == 16 ? 0 : -1;
}

static int uuid_eq(const uint8_t a[16], const uint8_t b[16])
{
    return memcmp(a, b, 16) == 0;
}

static int32_t pool_find(const janus_synfs *s, const uint8_t uuid[16])
{
    for (uint32_t i = 0; i < s->n_pools; i++)
        if (s->pools[i].active && uuid_eq(s->pools[i].pool_uuid, uuid))
            return (int32_t)i;
    return -1;
}

static pool_rec *pool_at(janus_synfs *s, uint32_t idx)
{
    if (idx >= s->n_pools) return NULL;
    if (!s->pools[idx].active) return NULL;
    return &s->pools[idx];
}

/* ── session lookup ─────────────────────────────────────────────────── */

static rw_session *session_get(janus_synfs *s, uint32_t fid)
{
    for (uint32_t i = 0; i < JANUS_MAX_SESSIONS; i++)
        if (s->sessions[i].active && s->sessions[i].fid == fid)
            return &s->sessions[i];
    return NULL;
}

static rw_session *session_alloc(janus_synfs *s, session_kind kind,
                                    uint32_t fid,
                                    uint32_t pool_idx, uint64_t dataset_id)
{
    for (uint32_t i = 0; i < JANUS_MAX_SESSIONS; i++) {
        if (!s->sessions[i].active) {
            rw_session *u = &s->sessions[i];
            memset(u, 0, sizeof *u);
            u->active = 1;
            u->kind = kind;
            u->fid = fid;
            u->pool_idx = pool_idx;
            u->dataset_id = dataset_id;
            u->req_cap = JANUS_SESSION_MAX_REQ;
            u->req_buf = calloc(1, u->req_cap);
            if (!u->req_buf) { u->active = 0; return NULL; }
            u->resp_buf = calloc(1, JANUS_SESSION_MAX_RESP);
            if (!u->resp_buf) {
                free(u->req_buf);
                u->req_buf = NULL;
                u->active = 0;
                return NULL;
            }
            return u;
        }
    }
    return NULL;
}

static void session_free(rw_session *u)
{
    if (!u || !u->active) return;
    if (u->req_buf) {
        stm_ct_memzero(u->req_buf, u->req_cap);
        free(u->req_buf);
    }
    if (u->resp_buf) {
        stm_ct_memzero(u->resp_buf, JANUS_SESSION_MAX_RESP);
        free(u->resp_buf);
    }
    memset(u, 0, sizeof *u);
}

/* ── audit log ──────────────────────────────────────────────────────── */

static void audit_append_locked(janus_synfs *s, const char *line, size_t len)
{
    size_t need = s->audit_len + len;
    if (need > s->audit_cap) {
        size_t new_cap = s->audit_cap ? s->audit_cap : 4096;
        while (new_cap < need) {
            size_t grown = new_cap * 2;
            if (grown < new_cap) return;   /* overflow — drop the line */
            new_cap = grown;
        }
        uint8_t *grown = realloc(s->audit_buf, new_cap);
        if (!grown) return;
        s->audit_buf = grown;
        s->audit_cap = new_cap;
    }
    memcpy(s->audit_buf + s->audit_len, line, len);
    s->audit_len += len;
}

void janus_synfs_auditf(janus_synfs *s, const char *fmt, ...)
{
    if (!s) return;
    char line[512];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int pfx = snprintf(line, sizeof line, "%lld.%09ld ",
                        (long long)ts.tv_sec, ts.tv_nsec);
    if (pfx < 0 || (size_t)pfx >= sizeof line) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line + pfx, sizeof line - (size_t)pfx, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    size_t total = (size_t)pfx + (size_t)n;
    if (total >= sizeof line) total = sizeof line - 1;
    /* R11 P3-4: ensure every log entry ends in a newline, even on the
     * truncation path. Previously, a truncated line (total ==
     * sizeof-1) skipped the append because `total < sizeof line - 1`
     * was false, so the audit log silently merged the truncated line
     * with the next entry on readout. Overwrite the last byte with
     * '\n' on the truncation path — we lose one byte of content, but
     * log structure stays intact. */
    if (total == sizeof line - 1) {
        line[sizeof line - 2] = '\n';
        total = sizeof line - 1;
    } else if (total == 0 || line[total - 1] != '\n') {
        line[total++] = '\n';
    }
    pthread_mutex_lock(&s->audit_mu);
    audit_append_locked(s, line, total);
    pthread_mutex_unlock(&s->audit_mu);
}

/* ── vops: stat ─────────────────────────────────────────────────────── */

static void set_name(stm_p9_node_stat *out, const char *name)
{
    size_t n = strlen(name);
    if (n > STM_P9_NAME_MAX) n = STM_P9_NAME_MAX;
    memcpy(out->name, name, n);
    out->name[n] = '\0';
    out->name_len = (uint16_t)n;
}

static void stat_dir(stm_p9_node_stat *out, uint64_t qid, const char *name,
                      uint32_t mode)
{
    memset(out, 0, sizeof *out);
    out->qid_path = qid;
    out->qid_type = STM_P9_QTDIR;
    out->mode = mode;
    set_name(out, name);
}

static void stat_file(stm_p9_node_stat *out, uint64_t qid, const char *name,
                       uint32_t mode, uint64_t length)
{
    memset(out, 0, sizeof *out);
    out->qid_path = qid;
    out->qid_type = STM_P9_QTFILE;
    out->mode = mode;
    out->length = length;
    set_name(out, name);
}

static stm_status stat_at(janus_synfs *s, uint64_t qid_path,
                            stm_p9_node_stat *out)
{
    uint8_t k = qid_kind(qid_path);
    uint32_t pi = qid_pool(qid_path);
    uint64_t ds = qid_dataset(qid_path);

    switch (k) {
    case KIND_ROOT:
        stat_dir(out, qid_of(KIND_ROOT, 0, 0), "/", 0555 | STM_P9_DMDIR);
        return STM_OK;
    case KIND_POOLS_DIR:
        stat_dir(out, qid_of(KIND_POOLS_DIR, 0, 0), "pools", 0555 | STM_P9_DMDIR);
        return STM_OK;
    case KIND_AUDIT_LOG: {
        pthread_mutex_lock(&s->audit_mu);
        uint64_t len = s->audit_len;
        pthread_mutex_unlock(&s->audit_mu);
        stat_file(out, qid_of(KIND_AUDIT_LOG, 0, 0), "audit-log", 0444, len);
        return STM_OK;
    }
    case KIND_POOL_DIR: {
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        char name[37];
        uuid_hex(p->pool_uuid, name);
        stat_dir(out, qid_path, name, 0555 | STM_P9_DMDIR);
        return STM_OK;
    }
    case KIND_WRAP_KEY_INFO: {
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        stat_file(out, qid_path, "wrap-key-info", 0444,
                   strlen(p->backend.name) + 1);
        return STM_OK;
    }
    case KIND_DATASETS_DIR: {
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        stat_dir(out, qid_path, "datasets", 0555 | STM_P9_DMDIR);
        return STM_OK;
    }
    case KIND_DATASET_DIR: {
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        char name[21];
        snprintf(name, sizeof name, "%llu", (unsigned long long)ds);
        stat_dir(out, qid_path, name, 0555 | STM_P9_DMDIR);
        return STM_OK;
    }
    case KIND_UNWRAP: {
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        stat_file(out, qid_path, "unwrap", 0622, 0);
        return STM_OK;
    }
    case KIND_ROTATE: {
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        stat_file(out, qid_path, "rotate", 0622, 0);
        return STM_OK;
    }
    }
    return STM_ENOENT;
}

static stm_status vops_stat(void *ctx, uint64_t qid_path, stm_p9_node_stat *out)
{
    return stat_at(ctx, qid_path, out);
}

/* ── vops: walk ─────────────────────────────────────────────────────── */

static int str_eq(const char *s, size_t slen, const char *lit)
{
    size_t lit_len = strlen(lit);
    return slen == lit_len && memcmp(s, lit, slen) == 0;
}

/* Parse `name[0..name_len)` as an unsigned decimal up to 2^28-1 (the
 * dataset-id width in qid_path). Returns 0 on success, -1 on any
 * non-digit, empty input, overflow, or over-ceiling value.
 * R12 P3-4: cap name_len at 9 digits — the max value 268435455 fits
 * in 9 characters and longer inputs waste parse cycles on request-
 * rate attacks before the numeric overflow check rejects them. */
static int parse_dataset_id(const char *name, size_t name_len,
                             uint64_t *out_id)
{
    if (name_len == 0 || name_len > 9) return -1;
    /* Reject leading zero on multi-char names (strict canonical form). */
    if (name_len > 1 && name[0] == '0') return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < name_len; i++) {
        char c = name[i];
        if (c < '0' || c > '9') return -1;
        v = v * 10u + (uint64_t)(c - '0');
        if (v > (uint64_t)DATASET_ID_MASK) return -1;
    }
    *out_id = v;
    return 0;
}

static stm_status vops_walk(void *ctx, uint64_t dir_qid_path,
                              const char *name, size_t name_len,
                              stm_p9_node_stat *out)
{
    janus_synfs *s = ctx;
    uint8_t k = qid_kind(dir_qid_path);

    switch (k) {
    case KIND_ROOT:
        if (str_eq(name, name_len, "pools"))
            return stat_at(s, qid_of(KIND_POOLS_DIR, 0, 0), out);
        if (str_eq(name, name_len, "audit-log"))
            return stat_at(s, qid_of(KIND_AUDIT_LOG, 0, 0), out);
        return STM_ENOENT;
    case KIND_POOLS_DIR: {
        /* name is a UUID hex string */
        uint8_t uuid[16];
        if (uuid_from_hex(name, name_len, uuid) != 0) return STM_ENOENT;
        int32_t idx = pool_find(s, uuid);
        if (idx < 0) return STM_ENOENT;
        return stat_at(s, qid_of(KIND_POOL_DIR, (uint32_t)idx, 0), out);
    }
    case KIND_POOL_DIR: {
        uint32_t pi = qid_pool(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        if (str_eq(name, name_len, "wrap-key-info"))
            return stat_at(s, qid_of(KIND_WRAP_KEY_INFO, pi, 0), out);
        if (str_eq(name, name_len, "datasets"))
            return stat_at(s, qid_of(KIND_DATASETS_DIR, pi, 0), out);
        return STM_ENOENT;
    }
    case KIND_DATASETS_DIR: {
        uint32_t pi = qid_pool(dir_qid_path);
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        uint64_t ds = 0;
        if (parse_dataset_id(name, name_len, &ds) != 0) return STM_ENOENT;
        return stat_at(s, qid_of(KIND_DATASET_DIR, pi, ds), out);
    }
    case KIND_DATASET_DIR: {
        uint32_t pi = qid_pool(dir_qid_path);
        uint64_t ds = qid_dataset(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        if (str_eq(name, name_len, "unwrap"))
            return stat_at(s, qid_of(KIND_UNWRAP, pi, ds), out);
        if (str_eq(name, name_len, "rotate"))
            return stat_at(s, qid_of(KIND_ROTATE, pi, ds), out);
        return STM_ENOENT;
    }
    }
    return STM_ENOENT;
}

/* ── vops: readdir ──────────────────────────────────────────────────── */

static stm_status emit(stm_p9_readdir_cb cb, void *cb_ctx,
                         janus_synfs *s, uint64_t qid_path)
{
    stm_p9_node_stat st;
    stm_status rc = stat_at(s, qid_path, &st);
    if (rc != STM_OK) return rc;
    return cb(&st, cb_ctx);
}

static stm_status vops_readdir(void *ctx, uint64_t dir_qid_path,
                                 stm_p9_readdir_cb cb, void *cb_ctx)
{
    janus_synfs *s = ctx;
    uint8_t k = qid_kind(dir_qid_path);

    switch (k) {
    case KIND_ROOT: {
        stm_status rc = emit(cb, cb_ctx, s, qid_of(KIND_POOLS_DIR, 0, 0));
        if (rc != STM_OK) return rc;
        return emit(cb, cb_ctx, s, qid_of(KIND_AUDIT_LOG, 0, 0));
    }
    case KIND_POOLS_DIR:
        for (uint32_t i = 0; i < s->n_pools; i++) {
            if (!s->pools[i].active) continue;
            stm_status rc = emit(cb, cb_ctx, s, qid_of(KIND_POOL_DIR, i, 0));
            if (rc != STM_OK) return rc;
        }
        return STM_OK;
    case KIND_POOL_DIR: {
        uint32_t pi = qid_pool(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        stm_status rc = emit(cb, cb_ctx, s, qid_of(KIND_WRAP_KEY_INFO, pi, 0));
        if (rc != STM_OK) return rc;
        return emit(cb, cb_ctx, s, qid_of(KIND_DATASETS_DIR, pi, 0));
    }
    case KIND_DATASETS_DIR: {
        /* P4-4c: the daemon does not enumerate datasets — the
         * authoritative list lives in the FS keyschema. readdir
         * returns empty. Clients walk directly by numeric dataset_id. */
        uint32_t pi = qid_pool(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        return STM_OK;
    }
    case KIND_DATASET_DIR: {
        uint32_t pi = qid_pool(dir_qid_path);
        uint64_t ds = qid_dataset(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        stm_status rc = emit(cb, cb_ctx, s, qid_of(KIND_UNWRAP, pi, ds));
        if (rc != STM_OK) return rc;
        return emit(cb, cb_ctx, s, qid_of(KIND_ROTATE, pi, ds));
    }
    }
    return STM_ENOENT;
}

/* ── vops: open/read/write/clunk ────────────────────────────────────── */

static stm_status vops_open(void *ctx, uint32_t fid, uint64_t qid_path,
                              uint8_t mode)
{
    janus_synfs *s = ctx;
    uint8_t k = qid_kind(qid_path);

    switch (k) {
    case KIND_ROOT:
    case KIND_POOLS_DIR:
    case KIND_POOL_DIR:
    case KIND_DATASETS_DIR:
    case KIND_DATASET_DIR:
        return STM_OK;
    case KIND_WRAP_KEY_INFO:
    case KIND_AUDIT_LOG:
        if (mode != STM_P9_OREAD) return STM_EACCES;
        return STM_OK;
    case KIND_UNWRAP:
    case KIND_ROTATE: {
        uint32_t pi = qid_pool(qid_path);
        uint64_t ds = qid_dataset(qid_path);
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        if (mode != STM_P9_ORDWR) return STM_EACCES;
        session_kind kind = (k == KIND_UNWRAP) ? SESSION_UNWRAP : SESSION_ROTATE;
        pthread_mutex_lock(&s->mu);
        /* Clear any session with the same fid (new open supersedes). */
        rw_session *u = session_get(s, fid);
        if (u) session_free(u);
        u = session_alloc(s, kind, fid, pi, ds);
        pthread_mutex_unlock(&s->mu);
        if (!u) return STM_ENOMEM;
        return STM_OK;
    }
    }
    return STM_ENOENT;
}

/* Decode an LE u64 from the start of req_buf. */
static uint64_t req_u64_le(const rw_session *u)
{
    uint64_t v = 0;
    for (size_t i = 0; i < 8; i++)
        v |= (uint64_t)u->req_buf[i] << (i * 8);
    return v;
}

/* Materialize a SESSION_UNWRAP request. Request = key_id(8) ‖ wrapped;
 * response = DEK. */
static stm_status materialize_unwrap_locked(janus_synfs *s, rw_session *u)
{
    if (u->req_len < STM_JANUS_UNWRAP_REQ_HDR) return STM_EPROTOCOL;
    uint64_t key_id = req_u64_le(u);
    const uint8_t *wrapped = u->req_buf + STM_JANUS_UNWRAP_REQ_HDR;
    size_t wrapped_len = u->req_len - STM_JANUS_UNWRAP_REQ_HDR;

    pool_rec *p = pool_at(s, u->pool_idx);
    if (!p) return STM_ENOENT;
    if (!p->backend.unwrap) return STM_EBACKEND;

    size_t dek_len = JANUS_SESSION_MAX_RESP;
    stm_status rc = p->backend.unwrap(p->backend.ctx,
                                        p->pool_uuid,
                                        u->dataset_id,
                                        key_id,
                                        wrapped, wrapped_len,
                                        u->resp_buf, &dek_len);
    char uuid_s[37];
    uuid_hex(p->pool_uuid, uuid_s);
    if (rc != STM_OK) {
        janus_synfs_auditf(s, "unwrap pool=%s ds=%llu key=%llu FAIL rc=%d",
                           uuid_s,
                           (unsigned long long)u->dataset_id,
                           (unsigned long long)key_id, (int)rc);
        return rc;
    }
    u->resp_len = dek_len;
    u->materialized = 1;
    janus_synfs_auditf(s, "unwrap pool=%s ds=%llu key=%llu OK len=%zu",
                       uuid_s,
                       (unsigned long long)u->dataset_id,
                       (unsigned long long)key_id, dek_len);
    return STM_OK;
}

/* Materialize a SESSION_ROTATE request. Request = new_key_id(8);
 * response = DEK(32) ‖ wrapped. The daemon generates the DEK via
 * CSPRNG and wraps it under (pool_uuid, dataset_id, new_key_id).
 *
 * Callers already hold s->mu; req/resp buffers belong to the session. */
static stm_status materialize_rotate_locked(janus_synfs *s, rw_session *u)
{
    if (u->req_len != STM_JANUS_ROTATE_REQ_HDR) return STM_EPROTOCOL;
    uint64_t new_key_id = req_u64_le(u);

    pool_rec *p = pool_at(s, u->pool_idx);
    if (!p) return STM_ENOENT;
    if (!p->backend.wrap) return STM_EBACKEND;

    /* Generate fresh DEK. Stage in a local buffer (not directly in
     * resp_buf) so a wrap failure doesn't leak a half-valid response. */
    uint8_t dek[JANUS_ROTATE_DEK_LEN];
    stm_random_bytes(dek, sizeof dek);

    uint8_t wrapped[JANUS_ROTATE_WRAPPED_LEN];
    size_t  wrapped_len = sizeof wrapped;
    stm_status rc = p->backend.wrap(p->backend.ctx,
                                      p->pool_uuid,
                                      u->dataset_id,
                                      new_key_id,
                                      dek, sizeof dek,
                                      wrapped, &wrapped_len);
    char uuid_s[37];
    uuid_hex(p->pool_uuid, uuid_s);
    if (rc != STM_OK) {
        stm_ct_memzero(dek, sizeof dek);
        stm_ct_memzero(wrapped, sizeof wrapped);
        janus_synfs_auditf(s, "rotate pool=%s ds=%llu key=%llu FAIL rc=%d",
                           uuid_s,
                           (unsigned long long)u->dataset_id,
                           (unsigned long long)new_key_id, (int)rc);
        return rc;
    }
    if (wrapped_len != JANUS_ROTATE_WRAPPED_LEN) {
        stm_ct_memzero(dek, sizeof dek);
        stm_ct_memzero(wrapped, sizeof wrapped);
        janus_synfs_auditf(s, "rotate pool=%s ds=%llu key=%llu FAIL wrapped_len=%zu",
                           uuid_s,
                           (unsigned long long)u->dataset_id,
                           (unsigned long long)new_key_id, wrapped_len);
        return STM_EBACKEND;
    }

    /* Lay out resp as dek || wrapped. */
    memcpy(u->resp_buf, dek, sizeof dek);
    memcpy(u->resp_buf + sizeof dek, wrapped, wrapped_len);
    stm_ct_memzero(dek, sizeof dek);
    stm_ct_memzero(wrapped, sizeof wrapped);
    u->resp_len = sizeof dek + wrapped_len;
    u->materialized = 1;
    janus_synfs_auditf(s, "rotate pool=%s ds=%llu key=%llu OK",
                       uuid_s,
                       (unsigned long long)u->dataset_id,
                       (unsigned long long)new_key_id);
    return STM_OK;
}

static stm_status materialize_locked(janus_synfs *s, rw_session *u)
{
    switch (u->kind) {
    case SESSION_UNWRAP: return materialize_unwrap_locked(s, u);
    case SESSION_ROTATE: return materialize_rotate_locked(s, u);
    }
    return STM_EBACKEND;
}

static stm_status vops_read(void *ctx, uint32_t fid, uint64_t qid_path,
                              uint64_t offset, void *buf, uint32_t *inout_len)
{
    janus_synfs *s = ctx;
    uint8_t k = qid_kind(qid_path);

    switch (k) {
    case KIND_WRAP_KEY_INFO: {
        pool_rec *p = pool_at(s, qid_pool(qid_path));
        if (!p) return STM_ENOENT;
        char line[64];
        int n = snprintf(line, sizeof line, "%s\n", p->backend.name);
        if (n < 0) return STM_EIO;
        size_t total = (size_t)n;
        if (offset >= total) { *inout_len = 0; return STM_OK; }
        size_t avail = total - (size_t)offset;
        if (*inout_len > avail) *inout_len = (uint32_t)avail;
        memcpy(buf, line + offset, *inout_len);
        return STM_OK;
    }
    case KIND_AUDIT_LOG: {
        pthread_mutex_lock(&s->audit_mu);
        if (offset >= s->audit_len) {
            *inout_len = 0;
            pthread_mutex_unlock(&s->audit_mu);
            return STM_OK;
        }
        size_t avail = s->audit_len - (size_t)offset;
        if (*inout_len > avail) *inout_len = (uint32_t)avail;
        memcpy(buf, s->audit_buf + offset, *inout_len);
        pthread_mutex_unlock(&s->audit_mu);
        return STM_OK;
    }
    case KIND_UNWRAP:
    case KIND_ROTATE: {
        pthread_mutex_lock(&s->mu);
        rw_session *u = session_get(s, fid);
        if (!u) {
            pthread_mutex_unlock(&s->mu);
            return STM_EBACKEND;  /* should not happen — open gated this */
        }
        if (!u->materialized) {
            stm_status rc = materialize_locked(s, u);
            if (rc != STM_OK) {
                pthread_mutex_unlock(&s->mu);
                return rc;
            }
        }
        if (offset >= u->resp_len) {
            *inout_len = 0;
            pthread_mutex_unlock(&s->mu);
            return STM_OK;
        }
        size_t avail = u->resp_len - (size_t)offset;
        if (*inout_len > avail) *inout_len = (uint32_t)avail;
        memcpy(buf, u->resp_buf + offset, *inout_len);
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
    }
    }
    *inout_len = 0;
    return STM_ENOENT;
}

static stm_status vops_write(void *ctx, uint32_t fid, uint64_t qid_path,
                               uint64_t offset, const void *buf, uint32_t len,
                               uint32_t *out_written)
{
    janus_synfs *s = ctx;
    uint8_t k = qid_kind(qid_path);
    if (k != KIND_UNWRAP && k != KIND_ROTATE) return STM_EACCES;

    pthread_mutex_lock(&s->mu);
    rw_session *u = session_get(s, fid);
    if (!u) {
        pthread_mutex_unlock(&s->mu);
        return STM_EBACKEND;
    }
    /* Fresh Twrite after a read: start over. */
    if (u->materialized) {
        u->req_len = 0;
        u->resp_len = 0;
        u->materialized = 0;
        stm_ct_memzero(u->resp_buf, JANUS_SESSION_MAX_RESP);
    }
    /* Only append-at-end is supported. */
    if (offset != u->req_len) {
        pthread_mutex_unlock(&s->mu);
        return STM_EPROTOCOL;
    }
    if (u->req_len + len > u->req_cap) {
        pthread_mutex_unlock(&s->mu);
        return STM_ERANGE;
    }
    memcpy(u->req_buf + u->req_len, buf, len);
    u->req_len += len;
    *out_written = len;
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

static void vops_clunk(void *ctx, uint32_t fid, uint64_t qid_path)
{
    janus_synfs *s = ctx;
    (void)qid_path;
    pthread_mutex_lock(&s->mu);
    rw_session *u = session_get(s, fid);
    if (u) session_free(u);
    pthread_mutex_unlock(&s->mu);
}

static const stm_p9_vops g_vops = {
    .stat    = vops_stat,
    .walk    = vops_walk,
    .readdir = vops_readdir,
    .open    = vops_open,
    .read    = vops_read,
    .write   = vops_write,
    .clunk   = vops_clunk,
};

/* ── public API ─────────────────────────────────────────────────────── */

stm_status janus_synfs_create(janus_synfs **out)
{
    if (!out) return STM_EINVAL;
    janus_synfs *s = calloc(1, sizeof *s);
    if (!s) return STM_ENOMEM;
    if (pthread_mutex_init(&s->mu, NULL) != 0) {
        free(s);
        return STM_EIO;
    }
    if (pthread_mutex_init(&s->audit_mu, NULL) != 0) {
        pthread_mutex_destroy(&s->mu);
        free(s);
        return STM_EIO;
    }
    *out = s;
    return STM_OK;
}

stm_status janus_synfs_register_pool(janus_synfs *s,
                                      const uint8_t pool_uuid[16],
                                      janus_backend *backend)
{
    if (!s || !pool_uuid || !backend) return STM_EINVAL;
    if (s->n_pools >= JANUS_MAX_POOLS) return STM_ENOMEM;
    if (pool_find(s, pool_uuid) >= 0) return STM_EEXIST;

    pool_rec *p = &s->pools[s->n_pools];
    memset(p, 0, sizeof *p);
    p->active = 1;
    memcpy(p->pool_uuid, pool_uuid, 16);
    janus_backend_move(&p->backend, backend);
    s->n_pools++;
    return STM_OK;
}

uint64_t janus_synfs_root(const janus_synfs *s)
{
    (void)s;
    return qid_of(KIND_ROOT, 0, 0);
}

const stm_p9_vops *janus_synfs_vops(void)
{
    return &g_vops;
}

void janus_synfs_drop_all_sessions(janus_synfs *s)
{
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    for (uint32_t i = 0; i < JANUS_MAX_SESSIONS; i++) {
        if (s->sessions[i].active) session_free(&s->sessions[i]);
    }
    pthread_mutex_unlock(&s->mu);
}

void janus_synfs_destroy(janus_synfs *s)
{
    if (!s) return;
    for (uint32_t i = 0; i < JANUS_MAX_SESSIONS; i++)
        if (s->sessions[i].active) session_free(&s->sessions[i]);
    for (uint32_t i = 0; i < s->n_pools; i++) {
        if (s->pools[i].active && s->pools[i].backend.destroy)
            s->pools[i].backend.destroy(s->pools[i].backend.ctx);
    }
    if (s->audit_buf) {
        stm_ct_memzero(s->audit_buf, s->audit_cap);
        free(s->audit_buf);
    }
    pthread_mutex_destroy(&s->mu);
    pthread_mutex_destroy(&s->audit_mu);
    free(s);
}
