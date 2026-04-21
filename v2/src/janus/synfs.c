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
};

#define POOL_IDX_MASK    0x0FFFFFFFu
#define DATASET_IDX_MASK 0x0FFFFFFFu

static uint64_t qid_of(uint8_t kind, uint32_t pool_idx, uint32_t dataset_idx)
{
    return ((uint64_t)kind << 56)
         | ((uint64_t)(pool_idx    & POOL_IDX_MASK) << 28)
         | ((uint64_t)(dataset_idx & DATASET_IDX_MASK));
}

static uint8_t  qid_kind    (uint64_t q) { return (uint8_t)(q >> 56); }
static uint32_t qid_pool    (uint64_t q) { return (uint32_t)((q >> 28) & POOL_IDX_MASK); }
static uint32_t qid_dataset (uint64_t q) { return (uint32_t)(q & DATASET_IDX_MASK); }

/* ── pool + session records ─────────────────────────────────────────── */

#define JANUS_MAX_POOLS        16u
#define JANUS_MAX_DATASETS      1u  /* P4-4b MVP: one dataset (id=0) per pool */

typedef struct pool_rec {
    int      active;
    uint8_t  pool_uuid[16];
    uint64_t dataset_id;
    janus_backend backend;
} pool_rec;

#define JANUS_MAX_SESSIONS     32u
#define JANUS_SESSION_MAX_REQ  (STM_HYBRID_WRAP_OVERHEAD + 4096u + STM_JANUS_UNWRAP_REQ_HDR)
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

typedef struct unwrap_session {
    int       active;
    uint32_t  fid;
    uint32_t  pool_idx;
    uint32_t  dataset_idx;
    uint8_t  *req_buf;
    size_t    req_len;
    size_t    req_cap;
    uint8_t  *resp_buf;
    size_t    resp_len;
    int       unwrapped;   /* response materialised */
} unwrap_session;

struct janus_synfs {
    pthread_mutex_t mu;           /* guards pools + sessions */
    pthread_mutex_t audit_mu;     /* guards the audit log (separate to
                                     avoid reentrance when a handler
                                     logs from under `mu`) */
    pool_rec         pools[JANUS_MAX_POOLS];
    uint32_t         n_pools;

    unwrap_session   sessions[JANUS_MAX_SESSIONS];

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

static unwrap_session *session_get(janus_synfs *s, uint32_t fid)
{
    for (uint32_t i = 0; i < JANUS_MAX_SESSIONS; i++)
        if (s->sessions[i].active && s->sessions[i].fid == fid)
            return &s->sessions[i];
    return NULL;
}

static unwrap_session *session_alloc(janus_synfs *s, uint32_t fid,
                                       uint32_t pool_idx, uint32_t dataset_idx)
{
    for (uint32_t i = 0; i < JANUS_MAX_SESSIONS; i++) {
        if (!s->sessions[i].active) {
            unwrap_session *u = &s->sessions[i];
            memset(u, 0, sizeof *u);
            u->active = 1;
            u->fid = fid;
            u->pool_idx = pool_idx;
            u->dataset_idx = dataset_idx;
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

static void session_free(unwrap_session *u)
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
    uint32_t di = qid_dataset(qid_path);

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
        if (di != 0) return STM_ENOENT;
        char name[21];
        snprintf(name, sizeof name, "%llu", (unsigned long long)p->dataset_id);
        stat_dir(out, qid_path, name, 0555 | STM_P9_DMDIR);
        return STM_OK;
    }
    case KIND_UNWRAP: {
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        if (di != 0) return STM_ENOENT;
        stat_file(out, qid_path, "unwrap", 0622, 0);
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
        char ds_name[21];
        snprintf(ds_name, sizeof ds_name, "%llu",
                 (unsigned long long)p->dataset_id);
        if (!str_eq(name, name_len, ds_name)) return STM_ENOENT;
        return stat_at(s, qid_of(KIND_DATASET_DIR, pi, 0), out);
    }
    case KIND_DATASET_DIR: {
        uint32_t pi = qid_pool(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        if (str_eq(name, name_len, "unwrap"))
            return stat_at(s, qid_of(KIND_UNWRAP, pi, 0), out);
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
        uint32_t pi = qid_pool(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        return emit(cb, cb_ctx, s, qid_of(KIND_DATASET_DIR, pi, 0));
    }
    case KIND_DATASET_DIR: {
        uint32_t pi = qid_pool(dir_qid_path);
        if (!pool_at(s, pi)) return STM_ENOENT;
        return emit(cb, cb_ctx, s, qid_of(KIND_UNWRAP, pi, 0));
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
    case KIND_UNWRAP: {
        uint32_t pi = qid_pool(qid_path);
        uint32_t di = qid_dataset(qid_path);
        pool_rec *p = pool_at(s, pi);
        if (!p) return STM_ENOENT;
        if (mode != STM_P9_ORDWR) return STM_EACCES;
        pthread_mutex_lock(&s->mu);
        /* Clear any session with the same fid (new open supersedes). */
        unwrap_session *u = session_get(s, fid);
        if (u) session_free(u);
        u = session_alloc(s, fid, pi, di);
        pthread_mutex_unlock(&s->mu);
        if (!u) return STM_ENOMEM;
        return STM_OK;
    }
    }
    return STM_ENOENT;
}

/* Run the backend unwrap and populate session->resp_buf. Called
 * lazily on the first Tread after a Twrite. */
static stm_status materialize_unwrap_locked(janus_synfs *s,
                                              unwrap_session *u)
{
    if (u->req_len < STM_JANUS_UNWRAP_REQ_HDR) return STM_EPROTOCOL;
    uint64_t key_id = 0;
    for (size_t i = 0; i < 8; i++)
        key_id |= (uint64_t)u->req_buf[i] << (i * 8);
    const uint8_t *wrapped = u->req_buf + STM_JANUS_UNWRAP_REQ_HDR;
    size_t wrapped_len = u->req_len - STM_JANUS_UNWRAP_REQ_HDR;

    pool_rec *p = pool_at(s, u->pool_idx);
    if (!p) return STM_ENOENT;
    if (u->dataset_idx != 0) return STM_ENOENT;  /* MVP */
    if (!p->backend.unwrap) return STM_EBACKEND;

    size_t dek_cap = JANUS_SESSION_MAX_RESP;
    size_t dek_len = dek_cap;
    stm_status rc = p->backend.unwrap(p->backend.ctx,
                                        p->pool_uuid,
                                        p->dataset_id,
                                        key_id,
                                        wrapped, wrapped_len,
                                        u->resp_buf, &dek_len);
    char uuid_s[37];
    uuid_hex(p->pool_uuid, uuid_s);
    if (rc != STM_OK) {
        janus_synfs_auditf(s, "unwrap pool=%s ds=%llu key=%llu FAIL rc=%d",
                           uuid_s,
                           (unsigned long long)p->dataset_id,
                           (unsigned long long)key_id, (int)rc);
        return rc;
    }
    u->resp_len = dek_len;
    u->unwrapped = 1;
    janus_synfs_auditf(s, "unwrap pool=%s ds=%llu key=%llu OK len=%zu",
                       uuid_s,
                       (unsigned long long)p->dataset_id,
                       (unsigned long long)key_id, dek_len);
    return STM_OK;
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
    case KIND_UNWRAP: {
        pthread_mutex_lock(&s->mu);
        unwrap_session *u = session_get(s, fid);
        if (!u) {
            pthread_mutex_unlock(&s->mu);
            return STM_EBACKEND;  /* should not happen — open gated this */
        }
        if (!u->unwrapped) {
            stm_status rc = materialize_unwrap_locked(s, u);
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
    if (k != KIND_UNWRAP) return STM_EACCES;

    pthread_mutex_lock(&s->mu);
    unwrap_session *u = session_get(s, fid);
    if (!u) {
        pthread_mutex_unlock(&s->mu);
        return STM_EBACKEND;
    }
    /* Fresh Twrite after a read: start over. */
    if (u->unwrapped) {
        u->req_len = 0;
        u->resp_len = 0;
        u->unwrapped = 0;
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
    unwrap_session *u = session_get(s, fid);
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
                                      uint64_t dataset_id,
                                      janus_backend *backend)
{
    if (!s || !pool_uuid || !backend) return STM_EINVAL;
    if (s->n_pools >= JANUS_MAX_POOLS) return STM_ENOMEM;
    if (pool_find(s, pool_uuid) >= 0) return STM_EEXIST;

    pool_rec *p = &s->pools[s->n_pools];
    memset(p, 0, sizeof *p);
    p->active = 1;
    memcpy(p->pool_uuid, pool_uuid, 16);
    p->dataset_id = dataset_id;
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
