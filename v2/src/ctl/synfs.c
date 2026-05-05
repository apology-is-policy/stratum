/* SPDX-License-Identifier: ISC */
/*
 * stm_ctl synfs — operational synthetic filesystem (ARCH §14.3).
 *
 * Phase 9 P9-CTL-1a scope (foundation):
 *
 *   /                   directory (ro, world-readable)
 *   /version            read: build identity + format versions
 *   /state              read: attached-fs state (or placeholder)
 *
 * Subsequent sub-chunks layer on /pools/<name>/{status,devices,
 * datasets,scrub,...}, /tracing/, /debug/, /events, /metrics/.
 *
 * qid_path encoding
 * ─────────────────
 * The generic stm_p9_server passes our qid_path back to us on every
 * walk/stat/read; the layout encodes (kind:8 | reserved:56). The
 * remaining 56 bits are reserved for future sub-chunks (e.g. pool
 * index, dataset id). Keeping the kind in the high byte mirrors
 * janus/synfs.c so a reader of one understands the other.
 *
 * Concurrency
 * ───────────
 * Read paths are fully reentrant: stat/walk/readdir/open/read/clunk
 * touch only `stm_ctl::fs`, which is set at construction and never
 * mutated again. Body materialization for /version /state writes
 * a per-fid scratch buffer guarded by the instance mutex.
 * The fs-stats accessor (`stm_fs_stats_get`) is itself thread-safe.
 *
 * The instance is safe to share across SEQUENTIAL stm_p9_server
 * use — one server, run, destroy, next server, run, destroy —
 * because the sessions[] array is fully drained per-server-tear-
 * down via vops_clunk on every clunked fid. It is NOT safe to
 * share across CONCURRENT stm_p9_server instances: sessions[] is
 * keyed by `fid` alone (server-local), and two concurrently-active
 * servers can both hold fid=1, colliding. The future concurrent-
 * accept transport upgrade (R95 forward-note) must either give
 * each server its own stm_ctl, or extend the key to
 * `(server_idx, fid)` — the same posture src/9p/server.c took at
 * P9-9P-1 with `lock_owner = (server_idx << 32) | fid`.
 */

#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/p9.h>
#include <stratum/send_recv.h>      /* STM_SEND_VERSION */
#include <stratum/super.h>          /* STM_UB_VERSION */
#include <stratum/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── qid_path encoding ──────────────────────────────────────────────── */

enum {
    KIND_ROOT    = 0,
    KIND_VERSION = 1,
    KIND_STATE   = 2,
};

static uint64_t qid_of(uint8_t kind)
{
    return (uint64_t)kind << 56;
}

static uint8_t qid_kind(uint64_t q)
{
    return (uint8_t)(q >> 56);
}

/* ── per-fid materialized body ──────────────────────────────────────── */

/*
 * /version and /state read as text — we materialize the entire body
 * once per Topen so subsequent Treads at varying offsets see a
 * consistent snapshot. For unattached or post-attach state changes,
 * the body is regenerated on the next Topen.
 *
 * STM_CTL_BODY_MAX is the upper bound on a single materialization;
 * /version + /state both fit comfortably under 1 KiB (a couple
 * hundred bytes each). Cap chosen with headroom for future fields
 * but small enough that JANUS_MAX_SESSIONS-shaped pressure stays
 * cheap.
 */
#define STM_CTL_BODY_MAX     1024u
#define STM_CTL_MAX_SESSIONS 64u

typedef struct ctl_session {
    int       active;
    uint32_t  fid;
    uint64_t  qid_path;
    uint8_t   buf[STM_CTL_BODY_MAX];
    uint32_t  len;
} ctl_session;

struct stm_ctl {
    struct stm_fs   *fs;             /* may be NULL (unattached) */
    pthread_mutex_t  mu;             /* guards sessions[] only */
    ctl_session      sessions[STM_CTL_MAX_SESSIONS];
};

static ctl_session *session_get_locked(stm_ctl *c, uint32_t fid)
{
    for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++)
        if (c->sessions[i].active && c->sessions[i].fid == fid)
            return &c->sessions[i];
    return NULL;
}

static ctl_session *session_alloc_locked(stm_ctl *c, uint32_t fid,
                                          uint64_t qid_path)
{
    /* If the fid already has a session (e.g. open after a previous
     * open without intervening clunk — server may not enforce that
     * universally), reuse the slot. */
    for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++) {
        if (c->sessions[i].active && c->sessions[i].fid == fid) {
            c->sessions[i].qid_path = qid_path;
            c->sessions[i].len = 0;
            memset(c->sessions[i].buf, 0, sizeof c->sessions[i].buf);
            return &c->sessions[i];
        }
    }
    for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++) {
        if (!c->sessions[i].active) {
            ctl_session *s = &c->sessions[i];
            s->active = 1;
            s->fid = fid;
            s->qid_path = qid_path;
            s->len = 0;
            memset(s->buf, 0, sizeof s->buf);
            return s;
        }
    }
    return NULL;
}

static void session_free_locked(ctl_session *s)
{
    if (!s || !s->active) return;
    /* Body bytes are non-secret — version strings + counters. No
     * memzero needed. */
    memset(s, 0, sizeof *s);
}

/* ── body materializers ─────────────────────────────────────────────── */

static stm_status materialize_version(stm_ctl *c, ctl_session *s)
{
    (void)c;
    int n = snprintf((char *)s->buf, sizeof s->buf,
        "stratum-version: %s\n"
        "ub-version: %u\n"
        "fs-handle-version: %u\n"
        "send-version: %u\n",
        "2.0.0",
        (unsigned)STM_UB_VERSION,
        (unsigned)STM_FS_HANDLE_VERSION,
        (unsigned)STM_SEND_VERSION);
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

static stm_status materialize_state(stm_ctl *c, ctl_session *s)
{
    if (!c->fs) {
        int n = snprintf((char *)s->buf, sizeof s->buf,
            "mounted: no\n");
        if (n < 0) return STM_EIO;
        if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
        s->len = (uint32_t)n;
        return STM_OK;
    }

    stm_fs_stats stats;
    memset(&stats, 0, sizeof stats);
    stm_status rc = stm_fs_stats_get(c->fs, &stats);
    if (rc != STM_OK) return rc;

    int n = snprintf((char *)s->buf, sizeof s->buf,
        "mounted: yes\n"
        "read-only: %d\n"
        "wedged: %d\n"
        "current-gen: %llu\n"
        "alloc-root-paddr: 0x%llx\n"
        "data-total-blocks: %llu\n"
        "data-allocated-blocks: %llu\n"
        "data-pending-blocks: %llu\n"
        "data-free-blocks: %llu\n"
        "n-allocated-ranges: %llu\n",
        (int)stats.read_only,
        (int)stats.wedged,
        (unsigned long long)stats.current_gen,
        (unsigned long long)stats.alloc_root_paddr,
        (unsigned long long)stats.data_total_blocks,
        (unsigned long long)stats.data_allocated_blocks,
        (unsigned long long)stats.data_pending_blocks,
        (unsigned long long)stats.data_free_blocks,
        (unsigned long long)stats.n_allocated_ranges);
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

static stm_status materialize_locked(stm_ctl *c, ctl_session *s)
{
    switch (qid_kind(s->qid_path)) {
    case KIND_VERSION: return materialize_version(c, s);
    case KIND_STATE:   return materialize_state(c, s);
    }
    /* Should not happen — open gates body files only. */
    return STM_EBACKEND;
}

/* ── name table ─────────────────────────────────────────────────────── */

static const char *kind_name(uint8_t kind)
{
    switch (kind) {
    case KIND_ROOT:    return "/";
    case KIND_VERSION: return "version";
    case KIND_STATE:   return "state";
    }
    return NULL;
}

/* ── vops ───────────────────────────────────────────────────────────── */

static void set_name(stm_p9_node_stat *out, const char *name)
{
    size_t n = strlen(name);
    if (n > STM_P9_NAME_MAX) n = STM_P9_NAME_MAX;
    memcpy(out->name, name, n);
    out->name[n] = '\0';
    out->name_len = (uint16_t)n;
}

static stm_status stat_at(stm_ctl *c, uint64_t qid_path,
                           stm_p9_node_stat *out)
{
    uint8_t k = qid_kind(qid_path);
    const char *name = kind_name(k);
    if (!name) return STM_ENOENT;
    memset(out, 0, sizeof *out);
    out->qid_path = qid_path;
    if (k == KIND_ROOT) {
        out->qid_type = STM_P9_QTDIR;
        out->mode = 0555 | STM_P9_DMDIR;
    } else {
        out->qid_type = STM_P9_QTFILE;
        out->mode = 0444;
        /* `length` is reported as 0 for synthetic files: the actual
         * body is materialized at Topen and the FS doesn't know its
         * size in advance of materialization. Standard 9P pattern
         * (see /proc on Linux). Clients that care can read until EOF.
         *
         * `c` would let us pre-materialize; we choose not to (open
         * is the right time to snapshot state). */
        (void)c;
    }
    set_name(out, name);
    return STM_OK;
}

static stm_status vops_stat(void *ctx, uint64_t qid_path,
                              stm_p9_node_stat *out)
{
    return stat_at(ctx, qid_path, out);
}

static int str_eq(const char *s, size_t slen, const char *lit)
{
    size_t lit_len = strlen(lit);
    return slen == lit_len && memcmp(s, lit, slen) == 0;
}

static stm_status vops_walk(void *ctx, uint64_t dir_qid_path,
                              const char *name, size_t name_len,
                              stm_p9_node_stat *out)
{
    stm_ctl *c = ctx;
    if (qid_kind(dir_qid_path) != KIND_ROOT) return STM_ENOENT;
    if (str_eq(name, name_len, "version"))
        return stat_at(c, qid_of(KIND_VERSION), out);
    if (str_eq(name, name_len, "state"))
        return stat_at(c, qid_of(KIND_STATE), out);
    return STM_ENOENT;
}

static stm_status emit_entry(stm_ctl *c, stm_p9_readdir_cb cb, void *cb_ctx,
                               uint64_t qid_path)
{
    stm_p9_node_stat st;
    stm_status rc = stat_at(c, qid_path, &st);
    if (rc != STM_OK) return rc;
    return cb(&st, cb_ctx);
}

static stm_status vops_readdir(void *ctx, uint64_t dir_qid_path,
                                 stm_p9_readdir_cb cb, void *cb_ctx)
{
    stm_ctl *c = ctx;
    if (qid_kind(dir_qid_path) != KIND_ROOT) return STM_ENOENT;
    stm_status rc = emit_entry(c, cb, cb_ctx, qid_of(KIND_VERSION));
    if (rc != STM_OK) return rc;
    return emit_entry(c, cb, cb_ctx, qid_of(KIND_STATE));
}

static stm_status vops_open(void *ctx, uint32_t fid, uint64_t qid_path,
                              uint8_t mode)
{
    stm_ctl *c = ctx;
    uint8_t k = qid_kind(qid_path);
    /* Directories: open is advisory; readdir handles iteration. */
    if (k == KIND_ROOT) {
        if (mode != STM_P9_OREAD) return STM_EACCES;
        return STM_OK;
    }
    if (k != KIND_VERSION && k != KIND_STATE) return STM_ENOENT;
    if (mode != STM_P9_OREAD) return STM_EACCES;

    /* Snapshot the body now so subsequent Treads at varying offsets
     * see a consistent view. Subsequent re-opens (same fid, after
     * clunk, or simultaneous on a different fid in a different
     * server instance) re-snapshot. */
    pthread_mutex_lock(&c->mu);
    ctl_session *s = session_alloc_locked(c, fid, qid_path);
    if (!s) {
        pthread_mutex_unlock(&c->mu);
        return STM_ENOMEM;
    }
    stm_status rc = materialize_locked(c, s);
    if (rc != STM_OK) {
        session_free_locked(s);
        pthread_mutex_unlock(&c->mu);
        return rc;
    }
    pthread_mutex_unlock(&c->mu);
    return STM_OK;
}

static stm_status vops_read(void *ctx, uint32_t fid, uint64_t qid_path,
                              uint64_t offset, void *buf, uint32_t *inout_len)
{
    stm_ctl *c = ctx;
    uint8_t k = qid_kind(qid_path);
    if (k != KIND_VERSION && k != KIND_STATE) {
        *inout_len = 0;
        return STM_ENOENT;
    }
    pthread_mutex_lock(&c->mu);
    ctl_session *s = session_get_locked(c, fid);
    if (!s) {
        /* Read without prior open — generic stm_p9_server gates this
         * via per-fid is_open, so we shouldn't get here on the happy
         * path. Defensive: refuse. */
        pthread_mutex_unlock(&c->mu);
        *inout_len = 0;
        return STM_EBACKEND;
    }
    if (s->qid_path != qid_path) {
        /* fid bound to a different node than the read targets —
         * client confusion, refuse. */
        pthread_mutex_unlock(&c->mu);
        *inout_len = 0;
        return STM_EBACKEND;
    }
    if (offset >= s->len) {
        *inout_len = 0;
        pthread_mutex_unlock(&c->mu);
        return STM_OK;
    }
    uint32_t avail = s->len - (uint32_t)offset;
    if (*inout_len > avail) *inout_len = avail;
    memcpy(buf, s->buf + offset, *inout_len);
    pthread_mutex_unlock(&c->mu);
    return STM_OK;
}

static stm_status vops_write(void *ctx, uint32_t fid, uint64_t qid_path,
                               uint64_t offset, const void *buf,
                               uint32_t len, uint32_t *out_written)
{
    (void)ctx; (void)fid; (void)qid_path;
    (void)offset; (void)buf; (void)len;
    *out_written = 0;
    /* P9-CTL-1a: every node is read-only. Future sub-chunks add
     * action-trigger files (e.g. /pools/<n>/scrub) with their own
     * write paths and uid gating. */
    return STM_EACCES;
}

static void vops_clunk(void *ctx, uint32_t fid, uint64_t qid_path)
{
    stm_ctl *c = ctx;
    (void)qid_path;
    pthread_mutex_lock(&c->mu);
    ctl_session *s = session_get_locked(c, fid);
    if (s) session_free_locked(s);
    pthread_mutex_unlock(&c->mu);
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

stm_status stm_ctl_create(struct stm_fs *fs, stm_ctl **out)
{
    if (!out) return STM_EINVAL;
    stm_ctl *c = calloc(1, sizeof *c);
    if (!c) return STM_ENOMEM;
    if (pthread_mutex_init(&c->mu, NULL) != 0) {
        free(c);
        return STM_EIO;
    }
    c->fs = fs;
    *out = c;
    return STM_OK;
}

void stm_ctl_destroy(stm_ctl *c)
{
    if (!c) return;
    for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++)
        if (c->sessions[i].active) session_free_locked(&c->sessions[i]);
    pthread_mutex_destroy(&c->mu);
    free(c);
}

const stm_p9_vops *stm_ctl_vops(void)
{
    return &g_vops;
}

uint64_t stm_ctl_root(const stm_ctl *c)
{
    (void)c;
    return qid_of(KIND_ROOT);
}
