/* SPDX-License-Identifier: ISC */
/*
 * stm_slate — slate daemon's per-process UI state + lp9 vops backend.
 *
 * P9-SLATE-1 scope: /version /status /event /redraw /log/{tail,append}.
 * Compose against v2/specs/slate.tla (VersionMonotonic + EventFIFO +
 * ReadConsistent + DispatchProgress).
 *
 * Concurrency: stm_slate is shared across multiple per-connection lp9
 * server threads. All state accesses go through `mu`. Blocking reads
 * on /redraw cond_wait on `cv`; broadcast on every dispatch and on
 * stop.
 *
 * Trust boundaries (audit-tracked):
 *   - /event line bounded at STM_SLATE_EVENT_LINE_MAX (256 bytes)
 *     at the wire boundary (vops_write); empty lines refused with
 *     STM_EINVAL.
 *   - Per-fid materialized body bounded at STM_SLATE_BODY_MAX
 *     (4 KiB); snprintf-then-check.
 *   - /redraw blocking-read times out via the lp9 server's
 *     SO_RCVTIMEO at the connection level (set in stratum-slate
 *     serve binary, not here); within vops, the cond_wait is
 *     unbounded BUT bounded by stop_flag — daemon shutdown calls
 *     stm_slate_stop which broadcasts the cv → every blocked
 *     reader returns immediately.
 */

#include <stratum/slate.h>

#include <stratum/lp9.h>
#include <stratum/types.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Kind enum + meta table.                                                */
/* ────────────────────────────────────────────────────────────────────── */

typedef enum {
    SLATE_KIND_ROOT       = 0,
    SLATE_KIND_VERSION    = 1,
    SLATE_KIND_STATUS     = 2,
    SLATE_KIND_EVENT      = 3,
    SLATE_KIND_REDRAW     = 4,
    SLATE_KIND_LOG_DIR    = 5,
    SLATE_KIND_LOG_TAIL   = 6,
    SLATE_KIND_LOG_APPEND = 7,
    SLATE_KIND_MAX
} slate_kind;

typedef struct {
    bool         is_dir;
    uint32_t     mode;        /* posix permission bits only */
    const char  *name;
} slate_kind_meta;

/* POSIX file-type bits applied alongside mode. Mirrors src/ctl/synfs.c. */
#define SLATE_S_IFDIR   0040000u
#define SLATE_S_IFREG   0100000u

static const slate_kind_meta KIND_META[SLATE_KIND_MAX] = {
    [SLATE_KIND_ROOT]       = { true,  0555, "/"        },
    [SLATE_KIND_VERSION]    = { false, 0444, "version"  },
    [SLATE_KIND_STATUS]     = { false, 0444, "status"   },
    /* /event is mode 0200 (write-only). */
    [SLATE_KIND_EVENT]      = { false, 0200, "event"    },
    /* /redraw is read-only mode 0444 — blocking read returns version. */
    [SLATE_KIND_REDRAW]     = { false, 0444, "redraw"   },
    [SLATE_KIND_LOG_DIR]    = { true,  0555, "log"      },
    [SLATE_KIND_LOG_TAIL]   = { false, 0444, "tail"     },
    /* /log/append is mode 0200 (write-only). */
    [SLATE_KIND_LOG_APPEND] = { false, 0200, "append"   },
};

_Static_assert(SLATE_KIND_MAX == 8, "KIND_META[] sized to enum cardinality");
_Static_assert(sizeof("version") - 1     <= STM_LP9_NAME_MAX, "/version literal");
_Static_assert(sizeof("status") - 1      <= STM_LP9_NAME_MAX, "/status literal");
_Static_assert(sizeof("event") - 1       <= STM_LP9_NAME_MAX, "/event literal");
_Static_assert(sizeof("redraw") - 1      <= STM_LP9_NAME_MAX, "/redraw literal");
_Static_assert(sizeof("log") - 1         <= STM_LP9_NAME_MAX, "/log literal");
_Static_assert(sizeof("tail") - 1        <= STM_LP9_NAME_MAX, "/log/tail literal");
_Static_assert(sizeof("append") - 1      <= STM_LP9_NAME_MAX, "/log/append literal");

/* ────────────────────────────────────────────────────────────────────── */
/* qid_path encoding — kind in high byte, sub-id in low bytes.            */
/* ────────────────────────────────────────────────────────────────────── */

static uint64_t qid_of(slate_kind k)
{
    return ((uint64_t)(uint8_t)k) << 56;
}

static slate_kind qid_kind(uint64_t q)
{
    uint8_t b = (uint8_t)(q >> 56);
    return (b < SLATE_KIND_MAX) ? (slate_kind)b : SLATE_KIND_MAX;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Per-fid session — materialized body for read kinds.                    */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct slate_session {
    int       active;
    uint32_t  fid;
    uint64_t  qid_path;
    uint8_t   buf[STM_SLATE_BODY_MAX];
    uint32_t  len;
} slate_session;

/* ────────────────────────────────────────────────────────────────────── */
/* The state.                                                             */
/* ────────────────────────────────────────────────────────────────────── */

struct stm_slate {
    pthread_mutex_t mu;
    pthread_cond_t  cv;       /* broadcast on dispatch + on stop */

    bool            stopped;  /* stm_slate_stop sets; /redraw checks */

    uint64_t        version;
    char            status[STM_SLATE_STATUS_MAX + 1];
    size_t          status_len;

    /* /log/tail ring buffer. Keeps the last STM_SLATE_LOG_LINES lines.
     * Each entry is NUL-terminated; tail_len is the strlen. */
    char            log[STM_SLATE_LOG_LINES][STM_SLATE_LOG_LINE_MAX + 1];
    size_t          log_len[STM_SLATE_LOG_LINES];
    uint32_t        log_head;     /* index of oldest entry */
    uint32_t        log_count;    /* 0..STM_SLATE_LOG_LINES */

    /* Per-fid materialized bodies (mu-protected). */
    slate_session   sessions[STM_SLATE_MAX_SESSIONS];
};

/* ────────────────────────────────────────────────────────────────────── */
/* Internal helpers (must be called with mu held).                        */
/* ────────────────────────────────────────────────────────────────────── */

static void log_append_locked(stm_slate *s, const char *line, size_t len)
{
    if (len > STM_SLATE_LOG_LINE_MAX) len = STM_SLATE_LOG_LINE_MAX;

    /* Where the new entry lands. */
    uint32_t idx;
    if (s->log_count < STM_SLATE_LOG_LINES) {
        idx = (s->log_head + s->log_count) % STM_SLATE_LOG_LINES;
        s->log_count++;
    } else {
        /* Buffer full — drop the oldest. */
        idx = s->log_head;
        s->log_head = (s->log_head + 1u) % STM_SLATE_LOG_LINES;
    }
    memcpy(s->log[idx], line, len);
    s->log[idx][len] = '\0';
    s->log_len[idx] = len;
}

/* Dispatch one event line. SLATE-1's handler is "log got: <line>". */
static void dispatch_event_locked(stm_slate *s, const char *line, size_t len)
{
    char prefixed[STM_SLATE_LOG_LINE_MAX + 1];
    /* Format: "<sec>.<nsec> got: <line>" — bounded at STM_SLATE_LOG_LINE_MAX. */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int n = snprintf(prefixed, sizeof prefixed,
                     "%lld.%09ld got: ",
                     (long long)ts.tv_sec, (long)ts.tv_nsec);
    if (n < 0) n = 0;
    size_t off = (size_t)n;
    if (off > STM_SLATE_LOG_LINE_MAX) off = STM_SLATE_LOG_LINE_MAX;
    /* Bound copy to whatever fits. */
    size_t copy = len;
    if (copy > STM_SLATE_LOG_LINE_MAX - off) copy = STM_SLATE_LOG_LINE_MAX - off;
    memcpy(prefixed + off, line, copy);
    prefixed[off + copy] = '\0';
    log_append_locked(s, prefixed, off + copy);

    /* Bump version + wake everyone blocked on /redraw. The bump
     * happens after the log update so a /redraw reader that wakes on
     * this version sees the post-dispatch state. */
    s->version++;
    pthread_cond_broadcast(&s->cv);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Public state API.                                                      */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_slate_create(stm_slate **out)
{
    if (!out) return STM_EINVAL;
    stm_slate *s = calloc(1, sizeof *s);
    if (!s) return STM_ENOMEM;
    if (pthread_mutex_init(&s->mu, NULL) != 0) {
        free(s);
        return STM_EIO;
    }
    if (pthread_cond_init(&s->cv, NULL) != 0) {
        pthread_mutex_destroy(&s->mu);
        free(s);
        return STM_EIO;
    }
    s->version = 1u;
    *out = s;
    return STM_OK;
}

void stm_slate_stop(stm_slate *s)
{
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    s->stopped = true;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
}

void stm_slate_destroy(stm_slate *s)
{
    if (!s) return;
    pthread_mutex_destroy(&s->mu);
    pthread_cond_destroy(&s->cv);
    free(s);
}

uint64_t stm_slate_version(stm_slate *s)
{
    if (!s) return 0u;
    pthread_mutex_lock(&s->mu);
    uint64_t v = s->version;
    pthread_mutex_unlock(&s->mu);
    return v;
}

stm_status stm_slate_submit_event(stm_slate *s, const char *line, size_t len)
{
    if (!s || !line) return STM_EINVAL;
    /* Strip a trailing newline if present (matches the wire-format
     * convention: clients usually print with `echo`). */
    if (len > 0 && line[len - 1] == '\n') len--;
    if (len == 0) return STM_EINVAL;
    if (len > STM_SLATE_EVENT_LINE_MAX) return STM_EINVAL;

    pthread_mutex_lock(&s->mu);
    dispatch_event_locked(s, line, len);
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

stm_status stm_slate_set_status(stm_slate *s, const char *text, size_t len)
{
    if (!s || !text) return STM_EINVAL;
    if (len > STM_SLATE_STATUS_MAX) return STM_EINVAL;
    /* No embedded newlines — keeps the wire format line-oriented. */
    for (size_t i = 0; i < len; i++) {
        if (text[i] == '\n' || text[i] == '\r') return STM_EINVAL;
    }
    pthread_mutex_lock(&s->mu);
    memcpy(s->status, text, len);
    s->status[len] = '\0';
    s->status_len = len;
    s->version++;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

void stm_slate_drop_all_sessions(stm_slate *s)
{
    if (!s) return;
    pthread_mutex_lock(&s->mu);
    memset(s->sessions, 0, sizeof s->sessions);
    pthread_mutex_unlock(&s->mu);
}

uint64_t stm_slate_root(const stm_slate *s)
{
    (void)s;
    return qid_of(SLATE_KIND_ROOT);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Session helpers (mu held).                                             */
/* ────────────────────────────────────────────────────────────────────── */

static slate_session *session_get_locked(stm_slate *s, uint32_t fid)
{
    for (uint32_t i = 0; i < STM_SLATE_MAX_SESSIONS; i++) {
        if (s->sessions[i].active && s->sessions[i].fid == fid)
            return &s->sessions[i];
    }
    return NULL;
}

static slate_session *session_alloc_locked(stm_slate *s, uint32_t fid,
                                              uint64_t qid_path)
{
    for (uint32_t i = 0; i < STM_SLATE_MAX_SESSIONS; i++) {
        if (!s->sessions[i].active) {
            slate_session *ss = &s->sessions[i];
            ss->active = 1;
            ss->fid = fid;
            ss->qid_path = qid_path;
            ss->len = 0;
            return ss;
        }
    }
    return NULL;
}

static void session_free_locked(slate_session *ss)
{
    if (!ss || !ss->active) return;
    memset(ss, 0, sizeof *ss);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Body materialization (mu held when called by vops_lopen).              */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status materialize_version_locked(stm_slate *s, slate_session *ss)
{
    int n = snprintf((char *)ss->buf, sizeof ss->buf,
                     "%llu\n", (unsigned long long)s->version);
    if (n < 0 || n >= (int)sizeof ss->buf) return STM_ERANGE;
    ss->len = (uint32_t)n;
    return STM_OK;
}

static stm_status materialize_status_locked(stm_slate *s, slate_session *ss)
{
    /* Status as a single line + newline. */
    if (s->status_len + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, s->status, s->status_len);
    ss->buf[s->status_len] = '\n';
    ss->len = (uint32_t)(s->status_len + 1u);
    return STM_OK;
}

static stm_status materialize_log_tail_locked(stm_slate *s, slate_session *ss)
{
    size_t off = 0;
    for (uint32_t i = 0; i < s->log_count; i++) {
        uint32_t idx = (s->log_head + i) % STM_SLATE_LOG_LINES;
        size_t llen = s->log_len[idx];
        /* +1 for newline */
        if (off + llen + 1u > sizeof ss->buf) return STM_ERANGE;
        memcpy(ss->buf + off, s->log[idx], llen);
        ss->buf[off + llen] = '\n';
        off += llen + 1u;
    }
    ss->len = (uint32_t)off;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* lp9 vops.                                                              */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status getattr_at(uint64_t qid_path, stm_lp9_attr *out)
{
    slate_kind k = qid_kind(qid_path);
    if (k == SLATE_KIND_MAX) return STM_ENOENT;
    const slate_kind_meta *meta = &KIND_META[k];

    memset(out, 0, sizeof *out);
    out->qid.path = qid_path;
    out->valid    = STM_LP9_GETATTR_BASIC;
    out->nlink    = 1;
    if (meta->is_dir) {
        out->qid.qtype = STM_LP9_QTDIR;
        out->mode      = SLATE_S_IFDIR | meta->mode;
    } else {
        out->qid.qtype = STM_LP9_QTFILE;
        out->mode      = SLATE_S_IFREG | meta->mode;
    }
    return STM_OK;
}

static stm_status vops_getattr(void *ctx, uint64_t qid_path,
                                 uint64_t request_mask, stm_lp9_attr *out)
{
    (void)ctx; (void)request_mask;
    return getattr_at(qid_path, out);
}

static int str_eq(const char *s, size_t slen, const char *lit)
{
    size_t lit_len = strlen(lit);
    return slen == lit_len && memcmp(s, lit, slen) == 0;
}

static stm_status vops_walk(void *ctx, uint64_t dir_qid_path,
                              const char *name, size_t name_len,
                              stm_lp9_qid *out)
{
    (void)ctx;
    slate_kind dk = qid_kind(dir_qid_path);
    slate_kind target = SLATE_KIND_MAX;

    switch (dk) {
    case SLATE_KIND_ROOT:
        if (str_eq(name, name_len, "version"))   target = SLATE_KIND_VERSION;
        else if (str_eq(name, name_len, "status"))  target = SLATE_KIND_STATUS;
        else if (str_eq(name, name_len, "event"))   target = SLATE_KIND_EVENT;
        else if (str_eq(name, name_len, "redraw"))  target = SLATE_KIND_REDRAW;
        else if (str_eq(name, name_len, "log"))     target = SLATE_KIND_LOG_DIR;
        break;
    case SLATE_KIND_LOG_DIR:
        if (str_eq(name, name_len, "tail"))     target = SLATE_KIND_LOG_TAIL;
        else if (str_eq(name, name_len, "append"))  target = SLATE_KIND_LOG_APPEND;
        break;
    default:
        return STM_ENOENT;
    }
    if (target == SLATE_KIND_MAX) return STM_ENOENT;

    stm_lp9_attr a;
    stm_status rc = getattr_at(qid_of(target), &a);
    if (rc != STM_OK) return rc;
    *out = a.qid;
    return STM_OK;
}

typedef struct {
    uint64_t          offset;
    uint64_t          pos;
    stm_lp9_dirent_cb cb;
    void             *cb_ctx;
} readdir_emit;

static stm_status emit_entry(slate_kind k, readdir_emit *em)
{
    const slate_kind_meta *meta = &KIND_META[k];

    uint64_t this_cookie = ++em->pos;
    if (this_cookie <= em->offset) return STM_OK;

    stm_lp9_dirent e;
    memset(&e, 0, sizeof e);
    stm_lp9_attr a;
    stm_status rc = getattr_at(qid_of(k), &a);
    if (rc != STM_OK) return rc;
    e.qid     = a.qid;
    e.cookie  = this_cookie;
    e.dt_type = meta->is_dir ? 4u : 8u;     /* DT_DIR / DT_REG */
    size_t nl = strlen(meta->name);
    if (nl > STM_LP9_NAME_MAX) nl = STM_LP9_NAME_MAX;
    memcpy(e.name, meta->name, nl);
    e.name[nl] = '\0';
    e.name_len = (uint16_t)nl;
    return em->cb(&e, em->cb_ctx);
}

static stm_status vops_readdir(void *ctx, uint64_t dir_qid_path,
                                 uint64_t cookie_start,
                                 stm_lp9_dirent_cb cb, void *cb_ctx)
{
    (void)ctx;
    slate_kind dk = qid_kind(dir_qid_path);
    readdir_emit em = { .offset = cookie_start, .pos = 0, .cb = cb,
                          .cb_ctx = cb_ctx };
    stm_status rc;
    switch (dk) {
    case SLATE_KIND_ROOT:
        rc = emit_entry(SLATE_KIND_VERSION, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_STATUS, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_EVENT, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_REDRAW, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_LOG_DIR, &em);
    case SLATE_KIND_LOG_DIR:
        rc = emit_entry(SLATE_KIND_LOG_TAIL, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_LOG_APPEND, &em);
    default:
        return STM_ENOTDIR;
    }
}

static stm_status vops_lopen(void *ctx, uint32_t fid, uint64_t qid_path,
                               uint32_t flags)
{
    stm_slate *s = ctx;
    slate_kind k = qid_kind(qid_path);
    if (k == SLATE_KIND_MAX) return STM_ENOENT;
    const slate_kind_meta *meta = &KIND_META[k];

    /* Mode-vs-accmode check. lp9 server already gates dirs to RDONLY;
     * here we map writable kinds (event, log/append) to O_WRONLY only,
     * and read-only kinds to O_RDONLY only. */
    uint32_t accmode = flags & STM_LP9_O_ACCMODE;
    if (k == SLATE_KIND_EVENT || k == SLATE_KIND_LOG_APPEND) {
        if (accmode != STM_LP9_O_WRONLY) return STM_EACCES;
    } else {
        if (accmode != STM_LP9_O_RDONLY) return STM_EACCES;
    }

    if (meta->is_dir) {
        /* Dirs don't need session state; readdir is stateless. */
        return STM_OK;
    }

    /* /redraw is special: no materialized body — vops_read does the
     * blocking-wait + emit. */
    if (k == SLATE_KIND_REDRAW) {
        pthread_mutex_lock(&s->mu);
        slate_session *ss = session_alloc_locked(s, fid, qid_path);
        if (!ss) {
            pthread_mutex_unlock(&s->mu);
            return STM_ENOMEM;
        }
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
    }

    /* Trigger files: allocate session, no body needed. */
    if (k == SLATE_KIND_EVENT || k == SLATE_KIND_LOG_APPEND) {
        pthread_mutex_lock(&s->mu);
        slate_session *ss = session_alloc_locked(s, fid, qid_path);
        if (!ss) {
            pthread_mutex_unlock(&s->mu);
            return STM_ENOMEM;
        }
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
    }

    /* Read-bodied kinds: snapshot state at lopen. */
    pthread_mutex_lock(&s->mu);
    slate_session *ss = session_alloc_locked(s, fid, qid_path);
    if (!ss) {
        pthread_mutex_unlock(&s->mu);
        return STM_ENOMEM;
    }
    stm_status rc = STM_OK;
    switch (k) {
    case SLATE_KIND_VERSION:
        rc = materialize_version_locked(s, ss);
        break;
    case SLATE_KIND_STATUS:
        rc = materialize_status_locked(s, ss);
        break;
    case SLATE_KIND_LOG_TAIL:
        rc = materialize_log_tail_locked(s, ss);
        break;
    default:
        rc = STM_EBACKEND;
        break;
    }
    if (rc != STM_OK) {
        session_free_locked(ss);
        pthread_mutex_unlock(&s->mu);
        return rc;
    }
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

static stm_status vops_read(void *ctx, uint32_t fid, uint64_t qid_path,
                              uint64_t offset, void *buf, uint32_t *inout_len)
{
    stm_slate *s = ctx;
    slate_kind k = qid_kind(qid_path);
    if (k == SLATE_KIND_MAX || KIND_META[k].is_dir) {
        *inout_len = 0;
        return STM_ENOENT;
    }

    /* /redraw: blocking-read until version > offset OR daemon stops. */
    if (k == SLATE_KIND_REDRAW) {
        pthread_mutex_lock(&s->mu);
        slate_session *ss = session_get_locked(s, fid);
        if (!ss) {
            pthread_mutex_unlock(&s->mu);
            *inout_len = 0;
            return STM_EBACKEND;
        }
        /* Wait while version <= offset AND not stopped. The reader
         * passes its last-seen version as `offset`; we wake when
         * version advances past it (i.e. when at least one dispatch
         * has fired since then). Stop wakes too. */
        while (s->version <= offset && !s->stopped) {
            pthread_cond_wait(&s->cv, &s->mu);
        }
        /* Format current version; clients parse decimal + newline. */
        char tmp[64];
        int n = snprintf(tmp, sizeof tmp,
                         "%llu\n", (unsigned long long)s->version);
        if (n < 0) n = 0;
        uint32_t to_emit = (uint32_t)n;
        if (to_emit > *inout_len) to_emit = *inout_len;
        memcpy(buf, tmp, to_emit);
        *inout_len = to_emit;
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
    }

    /* Snapshot-bodied kinds: serve from session->buf. */
    pthread_mutex_lock(&s->mu);
    slate_session *ss = session_get_locked(s, fid);
    if (!ss) {
        pthread_mutex_unlock(&s->mu);
        *inout_len = 0;
        return STM_EBACKEND;
    }
    if (ss->qid_path != qid_path) {
        pthread_mutex_unlock(&s->mu);
        *inout_len = 0;
        return STM_EBACKEND;
    }
    if (offset >= ss->len) {
        *inout_len = 0;
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
    }
    uint32_t avail = ss->len - (uint32_t)offset;
    if (*inout_len > avail) *inout_len = avail;
    memcpy(buf, ss->buf + offset, *inout_len);
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

static stm_status vops_write(void *ctx, uint32_t fid, uint64_t qid_path,
                               uint64_t offset, const void *buf,
                               uint32_t len, uint32_t *out_written)
{
    stm_slate *s = ctx;
    (void)offset;
    *out_written = 0;
    slate_kind k = qid_kind(qid_path);
    if (k == SLATE_KIND_MAX) return STM_ENOENT;

    /* Validate fid bound to this kind via session. */
    pthread_mutex_lock(&s->mu);
    slate_session *ss = session_get_locked(s, fid);
    if (!ss || ss->qid_path != qid_path) {
        pthread_mutex_unlock(&s->mu);
        return STM_EBACKEND;
    }
    pthread_mutex_unlock(&s->mu);

    if (k == SLATE_KIND_EVENT) {
        if (len == 0) return STM_EINVAL;
        if (len > STM_SLATE_EVENT_LINE_MAX) return STM_EINVAL;
        stm_status rc = stm_slate_submit_event(s, (const char *)buf, len);
        if (rc != STM_OK) return rc;
        *out_written = len;
        return STM_OK;
    }
    if (k == SLATE_KIND_LOG_APPEND) {
        if (len == 0) return STM_EINVAL;
        if (len > STM_SLATE_LOG_LINE_MAX) return STM_EINVAL;
        size_t l = len;
        if (l > 0 && ((const char *)buf)[l - 1] == '\n') l--;
        if (l == 0) return STM_EINVAL;
        pthread_mutex_lock(&s->mu);
        log_append_locked(s, (const char *)buf, l);
        s->version++;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        *out_written = len;
        return STM_OK;
    }
    return STM_EACCES;
}

static void vops_clunk(void *ctx, uint32_t fid, uint64_t qid_path)
{
    stm_slate *s = ctx;
    (void)qid_path;
    pthread_mutex_lock(&s->mu);
    slate_session *ss = session_get_locked(s, fid);
    if (ss) session_free_locked(ss);
    pthread_mutex_unlock(&s->mu);
}

static const stm_lp9_vops g_vops = {
    .getattr  = vops_getattr,
    .walk     = vops_walk,
    .readdir  = vops_readdir,
    .lopen    = vops_lopen,
    .read     = vops_read,
    .write    = vops_write,
    .clunk    = vops_clunk,
    .lcreate  = NULL,
    .mkdir    = NULL,
    .unlinkat = NULL,
    .setattr  = NULL,
    .fsync    = NULL,
    .symlink  = NULL,
    .readlink = NULL,
};

const stm_lp9_vops *stm_slate_vops(void)
{
    return &g_vops;
}
