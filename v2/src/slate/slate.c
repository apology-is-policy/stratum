/* SPDX-License-Identifier: ISC */
/*
 * stm_slate — slate daemon's per-process UI state + lp9 vops backend.
 *
 * P9-SLATE-1 scope: /version /status /event /redraw /log/{tail,append}.
 * P9-SLATE-2 scope: + /connection/{socket,connected,attach}
 *                   + /panels/{left,right}/{path,entries} (read-only).
 * Compose against v2/specs/slate.tla (VersionMonotonic + EventFIFO +
 * ReadConsistent + DispatchProgress + ConnectionAtomic +
 * PanelPathConsistent).
 *
 * Concurrency: stm_slate is shared across multiple per-connection lp9
 * server threads. All UI-state accesses go through `mu`. Blocking reads
 * on /redraw cond_wait on `cv`; broadcast on every dispatch and on
 * stop / attach / disconnect.
 *
 * SLATE-2 adds a SECOND mutex `backend_mu` that serialises every
 * libstratum-9p call against the held `stm_9p_client *backend`. The
 * 9p_client API is one-op-at-a-time; without backend_mu, two slate
 * connections both reading /panels/X/entries would corrupt the wire
 * framing. backend_mu also pins the backend pointer so Disconnect /
 * Attach can't tear it down concurrently with an in-progress op.
 *
 * Lock ordering: backend_mu → mu. Always acquire backend_mu first
 * when both are needed. Never the reverse — would deadlock against
 * Attach (which takes backend_mu, then briefly s->mu to swap state).
 *
 * Trust boundaries (audit-tracked):
 *   - /event line bounded at STM_SLATE_EVENT_LINE_MAX (256 bytes)
 *     at the wire boundary (vops_write); empty lines refused with
 *     STM_EINVAL.
 *   - /connection/attach payload bounded at STM_SLATE_SOCKET_MAX
 *     at vops_write; empty body = disconnect; embedded NUL refused.
 *   - Per-fid materialized body bounded at STM_SLATE_BODY_MAX
 *     (4 KiB); snprintf-then-check.
 *   - /log/tail and /panels/X/entries use heap-allocated bulk_buf
 *     (R114 P1-1 doctrine — body that exceeds STM_SLATE_BODY_MAX
 *     MUST go through bulk_buf).
 *   - /redraw blocking-read is bounded by stop_flag; daemon shutdown
 *     calls stm_slate_stop which broadcasts cv → every blocked
 *     reader returns immediately.
 *   - Backend lifecycle: attach swaps under backend_mu (old-close
 *     before new-dial returns); disconnect snapshots+nulls backend
 *     under both locks, destroys outside any lock.
 */

#include <stratum/slate.h>

#include <stratum/9p.h>
#include <stratum/9p_client.h>
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
    SLATE_KIND_ROOT             = 0,
    SLATE_KIND_VERSION          = 1,
    SLATE_KIND_STATUS           = 2,
    SLATE_KIND_EVENT            = 3,
    SLATE_KIND_REDRAW           = 4,
    SLATE_KIND_LOG_DIR          = 5,
    SLATE_KIND_LOG_TAIL         = 6,
    SLATE_KIND_LOG_APPEND       = 7,
    /* SLATE-2: /connection/ subtree. */
    SLATE_KIND_CONN_DIR         = 8,
    SLATE_KIND_CONN_SOCKET      = 9,
    SLATE_KIND_CONN_CONNECTED   = 10,
    SLATE_KIND_CONN_ATTACH      = 11,
    /* SLATE-2: /panels/{left,right}/{path,entries}. */
    SLATE_KIND_PANELS_DIR       = 12,
    SLATE_KIND_PANEL_L_DIR      = 13,
    SLATE_KIND_PANEL_L_PATH     = 14,
    SLATE_KIND_PANEL_L_ENTRIES  = 15,
    SLATE_KIND_PANEL_R_DIR      = 16,
    SLATE_KIND_PANEL_R_PATH     = 17,
    SLATE_KIND_PANEL_R_ENTRIES  = 18,
    /* SLATE-3a: per-panel cursor + action. */
    SLATE_KIND_PANEL_L_CURSOR   = 19,
    SLATE_KIND_PANEL_L_ACTION   = 20,
    SLATE_KIND_PANEL_R_CURSOR   = 21,
    SLATE_KIND_PANEL_R_ACTION   = 22,
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
    [SLATE_KIND_ROOT]             = { true,  0555, "/"          },
    [SLATE_KIND_VERSION]          = { false, 0444, "version"    },
    [SLATE_KIND_STATUS]           = { false, 0444, "status"     },
    /* /event is mode 0200 (write-only). */
    [SLATE_KIND_EVENT]            = { false, 0200, "event"      },
    /* /redraw is read-only mode 0444 — blocking read returns version. */
    [SLATE_KIND_REDRAW]           = { false, 0444, "redraw"     },
    [SLATE_KIND_LOG_DIR]          = { true,  0555, "log"        },
    [SLATE_KIND_LOG_TAIL]         = { false, 0444, "tail"       },
    /* /log/append is mode 0200 (write-only). */
    [SLATE_KIND_LOG_APPEND]       = { false, 0200, "append"     },
    /* SLATE-2: /connection/ subtree. */
    [SLATE_KIND_CONN_DIR]         = { true,  0555, "connection" },
    [SLATE_KIND_CONN_SOCKET]      = { false, 0444, "socket"     },
    [SLATE_KIND_CONN_CONNECTED]   = { false, 0444, "connected"  },
    /* /connection/attach is mode 0200 (write-only). */
    [SLATE_KIND_CONN_ATTACH]      = { false, 0200, "attach"     },
    /* SLATE-2: /panels/ subtree. */
    [SLATE_KIND_PANELS_DIR]       = { true,  0555, "panels"     },
    [SLATE_KIND_PANEL_L_DIR]      = { true,  0555, "left"       },
    [SLATE_KIND_PANEL_L_PATH]     = { false, 0444, "path"       },
    [SLATE_KIND_PANEL_L_ENTRIES]  = { false, 0444, "entries"    },
    [SLATE_KIND_PANEL_R_DIR]      = { true,  0555, "right"      },
    [SLATE_KIND_PANEL_R_PATH]     = { false, 0444, "path"       },
    [SLATE_KIND_PANEL_R_ENTRIES]  = { false, 0444, "entries"    },
    /* SLATE-3a: cursor is RW (mode 0644 — readable + writable);
     * action is write-only (mode 0200). */
    [SLATE_KIND_PANEL_L_CURSOR]   = { false, 0644, "cursor"     },
    [SLATE_KIND_PANEL_L_ACTION]   = { false, 0200, "action"     },
    [SLATE_KIND_PANEL_R_CURSOR]   = { false, 0644, "cursor"     },
    [SLATE_KIND_PANEL_R_ACTION]   = { false, 0200, "action"     },
};

_Static_assert(SLATE_KIND_MAX == 23, "KIND_META[] sized to enum cardinality");
_Static_assert(sizeof("version") - 1     <= STM_LP9_NAME_MAX, "/version literal");
_Static_assert(sizeof("status") - 1      <= STM_LP9_NAME_MAX, "/status literal");
_Static_assert(sizeof("event") - 1       <= STM_LP9_NAME_MAX, "/event literal");
_Static_assert(sizeof("redraw") - 1      <= STM_LP9_NAME_MAX, "/redraw literal");
_Static_assert(sizeof("log") - 1         <= STM_LP9_NAME_MAX, "/log literal");
_Static_assert(sizeof("tail") - 1        <= STM_LP9_NAME_MAX, "/log/tail literal");
_Static_assert(sizeof("append") - 1      <= STM_LP9_NAME_MAX, "/log/append literal");
_Static_assert(sizeof("connection") - 1  <= STM_LP9_NAME_MAX, "/connection literal");
_Static_assert(sizeof("socket") - 1      <= STM_LP9_NAME_MAX, "/connection/socket");
_Static_assert(sizeof("connected") - 1   <= STM_LP9_NAME_MAX, "/connection/connected");
_Static_assert(sizeof("attach") - 1      <= STM_LP9_NAME_MAX, "/connection/attach");
_Static_assert(sizeof("panels") - 1      <= STM_LP9_NAME_MAX, "/panels literal");
_Static_assert(sizeof("left") - 1        <= STM_LP9_NAME_MAX, "/panels/left literal");
_Static_assert(sizeof("right") - 1       <= STM_LP9_NAME_MAX, "/panels/right literal");
_Static_assert(sizeof("path") - 1        <= STM_LP9_NAME_MAX, "/panels/X/path");
_Static_assert(sizeof("entries") - 1     <= STM_LP9_NAME_MAX, "/panels/X/entries");
_Static_assert(sizeof("cursor") - 1      <= STM_LP9_NAME_MAX, "/panels/X/cursor");
_Static_assert(sizeof("action") - 1      <= STM_LP9_NAME_MAX, "/panels/X/action");

/* Backend fid convention. The slate daemon is the SOLE 9P client of
 * its attached stratumd; the lib's caller-managed fid namespace is
 * fully ours. We pin two fids: the attach root (lifetime = backend
 * lifetime) and a working fid (clunked at end of every backend op).
 *
 * The 200-block keeps slate's fids cleanly separated from any future
 * slate-internal scratch or extension uses. */
#define SLATE_BACKEND_ROOT_FID  ((uint32_t)200u)
#define SLATE_BACKEND_WORK_FID  ((uint32_t)201u)
#define SLATE_BACKEND_ENT_FID   ((uint32_t)202u)
/* SLATE-3b: CWD_FID is a clone of WORK_FID bound to the panel's cwd
 * before WORK is Tlopen'd. Per-entry Twalks issue from CWD_FID so a
 * nested cwd ("/sub/...") resolves entry names to the correct
 * directory rather than always to root. CWD stays UNOPENED so
 * Twalk(CWD, ENT, [name]) is unambiguously valid in 9P2000.L
 * (walking from an opened fid is server-defined; from an unopened
 * fid is universal). */
#define SLATE_BACKEND_CWD_FID   ((uint32_t)203u)

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
    /* R114 P1-1: bulk-format kinds (currently only /log/tail) live
     * here — heap-allocated at lopen-materialize, freed at clunk
     * BEFORE the memset (mirrors /ctl/'s P9-CTL-1e bulk_buf pattern).
     * NULL on the bounded-body path. */
    uint8_t  *bulk_buf;
    uint32_t  bulk_len;
} slate_session;

/* ────────────────────────────────────────────────────────────────────── */
/* The state.                                                             */
/* ────────────────────────────────────────────────────────────────────── */

/* SLATE-2 + SLATE-3a: per-panel state. */
typedef struct {
    char     path[STM_SLATE_PATH_MAX + 1];     /* NUL-terminated; "" disconnected */
    size_t   path_len;
    /* SLATE-3a: cursor is a numeric index into the panel's current
     * entries listing. Bounds-checking against the entry count is
     * the renderer's responsibility — slate accepts any uint32_t.
     * Reset to 0 on attach + disconnect + cwd change. */
    uint32_t cursor;
} slate_panel;

#define SLATE_PANEL_LEFT  0
#define SLATE_PANEL_RIGHT 1
#define SLATE_PANEL_COUNT 2

struct stm_slate {
    pthread_mutex_t mu;
    pthread_cond_t  cv;       /* broadcast on dispatch + on stop +
                               * on attach + on disconnect */

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

    /* SLATE-2: connection state. ConnectionAtomic invariant:
     *   connected == (socket_len > 0)
     * is maintained at every transition. PanelPathConsistent:
     *   connected => panel[i].path_len > 0 (path = "/")
     *   ~connected => panel[i].path_len == 0
     * Both invariants are touched only in attach/disconnect/destroy. */
    bool            connected;
    char            socket[STM_SLATE_SOCKET_MAX + 1];
    size_t          socket_len;
    slate_panel     panel[SLATE_PANEL_COUNT];

    /* SLATE-2: backend client. Allocated at attach, swapped/cleared
     * under backend_mu. May be NULL (disconnected) or non-NULL
     * (connected). When connected, root fid SLATE_BACKEND_ROOT_FID is
     * bound to the attach root; working fids are allocated/clunked
     * per backend op. */
    pthread_mutex_t backend_mu;       /* serialises every stm_9p_* call */
    stm_9p_client  *backend;          /* protected by `mu` for read,
                                       * by both for write (attach/dis) */

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
    if (pthread_mutex_init(&s->backend_mu, NULL) != 0) {
        pthread_cond_destroy(&s->cv);
        pthread_mutex_destroy(&s->mu);
        free(s);
        return STM_EIO;
    }
    s->version = 1u;
    /* PanelPathConsistent + ConnectionAtomic both hold by calloc:
     *   connected = false; socket_len = 0; panel[i].path_len = 0. */
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
    /* Close the backend if held. Caller has already destroyed every
     * lp9 server using this state (R96 P2-1 doctrine), so no
     * concurrent backend op is possible at this point. */
    pthread_mutex_lock(&s->backend_mu);
    pthread_mutex_lock(&s->mu);
    stm_9p_client *bc = s->backend;
    s->backend = NULL;
    /* R115 P3-6: defensive sweep of any leftover heap-allocated
     * bulk_buf in sessions. R96 P2-1 caller contract should have
     * drained all sessions via vops_clunk → session_free_locked
     * BEFORE we got here, but a future caller violating the contract
     * (or a unit test bypassing the lp9 server) would leak otherwise.
     * Free BEFORE the memset that clears the slot pointer (load-
     * bearing order — same posture as session_free_locked). */
    for (uint32_t i = 0; i < STM_SLATE_MAX_SESSIONS; i++) {
        if (s->sessions[i].active && s->sessions[i].bulk_buf) {
            free(s->sessions[i].bulk_buf);
            s->sessions[i].bulk_buf = NULL;
        }
    }
    pthread_mutex_unlock(&s->mu);
    if (bc) stm_9p_close(bc);
    pthread_mutex_unlock(&s->backend_mu);

    pthread_mutex_destroy(&s->backend_mu);
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
    /* Free any heap-allocated bulk_buf before zeroing the slot pointer
     * (R114 P1-1 doctrine — same posture as session_free_locked). */
    for (uint32_t i = 0; i < STM_SLATE_MAX_SESSIONS; i++) {
        if (s->sessions[i].active && s->sessions[i].bulk_buf) {
            free(s->sessions[i].bulk_buf);
        }
    }
    memset(s->sessions, 0, sizeof s->sessions);
    pthread_mutex_unlock(&s->mu);
}

/* ────────────────────────────────────────────────────────────────────── */
/* SLATE-2: connection state mutators + accessors.                        */
/* ────────────────────────────────────────────────────────────────────── */

/* Mu held; perform the post-attach state swap atomically. ConnectionAtomic
 * + PanelPathConsistent both maintained: connected becomes TRUE, socket
 * is set, panel paths reset to "/", panel cursors reset to 0, version
 * bumps, cv broadcasts. */
static void attach_state_swap_locked(stm_slate *s, const char *path, size_t len,
                                       stm_9p_client *new_bc, stm_9p_client **old_bc_out)
{
    *old_bc_out = s->backend;
    s->backend = new_bc;
    memcpy(s->socket, path, len);
    s->socket[len] = '\0';
    s->socket_len = len;
    s->connected = true;
    for (int i = 0; i < SLATE_PANEL_COUNT; i++) {
        s->panel[i].path[0] = '/';
        s->panel[i].path[1] = '\0';
        s->panel[i].path_len = 1u;
        s->panel[i].cursor = 0u;
    }
    s->version++;
    pthread_cond_broadcast(&s->cv);
}

/* Mu held; perform the post-disconnect state swap. ConnectionAtomic
 * + PanelPathConsistent both maintained: connected becomes FALSE,
 * socket clears, panel paths clear, cursors reset, version bumps,
 * cv broadcasts. */
static void disconnect_state_swap_locked(stm_slate *s, stm_9p_client **old_bc_out)
{
    *old_bc_out = s->backend;
    s->backend = NULL;
    s->socket[0] = '\0';
    s->socket_len = 0;
    s->connected = false;
    for (int i = 0; i < SLATE_PANEL_COUNT; i++) {
        s->panel[i].path[0] = '\0';
        s->panel[i].path_len = 0;
        s->panel[i].cursor = 0u;
    }
    s->version++;
    pthread_cond_broadcast(&s->cv);
}

stm_status stm_slate_disconnect(stm_slate *s)
{
    if (!s) return STM_EINVAL;

    pthread_mutex_lock(&s->backend_mu);
    pthread_mutex_lock(&s->mu);
    if (!s->connected) {
        /* No-op — leave version unchanged (matches "version changes
         * only on real state mutation" doctrine). */
        pthread_mutex_unlock(&s->mu);
        pthread_mutex_unlock(&s->backend_mu);
        return STM_OK;
    }
    stm_9p_client *old_bc = NULL;
    disconnect_state_swap_locked(s, &old_bc);
    pthread_mutex_unlock(&s->mu);
    /* R115 P2-1: close UNDER backend_mu (matches stm_slate_attach's
     * close-then-unlock order). backend_mu pins the backend pointer
     * for any concurrent panel-entries op so we don't close out from
     * under it. Releasing backend_mu BEFORE close would let a new
     * attach start dialing while old_bc is still being closed —
     * inconsistent with attach's discipline and allows fd-exhaustion
     * race under disconnect/attach storms. */
    if (old_bc) stm_9p_close(old_bc);
    pthread_mutex_unlock(&s->backend_mu);
    return STM_OK;
}

stm_status stm_slate_attach(stm_slate *s, const char *socket_path, size_t len)
{
    if (!s) return STM_EINVAL;
    /* Empty body = disconnect. */
    if (len == 0) return stm_slate_disconnect(s);
    if (!socket_path) return STM_EINVAL;
    if (len > STM_SLATE_SOCKET_MAX) return STM_EINVAL;
    /* Embedded NUL refused (paths to AF_UNIX sockets cannot contain
     * NUL except for the abstract-namespace leading byte on Linux,
     * which v2.0 doesn't support — forward-noted). */
    for (size_t i = 0; i < len; i++) {
        if (socket_path[i] == '\0') return STM_EINVAL;
    }

    /* Make a NUL-terminated copy for stm_9p_dial_unix (the API takes
     * a C string). */
    char path[STM_SLATE_SOCKET_MAX + 1];
    memcpy(path, socket_path, len);
    path[len] = '\0';

    /* Take backend_mu — blocks any concurrent backend op AND any
     * concurrent attach/disconnect. The dial happens UNDER
     * backend_mu but NOT under s->mu so /event etc keep flowing. */
    pthread_mutex_lock(&s->backend_mu);

    stm_9p_dial_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.msize    = 0;             /* default — server may downgrade */
    opts.uname    = NULL;          /* "" */
    opts.aname    = NULL;          /* default root dataset */
    opts.n_uname  = (uint32_t)-1;  /* sentinel — server uses uid */
    opts.root_fid = SLATE_BACKEND_ROOT_FID;

    stm_9p_client *new_bc = NULL;
    stm_status rc = stm_9p_dial_unix(path, &opts, &new_bc);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }

    /* Swap state under s->mu. */
    pthread_mutex_lock(&s->mu);
    stm_9p_client *old_bc = NULL;
    attach_state_swap_locked(s, path, len, new_bc, &old_bc);
    pthread_mutex_unlock(&s->mu);

    /* Close the prior backend OUTSIDE s->mu (still UNDER backend_mu so
     * no other op can have a reference to old_bc — they would have
     * to take backend_mu first). */
    if (old_bc) stm_9p_close(old_bc);

    pthread_mutex_unlock(&s->backend_mu);
    return STM_OK;
}

bool stm_slate_connected(stm_slate *s)
{
    if (!s) return false;
    pthread_mutex_lock(&s->mu);
    bool v = s->connected;
    pthread_mutex_unlock(&s->mu);
    return v;
}

size_t stm_slate_socket(stm_slate *s, char *buf, size_t buf_cap)
{
    if (!s) return 0;
    pthread_mutex_lock(&s->mu);
    size_t n = s->socket_len;
    if (buf && buf_cap > 0) {
        size_t copy = (n < buf_cap - 1) ? n : (buf_cap - 1);
        memcpy(buf, s->socket, copy);
        buf[copy] = '\0';
    }
    pthread_mutex_unlock(&s->mu);
    return n;
}

size_t stm_slate_panel_path(stm_slate *s, int panel_idx,
                              char *buf, size_t buf_cap)
{
    if (!s) return 0;
    if (panel_idx < 0 || panel_idx >= SLATE_PANEL_COUNT) return 0;
    pthread_mutex_lock(&s->mu);
    size_t n = s->panel[panel_idx].path_len;
    if (buf && buf_cap > 0) {
        size_t copy = (n < buf_cap - 1) ? n : (buf_cap - 1);
        memcpy(buf, s->panel[panel_idx].path, copy);
        buf[copy] = '\0';
    }
    pthread_mutex_unlock(&s->mu);
    return n;
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
    /* R114 P1-1: free bulk_buf BEFORE memset zeros the pointer.
     * Mirrors /ctl/ P9-CTL-1e session_free_locked discipline; the
     * order is load-bearing — reverse it and the alloc leaks. */
    free(ss->bulk_buf);
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

/* SLATE-2: /connection/socket — current backend socket path or empty
 * line. Always emits at least a trailing newline so readers see a
 * one-line file. */
static stm_status materialize_conn_socket_locked(stm_slate *s, slate_session *ss)
{
    if (s->socket_len + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, s->socket, s->socket_len);
    ss->buf[s->socket_len] = '\n';
    ss->len = (uint32_t)(s->socket_len + 1u);
    return STM_OK;
}

/* SLATE-2: /connection/connected — "1\n" or "0\n". */
static stm_status materialize_conn_connected_locked(stm_slate *s, slate_session *ss)
{
    ss->buf[0] = s->connected ? '1' : '0';
    ss->buf[1] = '\n';
    ss->len = 2u;
    return STM_OK;
}

/* SLATE-2: /panels/X/path — current panel cwd + newline, or empty
 * (just newline) if disconnected. */
static stm_status materialize_panel_path_locked(stm_slate *s, slate_session *ss,
                                                    int panel_idx)
{
    size_t n = s->panel[panel_idx].path_len;
    if (n + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, s->panel[panel_idx].path, n);
    ss->buf[n] = '\n';
    ss->len = (uint32_t)(n + 1u);
    return STM_OK;
}

/* SLATE-3a: /panels/X/cursor — current cursor index + newline.
 * Decimal format; max 10 digits + '\n' + NUL fits in BODY_MAX. */
static stm_status materialize_panel_cursor_locked(stm_slate *s, slate_session *ss,
                                                      int panel_idx)
{
    int n = snprintf((char *)ss->buf, sizeof ss->buf,
                        "%u\n", (unsigned)s->panel[panel_idx].cursor);
    if (n < 0 || n >= (int)sizeof ss->buf) return STM_ERANGE;
    ss->len = (uint32_t)n;
    return STM_OK;
}

/* R114 P1-1: /log/tail uses a per-fid heap-allocated bulk_buf so
 * 100 × 321-byte log lines (~32 KiB worst case) can be served. The
 * fixed-size ss->buf (4 KiB) covers /version + /status only.
 * Mirrors /ctl/'s P9-CTL-1e Prometheus exposition pattern. */
static stm_status materialize_log_tail_locked(stm_slate *s, slate_session *ss)
{
    /* Compute total size first so we malloc once. */
    size_t total = 0;
    for (uint32_t i = 0; i < s->log_count; i++) {
        uint32_t idx = (s->log_head + i) % STM_SLATE_LOG_LINES;
        total += s->log_len[idx] + 1u;     /* +1 for newline */
    }
    if (total > STM_SLATE_LOG_TAIL_MAX) return STM_ERANGE;

    /* Empty body is fine — bulk_buf stays NULL, vops_read serves 0
     * bytes from ss->buf (already zeroed). */
    if (total == 0) {
        ss->bulk_buf = NULL;
        ss->bulk_len = 0;
        return STM_OK;
    }

    uint8_t *buf = malloc(total);
    if (!buf) return STM_ENOMEM;

    size_t off = 0;
    for (uint32_t i = 0; i < s->log_count; i++) {
        uint32_t idx = (s->log_head + i) % STM_SLATE_LOG_LINES;
        size_t llen = s->log_len[idx];
        memcpy(buf + off, s->log[idx], llen);
        buf[off + llen] = '\n';
        off += llen + 1u;
    }
    ss->bulk_buf = buf;
    ss->bulk_len = (uint32_t)total;
    return STM_OK;
}

/* ────────────────────────────────────────────────────────────────────── */
/* SLATE-2: /panels/X/entries materialisation — calls into                */
/* libstratum-9p under backend_mu (NEVER under s->mu).                    */
/* ────────────────────────────────────────────────────────────────────── */

/* Collected dirent for two-phase render. Phase 1 enumerates names
 * and types via Treaddir; Phase 2 iterates the list and does
 * Twalk + Tgetattr per entry to fetch mode/size/mtime. Phase 1 has
 * to complete before Phase 2 starts because we re-bind SLATE_BACKEND_
 * ENT_FID per entry — overlapping a Treaddir cursor with a Twalk on
 * the same connection would intermix wire ops. */
typedef struct {
    char     name[STM_LP9_NAME_MAX + 1];
    uint16_t name_len;
    uint8_t  type;        /* DT_* */
} slate_dirent;

typedef struct {
    slate_dirent *arr;
    uint32_t      cap;
    uint32_t      count;
} slate_dir_collect;

static stm_status collect_dirent_cb(const stm_9p_qid *qid, uint64_t cookie,
                                       uint8_t type, const char *name,
                                       size_t name_len, void *ctx)
{
    (void)qid; (void)cookie;
    slate_dir_collect *dc = ctx;
    /* Skip "." and "..". */
    if ((name_len == 1 && name[0] == '.') ||
        (name_len == 2 && name[0] == '.' && name[1] == '.')) {
        return STM_OK;
    }
    if (dc->count >= dc->cap) {
        /* Stop iteration cleanly — caller treats this as truncation,
         * not an error. R111 P2 F-3: pick a status the server won't
         * produce for the readdir. */
        return STM_ENOTSUPPORTED;
    }
    if (name_len > STM_LP9_NAME_MAX) name_len = STM_LP9_NAME_MAX;
    slate_dirent *de = &dc->arr[dc->count++];
    memcpy(de->name, name, name_len);
    de->name[name_len] = '\0';
    de->name_len = (uint16_t)name_len;
    de->type = type;
    return STM_OK;
}

/* Walk root → cwd into out_fid. Path is "/" or "/a/b/c". Empty path
 * is invalid (caller must short-circuit). Returns STM_OK on success.
 * On error, out_fid is NOT bound (per Twalk partial-walk semantics). */
static stm_status walk_to_cwd(stm_9p_client *bc, const char *cwd,
                                 uint32_t out_fid)
{
    /* Parse path components. STM_9P_MAX_WALK = 16 — paths deeper
     * than that need iterative re-walking; SLATE-2 only ever sees
     * "/" so this short-circuits. SLATE-3 will need iterative walk. */
    const char *names_arr[STM_9P_MAX_WALK];
    char        names_buf[STM_9P_MAX_WALK][STM_LP9_NAME_MAX + 1];
    uint16_t    n_names = 0;

    const char *p = cwd;
    if (*p == '/') p++;
    while (*p) {
        if (n_names >= STM_9P_MAX_WALK) return STM_EINVAL;
        const char *slash = strchr(p, '/');
        size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);
        if (comp_len == 0) {
            /* "//" — skip the empty component. */
            if (!slash) break;
            p = slash + 1;
            continue;
        }
        if (comp_len > STM_LP9_NAME_MAX) return STM_EINVAL;
        memcpy(names_buf[n_names], p, comp_len);
        names_buf[n_names][comp_len] = '\0';
        names_arr[n_names] = names_buf[n_names];
        n_names++;
        if (!slash) break;
        p = slash + 1;
    }

    return stm_9p_walk(bc, SLATE_BACKEND_ROOT_FID, out_fid,
                          n_names, names_arr, NULL, NULL);
}

/* Render panel entries against the backend. Acquires + releases
 * backend_mu. Briefly takes s->mu only to read the backend pointer.
 * Returns:
 *   STM_OK + *out_buf=NULL + *out_len=0  → disconnected; serve empty
 *   STM_OK + *out_buf=heap + *out_len>0  → success; caller frees buf
 *   any other status                     → backend error; *out_buf=NULL
 *
 * Body format: one line per entry, "TYPE MODE SIZE MTIME NAME\n".
 * Truncated at STM_SLATE_ENTRIES_MAX entries. */
static stm_status panel_entries_render(stm_slate *s, const char *cwd,
                                            uint8_t **out_buf, uint32_t *out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    pthread_mutex_lock(&s->backend_mu);

    /* Snapshot backend pointer under s->mu (very brief). After we
     * release s->mu, the backend pointer can't change because we
     * still hold backend_mu (Disconnect / Attach also take backend_mu
     * before mutating s->backend). */
    pthread_mutex_lock(&s->mu);
    stm_9p_client *bc = s->backend;
    pthread_mutex_unlock(&s->mu);
    if (!bc) {
        pthread_mutex_unlock(&s->backend_mu);
        return STM_OK;  /* disconnected → empty body. */
    }

    /* Phase 1: walk to cwd, clone to CWD_FID for per-entry walks
     * (R115 P3 + R116 P3 forward-note carry — supports nested cwd),
     * lopen WORK for read, readdir batches into a collected name list.
     * Clunk WORK after readdir; CWD lives until end of phase 2. */
    stm_status rc = walk_to_cwd(bc, cwd, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }
    /* Clone WORK to CWD_FID via Twalk(WORK, CWD, n_names=0) — both
     * point at the panel's cwd, both unopened. Done BEFORE lopen
     * on WORK so the source fid is unopened (clean walk semantics). */
    rc = stm_9p_walk(bc, SLATE_BACKEND_WORK_FID, SLATE_BACKEND_CWD_FID,
                        0u, NULL, NULL, NULL);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }
    rc = stm_9p_lopen(bc, SLATE_BACKEND_WORK_FID,
                         STM_9P_O_RDONLY | STM_9P_O_DIRECTORY,
                         NULL, NULL);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }

    slate_dirent *arr = calloc(STM_SLATE_ENTRIES_MAX, sizeof *arr);
    if (!arr) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->backend_mu);
        return STM_ENOMEM;
    }
    slate_dir_collect dc = { arr, STM_SLATE_ENTRIES_MAX, 0 };

    /* Loop Treaddir batches until count==0 (EOF) or cb-stop. */
    uint64_t offset = 0;
    while (1) {
        uint32_t entries = 0;
        uint64_t next_off = offset;
        rc = stm_9p_readdir(bc, SLATE_BACKEND_WORK_FID,
                               offset, 0u,
                               collect_dirent_cb, &dc,
                               &entries, &next_off);
        /* cb-stop → STM_ENOTSUPPORTED (truncation sentinel) — fine. */
        if (rc == STM_ENOTSUPPORTED) { rc = STM_OK; break; }
        if (rc != STM_OK) break;
        if (entries == 0) break;        /* EOF */
        if (next_off == offset) break;  /* defensive — server stuck */
        offset = next_off;
    }
    (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        free(arr);
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }

    /* Phase 2: per-entry walk + getattr. Walks from CWD_FID (the
     * panel's cwd) so nested cwds resolve correctly. Use
     * SLATE_BACKEND_ENT_FID. On any per-entry failure we record
     * minimal info (mode=0, size=0, mtime=0); the listing remains
     * usable. */
    size_t body_cap = (size_t)dc.count * STM_SLATE_ENTRY_LINE_MAX + 1u;
    if (body_cap == 1u) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        free(arr);
        pthread_mutex_unlock(&s->backend_mu);
        return STM_OK;  /* empty dir → empty body */
    }
    if (body_cap > STM_SLATE_LOG_TAIL_MAX) body_cap = STM_SLATE_LOG_TAIL_MAX;
    uint8_t *body = malloc(body_cap);
    if (!body) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        free(arr);
        pthread_mutex_unlock(&s->backend_mu);
        return STM_ENOMEM;
    }

    size_t body_off = 0;
    for (uint32_t i = 0; i < dc.count; i++) {
        slate_dirent *de = &arr[i];
        uint32_t mode_lo = 0;
        uint64_t size = 0;
        uint64_t mtime = 0;

        const char *names_arr[1] = { de->name };
        if (stm_9p_walk(bc, SLATE_BACKEND_CWD_FID, SLATE_BACKEND_ENT_FID,
                            1, names_arr, NULL, NULL) == STM_OK) {
            stm_9p_attr a;
            memset(&a, 0, sizeof a);
            (void)stm_9p_getattr(bc, SLATE_BACKEND_ENT_FID,
                                    STM_9P_GETATTR_MODE | STM_9P_GETATTR_SIZE |
                                    STM_9P_GETATTR_MTIME, &a);
            (void)stm_9p_clunk(bc, SLATE_BACKEND_ENT_FID);
            mode_lo = a.mode & 07777u;
            size    = a.size;
            mtime   = a.mtime_sec;
        }

        char tc;
        switch (de->type) {
            case 4u:  tc = 'd'; break;   /* DT_DIR */
            case 8u:  tc = '-'; break;   /* DT_REG */
            case 10u: tc = 'l'; break;   /* DT_LNK */
            default:  tc = '?'; break;
        }

        /* R115 P1-1: sanitize control bytes in entry name BEFORE
         * snprintf'ing into the line-oriented body. stm_fs's
         * `fs_validate_dirent_name` only rejects '/' and '\0' (POSIX
         * permits any other byte in filenames); without this filter,
         * a filename containing '\n' would split the rendered line
         * and let a malicious or buggy backend forge entries that a
         * line-by-line renderer treats as real files. R99 P2-1
         * doctrine class — sanitize at the display surface since
         * stm_fs cannot tighten its filter without breaking POSIX.
         * Bytes < 0x20 OR == 0x7F replaced with '?'; UTF-8 multi-byte
         * sequences (≥ 0x80) pass through unchanged. The ORIGINAL
         * name is used for the per-entry Twalk above so we still
         * resolve the real backend file. */
        char safe_name[STM_LP9_NAME_MAX + 1];
        size_t safe_len = de->name_len;
        if (safe_len > STM_LP9_NAME_MAX) safe_len = STM_LP9_NAME_MAX;
        for (size_t ni = 0; ni < safe_len; ni++) {
            unsigned char c = (unsigned char)de->name[ni];
            safe_name[ni] = (c < 0x20u || c == 0x7Fu) ? '?' : (char)c;
        }
        safe_name[safe_len] = '\0';

        char line[STM_SLATE_ENTRY_LINE_MAX + 1];
        int n = snprintf(line, sizeof line, "%c %04o %llu %llu %s\n",
                            tc, (unsigned)mode_lo,
                            (unsigned long long)size,
                            (unsigned long long)mtime,
                            safe_name);
        if (n < 0) n = 0;
        if (n >= (int)sizeof line) n = (int)sizeof line - 1;
        if (body_off + (size_t)n > body_cap) break;  /* hard cap */
        memcpy(body + body_off, line, (size_t)n);
        body_off += (size_t)n;
    }

    (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
    free(arr);
    pthread_mutex_unlock(&s->backend_mu);

    *out_buf = body;
    *out_len = (uint32_t)body_off;
    return STM_OK;
}

/* SLATE-3b: action verb dispatch. Table-driven (R104 doctrine + R116
 * P3-3 carry) so SLATE-3c+'s additional verbs (key F3 view, mouse
 * click, etc.) just append a row.
 *
 * Each verb's handler returns STM_OK on successful dispatch (whether
 * or not state changed), or a non-OK status on failure. The handler
 * is responsible for any version bump under s->mu.
 *
 * "key Up" / "key Down": cursor adjustment, no backend op required;
 * implemented inline to avoid the overhead of a backend round-trip.
 * "key Enter": calls descend_panel (forward declaration below). */
static stm_status descend_panel(stm_slate *s, int panel_idx);

static stm_status verb_key_up(stm_slate *s, int panel_idx)
{
    pthread_mutex_lock(&s->mu);
    bool moved = false;
    if (s->panel[panel_idx].cursor > 0u) {
        s->panel[panel_idx].cursor--;
        moved = true;
    }
    if (moved) {
        s->version++;
        pthread_cond_broadcast(&s->cv);
    }
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

static stm_status verb_key_down(stm_slate *s, int panel_idx)
{
    pthread_mutex_lock(&s->mu);
    bool moved = false;
    if (s->panel[panel_idx].cursor < UINT32_MAX) {
        s->panel[panel_idx].cursor++;
        moved = true;
    }
    if (moved) {
        s->version++;
        pthread_cond_broadcast(&s->cv);
    }
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

static stm_status verb_key_enter(stm_slate *s, int panel_idx)
{
    return descend_panel(s, panel_idx);
}

/* SLATE-3c "key Backspace": ascend to parent dir. Pure state
 * mutation — no backend op needed because the parent of any path
 * reached via descend was reachable AT DESCEND TIME (we walked
 * through it then). If the backend has since removed it,
 * panel_entries_render's walk_to_cwd will fail and the entries
 * listing will be empty — graceful degradation, not a soundness
 * issue. Disconnected → STM_EBACKEND. Already at root → no-op
 * (no version bump per "version changes only on real state mutation"
 * doctrine). */
static stm_status ascend_panel(stm_slate *s, int panel_idx)
{
    pthread_mutex_lock(&s->mu);
    if (!s->connected) {
        pthread_mutex_unlock(&s->mu);
        return STM_EBACKEND;
    }
    size_t cwd_len = s->panel[panel_idx].path_len;
    if (cwd_len == 0u) {
        pthread_mutex_unlock(&s->mu);
        return STM_EBACKEND;
    }
    /* R118 P3-1 defense-in-depth: same bound check posture as
     * descend_panel + lopen_panel_entries. Today's state machine
     * never exceeds STM_SLATE_PATH_MAX (attach sets 1, descend caps
     * at target_path_len, ascend only shrinks), but a future writable
     * /panels/X/cwd or `goto` verb that bypasses the cap would let
     * the loop below walk past the buffer end if path_len were
     * corrupt. */
    if (cwd_len > STM_SLATE_PATH_MAX) {
        pthread_mutex_unlock(&s->mu);
        return STM_ERANGE;
    }
    /* Already at root — no-op. */
    if (cwd_len == 1u && s->panel[panel_idx].path[0] == '/') {
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
    }
    /* Find the last '/' — everything before it is the parent path.
     * SLATE-3b's descend produces "/<a>" or "/<a>/<b>" etc., so the
     * last '/' always exists and is at index ≥ 0. */
    size_t last_slash = 0u;
    bool found_slash = false;
    for (size_t i = cwd_len; i > 0u; i--) {
        if (s->panel[panel_idx].path[i - 1u] == '/') {
            last_slash = i - 1u;
            found_slash = true;
            break;
        }
    }
    if (!found_slash) {
        /* Defensive — descend always produces leading-/ paths;
         * a path without '/' would be a state-machine violation. */
        pthread_mutex_unlock(&s->mu);
        return STM_ERANGE;
    }
    if (last_slash == 0u) {
        /* path was "/<single>" — parent is "/". */
        s->panel[panel_idx].path[0] = '/';
        s->panel[panel_idx].path[1] = '\0';
        s->panel[panel_idx].path_len = 1u;
    } else {
        /* path was "/<a>/.../<x>" — truncate at last_slash, keeping
         * the prefix as the new path. */
        s->panel[panel_idx].path[last_slash] = '\0';
        s->panel[panel_idx].path_len = last_slash;
    }
    s->panel[panel_idx].cursor = 0u;
    s->version++;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

static stm_status verb_key_backspace(stm_slate *s, int panel_idx)
{
    return ascend_panel(s, panel_idx);
}

typedef struct {
    const char  *verb;       /* literal — not NUL-terminated */
    size_t       verb_len;
    stm_status (*handler)(stm_slate *, int panel_idx);
} action_verb_row;

static const action_verb_row ACTION_VERBS[] = {
    { "key Up",        6u,  verb_key_up        },
    { "key Down",      8u,  verb_key_down      },
    { "key Enter",     9u,  verb_key_enter     },
    { "key Backspace", 13u, verb_key_backspace },
};

#define ACTION_VERBS_COUNT (sizeof(ACTION_VERBS) / sizeof(ACTION_VERBS[0]))

static stm_status action_dispatch_verb(stm_slate *s, int panel_idx,
                                            const char *body, size_t body_len)
{
    for (size_t i = 0; i < ACTION_VERBS_COUNT; i++) {
        const action_verb_row *r = &ACTION_VERBS[i];
        if (body_len == r->verb_len &&
            memcmp(body, r->verb, r->verb_len) == 0) {
            return r->handler(s, panel_idx);
        }
    }
    return STM_ENOTSUPPORTED;
}

/* SLATE-3b "key Enter": descend into the cursor's entry if it's a
 * directory. Snapshots cursor + cwd under s->mu, runs a backend
 * walk + readdir + getattr to find entries[cursor], builds new
 * cwd path, atomically swaps panel.path under s->mu (with cursor
 * reset to 0). On failure (cursor out of range, entry not a dir,
 * disconnected mid-op) returns the appropriate error and leaves
 * panel state untouched. */
typedef struct {
    uint32_t target_idx;
    uint32_t emitted;
    bool     found;
    bool     bad_name;   /* R117 P1-1: target entry name contains a
                          * control byte; descend MUST refuse to keep
                          * panel.path consistent with backend names. */
    char     name[STM_LP9_NAME_MAX + 1];
    uint16_t name_len;
    uint8_t  type;
} descend_find_ctx;

static stm_status descend_find_cb(const stm_9p_qid *qid, uint64_t cookie,
                                       uint8_t type, const char *name,
                                       size_t name_len, void *ctx)
{
    (void)qid; (void)cookie;
    descend_find_ctx *fc = ctx;
    /* Skip "." and "..". */
    if ((name_len == 1 && name[0] == '.') ||
        (name_len == 2 && name[0] == '.' && name[1] == '.')) {
        return STM_OK;
    }
    if (fc->emitted == fc->target_idx) {
        if (name_len > STM_LP9_NAME_MAX) name_len = STM_LP9_NAME_MAX;
        memcpy(fc->name, name, name_len);
        fc->name[name_len] = '\0';
        fc->name_len = (uint16_t)name_len;
        fc->type = type;
        fc->found = true;
        /* R117 P1-1: same R115 P1-1 line-injection class extended to
         * the descend write-site. /panels/X/path is line-oriented; if
         * an entry name embeds '\n' / '\r' / '\x7F' / any byte < 0x20,
         * writing it into panel.path would forge multi-line reads of
         * /panels/left/path. R115's solution (sanitize at display)
         * doesn't apply here because panel.path is ALSO used as a
         * KEY for subsequent backend ops (panel_entries_render's
         * walk_to_cwd(path)) — sanitizing on storage would diverge
         * from the real backend name and break the entries-listing.
         * Instead: REFUSE descent into such entries. UTF-8 multi-byte
         * sequences (≥ 0x80) pass through unchanged. */
        for (uint16_t i = 0; i < fc->name_len; i++) {
            unsigned char c = (unsigned char)fc->name[i];
            if (c < 0x20u || c == 0x7Fu) {
                fc->bad_name = true;
                break;
            }
        }
        /* Stop iteration via R111 P2 F-3 sentinel. */
        return STM_ENOTSUPPORTED;
    }
    fc->emitted++;
    return STM_OK;
}

/* Build the post-descent cwd path. cwd is the current panel cwd
 * (NUL-terminated, length cwd_len). entry is the entry name. Result
 * lands in `out` (caller's buffer of size out_cap). Returns STM_OK
 * on success (with `*out_len` set to the result length excluding
 * NUL), STM_ERANGE if out is too small. */
static stm_status build_descended_path(const char *cwd, size_t cwd_len,
                                            const char *entry, size_t entry_len,
                                            char *out, size_t out_cap,
                                            size_t *out_len)
{
    /* Cases:
     *   cwd = "/"      → out = "/" + entry
     *   cwd = "/a/b/c" → out = cwd + "/" + entry
     */
    int n;
    if (cwd_len == 1 && cwd[0] == '/') {
        n = snprintf(out, out_cap, "/%.*s",
                        (int)entry_len, entry);
    } else {
        n = snprintf(out, out_cap, "%.*s/%.*s",
                        (int)cwd_len, cwd,
                        (int)entry_len, entry);
    }
    if (n < 0 || (size_t)n >= out_cap) return STM_ERANGE;
    *out_len = (size_t)n;
    return STM_OK;
}

static stm_status descend_panel(stm_slate *s, int panel_idx)
{
    /* Snapshot cwd + cursor under s->mu. */
    char cwd[STM_SLATE_PATH_MAX + 1];
    size_t cwd_len;
    uint32_t cursor;
    pthread_mutex_lock(&s->mu);
    if (!s->connected) {
        pthread_mutex_unlock(&s->mu);
        return STM_EBACKEND;  /* not connected — descend has no target */
    }
    cwd_len = s->panel[panel_idx].path_len;
    if (cwd_len == 0u || cwd_len > STM_SLATE_PATH_MAX) {
        pthread_mutex_unlock(&s->mu);
        return STM_ERANGE;
    }
    memcpy(cwd, s->panel[panel_idx].path, cwd_len);
    cwd[cwd_len] = '\0';
    cursor = s->panel[panel_idx].cursor;
    pthread_mutex_unlock(&s->mu);

    /* R117 P3-1: cap cursor at STM_SLATE_ENTRIES_MAX so descend's
     * readdir loop terminates promptly (parity with
     * panel_entries_render's truncation cap). A cursor beyond the
     * rendered cap can't possibly correspond to a user-visible
     * entry; refuse early to bound the worst-case backend scan and
     * the duration backend_mu is held. */
    if (cursor >= STM_SLATE_ENTRIES_MAX) {
        return STM_EINVAL;
    }

    /* Take backend_mu and snapshot the backend client. */
    pthread_mutex_lock(&s->backend_mu);
    pthread_mutex_lock(&s->mu);
    stm_9p_client *bc = s->backend;
    pthread_mutex_unlock(&s->mu);
    if (!bc) {
        pthread_mutex_unlock(&s->backend_mu);
        return STM_EBACKEND;  /* not connected — descend has no target */
    }

    /* Walk to cwd, lopen for read, readdir until we find the
     * cursor-th non-./.. entry. */
    stm_status rc = walk_to_cwd(bc, cwd, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }
    rc = stm_9p_lopen(bc, SLATE_BACKEND_WORK_FID,
                         STM_9P_O_RDONLY | STM_9P_O_DIRECTORY,
                         NULL, NULL);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }

    descend_find_ctx fc = { .target_idx = cursor, .emitted = 0,
                              .found = false, .type = 0, .name_len = 0 };
    uint64_t offset = 0;
    while (1) {
        uint32_t entries = 0;
        uint64_t next_off = offset;
        rc = stm_9p_readdir(bc, SLATE_BACKEND_WORK_FID,
                               offset, 0u,
                               descend_find_cb, &fc,
                               &entries, &next_off);
        if (rc == STM_ENOTSUPPORTED) { rc = STM_OK; break; }  /* found-stop */
        if (rc != STM_OK) break;
        if (entries == 0) break;        /* EOF */
        if (next_off == offset) break;  /* defensive */
        offset = next_off;
        if (fc.found) break;
    }
    (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->backend_mu);
        return rc;
    }
    if (!fc.found) {
        /* Cursor out of range relative to current entries. */
        pthread_mutex_unlock(&s->backend_mu);
        return STM_EINVAL;
    }
    if (fc.bad_name) {
        /* R117 P1-1: entry name has control bytes — refuse descent.
         * Writing the raw name into panel.path would forge multi-line
         * reads of /panels/X/path; sanitizing on storage would
         * diverge from the real backend name and break the entries
         * listing's walk_to_cwd lookup. */
        pthread_mutex_unlock(&s->backend_mu);
        return STM_EINVAL;
    }
    if (fc.type != 4u /* DT_DIR */) {
        /* Not a directory — refuse descend. SLATE-3c will route
         * non-dir Enter to a "view as file" handler. */
        pthread_mutex_unlock(&s->backend_mu);
        return STM_ENOTDIR;
    }

    /* Confirm the entry is actually a directory via Twalk + Tgetattr
     * (defense against a stale dirent type bit). Walks from CWD_FID
     * — but CWD_FID isn't bound here (panel_entries_render binds it,
     * descend_panel doesn't). Use the per-walk-from-root pattern via
     * walk_to_cwd into ENT_FID. */
    {
        char target_path[STM_SLATE_PATH_MAX + 1];
        size_t target_path_len;
        rc = build_descended_path(cwd, cwd_len, fc.name, fc.name_len,
                                       target_path, sizeof target_path,
                                       &target_path_len);
        if (rc != STM_OK) {
            pthread_mutex_unlock(&s->backend_mu);
            return rc;
        }
        rc = walk_to_cwd(bc, target_path, SLATE_BACKEND_ENT_FID);
        if (rc != STM_OK) {
            pthread_mutex_unlock(&s->backend_mu);
            return rc;
        }
        stm_9p_attr a;
        memset(&a, 0, sizeof a);
        rc = stm_9p_getattr(bc, SLATE_BACKEND_ENT_FID,
                                STM_9P_GETATTR_MODE, &a);
        (void)stm_9p_clunk(bc, SLATE_BACKEND_ENT_FID);
        if (rc != STM_OK) {
            pthread_mutex_unlock(&s->backend_mu);
            return rc;
        }
        /* POSIX S_IFDIR = 0040000 in the high bits of mode. */
        if ((a.mode & 0170000u) != 0040000u) {
            pthread_mutex_unlock(&s->backend_mu);
            return STM_ENOTDIR;
        }

        /* All checks passed — commit the new cwd under s->mu. Re-check
         * connected (Disconnect could have raced; backend_mu prevents
         * the backend ptr from changing, but s->connected can flip
         * to false if Disconnect ran AFTER we checked above. Wait,
         * Disconnect also takes backend_mu — so it's blocked behind us.
         * Belt-and-suspenders re-check anyway.) */
        pthread_mutex_lock(&s->mu);
        if (!s->connected) {
            pthread_mutex_unlock(&s->mu);
            pthread_mutex_unlock(&s->backend_mu);
            return STM_EBACKEND;  /* not connected — descend has no target */
        }
        memcpy(s->panel[panel_idx].path, target_path, target_path_len);
        s->panel[panel_idx].path[target_path_len] = '\0';
        s->panel[panel_idx].path_len = target_path_len;
        s->panel[panel_idx].cursor = 0u;
        s->version++;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
    }

    pthread_mutex_unlock(&s->backend_mu);
    return STM_OK;
}

/* Lopen path for /panels/X/entries: do the backend op OUTSIDE s->mu,
 * then session-alloc + attach the produced bulk_buf. */
static stm_status lopen_panel_entries(stm_slate *s, uint32_t fid,
                                          uint64_t qid_path, int panel_idx)
{
    /* Snapshot path under s->mu (brief). */
    char path[STM_SLATE_PATH_MAX + 1];
    size_t path_len;
    pthread_mutex_lock(&s->mu);
    path_len = s->panel[panel_idx].path_len;
    /* R115 P3-3: defense-in-depth bound. SLATE-2's state machine
     * guarantees path_len ≤ STM_SLATE_PATH_MAX (only "/" or "" are
     * set), but a SLATE-3 chunk introducing /panels/X/cwd writable
     * would break this if the writer doesn't enforce the cap. Match
     * materialize_panel_path_locked's defensive posture. */
    if (path_len > STM_SLATE_PATH_MAX) {
        pthread_mutex_unlock(&s->mu);
        return STM_ERANGE;
    }
    if (path_len > 0) {
        memcpy(path, s->panel[panel_idx].path, path_len);
    }
    path[path_len] = '\0';
    pthread_mutex_unlock(&s->mu);

    uint8_t *body = NULL;
    uint32_t body_len = 0;

    if (path_len > 0) {
        stm_status rc = panel_entries_render(s, path, &body, &body_len);
        if (rc != STM_OK) {
            free(body);
            return rc;
        }
    }
    /* path_len == 0 → disconnected; body stays NULL/0. */

    pthread_mutex_lock(&s->mu);
    slate_session *ss = session_alloc_locked(s, fid, qid_path);
    if (!ss) {
        pthread_mutex_unlock(&s->mu);
        free(body);
        return STM_ENOMEM;
    }
    ss->bulk_buf = body;
    ss->bulk_len = body_len;
    pthread_mutex_unlock(&s->mu);
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
        if (str_eq(name, name_len, "version"))         target = SLATE_KIND_VERSION;
        else if (str_eq(name, name_len, "status"))     target = SLATE_KIND_STATUS;
        else if (str_eq(name, name_len, "event"))      target = SLATE_KIND_EVENT;
        else if (str_eq(name, name_len, "redraw"))     target = SLATE_KIND_REDRAW;
        else if (str_eq(name, name_len, "log"))        target = SLATE_KIND_LOG_DIR;
        else if (str_eq(name, name_len, "connection")) target = SLATE_KIND_CONN_DIR;
        else if (str_eq(name, name_len, "panels"))     target = SLATE_KIND_PANELS_DIR;
        break;
    case SLATE_KIND_LOG_DIR:
        if (str_eq(name, name_len, "tail"))            target = SLATE_KIND_LOG_TAIL;
        else if (str_eq(name, name_len, "append"))     target = SLATE_KIND_LOG_APPEND;
        break;
    case SLATE_KIND_CONN_DIR:
        if (str_eq(name, name_len, "socket"))          target = SLATE_KIND_CONN_SOCKET;
        else if (str_eq(name, name_len, "connected"))  target = SLATE_KIND_CONN_CONNECTED;
        else if (str_eq(name, name_len, "attach"))     target = SLATE_KIND_CONN_ATTACH;
        break;
    case SLATE_KIND_PANELS_DIR:
        if (str_eq(name, name_len, "left"))            target = SLATE_KIND_PANEL_L_DIR;
        else if (str_eq(name, name_len, "right"))      target = SLATE_KIND_PANEL_R_DIR;
        break;
    case SLATE_KIND_PANEL_L_DIR:
        if (str_eq(name, name_len, "path"))            target = SLATE_KIND_PANEL_L_PATH;
        else if (str_eq(name, name_len, "entries"))    target = SLATE_KIND_PANEL_L_ENTRIES;
        else if (str_eq(name, name_len, "cursor"))     target = SLATE_KIND_PANEL_L_CURSOR;
        else if (str_eq(name, name_len, "action"))     target = SLATE_KIND_PANEL_L_ACTION;
        break;
    case SLATE_KIND_PANEL_R_DIR:
        if (str_eq(name, name_len, "path"))            target = SLATE_KIND_PANEL_R_PATH;
        else if (str_eq(name, name_len, "entries"))    target = SLATE_KIND_PANEL_R_ENTRIES;
        else if (str_eq(name, name_len, "cursor"))     target = SLATE_KIND_PANEL_R_CURSOR;
        else if (str_eq(name, name_len, "action"))     target = SLATE_KIND_PANEL_R_ACTION;
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
        rc = emit_entry(SLATE_KIND_LOG_DIR, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_CONN_DIR, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_PANELS_DIR, &em);
    case SLATE_KIND_LOG_DIR:
        rc = emit_entry(SLATE_KIND_LOG_TAIL, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_LOG_APPEND, &em);
    case SLATE_KIND_CONN_DIR:
        rc = emit_entry(SLATE_KIND_CONN_SOCKET, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_CONN_CONNECTED, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_CONN_ATTACH, &em);
    case SLATE_KIND_PANELS_DIR:
        rc = emit_entry(SLATE_KIND_PANEL_L_DIR, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_PANEL_R_DIR, &em);
    case SLATE_KIND_PANEL_L_DIR:
        rc = emit_entry(SLATE_KIND_PANEL_L_PATH, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_PANEL_L_ENTRIES, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_PANEL_L_CURSOR, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_PANEL_L_ACTION, &em);
    case SLATE_KIND_PANEL_R_DIR:
        rc = emit_entry(SLATE_KIND_PANEL_R_PATH, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_PANEL_R_ENTRIES, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_PANEL_R_CURSOR, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_PANEL_R_ACTION, &em);
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
     * here we infer permission from KIND_META[k].mode and validate
     * against the requested access mode. R/W kinds (e.g., SLATE-3a's
     * /panels/X/cursor with mode 0644) accept O_RDONLY OR O_WRONLY OR
     * O_RDWR; write-only kinds (mode 0200) accept only O_WRONLY;
     * read-only kinds (mode 0444) accept only O_RDONLY. */
    uint32_t accmode = flags & STM_LP9_O_ACCMODE;
    bool readable = (meta->mode & 0444u) != 0u;
    bool writable = (meta->mode & 0222u) != 0u;
    if (accmode == STM_LP9_O_RDONLY) {
        if (!readable) return STM_EACCES;
    } else if (accmode == STM_LP9_O_WRONLY) {
        if (!writable) return STM_EACCES;
    } else if (accmode == STM_LP9_O_RDWR) {
        if (!(readable && writable)) return STM_EACCES;
    } else {
        return STM_EINVAL;
    }
    /* Track whether this open intends to read — affects whether we
     * materialise a body or just allocate a session for write. */
    bool open_for_read = (accmode == STM_LP9_O_RDONLY ||
                          accmode == STM_LP9_O_RDWR);

    if (meta->is_dir) {
        /* Dirs don't need session state; readdir is stateless. */
        return STM_OK;
    }

    /* SLATE-2: /panels/X/entries does a backend op OUTSIDE s->mu.
     * Fast-track to a dedicated lopen path. */
    if (k == SLATE_KIND_PANEL_L_ENTRIES) {
        return lopen_panel_entries(s, fid, qid_path, SLATE_PANEL_LEFT);
    }
    if (k == SLATE_KIND_PANEL_R_ENTRIES) {
        return lopen_panel_entries(s, fid, qid_path, SLATE_PANEL_RIGHT);
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

    /* Allocate session. For write-only opens, no body is materialised
     * (vops_read on a write-only fid would fall through to the
     * EBACKEND path; renderers don't read these). For read-capable
     * opens, snapshot the body now. */
    pthread_mutex_lock(&s->mu);
    slate_session *ss = session_alloc_locked(s, fid, qid_path);
    if (!ss) {
        pthread_mutex_unlock(&s->mu);
        return STM_ENOMEM;
    }
    if (!open_for_read) {
        /* Write-only kind (event, log/append, conn/attach, action) —
         * no body. */
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
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
    case SLATE_KIND_CONN_SOCKET:
        rc = materialize_conn_socket_locked(s, ss);
        break;
    case SLATE_KIND_CONN_CONNECTED:
        rc = materialize_conn_connected_locked(s, ss);
        break;
    case SLATE_KIND_PANEL_L_PATH:
        rc = materialize_panel_path_locked(s, ss, SLATE_PANEL_LEFT);
        break;
    case SLATE_KIND_PANEL_R_PATH:
        rc = materialize_panel_path_locked(s, ss, SLATE_PANEL_RIGHT);
        break;
    case SLATE_KIND_PANEL_L_CURSOR:
        rc = materialize_panel_cursor_locked(s, ss, SLATE_PANEL_LEFT);
        break;
    case SLATE_KIND_PANEL_R_CURSOR:
        rc = materialize_panel_cursor_locked(s, ss, SLATE_PANEL_RIGHT);
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

    /* Snapshot-bodied kinds: serve from session->buf or bulk_buf
     * (R114 P1-1: /log/tail uses heap-alloc bulk_buf since 100 ×
     * 321 bytes exceeds STM_SLATE_BODY_MAX). */
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

    /* Bulk-format kinds (currently only /log/tail). */
    if (ss->bulk_buf) {
        if (offset >= ss->bulk_len) {
            *inout_len = 0;
            pthread_mutex_unlock(&s->mu);
            return STM_OK;
        }
        uint32_t avail = ss->bulk_len - (uint32_t)offset;
        if (*inout_len > avail) *inout_len = avail;
        memcpy(buf, ss->bulk_buf + offset, *inout_len);
        pthread_mutex_unlock(&s->mu);
        return STM_OK;
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
    if (k == SLATE_KIND_CONN_ATTACH) {
        /* SLATE-2: write a stratumd socket path to dial; empty body
         * (or whitespace-stripped empty) disconnects. R101 P2-2
         * carry: zero-byte writes are NOT refused — empty payload is
         * the documented disconnect verb. Bound the input at
         * STM_SLATE_SOCKET_MAX. */
        if (len > STM_SLATE_SOCKET_MAX) return STM_EINVAL;
        size_t l = len;
        if (l > 0 && ((const char *)buf)[l - 1] == '\n') l--;
        stm_status rc;
        if (l == 0) {
            rc = stm_slate_disconnect(s);
        } else {
            rc = stm_slate_attach(s, (const char *)buf, l);
        }
        if (rc != STM_OK) return rc;
        *out_written = len;
        return STM_OK;
    }
    if (k == SLATE_KIND_PANEL_L_CURSOR || k == SLATE_KIND_PANEL_R_CURSOR) {
        /* SLATE-3a: write a decimal cursor index to /panels/X/cursor.
         * Format: "<N>" or "<N>\n". Bound by STM_SLATE_CURSOR_INPUT_MAX
         * — 16 digits + newline + NUL covers any uint32. Empty body
         * refused (use action verbs to adjust without picking a value). */
        if (len == 0) return STM_EINVAL;
        if (len > 16u) return STM_EINVAL;
        char tmp[17];
        memcpy(tmp, buf, len);
        tmp[len] = '\0';
        size_t l = len;
        if (l > 0 && tmp[l - 1] == '\n') tmp[--l] = '\0';
        if (l == 0) return STM_EINVAL;
        /* Parse decimal — every character must be a digit. */
        unsigned long long v = 0;
        for (size_t i = 0; i < l; i++) {
            if (tmp[i] < '0' || tmp[i] > '9') return STM_EINVAL;
            v = v * 10ull + (unsigned long long)(tmp[i] - '0');
            if (v > 0xFFFFFFFFull) return STM_EINVAL;
        }
        int panel_idx = (k == SLATE_KIND_PANEL_L_CURSOR) ? SLATE_PANEL_LEFT
                                                         : SLATE_PANEL_RIGHT;
        /* R116 P3-2: gate version bump on actual change. A redundant
         * cursor write (same value) is a no-op — bumping version would
         * wake every blocked /redraw reader for nothing, violating the
         * "version changes only via real state mutation" doctrine
         * (matches the action handler's `handled && moved` posture). */
        pthread_mutex_lock(&s->mu);
        if (s->panel[panel_idx].cursor != (uint32_t)v) {
            s->panel[panel_idx].cursor = (uint32_t)v;
            s->version++;
            pthread_cond_broadcast(&s->cv);
        }
        pthread_mutex_unlock(&s->mu);
        *out_written = len;
        return STM_OK;
    }
    if (k == SLATE_KIND_PANEL_L_ACTION || k == SLATE_KIND_PANEL_R_ACTION) {
        /* SLATE-3a/3b: dispatch a panel action verb via a static verb
         * table (R104 P3-3+P3-4 doctrine + R116 P3-3 carry — table
         * scales as SLATE-3c+ adds key F3 / mouse / etc.). Empty
         * body refused. */
        if (len == 0) return STM_EINVAL;
        if (len > STM_SLATE_EVENT_LINE_MAX) return STM_EINVAL;
        size_t l = len;
        if (l > 0 && ((const char *)buf)[l - 1] == '\n') l--;
        if (l == 0) return STM_EINVAL;
        const char *p = (const char *)buf;
        int panel_idx = (k == SLATE_KIND_PANEL_L_ACTION) ? SLATE_PANEL_LEFT
                                                         : SLATE_PANEL_RIGHT;
        stm_status verb_rc = action_dispatch_verb(s, panel_idx, p, l);
        if (verb_rc != STM_OK) return verb_rc;
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
