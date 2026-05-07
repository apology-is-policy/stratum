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
    SLATE_KIND_PANEL_L_CURSOR    = 19,
    SLATE_KIND_PANEL_L_ACTION    = 20,
    SLATE_KIND_PANEL_R_CURSOR    = 21,
    SLATE_KIND_PANEL_R_ACTION    = 22,
    /* SLATE-3c-selection: per-panel multi-select. */
    SLATE_KIND_PANEL_L_SELECTION = 23,
    SLATE_KIND_PANEL_R_SELECTION = 24,
    /* SLATE-4-confirm + SLATE-4b: /dialogs subtree. The DIALOG_*
     * leaf kinds encode dialog id in the LOWER 56 bits of qid_path;
     * the kind byte stays in the high byte. /dialogs and
     * /dialogs/stack are static (id=0). */
    SLATE_KIND_DIALOGS_DIR       = 25,  /* /dialogs */
    SLATE_KIND_DIALOG_STACK      = 26,  /* /dialogs/stack (R) */
    SLATE_KIND_DIALOG_DIR        = 27,  /* /dialogs/<id> (parent dir) */
    SLATE_KIND_DIALOG_KIND       = 28,  /* /dialogs/<id>/kind */
    SLATE_KIND_DIALOG_TITLE      = 29,  /* /dialogs/<id>/title */
    SLATE_KIND_DIALOG_BODY       = 30,  /* /dialogs/<id>/body */
    SLATE_KIND_DIALOG_OPTIONS    = 31,  /* /dialogs/<id>/options */
    SLATE_KIND_DIALOG_RESULT     = 32,  /* /dialogs/<id>/result (W) */
    /* SLATE-4b: editable input field (kind=input only; absent at
     * walk + readdir for confirm-kind dialogs). */
    SLATE_KIND_DIALOG_INPUT      = 33,  /* /dialogs/<id>/input (RW) */
    /* SLATE-5a: /editor subtree. Per SLATE-DESIGN §3 + §8. v5a is
     * scaffolding + open verb (read-only across all leaves;
     * action accepts no verbs yet). SLATE-5b will add content +
     * cursor RW + save/quit/revert/save-and-quit actions. */
    SLATE_KIND_EDITOR_DIR        = 34,  /* /editor */
    SLATE_KIND_EDITOR_ACTIVE     = 35,  /* /editor/active */
    SLATE_KIND_EDITOR_FILENAME   = 36,  /* /editor/filename */
    SLATE_KIND_EDITOR_CONTENT    = 37,  /* /editor/content */
    SLATE_KIND_EDITOR_CURSOR     = 38,  /* /editor/cursor */
    SLATE_KIND_EDITOR_MODIFIED   = 39,  /* /editor/modified */
    SLATE_KIND_EDITOR_ACTION     = 40,  /* /editor/action (W) */
    /* SLATE-4a: per-panel /connection/{left,right} subtree. The
     * top-level /connection/{socket,connected,attach} kinds become
     * back-compat aliases for panel 0 (LEFT). The newly-added
     * per-panel kinds are the canonical surface and are required
     * for the dual-pane host-on-one-side / stratum-on-the-other
     * workflow. */
    SLATE_KIND_CONN_L_DIR        = 41,
    SLATE_KIND_CONN_L_SOCKET     = 42,
    SLATE_KIND_CONN_L_CONNECTED  = 43,
    SLATE_KIND_CONN_L_ATTACH     = 44,
    SLATE_KIND_CONN_R_DIR        = 45,
    SLATE_KIND_CONN_R_SOCKET     = 46,
    SLATE_KIND_CONN_R_CONNECTED  = 47,
    SLATE_KIND_CONN_R_ATTACH     = 48,
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
    [SLATE_KIND_PANEL_L_CURSOR]    = { false, 0644, "cursor"    },
    [SLATE_KIND_PANEL_L_ACTION]    = { false, 0200, "action"    },
    [SLATE_KIND_PANEL_R_CURSOR]    = { false, 0644, "cursor"    },
    [SLATE_KIND_PANEL_R_ACTION]    = { false, 0200, "action"    },
    /* SLATE-3c-selection: comma-separated entry indices, RW. */
    [SLATE_KIND_PANEL_L_SELECTION] = { false, 0644, "selection" },
    [SLATE_KIND_PANEL_R_SELECTION] = { false, 0644, "selection" },
    /* SLATE-4-confirm + SLATE-4b: /dialogs subtree.
     * /dialogs is mode 0555 (read-execute for walk + readdir).
     * /dialogs/<id> dirs are mode 0555.
     * Read-only leaves are 0444; result is 0200 (write-only);
     * SLATE-4b's /input is RW mode 0644. */
    [SLATE_KIND_DIALOGS_DIR]       = { true,  0555, "dialogs"   },
    [SLATE_KIND_DIALOG_STACK]      = { false, 0444, "stack"     },
    [SLATE_KIND_DIALOG_DIR]        = { true,  0555, "<id>"      },
    [SLATE_KIND_DIALOG_KIND]       = { false, 0444, "kind"      },
    [SLATE_KIND_DIALOG_TITLE]      = { false, 0444, "title"     },
    [SLATE_KIND_DIALOG_BODY]       = { false, 0444, "body"      },
    [SLATE_KIND_DIALOG_OPTIONS]    = { false, 0444, "options"   },
    [SLATE_KIND_DIALOG_RESULT]     = { false, 0200, "result"    },
    [SLATE_KIND_DIALOG_INPUT]      = { false, 0644, "input"     },
    /* SLATE-5a + SLATE-5b: /editor subtree.
     * /editor is mode 0555 (read-execute for walk + readdir).
     * SLATE-5a leaves: active/filename/modified are RO (0444);
     * action is W (0200). SLATE-5b lifts content + cursor to RW
     * (0644 — RDONLY/WRONLY/RDWR all accepted) and adds verbs
     * save/quit/revert/save-and-quit at /editor/action. */
    [SLATE_KIND_EDITOR_DIR]        = { true,  0555, "editor"    },
    [SLATE_KIND_EDITOR_ACTIVE]     = { false, 0444, "active"    },
    [SLATE_KIND_EDITOR_FILENAME]   = { false, 0444, "filename"  },
    [SLATE_KIND_EDITOR_CONTENT]    = { false, 0644, "content"   },
    [SLATE_KIND_EDITOR_CURSOR]     = { false, 0644, "cursor"    },
    [SLATE_KIND_EDITOR_MODIFIED]   = { false, 0444, "modified"  },
    [SLATE_KIND_EDITOR_ACTION]     = { false, 0200, "action"    },
    /* SLATE-4a: per-panel /connection/{left,right} subtree.  Same
     * layout as the top-level /connection/{socket,connected,attach}
     * (which retains the same KIND_META[] entries above as panel-0
     * back-compat aliases). */
    [SLATE_KIND_CONN_L_DIR]        = { true,  0555, "left"      },
    [SLATE_KIND_CONN_L_SOCKET]     = { false, 0444, "socket"    },
    [SLATE_KIND_CONN_L_CONNECTED]  = { false, 0444, "connected" },
    [SLATE_KIND_CONN_L_ATTACH]     = { false, 0200, "attach"    },
    [SLATE_KIND_CONN_R_DIR]        = { true,  0555, "right"     },
    [SLATE_KIND_CONN_R_SOCKET]     = { false, 0444, "socket"    },
    [SLATE_KIND_CONN_R_CONNECTED]  = { false, 0444, "connected" },
    [SLATE_KIND_CONN_R_ATTACH]     = { false, 0200, "attach"    },
};

_Static_assert(SLATE_KIND_MAX == 49, "KIND_META[] sized to enum cardinality");
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
_Static_assert(sizeof("selection") - 1   <= STM_LP9_NAME_MAX, "/panels/X/selection");
_Static_assert(sizeof("dialogs") - 1     <= STM_LP9_NAME_MAX, "/dialogs");
_Static_assert(sizeof("stack") - 1       <= STM_LP9_NAME_MAX, "/dialogs/stack");
_Static_assert(sizeof("kind") - 1        <= STM_LP9_NAME_MAX, "/dialogs/X/kind");
_Static_assert(sizeof("title") - 1       <= STM_LP9_NAME_MAX, "/dialogs/X/title");
_Static_assert(sizeof("body") - 1        <= STM_LP9_NAME_MAX, "/dialogs/X/body");
_Static_assert(sizeof("options") - 1     <= STM_LP9_NAME_MAX, "/dialogs/X/options");
_Static_assert(sizeof("result") - 1      <= STM_LP9_NAME_MAX, "/dialogs/X/result");
_Static_assert(sizeof("input") - 1       <= STM_LP9_NAME_MAX, "/dialogs/X/input");
_Static_assert(sizeof("editor") - 1      <= STM_LP9_NAME_MAX, "/editor");
_Static_assert(sizeof("active") - 1      <= STM_LP9_NAME_MAX, "/editor/active");
_Static_assert(sizeof("filename") - 1    <= STM_LP9_NAME_MAX, "/editor/filename");
_Static_assert(sizeof("content") - 1     <= STM_LP9_NAME_MAX, "/editor/content");
_Static_assert(sizeof("modified") - 1    <= STM_LP9_NAME_MAX, "/editor/modified");

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
/* P9-SLATE-3c-walk (R117 P3-3 closure): two ping-pong scratch fids
 * for walk_to_cwd's iterative re-walk. Used only when cwd depth
 * exceeds STM_9P_MAX_WALK (16) components. Each iterated batch
 * walks from the current scratch fid into the next, with the
 * previous scratch clunked. The LAST batch walks into out_fid
 * (caller's intended destination — typically WORK_FID). Both walk
 * fids live entirely within walk_to_cwd's call frame; the caller
 * never observes them. */
#define SLATE_BACKEND_WALK_A_FID ((uint32_t)204u)
#define SLATE_BACKEND_WALK_B_FID ((uint32_t)205u)

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

/* SLATE-4-confirm: dialog kinds encode the monotonic dialog id in
 * the LOWER 56 bits of qid_path. /dialogs and /dialogs/stack are
 * static (id=0). DIALOG_DIR + leaves carry the id.
 *
 * R121 P3-1: this mask is the structural cap on dialog ids — once
 * `next_dialog_id > SLATE_QID_ID_MASK` (= 2^56-1), the id no
 * longer round-trips through qid_dialog_id() unscathed, so the
 * dialog becomes structurally unaddressable. The saturation
 * check in dialog_open_locked refuses with STM_EOVERFLOW at this
 * threshold (NOT at UINT64_MAX) to keep the "ids are monotonic
 * and never reused" invariant honest. */
#define SLATE_QID_ID_MASK  ((uint64_t)0x00FFFFFFFFFFFFFFull)

static uint64_t qid_of_dialog(slate_kind k, uint64_t dialog_id)
{
    return (((uint64_t)(uint8_t)k) << 56) | (dialog_id & SLATE_QID_ID_MASK);
}

static uint64_t qid_dialog_id(uint64_t q)
{
    return q & SLATE_QID_ID_MASK;
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

/* SLATE-2 + SLATE-3a + SLATE-3c-selection + SLATE-4a: per-panel
 * state. */
#define SLATE_SELECTION_BYTES ((STM_SLATE_ENTRIES_MAX + 7u) / 8u)

typedef struct {
    /* SLATE-4a: per-panel backend connection. The dual-pane host-on-
     * one-side / stratum-on-the-other workflow needs each panel to
     * bind its OWN backend client. backend_mu serializes ALL
     * libstratum-9p ops on this panel (the lib is one-op-at-a-time
     * per connection — see include/stratum/9p_client.h §Concurrency).
     *
     * Lock ordering: panel[i].backend_mu → s->mu. NEVER take more
     * than one panel's backend_mu at a time. Future cross-panel ops
     * (SWISS-4d copy across panels) MUST take them in a fixed order
     * (panel 0 first, then panel 1) and never the reverse, OR
     * release one before taking another.
     *
     * ConnectionAtomic per panel: connected == (socket_len > 0).
     * PanelPathConsistent per panel: connected ⇒ path != ""; not
     * connected ⇒ path == "".
     */
    pthread_mutex_t backend_mu;
    stm_9p_client  *backend;
    char            socket[STM_SLATE_SOCKET_MAX + 1];
    size_t          socket_len;
    bool            connected;

    /* Panel cwd. */
    char     path[STM_SLATE_PATH_MAX + 1];     /* NUL-terminated; "" disconnected */
    size_t   path_len;
    /* SLATE-3a: cursor is a numeric index into the panel's current
     * entries listing. Bounds-checking against the entry count is
     * the renderer's responsibility — slate accepts any uint32_t.
     * SLATE-4a adds defense-in-depth via entries_count cache (see
     * below) so verb_key_down can clamp without a backend round-
     * trip. Reset to 0 on attach + disconnect + cwd change. */
    uint32_t cursor;
    /* SLATE-3c-selection: bitset of selected entry indices.
     * Bit (idx % 8) of byte (idx / 8) is set iff entry `idx` is
     * selected. STM_SLATE_ENTRIES_MAX (200) bits = 25 bytes.
     * Reset to all-zero on attach + disconnect + descend + ascend.
     * Indices ≥ STM_SLATE_ENTRIES_MAX are refused at write parse
     * (parity with cursor cap; selection over invisible entries
     * makes no sense). */
    uint8_t  selection[SLATE_SELECTION_BYTES];
    /* SLATE-4a entries-count cache: latest count of rendered
     * entries from panel_entries_render, INCLUDING the synthesized
     * ".." entry (which sits at index 0 when path != "/"). The
     * cursor sees the same indices the renderer sees. Used by
     * verb_key_down to clamp without a backend round-trip (defense-
     * in-depth on top of the TUI's own clamp at SWISS-3b — fixes
     * user-reported bug "you can scroll past the last file").
     *
     * Reset to 0 on every cwd-changing op (attach, disconnect,
     * descend, ascend) — the cache is invalid until the next
     * panel-entries materialise re-populates it. A panel that has
     * never been opened on /entries has entries_count = 0, in
     * which case verb_key_down skips the clamp (renderer hasn't
     * rendered yet). */
    uint32_t entries_count;
} slate_panel;

/* SLATE-4a: panel index constants now live in the public header.
 * Keep a private alias for the existing slate.c references that
 * use the short SLATE_PANEL_* names for code-density. */
#define SLATE_PANEL_LEFT   STM_SLATE_PANEL_LEFT
#define SLATE_PANEL_RIGHT  STM_SLATE_PANEL_RIGHT
#define SLATE_PANEL_COUNT  STM_SLATE_PANEL_COUNT

/* SLATE-4-confirm + SLATE-4b: dialog slot state. The
 * stm_slate->dialogs[STM_SLATE_DIALOG_MAX_ACTIVE] array carries up
 * to N simultaneously-active dialogs. Each slot is one of:
 *   FREE:   active = false (id field is 0, fresh memset state)
 *   ACTIVE: active = true  (slot displayed; id is the monotonic id)
 * A slot becomes FREE again on result-write OR programmatic cancel.
 * The "top" of the stack is the active slot with the highest id
 * (since ids are allocated monotonically, this is the most-recently-
 * opened slot). Per DialogStackLIFO (SLATE-DESIGN §11), only the
 * top accepts results.
 *
 * Slot.input is the editable string field for kind=INPUT only;
 * unused (zero) for kind=CONFIRM. */
typedef enum {
    SLATE_DIALOG_KIND_NONE = 0,
    SLATE_DIALOG_KIND_CONFIRM,
    SLATE_DIALOG_KIND_INPUT,
} slate_dialog_kind;

typedef struct {
    bool                active;
    uint64_t            id;       /* monotonic; 0 reserved for "no dialog" */
    slate_dialog_kind   kind;
    char                title[STM_SLATE_DIALOG_TITLE_MAX + 1];
    size_t              title_len;
    char                body[STM_SLATE_DIALOG_BODY_MAX + 1];
    size_t              body_len;
    char                options[STM_SLATE_DIALOG_OPTIONS_MAX + 1];
    size_t              options_len;
    /* SLATE-4b: editable string field, INPUT kind only. */
    char                input[STM_SLATE_DIALOG_INPUT_MAX + 1];
    size_t              input_len;
} slate_dialog;

/* SLATE-4b: most-recent dismiss completion record. Single-record
 * model — at result-write time the daemon snapshots (id, kind,
 * result, input) here for the consumer to retrieve via
 * stm_slate_dialog_consume(). v1.0 limitation: rapid back-to-back
 * dismisses can overwrite each other; consumers should consume
 * promptly after detecting dismiss via /redraw + /version. v1.1
 * may add a per-id consumption queue. */
typedef struct {
    uint64_t            id;       /* 0 = no record */
    slate_dialog_kind   kind;
    char                result[STM_SLATE_DIALOG_OPTION_MAX + 1];
    size_t              result_len;
    char                input[STM_SLATE_DIALOG_INPUT_MAX + 1];
    size_t              input_len;
} slate_dialog_completion;

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

    /* SLATE-4a: per-panel state. ConnectionAtomic + PanelPathConsistent
     * invariants now hold PER PANEL — see the slate_panel struct
     * comment for details. The top-level /connection/{socket,connected,
     * attach} synfs files become panel-0 back-compat aliases. Each
     * panel has its OWN backend client + backend_mu so concurrent
     * ops on the two panels don't serialise. */
    slate_panel     panel[SLATE_PANEL_COUNT];

    /* SLATE-4-confirm + SLATE-4b: multi-dialog stack. Up to
     * STM_SLATE_DIALOG_MAX_ACTIVE dialogs may be active simultaneously.
     * next_dialog_id starts at 1; id 0 is reserved for "no active
     * dialog". next_dialog_id is monotonic — never reused even after
     * dismiss. The top of the stack = active slot with the highest
     * id (since ids are allocated monotonically, this is the most-
     * recently-opened slot). */
    slate_dialog            dialogs[STM_SLATE_DIALOG_MAX_ACTIVE];
    uint64_t                next_dialog_id;
    slate_dialog_completion last_dismiss;

    /* SLATE-5a: editor state. Single editor session at v5a (no
     * multi-buffer at v1.0; SLATE-DESIGN §10 forward-notes
     * multi-pane editor for v1.1+).
     *
     * State machine:
     *   INACTIVE: editor_active = false; filename + content = "".
     *   ACTIVE:   editor_active = true; populated by "editor open" verb;
     *             cleared by "editor close" verb OR stm_slate_editor_close.
     *
     * editor_content is heap-allocated to avoid blowing s->mu's
     * critical-section size in the open path; bounded at
     * STM_SLATE_EDITOR_CONTENT_MAX. NULL when inactive.
     *
     * SLATE-5b will add: cursor mutation via /editor/cursor write,
     * content mutation via /editor/content write, modified flag
     * tracking (memcmp original vs current), action verbs save/quit/
     * revert/save-and-quit. */
    bool        editor_active;
    /* SLATE-4a: which panel's backend the editor is bound to.
     * Defaults to SLATE_PANEL_LEFT on bare "editor open <path>"
     * verbs; the panel-prefixed form "editor open <left|right>
     * <path>" sets it explicitly. Save/revert use this index to
     * pick the right backend. Disconnecting THIS panel clears the
     * editor (R124 P3-5 doctrine carry to per-panel). */
    int         editor_panel_idx;
    char        editor_filename[STM_SLATE_EDITOR_FILENAME_MAX + 1];
    size_t      editor_filename_len;
    uint8_t    *editor_content;
    size_t      editor_content_len;
    /* SLATE-5b: pristine baseline copied at open + at save. The
     * /editor/modified flag is `memcmp(editor_content, editor_original)
     * != 0 OR editor_content_len != editor_original_len`. */
    uint8_t    *editor_original;
    size_t      editor_original_len;
    uint32_t    editor_cursor_row;
    uint32_t    editor_cursor_col;
    bool        editor_modified;       /* derived; cached for fast read */

    /* Per-fid materialized bodies (mu-protected). */
    slate_session   sessions[STM_SLATE_MAX_SESSIONS];
};

/* ────────────────────────────────────────────────────────────────────── */
/* SLATE-4b dialog slot helpers (mu held).                                 */
/* ────────────────────────────────────────────────────────────────────── */

/* Find the active slot whose id matches `id`. Returns slot index in
 * [0, STM_SLATE_DIALOG_MAX_ACTIVE), or -1 if no match.  Linear scan
 * is O(N) where N = STM_SLATE_DIALOG_MAX_ACTIVE = 4 — trivial. */
static int dialog_slot_for_id_locked(stm_slate *s, uint64_t id)
{
    if (id == 0u) return -1;
    for (int i = 0; i < (int)STM_SLATE_DIALOG_MAX_ACTIVE; i++) {
        if (s->dialogs[i].active && s->dialogs[i].id == id) return i;
    }
    return -1;
}

/* Find the first FREE slot. Returns index, or -1 if all slots are
 * active (caller should return STM_EBUSY in that case). */
static int dialog_slot_free_locked(stm_slate *s)
{
    for (int i = 0; i < (int)STM_SLATE_DIALOG_MAX_ACTIVE; i++) {
        if (!s->dialogs[i].active) return i;
    }
    return -1;
}

/* Return the topmost dialog id (highest active id), or 0 if none. */
static uint64_t dialog_top_id_locked(stm_slate *s)
{
    uint64_t top = 0u;
    for (int i = 0; i < (int)STM_SLATE_DIALOG_MAX_ACTIVE; i++) {
        if (s->dialogs[i].active && s->dialogs[i].id > top) {
            top = s->dialogs[i].id;
        }
    }
    return top;
}

/* R121 P3-5: combined slot-lookup-with-top in a single scan.
 * Returns slot index for `did` (or -1) AND top id via *out_top.
 * Used by vops_write DIALOG_RESULT (the only caller that needs
 * BOTH the slot and the top in one decision); other callers stick
 * with the simpler dialog_slot_for_id_locked / dialog_top_id_locked
 * helpers. With STM_SLATE_DIALOG_MAX_ACTIVE = 4 the savings are
 * trivial; the consolidated form is forward-looking — once the
 * cap is bumped (slate.h:233 forward-note) the constant matters. */
static int dialog_lookup_and_top_locked(stm_slate *s, uint64_t did,
                                              uint64_t *out_top)
{
    int slot = -1;
    uint64_t top = 0u;
    for (int i = 0; i < (int)STM_SLATE_DIALOG_MAX_ACTIVE; i++) {
        if (!s->dialogs[i].active) continue;
        if (s->dialogs[i].id == did) slot = i;
        if (s->dialogs[i].id > top)  top = s->dialogs[i].id;
    }
    if (out_top) *out_top = top;
    return slot;
}

/* Return the count of active dialogs (0..STM_SLATE_DIALOG_MAX_ACTIVE). */
static size_t dialog_count_locked(stm_slate *s)
{
    size_t n = 0;
    for (int i = 0; i < (int)STM_SLATE_DIALOG_MAX_ACTIVE; i++) {
        if (s->dialogs[i].active) n++;
    }
    return n;
}

/* Collect the active ids into out_ids (caller-provided) sorted
 * ascending. Returns the count. out_ids must hold at least
 * STM_SLATE_DIALOG_MAX_ACTIVE entries. Insertion sort with N=4 is
 * trivial; no allocation. */
static size_t dialog_collect_sorted_locked(stm_slate *s, uint64_t *out_ids)
{
    size_t n = 0;
    for (int i = 0; i < (int)STM_SLATE_DIALOG_MAX_ACTIVE; i++) {
        if (!s->dialogs[i].active) continue;
        uint64_t id = s->dialogs[i].id;
        size_t j = n;
        while (j > 0 && out_ids[j - 1] > id) {
            out_ids[j] = out_ids[j - 1];
            j--;
        }
        out_ids[j] = id;
        n++;
    }
    return n;
}

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
    /* SLATE-4a: each panel has its own backend_mu. Initialize per-
     * panel; tear down on any subsequent failure to keep the
     * lifecycle clean. */
    int initialized = 0;
    for (int i = 0; i < SLATE_PANEL_COUNT; i++) {
        if (pthread_mutex_init(&s->panel[i].backend_mu, NULL) != 0) {
            for (int j = 0; j < initialized; j++) {
                pthread_mutex_destroy(&s->panel[j].backend_mu);
            }
            pthread_cond_destroy(&s->cv);
            pthread_mutex_destroy(&s->mu);
            free(s);
            return STM_EIO;
        }
        initialized++;
    }
    s->version = 1u;
    /* PanelPathConsistent + ConnectionAtomic both hold by calloc:
     *   panel[i].connected = false;
     *   panel[i].socket_len = 0;
     *   panel[i].path_len = 0. */
    /* SLATE-4-confirm: dialog ids start at 1; 0 reserved for "no
     * active dialog" sentinel (see stm_slate_dialog_id). */
    s->next_dialog_id = 1u;
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
    /* SLATE-4a: close each panel's backend if held. Caller has
     * already destroyed every lp9 server using this state (R96 P2-1
     * doctrine), so no concurrent backend op is possible at this
     * point. Take each panel's backend_mu sequentially — never
     * concurrently — to keep the "single panel backend_mu at a
     * time" rule intact even at teardown. */
    stm_9p_client *closed[SLATE_PANEL_COUNT] = {0};
    for (int i = 0; i < SLATE_PANEL_COUNT; i++) {
        pthread_mutex_lock(&s->panel[i].backend_mu);
        pthread_mutex_lock(&s->mu);
        closed[i] = s->panel[i].backend;
        s->panel[i].backend = NULL;
        pthread_mutex_unlock(&s->mu);
        if (closed[i]) stm_9p_close(closed[i]);
        pthread_mutex_unlock(&s->panel[i].backend_mu);
    }
    pthread_mutex_lock(&s->mu);
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
    /* SLATE-5a + SLATE-5b: free any heap-allocated editor content
     * AND original baseline. */
    free(s->editor_content);
    s->editor_content = NULL;
    free(s->editor_original);
    s->editor_original = NULL;
    pthread_mutex_unlock(&s->mu);

    for (int i = 0; i < SLATE_PANEL_COUNT; i++) {
        pthread_mutex_destroy(&s->panel[i].backend_mu);
    }
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

/* SLATE-5a: parse "editor open <path>" — returns true if matches +
 * sets *out_path, *out_path_len. Path is whatever follows the
 * "editor open " prefix. The caller validates path bounds + bytes
 * via validate_editor_path. */
static bool parse_editor_open_verb(const char *line, size_t len,
                                       const char **out_path, size_t *out_path_len)
{
    static const char prefix[] = "editor open ";
    size_t prefix_len = sizeof(prefix) - 1u;
    if (len <= prefix_len) return false;
    if (memcmp(line, prefix, prefix_len) != 0) return false;
    *out_path = line + prefix_len;
    *out_path_len = len - prefix_len;
    return true;
}

static bool parse_editor_close_verb(const char *line, size_t len)
{
    static const char verb[] = "editor close";
    return len == sizeof(verb) - 1u && memcmp(line, verb, len) == 0;
}

stm_status stm_slate_submit_event(stm_slate *s, const char *line, size_t len)
{
    if (!s || !line) return STM_EINVAL;
    /* Strip a trailing newline if present (matches the wire-format
     * convention: clients usually print with `echo`). */
    if (len > 0 && line[len - 1] == '\n') len--;
    if (len == 0) return STM_EINVAL;
    if (len > STM_SLATE_EVENT_LINE_MAX) return STM_EINVAL;

    /* SLATE-5a: log the event line first (FIFO doctrine intact),
     * then route backend-touching verbs to their public APIs. */
    pthread_mutex_lock(&s->mu);
    dispatch_event_locked(s, line, len);
    pthread_mutex_unlock(&s->mu);

    /* SLATE-5a: editor verb routing. Every event line gets logged
     * by dispatch above; subsequent verb routing returns the
     * backend-op result so a caller writing to /event programmatically
     * via stm_slate_submit_event can react to errors. (Renderers
     * writing via Twrite to /event don't see the result; but they
     * can read /editor/active afterward to detect success.) */
    const char *epath = NULL;
    size_t epath_len = 0;
    if (parse_editor_open_verb(line, len, &epath, &epath_len)) {
        return stm_slate_editor_open(s, epath, epath_len);
    }
    if (parse_editor_close_verb(line, len)) {
        return stm_slate_editor_close(s);
    }
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

/* SLATE-4a: helper — clear the editor state if active. Mu held by
 * caller. Used at attach + disconnect on the editor's pinned panel.
 * R124 P3-5 doctrine carries: editor state is meaningless without
 * its bound panel's backend; save would otherwise walk a stale
 * filename against the new backend's filesystem. */
static void editor_clear_locked(stm_slate *s)
{
    if (!s->editor_active) return;
    free(s->editor_content);
    s->editor_content = NULL;
    s->editor_content_len = 0u;
    free(s->editor_original);
    s->editor_original = NULL;
    s->editor_original_len = 0u;
    s->editor_filename[0] = '\0';
    s->editor_filename_len = 0u;
    s->editor_active = false;
    s->editor_cursor_row = 0u;
    s->editor_cursor_col = 0u;
    s->editor_modified = false;
    s->editor_panel_idx = 0;
}

/* SLATE-4a: per-panel attach state swap. Mu held. ConnectionAtomic
 * + PanelPathConsistent both hold for the swapped panel: connected
 * becomes TRUE, socket is set, panel path resets to "/", cursor
 * resets to 0, selection clears, entries_count cache invalidates. */
static void attach_state_swap_locked(stm_slate *s, int panel_idx,
                                       const char *path, size_t len,
                                       stm_9p_client *new_bc, stm_9p_client **old_bc_out)
{
    slate_panel *p = &s->panel[panel_idx];
    *old_bc_out = p->backend;
    p->backend = new_bc;
    memcpy(p->socket, path, len);
    p->socket[len] = '\0';
    p->socket_len = len;
    p->connected = true;
    p->path[0] = '/';
    p->path[1] = '\0';
    p->path_len = 1u;
    p->cursor = 0u;
    p->entries_count = 0u;
    memset(p->selection, 0, sizeof p->selection);
    /* If the editor was bound to THIS panel, clear it (the underlying
     * backend just got replaced; editor state is no longer valid). */
    if (s->editor_active && s->editor_panel_idx == panel_idx) {
        editor_clear_locked(s);
    }
    s->version++;
    pthread_cond_broadcast(&s->cv);
}

/* SLATE-4a: per-panel disconnect state swap. Mu held. */
static void disconnect_state_swap_locked(stm_slate *s, int panel_idx,
                                              stm_9p_client **old_bc_out)
{
    slate_panel *p = &s->panel[panel_idx];
    *old_bc_out = p->backend;
    p->backend = NULL;
    p->socket[0] = '\0';
    p->socket_len = 0;
    p->connected = false;
    p->path[0] = '\0';
    p->path_len = 0;
    p->cursor = 0u;
    p->entries_count = 0u;
    memset(p->selection, 0, sizeof p->selection);
    /* If the editor was bound to THIS panel, clear it (the panel
     * disconnect terminates the editor session — backend gone). */
    if (s->editor_active && s->editor_panel_idx == panel_idx) {
        editor_clear_locked(s);
    }
    s->version++;
    pthread_cond_broadcast(&s->cv);
}

stm_status stm_slate_disconnect_panel(stm_slate *s, int panel_idx)
{
    if (!s) return STM_EINVAL;
    if (panel_idx < 0 || panel_idx >= SLATE_PANEL_COUNT) return STM_EINVAL;

    pthread_mutex_lock(&s->panel[panel_idx].backend_mu);
    pthread_mutex_lock(&s->mu);
    if (!s->panel[panel_idx].connected) {
        /* No-op — version unchanged. */
        pthread_mutex_unlock(&s->mu);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_OK;
    }
    stm_9p_client *old_bc = NULL;
    disconnect_state_swap_locked(s, panel_idx, &old_bc);
    pthread_mutex_unlock(&s->mu);
    /* R115 P2-1 carry: close UNDER backend_mu so concurrent ops on
     * THIS panel can't race a use-after-free. Other panels'
     * backend_mu are independent and unaffected. */
    if (old_bc) stm_9p_close(old_bc);
    pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
    return STM_OK;
}

stm_status stm_slate_attach_panel(stm_slate *s, int panel_idx,
                                       const char *socket_path, size_t len)
{
    if (!s) return STM_EINVAL;
    if (panel_idx < 0 || panel_idx >= SLATE_PANEL_COUNT) return STM_EINVAL;
    /* Empty body = disconnect THIS panel. */
    if (len == 0) return stm_slate_disconnect_panel(s, panel_idx);
    if (!socket_path) return STM_EINVAL;
    if (len > STM_SLATE_SOCKET_MAX) return STM_EINVAL;
    for (size_t i = 0; i < len; i++) {
        if (socket_path[i] == '\0') return STM_EINVAL;
    }

    char path[STM_SLATE_SOCKET_MAX + 1];
    memcpy(path, socket_path, len);
    path[len] = '\0';

    pthread_mutex_lock(&s->panel[panel_idx].backend_mu);

    stm_9p_dial_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.msize    = 0;
    opts.uname    = NULL;
    opts.aname    = NULL;
    opts.n_uname  = (uint32_t)-1;
    opts.root_fid = SLATE_BACKEND_ROOT_FID;

    stm_9p_client *new_bc = NULL;
    stm_status rc = stm_9p_dial_unix(path, &opts, &new_bc);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }

    pthread_mutex_lock(&s->mu);
    stm_9p_client *old_bc = NULL;
    attach_state_swap_locked(s, panel_idx, path, len, new_bc, &old_bc);
    pthread_mutex_unlock(&s->mu);

    if (old_bc) stm_9p_close(old_bc);

    pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
    return STM_OK;
}

/* SLATE-2 back-compat aliases: route to panel 0 (LEFT). */
stm_status stm_slate_attach(stm_slate *s, const char *socket_path, size_t len)
{
    return stm_slate_attach_panel(s, SLATE_PANEL_LEFT, socket_path, len);
}

stm_status stm_slate_disconnect(stm_slate *s)
{
    return stm_slate_disconnect_panel(s, SLATE_PANEL_LEFT);
}

bool stm_slate_panel_connected(stm_slate *s, int panel_idx)
{
    if (!s) return false;
    if (panel_idx < 0 || panel_idx >= SLATE_PANEL_COUNT) return false;
    pthread_mutex_lock(&s->mu);
    bool v = s->panel[panel_idx].connected;
    pthread_mutex_unlock(&s->mu);
    return v;
}

bool stm_slate_connected(stm_slate *s)
{
    return stm_slate_panel_connected(s, SLATE_PANEL_LEFT);
}

size_t stm_slate_panel_socket(stm_slate *s, int panel_idx,
                                  char *buf, size_t buf_cap)
{
    if (!s) return 0;
    if (panel_idx < 0 || panel_idx >= SLATE_PANEL_COUNT) return 0;
    pthread_mutex_lock(&s->mu);
    size_t n = s->panel[panel_idx].socket_len;
    if (buf && buf_cap > 0) {
        size_t copy = (n < buf_cap - 1) ? n : (buf_cap - 1);
        memcpy(buf, s->panel[panel_idx].socket, copy);
        buf[copy] = '\0';
    }
    pthread_mutex_unlock(&s->mu);
    return n;
}

size_t stm_slate_socket(stm_slate *s, char *buf, size_t buf_cap)
{
    return stm_slate_panel_socket(s, SLATE_PANEL_LEFT, buf, buf_cap);
}

/* SLATE-4-confirm: validate that a string contains no control bytes
 * (R115 P1-1 / R117 P1-1 doctrine carry). For dialog title and
 * options, NO control bytes including '\n'. For body, '\n' is
 * permitted (multi-line); other control bytes still refused. */
static stm_status validate_dialog_string(const char *s, size_t len,
                                              bool allow_newline)
{
    if (!s) return STM_EINVAL;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20u) {
            if (!(allow_newline && c == '\n')) return STM_EINVAL;
        } else if (c == 0x7Fu) {
            return STM_EINVAL;
        }
    }
    return STM_OK;
}

/* Common open-dialog path. Caller has validated all input strings.
 * Mu held by caller. Allocates a free slot, populates fields, bumps
 * version, broadcasts cv. Returns STM_OK with slot id in *out_id, or
 * STM_EBUSY (no free slot) / STM_EOVERFLOW (id saturation). */
static stm_status dialog_open_locked(stm_slate *s,
                                          slate_dialog_kind kind,
                                          const char *title,   size_t title_len,
                                          const char *body,    size_t body_len,
                                          const char *options, size_t options_len,
                                          const char *input,   size_t input_len,
                                          uint64_t *out_id)
{
    int slot = dialog_slot_free_locked(s);
    if (slot < 0) return STM_EBUSY;
    if (s->next_dialog_id > SLATE_QID_ID_MASK) {
        /* R121 P3-1: saturation threshold is the qid encoding's
         * 56-bit mask, NOT UINT64_MAX. Beyond SLATE_QID_ID_MASK
         * the id no longer round-trips through qid_dialog_id() —
         * the dialog would be structurally unaddressable. R29
         * P3-1 doctrine carry — never reuse ids; refuse cleanly
         * with STM_EOVERFLOW rather than wrap or silently
         * mis-address. */
        return STM_EOVERFLOW;
    }
    slate_dialog *d = &s->dialogs[slot];
    d->active = true;
    d->id = s->next_dialog_id;
    s->next_dialog_id++;
    d->kind = kind;
    memcpy(d->title, title, title_len);
    d->title[title_len] = '\0';
    d->title_len = title_len;
    memcpy(d->body, body, body_len);
    d->body[body_len] = '\0';
    d->body_len = body_len;
    memcpy(d->options, options, options_len);
    d->options[options_len] = '\0';
    d->options_len = options_len;
    if (input_len > 0u) memcpy(d->input, input, input_len);
    d->input[input_len] = '\0';
    d->input_len = input_len;
    *out_id = d->id;
    s->version++;
    pthread_cond_broadcast(&s->cv);
    return STM_OK;
}

stm_status stm_slate_open_confirm(stm_slate *s,
                                       const char *title,   size_t title_len,
                                       const char *body,    size_t body_len,
                                       const char *options, size_t options_len,
                                       uint64_t *out_id)
{
    if (!s || !title || !body || !options || !out_id) return STM_EINVAL;
    if (title_len == 0u || title_len > STM_SLATE_DIALOG_TITLE_MAX)
        return STM_EINVAL;
    if (body_len > STM_SLATE_DIALOG_BODY_MAX) return STM_EINVAL;
    if (options_len == 0u || options_len > STM_SLATE_DIALOG_OPTIONS_MAX)
        return STM_EINVAL;
    /* Title + options must be single-line. Body permits '\n'. */
    if (validate_dialog_string(title, title_len, false) != STM_OK)
        return STM_EINVAL;
    if (validate_dialog_string(body, body_len, true) != STM_OK)
        return STM_EINVAL;
    if (validate_dialog_string(options, options_len, false) != STM_OK)
        return STM_EINVAL;

    pthread_mutex_lock(&s->mu);
    stm_status rc = dialog_open_locked(s, SLATE_DIALOG_KIND_CONFIRM,
                                            title,   title_len,
                                            body,    body_len,
                                            options, options_len,
                                            NULL,    0u,
                                            out_id);
    pthread_mutex_unlock(&s->mu);
    return rc;
}

stm_status stm_slate_open_input(stm_slate *s,
                                       const char *title,   size_t title_len,
                                       const char *body,    size_t body_len,
                                       const char *options, size_t options_len,
                                       const char *default_input, size_t default_input_len,
                                       uint64_t *out_id)
{
    if (!s || !title || !body || !options || !out_id) return STM_EINVAL;
    /* default_input may be NULL when default_input_len == 0. */
    if (default_input_len > 0u && !default_input) return STM_EINVAL;
    if (title_len == 0u || title_len > STM_SLATE_DIALOG_TITLE_MAX)
        return STM_EINVAL;
    if (body_len > STM_SLATE_DIALOG_BODY_MAX) return STM_EINVAL;
    if (options_len == 0u || options_len > STM_SLATE_DIALOG_OPTIONS_MAX)
        return STM_EINVAL;
    if (default_input_len > STM_SLATE_DIALOG_INPUT_MAX)
        return STM_EINVAL;
    if (validate_dialog_string(title, title_len, false) != STM_OK)
        return STM_EINVAL;
    if (validate_dialog_string(body, body_len, true) != STM_OK)
        return STM_EINVAL;
    if (validate_dialog_string(options, options_len, false) != STM_OK)
        return STM_EINVAL;
    /* Input field is single-line at v1.0 (no embedded newlines). */
    if (default_input_len > 0u &&
        validate_dialog_string(default_input, default_input_len, false) != STM_OK)
        return STM_EINVAL;

    pthread_mutex_lock(&s->mu);
    stm_status rc = dialog_open_locked(s, SLATE_DIALOG_KIND_INPUT,
                                            title,         title_len,
                                            body,          body_len,
                                            options,       options_len,
                                            default_input, default_input_len,
                                            out_id);
    pthread_mutex_unlock(&s->mu);
    return rc;
}

stm_status stm_slate_dialog_cancel(stm_slate *s, uint64_t id)
{
    if (!s) return STM_EINVAL;
    if (id == 0u) return STM_EINVAL;
    pthread_mutex_lock(&s->mu);
    int slot = dialog_slot_for_id_locked(s, id);
    if (slot < 0) {
        pthread_mutex_unlock(&s->mu);
        return STM_ENOENT;
    }
    /* Programmatic cancel: clear slot, NO last_dismiss record (the
     * caller cancelled; there's no "result" to convey). */
    memset(&s->dialogs[slot], 0, sizeof s->dialogs[slot]);
    s->version++;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

stm_status stm_slate_dialog_consume(stm_slate *s, uint64_t id,
                                          char *result_buf, size_t result_cap, size_t *out_result_len,
                                          char *input_buf,  size_t input_cap,  size_t *out_input_len)
{
    if (!s) return STM_EINVAL;
    if (id == 0u) return STM_EINVAL;
    if (!out_result_len || !out_input_len) return STM_EINVAL;
    pthread_mutex_lock(&s->mu);
    if (s->last_dismiss.id != id) {
        pthread_mutex_unlock(&s->mu);
        return STM_ENOENT;
    }
    /* Match: copy the record into caller buffers, then clear it. */
    *out_result_len = s->last_dismiss.result_len;
    *out_input_len  = s->last_dismiss.input_len;
    if (result_buf && result_cap > 0u) {
        size_t copy = (s->last_dismiss.result_len < result_cap - 1u)
                            ? s->last_dismiss.result_len
                            : (result_cap - 1u);
        memcpy(result_buf, s->last_dismiss.result, copy);
        result_buf[copy] = '\0';
    }
    if (input_buf && input_cap > 0u) {
        size_t copy = (s->last_dismiss.input_len < input_cap - 1u)
                            ? s->last_dismiss.input_len
                            : (input_cap - 1u);
        memcpy(input_buf, s->last_dismiss.input, copy);
        input_buf[copy] = '\0';
    }
    memset(&s->last_dismiss, 0, sizeof s->last_dismiss);
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

bool stm_slate_dialog_active(stm_slate *s)
{
    if (!s) return false;
    pthread_mutex_lock(&s->mu);
    bool a = (dialog_count_locked(s) > 0u);
    pthread_mutex_unlock(&s->mu);
    return a;
}

bool stm_slate_dialog_is_active(stm_slate *s, uint64_t id)
{
    if (!s) return false;
    if (id == 0u) return false;
    pthread_mutex_lock(&s->mu);
    bool a = (dialog_slot_for_id_locked(s, id) >= 0);
    pthread_mutex_unlock(&s->mu);
    return a;
}

uint64_t stm_slate_dialog_id(stm_slate *s)
{
    if (!s) return 0u;
    pthread_mutex_lock(&s->mu);
    uint64_t id = dialog_top_id_locked(s);
    pthread_mutex_unlock(&s->mu);
    return id;
}

size_t stm_slate_dialog_count(stm_slate *s)
{
    if (!s) return 0u;
    pthread_mutex_lock(&s->mu);
    size_t n = dialog_count_locked(s);
    pthread_mutex_unlock(&s->mu);
    return n;
}

/* ────────────────────────────────────────────────────────────────────── */
/* SLATE-5a: editor open / close.                                         */
/* ────────────────────────────────────────────────────────────────────── */

/* Forward decl for stm_slate_editor_open's backend walk. */
static stm_status walk_to_cwd(stm_9p_client *bc, const char *cwd,
                                 uint32_t out_fid);

/* SLATE-5b: forward decl for the modified-flag recomputer used by
 * editor_save (defined later alongside the materialize functions). */
static void editor_recompute_modified_locked(stm_slate *s);

/* SLATE-5a: validate a path for "editor open". Bytes < 0x20 OR
 * == 0x7F are refused (R117 P1-1 doctrine — storage-as-key strings
 * cannot sanitize-on-display because the path is reused on save).
 * UTF-8 multi-byte (≥ 0x80) passes through. NUL embedded refused. */
static stm_status validate_editor_path(const char *path, size_t len)
{
    if (!path) return STM_EINVAL;
    if (len == 0u) return STM_EINVAL;
    if (len > STM_SLATE_EDITOR_FILENAME_MAX) return STM_EINVAL;
    if (path[0] != '/') return STM_EINVAL;  /* require absolute */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c == 0x00u) return STM_EINVAL;
        if (c < 0x20u || c == 0x7Fu) return STM_EINVAL;
    }
    return STM_OK;
}

/* SLATE-4a: panel-aware editor open. The bare public stm_slate_editor_open
 * routes here with panel_idx=SLATE_PANEL_LEFT for back-compat;
 * /event "editor open <left|right> <path>" sets the prefix
 * explicitly. Save + revert read s->editor_panel_idx to pick the
 * right backend. */
static stm_status editor_open_panel(stm_slate *s, int panel_idx,
                                         const char *path, size_t path_len)
{
    if (!s || !path) return STM_EINVAL;
    if (panel_idx < 0 || panel_idx >= SLATE_PANEL_COUNT) return STM_EINVAL;
    stm_status vrc = validate_editor_path(path, path_len);
    if (vrc != STM_OK) return vrc;

    /* Copy `path` into a NUL-terminated local buffer. The caller's
     * `path` is a (ptr, len) pair — typical when this is called
     * from /event verb dispatch where `path` is a slice of a
     * network read buffer. walk_to_cwd treats its argument as a
     * C string (parsed up to '\0'), so we MUST NUL-terminate
     * here to avoid reading beyond path_len into adjacent buffer
     * memory. (Validation already enforced no embedded NULs.) */
    char path_z[STM_SLATE_EDITOR_FILENAME_MAX + 1];
    memcpy(path_z, path, path_len);
    path_z[path_len] = '\0';

    pthread_mutex_lock(&s->panel[panel_idx].backend_mu);
    pthread_mutex_lock(&s->mu);
    stm_9p_client *bc = s->panel[panel_idx].backend;
    pthread_mutex_unlock(&s->mu);
    if (!bc) {
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_EBACKEND;
    }

    /* Phase 1: walk root → path → WORK_FID. */
    stm_status rc = walk_to_cwd(bc, path_z, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }

    /* Phase 2: getattr to verify regular file. */
    stm_9p_attr a;
    memset(&a, 0, sizeof a);
    rc = stm_9p_getattr(bc, SLATE_BACKEND_WORK_FID,
                            STM_9P_GETATTR_MODE | STM_9P_GETATTR_SIZE, &a);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    if ((a.mode & 0170000u) != 0100000u) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_EISDIR;
    }
    if (a.size > STM_SLATE_EDITOR_CONTENT_MAX) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_ERANGE;
    }

    /* Phase 3: Tlopen for read. */
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    rc = stm_9p_lopen(bc, SLATE_BACKEND_WORK_FID, 0u /* O_RDONLY */,
                         &oqid, &iounit);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }

    /* Phase 4: read full content into doubling-heap buffer. */
    uint8_t *buf = NULL;
    size_t cap = 0u;
    size_t got_total = 0u;
    size_t initial = (size_t)a.size;
    if (initial < 4096u) initial = 4096u;
    if (initial > STM_SLATE_EDITOR_CONTENT_MAX) {
        initial = STM_SLATE_EDITOR_CONTENT_MAX;
    }
    buf = malloc(initial);
    if (!buf) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_ENOMEM;
    }
    cap = initial;
    for (;;) {
        if (got_total >= STM_SLATE_EDITOR_CONTENT_MAX) {
            uint8_t probe[1];
            uint32_t probe_got = 0u;
            stm_status pr = stm_9p_read(bc, SLATE_BACKEND_WORK_FID,
                                              got_total, probe, 1u,
                                              &probe_got);
            if (pr == STM_OK && probe_got > 0u) {
                free(buf);
                (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
                pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
                return STM_ERANGE;
            }
            break;
        }
        if (got_total == cap) {
            size_t new_cap = cap * 2u;
            if (new_cap > STM_SLATE_EDITOR_CONTENT_MAX) {
                new_cap = STM_SLATE_EDITOR_CONTENT_MAX;
            }
            uint8_t *nb = realloc(buf, new_cap);
            if (!nb) {
                free(buf);
                (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
                pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
                return STM_ENOMEM;
            }
            buf = nb;
            cap = new_cap;
        }
        size_t remaining = cap - got_total;
        uint32_t chunk = (iounit > 0u && iounit < remaining)
                            ? iounit : (uint32_t)remaining;
        uint32_t got_now = 0u;
        rc = stm_9p_read(bc, SLATE_BACKEND_WORK_FID, got_total,
                            buf + got_total, chunk, &got_now);
        if (rc != STM_OK) {
            free(buf);
            (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return rc;
        }
        if (got_now == 0u) break;
        got_total += got_now;
    }
    /* Phase 5: clunk WORK. */
    (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);

    /* Phase 6: clone buf into editor_original baseline. */
    uint8_t *original = NULL;
    if (got_total > 0u) {
        original = malloc(got_total);
        if (!original) {
            free(buf);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return STM_ENOMEM;
        }
        memcpy(original, buf, got_total);
    }

    /* Phase 7: atomic state swap under s->mu. */
    pthread_mutex_lock(&s->mu);
    free(s->editor_content);
    s->editor_content = buf;
    s->editor_content_len = got_total;
    free(s->editor_original);
    s->editor_original = original;
    s->editor_original_len = got_total;
    memcpy(s->editor_filename, path, path_len);
    s->editor_filename[path_len] = '\0';
    s->editor_filename_len = path_len;
    s->editor_active = true;
    s->editor_panel_idx = panel_idx;
    s->editor_cursor_row = 0u;
    s->editor_cursor_col = 0u;
    s->editor_modified = false;
    s->version++;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);

    pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
    return STM_OK;
}

stm_status stm_slate_editor_open(stm_slate *s, const char *path, size_t path_len)
{
    return editor_open_panel(s, SLATE_PANEL_LEFT, path, path_len);
}

/* SLATE-5b: write the editor buffer back to the backend file +
 * fsync. Atomic-write style would use temp + rename; v1.0 uses
 * Tlopen WRONLY|O_TRUNC + Twrite + Tfsync. Partial-write failures
 * leave the file partially overwritten — acceptable for v1.0 (the
 * editor's modified flag stays true so the user knows the save
 * failed). v1.1 may switch to atomic temp-and-rename.
 *
 * On success: editor_modified=false; editor_original is replaced
 * with the just-written content snapshot (so future memcmp
 * correctly identifies further changes from the saved state). */
stm_status stm_slate_editor_save(stm_slate *s)
{
    if (!s) return STM_EINVAL;

    /* Snapshot panel_idx under mu BEFORE taking the panel's
     * backend_mu — we don't know which lock to take yet. The
     * editor_panel_idx field is set at editor_open time and only
     * cleared by editor_clear_locked (which holds mu). */
    pthread_mutex_lock(&s->mu);
    if (!s->editor_active) {
        pthread_mutex_unlock(&s->mu);
        return STM_ENOENT;
    }
    int panel_idx = s->editor_panel_idx;
    pthread_mutex_unlock(&s->mu);
    if (panel_idx < 0 || panel_idx >= SLATE_PANEL_COUNT) return STM_ENOENT;

    pthread_mutex_lock(&s->panel[panel_idx].backend_mu);

    /* Snapshot active state + filename + content under s->mu. */
    pthread_mutex_lock(&s->mu);
    /* Re-check editor_active + editor_panel_idx — concurrent close
     * could have fired between the snapshot above and now. */
    if (!s->editor_active || s->editor_panel_idx != panel_idx) {
        pthread_mutex_unlock(&s->mu);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_ENOENT;
    }
    stm_9p_client *bc = s->panel[panel_idx].backend;
    if (!bc) {
        pthread_mutex_unlock(&s->mu);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_EBACKEND;
    }
    char path[STM_SLATE_EDITOR_FILENAME_MAX + 1];
    memcpy(path, s->editor_filename, s->editor_filename_len);
    path[s->editor_filename_len] = '\0';
    size_t content_len = s->editor_content_len;
    uint8_t *content_snap = NULL;
    if (content_len > 0u) {
        content_snap = malloc(content_len);
        if (!content_snap) {
            pthread_mutex_unlock(&s->mu);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return STM_ENOMEM;
        }
        memcpy(content_snap, s->editor_content, content_len);
    }
    pthread_mutex_unlock(&s->mu);

    /* Phase 1: walk to file. */
    stm_status rc = walk_to_cwd(bc, path, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        free(content_snap);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    /* Phase 2: Tlopen WRONLY|TRUNC. */
    stm_9p_qid oqid;
    uint32_t iounit = 0;
    rc = stm_9p_lopen(bc, SLATE_BACKEND_WORK_FID,
                         STM_LP9_O_WRONLY | STM_LP9_O_TRUNC,
                         &oqid, &iounit);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        free(content_snap);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    /* Phase 3: Twrite chunked at iounit cap. */
    size_t off = 0u;
    while (off < content_len) {
        size_t remaining = content_len - off;
        uint32_t chunk = (iounit > 0u && iounit < remaining)
                            ? iounit : (uint32_t)remaining;
        uint32_t written = 0u;
        rc = stm_9p_write(bc, SLATE_BACKEND_WORK_FID, off,
                             content_snap + off, chunk, &written);
        if (rc != STM_OK) {
            (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
            free(content_snap);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return rc;
        }
        if (written == 0u) {
            (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
            free(content_snap);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return STM_ENOSPC;
        }
        off += written;
    }
    /* Phase 4: fsync. */
    rc = stm_9p_fsync(bc, SLATE_BACKEND_WORK_FID, /*datasync=*/0u);
    (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        free(content_snap);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }

    /* Phase 5: commit clean state. R124 P3-3 carry: concurrent close
     * could have fired between Phase 4 fsync and Phase 5 mu acquire;
     * if local state is gone, drop the snap (backend was written but
     * slate has no record). */
    pthread_mutex_lock(&s->mu);
    if (!s->editor_active || s->editor_panel_idx != panel_idx) {
        pthread_mutex_unlock(&s->mu);
        free(content_snap);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_OK;
    }
    free(s->editor_original);
    s->editor_original = content_snap;
    s->editor_original_len = content_len;
    editor_recompute_modified_locked(s);
    s->version++;
    pthread_cond_broadcast(&s->cv);
    pthread_mutex_unlock(&s->mu);

    pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
    return STM_OK;
}

/* SLATE-5b: re-read the backend file into the editor buffer,
 * dropping any unsaved edits. Effectively delegates to
 * editor_open(filename) but preserves the cursor by clamping
 * to the new content's bounds. */
stm_status stm_slate_editor_revert(stm_slate *s)
{
    if (!s) return STM_EINVAL;
    /* Snapshot current filename + panel_idx. */
    char path[STM_SLATE_EDITOR_FILENAME_MAX + 1];
    int panel_idx;
    pthread_mutex_lock(&s->mu);
    if (!s->editor_active) {
        pthread_mutex_unlock(&s->mu);
        return STM_ENOENT;
    }
    size_t plen = s->editor_filename_len;
    memcpy(path, s->editor_filename, plen);
    path[plen] = '\0';
    panel_idx = s->editor_panel_idx;
    pthread_mutex_unlock(&s->mu);
    /* Re-open against THIS editor's panel — this re-walks + re-reads
     * + replaces content + resets cursor to 0,0 + clears modified. */
    return editor_open_panel(s, panel_idx, path, plen);
}

stm_status stm_slate_editor_close(stm_slate *s)
{
    if (!s) return STM_EINVAL;
    pthread_mutex_lock(&s->mu);
    if (s->editor_active) {
        free(s->editor_content);
        s->editor_content = NULL;
        s->editor_content_len = 0u;
        free(s->editor_original);
        s->editor_original = NULL;
        s->editor_original_len = 0u;
        s->editor_filename[0] = '\0';
        s->editor_filename_len = 0u;
        s->editor_active = false;
        s->editor_panel_idx = 0;
        s->editor_cursor_row = 0u;
        s->editor_cursor_col = 0u;
        s->editor_modified = false;
        s->version++;
        pthread_cond_broadcast(&s->cv);
    }
    pthread_mutex_unlock(&s->mu);
    return STM_OK;
}

bool stm_slate_editor_active(stm_slate *s)
{
    if (!s) return false;
    pthread_mutex_lock(&s->mu);
    bool a = s->editor_active;
    pthread_mutex_unlock(&s->mu);
    return a;
}

size_t stm_slate_editor_filename(stm_slate *s, char *buf, size_t buf_cap)
{
    if (!s) return 0u;
    pthread_mutex_lock(&s->mu);
    size_t n = s->editor_filename_len;
    if (buf && buf_cap > 0u) {
        size_t copy = (n < buf_cap - 1u) ? n : (buf_cap - 1u);
        memcpy(buf, s->editor_filename, copy);
        buf[copy] = '\0';
    }
    pthread_mutex_unlock(&s->mu);
    return n;
}

size_t stm_slate_editor_content_len(stm_slate *s)
{
    if (!s) return 0u;
    pthread_mutex_lock(&s->mu);
    size_t n = s->editor_content_len;
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

/* SLATE-4a: /connection/{left,right}/socket — panel[i]'s socket
 * path or empty line. The top-level /connection/socket alias
 * targets panel 0 (LEFT) — same materializer with panel_idx=0. */
static stm_status materialize_conn_socket_locked(stm_slate *s,
                                                       slate_session *ss,
                                                       int panel_idx)
{
    size_t n = s->panel[panel_idx].socket_len;
    if (n + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, s->panel[panel_idx].socket, n);
    ss->buf[n] = '\n';
    ss->len = (uint32_t)(n + 1u);
    return STM_OK;
}

/* SLATE-4a: /connection/{left,right}/connected — "1\n" or "0\n". */
static stm_status materialize_conn_connected_locked(stm_slate *s,
                                                          slate_session *ss,
                                                          int panel_idx)
{
    ss->buf[0] = s->panel[panel_idx].connected ? '1' : '0';
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

/* SLATE-3c-selection: /panels/X/selection — comma-separated indices
 * + newline, or just "\n" when empty. Worst case (all 200 bits set,
 * indices 0..199 = "0,1,2,...,199") fits comfortably in BODY_MAX:
 * average index width ~3 chars + comma = ~800 bytes < 4096.
 * STM_SLATE_BODY_MAX. */
static stm_status materialize_panel_selection_locked(stm_slate *s, slate_session *ss,
                                                          int panel_idx)
{
    size_t off = 0;
    bool first = true;
    for (uint32_t idx = 0u; idx < STM_SLATE_ENTRIES_MAX; idx++) {
        uint32_t byte = idx >> 3;
        uint32_t bit  = idx & 7u;
        if ((s->panel[panel_idx].selection[byte] & (1u << bit)) == 0u) {
            continue;
        }
        int n = snprintf((char *)ss->buf + off, sizeof ss->buf - off,
                            first ? "%u" : ",%u", (unsigned)idx);
        if (n < 0) return STM_ERANGE;
        if ((size_t)n >= sizeof ss->buf - off) return STM_ERANGE;
        off += (size_t)n;
        first = false;
    }
    if (off + 1u > sizeof ss->buf) return STM_ERANGE;
    ss->buf[off] = '\n';
    ss->len = (uint32_t)(off + 1u);
    return STM_OK;
}

/* SLATE-4b: /dialogs/stack — comma-separated active dialog ids
 * sorted ascending + newline. Empty (just "\n") when no dialogs
 * active. With STM_SLATE_DIALOG_MAX_ACTIVE=4 ids and uint64_t up to
 * 20 decimal digits, worst case = 4*20 + 3 commas + 1 newline = 84
 * bytes — well within STM_SLATE_BODY_MAX. */
static stm_status materialize_dialog_stack_locked(stm_slate *s, slate_session *ss)
{
    uint64_t ids[STM_SLATE_DIALOG_MAX_ACTIVE];
    size_t n = dialog_collect_sorted_locked(s, ids);
    if (n == 0u) {
        ss->buf[0] = '\n';
        ss->len = 1u;
        return STM_OK;
    }
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        int w = snprintf((char *)ss->buf + off, sizeof ss->buf - off,
                            i == 0 ? "%llu" : ",%llu",
                            (unsigned long long)ids[i]);
        if (w < 0) return STM_ERANGE;
        if ((size_t)w >= sizeof ss->buf - off) return STM_ERANGE;
        off += (size_t)w;
    }
    if (off + 1u > sizeof ss->buf) return STM_ERANGE;
    ss->buf[off] = '\n';
    ss->len = (uint32_t)(off + 1u);
    return STM_OK;
}

/* SLATE-4b: /dialogs/<id>/kind — kind name + newline.
 * Caller has already verified the slot is still active under mu. */
static stm_status materialize_dialog_kind_locked(slate_dialog *d, slate_session *ss)
{
    const char *kind_name;
    switch (d->kind) {
    case SLATE_DIALOG_KIND_CONFIRM: kind_name = "confirm"; break;
    case SLATE_DIALOG_KIND_INPUT:   kind_name = "input";   break;
    default:
        /* R121 P3-4: this branch is unreachable today — every
         * active slot has CONFIRM or INPUT kind. STM_ECORRUPT
         * (rather than STM_EBACKEND) communicates that an
         * internal invariant has been violated rather than a
         * remote 9P op failed; if a future kind is added without
         * a switch arm here, the renderer error class is correct. */
        return STM_ECORRUPT;
    }
    int n = snprintf((char *)ss->buf, sizeof ss->buf, "%s\n", kind_name);
    if (n < 0 || n >= (int)sizeof ss->buf) return STM_ERANGE;
    ss->len = (uint32_t)n;
    return STM_OK;
}

/* SLATE-4b: /dialogs/<id>/title — single-line + newline. */
static stm_status materialize_dialog_title_locked(slate_dialog *d, slate_session *ss)
{
    if (d->title_len + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, d->title, d->title_len);
    ss->buf[d->title_len] = '\n';
    ss->len = (uint32_t)(d->title_len + 1u);
    return STM_OK;
}

/* SLATE-4b: /dialogs/<id>/body — multi-line + trailing newline. */
static stm_status materialize_dialog_body_locked(slate_dialog *d, slate_session *ss)
{
    if (d->body_len + 1u > sizeof ss->buf) {
        /* Body up to STM_SLATE_DIALOG_BODY_MAX (1024) + '\n' fits
         * in STM_SLATE_BODY_MAX (4096). Defensive nonetheless. */
        return STM_ERANGE;
    }
    memcpy(ss->buf, d->body, d->body_len);
    ss->buf[d->body_len] = '\n';
    ss->len = (uint32_t)(d->body_len + 1u);
    return STM_OK;
}

/* SLATE-4b: /dialogs/<id>/options — comma-separated + newline. */
static stm_status materialize_dialog_options_locked(slate_dialog *d, slate_session *ss)
{
    if (d->options_len + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, d->options, d->options_len);
    ss->buf[d->options_len] = '\n';
    ss->len = (uint32_t)(d->options_len + 1u);
    return STM_OK;
}

/* SLATE-4b: /dialogs/<id>/input — single-line editable string +
 * newline. Caller has verified slot.kind == INPUT. */
static stm_status materialize_dialog_input_locked(slate_dialog *d, slate_session *ss)
{
    if (d->input_len + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, d->input, d->input_len);
    ss->buf[d->input_len] = '\n';
    ss->len = (uint32_t)(d->input_len + 1u);
    return STM_OK;
}

/* SLATE-5a: /editor/active — "1\n" or "0\n" (always 2 bytes). */
static stm_status materialize_editor_active_locked(stm_slate *s, slate_session *ss)
{
    ss->buf[0] = s->editor_active ? '1' : '0';
    ss->buf[1] = '\n';
    ss->len = 2u;
    return STM_OK;
}

/* SLATE-5a: /editor/filename — filename + '\n'; just '\n' (1 byte)
 * when no editor active. */
static stm_status materialize_editor_filename_locked(stm_slate *s, slate_session *ss)
{
    if (s->editor_filename_len + 1u > sizeof ss->buf) return STM_ERANGE;
    memcpy(ss->buf, s->editor_filename, s->editor_filename_len);
    ss->buf[s->editor_filename_len] = '\n';
    ss->len = (uint32_t)(s->editor_filename_len + 1u);
    return STM_OK;
}

/* SLATE-5a: /editor/cursor — "row,col\n". v5a always "0,0\n". */
static stm_status materialize_editor_cursor_locked(stm_slate *s, slate_session *ss)
{
    int n = snprintf((char *)ss->buf, sizeof ss->buf, "%u,%u\n",
                        (unsigned)s->editor_cursor_row,
                        (unsigned)s->editor_cursor_col);
    if (n < 0 || n >= (int)sizeof ss->buf) return STM_ERANGE;
    ss->len = (uint32_t)n;
    return STM_OK;
}

/* SLATE-5a + SLATE-5b: /editor/modified — "1\n" or "0\n". The flag
 * is a cached derivation of (content vs original); recomputed at
 * every state-mutating editor op. */
static stm_status materialize_editor_modified_locked(stm_slate *s, slate_session *ss)
{
    ss->buf[0] = s->editor_modified ? '1' : '0';
    ss->buf[1] = '\n';
    ss->len = 2u;
    return STM_OK;
}

/* SLATE-5b: recompute the modified flag from the current content vs
 * pristine original. Caller has s->mu. */
static void editor_recompute_modified_locked(stm_slate *s)
{
    if (!s->editor_active) {
        s->editor_modified = false;
        return;
    }
    if (s->editor_content_len != s->editor_original_len) {
        s->editor_modified = true;
        return;
    }
    if (s->editor_content_len == 0u) {
        s->editor_modified = false;
        return;
    }
    s->editor_modified = (memcmp(s->editor_content, s->editor_original,
                                  s->editor_content_len) != 0);
}

/* SLATE-5a: /editor/content — file contents. Uses bulk_buf because
 * content can exceed STM_SLATE_BODY_MAX (4 KiB) — bounded only by
 * STM_SLATE_EDITOR_CONTENT_MAX (1 MiB). Snapshot at lopen, served
 * on subsequent reads (R114 P1-1 doctrine carry; same posture as
 * /log/tail and /panels/X/entries). NO sanitization — file
 * contents are what they are; renderers decide how to display
 * control bytes (this is a text-EDITING surface, not a line-
 * oriented log). Empty body (0 bytes, NOT "\n") when no editor
 * active — the editor IS the content; an inactive editor has
 * literally no content to show. */
static stm_status materialize_editor_content_locked(stm_slate *s, slate_session *ss)
{
    if (!s->editor_active || s->editor_content_len == 0u) {
        ss->len = 0u;
        return STM_OK;
    }
    /* R123 P3-3: defense-in-depth cap check before bulk_buf alloc.
     * editor_open + editor write paths already enforce
     * editor_content_len ≤ STM_SLATE_EDITOR_CONTENT_MAX, but a future
     * regression that lets the field grow past MAX would silently
     * malloc that much and bypass the design's memory-budget. The
     * single-point-of-failure nature of materialize argues for
     * belt-and-braces here. STM_ERANGE matches the cap-overrun
     * status used at the open/write paths. */
    if (s->editor_content_len > STM_SLATE_EDITOR_CONTENT_MAX) {
        return STM_ERANGE;
    }
    /* Use bulk_buf for content; allocate exact size. */
    ss->bulk_buf = malloc(s->editor_content_len);
    if (!ss->bulk_buf) return STM_ENOMEM;
    memcpy(ss->bulk_buf, s->editor_content, s->editor_content_len);
    ss->bulk_len = (uint32_t)s->editor_content_len;
    return STM_OK;
}

/* SLATE-4-confirm: validate that `result` (already trimmed of
 * trailing newline) is one of the comma-separated tokens in
 * `options`. Returns STM_OK if found, STM_EINVAL otherwise. */
static stm_status validate_dialog_result(const char *options, size_t options_len,
                                              const char *result, size_t result_len)
{
    if (result_len == 0u) return STM_EINVAL;
    /* Iterate options, splitting on ','. */
    size_t i = 0;
    while (i < options_len) {
        size_t start = i;
        while (i < options_len && options[i] != ',') i++;
        size_t tok_len = i - start;
        if (tok_len == result_len &&
            memcmp(options + start, result, result_len) == 0) {
            return STM_OK;
        }
        if (i < options_len) i++;  /* skip ',' */
    }
    return STM_EINVAL;
}

/* SLATE-3c-selection: parse a comma-separated decimal index list
 * "1,3,5" into a bitset. Empty body (or just "\n") → empty selection.
 * Strict format: digits and commas only; no whitespace, no leading
 * zeros (except literal "0"), no trailing comma, no duplicate comma,
 * no leading/trailing newlines beyond a single optional '\n' tail.
 * Indices ≥ STM_SLATE_ENTRIES_MAX refused as STM_EINVAL.
 *
 * Output: on success, `out_bits` holds the parsed bitset. On any
 * parse error or out-of-range index, returns the error WITHOUT
 * modifying caller's bitset. */
static stm_status parse_selection_bits(const char *body, size_t body_len,
                                            uint8_t out_bits[SLATE_SELECTION_BYTES])
{
    /* Strip optional trailing newline. */
    if (body_len > 0u && body[body_len - 1u] == '\n') body_len--;
    /* Empty body → empty selection. */
    uint8_t scratch[SLATE_SELECTION_BYTES];
    memset(scratch, 0, sizeof scratch);
    if (body_len == 0u) {
        memcpy(out_bits, scratch, sizeof scratch);
        return STM_OK;
    }

    size_t i = 0;
    while (i < body_len) {
        /* Parse one decimal index; first char must be a digit. */
        if (body[i] < '0' || body[i] > '9') return STM_EINVAL;
        unsigned long long v = 0;
        size_t start = i;
        while (i < body_len && body[i] >= '0' && body[i] <= '9') {
            v = v * 10ull + (unsigned long long)(body[i] - '0');
            if (v >= STM_SLATE_ENTRIES_MAX) return STM_EINVAL;
            i++;
        }
        /* Refuse "01", "001", etc. — exactly one zero before non-zero
         * leading digit means the value is "0" itself. */
        if (i - start > 1u && body[start] == '0') return STM_EINVAL;
        /* Set bit. */
        uint32_t idx = (uint32_t)v;
        scratch[idx >> 3] |= (uint8_t)(1u << (idx & 7u));
        if (i == body_len) break;
        /* Separator must be ','. */
        if (body[i] != ',') return STM_EINVAL;
        i++;
        /* No trailing comma. */
        if (i == body_len) return STM_EINVAL;
    }
    memcpy(out_bits, scratch, sizeof scratch);
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

/* Walk root → cwd into out_fid. Path is "/" or "/a/b/c". Empty
 * path is invalid (caller must short-circuit). Returns STM_OK on
 * success. On error, out_fid is NOT bound (per Twalk partial-walk
 * semantics).
 *
 * Path depth bound: cwd is bounded at STM_SLATE_PATH_MAX (1023);
 * with single-char components this admits ~511 path components,
 * well above 9P2000.L's STM_9P_MAX_WALK (16) per-Twalk cap. For
 * cwd ≤ STM_9P_MAX_WALK components the walk fits in a single
 * Twalk; for deeper paths we iterate, ping-ponging between two
 * scratch fids and walking the LAST batch into out_fid (R117 P3-3
 * closure — the SLATE-3 forward-note from CLAUDE.md slate row
 * clause 13). The scratch fids (WALK_A_FID + WALK_B_FID) live
 * entirely within this call; on success exactly one is clunked
 * during iteration (the source of the final step) and the other
 * is the now-bound out_fid (or nothing — the n_names ≤ 16 fast
 * path uses neither). On error, intermediate scratch fids are
 * clunked best-effort.
 *
 * Components are parsed into a heap-allocated buffer rather than
 * stack — bounded at ~131 KB worst case (max_comps × 257 bytes)
 * which would otherwise blow stack on slate's per-connection
 * worker pthreads. */
static stm_status walk_to_cwd(stm_9p_client *bc, const char *cwd,
                                 uint32_t out_fid)
{
    if (!cwd || *cwd == '\0') return STM_EINVAL;

    /* Upper-bound the component count by the slash count + 1. */
    size_t max_comps = 1u;
    for (const char *p = cwd; *p; p++) {
        if (*p == '/') max_comps++;
    }

    const char **names_arr = NULL;
    char *names_blob = NULL;
    if (max_comps > 0u) {
        names_arr = malloc(max_comps * sizeof(*names_arr));
        names_blob = malloc(max_comps * (STM_LP9_NAME_MAX + 1u));
        if (!names_arr || !names_blob) {
            free(names_arr);
            free(names_blob);
            return STM_ENOMEM;
        }
    }

    /* Parse cwd into NUL-terminated components into names_blob;
     * names_arr[i] points at the i-th component's slot. */
    size_t n_names = 0;
    const char *p = cwd;
    if (*p == '/') p++;
    while (*p) {
        const char *slash = strchr(p, '/');
        size_t comp_len = slash ? (size_t)(slash - p) : strlen(p);
        if (comp_len == 0u) {
            /* "//" — skip the empty component (treat like normalised). */
            if (!slash) break;
            p = slash + 1;
            continue;
        }
        if (comp_len > STM_LP9_NAME_MAX) {
            free(names_arr);
            free(names_blob);
            return STM_EINVAL;
        }
        char *dst = names_blob + n_names * (STM_LP9_NAME_MAX + 1u);
        memcpy(dst, p, comp_len);
        dst[comp_len] = '\0';
        names_arr[n_names] = dst;
        n_names++;
        if (!slash) break;
        p = slash + 1;
    }

    stm_status rc;

    /* Fast path: single Twalk handles all components. */
    if (n_names <= STM_9P_MAX_WALK) {
        rc = stm_9p_walk(bc, SLATE_BACKEND_ROOT_FID, out_fid,
                            (uint16_t)n_names, names_arr, NULL, NULL);
        free(names_arr);
        free(names_blob);
        return rc;
    }

    /* Iterative path: walk first STM_9P_MAX_WALK components from
     * ROOT into WALK_A; then ping-pong walk subsequent batches
     * (clunking the previous source after each step); the LAST
     * batch walks into out_fid. */
    rc = stm_9p_walk(bc, SLATE_BACKEND_ROOT_FID, SLATE_BACKEND_WALK_A_FID,
                        STM_9P_MAX_WALK, names_arr, NULL, NULL);
    if (rc != STM_OK) {
        free(names_arr);
        free(names_blob);
        return rc;
    }
    uint32_t src = SLATE_BACKEND_WALK_A_FID;
    uint32_t dst = SLATE_BACKEND_WALK_B_FID;
    size_t off = STM_9P_MAX_WALK;
    while (off < n_names) {
        size_t remaining = n_names - off;
        size_t batch = (remaining > STM_9P_MAX_WALK) ? STM_9P_MAX_WALK
                                                      : remaining;
        bool is_last = (off + batch == n_names);
        uint32_t target = is_last ? out_fid : dst;
        stm_status walk_rc = stm_9p_walk(bc, src, target, (uint16_t)batch,
                                              &names_arr[off], NULL, NULL);
        /* Always clunk src — once we've walked from it, it's spent
         * regardless of the walk outcome. Best-effort; we don't
         * propagate clunk errors over walk errors. */
        (void)stm_9p_clunk(bc, src);
        if (walk_rc != STM_OK) {
            free(names_arr);
            free(names_blob);
            return walk_rc;
        }
        if (is_last) {
            free(names_arr);
            free(names_blob);
            return STM_OK;
        }
        src = target;
        dst = (dst == SLATE_BACKEND_WALK_A_FID) ? SLATE_BACKEND_WALK_B_FID
                                                 : SLATE_BACKEND_WALK_A_FID;
        off += batch;
    }
    /* Loop exits via is_last → unreachable unless n_names was
     * miscounted. Defensive return. */
    free(names_arr);
    free(names_blob);
    return STM_OK;
}

/* SLATE-4a: render panel entries against `panel_idx`'s backend.
 * Acquires + releases panel[panel_idx].backend_mu. Briefly takes
 * s->mu only to read the panel's backend pointer.
 *
 * Returns:
 *   STM_OK + *out_buf=NULL + *out_len=0  → disconnected; serve empty
 *   STM_OK + *out_buf=heap + *out_len>0  → success; caller frees buf
 *   any other status                     → backend error; *out_buf=NULL
 *
 * Body format: one line per entry, "TYPE MODE SIZE MTIME NAME\n".
 * Truncated at STM_SLATE_ENTRIES_MAX entries.
 *
 * SLATE-4a synthesizes a leading ".." entry when cwd != "/" so the
 * cursor can land on it — pressing Enter on ".." ascends to the
 * parent (handled by the descend verb's special-case for the
 * synthetic name). The user-reported bug "missing .." closes via
 * this single synthesis point so external 9P clients (Halcyon,
 * scripts) see it too without each having to synthesise its own.
 *
 * out_count receives the rendered entries count (including the
 * synthetic "..") and is cached into panel.entries_count by the
 * caller for cursor-clamp defense-in-depth. */
static stm_status panel_entries_render(stm_slate *s, int panel_idx,
                                            const char *cwd,
                                            uint8_t **out_buf, uint32_t *out_len,
                                            uint32_t *out_count)
{
    *out_buf = NULL;
    *out_len = 0;
    *out_count = 0u;

    pthread_mutex_lock(&s->panel[panel_idx].backend_mu);

    pthread_mutex_lock(&s->mu);
    stm_9p_client *bc = s->panel[panel_idx].backend;
    pthread_mutex_unlock(&s->mu);
    if (!bc) {
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_OK;
    }

    stm_status rc = walk_to_cwd(bc, cwd, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    rc = stm_9p_walk(bc, SLATE_BACKEND_WORK_FID, SLATE_BACKEND_CWD_FID,
                        0u, NULL, NULL, NULL);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    rc = stm_9p_lopen(bc, SLATE_BACKEND_WORK_FID,
                         STM_9P_O_RDONLY | STM_9P_O_DIRECTORY,
                         NULL, NULL);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }

    slate_dirent *arr = calloc(STM_SLATE_ENTRIES_MAX, sizeof *arr);
    if (!arr) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_ENOMEM;
    }
    slate_dir_collect dc = { arr, STM_SLATE_ENTRIES_MAX, 0 };

    uint64_t offset = 0;
    while (1) {
        uint32_t entries = 0;
        uint64_t next_off = offset;
        rc = stm_9p_readdir(bc, SLATE_BACKEND_WORK_FID,
                               offset, 0u,
                               collect_dirent_cb, &dc,
                               &entries, &next_off);
        if (rc == STM_ENOTSUPPORTED) { rc = STM_OK; break; }
        if (rc != STM_OK) break;
        if (entries == 0) break;
        if (next_off == offset) break;
        offset = next_off;
    }
    (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        free(arr);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }

    /* SLATE-4a: synthesize a leading ".." entry when cwd != "/".
     * cwd_len > 1 ⇒ we're not at root (cwd is "/foo/.../x" or "/foo");
     * cwd_len == 1 + cwd[0] == '/' ⇒ at root, no synthesis. */
    bool synth_dotdot = !(cwd[0] == '/' && cwd[1] == '\0');

    /* Per-entry walk + getattr. */
    uint32_t emit_count = dc.count + (synth_dotdot ? 1u : 0u);
    size_t body_cap = (size_t)emit_count * STM_SLATE_ENTRY_LINE_MAX + 1u;
    if (body_cap == 1u) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        free(arr);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_OK;
    }
    if (body_cap > STM_SLATE_LOG_TAIL_MAX) body_cap = STM_SLATE_LOG_TAIL_MAX;
    uint8_t *body = malloc(body_cap);
    if (!body) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        free(arr);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_ENOMEM;
    }

    size_t body_off = 0;
    uint32_t rendered = 0u;

    /* Synthesised ".." at index 0 when not at root. Type=d, mode/size/
     * mtime are zeroes — the renderer treats name == ".." specially
     * (focus highlight / parent-icon). The descend verb's "key Enter
     * on .." → ascend short-circuit handles navigation. */
    if (synth_dotdot) {
        char line[STM_SLATE_ENTRY_LINE_MAX + 1];
        int n = snprintf(line, sizeof line, "d 0000 0 0 ..\n");
        if (n < 0) n = 0;
        if (n >= (int)sizeof line) n = (int)sizeof line - 1;
        if (body_off + (size_t)n <= body_cap) {
            memcpy(body + body_off, line, (size_t)n);
            body_off += (size_t)n;
            rendered++;
        }
    }

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

    /* Account for emitted backend entries (rendered counter only
     * counts those whose snprintf succeeded + fit). */
    rendered += dc.count;
    (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
    free(arr);
    pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);

    *out_buf = body;
    *out_len = (uint32_t)body_off;
    *out_count = rendered;
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
    /* SLATE-4a slate-side cursor clamp (defense-in-depth on the
     * TUI's own SWISS-3b clamp): if we have a fresh entries-count
     * cache from a recent panel-entries materialise, refuse the
     * advance when cursor is already at the last entry. The cache
     * is invalidated to 0 on every cwd-changing op (attach,
     * disconnect, descend, ascend) — when entries_count == 0 we
     * fall back to the original UINT32_MAX cap so a panel that has
     * never been opened on /entries doesn't get stuck. The fix
     * targets the user-reported bug "you can scroll past the last
     * file, breaks UI completely". */
    uint32_t cap = s->panel[panel_idx].entries_count;
    uint32_t cursor = s->panel[panel_idx].cursor;
    bool can_advance = (cap > 0u) ? (cursor + 1u < cap)
                                   : (cursor < UINT32_MAX);
    if (can_advance) {
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
    if (!s->panel[panel_idx].connected) {
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
    /* SLATE-4a: cwd changed → invalidate cached entries_count
     * (cursor clamp falls back to UINT32_MAX until the next
     * panel-entries materialise repopulates it). */
    s->panel[panel_idx].entries_count = 0u;
    /* SLATE-3c-selection: cwd change invalidates selection. */
    memset(s->panel[panel_idx].selection, 0,
              sizeof s->panel[panel_idx].selection);
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
    if (!s->panel[panel_idx].connected) {
        pthread_mutex_unlock(&s->mu);
        return STM_EBACKEND;
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

    /* SLATE-4a: synthetic ".." appears at index 0 when cwd != "/".
     * Treat key Enter on it as ascend — same effect as Backspace. */
    bool synth_dotdot_present = !(cwd[0] == '/' && cwd[1] == '\0');
    if (synth_dotdot_present && cursor == 0u) {
        return ascend_panel(s, panel_idx);
    }

    /* R117 P3-1 carry: cursor is in the user-visible index space;
     * subtract the synthetic ".." offset (if present) to get the
     * backend-relative target index. */
    uint32_t backend_target = synth_dotdot_present ? (cursor - 1u) : cursor;

    if (backend_target >= STM_SLATE_ENTRIES_MAX) {
        return STM_EINVAL;
    }

    pthread_mutex_lock(&s->panel[panel_idx].backend_mu);
    pthread_mutex_lock(&s->mu);
    stm_9p_client *bc = s->panel[panel_idx].backend;
    pthread_mutex_unlock(&s->mu);
    if (!bc) {
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_EBACKEND;
    }

    stm_status rc = walk_to_cwd(bc, cwd, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    rc = stm_9p_walk(bc, SLATE_BACKEND_WORK_FID, SLATE_BACKEND_CWD_FID,
                        0u, NULL, NULL, NULL);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    rc = stm_9p_lopen(bc, SLATE_BACKEND_WORK_FID,
                         STM_9P_O_RDONLY | STM_9P_O_DIRECTORY,
                         NULL, NULL);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }

    descend_find_ctx fc = { .target_idx = backend_target, .emitted = 0,
                              .found = false, .type = 0, .name_len = 0 };
    uint64_t offset = 0;
    while (1) {
        uint32_t entries = 0;
        uint64_t next_off = offset;
        rc = stm_9p_readdir(bc, SLATE_BACKEND_WORK_FID,
                               offset, 0u,
                               descend_find_cb, &fc,
                               &entries, &next_off);
        if (rc == STM_ENOTSUPPORTED) { rc = STM_OK; break; }
        if (rc != STM_OK) break;
        if (entries == 0) break;
        if (next_off == offset) break;
        offset = next_off;
        if (fc.found) break;
    }
    (void)stm_9p_clunk(bc, SLATE_BACKEND_WORK_FID);
    if (rc != STM_OK) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return rc;
    }
    if (!fc.found) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_EINVAL;
    }
    if (fc.bad_name) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_EINVAL;
    }
    if (fc.type != 4u /* DT_DIR */) {
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
        return STM_ENOTDIR;
    }

    {
        char target_path[STM_SLATE_PATH_MAX + 1];
        size_t target_path_len;
        rc = build_descended_path(cwd, cwd_len, fc.name, fc.name_len,
                                       target_path, sizeof target_path,
                                       &target_path_len);
        if (rc != STM_OK) {
            (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return rc;
        }
        const char *names_arr[1] = { fc.name };
        rc = stm_9p_walk(bc, SLATE_BACKEND_CWD_FID, SLATE_BACKEND_ENT_FID,
                            1u, names_arr, NULL, NULL);
        if (rc != STM_OK) {
            (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return rc;
        }
        stm_9p_attr a;
        memset(&a, 0, sizeof a);
        rc = stm_9p_getattr(bc, SLATE_BACKEND_ENT_FID,
                                STM_9P_GETATTR_MODE, &a);
        (void)stm_9p_clunk(bc, SLATE_BACKEND_ENT_FID);
        (void)stm_9p_clunk(bc, SLATE_BACKEND_CWD_FID);
        if (rc != STM_OK) {
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return rc;
        }
        if ((a.mode & 0170000u) != 0040000u) {
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return STM_ENOTDIR;
        }

        pthread_mutex_lock(&s->mu);
        if (!s->panel[panel_idx].connected) {
            pthread_mutex_unlock(&s->mu);
            pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
            return STM_EBACKEND;
        }
        memcpy(s->panel[panel_idx].path, target_path, target_path_len);
        s->panel[panel_idx].path[target_path_len] = '\0';
        s->panel[panel_idx].path_len = target_path_len;
        s->panel[panel_idx].cursor = 0u;
        /* SLATE-4a: cwd changed → invalidate cached entries_count. */
        s->panel[panel_idx].entries_count = 0u;
        /* SLATE-3c-selection: cwd change invalidates selection
         * indices (they referenced the old directory's entries). */
        memset(s->panel[panel_idx].selection, 0,
                  sizeof s->panel[panel_idx].selection);
        s->version++;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
    }

    pthread_mutex_unlock(&s->panel[panel_idx].backend_mu);
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
    uint32_t entries_count = 0u;

    if (path_len > 0) {
        stm_status rc = panel_entries_render(s, panel_idx, path,
                                                  &body, &body_len,
                                                  &entries_count);
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
    /* SLATE-4a: cache the rendered entries-count for slate-side
     * cursor clamp (verb_key_down). Updated even when entries_count
     * == 0 (empty dir) so a fresh-disconnect → fresh-attach sequence
     * forgets stale counts from before. */
    s->panel[panel_idx].entries_count = entries_count;
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

/* SLATE-4-confirm: parse a decimal name as uint64_t. Returns true
 * iff the entire name is digits and the parsed value fits in
 * uint64_t. Used by /dialogs walk to interpret child names as
 * dialog ids. */
static bool parse_decimal_u64(const char *name, size_t name_len,
                                  uint64_t *out)
{
    if (name_len == 0u) return false;
    /* Refuse leading zero (except literal "0"). */
    if (name_len > 1u && name[0] == '0') return false;
    uint64_t v = 0;
    for (size_t i = 0; i < name_len; i++) {
        char c = name[i];
        if (c < '0' || c > '9') return false;
        if (v > (UINT64_MAX - 9u) / 10u) return false;
        v = v * 10u + (uint64_t)(c - '0');
    }
    *out = v;
    return true;
}

static stm_status vops_walk(void *ctx, uint64_t dir_qid_path,
                              const char *name, size_t name_len,
                              stm_lp9_qid *out)
{
    stm_slate *s = ctx;
    slate_kind dk = qid_kind(dir_qid_path);

    /* SLATE-4b: /dialogs subtree has dynamic-id qids; the standard
     * switch-on-name pattern below assumes static qids (kind only).
     * Handle dialog walks first. */
    if (dk == SLATE_KIND_DIALOGS_DIR) {
        if (str_eq(name, name_len, "stack")) {
            stm_lp9_attr a;
            stm_status rc = getattr_at(qid_of(SLATE_KIND_DIALOG_STACK), &a);
            if (rc != STM_OK) return rc;
            *out = a.qid;
            return STM_OK;
        }
        uint64_t did;
        if (!parse_decimal_u64(name, name_len, &did)) return STM_ENOENT;
        /* Verify id matches an ACTIVE dialog slot. Stale ids
         * (dismissed dialogs) return ENOENT. */
        pthread_mutex_lock(&s->mu);
        bool match = (dialog_slot_for_id_locked(s, did) >= 0);
        pthread_mutex_unlock(&s->mu);
        if (!match) return STM_ENOENT;
        stm_lp9_attr a;
        stm_status rc = getattr_at(
            qid_of_dialog(SLATE_KIND_DIALOG_DIR, did), &a);
        if (rc != STM_OK) return rc;
        *out = a.qid;
        return STM_OK;
    }
    if (dk == SLATE_KIND_DIALOG_DIR) {
        uint64_t did = qid_dialog_id(dir_qid_path);
        /* Re-check freshness of the id (concurrent dismiss could
         * have cleared the slot). For "input" name: also gated on
         * the slot's kind == INPUT — confirm-kind dialogs do NOT
         * expose an input field. */
        pthread_mutex_lock(&s->mu);
        int slot = dialog_slot_for_id_locked(s, did);
        bool is_input_kind = (slot >= 0 &&
                              s->dialogs[slot].kind == SLATE_DIALOG_KIND_INPUT);
        pthread_mutex_unlock(&s->mu);
        if (slot < 0) return STM_ENOENT;
        slate_kind tk = SLATE_KIND_MAX;
        if (str_eq(name, name_len, "kind"))         tk = SLATE_KIND_DIALOG_KIND;
        else if (str_eq(name, name_len, "title"))   tk = SLATE_KIND_DIALOG_TITLE;
        else if (str_eq(name, name_len, "body"))    tk = SLATE_KIND_DIALOG_BODY;
        else if (str_eq(name, name_len, "options")) tk = SLATE_KIND_DIALOG_OPTIONS;
        else if (str_eq(name, name_len, "result"))  tk = SLATE_KIND_DIALOG_RESULT;
        else if (str_eq(name, name_len, "input")) {
            if (!is_input_kind) return STM_ENOENT;
            tk = SLATE_KIND_DIALOG_INPUT;
        } else return STM_ENOENT;
        stm_lp9_attr a;
        stm_status rc = getattr_at(qid_of_dialog(tk, did), &a);
        if (rc != STM_OK) return rc;
        *out = a.qid;
        return STM_OK;
    }

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
        else if (str_eq(name, name_len, "dialogs"))    target = SLATE_KIND_DIALOGS_DIR;
        else if (str_eq(name, name_len, "editor"))     target = SLATE_KIND_EDITOR_DIR;
        break;
    case SLATE_KIND_LOG_DIR:
        if (str_eq(name, name_len, "tail"))            target = SLATE_KIND_LOG_TAIL;
        else if (str_eq(name, name_len, "append"))     target = SLATE_KIND_LOG_APPEND;
        break;
    case SLATE_KIND_CONN_DIR:
        if (str_eq(name, name_len, "socket"))          target = SLATE_KIND_CONN_SOCKET;
        else if (str_eq(name, name_len, "connected"))  target = SLATE_KIND_CONN_CONNECTED;
        else if (str_eq(name, name_len, "attach"))     target = SLATE_KIND_CONN_ATTACH;
        else if (str_eq(name, name_len, "left"))       target = SLATE_KIND_CONN_L_DIR;
        else if (str_eq(name, name_len, "right"))      target = SLATE_KIND_CONN_R_DIR;
        break;
    case SLATE_KIND_CONN_L_DIR:
        if (str_eq(name, name_len, "socket"))          target = SLATE_KIND_CONN_L_SOCKET;
        else if (str_eq(name, name_len, "connected"))  target = SLATE_KIND_CONN_L_CONNECTED;
        else if (str_eq(name, name_len, "attach"))     target = SLATE_KIND_CONN_L_ATTACH;
        break;
    case SLATE_KIND_CONN_R_DIR:
        if (str_eq(name, name_len, "socket"))          target = SLATE_KIND_CONN_R_SOCKET;
        else if (str_eq(name, name_len, "connected"))  target = SLATE_KIND_CONN_R_CONNECTED;
        else if (str_eq(name, name_len, "attach"))     target = SLATE_KIND_CONN_R_ATTACH;
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
        else if (str_eq(name, name_len, "selection"))  target = SLATE_KIND_PANEL_L_SELECTION;
        break;
    case SLATE_KIND_EDITOR_DIR:
        if (str_eq(name, name_len, "active"))          target = SLATE_KIND_EDITOR_ACTIVE;
        else if (str_eq(name, name_len, "filename"))   target = SLATE_KIND_EDITOR_FILENAME;
        else if (str_eq(name, name_len, "content"))    target = SLATE_KIND_EDITOR_CONTENT;
        else if (str_eq(name, name_len, "cursor"))     target = SLATE_KIND_EDITOR_CURSOR;
        else if (str_eq(name, name_len, "modified"))   target = SLATE_KIND_EDITOR_MODIFIED;
        else if (str_eq(name, name_len, "action"))     target = SLATE_KIND_EDITOR_ACTION;
        break;
    case SLATE_KIND_PANEL_R_DIR:
        if (str_eq(name, name_len, "path"))            target = SLATE_KIND_PANEL_R_PATH;
        else if (str_eq(name, name_len, "entries"))    target = SLATE_KIND_PANEL_R_ENTRIES;
        else if (str_eq(name, name_len, "cursor"))     target = SLATE_KIND_PANEL_R_CURSOR;
        else if (str_eq(name, name_len, "action"))     target = SLATE_KIND_PANEL_R_ACTION;
        else if (str_eq(name, name_len, "selection"))  target = SLATE_KIND_PANEL_R_SELECTION;
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

/* SLATE-4-confirm R120 P3-1: variant that encodes a dialog id into
 * the emitted dirent's qid (low 56 bits). Used for /dialogs/<id>/
 * children so a client storing the dirent qid as a cache key
 * matches the qid bound by Twalk to the same name. */
static stm_status emit_entry_with_id(slate_kind k, uint64_t did,
                                          readdir_emit *em)
{
    const slate_kind_meta *meta = &KIND_META[k];

    uint64_t this_cookie = ++em->pos;
    if (this_cookie <= em->offset) return STM_OK;

    stm_lp9_dirent e;
    memset(&e, 0, sizeof e);
    stm_lp9_attr a;
    stm_status rc = getattr_at(qid_of_dialog(k, did), &a);
    if (rc != STM_OK) return rc;
    e.qid     = a.qid;
    e.cookie  = this_cookie;
    e.dt_type = meta->is_dir ? 4u : 8u;
    size_t nl = strlen(meta->name);
    if (nl > STM_LP9_NAME_MAX) nl = STM_LP9_NAME_MAX;
    memcpy(e.name, meta->name, nl);
    e.name[nl] = '\0';
    e.name_len = (uint16_t)nl;
    return em->cb(&e, em->cb_ctx);
}

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
        rc = emit_entry(SLATE_KIND_PANELS_DIR, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_DIALOGS_DIR, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_EDITOR_DIR, &em);
    case SLATE_KIND_LOG_DIR:
        rc = emit_entry(SLATE_KIND_LOG_TAIL, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_LOG_APPEND, &em);
    case SLATE_KIND_CONN_DIR:
        rc = emit_entry(SLATE_KIND_CONN_SOCKET, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_CONN_CONNECTED, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_CONN_ATTACH, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_CONN_L_DIR, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_CONN_R_DIR, &em);
    case SLATE_KIND_CONN_L_DIR:
        rc = emit_entry(SLATE_KIND_CONN_L_SOCKET, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_CONN_L_CONNECTED, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_CONN_L_ATTACH, &em);
    case SLATE_KIND_CONN_R_DIR:
        rc = emit_entry(SLATE_KIND_CONN_R_SOCKET, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_CONN_R_CONNECTED, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_CONN_R_ATTACH, &em);
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
        rc = emit_entry(SLATE_KIND_PANEL_L_ACTION, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_PANEL_L_SELECTION, &em);
    case SLATE_KIND_PANEL_R_DIR:
        rc = emit_entry(SLATE_KIND_PANEL_R_PATH, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_PANEL_R_ENTRIES, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_PANEL_R_CURSOR, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_PANEL_R_ACTION, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_PANEL_R_SELECTION, &em);
    case SLATE_KIND_EDITOR_DIR:
        rc = emit_entry(SLATE_KIND_EDITOR_ACTIVE, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_EDITOR_FILENAME, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_EDITOR_CONTENT, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_EDITOR_CURSOR, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry(SLATE_KIND_EDITOR_MODIFIED, &em);
        if (rc != STM_OK) return rc;
        return emit_entry(SLATE_KIND_EDITOR_ACTION, &em);
    case SLATE_KIND_DIALOGS_DIR: {
        /* SLATE-4b: emit "stack" + one decimal-name dirent per
         * active dialog id, sorted ascending. Snapshot the id list
         * under mu so we don't hold mu across the emit callbacks
         * (callbacks may take other locks for buffering). */
        rc = emit_entry(SLATE_KIND_DIALOG_STACK, &em);
        if (rc != STM_OK) return rc;
        stm_slate *s = ctx;
        uint64_t ids[STM_SLATE_DIALOG_MAX_ACTIVE];
        size_t n;
        pthread_mutex_lock(&s->mu);
        n = dialog_collect_sorted_locked(s, ids);
        pthread_mutex_unlock(&s->mu);
        for (size_t i = 0; i < n; i++) {
            uint64_t this_cookie = ++em.pos;
            if (this_cookie <= em.offset) continue;
            stm_lp9_dirent e;
            memset(&e, 0, sizeof e);
            stm_lp9_attr a;
            rc = getattr_at(qid_of_dialog(SLATE_KIND_DIALOG_DIR, ids[i]), &a);
            if (rc != STM_OK) return rc;
            e.qid     = a.qid;
            e.cookie  = this_cookie;
            e.dt_type = 4u;  /* DT_DIR */
            int w = snprintf(e.name, sizeof e.name, "%llu",
                                (unsigned long long)ids[i]);
            if (w < 0) return STM_EBACKEND;
            if (w >= (int)sizeof e.name) w = (int)sizeof e.name - 1;
            e.name_len = (uint16_t)w;
            rc = em.cb(&e, em.cb_ctx);
            if (rc != STM_OK) return rc;
        }
        return STM_OK;
    }
    case SLATE_KIND_DIALOG_DIR: {
        /* SLATE-4b: dialog children. Re-check id freshness AND
         * emit /input ONLY for kind=INPUT slots. R120 P3-1: emit
         * dirents with id-bearing qids (kind | dialog_id) so
         * client-side qid caching matches what Twalk(name) would
         * bind. */
        uint64_t did = qid_dialog_id(dir_qid_path);
        stm_slate *s = ctx;
        pthread_mutex_lock(&s->mu);
        int slot = dialog_slot_for_id_locked(s, did);
        bool is_input_kind = (slot >= 0 &&
                              s->dialogs[slot].kind == SLATE_DIALOG_KIND_INPUT);
        pthread_mutex_unlock(&s->mu);
        if (slot < 0) return STM_ENOENT;
        rc = emit_entry_with_id(SLATE_KIND_DIALOG_KIND, did, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry_with_id(SLATE_KIND_DIALOG_TITLE, did, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry_with_id(SLATE_KIND_DIALOG_BODY, did, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry_with_id(SLATE_KIND_DIALOG_OPTIONS, did, &em);
        if (rc != STM_OK) return rc;
        rc = emit_entry_with_id(SLATE_KIND_DIALOG_RESULT, did, &em);
        if (rc != STM_OK) return rc;
        if (is_input_kind) {
            return emit_entry_with_id(SLATE_KIND_DIALOG_INPUT, did, &em);
        }
        return STM_OK;
    }
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
         * no body. R121 P3-6: for dynamic-id writable dialog kinds
         * (DIALOG_RESULT + DIALOG_INPUT), validate the dialog id is
         * STILL alive at lopen-time — symmetric with the read-capable
         * path's stale-id discipline. The race between walk and
         * lopen is small but real: walk binds the qid; concurrent
         * dismiss frees the slot; lopen would otherwise return
         * STM_OK on a stale fid and the failure mode would only
         * surface at vops_write. Defense-in-depth at the lopen
         * entry point closes the gap (CLAUDE.md slate row clause
         * 22(g)). DIALOG_INPUT additionally re-checks kind == INPUT. */
        if (k == SLATE_KIND_DIALOG_RESULT || k == SLATE_KIND_DIALOG_INPUT) {
            uint64_t did = qid_dialog_id(qid_path);
            int slot = dialog_slot_for_id_locked(s, did);
            bool ok = (slot >= 0);
            if (ok && k == SLATE_KIND_DIALOG_INPUT) {
                ok = (s->dialogs[slot].kind == SLATE_DIALOG_KIND_INPUT);
            }
            if (!ok) {
                session_free_locked(ss);
                pthread_mutex_unlock(&s->mu);
                return STM_ENOENT;
            }
        }
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
        rc = materialize_conn_socket_locked(s, ss, SLATE_PANEL_LEFT);
        break;
    case SLATE_KIND_CONN_CONNECTED:
        rc = materialize_conn_connected_locked(s, ss, SLATE_PANEL_LEFT);
        break;
    case SLATE_KIND_CONN_L_SOCKET:
        rc = materialize_conn_socket_locked(s, ss, SLATE_PANEL_LEFT);
        break;
    case SLATE_KIND_CONN_L_CONNECTED:
        rc = materialize_conn_connected_locked(s, ss, SLATE_PANEL_LEFT);
        break;
    case SLATE_KIND_CONN_R_SOCKET:
        rc = materialize_conn_socket_locked(s, ss, SLATE_PANEL_RIGHT);
        break;
    case SLATE_KIND_CONN_R_CONNECTED:
        rc = materialize_conn_connected_locked(s, ss, SLATE_PANEL_RIGHT);
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
    case SLATE_KIND_PANEL_L_SELECTION:
        rc = materialize_panel_selection_locked(s, ss, SLATE_PANEL_LEFT);
        break;
    case SLATE_KIND_PANEL_R_SELECTION:
        rc = materialize_panel_selection_locked(s, ss, SLATE_PANEL_RIGHT);
        break;
    case SLATE_KIND_DIALOG_STACK:
        rc = materialize_dialog_stack_locked(s, ss);
        break;
    case SLATE_KIND_EDITOR_ACTIVE:
        rc = materialize_editor_active_locked(s, ss);
        break;
    case SLATE_KIND_EDITOR_FILENAME:
        rc = materialize_editor_filename_locked(s, ss);
        break;
    case SLATE_KIND_EDITOR_CONTENT:
        rc = materialize_editor_content_locked(s, ss);
        break;
    case SLATE_KIND_EDITOR_CURSOR:
        rc = materialize_editor_cursor_locked(s, ss);
        break;
    case SLATE_KIND_EDITOR_MODIFIED:
        rc = materialize_editor_modified_locked(s, ss);
        break;
    case SLATE_KIND_DIALOG_KIND:
    case SLATE_KIND_DIALOG_TITLE:
    case SLATE_KIND_DIALOG_BODY:
    case SLATE_KIND_DIALOG_OPTIONS:
    case SLATE_KIND_DIALOG_INPUT: {
        /* SLATE-4b: verify the qid's dialog id matches an active
         * slot before materialising. R29 P3-1 stale-id-as-ENOENT
         * discipline. For INPUT kind: also gate on slot.kind ==
         * INPUT (confirm-kind dialogs do NOT expose /input). */
        uint64_t did = qid_dialog_id(qid_path);
        int slot = dialog_slot_for_id_locked(s, did);
        if (slot < 0) { rc = STM_ENOENT; break; }
        slate_dialog *d = &s->dialogs[slot];
        if (k == SLATE_KIND_DIALOG_INPUT &&
            d->kind != SLATE_DIALOG_KIND_INPUT) {
            rc = STM_ENOENT;
            break;
        }
        if (k == SLATE_KIND_DIALOG_KIND)         rc = materialize_dialog_kind_locked(d, ss);
        else if (k == SLATE_KIND_DIALOG_TITLE)   rc = materialize_dialog_title_locked(d, ss);
        else if (k == SLATE_KIND_DIALOG_BODY)    rc = materialize_dialog_body_locked(d, ss);
        else if (k == SLATE_KIND_DIALOG_OPTIONS) rc = materialize_dialog_options_locked(d, ss);
        else                                     rc = materialize_dialog_input_locked(d, ss);
        break;
    }
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
    if (k == SLATE_KIND_CONN_ATTACH ||
        k == SLATE_KIND_CONN_L_ATTACH ||
        k == SLATE_KIND_CONN_R_ATTACH) {
        /* SLATE-2 + SLATE-4a: write a stratumd socket path to dial;
         * empty body disconnects. The top-level /connection/attach
         * routes to panel 0 (LEFT) for back-compat; the per-panel
         * /connection/{left,right}/attach surfaces are the canonical
         * SLATE-4a forms. R101 P2-2 carry: zero-byte writes ARE
         * accepted on attach (documented disconnect verb). */
        if (len > STM_SLATE_SOCKET_MAX) return STM_EINVAL;
        size_t l = len;
        if (l > 0 && ((const char *)buf)[l - 1] == '\n') l--;
        int target_panel = (k == SLATE_KIND_CONN_R_ATTACH)
                              ? SLATE_PANEL_RIGHT : SLATE_PANEL_LEFT;
        stm_status rc;
        if (l == 0) {
            rc = stm_slate_disconnect_panel(s, target_panel);
        } else {
            rc = stm_slate_attach_panel(s, target_panel,
                                            (const char *)buf, l);
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
    if (k == SLATE_KIND_PANEL_L_SELECTION || k == SLATE_KIND_PANEL_R_SELECTION) {
        /* SLATE-3c-selection: write a comma-separated index list to
         * /panels/X/selection. Empty body (or "\n" alone) clears the
         * selection. Worst-case input is ~1000 bytes (200 indices ×
         * up to 3 digits + commas + newline); STM_SLATE_BODY_MAX
         * (4 KiB) is plenty. */
        if (len > STM_SLATE_BODY_MAX) return STM_EINVAL;
        uint8_t parsed[SLATE_SELECTION_BYTES];
        stm_status rc = parse_selection_bits((const char *)buf, len, parsed);
        if (rc != STM_OK) return rc;
        int panel_idx = (k == SLATE_KIND_PANEL_L_SELECTION)
                            ? SLATE_PANEL_LEFT : SLATE_PANEL_RIGHT;
        pthread_mutex_lock(&s->mu);
        /* R116 P3-2 doctrine: bump version only on real change. */
        bool changed = (memcmp(s->panel[panel_idx].selection, parsed,
                                  sizeof parsed) != 0);
        if (changed) {
            memcpy(s->panel[panel_idx].selection, parsed, sizeof parsed);
            s->version++;
            pthread_cond_broadcast(&s->cv);
        }
        pthread_mutex_unlock(&s->mu);
        *out_written = len;
        return STM_OK;
    }
    if (k == SLATE_KIND_DIALOG_RESULT) {
        /* SLATE-4b: write a result label to dismiss the dialog.
         * Body must equal one of the comma-separated tokens in
         * dialog.options. R101 P2-2 carry: zero-byte refused.
         * DialogStackLIFO: only the top-of-stack dialog accepts
         * results — others return STM_EBUSY. */
        if (len == 0u) return STM_EINVAL;
        if (len > STM_SLATE_DIALOG_OPTION_MAX) return STM_EINVAL;
        size_t l = len;
        if (l > 0u && ((const char *)buf)[l - 1u] == '\n') l--;
        if (l == 0u) return STM_EINVAL;
        /* Validate result has no control bytes. */
        if (validate_dialog_string((const char *)buf, l, false) != STM_OK)
            return STM_EINVAL;
        uint64_t did = qid_dialog_id(qid_path);
        pthread_mutex_lock(&s->mu);
        /* R121 P3-5: combined slot-lookup + top-id scan (single
         * pass over the slot array). With STM_SLATE_DIALOG_MAX_ACTIVE
         * = 4 the savings are trivial; the consolidated form is
         * forward-looking. */
        uint64_t top = 0u;
        int slot = dialog_lookup_and_top_locked(s, did, &top);
        if (slot < 0) {
            /* Stale id — dialog was already dismissed or never existed. */
            pthread_mutex_unlock(&s->mu);
            return STM_ENOENT;
        }
        /* DialogStackLIFO (SLATE-DESIGN §11): only the top-of-stack
         * dialog (highest active id) accepts result writes. Earlier
         * dialogs are visible (read-side) but result-write returns
         * STM_EBUSY — renderers must dismiss the topmost first. */
        if (top != did) {
            pthread_mutex_unlock(&s->mu);
            return STM_EBUSY;
        }
        slate_dialog *d = &s->dialogs[slot];
        stm_status vrc = validate_dialog_result(d->options, d->options_len,
                                                       (const char *)buf, l);
        if (vrc != STM_OK) {
            /* R120 P3-4: no version bump on validation failure
             * (R116 P3-2 doctrine — version changes only on real
             * state mutation). */
            pthread_mutex_unlock(&s->mu);
            return vrc;
        }
        /* SLATE-4b: snapshot result + input into last_dismiss
         * record so the consumer can retrieve via
         * stm_slate_dialog_consume(). Single-record limitation
         * (rapid back-to-back dismisses overwrite); documented at
         * SLATE-4b in slate.h. */
        s->last_dismiss.id = did;
        s->last_dismiss.kind = d->kind;
        memcpy(s->last_dismiss.result, buf, l);
        s->last_dismiss.result[l] = '\0';
        s->last_dismiss.result_len = l;
        memcpy(s->last_dismiss.input, d->input, d->input_len);
        s->last_dismiss.input[d->input_len] = '\0';
        s->last_dismiss.input_len = d->input_len;
        /* Free the slot. id stays bumped via next_dialog_id, so a
         * future dialog gets a fresh id. */
        memset(d, 0, sizeof *d);
        s->version++;
        pthread_cond_broadcast(&s->cv);
        pthread_mutex_unlock(&s->mu);
        *out_written = len;
        return STM_OK;
    }
    if (k == SLATE_KIND_DIALOG_INPUT) {
        /* SLATE-4b: write the editable input string. RW kind —
         * mode 0644. R101 P2-2 carry: zero-byte refused (clients
         * setting empty input MUST programmatically reset via
         * open_input rather than write empty). Strip trailing
         * '\n' if present (matches confirm/result convention). */
        if (len == 0u) return STM_EINVAL;
        if (len > STM_SLATE_DIALOG_INPUT_MAX + 1u) return STM_EINVAL;
        size_t l = len;
        if (l > 0u && ((const char *)buf)[l - 1u] == '\n') l--;
        if (l > STM_SLATE_DIALOG_INPUT_MAX) return STM_EINVAL;
        /* Empty post-strip is allowed (clearing the field via "\n"). */
        if (l > 0u &&
            validate_dialog_string((const char *)buf, l, false) != STM_OK)
            return STM_EINVAL;
        uint64_t did = qid_dialog_id(qid_path);
        pthread_mutex_lock(&s->mu);
        int slot = dialog_slot_for_id_locked(s, did);
        if (slot < 0) {
            pthread_mutex_unlock(&s->mu);
            return STM_ENOENT;
        }
        slate_dialog *d = &s->dialogs[slot];
        if (d->kind != SLATE_DIALOG_KIND_INPUT) {
            /* /input only valid for input-kind dialogs. The walk
             * gate already filters this out for renderers, but if
             * a malicious client constructs the qid directly we
             * still refuse here (defense-in-depth). */
            pthread_mutex_unlock(&s->mu);
            return STM_ENOENT;
        }
        /* R116 P3-2 doctrine: bump version only on real change. */
        bool changed = (l != d->input_len) ||
                       (l > 0u && memcmp(d->input, buf, l) != 0);
        if (changed) {
            if (l > 0u) memcpy(d->input, buf, l);
            d->input[l] = '\0';
            d->input_len = l;
            s->version++;
            pthread_cond_broadcast(&s->cv);
        }
        pthread_mutex_unlock(&s->mu);
        *out_written = len;
        return STM_OK;
    }
    if (k == SLATE_KIND_EDITOR_CONTENT) {
        /* SLATE-5b: write replaces the editor buffer entirely
         * (clause 19 offset-ignored Twrite posture — every write
         * is a complete payload). Bound at MAX. R101 P2-2 carry:
         * zero-byte refused (clearing the buffer requires explicit
         * "1\n" or other body — write of an empty file is via the
         * caller's own choice; if they want empty, they should
         * close + re-open or use action="revert" instead). */
        if (len == 0u) return STM_EINVAL;
        if (len > STM_SLATE_EDITOR_CONTENT_MAX) return STM_ERANGE;
        /* No control-byte filter — files contain arbitrary bytes;
         * the editor IS a text-editing UI. Sanitization happens
         * at the renderer (CLAUDE.md slate row clause 23(g)). */
        uint8_t *new_buf = malloc(len);
        if (!new_buf) return STM_ENOMEM;
        memcpy(new_buf, buf, len);
        pthread_mutex_lock(&s->mu);
        if (!s->editor_active) {
            pthread_mutex_unlock(&s->mu);
            free(new_buf);
            return STM_ENOENT;
        }
        /* R116 P3-2: bump version only on real change. The whole-
         * payload-replace model means "new content == current
         * content" is the no-change case. */
        bool changed = (len != s->editor_content_len) ||
                       (len > 0u && memcmp(new_buf, s->editor_content,
                                              len) != 0);
        if (changed) {
            free(s->editor_content);
            s->editor_content = new_buf;
            s->editor_content_len = len;
            editor_recompute_modified_locked(s);
            s->version++;
            pthread_cond_broadcast(&s->cv);
        } else {
            free(new_buf);
        }
        pthread_mutex_unlock(&s->mu);
        *out_written = (uint32_t)len;
        return STM_OK;
    }
    if (k == SLATE_KIND_EDITOR_CURSOR) {
        /* SLATE-5b: write parses "row,col" — both are decimal
         * uint32_t. Trailing newline OK; empty body refused
         * (R101 P2-2 carry); no leading sign or whitespace.
         *
         * R124 P3-6: cursor is NOT validated against current
         * content bounds. Renderers handle bounds. This is
         * intentional: cursor is a free-form marker (a renderer
         * may use it as a logical scrollback position, a
         * "remember where I was" anchor, etc), not a content-
         * anchored offset. The renderer's display logic decides
         * what to do with cursors that fall past EOF / past the
         * last column of the row's actual content. */
        if (len == 0u) return STM_EINVAL;
        /* R124 P3-2: tight upper bound — "4294967295,4294967295\n" = 22 bytes;
         * any longer body is either malformed (extra leading zeros, garbage)
         * or an integer overflow precursor. Tightening rejects a class of
         * leading-zero-prefixed inputs without changing valid input space. */
        if (len > 22u) return STM_EINVAL;
        const char *p = (const char *)buf;
        size_t l = len;
        if (l > 0u && p[l - 1u] == '\n') l--;
        if (l == 0u) return STM_EINVAL;
        /* Find ','. */
        size_t comma = SIZE_MAX;
        for (size_t i = 0; i < l; i++) {
            if (p[i] == ',') { comma = i; break; }
        }
        if (comma == SIZE_MAX || comma == 0u || comma == l - 1u) {
            return STM_EINVAL;
        }
        uint32_t row = 0, col = 0;
        /* R124 P3-1: digit-aware overflow check accepts values up to
         * exactly UINT32_MAX. The previous gate `row > (UMAX-9)/10`
         * rejected 4294967290..4294967295 which are valid uint32. */
        for (size_t i = 0; i < comma; i++) {
            char c = p[i];
            if (c < '0' || c > '9') return STM_EINVAL;
            uint32_t digit = (uint32_t)(c - '0');
            if (row > UINT32_MAX / 10u ||
                (row == UINT32_MAX / 10u && digit > UINT32_MAX % 10u)) {
                return STM_EINVAL;
            }
            row = row * 10u + digit;
        }
        for (size_t i = comma + 1u; i < l; i++) {
            char c = p[i];
            if (c < '0' || c > '9') return STM_EINVAL;
            uint32_t digit = (uint32_t)(c - '0');
            if (col > UINT32_MAX / 10u ||
                (col == UINT32_MAX / 10u && digit > UINT32_MAX % 10u)) {
                return STM_EINVAL;
            }
            col = col * 10u + digit;
        }
        pthread_mutex_lock(&s->mu);
        if (!s->editor_active) {
            pthread_mutex_unlock(&s->mu);
            return STM_ENOENT;
        }
        /* R116 P3-2: bump only on real change. */
        if (row != s->editor_cursor_row || col != s->editor_cursor_col) {
            s->editor_cursor_row = row;
            s->editor_cursor_col = col;
            s->version++;
            pthread_cond_broadcast(&s->cv);
        }
        pthread_mutex_unlock(&s->mu);
        *out_written = (uint32_t)len;
        return STM_OK;
    }
    if (k == SLATE_KIND_EDITOR_ACTION) {
        /* SLATE-5b: editor action verbs save / quit / revert /
         * save-and-quit. R101 P2-2 carry: zero-byte refused. */
        if (len == 0u) return STM_EINVAL;
        if (len > STM_SLATE_EVENT_LINE_MAX) return STM_EINVAL;
        const char *p = (const char *)buf;
        size_t l = len;
        if (l > 0u && p[l - 1u] == '\n') l--;
        if (l == 0u) return STM_EINVAL;
        stm_status arc;
        if (l == 4u && memcmp(p, "save", 4u) == 0) {
            arc = stm_slate_editor_save(s);
        } else if (l == 4u && memcmp(p, "quit", 4u) == 0) {
            arc = stm_slate_editor_close(s);
        } else if (l == 6u && memcmp(p, "revert", 6u) == 0) {
            arc = stm_slate_editor_revert(s);
        } else if (l == 13u && memcmp(p, "save-and-quit", 13u) == 0) {
            arc = stm_slate_editor_save(s);
            if (arc == STM_OK) arc = stm_slate_editor_close(s);
        } else {
            return STM_ENOTSUPPORTED;
        }
        if (arc != STM_OK) return arc;
        *out_written = (uint32_t)len;
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
