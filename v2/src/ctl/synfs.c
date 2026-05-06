/* SPDX-License-Identifier: ISC */
/*
 * stm_ctl synfs — operational synthetic filesystem (ARCH §14.3).
 *
 * Phase 9 P9-CTL-1a foundation + P9-CTL-1b /pools/ subtree +
 * P9-CTL-1c /datasets/ + P9-CTL-1d-uid admin gate + P9-CTL-1d-events
 * /events log + P9-CTL-1d-debug-alloc /debug/allocator-state/:
 *
 *   /                                       directory (ro, world-readable)
 *   /version                                read: build identity + format versions
 *   /state                                  read: attached-fs state (or placeholder)
 *   /pools/                                 directory: registered pool(s)
 *   /pools/<uuid>/                          directory: per-pool entries
 *   /pools/<uuid>/status                    read: pool roster summary
 *   /pools/<uuid>/devices/                  directory: roster (incl REMOVED)
 *   /pools/<uuid>/devices/<id>/             directory: per-device
 *   /pools/<uuid>/devices/<id>/status       read: device-level state
 *   /datasets/                              directory: registered datasets
 *   /datasets/<id>/                         directory: per-dataset
 *   /datasets/<id>/properties               read: combined entry+effective props
 *   /datasets/<id>/create-snapshot          write: snapshot name (admin)
 *   /datasets/<id>/delete-snapshot          write: snapshot id (admin)
 *   /datasets/<id>/hold-snapshot            write: snapshot id (admin)
 *   /datasets/<id>/release-snapshot         write: snapshot id (admin)
 *   /admin/                                 directory: admin-only (mode 0500)
 *   /admin/peer                             read: caller uid/gid+is-admin (admin)
 *   /admin/clear-events                     write: reset /events log (admin)
 *   /events                                 read: append-only event log (world)
 *   /pools/<uuid>/scrub                     read: scrub state+counters (world)
 *   /pools/<uuid>/scrub-trigger             write: action verb (admin)
 *   /debug/                                 directory: admin-only diagnostics
 *   /debug/allocator-state/                 directory: per-device allocator state
 *   /debug/allocator-state/<device_id>      read: allocator stats (admin)
 *
 * Subsequent /debug/ sub-chunks add tree-walk, extent-map,
 * integrity-verify (admin-write triggers + admin-read dump files);
 * /tracing/, action triggers (snapshot create, scrub start), and
 * /metrics/ (Prometheus + OTLP) follow.
 *
 * qid_path encoding
 * ─────────────────
 * The generic stm_lp9_server passes our qid_path back to us on every
 * walk/getattr/read; the layout encodes:
 *
 *   bits 56-63   kind          (8 bits — index into KIND_META)
 *   bits 32-55   pool_idx      (24 bits — currently always 0; one pool max)
 *   bits  0-31   device_id     (32 bits — 0 unless kind names a device)
 *
 * Keeping the kind in the high byte mirrors janus/synfs.c so a reader
 * of one understands the other. The lower 56 bits are sub-chunk
 * extension space; -1c (datasets) will use part of them, -1d (debug)
 * may reuse them per its own kind, etc.
 *
 * Kind-table discipline (R96 P3-6)
 * ────────────────────────────────
 * The KIND_META[] array is the single source of truth for
 * (kind → static_name + is_dir + mode). Every code path that needs
 * to format a directory entry or check "is this a dir?" goes through
 * the table. Adding a new kind requires:
 *   1. Append to the `ctl_kind` enum (before KIND_MAX).
 *   2. Append a row to KIND_META[].
 *   3. Wire walk/readdir/materialize switches.
 *   4. Add a _Static_assert pinning the literal name length.
 * Forgetting (2) trips a clang -Wmissing-field-initializers; (4)
 * trips at build time if the name overflows STM_LP9_NAME_MAX.
 *
 * Concurrency
 * ───────────
 * The hard rule:
 *   - Safe to share one stm_ctl across SEQUENTIAL stm_lp9_server use
 *     (one server at a time — v2.0 stratumd serial accept).
 *   - NOT safe to share one stm_ctl across CONCURRENT stm_lp9_server
 *     instances. The future concurrent-accept transport upgrade
 *     (R95 forward-note) MUST either give each server its own
 *     stm_ctl, or extend sessions[]'s key from `fid` to
 *     `(server_idx, fid)` — the same posture src/9p/server.c took
 *     at P9-9P-1 (`lock_owner = (server_idx << 32) | fid`).
 *
 * Why the mutex isn't enough
 * ──────────────────────────
 * The instance mutex (`mu`) protects byte-level access to
 * `sessions[]` — within ONE server's vops calls, the mutex
 * serializes alloc/lookup/free. But the mutex does NOT protect
 * against fid-namespace collisions: two concurrent servers each
 * running `vops_lopen(fid=1)` would race in sessions[] and the
 * mutex doesn't know which server's fid 1 to associate with which
 * slot. So the mutex is defense-in-depth WITHIN a single server's
 * timeline (where the generic stm_lp9_server is itself single-
 * threaded per connection — Tflush is a server-level no-op so
 * cannot interrupt a vops call); it is NOT cross-server safety.
 *
 * Read paths against subsystem state (`stm_fs *`, `stm_pool *`)
 * call into those subsystems' own thread-safe accessors
 * (`stm_fs_stats_get`, `stm_pool_lock_shared` etc.). Body
 * materialization snapshots state at Tlopen so subsequent Treads
 * see a consistent view; concurrent fs/pool mutations after Tlopen
 * are reflected on the next Tlopen.
 */

#include <stratum/crypto.h>         /* stm_ct_memzero (R101 P3-1) */
#include <stratum/ctl.h>
#include <stratum/dataset.h>        /* stm_property + stm_dataset_entry */
#include <stratum/fs.h>
#include <stratum/lp9.h>
#include <stratum/pool.h>
#include <stratum/scrub.h>          /* stm_scrub_state, stm_scrub_status */
#include <stratum/snapshot.h>       /* STM_SNAP_NAME_MAX */
#include <stratum/send_recv.h>      /* STM_SEND_VERSION */
#include <stratum/super.h>          /* STM_UB_VERSION + STM_DEV_*_ values */
#include <stratum/sync.h>           /* STM_SYNC_DATASET_ID_MAX */
#include <stratum/types.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>      /* uid_t, gid_t */
#include <time.h>           /* clock_gettime */

/* ── kind enum + meta table ─────────────────────────────────────────── */

typedef enum {
    KIND_ROOT                 = 0,
    KIND_VERSION              = 1,
    KIND_STATE                = 2,
    KIND_POOLS_DIR            = 3,    /* /pools/ */
    KIND_POOL_DIR             = 4,    /* /pools/<uuid>/ */
    KIND_POOL_STATUS          = 5,    /* /pools/<uuid>/status */
    KIND_DEVICES_DIR          = 6,    /* /pools/<uuid>/devices/ */
    KIND_DEVICE_DIR           = 7,    /* /pools/<uuid>/devices/<id>/ */
    KIND_DEVICE_STATUS        = 8,    /* /pools/<uuid>/devices/<id>/status */
    KIND_DATASETS_DIR         = 9,    /* /datasets/ */
    KIND_DATASET_DIR          = 10,   /* /datasets/<id>/ */
    KIND_DATASET_PROPERTIES   = 11,   /* /datasets/<id>/properties */
    KIND_ADMIN_DIR            = 12,   /* /admin/ — admin-only directory */
    KIND_ADMIN_PEER           = 13,   /* /admin/peer — admin-only file */
    KIND_EVENTS               = 14,   /* /events — append-only event log */
    KIND_ADMIN_CLEAR_EVENTS   = 15,   /* /admin/clear-events — admin write trigger */
    KIND_DEBUG_DIR            = 16,   /* /debug/ — admin-only diagnostic dir */
    KIND_DEBUG_ALLOC_DIR      = 17,   /* /debug/allocator-state/ — per-device alloc */
    KIND_DEBUG_ALLOC          = 18,   /* /debug/allocator-state/<id> — admin-only file */
    KIND_POOL_SCRUB           = 19,   /* /pools/<uuid>/scrub — read state+counters */
    KIND_POOL_SCRUB_TRIGGER   = 20,   /* /pools/<uuid>/scrub-trigger — admin write */
    KIND_DATASET_CREATE_SNAPSHOT = 21, /* /datasets/<id>/create-snapshot — admin write */
    KIND_DATASET_DELETE_SNAPSHOT = 22, /* /datasets/<id>/delete-snapshot — admin write */
    KIND_DATASET_HOLD_SNAPSHOT   = 23, /* /datasets/<id>/hold-snapshot — admin write */
    KIND_DATASET_RELEASE_SNAPSHOT = 24, /* /datasets/<id>/release-snapshot — admin write */
    KIND_POOL_METRICS_DIR        = 25, /* /pools/<uuid>/metrics/ — observability subtree */
    KIND_POOL_METRICS_PROMETHEUS = 26, /* /pools/<uuid>/metrics/prometheus — bulk exposition */
    KIND_MAX
} ctl_kind;

typedef struct {
    bool         is_dir;
    bool         admin_required; /* P9-CTL-1d-uid: admin-only access */
    uint32_t     mode;          /* posix permission bits only;
                                 * file-type bits (S_IFDIR / S_IFREG)
                                 * are added by getattr_at based on is_dir */
    const char  *static_name;   /* NULL when name is dynamic (e.g. UUID) */
} ctl_kind_meta;

static const ctl_kind_meta KIND_META[KIND_MAX] = {
    [KIND_ROOT]               = { true,  false, 0555, "/"          },
    [KIND_VERSION]            = { false, false, 0444, "version"    },
    [KIND_STATE]              = { false, false, 0444, "state"      },
    [KIND_POOLS_DIR]          = { true,  false, 0555, "pools"      },
    [KIND_POOL_DIR]           = { true,  false, 0555, NULL         },  /* dynamic uuid */
    [KIND_POOL_STATUS]        = { false, false, 0444, "status"     },
    [KIND_DEVICES_DIR]        = { true,  false, 0555, "devices"    },
    [KIND_DEVICE_DIR]         = { true,  false, 0555, NULL         },  /* dynamic device id */
    [KIND_DEVICE_STATUS]      = { false, false, 0444, "status"     },
    [KIND_DATASETS_DIR]       = { true,  false, 0555, "datasets"   },
    [KIND_DATASET_DIR]        = { true,  false, 0555, NULL         },  /* dynamic dataset id */
    [KIND_DATASET_PROPERTIES] = { false, false, 0444, "properties" },
    [KIND_ADMIN_DIR]          = { true,  true,  0500, "admin"      },  /* admin-only dir */
    [KIND_ADMIN_PEER]         = { false, true,  0400, "peer"       },  /* admin-only file */
    [KIND_EVENTS]             = { false, false, 0444, "events"     },  /* world-readable log */
    [KIND_ADMIN_CLEAR_EVENTS] = { false, true,  0200, "clear-events" }, /* admin write-only */
    [KIND_DEBUG_DIR]          = { true,  true,  0500, "debug"           }, /* admin-only dir */
    [KIND_DEBUG_ALLOC_DIR]    = { true,  true,  0500, "allocator-state" }, /* admin-only dir */
    [KIND_DEBUG_ALLOC]        = { false, true,  0400, NULL              }, /* admin-only, dynamic device id */
    [KIND_POOL_SCRUB]         = { false, false, 0444, "scrub"           }, /* world-readable scrub state */
    [KIND_POOL_SCRUB_TRIGGER] = { false, true,  0200, "scrub-trigger"   }, /* admin write trigger */
    [KIND_DATASET_CREATE_SNAPSHOT] = { false, true, 0200, "create-snapshot" }, /* admin write trigger */
    [KIND_DATASET_DELETE_SNAPSHOT] = { false, true, 0200, "delete-snapshot" }, /* admin write trigger */
    [KIND_DATASET_HOLD_SNAPSHOT]   = { false, true, 0200, "hold-snapshot"   }, /* admin write trigger */
    [KIND_DATASET_RELEASE_SNAPSHOT] = { false, true, 0200, "release-snapshot" }, /* admin write trigger */
    [KIND_POOL_METRICS_DIR]        = { true,  false, 0555, "metrics"    }, /* world-readable observability dir */
    [KIND_POOL_METRICS_PROMETHEUS] = { false, false, 0444, "prometheus" }, /* world-readable bulk exposition */
};

/* R96 P3-2: pin every static-name literal length below STM_LP9_NAME_MAX
 * (63) at build time. Update both this assert block and KIND_META in
 * lockstep when adding new static-named kinds. (Dynamic names like
 * uuid hex (36 chars) and decimal device id (≤5 digits for 64 slots)
 * are also < 63 — that's a runtime bound check in the dynamic
 * decoder.) */
_Static_assert(sizeof("/") - 1        <= STM_LP9_NAME_MAX, "/ctl/ root literal");
_Static_assert(sizeof("version") - 1  <= STM_LP9_NAME_MAX, "/ctl/ /version literal");
_Static_assert(sizeof("state") - 1    <= STM_LP9_NAME_MAX, "/ctl/ /state literal");
_Static_assert(sizeof("pools") - 1    <= STM_LP9_NAME_MAX, "/ctl/ /pools literal");
_Static_assert(sizeof("status") - 1   <= STM_LP9_NAME_MAX, "/ctl/ /pools/.../status literal");
_Static_assert(sizeof("devices") - 1   <= STM_LP9_NAME_MAX, "/ctl/ /pools/.../devices literal");
_Static_assert(sizeof("datasets") - 1  <= STM_LP9_NAME_MAX, "/ctl/ /datasets literal");
_Static_assert(sizeof("properties") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /datasets/.../properties literal");
_Static_assert(sizeof("admin") - 1     <= STM_LP9_NAME_MAX, "/ctl/ /admin literal");
_Static_assert(sizeof("peer") - 1      <= STM_LP9_NAME_MAX, "/ctl/ /admin/peer literal");
_Static_assert(sizeof("events") - 1    <= STM_LP9_NAME_MAX, "/ctl/ /events literal");
_Static_assert(sizeof("clear-events") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /admin/clear-events literal");
_Static_assert(sizeof("debug") - 1     <= STM_LP9_NAME_MAX, "/ctl/ /debug literal");
_Static_assert(sizeof("allocator-state") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /debug/allocator-state literal");
/* The "scrub" literal is shared with KIND_POOL_STATUS's "status" — both
 * are 5-7 chars under STM_LP9_NAME_MAX. */
_Static_assert(sizeof("scrub") - 1     <= STM_LP9_NAME_MAX, "/ctl/ /pools/.../scrub literal");
_Static_assert(sizeof("scrub-trigger") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /pools/.../scrub-trigger literal");
_Static_assert(sizeof("create-snapshot") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /datasets/.../create-snapshot literal");
_Static_assert(sizeof("delete-snapshot") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /datasets/.../delete-snapshot literal");
_Static_assert(sizeof("hold-snapshot") - 1   <= STM_LP9_NAME_MAX, "/ctl/ /datasets/.../hold-snapshot literal");
_Static_assert(sizeof("release-snapshot") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /datasets/.../release-snapshot literal");
_Static_assert(sizeof("metrics") - 1    <= STM_LP9_NAME_MAX, "/ctl/ /pools/.../metrics literal");
_Static_assert(sizeof("prometheus") - 1 <= STM_LP9_NAME_MAX, "/ctl/ /pools/.../metrics/prometheus literal");
/* Dynamic names: pool-uuid hex (36 chars), decimal device-id (≤2
 * chars at v2.0's STM_POOL_DEVICES_MAX = 64 cap), decimal dataset-id
 * (≤9 chars at STM_SYNC_DATASET_ID_MAX = 0x0FFFFFFF ~= 268M = 9
 * digits). KIND_DEBUG_ALLOC reuses the same decimal device-id parser.
 * All bounded at runtime in the dynamic decoders. */

/* R97 P3-7: pin KIND_MAX so adding a new ctl_kind without extending
 * KIND_META[] trips this assert at build time, even if a downstream
 * build silently suppresses -Wmissing-field-initializers. Update the
 * literal in lockstep when growing the enum. */
_Static_assert(KIND_MAX == 27,
               "KIND_META[KIND_MAX] sized to enum cardinality; "
               "update both ctl_kind enum + KIND_META[] in lockstep");

/* ── qid_path encoding ──────────────────────────────────────────────── */

#define POOL_IDX_MASK    0x00FFFFFFu
#define DEVICE_ID_MASK   0xFFFFFFFFu

static uint64_t qid_of(ctl_kind kind, uint32_t pool_idx, uint32_t device_id)
{
    return ((uint64_t)(uint8_t)kind << 56)
         | ((uint64_t)(pool_idx & POOL_IDX_MASK) << 32)
         | (uint64_t)(device_id & DEVICE_ID_MASK);
}

static uint64_t qid_root(ctl_kind kind)
{
    return qid_of(kind, 0, 0);
}

static ctl_kind qid_kind(uint64_t q)
{
    uint8_t k = (uint8_t)(q >> 56);
    return (k < KIND_MAX) ? (ctl_kind)k : KIND_MAX;
}

static uint32_t qid_pool_idx(uint64_t q)
{
    return (uint32_t)((q >> 32) & POOL_IDX_MASK);
}

static uint32_t qid_device_id(uint64_t q)
{
    return (uint32_t)(q & DEVICE_ID_MASK);
}

/* Alias for the same low-32-bits slot but typed as uint64_t for the
 * dataset surface; STM_SYNC_DATASET_ID_MAX = 0x0FFFFFFF (28 bits)
 * fits comfortably in the 32-bit field. Kept as a separate name
 * so the reader of getattr_at / vops_walk can tell which kind's
 * data they're extracting.
 *
 * R99 P3-7: pin the format-bump invariant — if STM_SYNC_DATASET_ID_MAX
 * ever exceeds UINT32_MAX, the (uint32_t)dsid casts in qid_of() calls
 * silently truncate the high bits; a confused-deputy follows. The
 * static_assert below trips at build time so the format-widening
 * chunk MUST also widen qid_of's device_id field (or split it). */
_Static_assert(STM_SYNC_DATASET_ID_MAX <= UINT32_MAX,
               "qid_of's device_id field is uint32_t; widening "
               "STM_SYNC_DATASET_ID_MAX past UINT32_MAX requires "
               "widening the qid layout in lockstep");

static uint64_t qid_dataset_id(uint64_t q)
{
    return q & DEVICE_ID_MASK;
}

/* ── per-fid materialized body ──────────────────────────────────────── */

/*
 * /version, /state, /pools/<uuid>/status read as text — we
 * materialize the entire body once per Tlopen so subsequent Treads
 * at varying offsets see a consistent snapshot. For unattached
 * or post-attach state changes, the body is regenerated on the
 * next Tlopen.
 *
 * STM_CTL_BODY_MAX is the per-fid scratch budget. Each kind that
 * gets opened must materialize within this cap; the materializers
 * snprintf-then-check and refuse with STM_ERANGE on overflow.
 * Today's kinds (/version ~80 bytes, /state ~352 bytes worst case
 * with all-UINT64_MAX counters, /pools/<uuid>/status ~256 bytes
 * with full 64-device roster summary, /datasets/<id>/properties
 * ~615 bytes with all-max counters + 255-byte name, /debug/
 * allocator-state/<n> ~650 bytes with all-UINT64_MAX counters)
 * sit comfortably under 1 KiB.
 * Future sub-chunks may need to bump or per-kind-cap; do so in
 * lockstep with adding the new kind, and document the per-kind
 * justification (R96 P3-3).
 */
#define STM_CTL_BODY_MAX     1024u
#define STM_CTL_MAX_SESSIONS 64u

/* Cap on action-verb body length for write triggers
 * (KIND_POOL_SCRUB_TRIGGER and any future writable kind that takes
 * a verb). The longest legitimate verb today is "resume" at 6 chars;
 * 16 leaves headroom for "integrity-check" / "bg-rescan" without
 * ever letting a malicious 1 GiB body cause an unbounded memcmp.
 * R104 P3-4 lifted this from a hard-coded 16 to a #define for
 * searchability + ease of re-tuning. */
#define STM_CTL_VERB_MAX     16u

/* P9-CTL-1e: per-fid heap-allocated body cap for bulk-format kinds.
 * /pools/<uuid>/metrics/prometheus emits HELP+TYPE comments + per-
 * device records + scrub counters, which on a 64-device pool sums
 * to ~30 KiB; 64 KiB leaves headroom for forward additions
 * (per-dataset counters, latency histograms when added). Refuses
 * with STM_ERANGE if a single materialization would exceed the cap
 * — protects against runaway label-cardinality bugs.
 *
 * Enforced via prom_grow's bound check; the realloc-doubling growth
 * starts at STM_CTL_METRICS_INITIAL_CAP and doubles up to this cap. */
#define STM_CTL_METRICS_MAX           (64u * 1024u)
#define STM_CTL_METRICS_INITIAL_CAP   4096u

typedef struct ctl_session {
    int       active;
    uint32_t  fid;
    uint64_t  qid_path;
    uint8_t   buf[STM_CTL_BODY_MAX];
    uint32_t  len;
    /* P9-CTL-1d-events: when reading /events, the body lives in
     * c->event_buf rather than session->buf (the log can grow
     * larger than STM_CTL_BODY_MAX = 1 KiB). At Tlopen we snapshot
     * the event_len into snapshot_len; subsequent Treads serve
     * c->event_buf[0..snapshot_len] under c->mu, ignoring events
     * appended after Tlopen. uses_event_buf=1 marks this branch. */
    int       uses_event_buf;
    uint32_t  snapshot_len;
    /* P9-CTL-1e: per-fid heap-allocated body for bulk kinds whose
     * worst-case bytes exceed STM_CTL_BODY_MAX. NULL on the bounded-
     * body path. Owned by the session; freed at session_free_locked
     * (the free runs BEFORE the memset that clears the slot, since
     * memset would otherwise lose the pointer and leak the alloc).
     *
     * Lifecycle: allocated at vops_lopen's materializer call, freed
     * at vops_clunk → session_free_locked. The slot is calloc'd at
     * stm_ctl_create time; subsequent allocs after a free see
     * bulk_buf=NULL because session_free_locked memsets the whole
     * struct. */
    uint8_t  *bulk_buf;
    uint32_t  bulk_len;
} ctl_session;

/* P9-CTL-1d-events: event log buffer. Realloc-doubling growth like
 * janus's audit_buf (janus/synfs.c:260+). Lines are
 * `<sec>.<nsec> <text>\n` with monotonic timestamps. Bounded by
 * STM_CTL_EVENT_MAX (8 MiB) to prevent runaway growth from a chatty
 * producer; once exceeded, append refuses (drops the line) — better
 * than realloc'ing into OOM. /admin/clear-events resets the buffer
 * (admin-only). */
#define STM_CTL_EVENT_MAX  (8u * 1024u * 1024u)

struct stm_ctl {
    struct stm_fs    *fs;             /* may be NULL (unattached) */
    struct stm_pool  *pool;           /* may be NULL (no pool attached) */
    struct stm_scrub *scrub;          /* may be NULL (no scrub attached) */
    /* P9-CTL-1d-uid: peer credentials + admin policy. Set by
     * stratumd via stm_ctl_set_caller / stm_ctl_set_admin_uid
     * BEFORE the first stm_lp9_server_handle invocation; not
     * mu-protected on read paths. */
    uid_t            caller_uid;     /* (uid_t)-1 = unset */
    gid_t            caller_gid;     /* (gid_t)-1 = unset */
    uid_t            admin_uid;      /* (uid_t)-1 = no daemon-euid admin */
    pthread_mutex_t  mu;              /* guards sessions[] + event_buf */
    /* P9-CTL-1d-events: event log. Mu-protected. event_buf may be
     * realloc'd; readers must hold mu while copying out. */
    uint8_t         *event_buf;
    size_t           event_len;
    size_t           event_cap;
    ctl_session      sessions[STM_CTL_MAX_SESSIONS];
};

/* P9-CTL-1d-uid: admin gate. Permits a caller iff:
 *   caller_uid == 0           (root)
 *   OR caller_uid == admin_uid (typically the daemon's effective uid)
 * The default unset states are caller_uid = (uid_t)-1 and admin_uid =
 * (uid_t)-1, which deny admin access. Explicit "uid 0 is admin" is
 * the v2.0 baseline policy; future configurable allowlist deferred. */
static bool ctl_caller_is_admin(const stm_ctl *c)
{
    if (c->caller_uid == (uid_t)-1) return false;
    if (c->caller_uid == 0) return true;
    if (c->admin_uid != (uid_t)-1 && c->caller_uid == c->admin_uid)
        return true;
    return false;
}

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
    /* The generic stm_lp9_server rejects re-Tlopen on an open fid
     * (h_open: STM_EEXIST when is_open), so under the current
     * server we only see fresh fids here. R96 P3-1 audited the
     * old reuse-loop as dead and we removed it. */
    for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++) {
        if (!c->sessions[i].active) {
            ctl_session *s = &c->sessions[i];
            s->active = 1;
            s->fid = fid;
            s->qid_path = qid_path;
            s->len = 0;
            s->uses_event_buf = 0;
            s->snapshot_len = 0;
            /* P9-CTL-1e (R110 P3-4 polish): after session_free_locked's
             * memset, bulk_buf is already NULL on this slot. Setting it
             * explicitly is belt-and-suspenders against a future change
             * to session_free_locked that drops the memset. */
            s->bulk_buf = NULL;
            s->bulk_len = 0;
            memset(s->buf, 0, sizeof s->buf);
            return s;
        }
    }
    return NULL;
}

static void session_free_locked(ctl_session *s)
{
    if (!s || !s->active) return;
    /* P9-CTL-1e: free the bulk buffer BEFORE memset zeros the
     * pointer — otherwise the struct memset loses the pointer and
     * the alloc leaks. free(NULL) is well-defined, so the bounded-
     * body path (bulk_buf=NULL) skips this safely. The bulk body is
     * non-secret (counters + UUIDs), so memzero is not required;
     * mirrors the primary buf[]'s "no memzero needed" posture. */
    free(s->bulk_buf);
    /* Body bytes are non-secret — version strings + counters. No
     * memzero needed. */
    memset(s, 0, sizeof *s);
}

/* ── UUID hex helpers ───────────────────────────────────────────────── */

/*
 * Stratum stores a pool UUID as 2× uint64 (little-endian on disk).
 * The /ctl/ surface formats it as the canonical 36-char hex form
 * with dashes (e.g. "12345678-1234-1234-1234-123456789abc"). Keep
 * the format identical to janus's so an operator who's looked at
 * /keys/pools/<uuid>/ sees the same string at /ctl/pools/<uuid>/.
 */
#define UUID_HEX_LEN  36u

static void uuid_to_bytes(const uint64_t uuid_words[2], uint8_t out[16])
{
    /* Little-endian byte order matches the on-disk + janus convention. */
    for (size_t i = 0; i < 8; i++) {
        out[i]     = (uint8_t)(uuid_words[0] >> (i * 8));
        out[i + 8] = (uint8_t)(uuid_words[1] >> (i * 8));
    }
}

static void uuid_format_hex(const uint8_t bytes[16], char out[UUID_HEX_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    size_t p = 0;
    for (size_t i = 0; i < 16; i++) {
        out[p++] = hex[bytes[i] >> 4];
        out[p++] = hex[bytes[i] & 0xF];
        if (i == 3 || i == 5 || i == 7 || i == 9) out[p++] = '-';
    }
    out[p] = '\0';
}

/* Parse a 36-char hex form into 16 bytes. Returns 0 on success, -1 on
 * malformed input. `len` is the input length; must be exactly 36. */
static int uuid_parse_hex(const char *s, size_t len, uint8_t out[16])
{
    if (len != UUID_HEX_LEN) return -1;
    size_t hi = 0;
    uint8_t acc = 0;
    int nib = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = s[i];
        if (ch == '-') {
            if (i != 8 && i != 13 && i != 18 && i != 23) return -1;
            continue;
        }
        uint8_t v;
        if      (ch >= '0' && ch <= '9') v = (uint8_t)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') v = (uint8_t)(10 + ch - 'a');
        else if (ch >= 'A' && ch <= 'F') v = (uint8_t)(10 + ch - 'A');
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

static bool uuid_eq(const uint8_t a[16], const uint8_t b[16])
{
    return memcmp(a, b, 16) == 0;
}

/* Parse `name[0..len)` as an unsigned decimal device-id in
 * [0, STM_POOL_DEVICES_MAX). Strict canonical: rejects leading
 * zeros on multi-char names (so the wire form has exactly one
 * spelling per slot). Returns 0 on success, -1 on malformed. */
static int parse_device_id(const char *name, size_t len, uint16_t *out)
{
    if (len == 0 || len > 3) return -1;     /* 0..63 fits in 2 chars; defensive 3 */
    if (len > 1 && name[0] == '0') return -1;
    uint32_t v = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = name[i];
        if (ch < '0' || ch > '9') return -1;
        v = v * 10u + (uint32_t)(ch - '0');
        if (v >= STM_POOL_DEVICES_MAX) return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

/* Parse `name[0..len)` as an unsigned decimal dataset-id in
 * (0, STM_SYNC_DATASET_ID_MAX]. Same strict-canonical posture as
 * parse_device_id (rejects leading zeros on multi-char names).
 * STM_SYNC_DATASET_ID_MAX = 0x0FFFFFFF ~= 268435455 fits in 9
 * decimal digits; cap len at 10 defensive. Dataset id 0 is reserved
 * (STM_DATASET_ROOT_ID = 1; root takes id 1). The dataset_id type
 * is uint64_t to match the dataset.h surface, even though the wire
 * encoding caps at 28 bits. */
static int parse_dataset_id(const char *name, size_t len, uint64_t *out)
{
    if (len == 0 || len > 10) return -1;
    if (len > 1 && name[0] == '0') return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = name[i];
        if (ch < '0' || ch > '9') return -1;
        v = v * 10u + (uint64_t)(ch - '0');
        if (v > STM_SYNC_DATASET_ID_MAX) return -1;
    }
    /* R99 P3-2: dataset id 0 is reserved (the canonical id space
     * starts at STM_DATASET_ROOT_ID = 1). Reject "0" at the parser
     * boundary so the wire form has exactly one spelling per slot
     * and "syntactically refused" is distinguishable from "looked
     * up and missed." */
    if (v == 0) return -1;
    *out = v;
    return 0;
}

/* Parse `name[0..len)` as an unsigned decimal snapshot-id in
 * (0, UINT64_MAX]. Strict canonical: rejects leading zeros + "0"
 * (snapshot ids are 1-indexed; 0 is the STM_SNAP_NO_PREV sentinel
 * per snapshot.h::STM_SNAP_NO_PREV). 20-char cap matches UINT64_MAX
 * decimal length; the per-digit check `v > UINT64_MAX / 10` plus
 * the `v < (uint64_t)(ch - '0')` overflow recheck guards the multiply.
 *
 * Same shape as parse_dataset_id but with a wider range — snapshot
 * ids are an internal monotonic counter not constrained by the
 * sync-layer's dataset_id cap. */
static int parse_snapshot_id(const char *name, size_t len, uint64_t *out)
{
    if (len == 0 || len > 20) return -1;
    if (len > 1 && name[0] == '0') return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        char ch = name[i];
        if (ch < '0' || ch > '9') return -1;
        if (v > UINT64_MAX / 10u) return -1;
        v = v * 10u;
        uint64_t d = (uint64_t)(ch - '0');
        if (v > UINT64_MAX - d) return -1;
        v = v + d;
    }
    if (v == 0) return -1;
    *out = v;
    return 0;
}

/* Cap on the number of dataset ids collected per /datasets/ readdir
 * pass. v2.0 readdir returns one batch (caller pages via 9P-level
 * Tread offsets). Stratum's design point is hundreds of datasets at
 * most for typical pools; STM_CTL_DATASET_LIST_CAP = 1024 covers
 * realistic operational sizes with a 8 KiB stack footprint. Pools
 * with more than 1024 datasets would be truncated at the readdir
 * boundary — forward-noted to a future paginated-readdir chunk;
 * v2.0's /ctl/ doesn't carry persistent cursor state. */
#define STM_CTL_DATASET_LIST_CAP  1024u

/* Iter callback used by vops_readdir for KIND_DATASETS_DIR. Captures
 * the entry id into the caller's out array. Bounded by `cap`; on
 * overflow we stop iterating and the readdir result truncates. */
typedef struct {
    uint64_t *out;
    size_t   *n;
    size_t    cap;
} ds_collect_ctx;

static bool ds_collect_cb(const stm_dataset_entry *entry, void *ctx_v)
{
    ds_collect_ctx *ctx = ctx_v;
    if (*ctx->n >= ctx->cap) return false;     /* stop iteration */
    ctx->out[(*ctx->n)++] = entry->id;
    return true;
}

/* Get the attached pool's UUID as 16 bytes, or return false if no pool
 * is attached. */
static bool ctl_pool_uuid_bytes(const stm_ctl *c, uint8_t out[16])
{
    if (!c->pool) return false;
    uuid_to_bytes(stm_pool_uuid(c->pool), out);
    return true;
}

/* ── enum stringification ───────────────────────────────────────────── */

/* R98 P3-4: trailing "unknown" returns are LOAD-BEARING for tamper-
 * resilience, not redundant default fallbacks. `stm_pool_roster_
 * decode` writes the on-disk byte directly into the enum-typed
 * field without range-checking (pool.c:142-144), so a corrupt-but-
 * csum-bypassed roster could surface a slot with class/role/state
 * value past the documented enum top. The trailing return gives
 * deterministic output instead of UB; the synfs is the last line
 * of defense before operator-visible bytes. */
static const char *device_class_name(stm_device_class cls)
{
    switch (cls) {
    case STM_DEV_CLASS_UNSET: return "unset";
    case STM_DEV_CLASS_SSD:   return "ssd";
    case STM_DEV_CLASS_HDD:   return "hdd";
    case STM_DEV_CLASS_PMEM:  return "pmem";
    case STM_DEV_CLASS_ZNS:   return "zns";
    }
    return "unknown";
}

static const char *device_role_name(stm_device_role role)
{
    switch (role) {
    case STM_DEV_ROLE_UNSET: return "unset";
    case STM_DEV_ROLE_DATA:  return "data";
    case STM_DEV_ROLE_LOG:   return "log";
    case STM_DEV_ROLE_CACHE: return "cache";
    case STM_DEV_ROLE_SPARE: return "spare";
    }
    return "unknown";
}

static const char *device_state_name(stm_device_state state)
{
    switch (state) {
    case STM_DEV_STATE_UNSET:      return "unset";
    case STM_DEV_STATE_ONLINE:     return "online";
    case STM_DEV_STATE_OFFLINE:    return "offline";
    case STM_DEV_STATE_DEGRADED:   return "degraded";
    case STM_DEV_STATE_FAULTED:    return "faulted";
    case STM_DEV_STATE_REMOVED:    return "removed";
    case STM_DEV_STATE_EVACUATING: return "evacuating";
    }
    return "unknown";
}

/* P8.5 cleanup-2 (R108 P3-5 carry): map common stm_status refusal
 * codes to short tokens for /events audit-log forensic specificity.
 * Operators reading /events can grep for `result=err:einval` /
 * `result=err:ebusy` / etc. to triage failures without consulting
 * stm_status.h.
 *
 * STM_OK returns "ok" so the format `result=%s%s` with conditional
 * "err:" prefix renders cleanly: success → `result=ok`, failure →
 * `result=err:<code>`. Default "err" fallback for codes outside the
 * common refusal class (defense-in-depth — avoids silent
 * "err:" with empty suffix). */
static const char *status_short_name(stm_status s)
{
    switch (s) {
    case STM_OK:        return "ok";
    case STM_EINVAL:    return "einval";
    case STM_ENOENT:    return "enoent";
    case STM_EBUSY:     return "ebusy";
    case STM_EROFS:     return "erofs";
    case STM_EWEDGED:   return "ewedged";
    case STM_EOVERFLOW: return "eoverflow";
    case STM_EEXIST:    return "eexist";
    case STM_ECORRUPT:  return "ecorrupt";
    case STM_EBACKEND:  return "ebackend";
    case STM_EIO:       return "eio";
    case STM_EACCES:    return "eaccess";
    case STM_ERANGE:    return "erange";
    case STM_ENOMEM:    return "enomem";
    default:            return "err";
    }
}

/* R98 P3-4 lesson: trailing "unknown" return is LOAD-BEARING. While
 * stm_scrub_state values today are produced exclusively by scrub.c
 * under sc->lock (no on-disk parsing path that would skip range-check
 * — scrub state is in-memory only), keeping the default deterministic
 * matches the device_*_name discipline AND defends against a future
 * persisted-scrub-cursor extension that would re-introduce the parsing
 * trust boundary. */
static const char *scrub_state_name(stm_scrub_state st)
{
    switch (st) {
    case STM_SCRUB_STATE_IDLE:      return "idle";
    case STM_SCRUB_STATE_RUNNING:   return "running";
    case STM_SCRUB_STATE_PAUSED:    return "paused";
    case STM_SCRUB_STATE_COMPLETED: return "completed";
    }
    return "unknown";
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

/* Per-class device count in the roster. The roster includes REMOVED
 * slots; we report both totals and live counts so an operator can
 * spot evacuation-in-progress from the ratio.
 *
 * R97 P3-2: array bounds (5 / 5 / 7) pinned against the canonical
 * stm_device_* enum cardinalities below. If a future enum gains a
 * new value past the current top, the assert trips at build time
 * and the developer must extend BOTH the array bound AND every
 * per-class/role/state output formatter in lockstep. The
 * if-guard's silent "skip" used to hide the missed case at
 * runtime; the assert surfaces it at compile time. */
_Static_assert(STM_DEV_CLASS_ZNS == 4,
               "synfs.c per_class[5] depends on STM_DEV_CLASS_* range");
_Static_assert(STM_DEV_ROLE_SPARE == 4,
               "synfs.c per_role[5] depends on STM_DEV_ROLE_* range");
_Static_assert(STM_DEV_STATE_EVACUATING == 6,
               "synfs.c per_state[7] depends on STM_DEV_STATE_* range");

typedef struct {
    uint16_t total;
    uint16_t live;
    uint16_t per_class[5];     /* indexed by stm_device_class */
    uint16_t per_role[5];      /* indexed by stm_device_role */
    uint16_t per_state[7];     /* indexed by stm_device_state */
    uint64_t total_size_bytes;
    uint64_t live_size_bytes;
} pool_summary;

static void summarize_pool_locked(stm_pool *pool, pool_summary *out)
{
    memset(out, 0, sizeof *out);
    size_t n = stm_pool_device_count(pool);
    if (n > UINT16_MAX) n = UINT16_MAX;
    out->total = (uint16_t)n;
    out->live  = (uint16_t)stm_pool_live_device_count(pool);
    for (size_t i = 0; i < n; i++) {
        const stm_pool_device *d = stm_pool_device_info(pool, (uint16_t)i);
        if (!d) continue;
        if (d->class_ < 5) out->per_class[d->class_]++;
        if (d->role   < 5) out->per_role [d->role  ]++;
        if (d->state  < 7) out->per_state[d->state ]++;
        out->total_size_bytes += d->size_bytes;
        if (d->state != STM_DEV_STATE_REMOVED)
            out->live_size_bytes += d->size_bytes;
    }
}

static stm_status materialize_pool_status(stm_ctl *c, ctl_session *s)
{
    if (!c->pool) {
        /* Should not be reachable — vops_lopen gates KIND_POOL_STATUS
         * on c->pool != NULL. Defensive. */
        int n = snprintf((char *)s->buf, sizeof s->buf,
            "pool: not-attached\n");
        if (n < 0) return STM_EIO;
        if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
        s->len = (uint32_t)n;
        return STM_OK;
    }

    uint8_t uuid_b[16];
    uuid_to_bytes(stm_pool_uuid(c->pool), uuid_b);
    char uuid_s[UUID_HEX_LEN + 1];
    uuid_format_hex(uuid_b, uuid_s);

    stm_pool_lock_shared(c->pool);
    pool_summary sum;
    summarize_pool_locked(c->pool, &sum);
    uint64_t roster_hash = stm_pool_roster_hash(c->pool);
    stm_pool_unlock_shared(c->pool);

    int n = snprintf((char *)s->buf, sizeof s->buf,
        "pool-uuid: %s\n"
        "device-count-total: %u\n"
        "device-count-live: %u\n"
        "roster-hash: 0x%016llx\n"
        "size-bytes-total: %llu\n"
        "size-bytes-live: %llu\n"
        "class-ssd: %u\n"
        "class-hdd: %u\n"
        "class-pmem: %u\n"
        "class-zns: %u\n"
        "role-data: %u\n"
        "role-log: %u\n"
        "role-cache: %u\n"
        "role-spare: %u\n"
        "state-online: %u\n"
        "state-offline: %u\n"
        "state-degraded: %u\n"
        "state-faulted: %u\n"
        "state-removed: %u\n"
        "state-evacuating: %u\n",
        uuid_s,
        (unsigned)sum.total,
        (unsigned)sum.live,
        (unsigned long long)roster_hash,
        (unsigned long long)sum.total_size_bytes,
        (unsigned long long)sum.live_size_bytes,
        (unsigned)sum.per_class[STM_DEV_CLASS_SSD],
        (unsigned)sum.per_class[STM_DEV_CLASS_HDD],
        (unsigned)sum.per_class[STM_DEV_CLASS_PMEM],
        (unsigned)sum.per_class[STM_DEV_CLASS_ZNS],
        (unsigned)sum.per_role[STM_DEV_ROLE_DATA],
        (unsigned)sum.per_role[STM_DEV_ROLE_LOG],
        (unsigned)sum.per_role[STM_DEV_ROLE_CACHE],
        (unsigned)sum.per_role[STM_DEV_ROLE_SPARE],
        (unsigned)sum.per_state[STM_DEV_STATE_ONLINE],
        (unsigned)sum.per_state[STM_DEV_STATE_OFFLINE],
        (unsigned)sum.per_state[STM_DEV_STATE_DEGRADED],
        (unsigned)sum.per_state[STM_DEV_STATE_FAULTED],
        (unsigned)sum.per_state[STM_DEV_STATE_REMOVED],
        (unsigned)sum.per_state[STM_DEV_STATE_EVACUATING]);
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

/* Materialize /pools/<uuid>/devices/<id>/status — per-device record
 * snapshot. R97 P3-3 close: device_class_name/device_role_name/
 * device_state_name now wired here. */
static stm_status materialize_device_status(stm_ctl *c, ctl_session *s)
{
    if (!c->pool) return STM_EBACKEND;     /* gated at vops_lopen */
    uint16_t did = (uint16_t)qid_device_id(s->qid_path);

    stm_pool_lock_shared(c->pool);
    size_t total = stm_pool_device_count(c->pool);
    if (did >= total) {
        stm_pool_unlock_shared(c->pool);
        return STM_ENOENT;
    }
    /* R98 P2-1 / P3-5: stm_pool_device_info returns &devices[id] for
     * any in-bounds id (incl. REMOVED slots, which keep their UUID
     * + state for burn-audit). The `(d == NULL)` defensive check
     * below is unreachable under the current pool semantics; keeping
     * it as defense-in-depth against a future pool API that could
     * return NULL for in-bounds slots, but not load-bearing today. */
    const stm_pool_device *d = stm_pool_device_info(c->pool, did);
    if (!d) {
        stm_pool_unlock_shared(c->pool);
        return STM_ENOENT;
    }
    /* Snapshot to a local before unlock — the device record fields
     * the formatter touches (uuid, size_bytes, role, class_, state)
     * are all in the slot itself, which mutates only under the
     * exclusive side. We hold rdlock so reads are stable. */
    stm_pool_device snap = *d;
    stm_pool_unlock_shared(c->pool);

    uint8_t uuid_b[16];
    /* device uuid is uint64_t[2] — same shape as pool uuid. Reuse
     * the LE byte-pack convention for consistency at the wire form. */
    for (size_t i = 0; i < 8; i++) {
        uuid_b[i]     = (uint8_t)(snap.uuid[0] >> (i * 8));
        uuid_b[i + 8] = (uint8_t)(snap.uuid[1] >> (i * 8));
    }
    char uuid_s[UUID_HEX_LEN + 1];
    uuid_format_hex(uuid_b, uuid_s);

    int n = snprintf((char *)s->buf, sizeof s->buf,
        "device-id: %u\n"
        "device-uuid: %s\n"
        "size-bytes: %llu\n"
        "class: %s\n"
        "role: %s\n"
        "state: %s\n",
        (unsigned)did,
        uuid_s,
        (unsigned long long)snap.size_bytes,
        device_class_name(snap.class_),
        device_role_name(snap.role),
        device_state_name(snap.state));
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

/* R99 P3-4: pin the property-line block against STM_PROP_COUNT. If a
 * future chunk grows the enum (e.g., adds STM_PROP_DEDUP), the
 * materializer below silently omits the new property until a manual
 * edit catches up. Trip at build time. Update both this assert AND
 * materialize_dataset_properties's printf block in lockstep. */
_Static_assert(STM_PROP_COUNT == 5,
               "materialize_dataset_properties prints exactly 5 "
               "user-settable properties; extend the printf block "
               "whenever STM_PROP_COUNT grows (ARCH §8.4.2)");

/* Materialize /datasets/<id>/properties — surfaces the dataset's
 * five user-settable properties (effective values, with parent-walk
 * inheritance per property.tla::Effective) AND the metadata fields
 * from stm_dataset_entry (name, parent_id, created_txg, next_ino,
 * origin_snap_id). Combined to give operators a single view of the
 * dataset's full state.
 *
 * Body cap: worst-case ~615 bytes (255-byte name + 11 × 20-digit
 * decimals + line decoration). R99 P3-3 corrected from earlier
 * "~280 bytes" estimate — comfortable under STM_CTL_BODY_MAX
 * (60% headroom).
 *
 * Name safety: dataset.c's name_chars_valid (R99 P2-1) refuses
 * bytes < 0x20 + 0x7F at create_child / rename / create_clone, so
 * the `name: %.*s\n` formatter cannot embed a forged `\nflags: ...`
 * line. UTF-8 multi-byte sequences are accepted unchanged. */
static stm_status materialize_dataset_properties(stm_ctl *c, ctl_session *s)
{
    if (!c->fs) return STM_EBACKEND;     /* gated at vops_lopen */
    uint64_t dsid = qid_dataset_id(s->qid_path);

    stm_dataset_entry e;
    stm_status rc = stm_fs_dataset_lookup(c->fs, dsid, &e);
    if (rc != STM_OK) return rc;

    uint64_t compress = 0, quota = 0, encryption = 0, tiering = 0,
             promote_decay = 0;
    /* Each property lookup re-takes fs->lock. The values are read
     * over multiple short critical sections — between them, a
     * concurrent set_property could cause us to surface a mixed
     * snapshot. /ctl/ is operator state, not a transactional
     * surface; this is documented as a freshness tradeoff (R96
     * lesson on materialize-at-Tlopen semantics). Re-open to refresh. */
    rc = stm_fs_effective_dataset_property(c->fs, dsid,
                                              STM_PROP_COMPRESS, &compress);
    if (rc != STM_OK) return rc;
    rc = stm_fs_effective_dataset_property(c->fs, dsid,
                                              STM_PROP_QUOTA, &quota);
    if (rc != STM_OK) return rc;
    rc = stm_fs_effective_dataset_property(c->fs, dsid,
                                              STM_PROP_ENCRYPTION, &encryption);
    if (rc != STM_OK) return rc;
    rc = stm_fs_effective_dataset_property(c->fs, dsid,
                                              STM_PROP_TIERING, &tiering);
    if (rc != STM_OK) return rc;
    rc = stm_fs_effective_dataset_property(c->fs, dsid,
                                              STM_PROP_PROMOTE_DECAY_WINDOW,
                                              &promote_decay);
    if (rc != STM_OK) return rc;

    /* Note: `name` is dataset-supplied and should be safe (validated
     * at create_child against length + collision); but we still
     * truncate-check below. parent_id, created_txg, next_ino,
     * origin_snap_id are dataset-internal counters. */
    int n = snprintf((char *)s->buf, sizeof s->buf,
        "dataset-id: %llu\n"
        "name: %.*s\n"
        "parent-id: %llu\n"
        "created-txg: %llu\n"
        "next-ino: %llu\n"
        "origin-snap-id: %llu\n"
        "flags: 0x%08x\n"
        "compression: %llu\n"
        "quota: %llu\n"
        "encryption: %llu\n"
        "tiering: %llu\n"
        "promote-decay-window: %llu\n",
        (unsigned long long)e.id,
        (int)e.name_len, (const char *)e.name,
        (unsigned long long)e.parent_id,
        (unsigned long long)e.created_txg,
        (unsigned long long)e.next_ino,
        (unsigned long long)e.origin_snap_id,
        (unsigned)e.flags,
        (unsigned long long)compress,
        (unsigned long long)quota,
        (unsigned long long)encryption,
        (unsigned long long)tiering,
        (unsigned long long)promote_decay);
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

/* R100 P3-1: render uid/gid sentinel ((uid_t)-1 / (gid_t)-1) as the
 * literal "(unset)" rather than the integer max. Without this, an
 * operator running `cat /ctl/admin/peer` with a default-config
 * stratumd would see "admin-uid: 4294967295" — indistinguishable
 * from the daemon explicitly setting admin_uid = UINT_MAX. */
static int append_uid_line(char *buf, size_t cap, const char *label, uid_t v)
{
    if (v == (uid_t)-1) return snprintf(buf, cap, "%s(unset)\n", label);
    return snprintf(buf, cap, "%s%u\n", label, (unsigned)v);
}
static int append_gid_line(char *buf, size_t cap, const char *label, gid_t v)
{
    if (v == (gid_t)-1) return snprintf(buf, cap, "%s(unset)\n", label);
    return snprintf(buf, cap, "%s%u\n", label, (unsigned)v);
}

/* ── event log (P9-CTL-1d-events) ─────────────────────────────────── */

/* Append `len` bytes to c->event_buf under c->mu (must already be
 * held). Realloc-doubling growth, capped at STM_CTL_EVENT_MAX. On
 * cap exceed or alloc failure, drops the line silently — better
 * than refusing future events or aborting. */
static void event_append_locked(stm_ctl *c, const char *data, size_t len)
{
    if (len == 0) return;
    size_t need = c->event_len + len;
    if (need > STM_CTL_EVENT_MAX) return;
    if (need > c->event_cap) {
        size_t new_cap = c->event_cap ? c->event_cap : 4096;
        while (new_cap < need) {
            size_t grown = new_cap * 2;
            if (grown < new_cap) return;     /* overflow */
            new_cap = grown;
        }
        if (new_cap > STM_CTL_EVENT_MAX) new_cap = STM_CTL_EVENT_MAX;
        if (new_cap < need) return;           /* still too small */
        uint8_t *grown = realloc(c->event_buf, new_cap);
        if (!grown) return;                   /* alloc failed; drop */
        c->event_buf = grown;
        c->event_cap = new_cap;
    }
    memcpy(c->event_buf + c->event_len, data, len);
    c->event_len += len;
}

/* Format a timestamped line and append. Mirrors janus_synfs_auditf
 * (janus/synfs.c::janus_synfs_auditf): clock_gettime(CLOCK_REALTIME)
 * + vsnprintf-into-stack-buffer + append. Truncated lines are
 * forced-newline-terminated (R11 P3-4 lesson) so the line-oriented
 * format stays valid. */
void stm_ctl_log_event(stm_ctl *c, const char *fmt, ...)
{
    if (!c || !fmt) return;
    char line[512];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int pfx = snprintf(line, sizeof line, "%lld.%09ld ",
                        (long long)ts.tv_sec, (long)ts.tv_nsec);
    if (pfx < 0 || (size_t)pfx >= sizeof line) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line + pfx, sizeof line - (size_t)pfx, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    size_t total = (size_t)pfx + (size_t)n;
    if (total >= sizeof line) total = sizeof line - 1;
    /* Force trailing newline (R11 P3-4 — every log entry MUST end
     * with \n even on the truncation path; otherwise readout merges
     * the truncated line with the next entry). */
    if (total == sizeof line - 1) {
        line[sizeof line - 2] = '\n';
        total = sizeof line - 1;
    } else if (total == 0 || line[total - 1] != '\n') {
        line[total++] = '\n';
    }
    pthread_mutex_lock(&c->mu);
    event_append_locked(c, line, total);
    pthread_mutex_unlock(&c->mu);
}

/* Materialize /admin/peer — exposes the connecting client's uid/gid
 * + admin status as observed by the daemon. Read-only; admin-only
 * (vops_lopen enforces).
 *
 * Useful operationally: an admin running `cat /ctl/admin/peer` can
 * confirm "the daemon sees me as uid X / gid Y / admin=yes" before
 * trying privileged operations. Distinguishes "admin gate refused
 * because I'm not admin" from "the daemon thinks my uid is wrong"
 * (e.g., SO_PEERCRED returned the wrong identity).
 *
 * Body cap: 4 lines, ~30 chars worst case (incl. "(unset)" sentinel
 * placeholders) ≈ 120 bytes; STM_CTL_BODY_MAX = 1 KiB. Comfortable. */
static stm_status materialize_admin_peer(stm_ctl *c, ctl_session *s)
{
    char *p = (char *)s->buf;
    size_t left = sizeof s->buf;
    int n;
    n = append_uid_line(p, left, "caller-uid: ", c->caller_uid);
    if (n < 0 || (size_t)n >= left) return STM_ERANGE;
    p += n; left -= (size_t)n;
    n = append_gid_line(p, left, "caller-gid: ", c->caller_gid);
    if (n < 0 || (size_t)n >= left) return STM_ERANGE;
    p += n; left -= (size_t)n;
    n = append_uid_line(p, left, "admin-uid: ", c->admin_uid);
    if (n < 0 || (size_t)n >= left) return STM_ERANGE;
    p += n; left -= (size_t)n;
    n = snprintf(p, left, "is-admin: %s\n",
                  ctl_caller_is_admin(c) ? "yes" : "no");
    if (n < 0 || (size_t)n >= left) return STM_ERANGE;
    p += n;
    s->len = (uint32_t)(p - (char *)s->buf);
    return STM_OK;
}

/* Materialize /pools/<uuid>/scrub — read-only state + counters from
 * stm_scrub_status_get. Body: state (idle/running/paused/completed) +
 * cursor (device_id + start_block) + counters (verified, failed,
 * repaired, unrepairable, ranges_processed). 8 lines worst case ~275
 * bytes (state="completed" 9 chars + cursor_device_id 5 digits +
 * 6× UINT64_MAX 20-digit + per-line labels). STM_CTL_BODY_MAX = 1024
 * — ~3.7× headroom (R103 P3-4: tightened from earlier "~400 bytes"
 * estimate to the actual computed ceiling).
 *
 * stm_scrub_status_get takes sc's internal mutex; safe to call
 * without external coordination. The status snapshot reflects the
 * scrub at the moment of the call; subsequent steps mutate it. */
static stm_status materialize_pool_scrub(stm_ctl *c, ctl_session *s)
{
    if (!c->scrub) return STM_EBACKEND;     /* gated at vops_lopen */

    stm_scrub_status st;
    stm_status rc = stm_scrub_status_get(c->scrub, &st);
    if (rc != STM_OK) return rc;

    int n = snprintf((char *)s->buf, sizeof s->buf,
        "state: %s\n"
        "cursor-device-id: %u\n"
        "cursor-start-block: %llu\n"
        "blocks-verified: %llu\n"
        "blocks-failed: %llu\n"
        "blocks-repaired: %llu\n"
        "blocks-unrepairable: %llu\n"
        "ranges-processed: %llu\n",
        scrub_state_name(st.state),
        (unsigned)st.cursor_device_id,
        (unsigned long long)st.cursor_start_block,
        (unsigned long long)st.blocks_verified,
        (unsigned long long)st.blocks_failed,
        (unsigned long long)st.blocks_repaired,
        (unsigned long long)st.blocks_unrepairable,
        (unsigned long long)st.ranges_processed);
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

/* Materialize /debug/allocator-state/<device_id> — per-device allocator
 * state snapshot. Composes against stm_fs_alloc_stats_get (fs.c), which
 * resolves the per-device stm_alloc via stm_sync's attach table.
 *
 * Body cap: 13 lines × ~50 chars worst case (UINT64_MAX = 20 digits +
 * label) ≈ 650 bytes; STM_CTL_BODY_MAX = 1024. ~35% headroom.
 *
 * Returns STM_ENOENT if the device slot has no allocator attached
 * (unattached or REMOVED) — same shape as KIND_DEVICE_STATUS for
 * out-of-roster ids. The vops_lopen + getattr_at gates trap most of these
 * before reaching here; this is the inner-leg verification. */
static stm_status materialize_debug_alloc(stm_ctl *c, ctl_session *s)
{
    if (!c->fs) return STM_EBACKEND;     /* gated at vops_lopen */
    /* R102 P3-3: defense-in-depth bound check on the qid's low-32
     * device_id slot. All client-reachable qids for KIND_DEBUG_ALLOC
     * are constructed via qid_of(KIND_DEBUG_ALLOC, 0, did) with did
     * already < STM_POOL_DEVICES_MAX (parse_device_id + readdir
     * loop), so this never fires today. But narrowing uint32 → uint16
     * silently wraps if a future qid producer passes did > 65535;
     * the explicit gate keeps the materializer self-validating
     * regardless of upstream changes. Mirrors materialize_device_
     * status's defensive shape. */
    uint32_t did_wide = qid_device_id(s->qid_path);
    if (did_wide >= STM_POOL_DEVICES_MAX) return STM_ENOENT;
    uint16_t did = (uint16_t)did_wide;

    stm_alloc_stats stats;
    stm_status rc = stm_fs_alloc_stats_get(c->fs, did, &stats);
    if (rc != STM_OK) return rc;

    int n = snprintf((char *)s->buf, sizeof s->buf,
        "device-id: %u\n"
        "bootstrap-size-blocks: %llu\n"
        "bootstrap-total-units: %llu\n"
        "bootstrap-allocated-units: %llu\n"
        "bootstrap-bitmap-gen: %llu\n"
        "data-first-block: %llu\n"
        "data-last-block: %llu\n"
        "data-total-blocks: %llu\n"
        "data-allocated-blocks: %llu\n"
        "data-pending-blocks: %llu\n"
        "data-free-blocks: %llu\n"
        "n-allocated-ranges: %llu\n"
        "n-pending-ranges: %llu\n",
        (unsigned)did,
        (unsigned long long)stats.bootstrap_size_blocks,
        (unsigned long long)stats.bootstrap_total_units,
        (unsigned long long)stats.bootstrap_allocated_units,
        (unsigned long long)stats.bootstrap_bitmap_gen,
        (unsigned long long)stats.data_first_block,
        (unsigned long long)stats.data_last_block,
        (unsigned long long)stats.data_total_blocks,
        (unsigned long long)stats.data_allocated_blocks,
        (unsigned long long)stats.data_pending_blocks,
        (unsigned long long)stats.data_free_blocks,
        (unsigned long long)stats.n_allocated_ranges,
        (unsigned long long)stats.n_pending_ranges);
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

/* ── Prometheus exposition (P9-CTL-1e) ──────────────────────────────────── */
/*
 * Bulk-format materializer for /pools/<uuid>/metrics/prometheus
 * (ARCH §14.8.1). Body shape: HELP + TYPE comments + samples,
 * line-oriented ASCII, terminated by '\n'. World-readable (mode 0444).
 *
 * Body lives in s->bulk_buf (heap-allocated, capped at STM_CTL_METRICS_
 * MAX = 64 KiB). Bounded materializers use s->buf[STM_CTL_BODY_MAX];
 * /metrics/prometheus exceeds 1 KiB once per-device + scrub data are
 * emitted (~30 KiB on a 64-device pool with all sections active).
 *
 * Lock posture (R110 P3-5 + P3-8 polish): we don't hold MULTIPLE
 * subsystem locks concurrently. c->mu is held by the caller throughout
 * (vops_lopen's session-alloc loop); within that, the pool / fs / scrub
 * accessors each take their own internal lock SERIALLY (one at a time,
 * none nested). Pool roster snapshot via stm_pool_lock_shared
 * (released before the format pass), fs stats via stm_fs_stats_get +
 * stm_fs_dataset_count (each takes fs's internal lock briefly), scrub
 * status via stm_scrub_status_get (takes scrub's internal mutex). The
 * fs / scrub internal locks are not part of the public surface; the
 * names below are descriptive only. Output is computed from the
 * captured snapshots after every subsystem lock is released, so
 * format-time errors don't pin contended state.
 *
 * Trust boundaries:
 *   - Body MUST NOT leak secret bytes: only counters, UUIDs (public
 *     identifiers), enum-name strings filtered through device_*_name
 *     / scrub_state_name (R98 P3-4 trailing-"unknown" tamper-resilient).
 *   - Label values fed into the body are bounded: pool/device UUIDs
 *     are 36-char hex (no escaping needed); enum-name strings are a
 *     fixed allowlist. NO user-supplied strings (no dataset names, no
 *     snapshot names) flow into Prometheus labels at v2.0 — defers the
 *     Prometheus label-escape rule (R99 P2-1 line-injection class
 *     extends to label-value-injection in the exposition format).
 *     Forward-note: when per-dataset metrics are added, the dataset
 *     name MUST be sanitized OR labels keyed by dataset_id only.
 */

/* Realloc-doubling growth bounded by STM_CTL_METRICS_MAX. Returns
 * STM_OK on success, STM_ERANGE if the cap would be exceeded,
 * STM_ENOMEM on alloc failure. *buf may be NULL on entry; sets
 * *buf to the (possibly new) backing pointer. */
static stm_status prom_grow(uint8_t **buf, uint32_t *cap, uint32_t want)
{
    if (want <= *cap) return STM_OK;
    if (want > STM_CTL_METRICS_MAX) return STM_ERANGE;
    uint32_t new_cap = (*cap == 0) ? STM_CTL_METRICS_INITIAL_CAP : *cap;
    while (new_cap < want) {
        if (new_cap > STM_CTL_METRICS_MAX / 2) {
            new_cap = STM_CTL_METRICS_MAX;
            break;
        }
        new_cap *= 2;
    }
    if (new_cap < want) return STM_ERANGE;
    uint8_t *grown = realloc(*buf, new_cap);
    if (!grown) return STM_ENOMEM;
    *buf = grown;
    *cap = new_cap;
    return STM_OK;
}

/* vsnprintf-then-grow append. On any failure return *len is unchanged.
 * *cap is also unchanged in every failure mode except the rare
 * second-vsnprintf-truncation branch (STM_EIO when wrote != n) where
 * prom_grow already grew but the second write didn't complete; the
 * grown allocation is preserved on the caller's buf, so a subsequent
 * call benefits. R110 P3-3 polish. */
static stm_status prom_appendf(uint8_t **buf, uint32_t *cap, uint32_t *len,
                                const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static stm_status prom_appendf(uint8_t **buf, uint32_t *cap, uint32_t *len,
                                const char *fmt, ...)
{
    /* First pass: measure with NULL/0 so we know how much to grow. */
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) return STM_EIO;
    /* +1 for the NUL that vsnprintf writes; Prometheus body itself
     * doesn't need NUL termination but we use vsnprintf which always
     * writes one. The trailing NUL is overwritten by the next
     * append. */
    if ((uint64_t)*len + (uint64_t)n + 1 > UINT32_MAX) return STM_ERANGE;
    uint32_t need = *len + (uint32_t)n + 1;
    stm_status rc = prom_grow(buf, cap, need);
    if (rc != STM_OK) return rc;
    va_start(ap, fmt);
    int wrote = vsnprintf((char *)(*buf) + *len, *cap - *len, fmt, ap);
    va_end(ap);
    if (wrote < 0 || wrote != n) return STM_EIO;
    *len += (uint32_t)wrote;
    return STM_OK;
}

/* Per-device snapshot used for the metrics walk. Captured under
 * stm_pool_lock_shared and rendered after release so format-time
 * cost doesn't pin the pool roster lock. */
typedef struct {
    uint16_t           device_id;
    uint8_t            uuid[16];
    uint64_t           size_bytes;
    stm_device_class   class_;
    stm_device_role    role;
    stm_device_state   state;
} prom_device_snap;

#define STM_CTL_PROM_DEVICES_CAP  STM_POOL_DEVICES_MAX

static stm_status materialize_pool_metrics_prometheus(stm_ctl *c,
                                                        ctl_session *s)
{
    if (!c->pool) return STM_EBACKEND;     /* gated at vops_lopen */

    /* ── Gather snapshots ───────────────────────────────────────── */
    uint8_t pool_uuid_b[16];
    uuid_to_bytes(stm_pool_uuid(c->pool), pool_uuid_b);
    char pool_uuid_s[UUID_HEX_LEN + 1];
    uuid_format_hex(pool_uuid_b, pool_uuid_s);

    /* Pool roster snapshot. */
    pool_summary sum;
    stm_pool_lock_shared(c->pool);
    summarize_pool_locked(c->pool, &sum);
    /* Per-device records. STM_POOL_DEVICES_MAX = 64 fits comfortably
     * on the stack (64 × 48 bytes = 3 KiB). */
    prom_device_snap devs[STM_CTL_PROM_DEVICES_CAP];
    size_t total = stm_pool_device_count(c->pool);
    if (total > STM_CTL_PROM_DEVICES_CAP) total = STM_CTL_PROM_DEVICES_CAP;
    size_t n_devs = 0;
    for (size_t i = 0; i < total; i++) {
        const stm_pool_device *d =
            stm_pool_device_info(c->pool, (uint16_t)i);
        if (!d) continue;
        prom_device_snap *out = &devs[n_devs++];
        out->device_id = (uint16_t)i;
        uuid_to_bytes(d->uuid, out->uuid);
        out->size_bytes = d->size_bytes;
        out->class_ = d->class_;
        out->role = d->role;
        out->state = d->state;
    }
    stm_pool_unlock_shared(c->pool);

    /* fs stats (optional — when fs is unattached, fs gauges are
     * omitted; the materializer still produces a valid response). */
    bool have_fs = (c->fs != NULL);
    stm_fs_stats fs_stats;
    memset(&fs_stats, 0, sizeof fs_stats);
    size_t dataset_count = 0;
    if (have_fs) {
        stm_status frc = stm_fs_stats_get(c->fs, &fs_stats);
        if (frc != STM_OK) {
            /* Wedged-OK posture: stm_fs_stats_get returns STM_OK with
             * the wedged flag set, so a non-OK here is a real backend
             * failure (alloc tree fault). Surface as STM_EBACKEND so
             * the caller can distinguish from a clean unattached fs. */
            return STM_EBACKEND;
        }
        stm_status drc = stm_fs_dataset_count(c->fs, &dataset_count);
        if (drc == STM_EWEDGED) {
            /* R110 P2-1: wedged-fs availability gap. stm_fs_dataset_count
             * uses FS_GUARD_READ which refuses on wedged fs, but
             * stm_fs_stats_get above is wedged-OK. The two adjacent
             * accessors disagree on wedged-readability. Treat
             * STM_EWEDGED specifically at this site so the rest of the
             * body can render — operators MUST be able to see
             * `stratum_pool_wedged{...} 1` in the wedged state, since
             * the gauge is the whole point of having wedged in the
             * exposition. dataset_count surfaces as 0; the wedged gauge
             * tells the operator why. Same wedged-OK doctrine as
             * /debug/allocator-state and /state. */
            dataset_count = 0;
        } else if (drc != STM_OK) {
            /* Real backend failure (not wedged): refuse the read rather
             * than emit partial metrics. */
            return STM_EBACKEND;
        }
    }

    /* Scrub status (optional). */
    bool have_scrub = (c->scrub != NULL);
    stm_scrub_status scrub_st;
    memset(&scrub_st, 0, sizeof scrub_st);
    if (have_scrub) {
        stm_status src = stm_scrub_status_get(c->scrub, &scrub_st);
        if (src != STM_OK) return STM_EBACKEND;
    }

    /* ── Format body ────────────────────────────────────────────── */
    uint8_t *buf = NULL;
    uint32_t cap = 0;
    uint32_t len = 0;
    stm_status rc;

#define P(...) do { \
    rc = prom_appendf(&buf, &cap, &len, __VA_ARGS__); \
    if (rc != STM_OK) goto fail; \
} while (0)

    /* fs gauges (when attached). */
    if (have_fs) {
        P("# HELP stratum_pool_data_total_blocks Total data-area blocks.\n"
          "# TYPE stratum_pool_data_total_blocks gauge\n"
          "stratum_pool_data_total_blocks{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)fs_stats.data_total_blocks);
        P("# HELP stratum_pool_data_allocated_blocks Allocated data-area blocks.\n"
          "# TYPE stratum_pool_data_allocated_blocks gauge\n"
          "stratum_pool_data_allocated_blocks{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)fs_stats.data_allocated_blocks);
        P("# HELP stratum_pool_data_free_blocks Free data-area blocks.\n"
          "# TYPE stratum_pool_data_free_blocks gauge\n"
          "stratum_pool_data_free_blocks{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)fs_stats.data_free_blocks);
        P("# HELP stratum_pool_data_pending_blocks Allocated-but-uncommitted blocks.\n"
          "# TYPE stratum_pool_data_pending_blocks gauge\n"
          "stratum_pool_data_pending_blocks{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)fs_stats.data_pending_blocks);
        P("# HELP stratum_pool_n_allocated_ranges Distinct allocated ranges.\n"
          "# TYPE stratum_pool_n_allocated_ranges gauge\n"
          "stratum_pool_n_allocated_ranges{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)fs_stats.n_allocated_ranges);
        P("# HELP stratum_pool_current_gen Pool transaction generation.\n"
          "# TYPE stratum_pool_current_gen counter\n"
          "stratum_pool_current_gen{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)fs_stats.current_gen);
        P("# HELP stratum_pool_read_only 1 if mounted read-only.\n"
          "# TYPE stratum_pool_read_only gauge\n"
          "stratum_pool_read_only{pool=\"%s\"} %d\n",
          pool_uuid_s, (int)fs_stats.read_only);
        P("# HELP stratum_pool_wedged 1 if wedged (read-only-after-error).\n"
          "# TYPE stratum_pool_wedged gauge\n"
          "stratum_pool_wedged{pool=\"%s\"} %d\n",
          pool_uuid_s, (int)fs_stats.wedged);
        P("# HELP stratum_pool_datasets_total Number of registered datasets.\n"
          "# TYPE stratum_pool_datasets_total gauge\n"
          "stratum_pool_datasets_total{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)dataset_count);
    }

    /* Pool roster gauges. Always emitted (pool attached is the
     * gate to reach this materializer). */
    P("# HELP stratum_pool_devices_total Total devices in roster (incl. removed).\n"
      "# TYPE stratum_pool_devices_total gauge\n"
      "stratum_pool_devices_total{pool=\"%s\"} %u\n",
      pool_uuid_s, (unsigned)sum.total);
    P("# HELP stratum_pool_devices_live Live (non-removed) devices.\n"
      "# TYPE stratum_pool_devices_live gauge\n"
      "stratum_pool_devices_live{pool=\"%s\"} %u\n",
      pool_uuid_s, (unsigned)sum.live);
    P("# HELP stratum_pool_size_bytes_total Total roster size (incl. removed).\n"
      "# TYPE stratum_pool_size_bytes_total gauge\n"
      "stratum_pool_size_bytes_total{pool=\"%s\"} %llu\n",
      pool_uuid_s, (unsigned long long)sum.total_size_bytes);
    P("# HELP stratum_pool_size_bytes_live Live (non-removed) roster size.\n"
      "# TYPE stratum_pool_size_bytes_live gauge\n"
      "stratum_pool_size_bytes_live{pool=\"%s\"} %llu\n",
      pool_uuid_s, (unsigned long long)sum.live_size_bytes);

    /* R110 P3-2: pin per-state/class/role iteration bounds against the
     * pool_summary array sizes (which themselves are pinned to the enum
     * cardinality at lines 814-819). The literal `7` / `5` / `5` below
     * MUST equal the array sizes; static_asserts trip at build time if
     * an enum extension (e.g., adding STM_DEV_STATE_NEW past EVACUATING)
     * raises the cardinality without the corresponding loop bump. The
     * line-1539-bounds-vs-line-814-array static_asserts pin the loop
     * vs the per_state[] / per_class[] / per_role[] iteration. */
    _Static_assert(STM_DEV_STATE_EVACUATING + 1 == 7,
                   "synfs.c metrics loop iterates per_state[] count; "
                   "extending stm_device_state past EVACUATING requires "
                   "bumping the loop literal in lockstep");
    _Static_assert(STM_DEV_CLASS_ZNS + 1 == 5,
                   "synfs.c metrics loop iterates per_class[] count");
    _Static_assert(STM_DEV_ROLE_SPARE + 1 == 5,
                   "synfs.c metrics loop iterates per_role[] count");
    P("# HELP stratum_pool_devices_by_state Per-state device counts.\n"
      "# TYPE stratum_pool_devices_by_state gauge\n");
    for (uint8_t st = 0; st < 7; st++) {
        P("stratum_pool_devices_by_state{pool=\"%s\",state=\"%s\"} %u\n",
          pool_uuid_s, device_state_name((stm_device_state)st),
          (unsigned)sum.per_state[st]);
    }
    P("# HELP stratum_pool_devices_by_class Per-class device counts.\n"
      "# TYPE stratum_pool_devices_by_class gauge\n");
    for (uint8_t cls = 0; cls < 5; cls++) {
        P("stratum_pool_devices_by_class{pool=\"%s\",class=\"%s\"} %u\n",
          pool_uuid_s, device_class_name((stm_device_class)cls),
          (unsigned)sum.per_class[cls]);
    }
    P("# HELP stratum_pool_devices_by_role Per-role device counts.\n"
      "# TYPE stratum_pool_devices_by_role gauge\n");
    for (uint8_t r = 0; r < 5; r++) {
        P("stratum_pool_devices_by_role{pool=\"%s\",role=\"%s\"} %u\n",
          pool_uuid_s, device_role_name((stm_device_role)r),
          (unsigned)sum.per_role[r]);
    }

    /* Per-device records. */
    if (n_devs > 0) {
        P("# HELP stratum_device_size_bytes Per-device size.\n"
          "# TYPE stratum_device_size_bytes gauge\n");
        for (size_t i = 0; i < n_devs; i++) {
            char dev_uuid_s[UUID_HEX_LEN + 1];
            uuid_format_hex(devs[i].uuid, dev_uuid_s);
            P("stratum_device_size_bytes{pool=\"%s\",device=\"%s\"} %llu\n",
              pool_uuid_s, dev_uuid_s,
              (unsigned long long)devs[i].size_bytes);
        }
        P("# HELP stratum_device_info Per-device metadata; value always 1.\n"
          "# TYPE stratum_device_info gauge\n");
        for (size_t i = 0; i < n_devs; i++) {
            char dev_uuid_s[UUID_HEX_LEN + 1];
            uuid_format_hex(devs[i].uuid, dev_uuid_s);
            P("stratum_device_info{pool=\"%s\",device=\"%s\","
              "device_id=\"%u\",class=\"%s\",role=\"%s\",state=\"%s\"} 1\n",
              pool_uuid_s, dev_uuid_s, (unsigned)devs[i].device_id,
              device_class_name(devs[i].class_),
              device_role_name(devs[i].role),
              device_state_name(devs[i].state));
        }
    }

    /* Scrub gauges + counters (optional). */
    if (have_scrub) {
        P("# HELP stratum_scrub_state Scrub state (1 = active state).\n"
          "# TYPE stratum_scrub_state gauge\n");
        static const stm_scrub_state STATES[] = {
            STM_SCRUB_STATE_IDLE,    STM_SCRUB_STATE_RUNNING,
            STM_SCRUB_STATE_PAUSED,  STM_SCRUB_STATE_COMPLETED,
        };
        for (size_t i = 0; i < sizeof STATES / sizeof STATES[0]; i++) {
            P("stratum_scrub_state{pool=\"%s\",state=\"%s\"} %d\n",
              pool_uuid_s, scrub_state_name(STATES[i]),
              (int)(scrub_st.state == STATES[i]));
        }
        P("# HELP stratum_scrub_blocks_verified Blocks successfully verified.\n"
          "# TYPE stratum_scrub_blocks_verified counter\n"
          "stratum_scrub_blocks_verified{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)scrub_st.blocks_verified);
        P("# HELP stratum_scrub_blocks_failed Blocks failing verification.\n"
          "# TYPE stratum_scrub_blocks_failed counter\n"
          "stratum_scrub_blocks_failed{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)scrub_st.blocks_failed);
        P("# HELP stratum_scrub_blocks_repaired Blocks repaired after failure.\n"
          "# TYPE stratum_scrub_blocks_repaired counter\n"
          "stratum_scrub_blocks_repaired{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)scrub_st.blocks_repaired);
        P("# HELP stratum_scrub_blocks_unrepairable Failed blocks that could not be repaired.\n"
          "# TYPE stratum_scrub_blocks_unrepairable counter\n"
          "stratum_scrub_blocks_unrepairable{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)scrub_st.blocks_unrepairable);
        P("# HELP stratum_scrub_ranges_processed Allocated ranges processed.\n"
          "# TYPE stratum_scrub_ranges_processed counter\n"
          "stratum_scrub_ranges_processed{pool=\"%s\"} %llu\n",
          pool_uuid_s, (unsigned long long)scrub_st.ranges_processed);
    }

#undef P

    /* Hand the buffer to the session; vops_clunk frees. */
    s->bulk_buf = buf;
    s->bulk_len = len;
    return STM_OK;

fail:
    free(buf);
    return rc;
}

static stm_status materialize_locked(stm_ctl *c, ctl_session *s)
{
    switch (qid_kind(s->qid_path)) {
    case KIND_VERSION:            return materialize_version(c, s);
    case KIND_STATE:              return materialize_state(c, s);
    case KIND_POOL_STATUS:        return materialize_pool_status(c, s);
    case KIND_DEVICE_STATUS:      return materialize_device_status(c, s);
    case KIND_DATASET_PROPERTIES: return materialize_dataset_properties(c, s);
    case KIND_ADMIN_PEER:         return materialize_admin_peer(c, s);
    case KIND_DEBUG_ALLOC:        return materialize_debug_alloc(c, s);
    case KIND_POOL_SCRUB:         return materialize_pool_scrub(c, s);
    case KIND_POOL_METRICS_PROMETHEUS:
        return materialize_pool_metrics_prometheus(c, s);
    case KIND_ROOT:
    case KIND_POOLS_DIR:
    case KIND_POOL_DIR:
    case KIND_DEVICES_DIR:
    case KIND_DEVICE_DIR:
    case KIND_DATASETS_DIR:
    case KIND_DATASET_DIR:
    case KIND_ADMIN_DIR:
    case KIND_DEBUG_DIR:
    case KIND_DEBUG_ALLOC_DIR:
    case KIND_POOL_METRICS_DIR:       /* dir; no body */
    case KIND_EVENTS:                 /* served direct from event_buf */
    case KIND_ADMIN_CLEAR_EVENTS:     /* write-only; no body to materialize */
    case KIND_POOL_SCRUB_TRIGGER:     /* write-only; no body to materialize */
    case KIND_DATASET_CREATE_SNAPSHOT:/* write-only; no body to materialize */
    case KIND_DATASET_DELETE_SNAPSHOT:/* write-only; no body to materialize */
    case KIND_DATASET_HOLD_SNAPSHOT:  /* write-only; no body to materialize */
    case KIND_DATASET_RELEASE_SNAPSHOT:/* write-only; no body to materialize */
    case KIND_MAX:
        break;
    }
    /* Should not happen — open gates body files only. */
    return STM_EBACKEND;
}

/* ── getattr / walk / readdir ───────────────────────────────────────── */

/* POSIX file-type mode bits applied alongside KIND_META[].mode. */
#define CTL_S_IFDIR   0040000u
#define CTL_S_IFREG   0100000u

static void set_dirent_name(stm_lp9_dirent *out, const char *name,
                              size_t name_len)
{
    if (name_len > STM_LP9_NAME_MAX) name_len = STM_LP9_NAME_MAX;
    memcpy(out->name, name, name_len);
    out->name[name_len] = '\0';
    out->name_len = (uint16_t)name_len;
}

/* Fill `out` for a node with the given qid_path. The .L attr is
 * statx-shaped — fields the backend doesn't track (uid/gid/atime/
 * mtime/ctime/btime/blocks/blksize/rdev/gen/data_version) stay zero;
 * the materializer can set additional fields later. The `dyn_name` /
 * `dyn_name_len` outputs (when non-NULL) carry the synthetic name
 * for use by the readdir caller — getattr's wire reply has no name
 * field (names appear only in Twalk + Treaddir). */
static stm_status getattr_at(stm_ctl *c, uint64_t qid_path,
                               stm_lp9_attr *out,
                               char *out_dyn_name, size_t *out_dyn_len)
{
    ctl_kind k = qid_kind(qid_path);
    if (k == KIND_MAX) return STM_ENOENT;
    const ctl_kind_meta *meta = &KIND_META[k];

    /* Dynamic-named kinds: validate the dynamic context exists. */
    char dyn_name[UUID_HEX_LEN + 1];
    const char *name = meta->static_name;
    size_t name_len = name ? strlen(name) : 0;

    /* Pool-related kinds: pool_idx must be 0 (single-pool v2.0). */
    if (k == KIND_POOLS_DIR || k == KIND_POOL_DIR
        || k == KIND_POOL_STATUS || k == KIND_DEVICES_DIR
        || k == KIND_DEVICE_DIR || k == KIND_DEVICE_STATUS
        || k == KIND_POOL_SCRUB || k == KIND_POOL_SCRUB_TRIGGER
        || k == KIND_POOL_METRICS_DIR || k == KIND_POOL_METRICS_PROMETHEUS) {
        if (qid_pool_idx(qid_path) != 0) return STM_ENOENT;
    }

    if (k == KIND_POOL_DIR) {
        uint8_t uuid_b[16];
        if (!ctl_pool_uuid_bytes(c, uuid_b)) return STM_ENOENT;
        uuid_format_hex(uuid_b, dyn_name);
        name = dyn_name;
        name_len = UUID_HEX_LEN;
    }
    if ((k == KIND_POOL_STATUS || k == KIND_DEVICES_DIR) && !c->pool) {
        return STM_ENOENT;
    }
    /* /pools/<uuid>/metrics/ + /metrics/prometheus exist iff a pool is
     * attached. World-readable (mode 0444 / 0555) — no admin gate. The
     * fs/scrub attachments are optional; the materializer adapts the
     * body shape to what's available. */
    if ((k == KIND_POOL_METRICS_DIR || k == KIND_POOL_METRICS_PROMETHEUS)
            && !c->pool)
        return STM_ENOENT;
    /* /pools/<uuid>/scrub requires (a) pool attached (so the dir
     * exists) AND (b) scrub attached (so we have a handle to query).
     * A pool-attached-but-no-scrub state surfaces as "scrub file
     * doesn't exist," matching the operator's intuition: "no scrub
     * configured = no scrub file." Same gate for the trigger file:
     * without a scrub handle there's nothing to dispatch to, so
     * the trigger doesn't exist either. */
    if ((k == KIND_POOL_SCRUB || k == KIND_POOL_SCRUB_TRIGGER)
            && (!c->pool || !c->scrub))
        return STM_ENOENT;
    if (k == KIND_DEVICE_DIR || k == KIND_DEVICE_STATUS) {
        if (!c->pool) return STM_ENOENT;
        uint32_t did = qid_device_id(qid_path);
        stm_pool_lock_shared(c->pool);
        size_t total = stm_pool_device_count(c->pool);
        /* R98 P2-1 / P3-5: see materialize_device_status. The `d ==
         * NULL` check below is unreachable for in-bounds ids today
         * (REMOVED slots persist with non-NULL info). Defense-in-
         * depth against future pool semantics. */
        const stm_pool_device *d =
            (did < total) ? stm_pool_device_info(c->pool, (uint16_t)did) : NULL;
        bool valid = (d != NULL);
        stm_pool_unlock_shared(c->pool);
        if (!valid) return STM_ENOENT;
        if (k == KIND_DEVICE_DIR) {
            /* R98 P3-1: device id formats as decimal up to 2 chars
             * at v2.0's STM_POOL_DEVICES_MAX = 64 (max id 63). The
             * 37-byte dyn_name buffer (sized for the 36-char UUID
             * case) has comfortable headroom. */
            int n = snprintf(dyn_name, sizeof dyn_name, "%u", (unsigned)did);
            if (n < 0 || n >= (int)sizeof dyn_name) return STM_EIO;
            name = dyn_name;
            name_len = (size_t)n;
        }
    }

    /* KIND_DATASETS_DIR is always accessible (just empty when fs is
     * unattached), matching the /pools/ posture. The fs check lives
     * on the per-dataset kinds below. */
    if (k == KIND_DATASET_DIR || k == KIND_DATASET_PROPERTIES
            || k == KIND_DATASET_CREATE_SNAPSHOT
            || k == KIND_DATASET_DELETE_SNAPSHOT
            || k == KIND_DATASET_HOLD_SNAPSHOT
            || k == KIND_DATASET_RELEASE_SNAPSHOT) {
        if (!c->fs) return STM_ENOENT;
        uint64_t dsid = qid_dataset_id(qid_path);
        /* Validate the dataset is PRESENT (i.e. not destroyed).
         * stm_fs_dataset_lookup takes fs->lock briefly. R98 P2-1
         * lesson: dataset_destroy IS supported, so this gate is
         * load-bearing — STM_ENOENT here is a real "this id was
         * destroyed" signal, not defense-in-depth. */
        stm_dataset_entry tmp;
        stm_status drc = stm_fs_dataset_lookup(c->fs, dsid, &tmp);
        if (drc != STM_OK) return drc;
        if (k == KIND_DATASET_DIR) {
            int n = snprintf(dyn_name, sizeof dyn_name, "%llu",
                              (unsigned long long)dsid);
            if (n < 0 || n >= (int)sizeof dyn_name) return STM_EIO;
            name = dyn_name;
            name_len = (size_t)n;
        }
    }

    /* /debug/ subtree (P9-CTL-1d-debug). KIND_DEBUG_DIR itself is
     * always-stat-able at the root readdir level (mode 0500 conveys
     * "admin-only"); the walk-through gate at vops_walk fires on
     * non-admin traversal — same R100 P2-1 posture as /admin/.
     * The KIND_DEBUG_ALLOC_DIR + KIND_DEBUG_ALLOC kinds require fs
     * for any meaningful answer; without fs they ENOENT. */
    if (k == KIND_DEBUG_ALLOC_DIR && !c->fs) return STM_ENOENT;
    if (k == KIND_DEBUG_ALLOC) {
        if (!c->fs) return STM_ENOENT;
        /* R102 P3-1: use the cheap is-attached predicate, NOT the
         * full stats_get tree-scan, since getattr_at runs once per
         * emit_entry in the readdir loop (64× per readdir). The
         * range-check is inside stm_fs_alloc_attached (STM_EINVAL on
         * device_id ≥ STM_POOL_DEVICES_MAX); we treat that as
         * ENOENT at the synfs boundary so wire ops see "no such
         * file" not "invalid argument" for an out-of-range id. */
        uint32_t did = qid_device_id(qid_path);
        if (did >= STM_POOL_DEVICES_MAX) return STM_ENOENT;
        bool attached = false;
        stm_status arc = stm_fs_alloc_attached(c->fs, (uint16_t)did, &attached);
        if (arc != STM_OK || !attached) return STM_ENOENT;
        int n = snprintf(dyn_name, sizeof dyn_name, "%u", (unsigned)did);
        if (n < 0 || n >= (int)sizeof dyn_name) return STM_EIO;
        name = dyn_name;
        name_len = (size_t)n;
    }

    memset(out, 0, sizeof *out);
    out->qid.path = qid_path;
    out->valid    = STM_LP9_GETATTR_BASIC;
    out->nlink    = 1;
    if (meta->is_dir) {
        out->qid.qtype = STM_LP9_QTDIR;
        out->mode      = CTL_S_IFDIR | meta->mode;
    } else {
        out->qid.qtype = STM_LP9_QTFILE;
        out->mode      = CTL_S_IFREG | meta->mode;
        /* `size` is reported as 0 for synthetic files: the actual
         * body is materialized at Tlopen and the FS doesn't know its
         * size in advance. Standard 9P pattern (see /proc on Linux);
         * clients read until EOF. */
    }
    if (out_dyn_name && out_dyn_len) {
        if (name_len > UUID_HEX_LEN) name_len = UUID_HEX_LEN;
        memcpy(out_dyn_name, name, name_len);
        out_dyn_name[name_len] = '\0';
        *out_dyn_len = name_len;
    }
    return STM_OK;
}

static stm_status vops_getattr(void *ctx, uint64_t qid_path,
                                 uint64_t request_mask, stm_lp9_attr *out)
{
    (void)request_mask;     /* v1.0 always returns BASIC fields */
    return getattr_at(ctx, qid_path, out, NULL, NULL);
}

/* vops_walk helper: getattr_at → extract qid only. The existence
 * gates (pool/scrub/fs attached, dataset PRESENT, device in roster,
 * etc.) all fire inside getattr_at; the caller wants just the qid. */
static stm_status walk_to_qid(stm_ctl *c, uint64_t qid_path,
                                stm_lp9_qid *out)
{
    stm_lp9_attr a;
    stm_status rc = getattr_at(c, qid_path, &a, NULL, NULL);
    if (rc != STM_OK) return rc;
    *out = a.qid;
    return STM_OK;
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
    stm_ctl *c = ctx;
    ctl_kind dk = qid_kind(dir_qid_path);
    switch (dk) {
    case KIND_ROOT:
        if (str_eq(name, name_len, KIND_META[KIND_VERSION].static_name))
            return walk_to_qid(c, qid_root(KIND_VERSION), out);
        if (str_eq(name, name_len, KIND_META[KIND_STATE].static_name))
            return walk_to_qid(c, qid_root(KIND_STATE), out);
        if (str_eq(name, name_len, KIND_META[KIND_POOLS_DIR].static_name))
            return walk_to_qid(c, qid_root(KIND_POOLS_DIR), out);
        if (str_eq(name, name_len, KIND_META[KIND_DATASETS_DIR].static_name))
            return walk_to_qid(c, qid_root(KIND_DATASETS_DIR), out);
        if (str_eq(name, name_len, KIND_META[KIND_ADMIN_DIR].static_name))
            return walk_to_qid(c, qid_root(KIND_ADMIN_DIR), out);
        if (str_eq(name, name_len, KIND_META[KIND_EVENTS].static_name))
            return walk_to_qid(c, qid_root(KIND_EVENTS), out);
        if (str_eq(name, name_len, KIND_META[KIND_DEBUG_DIR].static_name))
            return walk_to_qid(c, qid_root(KIND_DEBUG_DIR), out);
        return STM_ENOENT;

    case KIND_POOLS_DIR: {
        uint8_t uuid_b[16];
        if (!ctl_pool_uuid_bytes(c, uuid_b)) return STM_ENOENT;
        uint8_t want[16];
        if (uuid_parse_hex(name, name_len, want) != 0) return STM_ENOENT;
        if (!uuid_eq(uuid_b, want)) return STM_ENOENT;
        return walk_to_qid(c, qid_root(KIND_POOL_DIR), out);
    }

    case KIND_POOL_DIR:
        if (!c->pool) return STM_ENOENT;
        if (str_eq(name, name_len, KIND_META[KIND_POOL_STATUS].static_name))
            return walk_to_qid(c, qid_root(KIND_POOL_STATUS), out);
        if (str_eq(name, name_len, KIND_META[KIND_DEVICES_DIR].static_name))
            return walk_to_qid(c, qid_root(KIND_DEVICES_DIR), out);
        /* /pools/<uuid>/scrub is conditional on c->scrub attachment.
         * If the scrub handle isn't attached, the file simply
         * doesn't exist (Twalk fails, readdir omits it). Once
         * attached, world-readable. */
        if (c->scrub
              && str_eq(name, name_len, KIND_META[KIND_POOL_SCRUB].static_name))
            return walk_to_qid(c, qid_root(KIND_POOL_SCRUB), out);
        /* /pools/<uuid>/scrub-trigger paired with the scrub-read
         * surface. Same conditional-dirent posture (R103 P3-2 carry):
         * exists iff scrub handle attached. The admin gate fires at
         * vops_lopen's meta->admin_required check; one-step Twalk
         * succeeds for any caller (POSIX `stat` against an admin-
         * only file is allowed — only open is gated). */
        if (c->scrub
              && str_eq(name, name_len,
                          KIND_META[KIND_POOL_SCRUB_TRIGGER].static_name))
            return walk_to_qid(c, qid_root(KIND_POOL_SCRUB_TRIGGER), out);
        /* /pools/<uuid>/metrics/ exists unconditionally when c->pool
         * is attached — fs/scrub attachments shape the body content
         * but don't gate the dirent. World-readable observability. */
        if (str_eq(name, name_len,
                     KIND_META[KIND_POOL_METRICS_DIR].static_name))
            return walk_to_qid(c, qid_root(KIND_POOL_METRICS_DIR), out);
        return STM_ENOENT;

    case KIND_POOL_METRICS_DIR:
        /* P9-CTL-1e: /pools/<uuid>/metrics/ children — only
         * "prometheus" today; OTLP exposition deferred. */
        if (!c->pool) return STM_ENOENT;
        if (str_eq(name, name_len,
                     KIND_META[KIND_POOL_METRICS_PROMETHEUS].static_name))
            return walk_to_qid(c, qid_root(KIND_POOL_METRICS_PROMETHEUS), out);
        return STM_ENOENT;

    case KIND_DEVICES_DIR: {
        if (!c->pool) return STM_ENOENT;
        uint16_t did = 0;
        if (parse_device_id(name, name_len, &did) != 0) return STM_ENOENT;
        return walk_to_qid(c, qid_of(KIND_DEVICE_DIR, 0, did), out);
    }

    case KIND_DEVICE_DIR: {
        if (!c->pool) return STM_ENOENT;
        if (!str_eq(name, name_len, KIND_META[KIND_DEVICE_STATUS].static_name))
            return STM_ENOENT;
        uint32_t did = qid_device_id(dir_qid_path);
        return walk_to_qid(c, qid_of(KIND_DEVICE_STATUS, 0, did), out);
    }

    case KIND_DATASETS_DIR: {
        if (!c->fs) return STM_ENOENT;
        uint64_t dsid = 0;
        if (parse_dataset_id(name, name_len, &dsid) != 0) return STM_ENOENT;
        return walk_to_qid(c, qid_of(KIND_DATASET_DIR, 0, (uint32_t)dsid), out);
    }

    case KIND_DATASET_DIR: {
        if (!c->fs) return STM_ENOENT;
        uint64_t dsid = qid_dataset_id(dir_qid_path);
        if (str_eq(name, name_len,
                     KIND_META[KIND_DATASET_PROPERTIES].static_name))
            return walk_to_qid(c,
                qid_of(KIND_DATASET_PROPERTIES, 0, (uint32_t)dsid), out);
        if (str_eq(name, name_len,
                     KIND_META[KIND_DATASET_CREATE_SNAPSHOT].static_name))
            return walk_to_qid(c,
                qid_of(KIND_DATASET_CREATE_SNAPSHOT, 0, (uint32_t)dsid), out);
        if (str_eq(name, name_len,
                     KIND_META[KIND_DATASET_DELETE_SNAPSHOT].static_name))
            return walk_to_qid(c,
                qid_of(KIND_DATASET_DELETE_SNAPSHOT, 0, (uint32_t)dsid), out);
        if (str_eq(name, name_len,
                     KIND_META[KIND_DATASET_HOLD_SNAPSHOT].static_name))
            return walk_to_qid(c,
                qid_of(KIND_DATASET_HOLD_SNAPSHOT, 0, (uint32_t)dsid), out);
        if (str_eq(name, name_len,
                     KIND_META[KIND_DATASET_RELEASE_SNAPSHOT].static_name))
            return walk_to_qid(c,
                qid_of(KIND_DATASET_RELEASE_SNAPSHOT, 0, (uint32_t)dsid), out);
        return STM_ENOENT;
    }

    case KIND_ADMIN_DIR:
        /* R100 P2-1: gate walk-THROUGH /admin/ for non-admin callers
         * so children's qids never leak. Without this gate, a non-
         * admin could Twalk(root, "admin", "peer") successfully —
         * step 0 binds /admin/'s qid (correct, matches POSIX
         * `stat /admin` for mode-0500 dirs), step 1 binds
         * /admin/peer's qid (LEAK — POSIX `stat /admin/peer` for a
         * non-admin would fail with EACCES on the parent traversal,
         * never revealing the file's metadata). The non-admin would
         * then Tgetattr the bound fid to read mode=0400 + qid_type. We
         * use STM_ENOENT (not STM_EACCES) so the wire response is
         * indistinguishable from "/admin/no_such_file" — the
         * documented "POSIX-mode-0500-dir" posture. The /admin/
         * dirent at root readdir remains visible (emit_entry calls
         * getattr_at, not vops_walk; readdir doesn't traverse). */
        if (!ctl_caller_is_admin(c)) return STM_ENOENT;
        if (str_eq(name, name_len, KIND_META[KIND_ADMIN_PEER].static_name))
            return walk_to_qid(c, qid_root(KIND_ADMIN_PEER), out);
        if (str_eq(name, name_len,
                     KIND_META[KIND_ADMIN_CLEAR_EVENTS].static_name))
            return walk_to_qid(c, qid_root(KIND_ADMIN_CLEAR_EVENTS), out);
        return STM_ENOENT;

    case KIND_DEBUG_DIR:
        /* R100 P2-1 posture (carried for the second admin-only dir
         * tree): walk-through /debug/ refuses non-admin with ENOENT
         * so child qid metadata never leaks. The single child today
         * is /debug/allocator-state/. /debug/ itself remains visible
         * at root readdir (mode 0500 conveys "admin-only" without
         * leaking children). Future /debug/{tree-walk, extent-map,
         * integrity-verify} sub-chunks add new walk targets here. */
        if (!ctl_caller_is_admin(c)) return STM_ENOENT;
        if (str_eq(name, name_len, KIND_META[KIND_DEBUG_ALLOC_DIR].static_name))
            return walk_to_qid(c, qid_root(KIND_DEBUG_ALLOC_DIR), out);
        return STM_ENOENT;

    case KIND_DEBUG_ALLOC_DIR: {
        /* Defense-in-depth admin re-check — primary gate at
         * KIND_DEBUG_DIR walk-through above already fired. */
        if (!ctl_caller_is_admin(c)) return STM_ENOENT;
        if (!c->fs) return STM_ENOENT;
        uint16_t did = 0;
        if (parse_device_id(name, name_len, &did) != 0) return STM_ENOENT;
        return walk_to_qid(c, qid_of(KIND_DEBUG_ALLOC, 0, did), out);
    }

    case KIND_VERSION:
    case KIND_STATE:
    case KIND_POOL_STATUS:
    case KIND_DEVICE_STATUS:
    case KIND_DATASET_PROPERTIES:
    case KIND_ADMIN_PEER:
    case KIND_EVENTS:
    case KIND_ADMIN_CLEAR_EVENTS:
    case KIND_DEBUG_ALLOC:
    case KIND_POOL_SCRUB:
    case KIND_POOL_SCRUB_TRIGGER:
    case KIND_DATASET_CREATE_SNAPSHOT:
    case KIND_DATASET_DELETE_SNAPSHOT:
    case KIND_DATASET_HOLD_SNAPSHOT:
    case KIND_DATASET_RELEASE_SNAPSHOT:
    case KIND_POOL_METRICS_PROMETHEUS:
    case KIND_MAX:
        break;
    }
    return STM_ENOENT;
}

/*
 * Cookie pagination helper. Each Treaddir invocation builds a fresh
 * `readdir_emit` and walks the directory's children, calling
 * emit_entry per candidate. emit_entry consults getattr_at to
 * existence-validate, then either:
 *   (a) returns STM_ENOENT → caller's `continue` skips this slot
 *       (existing race-skip semantics in /datasets/, /devices/);
 *   (b) skips silently because the candidate's position is at-or-
 *       before the client-supplied cookie cursor;
 *   (c) emits a stm_lp9_dirent with cookie = position+1.
 *
 * Position counter advances ONLY for entries that pass existence-
 * validation; STM_ENOENT slots don't consume a cookie. That keeps
 * the cookie sequence dense over actually-emittable entries, which
 * is what v9fs-Linux clients observe (and which makes the
 * "Treaddir(offset=N) skips first N entries" contract straightforward).
 */
typedef struct {
    uint64_t          offset;       /* cursor — Treaddir's `offset` */
    uint64_t          pos;          /* entries existence-confirmed so far */
    stm_lp9_dirent_cb cb;
    void             *cb_ctx;
} readdir_emit;

static stm_status emit_entry(stm_ctl *c, readdir_emit *em,
                               uint64_t qid_path)
{
    stm_lp9_attr a;
    char dyn_name[UUID_HEX_LEN + 1];
    size_t dyn_len = 0;
    stm_status rc = getattr_at(c, qid_path, &a, dyn_name, &dyn_len);
    if (rc != STM_OK) return rc;

    uint64_t this_cookie = ++em->pos;
    if (this_cookie <= em->offset) return STM_OK;     /* before cursor */

    stm_lp9_dirent e;
    memset(&e, 0, sizeof e);
    e.qid     = a.qid;
    e.cookie  = this_cookie;
    /* dt_type: DT_DIR=4 for dirs, DT_REG=8 for files. /ctl/ has no
     * symlinks, sockets, devices, or pipes. */
    e.dt_type = (a.qid.qtype & STM_LP9_QTDIR) ? 4u : 8u;
    set_dirent_name(&e, dyn_name, dyn_len);
    return em->cb(&e, em->cb_ctx);
}

static stm_status vops_readdir(void *ctx, uint64_t dir_qid_path,
                                 uint64_t cookie_start,
                                 stm_lp9_dirent_cb cb, void *cb_ctx)
{
    stm_ctl *c = ctx;
    ctl_kind dk = qid_kind(dir_qid_path);
    readdir_emit em = { .offset = cookie_start, .pos = 0, .cb = cb,
                          .cb_ctx = cb_ctx };
    stm_status rc;
    switch (dk) {
    case KIND_ROOT:
        rc = emit_entry(c, &em, qid_root(KIND_VERSION));
        if (rc != STM_OK) return rc;
        rc = emit_entry(c, &em, qid_root(KIND_STATE));
        if (rc != STM_OK) return rc;
        rc = emit_entry(c, &em, qid_root(KIND_POOLS_DIR));
        if (rc != STM_OK) return rc;
        /* /datasets/ is always listed (matches /pools/ posture):
         * the directory exists even when c->fs is unattached;
         * readdir simply returns empty. R99 P3-1 — earlier comment
         * here contradicted the code; rewritten to reflect the
         * actual always-listed semantics. */
        rc = emit_entry(c, &em, qid_root(KIND_DATASETS_DIR));
        if (rc != STM_OK) return rc;
        /* /admin/ is always-listed at the dir level (mode 0500
         * conveys "admin-only"; non-admin readdir of root SEES the
         * /admin dirent but Tlopen on it returns EACCES). Same
         * posture as POSIX root + 0500 dir: existence is visible,
         * contents aren't. */
        rc = emit_entry(c, &em, qid_root(KIND_ADMIN_DIR));
        if (rc != STM_OK) return rc;
        /* /events is world-readable (mode 0444) — any caller can
         * tail-read the operational event log. Admin-only write
         * trigger (clear-events) lives under /admin/. */
        rc = emit_entry(c, &em, qid_root(KIND_EVENTS));
        if (rc != STM_OK) return rc;
        /* /debug/ is always-listed at the root level (mode 0500
         * conveys "admin-only"; non-admin readdir-of-root SEES the
         * /debug dirent but Twalk-through and Tlopen both refuse
         * with ENOENT/EACCES). Same posture as /admin/. */
        return emit_entry(c, &em, qid_root(KIND_DEBUG_DIR));

    case KIND_POOLS_DIR:
        /* Enumerate registered pools. v2.0: at most one pool. */
        if (!c->pool) return STM_OK;
        return emit_entry(c, &em, qid_root(KIND_POOL_DIR));

    case KIND_POOL_DIR:
        if (!c->pool) return STM_ENOENT;
        rc = emit_entry(c, &em, qid_root(KIND_POOL_STATUS));
        if (rc != STM_OK) return rc;
        rc = emit_entry(c, &em, qid_root(KIND_DEVICES_DIR));
        if (rc != STM_OK) return rc;
        /* Conditional: scrub entry only emitted when a scrub handle
         * is attached. Mirrors the getattr_at gate so readdir + Twalk
         * are consistent — the entry isn't visible without a scrub.
         * The trigger entry pairs with the read entry (same scrub-
         * attached gate) — admin-only file (mode 0200) but visible
         * in readdir to non-admin per POSIX semantics; Tgetattr shows
         * mode 0200, only Tlopen+Twrite gate on admin. */
        if (c->scrub) {
            rc = emit_entry(c, &em, qid_root(KIND_POOL_SCRUB));
            if (rc != STM_OK) return rc;
            rc = emit_entry(c, &em, qid_root(KIND_POOL_SCRUB_TRIGGER));
            if (rc != STM_OK) return rc;
        }
        /* /pools/<uuid>/metrics/ is unconditional — observability is
         * always offered. Body content adapts to fs/scrub attachment;
         * see materialize_pool_metrics_prometheus. */
        return emit_entry(c, &em, qid_root(KIND_POOL_METRICS_DIR));

    case KIND_POOL_METRICS_DIR:
        /* /pools/<uuid>/metrics/ — single child today. Future
         * sub-chunks add /metrics/opentelemetry (OTLP exposition). */
        if (!c->pool) return STM_ENOENT;
        return emit_entry(c, &em, qid_root(KIND_POOL_METRICS_PROMETHEUS));

    case KIND_DEVICES_DIR: {
        if (!c->pool) return STM_ENOENT;
        stm_pool_lock_shared(c->pool);
        size_t total = stm_pool_device_count(c->pool);
        stm_pool_unlock_shared(c->pool);
        /* R98 P2-1: stm_pool_device_count is monotonic-non-decreasing
         * (only stm_pool_add_device increments; finish_evacuation
         * marks slots REMOVED but never decrements count). So
         * `total` captured here remains a valid upper bound for the
         * for-loop, and every `i < total` is a live in-bounds slot
         * for the duration of the iteration. REMOVED slots persist
         * in the roster and surface with state="removed" via
         * materialize_device_status — by design (R16 F3 burned-UUID
         * audit trail). The continue-on-STM_ENOENT below is
         * defense-in-depth for a future pool-layer change that
         * decrements count or returns NULL for in-bounds slots; not
         * exercised today. */
        for (size_t i = 0; i < total; i++) {
            stm_status erc = emit_entry(c, &em,
                qid_of(KIND_DEVICE_DIR, 0, (uint32_t)i));
            if (erc == STM_ENOENT) continue;
            if (erc != STM_OK) return erc;
        }
        return STM_OK;
    }

    case KIND_DEVICE_DIR: {
        if (!c->pool) return STM_ENOENT;
        uint32_t did = qid_device_id(dir_qid_path);
        return emit_entry(c, &em, qid_of(KIND_DEVICE_STATUS, 0, did));
    }

    case KIND_DATASETS_DIR: {
        /* If no fs attached, the directory is empty. */
        if (!c->fs) return STM_OK;
        /* Collect ids via stm_fs_dataset_iter (which holds fs->lock
         * for the duration), then emit_entry per id AFTER releasing
         * the lock. emit_entry → getattr_at → stm_fs_dataset_lookup
         * re-acquires fs->lock; doing this from inside the iter
         * callback would deadlock.
         *
         * R98 P2-1 lesson applied correctly: dataset_destroy IS
         * supported, so dataset_count is NOT monotonic and ids
         * are sparse. We can't iterate by id from 0 to count — must
         * use the iter API.
         *
         * The window between collect and emit allows a destroy to
         * happen, in which case getattr_at returns STM_ENOENT for that
         * id; we treat as "skip and continue" — REAL race-skip,
         * unlike /pools/devices/ where the equivalent is dead code. */
        uint64_t collected[STM_CTL_DATASET_LIST_CAP];
        size_t n_collected = 0;
        ds_collect_ctx collect_ctx = {
            .out = collected,
            .n = &n_collected,
            .cap = STM_CTL_DATASET_LIST_CAP,
        };
        rc = stm_fs_dataset_iter(c->fs, ds_collect_cb, &collect_ctx);
        if (rc != STM_OK) return rc;
        for (size_t i = 0; i < n_collected; i++) {
            stm_status erc = emit_entry(c, &em,
                qid_of(KIND_DATASET_DIR, 0, (uint32_t)collected[i]));
            if (erc == STM_ENOENT) continue;   /* destroyed mid-readdir */
            if (erc != STM_OK) return erc;
        }
        return STM_OK;
    }

    case KIND_DATASET_DIR: {
        if (!c->fs) return STM_ENOENT;
        uint64_t dsid = qid_dataset_id(dir_qid_path);
        rc = emit_entry(c, &em,
            qid_of(KIND_DATASET_PROPERTIES, 0, (uint32_t)dsid));
        if (rc != STM_OK) return rc;
        /* The trigger entries are admin-only (mode 0200) but visible
         * in readdir to non-admin per POSIX semantics — Tgetattr shows
         * mode 0200; only Tlopen+Twrite gate on admin. Same posture
         * as /pools/<uuid>/scrub-trigger. */
        rc = emit_entry(c, &em,
            qid_of(KIND_DATASET_CREATE_SNAPSHOT, 0, (uint32_t)dsid));
        if (rc != STM_OK) return rc;
        rc = emit_entry(c, &em,
            qid_of(KIND_DATASET_DELETE_SNAPSHOT, 0, (uint32_t)dsid));
        if (rc != STM_OK) return rc;
        rc = emit_entry(c, &em,
            qid_of(KIND_DATASET_HOLD_SNAPSHOT, 0, (uint32_t)dsid));
        if (rc != STM_OK) return rc;
        return emit_entry(c, &em,
            qid_of(KIND_DATASET_RELEASE_SNAPSHOT, 0, (uint32_t)dsid));
    }

    case KIND_ADMIN_DIR:
        rc = emit_entry(c, &em, qid_root(KIND_ADMIN_PEER));
        if (rc != STM_OK) return rc;
        return emit_entry(c, &em, qid_root(KIND_ADMIN_CLEAR_EVENTS));

    case KIND_DEBUG_DIR:
        /* /debug/ readdir doesn't gate on admin — vops_lopen already
         * gated at the dir-open level. A non-admin who got past
         * vops_lopen is impossible; this case only fires for an
         * admin's readdir. (Defense in depth would be redundant; the
         * walk-through gate at vops_walk + the open gate at vops_lopen
         * are the trust boundary.) Single child today: allocator-
         * state. Future sub-chunks add tree-walk, extent-map,
         * integrity-verify here. */
        return emit_entry(c, &em, qid_root(KIND_DEBUG_ALLOC_DIR));

    case KIND_DEBUG_ALLOC_DIR: {
        /* R102 P3-4: vops_lopen at KIND_DEBUG_ALLOC_DIR refuses with
         * STM_ENOENT when c->fs is NULL (line 1634), so this branch
         * is reachable only with c->fs != NULL. (Earlier comment
         * here described a "/datasets/-style empty-when-unattached"
         * posture that the code does not implement; corrected.)
         *
         * Iterate device slots 0..STM_POOL_DEVICES_MAX, emit only
         * those that have an allocator attached. REMOVED slots and
         * never-attached slots get skipped via the cheap predicate
         * (R102 P3-1: stm_fs_alloc_attached avoids the heavy tree-
         * scan from stm_fs_alloc_stats_get). The 64-slot bound caps
         * the lock-cycle cost; admin-only diagnostic surface so the
         * cost is acceptable. */
        for (uint16_t did = 0; did < STM_POOL_DEVICES_MAX; did++) {
            bool attached = false;
            stm_status arc = stm_fs_alloc_attached(c->fs, did, &attached);
            if (arc != STM_OK || !attached) continue;
            stm_status erc = emit_entry(c, &em,
                qid_of(KIND_DEBUG_ALLOC, 0, did));
            if (erc == STM_ENOENT) continue;     /* race: detached after probe */
            if (erc != STM_OK) return erc;
        }
        return STM_OK;
    }

    case KIND_VERSION:
    case KIND_STATE:
    case KIND_POOL_STATUS:
    case KIND_DEVICE_STATUS:
    case KIND_DATASET_PROPERTIES:
    case KIND_ADMIN_PEER:
    case KIND_EVENTS:
    case KIND_ADMIN_CLEAR_EVENTS:
    case KIND_DEBUG_ALLOC:
    case KIND_POOL_SCRUB:
    case KIND_POOL_SCRUB_TRIGGER:
    case KIND_DATASET_CREATE_SNAPSHOT:
    case KIND_DATASET_DELETE_SNAPSHOT:
    case KIND_DATASET_HOLD_SNAPSHOT:
    case KIND_DATASET_RELEASE_SNAPSHOT:
    case KIND_POOL_METRICS_PROMETHEUS:
    case KIND_MAX:
        break;
    }
    return STM_ENOENT;
}

static stm_status vops_lopen(void *ctx, uint32_t fid, uint64_t qid_path,
                               uint32_t flags)
{
    stm_ctl *c = ctx;
    ctl_kind k = qid_kind(qid_path);
    if (k == KIND_MAX) return STM_ENOENT;
    const ctl_kind_meta *meta = &KIND_META[k];

    /* Extract POSIX access mode from the .L Tlopen flags. The lp9
     * server has already validated dir/file vs O_DIRECTORY (returns
     * ENOTDIR/EISDIR before reaching us); our remaining job is the
     * read-only-vs-write-only gate per kind. We refuse any flags
     * we don't understand (the trigger files only support pure
     * O_WRONLY; opening with O_RDWR or O_TRUNC etc. is refused at
     * the "right access mode" check below). */
    uint32_t accmode = flags & STM_LP9_O_ACCMODE;

    /* Mode-gating: most nodes are read-only. KIND_ADMIN_CLEAR_EVENTS
     * (P9-CTL-1d-events) and KIND_POOL_SCRUB_TRIGGER (P9-CTL-1d-
     * scrub-trigger) are write-only triggers (mode 0200) — accept
     * O_WRONLY only. R101 P3-5 forward-note suggested folding this
     * into `meta->mode & 0222` once the writable-kind family grew;
     * with two writable kinds we now have the family. The explicit
     * check below is still preferred since the kind list is small
     * and explicit-by-kind reads more clearly than a bitmask test. */
    if (k == KIND_ADMIN_CLEAR_EVENTS || k == KIND_POOL_SCRUB_TRIGGER
            || k == KIND_DATASET_CREATE_SNAPSHOT
            || k == KIND_DATASET_DELETE_SNAPSHOT
            || k == KIND_DATASET_HOLD_SNAPSHOT
            || k == KIND_DATASET_RELEASE_SNAPSHOT) {
        if (accmode != STM_LP9_O_WRONLY) return STM_EACCES;
    } else {
        if (accmode != STM_LP9_O_RDONLY) return STM_EACCES;
    }

    /* P9-CTL-1d-uid: admin gate. Refuse non-admin Tlopen on
     * admin-only kinds with EACCES. The check happens BEFORE the
     * per-kind validity gates (e.g., dataset-still-PRESENT) so a
     * non-admin probing the existence of /admin/peer cannot
     * distinguish "EACCES because not admin" from "ENOENT because
     * the path doesn't exist" — same defensive posture as POSIX
     * mode 0500 directories. */
    if (meta->admin_required && !ctl_caller_is_admin(c))
        return STM_EACCES;

    /* Directories: open is advisory; readdir handles iteration. */
    if (meta->is_dir) {
        /* Validate the directory still exists in the current state. */
        if ((k == KIND_POOL_DIR || k == KIND_DEVICES_DIR
                || k == KIND_DEVICE_DIR
                || k == KIND_POOL_METRICS_DIR) && !c->pool)
            return STM_ENOENT;
        if (k == KIND_DEVICE_DIR) {
            /* Slot must still be in range. */
            uint32_t did = qid_device_id(qid_path);
            stm_pool_lock_shared(c->pool);
            size_t total = stm_pool_device_count(c->pool);
            stm_pool_unlock_shared(c->pool);
            if (did >= total) return STM_ENOENT;
        }
        /* /datasets/ is always-open (matches /pools/ posture); only
         * the per-dataset kinds require fs. */
        if (k == KIND_DATASET_DIR && !c->fs)
            return STM_ENOENT;
        if (k == KIND_DATASET_DIR) {
            /* Dataset must still be PRESENT (could have been
             * destroyed between Twalk and Tlopen). R98 P2-1 lesson:
             * this is a REAL race-skip, not dead defense. */
            uint64_t dsid = qid_dataset_id(qid_path);
            stm_dataset_entry tmp;
            stm_status drc = stm_fs_dataset_lookup(c->fs, dsid, &tmp);
            if (drc != STM_OK) return drc;
        }
        /* /debug/ is always-open (admin gate fired above); /debug/
         * allocator-state requires fs since it iterates over per-
         * device alloc state. Without fs the dir is empty (vops_
         * readdir returns STM_OK with no entries). */
        if (k == KIND_DEBUG_ALLOC_DIR && !c->fs)
            return STM_ENOENT;
        return STM_OK;
    }

    /* File kinds: validate context, materialize body. */
    if ((k == KIND_POOL_STATUS || k == KIND_DEVICE_STATUS
            || k == KIND_POOL_METRICS_PROMETHEUS) && !c->pool)
        return STM_ENOENT;
    if ((k == KIND_DATASET_PROPERTIES) && !c->fs) return STM_ENOENT;
    if (k == KIND_DATASET_CREATE_SNAPSHOT
            || k == KIND_DATASET_DELETE_SNAPSHOT
            || k == KIND_DATASET_HOLD_SNAPSHOT
            || k == KIND_DATASET_RELEASE_SNAPSHOT) {
        if (!c->fs) return STM_ENOENT;
        /* Dataset must still be PRESENT (R98 P2-1 carry — destroyed
         * mid-walk-then-Tlopen returns ENOENT). */
        uint64_t dsid = qid_dataset_id(qid_path);
        stm_dataset_entry tmp;
        stm_status drc = stm_fs_dataset_lookup(c->fs, dsid, &tmp);
        if (drc != STM_OK) return drc;
    }
    /* /pools/<uuid>/scrub + /pools/<uuid>/scrub-trigger both require
     * pool + scrub attached. The dual-gate mirrors getattr_at — without
     * scrub, the file doesn't exist (consistent operator semantics). */
    if ((k == KIND_POOL_SCRUB || k == KIND_POOL_SCRUB_TRIGGER)
            && (!c->pool || !c->scrub))
        return STM_ENOENT;
    if (k == KIND_DEBUG_ALLOC) {
        if (!c->fs) return STM_ENOENT;
        uint32_t did = qid_device_id(qid_path);
        if (did >= STM_POOL_DEVICES_MAX) return STM_ENOENT;
        /* R102 P3-1: cheap is-attached predicate; the materialize
         * call below runs the full stats_get tree-scan on the OK
         * path. Avoids two scans on every Tlopen.
         *
         * Re-probe at Tlopen — between Twalk and Tlopen the device
         * could have been removed (forward-noted: today the sync
         * attach table only mutates at sync_create / replace_device_
         * online; a future evacuate path would race here). */
        bool attached = false;
        stm_status arc = stm_fs_alloc_attached(c->fs, (uint16_t)did, &attached);
        if (arc != STM_OK || !attached) return STM_ENOENT;
    }

    /* P9-CTL-1d-events: KIND_EVENTS reads from c->event_buf directly
     * (the log can grow past STM_CTL_BODY_MAX = 1 KiB). Snapshot the
     * length at Tlopen so subsequent Treads see a stable view; events
     * appended after Tlopen are visible only on a re-Tlopen. */
    if (k == KIND_EVENTS) {
        pthread_mutex_lock(&c->mu);
        ctl_session *s = session_alloc_locked(c, fid, qid_path);
        if (!s) {
            pthread_mutex_unlock(&c->mu);
            return STM_ENOMEM;
        }
        s->uses_event_buf = 1;
        s->snapshot_len = (c->event_len > UINT32_MAX)
            ? UINT32_MAX
            : (uint32_t)c->event_len;
        pthread_mutex_unlock(&c->mu);
        return STM_OK;
    }

    /* P9-CTL-1d-events + P9-CTL-1d-scrub-trigger: write-only trigger
     * kinds allocate a session for write tracking. Body buffer
     * unused; vops_write does the action dispatch. */
    if (k == KIND_ADMIN_CLEAR_EVENTS || k == KIND_POOL_SCRUB_TRIGGER
            || k == KIND_DATASET_CREATE_SNAPSHOT
            || k == KIND_DATASET_DELETE_SNAPSHOT
            || k == KIND_DATASET_HOLD_SNAPSHOT
            || k == KIND_DATASET_RELEASE_SNAPSHOT) {
        pthread_mutex_lock(&c->mu);
        ctl_session *s = session_alloc_locked(c, fid, qid_path);
        if (!s) {
            pthread_mutex_unlock(&c->mu);
            return STM_ENOMEM;
        }
        pthread_mutex_unlock(&c->mu);
        return STM_OK;
    }

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
    ctl_kind k = qid_kind(qid_path);
    if (k == KIND_MAX || KIND_META[k].is_dir) {
        *inout_len = 0;
        return STM_ENOENT;
    }
    pthread_mutex_lock(&c->mu);
    ctl_session *s = session_get_locked(c, fid);
    if (!s) {
        /* Read without prior open — generic stm_lp9_server gates this
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
    /* P9-CTL-1d-events: /events reads from c->event_buf directly
     * (bypasses session->buf since the log can be >1 KiB). The
     * snapshot_len captured at Tlopen is the upper bound; events
     * appended after Tlopen are not visible to this fid. */
    if (s->uses_event_buf) {
        if (offset >= s->snapshot_len) {
            *inout_len = 0;
            pthread_mutex_unlock(&c->mu);
            return STM_OK;
        }
        uint32_t avail = s->snapshot_len - (uint32_t)offset;
        if (*inout_len > avail) *inout_len = avail;
        memcpy(buf, c->event_buf + offset, *inout_len);
        pthread_mutex_unlock(&c->mu);
        return STM_OK;
    }
    /* P9-CTL-1e: bulk-format kinds (currently only /pools/<uuid>/
     * metrics/prometheus) live in s->bulk_buf — heap-allocated at
     * Tlopen, freed at Tclunk. The bulk_buf is per-session-owned, so
     * concurrent reads at varying offsets see the same snapshot. */
    if (s->bulk_buf) {
        if (offset >= s->bulk_len) {
            *inout_len = 0;
            pthread_mutex_unlock(&c->mu);
            return STM_OK;
        }
        uint32_t avail = s->bulk_len - (uint32_t)offset;
        if (*inout_len > avail) *inout_len = avail;
        memcpy(buf, s->bulk_buf + offset, *inout_len);
        pthread_mutex_unlock(&c->mu);
        return STM_OK;
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
    stm_ctl *c = ctx;
    (void)offset; (void)buf;
    *out_written = 0;
    ctl_kind k = qid_kind(qid_path);

    /* P9-CTL-1d-events: KIND_ADMIN_CLEAR_EVENTS — first writable
     * kind. Admin gate already fired at vops_lopen; if we reach
     * vops_write the caller IS admin (the fid couldn't have opened
     * for write otherwise). Defense-in-depth re-check anyway:
     * vops_lopen's gate is the primary, but if a future server bug
     * routed write to this fid without proper open, the gate here
     * catches it. */
    if (k == KIND_ADMIN_CLEAR_EVENTS) {
        if (!ctl_caller_is_admin(c)) return STM_EACCES;
        /* R101 P2-2: refuse 0-byte Twrite. The contract says "any
         * data triggers" — 0 bytes isn't data. POSIX `write(fd, _,
         * 0)` is well-defined as no-op-or-implementation-defined,
         * so accepting 0-byte writes as triggers is a UX surprise
         * (`echo -n "" >...` would silently destroy the log).
         *
         * R107 (P8.5 cleanup): post-admin refusal logged per the
         * R105 P3-1 doctrine — operators see every authorized
         * trigger attempt regardless of outcome. */
        if (len == 0) {
            stm_ctl_log_event(c,
                "events log clear refused (zero-byte) by uid=%u",
                (unsigned)c->caller_uid);
            return STM_EINVAL;
        }
        pthread_mutex_lock(&c->mu);
        ctl_session *s = session_get_locked(c, fid);
        if (!s || s->qid_path != qid_path) {
            pthread_mutex_unlock(&c->mu);
            return STM_EBACKEND;
        }
        /* Reset the event log. Any data the client sent is ignored —
         * the trigger is the act of writing, not the content. */
        if (c->event_buf) {
            stm_ct_memzero(c->event_buf, c->event_cap);
            c->event_len = 0;
        }
        /* R101 P2-1: invalidate any active /events snapshots. Without
         * this, a reader holding snapshot_len = N from before the
         * clear would see N bytes of zeros (post-memset) — a frankenstein
         * view that violates the documented "snapshot stability"
         * contract. Reset uses_event_buf and snapshot_len on every
         * active /events session so subsequent Treads return clean EOF
         * (count=0). Operators re-Tlopen to see the post-clear log. */
        for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++) {
            ctl_session *e = &c->sessions[i];
            if (e->active && e->uses_event_buf) {
                e->uses_event_buf = 0;
                e->snapshot_len = 0;
            }
        }
        pthread_mutex_unlock(&c->mu);
        /* Self-log the clear so operators have a marker even after
         * the action runs. */
        stm_ctl_log_event(c, "events log cleared by uid=%u",
                            (unsigned)c->caller_uid);
        *out_written = len;
        return STM_OK;
    }

    /* P9-CTL-1d-scrub-trigger: KIND_POOL_SCRUB_TRIGGER — second
     * writable kind. The body holds an action verb identifying which
     * scrub state-machine transition to drive: "start", "pause",
     * "resume", or "reset". The verb is parsed against a fixed table;
     * dispatch invokes the matching stm_scrub_* primitive.
     *
     * Carries the R101 P2-2 / P2-1 / P3-5 lessons:
     *   (a) admin gate at vops_lopen's meta->admin_required (primary).
     *   (b) defense-in-depth admin re-check at vops_write.
     *   (c) zero-byte Twrite refusal — len == 0 is STM_EINVAL.
     *   (d) consistent KIND_META[] mode-bit + vops_write/open
     *       dispatch (mode_check at vops_lopen already handled).
     *
     * Gate ordering (R104 P3-5 — locked against drive-by edits):
     *   admin re-check  →  zero-byte refusal  →  scrub-attached
     *     →  session lookup-and-validate.
     * Rationale: an unauthenticated zero-byte write must report
     * EACCES (the admin gate), not EINVAL (the zero-byte gate) —
     * same POSIX-priority shape as path-traversal returning EACCES
     * over EINVAL when a refused dirfd is hit first.
     *
     * Audit log: every action attempt records (uid, verb, result)
     * via stm_ctl_log_event regardless of success — so an operator
     * reading /events sees both successful and failed dispatches.
     * Failed dispatches return the underlying scrub_* status to the
     * client; the audit log captures the same. */
    if (k == KIND_POOL_SCRUB_TRIGGER) {
        if (!ctl_caller_is_admin(c)) return STM_EACCES;
        /* R107 (P8.5 cleanup): post-admin refusals all log per
         * R105 P3-1 doctrine. */
        if (len == 0) {
            stm_ctl_log_event(c,
                "scrub-trigger uid=%u verb=<zero-byte> result=err:einval",
                (unsigned)c->caller_uid);
            return STM_EINVAL;
        }
        if (!c->scrub) return STM_EBACKEND;     /* gated at vops_lopen */
        pthread_mutex_lock(&c->mu);
        ctl_session *s = session_get_locked(c, fid);
        if (!s || s->qid_path != qid_path) {
            pthread_mutex_unlock(&c->mu);
            return STM_EBACKEND;
        }
        pthread_mutex_unlock(&c->mu);
        /* R104 P2-1 / F-5: c->mu is INTENTIONALLY released before
         * verb dispatch. The session lookup above is purely a
         * pre-dispatch fid-validity gate — we don't reuse `s` after
         * unlock. Releasing c->mu before invoking verb_op keeps the
         * scrub's internal sc->lock from nesting under c->mu (which
         * stm_ctl_log_event also takes); the lock order is therefore
         * sc->lock → release → c->mu. Under v2.0's serial-server
         * posture this is trivially safe (no concurrent dispatch can
         * race against `stm_ctl_drop_all_sessions`, which would also
         * take c->mu). Concurrent-accept upgrades MUST re-strengthen
         * the validation gate (e.g., per-session refcount that
         * drop_all_sessions waits on) — same R94 P2-1 / R97 P2-2
         * forward-note class. */

        /* Trim trailing whitespace + newline. The verb table is
         * matched against the trimmed slice. Bound the comparison
         * length to avoid pathological huge-buffer strncmp scans —
         * the longest verb is "resume" (6 chars). */
        size_t end = len;
        while (end > 0) {
            uint8_t ch = ((const uint8_t *)buf)[end - 1];
            if (ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t')
                break;
            end--;
        }
        if (end == 0) {
            /* whitespace-only body — R107 P8.5 carry: log per doctrine */
            stm_ctl_log_event(c,
                "scrub-trigger uid=%u verb=<whitespace-only> result=err:einval",
                (unsigned)c->caller_uid);
            return STM_EINVAL;
        }

        /* Cap the verb length at STM_CTL_VERB_MAX so a malicious 1
         * GiB body doesn't cause us to scan unbounded memory. The
         * longest legitimate verb is "resume" (6 chars); anything
         * past 16 is definitely garbage. */
        size_t cmp_len = (end > STM_CTL_VERB_MAX) ? STM_CTL_VERB_MAX : end;

        /* R104 P3-3: verb dispatch table — replaces the per-clause
         * if-chain. Easier to extend (e.g., a future "step" verb for
         * testing) and reads the cmp_len-vs-name-length comparison
         * without per-line repetition of the size literal. */
        static const struct {
            const char *name;
            size_t      name_len;
            stm_status (*op)(stm_scrub *);
        } VERBS[] = {
            { "start",  5, stm_scrub_start  },
            { "pause",  5, stm_scrub_pause  },
            { "resume", 6, stm_scrub_resume },
            { "reset",  5, stm_scrub_reset  },
        };

        const char *verb_str = NULL;
        stm_status (*verb_op)(stm_scrub *) = NULL;
        for (size_t i = 0; i < sizeof VERBS / sizeof VERBS[0]; i++) {
            if (cmp_len == VERBS[i].name_len
                  && memcmp(buf, VERBS[i].name, VERBS[i].name_len) == 0) {
                verb_str = VERBS[i].name;
                verb_op  = VERBS[i].op;
                break;
            }
        }
        if (!verb_op) {
            /* Unknown verb. Log + refuse. */
            stm_ctl_log_event(c, "scrub-trigger uid=%u verb=<unknown> result=err:einval",
                                (unsigned)c->caller_uid);
            return STM_EINVAL;
        }

        stm_status rc = verb_op(c->scrub);
        stm_ctl_log_event(c, "scrub-trigger uid=%u verb=%s result=%s%s",
                            (unsigned)c->caller_uid, verb_str,
                            rc == STM_OK ? "" : "err:",
                            status_short_name(rc));
        if (rc != STM_OK) return rc;
        *out_written = len;
        return STM_OK;
    }

    /* P9-CTL-1d-actions-snapshot-create: KIND_DATASET_CREATE_SNAPSHOT
     * — third writable kind. Body is the snapshot name (1..STM_SNAP_
     * NAME_MAX bytes) optionally with trailing whitespace; the
     * dataset_id comes from the qid_path.
     *
     * Carries the established writable-kind family discipline:
     *   (a) admin gate at vops_lopen's meta->admin_required.
     *   (b) defense-in-depth admin re-check at vops_write.
     *   (c) zero-byte Twrite refusal (R101 P2-2).
     *   (d) gate ordering: admin → zero-byte → fs-attached →
     *       session-validate (R104 P3-5 carry).
     *
     * Name-char validation lives at snapshot.c::stm_snap_name_chars_
     * valid (R99 P2-1 source-side carry — refuses bytes < 0x20 +
     * 0x7F). The wrapper passes the body slice through; the gate
     * fires inside snapshot_create_inner. Same single-source-of-
     * truth posture as dataset.c's name validation. */
    if (k == KIND_DATASET_CREATE_SNAPSHOT) {
        /* R100 admin gate is the trust boundary. R105 P3-1 doctrine
         * (also see CLAUDE.md trigger entry clause 6): pre-admin-
         * gate refusals do NOT log to /events — flooding the event
         * log with non-admin denial-of-service noise would let an
         * attacker burn the 8 MiB cap. Post-admin-gate refusals
         * (zero-byte, whitespace-only, oversize, snapshot.c
         * rejection, name collision, etc.) DO log so the operator
         * has a forensic trail of every authorized attempt. */
        if (!ctl_caller_is_admin(c)) return STM_EACCES;
        if (!c->fs) return STM_EBACKEND;     /* gated at vops_lopen */
        pthread_mutex_lock(&c->mu);
        ctl_session *s = session_get_locked(c, fid);
        if (!s || s->qid_path != qid_path) {
            pthread_mutex_unlock(&c->mu);
            return STM_EBACKEND;
        }
        pthread_mutex_unlock(&c->mu);

        uint64_t dsid = qid_dataset_id(qid_path);

        /* R101 P2-2: zero-byte refusal — but log first since it's
         * post-admin. */
        if (len == 0) {
            stm_ctl_log_event(c,
                "create-snapshot uid=%u dataset=%llu name-len=0 result=err:einval",
                (unsigned)c->caller_uid, (unsigned long long)dsid);
            return STM_EINVAL;
        }

        /* Trim trailing whitespace + newline. R104 carry. */
        size_t end = len;
        while (end > 0) {
            uint8_t ch = ((const uint8_t *)buf)[end - 1];
            if (ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t')
                break;
            end--;
        }
        if (end == 0) {
            /* whitespace-only body */
            stm_ctl_log_event(c,
                "create-snapshot uid=%u dataset=%llu name-len=0 result=err:einval",
                (unsigned)c->caller_uid, (unsigned long long)dsid);
            return STM_EINVAL;
        }
        /* Refuse names exceeding STM_SNAP_NAME_MAX up front so the
         * audit log distinguishes "obviously-too-long" from
         * "snapshot.c rejected" — both end up STM_EINVAL but the
         * cap check here is cheap. The wrapper validates again
         * (defense-in-depth). */
        if (end > STM_SNAP_NAME_MAX) {
            stm_ctl_log_event(c,
                "create-snapshot uid=%u dataset=%llu name-len=%zu result=err:einval",
                (unsigned)c->caller_uid, (unsigned long long)dsid, end);
            return STM_EINVAL;
        }

        uint64_t snap_id = 0;
        stm_status rc = stm_fs_create_snapshot(c->fs, dsid,
                                                  (const char *)buf, end,
                                                  &snap_id);
        stm_ctl_log_event(c,
            "create-snapshot uid=%u dataset=%llu name-len=%zu result=%s%s snap-id=%llu",
            (unsigned)c->caller_uid,
            (unsigned long long)dsid,
            end,
            rc == STM_OK ? "" : "err:",
            status_short_name(rc),
            (unsigned long long)snap_id);
        if (rc != STM_OK) return rc;
        *out_written = len;
        return STM_OK;
    }

    /* P9-CTL-1d-actions-snapshot-delete: KIND_DATASET_DELETE_SNAPSHOT
     * — fourth writable kind. Body is a decimal snapshot_id (1..
     * UINT64_MAX), optionally with trailing whitespace. Carries the
     * established writable-kind family discipline (R105 P3-1 audit-
     * log doctrine: pre-admin-gate refusals NOT logged; post-admin-
     * gate refusals DO log).
     *
     * Forward-note: name-based deletion (lookup-by-name → id →
     * delete) is a future ergonomic improvement. Today operators
     * read snap-id from /events at create time. */
    if (k == KIND_DATASET_DELETE_SNAPSHOT) {
        if (!ctl_caller_is_admin(c)) return STM_EACCES;
        if (!c->fs) return STM_EBACKEND;     /* gated at vops_lopen */
        pthread_mutex_lock(&c->mu);
        ctl_session *s = session_get_locked(c, fid);
        if (!s || s->qid_path != qid_path) {
            pthread_mutex_unlock(&c->mu);
            return STM_EBACKEND;
        }
        pthread_mutex_unlock(&c->mu);

        uint64_t dsid = qid_dataset_id(qid_path);

        if (len == 0) {
            stm_ctl_log_event(c,
                "delete-snapshot uid=%u dataset=%llu snap-id=0 result=err:einval",
                (unsigned)c->caller_uid, (unsigned long long)dsid);
            return STM_EINVAL;
        }

        /* Trim trailing whitespace + newline. */
        size_t end = len;
        while (end > 0) {
            uint8_t ch = ((const uint8_t *)buf)[end - 1];
            if (ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t')
                break;
            end--;
        }
        if (end == 0) {
            stm_ctl_log_event(c,
                "delete-snapshot uid=%u dataset=%llu snap-id=0 result=err:einval",
                (unsigned)c->caller_uid, (unsigned long long)dsid);
            return STM_EINVAL;
        }

        uint64_t snap_id = 0;
        if (parse_snapshot_id((const char *)buf, end, &snap_id) != 0) {
            stm_ctl_log_event(c,
                "delete-snapshot uid=%u dataset=%llu snap-id=<bad-parse> result=err:einval",
                (unsigned)c->caller_uid, (unsigned long long)dsid);
            return STM_EINVAL;
        }

        size_t freed = 0;
        stm_status rc = stm_fs_delete_snapshot(c->fs, snap_id, &freed);
        stm_ctl_log_event(c,
            "delete-snapshot uid=%u dataset=%llu snap-id=%llu freed-paddrs=%zu result=%s%s",
            (unsigned)c->caller_uid,
            (unsigned long long)dsid,
            (unsigned long long)snap_id,
            freed,
            rc == STM_OK ? "" : "err:",
            status_short_name(rc));
        if (rc != STM_OK) return rc;
        *out_written = len;
        return STM_OK;
    }

    /* P9-CTL-1d-actions-snapshot-hold: KIND_DATASET_HOLD_SNAPSHOT
     * + KIND_DATASET_RELEASE_SNAPSHOT — fifth + sixth writable
     * kinds. Symmetric pair: identical body shape (decimal snap_id),
     * identical gate ordering (R104 P3-5 carry), identical audit-
     * log discipline (R105 P3-1 carry). Body is a decimal
     * snapshot_id (1..UINT64_MAX), optionally with trailing
     * whitespace.
     *
     * Hold/release mutate the snapshot_index's hold_count counter,
     * which IS persisted on disk (R108 P2-1 fix — snapshot.h's
     * on-disk layout puts hold_count at offset 40 of the snapshot
     * record; stm_snapshot_hold/_release set idx->dirty so the next
     * stm_sync_commit flushes the value). Hold gates delete via
     * STM_EBUSY (snapshot.tla::HoldPreventsDelete). */
    if (k == KIND_DATASET_HOLD_SNAPSHOT
            || k == KIND_DATASET_RELEASE_SNAPSHOT) {
        const char *verb = (k == KIND_DATASET_HOLD_SNAPSHOT)
                              ? "hold-snapshot" : "release-snapshot";

        if (!ctl_caller_is_admin(c)) return STM_EACCES;
        if (!c->fs) return STM_EBACKEND;     /* gated at vops_lopen */
        pthread_mutex_lock(&c->mu);
        ctl_session *s = session_get_locked(c, fid);
        if (!s || s->qid_path != qid_path) {
            pthread_mutex_unlock(&c->mu);
            return STM_EBACKEND;
        }
        pthread_mutex_unlock(&c->mu);

        uint64_t dsid = qid_dataset_id(qid_path);

        if (len == 0) {
            stm_ctl_log_event(c,
                "%s uid=%u dataset=%llu snap-id=0 result=err:einval",
                verb, (unsigned)c->caller_uid,
                (unsigned long long)dsid);
            return STM_EINVAL;
        }

        size_t end = len;
        while (end > 0) {
            uint8_t ch = ((const uint8_t *)buf)[end - 1];
            if (ch != '\n' && ch != '\r' && ch != ' ' && ch != '\t')
                break;
            end--;
        }
        if (end == 0) {
            stm_ctl_log_event(c,
                "%s uid=%u dataset=%llu snap-id=0 result=err:einval",
                verb, (unsigned)c->caller_uid,
                (unsigned long long)dsid);
            return STM_EINVAL;
        }

        uint64_t snap_id = 0;
        if (parse_snapshot_id((const char *)buf, end, &snap_id) != 0) {
            stm_ctl_log_event(c,
                "%s uid=%u dataset=%llu snap-id=<bad-parse> result=err:einval",
                verb, (unsigned)c->caller_uid,
                (unsigned long long)dsid);
            return STM_EINVAL;
        }

        stm_status rc;
        if (k == KIND_DATASET_HOLD_SNAPSHOT)
            rc = stm_fs_hold_snapshot(c->fs, snap_id);
        else
            rc = stm_fs_release_snapshot(c->fs, snap_id);
        stm_ctl_log_event(c,
            "%s uid=%u dataset=%llu snap-id=%llu result=%s%s",
            verb, (unsigned)c->caller_uid,
            (unsigned long long)dsid,
            (unsigned long long)snap_id,
            rc == STM_OK ? "" : "err:",
            status_short_name(rc));
        if (rc != STM_OK) return rc;
        *out_written = len;
        return STM_OK;
    }

    /* All other kinds remain read-only. */
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

static const stm_lp9_vops g_vops = {
    .getattr  = vops_getattr,
    .walk     = vops_walk,
    .readdir  = vops_readdir,
    .lopen    = vops_lopen,
    .read     = vops_read,
    .write    = vops_write,
    .clunk    = vops_clunk,
    /* Optional ops: NULL → server replies Rlerror(ENOSYS). /ctl/'s
     * tree is fixed by code; no Tlcreate / Tmkdir / Tunlinkat /
     * Tsymlink slots. /ctl/'s synthetic files don't expose
     * settable attrs (Tsetattr) or Treadlink / Tfsync surfaces. */
    .lcreate  = NULL,
    .mkdir    = NULL,
    .unlinkat = NULL,
    .setattr  = NULL,
    .fsync    = NULL,
    .symlink  = NULL,
    .readlink = NULL,
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
    c->pool = NULL;
    /* P9-CTL-1d-uid: caller credentials default to "unset" sentinel
     * (uid_t)-1 / (gid_t)-1. With both unset, ctl_caller_is_admin
     * returns false → admin-only kinds refuse access. Stratumd
     * stamps real credentials via stm_ctl_set_caller before serving. */
    c->caller_uid = (uid_t)-1;
    c->caller_gid = (gid_t)-1;
    c->admin_uid  = (uid_t)-1;
    *out = c;
    return STM_OK;
}

stm_status stm_ctl_set_caller(stm_ctl *c, uid_t caller_uid, gid_t caller_gid)
{
    if (!c) return STM_EINVAL;
    c->caller_uid = caller_uid;
    c->caller_gid = caller_gid;
    return STM_OK;
}

stm_status stm_ctl_set_admin_uid(stm_ctl *c, uid_t admin_uid)
{
    if (!c) return STM_EINVAL;
    c->admin_uid = admin_uid;
    return STM_OK;
}

void stm_ctl_drop_all_sessions(stm_ctl *c)
{
    if (!c) return;
    pthread_mutex_lock(&c->mu);
    for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++) {
        if (c->sessions[i].active) session_free_locked(&c->sessions[i]);
    }
    pthread_mutex_unlock(&c->mu);
}

stm_status stm_ctl_attach_pool(stm_ctl *c, struct stm_pool *pool)
{
    /* R97 P2-1: NULL pool is rejected. Earlier shape silently
     * "succeeded" by storing NULL, which let a programmer-error
     * caller pass STM_OK back unnoticed. */
    if (!c || !pool) return STM_EINVAL;
    /* Idempotent attach of the SAME pool is a no-op; attaching a
     * different pool with one already bound is refused — the daemon
     * lifecycle that produces concurrent multi-pool /ctl/ is forward-
     * noted to a future sub-chunk. */
    if (c->pool && c->pool != pool) return STM_EEXIST;
    c->pool = pool;
    return STM_OK;
}

stm_status stm_ctl_attach_scrub(stm_ctl *c, struct stm_scrub *scrub)
{
    /* R97 P2-1 carry: NULL scrub is rejected with STM_EINVAL — same
     * shape as attach_pool. Idempotent same-pointer; STM_EEXIST on
     * different scrub. v2.0 supports at most one attached scrub.
     *
     * R97 P2-2 carry: this writes c->scrub without c->mu; vops read
     * paths read c->scrub without c->mu. Serial-server posture is the
     * implicit safety; concurrent-accept must extend locking. */
    if (!c || !scrub) return STM_EINVAL;
    if (c->scrub && c->scrub != scrub) return STM_EEXIST;
    c->scrub = scrub;
    return STM_OK;
}

void stm_ctl_destroy(stm_ctl *c)
{
    if (!c) return;
    for (uint32_t i = 0; i < STM_CTL_MAX_SESSIONS; i++)
        if (c->sessions[i].active) session_free_locked(&c->sessions[i]);
    /* P9-CTL-1d-events: release the event log buffer. Zero before
     * free — the log may contain operationally-sensitive context
     * (uids, dataset names, etc.) that an attacker recovering freed
     * heap pages could harvest. R101 P3-1: stm_ct_memzero (not
     * memset) because the write has no observable effect post-free
     * and a DSE-eligible memset could be elided by aggressive
     * optimizers. Matches janus's audit_buf cleanup pattern
     * (synfs.c:904). */
    if (c->event_buf) {
        stm_ct_memzero(c->event_buf, c->event_cap);
        free(c->event_buf);
    }
    pthread_mutex_destroy(&c->mu);
    free(c);
}

const stm_lp9_vops *stm_ctl_vops(void)
{
    return &g_vops;
}

uint64_t stm_ctl_root(const stm_ctl *c)
{
    (void)c;
    return qid_root(KIND_ROOT);
}
