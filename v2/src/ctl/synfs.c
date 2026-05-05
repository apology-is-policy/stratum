/* SPDX-License-Identifier: ISC */
/*
 * stm_ctl synfs — operational synthetic filesystem (ARCH §14.3).
 *
 * Phase 9 P9-CTL-1a foundation + P9-CTL-1b /pools/ subtree:
 *
 *   /                        directory (ro, world-readable)
 *   /version                 read: build identity + format versions
 *   /state                   read: attached-fs state (or placeholder)
 *   /pools/                  directory: registered pool(s)
 *   /pools/<uuid>/           directory: per-pool entries
 *   /pools/<uuid>/status     read: pool roster summary, redundancy
 *
 * Subsequent sub-chunks layer on /pools/<uuid>/devices/<id>/{...},
 * /datasets/, /tracing/, /debug/, /events, /metrics/.
 *
 * qid_path encoding
 * ─────────────────
 * The generic stm_p9_server passes our qid_path back to us on every
 * walk/stat/read; the layout encodes:
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
 * trips at build time if the name overflows STM_P9_NAME_MAX.
 *
 * Concurrency
 * ───────────
 * The hard rule:
 *   - Safe to share one stm_ctl across SEQUENTIAL stm_p9_server use
 *     (one server at a time — v2.0 stratumd serial accept).
 *   - NOT safe to share one stm_ctl across CONCURRENT stm_p9_server
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
 * running `vops_open(fid=1)` would race in sessions[] and the
 * mutex doesn't know which server's fid 1 to associate with which
 * slot. So the mutex is defense-in-depth WITHIN a single server's
 * timeline (where the generic stm_p9_server is itself single-
 * threaded per connection — Tflush is a server-level no-op so
 * cannot interrupt a vops call); it is NOT cross-server safety.
 *
 * Read paths against subsystem state (`stm_fs *`, `stm_pool *`)
 * call into those subsystems' own thread-safe accessors
 * (`stm_fs_stats_get`, `stm_pool_lock_shared` etc.). Body
 * materialization snapshots state at Topen so subsequent Treads
 * see a consistent view; concurrent fs/pool mutations after Topen
 * are reflected on the next Topen.
 */

#include <stratum/ctl.h>
#include <stratum/fs.h>
#include <stratum/p9.h>
#include <stratum/pool.h>
#include <stratum/send_recv.h>      /* STM_SEND_VERSION */
#include <stratum/super.h>          /* STM_UB_VERSION + STM_DEV_*_ values */
#include <stratum/types.h>

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── kind enum + meta table ─────────────────────────────────────────── */

typedef enum {
    KIND_ROOT         = 0,
    KIND_VERSION      = 1,
    KIND_STATE        = 2,
    KIND_POOLS_DIR    = 3,    /* /pools/ */
    KIND_POOL_DIR     = 4,    /* /pools/<uuid>/ */
    KIND_POOL_STATUS  = 5,    /* /pools/<uuid>/status */
    KIND_MAX
} ctl_kind;

typedef struct {
    bool         is_dir;
    uint32_t     mode;          /* posix mode bits, sans STM_P9_DMDIR */
    const char  *static_name;   /* NULL when name is dynamic (e.g. UUID) */
} ctl_kind_meta;

static const ctl_kind_meta KIND_META[KIND_MAX] = {
    [KIND_ROOT]         = { true,  0555, "/"       },
    [KIND_VERSION]      = { false, 0444, "version" },
    [KIND_STATE]        = { false, 0444, "state"   },
    [KIND_POOLS_DIR]    = { true,  0555, "pools"   },
    [KIND_POOL_DIR]     = { true,  0555, NULL      },  /* dynamic uuid */
    [KIND_POOL_STATUS]  = { false, 0444, "status"  },
};

/* R96 P3-2: pin every static-name literal length below STM_P9_NAME_MAX
 * (63) at build time. Update both this assert block and KIND_META in
 * lockstep when adding new static-named kinds. (Dynamic names like
 * uuid hex (36 chars) are also < 63 — that's a runtime bound check
 * in the dynamic decoder.) */
_Static_assert(sizeof("/") - 1        <= STM_P9_NAME_MAX, "/ctl/ root literal");
_Static_assert(sizeof("version") - 1  <= STM_P9_NAME_MAX, "/ctl/ /version literal");
_Static_assert(sizeof("state") - 1    <= STM_P9_NAME_MAX, "/ctl/ /state literal");
_Static_assert(sizeof("pools") - 1    <= STM_P9_NAME_MAX, "/ctl/ /pools literal");
_Static_assert(sizeof("status") - 1   <= STM_P9_NAME_MAX, "/ctl/ /pools/.../status literal");

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

/* ── per-fid materialized body ──────────────────────────────────────── */

/*
 * /version, /state, /pools/<uuid>/status read as text — we
 * materialize the entire body once per Topen so subsequent Treads
 * at varying offsets see a consistent snapshot. For unattached
 * or post-attach state changes, the body is regenerated on the
 * next Topen.
 *
 * STM_CTL_BODY_MAX is the per-fid scratch budget. Each kind that
 * gets opened must materialize within this cap; the materializers
 * snprintf-then-check and refuse with STM_ERANGE on overflow.
 * Today's kinds (/version ~80 bytes, /state ~352 bytes worst case
 * with all-UINT64_MAX counters, /pools/<uuid>/status ~256 bytes
 * with full 64-device roster summary) sit comfortably under 1 KiB.
 * Future sub-chunks (/pools/<n>/devices, /datasets/<id>/properties
 * with many properties) may need to bump or per-kind-cap; do so
 * in lockstep with adding the new kind, and document the per-kind
 * justification (R96 P3-3).
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
    struct stm_pool *pool;           /* may be NULL (no pool attached) */
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
    /* The generic stm_p9_server rejects re-Topen on an open fid
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

/* Get the attached pool's UUID as 16 bytes, or return false if no pool
 * is attached. */
static bool ctl_pool_uuid_bytes(const stm_ctl *c, uint8_t out[16])
{
    if (!c->pool) return false;
    uuid_to_bytes(stm_pool_uuid(c->pool), out);
    return true;
}

/* ── enum stringification ───────────────────────────────────────────── */

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
 * spot evacuation-in-progress from the ratio. */
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
        /* Should not be reachable — vops_open gates KIND_POOL_STATUS
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
    /* Suppress unused-static-fn warnings for the helpers — they
     * are reserved for the next sub-sub-chunk that adds the
     * /pools/<uuid>/devices/<id>/{class,role,state,...} surface. */
    (void)device_class_name;
    (void)device_role_name;
    (void)device_state_name;
    if (n < 0) return STM_EIO;
    if ((size_t)n >= sizeof s->buf) return STM_ERANGE;
    s->len = (uint32_t)n;
    return STM_OK;
}

static stm_status materialize_locked(stm_ctl *c, ctl_session *s)
{
    switch (qid_kind(s->qid_path)) {
    case KIND_VERSION:     return materialize_version(c, s);
    case KIND_STATE:       return materialize_state(c, s);
    case KIND_POOL_STATUS: return materialize_pool_status(c, s);
    case KIND_ROOT:
    case KIND_POOLS_DIR:
    case KIND_POOL_DIR:
    case KIND_MAX:
        break;
    }
    /* Should not happen — open gates body files only. */
    return STM_EBACKEND;
}

/* ── stat / walk / readdir ──────────────────────────────────────────── */

static void set_name(stm_p9_node_stat *out, const char *name, size_t name_len)
{
    if (name_len > STM_P9_NAME_MAX) name_len = STM_P9_NAME_MAX;
    memcpy(out->name, name, name_len);
    out->name[name_len] = '\0';
    out->name_len = (uint16_t)name_len;
}

/* Fill `out` for a node with the given qid_path, computing its display
 * name from KIND_META + (for KIND_POOL_DIR) the attached pool's UUID. */
static stm_status stat_at(stm_ctl *c, uint64_t qid_path,
                           stm_p9_node_stat *out)
{
    ctl_kind k = qid_kind(qid_path);
    if (k == KIND_MAX) return STM_ENOENT;
    const ctl_kind_meta *meta = &KIND_META[k];

    /* Dynamic-named kinds: validate the dynamic context exists. */
    char dyn_name[UUID_HEX_LEN + 1];
    const char *name = meta->static_name;
    size_t name_len = name ? strlen(name) : 0;

    if (k == KIND_POOL_DIR) {
        uint8_t uuid_b[16];
        if (!ctl_pool_uuid_bytes(c, uuid_b)) return STM_ENOENT;
        if (qid_pool_idx(qid_path) != 0) return STM_ENOENT;
        uuid_format_hex(uuid_b, dyn_name);
        name = dyn_name;
        name_len = UUID_HEX_LEN;
    }
    if ((k == KIND_POOL_STATUS) && !c->pool) {
        return STM_ENOENT;
    }
    if ((k == KIND_POOLS_DIR) || (k == KIND_POOL_DIR)
        || (k == KIND_POOL_STATUS)) {
        if (qid_pool_idx(qid_path) != 0) return STM_ENOENT;
    }

    memset(out, 0, sizeof *out);
    out->qid_path = qid_path;
    if (meta->is_dir) {
        out->qid_type = STM_P9_QTDIR;
        out->mode     = meta->mode | STM_P9_DMDIR;
    } else {
        out->qid_type = STM_P9_QTFILE;
        out->mode     = meta->mode;
        /* `length` is reported as 0 for synthetic files: the actual
         * body is materialized at Topen and the FS doesn't know its
         * size in advance. Standard 9P pattern (see /proc on Linux);
         * clients read until EOF. */
    }
    set_name(out, name, name_len);
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
    ctl_kind dk = qid_kind(dir_qid_path);
    switch (dk) {
    case KIND_ROOT:
        if (str_eq(name, name_len, KIND_META[KIND_VERSION].static_name))
            return stat_at(c, qid_root(KIND_VERSION), out);
        if (str_eq(name, name_len, KIND_META[KIND_STATE].static_name))
            return stat_at(c, qid_root(KIND_STATE), out);
        if (str_eq(name, name_len, KIND_META[KIND_POOLS_DIR].static_name))
            return stat_at(c, qid_root(KIND_POOLS_DIR), out);
        return STM_ENOENT;

    case KIND_POOLS_DIR: {
        uint8_t uuid_b[16];
        if (!ctl_pool_uuid_bytes(c, uuid_b)) return STM_ENOENT;
        uint8_t want[16];
        if (uuid_parse_hex(name, name_len, want) != 0) return STM_ENOENT;
        if (!uuid_eq(uuid_b, want)) return STM_ENOENT;
        return stat_at(c, qid_root(KIND_POOL_DIR), out);
    }

    case KIND_POOL_DIR:
        if (!c->pool) return STM_ENOENT;
        if (str_eq(name, name_len, KIND_META[KIND_POOL_STATUS].static_name))
            return stat_at(c, qid_root(KIND_POOL_STATUS), out);
        return STM_ENOENT;

    case KIND_VERSION:
    case KIND_STATE:
    case KIND_POOL_STATUS:
    case KIND_MAX:
        break;
    }
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
    ctl_kind dk = qid_kind(dir_qid_path);
    stm_status rc;
    switch (dk) {
    case KIND_ROOT:
        rc = emit_entry(c, cb, cb_ctx, qid_root(KIND_VERSION));
        if (rc != STM_OK) return rc;
        rc = emit_entry(c, cb, cb_ctx, qid_root(KIND_STATE));
        if (rc != STM_OK) return rc;
        return emit_entry(c, cb, cb_ctx, qid_root(KIND_POOLS_DIR));

    case KIND_POOLS_DIR:
        /* Enumerate registered pools. v2.0: at most one pool. */
        if (!c->pool) return STM_OK;
        return emit_entry(c, cb, cb_ctx, qid_root(KIND_POOL_DIR));

    case KIND_POOL_DIR:
        if (!c->pool) return STM_ENOENT;
        return emit_entry(c, cb, cb_ctx, qid_root(KIND_POOL_STATUS));

    case KIND_VERSION:
    case KIND_STATE:
    case KIND_POOL_STATUS:
    case KIND_MAX:
        break;
    }
    return STM_ENOENT;
}

static stm_status vops_open(void *ctx, uint32_t fid, uint64_t qid_path,
                              uint8_t mode)
{
    stm_ctl *c = ctx;
    ctl_kind k = qid_kind(qid_path);
    if (k == KIND_MAX) return STM_ENOENT;
    const ctl_kind_meta *meta = &KIND_META[k];

    /* Mode-gating: every node is read-only at v2.0. */
    if (mode != STM_P9_OREAD) return STM_EACCES;

    /* Directories: open is advisory; readdir handles iteration. */
    if (meta->is_dir) {
        /* Validate the directory still exists in the current state
         * (e.g. /pools/<uuid>/ requires c->pool != NULL). */
        if (k == KIND_POOL_DIR && !c->pool) return STM_ENOENT;
        return STM_OK;
    }

    /* File kinds: validate context, materialize body. */
    if (k == KIND_POOL_STATUS && !c->pool) return STM_ENOENT;

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
    /* P9-CTL-1a/-1b: every node is read-only. Future sub-chunks add
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
    c->pool = NULL;
    *out = c;
    return STM_OK;
}

stm_status stm_ctl_attach_pool(stm_ctl *c, struct stm_pool *pool)
{
    if (!c) return STM_EINVAL;
    /* Idempotent attach of the SAME pool is a no-op; attaching a
     * different pool with one already bound is refused — the daemon
     * lifecycle that produces concurrent multi-pool /ctl/ is forward-
     * noted to a future sub-chunk. */
    if (c->pool && c->pool != pool) return STM_EEXIST;
    c->pool = pool;
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
    return qid_root(KIND_ROOT);
}
