/* SPDX-License-Identifier: ISC */
/*
 * stm_dirty_buffer — per-inode plaintext write buffer (SWISS-4q-flush).
 *
 *   see include/stratum/dirty_buffer.h for the public API.
 *   see v2/specs/writeback.tla for the spec this realizes.
 *
 * Internal data structure:
 *
 *   bucket[STM_DBUF_BUCKETS]   — hash table, chained
 *      → inode_entry           — one per buffered (dataset_id, ino)
 *          → range (sorted)    — one per contiguous buffered range
 *              ↓
 *              uint8_t *data   — heap-allocated, owned by the buffer
 *
 *   The hash buckets are fixed at STM_DBUF_BUCKETS (256). Collision
 *   chains are short for realistic workloads (per-inode entries are
 *   bounded by the global cap / per-inode min-write-size, ~64K worst
 *   case, ~256 per bucket worst case — short enough that linear scan
 *   inside a bucket is fine).
 *
 *   Ranges within an inode_entry are kept in a singly-linked list
 *   sorted by `off`, with the invariant that pairwise ranges are
 *   NON-OVERLAPPING (writeback.tla::BufferRangesNonOverlapWithinIno).
 *   Insert maintains this by removing overlapping ranges before
 *   placing the new one.
 *
 * Concurrency: every public call locks buf->mu before touching state.
 * Drain callbacks run UNDER buf->mu — caller MUST NOT re-enter the
 * buffer from the callback (would deadlock).
 */

#include <stratum/dirty_buffer.h>
#include <stratum/super.h>     /* STM_UB_SIZE — extent block granularity */

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define STM_DBUF_BUCKETS 256u

typedef struct stm_dbuf_range {
    uint64_t                off;
    uint64_t                len;
    uint8_t                *data;     /* owned */
    struct stm_dbuf_range  *next;
} stm_dbuf_range;

typedef struct stm_dbuf_inode {
    uint64_t                dataset_id;
    uint64_t                ino;
    size_t                  bytes;   /* sum of all ranges' len */
    stm_dbuf_range         *head;    /* sorted by off, ascending */
    struct stm_dbuf_inode  *bucket_next;
} stm_dbuf_inode;

struct stm_dirty_buffer {
    pthread_mutex_t   mu;
    size_t            inode_cap;
    size_t            global_cap;
    size_t            total_bytes;
    stm_dbuf_inode   *buckets[STM_DBUF_BUCKETS];
};

/* ───────────────────────────── helpers ────────────────────────────── */

static uint32_t bucket_hash(uint64_t ds, uint64_t ino)
{
    /* Mix dataset_id + ino. xxHash would be nicer; this is enough for
     * v1 since collisions are rare and chain-walk is O(chain length). */
    uint64_t x = (ds * UINT64_C(0x9E3779B97F4A7C15)) ^ ino;
    x ^= x >> 33;
    x *= UINT64_C(0xFF51AFD7ED558CCD);
    x ^= x >> 33;
    return (uint32_t)(x % STM_DBUF_BUCKETS);
}

static stm_dbuf_inode *find_inode_locked(stm_dirty_buffer *buf,
                                           uint64_t ds, uint64_t ino)
{
    uint32_t b = bucket_hash(ds, ino);
    for (stm_dbuf_inode *e = buf->buckets[b]; e; e = e->bucket_next) {
        if (e->dataset_id == ds && e->ino == ino) return e;
    }
    return NULL;
}

/* Find-or-create. Returns NULL on alloc failure. */
static stm_dbuf_inode *get_or_create_inode_locked(stm_dirty_buffer *buf,
                                                     uint64_t ds, uint64_t ino)
{
    stm_dbuf_inode *e = find_inode_locked(buf, ds, ino);
    if (e) return e;
    e = calloc(1, sizeof *e);
    if (!e) return NULL;
    e->dataset_id = ds;
    e->ino = ino;
    uint32_t b = bucket_hash(ds, ino);
    e->bucket_next = buf->buckets[b];
    buf->buckets[b] = e;
    return e;
}

static void free_range(stm_dbuf_range *r)
{
    if (!r) return;
    free(r->data);
    free(r);
}

/* Unlink + free entire inode entry. */
static void destroy_inode_locked(stm_dirty_buffer *buf, stm_dbuf_inode *e)
{
    uint32_t b = bucket_hash(e->dataset_id, e->ino);
    stm_dbuf_inode **slot = &buf->buckets[b];
    while (*slot && *slot != e) slot = &(*slot)->bucket_next;
    if (*slot) *slot = e->bucket_next;
    stm_dbuf_range *r = e->head;
    while (r) {
        stm_dbuf_range *n = r->next;
        free_range(r);
        r = n;
    }
    buf->total_bytes -= e->bytes;
    free(e);
}

static bool ranges_overlap(uint64_t a, uint64_t la,
                              uint64_t b, uint64_t lb)
{
    if (la == 0 || lb == 0) return false;
    return a < b + lb && b < a + la;
}

/* ───────────────────────────── public API ─────────────────────────── */

stm_status stm_dirty_buffer_create(size_t per_inode_cap_bytes,
                                       size_t global_cap_bytes,
                                       stm_dirty_buffer **out)
{
    if (!out) return STM_EINVAL;
    if (per_inode_cap_bytes == 0 || global_cap_bytes == 0) return STM_EINVAL;
    if (per_inode_cap_bytes > global_cap_bytes) return STM_EINVAL;
    stm_dirty_buffer *buf = calloc(1, sizeof *buf);
    if (!buf) return STM_ENOMEM;
    if (pthread_mutex_init(&buf->mu, NULL) != 0) {
        free(buf);
        return STM_ENOMEM;
    }
    buf->inode_cap   = per_inode_cap_bytes;
    buf->global_cap  = global_cap_bytes;
    buf->total_bytes = 0;
    *out = buf;
    return STM_OK;
}

void stm_dirty_buffer_destroy(stm_dirty_buffer *buf)
{
    if (!buf) return;
    pthread_mutex_lock(&buf->mu);
    for (uint32_t b = 0; b < STM_DBUF_BUCKETS; b++) {
        stm_dbuf_inode *e = buf->buckets[b];
        while (e) {
            stm_dbuf_inode *n = e->bucket_next;
            stm_dbuf_range *r = e->head;
            while (r) {
                stm_dbuf_range *rn = r->next;
                free_range(r);
                r = rn;
            }
            free(e);
            e = n;
        }
        buf->buckets[b] = NULL;
    }
    pthread_mutex_unlock(&buf->mu);
    pthread_mutex_destroy(&buf->mu);
    free(buf);
}

stm_status stm_dirty_buffer_insert(stm_dirty_buffer *buf,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t off, uint64_t len,
                                       const void *data)
{
    if (!buf || !data) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    /* Overflow guard. */
    if (off > UINT64_MAX - len) return STM_EINVAL;
    if (len > buf->inode_cap) return STM_ENOSPC;  /* impossibly large */

    pthread_mutex_lock(&buf->mu);

    /* Compute what the inode_bytes would be AFTER removing overlap. */
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    size_t overlap_bytes = 0;
    if (e) {
        for (stm_dbuf_range *r = e->head; r; r = r->next) {
            if (ranges_overlap(r->off, r->len, off, len)) {
                overlap_bytes += r->len;
            }
        }
    }
    size_t cur_inode_bytes = e ? e->bytes : 0;
    size_t cur_global_bytes = buf->total_bytes;
    /* Per writeback.tla::BufferedWrite cap clauses: after dropping
     * overlapping ranges and adding `len`, the per-inode + global
     * byte counters must respect the caps. */
    if (cur_inode_bytes - overlap_bytes + len > buf->inode_cap) {
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOSPC;
    }
    if (cur_global_bytes - overlap_bytes + len > buf->global_cap) {
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOSPC;
    }

    /* Allocate the new range up-front (so a malloc failure leaves
     * the buffer unmodified). */
    stm_dbuf_range *newr = malloc(sizeof *newr);
    if (!newr) {
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOMEM;
    }
    newr->off = off;
    newr->len = len;
    newr->next = NULL;
    newr->data = malloc((size_t)len);
    if (!newr->data) {
        free(newr);
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOMEM;
    }
    memcpy(newr->data, data, (size_t)len);

    /* Find-or-create the inode entry. We allocated the new range
     * already; if get_or_create fails we have to clean up. */
    e = get_or_create_inode_locked(buf, dataset_id, ino);
    if (!e) {
        free(newr->data);
        free(newr);
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOMEM;
    }

    /* Walk the sorted range list. Drop overlapping ranges + accumulate
     * bytes freed. Find the insertion point for the new range. */
    stm_dbuf_range **slot = &e->head;
    while (*slot) {
        stm_dbuf_range *r = *slot;
        if (ranges_overlap(r->off, r->len, off, len)) {
            /* Drop r. */
            *slot = r->next;
            e->bytes -= r->len;
            buf->total_bytes -= r->len;
            free_range(r);
            continue;
        }
        if (r->off >= off + len) break;   /* insertion point reached */
        slot = &r->next;
    }
    newr->next = *slot;
    *slot = newr;
    e->bytes      += len;
    buf->total_bytes += len;

    pthread_mutex_unlock(&buf->mu);
    return STM_OK;
}

stm_status stm_dirty_buffer_lookup(stm_dirty_buffer *buf,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t off, uint64_t len,
                                       void *out_buf, size_t *out_covered)
{
    if (!buf || !out_buf || !out_covered) return STM_EINVAL;
    *out_covered = 0;
    if (len == 0) return STM_OK;
    if (off > UINT64_MAX - len) return STM_EINVAL;

    pthread_mutex_lock(&buf->mu);
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    if (!e) {
        pthread_mutex_unlock(&buf->mu);
        return STM_OK;
    }

    /* Walk the sorted range list. Copy the LONGEST CONTIGUOUS prefix
     * of [off, off+len) into out_buf. Stop at the first gap. */
    uint8_t *dst = (uint8_t *)out_buf;
    uint64_t covered = 0;
    for (stm_dbuf_range *r = e->head; r; r = r->next) {
        if (r->off + r->len <= off + covered) {
            /* Range ends before our cursor — skip. */
            continue;
        }
        if (r->off > off + covered) {
            /* Gap before this range. Stop. */
            break;
        }
        /* Range covers [max(r->off, off+covered), r->off+r->len). */
        uint64_t take_start = off + covered;
        uint64_t take_end   = r->off + r->len;
        if (take_end > off + len) take_end = off + len;
        if (take_end <= take_start) {
            /* Defensive — shouldn't happen given sorted-non-overlap. */
            continue;
        }
        uint64_t take_len = take_end - take_start;
        uint64_t src_off  = take_start - r->off;
        memcpy(dst + covered, r->data + src_off, (size_t)take_len);
        covered += take_len;
        if (covered >= len) break;
    }
    *out_covered = (size_t)covered;

    pthread_mutex_unlock(&buf->mu);
    return STM_OK;
}

void stm_dirty_buffer_overlay(stm_dirty_buffer *buf,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t req_off, size_t req_len,
                                  void *out_buf)
{
    if (!buf || !out_buf || req_len == 0) return;
    if (req_off > UINT64_MAX - req_len) return;

    pthread_mutex_lock(&buf->mu);
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    if (!e) {
        pthread_mutex_unlock(&buf->mu);
        return;
    }
    uint8_t *dst = (uint8_t *)out_buf;
    uint64_t req_end = req_off + req_len;
    for (stm_dbuf_range *r = e->head; r; r = r->next) {
        if (r->off >= req_end) break;          /* list sorted; no more overlap */
        if (r->off + r->len <= req_off) continue; /* range fully before req */
        uint64_t s  = (r->off > req_off) ? r->off : req_off;
        uint64_t en = (r->off + r->len < req_end) ? (r->off + r->len) : req_end;
        if (en <= s) continue;
        uint64_t take_len = en - s;
        uint64_t dst_off  = s - req_off;
        uint64_t src_off  = s - r->off;
        memcpy(dst + dst_off, r->data + src_off, (size_t)take_len);
    }
    pthread_mutex_unlock(&buf->mu);
}

/* Coalesce contiguous buffered ranges into as few extent writes as
 * possible — realizing the dirty buffer's stated purpose ("absorbs
 * many-small-writes ... and emits them as fewer/larger extents at
 * flush time"). Without coalescing, each <=4 KiB range becomes its own
 * extent, and each extent pays a full AEAD-tag block -> ~2-2.7x storage
 * amplification that prematurely exhausts the pool (the #352 on-device
 * `go build` ENOSPC: an 8 MiB file consumed ~16-24 MiB, failing at the
 * exact on-device offset on a near-full pool).
 *
 * A run is the maximal prefix of contiguous ranges whose 4 KiB-aligned
 * span stays within inode_cap (== the extent recordsize), so each
 * emitted extent passes the extent layer's per-record size check
 * (fs_write_extent_aligned_locked's ERANGE guard / stm_sync_write_extent
 * len<=RECORDSIZE). The run's bytes are copied into one contiguous
 * buffer and emitted as a single cb. A fully-contiguous 8 MiB buffer
 * collapses from ~2048 tiny extents to 1-2 -> ~1x amplification.
 *
 * Pop-on-success is preserved at RUN granularity (the per-range
 * pop-on-success rationale, post-c60b9e9, generalizes): on cb failure
 * the run + all later ranges stay buffered (the fs retry dance
 * re-drains them, no duplicate-extent cycle since nothing was popped);
 * on success the whole run is freed. The spec's Flush (writeback.tla)
 * models draining ranges into committed extents abstractly — it does
 * not constrain extent granularity — so coalescing preserves
 * ReadHidesFlushOrder / FlushPaddrFreshness / FlushPreservesNoOverlap.
 *
 * Caller holds buf->mu. */
static stm_status drain_inode_coalesced_locked(stm_dirty_buffer *buf,
                                                  stm_dbuf_inode *e,
                                                  stm_dirty_buffer_drain_cb cb,
                                                  void *user)
{
    const uint64_t ds = e->dataset_id, ino = e->ino;
    const uint64_t BLK = (uint64_t)STM_UB_SIZE;

    while (e->head) {
        stm_dbuf_range *first = e->head;
        uint64_t run_start   = first->off;
        uint64_t run_end     = first->off + first->len;
        uint64_t aligned_off = run_start & ~(BLK - 1u);

        /* Extend over contiguous ranges while the emitted extent's
         * 4 KiB-aligned span stays within the recordsize cap. */
        stm_dbuf_range *stop = first->next;
        while (stop && stop->off == run_end) {
            uint64_t cand_end    = stop->off + stop->len;
            uint64_t aligned_end = (cand_end + BLK - 1u) & ~(BLK - 1u);
            if (aligned_end - aligned_off > (uint64_t)buf->inode_cap) break;
            run_end = cand_end;
            stop    = stop->next;
        }

        uint64_t    run_len   = run_end - run_start;
        const void *emit_data = first->data;   /* single-range fast path */
        uint8_t    *coal      = NULL;
        if (first->next != stop) {
            coal = malloc((size_t)run_len);
            if (coal) {
                for (stm_dbuf_range *x = first; x != stop; x = x->next)
                    memcpy(coal + (x->off - run_start), x->data,
                           (size_t)x->len);
                emit_data = coal;
            } else {
                /* Transient OOM: degrade to a single-range emit so the
                 * flush still makes progress (never wedges). */
                stop      = first->next;
                run_len   = first->len;
                emit_data = first->data;
            }
        }

        stm_status crc = cb(user, ds, ino, run_start, run_len, emit_data);
        free(coal);
        if (crc != STM_OK) return crc;

        /* Pop the emitted run on success. */
        while (e->head != stop) {
            stm_dbuf_range *done = e->head;
            e->head = done->next;
            e->bytes         -= done->len;
            buf->total_bytes -= done->len;
            free_range(done);
        }
    }
    return STM_OK;
}

stm_status stm_dirty_buffer_drain_ino(stm_dirty_buffer *buf,
                                          uint64_t dataset_id, uint64_t ino,
                                          stm_dirty_buffer_drain_cb cb,
                                          void *user)
{
    if (!buf || !cb) return STM_EINVAL;
    pthread_mutex_lock(&buf->mu);
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    if (!e || !e->head) {
        pthread_mutex_unlock(&buf->mu);
        return STM_OK;
    }
    stm_status rc = drain_inode_coalesced_locked(buf, e, cb, user);
    if (e->head == NULL) {
        /* Fully drained — destroy entry. */
        destroy_inode_locked(buf, e);
    }
    pthread_mutex_unlock(&buf->mu);
    return rc;
}

stm_status stm_dirty_buffer_drain_all(stm_dirty_buffer *buf,
                                          stm_dirty_buffer_drain_cb cb,
                                          void *user)
{
    if (!buf || !cb) return STM_EINVAL;
    pthread_mutex_lock(&buf->mu);
    stm_status first_err = STM_OK;
    /* Per-inode iteration uses the same pop-on-success semantics as
     * drain_ino — see the comment block there for the rationale. */
    for (uint32_t b = 0; b < STM_DBUF_BUCKETS; b++) {
        stm_dbuf_inode *e = buf->buckets[b];
        while (e) {
            stm_dbuf_inode *next = e->bucket_next;
            stm_status rc = drain_inode_coalesced_locked(buf, e, cb, user);
            if (e->head == NULL) {
                destroy_inode_locked(buf, e);
            } else {
                if (first_err == STM_OK) first_err = rc;
            }
            e = next;
        }
    }
    pthread_mutex_unlock(&buf->mu);
    return first_err;
}

void stm_dirty_buffer_drop_ino(stm_dirty_buffer *buf,
                                   uint64_t dataset_id, uint64_t ino)
{
    if (!buf) return;
    pthread_mutex_lock(&buf->mu);
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    if (e) destroy_inode_locked(buf, e);
    pthread_mutex_unlock(&buf->mu);
}

size_t stm_dirty_buffer_inode_bytes(stm_dirty_buffer *buf,
                                        uint64_t dataset_id, uint64_t ino)
{
    if (!buf) return 0;
    pthread_mutex_lock(&buf->mu);
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    size_t bytes = e ? e->bytes : 0;
    pthread_mutex_unlock(&buf->mu);
    return bytes;
}

size_t stm_dirty_buffer_total_bytes(stm_dirty_buffer *buf)
{
    if (!buf) return 0;
    pthread_mutex_lock(&buf->mu);
    size_t b = buf->total_bytes;
    pthread_mutex_unlock(&buf->mu);
    return b;
}

bool stm_dirty_buffer_has_ino(stm_dirty_buffer *buf,
                                  uint64_t dataset_id, uint64_t ino)
{
    if (!buf) return false;
    pthread_mutex_lock(&buf->mu);
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    bool present = (e != NULL && e->head != NULL);
    pthread_mutex_unlock(&buf->mu);
    return present;
}
