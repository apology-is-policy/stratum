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
 *   Insert maintains this by SPLIT-SALVAGING overlapped ranges: the
 *   new range supersedes only the bytes it actually covers; a
 *   partially-overlapped range's sticking-out head/tail bytes are
 *   preserved as remnant ranges (at most two exist -- only the first
 *   overlapped range can stick out before the write, only the last
 *   can stick out past it). Whole-dropping a partially-overlapped
 *   range would DISCARD its non-overlapped bytes -- the Thylacine
 *   #342 on-disk zeros corruption (a 41-byte updateBuildID stamp
 *   dropped a buffered 186-byte compiler flush; the lost bytes fell
 *   through to an underlying extent's zero pad). The same lost-tail
 *   class the extent layer's covering write closed (#352-F1), one
 *   layer up.
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
    uint64_t                cap;      /* data allocation size (>= len; a
                                       * shelf-reused buffer keeps its true
                                       * capacity so re-shelving never
                                       * shrinks the shelf's metadata) */
    uint8_t                *data;     /* owned */
    struct stm_dbuf_range  *next;
} stm_dbuf_range;

typedef struct stm_dbuf_inode {
    uint64_t                dataset_id;
    uint64_t                ino;
    size_t                  bytes;   /* sum of all ranges' len */
    uint64_t                footprint_blocks; /* sum of ranges' blocks_spanned */
    stm_dbuf_range         *head;    /* sorted by off, ascending */
    struct stm_dbuf_inode  *bucket_next;
} stm_dbuf_inode;

/* T4-A-2 (task #58): the range data-buffer shelf. The insert band was
 * measured COPY-bound at ~2.3 GB/s -- demand-zero-fault speed, not
 * memcpy speed: every big insert malloc'd a fresh buffer and first-
 * touched all its pages inside the payload memcpy (one fault per 4 KiB
 * page). Freed range buffers >= DBUF_SHELF_MIN park here (bounded
 * slots; every alloc/free site already holds buf->mu), so the dominant
 * homogeneous ~127 KiB flush class reuses resident, TLB-warm pages and
 * the copy runs at memory speed. A reused buffer's stale prior bytes
 * are unreachable: every consumer serves within [0, r->len) and the
 * insert memcpys exactly that window. (Detectability caveat inherent
 * to any reuse pool: a reused buffer is cap >= len bytes, so a
 * hypothetical consumer over-read past len would return stale bytes
 * where a fresh exact-len malloc would ASan-trap -- the byte-exactness
 * regression leg guards the real hazard.) Worst-case shelf residency is
 * DBUF_SHELF_SLOTS x the largest shelved cap (24 x ~256 KiB ~= 6 MiB),
 * owned by the buffer and freed at destroy. */
#define DBUF_SHELF_SLOTS 24u
#define DBUF_SHELF_MIN   (32u * 1024u)

struct stm_dirty_buffer {
    pthread_mutex_t   mu;
    size_t            inode_cap;
    size_t            global_cap;
    size_t            total_bytes;
    uint64_t          total_footprint_blocks; /* #40: sum of inodes' footprint */
    stm_dbuf_inode   *buckets[STM_DBUF_BUCKETS];
    struct { uint8_t *p; uint64_t cap; } shelf[DBUF_SHELF_SLOTS];
    uint32_t          shelf_n;
    uint64_t          shelf_hits;    /* shelf_alloc served from the shelf */
    uint64_t          shelf_misses;  /* shelf_alloc fell to malloc */
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

/* Free a range, shelving its data buffer for reuse when it is big
 * enough to matter and the shelf has room (caller holds buf->mu). */
static void free_range(stm_dirty_buffer *buf, stm_dbuf_range *r)
{
    if (!r) return;
    if (r->data && r->cap >= DBUF_SHELF_MIN
        && buf->shelf_n < DBUF_SHELF_SLOTS) {
        buf->shelf[buf->shelf_n].p   = r->data;
        buf->shelf[buf->shelf_n].cap = r->cap;
        buf->shelf_n++;
    } else {
        free(r->data);
    }
    free(r);
}

/* Shelf-first data-buffer alloc (caller holds buf->mu). Reuse a parked
 * buffer when len fits within its capacity with bounded slack
 * (cap/2 <= len keeps the waste under 2x; the homogeneous flush class
 * matches near-exactly). *cap_out records the TRUE allocation size for
 * the range's cap field. */
static uint8_t *shelf_alloc(stm_dirty_buffer *buf, uint64_t len,
                              uint64_t *cap_out)
{
    for (uint32_t i = 0; i < buf->shelf_n; i++) {
        uint64_t cap = buf->shelf[i].cap;
        if (len <= cap && len >= cap / 2u) {
            uint8_t *ptr = buf->shelf[i].p;
            buf->shelf_n--;
            buf->shelf[i] = buf->shelf[buf->shelf_n];
            *cap_out = cap;
            buf->shelf_hits++;
            return ptr;
        }
    }
    *cap_out = len;
    buf->shelf_misses++;
    return malloc((size_t)len);
}

void stm_dirty_buffer_shelf_stats(stm_dirty_buffer *buf,
                                    uint64_t *hits, uint64_t *misses)
{
    if (!buf) { if (hits) *hits = 0; if (misses) *misses = 0; return; }
    pthread_mutex_lock(&buf->mu);
    if (hits)   *hits   = buf->shelf_hits;
    if (misses) *misses = buf->shelf_misses;
    pthread_mutex_unlock(&buf->mu);
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
        free_range(buf, r);
        r = n;
    }
    buf->total_bytes -= e->bytes;
    buf->total_footprint_blocks -= e->footprint_blocks;
    free(e);
}

static bool ranges_overlap(uint64_t a, uint64_t la,
                              uint64_t b, uint64_t lb)
{
    if (la == 0 || lb == 0) return false;
    return a < b + lb && b < a + la;
}

/* Distinct STM_UB_SIZE blocks a byte range touches -- the pool footprint a
 * flush reserves for it, since a write aligns to block boundaries (a 1-byte
 * write to a fresh block costs a whole block). The #40 admission counts in
 * these, not logical bytes. Per-range summing is CONSERVATIVE (two adjacent
 * sub-block ranges in one block count it twice) -- safe: it never under-counts
 * the footprint, so admission never over-admits; the only cost is a rare, at
 * most spurious refusal on sub-block scatter within a block. len==0 -> 0.
 *
 * #40 overhead hardening (CHASE C-2): the drain emits each range as
 * <=RECORDSIZE extents whose ON-DISK reserve is plaintext + AEAD tag +
 * record header (sync.c: total_bytes = len + tag_len), i.e. up to ONE
 * block MORE per emitted extent than the plaintext span. Charge that
 * overhead here -- 1 block per started RECORDSIZE piece -- so "accepted
 * buffered write" stays "committable" exactly FOR EXTENTS LANDING ON
 * HOLES (the transition/append shape: aligned, no prior extents; the
 * charged sum >= the drain's reserve by ceil-subadditivity under run
 * coalescing). Pre-fix the invariant held only when the refusal margin
 * happened to exceed the summed per-extent overhead; the fs-level
 * transition-into-buffer change shifted the margin and exposed it.
 * REMAINING residual (C-2-F2-audit F3): a drain landing on PARTIALLY
 * OVERLAPPED existing extents pays the covering-write RMW expansion
 * (fs.c fs_write_extent_aligned_locked -- up to the neighbors' full
 * spans), which is NOT charged here; that corner stays a
 * conservative-retry residual (reclaim-on-ENOSPC + the fs retry dance),
 * bounded to availability, never corruption. DBUF_RECPIECE
 * mirrors STM_FS_RECORDSIZE_MAX (8 MiB) conservatively: a smaller real
 * recordsize would only mean MORE pieces than charged -- so keep the
 * mirror <= the fs constant. Used by every footprint site (insert add,
 * overlap vacate, per-range remove) so accounting stays symmetric. */
#define DBUF_RECPIECE (8ull * 1024u * 1024u)
static uint64_t blocks_spanned(uint64_t off, uint64_t len)
{
    if (len == 0) return 0;
    uint64_t blk   = (uint64_t)STM_UB_SIZE;
    uint64_t first = off / blk;
    uint64_t last  = (off + len - 1u) / blk;
    uint64_t pieces = (len + DBUF_RECPIECE - 1u) / DBUF_RECPIECE;
    return last - first + 1u + pieces;
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
                free_range(buf, r);
                r = rn;
            }
            free(e);
            e = n;
        }
        buf->buckets[b] = NULL;
    }
    for (uint32_t i = 0; i < buf->shelf_n; i++)
        free(buf->shelf[i].p);
    buf->shelf_n = 0;
    pthread_mutex_unlock(&buf->mu);
    pthread_mutex_destroy(&buf->mu);
    free(buf);
}

static stm_status dbuf_insert_bounded(stm_dirty_buffer *buf,
                                        uint64_t dataset_id, uint64_t ino,
                                        uint64_t off, uint64_t len,
                                        const void *data,
                                        uint64_t max_footprint_blocks)
{
    if (!buf || !data) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    /* Overflow guard. */
    if (off > UINT64_MAX - len) return STM_EINVAL;
    if (len > buf->inode_cap) return STM_ENOSPC;  /* impossibly large */

    pthread_mutex_lock(&buf->mu);

    /* Pre-scan: find the overlapped ranges + the split-salvage remnants.
     * The list is sorted + non-overlapping, so the overlapped ranges are
     * consecutive and only the FIRST can stick out before the new write
     * (head remnant) and only the LAST past it (tail remnant); one range
     * fully containing the write yields both. The new range supersedes
     * only [off, off+len) -- the remnants keep every other live byte
     * (whole-dropping them was the Thylacine #342 data loss). */
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    stm_dbuf_range *first_ov = NULL, *last_ov = NULL;
    size_t dropped_bytes = 0;
    uint64_t removed_footprint = 0;   /* #40: block-spans the overlapped ranges vacate */
    if (e) {
        for (stm_dbuf_range *r = e->head; r; r = r->next) {
            if (ranges_overlap(r->off, r->len, off, len)) {
                if (!first_ov) first_ov = r;
                last_ov = r;
                dropped_bytes += r->len;
                removed_footprint += blocks_spanned(r->off, r->len);
            }
        }
    }
    uint64_t end = off + len;
    uint64_t head_len = (first_ov && first_ov->off < off)
                            ? off - first_ov->off : 0u;
    uint64_t last_end = last_ov ? last_ov->off + last_ov->len : 0u;
    uint64_t tail_len = (last_ov && last_end > end) ? last_end - end : 0u;
    /* #40: block-spans the head-remnant + new range + tail-remnant occupy.
     * Per-range (each stored separately) so it matches the drain-time
     * subtraction; conservative vs the contiguous union (see blocks_spanned). */
    uint64_t added_footprint = blocks_spanned(off, len)
        + (head_len > 0u ? blocks_spanned(first_ov->off, head_len) : 0u)
        + (tail_len > 0u ? blocks_spanned(end, tail_len) : 0u);

    /* Per writeback.tla::BufferedWrite cap clauses: after superseding the
     * covered bytes (dropped minus the salvaged remnants) and adding
     * `len`, the per-inode + global byte counters must respect the caps.
     * superseded >= 0 always: the remnants are sub-spans of the dropped
     * ranges. */
    size_t superseded = dropped_bytes - (size_t)head_len - (size_t)tail_len;
    size_t cur_inode_bytes = e ? e->bytes : 0;
    size_t cur_global_bytes = buf->total_bytes;
    if (cur_inode_bytes - superseded + len > buf->inode_cap) {
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOSPC;
    }
    if (cur_global_bytes - superseded + len > buf->global_cap) {
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOSPC;
    }
    /* #40 pool-aware admission: the buffered block footprint (what a flush
     * reserves from the pool) must stay <= max_footprint_blocks (the pool's
     * free blocks), so an accepted buffered write is always committable.
     * Checked HERE -- atomically with the insert under buf->mu -- so two
     * concurrent SH writers cannot both pass a stale free-space snapshot and
     * jointly over-admit (the check-then-insert race). removed_footprint <=
     * total_footprint_blocks always (the overlapped ranges are resident). */
    if (buf->total_footprint_blocks - removed_footprint + added_footprint
            > max_footprint_blocks) {
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOSPC;
    }

    /* Allocate the new range AND both remnants up-front (so a malloc
     * failure leaves the buffer unmodified). The remnant data is copied
     * out of the still-live overlapped ranges before any mutation. */
    stm_dbuf_range *newr = NULL, *headr = NULL, *tailr = NULL;
    newr = malloc(sizeof *newr);
    if (!newr) goto oom;
    newr->off = off;
    newr->len = len;
    newr->cap = 0;
    newr->next = NULL;
    newr->data = shelf_alloc(buf, len, &newr->cap);
    if (!newr->data) goto oom;
    memcpy(newr->data, data, (size_t)len);

    if (head_len > 0u) {
        headr = malloc(sizeof *headr);
        if (!headr) goto oom;
        headr->off = first_ov->off;
        headr->len = head_len;
        headr->cap = 0;
        headr->next = NULL;
        headr->data = shelf_alloc(buf, head_len, &headr->cap);
        if (!headr->data) goto oom;
        memcpy(headr->data, first_ov->data, (size_t)head_len);
    }
    if (tail_len > 0u) {
        tailr = malloc(sizeof *tailr);
        if (!tailr) goto oom;
        tailr->off = end;
        tailr->len = tail_len;
        tailr->cap = 0;
        tailr->next = NULL;
        tailr->data = shelf_alloc(buf, tail_len, &tailr->cap);
        if (!tailr->data) goto oom;
        memcpy(tailr->data, last_ov->data + (last_ov->len - tail_len),
               (size_t)tail_len);
    }

    /* Find-or-create the inode entry. We allocated the new ranges
     * already; if get_or_create fails we have to clean up. */
    e = get_or_create_inode_locked(buf, dataset_id, ino);
    if (!e) goto oom;

    /* Walk the sorted range list. Drop overlapped ranges + find the
     * insertion point, then splice head-remnant -> new -> tail-remnant.
     * Order stays sorted: headr->off < off (a strict prefix of the first
     * overlapped range), tailr->off == end, and any kept range past the
     * splice has r->off >= end but cannot start inside [end, end+tail_len)
     * (it would have overlapped last_ov, violating the invariant). */
    stm_dbuf_range **slot = &e->head;
    while (*slot) {
        stm_dbuf_range *r = *slot;
        if (ranges_overlap(r->off, r->len, off, len)) {
            /* Superseded: its salvageable head/tail already live in
             * headr/tailr. */
            *slot = r->next;
            e->bytes -= r->len;
            buf->total_bytes -= r->len;
            uint64_t sp = blocks_spanned(r->off, r->len);
            e->footprint_blocks         -= sp;
            buf->total_footprint_blocks -= sp;
            free_range(buf, r);
            continue;
        }
        if (r->off >= end) break;   /* insertion point reached */
        slot = &r->next;
    }
    if (tailr) { tailr->next = *slot; *slot = tailr; }
    else       { newr->next  = *slot; }
    if (tailr) newr->next = tailr;
    if (headr) { headr->next = newr; *slot = headr; }
    else       { *slot = newr; }
    size_t added = (size_t)len + (size_t)head_len + (size_t)tail_len;
    e->bytes         += added;
    buf->total_bytes += added;
    e->footprint_blocks         += added_footprint;
    buf->total_footprint_blocks += added_footprint;

    pthread_mutex_unlock(&buf->mu);
    return STM_OK;

oom:
    if (newr)  { free(newr->data);  free(newr);  }
    if (headr) { free(headr->data); free(headr); }
    if (tailr) { free(tailr->data); free(tailr); }
    pthread_mutex_unlock(&buf->mu);
    return STM_ENOMEM;
}

stm_status stm_dirty_buffer_insert(stm_dirty_buffer *buf,
                                       uint64_t dataset_id, uint64_t ino,
                                       uint64_t off, uint64_t len,
                                       const void *data)
{
    /* Unbounded by pool footprint (the RAM caps still apply). The footprint
     * counters are maintained regardless, so a later bounded insert sees a
     * correct total. */
    return dbuf_insert_bounded(buf, dataset_id, ino, off, len, data,
                                UINT64_MAX);
}

stm_status stm_dirty_buffer_insert_bounded(stm_dirty_buffer *buf,
                                               uint64_t dataset_id, uint64_t ino,
                                               uint64_t off, uint64_t len,
                                               const void *data,
                                               uint64_t max_footprint_blocks)
{
    return dbuf_insert_bounded(buf, dataset_id, ino, off, len, data,
                                max_footprint_blocks);
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

size_t stm_dirty_buffer_overlay(stm_dirty_buffer *buf,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t req_off, size_t req_len,
                                  void *out_buf)
{
    /* Returns the inode's post-overlay resident byte count (0 if absent) --
     * the C-2-F2-audit F2 fix's coherence token: the buffered-read caller
     * compares it to the pre-fill count and retries the fill+overlay while
     * they differ (a cross-inode drain_all -- which holds buf->mu across
     * the WHOLE drain, cbs included -- popped ranges between the reader's
     * fill and this overlay, landing them as extents the fill predates).
     * Termination is monotone: same-ino inserts are excluded by the
     * reader's shared pin, so the count only DECREASES -- at most one
     * retry per popped-run episode. */
    if (!buf || !out_buf || req_len == 0) return 0;
    if (req_off > UINT64_MAX - req_len) return 0;

    pthread_mutex_lock(&buf->mu);
    stm_dbuf_inode *e = find_inode_locked(buf, dataset_id, ino);
    if (!e) {
        pthread_mutex_unlock(&buf->mu);
        return 0;
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
    size_t resident = e->bytes;
    pthread_mutex_unlock(&buf->mu);
    return resident;
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
            uint64_t sp = blocks_spanned(done->off, done->len);
            e->footprint_blocks         -= sp;
            buf->total_footprint_blocks -= sp;
            free_range(buf, done);
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

uint64_t stm_dirty_buffer_total_footprint_blocks(stm_dirty_buffer *buf)
{
    if (!buf) return 0;
    pthread_mutex_lock(&buf->mu);
    uint64_t f = buf->total_footprint_blocks;
    pthread_mutex_unlock(&buf->mu);
    return f;
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
