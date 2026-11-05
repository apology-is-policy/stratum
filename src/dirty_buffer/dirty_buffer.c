/* SPDX-License-Identifier: ISC */
/*
 * stm_dirty_buffer — per-inode plaintext write buffer (SWISS-4q-flush).
 *
 *   see include/stratum/dirty_buffer.h for the public API.
 *   see specs/writeback.tla for the spec this realizes.
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

/* The covering write a drain makes for a range that partly overlaps
 * extents: every range inside it shares this one charge, so writes into
 * one extent pay for its rewrite once. Its extents stay as they were while
 * a range inside it is buffered: an op that rewrites extents drains the
 * inode first, and a drain's covering write takes in every buffered byte
 * below where it ends. */
typedef struct stm_dbuf_cover {
    uint64_t               lo, hi;   /* bytes, block-aligned; lo == hi: not
                                      * known, so never shared */
    uint64_t               charge;   /* the whole covering write */
    uint32_t               refs;     /* buffered ranges inside it */
    uint32_t               keep;     /* an insert's scratch: refs after it */
    struct stm_dbuf_cover *next;
} stm_dbuf_cover;

typedef struct stm_dbuf_range {
    uint64_t                off;
    uint64_t                len;
    uint64_t                charge;   /* footprint blocks: its span, or only
                                       * its records inside a cover */
    stm_dbuf_cover         *cover;    /* NULL: its drain writes its span */
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
    uint64_t                footprint_blocks; /* ranges' and covers' charges */
    stm_dbuf_range         *head;    /* sorted by off, ascending */
    stm_dbuf_cover         *covers;
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
    /* The pool's hold on total_footprint_blocks; NULL: none. */
    stm_dirty_buffer_reserve_fn reserve;
    stm_dirty_buffer_release_fn release;
    void                       *res_user;
    uint32_t                    charge_factor; /* pool blocks per block */
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

static void free_covers(stm_dbuf_inode *e)
{
    while (e->covers) {
        stm_dbuf_cover *c = e->covers;
        e->covers = c->next;
        free(c);
    }
}

/* Drops a range's hold on its cover; the cover's charge when that was the
 * last hold, which the caller takes off the footprint. */
static uint64_t cover_put(stm_dbuf_inode *e, stm_dbuf_cover *c)
{
    if (!c || --c->refs > 0u) return 0;
    stm_dbuf_cover **s = &e->covers;
    while (*s != c) s = &(*s)->next;
    *s = c->next;
    uint64_t charge = c->charge;
    free(c);
    return charge;
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
    free_covers(e);
    buf->total_bytes -= e->bytes;
    buf->total_footprint_blocks -= e->footprint_blocks;
    if (e->footprint_blocks > 0u && buf->release)
        buf->release(buf->res_user, e->footprint_blocks);
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
 * A drain landing on PARTIALLY OVERLAPPED existing extents also rewrites
 * them whole (fs.c fs_write_extent_aligned_locked's covering write). The
 * caller charges those blocks as the insert's extra_blocks; the inode's
 * cover entry carries them, for every range inside it and the remnants
 * of a split. Left uncharged, a write
 * admitted on a near-full pool could never drain, and every commit after
 * it failed. DBUF_RECPIECE
 * mirrors STM_FS_RECORDSIZE_MAX (8 MiB) conservatively: a smaller real
 * recordsize would only mean MORE pieces than charged -- so keep the
 * mirror <= the fs constant. A range's charge is set once, at insert, and
 * every removal subtracts that charge, so accounting stays symmetric; a
 * cover's, when the last range inside it goes.
 * A drain that finds no free run long enough for a record writes it in
 * pieces, each with its own tag, so it may spend up to charge_factor
 * blocks per block of data (stm_dirty_buffer_set_charge_factor): the span
 * is charged that many times. */
#define DBUF_RECPIECE (8ull * 1024u * 1024u)
static uint64_t blocks_spanned(const stm_dirty_buffer *buf, uint64_t off,
                               uint64_t len)
{
    if (len == 0) return 0;
    uint64_t blk   = (uint64_t)STM_UB_SIZE;
    uint64_t first = off / blk;
    uint64_t last  = (off + len - 1u) / blk;
    uint64_t pieces = (len + DBUF_RECPIECE - 1u) / DBUF_RECPIECE;
    return buf->charge_factor * (last - first + 1u) + pieces;
}

/* A range's own charge: its span, or inside a cover, whose charge holds
 * the span, its records. */
static uint64_t range_charge(const stm_dirty_buffer *buf, uint64_t off,
                             uint64_t len, const stm_dbuf_cover *c)
{
    if (!c) return blocks_spanned(buf, off, len);
    return (len + DBUF_RECPIECE - 1u) / DBUF_RECPIECE;
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
    buf->charge_factor = 1u;
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
            free_covers(e);
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
                                        uint64_t extra_blocks,
                                        uint64_t max_footprint_blocks,
                                        stm_dirty_buffer_admit_fn admit,
                                        void *admit_user)
{
    if (!buf || !data) return STM_EINVAL;
    if (extra_blocks > (uint64_t)UINT32_MAX) return STM_EINVAL;
    if (len == 0) return STM_EINVAL;
    /* Overflow guard. */
    if (off > UINT64_MAX - len) return STM_EINVAL;
    if (len > buf->inode_cap) return STM_ENOSPC;  /* impossibly large */

    pthread_mutex_lock(&buf->mu);
    uint64_t c_lo = 0, c_hi = 0;
    if (admit) {
        stm_status as = admit(admit_user, dataset_id, ino, off, len,
                              &extra_blocks, &c_lo, &c_hi);
        if (as == STM_OK && extra_blocks > (uint64_t)UINT32_MAX)
            as = STM_EINVAL;
        if (as != STM_OK) {
            pthread_mutex_unlock(&buf->mu);
            return as;
        }
    }

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
        for (stm_dbuf_cover *c = e->covers; c; c = c->next) c->keep = c->refs;
        for (stm_dbuf_range *r = e->head; r; r = r->next) {
            if (ranges_overlap(r->off, r->len, off, len)) {
                if (!first_ov) first_ov = r;
                last_ov = r;
                dropped_bytes += r->len;
                removed_footprint += r->charge;
                if (r->cover) r->cover->keep--;
            }
        }
    }
    uint64_t end = off + len;
    uint64_t head_len = (first_ov && first_ov->off < off)
                            ? off - first_ov->off : 0u;
    uint64_t last_end = last_ov ? last_ov->off + last_ov->len : 0u;
    uint64_t tail_len = (last_ov && last_end > end) ? last_end - end : 0u;
    /* #40: the charges of the head-remnant + new range + tail-remnant.
     * Per-range (each stored separately) so it matches the drain-time
     * subtraction; conservative vs the contiguous union (see blocks_spanned).
     * A remnant stays inside its range's cover. The new range joins a cover
     * that holds its own (as the cover stands now), or charges its cover
     * whole: the extra beyond the range plus the range's blocks. */
    stm_dbuf_cover *share = NULL;
    uint64_t cover_charge = 0;
    if (extra_blocks > 0u) {
        for (stm_dbuf_cover *c = e ? e->covers : NULL; c && !share;
             c = c->next)
            if (c->lo < c->hi && c->lo <= c_lo && c_hi <= c->hi && c_lo < c_hi)
                share = c;
        if (!share)
            cover_charge = extra_blocks
                         + blocks_spanned(buf, off, len)
                         - (len + DBUF_RECPIECE - 1u) / DBUF_RECPIECE;
    }
    bool covered = extra_blocks > 0u;
    uint64_t new_charge  = covered
        ? (len + DBUF_RECPIECE - 1u) / DBUF_RECPIECE
        : blocks_spanned(buf, off, len);
    uint64_t head_charge = head_len > 0u
        ? range_charge(buf, first_ov->off, head_len, first_ov->cover) : 0u;
    uint64_t tail_charge = tail_len > 0u
        ? range_charge(buf, end, tail_len, last_ov->cover) : 0u;
    if (head_len > 0u && first_ov->cover) first_ov->cover->keep++;
    if (tail_len > 0u && last_ov->cover) last_ov->cover->keep++;
    if (share) share->keep++;
    for (stm_dbuf_cover *c = e ? e->covers : NULL; c; c = c->next)
        if (c->keep == 0u) removed_footprint += c->charge;
    uint64_t added_footprint = new_charge + head_charge + tail_charge
                             + cover_charge;

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
     * free blocks, for a caller that passes them; the fs holds the charge in
     * the pool's reservation instead, below).
     * Checked HERE -- atomically with the insert under buf->mu -- so two
     * concurrent SH writers cannot both pass a stale free-space snapshot and
     * jointly over-admit (the check-then-insert race). The bound itself is
     * only as fresh as its reading: an admit callback reads it here, after
     * any drain. removed_footprint <= total_footprint_blocks always (the
     * overlapped ranges are resident). */
    if (buf->total_footprint_blocks - removed_footprint + added_footprint
            > max_footprint_blocks) {
        pthread_mutex_unlock(&buf->mu);
        return STM_ENOSPC;
    }
    /* The pool holds the net charge with the insert: a refusal leaves the
     * buffer as it was. */
    uint64_t taken = added_footprint > removed_footprint
                   ? added_footprint - removed_footprint : 0u;
    if (taken > 0u && buf->reserve) {
        stm_status rs = buf->reserve(buf->res_user, taken);
        if (rs != STM_OK) {
            pthread_mutex_unlock(&buf->mu);
            return rs;
        }
    } else {
        taken = 0u;
    }

    /* Allocate the new range AND both remnants up-front (so a malloc
     * failure leaves the buffer unmodified). The remnant data is copied
     * out of the still-live overlapped ranges before any mutation. */
    stm_dbuf_range *newr = NULL, *headr = NULL, *tailr = NULL;
    stm_dbuf_cover *newc = NULL;
    if (covered && !share) {
        newc = malloc(sizeof *newc);
        if (!newc) goto oom;
        newc->lo = c_lo < c_hi ? c_lo : 0u;
        newc->hi = c_lo < c_hi ? c_hi : 0u;
        newc->charge = cover_charge;
        newc->refs = 1u;
        newc->keep = 1u;
    }
    newr = malloc(sizeof *newr);
    if (!newr) goto oom;
    newr->off = off;
    newr->len = len;
    newr->charge = new_charge;
    newr->cover = share ? share : newc;
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
        headr->charge = head_charge;
        headr->cover = first_ov->cover;
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
        tailr->charge = tail_charge;
        tailr->cover = last_ov->cover;
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
            uint64_t sp = r->charge;
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
    /* The covers the superseded ranges held: what the insert left them. */
    for (stm_dbuf_cover **cs = &e->covers; *cs; ) {
        stm_dbuf_cover *c = *cs;
        c->refs = c->keep;
        if (c->refs > 0u) { cs = &c->next; continue; }
        *cs = c->next;
        e->footprint_blocks         -= c->charge;
        buf->total_footprint_blocks -= c->charge;
        free(c);
    }
    if (newc) { newc->next = e->covers; e->covers = newc; }
    size_t added = (size_t)len + (size_t)head_len + (size_t)tail_len;
    e->bytes         += added;
    buf->total_bytes += added;
    e->footprint_blocks         += added_footprint;
    buf->total_footprint_blocks += added_footprint;
    if (removed_footprint > added_footprint && buf->release)
        buf->release(buf->res_user, removed_footprint - added_footprint);

    pthread_mutex_unlock(&buf->mu);
    return STM_OK;

oom:
    free(newc);
    if (newr)  { free(newr->data);  free(newr);  }
    if (headr) { free(headr->data); free(headr); }
    if (tailr) { free(tailr->data); free(tailr); }
    if (taken > 0u && buf->release) buf->release(buf->res_user, taken);
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
                                0u, UINT64_MAX, NULL, NULL);
}

stm_status stm_dirty_buffer_insert_bounded(stm_dirty_buffer *buf,
                                               uint64_t dataset_id, uint64_t ino,
                                               uint64_t off, uint64_t len,
                                               const void *data,
                                               uint64_t extra_blocks,
                                               uint64_t max_footprint_blocks)
{
    return dbuf_insert_bounded(buf, dataset_id, ino, off, len, data,
                                extra_blocks, max_footprint_blocks,
                                NULL, NULL);
}

stm_status stm_dirty_buffer_insert_admitted(stm_dirty_buffer *buf,
                                            uint64_t dataset_id, uint64_t ino,
                                            uint64_t off, uint64_t len,
                                            const void *data,
                                            stm_dirty_buffer_admit_fn admit,
                                            void *admit_user)
{
    if (!admit) return STM_EINVAL;
    return dbuf_insert_bounded(buf, dataset_id, ino, off, len, data,
                                0u, UINT64_MAX, admit, admit_user);
}

void stm_dirty_buffer_set_charge_factor(stm_dirty_buffer *buf,
                                        uint32_t factor)
{
    if (!buf || factor == 0u) return;
    pthread_mutex_lock(&buf->mu);
    buf->charge_factor = factor;
    pthread_mutex_unlock(&buf->mu);
}

void stm_dirty_buffer_set_reservation(stm_dirty_buffer *buf,
                                      stm_dirty_buffer_reserve_fn reserve,
                                      stm_dirty_buffer_release_fn release,
                                      void *user)
{
    if (!buf) return;
    pthread_mutex_lock(&buf->mu);
    buf->reserve  = reserve;
    buf->release  = release;
    buf->res_user = user;
    pthread_mutex_unlock(&buf->mu);
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

/* Copies the inode's buffered bytes in [req_off, req_end) into dst, which
 * holds that span. Caller holds buf->mu. */
static void overlay_locked(const stm_dbuf_inode *e, uint64_t req_off,
                           uint64_t req_end, uint8_t *dst)
{
    for (const stm_dbuf_range *r = e->head; r; r = r->next) {
        if (r->off >= req_end) break;          /* list sorted; no more overlap */
        if (r->off + r->len <= req_off) continue; /* range fully before req */
        uint64_t s  = (r->off > req_off) ? r->off : req_off;
        uint64_t en = (r->off + r->len < req_end) ? (r->off + r->len) : req_end;
        if (en <= s) continue;
        memcpy(dst + (s - req_off), r->data + (s - r->off), (size_t)(en - s));
    }
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
    overlay_locked(e, req_off, req_off + req_len, (uint8_t *)out_buf);
    size_t resident = e->bytes;
    pthread_mutex_unlock(&buf->mu);
    return resident;
}


struct stm_dirty_buffer_drain_view {
    const stm_dbuf_inode *e;
};

void stm_dirty_buffer_view_overlay(const stm_dirty_buffer_drain_view *view,
                                   uint64_t off, uint64_t len, void *dst)
{
    if (!view || !dst || len == 0u || off > UINT64_MAX - len) return;
    overlay_locked(view->e, off, off + len, (uint8_t *)dst);
}

/* Drops the first `cut` bytes of a range whose head a drain wrote. The
 * charge stays: the rest lies inside the cover it was taken for. Caller
 * holds buf->mu. */
static void trim_range_head(stm_dirty_buffer *buf, stm_dbuf_inode *e,
                            stm_dbuf_range *r, uint64_t cut)
{
    memmove(r->data, r->data + cut, (size_t)(r->len - cut));
    r->off += cut;
    r->len -= cut;
    e->bytes         -= cut;
    buf->total_bytes -= cut;
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
 * A run's write can take in more than the run: the covering write
 * rewrites whole every extent the run partly overlaps, as one new
 * extent. It takes the other buffered bytes inside it from the view and
 * reports where it ended, and everything below that is dropped here.
 * Otherwise the next run, starting inside that new extent, would rewrite
 * it whole again: runs that each straddle a block boundary rewrote a
 * growing extent once per run, more blocks than they were admitted on.
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

        stm_dirty_buffer_drain_view view = { e };
        uint64_t upto = run_start + run_len;
        stm_status crc = cb(user, ds, ino, run_start, run_len, emit_data,
                            &view, &upto);
        free(coal);
        if (crc != STM_OK) {
            if (buf->release) buf->release(buf->res_user, 0u);
            return crc;
        }
        if (upto < run_start + run_len) upto = run_start + run_len;

        /* Pop what the write took: the run, and every later byte below
         * upto. A range crossing upto keeps its tail. */
        uint64_t popped = 0;
        while (e->head && e->head->off + e->head->len <= upto) {
            stm_dbuf_range *done = e->head;
            e->head = done->next;
            e->bytes         -= done->len;
            buf->total_bytes -= done->len;
            uint64_t sp = done->charge + cover_put(e, done->cover);
            e->footprint_blocks         -= sp;
            buf->total_footprint_blocks -= sp;
            popped += sp;
            free_range(buf, done);
        }
        if (buf->release) buf->release(buf->res_user, popped);
        if (e->head && e->head->off < upto)
            trim_range_head(buf, e, e->head, upto - e->head->off);
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
