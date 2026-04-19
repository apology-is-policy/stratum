/*
 * Persistent allocator delta log — Phase D #2, Stage 2.
 *
 * Buffers allocator deltas in memory and flushes them to a backward-
 * linked chunk chain on commit. See include/stratum/space.h for the
 * format contract and docs/STRATUM.md §5.5 for the staging plan.
 *
 * Stage 2 holds ALL log entries in memory (append-only array). This is
 * fine while the log is in isolation tests; Stage 3 integration will
 * need per-chunk streaming to keep RAM bounded for long-running sessions
 * between folds.
 */

#include "stratum/space.h"
#include "stratum/block.h"
#include "stratum/csum.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define STM_SPACE_LOG_MAGIC  0x5354524d2d2d4c47ULL /* "STRM--LG" */

struct stm_space_log {
    struct stm_block_dev   *dev;
    stm_space_log_alloc_cb  alloc_cb;
    void                   *alloc_ctx;

    /* All entries currently known to the log, in insert order. Includes
     * both on-disk and pending. Built from the chain at open-time, then
     * extended by stm_space_log_append. */
    struct stm_space_entry *entries;
    uint32_t                count;
    uint32_t                capacity;

    /* How many of `entries` are already persisted as chunks. Append
     * advances `count`; commit advances `persisted` by writing the tail
     * of new entries to new chunks linked backward to the old head. */
    uint32_t                persisted;

    /* Paddrs of the persisted chunks in order from oldest to newest.
     * The newest is the current head (what gets stored in the SB).
     * Kept in-memory so truncate can free all of them without re-walking
     * the chain on disk. */
    uint64_t               *chunk_paddrs;
    uint32_t                nchunks;
    uint32_t                chunks_cap;
};

/* ── on-disk encode/decode ────────────────────────────────────────── */

static void encode_hdr(struct stm_space_log_hdr *h,
                       uint64_t gen, uint64_t prev_paddr, uint32_t count)
{
    memset(h, 0, sizeof(*h));
    h->slh_magic       = cpu_to_le64(STM_SPACE_LOG_MAGIC);
    h->slh_gen          = cpu_to_le64(gen);
    h->slh_prev_paddr   = cpu_to_le64(prev_paddr);
    h->slh_count        = cpu_to_le32(count);
    /* csum filled in after the body is serialized */
}

static int grow_entries(struct stm_space_log *log, uint32_t needed)
{
    if (log->capacity >= needed) return 0;
    uint32_t cap = log->capacity ? log->capacity : 64;
    while (cap < needed) {
        if (cap > UINT32_MAX / 2) return -ENOMEM;
        cap *= 2;
    }
    void *nb = realloc(log->entries, (size_t)cap * sizeof(*log->entries));
    if (!nb) return -ENOMEM;
    log->entries  = nb;
    log->capacity = cap;
    return 0;
}

static int grow_chunks(struct stm_space_log *log, uint32_t needed)
{
    if (log->chunks_cap >= needed) return 0;
    uint32_t cap = log->chunks_cap ? log->chunks_cap : 8;
    while (cap < needed) {
        if (cap > UINT32_MAX / 2) return -ENOMEM;
        cap *= 2;
    }
    void *nb = realloc(log->chunk_paddrs, (size_t)cap * sizeof(*log->chunk_paddrs));
    if (!nb) return -ENOMEM;
    log->chunk_paddrs = nb;
    log->chunks_cap   = cap;
    return 0;
}

/* Read one chunk, verify, extract entries into the tail of log->entries.
 * Returns prev_paddr via *out_prev (0 = chain tail reached). */
static int read_chunk(struct stm_space_log *log, uint64_t paddr,
                      uint64_t *out_prev)
{
    uint8_t buf[STM_SPACE_LOG_CHUNK_SIZE];
    int rc = stm_block_read(log->dev, paddr, buf, sizeof(buf));
    if (rc) return rc;

    const struct stm_space_log_hdr *h = (const struct stm_space_log_hdr *)buf;
    if (le64_to_cpu(h->slh_magic) != STM_SPACE_LOG_MAGIC) return -EIO;

    uint32_t count = le32_to_cpu(h->slh_count);
    if (count > STM_SPACE_LOG_MAX_ENTRIES) return -EIO;

    /* Verify csum. Layout: header-with-csum-zeroed ‖ entries. */
    struct stm_space_log_hdr vh = *h;
    memset(vh.slh_csum, 0, sizeof(vh.slh_csum));
    uint8_t tmp[STM_SPACE_LOG_CHUNK_SIZE];
    memcpy(tmp, &vh, sizeof(vh));
    memcpy(tmp + sizeof(vh), buf + sizeof(vh),
           sizeof(buf) - sizeof(vh));
    if (stm_csum_verify(tmp, sizeof(tmp), h->slh_csum) != 0) return -EIO;

    if (grow_entries(log, log->count + count) != 0) return -ENOMEM;

    const struct stm_space_entry *src =
        (const struct stm_space_entry *)(buf + sizeof(*h));
    memcpy(&log->entries[log->count], src,
           (size_t)count * sizeof(*src));
    log->count += count;

    *out_prev = le64_to_cpu(h->slh_prev_paddr);
    return 0;
}

/* ── open / close ─────────────────────────────────────────────────── */

int stm_space_log_open(struct stm_block_dev *dev, uint64_t head_paddr,
                       stm_space_log_alloc_cb alloc_cb, void *alloc_ctx,
                       struct stm_space_log **out)
{
    struct stm_space_log *log = calloc(1, sizeof(*log));
    if (!log) return -ENOMEM;
    log->dev       = dev;
    log->alloc_cb  = alloc_cb;
    log->alloc_ctx = alloc_ctx;

    if (head_paddr == 0) {
        *out = log;
        return 0;
    }

    /* Walk the backward chain collecting chunk paddrs (newest first).
     * Read entries in chunk order — each read_chunk appends to the tail
     * of log->entries, but insert order within the full log is
     * oldest-chunk-entries first → newest-chunk-entries last. So we:
     *   1. Walk head→prev, remembering paddrs in a stack.
     *   2. Pop the stack (= oldest→newest order) and read each chunk.
     * This yields entries in insert order, and chunk_paddrs ends up in
     * oldest→newest order for later truncate. */
    uint64_t  stack[1024];
    int       depth = 0;
    uint64_t  p = head_paddr;
    while (p != 0 && depth < (int)(sizeof(stack) / sizeof(stack[0]))) {
        /* We'll read later; for now just walk the chain to collect. */
        uint8_t hdr[sizeof(struct stm_space_log_hdr)];
        int rc = stm_block_read(dev, p, hdr, sizeof(hdr));
        if (rc) { stm_space_log_close(log); return rc; }
        const struct stm_space_log_hdr *h =
            (const struct stm_space_log_hdr *)hdr;
        if (le64_to_cpu(h->slh_magic) != STM_SPACE_LOG_MAGIC) {
            stm_space_log_close(log); return -EIO;
        }
        stack[depth++] = p;
        p = le64_to_cpu(h->slh_prev_paddr);
    }
    if (p != 0) {
        /* Chain too long for the fixed stack. Bump the stack size if
         * we ever hit this; for Stage 2 tests, 1024 chunks ×126 entries
         * = 129 024 entries is plenty. */
        stm_space_log_close(log); return -E2BIG;
    }

    if (grow_chunks(log, (uint32_t)depth) != 0) {
        stm_space_log_close(log); return -ENOMEM;
    }

    /* Pop stack — yields oldest first. */
    for (int i = depth - 1; i >= 0; i--) {
        uint64_t chunk_paddr = stack[i];
        uint64_t dummy_prev;
        int rc = read_chunk(log, chunk_paddr, &dummy_prev);
        if (rc) { stm_space_log_close(log); return rc; }
        log->chunk_paddrs[log->nchunks++] = chunk_paddr;
    }
    log->persisted = log->count;

    *out = log;
    return 0;
}

void stm_space_log_close(struct stm_space_log *log)
{
    if (!log) return;
    free(log->entries);
    free(log->chunk_paddrs);
    free(log);
}

/* ── append / commit / walk ───────────────────────────────────────── */

int stm_space_log_append(struct stm_space_log *log,
                         const struct stm_space_entry *entry)
{
    if (grow_entries(log, log->count + 1) != 0) return -ENOMEM;
    log->entries[log->count++] = *entry;
    return 0;
}

uint32_t stm_space_log_pending(struct stm_space_log *log)
{
    return log->count - log->persisted;
}

int stm_space_log_commit(struct stm_space_log *log, uint64_t gen,
                         uint64_t *out_head_paddr)
{
    /* Nothing new to persist — report current head. */
    if (log->persisted == log->count) {
        *out_head_paddr = log->nchunks == 0 ? 0
                                            : log->chunk_paddrs[log->nchunks - 1];
        return 0;
    }

    uint32_t pending = log->count - log->persisted;
    uint32_t nchunks_new = (pending + STM_SPACE_LOG_MAX_ENTRIES - 1) /
                          STM_SPACE_LOG_MAX_ENTRIES;

    if (grow_chunks(log, log->nchunks + nchunks_new) != 0) return -ENOMEM;

    uint64_t prev = log->nchunks == 0 ? 0
                                      : log->chunk_paddrs[log->nchunks - 1];
    uint32_t consumed = log->persisted;
    for (uint32_t i = 0; i < nchunks_new; i++) {
        uint32_t take = log->count - consumed;
        if (take > STM_SPACE_LOG_MAX_ENTRIES) take = STM_SPACE_LOG_MAX_ENTRIES;

        uint64_t paddr = 0;
        int rc = log->alloc_cb(log->alloc_ctx, &paddr);
        if (rc) return rc;

        uint8_t buf[STM_SPACE_LOG_CHUNK_SIZE];
        memset(buf, 0, sizeof(buf));
        struct stm_space_log_hdr *h = (struct stm_space_log_hdr *)buf;
        encode_hdr(h, gen, prev, take);
        memcpy(buf + sizeof(*h), &log->entries[consumed],
               (size_t)take * sizeof(struct stm_space_entry));

        /* csum the whole 4096-byte block with the csum field zeroed. */
        stm_csum_compute(buf, sizeof(buf), h->slh_csum);

        rc = stm_block_write(log->dev, paddr, buf, sizeof(buf));
        if (rc) return rc;

        log->chunk_paddrs[log->nchunks++] = paddr;
        prev = paddr;
        consumed += take;
    }

    log->persisted = log->count;
    *out_head_paddr = log->chunk_paddrs[log->nchunks - 1];
    return 0;
}

int stm_space_log_walk(struct stm_space_log *log,
                       stm_space_log_walk_cb cb, void *ctx)
{
    for (uint32_t i = 0; i < log->count; i++) {
        int rc = cb(&log->entries[i], ctx);
        if (rc) return rc;
    }
    return 0;
}

/* ── fold ─────────────────────────────────────────────────────────── */

int stm_space_log_fold_into(struct stm_space_log *log,
                            struct stm_space *tree, uint64_t gen)
{
    for (uint32_t i = 0; i < log->count; i++) {
        const struct stm_space_entry *e = &log->entries[i];
        uint64_t paddr = le64_to_cpu(e->se_paddr);
        uint64_t count = le64_to_cpu(e->se_count);
        int rc;
        switch (e->se_op) {
            case STM_SPACE_ALLOC:
                rc = stm_space_insert(tree, paddr, count, gen);
                break;
            case STM_SPACE_REF:
                rc = stm_space_ref(tree, paddr, gen);
                break;
            case STM_SPACE_FREE:
                rc = stm_space_unref(tree, paddr, gen);
                break;
            default:
                return -EIO;
        }
        if (rc) return rc;
    }
    return 0;
}

void stm_space_log_truncate(struct stm_space_log *log,
                            stm_space_log_free_cb free_cb, void *free_ctx)
{
    if (free_cb) {
        for (uint32_t i = 0; i < log->nchunks; i++)
            free_cb(free_ctx, log->chunk_paddrs[i]);
    }
    log->nchunks   = 0;
    log->count     = 0;
    log->persisted = 0;
}
