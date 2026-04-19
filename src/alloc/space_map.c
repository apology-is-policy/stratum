/*
 * Persistent allocator — Phase D #2, Stage 1.
 *
 * Wraps an stm_btree as a sorted map of allocated block ranges. Free
 * space is implicit (the gaps). See include/stratum/space.h for the API
 * contract and docs/STRATUM.md §14 for the staging plan.
 *
 * Stage 1 has no sync-ordering or crash-safety machinery beyond what the
 * underlying btree already provides — stm_space_commit calls through to
 * stm_btree_flush. No log, no integration with the live filesystem.
 * Stage 2 will add the delta log; Stage 3 will wire mount to build the
 * in-memory refcount array from the tree instead of walking.
 */

#include "stratum/space.h"
#include "stratum/btree.h"
#include "stratum/crypto.h"
#include "stratum/key.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct stm_space {
    struct stm_btree *tree;
};

static struct stm_key space_key(uint64_t start)
{
    struct stm_key_cpu kc = {
        .ino = 0, .type = STM_KEY_SPACE, .offset = start,
    };
    return stm_key_from_cpu(&kc);
}

int stm_space_open(struct stm_block_dev *dev, struct stm_bptr root,
                   uint16_t height, struct stm_space **out)
{
    struct stm_space *sp = calloc(1, sizeof(*sp));
    if (!sp) return -ENOMEM;
    int rc = stm_btree_open(dev, root, height, &sp->tree);
    if (rc) { free(sp); return rc; }
    /* The space tree lives in its own namespace on the volume. Stage 1
     * tests use it unencrypted; the fs layer will attach crypto via
     * stm_space_set_crypto before any write on encrypted volumes. */
    *out = sp;
    return 0;
}

void stm_space_set_crypto(struct stm_space *sp, struct stm_crypto *ctx)
{
    stm_btree_set_crypto(sp->tree, ctx);
}

void stm_space_close(struct stm_space *sp)
{
    if (!sp) return;
    stm_btree_close(sp->tree);
    free(sp);
}

/* Serialize a tree value into on-disk form. The stm_space_val struct is
 * packed but members are le* already, so a direct memcpy is enough. */
static void encode_val(struct stm_space_val *v, uint64_t count, uint32_t refcount)
{
    v->sv_count    = cpu_to_le64(count);
    v->sv_refcount = cpu_to_le32(refcount);
}

int stm_space_insert(struct stm_space *sp, uint64_t start, uint64_t count,
                     uint64_t gen)
{
    if (count == 0) return -EINVAL;

    /* EEXIST guard. A range inserted over an existing one would overwrite
     * refcount / length silently — pushing the caller to use stm_space_ref
     * instead. Btree lookup handles not-found cleanly via -ENOENT. */
    struct stm_key k = space_key(start);
    struct stm_space_val existing;
    uint32_t vlen = sizeof(existing);
    int rc = stm_btree_lookup(sp->tree, &k, &existing, &vlen);
    if (rc == 0) return -EEXIST;
    if (rc != -ENOENT) return rc;

    struct stm_space_val v;
    encode_val(&v, count, 1);
    return stm_btree_insert(sp->tree, &k, &v, sizeof(v), gen);
}

int stm_space_lookup(struct stm_space *sp, uint64_t start,
                     uint64_t *out_count, uint32_t *out_refcount)
{
    struct stm_key k = space_key(start);
    struct stm_space_val v;
    uint32_t vlen = sizeof(v);
    int rc = stm_btree_lookup(sp->tree, &k, &v, &vlen);
    if (rc) return rc;
    if (vlen != sizeof(v)) return -EIO;  /* corrupted entry */
    if (out_count)    *out_count    = le64_to_cpu(v.sv_count);
    if (out_refcount) *out_refcount = le32_to_cpu(v.sv_refcount);
    return 0;
}

int stm_space_ref(struct stm_space *sp, uint64_t start, uint64_t gen)
{
    struct stm_key k = space_key(start);
    struct stm_space_val v;
    uint32_t vlen = sizeof(v);
    int rc = stm_btree_lookup(sp->tree, &k, &v, &vlen);
    if (rc) return rc;
    if (vlen != sizeof(v)) return -EIO;

    uint32_t cur = le32_to_cpu(v.sv_refcount);
    /* 32-bit refcount saturation — one range shared across ~4B snapshots
     * would be unusual, but still refuse rather than silently wrap. */
    if (cur == 0xFFFFFFFFu) return -EOVERFLOW;
    encode_val(&v, le64_to_cpu(v.sv_count), cur + 1);
    return stm_btree_insert(sp->tree, &k, &v, sizeof(v), gen);
}

int stm_space_unref(struct stm_space *sp, uint64_t start, uint64_t gen)
{
    struct stm_key k = space_key(start);
    struct stm_space_val v;
    uint32_t vlen = sizeof(v);
    int rc = stm_btree_lookup(sp->tree, &k, &v, &vlen);
    if (rc) return rc;
    if (vlen != sizeof(v)) return -EIO;

    uint32_t cur = le32_to_cpu(v.sv_refcount);
    if (cur == 0) return -EINVAL;   /* shouldn't be possible; tree invariant */
    if (cur == 1) {
        /* Last holder — range becomes free. */
        return stm_btree_delete(sp->tree, &k, gen);
    }
    encode_val(&v, le64_to_cpu(v.sv_count), cur - 1);
    return stm_btree_insert(sp->tree, &k, &v, sizeof(v), gen);
}

/* ── find_gap ─────────────────────────────────────────────────────── */

/* Single full-scan pass. For each gap [prev_end, entry.start), record
 *   - the best "phase-0" candidate: gap_start >= hint (or gap extends
 *     past hint, in which case the candidate is max(gap_start, hint))
 *   - as fallback, the first gap of sufficient size regardless of hint
 * "First fit" within each phase — scan is sorted, so the first hit is
 * the lowest-address one. Then we pick phase-0 over phase-1 so the
 * roving hint doesn't cause free-space fragmentation on every alloc. */
struct gap_ctx {
    uint64_t  requested;
    uint64_t  total;
    uint64_t  hint;
    uint64_t  prev_end;    /* end (exclusive) of the last entry seen */
    uint64_t  phase0_start;
    uint64_t  phase1_start;
    int       phase0_set;
    int       phase1_set;
};

static void consider_gap(struct gap_ctx *g, uint64_t gap_start, uint64_t gap_end)
{
    if (gap_end <= gap_start) return;
    uint64_t gap_size = gap_end - gap_start;

    /* Phase-0: allocate at max(gap_start, hint) if the tail of the gap
     * after that point is at least `requested`. */
    if (!g->phase0_set && gap_end > g->hint) {
        uint64_t candidate = gap_start > g->hint ? gap_start : g->hint;
        if (gap_end - candidate >= g->requested) {
            g->phase0_start = candidate;
            g->phase0_set = 1;
        }
    }

    /* Phase-1 fallback: any gap large enough, first-fit. */
    if (!g->phase1_set && gap_size >= g->requested) {
        g->phase1_start = gap_start;
        g->phase1_set = 1;
    }
}

static int gap_cb(const struct stm_key *key, const void *val,
                  uint32_t vlen, void *ctx)
{
    struct gap_ctx *g = ctx;
    if (vlen != sizeof(struct stm_space_val)) return -EIO;

    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (kc.type != STM_KEY_SPACE) return 0;   /* defensive */

    uint64_t start = kc.offset;
    struct stm_space_val v;
    memcpy(&v, val, sizeof(v));
    uint64_t count = le64_to_cpu(v.sv_count);

    consider_gap(g, g->prev_end, start);

    uint64_t end = start + count;
    if (end > g->prev_end) g->prev_end = end;

    /* Early-stop once phase-0 is resolved — phase-1 might find a better
     * fallback but only if phase-0 never fires, so we can't short-circuit
     * here unless phase-1 is also already set. */
    if (g->phase0_set && g->phase1_set) return 1;
    return 0;
}

int stm_space_find_gap(struct stm_space *sp, uint64_t total_blocks,
                       uint64_t hint, uint64_t count,
                       uint64_t *out_start)
{
    if (count == 0 || count > total_blocks) return -EINVAL;
    if (hint >= total_blocks) hint = 0;

    struct gap_ctx g = {
        .requested    = count,
        .total        = total_blocks,
        .hint         = hint,
        .prev_end     = 0,
        .phase0_set   = 0,
        .phase1_set   = 0,
    };

    struct stm_key lo = space_key(0);
    struct stm_key hi = space_key(UINT64_MAX);
    int rc = stm_btree_scan(sp->tree, &lo, &hi, gap_cb, &g);
    if (rc < 0) return rc;

    /* Trailing gap after the last entry. */
    consider_gap(&g, g.prev_end, total_blocks);

    if (g.phase0_set) { *out_start = g.phase0_start; return 0; }
    if (g.phase1_set) { *out_start = g.phase1_start; return 0; }
    return -ENOSPC;
}

/* ── walk ─────────────────────────────────────────────────────────── */

struct walk_ctx {
    stm_space_walk_cb user_cb;
    void             *user_ctx;
};

static int walk_cb(const struct stm_key *key, const void *val,
                   uint32_t vlen, void *ctx)
{
    struct walk_ctx *w = ctx;
    if (vlen != sizeof(struct stm_space_val)) return -EIO;

    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (kc.type != STM_KEY_SPACE) return 0;

    struct stm_space_val v;
    memcpy(&v, val, sizeof(v));
    return w->user_cb(kc.offset,
                      le64_to_cpu(v.sv_count),
                      le32_to_cpu(v.sv_refcount),
                      w->user_ctx);
}

int stm_space_walk(struct stm_space *sp, stm_space_walk_cb cb, void *ctx)
{
    struct stm_key lo = space_key(0);
    struct stm_key hi = space_key(UINT64_MAX);
    struct walk_ctx w = { .user_cb = cb, .user_ctx = ctx };
    return stm_btree_scan(sp->tree, &lo, &hi, walk_cb, &w);
}

int stm_space_commit(struct stm_space *sp, uint64_t gen)
{
    return stm_btree_flush(sp->tree, gen);
}

struct stm_bptr stm_space_root(struct stm_space *sp)
{
    return stm_btree_root(sp->tree);
}

uint16_t stm_space_height(struct stm_space *sp)
{
    return stm_btree_height(sp->tree);
}
