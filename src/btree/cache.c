/*
 * stm_node_cache — LRU cache of decoded btree nodes, keyed by paddr.
 *
 * Motivation: without caching, every stm_btree_read_node pays disk read
 * + xxHash3-128 verify + (optional) XChaCha20-Poly1305 decrypt +
 * (optional) LZ4/ZSTD decompress + struct decode. The root is hit on
 * every op and is the hottest paddr on any btree workload. A fixed-
 * size LRU captures the tree's upper levels and collapses the repeated
 * tree-walk cost to pointer-lookup + clone.
 *
 * Correctness contract (see docs/STRATUM.md §22 and CLAUDE.md):
 *
 *   INVARIANT: at any moment, a cache entry (paddr, node) reflects
 *              EXACTLY the node most recently written to `paddr` in
 *              this session. The cache never returns stale data.
 *
 * The invariant is maintained by:
 *
 *   1. `stm_btree_read_node` inserts (paddr, clone-of-node) on every
 *      successful read (and serves from cache on hit, skipping disk).
 *   2. `stm_btree_write_node` inserts (paddr, clone-of-node) on every
 *      successful write — overwriting any stale entry at the same paddr.
 *      Since writes always go to fresh paddrs (COW via stm_alloc_extent),
 *      this is how a paddr reallocated across a sync gets a fresh entry.
 *   3. `stm_btree_close` destroys the cache and every node it holds.
 *   4. `stm_btree_cache_flush` — called from snap_rollback reopen paths
 *      and any context where the tree's root is being replaced wholesale.
 *
 * Because every stm_btree_write_node allocates a fresh paddr, no in-session
 * "write-behind" problem exists. Cross-sync paddr reuse is handled by
 * rule (2): when the reused paddr is written to, the cache entry updates.
 *
 * Clone-on-hit (via stm_node_clone) preserves the existing ownership
 * model — callers of stm_btree_read_node own the returned struct stm_node
 * and are free to mutate or free it without disturbing the cache.
 */

#include "btree_internal.h"

#include <stdlib.h>
#include <string.h>

/* Hash table entries live in per-bucket chains. Each entry is also in the
 * LRU doubly-linked list, ordered head=most-recent, tail=oldest. */
struct cache_entry {
    uint64_t            paddr;
    struct stm_node    *node;       /* cache owns this; released on evict */
    struct cache_entry *hash_next;  /* bucket chain */
    struct cache_entry *lru_prev;   /* closer to head = more recent */
    struct cache_entry *lru_next;
};

#define CACHE_BUCKETS 128   /* power of 2; hash = (paddr / node_size) & mask */

struct stm_node_cache {
    struct cache_entry *buckets[CACHE_BUCKETS];
    struct cache_entry *lru_head;   /* most recent */
    struct cache_entry *lru_tail;   /* oldest */
    uint32_t            count;
    uint32_t            capacity;   /* max entries; 0 = unlimited (tests) */
};

static uint32_t hash_paddr(uint64_t paddr)
{
    /* paddrs are node-size aligned; divide out the alignment to widen the
     * low bits before masking. Mixing via golden ratio smooths clustering
     * if paddrs ever become non-uniformly distributed. */
    uint64_t h = paddr / (uint64_t)STM_NODE_SIZE;
    h *= UINT64_C(0x9E3779B97F4A7C15);
    return (uint32_t)(h >> 32) & (CACHE_BUCKETS - 1);
}

/* --- LRU list helpers (head = MRU, tail = LRU) --- */

static void lru_unlink(struct stm_node_cache *c, struct cache_entry *e)
{
    if (e->lru_prev) e->lru_prev->lru_next = e->lru_next;
    else             c->lru_head = e->lru_next;
    if (e->lru_next) e->lru_next->lru_prev = e->lru_prev;
    else             c->lru_tail = e->lru_prev;
}

static void lru_push_front(struct stm_node_cache *c, struct cache_entry *e)
{
    e->lru_prev = NULL;
    e->lru_next = c->lru_head;
    if (c->lru_head) c->lru_head->lru_prev = e;
    c->lru_head = e;
    if (!c->lru_tail) c->lru_tail = e;
}

static void lru_touch(struct stm_node_cache *c, struct cache_entry *e)
{
    if (c->lru_head == e) return;
    lru_unlink(c, e);
    lru_push_front(c, e);
}

/* --- hash-bucket helpers --- */

static struct cache_entry *bucket_find(struct stm_node_cache *c,
                                       uint32_t h, uint64_t paddr)
{
    struct cache_entry *e = c->buckets[h];
    while (e) {
        if (e->paddr == paddr) return e;
        e = e->hash_next;
    }
    return NULL;
}

static void bucket_unlink(struct stm_node_cache *c, uint32_t h,
                          struct cache_entry *target)
{
    struct cache_entry **pp = &c->buckets[h];
    while (*pp) {
        if (*pp == target) { *pp = target->hash_next; return; }
        pp = &(*pp)->hash_next;
    }
}

static void entry_free(struct cache_entry *e)
{
    stm_node_free(e->node);
    free(e);
}

/* --- public API --- */

struct stm_node_cache *stm_node_cache_new(uint32_t capacity)
{
    struct stm_node_cache *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->capacity = capacity;
    return c;
}

void stm_node_cache_free(struct stm_node_cache *c)
{
    if (!c) return;
    struct cache_entry *e = c->lru_head;
    while (e) {
        struct cache_entry *next = e->lru_next;
        entry_free(e);
        e = next;
    }
    free(c);
}

/* Evict the LRU entry. Caller is responsible for checking count > 0. */
static void cache_evict_one(struct stm_node_cache *c)
{
    struct cache_entry *victim = c->lru_tail;
    if (!victim) return;
    uint32_t h = hash_paddr(victim->paddr);
    bucket_unlink(c, h, victim);
    lru_unlink(c, victim);
    c->count--;
    entry_free(victim);
}

/* Insert or replace (paddr, node). Takes ownership of `node` — the cache
 * will free it on eviction or when replaced. Caller must not free `node`
 * after this call.
 *
 * Hot path: common case is "paddr not in cache, count < capacity" — one
 * bucket walk + one allocation.
 *
 * Correctness-critical: on replace, the OLD node is freed before the new
 * one takes its place. No caller outside the cache should be holding a
 * pointer to the old one (callers get clones via stm_node_cache_get).
 */
void stm_node_cache_insert(struct stm_node_cache *c, uint64_t paddr,
                           struct stm_node *node)
{
    if (!c || !node) { stm_node_free(node); return; }

    uint32_t h = hash_paddr(paddr);
    struct cache_entry *e = bucket_find(c, h, paddr);
    if (e) {
        /* Replace: preserves LRU position's semantics by touching. */
        stm_node_free(e->node);
        e->node = node;
        lru_touch(c, e);
        return;
    }

    /* Evict before insert if at capacity. */
    while (c->capacity && c->count >= c->capacity) {
        cache_evict_one(c);
    }

    e = calloc(1, sizeof(*e));
    if (!e) { stm_node_free(node); return; }  /* cache is best-effort */
    e->paddr = paddr;
    e->node  = node;
    e->hash_next = c->buckets[h];
    c->buckets[h] = e;
    lru_push_front(c, e);
    c->count++;
}

/* Lookup by paddr. On hit: returns a CLONE of the cached node (caller owns
 * it). On miss: returns NULL.
 *
 * The clone preserves the existing ownership model — every caller of
 * stm_btree_read_node currently gets a freshly-allocated node that they
 * may mutate or free. The cache must survive that, so we hand out clones
 * rather than aliasing internals.
 */
struct stm_node *stm_node_cache_get(struct stm_node_cache *c, uint64_t paddr)
{
    if (!c) return NULL;
    uint32_t h = hash_paddr(paddr);
    struct cache_entry *e = bucket_find(c, h, paddr);
    if (!e) return NULL;
    lru_touch(c, e);
    return stm_node_clone(e->node);
}

/* Invalidate every entry. Called from rollback's tree-replacement path —
 * after fs->tree is reopened at a different root, the prior cache's
 * contents might correspond to paddrs that the new tree doesn't reference
 * and that could be reallocated before the cache entries age out. */
void stm_node_cache_flush(struct stm_node_cache *c)
{
    if (!c) return;
    struct cache_entry *e = c->lru_head;
    while (e) {
        struct cache_entry *next = e->lru_next;
        entry_free(e);
        e = next;
    }
    memset(c->buckets, 0, sizeof(c->buckets));
    c->lru_head = NULL;
    c->lru_tail = NULL;
    c->count = 0;
}

/* Number of entries currently cached — for tests / diagnostics. */
uint32_t stm_node_cache_count(const struct stm_node_cache *c)
{
    return c ? c->count : 0;
}

/* Drop any entry at `paddr`. Called by stm_btree_write_node — every write
 * lands at a fresh paddr under COW, but across sync boundaries a PENDING-
 * then-freed paddr can be reallocated and receive new content. If the
 * cache still holds the pre-free content for that paddr, a subsequent
 * read would return stale data. Invalidating on write closes that window;
 * next read fetches fresh and repopulates. */
void stm_node_cache_invalidate(struct stm_node_cache *c, uint64_t paddr)
{
    if (!c) return;
    uint32_t h = hash_paddr(paddr);
    struct cache_entry *e = bucket_find(c, h, paddr);
    if (!e) return;
    bucket_unlink(c, h, e);
    lru_unlink(c, e);
    c->count--;
    entry_free(e);
}
