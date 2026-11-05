/* SPDX-License-Identifier: ISC */
/*
 * btree_engine — paddr-keyed node cache.
 *
 * A chained hash table mapping a clean node's paddr to its in-memory
 * eng_node. NON-OWNING: the cache never frees a node. Node lifetime is
 * the tree — every loaded node is linked as some parent's child.mem,
 * and the engine frees the whole tree by a recursive walk at destroy.
 *
 * impl-1b never frees a node mid-life (no delete / merge), so the cache
 * needs no entry-removal path: it only ever gains entries (on a disk
 * read) and is torn down whole at engine destroy. A node that goes
 * clean -> dirty keeps its (now stale) paddr key, but a dirty child is
 * always reached via the parent's child.mem pointer, never via the
 * cache, so the stale key is never consulted. See engine_internal.h
 * for the design note on why the cache is rarely hit in impl-1b and
 * load-bearing in impl-2.
 */

#include "engine_internal.h"

#include <stdlib.h>

/* Fibonacci hash of the 64-bit paddr down to ENG_CACHE_BITS. */
static inline uint32_t cache_bucket(uint64_t paddr)
{
    uint64_t h = paddr * UINT64_C(0x9E3779B97F4A7C15);
    return (uint32_t)(h >> (64u - ENG_CACHE_BITS));
}

void eng_cache_init(eng_cache *c)
{
    for (uint32_t i = 0; i < ENG_CACHE_BUCKETS; i++)
        c->buckets[i] = NULL;
    c->n_entries = 0;
}

void eng_cache_destroy(eng_cache *c)
{
    for (uint32_t i = 0; i < ENG_CACHE_BUCKETS; i++) {
        eng_cache_ent *e = c->buckets[i];
        while (e) {
            eng_cache_ent *next = e->next;
            free(e);                 /* the entry struct only — NOT e->node */
            e = next;
        }
        c->buckets[i] = NULL;
    }
    c->n_entries = 0;
}

eng_node *eng_cache_get(const eng_cache *c, uint64_t paddr)
{
    for (eng_cache_ent *e = c->buckets[cache_bucket(paddr)]; e; e = e->next) {
        if (e->paddr == paddr)
            return e->node;
    }
    return NULL;
}

stm_status eng_cache_put(eng_cache *c, uint64_t paddr, eng_node *node)
{
    uint32_t b = cache_bucket(paddr);

    /* A paddr is reserved fresh and never reused within an engine's
     * life, so a put for an already-present paddr would be a bug; if
     * it happens, refresh the slot rather than chain a duplicate. */
    for (eng_cache_ent *e = c->buckets[b]; e; e = e->next) {
        if (e->paddr == paddr) {
            e->node = node;
            return STM_OK;
        }
    }

    eng_cache_ent *e = malloc(sizeof *e);
    if (!e) return STM_ENOMEM;
    e->paddr = paddr;
    e->node  = node;
    e->next  = c->buckets[b];
    c->buckets[b] = e;
    c->n_entries++;
    return STM_OK;
}
