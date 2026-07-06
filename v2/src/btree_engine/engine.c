/* SPDX-License-Identifier: ISC */
/*
 * btree_engine — public API: lifecycle, descent, insert / split,
 * lookup, commit, scan, verify.
 *
 * See include/stratum/btree_engine.h for the contract and
 * v2/docs/reference/24-btree-engine.md for the as-built reference.
 *
 * The B+tree mechanics:
 *  - descent routes a key through internal pivots to its leaf;
 *  - insert is bottom-up — node_insert recurses to the leaf, mutates
 *    it, and returns an optional (separator, right-sibling) split that
 *    the parent splices in, splitting in turn if it overflows;
 *  - a root split grows a fresh root level.
 *
 * Every node on a mutated root-to-leaf path is marked dirty; commit
 * walks bottom-up, writing each dirty node to a fresh paddr and
 * skipping clean subtrees entirely.
 *
 * Commit is incremental and three-phase (9.6-impl-2): a flush writes
 * the dirty nodes and records every node's superseded + fresh paddr;
 * a finalize publishes the new root and deferred-frees the superseded
 * paddrs; an abort discards the flush, deferred-frees the fresh
 * paddrs, and reverts to the previous durable root — the crash-revert
 * path. The model is v2/specs/btree.tla (WriteNode / FinalCommit /
 * Crash + DurableTreeWellFormed / CommittedTreeMerkleConsistent /
 * FreedNodesNotReachable).
 */

#include "engine_internal.h"

#include <stratum/ebr.h>

#include <sched.h>

#include <stratum/bootstrap.h>

#include <stdlib.h>
#include <string.h>

/* The engine node is exactly one bootstrap-allocator node (4 × 4 KiB). */
_Static_assert(STM_BTREE_ENGINE_NODE_SIZE == STM_BOOTSTRAP_NODE_BLOCKS * 4096u,
               "engine node size must equal one bootstrap node");
_Static_assert(STM_BTREE_ENGINE_NODE_SIZE >= STM_BTNODE_MIN_SIZE,
               "engine node must fit a btnode header + csum");
_Static_assert(ENG_MAX_ITEM_BYTES > STM_BTNODE_ENTRY_HDR_SIZE,
               "max entry must admit at least a zero-length key + value");

/* Result of a node split bubbling up to its parent. */
typedef struct {
    bool      happened;
    eng_node *right;        /* the new right sibling */
    uint8_t  *sep_key;      /* owned — ownership passes to the splice */
    uint32_t  sep_len;
} split_result;

/* Pending-commit bookkeeping — defined in the Commit section below;
 * forward-declared so stm_btree_engine_destroy can implicitly abort a
 * flushed-but-unfinalized commit. */
static void pending_reset(eng_pending *p);
static void pending_free_paddrs(stm_btree_engine *eng,
                                 const paddr_vec *v, uint64_t free_gen);

/* 9.8-LF-2: load_root is the single materialisation chokepoint for
 * eng->root + eng->mvcc_root; forward-declared so stm_btree_engine_open
 * can eager-warm post-engine_alloc. Defined in the Node loading section. */
static stm_status load_root(stm_btree_engine *eng, eng_node **out);
/* 9.8-BE (chunk 7b): the on-disk-buffer read consult — defined with the
 * concurrent-lookup block; the serial lookup above it also calls it. */
static stm_status buffer_resolve_for_key(const eng_node *n,
                                          const void *key, size_t key_len,
                                          uint32_t *out_kind,
                                          void **out_value,
                                          size_t *out_value_len);
/* 9.8-BE-prepend: the chain read consult (SEALED-aware) + the cache
 * drop — both defined later; the serial lookup / the mini-
 * consolidation call them from above. */
static stm_status chain_resolve_for_key(const eng_node *n,
                                         const void *key, size_t key_len,
                                         uint32_t *out_kind,
                                         void **out_value,
                                         size_t *out_value_len,
                                         bool *out_sealed);
static void cache_reset(stm_btree_engine *eng);

/* ========================================================================= */
/* Lifecycle.                                                                  */
/* ========================================================================= */

static stm_status engine_alloc(const stm_btree_store_vtable *vt, void *vt_ctx,
                                const stm_btree_crypt_ctx *cx, uint64_t tree_id,
                                stm_btree_engine **out)
{
    if (!vt || !vt->reserve || !vt->write || !vt->read) return STM_EINVAL;
    if (!cx || !cx->metadata_key)                       return STM_EINVAL;
    if (!out)                                           return STM_EINVAL;

    stm_btree_engine *eng = calloc(1, sizeof *eng);
    if (!eng) return STM_ENOMEM;
    eng->vt      = vt;
    eng->vt_ctx  = vt_ctx;
    eng->cx      = *cx;          /* metadata_key pointer borrowed */
    eng->tree_id = tree_id;
    eng_cache_init(&eng->cache);
    /* 9.8-LF-1: concurrency substrate. commit_mu serialises future
     * three-phase commits (LF-2 wires it around the mvcc_root CAS);
     * next_delta_seq is the engine-wide monotonic source for delta
     * seq numbers (LF-BE-prepend's CAS-prepend site reads it). */
    if (pthread_mutex_init(&eng->commit_mu, NULL) != 0) {
        eng_cache_destroy(&eng->cache);
        free(eng);
        return STM_ENOMEM;
    }
    /* P9.5-PARALLEL-3 fix: serial-path mutual exclusion (see engine_internal.h). */
    if (pthread_mutex_init(&eng->serial_mu, NULL) != 0) {
        pthread_mutex_destroy(&eng->commit_mu);
        eng_cache_destroy(&eng->cache);
        free(eng);
        return STM_ENOMEM;
    }
    atomic_init(&eng->next_delta_seq, (uint64_t)0);
    /* 9.8-LF-2: mvcc_root is NULL until the in-memory root materialises.
     * engine_create publishes the empty leaf immediately; engine_open
     * leaves it NULL and the first descent — serial-path (load_root via
     * lookup/insert/etc.) OR concurrent-path (slow-warm path inside
     * stm_btree_engine_lookup_concurrent) — publishes via load_root. */
    atomic_init(&eng->mvcc_root, (eng_node *)NULL);
    /* 9.8-BE-prepend: the sticky concurrent-regime latch (see
     * engine_internal.h). */
    atomic_init(&eng->concurrent_regime, false);
    *out = eng;
    return STM_OK;
}

stm_status stm_btree_engine_create(const stm_btree_store_vtable *vt,
                                    void *vt_ctx,
                                    const stm_btree_crypt_ctx *cx,
                                    uint64_t tree_id,
                                    stm_btree_engine **out_eng)
{
    stm_btree_engine *eng = NULL;
    stm_status s = engine_alloc(vt, vt_ctx, cx, tree_id, &eng);
    if (s != STM_OK) return s;

    eng->root = eng_node_new_leaf();       /* fresh empty-leaf root, dirty */
    if (!eng->root) {
        /* engine_alloc initialised the cache + commit_mu; full teardown
         * required to symmetric-destroy both. NULL-safe + partial-init
         * tolerant (R169 P1-1). */
        stm_btree_engine_destroy(eng);
        return STM_ENOMEM;
    }
    eng->has_durable_root = false;
    /* 9.8-LF-2: publish for concurrent readers. The empty leaf is
     * reachable immediately — a stm_btree_engine_lookup_concurrent
     * issued right after engine_create returns a miss for any key
     * (well-defined behaviour). */
    atomic_store_explicit(&eng->mvcc_root, eng->root, memory_order_release);
    *out_eng = eng;
    return STM_OK;
}

stm_status stm_btree_engine_open(const stm_btree_store_vtable *vt,
                                  void *vt_ctx,
                                  const stm_btree_crypt_ctx *cx,
                                  uint64_t tree_id,
                                  uint64_t root_paddr, uint64_t root_gen,
                                  const uint8_t root_csum[32],
                                  stm_btree_engine **out_eng)
{
    if (!root_csum) return STM_EINVAL;
    stm_btree_engine *eng = NULL;
    stm_status s = engine_alloc(vt, vt_ctx, cx, tree_id, &eng);
    if (s != STM_OK) return s;

    eng->root             = NULL;          /* lazy — loaded on first descent */
    eng->root_paddr       = root_paddr;
    eng->root_gen         = root_gen;
    memcpy(eng->root_csum, root_csum, STM_BTNODE_CSUM_SIZE);
    eng->has_durable_root = true;

    /* 9.8-LF-2: mvcc_root left NULL post-open. The first call to either
     * a serial-path op (lookup / insert / etc.) OR
     * stm_btree_engine_lookup_concurrent will materialise the durable
     * root via load_root which publishes mvcc_root release-store.
     *
     * Why lazy + not eager: corruption (tampered ciphertext, wrong
     * csum) is detected at first descent — established contract
     * (engine_ciphertext_tamper_detected + engine_wrong_csum_open_rejected
     * regression tests). An eager warm would surface STM_ECORRUPT at
     * open and is a strictly-more-aggressive failure-surface contract;
     * not worth the contract change for the 1 disk-read amortisation.
     *
     * Concurrent-path first call without a prior serial-path op:
     * stm_btree_engine_lookup_concurrent's slow warm under `commit_mu`
     * single-shot materialises (double-checked locking pattern). */
    *out_eng = eng;
    return STM_OK;
}

/* The pure-RAM half of engine teardown — everything a pinned concurrent
 * reader may still be touching (the published tree + its delta chains,
 * commit_mu on the slow-warm path) plus the engine-private allocations.
 * Touches NO store/pool state and takes no locks, so it is safe as an
 * EBR destructor invoked from any thread at any later time
 * (9.8-BE-engine-retire, chunk 9b). */
static void engine_free_ram_cb(void *eng_)
{
    stm_btree_engine *eng = eng_;
    eng_node_free_recursive(eng->root);    /* frees every in-memory node */
    eng_cache_destroy(&eng->cache);        /* frees the index, not nodes */
    paddr_vec_free(&eng->orphaned_spill_blocks);
    pthread_mutex_destroy(&eng->serial_mu);
    pthread_mutex_destroy(&eng->commit_mu);
    free(eng);
}

/* A commit flushed but never finalized/aborted: hand the
 * flushed-but-unrooted paddrs back to the allocator (deferred-free)
 * so they do not leak on disk — an implicit abort. The pending
 * tracking arrays themselves are freed by pending_reset; when no
 * commit is pending those arrays are already NULL.
 *
 * Runs synchronously in the tearing-down thread for BOTH destroy and
 * retire: the pending state is commit-private (a concurrent reader can
 * never reach it — commits mutate only the un-published shadow), and
 * the paddr hand-back calls into the store vtable, which must not
 * outlive the pool the way an EBR-deferred callback could. */
static void engine_implicit_abort_pending(stm_btree_engine *eng)
{
    if (!eng->pending.active) return;
    pending_free_paddrs(eng, &eng->pending.fresh, eng->pending.gen);
    if (eng->pending.clone)
        eng_node_free_recursive(eng->pending.shadow_root);
    pending_reset(&eng->pending);
}

void stm_btree_engine_destroy(stm_btree_engine *eng)
{
    if (!eng) return;
    engine_implicit_abort_pending(eng);
    engine_free_ram_cb(eng);
}

void stm_btree_engine_retire(stm_btree_engine *eng)
{
    if (!eng) return;
    engine_implicit_abort_pending(eng);
    if (stm_ebr_retire(eng, engine_free_ram_cb) != STM_OK) {
        /* Retire-record OOM (~32 bytes): leak the engine rather than
         * free under a possibly-pinned reader — the invalidate_memtree
         * posture. Strictly safer, once, on an already-OOM path. */
        return;
    }
    (void)stm_ebr_try_advance();
}

/* ========================================================================= */
/* Node loading.                                                               */
/* ========================================================================= */

/* Resolve the root node, reading it from disk on the first descent of
 * an opened tree.
 *
 * Threading (9.8-LF-2 R170 P2-4): load_root mutates `eng->root`
 * non-atomically; callers must ensure no concurrent execution of
 * load_root against the same engine. Two caller classes today:
 *   - Serial-path callers (lookup / insert / delete / scan /
 *     commit_flush) — rely on the fs.c-level `fs->global` EX lock OR
 *     a test discipline of single-threaded use. They do NOT take
 *     commit_mu.
 *   - The slow-warm path inside `stm_btree_engine_lookup_concurrent`
 *     — holds `eng->commit_mu` across the load_root call, so multiple
 *     concurrent readers don't trip each other.
 * R171 update post-LF-3 (statuses as of 9.8-BE-prepend, chunk 9):
 * serial-path writers hold `fs->global` SH (PARALLEL-3 impl-5/6) and
 * wait-free readers hold NO `fs->global` lock at all. The family:
 *   - R171 P0-1 (leaf-value UAF: the in-place `free(old) → assign`
 *     upsert under a reader's memcpy) — ENGINE-CLOSED at chunk 9:
 *     `insert/delete_concurrent` route mutations through CAS-
 *     prepended deltas, and a latched engine's commits mutate only a
 *     private shadow (published nodes immutable; supersedes EBR-
 *     retire). The SERIAL write path is unchanged, so unported fs.c
 *     writers keep the R171 P1-1 SH-fallback stopgap envelope until
 *     chunk 10 ports them onto the `_concurrent` APIs.
 *   - R171 P0-2 (the ENGINE STRUCT freed under a reader by rollback /
 *     dataset_destroy / sync_close) — CLOSED at chunk 9b
 *     (9.8-BE-engine-retire): stm_btree_engine_retire defers the RAM
 *     teardown through EBR; dataset_engine_close_locked unpublishes
 *     then retires (phase-9.8-design.md 5.1.1).
 *   - R171 P0-4 (invalidate_memtree freeing the tree under a pinned
 *     reader) — CLOSED at chunk 9: invalidate publishes NULL then
 *     EBR-retires the tree; the clone-commit failure paths never
 *     invalidate at all (the published tree is byte-untouched).
 * Thylacine reachability (Stratum Stabilization Area D, 2026-06-25):
 * the family needs a concurrent reader+writer on ONE engine, which a
 * single serial stratumd connection never produces -- unreachable at
 * v1.0, reachable under A-5b multi-connection-same-dataset (and under
 * CF-2's worker pool, which is why CF-1 lands the closure first).
 * Chunk 9 realised the concurrent-commit discipline: commit_flush /
 * finalize / abort hold commit_mu for their whole span; any new
 * load_root caller MUST follow it.
 *
 * 9.8-LF-2: every code path that sets eng->root to a non-NULL node
 * MUST atomic-store-release that pointer into eng->mvcc_root — this
 * is the single source of root materialisations, so publishing here
 * keeps the (eng->root, eng->mvcc_root) invariant: mvcc_root mirrors
 * eng->root, except briefly inside invalidate_memtree where mvcc_root
 * is cleared FIRST. The OTHER write sites to the pair (chunk 9): the
 * serial root-grow in `stm_btree_engine_insert` (R170 P2-3), the
 * legacy-arm grow_root_absorb (publish-at-quiescence, R173 F2), the
 * mini-consolidation's clone publish, and commit_finalize_clone's
 * shadow swap — the latter two under commit_mu (+ serial_mu for the
 * mini). */
static stm_status load_root(stm_btree_engine *eng, eng_node **out)
{
    if (eng->root) { *out = eng->root; return STM_OK; }

    /* No in-memory root and no durable root: a never-committed tree
     * whose in-memory root a failed flush / commit_abort dropped (see
     * invalidate_memtree). Re-create the empty-leaf root that
     * stm_btree_engine_create starts from — the tree is empty again,
     * which is the correct post-crash state of an uncommitted tree. */
    if (!eng->has_durable_root) {
        eng_node *e = eng_node_new_leaf();
        if (!e) return STM_ENOMEM;
        eng->root = e;
        atomic_store_explicit(&eng->mvcc_root, e, memory_order_release);
        *out = e;
        return STM_OK;
    }

    eng_node *r = NULL;
    stm_status s = eng_node_read(eng, eng->root_paddr, eng->root_gen,
                                 eng->root_csum, &r);
    if (s != STM_OK) return s;
    /* 9.8-BE-prepend: seed the delta-seq counter from the root's
     * persisted high water (btnode.h n_seq_hw) so seqs minted this
     * process-lifetime stay strictly above every message persisted by
     * a prior one — per-key newest-wins must not invert across a
     * restart. Safe as a plain max here: this runs before mvcc_root
     * publishes the materialised root, and prepends only reach a root
     * through mvcc_root, so no fetch_add can race the seed. */
    if (r->seq_hw > atomic_load_explicit(&eng->next_delta_seq,
                                         memory_order_relaxed))
        atomic_store_explicit(&eng->next_delta_seq, r->seq_hw,
                              memory_order_relaxed);
    (void)eng_cache_put(&eng->cache, eng->root_paddr, r);   /* best-effort */
    eng->root = r;
    atomic_store_explicit(&eng->mvcc_root, r, memory_order_release);
    *out = r;
    return STM_OK;
}

/*
 * Single-flight materialisation front for the SERIAL entry points
 * (R174 F1). The serial ops hold only serial_mu and the concurrent
 * slow-warm holds only commit_mu — disjoint — so two bare load_root
 * bodies could race an engine's FIRST materialisation (lazy open, or
 * post-invalidate): both read the disk root, both plain-store
 * eng->root and publish, the loser's tree leaks unreachable, an
 * acknowledged prepend CAS'd onto the loser's chain is silently
 * lost, and the loser's late seq seed can clobber the counter back
 * below already-minted seqs. The miss path therefore serialises with
 * every other materialiser and publisher on commit_mu (double-checked
 * on eng->root inside the lock). Lock order: the callers hold
 * serial_mu, so this realises serial_mu OUTER -> commit_mu INNER —
 * the documented order the mini also uses. The fast path stays a
 * plain read: a non-NULL eng->root can only be swapped by the mini
 * (excluded — it takes serial_mu) or a commit publish (excluded by
 * the commit-vs-serial caller contract, unchanged since 9.6).
 */
static stm_status load_root_locked(stm_btree_engine *eng, eng_node **out)
{
    if (eng->root) { *out = eng->root; return STM_OK; }
    pthread_mutex_lock(&eng->commit_mu);
    stm_status s = STM_OK;
    if (eng->root) *out = eng->root;
    else           s = load_root(eng, out);
    pthread_mutex_unlock(&eng->commit_mu);
    return s;
}

/*
 * Resolve child `idx` of an internal node, reading it from disk if it
 * is not yet resident.
 *
 * The in-memory structure MUST stay a strict tree — eng_node_free_recursive
 * and commit_node descend child.mem assuming every node has exactly one
 * parent. The node cache makes that an enforced invariant: every cached
 * node is one already linked into the tree (load_root, or a prior
 * load_child, cached it and then linked it). So a cache hit here — for a
 * paddr this slot has not itself linked — means the on-disk tree points
 * at one paddr from two parent slots: a DAG, or a cycle when the paddr
 * is an ancestor's. That is corruption; reject it rather than build a
 * DAG (which would double-free, or stack-overflow on a cycle, at
 * destroy). A node is cached only AFTER it passes every gate below, so
 * a rejected freshly-read node is never left dangling in the cache.
 *
 * 9.8-BE-prepend concurrency: the slot resolve + link go through the
 * eng_child_mem helpers so a cold WAIT-FREE descent can link safely —
 * two racing descents CAS the same slot; the loser frees its copy and
 * adopts the winner (strict tree preserved: one linked node, one
 * parent). `use_cache = false` on the wait-free path (and the shadow
 * flush): the cache is a plain hash table mutated with no lock — only
 * caller-serialized contexts (serial descents, the legacy commit) may
 * touch it, and the shadow flush must not consult it at all (old-tree
 * nodes sit there under the same paddrs the shadow re-loads — a false
 * duplicate-paddr hit). An uncached descent loses the early DAG gate;
 * on-disk cycles remain caught by the descent depth caps, and a
 * double-loaded DAG node yields two singly-parented copies — degraded
 * detection, never unsafety. A pinned reader can also race the paddr's
 * DISK lifecycle (superseded at a commit it overlapped, reclaimed +
 * rewritten commits later): the bptr csum carried here makes that a
 * Merkle-gate STM_ECORRUPT — fail-closed; the fs-layer SH-fallback
 * (R171 P1-1) retries against the current root.
 */
static stm_status load_child(stm_btree_engine *eng, eng_node *node,
                              uint32_t idx, bool use_cache,
                              eng_node **out, bool *out_stale)
{
    eng_child *ch = &node->children[idx];
    eng_node *mem = eng_child_mem_acquire(ch);
    if (mem == ENG_CHILD_TOMBSTONE) {
        /* The node was superseded and swept (mini-consolidation) —
         * only a wait-free descent pinned on the husk can see this;
         * it restarts from mvcc_root. Impossible for the tombstone-
         * blind callers (private shadows, serial trees under the
         * exclusion contract) — corrupt if it happens there. */
        if (!out_stale) return STM_ECORRUPT;
        *out_stale = true;
        return STM_OK;
    }
    if (mem) { *out = mem; return STM_OK; }

    if (use_cache && eng_cache_get(&eng->cache, ch->paddr) != NULL)
        return STM_ECORRUPT;            /* duplicate child paddr / cycle */

    eng_node *child = NULL;
    stm_status s = eng_node_read(eng, ch->paddr, ch->gen, ch->csum, &child);
    if (s != STM_OK) return s;

    /* The parent's bptr kind must agree with the decoded node kind. */
    if (child->is_leaf != ch->is_leaf) {
        eng_node_free(child);           /* not yet linked/cached — safe */
        return STM_ECORRUPT;
    }

    eng_node *expected = NULL;
    if (!eng_child_mem_cas_link(ch, &expected, child)) {
        /* A racing wait-free descent linked this slot first (adopt its
         * child), or a consolidator swept the husk under us (restart).
         * Ours was never reachable — plain free. */
        eng_node_free(child);
        if (expected == ENG_CHILD_TOMBSTONE) {
            if (!out_stale) return STM_ECORRUPT;
            *out_stale = true;
            return STM_OK;
        }
        *out = expected;
        return STM_OK;
    }
    if (use_cache)
        (void)eng_cache_put(&eng->cache, ch->paddr, child); /* after the gate */
    *out = child;
    return STM_OK;
}

/* ========================================================================= */
/* Insert.                                                                     */
/* ========================================================================= */

/*
 * Recursively insert (key, value) under `node`. On return: STM_OK with
 * out_split->happened == FALSE (absorbed), STM_OK with happened == TRUE
 * (node split — the parent must splice (sep_key, right) in), or an
 * error with out_split untouched. See the reference doc §"Failure
 * atomicity" for the ENOMEM contract.
 */
static stm_status node_insert(stm_btree_engine *eng, eng_node *node,
                               const void *key, size_t key_len,
                               const void *val, size_t val_len,
                               uint32_t depth, split_result *out_split)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    /* 9.8-BE (chunk 8): the serial write path may not mutate THROUGH
     * a buffered node — a direct leaf write racing pending messages
     * for the same key breaks newest-wins (an older buffered DELETE
     * would later flush over a newer direct INSERT). One engine never
     * mixes regimes (today's serial fs.c writers have no message
     * producer; chunk 10's ported writers go through messages), so a
     * buffered node on a serial write descent is misuse — refused
     * loudly rather than silently corrupting. */
    if (node->buf_count) return STM_ENOTSUPPORTED;
    node->dirty = true;

    if (node->is_leaf) {
        stm_status s = eng_leaf_put(node, key, key_len, val, val_len);
        if (s != STM_OK) return s;
        if (eng_leaf_payload_bytes(node) > ENG_PAYLOAD_CAP) {
            s = eng_split_leaf(node, &out_split->right,
                               &out_split->sep_key, &out_split->sep_len);
            if (s != STM_OK) return s;     /* leaf left over-cap but complete */
            out_split->happened = true;
        }
        return STM_OK;
    }

    /* Reserve splice capacity BEFORE descending: a child split that
     * bubbles back up must splice without an allocation that could
     * fail and strand the split half. */
    stm_status s = eng_internal_reserve_splice(node);
    if (s != STM_OK) return s;

    uint32_t idx = eng_pivot_child_for(node, key, key_len);
    eng_node *child = NULL;
    s = load_child(eng, node, idx, /*use_cache=*/true, &child, NULL);
    if (s != STM_OK) return s;

    split_result cs = { 0 };
    s = node_insert(eng, child, key, key_len, val, val_len, depth + 1u, &cs);
    if (s != STM_OK) return s;             /* cs untouched on the error path */

    if (cs.happened) {
        eng_internal_splice(node, idx, cs.sep_key, cs.sep_len, cs.right);
        /* 9.8-BE (chunk 7b): internal pivot/child bytes budget against
         * the CARVED cap (payload minus the ε buffer region, §5.3) so
         * a full buffer can never displace pivot capacity. Pre-9.8
         * nodes packed past the carve split here on first touch. */
        if (eng_internal_payload_bytes(node) > ENG_INTERNAL_PC_CAP) {
            s = eng_split_internal(node, &out_split->right,
                                   &out_split->sep_key, &out_split->sep_len);
            if (s != STM_OK) return s;     /* node left over-cap but complete */
            out_split->happened = true;
        }
    }
    return STM_OK;
}

static stm_status engine_insert_locked(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    const void *value, size_t value_len)
{
    if (!eng)                       return STM_EINVAL;
    if (key_len   && !key)          return STM_EINVAL;
    if (value_len && !value)        return STM_EINVAL;

    /* Value- and key-size bounds (9.6-impl-3). A large value spills
     * out-of-line — only a value over the cap, or a key so large the
     * entry could not fit even as a spilled indirection, is refused.
     * The arg-shape checks above pre-empt STM_EBUSY (R135 doctrine). */
    if (value_len > STM_BTREE_ENGINE_MAX_VALUE_BYTES) return STM_ERANGE;
    size_t spilled_entry = (size_t)STM_BTNODE_ENTRY_HDR_SIZE + key_len +
                           ENG_VAL_TAG_SIZE + ENG_SPILL_INDIRECT_SIZE;
    if (spilled_entry > ENG_MAX_ITEM_BYTES) return STM_ERANGE;  /* key too big */

    /* No mutation inside a flushed-but-unfinalized commit window. */
    if (eng->pending.active)        return STM_EBUSY;

    eng_node *root = NULL;
    stm_status s = load_root_locked(eng, &root);
    if (s != STM_OK) return s;

    /* 9.8-BE-prepend regime purity (the buffered-node guard's chain
     * twin): a serial write through a root carrying pending deltas
     * would race newest-wins with the message stream — and a serial
     * root-grow would orphan the chain one level down where no
     * consolidator looks. One engine never mixes write regimes. */
    if (atomic_load_explicit(&root->chain_head, memory_order_acquire))
        return STM_ENOTSUPPORTED;

    /* Pre-allocate the node a root split would need, so a root split
     * is itself infallible (the descent's keys can never be stranded). */
    eng_node *spare = eng_node_new_internal_sized(1, 2);
    if (!spare) return STM_ENOMEM;

    split_result rs = { 0 };
    s = node_insert(eng, root, key, key_len, value, value_len, 0, &rs);
    if (s != STM_OK) { eng_node_free(spare); return s; }

    if (rs.happened) {
        /* Grow a new root level: [ old root | rs.right ], pivot rs.sep. */
        spare->is_leaf  = false;
        spare->dirty    = true;
        spare->n_pivots = 1;
        spare->pivots[0].key     = rs.sep_key;       /* ownership transfers */
        spare->pivots[0].key_len = rs.sep_len;
        spare->children[0] = (eng_child){ .mem = root, .is_leaf = root->is_leaf };
        spare->children[1] = (eng_child){ .mem = rs.right,
                                          .is_leaf = rs.right->is_leaf };
        eng->root = spare;
        /* 9.8-LF-2 (R170 P2-3): every eng->root reassignment publishes
         * mvcc_root release-store. The invariant from engine_internal.h
         * (mvcc_root mirrors eng->root except briefly inside
         * invalidate_memtree) holds across root-grow too. At LF-2
         * production callers hold fs->global EX so concurrent readers
         * can't be racing here, but the publish keeps the invariant
         * intact for LF-3+ and for the test surface that bypasses
         * fs->global. The PRIOR root pointer is now `spare->children[0].mem`
         * — still alive in the tree, no EBR retire needed. */
        atomic_store_explicit(&eng->mvcc_root, spare, memory_order_release);
    } else {
        eng_node_free(spare);
    }
    return STM_OK;
}

stm_status stm_btree_engine_insert(stm_btree_engine *eng,
                                   const void *key, size_t key_len,
                                   const void *value, size_t value_len)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_insert_locked(eng, key, key_len, value, value_len);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* ========================================================================= */
/* Lookup.                                                                     */
/* ========================================================================= */

static stm_status engine_lookup_locked(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found,
                                    void **out_value, size_t *out_value_len)
{
    if (!eng || !out_found || !out_value || !out_value_len) return STM_EINVAL;
    if (key_len && !key) return STM_EINVAL;
    *out_found     = false;
    *out_value     = NULL;
    *out_value_len = 0;
    if (eng->pending.active) return STM_EBUSY;

    eng_node *node = NULL;
    stm_status s = load_root_locked(eng, &node);
    if (s != STM_OK) return s;

    for (uint32_t depth = 0; ; depth++) {
        if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
        /* 9.8-BE-prepend: pending chain deltas resolve first (their
         * seqs are strictly above every buffered message). Root-only
         * in practice — deeper chains stay empty — but the consult is
         * uniform. A SEALED head is impossible in legal serial use
         * (the mini holds serial_mu; the finalize seal is excluded by
         * the caller's commit-vs-serial contract) — refuse EBUSY
         * rather than read around acknowledged mutations. */
        uint32_t kind = 0;
        bool sealed = false;
        s = chain_resolve_for_key(node, key, key_len, &kind,
                                  out_value, out_value_len, &sealed);
        if (s != STM_OK) return s;
        if (sealed) return STM_EBUSY;
        if (kind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
        if (kind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }
        if (node->is_leaf) break;
        /* 9.8-BE (chunk 7b): a persisted message on the descent path
         * resolves the key before the leaf does (newest-wins; the
         * design-§5.2 read protocol). Serial lookups see buffered
         * nodes exactly like concurrent ones — a node read from disk
         * carries its buffer regardless of which path reads it. */
        uint32_t bkind = 0;
        s = buffer_resolve_for_key(node, key, key_len, &bkind,
                                   out_value, out_value_len);
        if (s != STM_OK) return s;
        if (bkind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
        if (bkind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }
        uint32_t idx = eng_pivot_child_for(node, key, key_len);
        s = load_child(eng, node, idx, /*use_cache=*/true, &node, NULL);
        if (s != STM_OK) return s;
    }

    bool found = false;
    uint32_t i = eng_leaf_lower_bound(node, key, key_len, &found);
    if (!found) return STM_OK;             /* miss — outs already cleared */

    *out_found = true;
    uint32_t vl = node->entries[i].val_len;
    if (vl) {
        void *v = malloc(vl);
        if (!v) return STM_ENOMEM;
        memcpy(v, node->entries[i].val, vl);
        *out_value = v;
    }
    *out_value_len = vl;
    return STM_OK;
}

stm_status stm_btree_engine_lookup(stm_btree_engine *eng,
                                   const void *key, size_t key_len,
                                   bool *out_found,
                                   void **out_value, size_t *out_value_len)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_lookup_locked(eng, key, key_len, out_found,
                                        out_value, out_value_len);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* ========================================================================= */
/* 9.8-LF-1: concurrent (EBR-pinned) lookup.                                   */
/* ========================================================================= */

/*
 * Walk node `n`'s in-memory delta chain newest-first looking for an
 * applicable message for `key`. On a hit, populate `*out_kind` with
 * the delta op (INSERT / DELETE) and — for INSERT — copy the value
 * into a freshly malloc'd buffer at (*out_value, *out_value_len);
 * the caller frees *out_value. On a miss, *out_kind = 0 and the value
 * outs are left untouched.
 *
 * Memory ordering:
 *   - Head load is `acquire` so that the (currently absent) writer's
 *     CAS-release publish at LF-BE-prepend synchronises-with the
 *     reader's chain traversal — the reader sees every byte of every
 *     delta that's reachable from `head`.
 *   - `next` pointers are stable for the EBR epoch duration (a delta
 *     ever made reachable stays alive until at least one EBR advance
 *     past the consolidator's retire). The reader is inside an EBR
 *     epoch (caller contract), so the walk is wait-free + safe.
 *
 * Spec composition: realizes bepsilon.tla::PerKeyNewestWins (LIFO
 * walk; first applicable delta wins) and the chain-side of
 * concurrency_mvcc.tla::ReaderObservesCoherentTree (the EBR epoch
 * bounds delta lifetime).
 *
 * Returns STM_OK with *out_kind == 0 when the chain has no message
 * for `key`. STM_ENOMEM when an INSERT's value copy fails.
 *
 * 9.8-BE-prepend: a SEALED head means a consolidator is superseding
 * this node right now — the caller must re-load mvcc_root and restart
 * (*out_sealed set; the outs untouched). Treating a seal as an empty
 * chain would drop acknowledged mutations from the read for the seal
 * window.
 */
static stm_status chain_resolve_for_key(const eng_node *n,
                                         const void *key, size_t key_len,
                                         uint32_t *out_kind,
                                         void **out_value,
                                         size_t *out_value_len,
                                         bool *out_sealed)
{
    *out_kind   = 0;
    *out_sealed = false;
    eng_delta *d = atomic_load_explicit(&n->chain_head, memory_order_acquire);
    if (d == ENG_CHAIN_SEALED) {
        *out_sealed = true;
        return STM_OK;
    }
    while (d) {
        if (eng_key_cmp(d->key, d->key_len, key, key_len) == 0) {
            if (d->op == ENG_DELTA_DELETE) {
                *out_kind = ENG_DELTA_DELETE;
                return STM_OK;
            }
            /* ENG_DELTA_INSERT — newest wins; copy the value out. */
            *out_kind = ENG_DELTA_INSERT;
            if (d->value_len) {
                void *v = malloc(d->value_len);
                if (!v) return STM_ENOMEM;
                memcpy(v, d->value, d->value_len);
                *out_value     = v;
                *out_value_len = d->value_len;
            } else {
                *out_value     = NULL;
                *out_value_len = 0;
            }
            return STM_OK;
        }
        d = d->next;
    }
    return STM_OK;                          /* miss — chain has no msg */
}

/*
 * 9.8-BE (chunk 7b): consult an internal node's DECODED on-disk
 * message buffer for `key` — the design-§5.2 read step between the
 * chain (whose seqs are strictly greater by construction) and the
 * pivot descent. Same out contract as chain_resolve_for_key.
 *
 * Deliberately ORDER-INDEPENDENT (tracks the max-seq match) — the
 * in-memory array's order can rot when a pivot splice re-routes
 * targets (the on-disk order is re-normalised at eng_node_write), so
 * the resolver must not lean on it. buf_count is bounded by the
 * region cap (~tens) on any RELOADED node; on the LIVE root of a
 * latched engine each mini-consolidation appends ~threshold more
 * between commits, so the linear pass grows with the write burst
 * until the next commit flushes (R174 F4 — the caller's commit
 * cadence is the bound; see the reference doc's caveat).
 */
static stm_status buffer_resolve_for_key(const eng_node *n,
                                          const void *key, size_t key_len,
                                          uint32_t *out_kind,
                                          void **out_value,
                                          size_t *out_value_len)
{
    *out_kind = 0;
    const eng_msg *best = NULL;
    for (uint32_t i = 0; i < n->buf_count; i++) {
        const eng_msg *m = &n->buf_msgs[i];
        if (eng_key_cmp(m->key, m->key_len, key, key_len) != 0) continue;
        if (!best || m->seq > best->seq) best = m;
    }
    if (!best) return STM_OK;
    if (best->op == ENG_DELTA_DELETE) {
        *out_kind = ENG_DELTA_DELETE;
        return STM_OK;
    }
    *out_kind = ENG_DELTA_INSERT;
    if (best->value_len) {
        void *v = malloc(best->value_len);
        if (!v) return STM_ENOMEM;
        memcpy(v, best->value, best->value_len);
        *out_value     = v;
        *out_value_len = best->value_len;
    } else {
        *out_value     = NULL;
        *out_value_len = 0;
    }
    return STM_OK;
}

/*
 * Shared entry for the wait-free paths (lookup / scan / prepend): an
 * mvcc_root acquire-load, slow-warming via load_root under commit_mu
 * (double-checked locking; load_root publishes on success).
 *
 * 9.8-LF-2 slow-warm rationale: the first descent after engine_open
 * (lazy) or after invalidate_memtree materialises eng->root under
 * commit_mu so concurrent warmers serialise against each other and
 * against commits (which hold commit_mu for their whole span since
 * 9.8-BE-prepend). Production serial-path load_root callers stay
 * outside commit_mu — excluded by the fs->global contract one layer
 * up.
 *
 * Spec composition: concurrency_mvcc.tla::ReaderEnter — the
 * acquire-load models the reader's "atomically pin the current
 * published root" step; EBR (caller responsibility) keeps the
 * reachable set alive.
 */
static stm_status concurrent_root(stm_btree_engine *eng, eng_node **out)
{
    eng_node *node = atomic_load_explicit(&eng->mvcc_root,
                                          memory_order_acquire);
    if (node) { *out = node; return STM_OK; }
    pthread_mutex_lock(&eng->commit_mu);
    node = atomic_load_explicit(&eng->mvcc_root, memory_order_acquire);
    stm_status s = STM_OK;
    if (!node) s = load_root(eng, &node);
    pthread_mutex_unlock(&eng->commit_mu);
    if (s != STM_OK) return s;
    *out = node;
    return STM_OK;
}

/* Bound on published-root reloads when a seal is observed. A seal
 * window does no I/O and is bounded by the deltas that arrived during
 * one unsealed fold pass (the mini) or one commit flush (the finalize
 * residue migration) — zero-to-few in the common case, but NOT "a few
 * instructions" under an adversarial burst, so the spin yields the
 * CPU every ENG_SEAL_YIELD_EVERY attempts (the sealer may be
 * preempted on this very core) and surfaces STM_EBUSY only past the
 * cap. Callers treat that as a transient contention signal and retry
 * at their level (the fs-layer fallback shape), not as corruption. */
#define ENG_SEAL_RETRY_MAX   65536u
#define ENG_SEAL_YIELD_EVERY 1024u

/*
 * One EBR-pinned descent attempt (the body of
 * stm_btree_engine_lookup_concurrent). *retry is set — with the outs
 * cleared and STM_OK returned — when a SEALED chain head was observed:
 * the pinned root is being superseded mid-read and the caller restarts
 * from the fresh mvcc_root.
 *
 * No `pending.active` check — between commit_flush and
 * commit_finalize the published tree is untouched: the legacy arm's
 * in-place rewrite mutates only reader-irrelevant fields on resident
 * nodes (paddr/gen/csum/dirty), and the 9.8-BE-prepend clone arm
 * mutates only the private shadow. The publish at commit_finalize is
 * the release-store synchronisation point.
 */
static stm_status lookup_concurrent_attempt(stm_btree_engine *eng,
                                            const void *key, size_t key_len,
                                            bool *out_found,
                                            void **out_value,
                                            size_t *out_value_len,
                                            bool *retry)
{
    *out_found     = false;
    *out_value     = NULL;
    *out_value_len = 0;
    *retry         = false;
    eng_node *node = NULL;
    stm_status s = concurrent_root(eng, &node);
    if (s != STM_OK) return s;
    bool sealed = false;

    /* Descent — walk the chain at every node before consulting the
     * base (root-only carries deltas in practice; the walk is
     * uniform). */
    for (uint32_t depth = 0; !node->is_leaf; depth++) {
        if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

        uint32_t kind = 0;
        s = chain_resolve_for_key(node, key, key_len, &kind,
                                  out_value, out_value_len, &sealed);
        if (s != STM_OK) return s;
        if (sealed) break;
        if (kind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
        if (kind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }

        /* 9.8-BE (chunk 7b; doctrine corrected per R172 F1): the
         * on-disk buffer sits BELOW the chain (chain seqs strictly
         * greater by construction, §5.2) and ABOVE the descent.
         * Reader-safety under EBR rests on COW, NOT writer exclusion:
         * this wait-free reader holds NO rwlock (fs.c PARALLEL-3), so
         * fs->global EX excludes nothing here. The binding obligation
         * — on chunk 8/9's flush/prepend and on every existing
         * mutator (eng_node_write's in-place normalise,
         * eng_split_internal's partition + free) — is that buf_msgs
         * is MUTATED only on a node that is not mvcc-published (a
         * dirty COW copy no reader can reach); a published node's
         * buffer is immutable until the node is superseded and
         * EBR-retired. Dormant at chunk 7 (no production writer). */
        uint32_t bkind = 0;
        s = buffer_resolve_for_key(node, key, key_len, &bkind,
                                   out_value, out_value_len);
        if (s != STM_OK) return s;
        if (bkind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
        if (bkind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }

        uint32_t idx = eng_pivot_child_for(node, key, key_len);
        s = load_child(eng, node, idx, /*use_cache=*/false, &node, &sealed);
        if (s != STM_OK) return s;
        if (sealed) break;                 /* tombstoned slot — restart */
    }
    if (sealed) { *retry = true; return STM_OK; }

    /* Leaf — consult the leaf's chain first, then its sorted entries.
     * (The leaf-side chain hosts the same message vocabulary; useful
     * once a flush cascades messages all the way to leaves, 9.8-BE.) */
    uint32_t kind = 0;
    s = chain_resolve_for_key(node, key, key_len, &kind,
                              out_value, out_value_len, &sealed);
    if (s != STM_OK) return s;
    if (sealed) { *retry = true; return STM_OK; }
    if (kind == ENG_DELTA_INSERT) { *out_found = true;  return STM_OK; }
    if (kind == ENG_DELTA_DELETE) { *out_found = false; return STM_OK; }

    bool found = false;
    uint32_t i = eng_leaf_lower_bound(node, key, key_len, &found);
    if (!found) return STM_OK;             /* miss — outs already cleared */

    *out_found = true;
    uint32_t vl = node->entries[i].val_len;
    if (vl) {
        void *v = malloc(vl);
        if (!v) return STM_ENOMEM;
        memcpy(v, node->entries[i].val, vl);
        *out_value = v;
    }
    *out_value_len = vl;
    return STM_OK;
}

stm_status stm_btree_engine_lookup_concurrent(stm_btree_engine *eng,
                                               stm_ebr_thread *ebr,
                                               const void *key, size_t key_len,
                                               bool *out_found,
                                               void **out_value,
                                               size_t *out_value_len)
{
    if (!eng || !ebr || !out_found || !out_value || !out_value_len)
        return STM_EINVAL;
    if (key_len && !key) return STM_EINVAL;
    /* `ebr` value is documentation at LF-1: caller's pre-`enter`
     * keeps every node we touch alive. Suppress unused-arg under
     * compilers that don't see through the validation check. */
    (void)ebr;

    /* 9.8-LF-2: enter via the atomically-published mvcc_root; restart
     * on a seal (9.8-BE-prepend — the replacement root is published
     * within a few RAM instructions of any seal). */
    for (uint32_t attempt = 0; attempt < ENG_SEAL_RETRY_MAX; attempt++) {
        bool retry = false;
        stm_status s = lookup_concurrent_attempt(eng, key, key_len,
                                                 out_found, out_value,
                                                 out_value_len, &retry);
        if (s != STM_OK || !retry) return s;
        if ((attempt + 1u) % ENG_SEAL_YIELD_EVERY == 0u)
            sched_yield();
    }
    return STM_EBUSY;                      /* see ENG_SEAL_RETRY_MAX */
}

/* ========================================================================= */
/* Delete (9.6-impl-4a).                                                        */
/* ========================================================================= */

/*
 * Recursively delete `key` under `node`. On a hit the leaf entry is
 * removed and every node on the root-to-leaf path is marked dirty (so
 * commit COWs the path, sharing the unchanged subtrees); *removed is
 * set TRUE. On a miss nothing is mutated and *removed is FALSE.
 *
 * Delete-without-merge: no node is merged or structurally removed, so
 * — unlike node_insert — there is no split / splice to bubble up, and
 * a failed delete (STM_ENOMEM from eng_leaf_remove's orphan-sink
 * reserve) mutates nothing at all.
 */
static stm_status node_delete(stm_btree_engine *eng, eng_node *node,
                               const void *key, size_t key_len,
                               uint32_t depth, bool *removed)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    /* Serial-writes-through-a-buffered-node guard — see node_insert.
     * (A direct remove racing a buffered INSERT for the same key would
     * be resurrected by the later flush.) */
    if (node->buf_count) return STM_ENOTSUPPORTED;

    if (node->is_leaf) {
        bool found = false;
        uint32_t i = eng_leaf_lower_bound(node, key, key_len, &found);
        if (!found) { *removed = false; return STM_OK; }
        stm_status s = eng_leaf_remove(node, i, &eng->orphaned_spill_blocks);
        if (s != STM_OK) return s;          /* leaf intact on failure */
        node->dirty = true;
        *removed = true;
        return STM_OK;
    }

    uint32_t idx = eng_pivot_child_for(node, key, key_len);
    eng_node *child = NULL;
    stm_status s = load_child(eng, node, idx, /*use_cache=*/true, &child,
                              NULL);
    if (s != STM_OK) return s;
    s = node_delete(eng, child, key, key_len, depth + 1u, removed);
    if (s != STM_OK) return s;
    if (*removed) node->dirty = true;       /* this ancestor is COWed too */
    return STM_OK;
}

static stm_status engine_delete_locked(stm_btree_engine *eng,
                                    const void *key, size_t key_len,
                                    bool *out_found)
{
    if (!eng)            return STM_EINVAL;
    if (key_len && !key) return STM_EINVAL;
    if (out_found) *out_found = false;
    /* The arg-shape checks above pre-empt STM_EBUSY (R135 doctrine). */
    if (eng->pending.active) return STM_EBUSY;

    eng_node *root = NULL;
    stm_status s = load_root_locked(eng, &root);
    if (s != STM_OK) return s;

    /* Serial-write chain guard — see engine_insert_locked. */
    if (atomic_load_explicit(&root->chain_head, memory_order_acquire))
        return STM_ENOTSUPPORTED;

    bool removed = false;
    s = node_delete(eng, root, key, key_len, 0, &removed);
    if (s != STM_OK) return s;
    if (out_found) *out_found = removed;
    return STM_OK;
}

stm_status stm_btree_engine_delete(stm_btree_engine *eng,
                                   const void *key, size_t key_len,
                                   bool *out_found)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_delete_locked(eng, key, key_len, out_found);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* ========================================================================= */
/* 9.8-BE-prepend (chunk 9): the lock-free writer path.                        */
/* ========================================================================= */

/* stm_ebr_destructor adapters. */
static void node_free_recursive_cb(void *p) { eng_node_free_recursive(p); }
static void node_free_single_cb(void *p)    { eng_node_free(p); }

/*
 * CAS-prepend `d` onto the published root's chain
 * (concurrency.tla::WriterPrependDelta). The caller is EBR-pinned, so
 * a root superseded between the mvcc_root load and the CAS is a husk
 * whose memory is grace-protected: the CAS then observes SEALED (every
 * supersede seals first) and the loop re-loads mvcc_root. One
 * unsealed-supersede exception exists — invalidate_memtree retires
 * the tree without sealing — and a prepend that lands on the dying
 * root linearises before the invalidation: the delta dies with the
 * tree exactly like every other uncommitted mutation the invalidate
 * reverts (the retire destructor drains it; no leak, no UAF).
 *
 * On success *out_depth carries the post-prepend chain depth (the
 * mini-consolidation trigger).
 */
static stm_status chain_prepend(stm_btree_engine *eng, eng_delta *d,
                                uint32_t *out_depth)
{
    for (uint32_t attempt = 0; attempt < ENG_SEAL_RETRY_MAX; attempt++) {
        eng_node *root = NULL;
        stm_status s = concurrent_root(eng, &root);
        if (s != STM_OK) return s;

        eng_delta *h = atomic_load_explicit(&root->chain_head,
                                            memory_order_acquire);
        while (h != ENG_CHAIN_SEALED) {
            d->next = h;
            if (atomic_compare_exchange_weak_explicit(
                    &root->chain_head, &h, d,
                    memory_order_release, memory_order_acquire)) {
                *out_depth = atomic_fetch_add_explicit(&root->chain_depth,
                                                       1u,
                                                       memory_order_relaxed)
                             + 1u;
                return STM_OK;
            }
            /* h reloaded by the failed CAS; re-check the seal. */
        }
        /* Sealed: re-load mvcc_root and retry; yield periodically so
         * a preempted sealer can finish its window. */
        if ((attempt + 1u) % ENG_SEAL_YIELD_EVERY == 0u)
            sched_yield();
    }
    return STM_EBUSY;                      /* see ENG_SEAL_RETRY_MAX */
}

/*
 * Fold a detached chain (LIFO, newest-first) into `clone`'s message
 * buffer as deep-copied msgs in ASCENDING seq order, appended after
 * the existing buffer content (in-memory order may rot; the resolver
 * is order-independent and eng_node_write re-normalises). On OOM the
 * clone keeps whatever was appended (the caller frees it wholesale)
 * and the chain is untouched — restorable.
 */
/* Reverse the LIFO segment [head..stop) into an ascending-seq pointer
 * scratch (v[0] = oldest; stop == NULL walks the whole chain). *out_k
 * = length; NULL scratch iff empty. */
static stm_status chain_to_ascending(eng_delta *head, eng_delta *stop,
                                     eng_delta ***out_v, uint32_t *out_k)
{
    uint32_t k = 0;
    for (eng_delta *d = head; d != stop; d = d->next) {
        if (k == UINT32_MAX) return STM_ECORRUPT;   /* defensive */
        k++;
    }
    *out_v = NULL;
    *out_k = k;
    if (!k) return STM_OK;
    eng_delta **v = eng_buf_alloc((size_t)k * sizeof *v);
    if (!v) return STM_ENOMEM;
    uint32_t i = k;
    for (eng_delta *d = head; d != stop; d = d->next) v[--i] = d;
    *out_v = v;
    return STM_OK;
}

/* Append deltas v[from..k) (ascending seq) to `node`'s message buffer
 * as deep copies. buf_count always covers exactly the fully-owned
 * slots, so a partial-OOM node frees cleanly. */
static stm_status msgs_append_deltas(eng_node *node,
                                     eng_delta *const *v,
                                     uint32_t from, uint32_t k)
{
    if (from >= k) return STM_OK;
    eng_msg *g = eng_buf_realloc(node->buf_msgs,
                                 ((size_t)node->buf_count + (k - from))
                                 * sizeof *g);
    if (!g) return STM_ENOMEM;
    node->buf_msgs = g;

    for (uint32_t i = from; i < k; i++) {
        const eng_delta *d = v[i];
        eng_msg m = { 0 };
        m.op  = (uint8_t)d->op;
        m.seq = d->seq;
        if (d->key_len) {
            m.key = eng_buf_alloc(d->key_len);
            if (!m.key) return STM_ENOMEM;
            memcpy(m.key, d->key, d->key_len);
            m.key_len = d->key_len;
        }
        if (d->value_len) {
            m.value = eng_buf_alloc(d->value_len);
            if (!m.value) { free(m.key); return STM_ENOMEM; }
            memcpy(m.value, d->value, d->value_len);
            m.value_len = d->value_len;
        }
        node->buf_msgs[node->buf_count] = m;
        node->buf_count++;
    }
    return STM_OK;
}

/* Fold the LIFO segment [head..stop) into `clone`'s buffer as deep
 * copies, ascending seq. */
static stm_status chain_fold_into_buffer(eng_node *clone, eng_delta *head,
                                         eng_delta *stop)
{
    eng_delta **v = NULL;
    uint32_t    k = 0;
    stm_status s = chain_to_ascending(head, stop, &v, &k);
    if (s != STM_OK) return s;
    s = msgs_append_deltas(clone, v, 0, k);
    free(v);
    return s;
}

/*
 * Inline mini-consolidation (design 2.2 / 5.3, the btree_lf
 * consolidate analog): drain the root chain into a single-node COW
 * clone's message buffer, publish the clone, EBR-retire the husk and
 * the detached chain. Trylock-only — a running commit, another mini,
 * or any serial op just leaves the chain long until a later prepend
 * retries (bounded reader cost, never blocked writers).
 *
 * Lock order: serial_mu OUTER -> commit_mu INNER (the documented
 * future-co-holder order from engine_internal.h, realised here).
 * serial_mu excludes serial descents mutating the tree under the
 * clone; commit_mu excludes commits and other minis, and makes the
 * (eng->root, mvcc_root) swap atomic against slow-warm readers.
 *
 * The single-node clone SHARES the subtree (children[].mem pointers
 * copied) — sound because the husk retires with the SINGLE-node
 * destructor: ownership of the shared children transfers atomically
 * to the clone at publish; a reader pinned on the husk still descends
 * them (immutable, alive) until its epoch exits. Internal roots only:
 * a leaf root has no buffer to consolidate into and applying could
 * force a split (a structural grow is the commit consolidator's job);
 * its chain just grows until the next commit.
 */
static void engine_try_mini_consolidate(stm_btree_engine *eng)
{
    if (pthread_mutex_trylock(&eng->serial_mu) != 0) return;
    if (pthread_mutex_trylock(&eng->commit_mu) != 0) {
        pthread_mutex_unlock(&eng->serial_mu);
        return;
    }

    eng_node *root = eng->root;            /* mirror of mvcc_root here */
    eng_delta *detached = NULL;
    eng_node  *clone    = NULL;
    bool       published = false;

    if (eng->pending.active) goto out;     /* commit window open */
    if (!root || root->is_leaf) goto out;
    if (atomic_load_explicit(&root->chain_depth, memory_order_relaxed) <
        ENG_CONSOLIDATE_THRESHOLD)
        goto out;                          /* raced a prior mini */

    /* Build the clone BEFORE sealing — the live chain keeps serving
     * readers and writers across the fallible part. */
    clone = eng_node_clone_shallow(root);
    if (!clone) goto out;

    /* Round 1 — UNSEALED bulk fold (R174 F2): the segment below a
     * captured head is immutable (prepend-only; ->next never mutated),
     * so the O(chain) alloc+copy work runs with readers and writers
     * fully live. A fold OOM here just discards the clone — the live
     * chain was never touched. */
    eng_delta *snap = atomic_load_explicit(&root->chain_head,
                                           memory_order_acquire);
    if (!snap) goto out;                   /* raced empty */
    if (chain_fold_into_buffer(clone, snap, NULL) != STM_OK) goto out;

    /* Seal + the suffix: only the deltas that arrived DURING round 1
     * fold inside the seal window — bounded by the arrival rate over
     * one fold pass, zero-to-few in practice. */
    detached = atomic_exchange_explicit(&root->chain_head, ENG_CHAIN_SEALED,
                                        memory_order_acq_rel);
    if (detached != snap &&
        chain_fold_into_buffer(clone, detached, snap) != STM_OK) {
        /* OOM mid-suffix: restore the detached chain (no other sealer
         * exists under commit_mu; spinners CAS onto the restored
         * head) — nothing lost, nothing published. */
        atomic_store_explicit(&root->chain_head, detached,
                              memory_order_release);
        detached = NULL;
        goto out;
    }
    clone->dirty = true;

    eng->root = clone;
    atomic_store_explicit(&eng->mvcc_root, clone, memory_order_release);
    published = true;

    /* Tombstone sweep (see ENG_CHILD_TOMBSTONE): claim every husk
     * child slot so a pinned descent can no longer link into a node
     * whose retire is NON-recursive. A link that landed between the
     * shallow copy and this xchg is adopted into the clone's still-
     * cold slot — or, if a reader already linked the clone's slot
     * independently, retired (recursively: deeper links may hang off
     * it by the time grace ends). */
    for (uint32_t i = 0; i < root->n_pivots + 1u; i++) {
        eng_node *late = __atomic_exchange_n(&root->children[i].mem,
                                             ENG_CHILD_TOMBSTONE,
                                             __ATOMIC_ACQ_REL);
        /* Acquire: the published clone's slot may be CAS-linked by a
         * cold descent at this instant (R174 F3 — the CAS below is
         * authoritative either way; the atomic read keeps the module
         * race-free formally, not just behaviorally). */
        if (late == eng_child_mem_acquire(&clone->children[i]))
            continue;                                   /* shared/NULL */
        eng_node *expect = NULL;
        if (!eng_child_mem_cas_link(&clone->children[i], &expect, late)) {
            if (stm_ebr_retire(late, node_free_recursive_cb) != STM_OK) {
                /* leak — safer than freeing under a pinned reader */
            }
        }
    }

    /* The husk's cache entry (keyed by its paddr) must not outlive it;
     * safe to reset wholesale — readers never touch the cache and both
     * serialising mutexes are held. */
    cache_reset(eng);

    /* Grace-deferred reclamation; a retire-record OOM leaks (strictly
     * safer than freeing under a pinned reader). */
    if (stm_ebr_retire(root, node_free_single_cb) != STM_OK) { /* leak */ }
    if (stm_ebr_retire(detached, eng_delta_chain_free) != STM_OK) { /* leak */ }
    (void)stm_ebr_try_advance();

out:
    if (clone && !published)
        eng_node_free(clone);   /* SINGLE free — shared subtree pointers */
    pthread_mutex_unlock(&eng->commit_mu);
    pthread_mutex_unlock(&eng->serial_mu);
}

/*
 * Common validated writer entry: latch the concurrent regime, mint a
 * seq, deep-copy the mutation into a delta, prepend, maybe mini-
 * consolidate. The caller is inside an EBR epoch (public contract).
 */
static stm_status engine_prepend_op(stm_btree_engine *eng, eng_delta_op op,
                                    const void *key, size_t key_len,
                                    const void *value, size_t value_len)
{
    /* Latch BEFORE the delta can become visible: any commit that can
     * observe the delta (chain load-acquire) then also observes the
     * latch (it is sequenced before the publishing CAS-release). The
     * FIRST _concurrent op must not race an in-flight legacy commit —
     * caller-sequenced (production: commits under fs->global EX vs
     * writers under SH; the regime transition is a code boundary, not
     * a runtime race). */
    atomic_store_explicit(&eng->concurrent_regime, true,
                          memory_order_release);

    /* Resolve the root BEFORE minting the seq: on a lazily-opened
     * engine the slow-warm inside concurrent_root runs load_root,
     * which SEEDS next_delta_seq from the persisted high water — a
     * seq minted first would order below already-persisted messages
     * and invert newest-wins after the next consolidation. */
    eng_node *seed_root = NULL;
    stm_status rs = concurrent_root(eng, &seed_root);
    if (rs != STM_OK) return rs;

    uint64_t seq = atomic_fetch_add_explicit(&eng->next_delta_seq, 1u,
                                             memory_order_relaxed) + 1u;
    if (seq > STM_BTNODE_MSG_SEQ_MAX)
        return STM_ERANGE;                 /* 48-bit wire bound */

    eng_delta *d = eng_delta_new(op, seq, key, (uint32_t)key_len,
                                 value, (uint32_t)value_len);
    if (!d) return STM_ENOMEM;

    uint32_t depth = 0;
    stm_status s = chain_prepend(eng, d, &depth);
    if (s != STM_OK) { eng_delta_free(d); return s; }

    if (depth >= ENG_CONSOLIDATE_THRESHOLD)
        engine_try_mini_consolidate(eng);
    return STM_OK;
}

/* CF-2d: the injected-seal test knob — see the engine_internal.h
 * contract. Same countdown idiom as eng_test_oom_countdown (the
 * fetch_sub that returns 0 fires AND lands the value on -1 =
 * disabled, so skip-N-fire-once needs no explicit re-arm), plus the
 * -2 fire-always sentinel for the honest-EBUSY-at-the-bound leg. */
_Atomic(int) eng_test_busy_countdown = -1;

static bool eng_test_busy_fire(void)
{
    int v = atomic_load_explicit(&eng_test_busy_countdown,
                                 memory_order_relaxed);
    if (v == -2) return true;
    if (v >= 0 &&
        atomic_fetch_sub_explicit(&eng_test_busy_countdown, 1,
                                  memory_order_relaxed) == 0)
        return true;
    return false;
}

stm_status stm_btree_engine_insert_concurrent(stm_btree_engine *eng,
                                              stm_ebr_thread *ebr,
                                              const void *key, size_t key_len,
                                              const void *value,
                                              size_t value_len)
{
    if (!eng || !ebr)               return STM_EINVAL;
    if (key_len   && !key)          return STM_EINVAL;
    if (value_len && !value)        return STM_EINVAL;
    (void)ebr;                             /* caller's pre-enter contract */

    /* The serial insert's bounds, plus the buffered-message key bound
     * (a delta must be expressible as an on-disk message — key_len:2
     * on the wire, STM_METAKEY-scale by policy). */
    if (value_len > STM_BTREE_ENGINE_MAX_VALUE_BYTES) return STM_ERANGE;
    if (key_len > STM_BTNODE_MSG_KEY_MAX)             return STM_ERANGE;
    size_t spilled_entry = (size_t)STM_BTNODE_ENTRY_HDR_SIZE + key_len +
                           ENG_VAL_TAG_SIZE + ENG_SPILL_INDIRECT_SIZE;
    if (spilled_entry > ENG_MAX_ITEM_BYTES) return STM_ERANGE;

    if (eng_test_busy_fire()) return STM_EBUSY;   /* CF-2d injection */

    return engine_prepend_op(eng, ENG_DELTA_INSERT, key, key_len,
                             value, value_len);
}

stm_status stm_btree_engine_delete_concurrent(stm_btree_engine *eng,
                                              stm_ebr_thread *ebr,
                                              const void *key, size_t key_len)
{
    if (!eng || !ebr)      return STM_EINVAL;
    if (key_len && !key)   return STM_EINVAL;
    (void)ebr;
    if (key_len > STM_BTNODE_MSG_KEY_MAX) return STM_ERANGE;

    if (eng_test_busy_fire()) return STM_EBUSY;   /* CF-2d injection */

    return engine_prepend_op(eng, ENG_DELTA_DELETE, key, key_len, NULL, 0);
}

/* ========================================================================= */
/* Bε flush (9.8-BE-flush, chunk 8).                                           */
/* ========================================================================= */

/*
 * The flush moves an internal node's buffered messages exactly one
 * tree level down (design §5.2): an internal child absorbs them into
 * its own buffer (recursing when that buffer crosses the region cap);
 * a leaf child has them APPLIED. Splits are handled EAGERLY — the
 * over-cap check runs after every single splice, so every
 * eng_split_internal call sees a total at most one splice past
 * ENG_INTERNAL_PC_CAP — within the chooser's feasible band
 * T <= 2 x PC_CAP - max_pivot (the band argument in the reference
 * doc's chunk-8 section; R173 F3 — NOT R172 F4's narrower 4/3-cap
 * proof). Because one flush can peel a node more than once, peels
 * accumulate in an eng_split_vec instead of a single split_result;
 * message routing mid-flush goes through the FAMILY (the node plus
 * its peels so far) so a peel's key range keeps receiving its
 * messages after the split.
 *
 * R172 F1 (BINDING): everything here mutates buf_msgs and node
 * structure. It may only run on a subtree no wait-free reader can be
 * traversing — reader safety is COW, never writer exclusion. The only
 * production caller is the commit path (LF-2 regime: fs->global EX
 * writers; production buffers stay empty until chunk 9); chunk 9's
 * consolidator MUST route flushes through unpublished COW copies.
 */

static int msg_seq_cmp(const void *a, const void *b)
{
    const eng_msg *ma = a, *mb = b;
    if (ma->seq < mb->seq) return -1;
    if (ma->seq > mb->seq) return 1;
    return 0;
}

static stm_status split_vec_push(eng_split_vec *vec,
                                 uint8_t *sep_key, uint32_t sep_len,
                                 eng_node *right)
{
    if (vec->n == vec->cap) {
        uint32_t nc = vec->cap ? vec->cap * 2u : 4u;
        eng_split_ent *nv = eng_buf_realloc(vec->v, (size_t)nc * sizeof *nv);
        if (!nv) return STM_ENOMEM;        /* caller frees sep_key/right */
        vec->v   = nv;
        vec->cap = nc;
    }
    vec->v[vec->n++] = (eng_split_ent){ .sep_key = sep_key,
                                        .sep_len = sep_len,
                                        .right   = right };
    return STM_OK;
}

/*
 * Route `key` across the flush family: `node` plus the siblings
 * peeled off it so far. A peel covers [its separator, the next-higher
 * separator); node keeps (-inf, min separator) — so the member with
 * the LARGEST separator <= key covers key (key == sep routes to the
 * peel, matching the split partition's `>= sep -> right`).
 */
static eng_node *flush_family_route(eng_node *node, const eng_split_vec *vec,
                                    const void *key, size_t key_len)
{
    eng_node            *best = node;
    const eng_split_ent *bs   = NULL;
    for (uint32_t i = 0; i < vec->n; i++) {
        const eng_split_ent *e = &vec->v[i];
        if (eng_key_cmp(e->sep_key, e->sep_len, key, key_len) <= 0 &&
            (!bs || eng_key_cmp(e->sep_key, e->sep_len,
                                bs->sep_key, bs->sep_len) > 0)) {
            best = e->right;
            bs   = e;
        }
    }
    return best;
}

/*
 * Eager self-split of family member `t`, run immediately after every
 * splice into it. The while is defensive — the eager discipline keeps
 * the total within one splice of the cap, so one split always
 * suffices (and strictly reduces the byte count, so the loop
 * terminates regardless).
 */
static stm_status flush_eager_split(eng_node *t, eng_split_vec *out_vec)
{
    while (eng_internal_payload_bytes(t) > ENG_INTERNAL_PC_CAP) {
        eng_node *right = NULL;
        uint8_t  *sep   = NULL;
        uint32_t  sl    = 0;
        stm_status s = eng_split_internal(t, &right, &sep, &sl);
        if (s != STM_OK) return s;
        s = split_vec_push(out_vec, sep, sl, right);
        if (s != STM_OK) {
            free(sep);
            /* The moved-out half is no longer reachable from t —
             * freeing it here cannot double-free with the caller's
             * memtree invalidation. */
            eng_node_free_recursive(right);
            return s;
        }
    }
    return STM_OK;
}

/*
 * Splice one child-level peel (sep, right) into the family member
 * covering sep, then eagerly re-split that member. Owns (sep, right):
 * on failure both are freed (they are not tree-reachable).
 */
static stm_status flush_absorb_peel(eng_node *node, eng_split_vec *out_vec,
                                    uint8_t *sep, uint32_t sep_len,
                                    eng_node *right)
{
    eng_node *t = flush_family_route(node, out_vec, sep, sep_len);
    stm_status s = eng_internal_reserve_splice(t);
    if (s != STM_OK) {
        free(sep);
        eng_node_free_recursive(right);
        return s;
    }
    eng_internal_splice(t, eng_pivot_child_for(t, sep, sep_len),
                        sep, sep_len, right);
    /* The splice mutated t's structure — commit_node must rewrite it.
     * flush_walk's absorb target need not be otherwise dirty (its own
     * buffer may be under-cap): R173 F1. */
    t->dirty = true;
    return flush_eager_split(t, out_vec);
}

/* Move message *m into an internal child's buffer (struct copy — the
 * key/value heap transfers; the caller zeroes the source slot). Exact
 * realloc per append: counts are bounded by the region cap plus the
 * in-flight batch, both small. */
static stm_status flush_buf_append(eng_node *child, const eng_msg *m)
{
    eng_msg *g = eng_buf_realloc(child->buf_msgs,
                                 ((size_t)child->buf_count + 1u) * sizeof *g);
    if (!g) return STM_ENOMEM;
    child->buf_msgs = g;
    g[child->buf_count++] = *m;
    return STM_OK;
}

/*
 * Apply one message to a leaf child. INSERT upserts (a message value
 * is wire-bounded far below the spill threshold, but eng_leaf_put
 * handles any size uniformly — spill is decided downstream by
 * leaf_sync_spill at commit, which runs AFTER the flush). DELETE
 * removes if present, routing an orphaned spill chain to the commit
 * bookkeeping; a DELETE for an absent key is a no-op.
 */
static stm_status flush_leaf_apply(stm_btree_engine *eng, eng_node *leaf,
                                   const eng_msg *m)
{
    if (m->op == ENG_DELTA_INSERT)
        return eng_leaf_put(leaf, m->key, m->key_len,
                            m->value, m->value_len);
    bool found = false;
    uint32_t i = eng_leaf_lower_bound(leaf, m->key, m->key_len, &found);
    if (!found) return STM_OK;
    return eng_leaf_remove(leaf, i, &eng->orphaned_spill_blocks);
}

stm_status eng_flush_node(stm_btree_engine *eng, eng_node *node,
                           uint32_t depth, eng_split_vec *vec)
{
    if (depth >= ENG_FLUSH_MAX_RECURSION) return STM_ECORRUPT;
    if (node->is_leaf || !node->buf_count) return STM_OK;

    /* Detach the WHOLE buffer up front (design §5.2 step 5's clear) —
     * a split of `node` mid-delivery then partitions an empty buffer.
     * From here every exit leaves the buffer detached and node dirty;
     * an error mid-delivery leaves the memtree half-mutated and the
     * caller MUST drop it (the durable tree still holds every
     * message — nothing is lost or duplicated). */
    eng_msg  *msgs = node->buf_msgs;
    uint32_t  n    = node->buf_count;
    node->buf_msgs  = NULL;
    node->buf_count = 0;
    node->dirty     = true;

    /* Deliver in ascending-seq order so per-key newest-wins holds at
     * every recipient (bepsilon.tla::FlushPreservesNewestWins) — the
     * in-memory array order is not trustworthy (chunk 7b). */
    qsort(msgs, n, sizeof *msgs, msg_seq_cmp);

    stm_status s = STM_OK;
    for (uint32_t i = 0; i < n && s == STM_OK; i++) {
        eng_msg  *m   = &msgs[i];
        eng_node *f   = flush_family_route(node, vec, m->key, m->key_len);
        uint32_t  idx = eng_pivot_child_for(f, m->key, m->key_len);
        eng_node *child = NULL;
        s = load_child(eng, f, idx, /*use_cache=*/false, &child, NULL);
        if (s != STM_OK) break;

        if (!child->is_leaf) {
            s = flush_buf_append(child, m);
            if (s != STM_OK) break;
            /* Heap ownership moved into the child; keep the source
             * slot inert for the final array free. */
            m->key = NULL;  m->value = NULL;
            m->key_len = 0; m->value_len = 0;
            child->dirty = true;
            if (eng_msgs_region_bytes(child->buf_msgs, child->buf_count) >
                ENG_BUFFER_REGION_MAX) {
                /* The child's buffer crossed the region cap — flush it
                 * in turn. Its peels sit at THIS node's level: splice
                 * each into the family. */
                eng_split_vec cvec = { 0 };
                s = eng_flush_node(eng, child, depth + 1u, &cvec);
                for (uint32_t j = 0; s == STM_OK && j < cvec.n; j++) {
                    eng_split_ent *e = &cvec.v[j];
                    s = flush_absorb_peel(node, vec, e->sep_key, e->sep_len,
                                          e->right);
                    e->sep_key = NULL;      /* consumed (or freed) */
                    e->right   = NULL;
                }
                eng_split_vec_free_deep(&cvec);    /* un-spliced remainder */
            }
        } else {
            s = flush_leaf_apply(eng, child, m);
            if (s != STM_OK) break;
            child->dirty = true;
            if (eng_leaf_payload_bytes(child) > ENG_PAYLOAD_CAP) {
                s = eng_internal_reserve_splice(f);
                if (s != STM_OK) break;
                eng_node *right = NULL;
                uint8_t  *sep   = NULL;
                uint32_t  sl    = 0;
                s = eng_split_leaf(child, &right, &sep, &sl);
                if (s != STM_OK) break;
                eng_internal_splice(f, idx, sep, sl, right);
                s = flush_eager_split(f, vec);
            }
        }
    }

    eng_msg_array_free(msgs, n);
    return s;
}

/*
 * Commit-time flush trigger (design §3.4 step 2): walk the RESIDENT
 * in-memory tree; any internal node whose buffer exceeds the region
 * cap flushes toward the leaves. A node's peels splice into its
 * parent's family; the root's peels bubble to the commit wrapper for
 * the root grow. Children are read at a live bound — splices from a
 * child's flush grow the count, and the freshly spliced siblings
 * (already flushed / empty-buffered) re-check as no-ops.
 */
static stm_status flush_walk(stm_btree_engine *eng, eng_node *node,
                             uint32_t depth, eng_split_vec *vec)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    if (node->is_leaf) return STM_OK;

    stm_status s = STM_OK;
    if (node->buf_count &&
        eng_msgs_region_bytes(node->buf_msgs, node->buf_count) >
            ENG_BUFFER_REGION_MAX)
        s = eng_flush_node(eng, node, depth, vec);

    for (uint32_t i = 0; s == STM_OK && i < node->n_pivots + 1u; i++) {
        eng_node *c = node->children[i].mem;
        if (!c || c->is_leaf) continue;
        eng_split_vec cvec = { 0 };
        s = flush_walk(eng, c, depth + 1u, &cvec);
        for (uint32_t j = 0; s == STM_OK && j < cvec.n; j++) {
            eng_split_ent *e = &cvec.v[j];
            s = flush_absorb_peel(node, vec, e->sep_key, e->sep_len,
                                  e->right);
            e->sep_key = NULL;
            e->right   = NULL;
        }
        eng_split_vec_free_deep(&cvec);
        /* A dirtied descendant re-binds its parent's child bptr at
         * commit — but commit_node only visits children of DIRTY
         * nodes, so the dirtiness must bubble to the commit root or
         * the rewritten subtree is never reached and the "successful"
         * commit persists nothing of it (R173 F1: acked-commit data
         * loss; proven by reproduction against a clean ancestor). */
        if (s == STM_OK && c->dirty) node->dirty = true;
    }
    return s;
}

/*
 * Absorb root-level peels by growing the tree upward: a fresh
 * internal root takes the old root as child 0 and splices every peel
 * at its routed position (peel ranges are disjoint, so any splice
 * order lands sorted). Splicing can push the new root over the cap —
 * its own eager peels feed the next round. Consumes *vec.
 *
 * mvcc_root is published ONCE, after the last peel is spliced (R173
 * F2): a mid-construction root (0 pivots, half its ranges still in
 * un-spliced peels) must never be reader-visible — a wait-free
 * reader holds no lock, so a per-round publish would route peeled
 * ranges into the wrong remaining subtree. The brief eng->root /
 * mvcc_root divergence during the grow matches invalidate_memtree's
 * documented exception to the R170 P2-3 mirror invariant; the error
 * arms leave the unpublished half-built root for the caller's
 * invalidate_memtree.
 */
static stm_status grow_root_absorb(stm_btree_engine *eng, eng_node **rootp,
                                   eng_split_vec *vec, bool publish)
{
    uint32_t rounds = 0;
    while (vec->n) {
        if (++rounds > ENG_FLUSH_MAX_RECURSION) {
            eng_split_vec_free_deep(vec);
            return STM_ECORRUPT;
        }
        eng_node *nr = eng_node_new_internal_sized(vec->n, vec->n + 1u);
        if (!nr) {
            eng_split_vec_free_deep(vec);
            return STM_ENOMEM;
        }
        nr->dirty       = true;
        /* Carry the seq high water with the root identity (the stamp
         * site reads the CURRENT root's field — 9.8-BE-prepend). */
        nr->seq_hw      = (*rootp)->seq_hw;
        nr->children[0] = (eng_child){ .mem     = *rootp,
                                       .is_leaf = (*rootp)->is_leaf };
        *rootp = nr;           /* prior root reachable as children[0].mem */

        eng_split_vec next = { 0 };
        stm_status    s    = STM_OK;
        for (uint32_t i = 0; s == STM_OK && i < vec->n; i++) {
            eng_split_ent *e = &vec->v[i];
            s = flush_absorb_peel(nr, &next, e->sep_key, e->sep_len,
                                  e->right);
            e->sep_key = NULL;
            e->right   = NULL;
        }
        eng_split_vec_free_deep(vec);          /* un-consumed remainder */
        *vec = next;
        if (s != STM_OK) {
            eng_split_vec_free_deep(vec);
            return s;
        }
    }
    if (publish)
        atomic_store_explicit(&eng->mvcc_root, *rootp,
                              memory_order_release);
    return STM_OK;
}

/* ========================================================================= */
/* Commit — incremental COW, three-phase (flush / finalize / abort).            */
/* ========================================================================= */

/* ---- paddr_vec — the growable commit superseded / fresh sets. -------------- */

/* Free the backing store and zero the vector. */
void paddr_vec_free(paddr_vec *v)
{
    free(v->v);
    v->v = NULL;
    v->n = 0;
    v->cap = 0;
}

/* Ensure room for `additional` more entries beyond the current count.
 * Callers that must record a paddr AFTER an irreversible device write
 * reserve first, so the subsequent push cannot fail and leak it. */
STM_MUST_USE
stm_status paddr_vec_reserve(paddr_vec *v, uint32_t additional)
{
    if ((uint32_t)(v->cap - v->n) >= additional) return STM_OK;
    uint64_t want = (uint64_t)v->n + additional;
    if (want > UINT32_MAX) return STM_ENOMEM;
    uint32_t nc = v->cap ? v->cap : 8u;
    while (nc < want) {
        if (nc > UINT32_MAX / 2u) { nc = (uint32_t)want; break; }
        nc *= 2u;
    }
    uint64_t *nv = realloc(v->v, (size_t)nc * sizeof *nv);
    if (!nv) return STM_ENOMEM;
    v->v   = nv;
    v->cap = nc;
    return STM_OK;
}

/* Append `p`. Grows on demand — fallible. */
STM_MUST_USE
stm_status paddr_vec_push(paddr_vec *v, uint64_t p)
{
    stm_status s = paddr_vec_reserve(v, 1u);
    if (s != STM_OK) return s;
    v->v[v->n++] = p;
    return STM_OK;
}

/* Free both paddr vectors and zero the pending record. */
static void pending_reset(eng_pending *p)
{
    paddr_vec_free(&p->superseded);
    paddr_vec_free(&p->fresh);
    *p = (eng_pending){ 0 };
}

/*
 * Hand a set of paddrs back to the allocator (deferred-free, stamped
 * `free_gen`). Best-effort: a vt->free failure is a (rare) reclaim
 * miss, never a correctness fault, and must not fail a finalize/abort
 * whose primary effect — publish the new root, or revert to the old —
 * is already decided.
 */
static void pending_free_paddrs(stm_btree_engine *eng,
                                 const paddr_vec *v, uint64_t free_gen)
{
    if (!eng->vt->free) return;
    for (uint32_t i = 0; i < v->n; i++)
        (void)eng->vt->free(eng->vt_ctx, v->v[i], free_gen);
}

/*
 * Drop every node-cache entry. The cache is non-owning — it never frees
 * a node — so this releases only the index structs; node lifetime is
 * the in-memory tree. Called wherever the set of live paddrs shifts out
 * from under the cache: commit_finalize (the superseded paddrs are now
 * freed) and invalidate_memtree. Without the finalize reset the cache
 * would keep entries keyed by freed paddrs, and once the allocator
 * recycles a freed paddr (impl-4) a stale hit would mis-fire
 * load_child's duplicate-paddr gate (R151 P3-1).
 */
static void cache_reset(stm_btree_engine *eng)
{
    eng_cache_destroy(&eng->cache);
    eng_cache_init(&eng->cache);
}

/*
 * Drop the in-memory tree and the node cache. The durable root triple
 * is left untouched, so the next descent reloads it from disk — or, for
 * a never-committed tree, load_root lazily re-creates an empty leaf.
 * Called on commit_abort and on a failed flush: both are the
 * in-process realisation of btree.tla's Crash — the in-flight nodes
 * are reclaimed and the last durable root is what survives.
 */
static void invalidate_memtree(stm_btree_engine *eng)
{
    /* Clear mvcc_root FIRST, then EBR-retire the tree (9.8-BE-prepend
     * — the R171 P0-4 closure): a reader that acquire-loaded the root
     * before the clear keeps a grace-protected coherent tree; a
     * fresh reader slow-warms the durable root under commit_mu. The
     * pre-chunk-9 free-without-retire here was the documented LF-2
     * UAF window. The root's residual chain (deltas an aborted commit
     * reverts) dies with the tree — the recursive destructor drains
     * per node. A retire-record OOM leaks the tree: strictly safer
     * than freeing under a possibly-pinned reader, once, on an
     * already-OOM failure path. */
    atomic_store_explicit(&eng->mvcc_root, (eng_node *)NULL,
                          memory_order_release);
    if (eng->root) {
        if (stm_ebr_retire(eng->root, node_free_recursive_cb) != STM_OK) {
            /* leak (see above) */
        }
        eng->root = NULL;
        (void)stm_ebr_try_advance();
    }
    cache_reset(eng);
    /* A delete's orphaned spill-chain paddrs are in-memory mutation
     * bookkeeping — they go with the dropped tree. The durable tree
     * still references those chains, so they must NOT be freed; just
     * clear the list (keep its backing store for reuse). */
    eng->orphaned_spill_blocks.n = 0u;
}

/*
 * Count the dirty nodes reachable from `node` through dirty ancestors —
 * exactly the set commit_node will rewrite. A clean node short-circuits
 * (node_insert dirties every ancestor of a mutation, so a clean node
 * implies a wholly-clean subtree). The count is commit_flush's
 * initial-capacity hint for the superseded / fresh paddr vectors.
 */
static stm_status count_dirty(const eng_node *node, uint32_t depth,
                               uint32_t *n)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;
    if (!node->dirty)          return STM_OK;
    if (*n == UINT32_MAX)      return STM_ECORRUPT;   /* defensive */
    (*n)++;
    if (!node->is_leaf) {
        uint32_t nc = node->n_pivots + 1u;
        for (uint32_t i = 0; i < nc; i++) {
            if (!node->children[i].mem) continue;
            stm_status s = count_dirty(node->children[i].mem, depth + 1u, n);
            if (s != STM_OK) return s;
        }
    }
    return STM_OK;
}

/*
 * Sync a dirty leaf's spilled values to disk BEFORE the leaf node is
 * written (phase-9.6-impl-3-spill-design.md §6). A spill chain is
 * rewritten only when its value changed:
 *
 *  - value still spills, chain dirty  -> free the old chain (superseded)
 *    and write a fresh one (fresh);
 *  - value still spills, chain clean  -> reuse the existing chain;
 *  - value now fits inline            -> free the old chain (superseded),
 *    drop the eng_spill;
 *  - value newly spills               -> allocate eng_spill, write a chain.
 *
 * The superseded slots are reserved up front so the record cannot fail
 * after a chain is logically gone. On any failure the partial state is
 * left for commit_flush's failed-flush handler: every fresh block paddr
 * is already in pending.fresh; every in-memory eng_spill is freed by
 * invalidate_memtree.
 */
static stm_status leaf_sync_spill(stm_btree_engine *eng, eng_node *leaf,
                                   uint64_t gen)
{
    for (uint32_t i = 0; i < leaf->n_entries; i++) {
        eng_entry *e = &leaf->entries[i];
        size_t inline_entry = (size_t)STM_BTNODE_ENTRY_HDR_SIZE +
                              e->key_len + ENG_VAL_TAG_SIZE + e->val_len;
        bool spilled = inline_entry > ENG_MAX_ITEM_BYTES;

        if (!spilled) {
            if (!e->spill) continue;            /* inline -> inline */
            /* The value shrank below the inline bound — free the stale
             * on-disk chain, drop the spill record. */
            stm_status s = paddr_vec_reserve(&eng->pending.superseded,
                                             e->spill->n_blocks);
            if (s != STM_OK) return s;
            for (uint32_t j = 0; j < e->spill->n_blocks; j++)
                (void)paddr_vec_push(&eng->pending.superseded,
                                     e->spill->blocks[j]);
            free(e->spill->blocks);
            free(e->spill);
            e->spill = NULL;
            continue;
        }

        /* Spilled. Ensure the spill record exists (a value that newly
         * crossed the inline bound has none yet). */
        if (!e->spill) {
            e->spill = calloc(1, sizeof *e->spill);
            if (!e->spill) return STM_ENOMEM;
            e->spill->dirty = true;
        }
        if (!e->spill->dirty) continue;         /* clean — reuse the chain */

        /* Free the stale chain (superseded), then write a fresh one. */
        stm_status s = paddr_vec_reserve(&eng->pending.superseded,
                                         e->spill->n_blocks);
        if (s != STM_OK) return s;
        for (uint32_t j = 0; j < e->spill->n_blocks; j++)
            (void)paddr_vec_push(&eng->pending.superseded,
                                 e->spill->blocks[j]);
        free(e->spill->blocks);
        e->spill->blocks   = NULL;
        e->spill->n_blocks = 0;

        s = eng_spill_chain_write(eng, e->val, e->val_len, gen,
                                  e->spill, &eng->pending.fresh);
        if (s != STM_OK) return s;     /* reserved fresh blocks already logged */
    }
    return STM_OK;
}

/*
 * Commit `node` and its dirty descendants bottom-up. A clean node (and
 * therefore its wholly-clean subtree — node_insert dirties every
 * ancestor of a mutation) short-circuits with its existing durable
 * paddr / csum, so only dirty root-to-leaf paths are rewritten.
 *
 * For a dirty leaf, leaf_sync_spill first writes / frees the entries'
 * spill chains. Each rewritten node's PRIOR paddr is recorded into
 * pending.superseded and its FRESH paddr into pending.fresh — finalize
 * frees the superseded set, abort frees the fresh set. A RAM-fresh node
 * (a split product, a grown root) has prior paddr 0 — nothing to
 * supersede. A clean (shared) subtree is never recorded, so a freed
 * paddr is never reachable from the new durable root
 * (btree.tla::FreedNodesNotReachable).
 *
 * The fresh / superseded slots are reserved BEFORE the device write so
 * the post-write record cannot fail and leak the just-written node.
 * The depth cap is defence in depth: the in-memory tree is built by
 * node_insert (depth-capped) and load_child (which rejects DAGs /
 * cycles), so it is always a strict tree of depth <= ENG_MAX_DEPTH.
 */
static stm_status commit_node(stm_btree_engine *eng, eng_node *node,
                               uint64_t gen, uint32_t depth,
                               uint64_t *out_paddr,
                               uint8_t out_csum[STM_BTNODE_CSUM_SIZE])
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    if (!node->dirty) {
        *out_paddr = node->paddr;
        memcpy(out_csum, node->csum, STM_BTNODE_CSUM_SIZE);
        return STM_OK;
    }

    if (!node->is_leaf) {
        uint32_t nc = node->n_pivots + 1u;
        for (uint32_t i = 0; i < nc; i++) {
            eng_child *ch = &node->children[i];
            if (!ch->mem) continue;        /* on-disk clean — slot current */
            uint64_t cp = 0;
            uint8_t  cc[STM_BTNODE_CSUM_SIZE];
            stm_status s = commit_node(eng, ch->mem, gen, depth + 1u, &cp, cc);
            if (s != STM_OK) return s;
            ch->paddr   = cp;
            ch->gen     = ch->mem->gen;
            ch->is_leaf = ch->mem->is_leaf;
            memcpy(ch->csum, cc, STM_BTNODE_CSUM_SIZE);
        }
    } else {
        /* Write / free the leaf's spilled-value chains first, so
         * eng_node_write encodes each spilled entry's indirection from
         * the now-current eng_spill. */
        stm_status s = leaf_sync_spill(eng, node, gen);
        if (s != STM_OK) return s;
    }

    /* Reserve the pending slots BEFORE the irreversible device write —
     * one fresh paddr always, one superseded iff this node had a prior
     * on-disk location — so the post-write pushes cannot fail. */
    uint64_t old_paddr = node->paddr;          /* 0 for a RAM-fresh node */
    stm_status s = paddr_vec_reserve(&eng->pending.fresh, 1u);
    if (s != STM_OK) return s;
    if (old_paddr != 0) {
        s = paddr_vec_reserve(&eng->pending.superseded, 1u);
        if (s != STM_OK) return s;
    }

    s = eng_node_write(eng, node, gen);        /* assigns a fresh paddr */
    if (s != STM_OK) return s;

    (void)paddr_vec_push(&eng->pending.fresh, node->paddr);   /* reserved */
    if (old_paddr != 0)
        (void)paddr_vec_push(&eng->pending.superseded, old_paddr); /* reserved */

    *out_paddr = node->paddr;
    memcpy(out_csum, node->csum, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

/*
 * Consolidate the consumed chain segment into the private shadow
 * (9.8-BE-prepend): an internal shadow root absorbs the deltas as
 * buffered messages (the RAM buffer is unbounded; the flush loop
 * distributes anything over-cap); a LEAF shadow root has them APPLIED
 * ascending, splitting + growing to an internal root the moment the
 * leaf overflows — the remaining deltas then buffer on the fresh
 * internal root. *shadowp may be replaced by the grow. Every failure
 * leaves a coherent (possibly half-consolidated) PRIVATE tree the
 * caller frees wholesale; the live tree and the chain are untouched.
 */
static stm_status shadow_consolidate(stm_btree_engine *eng,
                                     eng_node **shadowp,
                                     eng_delta *consumed)
{
    if (!consumed) return STM_OK;

    eng_delta **v = NULL;
    uint32_t    k = 0;
    stm_status s = chain_to_ascending(consumed, NULL, &v, &k);
    if (s != STM_OK) return s;

    eng_node *shadow = *shadowp;
    if (!shadow->is_leaf) {
        s = msgs_append_deltas(shadow, v, 0, k);
        if (s == STM_OK) shadow->dirty = true;
        free(v);
        return s;
    }

    /* Leaf root: apply ascending; grow on overflow. */
    for (uint32_t i = 0; i < k; i++) {
        const eng_delta *d = v[i];
        eng_msg view = {
            .op        = (uint8_t)d->op,
            .seq       = d->seq,
            .key       = d->key,
            .key_len   = d->key_len,
            .value     = d->value,
            .value_len = d->value_len,
        };
        s = flush_leaf_apply(eng, shadow, &view);
        if (s != STM_OK) { free(v); return s; }
        shadow->dirty = true;

        if (eng_leaf_payload_bytes(shadow) > ENG_PAYLOAD_CAP) {
            eng_node *right = NULL;
            uint8_t  *sep   = NULL;
            uint32_t  sl    = 0;
            s = eng_split_leaf(shadow, &right, &sep, &sl);
            if (s != STM_OK) { free(v); return s; }
            eng_node *nr = eng_node_new_internal_sized(1, 2);
            if (!nr) {
                free(sep);
                eng_node_free_recursive(right);
                free(v);
                return STM_ENOMEM;
            }
            nr->dirty            = true;
            nr->seq_hw           = shadow->seq_hw;
            nr->n_pivots         = 1;
            nr->pivots[0].key     = sep;           /* ownership transfers */
            nr->pivots[0].key_len = sl;
            nr->children[0] = (eng_child){ .mem = shadow, .is_leaf = true };
            nr->children[1] = (eng_child){ .mem = right,  .is_leaf = true };
            *shadowp = nr;

            /* The remainder buffers on the fresh internal root; the
             * flush loop distributes it. */
            s = msgs_append_deltas(nr, v, i + 1u, k);
            free(v);
            return s;
        }
    }
    free(v);
    return STM_OK;
}

/* The 9.8-BE-prepend CLONE arm of commit_flush — see the dispatch in
 * commit_flush_locked. Consolidates the live root's chain into a
 * private deep clone (the shadow), runs the chunk-8 Bε flush and the
 * COW node rewrite entirely on the shadow, and stashes it in
 * eng->pending for finalize to adopt. The published tree is BYTE-
 * UNTOUCHED on every path — success, OOM, I/O failure — so wait-free
 * readers stay coherent and no failure needs invalidate_memtree
 * (contrast the legacy arm, which mutates in place and must drop the
 * memtree on failure). */
static stm_status commit_flush_clone(stm_btree_engine *eng, uint64_t gen,
                                     eng_node *root,
                                     uint64_t *out_root_paddr,
                                     uint64_t *out_root_gen,
                                     uint8_t out_root_csum[32])
{
    eng_pending *p = &eng->pending;
    uint32_t orphan_base = eng->orphaned_spill_blocks.n;
    stm_status s;

    /* The chain head consumed by this commit. The chain STAYS in place
     * serving readers for the whole flush; deltas prepended during it
     * sit strictly above `consumed` and migrate onto the shadow at
     * finalize. Under commit_mu the head cannot be SEALED (sealers
     * hold it too). */
    eng_delta *consumed = atomic_load_explicit(&root->chain_head,
                                               memory_order_acquire);
    if (consumed == ENG_CHAIN_SEALED) return STM_ECORRUPT;

    eng_node *shadow = eng_node_clone_resident(root);
    if (!shadow) return STM_ENOMEM;

    s = shadow_consolidate(eng, &shadow, consumed);
    if (s != STM_OK) goto fail_shadow;

    /* The commit-time Bε flush (chunk 8) on the private shadow —
     * design 3.4 step 2, re-run to quiescence; root-level peels grow
     * the shadow locally (NO publish — finalize publishes). */
    for (uint32_t round = 0; ; round++) {
        if (round > ENG_FLUSH_MAX_RECURSION) {
            s = STM_ECORRUPT;
            goto fail_shadow;
        }
        eng_split_vec rvec = { 0 };
        s = flush_walk(eng, shadow, 0, &rvec);
        if (s != STM_OK) {
            eng_split_vec_free_deep(&rvec);
            goto fail_shadow;
        }
        if (!rvec.n) break;
        s = grow_root_absorb(eng, &shadow, &rvec, /*publish=*/false);
        if (s != STM_OK) goto fail_shadow;
    }

    /* Stamp the seq high water on the outgoing root (see btnode.h):
     * an upper bound on every message seq this tree can carry — the
     * counter covers chain-minted seqs; the buffer max covers forged /
     * inherited content. Only a dirty root is rewritten, and any
     * consolidated delta dirtied it. */
    if (shadow->dirty) {
        uint64_t hw = atomic_load_explicit(&eng->next_delta_seq,
                                           memory_order_relaxed);
        if (shadow->seq_hw > hw) hw = shadow->seq_hw;
        for (uint32_t i = 0; i < shadow->buf_count; i++)
            if (shadow->buf_msgs[i].seq > hw) hw = shadow->buf_msgs[i].seq;
        shadow->seq_hw = hw;
    }

    uint32_t n_dirty = 0;
    s = count_dirty(shadow, 0, &n_dirty);
    if (s != STM_OK) goto fail_shadow;

    s = paddr_vec_reserve(&p->superseded, n_dirty);
    if (s == STM_OK) s = paddr_vec_reserve(&p->fresh, n_dirty);
    if (s != STM_OK) goto fail_pending;
    p->gen = gen;

    /* COPY (not drain) the orphaned spill paddrs into the superseded
     * set — the engine list stays intact so abort / failure can
     * truncate back to orphan_base (see eng_pending). Finalize zeroes
     * it. */
    s = paddr_vec_reserve(&p->superseded, eng->orphaned_spill_blocks.n);
    if (s != STM_OK) goto fail_pending;
    for (uint32_t i = 0; i < eng->orphaned_spill_blocks.n; i++)
        (void)paddr_vec_push(&p->superseded, eng->orphaned_spill_blocks.v[i]);

    uint64_t rp = 0;
    uint8_t  rc[STM_BTNODE_CSUM_SIZE];
    s = commit_node(eng, shadow, gen, 0, &rp, rc);
    if (s != STM_OK) {
        /* Reclaim whatever shadow nodes were written (never durably
         * rooted); the published tree needs NO invalidate — it was
         * never touched. */
        pending_free_paddrs(eng, &p->fresh, gen);
        goto fail_pending;
    }

    p->new_root_paddr = rp;
    p->new_root_gen   = shadow->gen;
    memcpy(p->new_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    p->active        = true;
    p->clone         = true;
    p->shadow_root   = shadow;
    p->consumed_head = consumed;
    p->orphan_base   = orphan_base;

    *out_root_paddr = rp;
    *out_root_gen   = shadow->gen;
    memcpy(out_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    return STM_OK;

fail_pending:
    pending_reset(p);
fail_shadow:
    eng->orphaned_spill_blocks.n = orphan_base;
    eng_node_free_recursive(shadow);
    return s;
}

static stm_status commit_flush_locked(stm_btree_engine *eng, uint64_t gen,
                                      uint64_t *out_root_paddr,
                                      uint64_t *out_root_gen,
                                      uint8_t out_root_csum[32])
{
    if (eng->pending.active) return STM_EBUSY;
    /* The commit gen must strictly increase across FINALIZED commits —
     * node birth-gens (n_gen) are an ordering Phase 9.7's snapshot
     * retention keys on (design §3.9). It is NOT the source of
     * AEAD-nonce uniqueness: that rests on the allocator's
     * free_gen < committed_gen deferred-free discipline (a freed paddr
     * stays PENDING — un-reclaimable — until an allocator commit past
     * its free_gen; see commit_finalize / commit_abort and
     * reference/24 §Commit). An aborted commit does not consume its
     * gen, so the same gen may be reused by the retried commit. */
    if (eng->has_durable_root && gen <= eng->root_gen) return STM_EINVAL;

    eng_node *root = NULL;
    stm_status s = load_root(eng, &root);
    if (s != STM_OK) return s;             /* no pending window opened */

    /* 9.8-BE-prepend: a latched engine commits through the CLONE arm —
     * every reader-relevant mutation (consolidation, flush, node
     * rewrite) happens on a private shadow, and finalize publishes +
     * retires. The latch is sticky (see engine_internal.h): even an
     * empty chain leaves message state in PUBLISHED buffers that the
     * legacy in-place arm would scramble under wait-free readers. */
    if (atomic_load_explicit(&eng->concurrent_regime, memory_order_acquire))
        return commit_flush_clone(eng, gen, root, out_root_paddr,
                                  out_root_gen, out_root_csum);

    /* 9.8-BE-flush (chunk 8): commit-time Bε flush — any resident node
     * whose message buffer exceeds the region cap flushes toward the
     * leaves (design §3.4 step 2). Runs BEFORE count_dirty (a flush
     * dirties more nodes) and before the pending window opens, so a
     * failure needs no pending rollback. Root-level peels grow the
     * tree upward; the walk re-runs until quiescent so subtrees under
     * fresh peels are covered too. On any failure the half-flushed
     * memtree is dropped — the durable tree still holds every message
     * (bepsilon.tla::FlushPreservesMessages via full-clear delivery +
     * COW failure atomicity). */
    for (uint32_t round = 0; ; round++) {
        if (round > ENG_FLUSH_MAX_RECURSION) {
            invalidate_memtree(eng);
            return STM_ECORRUPT;
        }
        eng_split_vec rvec = { 0 };
        s = flush_walk(eng, root, 0, &rvec);
        if (s != STM_OK) {
            eng_split_vec_free_deep(&rvec);
            invalidate_memtree(eng);
            return s;
        }
        if (!rvec.n) break;                /* quiescent — no peels */
        s = grow_root_absorb(eng, &eng->root, &rvec, /*publish=*/true);
        if (s != STM_OK) {
            invalidate_memtree(eng);
            return s;
        }
        root = eng->root;                  /* the tree grew a level */
    }

    /* Seq-high-water stamp — the legacy-arm twin of the clone arm's
     * (forged buffered trees committed through this arm must reload
     * with a covering hw; see btnode.h). */
    if (root->dirty && !root->is_leaf) {
        uint64_t hw = atomic_load_explicit(&eng->next_delta_seq,
                                           memory_order_relaxed);
        if (root->seq_hw > hw) hw = root->seq_hw;
        for (uint32_t i = 0; i < root->buf_count; i++)
            if (root->buf_msgs[i].seq > hw) hw = root->buf_msgs[i].seq;
        root->seq_hw = hw;
    }

    /* count_dirty gives the initial-capacity hint for the paddr vectors
     * (spill chains grow them further during the walk). p is zeroed —
     * calloc at create/open, pending_reset after every commit and after
     * every failed flush. */
    uint32_t n_dirty = 0;
    s = count_dirty(root, 0, &n_dirty);
    if (s != STM_OK) {
        /* A count_dirty failure means a malformed in-memory tree (the
         * depth cap — a cycle). Drop it, consistent with the
         * commit_node corrupt-tree exit below; the next descent reloads
         * the durable root. Unreachable in practice — node_insert and
         * load_child keep the in-memory tree a strict depth-capped
         * tree — so no pending window was opened either. */
        invalidate_memtree(eng);
        return s;
    }

    eng_pending *p = &eng->pending;
    s = paddr_vec_reserve(&p->superseded, n_dirty);
    if (s == STM_OK) s = paddr_vec_reserve(&p->fresh, n_dirty);
    if (s != STM_OK) {
        pending_reset(p);                  /* no pending window opened */
        return s;
    }
    p->gen = gen;

    /* Spill chains orphaned by stm_btree_engine_delete since the last
     * commit join the superseded set — finalize deferred-frees them.
     * Drained here, as the in-memory deletes are about to be made
     * durable; a failed flush below drops the in-memory tree (the
     * deletes revert) and this now-empty list stays consistent. */
    s = paddr_vec_reserve(&p->superseded, eng->orphaned_spill_blocks.n);
    if (s != STM_OK) {
        pending_reset(p);
        return s;
    }
    for (uint32_t i = 0; i < eng->orphaned_spill_blocks.n; i++)
        (void)paddr_vec_push(&p->superseded, eng->orphaned_spill_blocks.v[i]);
    eng->orphaned_spill_blocks.n = 0u;

    uint64_t rp = 0;
    uint8_t  rc[STM_BTNODE_CSUM_SIZE];
    s = commit_node(eng, root, gen, 0, &rp, rc);
    if (s != STM_OK) {
        /* Failed flush — the in-process Crash. Reclaim whatever nodes
         * were written (unrooted), drop the now-inconsistent in-memory
         * tree, leave the durable root naming the previous tree. */
        pending_free_paddrs(eng, &p->fresh, gen);
        pending_reset(p);
        invalidate_memtree(eng);
        return s;
    }

    /* Flush succeeded — record the PROSPECTIVE root. The durable triple
     * (eng->root_*) stays the previous tree until commit_finalize.
     * new_root_gen is the gen the ROOT NODE was actually written at
     * (root->gen): a no-op commit of an all-clean tree keeps the root's
     * prior gen, so the triple stays openable at that gen. */
    p->new_root_paddr = rp;
    p->new_root_gen   = root->gen;
    memcpy(p->new_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    p->active = true;

    *out_root_paddr = rp;
    *out_root_gen   = root->gen;
    memcpy(out_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_commit_flush(stm_btree_engine *eng, uint64_t gen,
                                          uint64_t *out_root_paddr,
                                          uint64_t *out_root_gen,
                                          uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_gen || !out_root_csum)
        return STM_EINVAL;
    /* 9.8-BE-prepend: commits hold commit_mu for their whole span —
     * one commit per engine (design 3.4 step 1), mini-consolidations
     * excluded, slow-warm readers serialised. Lock order: commit_mu
     * OUTER -> the store vtable I/O (R170 P3-2). */
    pthread_mutex_lock(&eng->commit_mu);
    stm_status s = commit_flush_locked(eng, gen, out_root_paddr,
                                       out_root_gen, out_root_csum);
    pthread_mutex_unlock(&eng->commit_mu);
    return s;
}

/*
 * Copy the chain prefix (residue_head .. consumed_head) — the deltas
 * prepended DURING the flush — onto the (still-private) shadow's
 * chain, preserving LIFO order. The originals are NOT relinked: a
 * pinned reader may be mid-walk anywhere in the detached chain, so its
 * ->next pointers must never change; the whole detached chain retires
 * as one unit and the prefix crosses as fresh copies. Empty in
 * production (fs->global EX excludes writers during commits) — the
 * engine-level guarantee is for embedded/test callers.
 */
static stm_status migrate_residue(eng_node *shadow, eng_delta *residue,
                                  eng_delta *consumed)
{
    eng_delta *copies = NULL;                  /* newest-first, built tail-up */
    eng_delta *tail   = NULL;
    uint32_t   k      = 0;
    for (eng_delta *d = residue; d != consumed; d = d->next) {
        eng_delta *c = eng_delta_new(d->op, d->seq, d->key, d->key_len,
                                     d->value, d->value_len);
        if (!c) {
            eng_delta_chain_free(copies);
            return STM_ENOMEM;
        }
        if (tail) tail->next = c;
        else      copies     = c;
        tail = c;
        k++;
    }
    if (!k) return STM_OK;
    atomic_store_explicit(&shadow->chain_head, copies,
                          memory_order_relaxed);   /* private pre-publish */
    atomic_store_explicit(&shadow->chain_depth, k, memory_order_relaxed);
    return STM_OK;
}

/* The 9.8-BE-prepend CLONE arm of finalize: seal + detach the old
 * root's chain, migrate the flush-window prefix, publish the shadow,
 * EBR-retire the whole superseded tree + the detached chain —
 * concurrency_mvcc.tla::WriterCommit's correct branch (publish, THEN
 * retire; BuggyImmediateFree is the counterexample). */
static stm_status commit_finalize_clone(stm_btree_engine *eng)
{
    eng_pending *p      = &eng->pending;
    eng_node    *old    = eng->root;
    eng_node    *shadow = p->shadow_root;

    /* Seal first: prepends and readers observing the sentinel re-load
     * mvcc_root (the publish below lands within a few instructions).
     * Migration is the one fallible step — on OOM, restore the chain
     * and fail the finalize with the pending window intact
     * (retriable; nothing published, nothing lost). */
    eng_delta *residue = atomic_exchange_explicit(&old->chain_head,
                                                  ENG_CHAIN_SEALED,
                                                  memory_order_acq_rel);
    stm_status s = migrate_residue(shadow, residue, p->consumed_head);
    if (s != STM_OK) {
        atomic_store_explicit(&old->chain_head, residue,
                              memory_order_release);
        return s;
    }

    /* Durable triple publish (btree.tla's FinalCommit). */
    eng->root_paddr       = p->new_root_paddr;
    eng->root_gen         = p->new_root_gen;
    memcpy(eng->root_csum, p->new_root_csum, STM_BTNODE_CSUM_SIZE);
    eng->has_durable_root = true;

    /* RAM publish: the true pointer swap the LF-2 forward-note
     * reserved. Readers pinned on `old` keep a coherent immutable
     * tree until their epochs exit. */
    eng->root = shadow;
    atomic_store_explicit(&eng->mvcc_root, shadow, memory_order_release);

    /* Grace-deferred reclamation of the WHOLE superseded tree (the
     * recursive destructor also owns any child a pinned descent
     * late-links into it) + the detached chain. A retire-record OOM
     * leaks — strictly safer than freeing under a pinned reader. */
    if (stm_ebr_retire(old, node_free_recursive_cb) != STM_OK) { /* leak */ }
    if (residue &&
        stm_ebr_retire(residue, eng_delta_chain_free) != STM_OK) { /* leak */ }

    pending_free_paddrs(eng, &p->superseded, p->gen);
    eng->orphaned_spill_blocks.n = 0u;     /* copied at flush; now adopted */
    cache_reset(eng);                      /* old-tree entries die with it */
    pending_reset(p);
    (void)stm_ebr_try_advance();
    return STM_OK;
}

static stm_status commit_finalize_locked(stm_btree_engine *eng)
{
    eng_pending *p = &eng->pending;
    if (!p->active) return STM_EINVAL;

    if (p->clone) return commit_finalize_clone(eng);

    /* Publish: the flushed root becomes the durable root (btree.tla's
     * FinalCommit). The in-memory tree already matches it — every node
     * is clean at its new paddr — so it is kept, not invalidated. */
    eng->root_paddr       = p->new_root_paddr;
    eng->root_gen         = p->new_root_gen;
    memcpy(eng->root_csum, p->new_root_csum, STM_BTNODE_CSUM_SIZE);
    eng->has_durable_root = true;

    /* 9.8-LF-2: re-publish mvcc_root.
     *
     * At LF-2 commit_node mutates eng->root nodes in place (paddr/gen/
     * csum/dirty fields updated; entries/pivots/children-mem fields are
     * NOT touched on resident nodes), so the in-memory root POINTER
     * value is unchanged across a commit IF no root-grow happened
     * between commits. A root-grow during an insert (between this
     * commit and the previous one) reassigns eng->root to a fresh
     * internal node — `stm_btree_engine_insert` already publishes that
     * pointer change to mvcc_root at the root-grow site (R170 P2-3),
     * so this finalize republish is typically idempotent (same
     * pointer as the prior publish). The publish here is the
     * release-fence — a concurrent reader's subsequent acquire-load
     * synchronises-with this store, guaranteeing it observes every
     * byte commit_node mutated. At LF-2 there is no superseded
     * in-memory eng_node pointer to retire (the root-grow's prior
     * root stays alive as the new root's child[0].mem; in-place
     * commit mutation produces no superseded pointer either).
     *
     * LF-BE-prepend's consolidator will COW the dirty root-to-leaf
     * path producing a FRESH root pointer; at that point the
     * pre-publish acquire-load of old_root + the post-publish
     * stm_ebr_retire(old_root, eng_node_free_recursive) pair lands
     * HERE — the realisation of concurrency_mvcc.tla::WriterCommit's
     * correct branch (atomically publish new root, then retire
     * superseded). The forward-note is intentionally just before
     * pending_reset so the retire site is co-located with the
     * superseded-paddr free; both are the writer's "the prior tree
     * is gone" step.
     */
    atomic_store_explicit(&eng->mvcc_root, eng->root, memory_order_release);

    /* Deferred-free the superseded paddrs — the previous tree's
     * rewritten nodes, now unreachable from the new durable root. The
     * free_gen stamp is the commit's write gen; the allocator reclaims
     * them on a later commit (free_gen < committed_gen — allocator.tla,
     * bootstrap.h). A clean/shared subtree is never in `superseded`, so
     * this never frees a node the new root still points at
     * (btree.tla::FreedNodesNotReachable). */
    pending_free_paddrs(eng, &p->superseded, p->gen);
    /* The superseded paddrs are now freed — drop the node cache so it
     * carries no entry keyed by a freed paddr. The in-memory tree is
     * kept (reached via eng->root + child.mem); the cache only indexes
     * purely-on-disk children and lazily refills (R151 P3-1). */
    cache_reset(eng);
    pending_reset(p);
    return STM_OK;
}

stm_status stm_btree_engine_commit_finalize(stm_btree_engine *eng)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->commit_mu);
    stm_status s = commit_finalize_locked(eng);
    pthread_mutex_unlock(&eng->commit_mu);
    return s;
}

static stm_status commit_abort_locked(stm_btree_engine *eng)
{
    eng_pending *p = &eng->pending;
    if (!p->active) return STM_EINVAL;

    if (p->clone) {
        /* 9.8-BE-prepend clone arm: reclaim the shadow's written
         * paddrs and discard it (never published — plain recursive
         * free). The PUBLISHED tree and its chain were never touched:
         * unlike the legacy arm there is nothing to invalidate, and
         * the un-consumed deltas stay live for the next commit (an
         * aborted clone commit loses nothing in RAM — the strictly
         * safer semantic; the legacy arm's revert-everything comes
         * from its in-place flush having already scrambled the tree).
         * Orphan entries the SHADOW's message-applies pushed are
         * truncated away; the pre-flush prefix survives (its serial-
         * era deletes are still in the live tree). */
        pending_free_paddrs(eng, &p->fresh, p->gen);
        eng_node_free_recursive(p->shadow_root);
        eng->orphaned_spill_blocks.n = p->orphan_base;
        pending_reset(p);
        return STM_OK;
    }

    /* Discard the flush (btree.tla's Crash): the freshly-written nodes
     * were never durably rooted, so reclaim them; the durable root
     * triple is untouched. Drop the in-memory tree — it is now clean at
     * paddrs we just freed — so the next descent reloads the previous
     * durable root. */
    pending_free_paddrs(eng, &p->fresh, p->gen);
    pending_reset(p);
    invalidate_memtree(eng);
    return STM_OK;
}

stm_status stm_btree_engine_commit_abort(stm_btree_engine *eng)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->commit_mu);
    stm_status s = commit_abort_locked(eng);
    pthread_mutex_unlock(&eng->commit_mu);
    return s;
}

stm_status stm_btree_engine_commit(stm_btree_engine *eng, uint64_t gen,
                                    uint64_t *out_root_paddr,
                                    uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_csum) return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;

    uint64_t rp = 0, rg = 0;
    uint8_t  rc[STM_BTNODE_CSUM_SIZE];
    stm_status s = stm_btree_engine_commit_flush(eng, gen, &rp, &rg, rc);
    if (s != STM_OK) return s;             /* a failed flush reverts itself */

    /* The flush produced the new root triple — return it now, before
     * the finalize, so the caller has a usable triple regardless of
     * finalize's outcome. commit_finalize is infallible after a
     * successful flush (its only failure exit is the no-pending guard,
     * which cannot fire here), so its return value is the commit's. */
    *out_root_paddr = rp;
    memcpy(out_root_csum, rc, STM_BTNODE_CSUM_SIZE);
    return stm_btree_engine_commit_finalize(eng);
}

stm_status stm_btree_engine_get_root(const stm_btree_engine *eng,
                                      uint64_t *out_root_paddr,
                                      uint64_t *out_root_gen,
                                      uint8_t out_root_csum[32])
{
    if (!eng || !out_root_paddr || !out_root_gen || !out_root_csum)
        return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;
    if (!eng->has_durable_root) return STM_EINVAL;
    *out_root_paddr = eng->root_paddr;
    *out_root_gen   = eng->root_gen;
    memcpy(out_root_csum, eng->root_csum, STM_BTNODE_CSUM_SIZE);
    return STM_OK;
}

stm_status stm_btree_engine_verify(stm_btree_engine *eng)
{
    if (!eng) return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;
    if (!eng->has_durable_root) return STM_EINVAL;
    return eng_verify_subtree(eng, eng->root_paddr, eng->root_gen,
                              eng->root_csum, 0);
}

/* ========================================================================= */
/* Paddr enumeration (9.7-impl-4b — rollback block reclamation).               */
/* ========================================================================= */

/*
 * Recursive node + spill-block paddr enumerator. Built on eng_node_read,
 * which does the read + Merkle + AEAD + decode and — for a leaf —
 * materialises every spilled value's chain into entry->spill->blocks; so
 * the walk inherits every integrity gate eng_node_read enforces. Mirrors
 * eng_verify_subtree's descent shape but emits each on-disk block paddr
 * via `cb` rather than only verifying it. A nonzero `cb` return aborts
 * the walk via `*stopped` (the established scan_node pattern).
 */
static stm_status engine_walk_paddrs_subtree(
        stm_btree_engine *eng, uint64_t paddr, uint64_t gen,
        const uint8_t csum[STM_BTNODE_CSUM_SIZE], uint32_t depth,
        stm_btree_engine_paddr_cb cb, void *ctx, bool *stopped)
{
    if (*stopped) return STM_OK;
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    eng_node *n = NULL;
    stm_status s = eng_node_read(eng, paddr, gen, csum, &n);
    if (s != STM_OK) return s;

    /* Emit this node's own paddr. */
    if (cb(paddr, ctx) != 0) { *stopped = true; eng_node_free(n); return STM_OK; }

    if (n->is_leaf) {
        /* Each spilled value's chain blocks were materialised into
         * entry->spill->blocks by eng_node_read's leaf_load_cb. */
        for (uint32_t i = 0; i < n->n_entries; i++) {
            eng_spill *sp = n->entries[i].spill;
            if (!sp) continue;
            for (uint32_t j = 0; j < sp->n_blocks; j++) {
                if (cb(sp->blocks[j], ctx) != 0) {
                    *stopped = true; eng_node_free(n); return STM_OK;
                }
            }
        }
        eng_node_free(n);
        return STM_OK;
    }

    /* Internal: recurse through every child (children are not loaded
     * into n->children[i].mem by eng_node_read — the walk re-reads each
     * from its bptr, so eng_node_free of one node frees no subtree).
     * R161 P3-2: eng_node_read's child_load_cb already rejected any
     * child bptr whose kind byte is not LEAF/INTERNAL (STM_ECORRUPT at
     * decode), so this walk inherits eng_verify_subtree's explicit
     * child-kind gate transitively — a bad-kind parent never decodes. */
    uint32_t nc = n->n_pivots + 1u;
    for (uint32_t i = 0; s == STM_OK && i < nc && !*stopped; i++) {
        s = engine_walk_paddrs_subtree(eng, n->children[i].paddr,
                                          n->children[i].gen,
                                          n->children[i].csum,
                                          depth + 1u, cb, ctx, stopped);
    }
    eng_node_free(n);
    return s;
}

stm_status stm_btree_engine_walk_paddrs(stm_btree_engine *eng,
                                          stm_btree_engine_paddr_cb cb,
                                          void *ctx)
{
    if (!eng || !cb)            return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;
    if (!eng->has_durable_root) return STM_EINVAL;
    bool stopped = false;
    return engine_walk_paddrs_subtree(eng, eng->root_paddr, eng->root_gen,
                                         eng->root_csum, 0, cb, ctx, &stopped);
}

/* ========================================================================= */
/* Scan + stats.                                                                */
/* ========================================================================= */

/* ---- Scan message overlay (9.8-BE-flush, chunk 8). ------------------------ */

/*
 * A scan descending through buffered internal nodes carries down an
 * OVERLAY window: per key, the newest (max-seq) pending message
 * applicable to the subtree. At the leaf the window merges with the
 * stored entries — an INSERT overrides or introduces its key, a
 * DELETE hides it — so the enumeration observes exactly what a
 * lookup would (bepsilon.tla::PerKeyNewestWins). READ-ONLY by design:
 * a scan never flushes (R172 F1 — a published node's buffer is
 * immutable under wait-free readers; a reader cannot COW), so the
 * concurrent walker gets the merge for free.
 *
 * The window is a key-sorted array of message POINTERS into the
 * nodes' buf_msgs arrays; those stay stable for the walk's lifetime
 * (the serial path holds serial_mu; the concurrent path is EBR-pinned
 * over immutable published buffers).
 */

static int msg_key_seq_cmp(const void *a, const void *b)
{
    const eng_msg *ma = *(const eng_msg *const *)a;
    const eng_msg *mb = *(const eng_msg *const *)b;
    int c = eng_key_cmp(ma->key, ma->key_len, mb->key, mb->key_len);
    if (c) return c;
    /* Newest first within a key. Equal (key, seq) cannot come from one
     * codec-validated node, but a hostile pool can stage the pair
     * across LEVELS — the tie must compare consistently or the qsort
     * is UB (R173 F5); dedupe then keeps whichever sorted first. */
    if (ma->seq != mb->seq) return (ma->seq > mb->seq) ? -1 : 1;
    return 0;
}

/*
 * Fold `node`'s buffered messages into the inherited window: clip to
 * [lo, hi] when bounded, dedupe to max-seq per key, and merge with
 * the (already unique-keyed) inherited entries — newest seq wins on a
 * key collision. *out gets a fresh array the caller frees; the
 * inherited window is never modified.
 */
static stm_status overlay_merge(const eng_node *node, bool bounded,
                                const void *lo, size_t lo_len,
                                const void *hi, size_t hi_len,
                                const eng_msg **win, uint32_t win_n,
                                const eng_msg ***out, uint32_t *out_n)
{
    const eng_msg **own = malloc((size_t)node->buf_count * sizeof *own);
    if (!own) return STM_ENOMEM;
    uint32_t on = 0;
    for (uint32_t i = 0; i < node->buf_count; i++) {
        const eng_msg *m = &node->buf_msgs[i];
        if (bounded &&
            (eng_key_cmp(m->key, m->key_len, lo, lo_len) < 0 ||
             eng_key_cmp(m->key, m->key_len, hi, hi_len) > 0))
            continue;
        own[on++] = m;
    }
    qsort(own, on, sizeof *own, msg_key_seq_cmp);
    uint32_t dn = 0;                       /* keep first per key = max seq */
    for (uint32_t i = 0; i < on; i++) {
        if (dn && eng_key_cmp(own[i]->key, own[i]->key_len,
                              own[dn - 1u]->key, own[dn - 1u]->key_len) == 0)
            continue;
        own[dn++] = own[i];
    }
    on = dn;

    /* Everything clipped out and nothing inherited — malloc(0) may
     * legally return NULL, which must not read as ENOMEM. */
    if (on + win_n == 0) {
        free(own);
        *out   = NULL;
        *out_n = 0;
        return STM_OK;
    }

    const eng_msg **mg = malloc(((size_t)on + win_n) * sizeof *mg);
    if (!mg) { free(own); return STM_ENOMEM; }
    uint32_t n = 0, a = 0, b = 0;
    while (a < on && b < win_n) {
        int c = eng_key_cmp(own[a]->key, own[a]->key_len,
                            win[b]->key, win[b]->key_len);
        if (c < 0)      mg[n++] = own[a++];
        else if (c > 0) mg[n++] = win[b++];
        else {
            /* Same key at two levels — newest wins. (An inherited
             * message is an ancestor's, strictly newer than any of
             * node's for that key; the seq comparison encodes that
             * without leaning on it.) */
            mg[n++] = (own[a]->seq > win[b]->seq) ? own[a] : win[b];
            a++; b++;
        }
    }
    while (a < on)    mg[n++] = own[a++];
    while (b < win_n) mg[n++] = win[b++];
    free(own);
    *out   = mg;
    *out_n = n;
    return STM_OK;
}

/*
 * Merge-emit a leaf's in-range entries with its overlay window. Both
 * sequences ascend by key; on a key match the overlay wins (a stored
 * entry predates every buffered message above it).
 */
static stm_status leaf_merge_emit(const eng_node *leaf, bool concurrent,
                                  bool bounded,
                                  const void *lo, size_t lo_len,
                                  const void *hi, size_t hi_len,
                                  const eng_msg **win, uint32_t win_n,
                                  stm_btree_engine_iter_cb cb, void *ctx,
                                  bool *stopped)
{
    uint32_t ei = 0;
    if (bounded) {
        bool dummy = false;
        ei = eng_leaf_lower_bound(leaf, lo, lo_len, &dummy);
    }
    uint32_t wi = 0;
    for (;;) {
        const eng_entry *e = (ei < leaf->n_entries) ? &leaf->entries[ei]
                                                    : NULL;
        if (e && bounded &&
            eng_key_cmp(e->key, e->key_len, hi, hi_len) > 0)
            e = NULL;                      /* sorted leaf — past hi */
        const eng_msg *m = (wi < win_n) ? win[wi] : NULL;
        if (!e && !m) break;

        int c;
        if (!e)      c = 1;                /* window only */
        else if (!m) c = -1;               /* entry only */
        else c = eng_key_cmp(e->key, e->key_len, m->key, m->key_len);

        if (c < 0) {
            /* CF-2d injection: land STM_EBUSY mid-emission on the
             * concurrent walk (the caller's ctx is partially filled
             * — exactly the mid-walk-seal shape). Never on the
             * serial walk (serial_mu excludes sealers; the serial
             * scan MUST NOT EBUSY). */
            if (concurrent && eng_test_busy_fire()) return STM_EBUSY;
            if (cb(e->key, e->key_len, e->val, e->val_len, ctx) != 0) {
                *stopped = true;
                return STM_OK;
            }
            ei++;
        } else {
            /* The window covers this key (c > 0: introduced; c == 0:
             * overrides the stored entry). A DELETE emits nothing. */
            if (m->op == ENG_DELTA_INSERT) {
                if (concurrent && eng_test_busy_fire()) return STM_EBUSY;
                if (cb(m->key, m->key_len, m->value, m->value_len,
                       ctx) != 0) {
                    *stopped = true;
                    return STM_OK;
                }
            }
            if (c == 0) ei++;
            wi++;
        }
    }
    return STM_OK;
}

/*
 * The unified subtree scan (full when !bounded, [lo, hi] otherwise;
 * both serial and concurrent walks run this body). `win` holds the
 * ancestors' pending messages routed into this subtree, key-sorted
 * and unique per key.
 */
static stm_status scan_subtree(stm_btree_engine *eng, eng_node *node,
                               bool concurrent, bool bounded,
                               const void *lo, size_t lo_len,
                               const void *hi, size_t hi_len,
                               const eng_msg **win, uint32_t win_n,
                               stm_btree_engine_iter_cb cb, void *ctx,
                               uint32_t depth, bool *stopped, bool *stale)
{
    if (depth > ENG_MAX_DEPTH) return STM_ECORRUPT;

    if (node->is_leaf)
        return leaf_merge_emit(node, concurrent, bounded,
                               lo, lo_len, hi, hi_len,
                               win, win_n, cb, ctx, stopped);

    /* Fold this node's buffered messages into the inherited window. */
    const eng_msg **merged   = NULL;
    uint32_t        merged_n = 0;
    stm_status s = STM_OK;
    if (node->buf_count) {
        s = overlay_merge(node, bounded, lo, lo_len, hi, hi_len,
                          win, win_n, &merged, &merged_n);
        if (s != STM_OK) return s;
        win   = merged;
        win_n = merged_n;
    }

    uint32_t c_lo = bounded ? eng_pivot_child_for(node, lo, lo_len) : 0;
    uint32_t c_hi = bounded ? eng_pivot_child_for(node, hi, hi_len)
                            : node->n_pivots;
    uint32_t w = 0;
    for (uint32_t i = c_lo; i <= c_hi; i++) {
        /* The window slice routing to child i — contiguous, since the
         * window is key-sorted and routing is monotone in the key. */
        uint32_t wbeg = w;
        while (w < win_n &&
               eng_pivot_child_for(node, win[w]->key, win[w]->key_len) == i)
            w++;
        eng_node *child = NULL;
        s = load_child(eng, node, i, /*use_cache=*/!concurrent, &child,
                       concurrent ? stale : NULL);
        if (s != STM_OK) break;
        if (concurrent && *stale) break;   /* tombstoned slot — restart */
        s = scan_subtree(eng, child, concurrent, bounded,
                         lo, lo_len, hi, hi_len,
                         win ? win + wbeg : NULL, w - wbeg,
                         cb, ctx, depth + 1u, stopped, stale);
        if (s != STM_OK || *stopped || (concurrent && *stale)) break;
    }
    free(merged);
    return s;
}

/*
 * Snapshot the root's delta chain into a scan window: a key-sorted,
 * per-key-newest array of eng_msg VIEWS aliasing the delta bytes
 * (read-only; the deltas outlive the scan — EBR pin on the concurrent
 * path, serial_mu + the regime contract on the serial path). *store
 * carries the backing msg structs, *win the sorted view pointers;
 * both freed by the caller (free(), never eng_msg_array_free — the
 * bytes are borrowed). A SEALED head sets *sealed. Chain seqs sit
 * strictly above every buffered seq PER KEY — that rests on the
 * _concurrent mutators' per-key caller obligation (R175 F4, see
 * btree_engine.h): seq is fetch_add'd BEFORE the CAS prepend, so
 * mint order can trail prepend order across KEYS, but same-key
 * writers are externally serialized (the subsystem idx->lock in
 * production), so per-key chain seqs stay above folded/buffered
 * seqs and overlay_merge's per-key newest-wins comparisons compose
 * unchanged.
 */
static stm_status chain_window_build(const eng_node *root, bool bounded,
                                     const void *lo, size_t lo_len,
                                     const void *hi, size_t hi_len,
                                     eng_msg **store, const eng_msg ***win,
                                     uint32_t *win_n, bool *sealed)
{
    *store  = NULL;
    *win    = NULL;
    *win_n  = 0;
    *sealed = false;

    eng_delta *head = atomic_load_explicit(&root->chain_head,
                                           memory_order_acquire);
    if (head == ENG_CHAIN_SEALED) {
        *sealed = true;
        return STM_OK;
    }
    if (!head) return STM_OK;

    uint32_t k = 0;
    for (eng_delta *d = head; d; d = d->next) {
        if (k == UINT32_MAX) return STM_ECORRUPT;
        k++;
    }
    eng_msg *st = malloc((size_t)k * sizeof *st);
    const eng_msg **vw = malloc((size_t)k * sizeof *vw);
    if (!st || !vw) { free(st); free(vw); return STM_ENOMEM; }

    uint32_t n = 0;
    for (eng_delta *d = head; d; d = d->next) {
        if (bounded &&
            (eng_key_cmp(d->key, d->key_len, lo, lo_len) < 0 ||
             eng_key_cmp(d->key, d->key_len, hi, hi_len) > 0))
            continue;
        st[n] = (eng_msg){ .op        = (uint8_t)d->op,
                           .seq       = d->seq,
                           .key       = d->key,
                           .key_len   = d->key_len,
                           .value     = d->value,
                           .value_len = d->value_len };
        vw[n] = &st[n];
        n++;
    }
    qsort(vw, n, sizeof *vw, msg_key_seq_cmp);
    uint32_t dn = 0;                       /* keep first per key = max seq */
    for (uint32_t i = 0; i < n; i++) {
        if (dn && eng_key_cmp(vw[i]->key, vw[i]->key_len,
                              vw[dn - 1u]->key, vw[dn - 1u]->key_len) == 0)
            continue;
        vw[dn++] = vw[i];
    }
    *store = st;
    *win   = vw;
    *win_n = dn;
    return STM_OK;
}

/*
 * One whole-tree merged scan attempt from `root`: chain window +
 * subtree walk. A SEALED chain observed at the window build — BEFORE
 * any callback fired — sets *restart (safe to re-run against the
 * fresh mvcc_root). A tombstoned slot observed MID-WALK cannot
 * restart silently (callbacks already fired; a re-run would emit
 * duplicates) — it surfaces STM_EBUSY, and the caller's transient-
 * retry discipline (the fs-layer R171 P1-1 fallback shape) re-drives
 * the whole op. Both are seal-window-transient; production serial
 * callers can see neither (the exclusion contracts).
 */
static stm_status scan_tree(stm_btree_engine *eng, eng_node *root,
                            bool concurrent, bool bounded,
                            const void *lo, size_t lo_len,
                            const void *hi, size_t hi_len,
                            stm_btree_engine_iter_cb cb, void *ctx,
                            bool *restart)
{
    eng_msg        *store = NULL;
    const eng_msg **win   = NULL;
    uint32_t        win_n = 0;
    bool            sealed = false, stale = false, stopped = false;

    *restart = false;
    stm_status s = chain_window_build(root, bounded, lo, lo_len, hi, hi_len,
                                      &store, &win, &win_n, &sealed);
    if (s != STM_OK) return s;
    if (sealed) { *restart = true; return STM_OK; }

    s = scan_subtree(eng, root, concurrent, bounded, lo, lo_len, hi, hi_len,
                     win, win_n, cb, ctx, 0, &stopped, &stale);
    free(store);
    free(win);
    if (s == STM_OK && stale) return STM_EBUSY;
    return s;
}

static stm_status engine_scan_locked(stm_btree_engine *eng,
                                  stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng || !cb) return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;
    eng_node *root = NULL;
    stm_status s = load_root_locked(eng, &root);
    if (s != STM_OK) return s;
    bool restart = false;
    s = scan_tree(eng, root, /*concurrent=*/false, /*bounded=*/false,
                  NULL, 0, NULL, 0, cb, ctx, &restart);
    if (s == STM_OK && restart) return STM_EBUSY;   /* misuse — see lookup */
    return s;
}

stm_status stm_btree_engine_scan(stm_btree_engine *eng,
                                 stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_scan_locked(eng, cb, ctx);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

static stm_status engine_scan_range_locked(stm_btree_engine *eng,
                                        const void *lo_key, size_t lo_key_len,
                                        const void *hi_key, size_t hi_key_len,
                                        stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng || !cb)            return STM_EINVAL;
    if (lo_key_len && !lo_key)  return STM_EINVAL;
    if (hi_key_len && !hi_key)  return STM_EINVAL;
    if (eng->pending.active)    return STM_EBUSY;

    eng_node *root = NULL;
    stm_status s = load_root_locked(eng, &root);
    if (s != STM_OK) return s;
    bool restart = false;
    s = scan_tree(eng, root, /*concurrent=*/false, /*bounded=*/true,
                  lo_key, lo_key_len, hi_key, hi_key_len, cb, ctx, &restart);
    if (s == STM_OK && restart) return STM_EBUSY;   /* misuse — see lookup */
    return s;
}

stm_status stm_btree_engine_scan_range(stm_btree_engine *eng,
                                       const void *lo_key, size_t lo_key_len,
                                       const void *hi_key, size_t hi_key_len,
                                       stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_scan_range_locked(eng, lo_key, lo_key_len,
                                            hi_key, hi_key_len, cb, ctx);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}

/* 9.8-LF-3b: concurrent (EBR-pinned) range scan.
 *
 * Sibling of stm_btree_engine_lookup_concurrent — same slow-warm shape
 * (mvcc_root acquire-load + double-checked load_root under commit_mu)
 * and same LF-2 preconditions (no concurrent writer / commit_abort,
 * cache-warmed working set). The chain walk at every node is currently
 * a no-op (chain always empty at LF-2); the body is the shared
 * scan_subtree — buffered messages merge (chunk 8), and 9.8-BE-prepend
 * plugs delta-application in without rewriting callers. */
stm_status stm_btree_engine_scan_range_concurrent(stm_btree_engine *eng,
                                                   stm_ebr_thread *ebr,
                                                   const void *lo_key, size_t lo_key_len,
                                                   const void *hi_key, size_t hi_key_len,
                                                   stm_btree_engine_iter_cb cb, void *ctx)
{
    if (!eng || !ebr || !cb)    return STM_EINVAL;
    if (lo_key_len && !lo_key)  return STM_EINVAL;
    if (hi_key_len && !hi_key)  return STM_EINVAL;
    /* `ebr` value is documentation at LF-3b: caller's pre-`enter`
     * keeps every node we touch alive (per the EBR contract). */
    (void)ebr;

    /* Acquire-load the published root (slow-warm under commit_mu via
     * concurrent_root); merged view = chain window + buffers + base.
     * A seal observed BEFORE any callback restarts against the fresh
     * root; a mid-walk tombstone surfaces STM_EBUSY (see scan_tree —
     * duplicate emission is worse than a transient retry). */
    for (uint32_t attempt = 0; attempt < ENG_SEAL_RETRY_MAX; attempt++) {
        eng_node *root = NULL;
        stm_status s = concurrent_root(eng, &root);
        if (s != STM_OK) return s;
        bool restart = false;
        s = scan_tree(eng, root, /*concurrent=*/true, /*bounded=*/true,
                      lo_key, lo_key_len, hi_key, hi_key_len,
                      cb, ctx, &restart);
        if (s != STM_OK || !restart) return s;
        if ((attempt + 1u) % ENG_SEAL_YIELD_EVERY == 0u)
            sched_yield();
    }
    return STM_EBUSY;                      /* see ENG_SEAL_RETRY_MAX */
}

static int count_cb(const void *k, size_t kl, const void *v, size_t vl,
                     void *ctx)
{
    (void)k; (void)kl; (void)v; (void)vl;
    (*(uint64_t *)ctx)++;
    return 0;
}

static stm_status engine_stats_get_locked(stm_btree_engine *eng,
                                       stm_btree_engine_stats *out)
{
    if (!eng || !out) return STM_EINVAL;
    if (eng->pending.active) return STM_EBUSY;

    /* Snapshot the node-I/O counters BEFORE the walk below, so the
     * getter's own load_root/load_child/scan reads do not count into
     * the node_reads it returns (chunk 11). */
    out->node_writes      = atomic_load_explicit(&eng->stat_node_writes,
                                                 memory_order_relaxed);
    out->node_leaf_writes = atomic_load_explicit(&eng->stat_node_leaf_writes,
                                                 memory_order_relaxed);
    out->node_reads       = atomic_load_explicit(&eng->stat_node_reads,
                                                 memory_order_relaxed);

    eng_node *root = NULL;
    stm_status s = load_root_locked(eng, &root);
    if (s != STM_OK) return s;

    /* Height — descend the leftmost spine. */
    uint32_t height = 1;
    eng_node *node = root;
    while (!node->is_leaf) {
        if (height > ENG_MAX_DEPTH) return STM_ECORRUPT;
        s = load_child(eng, node, 0, /*use_cache=*/true, &node, NULL);
        if (s != STM_OK) return s;
        height++;
    }

    /* Key count — full scan (buffer-merged: counts the logical view,
     * so a buffered INSERT counts and a buffered DELETE does not). */
    uint64_t n_keys = 0;
    bool restart = false;
    s = scan_tree(eng, root, /*concurrent=*/false, /*bounded=*/false,
                  NULL, 0, NULL, 0, count_cb, &n_keys, &restart);
    if (s == STM_OK && restart) return STM_EBUSY;   /* misuse — see lookup */
    if (s != STM_OK) return s;

    out->n_keys = n_keys;
    out->height = height;
    return STM_OK;
}

stm_status stm_btree_engine_stats_get(stm_btree_engine *eng,
                                      stm_btree_engine_stats *out)
{
    if (!eng) return STM_EINVAL;
    pthread_mutex_lock(&eng->serial_mu);
    stm_status s = engine_stats_get_locked(eng, out);
    pthread_mutex_unlock(&eng->serial_mu);
    return s;
}
