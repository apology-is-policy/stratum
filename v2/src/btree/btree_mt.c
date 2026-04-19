/* SPDX-License-Identifier: ISC */
/*
 * Concurrent Bε-tree — Phase 2 fallback implementation.
 *
 * Strategy: tree-wide pthread_rwlock_t. Readers (lookup, scan) take a
 * shared lock; mutators (insert, delete) take exclusive. Scan's
 * flush-all-before-walk step is a MUTATION in the single-threaded tree,
 * so stm_btree_mt_scan must hold the exclusive lock. We accept the
 * throughput hit at Phase 2 — this is explicitly the fallback per
 * ARCHITECTURE §3.8, chosen for correctness over performance.
 *
 * A future pass will either:
 *   (a) move to per-node rwlock coupling (ARCH §3.8's stated design),
 *       giving readers true parallelism; or
 *   (b) ship the lock-free Bw-tree delta-chain path (§3.4) which is the
 *       default runtime. Both paths will coexist behind a compile flag.
 *
 * Thread model:
 *   - Registration-free: any thread can call any op. The rwlock itself is
 *     the coordination point. EBR is not involved because we don't
 *     retire-and-reclaim at this layer.
 */
#include <stratum/btree.h>

#include <pthread.h>
#include <stdlib.h>

struct stm_btree_mt {
    stm_btree        *inner;
    pthread_rwlock_t  lock;
};

stm_status stm_btree_mt_new(const stm_btree_opts *opts, stm_btree_mt **out)
{
    if (!out) return STM_EINVAL;
    stm_btree_mt *t = calloc(1, sizeof *t);
    if (!t) return STM_ENOMEM;

    stm_status s = stm_btree_new(opts, &t->inner);
    if (s != STM_OK) { free(t); return s; }

    if (pthread_rwlock_init(&t->lock, NULL) != 0) {
        stm_btree_free(t->inner);
        free(t);
        return STM_EBACKEND;
    }

    *out = t;
    return STM_OK;
}

void stm_btree_mt_free(stm_btree_mt *t)
{
    if (!t) return;
    pthread_rwlock_destroy(&t->lock);
    stm_btree_free(t->inner);
    free(t);
}

stm_status stm_btree_mt_insert(stm_btree_mt *t,
                               const void *key, size_t key_len,
                               const void *value, size_t value_len)
{
    if (!t) return STM_EINVAL;
    pthread_rwlock_wrlock(&t->lock);
    stm_status s = stm_btree_insert(t->inner, key, key_len, value, value_len);
    pthread_rwlock_unlock(&t->lock);
    return s;
}

stm_status stm_btree_mt_lookup(stm_btree_mt *t,
                               const void *key, size_t key_len,
                               void *buf, size_t buf_cap,
                               size_t *out_value_len)
{
    if (!t) return STM_EINVAL;
    pthread_rwlock_rdlock(&t->lock);
    stm_status s = stm_btree_lookup(t->inner, key, key_len,
                                     buf, buf_cap, out_value_len);
    pthread_rwlock_unlock(&t->lock);
    return s;
}

stm_status stm_btree_mt_delete(stm_btree_mt *t,
                               const void *key, size_t key_len)
{
    if (!t) return STM_EINVAL;
    pthread_rwlock_wrlock(&t->lock);
    stm_status s = stm_btree_delete(t->inner, key, key_len);
    pthread_rwlock_unlock(&t->lock);
    return s;
}

stm_status stm_btree_mt_scan(stm_btree_mt *t,
                             const void *lo_key, size_t lo_key_len,
                             const void *hi_key, size_t hi_key_len,
                             stm_btree_scan_cb cb, void *ctx)
{
    if (!t) return STM_EINVAL;
    /* Scan flush-all mutates, so take exclusive lock. */
    pthread_rwlock_wrlock(&t->lock);
    stm_status s = stm_btree_scan(t->inner, lo_key, lo_key_len,
                                   hi_key, hi_key_len, cb, ctx);
    pthread_rwlock_unlock(&t->lock);
    return s;
}
