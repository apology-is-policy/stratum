/* SPDX-License-Identifier: ISC */
/*
 * Bε-tree — the metadata data structure.
 *
 * See ARCHITECTURE §3 (concurrency), §6 (allocator interaction), §7.11
 * (Merkle integration). The two-layer model:
 *
 *   1. Pure data-structure layer (this header + src/btree/node*,
 *      src/btree/btree.c). A Bε-tree with message buffers at internal
 *      nodes and sorted entries at leaves. All keys and values are opaque
 *      byte strings. Thread-unsafe; callers in Phase 2 use it single-
 *      threaded to establish correct semantics.
 *
 *   2. Concurrency layer (src/btree/concurrent.c, Phase 2 tail). Adds
 *      Bw-tree-style CAS delta chains, MVCC root snapshotting, and EBR
 *      for safe reclamation. Layered on the single-threaded ops for ease
 *      of proof.
 *
 * On-disk serialization comes in Phase 3 alongside the block-I/O path.
 * This header is about the in-memory contract.
 *
 * ## Keys and values
 *
 * Keys compare lexicographically as unsigned byte strings. No key
 * encoding is imposed at this layer — callers pass bytes. Values are
 * opaque. The tree copies both on insert.
 *
 * Duplicate keys are not allowed: inserting a key that already exists
 * overwrites the old value (UPSERT semantics at the API).
 *
 * ## Messages and buffers (the ε part)
 *
 * Internal nodes carry a small message buffer holding pending
 * operations (insert/delete) destined for children. Inserts append to the
 * root's buffer; when a node's buffer is full, a flush pushes messages
 * into the appropriate children. This amortizes writes across levels
 * (Bender et al. 2007) and is the matching shape for Bw-tree delta
 * chains in the concurrency layer.
 */
#ifndef STRATUM_V2_BTREE_H
#define STRATUM_V2_BTREE_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles. */
typedef struct stm_btree stm_btree;
typedef struct stm_bt_node stm_bt_node;

/* ========================================================================= */
/* Construction                                                               */
/* ========================================================================= */

typedef struct {
    /* Soft target for how many entries a leaf may hold before a split is
     * considered. Internal nodes use the same target for pivot count. */
    uint32_t target_entries;

    /* How many messages an internal node's buffer holds before a flush.
     * Typical: target_entries / 4. */
    uint32_t target_messages;
} stm_btree_opts;

stm_btree_opts stm_btree_opts_default(void);

STM_MUST_USE
stm_status stm_btree_new(const stm_btree_opts *opts, stm_btree **out);

void stm_btree_free(stm_btree *t);

/* ========================================================================= */
/* Basic ops (Phase 2 — single-threaded).                                     */
/* ========================================================================= */

/*
 * Upsert: if the key exists, its value is replaced.
 */
STM_MUST_USE
stm_status stm_btree_insert(stm_btree *t,
                            const void *key, size_t key_len,
                            const void *value, size_t value_len);

/*
 * Lookup: if the key exists, writes its value into the caller-allocated
 * buffer (up to buf_cap bytes) and sets *out_value_len to the full value
 * length. Returns STM_ENOENT if the key does not exist. If buf_cap is 0
 * or buf is NULL, only the length is populated.
 *
 * Truncation semantics: if value_len > buf_cap, STM_ERANGE is returned
 * and *out_value_len reflects the required length.
 */
STM_MUST_USE
stm_status stm_btree_lookup(const stm_btree *t,
                            const void *key, size_t key_len,
                            void *buf, size_t buf_cap,
                            size_t *out_value_len);

/*
 * Delete: removes the key if present. Returns STM_ENOENT if absent.
 */
STM_MUST_USE
stm_status stm_btree_delete(stm_btree *t,
                            const void *key, size_t key_len);

/*
 * Scan: iterate keys in [lo, hi) in ascending order. Callback returns
 * zero to continue, nonzero to stop early. The key/value pointers handed
 * to the callback are valid only for the duration of the call.
 */
typedef int (*stm_btree_scan_cb)(const void *key, size_t key_len,
                                  const void *value, size_t value_len,
                                  void *ctx);

STM_MUST_USE
stm_status stm_btree_scan(const stm_btree *t,
                          const void *lo_key, size_t lo_key_len,
                          const void *hi_key, size_t hi_key_len,
                          stm_btree_scan_cb cb, void *ctx);

/* ========================================================================= */
/* Observability                                                              */
/* ========================================================================= */

typedef struct {
    uint64_t n_entries;          /* total live keys */
    uint64_t n_nodes;            /* total nodes (leaves + internal) */
    uint64_t n_leaves;
    uint64_t n_messages_buffered;
    uint32_t height;
    uint64_t bytes_keys;
    uint64_t bytes_values;
} stm_btree_stats;

void stm_btree_stats_of(const stm_btree *t, stm_btree_stats *out);

/* ========================================================================= */
/* Concurrent wrapper — Phase 2 fallback                                      */
/* ========================================================================= */

/*
 * A thread-safe wrapper over stm_btree. The fallback per ARCHITECTURE §3.8.
 * At Phase 2 this uses a single tree-wide rwlock — writers exclude everyone,
 * readers share. Per-node lock coupling (the proper §3.8 design) and the
 * lock-free Bw-tree path (§3.4, the default at runtime) are Phase 2-tail
 * work.
 *
 * API mirrors the single-threaded API with "_mt" suffix. Internally
 * delegates to stm_btree_*.
 */
typedef struct stm_btree_mt stm_btree_mt;

STM_MUST_USE
stm_status stm_btree_mt_new(const stm_btree_opts *opts, stm_btree_mt **out);

void stm_btree_mt_free(stm_btree_mt *t);

STM_MUST_USE
stm_status stm_btree_mt_insert(stm_btree_mt *t,
                               const void *key, size_t key_len,
                               const void *value, size_t value_len);

STM_MUST_USE
stm_status stm_btree_mt_lookup(stm_btree_mt *t,
                               const void *key, size_t key_len,
                               void *buf, size_t buf_cap,
                               size_t *out_value_len);

STM_MUST_USE
stm_status stm_btree_mt_delete(stm_btree_mt *t,
                               const void *key, size_t key_len);

STM_MUST_USE
stm_status stm_btree_mt_scan(stm_btree_mt *t,
                             const void *lo_key, size_t lo_key_len,
                             const void *hi_key, size_t hi_key_len,
                             stm_btree_scan_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_BTREE_H */
