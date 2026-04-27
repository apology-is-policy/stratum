/* SPDX-License-Identifier: ISC */
/*
 * Repair-log sub-tree (Phase 7 chunk P7-15, ARCH §7.15.4).
 *
 *   see ARCHITECTURE §7.15.4 for the design intent — every scrub-
 *   driven replica rewrite emits a log entry (timestamp, paddr,
 *   corruption type, redundancy source, verification result) so
 *   admins can review repair activity and infer imminent hardware
 *   failure.
 *   see v2/specs/bptr.tla `LogIntegrity` invariant for the formal
 *   shape: "every emitted log entry corresponds to a rewrite that
 *   actually landed and carries the picked source's index."
 *
 * What this module does:
 *
 *   - Persists an append-only log of repair events to a single-leaf
 *     btnode rooted at `ub_repair_log_root`. Plaintext + Merkle-
 *     covered (the bptr's bp_csum is the btnode self-csum); same
 *     shape as the keyschema sub-tree.
 *   - Allocates a monotonic `seq_id` per emit. Entries never
 *     mutate or delete (audit-trail semantics); growth is bounded
 *     only by the single-leaf payload until a future multi-leaf
 *     graduation (matches keyschema's MVP).
 *   - Composes with sync_commit's idempotent retry: a clean (no
 *     emit since last commit) repair-log returns the cached
 *     (root_paddr, root_csum) without re-persisting, preserving
 *     quorum.tla::ContentQuorumAtGen across STM_EQUORUM retries.
 *
 * Lifecycle (mirrors stm_keyschema):
 *
 *   stm_repair_log_index_create(d, boot, &rl)
 *       Fresh-pool handle. Empty in-RAM state.
 *
 *   stm_repair_log_index_open(d, boot, &rl)
 *       Re-open handle; call `_load_at` afterwards to hydrate.
 *
 *   stm_repair_log_index_load_at(rl, root_paddr, expected_csum,
 *                                  starting_seq_id)
 *       Read the durable node + verify Merkle + decode entries.
 *       `starting_seq_id` (from `ub_repair_log_next_seq`) seeds
 *       the in-RAM seq counter so the next emit picks up where
 *       the previous mount left off without re-reading every entry
 *       to derive the max.
 *
 *   stm_repair_log_index_emit(rl, entry, &out_seq_id)
 *       Append an entry; assigns seq_id; persists on next commit.
 *
 *   stm_repair_log_index_commit(rl, committed_gen,
 *                                 &out_paddr, &out_csum,
 *                                 &out_next_seq)
 *       Serialize current state + return the new root paddr +
 *       bp_csum + next_seq. Caller plumbs into the uberblock.
 */
#ifndef STRATUM_V2_REPAIR_LOG_H
#define STRATUM_V2_REPAIR_LOG_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev       stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap  stm_bootstrap;

typedef struct stm_repair_log_index stm_repair_log_index;

/*
 * Type of corruption detected on the target replica that prompted
 * the rewrite. Maps to bptr.tla's `read_outcome` set, restricted
 * to the rewriting-eligible cases.
 */
typedef enum {
    STM_REPAIR_TYPE_NONE      = 0,
    STM_REPAIR_TYPE_CSUM_FAIL = 1,   /* AEAD/csum mismatch */
    STM_REPAIR_TYPE_IO_ERR    = 2,   /* bdev I/O error */
} stm_repair_type;

/*
 * Outcome of the rewrite + verify cycle. Maps to bptr.tla's
 * `rewrite_outcome` set.
 */
typedef enum {
    STM_REPAIR_RESULT_NONE        = 0,
    STM_REPAIR_RESULT_OK_VERIFIED = 1,   /* rewrite landed + verified */
    STM_REPAIR_RESULT_FAIL        = 2,   /* writeback failed verify */
} stm_repair_result;

/*
 * One logged repair event. `seq_id` is assigned by the index at
 * emit time (monotonic, never recycled — preserves audit-trail
 * semantics across rotations).
 */
typedef struct {
    uint64_t          seq_id;
    uint64_t          timestamp_ns;        /* CLOCK_REALTIME at emit */
    uint64_t          target_paddr;        /* the rewritten paddr */
    uint64_t          source_paddr;        /* the source replica's paddr */
    uint8_t           target_replica_idx;  /* index in extent's replicas[] */
    uint8_t           source_replica_idx;
    stm_repair_type   type;                /* u8 on disk */
    stm_repair_result result;              /* u8 on disk */
    uint8_t           reserved[4];         /* zero on emit; ignored on load */
} stm_repair_log_entry;

/* On-disk value length per entry: 8-byte key + 32-byte value =
 * 40 bytes encoded. */
#define STM_REPAIR_LOG_VAL_LEN  32u

/* R47 P3-1 — single-leaf MVP cap, enforced at emit time. The
 * btnode payload max is ~131 KiB; per-entry encoding overhead
 * (length prefixes + per-entry framing) varies, so the cap below
 * is a conservative bound that leaves headroom. Once exceeded,
 * `stm_repair_log_index_emit` returns STM_ERANGE rather than
 * letting `_commit` fail at sync-flush time and wedging every
 * subsequent commit (data writes, dataset/snapshot mutations,
 * scrub progress) until the operator drains the in-RAM list —
 * which the API has no path to do today (append-only, by
 * design). The scrub β cb's emit is best-effort and silently
 * absorbs the STM_ERANGE; only the audit-trail entry is lost,
 * the repair itself still lands.
 *
 * Multi-leaf graduation is future work; matches keyschema MVP. */
#define STM_REPAIR_LOG_MAX_ENTRIES  2048u

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

STM_MUST_USE
stm_status stm_repair_log_index_create(stm_bdev *d, stm_bootstrap *boot,
                                         stm_repair_log_index **out_rl);

STM_MUST_USE
stm_status stm_repair_log_index_open(stm_bdev *d, stm_bootstrap *boot,
                                       stm_repair_log_index **out_rl);

void stm_repair_log_index_close(stm_repair_log_index *rl);

/* ========================================================================= */
/* Persistence.                                                               */
/* ========================================================================= */

/*
 * Read the durable repair-log root, verify its Merkle link
 * (`expected_csum` matches the stored bp_csum), decode entries
 * into the in-RAM list. `root_paddr == 0` is a no-op (fresh pool;
 * leaves the index empty).
 *
 * `starting_seq_id` seeds the next-seq counter from the persisted
 * `ub_repair_log_next_seq` so post-mount emits monotonically
 * continue from the durable view (rather than restarting from 0,
 * which would let new entries collide with persisted seq_ids).
 *
 * STM_ECORRUPT on Merkle / decode failure.
 */
STM_MUST_USE
stm_status stm_repair_log_index_load_at(stm_repair_log_index *rl,
                                          uint64_t root_paddr,
                                          const uint8_t expected_csum[32],
                                          uint64_t starting_seq_id);

/*
 * Serialize the current state to a fresh single-leaf node, write
 * via the bootstrap pool, free the previous node (if any) at
 * `committed_gen`, and return the new root paddr + bp_csum + the
 * persisted next_seq counter.
 *
 * Idempotent retry: a clean repair-log (no emit since last
 * commit) short-circuits to the cached (root_paddr, root_csum,
 * next_seq) — preserves quorum.tla::ContentQuorumAtGen across
 * STM_EQUORUM retries (R14b P2-1 pattern).
 *
 * Always emits one node even on an empty index so callers always
 * have a valid bptr in the uberblock.
 *
 * STM_ERANGE if entries exceed single-leaf capacity (multi-leaf
 * graduation deferred).
 */
STM_MUST_USE
stm_status stm_repair_log_index_commit(stm_repair_log_index *rl,
                                         uint64_t committed_gen,
                                         uint64_t *out_root_paddr,
                                         uint8_t out_root_csum[32],
                                         uint64_t *out_next_seq);

/*
 * Last-committed root paddr + csum. Both zero before any commit.
 */
STM_MUST_USE
stm_status stm_repair_log_index_get_root(const stm_repair_log_index *rl,
                                           uint64_t *out_root_paddr,
                                           uint8_t out_root_csum[32]);

/* ========================================================================= */
/* Entry append + read.                                                       */
/* ========================================================================= */

/*
 * Append `entry` to the in-RAM list. The index assigns a
 * monotonic seq_id (returned via `*out_seq_id`); callers should
 * leave `entry->seq_id` at zero — any pre-set value is overwritten.
 *
 * Validation: `type` and `result` must be in their enum range
 * (else STM_EINVAL). target_replica_idx and source_replica_idx
 * must differ (per bptr.tla's LogIntegrity); equal indices are
 * STM_EINVAL — a rewrite never sources from itself.
 *
 * Persists on next commit.
 */
STM_MUST_USE
stm_status stm_repair_log_index_emit(stm_repair_log_index *rl,
                                       const stm_repair_log_entry *entry,
                                       uint64_t *out_seq_id);

/*
 * Number of entries currently in RAM. Test-facing.
 */
size_t stm_repair_log_index_count(const stm_repair_log_index *rl);

/*
 * Iterate every entry in seq_id order. cb returns 0 to continue,
 * non-zero to stop iteration early. The iter return value is
 * STM_OK on success (or STM_EINVAL on bad args); the cb-side
 * state is the only signal of early termination — the iter
 * itself does not propagate the cb's non-zero return code.
 *
 * **R47 P3-4**: the cb runs while the index's internal mutex is
 * held. The cb MUST NOT call back into any other
 * `stm_repair_log_index_*` API on the same handle — the mutex is
 * PTHREAD_MUTEX_ERRORCHECK so re-entry returns EDEADLK rather
 * than self-deadlocking, but the project's `must_lock` /
 * `must_unlock` helpers swallow that silently and the resulting
 * state is undefined. Symmetric with scrub.h's "callback contract"
 * prohibition on cb re-entry into the scrub API.
 */
typedef int (*stm_repair_log_iter_cb)(const stm_repair_log_entry *e, void *ctx);

STM_MUST_USE
stm_status stm_repair_log_index_iter(const stm_repair_log_index *rl,
                                       stm_repair_log_iter_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_REPAIR_LOG_H */
