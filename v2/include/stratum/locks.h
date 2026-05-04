/* SPDX-License-Identifier: ISC */
/*
 * Stratum v2 — advisory lock table (P8-POSIX-7d).
 *
 * Models Linux flock(2) + fcntl(2) F_SETLK / F_GETLK / F_OFD_SETLK
 * advisory-lock semantics. The table is per-fs, in-RAM only —
 * advisory locks don't persist across mount (POSIX behavior:
 * fcntl + flock locks are released by close, and a fresh mount
 * has no fds).
 *
 * Spec: v2/specs/locks.tla. The HEADLINE invariant is
 * `NoConflictingLocks` — two locks conflict iff (a) overlapping
 * byte ranges in the same inode, AND (b) different owners, AND
 * (c) at least one is EXCLUSIVE. The lock-acquire path enforces
 * this via the conflict check before insertion.
 *
 * MVP scope: NON-BLOCKING only (Linux F_SETLK shape). Returns
 * STM_EAGAIN on conflict. Blocking F_SETLKW + the deadlock-
 * detection wait-graph are deferred to a future sub-chunk.
 */
#ifndef STRATUM_V2_LOCKS_H
#define STRATUM_V2_LOCKS_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Lock-type discriminator. */
#define STM_LOCK_SHARED    0u
#define STM_LOCK_EXCLUSIVE 1u

struct stm_lock_table;
typedef struct stm_lock_table stm_lock_table;

/* Lifecycle. The fs creates one table at mount and frees it at
 * unmount. Returns NULL on STM_ENOMEM. */
stm_lock_table *stm_lock_table_create(void);
void stm_lock_table_close(stm_lock_table *t);

/*
 * Acquire a lock. Non-blocking — returns STM_EAGAIN if any
 * existing lock at (dataset_id, ino) overlapping [off, off+len)
 * conflicts (different owner + at-least-one-exclusive).
 *
 * Same-owner re-lock: ALWAYS admitted (POSIX permits an owner to
 * upgrade/downgrade/stack its own locks; this MVP doesn't merge
 * or split records — each Acquire adds a discrete record).
 *
 * `len = 0` means "to EOF" — internally normalized to UINT64_MAX
 * - off so range arithmetic is uniform. Linux fcntl(2) treats
 * len=0 the same way.
 *
 * Refusals:
 *   - NULL t (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 (STM_EINVAL).
 *   - owner_id == 0 (STM_EINVAL — reserved as "no owner").
 *   - type not in {STM_LOCK_SHARED, STM_LOCK_EXCLUSIVE}
 *     (STM_EINVAL).
 *   - off + len overflows uint64_t when len != 0 (STM_EOVERFLOW).
 *   - STM_ENOMEM if the records[] buffer can't grow.
 *   - Conflicting lock present → STM_EAGAIN.
 */
STM_MUST_USE
stm_status stm_lock_acquire(stm_lock_table *t,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t owner_id, uint8_t type,
                                  uint64_t off, uint64_t len);

/*
 * Release locks held by `owner_id` at (dataset_id, ino) matching
 * EXACTLY (off, len). MVP: exact-match only — caller must release
 * with the same range it acquired. Idempotent: returns STM_OK
 * even if no matching lock exists.
 *
 * Refusals:
 *   - NULL t (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 OR owner_id == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_lock_release(stm_lock_table *t,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t owner_id,
                                  uint64_t off, uint64_t len);

/*
 * Test whether an acquire WOULD succeed without modifying the
 * table — F_GETLK shape. On STM_OK, `*out_would_grant = true`
 * means acquire would succeed; `false` means a conflict exists.
 * If `out_conflicting_owner` is non-NULL AND the result is
 * "would not grant", populates with the conflicting owner's id
 * (any one of them; non-deterministic if multiple).
 */
STM_MUST_USE
stm_status stm_lock_test(const stm_lock_table *t,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t owner_id, uint8_t type,
                              uint64_t off, uint64_t len,
                              bool *out_would_grant,
                              uint64_t *out_conflicting_owner);

/*
 * Release every lock held by `owner_id` across all inodes — the
 * post-close cleanup pattern. Linux releases all OFD locks tied
 * to a closing fd; bindings call this on fd-close.
 *
 * Refusals:
 *   - NULL t (STM_EINVAL).
 *   - owner_id == 0 (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_lock_release_owner(stm_lock_table *t, uint64_t owner_id);

/*
 * Diagnostic: count the number of currently-held locks. Pure
 * read; safe under concurrent writers (locks the table for the
 * duration). Used by tests + admin tools.
 */
STM_MUST_USE
stm_status stm_lock_count(const stm_lock_table *t, size_t *out_count);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_LOCKS_H */
