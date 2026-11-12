/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Stratum v2 — advisory lock table (P8-POSIX-7d).
 *
 * Models Linux flock(2) + fcntl(2) F_SETLK / F_GETLK / F_OFD_SETLK
 * advisory-lock semantics. The table is per-fs, in-RAM only —
 * advisory locks don't persist across mount (POSIX behavior:
 * fcntl + flock locks are released by close, and a fresh mount
 * has no fds).
 *
 * Spec: specs/locks.tla. The HEADLINE invariant is
 * `NoConflictingLocks` — two locks conflict iff (a) overlapping
 * byte ranges in the same inode, AND (b) different owners, AND
 * (c) at least one is EXCLUSIVE. The lock-acquire path enforces
 * this via the conflict check before insertion.
 *
 * Ranges follow POSIX: an owner's request replaces what that owner held
 * over its range (upgrade, downgrade, split), a release trims and splits,
 * and an owner's records on one file never overlap.
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

/* Bounds on the table, so no client can grow the server's memory without
 * limit: per owner (one fid), per client (an identity the caller names, so
 * that one identity cannot spend everyone's share of the table), and in all.
 * A request that would pass any of them answers STM_ENOLCK and changes
 * nothing. */
#define STM_LOCK_MAX_PER_OWNER  256u
#define STM_LOCK_MAX_PER_CLIENT 4096u
#define STM_LOCK_MAX_RECORDS    65536u

struct stm_lock_table;
typedef struct stm_lock_table stm_lock_table;

/* A conflicting lock as stm_lock_test reports it: its owner, type and
 * range [off, end), end UINT64_MAX meaning to EOF. */
typedef struct {
    uint64_t owner_id;
    uint8_t  type;
    uint64_t off;
    uint64_t end;
} stm_lock_conflict;

/* Lifecycle. The fs creates one table at mount and frees it at
 * unmount. Returns NULL on STM_ENOMEM. */
stm_lock_table *stm_lock_table_create(void);
void stm_lock_table_close(stm_lock_table *t);

/*
 * Acquire a lock. Non-blocking — returns STM_EAGAIN if any
 * existing lock at (dataset_id, ino, gen) overlapping [off, off+len)
 * conflicts (different owner + at-least-one-exclusive). `gen` is the
 * inode incarnation (si_gen) locked: records on another incarnation of
 * the same ino never conflict, so a freed file's locks cannot refuse
 * the file that reuses its number.
 *
 * Same-owner re-lock: never a conflict. The request replaces what the
 * owner held over [off, off+len) atomically (POSIX upgrade, downgrade
 * and split), and a record of the same type that overlaps or abuts it
 * merges into one. A refusal leaves the owner's locks as they were.
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
 *   - STM_ENOLCK past STM_LOCK_MAX_PER_OWNER or STM_LOCK_MAX_RECORDS.
 *   - Conflicting lock present → STM_EAGAIN.
 */
STM_MUST_USE
stm_status stm_lock_acquire(stm_lock_table *t,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t gen,
                                  uint64_t owner_id, uint8_t type,
                                  uint64_t off, uint64_t len);

/*
 * stm_lock_acquire on behalf of `client`, whose records count against
 * STM_LOCK_MAX_PER_CLIENT. 0 names no client and counts against nothing.
 * Every record this request writes is the client's: a piece it splits from
 * another client's record on the same owner included, since the request is
 * what grew the table. Past the bound: STM_ENOLCK, nothing changed.
 */
STM_MUST_USE
stm_status stm_lock_acquire_as(stm_lock_table *t,
                                     uint64_t dataset_id, uint64_t ino,
                                     uint64_t gen,
                                     uint64_t owner_id, uint64_t client,
                                     uint8_t type,
                                     uint64_t off, uint64_t len);

/*
 * Release what `owner_id` holds at (dataset_id, ino) within
 * [off, off+len), on any incarnation: a record inside the range goes,
 * one crossing its edge is trimmed, one spanning it is split in two.
 * Idempotent: returns STM_OK when the owner holds nothing there.
 *
 * Refusals:
 *   - NULL t (STM_EINVAL).
 *   - dataset_id == 0 OR ino == 0 OR owner_id == 0 (STM_EINVAL).
 *   - off + len overflows uint64_t when len != 0 (STM_EOVERFLOW).
 *   - A split past STM_LOCK_MAX_PER_OWNER, STM_LOCK_MAX_RECORDS or, for the
 *     client of the record it splits, STM_LOCK_MAX_PER_CLIENT (STM_ENOLCK,
 *     nothing released), or STM_ENOMEM.
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
 * If `out_conflict` is non-NULL AND the result is "would not grant",
 * it gets the first conflicting record: owner, type and range.
 */
STM_MUST_USE
stm_status stm_lock_test(const stm_lock_table *t,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t gen,
                              uint64_t owner_id, uint8_t type,
                              uint64_t off, uint64_t len,
                              bool *out_would_grant,
                              stm_lock_conflict *out_conflict);

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
 * Release every lock on (dataset_id, ino), every incarnation, whoever
 * holds it. The fs calls it as it frees the inode, so the freed
 * incarnation's records go at once rather than when their owners close.
 *
 * Refusals:
 *   - NULL t (STM_EINVAL).
 */
STM_MUST_USE
stm_status stm_lock_release_ino(stm_lock_table *t, uint64_t dataset_id,
                                uint64_t ino);

/*
 * Diagnostic: count the number of currently-held locks. Pure
 * read; safe under concurrent writers (locks the table for the
 * duration). Used by tests + admin tools.
 */
STM_MUST_USE
stm_status stm_lock_count(const stm_lock_table *t, size_t *out_count);

/* One held record, as stm_lock_snapshot copies it out. */
typedef struct {
    uint64_t dataset_id;
    uint64_t ino;
    uint64_t gen;
    uint64_t owner_id;
    uint8_t  type;
    uint64_t off;
    uint64_t end;          /* exclusive; UINT64_MAX = to EOF */
    uint64_t client;       /* whose share it counts against; 0 = no one's */
} stm_lock_record_view;

/*
 * Diagnostic: copy up to `cap` held records into `out` (any order) and
 * set `*out_n` to the number held, which may exceed `cap`. Taken under
 * the table lock, so it is one consistent state. Used by tests.
 */
STM_MUST_USE
stm_status stm_lock_snapshot(const stm_lock_table *t,
                             stm_lock_record_view *out, size_t cap,
                             size_t *out_n);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_LOCKS_H */
