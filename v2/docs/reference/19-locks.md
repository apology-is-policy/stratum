# 19 — Advisory lock table (P8-POSIX-7d)

## Purpose

Per-fs, in-RAM advisory lock table backing the Linux `flock(2)` + `fcntl(2)`
`F_SETLK` / `F_GETLK` / `F_OFD_SETLK` surface. The table tracks byte-range
locks keyed by `(dataset_id, ino, owner_id, off, len, type)`, with conflict
detection at acquire time. POSIX advisory locks don't persist across mount
(closing the fd releases them; a fresh mount has no fds), so this layer is
deliberately memory-only — no btree, no AEAD, no Merkle binding.

The locks module is the bridge between:

- **fs.c** (`stm_fs_*` byte-range lock wrappers — public API).
- **9P2000.L server** (`Tlock` / `Tgetlock` op handlers in
  `v2/src/9p/server.c`).
- **Per-fd cleanup** at fid clunk / connection detach (the
  `stm_fs_release_lock_owner` path, which composes against the
  `ReleaseOwner` action in `locks.tla`).

Header: `v2/include/stratum/locks.h` (126 lines).
Impl: `v2/src/locks/locks.c` (280 lines).
Spec: `v2/specs/locks.tla`.

## Public API

### Lifecycle

```c
stm_lock_table *stm_lock_table_create (void);
void            stm_lock_table_close  (stm_lock_table *t);
```

`_create` returns an empty table. The fs creates one at mount and frees
it at unmount; lifetime is bounded by the `stm_fs` handle.

### Mutation

```c
stm_status stm_lock_acquire        (t, dataset_id, ino, owner_id,
                                       type, off, len);
stm_status stm_lock_release        (t, dataset_id, ino, owner_id,
                                       off, len);
stm_status stm_lock_release_owner  (t, owner_id);
```

`stm_lock_acquire` is **non-blocking** (Linux `F_SETLK` shape) — returns
`STM_EAGAIN` on conflict. Same-owner re-lock is ALWAYS admitted (POSIX
permits an owner to upgrade/downgrade/stack its own locks; this MVP
doesn't merge or split records — each Acquire adds a discrete record).
`len = 0` means "to EOF" — normalized internally to `UINT64_MAX - off`.

`stm_lock_release` is **exact-match only**: caller must release with the
same `(off, len)` it acquired. Idempotent (returns `STM_OK` if no matching
record exists). MVP scope per `locks.h`: range-aware split/merge on
partial release is deferred.

`stm_lock_release_owner` is the **post-close cleanup** path — releases
EVERY lock held by `owner_id` across all inodes. Linux releases all OFD
locks tied to a closing fd; bindings call this on fd-close.

### Inspection

```c
stm_status stm_lock_test  (t, dataset_id, ino, owner_id, type, off, len,
                                *out_would_grant, *out_conflicting_owner);
stm_status stm_lock_count (t, *out_count);
```

`stm_lock_test` is `F_GETLK` shape — pure read; reports whether an
acquire WOULD succeed without modifying the table. On conflict, populates
`out_conflicting_owner` (any one of them if multiple).

`stm_lock_count` returns the global count of currently-held locks.
Diagnostic; used by tests + admin tools.

## Implementation

### Conflict predicate

Two locks **conflict** iff ALL THREE hold:

1. Overlapping byte ranges in the same `(dataset_id, ino)`.
2. **Different** owners (same-owner is admitted unconditionally).
3. At least one is `STM_LOCK_EXCLUSIVE`.

This is the `NoConflictingLocks` invariant from `locks.tla` — the
headline safety property. The acquire path checks this predicate
against EVERY existing lock at the same `(ds, ino)` before insertion;
a single conflict refuses the acquire.

### Range arithmetic

Lengths normalize to `UINT64_MAX - off` for `len == 0` so range overlap
is uniform across "explicit byte range" + "to EOF" calls. Acquire
refuses `off + len` overflowing `uint64_t` (`STM_EOVERFLOW`) when
`len != 0`, before normalization.

### Storage layout

Single mutex-protected `records` array (heap-grown linear vector).
Linear scan of all records on every acquire / release / test — bounded
acceptable at MVP since the typical workload is dozens of locks per
mount. A future optimization could index by `(dataset_id, ino)` to
short-circuit non-matching scans.

### Caller contracts

- `owner_id == 0` is reserved as "no owner" — refused (`STM_EINVAL`).
- `dataset_id == 0` and `ino == 0` are reserved (`STM_EINVAL`).
- `type` must be `STM_LOCK_SHARED` (0) or `STM_LOCK_EXCLUSIVE` (1) —
  any other value is `STM_EINVAL`.

## Spec cross-reference

`v2/specs/locks.tla` pins the load-bearing invariant:

- **`NoConflictingLocks`** — at every reachable state, no two locks
  satisfy the conflict predicate. Acquire and ReleaseOwner are the
  only mutators; both preserve the invariant.

Spec actions:

- `Acquire(t, ds, ino, owner, type, off, len)` — adds a record
  unless any existing record conflicts.
- `Release(t, ds, ino, owner, off, len)` — exact-match drop.
- `ReleaseOwner(t, owner)` — drop all records with matching owner_id.
- `Test(t, ds, ino, owner, type, off, len)` — pure read; returns
  `would_grant ∈ BOOLEAN`.

Buggy variants (in spec; need not be re-spelled in impl):

- `BuggyAcquireIgnoresConflict` — Acquire admits records regardless
  of overlap. Trips `NoConflictingLocks` within ~3 states.
- `BuggyReleaseOwnerSkipsSomeInode` — partial-release of an owner.
  Trips `NoConflictingLocks` only against a fid-clunk-mid-flock
  scenario.

## SPEC-TO-CODE mapping

| Spec action | Impl function | File |
|---|---|---|
| `Acquire` | `stm_lock_acquire` | `v2/src/locks/locks.c` |
| `Release` | `stm_lock_release` | same |
| `ReleaseOwner` | `stm_lock_release_owner` | same |
| `Test` | `stm_lock_test` | same |
| `NoConflictingLocks` invariant | conflict check inside `stm_lock_acquire` | same |

## Tests

- `tests/test_locks.c` — direct unit coverage. Acquire / Release /
  Test / ReleaseOwner happy paths + every refusal + the conflict matrix
  (same-owner same-range, same-owner overlapping-range, different-owner
  non-overlapping, different-owner overlapping shared-vs-shared,
  different-owner overlapping with-exclusive).
- `tests/test_fs.c` — composes with fs.c wrappers
  (`stm_fs_lock_acquire` / `_release` / `_test`) and validates that the
  9P-server's lock-owner-on-clunk pathway works end-to-end.
- 9P-server integration tests in `tests/test_p9.c` cover `Tlock` /
  `Tgetlock` wire-level handlers.

## Status

| Feature | State | Notes |
|---|---|---|
| Acquire (F_SETLK) | LIVE | Non-blocking; returns STM_EAGAIN on conflict |
| Release (exact-match) | LIVE | Idempotent on no-match |
| Test (F_GETLK) | LIVE | Pure read |
| ReleaseOwner | LIVE | Post-close cleanup pathway |
| Blocking F_SETLKW + deadlock-detection wait-graph | DEFERRED | Forward-noted in `locks.h` MVP scope; would extend `locks.tla` with a `WaitsFor` shadow relation |
| Range-aware split/merge on partial release | DEFERRED | Today's release is exact-match only |
| Persistence across mount | NEVER | POSIX semantics — advisory locks die with the fd |

Audit class: any change to acquire / release / release_owner must
preserve `NoConflictingLocks`. The conflict check is the load-bearing
predicate; an off-by-one in the overlap math or a missed
same-owner short-circuit would surface as concurrent
incompatible-mode acquires both succeeding.
