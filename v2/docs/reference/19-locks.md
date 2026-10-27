# 19 — Advisory lock table (P8-POSIX-7d)

## Purpose

Per-fs, in-RAM advisory lock table backing the Linux `flock(2)` + `fcntl(2)`
`F_SETLK` / `F_GETLK` / `F_OFD_SETLK` surface. The table tracks byte-range
locks keyed by `(dataset_id, ino, gen, owner_id, off, len, type)`, with conflict
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
stm_status stm_lock_acquire        (t, dataset_id, ino, gen, owner_id,
                                       type, off, len);
stm_status stm_lock_release        (t, dataset_id, ino, owner_id,
                                       off, len);
stm_status stm_lock_release_owner  (t, owner_id);
stm_status stm_lock_release_ino    (t, dataset_id, ino);
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

`stm_lock_release_ino` is the **inode-free** path — releases every lock on
`(dataset_id, ino)`, every incarnation, whoever holds it. fs.c's freed-inode
cleanup calls it once the inode is freed, so a freed file's records go at
once instead of when their owners close; a fid on the freed file answers
ESTALE, so it could not release them itself (test
`fs_freed_inode_takes_its_locks_with_it`).

### Inspection

```c
stm_status stm_lock_test  (t, dataset_id, ino, gen, owner_id, type, off, len,
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

1. Overlapping byte ranges on the same incarnation `(dataset_id, ino, gen)`.
2. **Different** owners (same-owner is admitted unconditionally).
3. At least one is `STM_LOCK_EXCLUSIVE`.

This is the `NoConflictingLocks` invariant from `locks.tla` — the
headline safety property. The acquire path checks this predicate
against EVERY existing lock at the same `(ds, ino, gen)` before insertion;
a single conflict refuses the acquire.

### Incarnations

`gen` is the inode's `si_gen`. A record on one incarnation never
conflicts with another incarnation of the same ino, so a lock left on a
file that is gone cannot refuse the file that reuses its number. A free
also drops the records (`stm_lock_release_ino`), but a snapshot rollback
discards files without that path; their records stay inert until their
owners close, and the reused ino gets a gen above every discarded one
(16-inode's rollback floors).

The fs wrappers name the incarnation themselves: `stm_fs_lock` reads the
live `si_gen` under fs->global EX and refuses a missing inode
(`STM_ENOENT`); `stm_fs_lock_test` reads it without the lock (the answer
is about the incarnation it read). Their `*_if_gen` twins, which the 9P
server calls with a fid's `cached_gen`, answer `STM_ESTALE` when the live
incarnation is not that one.

`stm_lock_release` is the exception: its match is `(ds, ino, owner, off,
end)`, without the gen, so it also drops the owner's identical lock on
another incarnation of the number. Nothing can observe that. A free drops
its incarnation's locks, so only an incarnation a rollback discarded can
still hold one; those locks refuse nothing on any other incarnation, and
the discarded gen never comes back, so no acquire or test meets them
again. (`locks_release_drops_only_its_owners_lock_there` pins the match.)

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
  satisfy the conflict predicate. Acquire, Release and ReleaseOwner
  are the mutators; each preserves it.
- **`OwnLocksNeverRefuse`** — an owner's own locks never refuse its
  acquire, so it may stack or upgrade over any range it holds.
- **`DifferentInosNeverInteract`** — a lock on one inode never refuses
  an acquire on another, whatever its owner, type or range.
- **`DropsAreReleases`** (an action property) — a step removes exactly
  what the action it took names: every lock of the owner on that range
  of that inode for a Release, every lock of the owner for a
  ReleaseOwner, nothing for an Acquire. A history variable, `last`,
  records each step's action and arguments, so a Release that removes
  another range, or nothing, is judged rather than read as a stutter.
  The invariants cannot see a removal at all, since a removal never
  makes a conflict.

Spec actions (the spec's inode is one incarnation, the impl's `(ds, ino,
gen)`; it has no datasets and no table argument):

- `Acquire(ino, owner, type, off, len)` — adds a lock unless an existing
  one refuses it (`AcquireRefuses`).
- `Release(ino, owner, off, len)` — drops every lock of the owner on that
  range of that inode, whatever its type. The impl matches without the
  gen (above).
- `ReleaseOwner(owner)` — drops every lock of the owner.

`stm_lock_test` is a pure read with no spec action: it answers whether
`Acquire` would admit the candidate, by the same refusal predicate.

Buggy variants change only what Acquire checks (`AcquireRefuses`); the
invariants judge by the healthy `Conflicts`:

- `BuggyShared_Excl_Granted` — Acquire refuses only EXCLUSIVE against
  EXCLUSIVE. Fires `NoConflictingLocks` after two acquires
  (`locks_shared_excl_granted_buggy.cfg`).
- `BuggyOwnerCheckMissing` — Acquire ignores the owner, so an owner's
  own exclusive lock refuses its next acquire. Fires
  `OwnLocksNeverRefuse` (`locks_owner_check_missing_buggy.cfg`).
- `BuggyInoBlind` — Acquire compares ranges without the inode, so a
  lock on one file refuses an acquire on another. Fires
  `DifferentInosNeverInteract` (`locks_ino_blind_buggy.cfg`).
  `NoConflictingLocks` cannot see this bug: a refusal adds no record.

Three more change Release, and only `DropsAreReleases` can see them:

- `BuggyReleaseOwnerBlind` — Release drops the matching range of every
  owner, so one owner's unlock frees another's lock
  (`locks_release_owner_blind_buggy.cfg`, 2 steps).
- `BuggyReleaseInoBlind` — Release drops the owner's matching range on
  every inode (`locks_release_ino_blind_buggy.cfg`, 2 steps).
- `BuggyReleaseDropsNothing` — Release removes nothing, so an unlock
  leaves the lock held (`locks_release_drops_nothing_buggy.cfg`, 2
  steps).

Runtime twin of all three: `locks_release_drops_only_its_owners_lock_there`.

## SPEC-TO-CODE mapping

| Spec action | Impl function | File |
|---|---|---|
| `Acquire` | `stm_lock_acquire` | `v2/src/locks/locks.c` |
| `Release` | `stm_lock_release` | same |
| `ReleaseOwner` | `stm_lock_release_owner` | same |
| `Test` (no spec action; `AcquireRefuses`) | `stm_lock_test` | same |
| `NoConflictingLocks` invariant | conflict check inside `stm_lock_acquire` | same |
| `DifferentInosNeverInteract` invariant | `conflicts`'s `(dataset_id, ino, gen)` match | same |
| `DropsAreReleases` property | `stm_lock_release`'s `(dataset_id, ino, owner_id, off, end)` match; `stm_lock_release_owner` | same |

## Tests

- `tests/test_locks.c` — direct unit coverage. Acquire / Release /
  Test / ReleaseOwner happy paths + every refusal + the conflict matrix
  (same-owner same-range, same-owner overlapping-range, different-owner
  non-overlapping, different-owner overlapping shared-vs-shared,
  different-owner overlapping with-exclusive, other incarnation
  `locks_other_incarnation_never_conflicts`, and what a release leaves
  `locks_release_drops_only_its_owners_lock_there`).
- `tests/test_fs.c` — `fs_lock_on_a_rolled_back_file_never_refuses_its_successor`,
  `fs_if_gen_ops_act_only_on_their_incarnation`.
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
