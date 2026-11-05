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

Header: `v2/include/stratum/locks.h`.
Impl: `v2/src/locks/locks.c`.
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
stm_status stm_lock_acquire_as     (t, dataset_id, ino, gen, owner_id, client,
                                       type, off, len);
stm_status stm_lock_release        (t, dataset_id, ino, owner_id,
                                       off, len);
stm_status stm_lock_release_owner  (t, owner_id);
stm_status stm_lock_release_ino    (t, dataset_id, ino);
```

`stm_lock_acquire` is **non-blocking** (Linux `F_SETLK` shape) — returns
`STM_EAGAIN` on conflict. An owner's own records never refuse it. A request
replaces what its owner holds over the range, as POSIX asks: an upgrade, a
downgrade or a split. A record of the same type that overlaps or abuts the
request merges into it, and a request at the type already held over its whole
range changes nothing. A request that would write more than a bound allows
answers `STM_ENOLCK` (Bounds). `len = 0` means "to EOF": the record's end is
`UINT64_MAX`.

`stm_lock_release` trims and splits the owner's records over the range,
whatever their type. Idempotent (returns `STM_OK` if it overlaps nothing). A
release in the middle of a record makes two records of one, so it can answer
`STM_ENOLCK` and release nothing. A whole-file unlock adds no record, so no
bound can refuse it.

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

`stm_lock_release` is the exception: it matches `(ds, ino, owner)` and any
overlap with the range, without the gen, so it also trims the owner's lock on
another incarnation of the number. Only the bounds can observe that: a record
on a discarded incarnation still counts, so a trim moves its client's share and
a split can answer `STM_ENOLCK`. A free drops its incarnation's locks, so only
an incarnation a rollback discarded can still hold one; those locks refuse
nothing on any other incarnation, and the discarded gen never comes back, so no
acquire or test meets them again.
(`locks_release_drops_only_its_owners_lock_there` pins the match,
`locks_client_bound_two_incarnations` the share.)

### Range arithmetic

A `len` of 0 normalizes to an end of `UINT64_MAX`, so range overlap is uniform
across "explicit byte range" + "to EOF" calls. Acquire
refuses `off + len` overflowing `uint64_t` (`STM_EOVERFLOW`) when
`len != 0`, before normalization.

### Storage layout

Single mutex-protected `records` array (heap-grown linear vector).
Linear scan of all records on every acquire / release / test — bounded
acceptable at MVP since the typical workload is dozens of locks per
mount. A future optimization could index by `(dataset_id, ino)` to
short-circuit non-matching scans.

### Bounds

A request past `STM_LOCK_MAX_PER_OWNER` (256, one fid),
`STM_LOCK_MAX_PER_CLIENT` (4096, one client) or `STM_LOCK_MAX_RECORDS`
(65536) answers `STM_ENOLCK` and changes nothing. The owner bound alone does
not stop one identity holding many fids from filling the table for everyone,
so `stm_lock_acquire_as` names a client, and `stm_lock_acquire` names none (0),
which counts against no share. Every record a request writes is its client's,
a piece split from another client's record on the same owner included: the
request is what grew the table. A request that writes nothing (every byte is
held at that type) meets no bound and keeps the record's client. A release names
no client, so the pieces of a split keep their record's, and the split is refused
when that client's share is full: unchecked, a release in the middle of each
record would double it.

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
- **`OwnRecordsDisjoint`** -- one owner's records on one inode never overlap.
- **`HeldBytesExact`** (an action property) -- a step changes exactly what
  the action it took names, byte by byte: after an Acquire the owner holds
  exactly the asked type on every byte of the range, after a Release nothing
  there, after a ReleaseOwner nothing anywhere, and every other (inode, owner,
  byte) holds what it held. A history variable, `last`, records each step's
  action and arguments, so a Release that removes another range, or nothing,
  is judged rather than read as a stutter. The invariants cannot see a removal
  at all, since a removal never makes a conflict.

Spec actions (the spec's inode is one incarnation, the impl's `(ds, ino,
gen)`; it has no datasets and no table argument):

- `Acquire(ino, owner, type, off, len)` -- replaces what the owner held over
  the range, unless another owner's lock refuses it (`AcquireRefuses`).
- `Release(ino, owner, off, len)` -- trims and splits every lock of the owner
  on that range of that inode, whatever its type. The impl matches without
  the gen (above).
- `ReleaseOwner(owner)` — drops every lock of the owner.

`stm_lock_test` is a pure read with no spec action: it answers whether
`Acquire` would admit the candidate, by the same refusal predicate.

Three buggy variants change only what Acquire checks (`AcquireRefuses`); the
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

One changes what Acquire writes:

- `BuggyAcquireStacks` -- Acquire adds its record beside the owner's
  overlapping ones instead of replacing them, so a downgrade leaves the
  exclusive record standing. Fires `OwnRecordsDisjoint`
  (`locks_acquire_stacks_buggy.cfg`, 2 steps).

Four change Release, and only `HeldBytesExact` can see them:

- `BuggyReleaseOwnerBlind` — Release drops the matching range of every
  owner, so one owner's unlock frees another's lock
  (`locks_release_owner_blind_buggy.cfg`, 2 steps).
- `BuggyReleaseInoBlind` — Release drops the owner's matching range on
  every inode (`locks_release_ino_blind_buggy.cfg`, 2 steps).
- `BuggyReleaseDropsNothing` — Release removes nothing, so an unlock
  leaves the lock held (`locks_release_drops_nothing_buggy.cfg`, 2
  steps).
- `BuggyReleaseExactOnly` -- Release drops only a record with exactly its
  range, so an unlock of part of a lock leaves bytes held
  (`locks_release_exact_only_buggy.cfg`).

Runtime twins: `locks_release_drops_only_its_owners_lock_there` and
`locks_release_trims_and_splits`.

## SPEC-TO-CODE mapping

| Spec action | Impl function | File |
|---|---|---|
| `Acquire` | `stm_lock_acquire_as` (`stm_lock_acquire` names no client) | `v2/src/locks/locks.c` |
| `Release` | `stm_lock_release` | same |
| `ReleaseOwner` | `stm_lock_release_owner` | same |
| `Test` (no spec action; `AcquireRefuses`) | `stm_lock_test` | same |
| `NoConflictingLocks` invariant | conflict check inside `stm_lock_acquire_as` | same |
| `DifferentInosNeverInteract` invariant | `conflicts`'s `(dataset_id, ino, gen)` match | same |
| `OwnRecordsDisjoint` invariant | the replacing apply loop of `stm_lock_acquire_as` | same |
| `HeldBytesExact` property | the range arithmetic of `stm_lock_acquire_as` and `stm_lock_release`; `stm_lock_release_owner` | same |

## Tests

- `tests/test_locks.c` — direct unit coverage. Acquire / Release /
  Test / ReleaseOwner happy paths + every refusal + the conflict matrix
  (same-owner same-range, same-owner overlapping-range, different-owner
  non-overlapping, different-owner overlapping shared-vs-shared,
  different-owner overlapping with-exclusive, other incarnation
  `locks_other_incarnation_never_conflicts`, and what a release leaves
  `locks_release_drops_only_its_owners_lock_there`), the client bound
  (`locks_client_bound`, `locks_client_bound_split`,
  `locks_client_bound_two_incarnations`, `locks_client_pays_for_what_it_writes`,
  `locks_client_pays_for_a_merge`, `locks_client_converts_its_own_at_the_bound`,
  `locks_no_client_no_share`, `locks_relock_writes_nothing`) and the table's
  (`locks_table_bound`).
- `tests/test_fs_identity.c` -- `fs_lock_on_a_rolled_back_file_never_refuses_its_successor`,
  `fs_if_gen_ops_act_only_on_their_incarnation`.
- `tests/test_fs.c` — composes with fs.c wrappers
  (`stm_fs_lock` / `stm_fs_unlock` / `stm_fs_lock_test`) and validates that the
  9P-server's lock-owner-on-clunk pathway works end-to-end.
- 9P-server integration tests in `tests/test_9p.c` cover `Tlock` /
  `Tgetlock` wire-level handlers.

## Status

| Feature | State | Notes |
|---|---|---|
| Acquire (F_SETLK) | LIVE | Non-blocking; returns STM_EAGAIN on conflict |
| Release (trims and splits) | LIVE | Idempotent on no overlap |
| Bounds per owner, per client and in all | LIVE | `STM_ENOLCK`, nothing changed |
| Test (F_GETLK) | LIVE | Pure read |
| ReleaseOwner | LIVE | Post-close cleanup pathway |
| Blocking F_SETLKW + deadlock-detection wait-graph | DEFERRED | Forward-noted in `locks.h` MVP scope; would extend `locks.tla` with a `WaitsFor` shadow relation |
| Persistence across mount | NEVER | POSIX semantics — advisory locks die with the fd |

Audit class: any change to acquire / release / release_owner must
preserve `NoConflictingLocks`. The conflict check is the load-bearing
predicate; an off-by-one in the overlap math or a missed
same-owner short-circuit would surface as concurrent
incompatible-mode acquires both succeeding.
