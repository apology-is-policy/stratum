# R171 audit findings — 9.8-LF-3 series (c06e47a..8f7b72f)

Scope: c06e47a (LF-3a) + 8362ac0 (LF-3b/c) + 3d6bbca (LF-3b cont / LF-3c cont) + 8f7b72f (LF-3d).

The LF-3 series ports 21 fs.c public-read entry points from the
`fs->global` SH rdlock to a wait-free path that uses only an atomic
wedge check + EBR pin. The wait-free reader holds NO `fs->global` lock
at any point. The LF-2 engine docstring at `v2/src/btree_engine/engine.c`
lines 199-211 explicitly claims that the LF-2 substrate is correct
under the assumption that "serial and concurrent paths are mutually
excluded by `fs->global`'s EX-vs-SH" — LF-3 LIFTS half of that
exclusion (the reader no longer holds SH), and the PARALLEL-3 impl-1..6
ports earlier this branch already lifted the other half (writers now
hold SH instead of EX). The composition is that **reader and writer
can now run simultaneously against the same engine on the same
inode**, which the engine substrate is not yet designed to tolerate
until BE-prepend ships. The R171 audit's job is to enumerate what
that gap actually costs.

The commit messages treat this as "STM_ECORRUPT under contention,
forward-noted to BE-prepend (#1218)". That framing understates two
classes of problem:

  (a) The leaf-level value-byte race is not just a torn-read producing
      STM_ECORRUPT; it is a `free()`-then-`memcpy()` from the freed
      buffer in `eng_leaf_put`. Memory-unsafe by every definition.
      Documented as P0-1.

  (b) The engine HANDLE itself is freed synchronously (no EBR retire)
      on rollback, dataset destroy, sync close, and unmount. Wait-free
      readers that have resolved an engine pointer but not yet
      finished using it can land on a freed engine struct. Documented
      as P0-2 / P0-3.

## P0 (critical)

### P0-1: Same-engine writer can free leaf value buffer mid-`memcpy` in wait-free reader (UAF)

The wait-free reader's lookup path:

  `v2/src/btree_engine/engine.c:613-617`

  ```c
  uint32_t vl = node->entries[i].val_len;
  if (vl) {
      void *v = malloc(vl);
      if (!v) return STM_ENOMEM;
      memcpy(v, node->entries[i].val, vl);     /* <-- race read */
      ...
  }
  ```

The concurrent writer's upsert path:

  `v2/src/btree_engine/node.c:303-324`

  ```c
  if (found) {
      /* Upsert: replace the value, keep the key. */
      uint8_t *vc = NULL;
      stm_status s = eng_dup(val, val_len, &vc);   /* 1. malloc new */
      if (s != STM_OK) return s;
      free(n->entries[i].val);                     /* 2. free old */
      n->entries[i].val     = vc;                  /* 3. assign new ptr */
      n->entries[i].val_len = (uint32_t)val_len;
      ...
  }
  ```

Between step 2 and step 3 the writer leaves `n->entries[i].val` pointing
at freed memory. A wait-free reader scheduled in this window does
`memcpy(v, freed_ptr, vl)`, returning arbitrary bytes (or faulting if
the allocator unmapped the slab). The window is microseconds but real.

The race is fired by every LF-3d test that pairs a writer with a
same-engine reader. The `lf3d_read_inline_vs_chmod_same_inode` test
(`v2/tests/test_compound_ops_concurrent.c:1917`) explicitly racy: chmod
writer calls `stm_inode_set` → `stm_btree_engine_insert` → `eng_leaf_put`
upsert → free+new on the 256-byte inode-value buffer; INLINE-mode
reader calls `stm_fs_read` → `stm_inode_lookup_concurrent` →
`stm_btree_engine_lookup_concurrent` → that exact `memcpy`. The 256-byte
free is fast and usually reissued by the next 256-byte malloc — which is
the writer's own `eng_dup` for the next iteration — so the reader USUALLY
sees coherent bytes. But "usually" is not "always", and a sufficiently
large slab/tcmalloc kernel may unmap a freed 256-byte block instantly
under adversarial heap pressure.

The `[[flake-per-inode-cfr-concurrent]]` flake documented at
`memory/MEMORY.md` is consistent with this UAF surfacing under
contention.

The commit messages acknowledge this as the "LF-2 reader-vs-writer
caveat" and forward-note BE-prepend's CAS-prepend writer model as the
fix. But the LF-2 docstring at `engine.c:199-211` claims the LF-2
substrate is correct because `fs->global` EX-vs-SH excludes serial-path
(writer) vs concurrent-path (reader). **LF-3 invalidates that claim**
— the wait-free reader no longer holds SH, and PARALLEL-3 writers no
longer hold EX, so the exclusion is broken.

**Reproduction (in principle)**: run `lf3d_read_inline_vs_chmod_same_inode`
under ASan with the heap configured to munmap-on-free (`MALLOC_CONF=munmap_on_free:true`
or equivalent). The reader will fault on the first race iteration.

**Fix sketches**:

1. (Robust) Implement BE-prepend's CAS-prepend writer ASAP and retire
   the in-place leaf value rewrite. This is the planned closure
   (#1218). Until then, LF-3 should NOT be advertised as production-
   ready for same-engine concurrent reader-vs-writer; advertise the
   crown-jewel property as "wait-free reader vs DISJOINT-engine
   writer" only.

2. (Stopgap) Make the writer rewrite leaf values via a release-store
   of an atomic pointer + EBR-retire the old buffer. Reader uses
   acquire-load. Requires changing `eng_entry.val` to
   `_Atomic(uint8_t *)` and routing the free through `stm_ebr_retire(old_val, free)`.

3. (Documentation) If the BE-prepend closure is imminent, at minimum
   update the engine docstring at `engine.c:199-211` to remove the
   "mutually excluded by `fs->global`" claim (which is no longer true)
   and replace with the actual contract: "the reader/writer race is
   PRESENT at LF-3 and surfaces as torn-state STM_ECORRUPT OR
   undefined behavior via UAF in `eng_leaf_put`; valid only in
   reader-quiescent OR same-engine-disjoint-key configurations until
   BE-prepend lands". This stops a future reader of the docstring
   from believing the substrate is sound under LF-3.

Cite: `v2/src/btree_engine/engine.c:613-617`, `v2/src/btree_engine/node.c:303-324`,
`v2/src/btree_engine/engine.c:199-211` (stale claim), `v2/tests/test_compound_ops_concurrent.c:1917`.

### P0-2: Engine handle UAF on rollback + dataset_destroy + close_engine racing with wait-free reader

`stm_dataset_index_get_engine` releases `idx->lock` BEFORE the caller
uses the returned engine pointer:

  `v2/src/dataset/dataset.c:1491-1512`

  ```c
  must_lock(&idx->lock);
  ...
  *out_engine = idx->slots[s].engine;
  must_unlock(&idx->lock);      /* <-- pointer is exposed; lock is dropped */
  return STM_OK;
  ```

Three call sites then synchronously destroy the engine:

  - `stm_dataset_destroy` (rollback path on dataset-create failure) —
    `v2/src/dataset/dataset.c:531-566` (line 561).
  - `stm_dataset_index_close_engine` (manual close API; no production
    callers today, but the API is public) — `v2/src/dataset/dataset.c:1514-1528`.
  - `stm_dataset_index_set_engine_root` (the rollback hot path,
    called from `stm_fs_rollback_snapshot`) — `v2/src/dataset/dataset.c:1532-1583`
    (line 1562, after `pending_flush` refusal).

Each calls `dataset_engine_close_locked` →
`stm_btree_engine_destroy(eng)` → `free(eng)` synchronously under
`idx->lock`. The engine struct is NOT retired through EBR; the EBR
substrate only retires individual eng_node pointers (and even those
are forward-noted at LF-BE-prepend, not yet implemented).

A wait-free reader that obtained the engine pointer via
`stm_dataset_index_get_engine` BEFORE this destroy can dereference a
freed engine struct in `stm_btree_engine_lookup_concurrent` —
specifically the `atomic_load_explicit(&eng->mvcc_root, ...)` at
`v2/src/btree_engine/engine.c:549`. UAF on the atomic itself.

`stm_fs_rollback_snapshot` holds `fs->global` wrlock
(`v2/src/fs/fs.c:8499`), but LF-3 wait-free readers DO NOT TAKE
`fs->global` AT ALL. The wrlock-vs-wrlock exclusion that historically
guarded `dataset_engine_close_locked` is bypassed by the wait-free
read path.

The race window:

  - T1 (wait-free reader, e.g. stm_fs_stat): atomic wedged check
    (false), enter EBR, call `stm_dataset_index_get_engine` (takes
    idx->lock briefly, returns engine ptr, drops idx->lock).
  - T2 (writer, e.g. stm_fs_rollback_snapshot): acquires `fs->global`
    wrlock (does NOT exclude T1), then `stm_dataset_index_set_engine_root`
    → `dataset_engine_close_locked` → `free(eng)`.
  - T1: enters `stm_btree_engine_lookup_concurrent`, dereferences freed
    engine ptr.

**Reproduction (in principle)**: add a race test that runs
`stm_fs_rollback_snapshot` against a wait-free `stm_fs_stat` on the
same dataset. The LF-3d tests don't cover rollback paths at all.

**Fix sketches**:

1. (Robust) Wrap the engine struct itself in EBR retirement. Replace
   `stm_btree_engine_destroy(eng); free(eng)` in `dataset_engine_close_locked`
   with `stm_ebr_retire(eng, btree_engine_destroy_via_ebr)`. Pre-LF-BE-prepend,
   the engine's node tree free path inside the destroy still has the
   `invalidate_memtree` UAF (clause P0-4), but the engine struct itself
   is at least safe.

2. (Stopgap) Make `stm_fs_rollback_snapshot` and similar destroy-path
   API document that they require a quiescent reader population, then
   enforce by upgrading the wedge gate to a 2-step ("draining" state
   that wait-free readers refuse to enter) before the destroy. The
   tricky part is "how do you drain readers that don't hold any lock?"
   — needs an EBR-style epoch barrier (`stm_ebr_try_advance` until all
   pre-call readers have exited).

3. (Documentation) At minimum document this constraint in `dataset.h`
   for `stm_dataset_index_get_engine` and `stm_dataset_index_close_engine`
   / `stm_dataset_index_set_engine_root` — and update CLAUDE.md's
   §"trust list" rollback row to acknowledge that LF-3 introduces a
   reader-rollback UAF that BE-prepend or a separate engine-retirement
   chunk must close.

Cite: `v2/src/dataset/dataset.c:1491-1512` (get_engine), `v2/src/dataset/dataset.c:1483-1487`
(close_locked), `v2/src/dataset/dataset.c:1532-1583` (set_engine_root), `v2/src/fs/fs.c:8499`
(rollback wrlock), `v2/src/btree_engine/engine.c:170-187` (engine destroy).

### P0-3: `stm_fs_unmount` UAF on subsystem indices + engine + fs struct against wait-free readers

`stm_fs_unmount` tears the fs down WITHOUT any wedge transition or
reader-drain:

  `v2/src/fs/fs.c:1371-1432`

  ```c
  stm_status stm_fs_unmount(stm_fs *fs)
  {
      if (!fs) return STM_EINVAL;
      pthread_rwlock_wrlock(&fs->global);   /* excludes SH-takers, NOT wait-free readers */
      ...
      stm_sync_close(fs->sync);             /* frees inode_idx, dirent_idx, xattr_idx, etc., and sync itself */
      stm_alloc_close(fs->alloc);           /* frees alloc */
      ...
      pthread_rwlock_destroy(&fs->global);  /* destroys the rwlock (PHI calls on it post-destroy are UB) */
      free(fs);                             /* frees the fs struct */
  }
  ```

A wait-free reader running concurrently with unmount can be inside any
of these paths:

  - Reading `fs->sync` (pointer) and calling `stm_sync_inode_index(fs->sync)`
    AFTER `stm_sync_close(fs->sync)` has freed the sync struct: UAF on
    `fs->sync->inode_idx`.
  - Holding an `iidx` pointer obtained pre-close and entering
    `stm_inode_lookup_concurrent` AFTER `stm_inode_index_close(iidx)`
    has freed the idx struct: UAF on the dataset_id lookup path.
  - Holding an engine pointer obtained pre-close and entering
    `stm_btree_engine_lookup_concurrent` AFTER
    `stm_dataset_index_close(idx)` has freed every engine: UAF on the
    mvcc_root atomic load.
  - Calling `atomic_load_explicit(&fs->wedged, acquire)` AFTER
    `free(fs)` has returned the fs struct to the allocator: UAF on
    the atomic itself, possibly returning attacker-controlled bytes if
    the allocator's freelist is fast.

The atomic wedge check provides ZERO protection against unmount,
because unmount NEVER sets `fs->wedged = true`. The only wedge-set
site is `stm_fs_mark_wedged` at `v2/src/fs/fs.c:9411`, and unmount
does not call it.

In practice, applications quiesce all in-flight stm_fs_* calls before
calling unmount. Stratumd does this via the accept-loop shutdown +
worker join. But the LF-3 ports WIDEN the public stm_fs_* contract:
prior to LF-3, the implicit contract was "stm_fs_unmount excludes
in-flight stm_fs_* via fs->global rwlock"; under LF-3 it's "the
caller MUST ensure no concurrent stm_fs_* read calls; unmount itself
provides NO exclusion guarantee for wait-free readers." Any embedded
or in-process test harness that doesn't carefully sequence
unmount-after-reader-quiesce will hit UAF.

**Reproduction (in principle)**: launch a reader thread doing
`stm_fs_stat` in a loop. From the main thread, after a few
microseconds, call `stm_fs_unmount`. Without explicit quiesce, the
reader will UAF on `fs->sync` or downstream pointers.

**Fix sketches**:

1. Add a "draining" state: `stm_fs_unmount` first atomically sets a
   flag (or sets `fs->wedged = true` via release-store) THEN walks all
   EBR threads and waits via `stm_ebr_try_advance` until in-flight
   readers have exited their epochs. Only then proceed to
   `stm_sync_close` etc. This requires the wait-free readers to check
   the "draining" flag AFTER entering EBR (they could be past the
   wedge check but not yet in EBR — a hazard). The cleanest pattern is
   "wedge → ebr-advance-until-empty → sync_close → free".

2. (Documentation) Update the `stm_fs_unmount` docstring and CLAUDE.md
   to declare: "Caller MUST ensure no concurrent stm_fs_* calls are
   in flight before invoking stm_fs_unmount; LF-3 wait-free readers do
   not synchronize against unmount." This is the minimum that should
   accompany a release-candidate LF-3.

Cite: `v2/src/fs/fs.c:1371-1432` (unmount), `v2/src/sync/sync.c:2263-2305`
(sync_close frees indices + sync struct), `v2/src/inode/inode.c:553-576`
(inode_index_close), `v2/src/dirent/dirent.c:462+`
(dirent_index_close), `v2/src/fs/fs.c:9411-9422` (mark_wedged DOES NOT
fire from unmount).

### P0-4: `invalidate_memtree` UAF against pinned wait-free reader (LF-2 limitation, now reachable at LF-3)

The engine's `invalidate_memtree` self-documents a UAF:

  `v2/src/btree_engine/engine.c:780-806`

  ```c
  /* LF-2 LIMITATION (closes at LF-BE-prepend with EBR retire): a
   * reader that already acquire-loaded the soon-to-be-stale root
   * pointer BEFORE this store is STILL holding it when the
   * subsequent eng_node_free_recursive runs — that is a UAF.
   * The contract: invalidate_memtree (failed flush + commit_abort)
   * must NEVER run concurrent with a pinned reader; production
   * callers serialise via fs->global EX, and the LF-2 test gate
   * runs reader-quiescent abort scenarios only. ...
   */
  atomic_store_explicit(&eng->mvcc_root, NULL, release);
  eng_node_free_recursive(eng->root);   /* <-- UAF: reader may still descend */
  eng->root = NULL;
  ```

The documented contract — "must NEVER run concurrent with a pinned
reader; production callers serialise via fs->global EX" — was true
prior to LF-3. **LF-3 invalidates the contract**: wait-free readers do
not take fs->global, and `invalidate_memtree` is called from:

  - `stm_btree_engine_commit_flush`'s failure path
    (`engine.c:1018, 1054`) — called from sync_commit's M-cascade,
    which holds `sync->lock` and pool's lock but NOT `fs->global`.
  - `stm_btree_engine_commit_abort` (`engine.c:1150`) — same posture.

A wait-free reader pinned on the engine tree when a commit fails or
aborts has its descended-from nodes freed under it. UAF.

LF-3a's commit message acknowledges this as the "reader-vs-writer
caveat" forward-noted to BE-prepend. The audit's findings:

  - This is structurally identical to P0-2 (engine handle UAF) and
    P0-1 (leaf value UAF) — three symptoms of the same root cause
    (wait-free readers cannot be safely supported against the LF-2
    substrate's free-without-retire pattern).
  - The forward-note in `engine.c:786-795` is now subtly wrong: it
    asserts "production callers serialise via fs->global EX" — this
    needs to be updated to acknowledge LF-3's regime AND state the
    actual exposure surface.

**Reproduction (in principle)**: trigger a commit_flush failure
(inject a write_node failure via ASan) on a node tree that has a
wait-free reader actively pinned. The reader fault on the next
internal-node descent.

**Fix sketches**: same as P0-2 — EBR-retire the eng_node tree (the
"LF-BE-prepend close" the docstring describes) and replace
`eng_node_free_recursive` with `stm_ebr_retire(root,
eng_node_free_recursive)`. Until BE-prepend lands, LF-3 cannot be
considered safe against commit failures.

Cite: `v2/src/btree_engine/engine.c:780-806`, `engine.c:1018+1054+1150`.

## P1 (severe)

### P1-1: `stm_fs_listxattr` / `stm_fs_stat` / `stm_fs_lookup` / `stm_fs_readlink` / `stm_fs_getxattr` lack `stm_fs_read`'s SH-fallback for transient STM_ECORRUPT

The LF-3d commit message forward-notes this explicitly (commit `8f7b72f`
forward-note: "stm_fs_listxattr / stm_fs_stat do not have stm_fs_read's
wait-free → SH-fallback. Under same-engine concurrent writer they
propagate transient STM_ECORRUPT.").

`stm_fs_read`'s INLINE branch falls through to the SH-rdlock path on
`ls != STM_OK` (`v2/src/fs/fs.c:2076-2102`) so a transient race
manifests as a (slow) retry under the serial idx-mutex.

The other ports return the wait-free path's status DIRECTLY to the
caller:

  - `stm_fs_stat` (`v2/src/fs/fs.c:3206-3239`) — no fallback.
  - `stm_fs_lookup` (`v2/src/fs/fs.c:2187-2230`) — no fallback.
  - `stm_fs_readlink` (`v2/src/fs/fs.c:3897+`) — no fallback.
  - `stm_fs_get_seals` (`v2/src/fs/fs.c:4212-4226`) — no fallback.
  - `stm_fs_name_to_handle` (`v2/src/fs/fs.c:4249+`) — no fallback.
  - `stm_fs_open_by_handle` (`v2/src/fs/fs.c:4347+`) — no fallback.
  - `stm_fs_getxattr` (`v2/src/fs/fs.c:5327+`) — no fallback.
  - `stm_fs_listxattr` (`v2/src/fs/fs.c:5376+`) — no fallback.
  - `stm_fs_readdir` (`v2/src/fs/fs.c:5009+`) — no fallback.

A concurrent writer that causes a transient torn read surfaces
STM_ECORRUPT directly to the caller. Callers (9P server, the
stratum-slate TUI, /ctl/) treat STM_ECORRUPT as an unrecoverable
filesystem-integrity error, which can panic the calling process or
flag the volume as corrupt — but the underlying disk state IS NOT
corrupt; only the wait-free read was torn.

The same-engine concurrent writer race is the documented LF-2
limitation, but the consequences here are real: under a chmod-heavy
workload, a stat reader will see spurious STM_ECORRUPT roughly as
often as `eng_leaf_put` lands its free-then-assign window. The
`[[flake-per-inode-cfr-concurrent]]` flake is consistent with this.

**Reproduction**: run `lf3d_listxattr_stable_vs_chmod_disjoint_inode`
(passes today on disjoint inodes) but flip the chmod target to the
reader's inode → STM_ECORRUPT propagated. The `impl6_stat_reader_vs_chmod_writer_same_inode`
test does exactly this scenario and is documented as flaky.

**Fix sketches**:

1. (Easy + correct) Back-port `stm_fs_read`'s fallback pattern to
   every other LF-3 read entry: on STM_ECORRUPT from the wait-free
   lookup, exit EBR, acquire fs->global SH, retry through the serial
   path. This eliminates the spurious error visibility at the cost of
   slow-path latency on contention.

2. (Strict / less code) Document the contract: LF-3 read ops can
   return STM_ECORRUPT under same-engine concurrent writer. Callers
   that need stability must retry. Less surgery but a worse API
   contract.

3. Wait for BE-prepend to land and skip the fallback entirely.

The LF-3d commit message defers this to R171's call. My
recommendation: ship the fallback uniformly across all wait-free read
entries. The cost is one branch per call; the gain is API stability.

Cite: see line numbers above; `v2/src/fs/fs.c:2076-2102` (stm_fs_read
fallback to compare).

### P1-2: Wait-free `stm_fs_listxattr`'s two-pass count→materialize is TOCTOU-fragile under same-engine writer

  `v2/src/fs/fs.c:5415-5445`

The listxattr port runs two passes through `stm_xattr_list_concurrent`:
first pass with `max_entries=0` to compute the count, second pass with
a malloc'd buffer of exactly that count. Both passes scan the engine.

A concurrent writer that adds or removes an xattr between the two
passes changes the count. The second pass with `max_entries = n_total`
returns `got != n_total` → the code at line 5441 returns STM_ECORRUPT.

This is a different failure mode from P0-1 (which is a UAF on the
value bytes during a single pass). P1-2 is a count-vs-materialize TOCTOU.

The same-engine writer race is acknowledged. The fix is similar to
P1-1: fall back to the serial path on count-mismatch (which can be
combined with the P1-1 fallback so the two-pass IS the wait-free
attempt and the SH-rdlock retry uses the single-pass `stm_xattr_list`).

**Fix sketch**: same as P1-1. The 2-pass shape is correct only when
the index is stable across calls.

Cite: `v2/src/fs/fs.c:5415-5445`.

### P1-3: LF-3 widens the public stm_fs_* contract without documenting the new caller obligation

The LF-3 ports collapse the prior implicit guarantee — "stm_fs_unmount /
stm_fs_mark_wedged / commit-failure-rollback exclude all in-flight
stm_fs_* calls via fs->global" — to "stm_fs_unmount and friends
exclude in-flight EX-takers and SH-takers, but NOT wait-free readers."

Callers that relied on the old contract (e.g. an in-process test
harness that calls unmount immediately after a reader on a different
thread) now have to add explicit reader-quiesce logic. Stratumd is
fine because its accept-loop shutdown drains workers before unmount.
But this is a non-obvious caller obligation that should be documented.

**Fix sketch**: extend `v2/include/stratum/fs.h`'s stm_fs_unmount
docstring AND the `stm_fs` global lock-hierarchy comment in fs.c (the
big block at fs.c:35-66) to enumerate the LF-3 contract. Likewise
update the CLAUDE.md scripture trust-list FS-trigger row.

The current fs.c comment at `v2/src/fs/fs.c:51-57` reads:

  "PARALLEL-3 impl-6 pure-read ops (stm_fs_read / stat / lookup / ...):
   take fs->global SH (rdlock) and NO ..."

This is OUT OF DATE. Post-LF-3 these ops take `fs->global` SH **OR**
the wait-free path with FS_GUARD_READ_LOCKLESS + EBR; the comment
should be updated.

Cite: `v2/src/fs/fs.c:35-66` (lock-hierarchy comment), `v2/include/stratum/fs.h`
(public docstrings).

### P1-4: `stm_fs_create_dataset` / `stm_fs_create_clone` race-window UAF on engine if dataset is destroyed mid-creation by another writer

This is a corollary of P0-2 in a narrower window. The
`stm_fs_create_dataset` rollback path calls `stm_dataset_destroy` on
its own freshly-created dataset. If a wait-free reader has called
`stm_fs_dataset_lookup` or similar against the dataset BEFORE its
rollback fires, the reader's engine pointer (obtained via a prior
read call) can land on freed memory.

In practice this only manifests if (a) a wait-free reader sees the
fresh dataset before create rolls back, AND (b) the reader still
holds the engine pointer when the rollback's `stm_dataset_destroy`
fires. The window is small because the rollback happens fast and the
fresh dataset is unlikely to be observed by other readers.

But the architectural issue is real: ANY path that destroys a dataset
or invalidates an engine assumes no wait-free reader is mid-call,
which LF-3 doesn't enforce.

Cite: `v2/src/fs/fs.c:6544`, `v2/src/fs/fs.c:6615`, `v2/src/fs/fs.c:6721`,
`v2/src/fs/fs.c:6742`, `v2/src/fs/fs.c:6759` (5 stm_dataset_destroy
sites in rollback paths).

## P2 (substantive)

### P2-1: `pthread_key_create` failure in `fs_ebr_key_init` is silently ignored

  `v2/src/fs/fs.c:300-308`

  ```c
  static void fs_ebr_key_init(void)
  {
      (void)pthread_key_create(&fs_ebr_key, fs_ebr_destructor);
  }
  ```

If `pthread_key_create` fails (rare but possible: process key limit
exceeded, OOM), the key remains uninitialized. Subsequent
`pthread_getspecific(fs_ebr_key)` on the uninitialized key is
undefined behavior (POSIX); on practice it returns NULL, then
`pthread_setspecific` returns EINVAL, then the handle is freed, then
the next call repeats — every wait-free read incurs a full
register/free pair (~500ns instead of ~5ns). The docstring at
fs.c:302-306 acknowledges this as "force every reader through ...
per call" but the actual behavior may also subtly mask the failure
mode if any compiler/libc returns an unset value or panics on
pthread_getspecific with a bad key.

**Fix sketch**: if `pthread_key_create` fails, propagate the failure
through to `stm_fs_mount` so the daemon refuses to start. The
graceful-degradation posture is harmful here — it converts a
catastrophic configuration failure into a silent perf-regression.

Cite: `v2/src/fs/fs.c:300-308`.

### P2-2: EBR `stm_ebr_shutdown` docstring claims panic-on-alive-threads but the impl frees them silently

  `v2/include/stratum/ebr.h:139-144`

  ```
  Teardown. Forces reclamation of all pending retires regardless of
  active readers (only safe at shutdown). Panics if any threads are
  still registered.
  ```

  `v2/src/ebr/ebr.c:331-356`

The implementation does NOT panic — it walks the threads list and
frees every entry (line 344-348). The docstring is wrong.

This is a docstring drift, not a soundness issue, but it matters
because callers reading the header may believe they have a safety
gate they don't. The actual behavior (silent free of alive threads)
is more permissive than the docstring; a future caller relying on the
documented panic would not be protected.

**Fix sketch**: either implement the panic (call `abort()` if any
alive thread is found) OR update the docstring to reflect the actual
"forces free of all threads regardless of state" behavior.

Cite: `v2/include/stratum/ebr.h:139-144` (docstring), `v2/src/ebr/ebr.c:331-356`
(impl).

### P2-3: `stm_fs_dataset_iter` callback runs under dataset_index's mutex; subsequent callback-internal lock could deadlock

  `v2/src/fs/fs.c:6880-6892`

The wait-free port keeps the contract — "callback MUST NOT call back
into any stm_fs_* API" — but the lock now held during the callback
is the dataset_index's internal mutex (taken inside
`stm_dataset_iter`), not `fs->global` SH. If a future callback calls
back into ANY API that takes `dataset_idx->lock`
(`stm_dataset_index_get_engine`, `stm_dataset_lookup`, etc.), it
deadlocks (the mutex is non-recursive). Even a callback that calls
`stm_fs_dataset_lookup` reentrantly would deadlock — the wait-free
port of `stm_fs_dataset_lookup` calls `stm_dataset_lookup` which
takes `dataset_idx->lock`.

The docstring at fs.c:6837-6842 calls out the deadlock risk in
general terms. Tighten to mention that the lock is the dataset_idx's
internal mutex specifically and enumerate the APIs that would
deadlock.

Cite: `v2/src/fs/fs.c:6837-6842` (docstring), `v2/src/dataset/dataset.c::stm_dataset_iter`.

### P2-4: `idx->ds_idx` read is not atomic; technically UB under the C11 memory model

  `v2/src/inode/inode.c:902-906` (and similarly dirent.c, xattr.c, extent_index.c)

  ```c
  stm_inode_index *midx = (stm_inode_index *)idx;
  /* ds_idx is set ONCE at attach + never rewritten — safe to read
   * without idx_lock (the same posture inode_lookup_at_root uses). */
  if (midx->ds_idx == NULL) return STM_EINVAL;
  ```

The `ds_idx` field is plain (non-atomic). It's set ONCE inside
`stm_inode_index_attach_dataset_index` under `idx->lock`
(`v2/src/inode/inode.c:581-588`). A wait-free reader's plain load
WITHOUT a happens-before edge to that store is technically UB under
the C11 memory model. In practice on x86_64 with an aligned 8-byte
pointer this load is benign, but TSan will flag it and a non-TSO
architecture (ARM64 weak memory) could see a stale value.

The mount-time sequence almost always establishes happens-before
implicitly (the attach happens before the mount returns; the reader
runs after mount returns). The pthread_create barrier when the reader
thread is created provides synchronization. So this is more of a
"clean it up" finding than a real bug — but it's an easy win to wrap
ds_idx in `_Atomic`.

Cite: `v2/src/inode/inode.c:902-906`, `v2/src/dirent/dirent.c:721-722`,
`v2/src/xattr/xattr.c:787-788`, `v2/src/extent/extent_index.c:2120-2121`.

### P2-5: LF-3 ports of admin-path read getters bypass the wedge gate entirely (stm_fs_verify, stm_fs_dataset_iter, stm_fs_dataset_count, stm_fs_dataset_lookup)

  `v2/src/fs/fs.c:6873-6884` (stm_fs_dataset_lookup), `:6886-6897`
  (stm_fs_dataset_count), `:6899-6906` (stm_fs_dataset_iter),
  `:9402-9410` (stm_fs_verify)

These four are commented "wedged-OK" and skip even
`FS_GUARD_READ_LOCKLESS`. The wedged-OK rationale is correct for
verify (it's an introspective scrub-like op) and is questionable for
dataset_lookup / dataset_count / dataset_iter — these report on the
dataset table whose consistency under a wedged fs is undefined. The
test `stm_fs_dataset_lookup` returning content from a wedged fs
exposes potentially-stale data to operator tooling.

Less severe: the bigger issue is that NONE of these have ANY
protection against `stm_fs_unmount` racing. They directly dereference
`fs->sync` to obtain the dataset_index — if unmount has run, `fs->sync`
is freed and the dereference UAFs.

**Fix sketch**: at minimum add FS_GUARD_READ_LOCKLESS to
dataset_lookup / count / iter (they're not wedged-OK like verify is).
For unmount safety, see P0-3.

Cite: as above.

### P2-6: `stm_fs_read`'s INLINE-branch torn-state check at `iv.si_data_len > STM_INODE_INLINE_MAX` returns STM_ECORRUPT without falling back

  `v2/src/fs/fs.c:2081-2084`

The commit message claims "the wait-free path returns STM_ECORRUPT
under race; the fallback re-reads through the serial idx-mutex path
and succeeds" — but the check at line 2081 returns STM_ECORRUPT
directly. The fallback only fires when `ls != STM_OK` (line 2076 +
2101). In practice this check is unreachable because
`in_validate_value` inside `stm_inode_lookup_concurrent` catches
identical inconsistency first and returns STM_ECORRUPT, falling
through. But the defense-in-depth check at line 2081 doesn't follow
the same fallback discipline.

**Fix sketch**: replace the bare `return STM_ECORRUPT` at line 2083
with `goto fallback;` and a `fallback:` label that jumps to the
SH-rdlock path at line 2107.

Cite: `v2/src/fs/fs.c:2076-2103`.

## P3 (light)

### P3-1: Docstring typo — "stm_fs_ebr_thread_current" vs actual name `fs_ebr_thread_current`

  `v2/src/fs/fs.c:280`

The comment at line 280 says "stm_fs_ebr_thread_current()" but the
function is `fs_ebr_thread_current` (no `stm_` prefix because it's
static). Minor.

### P3-2: `fs_ebr_destructor` lacks a NULL-check on `handle` (defense-in-depth)

  `v2/src/fs/fs.c:295-298`

POSIX guarantees the key destructor is only called with non-NULL
values, so the existing `if (handle)` check is sufficient. But the
`(void)pthread_key_create(&fs_ebr_key, fs_ebr_destructor)` return
being ignored AND the destructor being defensive together imply
"slightly belt-and-suspenders, slightly ignoring failure".

### P3-3: The "9.8-LF-3" atomic-wedged comment at struct stm_fs (fs.c:193-214) claims `stm_fs_unmount` sets the atomics under EX

The comment reads:

  "Writers (stm_fs_unmount / stm_fs_mark_wedged / commit-failure
   rollback) still hold fs->global EX when they set these..."

But `stm_fs_unmount` does NOT set `fs->wedged` or `fs->read_only`;
it only reads them. Only `stm_fs_mark_wedged` sets them. The comment
is misleading.

**Fix sketch**: rewrite to acknowledge that unmount doesn't transition
the flags; mark_wedged does.

Cite: `v2/src/fs/fs.c:193-214`, `v2/src/fs/fs.c:1378-1394` (unmount reads).

### P3-4: Forward-note in `stm_fs_alloc_stats_get` (fs.c:6917-6920) says "future concurrent-attach-mutation paths MUST EITHER add per-call refcounting on stm_alloc OR extend this wrapper to take the attach-table mutex" but the path is unguarded today

The current implementation reads `fs->sync` then calls
`stm_sync_alloc(fs->sync, device_id)` then `stm_alloc_stats_get(a, ...)`
all without any guard. If unmount fires, `fs->sync` is freed → UAF.

This is a P0-3 corollary; the forward-note is correct in spirit but
the present-day implementation already has the gap. The comment
should be updated to say "if unmount can race with this caller, UAF
follows; v1.0 trusts the caller to quiesce."

Cite: `v2/src/fs/fs.c:6913-6925`.

### P3-5: LF-3d test `lf3d_inline_read_thread` silently passes if the writer hasn't yet run an iteration

  `v2/tests/test_compound_ops_concurrent.c:1887-1915`

The test starts the chmod writer and the inline-read reader on
separate threads with no synchronization barrier. If the reader
completes all `LF3D_ITERATIONS` iterations before the writer makes
any progress, the test passes trivially without exercising the
race. With `LF3D_ITERATIONS = 200`, the per-iteration cost of stat
is microseconds, and the chmod writer's per-iteration cost includes
a btree insert + commit overhead — the reader can finish first under
load. A more rigorous test would use a barrier to start both threads
simultaneously and a checked iteration-counter assertion that BOTH
counters grew above some minimum during overlap. The current
shape "verifies the wait-free path works in the no-race case" more
than "exercises the race".

This is also true of `impl6_stat_reader_vs_chmod_writer_same_inode`
and the documented [[flake-per-inode-cfr-concurrent]]. The fact that
the test sometimes fails IS what catches the bug — but it would be
better to make the race deterministic and probabilistic.

**Fix sketch**: precede both thread launches with a `pthread_barrier_t`
and require both threads to do at least N iterations in lockstep
(checked-after-join) before declaring success.

### P3-6: The LF-2 engine docstring at `engine.c:199-211` is now stale

The docstring claims:

  "At LF-2 the serial and concurrent paths are mutually excluded by
   `fs->global`'s EX-vs-SH; they don't actually race."

This is no longer true post-LF-3 (and was already weakened by
PARALLEL-3 impl-1..5/6 putting writers on SH). The docstring should
be updated to reflect the LF-3 reality: writers and readers DO race
on the same engine; the race is bounded by the
[[flake-per-inode-cfr-concurrent]] symptom class until BE-prepend
lands.

Cite: `v2/src/btree_engine/engine.c:199-211`.

### P3-7: The wait-free `stm_fs_read` INLINE branch reads `iv.si_data_kind` from a stack-local copy but the comment claims it "serves from inode-value bytes directly (wait-free)"

  `v2/src/fs/fs.c:2060-2102`

The wording is slightly imprecise: the inode value is COPIED out of
the engine's leaf via `memcpy(&v, vbuf, IN_VAL_LEN)` in
`stm_inode_lookup_concurrent` (`inode.c:930`). The wait-free read
serves from the COPY, not the engine's leaf directly. This is
defensible (the copy is what protects against further mutations
in-place by a writer), but the comment "serves from inode-value bytes
directly" makes it sound like a zero-copy path which it isn't.

This is more documentation hygiene than soundness.

### P3-8: Two `LF3D_INLINE_LEN` vs `STM_INODE_INLINE_MAX` documentation inconsistency

  `v2/tests/test_compound_ops_concurrent.c:1565`

  ```c
  #define LF3D_INLINE_LEN         64u   /* < STM_INODE_INLINE_MAX (100) */
  ```

`STM_INODE_INLINE_MAX` is currently 100 bytes; the test correctly
stays below. Hardcoded magic constants in test comments tend to
drift; consider `_Static_assert(LF3D_INLINE_LEN < STM_INODE_INLINE_MAX,
"...")` to make the relationship explicit.

### P3-9: Stale "fs->lock" references in `fs_flush_drain_cb` / `fs_flush_ino_locked` / `fs_flush_all_locked` docstrings

The PARALLEL-3 ports updated some docstrings but earlier R136 P2-2
notes the same issue. With LF-3 widening the lock posture further,
worth a second pass to ensure every "Caller holds fs->lock" or
"Caller holds fs->global EX" comment reflects LF-3's SH+pin reality.
A grep for "Caller holds fs->global" / "Caller holds fs->lock" in
fs.c surfaces ~20-30 sites; not every one needs editing, but a
deliberate sweep is warranted as part of LF-3 close.

### P3-10: The `lf3d_listxattr_stable_vs_chmod_disjoint_inode` test seeds an xattr on the reader's inode via `stm_fs_setxattr` BEFORE launching the threads, but the writer also touches `stm_xattr_index` (when chmod stamps ctime, no xattr is touched, BUT a future chmod adding to atime cache or similar could)

Today this isn't a bug, just a brittle invariant: the test assumes
chmod doesn't touch the xattr index. If a future refactor links
chmod to xattr (e.g., POSIX ACL stamping), the test would falsely
pass while exercising a cross-engine race the comment claims it
avoids.

This is light P3 — a fragility note rather than an actual issue.

## Summary

Severity counts: P0=4, P1=4, P2=6, P3=10.

The LF-3 series introduces a wait-free reader path that delivers the
crown-jewel "1M stat/sec" target on disjoint workloads (which the
LF-3d tests validate cleanly). But it does so by stripping the
`fs->global` SH read-side lock without retrofitting the engine
substrate or the fs lifecycle for safe concurrent reader-vs-writer
operation. The result is **four distinct UAF surfaces** (P0-1 leaf
value, P0-2 engine struct on rollback, P0-3 fs+sync+indices on
unmount, P0-4 mvcc_root on commit_abort) that the existing LF-2
substrate forward-noted to "LF-BE-prepend" closure but that LF-3 now
makes reachable via concurrent execution.

The commit messages and engine docstring repeatedly claim the
exposure is "transient STM_ECORRUPT under contention". That framing
is incomplete. The leaf-value race is `free()`-then-`memcpy()` from
freed memory — undefined behavior, not just a torn-state observation.
The engine-handle and fs-lifetime races are similarly UAFs on freed
memory regions that the allocator may have reused for unrelated data
or unmapped entirely.

**Suggested triage**:

1. **Before declaring LF-3 "done" / shippable as crown-jewel**:
   - Decide on the BE-prepend timeline (issue #1218). The cleanest
     answer is "do not advertise LF-3 production-ready until
     BE-prepend lands". The P0-1 / P0-4 / P0-3 / P0-2 UAFs are all
     planned-closure items.
   - If LF-3 must ship before BE-prepend, BACK-PORT the SH-fallback
     pattern (P1-1) to every wait-free read entry so transient
     STM_ECORRUPT does NOT propagate to callers, and document the
     reader-quiesce-before-unmount obligation (P1-3).

2. **Soundness corrections that can land before BE-prepend**:
   - P0-3: add a `stm_fs_unmount` reader-quiesce step (atomic
     "draining" flag + EBR-advance-until-empty loop). This closes
     the unmount UAF without waiting for BE-prepend's writer model.
   - P0-2: route `dataset_engine_close_locked`'s `stm_btree_engine_destroy`
     through `stm_ebr_retire`. This closes the rollback / dataset
     destroy UAF without waiting for BE-prepend.

3. **Documentation that can land immediately**:
   - P1-3: update fs.h docstrings + fs.c lock-hierarchy comment for
     LF-3's regime.
   - P3-3, P3-6: correct the stale claims in fs.c:193-214 and
     engine.c:199-211.

4. **Test improvements**:
   - P3-5: make the LF-3d race tests deterministically race-y via
     pthread barriers.
   - Add a rollback-vs-stat race test (closes the gap on P0-2
     coverage).
   - Add an unmount-vs-stat race test under sanitizers (closes the
     gap on P0-3 coverage).

The R171 audit's bottom line: LF-3 ships a real wait-free path for
the read hot-path but the substrate underneath is not yet sound for
the racy regimes the wait-free path exposes. The path forward is
either to back-port the SH-fallback (a quick safety net) AND/OR to
close the engine-side and fs-lifecycle UAFs with EBR retirement
before BE-prepend lands. The crown-jewel framing should be tempered
until those gaps close.
