# CF-4 C — commit-path cost: deferred block reclaim + reclaim-on-ENOSPC

Status: DESIGN (scripture-first). Charter = Thylacine `docs/CONCURRENT-FS.md`
§CF-4 ("commit-path cost -- Area G's designed follow-ups"), the third
commit-path lever after CF-4 A (the AEAD hardware lever) and CF-4 B (barrier
batching + clean-commit skip). Fixes Thylacine #374 (the go-build `$WORK`
cleanup pays a per-unlink reclaim double-commit -- 3.2 s/build). User-approved
direction 2026-07-08 (Option A of three; the measurement refuted the task's
"dirent sweep" premise). This document is the Stratum-side concretization:
the deferral, the reserve-path reclaim-on-ENOSPC backstop, the crash-safety
and availability analysis, and the invariants the focused audit prosecutes.

Lineage: SWISS-4q P2 (the per-unlink reclaim double-commit this doc removes),
R50 P2-1 (the strict-less-than sweep predicate -- the crash-safety invariant
this doc PRESERVES untouched), R128 P1-1/P1-2 + R130 (the reclaim helper +
its gating this doc reuses), R154 (failed-commit wedge doctrine), #791
(mount reconcile rebuilds `pending_head` -- the property that makes deferral
crash-safe), cf-4-design.md (CF-4 B: the clean-commit skip these reclaim
commits deliberately defeat via the alloc-tier sweep).

---

## 1. The finding (measured)

Thylacine #374 recorded the symptom as "14.6 ms per unlinkat x 222 = 3.2 s per
go build" and attributed it to "the serial dirent-unlink sweep holds serial_mu
for the whole walk" (the #39/#40 dirent-index family). **The measurement
refutes that.** `bench_create_many` CHURN mode, extended to time + attribute
the unlink phase, on the same host, two file shapes:

| file shape                     | unlink cost   | gen_delta (222 unlinks) |
|--------------------------------|---------------|-------------------------|
| INLINE (<=100 B, in the inode) | 8.84 us/file  | 0                       |
| EXTENT (>100 B, real blocks)   | 47,000 us/file| 888  (= 4 x 222)        |

The dirent-index tombstone -- the thing the task blamed -- is the *cheap*
8.84 us inline case. The cost appears only when a file owns real disk blocks,
and `gen_delta = 4 per unlink` is the tell: each `stm_sync_commit` advances the
generation counter by 2, so **two full commits fire on every extent-file
unlink**. That is the SWISS-4q reclaim (`fs_post_inode_free_reclaim_locked`
in `src/fs/fs.c`) firing an eager **double-commit** to hand the freed blocks
back immediately. 222 extent unlinks at go-build exit = **444 commits**, none
of which the build asked for (CF-4 A measured the whole build at 2 fsyncs).

### 1.1 Why it is a *double*-commit

An extent unlink frees the file's blocks. The free marks each block PENDING
(logically freed, awaiting the sweep that physically returns it to the free
pool) and stamps it with `free_gen = current_gen` -- call it G
(`sync.c::sync_drop_paddr_locked`, `stm_alloc_free`). The sweep that reclaims
PENDING runs inside `stm_alloc_commit` and uses a **strict** predicate:
reclaim only if `free_gen < committed_gen`.

The strictness is a crash-safety invariant (R50 P2-1): a block freed in
generation G is safe to physically reuse only once a generation >= G is
*durable on disk*. Otherwise a crash could roll back to a tree that still
references the block after it has been overwritten with new data -- silent
corruption. **This predicate is load-bearing and CF-4 C does not touch it.**

So to reclaim a `free_gen = G` block within the same session you need two
commits: commit #1 at gen G makes the freeing tree durable (its sweep does
not fire -- G is not `< G`); commit #2 at gen G+2 has `G < G+2`, so the sweep
reclaims. That is the double-commit, and today it fires per unlink.

---

## 2. The current reclaim story (the reframing)

The eager double-commit is NOT the norm in Stratum -- it is the inconsistent
special case. Grep of the freeing paths:

| freeing path                       | reclaim today            |
|------------------------------------|--------------------------|
| unlink (`fs_unlink_inode_and_dirent`) | eager double-commit   |
| `stm_fs_unlink_anon`               | eager double-commit      |
| `stm_fs_rename` overwrite branch   | eager double-commit      |
| `stm_fs_truncate` (shrink)         | **none** -- PENDING, next commit sweeps |
| write overwrite (COW old blocks)   | **none** -- PENDING, next commit sweeps |

Truncate-shrink and COW-overwrite -- both extremely common -- **already** leave
blocks PENDING and reclaim lazily at the next commit. Only the three
inode-*free* paths eager-commit. And critically: **there is no
reclaim-on-ENOSPC backstop anywhere today.** The only ENOSPC handling in
`fs.c` is the dirty-BUFFER-cap retry (`fs.c` ~2041, flushes the buffer to make
*buffer* room -- not allocator room).

Two consequences:

1. The availability guarantee the eager reclaim buys ("write to full, delete,
   rewrite in one session with no commit between -> the space is there";
   user-reported 2026-05-10 "copy 1.8 GB, delete, repeat -> ENOSPC after one
   cycle") is provided **only for the unlink pattern**. The identical pattern
   with truncate-to-0 or repeated in-place overwrite on a near-full,
   no-commit pool is a **latent ENOSPC gap today** -- it has no backstop.

2. Making unlink deferred (Option A) *aligns* it with truncate and overwrite.
   Adding a reserve-path reclaim-on-ENOSPC backstop makes the guarantee
   **uniform** across all three freeing paths AND closes the latent gap. So
   CF-4 C is a net improvement in consistency and robustness, not merely a
   perf trade.

The reclaim is safely deferrable: PENDING blocks are already crash-safe. On a
crash, mount reconcile (#791) rebuilds `pending_head` from the on-disk
refcount=0 entries, and any later commit's sweep reclaims them. Deferring only
changes *when* blocks return to the free pool -- the same "delay-only,
bounded" class CF-4 B's audit already dispositioned (F2/F3). And the unlink
not committing is POSIX-correct: unlink is not durable without fsync, and
every *other* mutation (write/create/rename) is already lazy-durable. Unlink
is the odd one out; deferring it aligns it with the filesystem.

---

## 3. Prior art (SOTA COW filesystems)

Deferred reclaim + reclaim-under-pressure is the COW-filesystem *norm*; the
eager per-unlink double-commit is the outlier. The crash-safety invariant
Stratum enforces (`free_gen < committed_gen`) is itself what each of these
enforces under a different name.

- **Btrfs** -- the tightest match. Freeing an extent inside a running
  transaction *pins* it (does not return it to free space) until that
  transaction commits, because the pre-free tree still references it until the
  commit lands -- Stratum's PENDING / `free_gen < committed_gen` almost
  one-to-one. The freeing work is queued as *delayed refs* and run at commit,
  not synchronously at unlink. And the ENOSPC handler (`flush_space`)
  escalates through flushing delayed refs up to `COMMIT_TRANS` -- it commits
  the transaction to unpin freed space and retries before returning ENOSPC.
  That is exactly CF-4 C's reserve-path reclaim-on-ENOSPC backstop. Both
  halves of Option A are Btrfs's model.
- **ZFS** -- freed blocks in a txg are not reusable until that txg syncs, and
  the `ms_defer` deferred-free trees hold freed space across ~2 txgs to guard
  the not-yet-fully-synced window -- the near-exact analog of needing UB-gen-G
  durable (commit #1) before a sweep at G+2 (commit #2). `feature@async_destroy`
  makes large deletes a background process (`zpool get freeing` drains
  gradually) -- the same "delete is cheap, reclaim is deferred, PENDING is
  visible in stats longer" shape. (It is why `df` "lies" right after a big
  `rm` on ZFS.)
- **WAFL (NetApp)** -- the origin: a block freed within a consistency point is
  unavailable until that CP completes on disk. Same invariant, same
  "deletes are metadata-cheap, space returns at the checkpoint."
- **bcachefs** -- the analogous thing at bucket granularity: a bucket's
  generation gates reuse and the allocator waits on journal commit before
  handing it back.

The honest distinction: in Btrfs and ZFS the deferred reclaim is folded into
the *normal* transaction/txg machinery -- there is no dedicated extra commit;
pinned/deferred space is swept as a side-effect of the next commit. Stratum
today instead pays two *dedicated* commits per unlink. CF-4 C realigns Stratum
with the Btrfs/ZFS model: **reclaim rides the commit that was going to happen
anyway, with a dedicated reclaim pass only under ENOSPC pressure.**

---

## 4. The design

Two changes, both in `src/fs/fs.c` (Stratum-side; the Thylacine kernel is
byte-unchanged).

### 4.1 Defer the reclaim (remove the eager double-commit)

Delete the `fs_post_inode_free_reclaim_locked` call from the three inode-free
sites: `fs_unlink_inode_and_dirent` (canonical unlink/rmdir),
`stm_fs_unlink_anon` (orphan free), and `stm_fs_rename`'s overwrite branch.
Each still runs `fs_pre_inode_free_cleanup_locked` (drop the dirty-buffer
entry + truncate extents to PENDING) and frees the inode -- it just no longer
commits. The freed blocks return to FREE via one of two paths (4.3).

The `cleanup_did_truncate` signal and the `needs_wedge` machinery at those
sites collapse away (there is no per-unlink commit to fail). The helpers
`fs_pre_inode_free_cleanup_locked` (drop-buffer + truncate) and
`fs_post_inode_free_reclaim_locked` (the double-commit) are RETAINED --
`_pre` still runs at every free; `_post` is repurposed as the reclaim-on-ENOSPC
body (4.2).

### 4.2 Reclaim-on-ENOSPC at the reserve path (the backstop)

Add, at each data-reserve site, an on-ENOSPC reclaim-then-retry:

```
rc = <reserve-bearing call>;
if (rc == STM_ENOSPC && stm_sync_pending_free_blocks(fs->sync) > 0) {
    /* Sweep the deferred PENDING via the double-commit, then retry once.
     * fs_post_inode_free_reclaim_locked returns true iff a commit failed
     * (crash-equivalent -> wedge, R154). Gate + retry-once = no livelock:
     * the reclaim consumes the pending, so a still-ENOSPC retry is a
     * genuinely-full pool -> return STM_ENOSPC. */
    if (fs_post_inode_free_reclaim_locked(fs)) { should_wedge; rc kept ENOSPC; }
    else rc = <retry the reserve-bearing call once>;
}
```

New accessor `stm_sync_pending_free_blocks(s)` (sync.c) sums the O(1)
`stm_alloc_pending_blocks(a)` across attached allocs -- a cheap gate so a
genuinely-full pool (no reclaimable PENDING) does not fire pointless commits
or livelock. The gate is the loop-freedom guarantee: the reclaim's second
commit sweeps every `free_gen < committed_gen` block, driving pending toward 0;
retry-once caps the recursion regardless.

**Reserve choke points covered** (the reserve-bearing sites from the fs.c
survey, all under `fs->global`; the reclaim's `stm_sync_commit` takes only
`s->lock`, so there is no fs->global reentrancy):

- `fs_write_covering_split_locked` -- the single choke for BOTH direct writes
  AND the dirty-buffer flush drain (the go-build + availability surface;
  ~99% of reserve traffic).
- the two INLINE->EXTENT transitions (`fs_write_regular_locked`,
  `stm_fs_truncate`) -- direct `stm_sync_write_extent` calls not via the split.
- `stm_fs_reflink`, `stm_fs_migrate_to_cold`, `stm_fs_promote_to_hot` -- the
  rare reserve-bearing ops (each pre-flushes through `fs_flush_ino_locked`,
  which is itself covered, and then reserves through its own sync call).

Firing the reclaim commit mid-flush is safe: `stm_sync_commit` does not touch
the fs dirty buffer (it stays buffered) and does not re-enter the flush; it
persists the extents written so far + sweeps PENDING; the reserve then retries
into the freed space. The persisted partial-flush state is a valid
intermediate (identical to any interrupted flush + commit); un-flushed
buffered ranges lost on a crash are un-fsync'd writes with no durability
guarantee (POSIX).

### 4.3 How freed blocks return to FREE (after 4.1)

1. **Lazily** -- any later `stm_sync_commit` (a client fsync, an unmount, the
   next build's commit) advances the generation, and its `alloc_commit` sweep
   reclaims all accumulated PENDING with `free_gen < committed_gen` in one
   pass. Free, because it rides a commit that was happening anyway. (Note: a
   single natural commit at gen G+2 sweeps a batch stamped `free_gen <= G`; a
   batch freed at the *current* uncommitted gen needs the next-plus-one
   commit, exactly as the eager path needed two.)
2. **On demand** -- 4.2's reclaim-on-ENOSPC, when an allocation would
   otherwise fail with reclaimable PENDING present.

For the go-build `$WORK` cleanup (222 extent unlinks at process exit, no
re-allocation after): **444 commits -> 0** -- the blocks reclaim at whatever
commit naturally follows, or are simply never needed. The write/rm/rewrite
near-full case pays exactly 2 commits, on demand, when the rewrite needs the
space -- instead of 444 eagerly.

---

## 5. Invariants (the audit prosecutes these)

- **INV-1 (crash-safety unchanged).** The strict-less-than sweep predicate
  (R50 P2-1) is byte-unchanged; PENDING blocks stay crash-safe (durable as
  refcount=0 after any commit; #791 mount reconcile rebuilds `pending_head`;
  a later commit's sweep reclaims). No freed block is physically reused before
  a generation >= its `free_gen` is durable. Deferral changes reclaim TIMING
  only, never the set of states reachable after a crash beyond the bounded
  "PENDING persists longer" delay.
- **INV-2 (availability preserved + made uniform).** Any reserve that would
  return STM_ENOSPC with reclaimable PENDING present first reclaims and
  retries. The "freed space is reusable within a session" guarantee now holds
  identically for unlink, truncate-shrink, and overwrite (was: unlink only) --
  and the truncate/overwrite latent ENOSPC gap is closed.
- **INV-3 (loop-freedom).** Reclaim-on-ENOSPC fires at most once per reserve:
  gated on `pending_free_blocks > 0` and retried exactly once. A still-ENOSPC
  retry returns STM_ENOSPC (a genuinely-full pool).
- **INV-4 (wedge correctness).** A failed reclaim commit is crash-equivalent
  (CF-4 B/R154: the engine three-phase abort drops the in-memory tree) ->
  the fs wedges, deferred past the fs->global unlock
  (`stm_fs_mark_wedged` takes fs->global). Reuses the existing
  `fs_post_inode_free_reclaim_locked` wedge signal verbatim.
- **INV-5 (durability semantics, deliberate).** unlink / rename-overwrite no
  longer commit, so they are no longer durable-without-fsync and no longer
  advance the generation counter -- consistent with CF-4 B's "gen-age =
  real-commit count" and with every other lazy-durable mutation. Freed space
  is visible in `stm_fs_stats.data_pending_blocks` longer (the ZFS `freeing`
  shape). Documented; POSIX-correct.

---

## 6. What this does NOT change

- The `free_gen < committed_gen` sweep predicate (R50 P2-1) -- untouched.
- The crash-safety of PENDING (#791 mount reconcile) -- untouched.
- The dirent-index tombstone path (the cheap 8.84 us part) -- untouched.
- Any 9P wire format, on-disk format, or ABI -- none. (`stm_sync_pending_
  free_blocks` + `stm_alloc_pending_blocks` are new in-process read-only
  accessors.)
- The eager reclaim helper `fs_post_inode_free_reclaim_locked` -- retained,
  repurposed as the reclaim-on-ENOSPC body.
- CF-4 B's clean-commit skip -- the reclaim commits deliberately defeat it
  (the alloc-tier sweep mutates the alloc tree -> the roots change -> the UB
  prototype differs -> not clean; the F2 disposition explicitly covers this).

---

## 7. Test plan

New + updated tests (`tests/test_fs.c`, `tests/bench_create_many.c`):

- **Availability regression (NEW -- the gap this fills).** Fill a small pool
  near-full with extent files, unlink them (no explicit commit), then
  reallocate the same volume -- MUST succeed via reclaim-on-ENOSPC. Plus the
  two variants that had no test and were latent gaps: truncate-to-0-then-
  rewrite and overwrite-churn-then-rewrite. Non-vacuous: without 4.2 the
  reallocation returns STM_ENOSPC.
- **Deferred-reclaim proof (NEW).** Unlink an extent file; assert the
  generation counter did NOT advance (no eager commit) AND
  `data_pending_blocks > 0`. Then `stm_fs_commit` twice; assert the blocks
  reached FREE (`data_pending_blocks` back to 0).
- **Loop-freedom (NEW).** A genuinely-full pool with no PENDING returns
  STM_ENOSPC without hanging (the gate short-circuits; the reclaim never
  fires).
- **bench_create_many CHURN** -- before/after the extent-unlink collapse
  (47 ms/file -> the inline-class cost) + `gen_delta` back to ~0 for the
  unlink batch.
- **Crash sweeps unchanged** -- `test_durability` + `test_crash_inject` must
  pass over the new ordering (no eager commit at unlink; the reclaim-on-ENOSPC
  commits are ordinary commits under CF-4 B's audited barrier discipline).
- **Updated** -- any test that pinned "unlink advances gen by 4" or "unlink is
  durable immediately" is corrected to the new contract (the CF-4 B precedent:
  gen-age = real-commit count).

---

## 8. Rollout

Scripture commit (this doc) first, no code. Then the impl commit
(the 3 deferrals + the reserve-path backstop + the accessor + tests),
referencing this doc's SHA. Then the focused audit (Opus 4.8 max -- Fable
quota out; the reviewer-model fallback), the full host suite (incl. the crash
sweeps), the before/after bench, and -- since the Thylacine kernel is
byte-unchanged -- NO SMP gate is owed (a boot-OK + suite confirmation only).
