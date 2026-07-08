# CF-4 B — commit-path cost: barrier batching + clean-commit short-circuit

Status: DESIGN (scripture-first; ratified charter = Thylacine
`docs/CONCURRENT-FS.md` §CF-4, user vote 2026-07-05; the stage split into
CF-4 A [the AEAD hardware lever, LANDED] + CF-4 B [this doc] recorded
2026-07-08 in the same charter). This document is the Stratum-side
concretization: the barrier-defer window, the single staged bootstrap COW,
the clean-commit short-circuit, the crash matrix, and the invariants the
focused audit prosecutes.

Lineage: `phase-9.6-impl-4b-sync-wiring-design.md` §5 (the durable-bitmap
barrier + crash-case matrix this doc extends), R7a P2-1 (the bootstrap
dual-slot/self-csum fallback this doc leans on), R154 (failed-commit
wedge doctrine), quorum.tla (reservation/final two-phase), R176 F1
(#369, the rollback-orphan rider).

---

## 1. Charter (from the ratified arc plan)

As measured (CF4RT, 2026-07-08): every commit issues ~10+ fsyncs — the
reservation UB (1), each component commit's internal
`stm_bootstrap_commit` (2 each: bitmap slot + header slot), the explicit
4b-iii bootstrap barrier (2), the final UB (1). An EMPTY commit costs
~23-33 ms; the fsbench 39-files/s auto-fsync ceiling IS this cost.
Commits do NOT fire mid-go-build (Tfsync n=2 per build), so this is a
fsync-workload lever, not a build lever — framed honestly.

CF-4 B collapses the ~10 fsyncs to **2 per commit** (one pre-final-UB
data barrier + the final-UB barrier) and makes a **content-identical
commit near-free** (no device I/O at all). Three pieces:

1. **bdev barrier-defer window** — during phases 1+2 of
   `stm_sync_commit`, `stm_bdev_fsync`/`_fdatasync` on the pool's
   devices records "barrier pending" and returns STM_OK; one real fsync
   per device fires at the window close, strictly before the final UB
   write (whose own fsync stays real).
2. **single staged bootstrap COW** — the N per-component
   `stm_bootstrap_commit` calls inside one `stm_sync_commit` collapse to
   ONE slot-pair COW at the 4b-iii barrier point. Load-bearing for the
   defer window, not just a perf item (§4.2).
3. **top-level clean-commit short-circuit** — if the would-be final UB
   is content-identical to the last UB this session durably wrote, the
   commit returns STM_OK writing nothing and advancing no gens.

Plus the rider: **#369** (R176 F1) — the create/link rollback's
`(void)stm_inode_free` orphan gets recorded instead of silently dropped.

## 2. As-built ground truth (what changes, what doesn't)

- `stm_sync_commit` (src/sync/sync.c:2474): reservation UB write+fsync →
  keyschema commit → CAS auto-GC sweep → per-device `stm_alloc_commit`
  (each ends with `stm_bootstrap_commit` = 2 fsyncs, alloc.c:1320) →
  alloc-roots commit → M-engine cascade flush → dataset/snap/repair/cas
  index commits (the btree_store-backed ones call `stm_bootstrap_commit`
  internally) → merkle → explicit `stm_bootstrap_commit(boot,
  target_gen)` (the 4b-iii durable-bitmap barrier) → final UB write+fsync
  → engines finalize → publish.
- `stm_bootstrap_commit` (src/bootstrap/pool.c:813): three-phase — scan
  (compute new bitmap + sweep-eligible PENDING), I/O (write bitmap to the
  NON-live slot, fsync, write header gen+1 to the NON-live slot, fsync),
  finalize (promote in-RAM, swap live slots). The header carries
  `h_bitmap_csum` over the whole bitmap region (R7a P2-1).
- `stm_bootstrap_open` (pool.c:505): reads BOTH header slots,
  candidate list highest-gen-first, validates each candidate's bitmap
  against `h_bitmap_csum`, falls back to the other header on mismatch.
  **This fallback is what makes fsync-deferral sound**: a torn/unsynced
  (header, bitmap) pair is detected and the other pair mounts.
- `stm_sb_label_write` (src/sb/mount.c:39): UB slot write + per-call
  fsync. UBs are self-csummed (`ub_csum`, BLAKE3 over the block);
  `stm_sb_mount_scan` picks the highest valid gen across 4 labels × 63
  ring slots; a torn UB slot fails decode and is skipped.
- The 9.6-impl-4b §5.4 crash matrix is the baseline: every window today
  is corruption-free; two windows leak bounded node sets, reclaimed by
  the #791 mount-time mark-sweep reconcile.
- `stm_fs_commit` (src/fs/fs.c:1478) wedges the fs on any
  `stm_sync_commit` error (R154) — retry-after-failure is refused
  EWEDGED. Unchanged.
- Concurrency envelope: `stm_sync_commit` runs under `fs->global` EX
  (every fs-level caller) + `s->lock` + pool lock SH. No other thread
  issues fsyncs on the pool's devices while a commit is in flight
  (mount/format/device-ops/evac all serialize against commit via the
  same locks; the dirty-buffer flush + extent writes never fsync — their
  durability IS the commit). The defer window is therefore
  single-threaded state; the flags are C11 atomics anyway as
  belt-and-braces.

## 3. The barrier-defer window (piece 1)

New bdev-level API (src/block/bdev.c + bdev_internal.h):

```c
void       stm_bdev_barrier_defer_begin(stm_bdev *d);
stm_status stm_bdev_barrier_defer_end(stm_bdev *d);    /* fire if pending */
void       stm_bdev_barrier_defer_cancel(stm_bdev *d); /* clear, no I/O  */
```

While armed, `stm_bdev_fsync`/`stm_bdev_fdatasync` set
`d->barrier_pending = true` and return STM_OK without touching the
device. `_end` issues ONE real `ops->fsync` iff pending, then disarms.
`_cancel` disarms without I/O — correct on every commit error path
because nothing that could be *named* by a durable UB has been made
nameable (the final UB never landed; the auth state stands; the fs
wedges per R154 where an engine flushed).

`stm_sync_commit` arms the window on every non-NULL pool device right
after the RO/wedged/gen guards, and:

- on the clean-skip path: cancels (nothing was written);
- on every error path: cancels (via the single exit ladder);
- on the commit path: `_end` fires the ONE data barrier per device
  strictly AFTER the reservation UB write + the staged bootstrap COW +
  every phase-2 node write, and strictly BEFORE the final UB write.
  The final UB's own `stm_sb_label_write` fsync runs OUTSIDE the window
  (already disarmed) and stays real — the second barrier.

Nesting is refused (`assert`-class: begin on an armed device is a
programming error; there is exactly one arming site).

## 4. The single staged bootstrap COW (piece 2)

### 4.1 New bootstrap API (src/bootstrap/pool.c)

```c
void       stm_bootstrap_commit_defer_begin(stm_bootstrap *a);
stm_status stm_bootstrap_commit_defer_end(stm_bootstrap *a);   /* one real COW */
void       stm_bootstrap_commit_defer_cancel(stm_bootstrap *a);
```

While armed, `stm_bootstrap_commit(a, gen)` records
`max(deferred_gen, gen)` + `deferred_pending = true` and returns STM_OK
— no scan, no I/O, no in-RAM promotion. `_end` runs the REAL three-phase
commit once, at the recorded gen (its two internal fsyncs are no-ops
under the still-armed bdev window; the bdev barrier that follows makes
the pair durable). `_cancel` clears the mode; the in-RAM bitmap keeps
any bits set by phase-2 reserves (harmless: the wedge/remount reloads
from disk, and in-RAM-ahead-of-disk is today's posture between commits
anyway).

`stm_sync_commit` arms defer on device 0's shared bootstrap AND every
attached alloc's bootstrap (multi-device: each device's alloc owns its
own bootstrap; today all metadata trees ride device 0's).

### 4.2 Why single-COW is load-bearing, not just fewer fsyncs

The dual-slot scheme ping-pongs: each `stm_bootstrap_commit` writes the
NON-live slot pair and promotes it live. Two commits within one defer
window would write BOTH slot pairs — the second one scribbling the
PRE-COMMIT durable pair — with neither fsynced. A crash then can tear
both header slots → `stm_bootstrap_open` finds no valid candidate →
STM_ECORRUPT → **pool brick**. Deferring the fsyncs without collapsing
to one COW per window is therefore UNSOUND. With the collapse, the
window writes exactly one (non-live) pair; the pre-commit pair is never
touched; R7a's fallback covers every torn/partial outcome.

(Today's code is safe without the collapse only because each COW is
made durable before the next one overwrites the elder slot.)

### 4.3 The bootstrap clean short-circuit (the bitmap-unchanged case)

`stm_bootstrap` gains a monotone taint flag:

```c
atomic_bool dirty;   /* relaxed; set by mutators, cleared under commit */
```

Set at: `stm_bootstrap_reserve` (bit_set), `stm_bootstrap_reconcile_end`
when it clears orphan bits (#791), `stm_bootstrap_set_user_data`.
NOT set by `stm_bootstrap_free` — a PENDING append changes no durable
state this commit (the bits stay set on disk; the entry is in-RAM only;
its sweep at a LATER commit is what mutates the bitmap).

The real commit (both the plain path and `_defer_end`) short-circuits:

```
if (!dirty && no pending entry with free_gen < committed_gen)
    return STM_OK;            /* no scan, no COW, no gen advance */
```

Rationale: bitmap_gen exists solely as the dual-slot tiebreak; skipping
its advance for a byte-identical region is unobservable at load. Every
caller that today relies on "commit persists my reserves" set `dirty`
when it reserved.

Sweep composition (audit F2, honest form): the sweepable disjunct keeps
the R50 semantics only WITHIN a commit that reaches the bootstrap COW.
The TOP-LEVEL clean skip (§6) fires before the bootstrap stage — the
bootstrap bitmap is not named by any UB field — so a commit whose only
pending work is the BOOTSTRAP-tier sweep (the previous dirty commit's
node retires) is skipped: those bits stay conservatively SET (never
re-handed — the safe direction) until the next UB-dirty commit sweeps
them, or the next mount's #791 reconcile reclaims them. Delay-only,
bounded at one commit's retires, self-healing. The ALLOC-tier pending
sweep is different: it runs inside phase 2's alloc_commit, mutates the
alloc tree, changes the roots — so it always defeats the skip.

Relaxed atomics are sufficient: the flag is a monotone taint written by
mutators (all serialized against commit by `fs->global`), read+cleared
only inside the commit (exclusive).

## 5. The restructured stm_sync_commit

```
lock pool SH + s->lock; RO/wedged/gen-wrap guards
capture astats_res + build res_prototype     (unchanged content: pre-flush
                                              mirrors; write DEFERRED)
arm: bdev defer window on every pool device; bootstrap defer on every
     attached alloc's bootstrap
Phase 2 (unchanged order):
  keyschema commit → CAS auto-GC sweep → per-device alloc_commit loop
  (their internal stm_bootstrap_commit calls now RECORD instead of COW)
  → alloc_roots commit → engines flush → dataset/snap/repair/cas commits
  → stats + merkle
CLEAN CHECK (new; §6):
  build fin_prototype; if content-identical to s->last_fin_ub
  (mod ub_gen/ub_txg/ub_repair_log_root_gen):
      engines finalize (adopt the unchanged triples; closes the pending
      windows the flush opened)
      cancel bootstrap defers + bdev windows; unlock; return STM_OK
      — gens NOT advanced, NOTHING written, NOTHING fsynced
Phase 1' (moved): write reservation UB to all devices (fsyncs deferred)
                  [non-fresh pools only, as today]
Barrier: bootstrap defer_end on every armed bootstrap (the ONE staged
         COW each; fsyncs deferred) → bdev defer_end on every device
         (fsync #1 — THE data barrier)
Phase 3: write final UB to all devices (its per-device fsync is real —
         fsync #2) → engines finalize → publish + stash
         s->last_fin_ub = fin_prototype
Error paths: single exit ladder — engines abort where required (as
         today), bootstrap defer cancel, bdev window cancel, unlock,
         return (fs.c wedges per R154).
```

### 5.1 Why moving the reservation write is sound

The reservation UB's content is built from the pre-phase-2 mirrors
(`s->alloc_root_*` etc.), which phase 2 never mutates (publish happens
at the end) — the build stays where it is today; only the WRITE moves.
Under the defer window the reservation's durability point was already
"at the barrier", so writing it just before the barrier is the same
durable ordering: reservation durable-before final-UB durable
(quorum.tla's phase order), and a pre-barrier crash leaves it
whole-or-torn-or-absent — all safe, since its content equals the auth
UB's (gen bumped) and a torn slot fails `ub_csum` and is skipped by the
mount scan.

### 5.2 The crash matrix (extends 9.6-impl-4b §5.4)

At a crash, ANY SUBSET of the un-barriered writes may be durable
(devices reorder freely between barriers). Write classes in the window
and why every subset is safe:

| Class | Where | Safety argument |
|---|---|---|
| New tree/engine nodes | COW paddrs, bitmap-free at auth | Unreferenced by every durably-selectable UB; orphan bytes. 4b §5.4 case (a). |
| Reservation UB | ring slot at gen auth+1 | Self-csummed: torn → skipped; whole → content == auth's roots. Either way mounts the auth state. |
| Staged bitmap slot | the non-live slot | Inert until a valid header names it. |
| Staged header slot | the non-live slot, gen+1, csums the staged bitmap | Torn → csum-invalid → fallback to live pair. Whole + bitmap torn → `h_bitmap_csum` mismatch → fallback (R7a). Whole + bitmap whole → mounts new bitmap with old UB: freshly-flushed nodes SET-but-unreferenced (bounded leak, #791-reclaimed) + previously-swept PENDING bits cleared (safe: those nodes were superseded ≥2 commits ago; no durably-selectable UB references them — the mount scan always selects gen ≥ auth, and auth's trees don't use them). Same end state as today's crash-after-4b-iii window. |
| Final UB | ring slot at target_gen | Written only AFTER the barrier ⇒ everything above durable first (INV-1/INV-3). Torn → skipped → auth/reservation mounts (leak-only). Whole → full new state. |

**No corruption in any window; the leak windows are exactly today's,
reclaimed by #791.** The one NEW obligation vs today is INV-2 (§4.2):
at most one bootstrap COW per window, pre-commit pair untouched.

### 5.3 Invariants (the audit prosecutes these)

- **INV-1 (barrier order):** staged bootstrap pair + reservation UB +
  every phase-2 node write are durable strictly before the final UB
  write is issued. (The single data barrier; 4b case-A generalized.)
- **INV-2 (single COW):** within one defer window, at most one bootstrap
  slot-pair is written; the pre-window live pair is never written.
- **INV-3 (reservation order):** reservation durable-before final
  (quorum.tla two-phase preserved).
- **INV-4 (fail-closed):** every error exit cancels both defer layers
  without issuing barriers; gens unadvanced; the engine abort/finalize
  pairing is exactly today's; fs.c's R154 wedge doctrine unchanged.
- **INV-5 (clean-skip soundness):** the skip fires only when the
  would-be UB is content-identical (mod ub_gen/ub_txg/
  ub_repair_log_root_gen) to the last UB THIS SESSION durably wrote;
  a skipped commit performs zero device writes; gens do not advance;
  in-RAM auth state stays equal to durable state.
- **INV-6 (window containment):** no fsync suppressed outside
  `stm_sync_commit`'s own extent (armed after the guards, always
  disarmed before unlock on every path).

## 6. The top-level clean-commit short-circuit (piece 3)

`stm_sync` gains:

```c
stm_uberblock last_fin_ub;      /* device-0-normalized shared prototype  */
bool          have_last_fin_ub; /* false at open/create — first commit
                                   in a session never skips              */
```

Stashed after every successful commit (the fin_prototype, which is
device-normalized by construction: `build_uberblock(target_device_id=0)`
+ per-device fields overwritten only inside `write_ub_to_all_devices`).
At mount it starts invalid — reconstructing a comparable prototype from
a scanned UB (which carries some device's identity fields + possibly a
mount-claim gen) is avoidable complexity; one full commit per session is
the conservative cost.

The comparison masks exactly three fields, each justified:
- `ub_gen` / `ub_txg`: the monotone counters — differ by construction.
- `ub_repair_log_root_gen`: stamped `target_gen` unconditionally by the
  commit (super.h documents it as recorded "for symmetry ... and
  future-proofing"; plaintext nodes take no AEAD nonce from it). With
  the root paddr/csum/next_seq all compared unmasked, an unchanged
  repair log keeps its old gen valid.

Everything else — roots, csums, per-tree gens, next-ids, stats, roster
(+hash), redundancy, scrub state, keyschema header, merkle root, pool
serial — is compared byte-for-byte. Any phase-2 activity that changed
durable-relevant state changes one of these (trees: root csum; CAS
GC/PENDING sweeps: alloc tree → roots; device ops: roster; scrub:
scrub bytes) and defeats the skip — "sweeps mark dirty" falls out
structurally rather than by flag-plumbing.

Semantics change (deliberate, documented): a content-identical
`stm_sync_commit` no longer advances `auth_gen`/`current_gen` and no
longer writes a UB. The public contract — "on STM_OK everything
buffered/committed is durable" — is unchanged (it was already durable).
Tests that pin "+2 per commit call" get adjusted to assert durability/
content instead (they were pinning an implementation detail; the fs.c
double-commit comment's "gen advance by 2 per call" concern is about
UNCHANGED semantics for the dirty case, which holds — a reclaim
double-commit's second pass sweeps PENDING → mutates the alloc tree →
roots change → not clean → writes as today).

Known clean-skip interactions verified against every `stm_sync_commit`
caller:
- fs.c unlink reclaim double-commit: 2nd commit sweeps → dirty → writes.
- device add/replace/evac multi-commits: each persists a roster change →
  dirty → writes. A genuinely-idempotent resume re-commit that finds
  everything already durable skips — which is the CORRECT outcome for a
  resume path (durability already holds).
- snapshot/dataset ops: index trees change → dirty.
- scrub cursor pushes: scrub bytes differ → dirty.

The engine pending windows (`commit_flush` opens one per engine
unconditionally — 4b §5.4) are closed on the clean path by FINALIZE
(adopting the unchanged triples; abort would drop the resident memtree
= crash-equivalent, wrong for a no-op).

### 6.1 The per-engine clean cost (the chunk-11 O(resident) term)

As-built ground truth: `stm_dataset_index_commit_engines_flush`
(dataset.c:1918) has NO per-engine dirtiness skip — every PRESENT+OPEN
engine runs the full cycle (`commit_flush_locked` engine.c:2668; the
chunk-10-latched clone arm `commit_flush_clone` engine.c:2559: clone
resident root + shadow consolidate + flush_walk to quiescence +
count_dirty + commit_node; finalize retires the whole old clone via
EBR). A CLEAN tree's cycle produces an UNCHANGED root triple
(engine.c:2799 — a no-op commit keeps the root's prior gen; commit_node
no-ops clean nodes), so the TOP-LEVEL skip already fires for empty
commits: the engine term is pure CPU/memory churn (~24 ms + O(resident)
EBR churn at 500K resident keys — the chunk-11 datum), never extra I/O
and never a UB write.

Disposition: the barrier batching + top-level skip land first (the
ratified core — they zero the I/O). The per-engine skip is a WRONG-SKIP-
LOSES-ACKED-DATA hazard class (the R174-F1 lineage: skipping a flush
that had unflushed state commits a stale triple), so it lands only on a
provably-sound choke point (a single mutation counter covering funnel
prepends + deletes + the #367 mid-op mini-flush root swaps), measured
first via bench_commit's empty scenario on a resident tree. If the
post-landing empty-commit CPU still hurts and the choke point is clean,
it lands in this chunk; otherwise it is recorded as a named seam with
the measured number.

## 7. #369 — the create/link rollback orphan (R176 F1 rider)

The four `(void)stm_inode_free(...)` rollback sites in
`fs_create_inode_and_link` (fs.c:2687/2702/2727/2739) drop the free's
status; under a doubly-wedged engine (the only reachable trigger, via
CF-2d's EBUSY) the child inode leaks silently.

Ground truth rules out the repair-log route: `stm_repair_log_entry`
(repair_log.h:94) is replica-rewrite-shaped — paddr pair + replica
indices, NO dataset/inode fields — and `stm_repair_log_index_emit`
validates `target_replica_idx != source_replica_idx`. Carrying an
orphan-inode event would need a new record kind (a format-bearing
extension) plus a scrub consumer for it — disproportionate for a
wedged-only leak the R176 disposition already rated leak-not-corruption.

Fix (this chunk): a shared `fs_rollback_inode_free()` helper replaces
the four `(void)` casts — it CHECKS the rollback status and, on
failure, emits a loud one-line diagnostic to stderr naming
(dataset_id, child_ino, status) — durable-visible for the daemon's
lifetime since #370 (the joey stderr drainer). The orphan is thereby
surfaced + operator-actionable instead of silent. The future
orphan-record kind (repair-log record v2 + scrub reclaim) is recorded
as a named seam here and in cf-2-design.md §6b.

## 8. What this does NOT change

- The commit protocol's PHASES and their content (reservation content,
  phase-2 order, merkle inputs, finalize/abort pairing) are byte-level
  unchanged; only WHERE durability barriers fire moves.
- No on-disk format change: same UB layout, same bootstrap header/slot
  scheme, same ring arithmetic. (The clean-skip changes WHEN a UB is
  written, never its bytes.)
- `stm_fs_commit`'s wedge doctrine (R154), the dirty-buffer flush, the
  unlink reclaim double-commit shape, quorum thresholds, FAULTED/REMOVED
  device skips: unchanged.
- Mount/format/mkfs paths: `stm_bootstrap_commit` outside a defer window
  behaves exactly as today (modulo the clean short-circuit, which no
  format-time caller hits — a fresh bootstrap is always dirty).

## 9. Test plan

- **Durability sweep over the NEW ordering**: fault-injection at every
  barrier point (crash after phase-2 writes pre-barrier; after barrier
  pre-final-UB; after final UB pre-finalize; torn staged header; torn
  staged bitmap; torn reservation; torn final UB) — each must remount to
  a consistent state per the §5.2 matrix. Reuses the existing
  crash-injection harness.
- **Single-COW proof**: a commit with multiple dirty components performs
  exactly one bootstrap slot-pair write (counters on the bdev write path
  in the test harness); the pre-commit live pair's bytes are untouched
  within the window.
- **Barrier-count proof**: a dirty commit issues exactly 2 real fsyncs
  per device; a clean commit issues 0 and writes 0 bytes.
- **Clean-skip semantics**: commit(); commit() — second returns STM_OK,
  gens unchanged, no I/O; remount sees the first commit's state.
  Dirty-clean-dirty interleavings; the unlink double-commit still
  reclaims (ENOSPC regression stays green); scrub-cursor pushes still
  persist; device-op commits still persist roster changes.
- **#369**: injected rollback-free failure emits the orphan record
  (or the documented-seam disposition's assertion).
- **bench_commit / fsbench**: before/after numbers recorded (the
  39-files/s ceiling is the headline).
- Full host suite + the Thylacine in-guest boot gate (stratumd serves
  the system pool; boot OK + suite + login E2E) before commit.
