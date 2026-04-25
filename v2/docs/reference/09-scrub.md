# 09 — Scrub (P5-5-α + β)

## Purpose

Background integrity sweep per ARCHITECTURE §7.14, §7.15, §12.7.
Two verify modes:

- **α-fallback** (default; no cb): iterates each pool device's
  alloc tree, reads every allocated block, counts I/O failures.
  No repair attempted.
- **β cb-mode** (`stm_scrub_set_verify_cb` installed): per-block
  outcome is delegated to the caller's verify-callback, which
  encapsulates the bptr-aware redundancy iteration (read each
  replica, verify, rewrite the corrupted device, verify the
  writeback). The cb returns `OK` / `REPAIRED` / `UNREPAIRABLE`;
  scrub charges the matching counter.

The β cb-shape is the integration point for the future P6 extent
manager: P6's bptr layer will plug a real cb that walks the
replica list, picks a verified replica, and rewrites the bad
device per ARCH §7.15. Tests today pass stub callbacks.

No durable cursor (γ), no IO throttling (future).

State machine lives entirely in RAM. Operators drive steps
manually; a step processes one allocated range at a time.

Intended audience: admin-invoked `stratum pool scrub tank` (future
CLI surface) + test harnesses validating that integrity-check paths
work end-to-end before data-loss scenarios are simulated.

## State machine

```
             ┌─────────┐
             │  IDLE   │ ◀─ stm_scrub_reset ──┐
             └────┬────┘                      │
                  │ stm_scrub_start           │
                  ▼                           │
             ┌─────────┐                      │
         ┌── │ RUNNING │                      │
         │   └──┬──────┘                      │
   step  │      │ pause                       │
  drains │      ▼                             │
  cursor │   ┌─────────┐                      │
         │   │ PAUSED  │                      │
         │   └──┬──────┘                      │
         │      │ resume                      │
         │      ▼                             │
         │    back to RUNNING                 │
         │                                    │
         ▼                                    │
       ┌──────────┐    stm_scrub_start ──▶ RUNNING  (restart)
       │COMPLETED │ ──────────────────────────┤
       └──────────┘ ────────────────────────  │
                                              │
                    stm_scrub_reset ──────────┘
```

Transitions (scrub.tla actions):

| Impl call | Spec action | From → To | Counters |
|---|---|---|---|
| `stm_scrub_start` | `Start` | IDLE → RUNNING | all zeroed |
| `stm_scrub_start` | `Restart` | COMPLETED → RUNNING | all zeroed |
| `stm_scrub_pause` | `Pause` | RUNNING → PAUSED | preserved |
| `stm_scrub_resume` | `Resume` | PAUSED → RUNNING | preserved |
| `stm_scrub_reset` | `Reset` | COMPLETED → IDLE | all zeroed |
| `stm_scrub_step` α / read OK | `StepClean` | RUNNING → RUNNING | `blocks_verified++` |
| `stm_scrub_step` α / read fail | `StepCorrupt` | RUNNING → RUNNING | `blocks_failed++` |
| `stm_scrub_step` β / cb returns OK | `StepClean` | RUNNING → RUNNING | `blocks_verified++` |
| `stm_scrub_step` β / cb returns REPAIRED | `StepRepaired` | RUNNING → RUNNING | `blocks_repaired++` |
| `stm_scrub_step` β / cb returns UNREPAIRABLE | `StepUnrepairable` | RUNNING → RUNNING | `blocks_unrepairable++` |
| `stm_scrub_step` (cursor drained) | `Complete` | RUNNING → COMPLETED | preserved |

Cursor: `(cursor_device_id, cursor_start_block)`. Inclusive lower
bound within the current device. After processing a range at `(dev,
start, length)`, cursor advances to `(dev, start + length)`. When a
device has no further live entries at or above `cursor_start_block`,
cursor advances to `(dev + 1, 0)`. When `cursor_device_id >=
device_count`, state flips to COMPLETED.

## Public API

```c
typedef enum {
    STM_SCRUB_STATE_IDLE      = 0,
    STM_SCRUB_STATE_RUNNING   = 1,
    STM_SCRUB_STATE_PAUSED    = 2,
    STM_SCRUB_STATE_COMPLETED = 3,
} stm_scrub_state;

/* β cb return value. */
typedef enum {
    STM_SCRUB_VERIFY_OK            = 0,
    STM_SCRUB_VERIFY_REPAIRED      = 1,
    STM_SCRUB_VERIFY_UNREPAIRABLE  = 2,
} stm_scrub_verify_outcome;

typedef stm_scrub_verify_outcome (*stm_scrub_verify_cb)(uint64_t paddr,
                                                          void    *ctx);

typedef struct {
    stm_scrub_state state;
    uint16_t        cursor_device_id;
    uint64_t        cursor_start_block;
    uint64_t        blocks_verified;
    uint64_t        blocks_failed;          // α-mode only; β leaves at 0
    uint64_t        blocks_repaired;        // β-mode only; α leaves at 0
    uint64_t        blocks_unrepairable;    // β-mode only; α leaves at 0
    uint64_t        ranges_processed;
} stm_scrub_status;

stm_status stm_scrub_create  (stm_sync *sync, stm_scrub **out);
void       stm_scrub_close   (stm_scrub *sc);

stm_status stm_scrub_start   (stm_scrub *sc);    // IDLE|COMPLETED → RUNNING
stm_status stm_scrub_pause   (stm_scrub *sc);    // RUNNING → PAUSED
stm_status stm_scrub_resume  (stm_scrub *sc);    // PAUSED → RUNNING
stm_status stm_scrub_reset   (stm_scrub *sc);    // COMPLETED → IDLE

stm_status stm_scrub_step    (stm_scrub *sc);     // process one range
stm_status stm_scrub_status_get(const stm_scrub *sc, stm_scrub_status *out);

/* β: install (or clear with cb=NULL,ctx=NULL) the verify-callback. */
stm_status stm_scrub_set_verify_cb(stm_scrub          *sc,
                                     stm_scrub_verify_cb cb,
                                     void               *ctx);
```

State-guard refusals:

- `start` refuses RUNNING, PAUSED → `STM_EINVAL`.
- `pause` refuses IDLE, PAUSED, COMPLETED → `STM_EINVAL`.
- `resume` refuses IDLE, RUNNING, COMPLETED → `STM_EINVAL`.
- `reset` refuses IDLE, RUNNING, PAUSED → `STM_EINVAL`.
- `step` on non-RUNNING is a no-op returning `STM_OK`.
- `status_get` is always safe.
- `set_verify_cb` rejects `cb=NULL,ctx!=NULL` (suspicious shape) →
  `STM_EINVAL`. Refuses RUNNING / PAUSED → `STM_EINVAL` (cb mode is
  frozen for the duration of a Start...Complete run so spec's
  `CallbackSetExclusivity` holds end-to-end). Valid in IDLE /
  COMPLETED. Install BEFORE `_start`, or between `_reset` and
  next `_start`, or in COMPLETED before `_start` (Restart) /
  `_reset`. To free ctx mid-run without first reaching COMPLETED,
  call `stm_scrub_close` (scrub never references ctx after close).

Thread safety: internal `pthread_mutex_t` serializes every API.

### Callback contract (β)

- The cb is invoked once per allocated block, in cursor order, under
  `sc->lock + pool->rdlock`. The cb must NOT call back into
  `stm_scrub_*` on the same handle (deadlock on `sc->lock`) and must
  NOT call APIs that acquire pool's wrlock (would block forever — we
  hold the rdlock).
- `paddr` is the encoded `(device_id, block_offset)` of the current
  block, suitable for plugging into the bptr layer.
- The cb classifies into `OK` / `REPAIRED` / `UNREPAIRABLE`:
  - `OK` ⇒ block read + verified clean. Identical to α `StepClean`.
  - `REPAIRED` ⇒ block was bad; cb has rewritten the corrupted
    device's copy from a verified replica AND verified the writeback
    (per ARCH §7.15.3). The cb is responsible for the repair-log
    entry (ARCH §7.15.4) before returning.
  - `UNREPAIRABLE` ⇒ block was bad; no surviving replica usable. Block
    left as-is on disk; ARCH §7.16.2 governs subsequent reads.
- Any other return value is treated defensively as `UNREPAIRABLE` so
  cursor still advances and `CallbackSetExclusivity` (failed = 0)
  holds. A misbehaving cb is the caller's bug; scrub never charges
  to `blocks_failed` in cb-mode.

## Implementation

`src/scrub/scrub.c` (~340 lines).

### Handle layout

```c
struct stm_scrub {
    pthread_mutex_t     lock;
    stm_sync           *sync;                // borrowed
    stm_pool           *pool;                // cached at create
    stm_scrub_state     state;
    uint16_t            cursor_device_id;
    uint64_t            cursor_start_block;
    uint64_t            blocks_verified;
    uint64_t            blocks_failed;
    uint64_t            blocks_repaired;
    uint64_t            blocks_unrepairable;
    uint64_t            ranges_processed;
    stm_scrub_verify_cb verify_cb;           // NULL ⇒ α-fallback
    void               *verify_ctx;          // borrowed; outlives scrub
};
```

`sync->pool` is immutable after create/open, so scrub caches `pool`
at create time — the step path doesn't re-enter `stm_sync_pool`.

`verify_cb` / `verify_ctx` are set independently of the run lifecycle
via `stm_scrub_set_verify_cb`. `scrub_reset_counters_locked` does NOT
clear them — Start/Restart/Reset zero counters but preserve cb
installation, matching the contract that cb installation is caller-
controlled and orthogonal to the run state machine.

### Step loop

```c
stm_scrub_step:
    lock(sc);
    if state != RUNNING: unlock; return OK;
    for (;;):
        pool_lock_shared(pool);              // pool.rdlock
        if cursor_device_id >= device_count:
            pool_unlock_shared;
            state := COMPLETED;
            unlock; return OK;
        di := pool_device_info(pool, cursor_device_id);
        if !di || di->state not in {ONLINE, EVACUATING}:
            pool_unlock_shared;
            cursor_device_id++;
            cursor_start_block := 0;
            continue;
        bd := pool_device_bdev(pool, cursor_device_id);
        a  := sync_alloc(sync, cursor_device_id);    // sync.lock briefly
        if !bd || !a:
            pool_unlock_shared;
            cursor_device_id++;
            cursor_start_block := 0;
            continue;
        s := alloc_first_allocated_from(a, cursor_start_block, &paddr, &length);
        if s == ENOENT:
            pool_unlock_shared;
            cursor_device_id++;
            cursor_start_block := 0;
            continue;
        if s != OK:
            pool_unlock_shared; unlock; return s;    // P2-2 gap (see below)
        start_block := paddr_offset(paddr);
        verify_range_locked(sc, bd, start_block, length);    // block-by-block
        ranges_processed++;
        cursor_start_block := start_block + length;
        pool_unlock_shared;
        unlock; return OK;
```

Per-block verify (branches on cb-set):

```c
verify_range_locked:
    if sc->verify_cb:
        // β cb-mode
        for b in 0..length:
            paddr_b := paddr_make(device_of(base_paddr),
                                   offset_of(base_paddr) + b);
            switch sc->verify_cb(paddr_b, sc->verify_ctx):
                OK            -> blocks_verified++;
                REPAIRED      -> blocks_repaired++;
                UNREPAIRABLE  -> blocks_unrepairable++;
                default       -> blocks_unrepairable++;  // defensive
        return;
    // α-fallback
    uint8_t buf[4096];
    for b in 0..length:
        offset := (start_block + b) * 4096;
        rs := bdev_read(bd, offset, buf, 4096);
        if rs == OK: blocks_verified++;
        else       : blocks_failed++;       // scrub continues (§7.16.1)
```

α-mode: no repair path; failures counted in `blocks_failed`.
β-mode: cb encapsulates read + repair + verify; per-outcome counter
charged. `blocks_failed` stays 0 in β-mode (CallbackSetExclusivity).
Both modes continue past per-block failure (§7.16.1).

## Locking

Lock order: `sc.lock → pool.rdlock → sync.lock (via stm_sync_alloc) → alloc.lock`.

Matches POOL OUTER, SYNC INNER, ALLOC LEAF. Holding `pool.rdlock`
across the bdev reads prevents concurrent `stm_pool_finish_evacuation`
from freeing the bdev pointer mid-read. The addendum commit
`86a71ec` established this; the pre-fix version used the pointer
readers without the lock — an R20 P1 but already addressed before
the audit fired.

Step holds `sc.lock` for the entire step body. Concurrent
`stm_scrub_pause` / `_status_get` / another `_step` block until the
current step returns. For a multi-MiB range this is seconds-class
latency — flagged by R20 P3-4 as a γ-scope throttling concern.

### β cb invocation context

The cb is invoked from inside `verify_range_locked`, with both
`sc->lock` and `pool->rdlock` held. **The pool's rwlock is
non-reentrant** — initialized with
`PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP` on Linux
(`pool.c:274-280`); a thread already holding rdlock that calls a
pool API which re-acquires the rdlock will deadlock if any writer
is queued. The cb must therefore avoid every pool API that takes
the rwlock internally (read OR write side).

Forbidden from the cb:

- Any `stm_scrub_*` on this handle (would deadlock on `sc->lock`).
- Pool write-side mutators (`stm_pool_add_device`, `_remove_device`,
  `_fail_device`, `_rejoin_device`, `_begin_evacuation`,
  `_finish_evacuation`, `_set_replace_claim`, `_clear_replace_claim`)
  — block forever waiting for our rdlock.
- Pool read APIs that internally call `pthread_rwlock_rdlock`:
  `stm_pool_replace_claim` (`pool.c:454`). Use the `_locked` variant
  if needed (it doesn't re-lock).

Allowed from the cb (no internal locking — pure pointer dereference
of the already-locked pool struct):

- `stm_pool_device_info(pool, dev)` (`pool.c:498-501`).
- `stm_pool_device_bdev(pool, dev)` (`pool.c:493-496`).
- `stm_pool_device_count(pool)`, `stm_pool_uuid(pool)`,
  `stm_pool_live_device_count(pool)` (all pure dereferences).
- `stm_pool_replace_claim_locked(pool)` (`pool.c:460-465`) — the
  caller-locked variant.
- `stm_sync_alloc(sync, dev)`: takes sync.lock briefly (pool order
  is OUTER → SYNC, so this is correct under our held rdlock).
- `stm_alloc_*` accessors on the alloc returned by
  `stm_sync_alloc` (alloc.lock is LEAF; no path back up).
- `stm_bdev_read` on the bdev returned by `stm_pool_device_bdev`
  (no pool/sync locks).

When in doubt, prefer `_locked` variants of pool APIs and treat the
held rdlock as a snapshot of pool state — the cb is a leaf in the
lock-acquire DAG.

## Spec cross-reference

Spec: `v2/specs/scrub.tla`. Invariants:

| Name | Statement |
|---|---|
| `TypeOK` | state ∈ States; counters bounded. |
| `StateMachineValid` | state ∈ {IDLE, RUNNING, PAUSED, COMPLETED}. |
| `CursorBounded` | cursor ≤ NumBlocks. |
| `ProcessedCount` | verified + failed + repaired + unrepairable = cursor. |
| `CallbackSetExclusivity` | `~CallbackSet ⇒ repaired = unrepairable = 0`; `CallbackSet ⇒ failed = 0`. |
| `CompletedIffDrained` | state = COMPLETED ⇒ cursor = NumBlocks. |
| `IdleMeansZero` | state = IDLE ⇒ cursor = 0 ∧ counters = 0. |
| `PauseResumeIdempotent` | snapshot_cursor > 0 ∧ state ∈ {PAUSED, RUNNING} ⇒ cursor ≥ snapshot_cursor. |
| `SnapshotPinnedWhilePaused` | state = PAUSED ⇒ snapshot_cursor = cursor. |
| `NoWorkWhenIdleOrCompleted` | IDLE ⇒ cursor=0; COMPLETED ⇒ cursor=NumBlocks. |

Fixed-α config (`scrub.cfg`): `NumBlocks=3, CorruptBlocks={2},
RepairableBlocks={}, CallbackSet=FALSE, BuggyResume=FALSE`.
19 distinct states at depth 8. All invariants hold.

Fixed-β config (`scrub_beta.cfg`): `NumBlocks=3,
CorruptBlocks={2,3}, RepairableBlocks={2}, CallbackSet=TRUE,
BuggyResume=FALSE`. Exercises StepClean (block 1), StepRepaired
(block 2 ∈ RepairableBlocks), StepUnrepairable (block 3 ∈
CorruptBlocks \ RepairableBlocks). 19 distinct states at depth 8.
All invariants hold including `CallbackSetExclusivity` (failed = 0).

Buggy-α config (`scrub_buggy.cfg`): `BuggyResume=TRUE`,
`CallbackSet=FALSE`. Models an impl where Resume zeros the cursor (a
"restart-on-resume" misunderstanding). `PauseResumeIdempotent`
VIOLATED at State 5 with the predicted 5-step trace
`Init → Start → StepClean(1) → Pause → Resume` (post-Resume
cursor=0 < snapshot_cursor=1).

SPEC-TO-CODE:

- `Start (IDLE→RUNNING)` → `stm_scrub_start` on `state == IDLE` branch.
- `Restart (COMPLETED→RUNNING)` → `stm_scrub_start` on `state == COMPLETED`.
- `Reset` → `stm_scrub_reset`.
- `Pause` / `Resume` → `stm_scrub_pause` / `_resume`.
- `StepClean(b)` α / β-OK → `verify_range_locked`'s OK paths.
- `StepCorrupt(b)` → α-fallback per-block error path.
- `StepRepaired(b)` → β cb-path REPAIRED branch.
- `StepUnrepairable(b)` → β cb-path UNREPAIRABLE branch.
- `Complete` → `stm_scrub_step`'s "cursor drained" branch.

## Tests

`tests/test_scrub.c` (26 tests):

- Lifecycle: `scrub_create_initial_state_is_idle`,
  `scrub_create_rejects_null_args`, `scrub_status_get_rejects_null_args`.
- State transitions: `scrub_start_idle_to_running`,
  `scrub_start_refuses_from_running_or_paused`,
  `scrub_pause_refuses_non_running`,
  `scrub_resume_refuses_non_paused`,
  `scrub_reset_refuses_non_completed`,
  `scrub_reset_from_completed_returns_to_idle`,
  `scrub_restart_from_completed_zeros_counters`.
- Step semantics: `scrub_step_on_empty_pool_transitions_to_completed`,
  `scrub_step_is_noop_when_not_running`,
  `scrub_step_sweeps_allocated_ranges`.
- Pause/Resume: `scrub_pause_resume_preserves_cursor_and_counters`
  (snapshot equality of all status fields except state across
  pause → resume).
- Failure handling: `scrub_step_counts_io_error_as_failed`
  (truncates backing file below a reserved paddr so per-block
  `stm_bdev_read` short-reads → STM_EIO; asserts blocks_failed
  increments and COMPLETED still reached).
- Multi-device: `scrub_multi_device_covers_every_attached_alloc`
  (mirror(2) 2-device pool, one 3-block range per device, asserts
  `ranges_processed=2, blocks_verified=6`),
  `scrub_skips_faulted_devices` (R20 P3-1).
- β cb-mode: `scrub_set_verify_cb_arg_validation` (NULL/EINVAL
  shape coverage), `scrub_set_verify_cb_refuses_running_or_paused`
  (state-guard self-audit P1 regression: cb mode frozen for the
  duration of a run), `scrub_cb_returns_ok_increments_verified`,
  `scrub_cb_returns_repaired_increments_repaired`,
  `scrub_cb_returns_unrepairable_increments_unrepairable`,
  `scrub_cb_mixed_outcomes_per_paddr` (cb keyed on paddr offset
  mod 3; asserts each counter sums correctly + ProcessedCount
  invariant),
  `scrub_cb_returns_unknown_charges_unrepairable_defensively`
  (R24 P3-3: misbehaving cb returning out-of-enum value charges
  to `blocks_unrepairable`, preserving CallbackSetExclusivity
  even under cb misbehavior),
  `scrub_cb_invoked_across_multiple_devices` (R24 P3-4: 2-device
  mirror, cb sees paddrs from both devices with correct device-id
  stamping; dev 0 → OK, dev 1 → REPAIRED; counters sum across
  devices), `scrub_no_cb_falls_back_to_alpha_behavior`
  (regression: with no cb installed, β scrub identical to α).

All green on default + ASan + TSan.

## Status

- [x] State machine IDLE / RUNNING / PAUSED / COMPLETED.
- [x] Per-device cursor + alloc-tree iteration via
      `stm_alloc_first_allocated_from`.
- [x] Per-block read + OK/fail counters (α).
- [x] Skip FAULTED + REMOVED devices.
- [x] Pool.rdlock around device lookups (addendum `86a71ec`).
- [x] Spec-first with buggy-config regression.
- [x] **β: caller-supplied verify-callback** with REPAIRED /
      UNREPAIRABLE / OK outcomes. CallbackSetExclusivity holds.
- [x] **β: scrub_beta.cfg** — fixed-impl spec config exercising
      all three cb outcomes. 19 states / depth 8, clean.

### R24 audit posture (closed 2026-04-25 @ *(pending)*)

R24 scoped audit on the P5-5-β commit `00869ee`. 0 P0 / 0 P1 / 2 P2 /
4 P3. β impl + spec sound; both P2s were doc-vs-code drift in
this file (state-guard table contradicting impl + misleading
"rdlock reentrantly" claim that would hazard P6's bptr-aware cb).

- [x] **P2-1**: state-guard refusal of `set_verify_cb` in
      RUNNING/PAUSED is now reflected in this doc's "State-guard
      refusals" bullet (was missing — claimed "callable in any
      state" while impl already refused).
- [x] **P2-2**: cb-context section rewritten to be precise about
      pool's `_NONRECURSIVE_NP` rwlock + which read APIs internally
      re-lock (`stm_pool_replace_claim`) vs. pure-deref accessors
      (`_device_info`, `_device_bdev`). Future P6 cb implementor
      now has accurate guidance + an explicit safe-list.
- [x] **P3-1**: `stm_scrub_status` field doc clarifies α/β refers
      to the run that produced the counters; cross-run windows
      (cb-cleared in COMPLETED with prior β counters still in
      view) documented as intentional + behavioral.
- [x] **P3-2**: `scrub.h` "Borrowed references" calls out
      `stm_scrub_close` as the abort pattern when ctx must be
      freed before the run reaches COMPLETED.
- [x] **P3-3**: new test
      `scrub_cb_returns_unknown_charges_unrepairable_defensively`
      exercises the impl's `default:` arm on the cb-outcome
      switch (misbehaving cb returning out-of-enum value).
- [x] **P3-4**: new test `scrub_cb_invoked_across_multiple_devices`
      asserts cb sees paddrs from both devices in a 2-device
      mirror pool with correct device-id stamping.

### R20 audit posture (closed 2026-04-24 @ `25d7c4a`)

- [x] **P2-1**: `cursor_start_block >= (1<<48)` + any non-OK non-ENOENT
      return from the alloc cursor now advances past the device
      instead of wedging scrub.
- [x] **P2-2**: `STM_ECORRUPT` from the alloc cursor advances past
      the device + bumps `ranges_processed` as a symbolic "tree
      unparseable" signal.
- [x] **P2-3**: `scrub.h` docstring clarifies that COMPLETED ⇒
      all ONLINE/EVACUATING devices swept, NOT "every allocated
      block verified". FAULTED + REMOVED silently skipped.
- [x] **P3-1**: `scrub_skips_faulted_devices` test added.
- [x] **P3-5**: `scrub.h` lifetime paragraph extended for per-device
      allocs (must outlive OR be detached before close).
- [x] **P3-7**: `scrub_pause_refuses_non_running` extended with
      COMPLETED case.

Deferred (γ-scope / future):

- [ ] **P3-2**: direct unit tests for `stm_alloc_first_allocated_from`
      (exercised indirectly via scrub today).
- [ ] **P3-3**: concurrent-scrub + pool-mutation TSan stress test.
- [ ] **P3-4** (γ): `stm_scrub_step` holds `sc.lock` for the
      duration of a multi-MiB range. Pause + status_get block
      arbitrarily long. Periodic lock drop or atomic-state flag
      can fix in γ.
- [ ] **P3-6** (γ): Spec models single-stream cursor; γ's
      durable-cursor work will need device-aware spec extension.

### γ pipeline

- **P5-5-γ**: durable pause/resume cursor. Persist cursor in a new
  UB field or dedicated scrub-metadata object. May bump
  `STM_UB_VERSION`. Enables resume across unmount/remount.
- **Future**: IO throttling (ARCH §7.14.3 low/medium/high priority),
  per-device parallelism (ARCH §12.7.1 "one thread per device"),
  P6 extent manager wiring (the bptr-aware verify-cb that replaces
  test stubs with a real replica-list iterator).

## Known caveats

- **α verify-only**: no per-block csum check. A block that returns
  bytes but is silently bit-rotten (csum-fail scenario) still counts
  as `blocks_verified` because we have no expected csum to compare
  to. Requires the bptr layer (P6) for full integrity coverage —
  but the β cb-shape is the integration point: P6's bptr-aware
  cb will perform the csum check and return REPAIRED /
  UNREPAIRABLE accordingly.
- **β cb is caller-supplied**: scrub itself does NOT carry a
  bptr-aware default. With no cb installed, scrub falls back to α
  (raw read, no csum). Production deployments need a real cb (P6
  unlock) for end-to-end integrity coverage.
- **FAULTED-device blocks are skipped silently**. Status_get
  gives no indication that coverage was degraded. Operators
  monitoring "scrub finished without errors" may misread the
  signal. R20 P2-3.
- **In-RAM cursor only**. An unmount mid-scrub loses the cursor;
  the next mount starts from (0, 0). γ addresses.
- **Single-threaded step**. Per-device parallelism is future
  work. Large pools with many devices scrub serially.
- **β cb under sc->lock + pool->rdlock**: long-running cbs (e.g. a
  network-replica fetch) block all other scrub APIs and pool
  mutations for the duration of the cb. The cb should be
  short-circuit-fast — locate replica, read, verify, write —
  not network-bound. γ's throttling work will refactor the lock-
  hold pattern.
