# 09 — Scrub (P5-5-α, verify-only)

## Purpose

Background integrity sweep per ARCHITECTURE §7.14 + §12.7. The
P5-5-α MVP is **verify-only**: it iterates each pool device's alloc
tree, reads every allocated block, and counts I/O failures. No
repair (β), no durable cursor (γ), no IO throttling (future).

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
| `stm_scrub_step` (clean block) | `StepClean` | RUNNING → RUNNING | `blocks_verified++` |
| `stm_scrub_step` (corrupt/EIO block) | `StepCorrupt` | RUNNING → RUNNING | `blocks_failed++` |
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

typedef struct {
    stm_scrub_state state;
    uint16_t        cursor_device_id;
    uint64_t        cursor_start_block;
    uint64_t        blocks_verified;
    uint64_t        blocks_failed;
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
```

State-guard refusals:

- `start` refuses RUNNING, PAUSED → `STM_EINVAL`.
- `pause` refuses IDLE, PAUSED, COMPLETED → `STM_EINVAL`.
- `resume` refuses IDLE, RUNNING, COMPLETED → `STM_EINVAL`.
- `reset` refuses IDLE, RUNNING, PAUSED → `STM_EINVAL`.
- `step` on non-RUNNING is a no-op returning `STM_OK`.
- `status_get` is always safe.

Thread safety: internal `pthread_mutex_t` serializes every API.

## Implementation

`src/scrub/scrub.c` (~290 lines).

### Handle layout

```c
struct stm_scrub {
    pthread_mutex_t lock;
    stm_sync       *sync;                  // borrowed
    stm_pool       *pool;                  // cached at create
    stm_scrub_state state;
    uint16_t        cursor_device_id;
    uint64_t        cursor_start_block;
    uint64_t        blocks_verified;
    uint64_t        blocks_failed;
    uint64_t        ranges_processed;
};
```

`sync->pool` is immutable after create/open, so scrub caches `pool`
at create time — the step path doesn't re-enter `stm_sync_pool`.

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

Per-block verify:

```c
verify_range_locked:
    uint8_t buf[4096];
    for b in 0..length:
        offset := (start_block + b) * 4096;
        rs := bdev_read(bd, offset, buf, 4096);
        if rs == OK: blocks_verified++;
        else        : blocks_failed++;       // scrub continues (§7.16.1)
```

No repair path; no retry. Failures are counted; `blocks_failed` is
surfaced to the operator via `status_get`. β will add repair from
surviving replicas.

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

## Spec cross-reference

Spec: `v2/specs/scrub.tla`. Invariants:

| Name | Statement |
|---|---|
| `TypeOK` | state ∈ States; counters bounded. |
| `StateMachineValid` | state ∈ {IDLE, RUNNING, PAUSED, COMPLETED}. |
| `CursorBounded` | cursor ≤ NumBlocks. |
| `ProcessedCount` | verified + failed = cursor. |
| `CompletedIffDrained` | state = COMPLETED ⇒ cursor = NumBlocks. |
| `IdleMeansZero` | state = IDLE ⇒ cursor = 0 ∧ counters = 0. |
| `PauseResumeIdempotent` | snapshot_cursor > 0 ∧ state ∈ {PAUSED, RUNNING} ⇒ cursor ≥ snapshot_cursor. |
| `SnapshotPinnedWhilePaused` | state = PAUSED ⇒ snapshot_cursor = cursor. |
| `NoWorkWhenIdleOrCompleted` | IDLE ⇒ cursor=0; COMPLETED ⇒ cursor=NumBlocks. |

Fixed config (`scrub.cfg`): `NumBlocks=3, CorruptBlocks={2}, BuggyResume=FALSE`.
19 distinct states at depth 8. All invariants hold.

Buggy config (`scrub_buggy.cfg`): `BuggyResume=TRUE`. Models an impl
where Resume zeros the cursor (a "restart-on-resume" misunderstanding).
`PauseResumeIdempotent` VIOLATED at State 5 with the predicted
5-step trace `Init → Start → StepClean(1) → Pause → Resume`
(post-Resume cursor=0 < snapshot_cursor=1).

SPEC-TO-CODE:

- `Start (IDLE→RUNNING)` → `stm_scrub_start` on `state == IDLE` branch.
- `Restart (COMPLETED→RUNNING)` → `stm_scrub_start` on `state == COMPLETED`.
- `Reset` → `stm_scrub_reset`.
- `Pause` / `Resume` → `stm_scrub_pause` / `_resume`.
- `StepClean(b)` → `stm_scrub_step`'s per-block `OK` path.
- `StepCorrupt(b)` → `stm_scrub_step`'s per-block error path.
- `Complete` → `stm_scrub_step`'s "cursor drained" branch.

## Tests

`tests/test_scrub.c` (16 tests):

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
  `ranges_processed=2, blocks_verified=6`).

All green on default + ASan + TSan.

## Status

- [x] State machine IDLE / RUNNING / PAUSED / COMPLETED.
- [x] Per-device cursor + alloc-tree iteration via
      `stm_alloc_first_allocated_from`.
- [x] Per-block read + OK/fail counters.
- [x] Skip FAULTED + REMOVED devices.
- [x] Pool.rdlock around device lookups (addendum `86a71ec`).
- [x] Spec-first with buggy-config regression.

### Known gaps — flagged by R20 (2026-04-24)

- [ ] **P2-1**: `cursor_start_block == (1<<48)` trips
      `stm_alloc_first_allocated_from`'s EINVAL guard, wedging
      scrub. Unreachable in practice (requires a 2^60-byte device)
      but formally a boundary bug. Fix: treat as
      "device drained" in step.
- [ ] **P2-2**: `STM_ECORRUPT` from the alloc cursor returns
      directly to caller without advancing, leaving scrub
      permanently wedged at a corrupt entry. Fix: treat as
      "skip this device"; log; increment a counter.
- [ ] **P2-3**: Spec's `CompletedIffDrained` implies cursor ==
      NumBlocks, but impl's COMPLETED can coexist with unscanned
      FAULTED-device blocks. Documentation drift — scrub.h needs
      an explicit "COMPLETED = all ONLINE/EVACUATING devices swept,
      NOT necessarily every allocated block".
- [ ] **P3-1**: No FAULTED-device-skip test in test_scrub.
- [ ] **P3-2**: No direct unit tests for
      `stm_alloc_first_allocated_from` (exercised indirectly only).
- [ ] **P3-3**: No concurrent-scrub + pool-mutation TSan stress
      test.
- [ ] **P3-4** (γ): `stm_scrub_step` holds `sc.lock` for the
      duration of a multi-MiB range. Pause + status_get block
      arbitrarily long. Periodic lock drop or atomic-state flag
      can fix in γ.
- [ ] **P3-5**: Lifetime docstring omits that per-device allocs
      must also outlive scrub (or be detached before close).
- [ ] **P3-6** (γ): Spec models single-stream cursor; γ's
      durable-cursor work will need device-aware spec extension.
- [ ] **P3-7**: `scrub_pause_refuses_non_running` test missing
      the COMPLETED case.

### β / γ pipeline

- **P5-5-β**: repair from redundancy. On `mirror_read` csum-fail,
  identify good replicas, rewrite the bad one via `stm_bdev_write`.
  Needs per-block replica-list knowledge (future bptr layer OR
  caller-supplied callback).
- **P5-5-γ**: durable pause/resume cursor. Persist cursor in a new
  UB field or dedicated scrub-metadata object. May bump
  `STM_UB_VERSION`. Enables resume across unmount/remount.
- **Future**: IO throttling (ARCH §7.14.3 low/medium/high priority),
  per-device parallelism (ARCH §12.7.1 "one thread per device").

## Known caveats

- **Verify-only**: no per-block csum check, no repair. A block that
  returns bytes but is silently bit-rotten (csum-fail scenario)
  still counts as `blocks_verified` because we have no expected
  csum to compare to. Requires the bptr layer (P6) for full
  integrity coverage.
- **FAULTED-device blocks are skipped silently**. Status_get
  gives no indication that coverage was degraded. Operators
  monitoring "scrub finished without errors" may misread the
  signal. R20 P2-3.
- **In-RAM cursor only**. An unmount mid-scrub loses the cursor;
  the next mount starts from (0, 0). γ addresses.
- **Single-threaded step**. Per-device parallelism is future
  work. Large pools with many devices scrub serially.
