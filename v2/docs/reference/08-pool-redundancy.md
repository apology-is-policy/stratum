# 08 — Pool, redundancy, device lifecycle

## Purpose

The pool layer owns the device roster — the set of `stm_bdev`s that
make up one Stratum pool — plus the redundancy model, per-pool
rwlock, and device-lifecycle state machine (add / remove / replace /
fail / rejoin / evacuate).

The redundancy work (currently only `mirror(n)`; RS + LRC post-P5)
is layered on top of sync's multi-device commit protocol:
reservation + write + read all fan out via the sync handle, with
the pool providing the per-device bdev pointers under pool.rdlock.

ARCH §4 (Storage pool), §5.6 (Quorum), §4.7 (Device lifecycle).

## Public API — pool

### Constants

```c
#define STM_POOL_DEVICES_MAX       64u          // hard cap per pool
#define STM_POOL_ROSTER_SLOT_SIZE  32u          // per-slot bytes in ub_roster
#define STM_POOL_ROSTER_BYTES    2048u          // 64 × 32 — matches ub_roster[]
```

### Roster entry

```c
typedef struct {
    uint64_t         uuid[2];
    uint64_t         size_bytes;
    stm_device_role  role;       // DATA / LOG / CACHE / SPARE
    stm_device_class class_;     // SSD / HDD / PMEM / ZNS
    stm_device_state state;      // UNSET/ONLINE/OFFLINE/DEGRADED/FAULTED/REMOVED/EVACUATING
    stm_bdev        *bdev;       // borrowed; caller owns lifecycle
} stm_pool_device;
```

### Lifecycle

```c
stm_status stm_pool_open (const stm_pool_open_opts *opts, stm_pool **out);
void       stm_pool_close(stm_pool *p);    // does NOT close bdevs (borrowed)
```

`stm_pool_open_opts`: pool_uuid + device_count + device[] + read_only.
`stm_pool_open` validates: device count in `[1, STM_POOL_DEVICES_MAX]`;
live slots have non-NULL bdev; REMOVED slots have NULL bdev + preserved
UUID (burned-UUID tracking); UUIDs non-zero and unique within roster
(live OR removed); role/class/state in range. On success, finalizes
`stm_pool_roster_hash`.

### Inspection

```c
size_t                  stm_pool_device_count     (const stm_pool *p);
size_t                  stm_pool_live_device_count(const stm_pool *p);  // excl. REMOVED
uint64_t                stm_pool_roster_hash      (const stm_pool *p);
stm_bdev               *stm_pool_device_bdev      (stm_pool *p, uint16_t id);
const stm_pool_device  *stm_pool_device_info      (const stm_pool *p, uint16_t id);
size_t                  stm_pool_roster_bytes     (const stm_pool *p, uint8_t out[2048]);
```

Pointer-returning readers (`_device_bdev`, `_device_info`) REQUIRE
the caller to hold `pool.rdlock` while dereferencing the returned
pointer. Scalar-returning readers (`_device_count`, `_roster_hash`,
`_live_device_count`) are atomic-load-safe on mainstream archs but
formally race under C11 — use them inside pool.rdlock when composing
with other pool reads.

### Locking

```c
void stm_pool_lock_shared  (stm_pool *p);
void stm_pool_unlock_shared(stm_pool *p);
void stm_pool_lock_exclusive  (stm_pool *p);
void stm_pool_unlock_exclusive(stm_pool *p);
```

Readers nest; writers are exclusive; a shared-lock request blocks
if a writer is waiting (Linux uses `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`
to prevent reader starvation — R18 P2-1).

**Lock order** (global): `POOL OUTER, SYNC INNER, ALLOC LEAF`.
Any reversal → deadlock. Pool mutators take the exclusive side
internally — callers MUST NOT pre-hold pool.rdlock before a
mutator call (recursive write-after-read is UB under POSIX rwlocks).

### Lifecycle (P5-4)

```c
stm_status stm_pool_add_device         (stm_pool *p, const stm_pool_device *new_dev);
stm_status stm_pool_remove_device      (stm_pool *p, uint16_t id, size_t floor);
stm_status stm_pool_begin_evacuation   (stm_pool *p, uint16_t id, size_t floor);
stm_status stm_pool_finish_evacuation  (stm_pool *p, uint16_t id);
stm_status stm_pool_fail_device        (stm_pool *p, uint16_t id);
stm_status stm_pool_rejoin_device      (stm_pool *p, uint16_t id);

// _locked variants for sync-layer composition (caller already holds pool.wrlock):
stm_status stm_pool_add_device_locked       (...);
stm_status stm_pool_remove_device_locked    (...);
stm_status stm_pool_begin_evacuation_locked (...);
stm_status stm_pool_finish_evacuation_locked(...);
stm_status stm_pool_fail_device_locked      (...);
stm_status stm_pool_rejoin_device_locked    (...);
```

**`add_device`** (P5-4a, ARCH §4.7.1):
- Append to roster at index = current `device_count`.
- Coerces state to ONLINE regardless of caller input (R16 F1).
- Reads size from `stm_bdev_caps_of(bdev)`, ignores caller `size_bytes` (R16 F2).
- Refuses duplicate UUID (including REMOVED tombstones — R16 F3 burned-UUID).
- Refuses roster full (`STM_ENOSPC`).
- RO pool: `STM_EROFS`.
- Next `sync_commit` picks up expanded membership automatically.

**`remove_device`** (P5-4b-i, ARCH §4.7.2):
- Flips slot to REMOVED; sets `bdev = NULL`; **preserves UUID**.
- Refuses `device_id == 0` with `STM_ENOTSUPPORTED` (metadata primary — R17 P1-1).
- Refuses if already REMOVED or EVACUATING.
- Refuses if any OTHER slot is EVACUATING (R17 P2-2).
- Enforces `live_count - 1 >= redundancy_floor` (evac.tla
  RedundancyPreservedOnRemove). Caller supplies floor from sync's
  redundancy profile — typically `profile.mirror_n`.
- **WARNING**: pool-level primitive; bypasses alloc-drain check.
  Sync-attached callers MUST use `stm_sync_remove_device` instead
  (wraps with drain probe + sync.lock + pool.wrlock atomically).

**`begin_evacuation`** / **`finish_evacuation`** (P5-4b-ii):
- `begin`: ONLINE or FAULTED → EVACUATING. Enforces AtMostOneEvacuating +
  redundancy floor.
- `finish`: EVACUATING → REMOVED. No floor re-check (happened at begin).
- Same drain-check warning as remove; sync-attached callers use
  `stm_sync_finish_evacuation`.

**`fail_device`** / **`rejoin_device`** (P5-4d-α, ARCH §4.7.4):
- `fail`: ONLINE → FAULTED. bdev pointer **preserved** (unlike
  remove's NULL-clear) — a subsequent rejoin can reuse it.
- `rejoin`: FAULTED → ONLINE.
- Dev 0 guard (R17 P1-1): refuses `device_id == 0`.
- RO refuses.
- **FAULTED-skip is symmetric across all sync I/O paths** (R21 /
  P5-6 P1 + P2-5):
  - `mirror_read` — ONLINE + EVACUATING read-accepted; FAULTED +
    REMOVED + others skipped.
  - `mirror_write` — ONLINE + EVACUATING written-to; FAULTED
    skipped (pre-fix would hang on the FAULTED bdev's fsync and
    starve mirror_quorum).
  - `sync_commit`'s per-alloc persistence loop — FAULTED devs'
    trees are NOT rewritten (stale-on-disk; reconcile at rejoin
    per P5-4d-β, deferred).
  - `write_ub_to_all_devices` (both reservation + final phases) —
    FAULTED skipped, same rationale.
  - `reserve_mirror` — already picks first-N ONLINE since
    P5-4b-ii-α.
  Overall contract: a single FAULTED device does NOT block commits
  on a pool whose remaining ONLINE count still meets quorum.
  Rejoin + reconcile catches the device up (β); until then,
  `mirror_read`'s csum-fallback masks any stale FAULTED content
  at read time.

**Burned-UUID** (R16 F3 / P5-4b-i): REMOVED slots persist in the
roster so add_device's uniqueness walk refuses re-add of a UUID
that previously identified a device. Historical AEAD nonces written
under that device's metadata_key are tied to `(pool_uuid, device_id)`;
re-adding with the same UUID but different slot (or vice versa)
would collide.

## Public API — redundancy

### Profile

```c
typedef struct { uint8_t kind; uint8_t mirror_n; } stm_redundancy_profile;

// kinds:
STM_RED_NONE   = 0       // no redundancy (N=1 default)
STM_RED_MIRROR = 1       // n-way mirror (mirror_n in [1, device_count])
STM_RED_RS     = 2       // reserved — STM_ENOTSUPPORTED at create
STM_RED_LRC    = 3       // reserved — STM_ENOTSUPPORTED at create
```

Declared at `stm_sync_create` / `_open`, stamped into every UB's
`ub_redundancy_kind + ub_redundancy_params[15]`, read back via
`stm_sync_redundancy_get`.

### Mirror protocol

```c
stm_status stm_sync_reserve_mirror(stm_sync *s, uint64_t nblocks,
                                      size_t n_replicas, uint64_t out_paddrs[]);
stm_status stm_sync_mirror_write  (stm_sync *s, const uint64_t paddrs[],
                                      size_t n, const void *buf, size_t len,
                                      size_t *out_confirmed);
stm_status stm_sync_mirror_read   (stm_sync *s, const uint64_t paddrs[],
                                      size_t n, void *buf, size_t len,
                                      const uint8_t expected_csum[32]);
```

**`reserve_mirror`**:

- Reserves `nblocks` on each of the first `n_replicas` ONLINE
  devices (picks first-N online — not positional; P5-4b-ii-α fix
  for evacuating-slot skip).
- Returns `out_paddrs[i]` for each reservation, with `device_id`
  stamped in top 16 bits.
- `n_replicas` MUST equal the pool's `mirror_n`.
- Each target device MUST have an attached alloc.
- Atomic: partial-failure rolls back already-reserved paddrs.

**`mirror_write`**:

- Writes `buf[0..len)` to every paddr in `paddrs[0..n)`, fsyncing
  each.
- Quorum (`⌊n/2⌋+1`) confirmed → `STM_OK`.
- Sub-quorum → `STM_EQUORUM`. Pool left with some replicas durable;
  scrub / retry reconciles (ARCH §7.15).
- `len` must be a multiple of `STM_UB_SIZE`.

**`mirror_read`**:

- Tries replicas in `paddrs[0..n)` order. For each:
  - Skip if device state not ONLINE or EVACUATING (FAULTED +
    REMOVED + UNSET rejected; P5-4d-α).
  - `stm_bdev_read` into `buf`.
  - BLAKE3(buf) == `expected_csum`? First match wins, returns
    `STM_OK`.
  - Mismatch: record `STM_ECORRUPT`; try next.
  - I/O error: record `first_err`; try next.
- All replicas exhausted without a csum match → returns
  `first_err` if any, else `STM_ECORRUPT`.

### Evacuation protocol

```c
stm_status stm_sync_evacuation_step(stm_sync *s, uint16_t target, uint16_t survivor,
                                       uint64_t *out_old_paddr, uint64_t *out_new_paddr);
```

One call = one allocated range migrated. Caller loops until
`STM_ENOENT`.

Per-step atomicity (evac.tla `EvacuateAtomic`):

1. Pick lowest-start allocated range on target via `stm_alloc_first_allocated`.
2. Read `length_blocks × 4 KiB` from target bdev.
3. Reserve `length_blocks` on survivor's alloc.
4. Write + fsync on survivor.
5. Free range from target's tree (PENDING; swept by next commit).

All 5 steps under sync's lock so they persist atomically. Crash
mid-step leaves target with the range still present (reserve on
survivor is in-RAM-only until commit).

**Caller supplies the survivor** because this layer cannot see which
devices hold OTHER replicas — picking a survivor that already holds
the block would collapse two replicas onto one device (violating
evac.tla's `s \notin replicas[b]` precondition).

**Size cap** (R17 P2-4): per-step transfer is capped at 4 MiB (1024
blocks). Ranges larger than that return `STM_ENOTSUPPORTED` — full
large-range evacuation needs partial-free on the alloc tree (Phase
6 extent manager refactor).

### Safe-removal wrappers

```c
stm_status stm_sync_remove_device    (stm_sync *s, uint16_t id, size_t floor);
stm_status stm_sync_finish_evacuation(stm_sync *s, uint16_t id);
```

- Atomically hold pool.wrlock + sync.lock.
- Probe `stm_alloc_first_allocated` — if the target has live ranges,
  return `STM_EBUSY` (caller must evacuate first).
- Delegate to `_locked` pool primitive for the state transition.
- `finish_evacuation` also detaches `s->allocs[id] = NULL` atomically;
  caller owns the detached alloc and must close it before closing
  the underlying bdev.

### Replace (P5-4c-α)

```c
stm_status stm_sync_replace_device_online(stm_sync *s, uint16_t old_id,
                                             const stm_pool_device *new_dev,
                                             stm_alloc *new_alloc,
                                             size_t redundancy_floor,
                                             uint16_t *out_new_device_id);
```

Composed sequence (ARCH §4.7.3):

```
1. stm_pool_add_device(new_dev)
2. stm_sync_attach_alloc(new_slot, new_alloc)
3. stm_sync_commit                          // persists ADD
4. stm_pool_begin_evacuation(old, floor)
5. stm_sync_commit                          // persists EVACUATING
6. Loop stm_sync_evacuation_step(old, new_slot, ...) until STM_ENOENT
7. stm_sync_commit                          // persists migrations
8. stm_sync_finish_evacuation(old)         // detaches old's alloc
9. stm_sync_commit                          // persists REMOVED
```

Caveats:
- **ONLINE → ONLINE only** today. FAULTED → new reconstruct (reading
  from surviving replicas and rebuilding) needs bptr-layer iteration,
  deferred to P5-4c-β (unlocks with P6 extent manager).
- `old_id == 0` returns `STM_ENOTSUPPORTED` (metadata primary guard).
- **New slot is a fresh roster index**, NOT a reuse of `old_id`.
  `old_id` becomes a REMOVED tombstone. True swap-into-old-slot
  requires burning the UUID entirely or a dedicated refactor.
- **Idempotent resume** (R19): if called with `old_id` already in
  EVACUATING state (crash between step 5 and 8), wrapper detects
  and resumes from step 6.
- **Rollback-or-wedge** (R19 P2-2): if any step's rollback itself
  fails, sync handle wedges rather than silently inconsistent.
- **Drain cap** (R19 P2-5): drain loop capped at `STM_REPLACE_DRAIN_MAX_STEPS = 100M`;
  exceeded → `STM_ECORRUPT`.

## Device state machine (evac.tla + device_lifecycle.tla)

```
             ┌──────────┐
             │  UNSET   │  (slot header before add; not a live state)
             └────┬─────┘
                  │ stm_pool_add_device
                  ▼
             ┌──────────┐                            ┌──────────┐
             │  ONLINE  │ ◀────── rejoin ──────────  │ FAULTED  │
             │          │ ─────── fail ────────────▶ │          │
             └──┬───────┘                            └────┬─────┘
                │                                         │
                │ begin_evacuation (floor permits)        │
                │                                         │
                ▼                                         │
             ┌──────────┐                                 │
             │EVACUATING│ ◀──────────── (cannot exit EVAC via fail)
             └────┬─────┘
                  │ finish_evacuation (drained)  OR  remove_device (direct; pool-only)
                  ▼
             ┌──────────┐
             │ REMOVED  │  (bdev=NULL, UUID preserved)
             └──────────┘
```

OFFLINE / DEGRADED states exist in the roster byte for future work
but aren't emitted by any current API. Only ONLINE / FAULTED /
EVACUATING / REMOVED transitions are implemented.

## Spec cross-reference

| Spec | Pins |
|---|---|
| `device_lifecycle.tla` | State-machine transitions (add / remove / replace / fail / rejoin / reconcile). `RosterMonotonic`, `RedundancyPreservedOnRemove`, `AddDeviceIdempotent`, `NoOrphanOnRemove`, `ReconcileRestoresState`. Large config (`device_lifecycle_large.cfg`) verified 10.6M states at depth 21. |
| `evac.tla` | Per-block evacuation atomicity. `EvacuationAtomic` (every block's replicas ∩ Live ≥ MirrorN at every reachable state), `AtMostOneEvacuating`, `RedundancyPreservedDuringEvacuation`, `NoTargetReplicasAfterComplete`. Buggy configs: release-before-write (EvacuationAtomic violated at State 3); no-drain-on-remove (violated at State 2). |
| `metadata_nonce.tla` | Per-device paddr stamping. `NonceUniqueness` under shared metadata_key across devices. |
| `quorum.tla` | Multi-device commit + mount under partial failure. (See [07-sb-sync.md](07-sb-sync.md).) |

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_pool` | 44 | open validation (zero count / duplicate UUID / malformed); roster encode/decode + hash determinism + identity-change sensitivity; fs format/mount roundtrip; v4/v5 version refusals; pool-mismatch refused; add_device; remove floor + burned-UUID; begin/finish evacuation guards; device-0 refusals across all mutators; fail/rejoin cycle + mirror_read FAULTED skip; RO pool refuses every mutator. |
| `test_sync_multi` | 36 | (See [07-sb-sync.md](07-sb-sync.md).) Multi-device quorum commit, mirror reservation, replace_device_online happy path + unsupported-paths, evacuation step happy path + non-evacuating-refused, safe-removal drain check, concurrent-reader/writer TSan stress. |

## Status

- [x] Pool open + close + scalar/pointer readers.
- [x] Per-pool rwlock with writer-preference (Linux).
- [x] `add_device` + `remove_device` + burned-UUID tracking.
- [x] `begin_evacuation` + `finish_evacuation`.
- [x] `fail_device` + `rejoin_device` (P5-4d-α).
- [x] `replace_device_online` (P5-4c-α) with idempotent resume.
- [x] `evacuation_step` with 4 MiB per-step cap.
- [x] Safe-removal + safe-finish-evacuation wrappers.
- [x] mirror(n) reserve / write (quorum) / read (first-match-wins).
- [x] Reserve picks first-N ONLINE (not positional).
- [x] mirror_read skips FAULTED + REMOVED.
- [x] mirror_write + sync_commit + write_ub_to_all_devices all skip
      FAULTED (R21 / P5-6 P1) — symmetric with mirror_read.
- [x] `stm_pool_open` refuses non-ONLINE state at slot 0 (R21 / P5-6
      P2-4) — metadata-primary invariant enforced at the construction
      boundary.
- [x] **Replace-in-flight claim** (P5-8 / closes R22 P3-3 + P3-4):
      `stm_sync_replace_device_online` claims the new slot atomically
      with the add (or with resume detection on retry).  While the
      claim is held, `stm_pool_{add,remove,fail,rejoin}_device` and
      `stm_pool_{begin,finish}_evacuation` on the claimed slot refuse
      with `STM_EBUSY`.  `_locked` variants bypass — replace's own
      internal pool ops can proceed.  Claim is idempotent on same-slot
      reclaim (lets retry reclaim its own prior partial-state claim);
      released only on full success of the replace.  Failed replace
      leaves the claim held so the partial in-RAM state is protected
      from concurrent mutators across the failure→retry window.

### Replace-in-flight claim API

```c
#define STM_POOL_REPLACE_CLAIM_NONE   UINT16_MAX

stm_status stm_pool_set_replace_claim       (stm_pool *p, uint16_t slot);
stm_status stm_pool_set_replace_claim_locked(stm_pool *p, uint16_t slot);
void       stm_pool_clear_replace_claim       (stm_pool *p);
void       stm_pool_clear_replace_claim_locked(stm_pool *p);
uint16_t   stm_pool_replace_claim(const stm_pool *p);   // for tests
```

Contract:

- **At most one claim** at a time.  `set_claim` on a different slot
  while a claim is held → `STM_EBUSY`.
- **Idempotent same-slot**: `set_claim(slot)` when claim is already
  on `slot` → `STM_OK` (no state change).  This lets a replace retry
  reclaim its own prior failed-call's claim without coordinating.
- **Clear is unconditional**: safe to call without the claim held
  (no-op).  Callers don't need to check before clearing.
- **Mutator refusal scope**: only the non-`_locked` wrappers
  consult the claim.  `_locked` variants are caller-controlled
  internal ops (replace itself uses these to proceed past the
  claim guard).
- **`add_device` refusal**: refuses while ANY claim is held (the
  new slot would land at the tail and could collide).

Lock discipline: `set/clear_locked` require pool.wrlock held by the
caller.  Public wrappers acquire it internally.  `replace_claim`
reader takes pool.rdlock.
- [x] Device-0 guard on every mutator (metadata primary).
- [ ] **FAULTED → new reconstruct** (P5-4c-β): needs bptr-layer
      block iteration. Deferred to P6 extent manager.
- [ ] **Reconcile after rejoin** (P5-4d-β): catch-up of stale
      FAULTED-device content. Same bptr dependency.
- [ ] **Evacuation resume across remount** (P5-4b-ii-γ): operator
      drives manually today.
- [ ] **Large-range evacuation** (>4 MiB): `STM_ENOTSUPPORTED`
      until partial-free lands.
- [ ] **Dynamic metadata primary**: device 0 currently hard-coded as
      the keyschema + alloc-roots host. Refactor to movable primary
      is post-P5 scope.
- [ ] **Hot spares**: roster carries `STM_DEV_ROLE_SPARE` but no
      auto-promote on fail. Future.
- [ ] **RS + LRC erasure coding**: post-P5.

## Known caveats

- **`remove_device` / `finish_evacuation` at the pool layer bypass
  the drain check.** They are PUBLIC APIs for pool-only tooling
  without an attached alloc, but sync-attached callers MUST use
  the sync-layer wrappers or risk the `evac_remove_no_drain_buggy`
  scenario. The WARNING in pool.h docstrings makes this explicit.
- **Burned-UUID tombstones never shrink.** `device_count` grows
  monotonically; REMOVED slots persist. Pools undergoing many
  add/remove cycles fill the 64-slot cap faster than those with
  stable roster. No compaction mechanism.
- **Replace creates a NEW slot.** `old_id` → REMOVED tombstone;
  `new_device` occupies a fresh slot at `device_count`. For a
  true in-place swap (reuse old_id's slot) we'd need to either
  burn the UUID entirely or add a dedicated swap primitive — not
  planned.
- **Mirror is the only redundancy mode today.** `STM_RED_RS` and
  `STM_RED_LRC` are reserved constants; pool creation refuses them
  with `STM_ENOTSUPPORTED`. Post-P5 deliverable.
