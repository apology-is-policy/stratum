# Phase 5 — status and pickup guide

Authoritative pickup guide for Phase 5 (multi-device + redundancy).
Last update 2026-04-21 after P5-0 landed. Companion to
`phase4-status.md`, which documents the crypto/integrity layer
Phase 5 builds on.

## TL;DR

Phase 5 = ARCH §4 (storage pool model) + §5 (superblock and quorum)
+ ROADMAP §8. Converts Stratum from single-device to N-device pools
with declared redundancy. Commit semantics lift from single-device
four-phase to multi-device three-phase-quorum per ARCH §5.6. First
redundancy profile is `mirror(n)`; RS + LRC erasure coding deferred
to a later sub-chunk.

| Commit | What | Tests |
|---|---|---|
| `<p5-0>` | **P5-0: `quorum.tla` formal spec**. Models multi-device commit (ARCH §5.6) with per-device UB rings, parallel reservation + final writes, quorum threshold = ⌊N/2⌋+1, device FAULTED / ONLINE state, rejoin + reconcile, coordinator crash. Proves `TypeOK`, `QuorumSafety` (phase=Published implies ≥quorum devices at target_gen), `AuthoritativeMono` (committed gens never regress), `CommitAtomic` (auth ≥ 2×commits_done), `OrphansNotAuthoritative` (partial-Phase-3 gens held by <quorum devices are never authoritative), `LiveCoordTargetValid` (coord's in-flight target_gen ≥ current auth), `QuorumDurability`, `MountGenBumpMulti`. Mount requires quorum of ONLINE devices (emergency mount is an explicit opt-in not modeled). TLC-clean under `Devices={1,2,3}, MaxCommits=3, MaxFaults=2`: 36839 distinct states, depth 35. Two iterations: initial pass rejected orphan gens from degraded-mount, then caught an over-strict `LiveCoordMonotonic` (`target > auth`) that Fails in the transient state where Phase 3 WriteFinals hit quorum on disk before CheckFinalQuorum fires. Fixed by weakening to `target_gen >= auth`. | Spec-only; 9 TLA+ specs clean including the new one. |

## Remaining Phase 5 work

Rough ordering; dependencies force roughly this sequence:

### P5-1: Pool layer foundation (`src/pool/`)

Introduces `stm_pool` — the new top-level handle that wraps N `stm_bdev`s. Covers ARCH §4.3 (pool composition) and §4.7 (device lifecycle, minus add/remove/replace which land in P5-4).

Decisions carried from ARCH §4:

- `stm_paddr_t` layout is unchanged: `(device_id: 16 bits, offset: 48 bits)`. Current code already uses this layout with device=0; P5-1 opens it up.
- Device roster persisted in every device's uberblock (per-device copy, reconstructible from any single device).
- Per-device UUID separate from device path (`/dev/nvme0n1` can rename to `/dev/nvme1n1` between reboots).
- Device role ∈ `{DATA, LOG, CACHE, SPARE}` and class ∈ `{SSD, HDD, PMEM, ZNS}`. P5-1 only implements DATA + SSD/HDD; the rest are stubs.
- Roster size ≤ 16 for MVP (fits in UB's reserved tail with room; ARCH §5.13 notes 64-device roster limit pre-spill-to-separate-object).

Format impact: STM_UB_VERSION 4 → 5. New fields in `ub_roster`: device_count, per-device (uuid, role, class, state, size), roster_hash (BLAKE3 over the roster sorted by device_id). All goes in `ub_reserved[1008]` — we have ~256 bytes left after Merkle + keyschema + alloc_root_gen.

### P5-2: Multi-device commit

Rewrites `stm_sync_commit` / `_open` per ARCH §5.6 + `quorum.tla`:

- Coordinator-level commit replaces per-device commit. `stm_sync` gains a `stm_pool *` (not `stm_bdev *`) and iterates the pool's device set on every UB write.
- Phase 1 reservation: write UB at `gen+1` to every ONLINE device, fsync in parallel, wait for quorum.
- Phase 3 final: write UB at `gen+2`, wait for quorum.
- Mount: scan all devices' rings, authoritative_gen = highest quorum-confirmed gen. BEHIND devices flagged for reconcile. Ahead-of-quorum devices (partial Phase 3) get overwritten on next commit.
- Preserves R9 mount-claim UB protocol end-to-end: claim UB at `durable_gen+1` with `ub_alloc_root_gen = durable_gen's alloc_root_gen`.
- Device FAULTED during commit: coordinator observes missing fsync confirmation; if quorum fails, aborts.

### P5-3: Mirror redundancy (`src/redundancy/` or extension of `src/alloc/`)

First redundancy profile: `mirror(n)`. Deliberately simpler than RS/LRC so we can validate the multi-device commit + redundancy integration end-to-end before taking on EC.

- `stm_alloc_reserve_mirror(n, out_paddrs[n])` — returns n paddrs on n distinct devices.
- Write path: issue n parallel writes; succeed on quorum-or-better, fail on less.
- Read path: read from any replica; on tag / csum failure, fall back to next replica.
- Mirror invariant: every logical block is durably stored on n physical paddrs across n devices.
- Crypto: each replica has its own paddr → its own nonce (per ARCH §4.4.3's "nonce naturally differentiates across devices").

### P5-4: Device lifecycle (`src/device-mgmt/`)

- `stm_pool_add_device` — appends to roster, advances `roster_hash`, new device starts empty (lazy add per ARCH §4.7.1).
- `stm_pool_remove_device` — evacuates + removes. Requires pool can still satisfy redundancy profile without it.
- `stm_pool_replace_device` — copy-on-replace (ONLINE→ONLINE) or reconstruct-on-replace (FAULTED→new). Reconstruct uses P5-3's mirror-read to rebuild.
- Device FAIL → DEGRADED state. Return → reconcile (per ARCH §5.8).
- Rebalance (ARCH §4.8) deferred to P5-4b — not needed for basic multi-device operation.

### P5-5: Scrub (`src/scrub/`)

- State machine: IDLE / RUNNING / PAUSED / COMPLETED.
- Pause / resume persistence: progress cursor checkpointed in the allocator tree so restart resumes from where it left off.
- IO throttling via `io_weight` knob (1–100).
- Repair from redundancy: on AEAD tag / csum mismatch in a stripe, read the surviving replicas, rewrite the bad block. Leverages P5-3's mirror-read primitive.
- Exposed via `stm_fs_scrub_start / _pause / _resume / _status`.

### P5-6: R13 adversarial audit

Spawned after P5-1 through P5-5 land. Scope: roster persistence, multi-device commit under partial failure, mirror redundancy, device lifecycle ops, scrub's crash-recovery, concurrent commit + device-fail races.

### Deferred — post-Phase-5

- Reed-Solomon (`rs(k,p)`) and LRC (`lrc(k,l,g)`) erasure coding. Requires Intel ISA-L SIMD integration + stripe geometry + full-stripe write discipline. Non-trivial; lands as its own sub-chunk once the core commit+redundancy shape is proven with mirrors.
- Hot spares (ARCH §4.10).
- Metadata ditto blocks (ARCH §4.5.4) for large pools.
- Class-aware placement (ARCH §4.9).

## ROADMAP §8.2 exit criteria status

- [ ] 4-device RAID-Z-equivalent pool survives single-device failure without data loss. (Requires P5-3 mirror at minimum, or P5-3b RS.)
- [ ] LRC repair 2-3× faster than RS for single-failure scenarios. (Deferred.)
- [ ] Scrub detects + repairs injected corruption. (P5-5.)
- [ ] Rebalance progress persists across restart. (Deferred to P5-4b.)
- [x] `quorum.tla` proves commit-under-partial-failure semantics. (P5-0.)

## Build + verify commands

```bash
cd v2

# Default + sanitizers — 24/24 suites from Phase 4, plus any Phase 5 additions.
cmake -B build -S . -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure

cmake -B build-asan -S . -DSTM_SANITIZE=asan \
    -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure

cmake -B build-tsan -S . -DSTM_SANITIZE=tsan \
    -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build-tsan -j
ctest --test-dir build-tsan --output-on-failure --timeout 180

# All 9 TLA+ specs (quorum.tla joins at P5-0)
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
cd specs
for s in sync concurrency structural balanced merge allocator merkle key_schema quorum; do
    echo "== $s =="
    java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
        -config $s.cfg $s.tla 2>&1 | tail -3
done
```

## Trip hazards carrying into Phase 5

Inherited + new:

- **Nonce uniqueness under multi-device** (ARCH §4.4.3). paddr's device_id naturally differentiates. The existing sync.tla nonce argument (uniqueness of `(paddr, gen)`) lifts to `(device_id, offset, gen)` with no additional burden: `gen` is pool-global monotonic per quorum.tla, and `device_id` distinguishes across devices trivially. Verified post-P5-2 that every AEAD call site threads the device-id-bearing paddr through unchanged.
- **Quorum at mount refuses degraded pools** (P5-0 spec finding). `Cardinality(OnlineDevices) >= QuorumN` is a hard precondition for Mount. Emergency mount (ARCH §5.11) is the only way to mount below quorum; it's an explicit admin opt-in and should be a separate code path, not a relaxation of the default Mount.
- **Orphan "ahead of quorum" gens are legal post-crash** (P5-0 spec finding). A partial Phase 3 write can leave one device at `gen+2` while the rest stay at `gen+1`. The impl must handle this: mount picks the highest QUORUM gen (likely `gen+1`), and the next commit overwrites the orphan device's `gen+2` UB via normal ring rotation. Writing a regression test that reproduces this (kill 2/3 devices mid-Phase-3) is a P5-2 deliverable.
- **Device add/remove changes the roster** (ARCH §5.5.4). Quorum is computed against the roster AT COMMIT TIME, not current roster. A commit that started before a `pool remove` completes must still reach quorum of the pre-remove roster. The `roster_hash` in uberblocks is the witness.
- **Format stability**: roster goes in `ub_reserved`, STM_UB_VERSION bumps 4 → 5 at P5-1. Feature-flag gating per ARCH §5.9.

## Known deltas from ARCH §4 + §5 (owed follow-ups)

- **Rebalance tree-embedded progress** (ARCH §4.8). ARCH envisions the rebalance cursor living in the allocator tree so it survives crashes. P5-4 MVP won't implement rebalance at all; cursor design happens in P5-4b.
- **Device class discovery** (ARCH §4.12). ARCH's open question is "probe via `/sys/block/…/rotational` + `queue/zoned` or require admin declaration". P5-1 requires admin declaration (simpler MVP); auto-probe can graft on later.
- **Log device semantics** (ARCH §4.12). ARCH defers this to §9 (block device). Phase 5 MVP doesn't support dedicated LOG-role devices; add later if ZIL-class latency optimization is wanted.

## References

1. `v2/docs/phase5-status.md` — this file.
2. `v2/docs/phase4-status.md` — Phase 4 exit + invariants Phase 5 builds on.
3. `docs/ARCHITECTURE.md §4` — storage pool.
4. `docs/ARCHITECTURE.md §5` — superblock + quorum.
5. `docs/ROADMAP-V2.md §8` — phase deliverables + exit criteria.
6. `memory/audit_v2_r0_closed_list.md` — cumulative closed-list (R0–R12).
7. `v2/specs/quorum.tla` + `quorum.cfg` — Phase 5 commit spec (P5-0).
