# Phase 5 — status and pickup guide

Authoritative pickup guide for Phase 5 (multi-device + redundancy).
Last update 2026-04-22 after P5-2 landed. Companion to
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
| `a078a38` | **P5-3c: mirror reserve / write fan-out / read fallback**. Enables mirror(n) redundancy end-to-end. Per-device allocator support: `stm_alloc` gains `device_id`, stamped into paddr top 16 bits on reserve, validated at free/ref/lookup. Public setter `stm_alloc_set_device_id` before any reserve on device > 0. Multi-alloc sync: `stm_sync` holds `stm_alloc *allocs[STM_POOL_DEVICES_MAX]` — primary at create/open; devices > 0 via `stm_sync_attach_alloc` (which installs per-device crypt ctx AND lazy-loads the tree from the roots object if mounted). `sync_commit` iterates every attached alloc, commits each, records `(paddr, csum, tree_gen)` in the roots object. Per-tree gen in roots entries: value layout extended 40 → 48 bytes (+8 for le64 root_gen) — trees can have different AEAD gens when `alloc_commit`'s R7c P2-5 short-circuits; the per-entry gen lets attach-time `load_tree_at` use the right nonce. Bug caught mid-impl by the mirror_survives_unmount_remount test (one clean-tree short-circuit → other tree advanced → AEAD-tag mismatch at remount). Mirror APIs: `stm_sync_reserve_mirror` (reserves one paddr per device 0..n-1 via their attached allocs; rollback on partial failure), `stm_sync_mirror_write` (parallel writes + fsyncs; STM_OK on ⌊n/2⌋+1, STM_EQUORUM below), `stm_sync_mirror_read` (tries replicas in order, BLAKE3-verifies each against caller-supplied expected_csum; first match wins; STM_ECORRUPT if all fail). | test_sync_multi +6: mirror(2) + mirror(3) roundtrip, tampered-replica fallback (three progressively-corrupt scenarios), reserve refuses NONE profile, attach_alloc arg validation (device_id=0 primary + uuid mismatch + double-attach), mount-remount with attach-loads-from-roots. test_alloc_roots signatures updated for 5-arg set / 4-arg get / iter-with-gen callback. 43/43 tests green on default + ASan + TSan. 9/9 TLA+ specs clean. |
| `c5ad8d7` | **P5-3b: allocator-roots object** (ARCH §6.1). New `stm_alloc_roots` module (`include/stratum/alloc_roots.h` + `src/alloc_roots/alloc_roots.c`). `ub_alloc_root` now points at the pool-level roots object (kind = new `STM_BPTR_KIND_ALLOC_ROOTS = 8`) instead of directly at a single alloc tree; the roots object is a small AEAD-encrypted Bε-tree (via `stm_btree_store_serialize`) whose leaves carry each device's alloc-tree root bptr keyed by `device_id`. Merkle chain remains transitively complete. For N=1 pools, one entry points at device 0's tree — identical FS-layer behavior, extra indirection. `stm_sync` gains a `stm_alloc_roots *roots` field; `sync_create` creates it, `sync_commit` drives `alloc_commit → roots_set → roots_commit` in sequence, `sync_open` reads via `alloc_roots_load_at`. Dirty-flag idempotency on both `roots_commit` AND `roots_set` (no-op when new value == existing entry) — preserves byte-identical UBs across retry per quorum.tla's ContentQuorumAtGen. Bug caught + fixed during integration: `alloc_roots_commit` calls `bootstrap_commit` at its tail so roots-paddr reservations become durable (otherwise the bitmap's persisted image didn't cover our new paddrs → STM_ECORRUPT on the next commit's free_tree). Format change: `STM_UB_VERSION 5 → 6`. | New `test_alloc_roots.c` (10 tests): unit coverage for set/get/count/iter/commit/load roundtrip + idempotency + tamper detection (wrong csum/key/gen). `test_sync_multi` +3: ub_points_at_alloc_roots, multi_commit_cycle (5 commits + remount + 1 more to exercise free_tree-on-old-roots), v5 UB refusal. `test_pool` +1: v5 version rejection. `test_sync` reworked: sync_ub_alloc_root_matches_tree now asserts the indirection is real (paddr != tree_root, kind = ALLOC_ROOTS). 40/40 tests green on default + ASan + TSan (27 suites; +10 in new test_alloc_roots, +4 in test_sync_multi & test_pool). 9/9 TLA+ specs clean (no spec change). |
| `a52b532` | **P5-3a: UB redundancy profile plumbing**. Threads a pool-wide `stm_redundancy_profile {kind, mirror_n}` through `stm_sync_create` / `stm_sync_open`. The profile is validated up-front (mirror_n in [1..device_count]; RS/LRC → STM_ENOTSUPPORTED forward-reserved) and stamped into every UB's ub_redundancy_kind + ub_redundancy_params[15] at commit. `stm_sync_open` decodes the canonical UB's profile, re-validates (including "mirror(n) on a pool that has since shrunk below n" → STM_ECORRUPT), exposes it via `stm_sync_redundancy_get`. Params encoding is layout-stable: NONE = all 15 bytes zero; MIRROR = params[0]=n, rest zero. Tail-byte checks reject both accidental drift and tamper even though ub_csum already covers the UB. Existing `stm_sync_create` callers pass NULL (= NONE) — 13 call sites updated via perl. Lays the groundwork for P5-3b (per-device alloc trees + alloc-roots object) and P5-3c (`stm_alloc_reserve_mirror` + write fan-out + read fallback). | `test_sync_multi` grows 4 new: mirror(2) roundtrip on NDEV=3 (byte-identical on-disk + round-trips through remount), null-profile-produces-NONE, create-rejects-malformed (mirror(0), mirror(n>3), NONE+n≠0, unknown kind, RS/LRC), mount-rejects-nonzero-tail-on-NONE (with ub_csum fix-up). 30/30 tests green on default + ASan + TSan. 9/9 TLA+ specs clean (no spec change). |
| `57a37e7` | **P5-0: `quorum.tla` formal spec**. Models multi-device commit (ARCH §5.6) with per-device UB rings, parallel reservation + final writes, quorum threshold = ⌊N/2⌋+1, device FAULTED / ONLINE state, rejoin + reconcile, coordinator crash. Proves `TypeOK`, `QuorumSafety` (phase=Published implies ≥quorum devices at target_gen), `AuthoritativeMono` (committed gens never regress), `CommitAtomic` (auth ≥ 2×commits_done), `OrphansNotAuthoritative` (partial-Phase-3 gens held by <quorum devices are never authoritative), `LiveCoordTargetValid` (coord's in-flight target_gen ≥ current auth), `QuorumDurability`, `MountGenBumpMulti`. Mount requires quorum of ONLINE devices (emergency mount is an explicit opt-in not modeled). TLC-clean under `Devices={1,2,3}, MaxCommits=3, MaxFaults=2`: 36839 distinct states, depth 35. Two iterations: initial pass rejected orphan gens from degraded-mount, then caught an over-strict `LiveCoordMonotonic` (`target > auth`) that Fails in the transient state where Phase 3 WriteFinals hit quorum on disk before CheckFinalQuorum fires. Fixed by weakening to `target_gen >= auth`. | Spec-only; 9 TLA+ specs clean including the new one. |
| `15d2d33` | **R14b P2-1: idempotent `stm_keyschema_commit`**. Dirty-flag on stm_keyschema; commit short-circuits and returns cached (paddr, csum) when clean. Symmetric to alloc's R7c P2-5. Closes the only R14b P2 finding — prevents the 3-way retry divergence scenario where rotating single-device successes across retries produce 3 distinct contents at target_gen, causing content-quorum to fail at mount. Regression test `sync_multi_keyschema_commit_idempotent_on_clean` verifies two consecutive sync_commits produce byte-identical ub_key_schema[512] bytes. 27/27 suites green on default + ASan + TSan. 9/9 TLA+ specs clean. |
| `3f946a2` | **R14 P5-2-scope audit close**. Spec-first fix: extended quorum.tla with content dimension + `ContentQuorumAtGen` invariant + `IdempotentRetry` CONSTANT + `RetryPhase3` action. Bonus spec fixes: Mount-overwrite-all, BeginCommit-visible-quorum gate, Reconcile-copy-peer-content. quorum.cfg (IdempotentRetry=TRUE, MaxFaults=0) clean at 2411 states; quorum_buggy.cfg finds ContentQuorumAtGen counterexample at depth 13 (demonstrates P1 at spec level). Impl: content-quorum agreement check in stm_sync_open replaces strict unanimity (groups visible devs at auth_gen by byte-level shared content; ≥quorum-group is canonical; dissenters are ARCH §5.8 orphans); byte-level `sync_ub_shared_bytes_match` auto-covers all shared fields (closes P2 on `ub_alloc_root_gen`); `stm_ub_decode` rejects ub_gen=0 (P3-3); `write_ub_to_all_devices` propagates last hard err on N=1 (P3-5). New test_sync_multi tests for minority divergence tolerated, no-content-quorum rejected, alloc_root_gen tamper detected; test_sb rejects ub_gen=0. |
| `1414cc4` | **P5-2: Multi-device 2-phase quorum commit**. Implements the commit + mount protocols for N-device pools per quorum.tla. Each commit writes reservation at gen=auth+1 (pre-flush roots; rollback target) and final at gen=auth+2 (post-flush roots + new merkle) to every pool device in parallel, with quorum (⌊N/2⌋+1) fsync confirmations required per phase. Mount scans every device, computes auth_gen = highest gen G such that ≥quorum devices have ub_gen ≥ G (derived by sorting valid gens descending and taking the kth element), validates content agreement among quorum members at gen=auth_gen, then writes a claim UB at auth+1 to every device (quorum required). Fresh-pool first commit is 1-phase (no pre-flush state); subsequent commits uniformly 2-phase. Struct cleanup: `stm_sync` drops cached `bdev`/`self_device_id` (no "self" in multi-device), adds `auth_gen` field. `build_uberblock` takes a `target_device_id` param; shared bytes + per-device fields split via a new `write_ub_to_all_devices` helper. New `STM_EQUORUM` status code for quorum-write failures. `stm_sync_info` exposes `auth_gen` alongside `current_gen`. Alloc tree still lives on device 0 (metadata primary) — P5-3+ mirror/RS will fan it out. | New `test_sync_multi.c` (7 tests): 3-device roundtrip, quorum fault tolerance (wipe 1 of 3 devices' UBs; mount succeeds), sub-quorum refusal (wipe 2 of 3; STM_EQUORUM), every-device UB write verification, orphan-ahead-of-quorum (OrphansNotAuthoritative), inconsistent-quorum-content rejection. Existing tests updated for +2 gen arithmetic (fresh commit at gen=1; subsequent commits advance auth by 2). All 26 suites green on default + ASan + TSan. 9/9 TLA+ specs clean. |
| `567b143` | **P5-1: Pool layer foundation**. Introduces `stm_pool` (`include/stratum/pool.h` + `src/pool/pool.c`) wrapping up to 64 `stm_bdev`s — today's configuration is always N=1 (degenerate). Adds `stm_device_state` enum. Populates the uberblock's previously-zero roster fields (`ub_device_count`, `ub_device_id`, `ub_device_class`, `ub_device_role`, `ub_roster[2048]`, `ub_roster_hash`) on every commit. `ub_roster` layout is 32 bytes per slot: `uuid[16] + size[8] + role[1] + class[1] + state[1] + reserved[5]`; up to 64 slots exactly match `ub_roster[2048]`. `ub_roster_hash` is the le64 truncation of BLAKE3-256 over the encoded 2048-byte roster. Refactors `stm_sync_create` / `stm_sync_open` to take a `stm_pool *` in place of `(stm_bdev*, pool_uuid, device_uuid)` — cleaner lifecycle, ready for P5-2 to iterate the pool's device set during commit. `stm_fs_format` builds a 1-device pool from `stm_fs_format_opts` (role=DATA, class=SSD, state=ONLINE default); `stm_fs_mount` peeks the durable UB via `stm_sb_mount_scan`, decodes the roster, constructs a matching `stm_pool`, and hands it to sync. Sync cross-validates `ub_roster_hash` + `ub_pool_uuid` + `ub_device_uuid` against the pool handle before proceeding — catches programmer error and roster tampering that preserved ub_csum. STM_UB_VERSION 4 → 5. v4 pools refused at mount by version check; no feature-flag allocation needed (version bump alone gates per ARCH §5.9). | New `test_pool.c` (12 tests): open validation, roster encode/decode roundtrip, roster hash determinism + identity-change sensitivity, fs format/mount roundtrip populates every roster field, decode rejects leftover bytes + zero UUID in populated slot, sync_open refuses wrong pool_uuid + wrong device_uuid. All 25 suites (24 prior + 1 new) green on default + ASan + TSan. |

## Remaining Phase 5 work

Rough ordering; dependencies force roughly this sequence:

### P5-1: Pool layer foundation (`src/pool/`) — **LANDED**

Landed above P5-0; specifics in the Landed-chunks table. Summary:
`stm_pool` wraps up to `STM_POOL_DEVICES_MAX = 64` `stm_bdev`s (MVP
exercises N=1 only); roster persisted in every device's uberblock
at `ub_roster[2048]` (32-byte slots: `uuid[16] + size[8] + role +
class + state + reserved[5]`); `ub_roster_hash` is the le64
truncation of BLAKE3-256(`ub_roster[2048]`); STM_UB_VERSION bumped
4→5. Sync + FS lifecycle refactored to thread a `stm_pool *` where
previously `(stm_bdev*, pool_uuid, device_uuid)` lived — P5-2 is
now pure body-change (iterate the pool's device set during commit).

### P5-2: Multi-device commit — **LANDED**

Landed above P5-1; specifics in the Landed-chunks table. Summary:
`stm_sync_commit` / `_open` iterate the pool's device set per
phase; each phase requires quorum of fsync confirmations. Commit
protocol is 2-phase (reservation at auth+1 with pre-flush roots,
final at auth+2 with post-flush roots); each commit advances auth
by 2. Mount scans all devices, computes auth via highest gen with
quorum, writes a claim UB at auth+1 (quorum required) and sets
auth_gen = auth+1 post-claim.

Fresh-pool first commit is 1-phase (no pre-flush state). `STM_EQUORUM`
is the new status for quorum-write failures. Alloc tree is still
single-device (device 0, the metadata primary) — multi-device data
redundancy lands in P5-3.

### P5-3: Mirror redundancy — split into three sub-chunks

First redundancy profile: `mirror(n)`. Deliberately simpler than RS/LRC so we can validate the multi-device commit + redundancy integration end-to-end before taking on EC.

**P5-3a: UB redundancy profile plumbing — LANDED (`a52b532`).** See the Landed-chunks table. Threads `stm_redundancy_profile` through sync, stamps it into every UB, validates + decodes at mount. No behavioral change — groundwork for the two chunks that follow.

**P5-3b: allocator-roots object — LANDED (`c5ad8d7`).** See the Landed-chunks table. Summary: `ub_alloc_root` points at a pool-level roots object (`STM_BPTR_KIND_ALLOC_ROOTS`); single-entry today, multi-entry unlocked for P5-3c. STM_UB_VERSION bumped 5 → 6.

**P5-3c: mirror reserve / write fan-out / read fallback — LANDED (`a078a38`).** See the Landed-chunks table. Summary: sync-level mirror API over N attached per-device allocs, exposed as `stm_sync_reserve_mirror` / `_mirror_write` / `_mirror_read`. Landed the full mirror redundancy MVP. Placement is deterministic (devices 0..n-1); a full free-space-weighted scorer per ARCH §6.7.2 follows in a later sub-chunk once extent-manager integration is live.

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

- [x] 4-device RAID-Z-equivalent pool survives single-device failure without data loss. **Mirror(n)** satisfies this at P5-3c — sync_multi_mirror_read_falls_back_on_tamper demonstrates 2-of-3 replica survival. Full 4-device RAID-Z (Reed-Solomon) lands post-Phase-5.
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
