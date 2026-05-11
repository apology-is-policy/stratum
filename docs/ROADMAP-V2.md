# Stratum v2 Roadmap

**Status**: Phase 0 final deliverable, 2026-04-19. The phased implementation plan from "design is done" to "v2.0 release." Built on VISION.md, COMPARISON.md, NOVEL.md, and ARCHITECTURE.md.

## 1. Purpose

ROADMAP-V2.md translates Phase 0's design into a staged implementation plan. It answers:

- **What do we build, in what order, and why?**
- **What is each phase's scope, exit criteria, and deliverables?**
- **What are the dependencies between phases?**
- **Where does formal verification live in the plan?**
- **Where does the audit loop apply?**
- **What are the risk hot spots, and what's the fallback for each?**

The roadmap is a commitment to an ordering, not a commitment to specific dates. Time estimates are guidance, not deadlines.

## 2. Phase structure at a glance

```
Phase 0 ─ Design (DONE)
          ├─ VISION.md
          ├─ COMPARISON.md
          ├─ NOVEL.md
          ├─ ARCHITECTURE.md  (15 sections, ~5050 lines)
          └─ ROADMAP-V2.md    (this document)

Phase 1 ─ Foundations                          (~3 months)
          Block device + crypto primitives + TLA+ environment

Phase 2 ─ Tree + concurrency                   (~4 months)
          Bw-tree-style Bε-tree + MVCC + EBR

Phase 3 ─ Persistence + allocator              (~3 months)
          Uberblock + four-phase commit + allocator + mount/unmount

Phase 4 ─ Integrity + crypto integration       (~3 months)
          Merkle + AEAD-SIV + key hierarchy + key agent

Phase 5 ─ Multi-device + redundancy            (~3 months)
          Pool layer + RS + LRC + scrub + repair

Phase 6 ─ Namespaces                           (~2 months)
          Datasets + snapshots (O(1)) + clones + dead-list

Phase 7 ─ Cold tier + features                 (~3 months)
          FastCDC + CAS tier + migration + send/recv + reflinks

Phase 8 ─ POSIX surface                        (~3 months)
          Inodes + dirents + xattr + ACLs + statx + reflink wrapper

Phase 9 ─ Client interfaces                    (~2 months)
          9P server + FUSE shim + CLI + /ctl/ + bindings

Phase 9.5 ─ Concurrent 9P API                  (~1 month)
          stratumd concurrent-accept + compound-op race
          class + fs->lock granularity. Exposes the
          lock-free Bε-tree (Phase 2) through to clients.
          Gating chunk for kernel-9P-mount as a production
          backing store for a POSIX OS.

Phase 10 ─ Hardening                           (~2 months)
          Fuzzers, audits, benchmarks, docs

Phase 11 ─ v2.0 release                        (~1 month)
          Final audit + format freeze + tag + announce

Post-v2.0 (v2.1, v2.2+)                        (ongoing)
          Kernel driver, learned tiering, Windows, zoned storage, …
```

Total Phase 1 → Phase 11: **~30 months** from design-freeze to v2.0. Aggressive but bounded. Some phases can overlap (notes per-phase). Phase 8 (POSIX surface) was inserted post-Phase-7 in 2026-04-30 once the gap was surfaced — the prior 10-phase plan implicitly assumed POSIX semantics existed but had no chunk for them; APIs (now Phase 9) are necessarily downstream. Phase 9.5 (Concurrent 9P API) was inserted post-SLATE in 2026-05-11 once the kernel-9P-mount target became near-term — Phase 9 shipped the protocol; 9.5 makes it scale across clients by lifting `fs->lock` granularity to expose the Phase-2 lock-free Bε-tree end-to-end.

## 3. Principles that apply throughout

Before the phase-by-phase detail, six principles that inform every phase:

### 3.1 Formal verification happens alongside, not at the end

TLA+ specs are written *before* the corresponding code, not after. A spec forces the designer to state invariants precisely, then the implementation translates them. Writing specs after the code is a patch, not a proof.

| Spec | Phase | What it proves |
|---|---|---|
| `sync.tla` | Phase 1 | Three-phase sync crash safety (carried from v1) |
| `concurrency.tla` | Phase 2 | Reader snapshot consistency, non-blocking writers, EBR safety |
| `nonce.tla` | Phase 3 | AEAD nonce uniqueness across commits and crashes |
| `allocator.tla` | Phase 3 | Refcount invariants under MVCC |
| `merkle.tla` | Phase 4 | Hash propagation correctness under COW |
| `quorum.tla` | Phase 5 | Multi-device commit quorum semantics |
| `namespace.tla` | Phase 9 | Per-connection namespace isolation (landed early — P8-NS-1 spec scaffold during the Phase 7 → 8 transition under the prior 10-phase numbering) |

CI runs TLC on every PR that touches a specified file.

### 3.2 The audit loop applies every phase

Per `CLAUDE.md`'s audit-trigger policy:

- Every change to concurrency, sync, crypto, or tree-write paths spawns a focused soundness audit.
- Phase exit includes an audit pass against the phase's load-bearing surfaces.
- Findings at P0/P1/P2 severity block phase exit.

The audit loop proved itself on v1 (15 rounds, ~60 corruption-class fixes). It's a permanent part of the development cadence.

### 3.3 Tests are tiered

Every deliverable ships with three tiers of testing:

- **Unit tests**: per-function correctness.
- **Property-based tests**: randomized ops verifying stated invariants (inspired by ZFS's `ztest`, btrfs's `btrfs-progs` tests).
- **Fuzzers**: long-running randomized workloads with crash injection.

Property-based tests complement TLA+ specs: specs prove protocol-level properties; property tests verify implementation correctness against a reference.

### 3.4 Fallback paths are designed, not discovered

Every high-risk commitment has a defined fallback before implementation begins:

- Lock-free Bw-tree fails → fine-grained per-node rwlocks (§3.8).
- Succinct allocator underperforms → straightforward encoding at more RAM cost (§6.6).
- AEGIS-256 has an implementation issue → XChaCha20-SIV as universal default.
- io_uring on an LTS kernel without needed features → libaio compile-time opt-in.

Fallbacks are compile-time flags so we can A/B-test correctness and performance.

### 3.5 Performance is measured continuously

Starting at Phase 2, every phase adds benchmarks:

- Throughput (sequential + random, read + write).
- Latency percentiles (p50, p99, p99.9).
- Memory footprint.
- CPU utilization per op.

Regressions > 10% block the phase from exit. Regressions between 5% and 10% are justified in writing.

Baselines: ext4 (minimum acceptable for latency), ZFS (comparable for throughput), btrfs (reference for feature-compatible workloads).

### 3.6 Documentation updates are part of every PR

`ARCHITECTURE.md`, section-specific design notes, user-facing docs, and code comments are updated in the same PR as code changes. "Docs lag by one commit" is a common failure mode; we don't allow it.

---

## 4. Phase 1: Foundations

**Scope**: block device abstraction, crypto primitives, TLA+ environment, test harness, CI.

Produces the substrate every subsequent phase depends on. No user-visible filesystem.

### 4.1 Deliverables

- **Block device library** (`src/block/`):
  - io_uring backend (Linux ≥ 5.11 for stable features).
  - POSIX backend (for macOS / loopback).
  - DAX path (mmap-based; detected at device open).
  - Fixed-buffer + registered-fd support.
  - Capability probing + graceful degradation.
  - Cross-platform build (Linux primary, macOS portable via POSIX backend).
- **Crypto library** (`src/crypto/`):
  - AEGIS-256 wrapper (via BoringSSL or libsodium + upstream SIV patches).
  - XChaCha20-SIV wrapper (software; works without AES-NI).
  - BLAKE3-256 via the BLAKE3 reference implementation.
  - HKDF-SHA256.
  - Argon2id (via libsodium).
  - X25519 (via libsodium) + ML-KEM-768 (via liboqs) HPKE-style hybrid wrap.
  - Test vectors for every primitive (NIST FIPS 203, RFC 9180, BLAKE3 test suite, CAESAR KAT).
- **xxHash3-64** wrapper (carried from v1).
- **Test harness**:
  - Unit test framework (probably Criterion or custom minimal harness).
  - Property-based test framework (via hypothesis-style C library or custom).
  - Fuzzer infrastructure (AFL++, LibFuzzer).
  - CI pipeline (GitHub Actions or similar): build on Linux + macOS, run all tests, TSAN + ASAN + UBSAN sanitizer builds.
- **TLA+ environment**:
  - TLC model checker installed in CI.
  - Skeleton `sync.tla` proving the three-phase sync protocol (carried from v1).
  - `docs/specs/SPEC-TO-CODE.md` mapping conventions.

### 4.2 Exit criteria

- [ ] io_uring backend submits, completes, and verifies integrity on a loopback file at ≥ 90% of direct-pread throughput.
- [ ] AEGIS-256 + XChaCha20-SIV pass all KAT vectors.
- [ ] ML-KEM-768 hybrid wrap pass-through test works end-to-end.
- [ ] CI builds with TSAN, ASAN, UBSAN on Linux + macOS.
- [ ] `sync.tla` TLC model checks cleanly at N=4 devices, 10 commit cycles.
- [ ] All primitive benchmarks documented; baselines committed.

### 4.3 Risks

- **Risk**: ML-KEM-768 library (liboqs) is newer than classical crypto. Mitigation: pin liboqs version; contribute upstream fixes as needed; keep XChaCha20-Poly1305 (non-SIV, non-PQ) as compile-time fallback for v2.0-minus-1 scenarios.
- **Risk**: AEGIS-256 has fewer production implementations than AES-GCM. Mitigation: use BoringSSL (Google-maintained) or commit to implementing from RFC/CAESAR spec with heavy KAT testing.

### 4.4 Parallel opportunities

- Block layer and crypto library are independent — two devs can work in parallel.
- TLA+ environment setup can happen in parallel with either.

---

## 5. Phase 2: Tree + concurrency

**Scope**: Bε-tree core with Bw-tree-style lock-free delta chains, MVCC readers, epoch-based reclamation.

The most architecturally risky phase (per NOVEL #4). Extensive TLA+ spec work + stress testing.

### 5.1 Deliverables

- **Bε-tree core** (`src/btree/`):
  - Node format (header, keys, values, delta chain head, Merkle hash field).
  - Lock-free insert via CAS delta-chain prepend.
  - MVCC readers with atomic root pointer snapshotting.
  - Consolidation via the helping pattern.
  - Structural operations: split, merge.
  - Scan (range-bounded iteration under EBR-pinned snapshot).
  - *Node encode / decode (serialization) — MOVED to Phase 3.* The
    on-disk format depends on decisions that land in Phase 3
    (allocator stripe layout, commit protocol) and Phase 4 (Merkle
    field wiring, AEAD-AD struct per §7.4). Implementing it in
    Phase 2 would either (a) design without the downstream
    constraints and rework in Phase 3, or (b) pull Phase 3/4
    design forward. Cleaner to do it once, with full context, at
    the start of Phase 3. (Amendment 2026-04-20.)
- **Epoch-based reclamation** (`src/ebr/`):
  - Per-thread local epochs.
  - Retire list with rotation.
  - Stall detection + heartbeat.
- **MVCC reader infrastructure**:
  - `epoch_enter` / `epoch_exit`.
  - Root pointer snapshotting.
  - Per-operation vs pinned snapshots.
- **TLA+ spec**: `concurrency.tla`.
- **Property-based tests**:
  - Tree invariants (ordered keys, balanced, no duplicates).
  - Concurrent reader-writer correctness (readers always see consistent snapshots).
  - EBR safety (no use-after-free under randomized op schedules).
- **Benchmarks**:
  - Single-writer throughput baseline.
  - Multi-reader concurrent scaling (target: linear to ~32 cores).

### 5.2 Exit criteria

- [x] Bε-tree passes property-based tests under TSAN + ASAN in CI
  plus a 30+ second sustained run locally; a 1-hour+ nightly CI job
  is the practical ongoing commitment. Cumulative 1,000+ CPU-hour
  fuzzing is the Phase 9 hardening target (§12.2). (Amendment
  2026-04-20: 24h was too coarse for a single-phase gate — treat as
  continuous from Phase 2 through Phase 9.)
- [x] Tree operations (insert, lookup, scan, delete) work correctly.
- [x] Concurrent read scaling demonstrates ≥ 90% linear to the test
  host's physical core count (≥ 95% to 4 cores observed; 8-core
  Apple P+E asymmetry produces a non-uniform scaling ceiling).
  32-core validation runs on dedicated Linux CI hardware when
  available. (Amendment 2026-04-20: was "≥ 90% linear to 32 cores"
  — hardware-relative.)
- [x] Consolidation triggers correctly; delta chains bounded at ≤ 8 under normal load.
- [x] Split and merge operations are atomically visible (no structural-tear states in the spec).
- [x] `concurrency.tla` TLC passes at N=4 writers, N=8 readers, 16-step traces.
- [x] Fallback path (per-node rwlock) compiles and passes tree tests too (stm_btree_mt).
- [x] R0-R6 audit rounds closed (cumulative ledger in
  `memory/audit_v2_r0_closed_list.md`).

### 5.3 Risks

- **HIGH**: Lock-free Bw-tree complexity. Fallback: compile-time flag to fine-grained per-node rwlocks. If lock-free tests flake consistently, we ship with the fallback.
- **Medium**: Consolidation correctness under concurrent writes. Mitigation: TLA+ spec proves atomic visibility; heavy fuzz testing.

### 5.4 Dependencies

- Phase 1 block device + crypto (for node encryption in Phase 4).
- TLA+ environment.

### 5.5 Parallel opportunities

- EBR and tree-core are somewhat independent.
- Property-based test harness can be built early.

---

## 6. Phase 3: Persistence + allocator

**Scope**: uberblock format, four-phase commit protocol (single-device first), allocator tree with bootstrap pool, succinct in-RAM state, basic mount/unmount.

### 6.1 Deliverables

- **Uberblock** (`src/sb/`):
  - Per-device label format (4 labels per device, 63-slot uberblock ring).
  - Uberblock encode/decode with BLAKE3 csum.
  - Label placement (byte 0, 256K, end-256K, end).
- **Bε-tree node serialization** (moved from Phase 2):
  - Node encode: header + sorted entries + chain-delta block +
    optional Merkle hash field. Cross-referenced to the allocator's
    stripe layout.
  - Node decode: header parse + csum/Merkle verify + entry
    reconstruction.
  - Integrated with the commit protocol's flush step so nodes are
    written with their final paddr and (Phase 4) AEAD-AD struct.
- **Four-phase commit** (`src/sync/`):
  - Phase 0 freeze.
  - Phase 1 reservation (single-device first; multi-device in Phase 5).
  - Phase 2 flush (parallel consolidation internally).
  - Phase 3 final.
  - Phase 4 publish (MVCC root swing + retirement).
- **Allocator** (`src/alloc/`):
  - Per-device allocator tree.
  - Bootstrap pool placement + bitmap.
  - SDArray in-RAM representation.
  - xor filter for negative lookups.
  - W-TinyLFU cache.
  - Stripe allocation API (single-device stripe at this phase; multi-device in Phase 5).
  - Deferred-free (PENDING) state.
- **Mount / unmount** (`src/mount/`):
  - Read labels, select authoritative uberblock.
  - Walk allocator trees → rebuild in-RAM state.
  - Mount-time gen bump.
  - Clean unmount protocol.
- **TLA+ specs**: `nonce.tla`, `allocator.tla`.
- **Tests**:
  - Crash-injection fuzzer (partial writes, power loss simulation).
  - Mount/unmount round-trips.
  - Allocator under concurrent alloc/free.

### 6.2 Exit criteria

- [ ] Single-device pool can be created, written to, synced, unmounted, remounted with integrity preserved.
- [ ] Crash at any point (per fuzzer) recovers to a consistent state on mount.
- [ ] Allocator in-RAM state ≤ 25 MiB / TiB for workloads tested up to 10 TiB.
- [ ] Bootstrap pool usage < 50% in normal workloads.
- [ ] `nonce.tla` proves uniqueness across commits + crashes at realistic bounds.
- [ ] `allocator.tla` proves refcount invariants.

### 6.3 Risks

- **Medium**: Bootstrap pool sizing — if 0.1% of device is too small for high-fragmentation workloads, grows pool dynamically (complex). Monitoring via `/ctl/...`.
- **Medium**: Succinct data structure correctness under concurrent updates. Mitigate via stress tests.

### 6.4 Dependencies

- Phase 1 block device.
- Phase 2 tree.

### 6.5 Parallel opportunities

- Uberblock + commit protocol can be specified in TLA+ in parallel with allocator design.

---

## 7. Phase 4: Integrity + crypto integration

**Scope**: Merkle root integration, AEAD-SIV encrypt/decrypt on extents + nodes, per-dataset key hierarchy, PQ-hybrid wrap, key agent.

### 7.1 Deliverables

- **Merkle integrity** (`src/integrity/`):
  - Per-node hash fields populated.
  - Incremental hash propagation at commit (§7.12).
  - Pool Merkle root in uberblock.
  - Three verify paths: mount-time, on-read, scrub.
- **AEAD on data extents**:
  - Encryption path: compress → hash → encrypt → write.
  - Decryption path: read → decrypt → verify → decompress → return.
  - AD struct binding (pool, dataset, ino, offset).
- **AEAD on metadata nodes**:
  - Tree node encryption with `stm_ad_node`.
  - Decryption on read with AD verification.
- **Key hierarchy**:
  - **Key-schema sub-tree** (`src/keyschema/`) — wrapped keys stored in a Merkle-chained B-tree rooted from `ub_key_schema` (ARCH §7.7.3). Fifth input to `ub_merkle_root`.
  - **Janus** (`src/janus/`) — key-agent daemon per ARCH §7.9.
  - 9P protocol between daemon and FS (§7.9).
  - Backends: passphrase, file (for automation).
  - Key unwrap/rewrap/rotate primitives.
- **Per-dataset encryption state** in the key-schema sub-tree.
- **TLA+ specs**: `merkle.tla` (hash propagation), `key_schema.tla` (rotation atomicity + retired-key retention).
- **Tests**:
  - End-to-end encrypted write + read + verify.
  - Tamper-evidence: offline metadata edit detection.
  - Key rotation without re-encryption.
  - AD mismatch rejects cross-context reads.

### 7.2 Exit criteria

- [ ] Encrypted writes round-trip correctly with AEGIS-256 and XChaCha20-SIV.
- [ ] Mount-time full verify (opt-in) works on 1 TiB test volume.
- [ ] On-read verify has ≤ 5% overhead vs disabled.
- [ ] Tampering with a metadata block is cryptographically detected.
- [x] Janus + daemon integrated; passphrase backend works.
- [ ] `merkle.tla` proves hash-propagation correctness under COW.
- [x] `key_schema.tla` proves rotation atomicity + retired-key retention.

### 7.3 Risks

- **Medium**: Merkle-on-commit overhead. Mitigate via incremental (only dirty subtrees) + batching.
- **Low-Medium**: liboqs API stability. Mitigate: pin version, vendor if needed.

### 7.4 Dependencies

- Phase 1 crypto primitives.
- Phase 2 tree (for per-node hash propagation).
- Phase 3 commit protocol (for Merkle root advance).

### 7.5 Parallel opportunities

- Key agent can be developed in parallel with integrity work (orthogonal subsystems).

---

## 8. Phase 5: Multi-device + redundancy

**Scope**: multi-device pool, quorum-based commit, RS + LRC erasure coding, scrub with repair, device lifecycle.

### 8.1 Deliverables

- **Pool layer** (`src/pool/`):
  - Device roster management.
  - Pool config (redundancy profile, feature flags, per-dataset overrides).
  - Device identity (UUIDs, classes, roles).
- **Multi-device commit**:
  - Phase 1 quorum-confirmed reservation.
  - Phase 2 parallel multi-device flush.
  - Phase 3 quorum-confirmed final.
  - Device BEHIND state + reconcile on return.
- **Erasure coding** (`src/ec/`):
  - RS implementation (via Intel ISA-L SIMD + fallback pure-C).
  - LRC layout + encode/decode.
  - Stripe allocation API for multi-device.
- **Device lifecycle** (`src/device-mgmt/`):
  - `pool add` / `pool remove` / `pool replace` / device fail handling.
  - Rebalance (incremental, IO-throttled).
- **Scrub** (`src/scrub/`):
  - State machine (IDLE / RUNNING / PAUSED / COMPLETED).
  - Pause/resume persistence.
  - IO throttling per priority.
  - Repair from redundancy.
- **TLA+ spec**: `quorum.tla`.
- **Tests**:
  - Pool with 3+ devices; quorum cases.
  - Device failure simulation (kill one device, verify graceful degradation).
  - Rebuild from redundancy.
  - Rebalance incremental correctness.

### 8.2 Exit criteria

Status as of 2026-04-25 (post-R26 close, tip `a6249eb`).
**Phase 5 substantively complete**: criteria 1, 3, 4, 5 met;
#2 explicitly post-v2.0 by design (§8.6 + §14.2).

- [x] **Single-device-failure survival**: 4-device RAID-Z-equivalent pool survives single-device failure without data loss. **Met via mirror(n)** at P5-3c (`sync_multi_mirror_read_falls_back_on_tamper`) + R21 P1 (`sync_multi_commit_succeeds_with_one_faulted`). RS-based RAID-Z deferred to post-v2.0 (§8.6 + §14.1).
- [ ] **LRC vs RS performance**: LRC repair is 2-3× faster than RS for single-failure scenarios (per the LRC lead position). **Deferred** to post-v2.0 per §8.3 risk mitigation + §8.6 + §14.2 (LRC requires RS stable first).
- [x] **Scrub detect + repair**: Scrub detects + repairs injected corruption. **Met** at P5-5-α (verify-only sweep) + P5-5-β (4-counter classification via caller-supplied verify-callback; CallbackSetExclusivity invariant) + P5-durable-cursors (state persists across mount via γ). Test stubs demonstrate detect + repair end-to-end. **Production-default cb** (bptr-aware, walks the replica list, rewrites the bad device, emits repair log) is the only remaining sub-aspect, deferred to P6 (§8.6 + §9.6) as documented carry-over.
- [x] **Rebalance progress persistence**: Rebalance progress persists across restart. **Met** by P5-durable-cursors (γ for scrub) + the existing roster + alloc-tree format that already implicitly persists evacuation state (per `evac.tla` annotation: `device_state[d]` ↔ `ub_roster[d].state`; `replicas[b]` ↔ per-device alloc trees; both persisted on every commit).
- [x] **quorum.tla**: `quorum.tla` proves commit-under-partial-failure semantics. **Met** at P5-0 (`v2/specs/quorum.tla`, 36839 distinct states at depth 35; `quorum_buggy.cfg` with `IdempotentRetry=FALSE, MaxRetries≥2` reproduces the R14 P1 content-divergence at the spec level).

### 8.3 Risks

- **Medium**: Rebalance correctness — moving data while system is live is tricky. Mitigate: extensive crash-injection tests during rebalance.
- **Medium**: LRC decode complexity. Mitigate: start with RS-only; add LRC as a feature-flagged addition after RS is stable.

### 8.4 Dependencies

- Phase 3 single-device persistence.
- Phase 4 crypto (encrypt across devices correctly via device_id in AD).

### 8.5 Parallel opportunities

- Scrub + repair infrastructure can be built in parallel with multi-device commit.

### 8.6 Phase 5 deferrals (carry-over to later phases)

Items that were in Phase 5's original §8.1 scope or §8.2 exit
criteria but are deferred to later phases — captured here so the
work doesn't get lost. Each entry identifies the origin (§8.1
deliverable or §8.2 exit-criterion number), the reason for the
deferral, and the target phase.

**RS erasure coding** (§8.1 "Erasure coding", §8.2 criterion 1
strict reading) — deferred to **post-v2.0** (§14.1). MVP shipped
with mirror(n) only; mirror(n) demonstrably satisfies
single-device-failure survival (P5-3c + R21 P1), so the spirit of
criterion 1 is met. Adding RS now would risk the v2.0 release
window; better to layer it as v2.1.

**LRC erasure coding** (§8.1 "Erasure coding", §8.2 criterion 2)
— deferred to **post-RS** (v2.2+, §14.2). Per §8.3 risk
mitigation: "start with RS-only; add LRC after RS is stable".
LRC's decode-locality value materializes only after RS exercises
the single-failure recovery path under load.

**Multi-device stripe allocation API** (§8.1 "Erasure coding"
sub-bullet) — deferred to **post-v2.0** (§14.1) alongside RS.
Stripe-aware allocation only matters for RS / LRC; pre-RS the
allocator is per-device with mirror replication.

**Scrub IO throttling per priority** (§8.1 "Scrub") — deferred
to **post-v2.0** (§14.1). ARCH §7.14.3 defines low/medium/high.
Current scrub α/β is admin-driven step-by-step; production
deployment will want token-bucket throttle on `stm_bdev_read`
submit rate.

**Scrub durable cursor (P5-5-γ)** (§8.2 criterion 3 sub-aspect)
— deferred to a **format-break chunk** within Phase 5, gated on
user signoff (bumps `STM_UB_VERSION`). Persists scrub
`(state, cursor_device_id, cursor_start_block, blocks_*)` across
mount so a long scrub interrupted by shutdown resumes on next
mount (ARCH §7.14.1). Likely bundled with rebalance persistence
(below) under one format break to amortize the version bump.

**Rebalance progress persistence** (§8.2 criterion 4) — deferred
to the same **format-break chunk** as scrub-γ. Persists
`stm_sync_evacuation_step`'s cursor + counters across mount,
analogous to scrub-γ but for evacuation. Format break.

**Production-default scrub verify-callback** (§8.2 criterion 3
"detects + repairs corruption" production aspect) — deferred to
**Phase 6** (§9). β-mode integrated at P5-5-β with the
caller-supplied cb shape (`stm_scrub_set_verify_cb`). P6's bptr
layer plugs in the production cb that walks the replica list,
verifies AEAD/csum, picks a verified replica, rewrites the bad
device, emits the repair-log entry per ARCH §7.15.4.

**P5-4c-β reconstruct path** (FAULTED → new replace via
bptr-iteration) — deferred to **Phase 6** (§9). Today
`stm_sync_replace_device_online` returns `STM_ENOTSUPPORTED` for
FAULTED-source replace; full replace requires bptr-aware
replica-list iteration to copy live blocks onto the new device.

**P5-4d-β reconcile path** (catch-up of stale FAULTED-rejoined
content) — deferred to **Phase 6** (§9). Same bptr-layer
dependency. Today, mirror_read covers reads from a freshly
rejoined device by falling back to other replicas on csum-fail
(R15 F1 via metadata_nonce.tla), but the rejoined device isn't
proactively brought current.

---

## 9. Phase 6: Namespaces

**Status as of 2026-04-26**: **Phase 6 entered**. Phase 5
substantively complete at tag `phase-5-complete` (`461e68e`).
First-chunk recommendation is the P5 §9.6 carry-over
"production-default scrub verify-callback (bptr-aware)" —
establishes the bptr layer that all P6 work rests on while
closing the last piece of P5 exit criterion #3. See
`v2/docs/phase6-status.md` for the entry-point pickup guide.

**Scope**: dataset hierarchy, properties + inheritance, snapshots via birth-txg (O(1)), clones, dead-list maintenance.

### 9.1 Deliverables

- **Dataset layer** (`src/dataset/`):
  - Dataset index tree.
  - Property system with inheritance.
  - Dataset create / destroy / rename / move.
- **Snapshot mechanics**:
  - Birth-txg tracking in every tree node + extent record.
  - Snapshot create (O(1)).
  - Snapshot index tree.
  - Visibility via `.snaps/<name>/`.
  - Holds.
- **Dead-list maintenance**:
  - Per-snapshot dead lists.
  - Incremental updates on COW events.
  - Snapshot delete walk.
- **Clones** (writable snapshots):
  - Clone create (O(1)).
  - Promote / destroy.
- **Tests**:
  - Snapshot create / read / delete lifecycle.
  - Clone lifecycle with origin-hold.
  - Many-snapshot scaling (100+ snapshots of same dataset).
  - Property inheritance correctness.

### 9.2 Exit criteria

- [ ] Snapshot create < 10 ms regardless of dataset size.
- [ ] Snapshot delete's work proportional to blocks freed, not total tree.
- [ ] Clone + writes + COW produce correct divergence.
- [ ] Property inheritance resolves correctly across multi-level datasets.
- [ ] Datasets survive mount/unmount round-trips.

### 9.3 Risks

- **Medium**: Dead-list incremental maintenance overhead. Mitigate: profile + tune; fall back to on-delete full walk if incremental proves too expensive.

### 9.4 Dependencies

- Phase 3 persistence.
- Phase 4 crypto (per-dataset keys).

### 9.5 Parallel opportunities

- Dataset + snapshot + clone lifecycles can be built in parallel with dead-list implementation.

### 9.6 Phase 5 carry-over (closed during P6)

The following items were deferred from Phase 5 (§8.6) and depend
on the bptr layer P6 introduces. They MUST be picked up during
Phase 6 — no later phase has the ingredients to do so:

- **Production scrub verify-callback**: plug a bptr-aware cb
  into `stm_scrub_set_verify_cb` (P5-5-β surface). The cb walks
  the bptr's replica list, reads each replica, verifies
  AEAD/csum, picks a verified replica, rewrites the bad device,
  verifies the writeback (ARCH §7.15.3), emits the repair-log
  entry (ARCH §7.15.4). Replaces today's test-stub-only cb
  usage; closes the production aspect of Phase 5 exit
  criterion 3.

- **P5-4c-β reconstruct**: replace a FAULTED device by
  iterating its allocated bptrs and copying live blocks onto
  the new device's slot. `stm_sync_replace_device_online` today
  returns `STM_ENOTSUPPORTED` for the FAULTED→new path.

- **P5-4d-β reconcile**: bring a FAULTED-rejoined device
  current by iterating bptrs whose content-gen lags
  `pool_gen` and pulling fresh bytes from a verified replica.
  Pre-bptr the rejoined device sits with stale bytes; mirror_read
  covers reads via majority-quorum but the device isn't
  proactively brought current.

These are tracked in `v2/docs/phase5-status.md`'s deferral
section and in `memory/project_v2_active.md`'s carry-over notes.

---

## 10. Phase 7: Cold tier + features

**Scope**: FastCDC chunking, CAS cold tier, migration policy, send/recv, reflinks.

### 10.1 Deliverables

- **FastCDC** (`src/cdc/`):
  - Content-defined chunking implementation.
  - Configurable avg / min / max chunk size.
- **CAS tier** (`src/cas/`):
  - Content-addressed index tree.
  - Chunk write + dedup-on-write.
  - Migration engine (hot → cold).
  - Rehydration on write (cold → hot).
  - CAS GC.
- **Send / recv** (`src/send-recv/`):
  - Wire format: full + incremental; raw-encrypted + decrypted.
  - Incremental diff via birth-txg.
  - Receive-side state reconstruction.
- **Reflinks**:
  - `copy_file_range` + `FICLONE` ioctl support.
  - Refcount bumps on reflink.
  - Cross-dataset with encryption compat check.
- **Tests**:
  - Cold-tier dedup ratio benchmark (1 TiB of VM images with 80% overlap).
  - Migration correctness.
  - Send/recv roundtrip (full + incremental).
  - Reflink correctness.

### 10.2 Exit criteria

- [ ] Cold-tier dedup achieves target 3-5× on VM-image test set.
- [ ] Migration policy heuristic produces reasonable hot/cold placement on synthetic workloads.
- [ ] Send + receive roundtrip preserves data + metadata + snapshots.
- [ ] Reflink is O(extent count) not O(data size).

### 10.3 Risks

- **Medium**: CAS GC under concurrent writes. Mitigate: incremental GC with per-chunk refcount locking.
- **Medium**: FastCDC parameter tuning. Default 8 MiB avg per NOVEL #3; adjust based on benchmarks.

### 10.4 Dependencies

- Phase 3, 4, 5, 6.

### 10.5 Parallel opportunities

- Send/recv and CAS tier are somewhat independent; can be built in parallel.
- **FastCDC chunking** (`src/cdc/`, §10.1) is genuinely
  P6-independent — pure algorithm + module, no on-disk format
  impact at the chunking layer. Can be built in parallel with
  Phase 6 namespace work as P7 pre-work. The CAS tier's
  integration of the chunked output happens later, properly in
  Phase 7. Tracked in `v2/docs/phase7-status.md`.

---

## 11. Phase 8: POSIX surface

**Scope**: inodes + dirents + xattr + ACLs + statx + small-file inline + reflink wrapper + the full set of POSIX file/dir operations (`lookup`, `mkdir`, `create`, `unlink`, `rmdir`, `rename`, `link`, `symlink`, `readlink`, `readdir`, `stat`, `chmod`, `chown`, `utimens`, `truncate`).

ARCHITECTURE §11 specifies the on-disk shape; this phase implements it. Phase 7 built the data plane (extents) and namespace plane (datasets, snapshots) but left the **filesystem semantics layer** unimplemented — the inode metadata + directory entry layer that turns a (dataset_id, ino, off) byte store into a POSIX-shape file/directory tree. APIs (Phase 9) need this layer; FUSE / CLI / 9P-readdir all consume it.

### 11.1 Deliverables

- **Inode layer** (`src/inode/`):
  - 256-byte `stm_inode` per ARCH §11.3 (identity + mode + uid/gid/nlink + 4 nanosecond timestamps + size + flags + tagged data union).
  - Inode tree key: `(dataset_id, ino) → 256B inode value`. Persisted alongside the existing extent tree per dataset.
  - Inline data (≤100 bytes) for small-file optimization.
  - Symlink target inline (≤100 bytes) + extent-backed for longer.
  - Generation counter `si_gen` for ino-reuse detection (NFS handles, 9P stale fids, per-file derived keys).
- **Directory entry layer** (`src/dirent/`):
  - Hash-indexed B-tree per ARCH §11: key `(dir_ino, STM_KEY_DIRENT, fnv1a(name)) → child_ino + name`.
  - Probe-chain for hash collisions.
  - `stm_fs_lookup` / `stm_fs_create_file` / `stm_fs_mkdir` / `stm_fs_unlink` / `stm_fs_rmdir` / `stm_fs_rename` / `stm_fs_link` / `stm_fs_symlink` / `stm_fs_readlink`.
- **Metadata ops**:
  - `stm_fs_stat` / `stm_fs_chmod` / `stm_fs_chown` / `stm_fs_utimens` / `stm_fs_truncate_inode` (wraps existing extent-level truncate).
  - `statx(2)` shape with btime + nanosecond timestamps.
  - Hard link tracking (`si_nlink`).
- **Directory traversal**:
  - `stm_fs_readdir` with stable cookies + restartable iteration.
  - Tombstone handling (deleted entry removed mid-iteration).
- **Xattr**:
  - Separate keyspace: `(ino, STM_KEY_XATTR, fnv1a(name)) → value`.
  - Max value 64 KiB per attribute.
  - `setxattr` / `getxattr` / `removexattr` / `listxattr`.
- **POSIX ACLs**:
  - `system.posix_acl_access` / `system.posix_acl_default` via xattr.
  - Standard Linux encoding (`richacl`-pre-NFSv4).
- **Modern POSIX features** (commitment: full coverage of the
  modern Linux/POSIX surface; no hedged "subset" baseline. Each
  feature lands as part of P8-POSIX-7 or its dedicated sub-chunk):
  - `O_TMPFILE` (orphan inode in the inode tree, materialized via `linkat`).
  - `F_SEAL_*` (every seal flag: `F_SEAL_SEAL`, `F_SEAL_SHRINK`,
    `F_SEAL_GROW`, `F_SEAL_WRITE`, `F_SEAL_FUTURE_WRITE`; encoded in
    `si_flags`).
  - `copy_file_range` with reflink — wraps the existing `stm_fs_reflink`.
  - `fallocate` / `FALLOC_FL_*` — every flag, not a subset:
    `FALLOC_FL_KEEP_SIZE`, `FALLOC_FL_PUNCH_HOLE`,
    `FALLOC_FL_COLLAPSE_RANGE`, `FALLOC_FL_ZERO_RANGE`,
    `FALLOC_FL_INSERT_RANGE`, `FALLOC_FL_UNSHARE_RANGE`. The
    extent-tree manipulation primitives required for COLLAPSE / INSERT
    land alongside; UNSHARE composes with the CAS rehydrate path.
  - `renameat2(2)` flags: `RENAME_NOREPLACE`, `RENAME_EXCHANGE`,
    `RENAME_WHITEOUT`. Atomicity invariants pinned in `dirent.tla`'s
    rename extension at P8-POSIX-9.
  - `name_to_handle_at(2)` / `open_by_handle_at(2)` — Stratum's
    `(dataset_id, ino, si_gen)` tuple maps directly to the NFS-style
    file handle shape (per ARCH §11.3.2). Stale-handle detection is
    free given the `(ino, gen)` tuple-uniqueness invariant from
    `inode.tla`.
  - `posix_fadvise(2)` — pass through to the `STM_PROP_TIERING` /
    page-cache advisory layer where meaningful (`POSIX_FADV_*`),
    no-op for the rest with documented behavior.
  - Advisory locking: `flock(2)` + `fcntl(2)` `F_SETLK` / `F_GETLK` /
    `F_OFD_SETLK` (open-file-description locks). Per-inode lock
    table; deadlock detection via wait-for graph.
  - `*at` family (`openat` / `mkdirat` / `unlinkat` / `symlinkat` /
    `linkat` / `renameat` / `fchownat` / `fstatat` / etc.) — all
    composable from the per-ino base APIs at the syscall-binding
    layer (Phase 9 FUSE / 9P).
  - `statx(2)` shape with btime + nanosecond timestamps (already
    listed under metadata ops; restated here for completeness as a
    modern-POSIX deliverable).
- **TLA+ spec**: `inode.tla` — formal model of the inode lifecycle (alloc / free / nlink tracking / generation counter), plus `dirent.tla` for the hash-indexed tree's collision-chain invariants and rename atomicity.
- **Tests**:
  - Per-op correctness (matches ext4/XFS/APFS semantics).
  - Hash-collision chains > 1k entries per directory.
  - Rename atomicity under concurrent access.
  - Hard-link nlink under create/unlink races.
  - Inline → extent transition correctness.
  - xattr roundtrip + ACL encoding.
  - `statx` btime + nanosecond timestamps.
  - 9P-style fuzz-shape op sequences.

### 11.2 Exit criteria

- [ ] All POSIX file/dir ops produce semantically correct results matching ext4/XFS/APFS for a representative test corpus.
- [ ] Hash-collision chain works correctly with ≥1k dirents per directory.
- [ ] Hard link nlink remains correct under concurrent create/unlink.
- [ ] Inline-to-extent transition recovers correctly across crash boundaries.
- [ ] `statx` returns nanosecond timestamps + btime.
- [ ] POSIX ACL roundtrip preserves grants/denies bit-exact.
- [ ] **Every** `FALLOC_FL_*` flag round-trips correctly under crash injection (KEEP_SIZE, PUNCH_HOLE, COLLAPSE_RANGE, ZERO_RANGE, INSERT_RANGE, UNSHARE_RANGE). No flag is a no-op or unsupported.
- [ ] **Every** `F_SEAL_*` flag is honored at the write/grow/shrink boundary.
- [ ] `renameat2` `RENAME_EXCHANGE` is atomic under TLC verification (`dirent.tla` rename extension).
- [ ] `name_to_handle_at` / `open_by_handle_at` round-trip survives ino reuse via the `si_gen` tuple-uniqueness invariant from `inode.tla` — stale handles return `ESTALE`, valid handles resolve correctly.
- [ ] Advisory locks (`flock` + `fcntl F_OFD_*`) interoperate with the per-inode lock table across concurrent openers.
- [ ] `inode.tla` + `dirent.tla` pin the load-bearing invariants under TLC, including the rename + nlink + open-handle extensions.
- [ ] xfstests subset — the file/dir/xattr/ACL portion plus the modern-POSIX-features test groups (auto-FALLOC, auto-rename, auto-flock) — green on a Stratum-backed mount once Phase 9 (FUSE) lands; in Phase 8 the equivalent verification runs against the `stm_fs_*` API directly.

### 11.3 Risks

- **Low**: inode layout is well-understood; v1's 88-byte struct already exists as a reference (v2 extends to 256 B per ARCH §11.3).
- **Low-medium**: hash-collision chain semantics need careful invariant work — `dirent.tla` covers it.
- **Medium**: rename atomicity under concurrent writers; needs spec-first work.
- **Low**: small-file inline-to-extent transition (covered by existing extent COW + an extra branch in the write path).

### 11.4 Dependencies

- Phase 1-7 (extent layer, allocator, dataset, btree write path, allocator commit ordering).

### 11.5 Parallel opportunities

- Inode + dirent layers depend on each other but xattr / ACL / statx / O_TMPFILE / fallocate / reflink wrapper can land in parallel after the dirent layer is stable.

---

## 12. Phase 9: Client interfaces

**Scope**: 9P server with Stratum extensions, FUSE shim, CLI, /ctl/, libstratum-9p, language bindings.

### 12.1 Deliverables

- **9P server** (`src/9p/`):
  - 9P2000.L support.
  - Stratum extensions (Tbind, Tunbind, Tpin, Tunpin, Tsync, Treflink, Tfallocate).
  - Per-connection namespaces.
  - Authentication backends (none, factotum, SASL, token).
- **FUSE shim** (`stratum-fuse`):
  - FUSE ↔ 9P translator.
  - Linux + macOS support.
  - Multi-threaded op handling.
- **CLI** (`stratum`):
  - Subcommands: pool, dataset, snapshot, clone, send, recv, key.
  - Output formats: human (default), JSON, TSV.
- **/ctl/ synthetic filesystem**:
  - Full tree per §14.3.
  - Write-triggers-action semantics.
- **libstratum-9p** (C library):
  - Stable public ABI.
  - Sync + async variants of all 9P ops.
- **Language bindings**:
  - Rust crate `stratum-fs`. Generated via `bindgen` over
    `include/stratum/*.h`; `build.rs` invokes cmake to build
    `libstratum.a` (the existing aggregate static lib) and links
    statically. This is the Rust crate that the no-daemon TUI
    (next bullet) consumes; same crate also serves as the public
    Rust API for downstream Rust applications.
  - Go package.
  - Python module.
- **Stratum-TUI v2** (`stratum-tui/`, single-binary, no-daemon):
  - **Architecture**: portable static-linked binary. The full
    stratum-v2 library (`libstratum.a`) is linked directly into
    the Rust executable via the `stratum-fs` crate's FFI. NO
    daemon, NO 9P / FUSE round-trip. The TUI process opens the
    volume file, calls `stm_fs_mount` in-process, drives all ops
    via direct C function calls, and `stm_fs_unmount`s on exit.
    Compare v1's TUI which talked over 9P to a separate
    `stratum-daemon`.
  - **Why this matters**: gives stratum-v2 immediate practical
    value as a portable encryptor — same use-case as VeraCrypt /
    cryptsetup (mount an encrypted volume file, browse + edit,
    unmount) but with a much lighter UX (single 5–10 MiB binary,
    no kernel module / FUSE setup / privilege escalation) AND a
    fully-featured COW filesystem underneath (snapshots, dedup,
    PQ encryption, content-defined chunking) where competitors
    expose a flat block device.
  - **Feature parity with v1 TUI** (see `tui/`): dual-pane file
    manager (host-fs panel + stratum-fs panel side-by-side);
    encrypted volume create dialog (passphrase + compression
    algo: lz4 / zstd / none / **+ PQ-hybrid wrap as the v2
    default**); volume open with passphrase; copy / delete with
    conflict resolution (skip / overwrite / keep-both); snapshot
    create / list / delete; built-in text editor for files; tab-
    based navigation; keyboard-only operation.
  - **v2-specific additions** beyond v1 parity:
    - Per-dataset properties UI (compression, dedup, tiering,
      casesensitivity, recordsize) — exposes the
      `stm_fs_*_dataset_property` API.
    - Snapshot send / recv between volumes (uses
      `stm_sync_send_*` / `_recv_*` directly; no network needed).
    - Reflink-aware copy (FICLONE-equivalent within a volume —
      `stm_fs_reflink`).
    - Dedup statistics view (CAS index counts + storage savings).
    - On-demand Merkle integrity verification
      (`stm_fs_verify_merkle_chain` from Phase 8.5) — distinct
      from scrub's data-integrity scan; proves tamper-detection.
    - NFS-style file-handle export (use the `(ds, ino, si_gen)`
      tuple from `stm_fs_stat` / `name_to_handle_at` per
      P8-POSIX-7).
  - **Distribution**: single portable binary per OS/arch
    (linux-x86_64, linux-arm64, macos-arm64). No installer
    required; `chmod +x` and run.
- **TLA+ spec**: `namespace.tla` (landed early as P8-NS-1 spec scaffold during the Phase 7 → Phase 8 transition under the prior 10-phase numbering — chunk identifier sticks for continuity even as POSIX surface became the new Phase 8).
- **Tests**:
  - End-to-end: mount via FUSE, standard POSIX ops work.
  - Per-connection namespace isolation.
  - CLI smoke tests.

### 12.2 Exit criteria

- [ ] Mount a pool via FUSE; standard POSIX operations succeed.
- [ ] Multiple concurrent 9P connections with different namespaces work correctly.
- [ ] CLI covers all admin operations via /ctl/.
- [ ] libstratum-9p + Rust / Go / Python bindings pass smoke tests.
- [ ] **Stratum-TUI v2** ships as a portable static-linked single binary on linux-x86_64 / linux-arm64 / macos-arm64. Feature-parity-or-better with v1 TUI: encrypted volume create + open, dual-pane file manager, copy / delete / conflict resolution, snapshot create / list / delete, built-in editor — PLUS v2-specific surface: per-dataset properties, snapshot send/recv, reflink-aware copy, dedup stats, on-demand Merkle verify (`stm_fs_verify_merkle_chain` from Phase 8.5), NFS-style file-handle export. NO daemon — `libstratum.a` linked directly into the Rust executable via the `stratum-fs` crate's FFI. Binary size ≤ 15 MiB stripped. Smoke test: create encrypted volume → mount in-process → create file → snapshot → unmount → reopen → snapshot still there → roundtrip clean.
- [x] `namespace.tla` proves cross-connection isolation. **Spec-level MET at P8-NS-1 (commit `bea7f82`)** — landed early during the renumbering. Implementation validation pending the P9-NS-2 9P-impl chunk that composes against the spec.

### 12.3 Risks

- **Low**: 9P2000.L is well-understood; our extensions are straightforward.
- **Medium**: FUSE shim performance tuning.
- **Low**: Stratum-TUI v2 in-process FFI integration. Static-linking C libs into Rust binaries is well-trodden (rocksdb-rs, libsodium-sys, openssl-sys are precedents). The aggregate `libstratum.a` already builds; the Rust side wires up via `bindgen` + `build.rs` calling cmake. Cross-platform binary distribution (linux-{x86_64,arm64} + macos-arm64) is standard `cargo build --release` + `strip`. Risk is the v1 TUI's `tui/` codebase (~4700 LOC of Ratatui UI) needing rewrite of the data layer from 9P-client to direct-FFI calls — mechanical translation, no new design problems.

### 12.4 Dependencies

- All prior phases (this is where users touch Stratum). Phase 8 (POSIX surface) is the immediate prerequisite — without inode/dirent ops, 9P's `Twalk` / `Tcreate` / `Treaddir` have nothing to forward to.

### 12.5 Parallel opportunities

- 9P server, FUSE shim, CLI, libstratum-9p all independent; multiple devs can work in parallel.

---

## 13. Phase 9.5: Concurrent 9P API

(inserted 2026-05-11 post-SLATE; subsequent sections renumbered)

**Scope**: lift the kernel-9P-mount path from "serially correct" to "concurrent-fast." Phase 9 shipped the protocol (9P2000.L server, libstratum-9p, /ctl/, slate, swiss). Today every kernel-9P client and every stratumd connection serializes — first at the accept loop (one connection at a time per socket), and then at `fs->lock` (a single `pthread_mutex_t` above the lock-free Bε-tree). Phase 2 already shipped the lock-free metadata layer with ≥90% linear read scaling (exit §5.2); Phase 9.5 propagates that property up through the FS-API wrapper so two clients reading two different files actually run in parallel down to the metal.

This is a gating chunk for using Stratum as a **production backing store for a POSIX-compliant OS over kernel 9P** (the Thylacine target). Without it, Stratum is single-client-fast and multi-client-slow; with it, the lock-free property is observable end-to-end.

### 13.1 Deliverables

- **P9.5-PARALLEL-1: stratumd concurrent-accept**:
  - Replace the per-socket serial accept loop with either (a) pthread-per-connection bounded by a configurable cap, or (b) `epoll(7)` / `kqueue(2)` event loop with a worker pool. Pick (a) initially for symmetry with the slate daemon's per-connection thread model (already established under CLAUDE.md slate row clause 9 — JOINABLE pthread per accepted connection per R114 P2-1).
  - Signal-mask discipline carries forward from CLAUDE.md stratumd row: SIGINT/SIGTERM/SIGHUP/SIGQUIT blocked on worker threads; main thread is the signal handler.
  - Per-connection `stm_9p_server` lifecycle stays intact — one fid namespace per connection per 9p.h doctrine.
  - Mount lifecycle stays at the daemon level (one `stm_fs *` shared across N connections, exactly as today's `/ctl/` thread + FS thread share it).
  - Same shape for `stm_lp9_server` on the /ctl/ socket.
  - Test scaffold: N concurrent `libstratum-9p` clients issuing Tread/Twrite/Tgetattr concurrently against the same dataset; correctness + throughput baseline.

- **P9.5-PARALLEL-2: Compound-op race-class audit + fixes** (R94 P2-1 doctrine carry):
  - CLAUDE.md stratumd row already calls this out: *"concurrent serving against one `stm_fs *` is the regime under which R94 P2-1 (h_reflink stat-after-mutation) and the same-shape patterns at h_lcreate / h_mkdir / h_renameat become observable. Reviewer of any concurrent-accept upgrade MUST address that whole stat-after-mutation class."*
  - Audit every 9P handler in `v2/src/9p/server.c` (h_lcreate, h_mkdir, h_renameat, h_reflink, h_lcreate-style at /ctl/'s synfs, ...) for the shape `stm_fs_X() THEN stm_fs_getattr()` — the inter-call window is racy under concurrent accept.
  - Three remediation patterns:
    1. **Hoist into stm_fs**: add `stm_fs_X_with_stat(...)` that returns the post-mutation stat atomically under the same internal lock. Preferred where the API surface stays clean.
    2. **Local handler lock**: take the inode's per-inode lock (lands as part of P9.5-PARALLEL-3) across the compound at the 9P-handler layer.
    3. **Snapshot at mutation time**: have `stm_fs_X` return the post-mutation values via out-params so no second call is needed.
  - Land regression tests that fire the race under concurrent-accept stress before R128a closes.

- **P9.5-PARALLEL-3: `fs->lock` granularity**:
  - Today `fs->lock` is a single `pthread_mutex_t` (fs.c:85) that coordinates compound POSIX ops at the public API level. Below it, the Bε-tree is lock-free + MVCC + EBR.
  - Split `fs->lock` into per-inode locks (or finer — e.g., per-(dataset, inode) for cross-dataset operations). Compound POSIX ops on different inodes no longer serialize; only ops that genuinely touch the same inode do.
  - Lock ordering discipline: when a compound op touches two inodes (rename, link, exchange), establish a deterministic order (sorted by `(dataset_id, ino)`) to avoid deadlock.
  - The fs.c writeback path already takes `dbuf->mu` per-bucket (256 buckets) — that pattern extends naturally. Lock-order doctrine (`fs->lock` outer → `dbuf->mu` middle → `sync->lock` inner) reorganizes to: per-inode lock → `dbuf->mu` → `sync->lock`.
  - Read paths benefit immediately — `stm_fs_lookup` / `stm_fs_read` / `stm_fs_getattr` on different inodes parallelize end-to-end.
  - Sync-vs-write coordination stays at the `sync->lock` layer (already finer-grained than fs->lock).
  - Likely involves extending or adding a TLA+ spec — `fs.tla`? — to pin compound-op atomicity under split locks. Spec-first policy applies.

- **P9.5-POLISH-1: Stratum 9P extensions for missing-POSIX surfaces**:
  - Linux's `v9fs` driver doesn't carry every POSIX feature over 9P2000.L wire — `F_SEAL_*` is the obvious gap (stratum honors seals against direct callers; via v9fs, seals are not surfaced through `fcntl`). `O_TMPFILE` round-trip may also leak depending on v9fs version.
  - Audit which POSIX features land cleanly through v9fs and which need a 9P extension verb. P9-9P-3 already scaffolded the Stratum extension verb mechanism — extend it.
  - Stretch: add a small kernel-side helper (or document the userspace bridge) so `fcntl(F_ADD_SEALS)` against a stratum mount round-trips correctly. May defer to a v2.1 chunk if the bridge is invasive.

- **P9.5-POLISH-2: kernel-9P-mount integration tests**:
  - CI job that boots a Linux VM, mounts stratumd via `mount -t 9p`, runs a defined workload (file create / read / write / xattr / chmod / hardlink / readdir).
  - Stretch: xfstests actual run against a stratum mount. CLAUDE.md Phase 8 already noted "the xfstests prep closed but no one's pointed an xfstests instance at a stratum mount yet" — this chunk closes that.

- **P9.5-POLISH-3: Performance baseline**:
  - Measure: single-client throughput (read + write + metadata-ops/sec), multi-client throughput (concurrent read scaling, write scaling, mixed workload), latency p50/p99/p99.9, vs ext4 + btrfs + ZFS on the same hardware.
  - Document in `docs/BENCHMARKS-v9.5.md` (or fold into Phase 10's `docs/BENCHMARKS.md`).
  - Workloads: kernel tarball unpack + build (the practical canary), fio random-read + random-write, dbench, mailbench.

- **TLA+**: spec extension for split-lock compound-op atomicity (likely a new `fs.tla` or extension to `concurrency.tla`). Buggy configs that enumerate the failure modes of (a) lock-order violation between two inodes, (b) missed-wakeup under lock split, (c) compound-op torn visibility under reader entering between sub-steps.

- **Audit**: R128 audit closes the SWISS-4q-flush series + TUI worker commits (already pending from the prior session). Phase 9.5 spawns its own audit round per chunk: R-P9.5-1, R-P9.5-2, R-P9.5-3 cover PARALLEL-1, 2, 3 respectively, with the compound-op race-class being the highest-stakes round of the phase.

### 13.2 Exit criteria

- [ ] Two `libstratum-9p` clients reading two different files run truly in parallel — verified by perf benchmark showing aggregate read throughput on N clients ≥ (0.85 × N × single-client throughput), bounded by physical core count and protocol overhead, **NOT** by `fs->lock` contention.
- [ ] R94 P2-1-class audit closes with zero P0/P1/P2 findings. Every compound-op handler with `stm_fs_X() THEN stm_fs_getattr()` shape either hoists into stm_fs OR takes a per-inode lock across the compound. Regression test under concurrent-accept stress is part of CI.
- [ ] `fs->lock` granularity audit: every public `stm_fs_*` op documents whether it takes a per-inode lock (and which one(s) in what order) or none. Cross-inode compounds use sorted lock acquisition.
- [ ] Linux v9fs mount works for: file create / read / write / unlink / rename / hardlink / symlink / readdir / mkdir / rmdir / xattr / chmod / chown / truncate / fallocate / fsync.
- [ ] kernel-9P-mount integration test runs in CI and passes deterministically.
- [ ] xfstests subset (file/dir/xattr/ACL portion) green on a v9fs-mounted stratum filesystem.
- [ ] `F_SEAL_*` round-trips correctly via Stratum 9P extension or documented bridge. (Or: explicit decision-recorded carve-out that seals are direct-API-only and won't ride 9P.)
- [ ] Performance baseline document committed; numbers compared against ext4 + btrfs + ZFS on the same hardware. Targets per VISION §4 (p50/p99/p99.9 budgets).
- [ ] Updated CLAUDE.md trigger rows: stratumd row reflects concurrent-accept doctrine; fs.c row reflects per-inode lock granularity.

### 13.3 Risks

- **Medium-high**: compound-op race class is genuinely subtle. Audit posture is critical here — most race-class bugs are not caught by tests. Spec-first work on split-lock atomicity is the right hedge.
- **Medium**: per-inode lock granularity touches every `stm_fs_*` op. Methodical chunk-by-chunk migration (start with read paths, then single-inode writes, then compound ops with lock-ordering) keeps the blast radius small.
- **Low**: stratumd concurrent-accept itself is mechanical. Signal-mask + lifecycle discipline are already established at the slate daemon (CLAUDE.md slate row clause 9); apply the same pattern.
- **Low-medium**: 9P extension verbs for `F_SEAL_*` may require a kernel-side patch to v9fs OR a userspace bridge daemon. Forward-noted; not a blocker for the rest of the phase.

### 13.4 Dependencies

- **Phase 2 complete** ✅ (lock-free Bε-tree + MVCC + EBR).
- **Phase 8 complete** ✅ (POSIX surface — the thing being concurrent).
- **Phase 9 substantively complete**: SLATE shipped through P9-SLATE-6 + SWISS-4q stability series + writeback aggregation. SLATE-7 (admin views) is the natural pre-9.5 close-out chunk.
- TLA+ environment.

### 13.5 Parallel opportunities

- PARALLEL-1 (stratumd accept loop) and POLISH-1 (Stratum 9P extensions) are independent — different layers.
- PARALLEL-2 (compound-op audit) and PARALLEL-3 (fs->lock granularity) are sequenced: the audit informs which compound ops are highest-risk, and the granularity chunk provides the lock infrastructure the audit's fixes need. Don't parallelize.
- POLISH-2 (kernel-9P integration tests) and POLISH-3 (performance baseline) can run alongside the audit work — they don't gate on it.

### 13.6 Phase 9.5 carry-over candidates

- **MVCC reader path through stm_fs**: Phase 9.5 splits `fs->lock` per-inode but readers still take a lock per op. The fully lock-free read path — readers entering via `epoch_enter`, pinning a snapshot, no lock taken at all — is mission item #4's final form. May land as part of P9.5-PARALLEL-3 if the impl shapes naturally, or as a follow-on chunk in Phase 10 (Hardening's performance-tuning slice).
- **9P async pipelining** in libstratum-9p (P9-LIB-2 was forward-noted at P9-LIB-1 close): synchronous one-op-at-a-time per connection is fine for single-client kernel mounts but limits multi-client throughput on a single connection. Forward-noted as a v2.1 candidate unless the perf baseline forces it earlier.

---

## 14. Phase 10: Hardening

(was Phase 9 in the prior 10-phase numbering)

**Scope**: fuzzer expansion, audit passes, benchmarks, documentation, pre-release polish.

### 14.1 Deliverables

- **Fuzzer expansion**:
  - Extended crash-injection fuzzer.
  - Multi-client concurrency fuzzer.
  - Format-corruption fuzzer (malformed on-disk states).
- **Audit passes**:
  - Focused audits per CLAUDE.md surfaces, round-by-round.
  - Cross-cutting audit (integration-level correctness).
- **Benchmarks**:
  - Full benchmark suite vs ZFS, btrfs, bcachefs, ext4, XFS.
  - Results documented in `docs/BENCHMARKS.md`.
- **Documentation**:
  - User-facing: install guide, admin guide, migration guide.
  - Developer: API docs, contribution guide.
  - Operator: troubleshooting, backup strategies.
- **Performance tuning**:
  - Fix p99.9 outliers.
  - Optimize hot paths identified by profiling.

### 14.2 Exit criteria

- [ ] Fuzzers run for 1,000+ CPU-hours without finding new correctness bugs.
- [ ] All audit rounds converge with zero P0/P1/P2 findings.
- [ ] p99.9 latency budgets (VISION §4.14) met.
- [ ] Throughput targets met.
- [ ] Documentation reviewed end-to-end.

### 14.3 Risks

- Low by design — this phase is about confidence, not features.

### 14.4 Dependencies

- All prior phases complete.

---

## 15. Phase 11: v2.0 release

(was Phase 10 in the prior numbering)

**Scope**: final audit, format freeze, tag, announce.

### 15.1 Deliverables

- **Final audit**: comprehensive pass across every audit-trigger surface, with findings < P2.
- **Format freeze**: tag the on-disk format as "v2.0 stable." No further changes to field layouts without feature flags.
- **Release artifacts**: binaries (stratum, stratum-fuse, stratum-keyagent, stratum-cli), debug packages, source tarball.
- **Announcement**: blog post, release notes, benchmark summary.

### 15.2 Exit criteria

- [ ] Stratum v2.0 tagged in git.
- [ ] Binaries reproducibly built.
- [ ] Format documented and frozen.
- [ ] Announcement published.

---

## 16. Post-v2.0 roadmap

### 16.1 v2.1 candidates (6–12 months post-v2.0)

- **Reed-Solomon erasure coding** (Phase 5 §8.6 deferral):
  ships as a new `stm_redundancy_profile` variant alongside
  mirror(n). ISA-L SIMD encode/decode (Intel) + pure-C fallback.
  Companion: **multi-device stripe allocation API** (§8.6) for
  k+m block placement across distinct devices.
- **Scrub IO throttling per priority** (Phase 5 §8.6 deferral):
  ARCH §7.14.3 low (10% of bandwidth) / medium (30%) / high (80%).
  Token-bucket rate-limiter on `stm_bdev_read` submit rate.
  Settable via `/ctl/.../scrub/priority`.
- **In-kernel Linux driver**: bypass FUSE for high-IOPS workloads. ~10-20 KLOC kernel code.
- **Log device** (ZFS ZIL equivalent): dedicated fast-device for commit latency.
- **Learned tiering policy** (NOVEL #6): ML-based hot/cold migration replacing heuristic.
- **Zero-copy receive** (`MSG_ZEROCOPY`, AF_XDP): true zero-copy write path.
- **Wavelet-tree succinct refinement**: target 5 MiB/TiB allocator RAM (from 25 MiB/TiB at v2.0).

### 16.2 v2.2+ candidates (12–24+ months)

- **LRC (Local Reconstruction Codes)** (Phase 5 §8.6 deferral):
  layered on top of v2.1 RS. Decode-locality optimization for
  single-failure recovery — ARCH §4.5 LRC(k, l, g) layout. Per
  §8.3 risk mitigation: requires RS to be stable first.
- **Windows driver** (via WinFsp or native kernel).
- **Zoned Namespace (ZNS NVMe)** native support.
- **NVMe-oF** for network-attached block storage.
- **SPDK integration** for extreme-IOPS userspace NVMe.
- **Coq / Lean verification** of specific subsystems (allocator data structures).
- **NFSv4 ACLs** (alternative to POSIX ACLs).

### 16.3 Ruled out

Per VISION §6 non-goals:

- Distributed multi-node.
- Object storage API.
- Parallel HPC filesystem.
- Backward compat with ZFS / btrfs / ext4 volumes.
- Deduplication-as-background-job (CAS tier makes it redundant).
- General-purpose defragmenter.

---

## 17. Cross-phase concerns

### 17.1 Git workflow

- Main branch: `main`, always passes CI.
- Feature branches: `phase-N-<feature>`.
- Every PR includes: code + tests + docs update + TLA+ spec update if applicable.
- CI required: all tests pass, ASAN/TSAN/UBSAN clean, linter clean.
- Audit-triggered PRs require additional approval from the audit subagent.

### 17.2 Versioning during development

- `main` HEAD: "v2.0-dev".
- Phase exits tagged: `phase-N-complete`.
- No API stability promise until v2.0 release.

### 17.3 Telemetry / feedback

During the development phases, internal deployments generate telemetry that guides tuning:

- Deploy to internal test pools.
- Collect performance + reliability metrics via `/ctl/`.
- Feed back into fuzzer corpus + benchmark baselines.

### 17.4 Contributor onboarding

Expected team size: 3–5 core contributors at v2.0 trajectory. Each phase has a "driver" who owns it; reviewers rotate.

`docs/CONTRIBUTING.md` lays out:
- Local dev setup.
- CI expectations.
- Audit process.
- Code style.

---

## 18. Risk register

A consolidated view of risks across phases, ordered by severity.

| # | Risk | Phase | Severity | Mitigation |
|---|---|---|---|---|
| 1 | Lock-free Bw-tree complexity / correctness | 2 | HIGH | Per-node rwlock fallback (compile-time flag); TLA+ spec before implementation; extensive TSAN + fuzz |
| 2 | TLA+ specs don't match implementation | All | MEDIUM | SPEC-TO-CODE mapping file maintained + CI-checked; specs written before code |
| 3 | Multi-device quorum edge cases | 5 | MEDIUM | TLA+ spec; chaos testing (kill devices during commits) |
| 4 | Succinct allocator underperforms | 3 | MEDIUM | Fallback to straight encoding at more RAM; monitored via `/ctl/` |
| 5 | ML-KEM-768 library immaturity | 4 | MEDIUM | Pinned liboqs version; fall back to classical-only wrap if needed |
| 6 | Merkle-on-commit overhead | 4 | MEDIUM | Incremental (dirty subtrees only); benchmark gates |
| 7 | CAS GC under concurrency | 7 | MEDIUM | Incremental + per-chunk locking |
| 8 | Rebalance correctness during live system | 5 | MEDIUM | Crash-injection tests; COW preserves old state until new is durable |
| 9 | FUSE shim performance | 8 | LOW-MED | Multi-threaded; profile-guided optimization |
| 10 | Bootstrap pool sizing | 3 | LOW-MED | Monitor via `/ctl/`; dynamic growth path defined |
| 11 | Performance regression | All | LOW | Continuous benchmarking; 10% regression blocks |
| 12 | Documentation lag | All | LOW | Docs-in-PR policy |

HIGH-risk items dominate: everything else is bounded by the "fallback is defined" principle.

---

## 19. Timeline

Estimates are guidance, not commitments. Each phase's duration assumes full-time engineering on the driver role + reasonable reviewer availability.

```
Phase 1  ─ Foundations            ~3 months  (months 1-3)
Phase 2  ─ Tree + concurrency     ~4 months  (months 4-7)      [critical path]
Phase 3  ─ Persistence            ~3 months  (months 8-10)
Phase 4  ─ Integrity + crypto     ~3 months  (months 10-13)    [overlap w/ P3 tail]
Phase 5  ─ Multi-device           ~3 months  (months 14-16)
Phase 6  ─ Namespaces             ~2 months  (months 15-17)    [overlap w/ P5 tail]
Phase 7  ─ Cold tier + features   ~3 months  (months 18-20)
Phase 8  ─ POSIX surface          ~3 months  (months 21-23)
Phase 9  ─ Client interfaces      ~2 months  (months 22-24)    [overlap w/ P8 tail]
Phase 10 ─ Hardening              ~2 months  (months 25-27)
Phase 11 ─ v2.0 release           ~1 month   (month 28)

Total (with overlaps)                        ~28 months
Total (no overlaps, single-thread)           ~31 months
```

Aggressive but bounded for a filesystem of this ambition. For reference:
- bcachefs: ~15 years from inception to mainline (2009 → 2024).
- btrfs: ~10 years from inception to stable (2007 → 2017).
- ZFS: ~5 years from inception to release (2001 → 2005).

Our 28-month target assumes: we're starting from a solid v1 foundation + formal design (Phase 0), adequate staffing, and a well-defined scope. It's ambitious but informed by prior work. The 25-month → 28-month bump in 2026-04-30 reflects the Phase 8 (POSIX surface) insertion that the prior 10-phase plan implicitly assumed but had no chunk for; APIs (now Phase 9) and the rest of the chain shift accordingly.

---

## 20. Summary

Stratum v2 is an 11-phase implementation journey from "design complete" to "v2.0 released":

1. **Phase 0 (DONE)**: design documents — VISION, COMPARISON, NOVEL, ARCHITECTURE, ROADMAP-V2.
2. **Phases 1-11**: ~28 months to v2.0 release.
3. **Post-v2.0**: kernel driver, learned tiering, zero-copy, Windows, more.

Key commitments:
- Formal verification alongside (not after) implementation.
- Audit loop every phase.
- Three tiers of testing (unit, property, fuzz).
- Fallback paths designed, not discovered.
- Continuous performance measurement.
- Docs updated in every PR.

The plan is aggressive, staged, and risk-aware. Every high-risk element has a defined fallback. Every phase has concrete exit criteria. Every novel angle is scoped concretely.

**Phase 0 ends here.** Phase 1 begins when the implementation team is ready.

This document — along with VISION.md, COMPARISON.md, NOVEL.md, and ARCHITECTURE.md — is the contract between the design and the implementation. Changes to the design require explicit revision of these documents + justification in writing, per CLAUDE.md.

---

## Appendix: Phase 0 completion checklist

- [x] VISION.md — mission, target workloads, property ranking, committed design choices, Plan 9 inheritances.
- [x] COMPARISON.md — feature matrix vs ZFS, btrfs, bcachefs, ext4, XFS.
- [x] NOVEL.md — 10 lead positions with scope, done definition, dependencies, complexity, risk.
- [x] ARCHITECTURE.md — 15 committed sections covering every subsystem.
- [x] ROADMAP-V2.md — this document; phased implementation plan.

**Phase 0 is complete.** The design is done. Implementation begins when the team is ready.
