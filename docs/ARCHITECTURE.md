# Stratum v2 Architecture

**Status**: Phase 0. Each section is stubbed with goals, decisions already committed, open questions, and subsections to write. Filled in across Phase 0 sessions.

## Section status legend

- **STUB** — structure only, no content yet.
- **DRAFT** — first-pass content, under discussion.
- **COMMITTED** — signed off; changes require explicit reopening and re-audit.

---

## 1. Purpose and how to read this document

**STATUS**: DRAFT

Source-of-truth design document for Stratum v2. Translates the properties in `VISION.md` and the novel-lead scopes in `NOVEL.md` into concrete architectural decisions. Every later implementation document references this file.

### 1.1 How to read

- §§1–2 set up the big picture.
- §§3–10 cover specific subsystems, roughly foundations-first: concurrency, storage, SB/quorum, allocator, crypto/integrity, namespace, block device, client interfaces.
- §§11–12 cover operational surfaces: POSIX semantics, I/O paths.
- §§13–15 cover cross-cutting concerns: format versioning, observability, policy.
- §16 is appendices.
- §§17–18 are the writing-order proposal and status summary.

### 1.2 Relationship to other Phase 0 documents

- **VISION.md** — what we're building and why.
- **COMPARISON.md** — positioning vs ZFS, btrfs, bcachefs.
- **NOVEL.md** — per-angle scope and sequencing for the 10 lead positions.
- **ARCHITECTURE.md** (this document) — concrete design decisions.
- **ROADMAP-V2.md** (after architecture) — phased implementation plan.

### 1.3 Change management

- Once a section reaches **COMMITTED**, changing it requires written rationale and explicit re-opening. CLAUDE.md's audit-trigger policy applies to architecture, not just to code.
- **DRAFT** sections are open for discussion.
- **STUB** sections claim the space and list the questions; content comes in dedicated passes.

---

## 2. Layer cake

**STATUS**: STUB

### 2.1 The stack

Top to bottom. Each layer has a clearly defined interface; layers don't reach around each other.

```
                                            │ control plane │ data plane │
 ───────────────────────────────────────────┼───────────────┼────────────┤
  Client interfaces (FUSE, CLI, kernel mod) │      ●        │     ●      │   §10
  9P server + per-connection namespaces     │      ●        │     ●      │   §8
  Filesystem (POSIX, extents, inodes)       │               │     ●      │   §8, §11
  Namespace / subvolume layer               │      ●        │     ●      │   §8
  Metadata tree (Bε-tree, MVCC, lock-free)  │               │     ●      │   §3, §6
  Cryptography + integrity                  │               │     ●      │   §7
  Allocator (tree-embedded, succinct)       │               │     ●      │   §6
  Superblock + quorum                       │      ●        │            │   §5
  Block device abstraction (io_uring, DAX)  │               │     ●      │   §9
  Storage pool (multi-device, redundancy)   │      ●        │     ●      │   §4
```

### 2.2 Key abstractions

- **Pool**: a collection of one or more devices hosting a single Stratum instance.
- **Volume**: a pool's top-level namespace.
- **Dataset** (aka subvolume): a nested namespace with independent snapshots, properties, and optionally keys.
- **Snapshot**: a frozen-in-time reference to a dataset's tree root.
- **Clone**: a writable dataset sharing initial state with a snapshot.
- **Extent**: a contiguous byte range of file data — either *hot* (paddr-addressed, at a specific device location) or *cold* (content-hash-addressed, stored in the CAS tier).
- **Chunk**: the content-defined unit in the cold tier. Boundaries determined by FastCDC.
- **Transaction group (txg)**: a batch of writes committed atomically. Advances `write_gen`.

Precise definitions and invariants go in their subsystem sections.

TO FILL IN:
- Relationship diagram (what references what).
- Formal invariants each abstraction maintains.

---

## 3. Concurrency model

**STATUS**: STUB — next writing session.

### 3.1 Goals

- Lock-free reads under all conditions.
- N concurrent writers parallelize up to the commit point; commit is serialized (End A).
- Readers always see a consistent tree snapshot via MVCC.
- No reader-writer starvation.

### 3.2 Decisions already committed (VISION §5.2, NOVEL #4)

- MVCC for readers.
- Lock-free Bε-tree writers on the hot path (Bw-tree-style delta chains via CAS).
- Single-writer txg commit (End A of the concurrency-vs-security rift).
- Epoch-based reclamation for old tree versions.
- TLA+ spec (`docs/specs/concurrency.tla`) proves the invariants (NOVEL #1).

### 3.3 Subsections to write

- **3.3.1** MVCC reader protocol — root pointer snapshotting, snapshot lifetime, reader-epoch machinery.
- **3.3.2** Writer pipeline — submit, pre-commit, buffer append, commit accumulation.
- **3.3.3** Bw-tree delta chains — record format, consolidation, split/merge under concurrency.
- **3.3.4** Epoch-based reclamation — epoch lifecycle, retired-object list, safe memory reclamation.
- **3.3.5** Commit protocol — txg boundary triggers, commit coordinator election, ordering with SB quorum and Merkle root update.
- **3.3.6** Fallback — fine-grained per-node rwlocks if full lock-free proves intractable.
- **3.3.7** TLA+ spec summary — what invariants are proved; what's out of scope.

### 3.4 Open questions

- Bw-tree vs B-link-tree. Bw-tree matches our message-buffer model; B-link-tree has simpler correctness proofs. Current lean: Bw-tree.
- Reclamation scheme: EBR (simple), VBR (2022; better latency under churn), hazard pointers (per-op cost). Current lean: EBR.
- Per-node delta order: FIFO vs LIFO vs timestamped. Affects consolidation correctness.
- Whether writers pre-declare working set (enables MVCC conflict detection pre-commit; costs API ergonomics).
- Reader snapshot duration: per-op (simple) vs explicit pin API (needed for scrub / send-recv).

---

## 4. Storage pool model

**STATUS**: STUB

### 4.1 Goals

- Multi-device pool with declared redundancy profile.
- Online add / remove / replace devices.
- Redundancy domains expressed independently of physical topology.
- Graceful degradation under device failure.

### 4.2 Decisions committed (COMPARISON §3.7)

- RS + LRC erasure coding.
- Mirror profile for small pools or hot metadata.

### 4.3 Subsections to write

- **4.3.1** Pool composition — device roster, pool version, feature flags.
- **4.3.2** Physical address space — `paddr = (device_id: u16, offset: u64)`. Nonce construction accommodates multi-device.
- **4.3.3** Redundancy profile — RS(k, n), LRC(k, l, r), mirror(n). Per-pool default + per-dataset override.
- **4.3.4** Stripe geometry — block-to-device-stripe mapping.
- **4.3.5** Device lifecycle — add (rebalance), remove (evacuate), replace (rebuild), fail (degrade).
- **4.3.6** Rebalance — triggers, progress reporting, IO throttling.
- **4.3.7** Mixed-class pools — SSD + HDD co-existence; per-extent placement.
- **4.3.8** Hot-spare policy.

### 4.4 Open questions

- Per-device uberblocks vs pool-wide SB. Probably both (per-device for quorum; pool-wide derived view).
- Strictness of online-add: always requires rebalance (expensive) vs deferred rebalance mode.
- Heterogeneous-size devices: supported (like btrfs) or not (more like ZFS before late-career relaxations).

---

## 5. Superblock and quorum

**STATUS**: STUB

### 5.1 Goals

- Per-device uberblock chain (rotating ring, like ZFS).
- Quorum across devices — majority of original roster must agree.
- Crash-safe update via atomic uberblock pointer advance.
- Merkle root of metadata in uberblock.

### 5.2 Decisions committed (VISION §5, NOVEL #1, NOVEL #5)

- Merkle root in the superblock.
- Three-phase sync protocol (refined for multi-device from v1).
- SB format versioned, feature-flag-aware.

### 5.3 Subsections to write

- **5.3.1** Uberblock format — rotating ring on each device, size, count.
- **5.3.2** Quorum semantics — majority-of-roster counting; behavior under partial failure.
- **5.3.3** Commit protocol — multi-device commit ordering, barrier sequencing.
- **5.3.4** Torn-write handling — per-uberblock csum; recovery.
- **5.3.5** Metadata root pointers — SB fields for main tree, allocator tree, snap tree, CAS tier index.
- **5.3.6** Feature flags — RO-compat vs incompat flag categories (ext4 pattern).
- **5.3.7** Version migration — forward-only reads, format-upgrade command.
- **5.3.8** Emergency recovery — degraded-mode mount when quorum is impossible.

### 5.4 Open questions

- Merkle root in every uberblock vs only at sync boundaries.
- Quorum counting: Raft-style "majority of original roster" vs "majority of currently-live members."
- Device identity: persistent UUID.

---

## 6. Allocator model

**STATUS**: STUB

### 6.1 Goals

- Tree-embedded (resolves v1 Stage 3 side-channel concern).
- Rollback-safe (allocator tree COWs with the main tree).
- O(log n) allocation and free.
- Succinct in-RAM state (NOVEL #6; ≤1 MiB per TiB).
- MVCC-compatible.

### 6.2 Decisions committed (VISION §5.4, COMPARISON §3.11)

- Tree-embedded, not side-channel.
- Succinct data structures (wavelet tree / SDArray / xor filter) for in-RAM state.
- W-TinyLFU cache for hot metadata.

### 6.3 Subsections to write

- **6.3.1** Allocator tree structure — per-device tree, keyed by extent start paddr.
- **6.3.2** Refcount semantics — snapshot sharing, range refcounts.
- **6.3.3** Allocation strategy — best-fit vs next-fit vs tiered; zoning interaction.
- **6.3.4** Free and deferred-free — PENDING state through commit, then truly free.
- **6.3.5** COW of the allocator itself — bootstrap pool per device; no recursion.
- **6.3.6** Succinct representation — specific encoding choice, performance characteristics.

### 6.4 Cold tier (CAS) allocator

- **6.4.1** Content-hash index — BLAKE3-256 keyed hash → paddr + refcount.
- **6.4.2** Chunk sizing — FastCDC parameters (min, avg, max).
- **6.4.3** GC — when and how CAS chunks are reclaimed.

### 6.5 Open questions

- Separate allocator tree (own root in SB) vs embedded in main tree's keyspace.
- Fragmentation prevention strategy.
- Bootstrap pool sizing per device.

---

## 7. Cryptography and integrity

**STATUS**: STUB

*(Merged from previous §9 Integrity + §10 Crypto — they're inseparable. AEAD tags are integrity on encrypted volumes; Merkle covers metadata; per-extent csum covers unencrypted data. Unified treatment.)*

### 7.1 Goals

- PQ-hybrid wrap keys (NOVEL #2).
- Nonce-misuse-resistant AEAD (NOVEL #2).
- Per-dataset keys with inheritance.
- Key agent separation (NOVEL #10).
- Merkle-rooted metadata integrity (NOVEL #5).
- Per-extent data integrity (xxHash3 on unencrypted, AEAD tag on encrypted).
- Online scrub with repair.

### 7.2 Decisions committed (VISION §5.2, NOVEL #2, NOVEL #5, NOVEL #10)

- Data: XChaCha20-SIV or AEGIS-256 (pick after benchmark).
- Wrap: X25519 + ML-KEM-768 hybrid.
- Nonce construction under End A (serialized txg commit).
- Merkle via BLAKE3-256; root in SB.
- Key agent is separate process.

### 7.3 Subsections to write

- **7.3.1** Key hierarchy — master wrap → per-dataset wrap → per-object data key.
- **7.3.2** Nonce construction — `(pool_id, device_id, paddr, txg, seq)`; proved unique in TLA+.
- **7.3.3** AEAD construction — specific SIV mode, test vectors, performance targets.
- **7.3.4** Associated-data design — multi-device + dataset context; extends v1's `stm_ad_extent`.
- **7.3.5** Key rotation — wrap-key rotation without data re-encrypt; data-key rotation.
- **7.3.6** Per-dataset encryption inheritance — key-from-parent vs independent-key.
- **7.3.7** Key agent protocol — FS↔agent request/response, audit logging.
- **7.3.8** Encrypted send / recv — raw-send preserving encryption.
- **7.3.9** Merkle hash placement — per-node subtree hash in Bε-tree node.
- **7.3.10** Hash update protocol — incremental, propagates to root on commit.
- **7.3.11** Verify paths — mount-time full verify (opt-in), on-read path verify (default), background scrub.
- **7.3.12** Scrub — scheduling, IO weight, progress reporting.
- **7.3.13** Repair — reconstruction from redundancy, repair logging.
- **7.3.14** Unrecoverable corruption handling.
- **7.3.15** Per-data-extent integrity — xxHash3 on unencrypted, AEAD tag on encrypted.

### 7.4 Open questions

- SIV final choice: XChaCha20-SIV (conservative, no HW req) vs AEGIS-256 (faster with AES-NI).
- Per-dataset key derivation: HKDF from master + dataset-path vs separate generate + master-wrap.
- Agent protocol: 9P over Unix socket vs bespoke RPC.
- Merkle over all metadata vs only SB-adjacent (root + tree roots).
- Scrub priority model.

---

## 8. Namespace model (subvolumes, datasets, snapshots, clones)

**STATUS**: STUB

### 8.1 Goals

- Hierarchical dataset structure.
- Per-dataset property inheritance.
- Per-dataset encryption keys.
- Snapshots and clones as first-class primitives.
- Per-connection namespace composition (NOVEL #8).

### 8.2 Decisions committed (VISION §5.5, NOVEL #8)

- Per-connection 9P namespaces for client isolation.
- Datasets have separate tree roots.

### 8.3 Subsections to write

- **8.3.1** Dataset hierarchy — paths, tree of datasets, depth policy.
- **8.3.2** Property inheritance — what's inherited, overridable, how recorded.
- **8.3.3** Snapshot mechanics — freeze tree root, refcount bumps, visibility.
- **8.3.4** Clone mechanics — writable snapshot, diverging tree root.
- **8.3.5** Send / recv — wire format, incremental via tree diff.
- **8.3.6** Per-connection namespace composition — `Tbind`, union mounts.
- **8.3.7** Dataset properties — canonical list, defaults, validation.
- **8.3.8** Dataset rename / move.

### 8.4 Open questions

- Arbitrary-depth dataset tree vs fixed depth.
- Snapshot deletion: immediate refcount drop vs mark-and-sweep.
- Cross-dataset hard links: allowed (rare use case, complicated) or disallowed.

---

## 9. Block device abstraction

**STATUS**: STUB

### 9.1 Goals

- io_uring-native on Linux.
- Zero-copy via fixed buffers and registered files.
- DAX-compatible for persistent memory.
- Portable fallback (libaio on older Linux; FUSE path on non-Linux).

### 9.2 Decisions committed (NOVEL #7)

- io_uring as primary submission path.
- Fixed buffers for zero-copy.
- DAX path for pmem.

### 9.3 Subsections to write

- **9.3.1** Abstract interface — what every backend implements.
- **9.3.2** io_uring backend — SQ/CQ management, SQ polling, registered files + buffers.
- **9.3.3** libaio backend (fallback).
- **9.3.4** FUSE backend (for non-Linux hosts).
- **9.3.5** DAX path — mmap-based, byte-addressable.
- **9.3.6** Sync semantics — fsync, fdatasync, barriers.
- **9.3.7** Error handling — transient, permanent, device removal.

### 9.4 Open questions

- Fixed-buffer aggressiveness (pinned-memory cost).
- SQ polling mode (kernel thread vs user thread).
- Atomicity assumptions for old hardware.

---

## 10. Client interfaces

**STATUS**: STUB

*(New section — captures how applications and OSes reach the filesystem. Separate from §9 block device layer (which is stratum's backing storage) and from §8 9P server (covered in namespace section as the protocol endpoint).)*

### 10.1 Goals

- Support multiple client paths: FUSE, in-kernel Linux module (post-v2.0), CLI, library bindings.
- 9P is the universal transport; clients are 9P consumers.
- Authentication + authorization at the 9P boundary, not per-client.

### 10.2 Decisions committed (VISION §5.5, COMPARISON §1)

- 9P-first architectural stance.
- FUSE shim is a client of 9P, not the native interface.
- In-kernel Linux driver is post-v2.0.

### 10.3 Subsections to write

- **10.3.1** FUSE shim — how it translates kernel VFS ops to 9P messages.
- **10.3.2** CLI tool — thin wrapper over `/ctl/` synthetic filesystem.
- **10.3.3** 9P client library — stable C API for applications that want direct 9P.
- **10.3.4** Language bindings — Rust, Go, Python. Thin wrappers over the C API.
- **10.3.5** In-kernel Linux driver (post-v2.0) — design sketch only.
- **10.3.6** Windows driver (post-v2.0, optional) — design sketch only.
- **10.3.7** Authentication at mount — how clients authenticate to 9P server.

### 10.4 Open questions

- Should the FUSE shim run as a separate process or linked into stratum?
- Language bindings ownership — upstream or community-maintained?
- Kernel-module timeline.

---

## 11. POSIX surface

**STATUS**: STUB

### 11.1 Goals

- Modern POSIX — everything in the ext4/XFS surface still relevant.
- Skip legacy quirks (noatime, no mandatory locking, etc.).

### 11.2 Decisions committed (VISION §6 non-goals)

- O_TMPFILE, F_SEAL_*, relatime, pipes-as-files: yes.
- Mandatory locking, atime: no.
- Obscure BSD extensions: no.

### 11.3 Subsections to write

- **11.3.1** Inode format — fields, timestamps, xattr, embedded-small-file (if any).
- **11.3.2** Directory format — hash-table / B-tree hybrid.
- **11.3.3** Extended attributes — tree location, size limits.
- **11.3.4** File data — extent tree, inline data for tiny files.
- **11.3.5** Locking — advisory (flock, fcntl); no mandatory.
- **11.3.6** ACLs — POSIX ACLs as xattr.
- **11.3.7** Timestamps — ns resolution; btime, mtime, atime (relatime), ctime.
- **11.3.8** Special files — FIFO, socket, device, symlink.
- **11.3.9** Reflinks (copy_file_range).
- **11.3.10** Hard links (same-dataset only).

### 11.4 Open questions

- Inline small-file data in inode (ext4 `inline_data`): yes or no.
- Max filename length, max path depth.

---

## 12. I/O paths

**STATUS**: STUB

### 12.1 Goals

- Document the happy path and recovery path for every operation.
- Make the invariants explicit — what holds at every step.

### 12.2 Subsections to write

- **12.2.1** Read path — lookup, integrity verify, decrypt, decompress, return.
- **12.2.2** Write path — allocate, compress, encrypt, hash-propagate, insert, accumulate-commit.
- **12.2.3** Sync path — three-phase commit (multi-device).
- **12.2.4** Rollback path — reconstruction of allocator state; Merkle reverify.
- **12.2.5** Scrub path — walk, verify, repair.
- **12.2.6** Mount path — SB selection, quorum check, verify (opt-in), open trees, attach.
- **12.2.7** Unmount path — flush, sync, detach, safe-close.
- **12.2.8** Migration path (hot ↔ cold tier).
- **12.2.9** Error recovery — transient, permanent, corruption.
- **12.2.10** Crash recovery — possible post-crash states; resolution protocol.

---

## 13. Format versioning policy

**STATUS**: STUB

*(Shortened from the original §11 "On-disk format." Each subsystem documents its own format in its section; this section is just the cross-cutting versioning policy.)*

### 13.1 Goals

- v2.0 format is stable; future changes via feature flags.
- Self-describing (new code can parse old volumes).
- Forward readability (old code refuses new-feature volumes cleanly, not by crashing).

### 13.2 Decisions committed (VISION §4.11)

- Pre-v2.0 (Phase 0 implementation work) is throwaway.
- v2.0 freezes the format; changes via feature flags.

### 13.3 Subsections to write

- **13.3.1** Feature flag taxonomy — incompat, RO-compat, compat (ext4 pattern).
- **13.3.2** SB version field vs feature flags — when each is bumped.
- **13.3.3** Migration paths — no in-place migration from v1; v2→v2.x via feature flag stabilization.
- **13.3.4** Endian policy — little-endian on disk, always.
- **13.3.5** Alignment rules — natural alignment; no unnecessary padding.
- **13.3.6** Stable-over-10-years commitment and what that means concretely.

---

## 14. Observability and debugging

**STATUS**: STUB

### 14.1 Goals

- Every subsystem exposes counters, events, histograms via `/ctl/`.
- Structured event log for forensic review.
- Debug dumps (tree walks, extent maps, integrity reports).

### 14.2 Decisions committed (NOVEL #9)

- `/ctl/` synthetic filesystem.
- Administration via cat/echo.

### 14.3 Subsections to write

- **14.3.1** Counter schema — naming, units, per-pool / per-dataset scoping.
- **14.3.2** Event log — format, retention, rotation.
- **14.3.3** Tracing — per-request sampling, correlation IDs.
- **14.3.4** Debug dumps — tree walk, extent map, allocator state, integrity verify.
- **14.3.5** Metrics integration — Prometheus / OpenTelemetry via sidecar scrapers reading `/ctl/`.

---

## 15. Cross-cutting concerns

**STATUS**: STUB

### 15.1 Feature-flag lifecycle

Introduction → stabilization → deprecation.

### 15.2 Error model

Error propagation across layers; user-visible errors.

### 15.3 Resource limits

Memory budgets, IO concurrency caps, CPU budgets.

### 15.4 Cancellation and timeouts

Long-running ops (scrub, rebalance, migration) support progress reporting and cancellation.

### 15.5 Backward compatibility

What old data a new binary can read. Per-feature opt-in.

### 15.6 Thread / task model

Threads stratum creates; their roles; coordination.

---

## 16. Appendices

### 16.1 Glossary

(Grows as sections get filled in.)

### 16.2 Reference algorithms

- FastCDC pseudocode.
- BLAKE3 + Merkle-root construction.
- XChaCha20-SIV / AEGIS-256 construction.
- ML-KEM-768 hybrid key agreement (HPKE pattern).
- Epoch-based reclamation protocol.
- Bw-tree delta-chain consolidation.
- Reed-Solomon encode/decode (over GF(2⁸)).
- Locally Repairable Codes layout.

### 16.3 Bibliography

- Bε-tree: Brodal et al. 2003; Bender et al. 2007.
- Bw-tree: Levandoski et al. 2013.
- FastCDC: Xia et al. 2016.
- Venti: Quinlan & Dorward 2002.
- BLAKE3: O'Connor et al. 2020.
- ML-KEM: NIST FIPS 203, 2024.
- AEGIS-256: Wu & Preneel, CAESAR 2013–2019.
- XChaCha20-SIV: Harris et al. 2019.
- LRC: Papailiopoulos & Dimakis 2012; Sathiamoorthy et al. 2013.
- TLA+: Lamport 2002+; 25 years of storage-industry use.
- RCU / EBR / VBR: McKenney 2001+; Kirsch 2022.
- Wavelet trees / SDArray: Jacobson 1989; Munro & Raman 1997; Okanohara & Sadakane 2007.
- W-TinyLFU: Mazi et al. 2015.
- xor filters: Graf & Lemire 2020.

---

## 17. Section writing order

Not every section needs equal depth. Writing order for Phase 0 sessions, reflecting foundational-ness and dependencies:

1. **§3 Concurrency** — largest blast radius; must be right first. (This session.)
2. **§4 Storage pool** — shapes every layer below.
3. **§5 Superblock / quorum** — depends on §4; precondition for sync machinery.
4. **§6 Allocator** — depends on §3, §4, §5.
5. **§7 Cryptography + integrity** — depends on §5 for key-slot layout in SB; depends on §3 for hash update protocol.
6. **§8 Namespace** — depends on §4, §5, §6, §7.
7. **§9 Block device** — relatively standalone.
8. **§10 Client interfaces** — depends on §8 for 9P surface.
9. **§11 POSIX surface** — relatively standalone.
10. **§12 I/O paths** — integration document, written last.
11. **§13 Format versioning** — derived from 3–10; committed last.
12. **§§14–15 operational polish** — continuous, mostly filled in once others are settled.

Each of §3–§5 and §7 is probably its own Phase 0 session. §6, §8, §9–§11 can be paired with adjacent sections. §12 and §13 are integration passes.

---

## 18. Status summary

| Section | Status | Priority |
|---|---|---|
| §1 Purpose | DRAFT | n/a |
| §2 Layer cake | STUB | 11 (thin pass once rest is settled) |
| §3 Concurrency | **next** | 1 |
| §4 Storage pool | STUB | 2 |
| §5 Superblock / quorum | STUB | 3 |
| §6 Allocator | STUB | 4 |
| §7 Cryptography + integrity | STUB | 5 |
| §8 Namespace | STUB | 6 |
| §9 Block device | STUB | 7 |
| §10 Client interfaces | STUB | 8 |
| §11 POSIX surface | STUB | 9 |
| §12 I/O paths | STUB | 10 (integration) |
| §13 Format versioning | STUB | 11 |
| §14 Observability | STUB | 12 |
| §15 Cross-cutting | STUB | 12 |
| §16 Appendices | STUB | continuous |
