# Stratum v2 Architecture

**Status**: Phase 0 — structural skeleton, 2026-04-19. Each section is stubbed with its goals, decisions already made (from VISION.md and NOVEL.md), open questions, and subsections to write. Filled in section-by-section in subsequent Phase 0 sessions.

## Section status legend

- **STUB** — structure only, no content yet.
- **DRAFT** — first-pass content, under discussion.
- **COMMITTED** — signed off; changes require explicit reopening.

---

## 1. Purpose and how to read this document

**STATUS**: DRAFT

This is the design specification for Stratum v2. It translates the properties in `VISION.md` and the novel-lead scopes in `NOVEL.md` into concrete architectural decisions. Every later implementation document (per-subsystem design notes, code comments, test plans) references this file as the source of truth.

### 1.1 How to read

- Sections 2–3 give the big picture: the layer cake and the principles.
- Sections 4–13 cover specific subsystems. Each has its own goals, decisions, and open questions.
- Sections 14–15 cover cross-cutting concerns (format versioning, observability).
- Appendices collect reference material: glossaries, derivations, algorithm pseudocode.

### 1.2 Relationship to other Phase 0 documents

- **VISION.md** — what we're building and why (workloads, properties, priorities).
- **COMPARISON.md** — how we position against ZFS, btrfs, bcachefs (what we match / lead / skip).
- **NOVEL.md** — per-angle scope and sequencing for the 10 lead positions.
- **ARCHITECTURE.md** (this document) — concrete design decisions for every subsystem.
- **ROADMAP-V2.md** (next) — phased implementation plan built on this document.

### 1.3 Change management

- Once a section reaches **COMMITTED**, changing it requires a written rationale and explicit re-opening. The audit-trigger policy in `CLAUDE.md` applies to the architecture, not just to code.
- Sections in **DRAFT** are open for discussion; push back whenever the reasoning feels thin.
- **STUB** sections exist to claim the space and list the questions; content comes in dedicated passes.

---

## 2. Layer cake

**STATUS**: STUB

The overall stack, top to bottom. Each layer has a clearly defined interface; layers don't reach around each other.

```
┌─────────────────────────────────────────────────┐
│  Clients: FUSE shim / in-kernel driver / CLI    │   (external)
├─────────────────────────────────────────────────┤
│  9P server + per-connection namespaces          │   §5, §8
├─────────────────────────────────────────────────┤
│  Filesystem (POSIX surface, extents, inodes)    │   §5, §13
├─────────────────────────────────────────────────┤
│  Namespace / subvolume layer                    │   §5
├─────────────────────────────────────────────────┤
│  Metadata tree (Bε-tree, MVCC, lock-free)       │   §3, §9
├─────────────────────────────────────────────────┤
│  Integrity layer (Merkle, per-extent csum)      │   §9
├─────────────────────────────────────────────────┤
│  Crypto layer (AEAD-SIV, key hierarchy)         │   §10
├─────────────────────────────────────────────────┤
│  Allocator (succinct, tree-embedded)            │   §6
├─────────────────────────────────────────────────┤
│  Cold tier (Venti-style CAS + CDC)              │   §6.3
├─────────────────────────────────────────────────┤
│  Superblock / quorum (per-device uberblocks)    │   §7
├─────────────────────────────────────────────────┤
│  Block device abstraction (io_uring, DAX)       │   §8 (§4 of NOVEL)
├─────────────────────────────────────────────────┤
│  Storage pool (multi-device, redundancy)        │   §4
└─────────────────────────────────────────────────┘
```

### 2.1 Key abstractions (to be defined precisely per section)

- **Pool**: a collection of one or more devices hosting a single Stratum instance.
- **Volume**: a pool's top-level namespace.
- **Subvolume / dataset**: a nested namespace with independent snapshots, properties, and optionally keys.
- **Snapshot**: a frozen-in-time reference to a subvolume's tree root.
- **Clone**: a writable subvolume sharing initial state with a snapshot.
- **Extent**: a contiguous byte range of file data, either hot (paddr-addressed) or cold (content-hash-addressed).
- **Chunk**: the content-defined unit in the cold tier, boundaries determined by FastCDC.

TO FILL IN:
- Precise definitions and invariants per abstraction.
- Relationship diagram (what references what).

---

## 3. Concurrency model

**STATUS**: STUB — the most consequential section. Draft first.

### 3.1 Goals

- Lock-free reads under all conditions.
- N concurrent writers parallelize up to the commit point; commit is serialized (End A).
- Readers always see a consistent tree snapshot.
- No reader-writer starvation.

### 3.2 Decisions already committed (from VISION §5.2, NOVEL #4)

- MVCC for readers.
- Lock-free Bε-tree writers on the hot path (message buffer appends via CAS delta chains; Bw-tree-style pattern).
- Single-writer transaction-group commit (End A of the concurrency-vs-security rift).
- Epoch-based reclamation for old tree versions.
- TLA+ spec (`docs/specs/concurrency.tla`) proves the invariants; see NOVEL #1.

### 3.3 Subsections to write

- **3.3.1** MVCC readers — root pointer protocol, snapshot lifetime, reader-epoch machinery.
- **3.3.2** Writer pipeline — submit, pre-commit validate, commit, publish. Where locks do and don't exist.
- **3.3.3** Bw-tree-style delta chains — the delta record format, chain length policy, consolidation trigger.
- **3.3.4** Epoch-based reclamation — epoch lifecycle, retired-object list, safe memory reclamation.
- **3.3.5** Commit path — transaction group boundaries, commit serialization, ordering with Merkle root update and SB quorum.
- **3.3.6** Fallback — fine-grained per-node locks + MVCC readers if lock-free writers prove intractable.
- **3.3.7** TLA+ spec summary — what invariants the spec proves, and what properties it doesn't (and why).

### 3.4 Open questions

- Bw-tree vs B-link-tree as the specific structure. Bw-tree delta chains match our Bε-tree message-buffer model naturally; B-link-tree has simpler correctness proofs.
- Reclamation: EBR (simplest), VBR (2022, better latency under high churn), hazard pointers (per-operation cost). Recommend EBR for v2.0.
- Per-node ordering of delta records — FIFO vs LIFO vs timestamped. Affects consolidation complexity.
- Whether we should mandate that writers declare their working set up front (enables MVCC conflict detection pre-commit, at cost of ergonomics).

---

## 4. Storage pool model

**STATUS**: STUB

### 4.1 Goals

- Multi-device pool with declared redundancy profile.
- Online add / remove / replace devices.
- Redundancy domains (for RAID, LRC, mirrors) expressed independently of physical topology.
- Graceful degradation under device failure.

### 4.2 Decisions already committed (from COMPARISON §3.7)

- RS + LRC erasure coding.
- Mirror profile for small pools or hot metadata.

### 4.3 Subsections to write

- **4.3.1** Pool composition — device roster, pool version, feature flags.
- **4.3.2** Physical address space — `paddr = (device_id: u16, offset: u64)`. Nonce construction accommodates multi-device.
- **4.3.3** Redundancy profile definition — RS(k, n), LRC(k, l, r), mirror(n). Per-pool default + per-dataset override.
- **4.3.4** Stripe geometry — how blocks map to device stripes; interaction with block-device abstraction.
- **4.3.5** Device lifecycle — add (rebalance), remove (evacuate), replace (rebuild), fail (degrade).
- **4.3.6** Rebalance — when, how, by whom (user-triggered vs automatic).
- **4.3.7** Mixed-class pools — SSD + HDD in one pool; per-extent placement via tier hints.
- **4.3.8** Hot-spare policy.

### 4.4 Open questions

- Device metadata location: per-device uberblock vs pool-wide SB. Probably both — each device has its own uberblock tree (ZFS pattern, needed for quorum; see §7), pool-wide SB is derived.
- How strict is the "add device online" path? Requires rebalance; rebalance is expensive; worth it vs "offline add with downtime"?
- Do we support heterogeneous-size devices? ZFS does (grudgingly); btrfs does (happily); both have problems at the edges.

---

## 5. Namespace model (subvolumes, datasets, snapshots, clones)

**STATUS**: STUB

### 5.1 Goals

- Hierarchical subvolume / dataset structure (ZFS-style).
- Per-dataset property inheritance.
- Per-dataset encryption keys.
- Snapshots and clones as first-class primitives.
- Per-connection namespace composition (NOVEL #8).

### 5.2 Decisions already committed (from VISION §5.5, NOVEL #8)

- Per-connection 9P namespaces for client isolation.
- Subvolumes have separate tree roots.

### 5.3 Subsections to write

- **5.3.1** Dataset hierarchy — names, paths, the tree of datasets.
- **5.3.2** Property inheritance — what's inherited, what's overridable, how overrides are recorded.
- **5.3.3** Snapshot mechanics — how "freeze tree root" works, refcount bumps, visibility.
- **5.3.4** Clone mechanics — writable snapshot, tree root diverges from parent.
- **5.3.5** Send / recv — wire format, incremental send via tree diff.
- **5.3.6** Per-connection namespace composition — 9P `Tbind` semantics, stack mounts.
- **5.3.7** Per-dataset encryption — key hierarchy (§10), key inheritance, key rotation across datasets.
- **5.3.8** Dataset properties — canonical list, defaults, validation.

### 5.4 Open questions

- How deep should the dataset tree be? ZFS allows arbitrary depth; btrfs has subvolumes (flat-ish). Arbitrary depth is more flexible; flat is simpler.
- Can a dataset be "moved" in the hierarchy? (ZFS: yes via `zfs rename`.) At what cost?
- What's the interaction between per-connection namespaces and dataset-level mount points? Does `Tbind` operate at the dataset level or below?
- Snapshot deletion: immediate (block-level refcount drop) or lazy (mark-and-sweep)?

---

## 6. Allocator model

**STATUS**: STUB

### 6.1 Goals

- Tree-embedded (resolves the v1 Stage 3 side-channel concern).
- Rollback-safe (COW of the allocator tree follows COW of the main tree).
- O(log n) allocation and free.
- Succinct in-RAM state (NOVEL #6; 1 MiB per TiB target).
- MVCC-compatible (readers see consistent allocator state per their snapshot).

### 6.2 Decisions already committed (from VISION §5.4, COMPARISON §3.11)

- Tree-embedded, not side-channel.
- Succinct data structures (wavelet tree / SDArray / xor filter) for in-RAM state.
- W-TinyLFU cache for hot metadata.

### 6.3 Subsections to write

- **6.3.1** Allocator tree structure — per-device tree, keyed by extent start paddr.
- **6.3.2** Refcount semantics — how refcounts track snapshot sharing.
- **6.3.3** Allocation strategy — best-fit vs next-fit vs tiered; interaction with zoning.
- **6.3.4** Free and deferred-free — PENDING state through commit, then truly free.
- **6.3.5** COW of the allocator itself — how allocator-tree nodes are allocated without recursion (the problem Phase D Stage 3 struggled with; the tree-embedded model solves it).
- **6.3.6** Succinct representation — specific choice of wavelet tree / SDArray / EF encoding, performance characteristics.
- **6.3.7** Cold tier allocation — CAS tier uses a different allocator (content-hash-indexed); see §6.4.

### 6.4 Cold tier allocator (CAS tier)

- **6.4.1** Content-hash index — BLAKE3-256 keyed hash → paddr + refcount.
- **6.4.2** Chunk sizing — FastCDC parameters (min, max, average).
- **6.4.3** GC — when and how CAS chunks get reclaimed.

### 6.5 Open questions

- Tree-embedded allocator: is the allocator tree a separate Bε-tree (own root in SB) or embedded in the main tree's keyspace? Former is cleaner; latter is more compact.
- How do we handle allocator-tree COW's own allocations? The recursion ghost from v1 Phase D Stage 3. Resolve by having a small pool of pre-reserved "bootstrap" blocks per device, used only for allocator tree updates.
- Fragmentation prevention. Over time, COW + free + alloc can fragment the address space. Defrag-as-you-go (bubble-sort-like) vs periodic offline compaction vs accept fragmentation.

---

## 7. Superblock and quorum model

**STATUS**: STUB

### 7.1 Goals

- Per-device uberblock chains (like ZFS).
- Quorum across devices (majority of live devices must agree on current pool state).
- Crash-safe update via atomic SB pointer advance.
- Merkle root of metadata in SB.

### 7.2 Decisions committed (from VISION §5, NOVEL #1, NOVEL #5)

- Merkle root in the superblock.
- Three-phase sync protocol (carried forward from v1; refined for multi-device).
- SB format versioned, feature-flag-aware.

### 7.3 Subsections to write

- **7.3.1** Uberblock format — per device, rotating ring of uberblocks (ZFS-style).
- **7.3.2** Quorum semantics — how many devices must agree for the pool to be mountable.
- **7.3.3** Commit protocol — multi-device commit ordering; what "committed" means across devices.
- **7.3.4** Torn write handling — uberblock csum, how we detect torn writes, recovery.
- **7.3.5** Metadata root pointer — how the SB points at the main tree, allocator tree, snap tree, CAS tree.
- **7.3.6** Feature flags — how new format features opt in without breaking old volumes.
- **7.3.7** Version migration — forward-only (old code can't read new volumes) vs backward-compat paths.
- **7.3.8** Emergency recovery — degraded-mode mount when quorum can't be achieved.

### 7.4 Open questions

- Should we embed the Merkle root in every uberblock or only at sync boundaries? Every uberblock is safer but costs hashing on every partial update.
- Quorum counting: pool of 3 devices needs 2 for quorum; pool of 4 needs 3? Go with Raft-like "majority of the original roster" rather than "majority of live members."
- Device identity: UUID per device? Persistent across re-mount, survives renaming.

---

## 8. Block device abstraction

**STATUS**: STUB

### 8.1 Goals

- io_uring-native on Linux.
- Zero-copy where possible (fixed buffers, registered files).
- Portable (FUSE on non-Linux, libaio fallback for old kernels).
- DAX-compatible for persistent memory.

### 8.2 Decisions committed (from NOVEL #7)

- io_uring as the primary submission path.
- Fixed buffers for zero-copy.
- DAX path for pmem.

### 8.3 Subsections to write

- **8.3.1** Abstract interface — what every backend must implement.
- **8.3.2** io_uring backend — submission queue management, completion loop, SQ polling mode, registered files + buffers.
- **8.3.3** libaio backend (fallback for old Linux).
- **8.3.4** FUSE backend (for non-Linux hosts, or when stratum is running as an unprivileged user daemon).
- **8.3.5** DAX path — mmap-based, byte-addressable.
- **8.3.6** Sync semantics — fsync, fdatasync, barriers. Per-device vs pool-wide.
- **8.3.7** Retry / error handling — transient failures, permanent failures, device removal.

### 8.4 Open questions

- How aggressive about fixed buffers? Pinning a fixed buffer for each concurrent operation consumes pinned kernel memory; not free.
- SQ polling mode: kernel thread vs CPU-polling user thread. Latency win, CPU cost.
- How do we handle partial writes on devices that don't guarantee atomic sector writes? (All modern NVMe guarantees 4K atomicity; older hardware doesn't.)

---

## 9. Integrity model

**STATUS**: STUB

### 9.1 Goals

- Merkle-rooted metadata integrity (NOVEL #5).
- Per-extent data integrity (xxHash3-64 on unencrypted, AEAD tag on encrypted).
- Detection + repair from redundancy (§4).
- Online scrub with progress / repair accounting.

### 9.2 Decisions committed (from NOVEL #5)

- BLAKE3-256 for Merkle hashes.
- Root in SB.
- Mount-time verify is opt-in; on-read verify is the default; scrub is continuous.

### 9.3 Subsections to write

- **9.3.1** Hash placement — each Bε-tree node carries its subtree hash.
- **9.3.2** Hash update protocol — incremental hash update on node modification, propagation to root.
- **9.3.3** Verify paths — mount-time full verify, on-read path verify, background scrub.
- **9.3.4** Scrub scheduling — default cadence, priority / IO weight, progress reporting.
- **9.3.5** Repair — when detection finds corruption, reconstruction from redundancy; repair logging.
- **9.3.6** Unrecoverable corruption — what to do when no redundancy exists; wedge vs IO-error-and-continue.
- **9.3.7** Per-data-extent integrity — xxHash3 on unencrypted extents, AEAD tag on encrypted.

### 9.4 Open questions

- Merkle over all metadata, or just "load-bearing" metadata (SB + tree roots)? Probably all, so every metadata block is covered.
- How do we handle intentional changes to metadata (snapshot creation updates many things)? Update hashes in the same commit; the Merkle root advances with the commit.
- Scrub priority: user-visible scrub (blocking) vs background scrub (low priority). Both modes.

---

## 10. Crypto model

**STATUS**: STUB

### 10.1 Goals

- PQ-hybrid wrap keys (NOVEL #2).
- Nonce-misuse-resistant AEAD (NOVEL #2).
- Per-dataset keys with inheritance.
- Key agent separation (NOVEL #10).

### 10.2 Decisions committed (from VISION §5.2, NOVEL #2, NOVEL #10)

- Data encryption: XChaCha20-SIV or AEGIS-256 (pick after benchmark).
- Key wrap: X25519 + ML-KEM-768 hybrid.
- Key agent is separate process.
- Nonce construction under End A (serialized txg commit).

### 10.3 Subsections to write

- **10.3.1** Key hierarchy — master wrap key → per-dataset wrap key → per-object data key.
- **10.3.2** Nonce construction — `(pool_id, device_id, paddr, txg, seq)` or similar; proved unique in TLA+ spec.
- **10.3.3** AEAD construction — specific SIV mode, test vectors, performance targets.
- **10.3.4** Associated data — extends v1's `stm_ad_extent` / `stm_ad_node` to multi-device + dataset context.
- **10.3.5** Key rotation — wrap key rotation without data re-encryption; data key rotation mechanics.
- **10.3.6** Per-dataset encryption — how keys are inherited from parent dataset; how to detach.
- **10.3.7** Key agent protocol — FS↔agent request/response, authentication, audit logging.
- **10.3.8** Encrypted send/recv — raw send preserving encryption on target (ZFS-style).

### 10.4 Open questions

- SIV mode final choice: XChaCha20-SIV (conservative, no hardware requirement) vs AEGIS-256 (faster with AES-NI, CAESAR winner, newer). Probably AEGIS-256 default on x86-64+AES-NI; XChaCha20-SIV fallback.
- Nonce field layout: encoding `(pool, device, paddr, txg, seq)` into 24 bytes. Room for 128 bits of key-material identifier? Probably enough.
- Per-dataset key derivation: HKDF from master + dataset-path, vs per-dataset key generation + master-wrap. Latter is more flexible for rotation.
- Agent protocol: 9P over Unix socket (consistency) vs custom bespoke (simpler). Probably 9P — already have the machinery.

---

## 11. On-disk format

**STATUS**: STUB

### 11.1 Goals

- Self-describing (new code can parse old volumes; feature flags announce compat level).
- Versioned (SB version + feature flags).
- Extensible (padding fields, flag reservations).
- Stable at v2.0 release (backward-compat for 10+ years).

### 11.2 Decisions committed (from VISION §4.11)

- Pre-v2.0 (i.e., Phase 0 work) is throwaway.
- v2.0 freezes format; future changes via feature flags.

### 11.3 Subsections to write

- **11.3.1** Version / feature-flag scheme.
- **11.3.2** SB layout — all fields, byte layout, alignment.
- **11.3.3** Bε-tree node format — header, key/value encoding, Merkle hash field, delta chain representation.
- **11.3.4** Extent record format — hot and cold variants, AEAD tag placement.
- **11.3.5** Allocator tree node format.
- **11.3.6** Snap tree node format (snapshot descriptors, refcount).
- **11.3.7** CAS entry format — content hash, refcount, compression/encryption state.
- **11.3.8** Key material format — wrapped keys in SB, per-dataset key slots.
- **11.3.9** Log formats (if any) — space-log style audit logs.

### 11.4 Open questions

- Endianness policy: little-endian on disk always (already v1 convention); keep it.
- Variable-length fields: bzip2-style self-describing vs fixed-size with padding. V1 used fixed-size; continue.
- How do we express "this volume requires feature X, refuse to mount without it"? RO-compatible vs RW-incompatible feature flags (ext4 pattern).

---

## 12. I/O paths

**STATUS**: STUB

### 12.1 Goals

- Document the happy path and recovery path for every operation.
- Make the invariants explicit — what's true at every step.

### 12.2 Subsections to write

- **12.2.1** Read path — lookup, integrity verify, decrypt, decompress, return.
- **12.2.2** Write path — allocate, compress, encrypt, hash-propagate, insert, commit.
- **12.2.3** Sync path — three-phase commit detail.
- **12.2.4** Rollback path — how a snapshot rollback reconstructs allocator state.
- **12.2.5** Scrub path — walk, verify, repair.
- **12.2.6** Mount path — SB selection, quorum, verify (opt-in), open trees, attach.
- **12.2.7** Unmount path — flush, sync, detach, safe-close.
- **12.2.8** Error recovery — transient IO error, permanent IO error, corruption detection.
- **12.2.9** Crash recovery — what state is possible at mount after crash; how we resolve.

---

## 13. Filesystem surface (POSIX)

**STATUS**: STUB

### 13.1 Goals

- Modern POSIX — everything in the ext4/XFS surface that's still relevant.
- Skip legacy quirks (noatime default, no mandatory locking, etc.).

### 13.2 Decisions committed (from VISION §6 non-goals)

- O_TMPFILE, F_SEAL_*, relatime, pipes-as-files: yes.
- Mandatory locking, atime: no.
- Obscure BSD extensions: no.

### 13.3 Subsections to write

- **13.3.1** Inode format — fields, timestamps, extended attributes, embedded-small-file optimization (if any).
- **13.3.2** Directory format — hash table + sorted list hybrid? B-tree? Evaluate.
- **13.3.3** Extended attributes — tree location, size limits.
- **13.3.4** File data — extent tree, inline data for small files.
- **13.3.5** Locking — advisory-only (flock/fcntl); no mandatory.
- **13.3.6** ACLs — POSIX ACLs as xattr, standard encoding.
- **13.3.7** Timestamps — nanosecond resolution, btime (creation time), mtime, atime (relatime), ctime.
- **13.3.8** Special files — FIFO, socket, device-node, symlink.
- **13.3.9** Reflinks (copy_file_range O(1)).
- **13.3.10** Hard links (cross-dataset? same-dataset only?).

### 13.4 Open questions

- Inline small-file data in the inode (ext4 `inline_data`) — yes or no? ZFS doesn't; btrfs does. Worth it for many-small-files workloads.
- Directory structure — btrfs uses a B-tree indexed by filename hash; that's probably what we do too, consistent with our Bε-tree.
- Max filename length, max path depth — go beyond 255 / 4096 for future-proofing?

---

## 14. Observability and debugging

**STATUS**: STUB

### 14.1 Goals

- Every subsystem exposes counters, events, histograms via `/ctl/`.
- Structured event log for forensic review.
- Debug dumps (tree walks, extent maps, integrity reports) accessible via `/ctl/`.

### 14.2 Decisions committed (from NOVEL #9)

- `/ctl/` synthetic filesystem.
- Administration via cat/echo.

### 14.3 Subsections to write

- **14.3.1** Counter schema — namespaces, naming, units.
- **14.3.2** Event log — format, retention, scope (per-pool, per-dataset).
- **14.3.3** Tracing — per-request sampling, correlation IDs across layers.
- **14.3.4** Debug dumps — tree walk, extent map, allocator state, integrity verify.
- **14.3.5** Integration with Prometheus / OpenTelemetry — optional, via a sidecar scraper reading `/ctl/`.

---

## 15. Cross-cutting concerns

**STATUS**: STUB

### 15.1 Feature-flag lifecycle

How features are introduced, stabilized, deprecated.

### 15.2 Error model

How errors propagate across layers; what the user sees.

### 15.3 Resource limits

Memory budgets, IO concurrency caps, CPU limits.

### 15.4 Cancellation and timeouts

Long-running operations (scrub, rebalance) support progress reporting and cancellation.

### 15.5 Backward compatibility

What old data a new binary can still read. Per-feature opt-in.

### 15.6 Thread / task model

Threads the stratum process creates; what they do; how they coordinate.

---

## 16. Appendices

### 16.1 Glossary

(Will grow as sections get filled in.)

### 16.2 Reference algorithms

- FastCDC pseudocode.
- BLAKE3 + Merkle-root construction.
- XChaCha20-SIV / AEGIS-256 construction.
- ML-KEM-768 hybrid key agreement (HPKE pattern).
- Epoch-based reclamation protocol.
- Bw-tree delta chain consolidation.

### 16.3 Known bibliography

- Bε-tree: Brodal et al. 2003; Bender et al. 2007.
- Bw-tree: Levandoski et al. 2013.
- FastCDC: Xia et al. 2016.
- Venti: Quinlan & Dorward 2002.
- BLAKE3: O'Connor et al. 2020.
- ML-KEM: NIST FIPS 203, 2024.
- AEGIS-256: Wu & Preneel, CAESAR 2013-2019.
- XChaCha20-SIV: Harris et al. 2019.
- LRC: Papailiopoulos & Dimakis 2012; Sathiamoorthy et al. 2013.
- TLA+: Lamport 2002+; 25 years of storage-industry use.

---

## 17. Section writing order (proposal)

Not every section needs the same depth. Proposed writing order for Phase 0 sessions, reflecting foundational-ness:

1. **§3 Concurrency** (largest blast radius; must be right first).
2. **§4 Storage pool** (shapes every layer below).
3. **§7 Superblock / quorum** (depends on §4; precondition for sync).
4. **§6 Allocator** (depends on §3, §4, §7).
5. **§10 Crypto** (depends on §7 for SB key-slot layout).
6. **§9 Integrity** (depends on §3 for hash update protocol).
7. **§8 Block device** (relatively standalone).
8. **§5 Namespace** (depends on §4, §6, §7, §10).
9. **§11 On-disk format** (derived from 3–10; committed last).
10. **§12 I/O paths** (integration document; tie it all together).
11. **§13 POSIX surface** (relatively standalone).
12. **§14, §15** (operational polish).

Each of §3–§6 is its own dedicated Phase 0 session at minimum. §10, §9, §5, §11, §12 can be paired with adjacent sections.

---

## 18. Status summary

| Section | Status | Writing priority |
|---|---|---|
| §1 Purpose | DRAFT | n/a |
| §2 Layer cake | STUB | 1 (small) |
| §3 Concurrency | STUB | 2 (large) |
| §4 Storage pool | STUB | 2 (large) |
| §5 Namespace | STUB | 4 |
| §6 Allocator | STUB | 3 |
| §7 SB / quorum | STUB | 3 |
| §8 Block device | STUB | 5 |
| §9 Integrity | STUB | 4 |
| §10 Crypto | STUB | 4 |
| §11 On-disk format | STUB | 6 (late) |
| §12 I/O paths | STUB | 6 (late) |
| §13 POSIX surface | STUB | 5 |
| §14 Observability | STUB | 7 |
| §15 Cross-cutting | STUB | 7 |
| §16 Appendices | STUB | continuous |

Ten sections in STUB state, ready to be filled in. §3 (Concurrency) is the natural next candidate.
