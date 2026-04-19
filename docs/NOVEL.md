# Stratum v2 Novel Angles — Scope and Sequencing

**Status**: Phase 0 draft, 2026-04-19. Concrete scope, "done" definition, dependencies, complexity, and risk per lead position.

## 1. Purpose

VISION.md committed Stratum v2 to ten lead positions versus ZFS, btrfs, and bcachefs. Each is real or marketing. This document is where we draw the line: for every angle, we define

1. **Scope** — what's in, what's deferred, what's out.
2. **Done** — a testable definition of "this shipped."
3. **Dependencies** — architectural decisions and other angles it builds on.
4. **Complexity** — rough KLOC and spec count.
5. **Risk** — mature technique vs research-grade.
6. **Priority** — what sequence, and what could be cut if schedule pressure comes.

The goal is to make `ARCHITECTURE.md` easier to write: each angle becomes a known quantity so we can focus on foundational decisions (concurrency model, storage pool, namespace model) rather than re-deriving scope for every novel feature.

## 2. Summary matrix

| # | Angle | Risk | LOC estimate | Sequence |
|---|---|---|---|---|
| 1 | Formal verification of sync + crash protocol | Low-med | 2–7 KLOC TLA+ | Continuous, starts early |
| 2 | PQ-hybrid AEAD-SIV encryption | Medium | 3–5 KLOC | Foundation (early) |
| 3 | Venti-style CAS cold tier + CDC | Medium | 5–8 KLOC | After hot tier stable |
| 4 | Lock-free metadata + MVCC readers | **High** | 8–12 KLOC | Core; longest path |
| 5 | Merkle-rooted metadata integrity | Low-med | 2–3 KLOC | Early, pairs with tree |
| 6 | Succinct in-RAM state | Medium | 4–6 KLOC | With persistent allocator |
| 7 | io_uring-native zero-copy I/O | Low-med | 2–3 KLOC | Foundation (first) |
| 8 | Per-connection 9P namespaces | Low | 3 KLOC | With namespace arch |
| 9 | Synthetic `/ctl/` administration | Low | 4–6 KLOC | Incremental, late |
| 10 | Factotum-style key agent | Medium | 5–6 KLOC | Parallel to core |

**Total novel-angle code**: 36–52 KLOC of C, plus 2–7 KLOC of TLA+. Fits within VISION.md's ~100 KLOC total budget once core + clients are added. If any angle blows past its estimate by 2×, it's a warning sign worth redesigning — filesystems don't tolerate runaway complexity well.

---

## 3. Per-angle scope

### 3.1 Angle #1 — Formal verification of sync + crash protocol

**Why it's novel**: no mainline filesystem has machine-checked specs. Academic filesystems (AOSP's FSCQ, PennFS) have proved correctness in Coq; they're research prototypes, not production systems. We'd be first to combine "production filesystem" with "formally verified critical paths."

**Scope — in**:
- TLA+ specification of the three-phase sync protocol. Proved safe under arbitrary write reordering, torn writes, and crash at any step.
- TLA+ spec of AEAD nonce uniqueness machinery. Proved that under concurrent writers, no `(paddr, write_gen)` pair repeats.
- TLA+ spec of the allocator refcount invariants under MVCC. Proved that no block is double-freed, no block leaks across txg boundaries.
- TLA+ spec of tree root commit atomicity. Proved that readers always see a consistent root, regardless of concurrent writer progress.
- TLA+ spec of per-connection namespace visibility. Proved that operations in one 9P connection's namespace never affect another's.
- CI pipeline: every commit touching the specified subsystems runs TLC model checking with bounded parameters.

**Scope — deferred**:
- Extracting executable code from specs (Coq/Dafny-style). We write C code that *implements* the spec; we don't generate C from the spec.
- Verification of functional correctness (e.g., "file contents read back equal what was written"). Property-based tests + fuzzers cover this; specs cover protocol invariants only.
- Specs for non-critical paths (e.g., the CLI wrapper, FUSE shim translation).

**Scope — out**:
- Verification of the crypto primitives themselves. We rely on established libraries (libsodium / liboqs) whose crypto has been audited externally.
- Verification of the filesystem at the whole-system level. Too expensive; prioritize the critical invariants.

**Done definition**:
- Five specs committed in `docs/specs/`: `sync.tla`, `nonce.tla`, `allocator.tla`, `tree_commit.tla`, `namespace.tla`.
- Each passes TLC model checking for at least 4 writer threads, 8 reader threads, 16-step traces, in under 10 minutes on a developer laptop.
- Each has an accompanying `SPEC-to-CODE.md` that maps spec actions to C code locations, so a developer can trace "this action in the spec corresponds to this function."
- CI runs TLC on every PR that touches a specified file.

**Dependencies**:
- Needs the architectural decisions for each specified subsystem to be fixed before the spec can be written.
- Nothing depends on this in turn; specs are verification, not a code dependency.

**Complexity**:
- ~300–1500 lines of TLA+ per spec; five specs total, 2–7 KLOC of spec code.
- Model-checking time: minutes for simple specs (sync), hours for complex ones (allocator under MVCC). Parameterizable for CI.

**Risk — Low-medium**:
- TLA+ is mature (Lamport, 25+ years). Production users: Amazon S3 (proved consistency), DynamoDB, Azure Cosmos DB, MongoDB, CockroachDB.
- Risk is our own ability to write correct, useful specs. Mitigate by starting with the sync spec (smallest, most studied class of protocol) and iterating.

**Alternative tools considered**:
- **Alloy**: nice for bounded checking but less well-suited to temporal logic.
- **Coq / Lean / Isabelle**: full interactive theorem proving; much higher cost, more expressive. Could adopt for a narrow subsystem (e.g., allocator data structure correctness) post-v2.0.
- **Dafny**: automated verification of imperative code, interesting middle ground. Considered but not chosen; less proven on distributed-systems protocols.

**Recommendation**: TLA+ for protocols, property-based tests + fuzzers for data structure functional correctness.

---

### 3.2 Angle #2 — PQ-hybrid AEAD-SIV encryption

**Why it's novel**: ZFS uses AES-GCM (classical, nonce-reuse-sensitive). bcachefs uses ChaCha20-Poly1305 (classical, same vulnerability). Neither uses SIV modes. No filesystem ships PQ-hybrid wrap keys by default.

**Scope — in**:
- Data encryption via **XChaCha20-SIV** (Harris et al., 2019, deterministic AEAD) or **AEGIS-256** (CAESAR finalist, also nonce-misuse-resistant). Final choice pending benchmarks.
- Wrap key establishment via **X25519 + ML-KEM-768 hybrid** (RFC 9180 HPKE pattern, adapted for at-rest). Classical security if ML-KEM is broken; PQ security if X25519 is broken; both hold = double security.
- Per-dataset keys with inheritance (ZFS-style).
- Key rotation supported (re-wrap, not re-encrypt).
- AES-NI / SHA-NI / VAES detection and fast paths on x86-64; ARMv8 crypto extensions on ARM.

**Scope — deferred**:
- Homomorphic operations on encrypted data (search on ciphertext, etc.). Research-grade; not a filesystem concern.
- Onion-layered encryption for different trust domains. Single wrap-key layer at v2.0.
- Hardware Security Module integration (covered by angle #10).

**Scope — out**:
- XTS mode. We explicitly reject XTS for data encryption because it's not AEAD.
- Classical-only wrap (no PQ). Regulatory pressure is real; PQ by default is the right call.

**Done definition**:
- All data blocks encrypted with XChaCha20-SIV (or AEGIS-256, post-benchmark).
- Wrap key derivation via hybrid KEM; key material verified via test vectors from ML-KEM FIPS 203 test suite.
- Per-dataset key isolation: test that datasets with different keys cannot decrypt each other.
- Benchmark: SIV encryption throughput ≥ 1 GB/s/core on commodity hardware (modern AES-NI equipped). Should be competitive with classical AEAD.
- Key rotation: dataset can have its wrap key rotated without re-encrypting data blocks.
- Test suite: includes known-answer tests, fault injection, and side-channel-resistance checks (constant-time paths).

**Dependencies**:
- Crypto library selection. libsodium has XChaCha20-Poly1305 but not SIV; we either add SIV to libsodium (upstream contribution) or switch to a library with SIV built in (BoringSSL has AES-GCM-SIV; liboqs has the KEMs).
- Nonce allocation model (already decided: End A).
- Key agent integration (angle #10) for unwrap ops.
- Namespace / per-dataset architecture decision.

**Complexity**:
- SIV implementation (or wrapping existing): 500–2000 LOC.
- Hybrid KEM (X25519 + ML-KEM-768): 500–1000 LOC mostly wrapping liboqs.
- Key schedule, wrap/unwrap, rotation: 1–2 KLOC.
- Test vectors + KAT suite: 500 LOC.
- Total: 3–5 KLOC.

**Risk — Medium**:
- ML-KEM is newly standardized (FIPS 203, August 2024). Implementations exist (liboqs, BoringSSL draft, Go Cryptography) but aren't as battle-tested as AES-GCM.
- SIV modes are well-specified but less deployed; implementation bugs have the same severity class as any AEAD bug.
- Mitigate: audit the crypto code specifically, use test vectors from RFC/FIPS, run against multiple reference implementations to cross-check.

---

### 3.3 Angle #3 — Venti-style CAS cold tier with content-defined chunking

**Why it's novel**: tiering + dedup + CDC have never been unified in a production filesystem. Plan 9's Fossil + Venti did the architectural pattern in 2002 without CDC. Restic/borg did CDC for backups. No one has combined all three at the POSIX filesystem layer.

**Scope — in**:
- Hot tier: Stratum's Bε-tree + extent model.
- Cold tier: a content-addressable store. Blocks keyed by BLAKE3-256 of content. Append-only on disk. Refcount per key for garbage collection.
- **FastCDC** (Xia et al. 2016) for content-defined boundary detection. Average chunk size configurable (default 8 MiB); boundaries detected via rolling hash.
- Migration engine: heuristic v1 (age-based + access-frequency). Learned policy v2 post-release.
- Transparent reads: file reads fetch from hot or cold tier based on where the chunk lives.
- Promotion on write: writing to a cold extent promotes the chunk to hot for the new version (COW).

**Scope — deferred**:
- Learned migration model (v1 uses LRU-style heuristics; ML model comes later).
- Cross-pool dedup (dedup only within a single volume at v2.0).
- User-facing dedup stats / reports beyond the basic `/ctl/` interface.

**Scope — out**:
- Online block-aligned dedup (ZFS DDT style). Content-defined is strictly better.
- Inline compression of CAS entries (the hash is over the uncompressed content; compression happens in the standard extent layer before CAS migration).

**Done definition**:
- Files can live in hot tier (every block at its own paddr) or cold tier (every chunk at its content hash).
- Migration triggered by policy; user can force via `echo <inode> > /ctl/pools/<name>/migrate-to-cold`.
- Reads transparently fetch from either tier without user awareness.
- Benchmark: 1 TiB of test VM images with known 80% content overlap stores in ≤ 250 GiB after migration. Matches restic/borg dedup ratios.
- GC test: delete half the files, scrub, verify CAS refcount decrements correctly, unused chunks reclaimed.

**Dependencies**:
- Hot tier (core filesystem) stable.
- BLAKE3 hash library.
- Extent model supports two "kinds" of extent: hot (paddr-addressed) and cold (hash-addressed).
- Namespace / subvolume model (migration is per-subvolume; properties may vary).

**Complexity**:
- FastCDC: 500 LOC (well-documented algorithm with reference impl).
- CAS store: hash index, refcount, GC walker. 3–5 KLOC.
- Migration engine: 1–2 KLOC for v1 heuristic.
- Extent-kind abstraction in core FS: 1–2 KLOC of changes.
- Total: 5–8 KLOC.

**Risk — Medium**:
- CAS stores are well-understood (Venti, git, restic, borg, Perkeep). Primary novelty is POSIX integration.
- CDC is well-specified but has a known "average case vs worst case" tradeoff (pathological inputs can produce tiny chunks or huge chunks). Mitigate with min/max chunk size clamps.
- GC under concurrent writes is a classical tricky area; benefit from existing literature.

---

### 3.4 Angle #4 — Lock-free metadata path + MVCC readers

**Why it's novel**: ZFS serializes at the txg commit. btrfs has known subvolume-lock contention. bcachefs is designed for lock-free reads but its writer path still takes locks. None has lock-free writers on the metadata tree. The Bε-tree architecture is an unusually good fit for lock-free writes because message-buffer appends are monotonic — they compose naturally as CAS on per-node delta chains.

**Scope — in**:
- **MVCC readers**: every reader grabs the current tree root pointer at operation start; holds a snapshot reference for the duration; releases on completion. Readers never see a half-updated tree.
- **Lock-free inner nodes**: message-buffer appends via CAS on delta chains (Bw-tree pattern). No lock on tree traversal.
- **Single-writer commit at sync point** (End A of the concurrency-vs-security discussion). Writers parallelize up to commit; one thread serializes the commit itself.
- **Epoch-based reclamation** (EBR) or **Version-Based Reclamation** (VBR, Kirsch 2022) for freeing old tree versions safely.

**Scope — deferred**:
- Fully lock-free multi-writer commit. That's a research-grade goal; the performance win vs serialized-commit is small for target workloads (commit is already O(new tree state), not a throughput bottleneck).
- Hardware Transactional Memory (Intel TSX, ARM TME) short-circuits for hot-path contention. Post-v2.0 if specific paths show contention.

**Scope — out**:
- Lock-free compaction of delta chains. The `consolidate` operation (merging a delta chain back into a fresh node) is done by a dedicated consolidator thread, not lock-free.

**Done definition**:
- Stress test: 32 concurrent reader threads sustain full read throughput under heavy writer load. Throughput scales ~linearly to physical-core count.
- Writer path: N writers (N = 4, 8, 16) produce expected total throughput without lock contention on the hot path (measured via `perf` / ring-buffer stalls).
- No-deadlock guarantee: fuzz test with random operation schedules for 24+ hours, zero hangs.
- TLA+ spec (from angle #1) proves: readers never see inconsistent tree state; no writer can prevent another writer from making progress (non-blocking property).

**Dependencies**:
- Concurrency model decision (committed: MVCC readers, End A writers).
- Reclamation scheme choice (EBR vs VBR vs hazard pointers). Recommend EBR for simplicity, upgrade to VBR if reclamation lag becomes a problem.
- Bw-tree vs B-link-tree structural choice.
- TLA+ spec (angle #1) for concurrency invariants.

**Complexity — this is the largest, highest-risk angle**:
- Epoch-based reclamation: 500 LOC.
- Bw-tree-style delta-chain Bε-tree: 3–5 KLOC of careful code (rewrites a significant portion of existing `btree/` code).
- MVCC root management: 1–2 KLOC.
- Extensive concurrency testing infrastructure (TSAN + stress + fuzz): 2 KLOC of test harness.
- Total: 8–12 KLOC.

**Risk — High**:
- Lock-free data structures are notoriously error-prone. ABA problems, memory reclamation bugs, subtle reorderings. This is where formal specs (angle #1) earn their keep.
- Mitigate: write the TLA+ spec first, prove the key invariants, then implement; run ThreadSanitizer on every CI build; maintain a fuzzing corpus that exercises concurrent schedules.
- Fallback plan: if full lock-free metadata proves intractable, fall back to fine-grained per-node locks with MVCC readers. Still beats ZFS and btrfs; ~30% of the throughput win vs full lock-free.

---

### 3.5 Angle #5 — Merkle-rooted metadata integrity

**Why it's novel**: filesystems check individual blocks. No filesystem Merkle-hashes the whole metadata tree with the root in the superblock. The property you get — "any offline metadata edit is cryptographically detectable" — is qualitatively different from "each block has a csum."

**Scope — in**:
- Every metadata node (btree internal + leaf, allocator tree nodes, snapshot tree nodes) has a BLAKE3-256 hash of its content and its children's hashes.
- Superblock carries the root hash.
- Verification paths:
    - **Mount-time full verify** (opt-in via `stratum mount --verify`): walk all metadata, verify every hash. Slow for large volumes; for paranoid deployments.
    - **On-read verification** (default): reads verify the path from leaf to root. ~log₂(n) hash computations per read. Cheap.
    - **Background scrub**: continuously walks metadata in the background, re-verifying.
- Root hash is updated incrementally on commit — only nodes actually modified in a txg get re-hashed, propagated up.

**Scope — deferred**:
- Merkle integrity over data blocks. Data is already covered by per-extent AEAD tags (encrypted) or xxHash (unencrypted). Metadata is where Merkle adds unique value.
- Publish-transparency-style root-hash log (like Certificate Transparency's CT logs). Interesting post-v2.0 for air-gapped volumes.

**Scope — out**:
- Pre-image resistance at the hash level beyond BLAKE3's 256-bit security. If BLAKE3 is broken, the whole integrity story dies; that's true of any cryptographic hash.

**Done definition**:
- Every metadata block has a Merkle path to the SB root.
- Mount-time verify mode works: modify a metadata block offline (via `dd`), mount with `--verify`, expect a loud integrity failure.
- On-read verify default: mount normally, attempt to read through a corrupted metadata block, get `-EIO` at the point of access.
- Performance: on-read verify adds < 5% latency overhead on a typical read. Mount-time full verify on 1 TiB volume completes in < 60 seconds on NVMe.

**Dependencies**:
- BLAKE3 library (already have xxHash; adding BLAKE3 is small).
- Tree data structures support a `hash` field on each node.
- Sync protocol advances hash + root bptr atomically.

**Complexity**:
- BLAKE3 wrapper: 200 LOC.
- Merkle hash propagation in Bε-tree: 1–2 KLOC.
- Verification paths: 500 LOC.
- Total: 2–3 KLOC.

**Risk — Low-medium**:
- Merkle trees are well-understood (Git, Bitcoin, Certificate Transparency, ZFS dedup table uses it).
- Performance risk: commit path has to hash up to the root. Mitigate via per-txg batching (one hash pass at commit, not per-write).

---

### 3.6 Angle #6 — Succinct in-RAM state

**Why it's novel**: existing filesystems use straightforward data structures — arrays, hash tables, lists. Succinct structures (wavelet trees, rank/select, SDArrays) are common in genomics, BWT-indexed search, information retrieval. No production filesystem uses them.

**Scope — in**:
- Allocator in-RAM state represented via **rank/select** over a compressed bitmap (SDArray or EF-encoded). Target: 2–4 bits per block average, vs 32 bits in v1.
- Approximate set membership (for cache-miss negative lookups) via **xor filters** (Graf & Lemire 2020). 40% smaller than Bloom filters with same false-positive rate.
- Node cache keyed by paddr uses a **wavelet-tree-indexed** fast-access structure for LRU state, if profiling shows contention.
- Cache sizes bounded: W-TinyLFU (Mazi et al. 2015) for admission; capped at 64–128 MiB by default.

**Scope — deferred**:
- Learned indices (Google Kraska et al. 2018) for hot lookups. Research-grade for filesystems; heuristic W-TinyLFU is good enough for v2.
- Succinct representation of the on-disk tree itself. We keep on-disk nodes in traditional format for simplicity.

**Scope — out**:
- Removing the in-memory cache entirely. We need a cache for hot metadata; the novelty is keeping it small, not eliminating it.

**Done definition**:
- Allocator RAM ≤ 1 MiB per TiB of data on a typical workload (measurable, concrete).
- 100-TiB test volume: allocator footprint ≤ 100 MiB.
- Cache works correctly: hit-rate on typical read workload ≥ 90% with 64 MiB cache (measure against LRU baseline).
- Benchmark: mount + first hundred file operations on 100-TiB volume complete within latency budgets from VISION §4.14.

**Dependencies**:
- Persistent allocator design (refined version of v1's Phase D #2 work).
- Library choice: **sdsl-lite** (C++, gold-standard) has bindings; alternatively native C implementation. Probably wrap sdsl-lite initially to reduce implementation cost.
- xor filter library — exists in multiple implementations (Go, Rust, C++, C).

**Complexity**:
- sdsl-lite wrapper: 1 KLOC.
- Allocator integration with succinct structures: 2–3 KLOC (revises the v1 allocator substantially).
- xor filter for cache lookups: 500 LOC.
- W-TinyLFU: 500 LOC (existing implementations to adapt).
- Total: 4–6 KLOC.

**Risk — Medium**:
- Succinct structures have predictable performance but research-to-production path is less trodden than classical structures.
- Mitigate: benchmark against straightforward implementations early; fall back if the succinct path underperforms on hot operations. Space savings are the goal, but not at the cost of cache-miss latency.

---

### 3.7 Angle #7 — io_uring-native zero-copy I/O

**Why it's novel**: existing filesystems use the traditional block I/O submission path. A few have io_uring awareness as an opt-in; none were designed around it.

**Scope — in**:
- Block device abstraction layer with io_uring as the Linux backend.
- Fixed-buffer submission for zero-copy reads/writes (eliminating one memcpy per I/O).
- Registered files (avoiding fd validation overhead).
- DAX-compatible path for byte-addressable persistent memory (Optane-style, or CXL memory devices).
- Portable fallback (libaio on older Linux; FUSE's own I/O path on non-Linux).

**Scope — deferred**:
- SPDK (userspace NVMe driver) integration. For extreme IOPS workloads; post-v2.0.
- Full NVMe-oF (NVMe over Fabrics) support. Server/storage-appliance workload; not our primary target.

**Scope — out**:
- Replacing the POSIX read/write syscall layer entirely. io_uring is one submission backend; synchronous `read(2)`/`write(2)` still works.

**Done definition**:
- Benchmark: sequential read throughput ≥ 90% of raw NVMe device bandwidth.
- Benchmark: 4k random write IOPS within 20% of raw NVMe (ioping comparison).
- DAX path tested (if hardware available; qemu `pmem` emulation otherwise).
- Fallback aio path works on Linux kernels pre-5.1.
- liburing dependency tracked and versioned.

**Dependencies**:
- Block device abstraction design (architecture decision).
- Nonce construction must accommodate multi-device (for pool storage; architecture decision).

**Complexity**:
- liburing wrapper + submission-completion loop: 1 KLOC.
- Fixed-buffer management: 500 LOC.
- DAX path: 500 LOC.
- Fallback aio: 500 LOC.
- Total: 2–3 KLOC.

**Risk — Low-medium**:
- io_uring is mature (Linux 5.1+, ABI-stable since 5.11).
- DAX is less mature but optional.
- Mitigate: keep the abstraction narrow so we can swap backends.

---

### 3.8 Angle #8 — Per-connection 9P namespaces

**Why it's novel**: no Unix-family filesystem offers per-connection namespace composition. Overlayfs, bind mounts, and containers provide it at the kernel layer via ad-hoc mechanisms. 9P has namespaces as a first-class protocol feature, and we can ship it that way.

**Scope — in**:
- Per-9P-connection mount table: each connection has its own view of subvolumes.
- 9P `Tattach` semantics extended with namespace-composition hints.
- Bind operation (`Tbind` or similar): connection's client can mount a subvolume at a path in its private namespace.
- Union mount (stacked namespace): multiple subvolumes composed as a single directory view.
- Authentication per-connection (existing 9P `Tauth` machinery).

**Scope — deferred**:
- Linux-kernel-level per-process namespaces (requires stratum-aware kernel module; post-v2.0).
- Namespace inheritance across forks (a Plan 9 feature; more meaningful with a Plan 9 OS; partial support via 9P connection cloning).
- Cross-mount union with non-stratum filesystems (complex; not obviously valuable).

**Scope — out**:
- Global namespace coordination across connections. Connections are explicitly isolated.

**Done definition**:
- Two concurrent 9P clients mount stratum; each runs `Tbind` operations; each sees its own resulting namespace.
- Test: mutation via client A in its namespace doesn't affect client B's view.
- Containerized workload: docker-style container can run against stratum with pre-configured per-container namespace composition.
- Documentation: a tutorial showing how to use per-connection namespaces for sandboxing.

**Dependencies**:
- 9P server refactor for per-connection state.
- Subvolume/dataset model (architecture decision).
- Authorization model (who's allowed to mount what).

**Complexity**:
- Per-connection namespace data structure: 1 KLOC.
- Bind operation implementation: 500 LOC.
- Union mount dispatcher: 1 KLOC.
- Test machinery (multi-client integration tests): 500 LOC.
- Total: 3 KLOC.

**Risk — Low**:
- Plan 9 designed and shipped this. We're re-implementing a known-good pattern.

---

### 3.9 Angle #9 — Synthetic `/ctl/` administration

**Why it's novel**: ZFS has `zfs`/`zpool` CLI, btrfs has `btrfs` CLI, bcachefs has `bcachefs` CLI — all separate binaries with bespoke output formats. Plan 9's `/srv`/`/mnt`/`/proc` pattern is how we do admin. No modern filesystem follows it.

**Scope — in**:
- Synthetic filesystem under `/ctl/` (or `/proc/stratum/`, final path TBD) exposing all admin surfaces.
- Pool-level ops: `/ctl/pools/<name>/status`, `/ctl/pools/<name>/scrub`, `/ctl/pools/<name>/snapshots/`.
- Dataset-level ops: `/ctl/pools/<name>/datasets/<path>/properties`, `/ctl/pools/<name>/datasets/<path>/snapshot`.
- Device-level ops: `/ctl/pools/<name>/devices/<dev>/smart`, `/ctl/pools/<name>/devices/<dev>/scrub`.
- Event log: `/ctl/logs/scrub`, `/ctl/logs/repair`, `/ctl/logs/errors`.
- Write-command semantics: `echo start > /ctl/pools/tank/scrub` triggers scrub. `echo @<name> > /ctl/pools/tank/datasets/home/snapshot` creates a snapshot.
- CLI wrapper (`stratum-cli`) as a thin convenience over cat/echo.

**Scope — deferred**:
- Full automation / eventing API. For sophisticated deployments. Basic admin is sufficient at v2.0.
- Web UI. Third-party concern.

**Scope — out**:
- GUI admin tools. We expose the filesystem; GUIs are someone else's problem.
- JSON-first output. Plain text with clear columns is the Plan 9 way; `awk` parses it fine.

**Done definition**:
- Every admin operation in v2.0 is accessible via `/ctl/`.
- Tutorial: "Administration without learning a new CLI" — shows all common ops via standard Unix tools.
- Remote admin: SSH + 9P forwarding = remote admin. No separate remote-access layer needed.
- CLI wrapper built: thin, scripts-as-documentation.

**Dependencies**:
- 9P server serves synthetic files.
- Every admin operation implemented and exposed.
- Documented path layout (versioned, stable).

**Complexity**:
- Synthetic-FS infrastructure: 1 KLOC.
- Per-operation exposed files: depends on operation count. Estimate 30–50 distinct files × 50–100 LOC each = 2–5 KLOC.
- CLI wrapper: 500 LOC.
- Total: 4–6 KLOC.

**Risk — Low**:
- Plan 9 proves the model; implementation is straightforward.
- Real risk is API churn: we commit to a path layout at v2.0 and then people script against it. Mitigate by versioning (`/ctl/v1/pools/...` initially).

---

### 3.10 Angle #10 — Factotum-style key agent

**Why it's novel**: ZFS and bcachefs bundle key management into the filesystem code. Plan 9's factotum split authentication into a dedicated process. We do the same for storage encryption — and pair it with HSM/TPM/KMS backends.

**Scope — in**:
- Dedicated agent process (`stratum-keyagent` or similar).
- Communication via Unix socket (or 9P locally).
- Backends:
    - Passphrase (Argon2id KDF, for laptops).
    - TPM 2.0 (for attested-boot systems).
    - YubiKey / FIDO2 (hardware token).
    - PKCS#11 (enterprise HSMs, cloud KMS proxies).
- Key rotation: agent can rotate wrap keys without remounting the FS.
- Audit log: every unwrap op recorded with timestamp, caller (connection), dataset.

**Scope — deferred**:
- Key-escrow / key-recovery workflows. Enterprise deployment concern.
- Cross-agent key sharing (federated key material). Distributed-systems territory.

**Scope — out**:
- Integrated UI for managing keys. Command-line first (fits the Plan 9 philosophy).
- Replacing dm-crypt. We encrypt at the 9P boundary, not the block device.

**Done definition**:
- Agent proxies to ≥ 3 backends at v2.0 (passphrase, TPM, PKCS#11).
- Test: key rotation rotates wrap key in the agent; subsequent FS operations use the new wrap without remount.
- Test: agent crash → FS operations requiring unwrap fail cleanly (EIO) but FS state stays consistent.
- Test: audit log contains every unwrap with enough context for forensic review.

**Dependencies**:
- Key schema in superblock (what's wrapped, how it's indexed).
- FS↔agent protocol design (probably: a simple "unwrap this wrapped key using context X" request/response).
- Backend integration for each supported HSM/token.

**Complexity**:
- Agent main: 1 KLOC.
- Passphrase backend: 200 LOC.
- TPM 2.0 backend: 1.5 KLOC (TPM API is fiddly).
- YubiKey backend: 500 LOC.
- PKCS#11 backend: 1 KLOC (well-specified but verbose).
- FS-side client library: 500 LOC.
- Total: 5–6 KLOC.

**Risk — Medium**:
- Backend integration is well-understood but crypto code everywhere needs careful review.
- TPM 2.0 is notoriously fiddly; easy to get bugs that leak key material via side channels.
- Mitigate: use upstream tools (tpm2-tools, tpm2-tss) as the backend rather than implementing TPM protocol directly; each backend gets an individual audit pass before shipping.

---

## 4. Sequencing

Natural order, derived from the dependencies:

### Phase I — Foundations (precondition for almost everything)

- **Angle #7 — io_uring block device.** Every other angle runs on top of I/O. Design this first.
- **Angle #2 — Crypto primitives.** SIV + hybrid KEM infrastructure. Independent of the tree; can be built in parallel.
- **Angle #1 — TLA+ specs for sync + nonce uniqueness.** Writing these forces clarity on the protocols before we implement them. Start with sync spec.

### Phase II — Core tree + concurrency

- **Angle #4 — Lock-free Bε-tree.** The biggest, riskiest angle. Implement against the TLA+ spec from Phase I.
- **Angle #5 — Merkle integrity.** Lives inside the Bε-tree; add hash fields as the tree is built.
- **Angle #6 — Succinct allocator.** The persistent allocator work from v1's Phase D, done right.

### Phase III — Namespace + features

- **Angle #8 — Per-connection 9P namespaces.** Requires subvolume/dataset model.
- **Angle #10 — Key agent.** Pair with #2 for full crypto story. Parallel to #8.
- **Angle #3 — CAS cold tier + CDC.** After the hot tier is stable, add the cold tier + migration.

### Phase IV — Admin + operational polish

- **Angle #9 — Synthetic `/ctl/`.** Incremental; every admin operation added earlier gets exposed here.

### Phase V — Continuous (throughout)

- **Angle #1 — TLA+ specs** keep growing as more subsystems stabilize. Every architectural subsystem gets a spec before it's declared done.

## 5. If we're cut for time

If we're pushed to ship faster and have to cut angles, the priority for cutting is:

1. **First to cut**: Angle #9 (synthetic `/ctl/`). Admin is a CLI wrapper initially; `/ctl/` can be incremental post-v2.0.
2. **Second**: Angle #6 (succinct structures). Modest cache + straightforward data structures work; we lose the 1-MiB-per-TiB lead position but not correctness.
3. **Third**: Angle #3 (CAS cold tier). Ship without tiering; add as v2.1. We lose the dedup + tiering lead positions.

Not cuttable:
- Angle #1 (formal verification) — without this, complexity is unmanageable.
- Angle #2 (PQ + SIV) — core security posture.
- Angle #4 (lock-free metadata) — core concurrency posture, architecturally hard to add later.
- Angle #5 (Merkle integrity) — core integrity posture.
- Angle #7 (io_uring) — foundational; the block abstraction is baked early.
- Angle #8 (per-connection namespaces) — architectural; hard to add later.
- Angle #10 (key agent) — goes with #2.

If we hit scope pressure, we cut angles 9 → 6 → 3 in that order. Past that, we re-plan.

## 6. Novel-angle risk summary

| Angle | Risk | Fallback if it fails |
|---|---|---|
| #1 Formal verification | Low-medium | Heavy fuzzing + audit loop (v1-proven) |
| #2 PQ + SIV | Medium | Ship classical AEAD with PQ wrap; SIV as v2.1 |
| #3 CAS cold tier | Medium | Ship without tier; tiering as v2.1 |
| #4 Lock-free metadata | **High** | Fine-grained per-node locks + MVCC readers (still beats ZFS/btrfs) |
| #5 Merkle integrity | Low-medium | Ship with per-block csums only (still matches state of the art) |
| #6 Succinct structures | Medium | Straightforward data structures (modest RAM cost) |
| #7 io_uring | Low-medium | libaio fallback |
| #8 Per-connection namespaces | Low | N/A (straightforward Plan 9 port) |
| #9 Synthetic `/ctl/` | Low | Standard CLI tool |
| #10 Key agent | Medium | In-process key handling (less clean but works) |

One genuine high-risk item (#4 lock-free metadata). All others have safe fallbacks. If #4 fails, we fall back to fine-grained locking and still beat ZFS and btrfs on concurrency; we lose the full lead position but not correctness.

## 7. Summary claim

Ten novel angles, total ~36–52 KLOC of C + 2–7 KLOC of TLA+. One high-risk item with a clear fallback. Dependencies are well-understood; sequencing is natural. Every angle has a testable "done" definition. Nothing is handwaving.

Stratum v2 is ambitious but the ambition is bounded and verifiable. We know what we're signing up for.
