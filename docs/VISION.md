# Stratum Vision

**Status**: Phase 0 draft, 2026-04-19. This is a living document; decisions here constrain every downstream design document. Every claim is contestable.

## 1. Purpose

What is Stratum *for*? This document answers three questions that every later design decision depends on:

1. **Who uses Stratum, and for what?** (§2, Target workloads)
2. **At what scale does Stratum need to work?** (§3, Scale targets)
3. **When design goals conflict, which wins?** (§4, Property ranking — the core of this document)

Plus: what Stratum deliberately does *not* try to be (§5, Non-goals).

## 2. Target workloads

In rough order of primacy. A design decision that serves workload 1 at the cost of workload 5 is acceptable; the reverse is not.

1. **Root filesystem of a future POSIX-compatible OS.** The long-horizon goal. Stratum hosts the OS itself — executables, libraries, configuration, logs, homedirs. Correctness under arbitrary workload, low overhead on the hot path, graceful degradation under pressure, bulletproof crash recovery. This workload dominates the design.

2. **Developer workstation.** Code, VMs, container images, builds, large intermediates. Heavy snapshot/rollback use (undo-my-build, git-alike timelines). High-throughput reads and writes. Dedup benefits substantial (VM images, build artifacts).

3. **Personal archive.** Photos, video, documents. Large sequential writes, occasional reads, long retention. Integrity-over-time is paramount (bit rot detection + repair from redundancy). Dedup benefits moderate.

4. **Server as file/backup target.** NFS/SMB/9P served from stratum. Multi-client concurrent reads, occasional heavy writes. Replication (send/recv) to off-site targets. Encryption at rest non-negotiable.

5. **Small embedded / IoT devices.** Limited RAM (< 512 MB), small disks (< 64 GiB), power-loss sensitive. Optional workload — if supporting it costs the primary workloads, drop it.

**Explicitly out of scope** (see §5 for more): distributed multi-node filesystems (Ceph, GlusterFS territory); object storage (S3-alike); parallel HPC filesystems (Lustre territory).

## 3. Scale targets

| Tier | Volume size | Files | Clients | RAM budget |
|---|---|---|---|---|
| Minimum | 32 MiB | 10³ | 1 | 4 MiB |
| Typical | 1 TiB | 10⁸ | 10² | 64 MiB |
| Large | 100 TiB | 10¹⁰ | 10³ | 2 GiB |
| Stretch | 10 PiB | 10¹¹ | 10⁴ | 32 GiB |

The RAM budget is *resident working set per mount*, not hard cap. A stretch-tier volume that needs 32 GiB to work at full performance is acceptable; one that needs 32 GiB just to mount is not. This is a direct rebuttal to ZFS's "1 GB RAM per TiB" heuristic, which disqualifies it from many of our target workloads.

**Single-volume max**: ≥ 1 EiB (matches ZFS, btrfs). **Single-file max**: ≥ 1 EiB (exceeds ext4's 16 TiB). **Max inodes**: 2⁶⁴ (practical) / 2⁶³ (reserved bit). **Pool-max-devices**: ≥ 1024 (matches ZFS-class pool limits).

## 4. Property ranking

The core of this document. Each property has:

- A short definition.
- The spectrum, with existing filesystems placed on it. Abbreviations: **ZFS**, **btrfs**, **bcachefs**, **XFS**, **ext4**. Stratum current = stratum v1 as of commit `1ac3f59`.
- A tentative Stratum v2 position, for discussion.

When two properties conflict, the one ranked higher in the overall priority (decided at the end of §4) wins. That overall priority is the single most important output of this document.

---

### 4.1 Data integrity — detection

**Definition**: does the filesystem detect silent data corruption (bit rot, torn writes, media errors, filesystem-cache bugs underneath) before handing bad bytes to the caller?

- **Weakest**: ext4 — no data checksums; metadata csums added ~2012. Assumes hardware is trustworthy.
- **Weak**: XFS — metadata csums (added ~2013); no data csums.
- **Strong**: btrfs, bcachefs — csums on data and metadata (CRC32C default, BLAKE2b / xxHash options).
- **Strongest**: ZFS — SHA-256 csums default, end-to-end, self-verified on every read.
- **Stratum current**: xxHash3-64 per extent, xxHash3-128 per btree node, AEAD tag on every encrypted block. On par with strongest.

**Stratum v2 tentative**: **strongest + tamper-evident**. Keep per-extent + per-node csums. Add Merkle root of all metadata in the superblock — detects not only bit rot but *offline tampering* of any metadata block. No existing filesystem does this.

### 4.2 Data integrity — repair

**Definition**: when corruption is detected, does the filesystem repair it automatically (given redundancy), or just report and fail?

- **Weakest**: ext4, XFS — report, let userspace handle it.
- **Moderate**: btrfs — auto-repair from DUP profile (metadata), RAID1/10 mirrors. RAID5/6 self-repair historically unreliable.
- **Strong**: ZFS — auto-repair from mirrors, RAIDZ, dittoblocks. Scrub walks the tree and heals.
- **Strong**: bcachefs — similar to ZFS, with modern erasure codes.
- **Stratum current**: **detect only** — we don't have redundancy infrastructure. Zero repair capability.

**Stratum v2 tentative**: **strong, with modern codes**. Mirrors + Reed-Solomon raidz-equivalent, optionally LDPC or lattice-based codes for faster rebuild. Online scrub with repair. This is a peer-parity requirement, not a lead angle.

### 4.3 Crash safety

**Definition**: after an arbitrary crash or power loss, does the filesystem return to a consistent state with bounded data loss?

- **Weakest**: non-journaled ext (historical). Lose metadata consistency.
- **Weak**: ext4, XFS — metadata-journal. Metadata always consistent; recent data may be lost.
- **Strong**: btrfs, bcachefs, ZFS — COW. Never inconsistent; lose at most the last un-synced transaction group.
- **Stratum current**: strong — three-phase sync with ping-pong superblock, 15-round audit converged. Proved by testing.

**Stratum v2 tentative**: **strongest + formally verified**. Same three-phase structure, but with TLA+ spec proved correct under arbitrary write reordering. No existing filesystem has machine-checked crash-safety proofs. This is **novel angle #1**.

### 4.4 Throughput

**Definition**: aggregate bytes/sec the filesystem can absorb under heavy sequential or parallel I/O. Measured against raw device throughput.

- **Best**: XFS, ext4 — thin layers. XFS designed for massive parallel RAID arrays. Near-raw-device for sequential.
- **Good**: bcachefs — modern, tiered caching, io_uring-ready.
- **Moderate**: ZFS, btrfs — COW + checksum + compression overhead. 50-70% of raw for sequential writes typical.
- **Stratum current**: moderate-to-good — 28-53 MB/s on TUI integration tests for small files; untested at scale.

**Stratum v2 tentative**: **good, approaching XFS on sequential**. io_uring-native path (novel angle #7) + zero-copy extents. COW has inherent write amplification ceiling; Merkle integrity adds a hash chain on commit. Accept ~70% of raw-device for sequential writes; optimize for small-file workloads where other COW FSes traditionally suffer.

### 4.5 Latency

**Definition**: p50 / p99 / p99.9 latency for single-file read/write operations.

- **Best**: ext4 — shortest code path. p50 ~100µs on NVMe.
- **Good**: XFS — slightly more overhead than ext4, similar order.
- **Moderate**: btrfs, bcachefs — COW paths add ~100µs overhead.
- **Moderate**: ZFS — ARC hits are fast; ARC misses slower; compression/encryption layers add ms.
- **Stratum current**: moderate — no latency targets set, no measurements.

**Stratum v2 tentative**: **good**. Target p99 < 500µs for small-file reads on NVMe, p99 < 2ms for writes. Lock-free reads (novel angle #4) remove contention penalties present in ZFS's per-dataset serialization and btrfs's subvolume locks.

### 4.6 Memory footprint

**Definition**: RAM used per mounted volume, especially as a function of volume size.

- **Best**: ext4 — O(active inodes). Few MiB per typical mount.
- **Good**: XFS — similar.
- **Moderate**: btrfs — O(active state + subvolume count).
- **High**: bcachefs — moderate; configurable.
- **Worst**: ZFS — ARC can consume gigabytes by default. "1 GB RAM per TiB data" is a real sizing recommendation.
- **Stratum current**: O(total blocks) for the refcount array — 1 GiB per TiB, matching ZFS's worst case. Phase D #2 was meant to fix this.

**Stratum v2 tentative**: **O(working set)**, target 1 MiB of allocator RAM per TiB of data. Persistent allocator with on-demand tree queries replaces the flat array. Cache sizing becomes policy, not requirement.

### 4.7 Concurrency

**Definition**: how many concurrent readers and writers can the filesystem sustain without contention?

- **Best**: XFS — aggressive fine-grained locking, MVCC-style inode logging, near-linear read scaling to 64+ cores.
- **Good**: ext4 — moderate; per-inode locks, shared page cache.
- **Moderate**: bcachefs — designed for lock-free reads, writer locks per subvolume.
- **Weak**: ZFS — global txg commit serialization; per-dataset locks. Multi-client performance suffers under contention.
- **Weak**: btrfs — subvolume-level locks; big-tree serialization. Known scalability bottleneck.
- **Stratum current**: **single-threaded.** No locking anywhere; single FUSE/9P loop.

**Stratum v2 tentative**: **best-class — lock-free readers + fine-grained writers**. MVCC for readers (always see a consistent snapshot via tree root reference counting). Lock-free writers on Bε-tree message buffers where possible (novel angle #4). This is a structural advantage: Bε-tree's buffered-insert model suits CAS-based writers better than B+ tree's in-place updates do.

### 4.8 Feature richness

**Definition**: how many user-facing features (snapshots, clones, send/recv, dedup, compression, encryption, quotas, tiered storage, subvolumes, properties).

- **Maximum**: ZFS — every feature, mature implementation.
- **High**: btrfs — most features, mixed maturity.
- **High-and-growing**: bcachefs — modern design, many features, some still beta.
- **Moderate**: XFS — focused feature set, what's there is polished.
- **Minimal**: ext4 — core filesystem + crypto + quota.
- **Stratum current**: moderate — snapshots (no clones), compression, encryption, POSIX surface. No send/recv, no dedup, no tiered storage, no subvolumes.

**Stratum v2 tentative**: **high**. Target parity with ZFS on user-facing features: snapshots, clones, send/recv, content-defined dedup (novel angle #3 — a lead), compression, encryption, quotas, per-dataset properties, tiered storage (novel angle #6 — a lead). Skip: deduplication-as-background-job (online CDC makes it moot); legacy compatibility shims.

### 4.9 Implementation complexity / auditability

**Definition**: code size and reviewability. Smaller and clearer is better for correctness and security.

- **Smallest**: ext4 — ~30 KLOC. Highly audited, well-understood.
- **Small**: XFS — ~80-100 KLOC. Complex but mature.
- **Medium**: bcachefs — ~100 KLOC. Cleaner-than-btrfs design.
- **Large**: btrfs — ~150 KLOC. Infamously tangled.
- **Huge**: ZFS — ~300+ KLOC. Extremely complex; few developers understand the whole thing.
- **Stratum current**: ~20 KLOC. Highly auditable.

**Stratum v2 tentative**: **aim for ~100 KLOC at feature-parity with ZFS**. Discipline: formal specs for load-bearing invariants (novel angle #1) keep the critical paths small. Feature-rich doesn't mean code-rich if the abstractions are right. If we hit 200 KLOC we've failed — that's btrfs territory and worth asking why.

### 4.10 Security posture

**Definition**: encryption, tamper-resistance, defense against malicious-disk-access threat model.

- **Weak**: ext4, XFS, btrfs — no built-in encryption. Rely on dm-crypt layer below.
- **Moderate**: ZFS — native encryption since 2019. AES-GCM with HMAC. Classical crypto.
- **Moderate**: bcachefs — native ChaCha20-Poly1305 encryption.
- **Stratum current**: **leading**. AEAD with AD binding (ss_version=2), per-extent integrity, Argon2id passphrase KDF, PQ-ready architecture.

**Stratum v2 tentative**: **strongest by margin**. PQ-hybrid wrap keys by default (ML-KEM-768 + XChaCha20-Poly1305; novel angle #2). Per-dataset keys with inheritance. Merkle-rooted integrity for tamper evidence (novel angle #5). This is the clearest lead-by-design area.

### 4.11 On-disk format stability

**Definition**: can a volume created today still be read in 10 years without migration?

- **Best**: ext4 — decades of backward compatibility.
- **Good**: XFS — v5 stable since ~2013.
- **Good**: ZFS — pool versions; old pools readable with new code, opt-in features.
- **Moderate**: btrfs — occasional incompatible feature flags.
- **Evolving**: bcachefs — has had breaking changes; still stabilizing.
- **Stratum current**: in flux (ss_version=2); all test volumes disposable by policy.

**Stratum v2 tentative**: **stable from v2.0 onward**. Pre-v2.0 (i.e. current Phase 0 work) is throwaway. At v2.0 release: freeze the on-disk format. Use feature flags in the superblock for opt-in extensions. Commit to backward-readability for 10+ years.

### 4.12 Portability

**Definition**: what platforms can mount a volume?

- **Best**: ext4 — Linux-native, read-only elsewhere.
- **Good**: ZFS — Linux (OpenZFS), FreeBSD, illumos, macOS (experimental). License friction with mainline Linux.
- **Moderate**: XFS — Linux-native, limited elsewhere.
- **Linux-only**: btrfs, bcachefs.
- **Stratum current**: portable by design — 9P server + FUSE, so any FUSE-capable or 9P-capable client works. Tested on macOS (Darwin) and Linux.

**Stratum v2 tentative**: **remain portable**. FUSE on Linux/macOS/BSD + 9P for universal. Native kernel driver for the future OS. No lock-in to any single host.

---

### 4.13 The meta-ranking (final)

We can't optimize for everything. When two properties conflict, which wins? The committed ordering:

1. **Crash safety** — nothing matters if a power failure can corrupt the volume.
2. **Data integrity (detection + repair)** — corruption we can't find is corruption we ship to the user.
3. **Security** — encryption and tamper-evidence are non-negotiable for the target workloads.
4. **Concurrency** — a single-threaded filesystem can't be an OS root in 2026+. Bumped to max within its pairwise conflicts (lock-free readers + MVCC).
5. **Memory footprint** — OS-root means running on resource-constrained systems. Target 1 MiB allocator RAM per TiB.
6. **Feature richness** — must match ZFS/btrfs for target-user credibility.
7. **Latency** — tail-latency budget enforces that integrity costs don't become pauses (see §4.14).
8. **Throughput** — aggregate bandwidth is allowed to land at ~70% of raw device if integrity needs it. Target workloads don't saturate disk.
9. **On-disk format stability** — only starts mattering at v2.0 release.
10. **Portability** — bonus, not a constraint. FUSE + 9P costs us ~15-30% performance ceiling and some POSIX edge cases, none of which constrain the design.
11. **Implementation simplicity** — traded for verification rigor. Complexity is allowed where we can machine-check it (formal specs, fuzzers, audit loops).

### 4.14 Tail-latency budget

Throughput ranking says "70% of raw is fine." That isn't a license for tail-latency spikes. A 50ms pause during a commit is invisible as throughput loss but visible to any user expecting sub-millisecond operations.

The budget, committed at v2.0:

- **Small read p99.9 ≤ 500µs** (NVMe, cache hit or miss).
- **Small write p99.9 ≤ 2ms** (NVMe, buffered; the fsync path can be longer).
- **fsync p99.9 ≤ 10ms** (commit point; batches integrity work).
- **Scrub and background repair never visible on foreground p99.9.**

Integrity work gets amortized across many small commits, not concentrated into a few large ones. Merkle-root computation per commit is sized to the commit's tree delta, not the whole tree. Mount-time metadata verification is opt-in (`stratum mount --verify`) rather than default, to keep `mount` p99.9 reasonable; full verification happens in scrub, continuously.

## 5. Committed design choices

The decisions made during Phase 0 discussion, 2026-04-19. Each one follows from the ranking above and constrains `ARCHITECTURE.md`.

### 5.1 Complexity stance

**Maximum complexity is permitted where it can be verified.** Implementation simplicity is ranked last. The trade:

- Every load-bearing invariant gets a machine-checkable spec (TLA+ or equivalent).
- Fuzzers and property-based tests are part of the development loop, not an afterthought.
- The audit loop that proved itself on v1 (15 rounds, ~60 corruption-class fixes found) becomes a permanent part of the development cadence.
- Running detailed technical documentation in `docs/` is load-bearing — undocumented complexity is the failure mode.

This elevates formal verification (novel angle #1) from "nice to have" to load-bearing. We can only afford aggressive complexity if we can verify it.

### 5.2 Nonce model — End A + AEAD-SIV

**Transaction-group-serialized nonce allocation** (ZFS-style), combined with **nonce-misuse-resistant AEAD** (XChaCha20-SIV or AEGIS-256) as belt-and-suspenders.

- Writers parallelize up to the commit point; commit is serialized. Nonce allocation is trivial under serialization.
- Readers are fully lock-free via MVCC; concurrency story is mostly about reads anyway.
- SIV construction means that even if a bug causes nonce reuse, worst case is "these two plaintexts are equal" leakage rather than full plaintext recovery.
- No production filesystem uses AEAD-SIV. This is a concrete novel angle — replaces "PQ crypto by default" as the lead crypto story with "PQ + nonce-misuse resistant, belt and suspenders."

### 5.3 Erasure coding — Reed-Solomon + Locally Repairable Codes

**RS as the baseline** (peer with ZFS raidz), **LRC as the large-pool profile** (Azure-proven, 2-3× faster single-failure rebuild).

- RS(k, n): classical, MDS-optimal, Intel ISA-L SIMD implementation.
- LRC(k, l, r): local parity groups reduce single-failure I/O; global parity handles multi-failure.
- First open-source filesystem to offer first-class LRC.

### 5.4 Memory model — succinct structures + modest cache

**Wavelet trees / rank-select / SDArrays / xor filters** for in-RAM state representation. Modest W-TinyLFU cache (64-128 MiB) for hot metadata.

- Target: 1 MiB allocator RAM per TiB of data (1000× ZFS).
- First filesystem to use succinct data structures at the metadata-state level.

### 5.5 Plan 9 architectural inheritances

Stratum picks up the thread Plan 9's Fossil + Venti started in 2002 and carries it forward with 25 years of hindsight.

- **Venti-style CAS cold tier.** Unifies content-defined chunking + tiered storage + dedup into one coherent architecture. Hot tier is the Bε-tree; cold tier is content-addressed (BLAKE3 or SHA3-256 keyed), append-only, dedup by construction. Learned-migration model decides hot → cold.
- **Per-connection 9P namespaces.** Subvolume composition is per-connection, not global. Native multi-client isolation; containers and OS services get private namespace views without extra layers.
- **Synthetic `/ctl/` admin interface.** Administration is `cat`, `echo`, `ls`. No separate `zfs`/`btrfs` CLI with bespoke output formats. Remote admin is 9P forwarding.
- **9P-first architectural stance.** 9P is the native protocol; FUSE, future Linux kernel module, and any other transport are clients. Encryption, authentication, and multi-client support happen at the 9P boundary.
- **Factotum-style key agent.** Key management separated into a dedicated agent process. FS asks for unwraps; agent mediates access, logs, rotates, proxies to HSM/TPM/YubiKey/cloud KMS.

### 5.6 The consolidated novel-angles list

After merging the Plan 9 inheritances and the decisions above, the leading differentiators become:

1. **Formally verified sync + crash protocol.** TLA+ spec, machine-checked correctness under arbitrary write reordering.
2. **PQ-hybrid AEAD-SIV encryption.** ML-KEM-768 wrap + XChaCha20-SIV / AEGIS-256 data encryption. First FS with both PQ default and nonce-misuse-resistant AEAD.
3. **Venti-style CAS cold tier with content-defined boundaries.** Dedup + tiering + CDC in one architecture.
4. **Lock-free metadata path + MVCC readers.** Bw-tree-style lock-free Bε-tree; zero-contention reads.
5. **Merkle-rooted metadata integrity.** Tamper-evident — every offline metadata edit cryptographically detectable.
6. **Succinct in-RAM state.** Wavelet trees / rank-select / xor filters. ~1 MiB allocator RAM per TiB.
7. **io_uring-native zero-copy I/O.** Modern block device abstraction, DAX-ready.
8. **Per-connection 9P namespaces.** Plan 9's per-process-namespace model, exposed per 9P connection. Native container/service isolation.
9. **Synthetic-file administration.** All admin via `/ctl/`. No separate tool.
10. **Factotum-style key agent.** HSM/TPM/KMS-proxyable key management, separated from the FS.

Nine genuine lead positions. The plan is not to match ZFS/btrfs — it's to leapfrog them architecturally by combining a modern security stack with Plan 9's filesystem-design thread.

## 6. Non-goals

Explicit non-goals, with rationale:

- **Distributed multi-node filesystem.** That's Ceph / GlusterFS / CephFS. Stratum is a single-pool filesystem; replication via send/recv, not CAP-theorem gymnastics.
- **Object storage API.** S3-compatible interfaces are a client concern, not a filesystem concern.
- **Parallel HPC filesystem.** Lustre / GPFS / BeeGFS target millions of concurrent clients on compute clusters. Stratum targets thousands. The scaling regime is different.
- **In-kernel Linux module at v2.0.** FUSE is good enough for the target workloads. Kernel module is a post-v2.0 effort if demand justifies it.
- **Compatibility shims for existing filesystems.** No ext4 inode layout compatibility. No ZFS pool import. Stratum's format is its own.
- **Legacy POSIX quirks we can skip.** `O_TMPFILE`? Yes. `F_SEAL_*`? Yes. atime mounts by default? No — relatime at best. Partial-write semantics of `write(2)`? Honored. Obscure BSD extensions? No.
- **General-purpose defragmenter.** COW + content-defined chunking makes most defrag moot. We don't ship one.
- **Online deduplication as a background job.** Content-defined chunking gives us dedup for free at the extent layer. No separate dedup tree.

## 7. Summary claim

Stratum v2 is the COW filesystem you'd design in 2026 if you were starting from scratch with the benefit of 25 years of filesystem hindsight — ZFS's reliability bar, btrfs's feature richness, ext4's efficiency — plus **Plan 9's architectural lineage** (Fossil/Venti tiered storage, per-connection namespaces, synthetic-file administration) carried forward with **modern foundations**: formal verification, post-quantum nonce-misuse-resistant AEAD, succinct in-memory state, lock-free metadata, Merkle-rooted integrity, locally-repairable erasure coding, io_uring-native I/O.

It is not a research filesystem — it is meant to be the thing you actually use. But it uses the research.

The consolidated value proposition: **Plan 9's thread, picked back up and carried forward.**
