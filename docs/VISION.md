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

### 4.13 The meta-ranking

We can't optimize for everything. When two properties conflict, which wins? A tentative ordering, **for discussion**:

1. **Crash safety** — nothing matters if a power failure can corrupt the volume.
2. **Data integrity (detection + repair)** — corruption we can't find is corruption we ship to the user.
3. **Security** — encryption and tamper-evidence are non-negotiable for the target workloads.
4. **Concurrency** — a single-threaded filesystem can't be an OS root in 2026+.
5. **Memory footprint** — OS-root means running on resource-constrained systems.
6. **Feature richness** — must match ZFS/btrfs for target-user credibility.
7. **Throughput** — important but can be traded for the above.
8. **Latency** — ditto; optimizable after the structure is right.
9. **Implementation simplicity** — a forcing function, not a deliverable.
10. **On-disk format stability** — only starts mattering at v2.0 release.
11. **Portability** — bonus, not a constraint.

**The question for you**: is this ordering right? Specifically:
- Should *security* come before *integrity*? (I put integrity higher because an unencrypted-but-correct file is more useful than an encrypted-but-corrupt file.)
- Should *concurrency* come before *memory footprint*? (I put concurrency higher because memory can be bought; serialization is architectural.)
- Should *throughput* come before *feature richness*? (I put feature richness higher because the target users need the features; a fast filesystem without snapshots isn't a contender.)
- Is anything missing from the list?

Every downstream design decision flows from this ordering. E.g.: "should we Merkle-verify metadata on every mount or defer to background scrub?" — if integrity > throughput, mount-time verify. If throughput > integrity, background. The ordering decides.

## 5. Non-goals

Explicit non-goals, with rationale:

- **Distributed multi-node filesystem.** That's Ceph / GlusterFS / CephFS. Stratum is a single-pool filesystem; replication via send/recv, not CAP-theorem gymnastics.
- **Object storage API.** S3-compatible interfaces are a client concern, not a filesystem concern.
- **Parallel HPC filesystem.** Lustre / GPFS / BeeGFS target millions of concurrent clients on compute clusters. Stratum targets thousands. The scaling regime is different.
- **In-kernel Linux module at v2.0.** FUSE is good enough for the target workloads. Kernel module is a post-v2.0 effort if demand justifies it.
- **Compatibility shims for existing filesystems.** No ext4 inode layout compatibility. No ZFS pool import. Stratum's format is its own.
- **Legacy POSIX quirks we can skip.** `O_TMPFILE`? Yes. `F_SEAL_*`? Yes. atime mounts by default? No — relatime at best. Partial-write semantics of `write(2)`? Honored. Obscure BSD extensions? No.
- **General-purpose defragmenter.** COW + content-defined chunking makes most defrag moot. We don't ship one.
- **Online deduplication as a background job.** Content-defined chunking gives us dedup for free at the extent layer. No separate dedup tree.

## 6. Summary claim

Stratum v2 is the COW filesystem you'd design in 2026 if you were starting from scratch with the benefit of 25 years of filesystem hindsight — ZFS's reliability bar, btrfs's feature richness, ext4's efficiency, plus formal verification, post-quantum crypto, content-defined chunking, Merkle-rooted integrity, lock-free metadata, tiered storage, and io_uring-native I/O as first-class design elements rather than add-ons.

It is not a research filesystem — it's meant to be the thing you actually use. But it uses the research.

---

## Open questions for the reader

1. Is the property ranking in §4.13 right? Which swaps would you make?
2. Which workload tier (§2) is overweighted or underweighted in the ranking?
3. Is anything in §5 (non-goals) actually a goal you'd want?
4. Is anything not in §5 that you'd explicitly rule out?
