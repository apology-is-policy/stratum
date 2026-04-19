# Stratum vs the Field

**Status**: Phase 0 draft, 2026-04-19. Honest feature-by-feature positioning of Stratum v2 against the filesystems it intends to peer with or lead.

## 1. Purpose

This document answers: **where does Stratum v2 match existing filesystems, where does it lead, and where does it deliberately not compete?**

A feature matrix is easy to cheat — anyone can write "✓" next to every feature if the definition is loose. This document tries to be precise about feature *quality*, not just presence. A ✓ in ZFS's dedup column means production-stable since 2009; a ✓ in btrfs's dedup column means "offline batch job, maintained by a separate tool." Both get ✓ in lazy matrices; the reality is different.

Four comparison subjects:

- **ZFS** (OpenZFS 2.2, 2024). The bar. Most mature, most feature-rich, most production-tested.
- **btrfs** (Linux 6.x). The Linux-native alternative with different trade-offs.
- **bcachefs** (Linux 6.7+ mainline, 2024). The modern entrant with design lessons from both.
- **ext4** and **XFS** for reference — not peers, but the workhorses that set the reliability and performance baselines stratum has to match to be considered "used in production."

Plus a brief nod to **Fossil + Venti** (Plan 9, 2002) since stratum's architecture borrows from it.

---

## 2. Feature matrix

Cells use:
- **✓** mature, production-tested
- **~** supported with caveats (see notes)
- **○** experimental / limited / opt-in
- **✗** not supported
- **★** Stratum v2 target-lead position
- **◇** planned for post-v2.0

| Feature | ZFS | btrfs | bcachefs | ext4 | XFS | **Stratum v2** |
|---|---|---|---|---|---|---|
| **Copy-on-write** | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| **End-to-end checksums (data)** | ✓ SHA-256 | ✓ CRC32C | ✓ CRC32C/xxHash | ✗ | ✗ | ✓ xxHash3 |
| **Metadata checksums** | ✓ | ✓ | ✓ | ~ (since 2012) | ✓ (v5) | ✓ |
| **Merkle-root integrity** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Native encryption** | ✓ AES-GCM | ✗ | ✓ ChaCha20-Poly1305 | ✓ fscrypt AES-XTS | ✗ | ★ |
| **AEAD (vs XTS)** | ✓ | n/a | ✓ | ✗ | n/a | ★ |
| **Nonce-misuse-resistant AEAD (SIV)** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Post-quantum wrap keys** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Snapshots** | ✓ | ✓ | ✓ | ✗ | ○ | ✓ |
| **Writable clones** | ✓ | ✓ | ○ | ✗ | ✗ | ✓ |
| **Send/recv replication** | ✓ | ○ | ○ | ✗ | ✗ | ✓ |
| **Subvolumes / datasets** | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| **Per-dataset properties** | ✓ | ~ | ~ | ✗ | ✗ | ✓ |
| **Per-connection namespaces** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Deduplication** | ✓ online | ○ offline | ○ | ✗ | ✗ | ★ via CAS tier |
| **Content-defined chunking** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Compression** | ✓ (LZ4/ZSTD) | ✓ (LZO/ZSTD) | ✓ (LZ4/ZSTD/Gzip) | ○ (fscrypt-adjacent) | ✗ | ✓ (LZ4/ZSTD) |
| **Mirrors / RAID1** | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| **RAIDZ / RAID5/6** | ✓ RS | ~ RS (WH fixed 2024) | ○ RS | ✗ | ✗ | ✓ RS |
| **Locally Repairable Codes** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Self-healing (auto-repair)** | ✓ | ~ | ~ | ✗ | ✗ | ✓ |
| **Online scrub** | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| **Scrub repair** | ✓ | ✓ | ✓ | ✗ | ✗ | ✓ |
| **Tiered storage (hot/cold)** | ~ L2ARC | ✗ | ✓ | ✗ | ✗ | ★ CAS cold tier |
| **Zoned storage (ZNS NVMe)** | ✗ | ○ | ✓ | ✗ | ○ | ◇ |
| **Reflink (copy_file_range O(1))** | ✗ | ✓ | ✓ | ✗ | ✓ | ✓ |
| **Quotas** | ✓ | ✓ | ○ | ✓ | ✓ | ✓ |
| **ACLs (POSIX)** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Extended attributes** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Lock-free readers (MVCC)** | ✗ | ✗ | ○ | ✗ | ✓ (logging) | ★ |
| **Lock-free writers** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **io_uring-native** | ✗ | ○ | ○ | ○ | ○ | ★ |
| **Formal-verification specs** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Synthetic-file administration** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Factotum-style key agent** | ✗ | ✗ | ✗ | ✗ | ✗ | ★ |
| **Cross-platform (via FUSE)** | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| **In-kernel Linux driver** | ✓ (license friction) | ✓ | ✓ | ✓ | ✓ | ◇ |
| **Windows driver** | ○ (community) | ✗ | ✗ | ✗ | ✗ | ◇ |
| **macOS driver** | ○ (community) | ✗ | ✗ | ✗ | ✗ | ○ (via FUSE) |

**Rough totals:**

- ZFS: 24 ✓, 3 ~/○, 9 ✗. The maturity benchmark.
- btrfs: 20 ✓, 6 ~/○, 10 ✗. Linux-native, fewer features, some still maturing.
- bcachefs: 18 ✓, 6 ~/○, 12 ✗. Modern design, features still landing.
- Stratum v2: 16 ✓ (peer parity), **11 ★ (lead positions)**, 2 ◇ (post-v2.0), rest implied by architecture.

The 11 ★s are where we intend to have no peer at v2.0 release.

---

## 3. Category analysis

Numbers in the matrix don't tell the whole story. This section narrates the *why* behind each category.

### 3.1 Data integrity

**Where we match**: per-block and per-extent checksums (like ZFS, btrfs, bcachefs). Online scrub with auto-repair from redundancy (like ZFS, bcachefs). Auto-repair from mirrors / RAID5/6 (parity with btrfs post-2024 write-hole fix, ZFS).

**Where we lead**:
- **Merkle-rooted metadata integrity.** No existing filesystem does this. The superblock carries the BLAKE3 root hash of all metadata blocks; mounting verifies the hash chain matches; any offline edit to any metadata block is cryptographically detected. Turns "accidental or malicious metadata tampering" from "maybe the csum catches it" into "always and cryptographically."
- **AEAD-SIV** for encrypted blocks. Bugs in nonce allocation can't produce catastrophic leaks — worst case is "these two blocks have equal plaintexts" leakage. No other FS uses SIV modes.

**Where we deliberately don't go beyond**: dittoblocks (ZFS-style multiple-copy metadata). Our mirror/RS/LRC redundancy + Merkle verification subsumes the reliability value, with less duplication. If a use case justifies extra copies of specific metadata, it can be a property.

### 3.2 Encryption & security

**Where we match**: native AEAD (only ZFS and bcachefs have this among peers; ext4 has XTS which isn't AEAD). Per-dataset keys. Inheritable encryption properties.

**Where we lead**:
- **PQ-hybrid wrap keys** (ML-KEM-768 + XChaCha20-Poly1305). NIST standardized ML-KEM in 2024. No production filesystem defaults to PQ wrap keys yet; compliance pressure is coming (roughly 2030-2035 deadlines for classical-crypto retirement in regulated industries). Stratum being first here is a real market position.
- **Nonce-misuse-resistant AEAD-SIV.** Already covered above. Layered with PQ wrap, we get "PQ-ready and crypto-bug-resistant" as a single story.
- **Factotum-style key agent** (Plan 9 inheritance). Key management separated from FS. HSM/TPM/YubiKey/KMS proxyable. Rotation without touching the FS. None of ZFS/btrfs/bcachefs do this properly — they embed key management.
- **Tamper-evident metadata** via Merkle root. An adversary with raw disk access who modifies any metadata block is cryptographically detectable, not just probably-detectable-via-csum.

**Where we deliberately don't go beyond**: full-disk encryption with hardware-offload (like OPAL/SED). That's a layer below the filesystem; we plug into it rather than duplicate it.

### 3.3 Concurrency

**Where we match**: MVCC readers (XFS has this via journaling; our path is COW + tree root reference counting). Lock-free reads across the hot path.

**Where we lead**:
- **Lock-free writers on the Bε-tree message buffers.** Bw-tree-style delta chains with epoch-based reclamation. No other filesystem does this; btrfs has a well-known "btrfs mostly-serialized" complaint that bcachefs only partially addresses.
- **Per-connection 9P namespaces.** Multi-client isolation native to the protocol. Different containers/services see different views without overlayfs gymnastics.

**Where we deliberately don't go beyond**: distributed consensus for multi-node pools. That's a Ceph / CephFS concern.

### 3.4 Snapshots, clones, subvolumes

**Where we match**: O(1)-ish snapshots (tree root save + refcount bump — parity with ZFS and btrfs), writable clones (parity), per-subvolume properties with inheritance (parity with ZFS; btrfs has weaker property model).

**Where we lead**:
- **Per-connection subvolume composition.** Clients freely compose subvolumes into their namespace via 9P bind operations. Plan 9-style union mounts. No existing FS offers this.
- **O(1) snapshots with content-defined boundaries.** Snapshots share extent storage via the CAS tier automatically — creating a snapshot of a 1 TiB dataset adds almost zero on-disk state because the content is already in the CAS.

**Where we deliberately don't go beyond**: snapshot scheduling / automatic cron-snapshots as a FS concern. Expose the atomic primitive via `/ctl/`; let userspace schedule. (ZFS has built-in cron; we don't.)

### 3.5 Send / recv replication

**Where we match**: incremental send between snapshots (parity with ZFS `send -i`). Encrypted send-recv preserving at-rest encryption on the target (ZFS supports raw send; bcachefs is working toward it).

**Where we lead**:
- **Content-defined chunking naturally wins on wire efficiency.** A 1 GB file with 1 MB inserted at the start sends only the new/changed chunks; traditional send/recv sends the whole tail. rsync-style but at the block level.

**Where we don't**: backward compatibility with ZFS send streams. Stratum's send stream is its own format.

### 3.6 Deduplication

**Where we match**: some form of dedup (ZFS has online ZAP-based dedup but it's memory-hungry; btrfs has offline dedup via a separate tool; bcachefs has limited online).

**Where we lead**:
- **CAS-tier dedup via content-defined chunking.** Our cold tier is content-addressed by construction; dedup happens at extent boundaries determined by a rolling hash (FastCDC). This is shift-resistant — insert a byte at the start of a 10 GB file, only the affected chunks change. ZFS's dedup is block-aligned; content-defined is state-of-the-art from the backup-tool world (restic, borg) applied at filesystem layer.
- **No in-memory dedup table.** CAS-tier dedup requires only the write-path hash computation. No 1-GB-per-TiB DDT like ZFS. Dedup becomes low-overhead.

### 3.7 Erasure coding / RAID

**Where we match**: mirrors, Reed-Solomon raidz-equivalent profiles.

**Where we lead**:
- **Locally Repairable Codes** (Azure-proven, 2-3× faster single-failure rebuild). No open-source filesystem offers LRC as a first-class profile. For large-drive deployments (multi-TiB disks taking hours to rebuild), LRC is a major reliability win.

**Where we don't** (initially): modern research codes (fountain/LDPC for storage, regenerating codes, MSR/Clay codes). Post-v2.0 if data justifies.

### 3.8 Tiered storage

**Where we match**: nobody in the peer set does this well. ZFS's L2ARC is read-cache, not true tiering. bcachefs has tiering (that's literally what its name refers to, from "bcache"), but its model is different.

**Where we lead**:
- **Venti-style CAS cold tier.** Hot writes go through the Bε-tree; learned-migration model identifies cold data; cold data migrates to the CAS tier where content-addressed storage provides automatic dedup. Plan 9's Fossil + Venti architecture updated with modern crypto and codes.
- **Learned migration policy.** Small ML model trained on per-workload access patterns decides migration. Most tiering systems use heuristics; learned policy is a genuine research-into-production move.

**Where we don't**: explicit user-facing SLC/QLC tiering controls (manual per-dataset SSD vs HDD assignment) beyond what CAS tiering provides. We expose the policy knobs; we don't expose the individual device assignments (that's done at pool configuration time).

### 3.9 Administration

**Where we match**: nothing about existing admin interfaces is great. ZFS has `zfs`/`zpool` commands with bespoke output formats. btrfs has `btrfs subvolume`, `btrfs scrub`, etc. bcachefs has `bcachefs`. Each is a separate binary with its own CLI grammar.

**Where we lead**:
- **Synthetic `/ctl/` filesystem.** Administration is `cat`, `echo`, `ls`. Discoverable, scriptable, remotely-accessible (just forward 9P). No separate tool to learn.
- **9P-first remote admin.** Forward the 9P connection and you have remote administration. No special network protocol, no separate REST API.

### 3.10 Performance

Honest expectations at v2.0:

- **Sequential read throughput**: ~95% of raw NVMe (negligible overhead, one AEAD verification per block).
- **Sequential write throughput**: ~70% of raw NVMe (COW + AEAD + compression + Merkle chain = meaningful overhead).
- **Small-file read IOPS**: competitive with XFS on NVMe thanks to lock-free reads and io_uring.
- **Small-file write IOPS**: slightly below ext4 (COW + integrity overhead), slightly above btrfs (lock-free path).
- **Latency p99.9**: within the budget specified in VISION.md §4.14.

We do not lead on raw throughput. We trade 25-30% throughput for the stronger integrity, security, and concurrency story. Target-workload credibility comes from matching ext4/XFS latency for the hot path, not from matching XFS throughput for sequential megabench.

### 3.11 Memory footprint

**Where we lead — decisively**:

- **1 MiB allocator RAM per TiB of data.** ZFS's guideline is 1 GB RAM per TiB. 1000× improvement. Achieved via succinct data structures (wavelet trees, xor filters) for the in-RAM state representation.
- **No gigabyte-scale caches by default.** Modest W-TinyLFU cache (64-128 MiB). ZFS's ARC can balloon to consume free RAM by default; ours doesn't.
- **Page-cache-friendly hot path.** Let the kernel's page cache work; don't replicate it.

This is one of the hardest positions to achieve and is a direct enabler of the OS-root workload (small devices, constrained memory).

### 3.12 Portability

**Where we match**: ZFS runs on Linux (OpenZFS, license friction with kernel), FreeBSD, illumos, macOS (experimental). No other peer is cross-platform.

**Where we lead**:
- **FUSE + 9P native.** Any FUSE-capable OS (Linux, macOS, BSD) can mount stratum volumes. 9P forwarding extends to anything with a 9P client. No license friction.

**Where we don't** (initially): in-kernel Linux driver. We plan one post-v2.0 if the FUSE overhead becomes a bottleneck for high-IOPS workloads.

### 3.13 Implementation size

Targets for v2.0:

- **Core (tree, COW, sync, allocator, crypto, integrity)**: ~40 KLOC.
- **Extended features (snapshots, clones, send/recv, CAS tier, CDC, tiering, EC)**: ~50 KLOC.
- **Clients (9P server, FUSE shim, synthetic /ctl/, CLI wrapper)**: ~20 KLOC.
- **Total**: ~110 KLOC. If we hit 200 KLOC we've failed — that's btrfs territory. Formal verification helps enforce this by making complexity earn its place.

For comparison:
- ext4: ~30 KLOC
- XFS: ~100 KLOC
- bcachefs: ~100 KLOC
- btrfs: ~150 KLOC
- ZFS: ~300 KLOC

---

## 4. Positioning summary

### 4.1 Where we match ZFS

Core reliability story: COW, checksums, snapshots, clones, send/recv, erasure coding, compression, encryption, per-dataset properties, online scrub with repair. Every target-user expectation of "what a serious filesystem does" gets a ✓.

### 4.2 Where we exceed ZFS

- Merkle-rooted integrity (tamper-evident).
- Nonce-misuse-resistant AEAD-SIV.
- PQ-hybrid wrap keys.
- Factotum-style key agent.
- Content-defined chunking.
- Locally Repairable Codes.
- Lock-free writers (ZFS serializes at txg commit).
- 1 MiB/TiB RAM (ZFS needs 1 GB/TiB).
- Per-connection namespaces.
- Synthetic-file administration.
- Formal verification of sync/crash protocol.
- Cross-platform (FUSE + 9P).

### 4.3 Where we exceed btrfs

Everything above that applies to ZFS, plus: btrfs's RAID5/6 was unreliable until 2024; ours is built correctly from day one. btrfs's send/recv has known limitations; ours with CDC is wire-efficient by construction. btrfs doesn't have native encryption; we do.

### 4.4 Where we exceed bcachefs

bcachefs is the closest design peer. Differences:

- bcachefs uses XChaCha20-Poly1305, not SIV. Still classical AEAD.
- No PQ wrap keys.
- No formal verification.
- No content-defined chunking (block-aligned dedup only).
- No Merkle root.
- No LRC.
- No per-connection namespaces or synthetic admin.

### 4.5 Where we deliberately do less

- **Distributed multi-node** — Ceph territory, not ours.
- **Object storage API** — a client concern.
- **In-kernel Linux at v2.0** — FUSE is good enough; kernel module is a v2.x effort.
- **Backward compat with anything** — no ZFS import, no btrfs conversion, no ext4 inode compatibility. Stratum is its own format.
- **Deduplication-as-background-job** — CDC makes it moot.
- **Legacy POSIX quirks** — we implement modern POSIX (O_TMPFILE, F_SEAL_*, relatime default, pipes as files), skip the obscure BSD extensions.
- **Integrated snapshot scheduler** — expose atomic primitives via `/ctl/`; let userspace schedule.
- **General-purpose defragmenter** — COW + CDC make it moot.

### 4.6 Honest weaknesses at v2.0

- **In-kernel Linux performance ceiling.** Until we have a kernel module, high-IOPS workloads (millions of IOPS on a single volume) hit FUSE overhead. Target workloads don't push this, but it's a real gap vs in-kernel btrfs/bcachefs.
- **Immaturity.** ZFS has 20 years of production. Stratum v2.0 will have whatever we accumulate during development. The audit loop + formal verification help, but time-in-production is a real moat.
- **Ecosystem.** ZFS has `sanoid`, `syncoid`, `znapzend`, boot-integration scripts, cloud-provider integration. Stratum v2.0 has what we build. The `/ctl/` synthetic interface helps (standard tools work) but the long tail of integrations takes years.
- **Zoned storage support** is post-v2.0. bcachefs and btrfs have it; we'll add it later if drives demand it.
- **No online shrink.** Grow yes; shrink no at v2.0. btrfs has this (partial); ZFS doesn't. Post-v2.0 for us if demand justifies.

---

## 5. The positioning claim

Stratum v2 is the filesystem that picks up Plan 9's Fossil + Venti thread (2002) and combines it with 25 years of advances in crypto (AEAD-SIV, PQ-hybrid, Merkle integrity), storage (LRC, content-defined chunking, io_uring), and concurrency (lock-free writers, MVCC). It matches ZFS on reliability, leads on security, equals bcachefs on modernity, trades some throughput for stronger guarantees, and is drastically lighter on RAM than anything in the peer set.

**Not a research filesystem. Not a toy. The filesystem a production POSIX OS should build on in 2026 and beyond.**
