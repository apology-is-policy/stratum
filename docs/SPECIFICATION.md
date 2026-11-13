# Stratum: Technical Specification

Stratum is a copy-on-write filesystem written in C17, with encryption and integrity built into its
format. It runs in user space and serves POSIX-shaped files over 9P2000.L. A single Rust binary,
`stratum`, packages it with a dual-pane file manager, so a Stratum volume can also be used as an
encrypted container file.

This document is for a technical reader who wants to know what Stratum does, how, what it costs,
and how it compares with established copy-on-write filesystems. It describes the code as it stands
and says plainly where the code stops short.

**Tree described:** on-disk format version 33. The filesystem code is the code of commit `471a339`.
Facts were taken from the source, not from older design prose. The older documents in this
repository (`ARCHITECTURE.md`, `ROADMAP.md`, parts of `reference/`) contain intentions and stale
statements; where they disagree with this document, this document was checked against the code.

**How to read a status.** Stratum has a large library layer and a smaller operator surface, so
"implemented" alone would mislead. This document uses four words:

| Status | Meaning |
|---|---|
| **Available** | Implemented and tested, and reachable by an operator through `stratumd`, 9P, `/ctl` or the `stratum` binary |
| **Library** | Implemented and tested as a C API, with no operator path yet |
| **Partial** | Works with the limits stated beside it |
| **Absent** | Not implemented. A design may exist in the older documents |

**How to read a claim.** Limits and behaviour marked *by reading* were established by reading the
code and were not demonstrated by running it. Numbers marked *derived* are arithmetic from constants
in the code, not measurements.

---

## 1. Summary

**What is unusual about Stratum:**

- **Encryption is the format, not an option.** There is no unencrypted mode. Every data extent and
  every metadata tree node except two small plaintext structures is sealed with AEGIS-256, using a
  32-byte authentication tag. Names, sizes, owners, the shape of the trees and the extent maps are
  not visible to someone holding only the disk.
- **Integrity and encryption compose.** Parent pointers carry a BLAKE3 hash of the child's
  ciphertext, forming a Merkle tree over metadata. Deferred frees and per-node generations exist so
  that an AEAD nonce does not repeat within one history.
- **Hybrid post-quantum key wrap.** X25519 and ML-KEM-768 through HKDF-SHA256, when built with liboqs.
- **A metadata engine that mixes three ideas.** A copy-on-write B+tree on disk, B-epsilon messages in
  internal nodes, and a CAS-prepended delta chain on the root in memory, reclaimed by epochs.
- **Formal modelling.** 43 TLA+ specifications with 135 deliberately broken configurations that must
  fail. Each records a bug class the model can catch.
- **Adversarial audit history.** Audit rounds numbered to R177, then per-chunk rounds, with 145 commits
  closing an audit.

**What it is not yet:**

- Not a production filesystem. The format is not frozen: until it is, a new version refuses older pools, with no
  upgrade path. There is no filesystem checker.
- Its own CI is not green. See section 15.
- Single device in every shipped path. No redundancy for metadata, no compression, no intent log.
- Metadata is capped at about 7 GiB per pool, and the size is fixed at format time.
- Several features exist only as library calls: clones, send and receive, cold tiering and dedup,
  multi-device pools, and key rotation. A background scrub does not actually run. See section 16.

---

## 2. Status at a glance

| Feature | Status | Limits |
|---|---|---|
| Copy-on-write with atomic commit | Available | Whole-pool commit; two device barriers per commit |
| AEAD encryption of data and metadata | Available | AEGIS-256 fixed; no cipher choice |
| Merkle-chained metadata | Available | Stops at the extent record; root is unkeyed (section 8) |
| Snapshots, readable through `.snaps` | Available | A dead list holds 256 entries, past which space leaks (section 10) |
| Rollback | Available | Destroys newer snapshots, as ZFS does |
| Snapshot holds | Available | Holds are lost on a crash if not yet committed |
| Reflink | Available | Whole file, same dataset, empty destination |
| Hard links, xattrs | Available | Xattr value at most 64 KiB |
| Symlinks | Partial | Target at most 100 bytes |
| Advisory locks | Partial | Non-blocking only, in RAM, no deadlock detection |
| fallocate | Partial | Reserves no space; punches whole extents only |
| 9P2000.L server with extensions | Available | Unix sockets only |
| `/ctl` administrative tree, Prometheus metrics | Available | |
| File manager and encrypted containers (`stratum`) | Partial | See section 14 |
| Clones | Library | Depth 1; cannot be destroyed; promote is a stub |
| Send and receive | Library | Plaintext stream; extents only, no names or metadata |
| Cold tier, content-defined chunking, dedup | Library | Offline only, never on hot writes |
| Multi-device, mirror, device replace | Library | Metadata on device 0 only |
| Dataset key rotation | Library | Pool key and wrap key cannot rotate |
| File seals, file handles, `O_TMPFILE`, `EXCHANGE`, `WHITEOUT` | Library | No 9P operation reaches them |
| Scrub | Partial | State machine and verbs exist; nothing drives it in a running daemon |
| Compression | Absent | Format reserves a byte; decoder refuses non-zero |
| ACLs, quotas, device nodes, FIFOs, sockets | Absent | Quota is a stored property that nothing enforces |
| Reed-Solomon, LRC | Absent | Refused at create |
| FUSE, kernel module, TCP listener | Absent | Linux can mount over v9fs; no test drives that here |
| fsck | Absent | |

---

## 3. On-disk layout

### 3.1 Device layout

```
+---------+---------+--------+----------------+-------------------------+---------+---------+
| Label 0 | Label 1 | margin | bootstrap pool |        data area        | Label 2 | Label 3 |
| 256 KiB | 256 KiB | 512 KiB| at 1 MiB       |                         | 256 KiB | 256 KiB |
+---------+---------+--------+----------------+-------------------------+---------+---------+
```

The minimum device is 8 MiB. The block size is fixed at 4 KiB.

### 3.2 Uberblocks

There is no separate superblock. The root of the filesystem is a 4 KiB **uberblock**, little-endian,
with magic `STRATUM2` and a BLAKE3-256 self-checksum.

- Each label holds 63 ring slots. Generation `g` goes to label `g % 4`, slot `g % 63`, which gives 252
  positions. A commit spends two generations, so a device retains about 126 commits of history
  (*derived*).
- One uberblock goes to one slot per device per generation. Redundancy comes from history and from
  other devices, not from writing one generation to all four labels.
- Mount scans every slot and takes the highest valid generation per device. Across devices, the
  authoritative generation is the quorum-th highest, with quorum `floor(live / 2) + 1` and a check that
  a quorum of devices at that generation hold identical content.
- A read-write mount writes a claim uberblock at `auth + 1`, so generations used by orphaned writes
  are never reused.

The uberblock carries the roots of the dataset index, the allocator roots, the snapshot index, the CAS
index, the key schema and the repair log. Per-dataset tree roots live in the dataset index.

### 3.3 Addresses

A physical address is 64 bits: 16 bits of device id and 48 bits of block offset. The format has room
for 65,536 device ids, the roster enforces 64 per pool, and a device can be 1 EiB (*derived*).

A block pointer (`stm_bptr`) is 64 bytes: address, kind, flags, a 32-byte checksum, and 16 further
bytes of which the engine uses 8 for the child's birth generation. The birth generation is an input to
the child's AEAD nonce, which is why the parent must hold it.

### 3.4 The bootstrap pool

All metadata lives in a dedicated region of device 0, the **bootstrap pool**, allocated in 16 KiB
nodes. File data lives in the data area, which has its own allocator.

- A bitmap of 14 blocks gives 458,752 bits, one per node, so the pool holds **7 GiB of metadata at
  most**. Past that, format returns `STM_ENOTSUPPORTED`.
- Header and bitmap exist in two slots, A and B, written alternately and selected by a checksummed
  generation.
- The size is **fixed at format and cannot grow**. `stratum mkfs` picks device/16, clamped to 8-256 MiB,
  and `--bootstrap` overrides it. The library default is `max(64 MiB, device/1024)`; with it, a device
  of about 7 TiB or more fails at format unless a size is passed (*derived*).

### 3.5 Trees

| Tree | Root held in | Store | Key | Value |
|---|---|---|---|---|
| Per-dataset metadata | Dataset entry | Engine | Tag byte + body | Inode, dirent, xattr or extent |
| Per-snapshot metadata | Snapshot entry | Engine (the captured root) | Same | Same |
| Dataset index | Uberblock | Whole-tree | 8-byte id | Entry with name, properties, root triple |
| Snapshot index | Uberblock | Whole-tree | 8-byte id | Record with name and inline dead lists |
| Allocator, per device | Allocator roots | Whole-tree | Big-endian start block | Length, refcount; refcount 0 is pending free |
| Allocator roots | Uberblock | Whole-tree | Device id | Root, hash, generation |
| CAS index | Uberblock | Whole-tree | 32-byte BLAKE3 | Replicas, refcount, length, generation |
| Key schema | Uberblock | Single plaintext leaf | Dataset id, key id | State, wrapper, wrapped key |
| Repair log | Uberblock | Single plaintext leaf | Sequence id | 32-byte repair record |

There are two stores, and the difference is the most important structural fact about Stratum today:

- **The engine** (`src/btree_engine`) writes 16 KiB nodes, copies only dirty paths, and has no size limit
  of its own. It holds everything that scales with file count: inodes, dirents, xattrs and extents, all in
  one tree per dataset, separated by a tag byte in the key.
- **The whole-tree store** (`src/btree_store`) is an older design. It writes 128 KiB nodes, at most two
  levels deep, and rewrites the whole tree on every commit where that tree is dirty. It still holds the
  allocator, which grows with the number of extents.

Moving the remaining trees onto the engine has been decided and is the next structural change. See
section 16.

### 3.6 Key records

**Inode, 256 bytes:** id, dataset, generation, mode, uid, gid, nlink, four timestamps with nanoseconds,
size, kind, flags, change version, and 100 bytes of inline storage used for small files and symlink
targets. `(ino, gen)` is unique over time: a freed inode number is reused with a bumped generation.

**Dirent:** key `tag, dir_ino, hash_probe`, where the hash is 64-bit FNV-1a plus an open-addressing probe
of at most 64. Value: child inode, generation, type, name of at most 255 bytes. A removal leaves a
tombstone so probe chains stay intact.

**Extent, 108 bytes:** kind (hot or cold), up to 4 replica addresses or a content hash, write generation,
length, key id, the origin dataset, inode and offset used as AEAD associated data, and link generation.

**Spill:** an engine value above the inline bound (5,408 bytes per entry) moves to a chain of 16 KiB
blocks, at most 1 MiB per value.

---

## 4. The metadata engine

### 4.1 What it is

On disk the engine is a **copy-on-write B+tree** whose internal nodes may carry **B-epsilon messages**. In
memory it adds one **CAS-prepended delta chain, on the root only**. A mutation travels from the root's
chain into the root's message buffer, down one level per size-triggered flush, and finally into a leaf.

- **Node:** 16 KiB. A 128-byte header, a 16,224-byte payload, and a trailing 32-byte AEAD tag.
- **Fanout:** about 143 to 158 children per internal node (*derived*). Epsilon is 1/4: pivots and children
  may use 3/4 of the payload, and the buffer 1/4.
- **Leaves:** about 59 inodes or 120 extents.
- **Consolidation:** a writer that leaves the chain 8 deltas deep tries, inline and only if the locks are free,
  to fold it into a fresh root.
- **Splits:** byte-balanced. There is no rightmost optimisation, so ascending inserts leave leaves half full.
- **Delete:** without merge. Nodes are never merged or removed, so a tree's node count and height never fall.
  Dirents, xattrs and inodes use tombstones and flags above the engine; only extents delete keys structurally.
- **No node eviction.** A tree's resident nodes stay in memory until its engine closes.

### 4.2 Trade-offs against the peers (analysis)

| Design | What Stratum gains | What Stratum pays |
|---|---|---|
| btrfs: path-COW B-trees, 16 KiB nodes, fsync log tree, extent tree | A small commit can dirty only the root rather than a whole path. No reader tree locks in the engine. Every node AEAD-sealed with a Merkle parent link | No log tree, so fsync is a pool commit. Allocator rewritten whole rather than an incremental extent tree. No merge |
| ZFS: indirect block trees, transaction groups, ZIL, space maps, ARC | One keyed, uniformly encrypted tree; nothing is left in plaintext for dedup tables or file sizes | No ZIL. No metaslabs: reserve is a first-fit scan. No ARC, so memory grows with touched metadata. Mount is a walk of all metadata. No cross-device metadata copies |
| bcachefs: log-structured 128-256 KiB nodes, one ordered journal, six-locks | Nothing to replay; one commit point; no reader tree locks | No cheap durable log path; whole nodes are rewritten at commit |
| Bw-tree: mapping table, per-page chains | Far less machinery, no log-structured store, ordinary COW on disk | One chain means one contention point. A seal briefly blocks writers, so it is not lock-free in the formal sense |
| B-epsilon trees: BetrFS, TokuDB | Buffered inserts with ordinary COW | Epsilon of 1/4 in 16 KiB nodes batches shallowly. A flush delivers the whole buffer rather than the heaviest child. Measured benefit is 1.0-2.0x node writes, far below the literature's order of magnitude and below this project's own 20-50x target |

The fair summary: Stratum's payoff is one atomic commit step, nothing to replay, and integrity by
construction. Its bill is commit latency and memory that scale beyond the dirty set.

---

## 5. Concurrency

### 5.1 What is genuinely lockless

At the engine API, these claims hold:

- **Lookup** (`stm_btree_engine_lookup_concurrent`) on a published, resident, unsealed tree takes no mutex and
  performs no CAS. Its loops are bounded by tree depth and by chain and buffer length. This is the wait-free
  fast path. An operation can leave it: a sealed chain restarts, a cold child reads the device, and a Merkle
  failure after a publish restarts, because a pinned reader can see a reused address and the hash catches it.
- **Insert and delete** (`stm_btree_engine_insert_concurrent`) are a CAS prepend. Among writers this is lock-free
  while the root is not sealed. A seal is lock-like: prependers wait for the sealer, up to a bound, then get
  `STM_EBUSY`.
- **Memory reclamation** is epoch-based. Entering and leaving an epoch is wait-free. Retiring is lock-free apart
  from `malloc`.
- **A published tree is immutable** except for its chain head and cold child links. A commit swaps in a private
  shadow copy and retires the old tree through the epochs.

### 5.2 What is not, at the filesystem level

These are the costs an honest reader must weigh against the section above. They were established by reading the
code. The size of each stall has not been measured.

- **Reads take a mutex.** Every metadata read resolves its engine through the per-pool dataset index mutex, three
  times per lookup, and a commit holds that mutex through each dataset's flush, including its device writes. So
  metadata reads wait during that phase of a commit. "Wait-free metadata reads" would be false as a filesystem claim.
- **Writers serialize.** A buffered write holds a shared global lock, a per-inode lock, the inode index mutex, the
  dataset index mutex and a global dirty-buffer mutex. Writers on different inodes contend on those mutexes.
- **All prepends hit one word**, the root's chain head. There are no per-subtree chains.
- **A commit excludes writers and extent data reads.** It takes `fs->global` exclusively across the dirty-buffer
  drain and the commit. Lockless metadata reads continue until they meet the dataset mutex.
- **One stalled reader stops all reclamation.** Epoch state is process-wide, and a cold descent holds its pin
  across device I/O.
- **Isolation is memory safety, not transactions.** Readers see the newest acknowledged state, including uncommitted
  deltas. A scan can straddle roots. Point-in-time views are snapshots, a separate mechanism.

An accurate one-line description: *metadata readers take no filesystem-wide lock and no engine lock on the common
path; they pin an epoch and take a brief per-pool mutex to resolve the tree. Writers prepend to the tree with a CAS
under per-inode and per-index locks. A commit excludes writers.*

### 5.3 Modelled and not modelled

The delta chain and epochs (`concurrency`), root publish and retire (`concurrency_mvcc`), the message buffer
(`bepsilon`) and the engine's commit (`btree`) have TLA+ models. These have **none**, and rest on audits, tests and
prose: seal and tombstone sentinels, cold CAS links, mini-consolidation, engine splits, spill chains, and the
dataset mutex read path.

---

## 6. Commit and crash consistency

### 6.1 The commit

A commit proceeds in this order:

1. Arm barrier deferral on each device, so `fsync` inside the commit only sets a flag.
2. Commit the key schema, sweep the CAS, and commit each device's allocator and the allocator roots.
3. Flush every dataset engine: deep-clone the resident tree, fold the chain, write dirty nodes bottom-up.
4. Commit the dataset index, snapshot index, repair log and CAS index.
5. Compute the pool Merkle root and build the final uberblock. If it is content-identical to the last durable one,
   finish without writing anything.
6. Write the **reservation uberblock**, which holds the old roots at a new generation.
7. Stage one copy-on-write of the bootstrap bitmap and header.
8. **First barrier:** one real flush per device.
9. Write the **final uberblock** with a real fsync, to a quorum. **This is the commit point.**
10. Finalize engines: publish the new tree, and defer-free superseded nodes.

That is two durability barriers per device per non-clean commit.

### 6.2 Crash states

| Crash | Result at mount |
|---|---|
| Before the first barrier | New nodes are unreferenced; a torn bootstrap slot fails its checksum and the other is used. Prior state |
| Between the barriers | The reservation uberblock may be newest; it holds the old roots. Prior state |
| Torn final uberblock | Its checksum fails and the scan skips it. Prior state |
| After the final uberblock | New state. Superseded nodes leak until the mount's sweep |

**There is no journal or intent log.** Everything since the last commit is lost in a crash: chains, buffers and the
dirty buffer.

Any failed commit wedges the filesystem, one way, until remount. A commit that fails cannot be retried in place.

### 6.3 Mount

Mount loads the allocator into RAM, writes its claim uberblock, and then runs a **mark-sweep across all metadata**:
every tree of every dataset and every snapshot is read, Merkle-checked and decrypted, to reclaim nodes orphaned by a
crash. This is what makes crash recovery simple, and it makes mount **O(all metadata nodes)**. Shared subtrees are
read again per snapshot; there is no deduplication of the walk.

### 6.4 When data becomes durable

- `fsync` is a **whole-pool commit**. `datasync` is ignored, and there is no per-file path.
- `O_SYNC` and `O_DSYNC` are defined and not consulted.
- Writes below 1 MiB go to a dirty buffer in RAM (8 MiB per inode, 256 MiB overall); larger writes go to the device
  directly. Neither is durable until a commit.
- *By reading*, **there is no periodic commit.** Commits happen on `fsync`, `Tsync`, snapshot, rollback, unmount and
  space pressure. Data written with no later `fsync` is lost in a crash however old it is. ZFS and btrfs commit every few
  seconds by default.

### 6.5 Cost of a commit

| Work | Scale |
|---|---|
| Engine node writes, spill rewrites | O(dirty) |
| Deep clone of every open engine's resident tree | O(resident), in RAM, every commit, even clean |
| Allocator, allocator roots, dataset index, snapshot index, CAS index | O(all records in that tree), when dirty |
| Key schema, repair log | One 128 KiB leaf, when dirty |
| Allocator statistics | O(allocator entries), in RAM, at least twice per commit |

A minimal metadata commit writes about 212 KiB (*derived*): two uberblocks, the bootstrap copy, the dataset index and
one engine node. A data write adds at least 256 KiB for the allocator and its roots.

---

## 7. Space allocation

**Data area.** The truth is an in-memory tree under one reader-writer lock, keyed by start block. Reserve is a **first-fit
scan from the start of the device**, with a minimum of 2 blocks to avoid unusable gaps. There is no equivalent of ZFS
metaslabs or btrfs block groups.

**Elias-Fano and xor filters** sit over the allocator's start blocks: a compressed sorted set and an xor8 filter with
about 0.4% false positives. They are worth noting because they are unusual, and they are narrower than they sound: they
accelerate **lookup and containment queries only**, never free-space search. They are rebuilt lazily after any reserve.

**Deferred frees.** A free keeps its entry at refcount 0, and a later commit deletes it. Generations step by 2, so a block
freed at generation `T` can be reused at `T + 2`. This is what keeps `(address, generation)`, and so the AEAD nonce, unique
within one history.

**Bootstrap pool.** A bitmap with a roving cursor. Frees go on a pending list held in RAM, returned at a commit's stage, or
early when a reserve finds nothing else, gated by the epochs and forced after 50 ms. A reader that meets a rewritten node
heals through the Merkle gate.

**A known weakness: free metadata space fragments.** Whole-tree stores need 8 adjacent 16 KiB nodes, while engine nodes take
one at a time, and a snapshot delete returns scattered singles. In a Python model of a 256 GiB pool, writers therefore stop
again soon after a delete with about a quarter of metadata space free but unusable: 1117, 733, 163 and 99 commits per cycle,
stopping at 6, 6, 23 and 25% free. That model has not been confirmed on the real code. Moving the trees to the engine
removes the cause, because nothing will need adjacent nodes (section 16).

---

## 8. Integrity

### 8.1 Coverage

| Object | Checked by |
|---|---|
| Uberblock | BLAKE3-256 self-checksum |
| Bootstrap header and bitmap | BLAKE3 self-checksums |
| Encrypted metadata node | BLAKE3-256 of the ciphertext, held in the parent; AEAD tag in the node |
| Key schema, repair log | BLAKE3 self-checksum, recorded in the uberblock |
| Data extent | AEAD tag only |

The **pool Merkle root** is BLAKE3-256 over the csums of the six live root trees, four retired zero slots and a public salt,
stored in the uberblock.

The chain runs from the uberblock through the dataset index, each dataset's root triple, and every engine node and spill
chain. Snapshots hold their own root triples under the snapshot index. **It stops at the extent record.** The record
authenticates the addresses, generation, key id and origin; the content is covered by the AEAD tag, not by a hash in the
chain.

### 8.2 When it is checked

The uberblock at decode, the root at mount, each node on device read, and each extent on read. A mismatch returns
`STM_ECORRUPT` or `STM_EBADTAG`, which reach a 9P client as `EIO`. Nothing rewrites on read.

### 8.3 What the Merkle root does and does not give

The uberblock checksum and the Merkle root are **unkeyed** and the salt is public. They detect corruption and partial tampering.
They do not authenticate: someone able to write the disk can recompute them. **Real authentication comes from the AEAD keys** on
encrypted trees and data.

The contrast with peers is real but specific: btrfs's parent pointers hold a generation and no child checksum, so its node graph
is not a Merkle tree; ZFS and bcachefs do store child checksums in the parent. Stratum's distinctive part is that this chain runs
over ciphertext in a filesystem with no plaintext metadata trees, rather than the chain itself.

---

## 9. Encryption

### 9.1 Primitives

| Purpose | Primitive | Parameters |
|---|---|---|
| Metadata nodes, data extents, CAS chunks | AEGIS-256 (libsodium 1.0.19 or later) | 32-byte key, 32-byte nonce, 32-byte tag |
| Key wrap | X25519 + ML-KEM-768, HKDF-SHA256, XChaCha20-Poly1305 | 1,192-byte blob per 32-byte key |
| Passphrase | Argon2id | t=2, 64 MiB, p=1, the only preset used |
| Hashes | BLAKE3-256 | Vendored, unkeyed |

**No cipher choice.** An XChaCha20-SIV primitive exists in `src/crypto`, and a passphrase-sealed keyfile's header may name it. No data or
metadata path uses it, and the build option `STM_AEAD_DEFAULT` only prints a status line.

**The nonce** is `paddr || gen || pool_uuid`, derived rather than stored. Per-extent associated data binds the pool, origin dataset,
inode and offset. So ciphertext cannot be moved to another address, generation, file, dataset or pool. Node associated data binds the
pool and device only.

**Granularity.** Per extent, up to 8 MiB, and per node. The whole extent is verified on each read. The tag is stored after the
ciphertext and rounded up to blocks, so **a 4 KiB write occupies two blocks**. Files of 100 bytes or fewer live inline in the inode.

**Post-quantum protection depends on the build.** With liboqs the wrap is hybrid. Without it, CMake falls back with a warning to
X25519 alone, and writes 1,088 zero bytes in the ML-KEM slot. The macOS CI build and the Thylacine OS build of Stratum both run
without it. Data and metadata use symmetric 256-bit keys in every build.

### 9.2 Key hierarchy

```
wrap keypair (X25519 + ML-KEM-768), held in a keyfile or by an agent
   wraps -> pool metadata key: random, one per pool, for the pool's lifetime
   wraps -> per-dataset DEK: random
```

- The **pool metadata key** seals every metadata node of every tree and all CAS chunks.
- A **DEK** seals only that dataset's hot file extents.
- So **per-dataset trees use the pool key**: names, sizes, owners, xattrs, extent maps, symlink targets and inline data up to 100 bytes
  are protected by the pool key rather than the DEK. Per-dataset keys separate file contents, not metadata.

**Agents.** `janus` is a Plan-9-style key agent (file and passphrase backends) over 9P on a Unix socket, and it returns plaintext DEKs
to the filesystem. `corvus`, part of the Thylacine OS, seals per-user dataset keys; a dataset with no key installed reads as locked
(`STM_ELOCKED`).

### 9.3 Plaintext on disk

- **Uberblocks,** up to 252 historical copies: UUIDs, generation, device count, capacity, free space, inode, dataset and snapshot counters,
  root addresses and checksums, scrub state.
- **Bootstrap:** the node allocation bitmap.
- **Key schema:** dataset ids, key ids, states, wrapper tags, corvus dataset paths (which can name users), wrapped keys.
- **Repair log:** timestamps, addresses, results.

### 9.4 Threat model

These attacks were **read from the code and not demonstrated**.

**An offline reader with the raw file and no keys learns** that it is a Stratum pool, everything listed in 9.3, which blocks are in use, and
extent lengths to 4 KiB. With two images, which blocks changed. They do **not** learn file names, exact sizes, which extent belongs to which
file, owners, contents or CAS hashes.

**Someone able to tamper with the file, with no keys, cannot** forge or edit an encrypted node or extent, get a modified block accepted on read,
or move ciphertext or a wrapped key elsewhere.

**They can:**

1. **Roll back.** Replace the image with an older one, or destroy the newest slots. Nothing anchors freshness outside the disk.
2. **Reinstate a retired key.** Key state is plaintext and outside the wrap's associated data, so new writes can be made to use an old DEK.
3. **Forge a whole pool, given the public wrap key.** The wrap is unauthenticated public-key encryption. Disk authenticity therefore depends on
   keeping that public key secret.
4. **Force nonce reuse.** Fork one image, by rollback or a plain file copy, and let both histories write: `(paddr, gen)` can repeat with different
   plaintext under the same key. AEGIS is not misuse-resistant. For this reason, **do not copy a Stratum volume, write to both copies and keep using
   both.** The pool metadata key cannot be rotated.
5. **Rewrite anything keyless,** including the repair log, and deny service by corruption.

**Out of scope:** a compromised live host, keys in RAM (most are not `mlock`ed, though they are wiped on close), plausible deniability, secure deletion
(there is no TRIM, so superseded ciphertext remains), dishonest `fsync`, and side channels.

### 9.5 Key management gaps

No passphrase or wrap-key change. No multiple unlock slots: one wrap keypair per pool, and losing it loses the pool. No TPM, PKCS#11 or hardware token.
Dataset DEK rotation exists in the library with no front end, and does not re-encrypt. The pool metadata key never rotates.

---

## 10. Snapshots and clones

**Create** is O(1) apart from its commit: it captures the dataset's root triple. Ids are pool-wide and never recycled. Snapshots are readable under a synthetic
`.snaps` directory and refuse writes.

**The reclaim rule** uses block birth generations, as ZFS does. A block that dies with a birth after the newest snapshot is freed; otherwise it goes on the newest
snapshot's dead list. Deleting a snapshot moves its lists to the older neighbour, or frees them if there is none.

**The limit today is severe.** Dead lists are stored inline in the snapshot's record, capped at **256 entries per tier** (data, node, cold). Past the cap the block
stays allocated with no list entry, permanently: overwriting more than 256 extents under a snapshot leaks space when that snapshot is later deleted. Writers get no error,
and nothing reports it.

**In progress, not on the main branch:** unbounded dead lists, using one copy-on-write tree per pool keyed by death generation, with deletes done in durable steps. Its
safety rule is modelled in `specs/dead_tree.tla` on that branch, and it has been through four audit rounds, the last of which found serious accounting faults. It lands with the move of
the trees to the engine (section 16).

**Rollback** destroys newer snapshots. **Holds** block deletion. A file handle does not survive a rollback and remount.

**Clones** (Library) share an origin snapshot's frozen tree. Depth 1 only: a clone cannot be snapshotted. Promote always returns `STM_ENOTSUPPORTED`. No path destroys a
clone, so its origin snapshot can never be deleted.

No per-snapshot used or referenced space accounting exists.

---

## 11. Dedup and tiering

Dedup is **offline**: hot writes are never deduplicated. It happens only when data migrates to the cold tier, or on receive, and the cold tier has no operator path other
than `Tfadvise`.

- **Chunking:** FastCDC with normalized chunking over a Gear hash, default average 8 MiB, minimum 2, maximum 32. Boundaries round to 4 KiB. Since an extent is at most 8 MiB,
  per-extent chunking at these defaults yields few chunks.
- **CAS:** keyed by unkeyed BLAKE3 of the plaintext, with a refcount. Chunks are sealed under the **pool** key so they can be shared between datasets, and the hash is stored
  only inside encrypted nodes.

**How encryption and dedup coexist.** This is a real difference from peers: ZFS allows dedup only within a dataset, its snapshots and its clones, and its dedup tables are
plaintext; bcachefs and APFS have no dedup. Stratum dedups across datasets with the hashes hidden from a disk reader. **The price is that migrating a dataset to cold removes
the DEK from reads**, so a holder of the pool key can read it. *By reading*, a locked dataset's cold extents remain readable, since they decrypt under the pool key with no check of the lock.

**Recorded ratios:** see section 17.

Reflink shares hot extents through the allocator's refcount and cold ones through the CAS. It is whole-file, same-dataset, with an empty destination. A range clone does not exist.

---

## 12. POSIX surface

| Area | Behaviour |
|---|---|
| Permissions | *By reading*, **the 9P server does not check mode bits against the client.** Authorization is `SO_PEERCRED` at attach plus `stratumd` dataset policies. Do not assume POSIX access control is enforced server-side |
| Rename | Over 9P: plain rename only. Moving a directory into its own subtree is refused. A directory rename across parents walks the moved subtree under one mutex, so it costs the subtree's entries |
| atime | Effectively `noatime`; set at create and by `utimens` |
| `st_blocks` | Synthetic, `(size + 511) / 512`, so `du` reports logical size |
| Sparse files | Supported; no `SEEK_HOLE` or `SEEK_DATA` |
| `O_APPEND` | Atomic: the end of file is read under the write's exclusive pin on the inode |
| Unlink while open | **I/O on the fid fails with `ENOENT`**, by design in `fid.tla`. POSIX keeps the file until the last close. Seen on a Thylacine guest |
| mmap | None at this layer; a client maps through its own cache |
| Read-only flags | `IMMUTABLE`, `APPEND`, `NODUMP` are defined and unused |

---

## 13. Interfaces

**9P2000.L server** (`stratumd`). Default msize 128 KiB, at most 8 MiB. Stratum extensions: `Tbind`, `Tunbind` (replace only), `Tsync`, `Treflink`, `Tfallocate`, `Tfadvise`,
and `Twalkgetattr`, a fused walk and getattr. `Tpin` and `Tunpin` are reserved and return `ENOSYS`. Transport is Unix sockets; there is no TCP listener. On a host a daemon's socket takes its path only once it listens, so a path that exists can be dialed; until then it is bound as the path, a dot and the pid, the path must leave room for that in the socket address, and a policy that confines the daemon to its socket's path must allow that name and its rename to the path. `stratumd`'s FS socket takes its path last, after its `/ctl/` socket listens. On a host a daemon started on a path where a running daemon's socket is refuses; a socket no process holds is removed, and a file there is left and refused. The look that tells the two apart is a datagram socket and its connect() to the name, which such a policy must allow as well: a look that is refused refuses the start. Daemons started at once on one path take turns at the look and the removal, by a lock on the path's directory held only for them and asked for only where a socket is found, which such a policy must allow too (a read-only open of the directory, and a lock on it); where the lock cannot be had, or somebody has kept it for a tenth of a second, each looks without a turn. A daemon's end removes its path only while the file there is still its own. On Thylacine the socket is bound in place, and a socket found at the path is removed whoever holds it.

**`/ctl`.** A synthetic administrative tree on a second socket. Status, datasets and snapshots to read. Verbs for snapshot create, delete, hold, release, rollback, compromise
marking, DEK install and evict, and scrub control. Prometheus text at `/pools/<uuid>/metrics/prometheus`. No verbs for clones, send, receive, tiering, devices, setting
properties or destroying datasets. `/events` is RAM-only, capped at 8 MiB, and silently drops past that.

**Other.** `libstratum-9p`, the stable C client ABI. `stratum-slate`, TUI state served as a 9P tree. A read-only host directory server. Platforms: Linux, macOS, and
aarch64 Thylacine with a virtio-blk backend; io_uring on Linux, POSIX elsewhere. On Thylacine a stop wakes no client, since `shutdown` on a `/srv` stream does nothing there, so a stop waits for each client to leave (T0.60).

---

## 14. The volume manager

`stratum` is one binary that re-executes itself as `serve`, `mkfs`, `fs`, `slate` and `host-fs`, plus a FAR Commander-style dual-pane terminal manager. It makes Stratum usable
as an encrypted container: a volume is a file, and the manager copies files between it and the host.

```
stratum mkfs vault.stm --size 4G --passphrase-stdin    create a volume
stratum tui --vol vault.stm                            open it
stratum fs -s SOCKET put ./dir /dir                    script it
```

**What works, from the code:** recursive copy (`F5`) with progress and conflict handling, delete (`F8`), mkdir (`F7`), a modal editor (`F3`, `F4`), the create-volume wizard
(`Shift+F7`), snapshot list, create, delete and rollback (`F9`, dataset 1 only), a pool map and snapshot graph (`F2`), and pressing Enter on a `.stm` file to mount it in the other pane. Nothing the screen draws sends a control character to the terminal: a file's ESC or BEL in the editor shows as `?`, a tab in a dialog as a space, and the editor keeps the bytes.

**How the daemons stop.** The manager's daemons hold a lifeline to it and stop when it does, however it ends. The manager kills one whose stop has not ended 30 s after it asked, which loses every write since the last commit if the final commit is slower than that. A call of the manager's own that a daemon has not answered does not hold a stop asked, or a quit, and neither does a dial that a daemon does not take, nor a helper the manager runs that waits on one: each waits a tenth of a second at a time and looks between, and ten seconds of the manager's running after the asking with nothing sent and nothing received (on Linux a daemon's taking of what was sent counts as well, a piece of some 36.5 KB at a time, so a daemon that takes longer than the ten seconds over one piece, or over 8 KiB on macOS, is given up as one that does not answer; the wait a stop is asked in began before the asking and counts for nothing, so the ten seconds are whole), the call is given up, or the helper killed with what it started, and the manager goes on to stop its daemons. A stop that comes while the manager is still starting counts as asked: TERM and INT are held until the screen, and the start's own waits, its check after the passphrase prompt and its first calls look for one held so. With a screen the start ends there with 1 and says it was asked to stop, as does one attached to a running slate on a stop asked before its screen is up, the passphrase unused where it had not been used yet; the prompt itself waits for its Enter. Headless, the waits and the check after the prompt end it the same, and a stop that comes once the daemons are up is that run's own end, with 0. Once a stop is asked, no line the manager writes stops it for the terminal: one started behind its shell says its last words from there under `stty tostop` too, and ends. One that a line had stopped there before the stop was asked writes that line when it is continued, and ends as well. The handler that stops the manager for a line looks for a stop asked as well, so one asked after the line's own look does not stop it either, however long the manager was held between that look and the write. A mode set the manager makes from behind, giving the terminal back after a passphrase or taking it for the screen, has the same stop and holds the same signals, and its wait looks the same: behind, once a stop is asked, the set is given up, and brought back in front it is made, and a stop asked while the manager waited there with no continue then ends it: the passphrase's terminal given back, or the screen's mode put back with no screen put up. The screen asks this of the terminal it sets: standard input, or else the controlling terminal. A stop asked between the handler's look and its stop, however long a stop from outside held the manager there, is the exception: that line or set stops the manager, and the next continue ends it. Each daemon that does not stop is killed at its 30 s, one after another, and `slate` does not stop while it waits on a daemon that does not answer, so such a stop takes 10 s and 30 s more for each such daemon: some 40 s with one, some 70 s with two. With nothing asked a daemon is waited for as long as it takes, and the screen stands still meanwhile (T0.85). One whose manager has gone is never killed, so a stop that never ends leaves the volume unlocked in memory, though no longer served, and `flock` reports it in use (T5.18). The manager's session directory, which holds their sockets and logs, goes when it ends, however it ends short of SIGKILL, a crash, a signal it does not handle, or its terminal closing at the instant a daemon it started binds its socket there; it handles TERM, INT, HUP and QUIT, and a panic still removes the directory. A stop asked, or a quit, that finds the manager's terminal taking nothing is not left to wait there: the screen writes through an open of the terminal of its own that does not wait in a write, and once the terminal has taken nothing for ten seconds of the manager's running after that, the manager gives it up and ends in order, its daemons stopped and the session directory removed, but without leaving its screen: with the code the signal alone would have left (that of the first signal that came; 1 where none did), the terminal's mode put back where the manager is in front, and what each terminal it gave up had not taken dropped where the manager is that terminal's controlling process, whose end would otherwise wait for it to drain (macOS); a terminal it does not control keeps what other programs wrote to it. What the manager sees of a terminal's taking is room coming back for its writes, which a pty gives in steps: after every read on macOS, and on Linux, for writes of the size the screen makes, after up to 3584 bytes read (measured), so a terminal that takes less than a step in the ten seconds can be given up as one that takes nothing. The manager's own lines to that terminal go through the same open and are given up with it. On another terminal they go through an open of that one of their own, and giving it up gives up the lines alone: the screen draws on and is put back, and the manager ends with the same code. Headless, where nothing draws, its lines wait on a terminal that takes nothing until it takes its stop, and then ten seconds at most, standard output a file or not, and a run whose lines were given up so ends as the signal alone would have ended it; its daemons' lines go to that terminal through an open of their own that does not wait, and a line written while the terminal has no room is lost, whole or in part (on Linux at once while its output is stopped). Where standard error's terminal cannot be opened again (on macOS by its name alone), the manager's lines and its daemons' are written to it as it is, and a terminal that takes nothing holds them as before. A terminal that takes again still shows the alternate screen, with mouse reports on and the cursor hidden, until `reset`. Where the terminal cannot be opened again the screen writes to standard output, and a terminal that takes nothing holds it as before (T0.83). The directory is made as mkdtemp makes one, 0700, its name the manager's pid and six characters no one knows ahead, so a directory left behind, or one another user made in a shared /tmp, never stands in its way. On a stop, a daemon ends the reading side of every connection and lets each request in hand run to its end. If its connections have not all ended 2 s later it shuts the writing side of every one still open, so a reply not sent by then is lost, whether its client was reading or not, though the request it answers still finishes. Its `/ctl/` connections still open then get the same, with 2 s of their own. Then it unmounts. So on a host no client, talking or silent, can keep a volume mounted; on Thylacine a stop reaches no connection and waits for each client to leave (T0.60). One image has one daemon, enforced with `flock`, and `mkfs` refuses a file holding data, a key in the way, and a volume in use.

**How a copy behaves.** `F5` copies the selection, or the entry under the cursor, into the other panel's directory, as one batch with progress.

- **What goes.** Regular files and directories. Symlinks and special files are left out and counted as skipped, and the summary says so. A name the manager cannot hold exactly, one that is not UTF-8 or holds a control character, is refused and counted as failed.
- **Refused whole.** Before anything moves, the batch is refused if any item's destination is the item itself, lies inside it, or contains it: by canonical path from host to host, by path within one volume. A bind mount hides from this check (T0.55).
- **Directories** are walked in name order and made before their contents, with the source's permission bits plus the owner's, so that the copy can fill them. One already there is merged into and keeps its mode. A symlink standing where a directory goes is refused. When a directory cannot be made, nothing under it is tried, and all of it counts as failed.
- **When the name is taken,** by a dangling symlink too, the manager asks: Skip, Overwrite or Keep both, each also for the rest of the batch, or Cancel. Skip on a directory skips everything under it. Overwrite on a directory merges into it. Keep both takes the first free name of the form `name-2.ext`, and a directory's contents go with it. Cancel ends the batch, and what is left counts as skipped. A Skip for the rest of the batch that was answered for a file merges into a directory already there, and meets each file inside with Skip.
- **A file is never half replaced.** New bytes for an existing name go to a temporary name beside it and are moved over the old file only once they are whole, so the old file stays readable until then. A new name on the host also goes through a temporary, then a hard link to the name, so a name that appeared meanwhile is refused, not replaced; on a filesystem with no hard links it is a rename, which would replace it. A new name on a volume is written in place by `stratum fs write -n`, which refuses a name that is there. A failed item removes only what it made.
- **Checked, not trusted.** The bytes that arrived are counted against the source's size. A host source is opened once, without following a link, and must be a regular file, so its size and mode come from the file whose bytes are read. A volume source is read by a process of its own, so it is asked again afterwards, and a changed inode, mode or size fails the item. Into the host, and over an existing name in a volume, that check comes before the copy is moved into place. A new name in a volume is committed by `write -n` before the check, and removed after a failed one, so a crash in between keeps it (T0.56).
- **Who may read it.** A copy is created with its source's permission bits, without setuid, setgid and sticky, so nobody the source keeps out can read it while it fills. Host temporaries are made at 0600.
- **Not kept:** modification time, owner, extended attributes, holes in sparse files, and hard links, which become separate files (T5.4).
- **A batch is not one transaction.** Stopped or killed part way, it leaves the items done so far. A kill during a volume item can leave a short file under a new name, and temporaries named `.stratum-copy-<pid>-<n>` (T0.56).

**How a delete behaves.** `F8` asks "Delete N items?" with No selected, and nothing is touched unless the answer is Yes. Items go one at a time, a directory with everything in it. Esc stops the batch after the item in hand. A quit key, `F5`, `F7` or `F8` during a batch asks Stop or Go on. No new item starts while it asks, though the item in hand runs on. A quit key quits only once no batch runs, and with a snapshot or scrub request still out it asks Wait or Quit, since quitting stops the volume under the request and its result is never shown; a signal, or the terminal closing, ends the manager at once, in the middle of the item in hand if there is one. A snapshot or scrub result replaces its own "Working" notice, or the snapshot list, and otherwise waits until no dialog is up, no batch runs and the editor is closed, by this manager or another client, so it never takes the Esc meant for a batch or the keys meant for the editor; past a batch's end it waits for the summary to be closed. A second such request, made while one is out, is refused and must be made again. In a field, a key pressed with Ctrl or Alt types nothing.

**Names.** A name the manager cannot show exactly, one that is not UTF-8, holds a control character (below U+0020, DEL, or C1, U+0080 to U+009F), or is longer than 9P's 255 bytes on the host, is listed with U+FFFD standing in, and no action accepts it: it is not entered, copied or deleted from the manager. A volume, keyfile or host path given to the manager that holds a control character, or is not UTF-8, is likewise opened nowhere, and nothing the manager writes to the terminal outside the screen carries a control character from a name. The subcommands that are tools rather than the manager, `stratum fs` and `stratum mkfs`, print names as they are, as a pipe would want them; `stratum fs ls -0` ends each with a NUL for scripts. The manager gives a child a volume or host directory name that begins with `-` as `./name`, so none reads it as an option. `stratum mkfs` makes a key named through a symlink where the link points, following a link at the key's name, and each it leads to, seven at most, only if the user or root owns it (on Thylacine, which has no root, the user); links among the directories above the key are the kernel's to judge. Where the links lead the key out of the directory it was named in, the directory they lead to has to be the user's or root's and, going by its mode, writable by nobody else or sticky; a new key is made through that directory's descriptor, so it is in the directory that was asked about. The volume is made with the key read back through the descriptor that made it, and a key that is there is read through the descriptor it was asked about through: the format and the mount are handed the key, and do not read it by its name. With no passphrase it uses a key already there as it is only when it is the user's alone: a regular file the user owns whose mode gives no one else access. An ACL, or a mount that shows every file as the caller's, is outside what the mode says. `--key-as-is` passes over the owner and the mode and nothing else: the key must still be a regular file, another user's link is still not followed, nothing is formatted over, no key is replaced, and beside `--passphrase-stdin` it is refused. Each link is looked at before it is read and again after, and one that cannot be read is refused, and so is one with more than one name, since the owner asked is the link's and any user may have given it the name it has there. A link that had a second name once is not told from any other; the asking of the directory is what holds against it. When the volume is claimed `mkfs` also asks what the name itself reaches, which has to be what the links, as read, end in, so on Linux, where a descriptor's name is a link and, for a pipe or an unlinked file, its text names no file, a key is not such a descriptor. At its use the key is opened through its name, and one that was not there at the claim, or that is another file than the claim asked about, is not used as it is. The links are asked about again where a new key is made. So another user's link left at a free name is not followed, whenever it is left: it is refused where it is asked about, and after the last asking it makes the new key's taking of the name fail. Once a new key has taken its name, the name has to reach it: where it does not, `mkfs` says where the key is, by the path its directory has by then where the system tells one, and ends with the volume formatted and the key kept. What is swapped at a name that was taken is T0.58's. `--force` follows any link it can read, whoever owns it, however many names it has and wherever it leads, lets a new key take the place of one it cannot read, uses any key it can open, and formats a file another user owns. Without it `mkfs` formats no file at the volume's name that another user owns, an empty one neither: its owner could remove the volume. A link at the volume's name is asked about as a key's links are, and the volume is formatted and mounted through the descriptor its claim holds, so it is made in the file that was asked about. A link at the volume's name that leads to no file is refused and said to be that: a new image is made only at a name that is no link. Where the name no longer leads to that file once the volume is made, `mkfs` says so, removes a key it made and ends 2. An image that a run made and did not finish is removed through the directory it was made in, and only while its name there is still that file; where it is not, the image is left and `mkfs` says where it is, or that it has no name any more, so nothing is removed by a path that may reach another file by then. An image that could not be locked is left as well, and said. `stratumd` mounts through the descriptor its lock is on, so the image it serves is the one it locked. A directory on the volume's way that another user controls is outside this, as it is for a key. The host panel checks on every use that a name still leads to the file it was walked to, so a file renamed away is not served as the file now at its name. It knows a file by device and inode, so a new file that reuses a freed inode number can take over the name of a fid still held on the old one (T0.62); the manager re-walks on every redraw and holds no such fid.

**Durability.** A manager copy runs one `stratum fs` command per item, and each mutating command ends with a whole-pool commit before it reports success. What the manager reports copied into a volume is therefore durable, and a copy of `N` items costs `N` commits. On the host, a file that replaces another is synced before it is moved into place; a new file is left to the host's own write-back.

**Known gaps:**

- No move or rename in the manager (`stratum fs mv` exists). Three of six admin panes say "Coming soon". Copies keep no modification time and skip symlinks.
- "Static" is partial: libsodium links dynamically.
- The host panel serves 9P clients other than the manager less well than 9P asks: a fid walked and never opened loses its name after about 2,048 newer lookups (T0.63), and a walk resolves each name from the root, so a symlink flipped among a name's components inside one walk can still be followed (T0.61).

**How keys work, and how this differs from VeraCrypt.** A volume always needs a **keyfile**, by default `<volume>.key` beside it. A passphrase does not derive the volume key; it seals the
keyfile with Argon2id. **Without `--passphrase-stdin`, the keyfile is plaintext, so anyone holding it holds the volume.** Losing it loses the volume, and there is no way to change a passphrase. Wherever the manager asks for one, at the terminal or in its screen, the keys mean the same: Enter submits, Backspace or Ctrl-H erases a character, Ctrl-U the line, and an Esc sequence or any other control key types nothing; at the terminal Ctrl-D, Ctrl-C and Ctrl-\ give up, and after a lone Esc the keys an escape sequence would hold are dropped: the next one, read as Alt with it, or after Esc [ or Esc O those that would finish the sequence. A passphrase is at most 255 bytes on every path: what is typed past that is counted, not kept, and a longer one is refused when submitted. One holding a control byte or a broken UTF-8 character can be given only on `--passphrase-stdin`. No `stratum` process dumps core, so none leaves a passphrase or a key on disk that way.

| | VeraCrypt | Stratum |
|---|---|---|
| Container looks random | Yes; no signature | No; magic `STRATUM2` and plaintext uberblocks |
| Hidden volumes, deniability | Yes | No |
| Mounts as an OS drive | Yes | No; through the manager, `stratum fs`, or v9fs on Linux |
| Passphrase alone opens it | Yes | No; a keyfile is always required |
| Change password, backup headers | Yes | No |
| Ciphers | Choice and cascades, XTS | AEGIS-256 only, authenticated |
| Detects tampering of data | No, by its own security model | Yes |
| Hides which sectors changed | No | No |
| Snapshots, rollback | Inside a guest filesystem, if any | Yes |
| Post-quantum key wrap | No | When built with liboqs |
| GUI, Windows | Yes | Terminal only; macOS and Linux |

Stratum is the opposite trade to VeraCrypt: it does not hide that it exists, but it authenticates everything it stores.

---

## 15. Evidence of correctness

**Tests.** 83 suites and 2,567 test legs, in C. The manager has 38 Rust integration tests, two of them in `concurrent_ctl`, and 194 unit tests, and three drivers run the real binary: `volume_smoke.sh`, `stop_with_clients.py`, and `manager_keys.py`, which plays the manager's keys in a terminal and reads the screen.

**TLA+.** 43 specifications with 191 configurations, of which 135 are deliberately broken and must fail. Coverage includes commit and quorum, allocator and deferred free, nonce uniqueness,
Merkle links, COW commit, delta chains and epochs, the namespace layer, compound operations, dead lists, clones, CAS, and the key schema. CI runs 12 of these configurations. The rest are run by
hand. Two cautions. `sync.tla`'s `NonceUnique` cannot fail as written, so nonce uniqueness rests on `allocator.tla` and `metadata_nonce.tla`. And `merkle.tla` assumes the attacker does not touch the
uberblock.

**Audits.** Adversarial review rounds numbered R0 to R177, the first 15 on an earlier prototype, then per-chunk rounds; 145 commits close an audit. A count of rounds is evidence of process, not a
result.

**Sanitizers.** ASan, UBSan, TSan and MSan build options.

**What the evidence does not cover:**

- **CI is red at the last published commit.** At `471a339`, 8 of 9 build jobs fail, and the last fully green run was 2026-04-20. On machines rather than in CI, at `71e6a41`: all 80 suites pass on Linux (arm64, gcc 14, io_uring on, warnings as errors) and on macOS. The sanitizer legs have not been triaged.
- **Zero fuzz targets.** `STM_BUILD_FUZZERS` exists and builds nothing.
- No xfstests run, no soak run, no kernel 9P mount in CI.
- The manager's CI job covers Linux and macOS since `f8f99b2`, and has not run in CI yet.

---

## 16. Limits and unbuilt work

### 16.1 Hard limits

| Limit | Value | Kind | Past it |
|---|---|---|---|
| File size | 2^63 - 1 bytes | Implementation | `EFBIG` |
| Device size | 1 EiB, *derived* | Format | Not representable |
| Devices per pool | 64 | Format | Refused |
| Filename | 255 bytes | Format | `EINVAL` |
| Directory probe chain | 64 | Implementation | `ENOSPC` at create |
| Symlink target | 100 bytes | Format | `ENAMETOOLONG` |
| Xattr name, value | 255 bytes, 64 KiB | Format, implementation | Error |
| Hard links | 2^32 - 1 | Format | `EOVERFLOW` |
| Extent | 8 MiB | Implementation | Split |
| Replicas per extent | 4 | Format | |
| Metadata per pool | 7 GiB; 256 MiB unless `--bootstrap` is passed | Format | `ENOSPC` |
| Inodes, upper bound | About 27M at 7 GiB; 966K at 256 MiB; 241K at 64 MiB, *derived*, with internal nodes ignored | Metadata space | `ENOSPC` |
| Datasets plus clones | About 104, *derived*: the key schema is one 128 KiB leaf | Implementation | *By reading*, create succeeds and every later commit fails |
| Allocator ranges | 9,391,788 per device, *derived* | Implementation | Commit fails and the filesystem wedges |
| CAS chunks | 1,646,722, *derived* | Implementation | |
| Dead list | 256 entries per tier per snapshot | Implementation | Space leaks silently |
| Clone depth | 1 | Implementation | Refused |
| Repair log | 2,048 entries | Implementation | Entry lost, repair still lands |
| Engine tree depth | 32 | Implementation | |
| Engine value | 1 MiB | Implementation | |
| Fids per 9P connection | 4,096 | Implementation | `EBADF` |
| Walk components | 16 per message | Implementation | Client walks in hops |
| Locks | 256 per owner, 4,096 per client, 65,536 total | Implementation | `ENOLCK` |
| 9P qid uniqueness | Low 32 bits of the inode number | Implementation | *By reading*, silent collision past 2^32 inodes |

### 16.2 Decided next

**All trees on the engine.** The allocator, allocator roots, dataset, snapshot and CAS indexes, key schema and repair log move off the whole-tree store. Nothing then needs adjacent nodes, which removes
the metadata fragmentation of section 7, the commit's whole-allocator rewrite, and the caps on allocator ranges and datasets. This is a format change, with no upgrade path (section 1). In the same model as section
7 it reaches 1220, 773, 586, 453 commits per cycle and stops near 0% free, with the caveat that the model assumes trees shrink as records go, and the engine has no merge yet, so that must be built too.

**Unbounded dead lists** arrive with it (section 10).

### 16.3 Known defects

All are tracked. Those marked *by reading* have not been reproduced yet.

- CI red, as in section 15.
- *By reading:* a full metadata pool wedges at commit, since nothing on the write path counts node space.
- *By reading:* snapshot create answers OK before the snapshot is durable.
- Unlink while open, as in section 12.
- *By reading:* a scrub started on a running daemon reports RUNNING and verifies nothing, since nothing steps it. When driven, it verifies hot extents only and counts everything else as verified.
- *By reading:* a device replace moves bytes without rewriting extent addresses (library only).
- *By reading:* a manager Overwrite can replace a volume image a daemon has open, or its key.
- *By reading:* a kill during a manager copy into a volume can leave a short file under a new name.

### 16.4 Unbuilt

Compression. Reed-Solomon and LRC. Metadata replicas: **all metadata is on device 0, and a corrupt metadata node is unrepairable.** Reconstruction of a failed device. Evacuating a range above 4 MiB. Periodic commit,
per-file fsync, and an intent log. fsck. Encryption-preserving (raw) send. Send of inodes, names, xattrs and deletes. Metadata scrub. Wrap-key and passphrase change. Per-dataset metadata keys. Hardware key backends.
Long symlinks. Blocking locks. ACLs. Quotas. Per-snapshot space accounting. FUSE and language bindings. Node merge, node eviction, and bootstrap growth. Format freeze.

`PRODUCTION-PLAN.md` orders all of this into a plan, with a definition of production quality.

---

## 17. Performance

**No benchmark against ext4, btrfs or ZFS has been run, so no comparison claim is made.** Stratum is expected to be slower at synchronous workloads because of whole-pool commits and the absence of an intent log, and this has not been quantified.

The figures below are recorded in this repository. None states its build type, and all predate later work, so treat them as indicative. They are not results for the current tree.

| Measure | Result | Provenance |
|---|---|---|
| AEGIS-256, 1 MiB | 8,835 MiB/s encrypt, 7,897 decrypt | Apple M2; no date or commit. A primitive ceiling, not filesystem throughput |
| BLAKE3, NEON | 1,898 MiB/s | Same |
| Commit, empty | 13.6 us | macOS with `F_FULLFSYNC`, 256 MiB pool; no date or commit. The clean-commit skip |
| Commit, metadata | 19.5 ms | Same |
| Commit, 4 KiB data | 27.7 ms, 118x write amplification | Same |
| Commit, 64 KiB data | 27.3 ms, 8.3x write amplification | Same |
| fsbench, in a Thylacine guest over 9P | 9.2 MiB/s sequential write, 27-29 MiB/s cold read, 78-103 MiB/s reread, about 1,300-1,560 creates/s | 2026-07-07, HVF, 4 CPUs. A guest figure, not a device figure |
| B-epsilon node write reduction | 1.83-2.04x at fsync per operation, 1.00x at batch cadence | Design note; target of 20-50x not met |
| Reflink | 2,062 to 15,141 ns per extent, N=1 to 1024 | 2026-04-30, macOS, commit `d444ca2` plus an uncommitted bench |
| Dedup ratio | 3.21 to 4.47 on a synthetic VM-image corpus (64 KiB chunks) | 2026-04-30, GCP e2-standard-4, commit `3ff8f77`. Not reachable from the shipped binary |

**Structural expectations (analysis):** a large commit is dominated by rewriting the allocator (about 14 MiB at 113 allocator units, *derived*), and a small one by barriers. A read is fast once resident, since tree nodes stay in memory, though unbounded memory
growth is the other side of that. A mount slows with total metadata.

---

## 18. Comparison

Sourced from each project's documentation or source on 2026-11-05. "Not found" means looked and not found, not absent. "Library" for Stratum means no operator path yet. Tags refer to section 19.

### 18.1 Structure and durability

| | Stratum | OpenZFS | btrfs | bcachefs | APFS |
|---|---|---|---|---|---|
| Metadata | COW B+tree with messages, 16 KiB; older trees rewritten whole | Block pointer tree, 128-byte bp [Z-spa] | COW B-trees, 16 KiB default [B-mkfs] | Log-structured b+tree nodes, 256 KiB default [BC-pdf] | B-trees, 4 KiB [A-ref] |
| fsync | Whole-pool commit | ZIL, optional SLOG [Z-zil] | Log tree [B-btrees] | Ordered journal [BC-pop] | Not found |
| Periodic commit | None, *by reading* | 5 s default [Z-mod] | 30 s default [B-man5] | Journal flush 1 s default [BC-pop] | Not found |
| Merkle parent links | Yes, over ciphertext | Yes (derived) [Z-spa] | No; generation only (derived) [L-btrtree] | Yes, "chain of trust" [BC-enc] | Fletcher in each object [A-ref]; hash tree only on signed system volumes [A-ssv] |
| Default checksum | BLAKE3 for nodes; AEAD for data | fletcher4 [Z-props] | crc32c [B-csum] | crc32c [BC-pop] | Fletcher 64 [A-ref] |
| Redundancy | Mirror, Library; metadata none | Mirror, raidz, dRAID, copies [Z-pool] | RAID profiles; RAID5/6 not for production [B-man5] | Replicas, erasure coding [BC-pop] | Not in the filesystem layer [A-faq] |
| Compression | None | lz4, zstd, gzip and more [Z-props] | zlib, lzo, zstd [B-comp] | gzip, lz4, zstd [BC-pop] | Not found |

### 18.2 Encryption and dedup

| | Stratum | OpenZFS | btrfs | bcachefs | APFS |
|---|---|---|---|---|---|
| Native encryption | Always on | Optional, per dataset [Z-props] | None in documents read; fscrypt series posted, merge not confirmed [B-status][B-lwnfs] | Whole filesystem, at format [BC-pop] | Optional [A-feat] |
| Cipher | AEGIS-256 | AES-CCM, AES-GCM [Z-props] | | ChaCha20-Poly1305 [BC-pop] | AES-XTS or CBC [A-feat] |
| Authenticated data | Yes, 256-bit tag | Yes | | Yes, 80-bit MAC default [BC-enc] | Not by XTS (analysis) |
| Names and sizes visible on disk | No | Dataset names and file sizes visible [Z-key] | | Superblock and node headers only [BC-enc] | Not found |
| Dedup | Offline, Library, across datasets | Inline; within a dataset and its family when encrypted [Z-key] | Out-of-band tools [B-dedup] | None [BC-faq] | None; clones [A-faq] |
| Post-quantum wrap | When built with liboqs | Not found | | Not found | Not found |

### 18.3 Snapshots and space

| | Stratum | OpenZFS | btrfs | bcachefs |
|---|---|---|---|---|
| Reclaim model | Birth generation, dead lists capped at 256 | Birth time, deadlists merged on destroy [Z-dsl][Z-destroy] | Refcounts in the extent tree [B-design] | Keys versioned by snapshot id [BC-snap] |
| Delete cost | Moves lists, frees at the end | Background `async_destroy` [Z-feat] | Background cleaning [B-subvol] | Proportional to the snapshot's data [BC-pdf] |
| Near-full | Refuses at commit; fragments today | 3.2% slop [Z-misc] | Global reserve, 512 MiB cap; can return ENOSPC with df showing free [L-rsv][B-man5] | Copygc, 8% reserve [BC-pop] |
| When no contiguous space | Refused | Gang blocks [Z-zio] | Metadata chunks [B-design] | Copygc [BC-pop] |

### 18.4 Limits

| | Stratum | OpenZFS | btrfs | APFS | ReFS |
|---|---|---|---|---|---|
| File size | 2^63 - 1 | 2^64 [Z-dnode] | 2^63 by VFS [B-man5] | 2^63 [A-comp] | 35 PB [R-over] |
| Filename | 255 | 255; 1023 with longname [Z-hdr] | 255 [B-man5] | 10-bit length field [A-ref] | 255 [R-over] |
| Files | Metadata-bound, 27M at the 7 GiB cap | 2^48 per objset [Z-dnode] | 2^64 per subvolume [B-man5] | 64-bit ids [A-comp] | 2^64 per directory (2012) [R-blog] |

bcachefs was removed from mainline Linux at 6.18 and ships as a DKMS module [L-618][BC-home]. HAMMER2 and WAFL are not tabled because too few comparable facts were found; WAFL's activemap and snapmap bitmaps are worth reading as a contrasting design [W-f17].

---

## 19. References

Z-spa https://raw.githubusercontent.com/openzfs/zfs/master/include/sys/spa.h
Z-zil https://raw.githubusercontent.com/openzfs/zfs/master/module/zfs/zil.c
Z-mod https://openzfs.github.io/openzfs-docs/man/master/4/zfs.4.html
Z-props https://openzfs.github.io/openzfs-docs/man/master/7/zfsprops.7.html
Z-pool https://openzfs.github.io/openzfs-docs/man/master/7/zpoolconcepts.7.html
Z-key https://openzfs.github.io/openzfs-docs/man/master/8/zfs-load-key.8.html
Z-feat https://openzfs.github.io/openzfs-docs/man/master/7/zpool-features.7.html
Z-dsl https://raw.githubusercontent.com/openzfs/zfs/master/module/zfs/dsl_dataset.c
Z-destroy https://raw.githubusercontent.com/openzfs/zfs/master/module/zfs/dsl_destroy.c
Z-misc https://raw.githubusercontent.com/openzfs/zfs/master/module/zfs/spa_misc.c
Z-zio https://raw.githubusercontent.com/openzfs/zfs/master/module/zfs/zio.c
Z-dnode https://raw.githubusercontent.com/openzfs/zfs/master/include/sys/dnode.h
Z-hdr https://raw.githubusercontent.com/openzfs/zfs/master/include/sys/fs/zfs.h
L-btrtree https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/btrfs_tree.h
L-rsv https://raw.githubusercontent.com/torvalds/linux/master/fs/btrfs/block-rsv.c
L-618 https://raw.githubusercontent.com/torvalds/linux/v6.18/fs/bcachefs/Kconfig
B-mkfs https://btrfs.readthedocs.io/en/latest/mkfs.btrfs.html
B-btrees https://btrfs.readthedocs.io/en/latest/dev/dev-btrees.html
B-man5 https://btrfs.readthedocs.io/en/latest/btrfs-man5.html
B-csum https://btrfs.readthedocs.io/en/latest/Checksumming.html
B-comp https://btrfs.readthedocs.io/en/latest/Compression.html
B-status https://btrfs.readthedocs.io/en/latest/Status.html
B-lwnfs https://lwn.net/Articles/1072623/
B-dedup https://btrfs.readthedocs.io/en/latest/Deduplication.html
B-design https://btrfs.readthedocs.io/en/latest/dev/dev-btrfs-design.html
B-subvol https://btrfs.readthedocs.io/en/latest/Subvolumes.html
BC-home https://bcachefs.org/
BC-faq https://bcachefs.org/FAQ/
BC-enc https://bcachefs.org/Encryption/
BC-snap https://bcachefs.org/Snapshots/
BC-pop https://raw.githubusercontent.com/koverstreet/bcachefs-tools/master/doc/bcachefs-principles-of-operation.tex
BC-pdf https://bcachefs.org/bcachefs-principles-of-operation.pdf
A-ref https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
A-faq https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/FAQ/FAQ.html
A-feat https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/Features/Features.html
A-comp https://developer.apple.com/library/archive/documentation/FileManagement/Conceptual/APFS_Guide/VolumeFormatComparison/VolumeFormatComparison.html
A-ssv https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web
R-over https://learn.microsoft.com/en-us/windows-server/storage/refs/refs-overview
R-blog https://learn.microsoft.com/en-us/archive/blogs/b8/building-the-next-generation-file-system-for-windows-refs
W-f17 https://www.usenix.org/system/files/conference/fast17/fast17-kesavan.pdf
V-spec https://veracrypt.io/en/VeraCrypt%20Volume%20Format%20Specification.html
V-hid https://veracrypt.io/en/Hidden%20Volume.html
V-sec https://veracrypt.io/en/Security%20Model.html
