# Stratum: the road to production

Everything known to stand between Stratum and production use, in the order to fix it. `SPECIFICATION.md` says what
Stratum is. This says what has to change. Most items come from that document, the rest from the defect queue and from
analysis, and each says which.

## What production means here

A list without an end never finishes, so this is the end. Stratum is production quality when all of these hold:

1. **No known defect** loses data, wedges a healthy pool or misreports silently.
2. **CI is green** on Linux and macOS, with gcc and clang, ASan, UBSan and TSan, and every TLA+ configuration runs on a schedule.
3. **A checker** can prove a pool consistent, and a crash harness runs it after every barrier prefix and write reordering.
4. **Fuzzing** covers every parser that reads untrusted bytes: on-disk structures, 9P, keyfiles, send streams.
5. **xfstests** pass through a real kernel mount with a published list of exclusions, and a long soak stays clean.
6. **Durability is honest:** written data becomes durable within a stated time, and `fsync` and `O_SYNC` mean what they say.
7. **One bad block does not lose a pool,** and metadata space does not decide a pool's fate at format time.
8. **Memory and mount time are bounded** by something other than total metadata.
9. **The format is frozen,** with a version policy and an upgrade tested on real old images.
10. **Someone outside this project has reviewed the cryptography,** and every fixable attack in the threat model is fixed.
11. **Benchmarks against ext4, btrfs and ZFS are published,** from one machine, with full provenance.
12. **Nothing is half there:** every feature in the specification is Available or has been removed.

## How to read the tables

| Column | Values |
|---|---|
| Evidence | **Seen**: reproduced or measured. **Read**: read in the code, never run. **Analysis**: reasoned from the design, unchecked. **Written**: a fix exists, not yet built |
| Size | S, M, L, XL: relative work, not a duration |

Every item that changes the on-disk format is in tier 2.

---

## Tier 0: broken today

Loses data, wedges, or says something untrue. No item here changes the format unless it says so.

### Snapshots and clones

Commit `e127378` already fixed the worst of this area, with a test that failed before it for nearly all: the pool made
unmountable by deleting a middle snapshot, rollback losing a file, and writes missing from incremental send, among others.
Host sanitizers and a Linux build were not run on that commit. What remains:

| # | Item | Evidence | Status |
|---|---|---|---|
| T0.1 | Past 256 entries per tier, a block stays allocated with no list entry, for ever, and nothing reports it | Read | Fixed on the dead-list branch; goes with T2.2 |
| T0.2 | A clone cannot write a file it inherited. Also owed: cold records on a clone's real file, a stale inherited dirent's generation | Seen, once; base run owed | Fix on a branch, audit owed |

### Wedges and silent limits

| # | Item | Evidence | Status |
|---|---|---|---|
| T0.3 | Dataset 105 or so: create succeeds, and the next commit fails and wedges the pool, because the key schema is one leaf | Read | Goes with T2.1 |
| T0.4 | 9.39M allocator ranges on a device: commit fails and the pool wedges | Read | Goes with T2.1 |
| T0.5 | A write's reclaim follows a failed flush into a wedge, where a commit on the same state answers the error and stays up | Read | Open |
| T0.6 | Any failed commit wedges until remount, including failures that are only lack of room | Read | Open; see T3.11 |
| T0.7 | Free metadata space fragments, and writers stop with a quarter of it free. So far a Python model only | Analysis; real-pool run queued | Goes with T2.1 |
| T0.25 | A full metadata pool wedges at commit. Nothing on the write path counts node space, so it admits writes that no commit can store | Read | Open; T3.11 for the refusal, T2.4 for the room |
| T0.26 | Snapshot create answers OK before the snapshot is durable: its slot is made after the commit and no commit follows, so a crash loses a snapshot reported as made | Read | Open |

### Things that do not do what they say

| # | Item | Evidence | Status |
|---|---|---|---|
| T0.8 | Rename of a directory into its own subtree makes an unreachable cycle | Read; leg written | Fix written |
| T0.9 | Manager editor: saving a file over 64 KiB keeps only the last chunk | Read; leg written | Fix written |
| T0.10 | Manager editor: says Saved before writing, discards the result, and `:wq` quits on a failed save | Read; leg written | Fix written |
| T0.11 | Manager editor: emptying a file and saving keeps the old bytes | Read; leg written | Fix written |
| T0.12 | Manager wizard: Use passphrase with an empty field makes a plaintext keyfile | Read; leg written | Fix written |
| T0.13 | Manager landing: panic on a non-ASCII recent path, New and Host do nothing, banner claims post-quantum in every build | Read; leg written | Fix written |
| T0.14 | Scrub reports RUNNING and verifies nothing, since nothing steps it. When driven it checks hot extents and counts the rest as verified. The manager's prompt promises repair | Read | Open |
| T0.15 | `O_SYNC` and `O_DSYNC` are not consulted, and `datasync` is ignored | Read | Open |
| T0.16 | `fallocate` reserves no space, so a later write can answer ENOSPC | Read | Open |
| T0.17 | Quota is a stored property that nothing enforces. `IMMUTABLE` and `APPEND` are defined and unused | Read | Open: enforce or remove |
| T0.18 | `st_blocks` is synthetic, so `du` reports logical size | Read | Open; true figure needs T2.15 |
| T0.19 | Silent 9P qid collision past 2^32 inodes | Read | Open |
| T0.20 | Device replace moves bytes without rewriting extent addresses (library only) | Read | Open |
| T0.21 | `/events` drops past 8 MiB without saying so | Read | Open |
| T0.27 | **`O_APPEND` is not atomic.** The 9P server reads the size and then writes there, so two appenders overwrite each other. The code's own comment says so | Read | Open |
| T0.28 | **Deleting an open file loses it.** I/O on an unlinked fid answers ENOENT, by design in `fid.tla`. POSIX keeps the file until the last close, and real software relies on that, including scratch files in SQLite and Python. Seen on a Thylacine guest, where `tmpfile()` has a workaround | Seen | **Decided:** keep the inode until the last clunk, on the orphan state anonymous inodes already have, and free it at mount after a crash. A file replaced by rename gets the same. `fid.tla` changes first |
| T0.29 | **Linux: the io_uring completion queue is drained by every waiting thread with no lock,** and `AUTO` picks io_uring wherever it is built. A completion can be taken twice or dispatched to the wrong thread. It may explain some of the Linux reds in T1.1, which is a hypothesis | Read | Open |
| T0.30 | **The manager's admin commands are refused.** Since `320d250` the `/ctl` admin must be named with `--admin-uid`, and the manager never names it, so snapshot create answers EACCES, and by reading so does every other admin verb behind `F9`. Two of the manager's own tests are red for this, and CI does not run them | Seen | Open |

### Security to establish, then decide

| # | Item | Evidence | Status |
|---|---|---|---|
| T0.22 | A locked dataset's cold extents can still be read: they decrypt under the pool key, with no check of the dataset's lock. Library only today, because nothing else reaches the cold tier | Read | Open |
| T0.23 | The 9P server does not check mode or owner against the client, and a create is owned by the connection's uid whatever the client asked | Read | Open: enforce, or state the model |
| T0.24 | Two copies of one volume, both written, reuse nonces. Copying a file is ordinary, and a restored backup does it too. Warn now in the manager and docs; the cure is T2.8 | Analysis | Open |

---

## Tier 1: the means to trust anything else

Build these before the big changes, since they are what will catch the big changes' bugs. T1.3 comes before T1.4 and T1.6, because they use it as their oracle.

| # | Item | Why | Size |
|---|---|---|---|
| T1.1 | Green CI: gcc break at `leaf.c:113`, Linux fault counters, `test_rc3_concurrent`, `test_slate_socket` (use-after-free under ASan, SEGV under TSan), `test_fs_frag`, `test_corvus_mount`, 11 TSan families in `test_compound_ops_concurrent`. None of these sanitizer results has been triaged, so real or test-only is unknown | Red since April. Nothing else is believable until it is green | L |
| T1.2 | Manager in CI on Linux too; sanitizers on a schedule, including legs that have no sanitizer result yet because a budget cut them off | The spec claims Linux, and CI only runs macOS | S |
| T1.3 | `stratum check`: read-only full walk and cross-checks: allocator against references, nlink, dirent against inode, reachability and cycles, dead lists, the bootstrap bitmap | No fsck exists. Peers have `zdb`, `btrfs check` and `fsck.bcachefs` | L |
| T1.4 | Crash harness: record writes and barriers, replay every barrier prefix, drop and reorder inside each barrier, mount, check, assert every acknowledged `fsync` | The strongest test a filesystem can have. Fault injection exists; this does not | L |
| T1.5 | Fuzz targets for uberblock, node, extent, dirent, keyfile, 9P and send decoding. `STM_BUILD_FUZZERS` builds nothing today | A filesystem that opens a stranger's container parses hostile input | M |
| T1.6 | xfstests through v9fs on Linux, plus an fsx and fsstress soak with `stratum check` at the end | No outside test suite has ever run against Stratum | M |
| T1.7 | All 191 TLA+ configurations on a schedule; CI runs 12 | Models that do not run stop meaning anything | S |
| T1.8 | Repair the models: `sync.tla`'s `NonceUnique` cannot fail, and `merkle.tla` assumes the uberblock is untouched | A check that cannot fail proves nothing | S |
| T1.9 | Model what has none: seal and tombstone sentinels, cold CAS links, mini-consolidation, engine splits, spill chains, the dataset mutex read path | These are the hardest code in the tree, and rest on prose | L |
| T1.10 | Benchmarks against ext4, btrfs and ZFS on one Linux machine: fio profiles with latency percentiles, small files, mount time, memory | Every SOTA claim here is unmeasured, and tier 3 needs the numbers | M |
| T1.11 | Refresh or delete stale documents: `ARCHITECTURE.md`, `ROADMAP.md`, `reference/` | They contradict the code in places | M |

---

## Tier 2: changes to the format

**The format is not frozen and no pool has to survive.** So until the freeze (T6.1) a format change has no upgrade path: a mount refuses any other version, by name, and the remedy is a new pool. That lets these land one at a time, which is easier to audit and to bisect than one large break. They still need designing together, because several want the same bytes: T2.5 and T2.8 in the block pointer, T2.6 and T2.7 in the extent record.

| # | Change | What it brings | Size | Call |
|---|---|---|---|---|
| T2.1 | All trees on the engine, with real node merge | Removes fragmentation, the whole-allocator rewrite and the caps. **Decided** | XL | Do |
| T2.2 | Unbounded dead lists | **Decided**, on branch, with findings from its last audit round still open | L | Do |
| T2.3 | Parent stored in a directory inode | Cycle check O(depth), not O(subtree) | S | Do |
| T2.4 | **Metadata space that grows.** 7 GiB at most, fixed at format, and 256 MiB by default gives under 1M files. Peers allocate metadata from the same space as data | Removes the hard wall in the bar's item 7 | L | Do |
| T2.5 | **Second copy of every metadata node.** One bad node is unrepairable today, whereas ZFS and btrfs keep two copies by default. The block pointer has 8 spare bytes | The bar's item 7. T2.8 may want the same bytes | L | Do |
| T2.6 | **Tag in the extent record, not after the ciphertext.** A 4 KiB write takes two blocks today. ZFS keeps its MAC in the block pointer | One block per 4 KiB, half the small-file space, and the Merkle chain reaches data content | M | Do |
| T2.7 | **Smaller sealing units.** A whole extent up to 8 MiB is verified on every read, so a 4 KiB random read can cost 8 MiB. ZFS's default record is 128 KiB | Random read speed, read amplification | M | Do |
| T2.8 | **Nonces that survive a forked image** (T0.24): a per-history value in the nonce or the key derivation | Closes the most realistic attack for a container file. AEGIS is not misuse-resistant | M | Do |
| T2.9 | **Key schema and uberblock authenticated** under a pool-derived key, checked just after unlock; key state in the associated data | Stops reinstating a retired key and rewriting keyless structures | M | Do |
| T2.10 | Authenticated wrap | Today, holding the public wrap key is enough to forge a pool | M | Do |
| T2.11 | **Key slots inside the volume,** as LUKS has: several unlock methods, a passphrase alone can open, change and revoke without touching data, header backup | The container's biggest usability gap (T5.1, T5.2) | M | Do |
| T2.12 | **Keyed directory hash.** FNV-1a is unkeyed and the probe chain is 64, so by analysis, unchecked, names chosen to collide can make a create answer ENOSPC | Removes a denial of service by crafted names | S | Do |
| T2.13 | Long symlinks: 100 bytes breaks real software, where peers take about 4 KiB | POSIX | S | Do |
| T2.14 | Inodes and dirents that return their space: a stored generation for reuse, tombstones removed. Today `rm -rf` returns only extent nodes, so the inode ceiling is a high-water mark | Needed for T2.1's merge to pay fully | M | Do, after T2.1 |
| T2.15 | Per-inode allocated blocks, per-snapshot used and referenced | True `st_blocks`, `du` and snapshot accounting | M | Do |
| T2.16 | The intent log's root and uberblock field | Part of T3.3 | S | With T3.3 |
| T2.17 | Seal or drop the uberblock's plaintext counters, and retire dead fields (`si_xattr_count`, `ub_flags_*`, the mirror slot) | Less for a disk reader to learn, less to carry | S | Do |
| T2.18 | Per-dataset metadata keys. Names and sizes sit under the pool key today, where ZFS uses the dataset's | Real separation between datasets, at the cost of cross-dataset dedup's simplicity | L | Later, before the freeze |
| T2.19 | Hide that a container is one: no magic, nothing in the clear | VeraCrypt's property. It conflicts with plaintext uberblocks and a pre-unlock key schema | XL | No |

---

## Tier 3: below the state of the art, no format change

Measure each one with T1.10 first and again afterwards.

| # | Item | Peers | Size |
|---|---|---|---|
| T3.1 | **Periodic commit.** Data with no later `fsync` is lost in a crash however old it is, and the clean-commit skip makes an idle timer free | ZFS 5 s, btrfs 30 s | S |
| T3.2 | **Reads stop taking the dataset mutex.** It is held through device writes, so metadata reads wait during that phase of every commit. Resolve the engine through epochs instead, which also makes the lockless claim true at the filesystem level | | M |
| T3.3 | **Intent log for `fsync`,** with per-file sync. A commit is two barriers and about 212 KiB, and fsync-heavy software such as databases pays that each time. Needs T2.16 | ZIL, btrfs log tree, bcachefs journal | XL |
| T3.4 | **Commit without stopping writers.** `fs->global` is held exclusively across the drain and the commit; open and syncing generations should overlap | ZFS txg stages | XL |
| T3.5 | **No deep clone per commit.** Each open engine's resident tree is cloned on every commit, even clean. Copy only the path that changes, and skip clean engines | | M |
| T3.6 | **Node eviction,** so resident memory stops growing with touched metadata | ARC, page cache | L |
| T3.7 | **Mount without the walk.** First stop re-reading shared subtrees per snapshot, using birth generations. Then record what a crash could orphan, so a clean mount walks nothing | ZFS, btrfs | S, then M |
| T3.8 | **Allocator:** by-size index and regions in place of first-fit from the start of the device; statistics kept incrementally rather than O(entries) per commit | Metaslabs, block groups | L |
| T3.9 | **Epochs per pool, and no pin across device I/O.** One stalled reader stops all reclamation process-wide | | M |
| T3.10 | Writer contention: the global dirty-buffer mutex, then the single chain head | | M, then L |
| T3.11 | **Fail like a peer.** Lack of room refuses the operation and keeps the pool. A real I/O failure goes read-only and stays readable (T0.6) | btrfs goes read-only, ZFS suspends | M |
| T3.12 | **TRIM.** `stm_bdev_discard` exists and nothing calls it. It also lets a volume file shrink and reduces leftover ciphertext | fstrim, autotrim | M |
| T3.13 | Engine: rightmost split for ascending inserts; flush the heaviest child, not the whole buffer | | S |
| T3.14 | Data that cannot find contiguous space gets split instead of refused; evacuation above 4 MiB | Gang blocks, copygc | M |
| T3.18 | A directory scan holds the whole dirent index mutex, so one large directory can stall every namespace writer for seconds | | M |
| T3.19 | An overwrite on the direct path costs O(allocator records), because a reserve invalidates the accelerators and a lookup rebuilds them. Fix before database workloads | | M |
| T3.20 | Freeing N metadata nodes costs O(N squared) at the bootstrap pool | | S |
| T3.21 | Full-pool and failure paths, with T3.11: partial truncate on a full pool answers ENOSPC, a failed drain write's spend has no reclaim path, a truncate freeing only cold records waits for an outside commit, 22 rollbacks ignore a failed allocator free | | M |

### Tier 3b: complexity that has not paid

The project's rule is that complexity must earn its place. After T1.10, keep each of these only on the numbers:

| # | Item | Today |
|---|---|---|
| T3.15 | B-epsilon messages | Measured 1.0-2.0x fewer node writes, against a 20-50x target |
| T3.16 | Elias-Fano and xor filters over the allocator | Serve lookups and containment only, never free-space search |
| T3.17 | Content-defined chunking at an 8 MiB average | An extent is at most 8 MiB, so few chunks result |

---

## Tier 4: features peers have

| # | Item | Size |
|---|---|---|
| T4.1 | **Real scrub:** metadata, data and cold; runs in the daemon; repairs from replicas once they exist; can be scheduled. **First fix two defects in its repair:** it rewrites a replica with no re-check, so it can overwrite a block since reissued to another file, and it treats a transient error as unrepairable. They are harmless only because nothing steps scrub today | L |
| T4.2 | **Compression,** zstd and lz4, with the length leak stated. The format reserves a byte | M |
| T4.3 | **Multi-device made Available:** mirror, replace, reconstruction, metadata beyond device 0, a `/ctl` path | XL |
| T4.4 | **Send and receive made real:** names, metadata, deletes, raw encrypted streams, a front end. Also: a record moved by collapse or insert is left out of an incremental, and a send holds no snapshot, so it can lose its source | L |
| T4.5 | **Clones made real:** destroy, promote, snapshot of a clone, a front end | M |
| T4.6 | Key management: wrap-key and pool-key rotation, re-encryption, DEK rotation front end, hardware tokens | L |
| T4.7 | Range reflink: partial, non-empty destination, `copy_file_range` | M |
| T4.8 | Blocking locks with deadlock detection; persistent holds through a crash; a lock poll scans every record under the global lock; one raw session can use up the lock table | M |
| T4.9 | `SEEK_HOLE` and `SEEK_DATA`, whole-range `fallocate` punch, relatime | S |
| T4.10 | Enforced quotas (T0.17) | M |
| T4.11 | ACLs; device nodes, FIFOs and sockets | M |
| T4.12 | 9P reach for what is library only: seals, file handles, `O_TMPFILE`, `EXCHANGE`, `WHITEOUT` | S |
| T4.13 | `/ctl` verbs for datasets, properties, devices and tiering | M |
| T4.14 | Small semantics: a failed create can leave the name linked, timestamps can skip under contention, a gid of -1 is stored as given | S |

---

## Tier 5: the encrypted container

Stratum as a modern alternative to VeraCrypt: a file-based volume and a manager to copy in and out.

| # | Item | Size |
|---|---|---|
| T5.1 | A passphrase alone opens a volume, one file with no keyfile beside it. A keyfile stays as an optional second factor. Needs T2.11 | M |
| T5.2 | Change passphrase, several slots, header backup and restore. Needs T2.11 | M |
| T5.3 | Move and rename in the manager; the three "Coming soon" panes built or removed | M |
| T5.4 | Copies keep mode, mtime and symlinks | S |
| T5.5 | A large copy makes one commit per batch, not one per item, still durable when it reports success | S |
| T5.6 | Mount as a drive: FUSE on Linux and macOS, or a loopback NFS server. Decide which | L |
| T5.7 | Key hygiene in the `stratum` binary: all key material in locked memory, core dumps off. Today the daemon's mounts lock on a best-effort basis, and only `janusd` turns off core dumps | S |
| T5.8 | Warn on rollback: remember the highest generation beside the keyfile or in the recents, and say so when a volume comes back older | S |
| T5.9 | A fully static binary (libsodium links dynamically today) and a post-quantum build as the default package | S |
| T5.10 | Remove `tui/`, `tools/stratum-slate-tty` and `run.sh`'s use of them, if the decision goes that way | S |
| T5.11 | `stratum serve` with no key source answers only `run failed (rc=-22)`, and should find `<volume>.key` or say what is missing. The hint `stratum mkfs` prints has the wrong command and option form | S |

---

## Tier 6: the finish

| # | Item |
|---|---|
| T6.1 | Format freeze, a version policy, feature flags for later additions, and from then on an upgrade path, tested on stored old images |
| T6.2 | External review of the cryptography, on a written design, with the threat model's remaining items accepted or fixed |
| T6.3 | Published benchmarks, with T1.10's method |
| T6.4 | Release process: versions, signed builds, a security policy and a way to report |
| T6.5 | The licence settled: `LICENSE` says GPL-3.0, and 254 source files say ISC |

---

## Not on the road

Recommended against for now, so nobody spends a pause on them. Each can be reopened by decision.

| Item | Why not |
|---|---|
| Cipher choice | One authenticated cipher has no downgrades and fewer modes to test. Agility has cost peers more than it has given them |
| Reed-Solomon, LRC | Mirror and metadata copies first. Parity is where peers have struggled most: btrfs still warns against RAID5/6 |
| Inline dedup | Offline dedup across datasets is already the unusual part. ZFS's inline tables are its most famous cost |
| Kernel module | User space over 9P is the design, and Thylacine's model |
| TCP listener | Needs authentication designed first, and nothing asks for it |
| Windows | Terminal-first container on macOS and Linux |
| Hidden volumes | See T2.19 |

---

## The order

1. **Finish the tidy:** T0.8-T0.13, then T1.1 and T1.2, and land it.
2. **Design tier 2 together,** settling which change gets which bytes, before the first of them lands.
3. **Trust before change:** T1.3, then T1.4, T1.5, T1.6, T1.10. Cheap wins alongside: T3.1, T0.24's warning, T0.15, T0.26, T0.27, T0.29, T0.28, T5.7.
4. **The format:** T2.1 and T2.2 first, then the rest of tier 2 one at a time. T0.1, T0.3, T0.4 and T0.7 go with the first two.
5. **Then by measurement:** tier 3 in whatever order T1.10 shows matters most, starting with T3.2, T3.5 and T3.7.
6. **Then tiers 4 and 5,** interleaved by use, and **tier 6** last.

## Rules for working the list

- One item at a time, and only one that is ready: dependencies done, no open decision.
- A format change bumps the version in the same commit, and `SPECIFICATION.md` says what changed.
- See it fail first. A test that fails without the fix lands with the fix.
- Audit anything on an audit-trigger surface before it lands, per `CLAUDE.md`.
- Update `SPECIFICATION.md` and this file in the same commit: mark the item done with its commit, or move it.
- New problems go here when found, with their evidence, even when they are not being fixed yet.
