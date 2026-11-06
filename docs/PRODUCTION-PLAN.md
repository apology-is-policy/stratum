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
| Evidence | **Seen**: reproduced or measured. **Read**: read in the code, never run. **Analysis**: reasoned from the design, unchecked. **Written**: a fix exists, not yet built or not yet seen to fail without it |
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
| T0.7 | Free metadata space fragments. A Python model says writers stop with a quarter of it free. The real pool has **not** shown that: on a Pi a valid run reached 10,000 commits at 26% free with no stop, and later stops came at 1 to 3% free. A clean run of the real pool is owed | Analysis, and a partial run against it | Goes with T2.1 |
| T0.25 | A full metadata pool wedges at commit. Nothing on the write path counts node space, so it admits writes that no commit can store | Read | Open; T3.11 for the refusal, T2.4 for the room |
| T0.26 | Snapshot create answers OK before the snapshot is durable: its slot is made after the commit and no commit follows, so a crash loses a snapshot reported as made | Read | Open |

### Things that do not do what they say

| # | Item | Evidence | Status |
|---|---|---|---|
| T0.8 | Rename of a directory into its own subtree made an unreachable cycle | Seen: leg red; each part of the fix removed in turn turns its own leg red | **Fixed** `f401da2`, `cb81147`. Every directory rename takes one mutex, since a rename adds the new entry before it drops the old and a walk between them would meet the child twice. A move across parents walks the moved subtree, so it costs the subtree's entries until T2.3. The walk reads each directory once since `2a590b9`: 1,142 ms before, 2.4 ms after, on the measuring leg's tree on a Mac |
| T0.9 | Manager editor: saving a file over 64 KiB killed the manager and lost the edit. The 9P client sent a message over the negotiated size and the slate dropped the connection. This list used to say only the last chunk was kept, which was a misreading: a trace shows the file was never reached | Seen | **Fixed** `3052d46`, `f584787` |
| T0.10 | Manager editor: said Saved before writing, discarded the result, and `:wq` quit on a failed save | Read; leg green | **Fixed** `dc426bf` |
| T0.11 | Manager editor: emptying a file and saving kept the old bytes | Read; leg green | **Fixed** `3052d46` |
| T0.12 | Manager wizard: Use passphrase with an empty field made a plaintext keyfile | Read; leg green | **Fixed** `30588ba`; it also asks twice |
| T0.13 | Manager landing: panic on a non-ASCII recent path, New and Host did nothing, banner claimed post-quantum in every build | Read; leg green | **Fixed** `bb24ebc` |
| T0.14 | Scrub reports RUNNING and verifies nothing, since nothing steps it. When driven it checks hot extents and counts the rest as verified. The manager's prompt promises repair | Read | Open |
| T0.15 | `O_SYNC` and `O_DSYNC` are not consulted, and `datasync` is ignored | Read | Open |
| T0.16 | `fallocate` reserves no space, so a later write can answer ENOSPC | Read | Open |
| T0.17 | Quota is a stored property that nothing enforces. `IMMUTABLE` and `APPEND` are defined and unused | Read | Open: enforce or remove |
| T0.18 | `st_blocks` is synthetic, so `du` reports logical size | Read | Open; true figure needs T2.15 |
| T0.19 | Silent 9P qid collision past 2^32 inodes | Read | Open |
| T0.20 | Device replace moves bytes without rewriting extent addresses (library only) | Read | Open |
| T0.21 | `/events` drops past 8 MiB without saying so | Read | Open |
| T0.27 | **`O_APPEND` was not atomic.** The 9P server read the size and then wrote there, so two appenders overwrote each other. The end of file is now read under the write's own exclusive pin | Written | **Fixed** `021c41a`; red owed |
| T0.28 | **Deleting an open file loses it.** I/O on an unlinked fid answers ENOENT, by design in `fid.tla`. POSIX keeps the file until the last close, and real software relies on that, including scratch files in SQLite and Python. Seen on a Thylacine guest, where `tmpfile()` has a workaround | Seen | **Decided:** keep the inode until the last clunk, on the orphan state anonymous inodes already have, and free it at mount after a crash. A file replaced by rename gets the same. `fid.tla` changes first |
| T0.29 | **Linux: every waiting thread drained the io_uring completion queue with no lock,** and `AUTO` picks io_uring wherever it is built. One thread now holds the reaper's seat and the rest wait for it. Also a failed submit reported failed an op the kernel could still run, and short memory ended the ring silently. Three suites crashed before these fixes and all are green since. With the old reaper put back in a copy, `test_bdev`'s many-threads leg crashes 3 times in 3, and `test_rc3_concurrent` and `test_corvus_mount` crash; the fixed file passes the same legs. The old submit and the ENOMEM end each turn their own legs red | Seen: legs red | **Fixed** `75f2df4`, `ca55069`, `b0cccd6` |
| T0.30 | **The manager's admin commands were refused for six weeks.** Since `320d250` the `/ctl` admin must be named with `--admin-uid`, and the manager never named it, so every admin verb behind `F9` answered EACCES. Two of the manager's own tests were red, and CI did not run them | Seen | **Fixed** `99e6b80` |
| T0.31 | Two daemons could open one volume, each writing commits the other knew nothing of | Seen: leg red | **Fixed** `d13a1c3`: one image, one daemon, by `flock` |
| T0.32 | `mkfs` destroyed whatever was at its path, under a running daemon too, and replaced the key first. It now refuses a file holding data and a key in the way, says why, and `--force` passes the first two and never a running daemon | Read; red owed | **Fixed** `2a590b9` |
| T0.33 | A manager whose terminal closed kept running with the volume unlocked. Its input loop never returns on a dead terminal, and on macOS `tcgetattr` still answers, so a watchdog must test a write | Seen on macOS | **Fixed** `7d3a5d3`, `047ead9`, `e3f2e07`; green owed on macOS |
| T0.34 | Manager editor: a failed read opened an empty buffer that a save would write back, and bytes that are not UTF-8 were decoded lossily and could be saved. It now refuses the first and opens the second read-only | Read; leg owed green | **Fixed** `71e6a41` |
| T0.35 | A daemon that refused to start read as a wrong passphrase, after a fixed 5 s | Seen | **Fixed** `71e6a41`, `e3f2e07`: it says the daemon's own reason |
| T0.36 | A daemon told to stop waited for each client: an idle one up to the idle timeout, a talking one for ever. A stop now ends every connection's reading side, and the request in hand still finishes. A slow request can still lengthen a stop | Read; red owed | **Fixed** `cfcf51f` |
| T0.37 | A device replace retried after the old device reached EVACUATING jumped past `new_slot`'s initializer, so a success left the claim held and every later change to that slot refused until the next mount. gcc found it at `-O2`, and the route had no test | Seen by the compiler; red owed | **Fixed** `e64fd0d` |
| T0.38 | The 9P client sent a zero-length write when no whole block fit the negotiated size, which reads as success with nothing written. It is now refused. Possible only at msize 4096 to 4118 | Read | **Fixed** `3bf389b` |
| T0.39 | `/ctl`'s Rlopen gives an iounit sized for a Tread, not a Twrite. Changing it is a wire change, so it waits for a decision | Read | Open |
| T0.40 | **Esc on the manager's "Delete N items?" deleted the selection.** The batch was built before the question, so Esc, or any dialog drawn over the question, started it. A batch now starts only on Yes | Seen: leg red | **Fixed** `bc7b15d` |
| T0.41 | **A delete could not be stopped once it had started.** Esc during a batch was lost while a worker held an item. From `d1c5df5` the quit keys showed a notice instead, and its Esc closed the notice and let the batch run on through the rest of the selection. The quit keys now ask Stop or Go on, no new item starts while the question shows, though the one in hand runs on, and Esc or Stop ends the batch after it | Written | **Fixed** `d1c5df5`, `7cf7854` |
| T0.42 | **`stratum fs write` and `fs read` answered 0 after failed I/O.** A failed read of the input, or a full disk under the output, left a short file under the final name and reported success. Both now check, the size is checked on every route, and `write -n` refuses a name already there and removes only what it made | Seen: leg red | **Fixed** `e7a0d99`, `bc7b15d`, `18b5b09` |
| T0.43 | **Manager copies lost data.** Overwrite onto the same path, or into the source's own subtree, deleted the source. Overwrite removed the old destination before the new one existed. A recursive copy dropped subtrees, symlinks and failed directories and reported 0 failed. Keep both on a volume truncated the existing file. A replacement is now written beside and renamed into place, every failure is counted, and a destination inside the source is refused | Read; legs green | **Fixed** `73735f0`, `bc7b15d` |
| T0.44 | **A copy could be led to write somewhere else.** A symlink inside the destination tree let a merge write over its source, a host temporary followed a symlink planted at its name, and a failed probe read as absent, so a copy truncated or removed someone else's file. A link where a directory goes is refused, temporaries are made with `O_EXCL` and written through their own handle, and a name found in the way is refused, never replaced | Read; legs green | **Fixed** `eb7495b`, `bc7b15d` |
| T0.45 | **Names the manager could not hold acted on other files.** A control byte was listed as `?`, so `x` and a newline read as `x?` and an action reached a real sibling of that name. Enter into a directory whose name is not UTF-8 made every action target the panel's root. Names holding a newline or a tab broke `stratum fs ls`'s parsing. A host name over 255 bytes was cut to its first 255, which can be a sibling's name. Each is now listed with a stand-in, U+FFFD, that no action accepts | Read; legs green; the long-name test seen red | **Fixed** `73735f0`, `98661ea`, `d1c5df5`, `d3de156` |
| T0.46 | **The 9P client's tag counter never wrapped,** so a connection died after 65,534 requests: a long copy, or a large directory redrawn often enough, ended the manager with `Error: walk` or emptied a panel | Seen; green under the same run owed | **Fixed** `7fc5a68` |
| T0.47 | **The host panel served the wrong files.** Its path table kept the first path each file was walked by, never checked it again, and was full at 4,096 entries. Past about 4,096 files listed in a session the host panel stopped working, a renamed directory listed whatever then sat at its old name, and opening a moved file served the file now at its old name. Opening a FIFO stopped the server. Each use now checks that the stored path still leads to the same file, the newest walk replaces the name, old entries are evicted, and only regular files and directories open. A walk now also checks that the leaf is the file a checked path with no link in it names, which narrows a symlink flipped among the parent's components to a swap inside one walk (T0.61) | Seen: tests red on the old code, and each of the stale listing, the open pin, the eviction window and the cut's step back red under its own sabotage | **Fixed** `fe54c65`, and part 2 of round 6 |
| T0.48 | **Copies lost or widened modes.** A copy set the mode after the create, or not at all, so a 0600 file was readable for a while or for good. The mode now goes with the create, in `Tlcreate` and `Tmkdir`, and host temporaries are made 0600 | Read; legs green | **Fixed** `eb7495b`, `18b5b09` |
| T0.49 | **Keys could be left readable or half written.** A key generated over an existing 0644 file stayed 0644, and the path forms wrote into the existing file, so a reader holding it open saw the new key or a mix. A key is now written to a temporary file beside it, at 0600, synced and renamed into place, and a link or other non-regular file at the name is refused | Seen: each defence removed turns its own test red | **Fixed** `c9febbd`, `38fb485` |
| T0.50 | **A stop could wait for ever on a client that was not reading** (follows T0.36). The send timeout was the idle timeout, 0, which means none, and `/ctl` had no grace at all. A stop now gives writes 2 s and then shuts the connection's writing side. On macOS `shutdown(SHUT_RDWR)` after `SHUT_RD` answers ENOTCONN and wakes nothing, by measurement, so the wake is `SHUT_WR` | Seen: leg red | **Fixed** `e7a0d99`, `c05029e` |
| T0.51 | `mkfs`'s last rename replaced a name made while it ran, and followed a symlink at its path; its temporary key was not exclusive; and a device with no size, such as `/dev/zero`, was read for ever | Seen: leg red | **Fixed** `e7a0d99`, `9b4e8f8` |
| T0.52 | **Delete acted on the wrong entries.** A selection was kept as positions, so after the listing changed `F8` deleted whatever then sat at the marked rows | Read; leg green | **Fixed** `dd94ed2` |
| T0.53 | A panic in the manager left the terminal raw, with no echo, until `reset`. A panic on the UI thread now puts the terminal back before the message prints | Written | **Fixed** `da5add6` |
| T0.54 | Overwrite can replace a volume image a daemon has open, or its key: nothing checks the destination's lock | Read | Open |
| T0.55 | A bind mount inside the destination is invisible to `canonicalize`, so a merge can still be led over its own source through one. Making one needs privilege | Read | Open |
| T0.56 | A copy into a volume writes a new name in place, so a kill mid-copy leaves a short file under the final name, and temporaries behind. The cure is a rename that refuses to replace, which the 9P server does not offer: a wire change, so it waits for a decision | Read | Open |
| T0.57 | A second manager on the same volume re-keys the slate's listing, so the first one's marks can name entries it never saw. A listing token on selection writes is a slate format change | Analysis | Open |
| T0.59 | **On Thylacine, a daemon from this series would have refused every client.** It dups each connection so a stop can reach it, and Thylacine's libc answers ENOSYS to `dup` of a socket. Its wait for free descriptors was `poll` over none, which that libc answers at once, so the wait would spin. A connection that cannot be duplicated is now served, and the wait sleeps | Read in Thylacine's libc; leg written | **Fixed** `96cd7ff` |
| T0.60 | On Thylacine a stop wakes no client: `shutdown` on a `/srv` stream does nothing there, so T0.36 and T0.50 do not reach it, and a stop waits for each client to leave. The cure is a half-close for `/srv` streams in Thylacine, or a stop the server's read loop polls for beside the client | Read | Open |
| T0.61 | The host panel's walk still resolves a name from the root at each step, so a symlink among the parent's components that flips fast enough can be followed between the check and the open. A walk now refuses a leaf that is not the file its checked path names, which narrows this to a swap of a real directory for a link inside one walk. The cure is a walk that opens each component relative to its parent's descriptor with `O_NOFOLLOW`, and an open through that descriptor, which also keeps a device swapped in from ever being opened. Today's client is the same user over a 0600 socket, so nothing is gained by it | Read | Open |
| T0.62 | The host panel knows a file by device and inode only. A freed inode number reused by a new file, or two numbers that fold onto one qid past 2^32, rebinds the qid when the new file is walked, and a fid still held on the old file is then served the new one. The manager re-walks on every redraw, so it never holds such a fid today. The cure is a birth time or generation in the identity | Read | Open |
| T0.63 | A fid the host panel walked but never opened loses its name once about 2,048 newer lookups pass, and then answers ENOENT, though 9P keeps a fid usable until it is clunked. Only opened fids pin their name. The manager re-walks every redraw, so it never meets this. The cure is a pin behind every fid the 9P server binds, which needs a bind and clunk hook from the server to the backend | Read | Open |
| T0.64 | **A snapshot or scrub result could be lost, or take the Esc meant for a batch.** A second request replaced the first one's job, so its result never showed. A result arriving over a running batch's progress took the Esc that cancels the batch, which then ran on, and one arriving over a batch's summary replaced it, the only report of the items that failed. A result now replaces only its own "Working" notice or the snapshot list, and otherwise waits, while the editor is open too; a second request is refused while one is out and must be made again; a notice no key asked for waits until the batch has ended; the editor opens only once no dialog is up, and a dialog is drawn over it; what waited for the editor shows when another client closes it; a quit key with a request out asks Wait or Quit, since quitting stops the volume under it and its result would never show | Unit tests, each red under its own sabotage | **Fixed** `eeac7f2` |
| T0.65 | `dist.sh` built the shipped binary with the test hooks in it, one of which turns off a stop's tracking of connections. Nothing outside the process could set it. It now builds without them, from an empty directory each time: a kept cache kept options the script does not pass, and the manager links every archive it finds there, a stale one too | Read | **Fixed** `eeac7f2`, from empty *(pending)* |
| T0.66 | **This series broke the build without the test hooks, the build Thylacine makes.** A directory rename's walk names its pause points in every build, but their type was declared only with the hooks on, so `fs.c` did not compile with them off; every gate here builds with them on. Seen when `dist.sh` began to build without them (T0.65). The type is now declared in every build, and `dist.sh`, which CI runs on Linux and macOS, builds that way each time | Seen: dist failed; every target builds with the hooks and the tests off (dist.sh's and Thylacine's configuration) under -Werror. The tests need the hooks: a configure with the tests on and the hooks off now stops and says so | **Fixed** `4a56896` |
| T0.67 | **Dialog text cut where it mattered.** The mkfs wizard's error, the only word of why no volume was made, was one row cut at 62 columns, so a long path lost its file name and mkfs's reason lost its end; a field longer than its box showed its first rows, not the end being typed or the cursor. The error wraps and the box grows by its rows, with the buttons kept on the bottom rows; a field taller than its box shows its end | Unit tests, each red under its own sabotage | **Fixed** *(pending)* |

### Security to establish, then decide

| # | Item | Evidence | Status |
|---|---|---|---|
| T0.22 | A locked dataset's cold extents can still be read: they decrypt under the pool key, with no check of the dataset's lock. Library only today, because nothing else reaches the cold tier | Read | Open |
| T0.23 | The 9P server does not check mode or owner against the client, and a create is owned by the connection's uid whatever the client asked | Read | Open: enforce, or state the model |
| T0.24 | Two copies of one volume, both written, reuse nonces. Copying a file is ordinary, and a restored backup does it too. Warn now in the manager and docs; the cure is T2.8 | Analysis | Open |
| T0.58 | `mkfs` writes a new key through its own descriptor, but the format then reads the key back by name, so whoever can rename in the key's directory can swap it between the two | Read | Open |

---

## Tier 1: the means to trust anything else

Build these before the big changes, since they are what will catch the big changes' bugs. T1.3 comes before T1.4 and T1.6, because they use it as their oracle.

| # | Item | Why | Size |
|---|---|---|---|
| T1.1 | Green CI. Done on a machine, not yet in CI since the branch has not been pushed: `-Werror` under gcc `594e2fe`; 80 of 80 suites on Linux, arm64, gcc 14, io_uring on, at `71e6a41`; the five fault suites read injection through the facade `93dd9c3`; the two hanging client suites were a test's own bug `b969b52`. Owed: the sanitizer legs, none of which has been triaged: `test_rc3_concurrent`, `test_slate_socket` (use-after-free under ASan, SEGV under TSan), `test_fs_frag`, `test_corvus_mount`, 11 TSan families in `test_compound_ops_concurrent` | Red since April. Nothing else is believable until it is green | L |
| T1.2 | Manager in CI on Linux too, building `dist.sh`, whose optimized gcc build is what caught T0.37. It never linked on Linux before `1f06b6c`. **Written** `f8f99b2`: the manager job runs on Linux and macOS and plays the keys; not yet run in CI. Owed: sanitizers on a schedule, including legs that have no sanitizer result yet because a budget cut them off | The spec claims Linux, and CI only ran macOS | S |
| T1.3 | `stratum check`: read-only full walk and cross-checks: allocator against references, nlink, dirent against inode, reachability and cycles, dead lists, the bootstrap bitmap | No fsck exists. Peers have `zdb`, `btrfs check` and `fsck.bcachefs` | L |
| T1.4 | Crash harness: record writes and barriers, replay every barrier prefix, drop and reorder inside each barrier, mount, check, assert every acknowledged `fsync` | The strongest test a filesystem can have. Fault injection exists; this does not | L |
| T1.5 | Fuzz targets for uberblock, node, extent, dirent, keyfile, 9P and send decoding. `STM_BUILD_FUZZERS` builds nothing today | A filesystem that opens a stranger's container parses hostile input | M |
| T1.6 | xfstests through v9fs on Linux, plus an fsx and fsstress soak with `stratum check` at the end | No outside test suite has ever run against Stratum | M |
| T1.7 | All 191 TLA+ configurations on a schedule; CI runs 12 | Models that do not run stop meaning anything | S |
| T1.8 | Repair the models: `sync.tla`'s `NonceUnique` cannot fail, and `merkle.tla` assumes the uberblock is untouched | A check that cannot fail proves nothing | S |
| T1.9 | Model what has none: seal and tombstone sentinels, cold CAS links, mini-consolidation, engine splits, spill chains, the dataset mutex read path | These are the hardest code in the tree, and rest on prose | L |
| T1.10 | Benchmarks against ext4, btrfs and ZFS on one Linux machine: fio profiles with latency percentiles, small files, mount time, memory | Every SOTA claim here is unmeasured, and tier 3 needs the numbers | M |
| T1.11 | Refresh or delete stale documents: `ARCHITECTURE.md`, `ROADMAP.md`, `reference/` | They contradict the code in places | M |
| T1.12 | Read the 260 `(void)` casts over results gcc would warn about, which the build silences with `-Wno-unused-result` | Each one drops an error on purpose or by accident, and nobody has looked | M |

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
| T5.4 | Copies keep mtime, symlinks and extended attributes. The mode is kept since `eb7495b` and `18b5b09` | S |
| T5.5 | A large copy makes one commit per batch, not one per item, still durable when it reports success | S |
| T5.6 | Mount as a drive: FUSE on Linux and macOS, or a loopback NFS server. Decide which | L |
| T5.7 | Key hygiene in the `stratum` binary: all key material in locked memory, core dumps off. Today the daemon's mounts lock on a best-effort basis, and only `janusd` turns off core dumps | S |
| T5.8 | Warn on rollback: remember the highest generation beside the keyfile or in the recents, and say so when a volume comes back older | S |
| T5.9 | A fully static binary (libsodium links dynamically today) and a post-quantum build as the default package | S |
| T5.10 | Remove `tui/`, `tools/stratum-slate-tty` and `run.sh`'s use of them, if the decision goes that way | S |
| T5.11 | `stratum serve` with no key source answered only `run failed (rc=-22)`. It now finds `<volume>.key` or says what is missing | **Fixed** `5b1d083` |
| T5.12 | The daemons outlived the manager, so a killed manager left the volume unlocked. They now stop when it does, however it ends: `4460db3`, `f440879`. **Fixed.** A `SIGKILL` of the manager still leaves its session directory behind | S |
| T5.13 | Panels list in the backend's order, which on ext4 is hash order. Sort by name | S |
| T5.14 | Say when marks are dropped. A changed listing clears them without a word today; the delete question names the one entry left and defaults to No | S |
| T5.15 | A failed probe of a destination name reads as absent. The create that follows refuses, so nothing is lost, but the reason given is wrong. Probe with three outcomes | S |
| T5.16 | The manager starts a daemon on the UI thread, which can wait up to 60 s with `TERM` masked. Start it on a worker and show progress | S |
| T5.17 | A daemon waiting out EMFILE logs nothing, so the wait looks like a hang | S |

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

1. **Finish the tidy:** T0.8-T0.13, T0.29-T0.38, T0.40-T0.53 and T0.59, then T1.1 and T1.2, and land it.
2. **Design tier 2 together,** settling which change gets which bytes, before the first of them lands.
3. **Trust before change:** T1.3, then T1.4, T1.5, T1.6, T1.10. Cheap wins alongside: T3.1, T0.24's warning, T0.15, T0.26, T0.28, T5.7.
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
