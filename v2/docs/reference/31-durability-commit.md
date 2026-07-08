# 31 — Durability + the commit path

As-built reference for Stratum's durability machinery: the transaction commit
(`stm_sync_commit`), the write-ordering barriers, the redundant-superblock
torn-write defense, the block-device flush primitive, and crash consistency.
Written for **Stratum Stabilization Area G** (durability under load:
commit / sync / fsync). Companion to `07-sb-sync.md` (superblock + sync state)
and `28-bdev-error-recovery.md` (the bdev failed-latch + recovery).

---

## 31.1 Purpose

A Stratum commit makes every in-RAM mutation since the last commit **durable
and atomic**: after a power loss at any instant, a remount observes either the
full prior committed state or the full new committed state — never a torn mix.
The 9P `Tsync` (and a clean unmount) map to a pool-wide commit; there is no
per-file fsync at v1.0 (31.6).

Two properties define correctness (both proven by `tests/test_durability.c`):

- **Durability** — a committed write is present + byte-exact after a crash.
- **Atomicity** — an uncommitted write rolls back; a power-cut at any point in
  a commit leaves exactly the old XOR exactly the new content.

---

## 31.2 The commit path — `stm_sync_commit` (`src/sync/sync.c`)

The commit is a **two-phase, copy-on-write checkpoint** (the fresh-pool case
collapses to one phase) with **exactly two durability barriers** (CF-4 B,
`docs/cf-4-design.md`). Sequence for an established pool (`auth_gen > 0`),
target gen `G = auth + 2`:

1. **Build the reservation prototype** (`reservation_gen = auth + 1`) — a copy
   of the previous authoritative uberblock with the gen bumped (content from
   the pre-flush mirrors, which phase 2 never mutates). Written in step 5.
2. **Arm the CF-4 B defer windows**: the bdev barrier-defer window on every
   pool device (fsyncs record "pending" instead of flushing) + the bootstrap
   commit-defer window on every attached alloc's bootstrap (the per-component
   `stm_bootstrap_commit` calls RECORD instead of COWing).
3. **Flush all metadata** at `G` (unchanged content + order):
   - keyschema commit
   - CAS auto-GC sweep (frees expired content-addressed entries)
   - per-device alloc commit (writes the allocator tree; its internal
     bootstrap commit records into the window)
   - alloc-roots, per-dataset M-engine cascade flush (inode / dirent / xattr /
     extent records — folded into `main_csum` since v30), dataset / snapshot /
     CAS / repair-log index commits.
4. **Merkle root + the final-UB prototype + the clean check** — if the
   would-be final UB is content-identical (mod `ub_gen`/`ub_txg`/
   `ub_repair_log_root_gen`) to the last UB this session durably wrote, the
   commit returns `STM_OK` **writing nothing**: no reservation, no COW, no
   barrier, gens unchanged (31.2.1).
5. **Reservation UB write** to every device under quorum (fsyncs deferred).
   This is the **rollback target** if the rest of the commit fails.
6. **The staged bootstrap COW** — ONE (bitmap, header) slot-pair write per
   bootstrap into the NON-live slots (`stm_bootstrap_commit_defer_stage`;
   fsyncs deferred; no in-RAM promotion yet).
7. **THE data barrier** — `stm_bdev_barrier_defer_end` per device: one real
   flush that makes the reservation + the staged pair + every phase-3 node
   write durable, strictly before the final UB write. Then the staged
   bootstrap state promotes (`_defer_finalize`: live-slot swap + pending
   sweep + dirty-taint clear).
8. **The commit point** — write the final UB at gen `G` to every device +
   **fsync** (`stm_sb_label_write` → `stm_bdev_write` + `stm_bdev_fsync`,
   real — the window is disarmed), under quorum.
9. **Post-commit** — engines finalize; advance the in-RAM `auth_gen` /
   `current_gen` / root pointers under `s->lock`; stash the final prototype
   for the next commit's clean check.

Every error exit inside the armed region routes through one ladder that
cancels both defer layers **without issuing barriers** — fail-closed: the
final UB never landed, COW discipline keeps the auth state intact, and the
fs wedges per R154 wherever an engine flushed. The bootstrap cancel keeps
the dirty taint and never promotes, so a retry re-COWs into the same
still-non-live pair (regression: `sync_cf4b_inject_fail_then_retry`, an
injected-failure sweep over every device op with in-process retries).

The durability hinge is the ordering **{all data + bitmap + header +
reservation durable} → {final UB durable}** — one barrier instead of ~8,
same invariant:

- Crash before the barrier → any SUBSET of the un-barriered writes may be
  durable: new nodes are unreferenced COW blocks; the staged bootstrap pair
  is torn-detected by the header's bitmap csum (open falls back to the live
  pair — R7a); a whole staged pair mounted with the old UB is the bounded
  case-A leak; the reservation is self-csummed and content-equals the auth
  UB. Every combination mounts to the auth state.
- Crash after the barrier, before the final UB → the previous authoritative
  UB is still the highest-gen valid one; the new metadata nodes are
  unreferenced garbage, reclaimed by the next mount's mark-and-sweep.
- Crash after the final UB fsync → the new tree is live; every node it
  references was made durable at the barrier.

### 31.2.1 The clean-commit short-circuit

`stm_sync` stashes the shared (device-0-normalized) prototype of the last UB
it durably wrote. A commit whose would-be prototype is byte-identical outside
three masked fields — `ub_gen` + `ub_txg` (the monotone counters) and
`ub_repair_log_root_gen` (stamped `target_gen` unconditionally; informational
— repair-log nodes are plaintext, the gen is never validated or used as a
nonce at mount) — skips ALL I/O and does NOT advance gens (in-RAM auth state
keeps equaling durable state). Structural consequence: any durable-relevant
activity (a tree write, a CAS-GC/PENDING sweep via the alloc tree, a roster
change, a scrub-cursor push) changes a compared byte and defeats the skip —
no flag plumbing. One deliberate composition delta (CF-4 B audit F2): the
BOOTSTRAP-tier pending sweep is invisible to the UB (the bootstrap is
self-rooted), so a commit whose only pending work is sweeping the previous
commit's node retires IS skipped — those bits stay conservatively SET
(never re-handed) until the next UB-dirty commit or the next mount's #791
reconcile. Delay-only, bounded, self-healing. The stash starts invalid at
open, so a session's first commit always writes. Deliberate semantics
change: gen-age is now REAL-commit count (a quiescent pool does not age;
the CAS `min_age_txgs` policy ages with activity) — and a caller of the
raw `stm_fs_free`/`stm_alloc_free` API who stamps `free_gen ==
current_gen` on an otherwise-quiescent pool defers that free's durability
to the next mutating commit (gens frozen ⇒ the strict-less-than sweep
never fires; no production path does this — every in-tree free rides
dirt or stamps `auth_gen`). The engine pending windows opened by the flush
are closed by FINALIZE on the clean path (a clean engine flush keeps its
prior root triple; abort would drop the resident memtree).

A failed `stm_sync_commit` **wedges** the fs (`stm_fs_commit`, R154 P2-1): the
inode engine's three-phase abort drops the in-RAM tree, so an in-process retry
would silently commit the reverted-to-previous-durable state. The wedge refuses
the retry with `STM_EWEDGED` (regression: `test_crash_inject.c::r154_*`).

### 31.2.2 Deferred block reclaim + reclaim-on-ENOSPC (CF-4 C)

An extent unlink / rmdir / overwriting-rename / truncate-shrink frees the
file's data blocks: the free stamps each block `free_gen = current_gen = G`
and moves it to the allocator's PENDING list (refcount 0). The sweep that
returns PENDING to FREE runs inside `stm_alloc_commit` under the strict
`free_gen < committed_gen` predicate (R50 P2-1 crash-safety — a freed block is
reusable only once a generation ≥ G is durable). So reclaiming G within a
session needs a commit at a gen > G.

Pre-CF-4-C, the three inode-*free* paths (`fs_unlink_inode_and_dirent`,
`stm_fs_unlink_anon`, `stm_fs_rename` overwrite) fired an eager **double-commit**
(`fs_post_inode_free_reclaim_locked`) at unlink to reclaim immediately — one
commit to make UB-gen-G durable, a second at G+2 to sweep. That was **the**
cost of the go-build `$WORK` cleanup: 222 extent unlinks = 444 commits, 3.2 s
(Thylacine #374). truncate-shrink and COW-overwrite already DEFERRED (no eager
reclaim), so the eager double-commit was the inconsistent special case, and
there was no reclaim-on-ENOSPC backstop anywhere (truncate/overwrite-then-
rewrite near-full-no-commit was a latent ENOSPC gap).

CF-4 C removes the eager double-commit and defers all three: freed blocks stay
PENDING (crash-safe — #791 mount reconcile rebuilds `pending_head`; any later
commit's sweep reclaims), returning to FREE either **lazily** at the next
commit (which rides a commit that was happening anyway) or **on demand** via a
reserve-path backstop. `fs_reclaim_on_enospc_locked`: when a data reserve
returns `STM_ENOSPC` and `stm_sync_pending_free_blocks(fs->sync) > 0`, it fires
the double-commit (sweeping the deferred PENDING) and the caller retries the
reserve once. Gated on pending > 0 + retried at most once ⇒ loop-free (a
still-ENOSPC retry is a genuinely-full pool). Wired at every data-reserve
choke: `fs_flush_ino_locked` / `fs_flush_all_locked` (the buffer drain — covers
buffered writes + the pre-flush of reflink/cfr/migrate/promote/truncate + the
commit flush), the direct `stm_fs_write` paths, the inline→extent transitions,
and the migrate/promote tier reserves. (reflink + cfr share existing blocks —
no new data reserve — so need no backstop. `stm_fs_reserve` — the raw
data-reserve API, test-only, no production caller — is also wrapped for
uniformity, CF-4 C audit F1.) A failed reclaim commit is crash-equivalent ⇒ it
wedges in place (`fs_mark_wedged_locked`, a monotone release-store safe under
either lock mode). NOTE that metadata and data draw from **disjoint** pools
(B-tree engine nodes + the alloc-tree's own COW nodes come from the bootstrap
bitmap via `stm_bootstrap_reserve`; only file-data extents come from the data
`stm_alloc_reserve`), so a data-full pool holding deferred DATA pending can
never starve a metadata commit's engine flush — the fsync path cannot wedge on
deferred data (CF-4 C audit, the withdrawn concern).

fsync-ENOSPC durability nuance (CF-4 C audit F2): the flush-internal reclaim
pops+commits successfully-drained runs before it retries, so a `stm_fs_commit`
that still returns `STM_ENOSPC` (a genuinely-full pool) leaves the
drained-so-far runs **durable** — a torn-partial file (si_size set at
write-time, only part of the extents durable → sparse holes past the drained
prefix) is exposed on a crash after such a failed fsync. This is POSIX-legal
(a failed fsync grants no durability guarantee) and is a deliberate consequence
of moving the reclaim into the drain; pre-CF-4-C a flush-ENOSPC committed
nothing (the buffer stayed intact for retry).

Deliberate semantics change (documented, POSIX-correct): unlink no longer
commits, so it is no longer durable-without-fsync and no longer advances the
generation — aligned with every other lazy-durable mutation and with 31.2.1's
"gen-age = real-commit count". Freed space is visible in
`stm_fs_stats.data_pending_blocks` longer (the ZFS `freeing` shape). The
double-commit runs under whatever `fs->global` mode the reserving op holds (SH
for the per-inode write/truncate/migrate/promote paths, EX for commit) — the
SAME posture the pre-CF-4-C eager reclaim had on the SH-held unlink path, moved
onto the rare ENOSPC path. Design: `docs/cf-4c-design.md`. SOTA parallels:
Btrfs pinned-extents + delayed-refs + `flush_space`→`COMMIT_TRANS`; ZFS
`ms_defer` 2-txg deferral + `async_destroy`; WAFL consistency-point deferral.

---

## 31.3 The superblock — redundancy + torn-write defense (`src/sb/mount.c`)

- **Layout:** `STM_LABELS_PER_DEVICE = 4` labels × `STM_UB_SLOTS_PER_LABEL = 63`
  commit-ring slots = **252 uberblock copies per device**. Labels 0/1 sit at
  the device head (offsets 0 / 256 KiB); labels 2/3 at the tail — localized so
  a controller scribble / firmware rewrite / cable-induced torn write cannot
  destroy all copies.
- **Ring rotation:** `slot = gen % 63`. A commit never overwrites the
  most-recent-prior UB until a full ring cycle (252 commits), so the prior
  durable state always survives a single torn UB write.
- **Selection (`stm_sb_mount_scan`):** scan all 4×63 slots, decode each
  (a BLAKE3 csum mismatch = torn/partial → skipped), pick the **highest valid
  `ub_gen`**. A torn final UB fails its MAC and is skipped, so mount falls back
  to the prior gen automatically.

The generation counter is monotonic (each commit bumps by 2 for an established
pool); the MAC over the encoded UB rejects any partial write. Together these
give torn-write recovery without a separate journal.

---

## 31.4 Write-ordering barriers (the bdev flush primitive)

Every durability barrier is `stm_bdev_fsync`. Since CF-4 B a dirty commit
issues exactly **two real barriers per device**: the pre-final-UB data
barrier (`stm_bdev_barrier_defer_end` — covering the reservation UB, the
staged bootstrap pair, and every phase-3 node write) and the final-UB fsync
(`stm_sb_label_write`). All intermediate fsyncs issued inside the commit's
armed window (bootstrap COW fsyncs, reservation-UB fsyncs) are recorded and
folded into the data barrier; a clean commit issues zero. Outside a commit
(`stm_sync_mirror_write`, `stm_sync_evacuation_step`, mount/format) fsyncs
are immediate as before — the window is armed only inside `stm_sync_commit`,
under the same lock envelope that excludes every other fsync caller. The
barrier's strength is the backend's:

### POSIX backend (`src/block/posix.c`) — host tests

`op_fsync` issues a real `fsync(2)` (or `F_FULLFSYNC` on macOS, which flushes
the disk cache — `fsync` alone does not on macOS). So the host test suite +
`test_durability` exercise true barriers.

### Thylacine backend (`src/block/bdev_thylacine.c`) — on-device (guest)

The in-guest virtio-blk driver. **Area G made durability self-contained:**

- **Negotiation (`init_device`):** if the device offers `VIRTIO_BLK_F_FLUSH`
  (feature bit 9, bank 0 — QEMU's virtio-blk always does), the driver accepts
  it and records `flush_supported`. It never requests a feature the device did
  not offer, so `FEATURES_OK` cannot be refused on the driver's account.
- **`op_fsync`:** when `flush_supported`, issue a `VIRTIO_BLK_T_FLUSH` request
  (a header→status descriptor chain with no data buffer: `desc[0].next` is
  repointed from 1 to 2 for the flush, restored to 1 by the next read/write),
  driven through the same `do_request` path as read/write — so a transient
  flush hiccup self-heals via the Area-F bounded reinit recovery. When the
  device offers no cache (`!flush_supported`), every completed write is already
  durable and `op_fsync` is a no-op.

Before Area G, `op_fsync` was an unconditional no-op whose correctness depended
entirely on the launch attaching the drives `cache=writethrough` (run-vm.sh).
Under a `cache=writeback` backing store that no-op would silently lose committed
writes on a host crash (RW-8 R4-F3). The FLUSH negotiation removes that coupling:
durability now rests on the on-device flush, not the launch flag — and a device
that genuinely offers no cache still works (the no-op is correct there).

---

## 31.5 Crash detection + recovery

There is **no persistent dirty/wedged flag on disk.** Instead:

- The `wedged` flag is in-RAM (`atomic`, set by `stm_fs_mark_wedged`), cleared
  on every fresh mount. It refuses writes/commits after an unrecoverable
  failure within a session; a crash simply drops it.
- Crash recovery is **mount-time mark-and-sweep** (`src/bootstrap/pool.c`):
  the mount walks every reachable tree from the selected UB, marks live nodes,
  and frees orphaned allocations left by a crashed mid-commit. The freed bits
  become durable on the next commit. Bounded at ~9 nodes/boot.

So a crash mid-commit costs at most a bounded leak of unreferenced metadata
nodes, reclaimed on the next remount + commit — never a torn or unmountable
tree (within the single-torn-write envelope the 252-UB + dual-bitmap/header
redundancy guarantees).

---

## 31.6 fsync / Tsync semantics

`h_sync` (`src/9p/server.c`) maps `Tsync` → `stm_fs_commit` → a full pool-wide
commit. There is **no per-file fsync**: an extent write is durable only after a
pool commit. A clean unmount (`stm_fs_unmount`) performs a final commit unless
the fs is read-only or wedged.

---

## 31.7 Throughput characterization (Area G bench)

`tests/bench_commit.c` measures the durable write+commit cycle (per-commit
device I/O via the `stm_bdev_io_stats` POSIX counter). Measured (256 MiB pool,
AEAD on; macOS `F_FULLFSYNC` host, so absolute commits/s reflects the host's
disk-cache-flush latency — the *structural* per-commit costs are
host-independent). BEFORE = pre-CF-4-B, AFTER = as-built:

| Scenario | fsyncs/c (before → after) | dev-KiB/c | us/commit | write-amp |
|---|---|---|---|---|
| empty (nothing dirty) | 6 → **0** | 128 → **0** | 19,756 → **13.6** | — |
| metadata (reserve) | 8 → **2** | 444 → 324 | 36,081 → 19,489 | — |
| data-4k | 10 → **2** | 652 → 472 | 51,324 → 27,732 | 163× → **118×** |
| data-64k | 10 → **2** | 712 → 532 | 48,149 → 27,250 | 11× → 8.3× |

In-guest (Thylacine fsbench, write+fsync per 4-KiB file): **39 → 340
files/s** (2,933 us/durable-file).

**The two Area-G findings this table used to carry are CLOSED by CF-4 B**
(`docs/cf-4-design.md`): the clean-commit short-circuit landed (31.2.1 —
including the CAS-GC/PENDING-sweep accounting, which falls out structurally
from the prototype comparison), and barrier batching landed (31.2/31.4: one
data barrier + one UB barrier). Remaining per-commit debt, tracked:

- **Metadata re-COW density.** ~470 KiB of metadata re-COW per 4-KiB data
  sync (118× write-amp) — the Area-S S-2 metadata-density axis, untouched by
  barrier work.
- **The per-engine O(resident) flush cycle.** `commit_engines_flush` walks
  every open engine's resident tree per commit even when clean (clone +
  consolidate + EBR retire; ~24 ms CPU at 500K resident keys — the chunk-11
  datum). CPU-only: a clean engine keeps its prior root triple, so the
  top-level skip already zeroes the I/O. A per-engine dirtiness skip is a
  wrong-skip-loses-acked-data hazard class (R174-F1 lineage), so it lands
  only on a provably-sound mutation-counter choke point — the named seam in
  cf-4-design.md §6.1.

The FLUSH negotiation (31.4) is also a throughput *enabler*: it lets the launch
use `cache=writeback` (writes batch in the device cache; only the 2 fsyncs
become real barriers) instead of `cache=writethrough` (every write a synchronous
barrier). That default-posture change is a separate decision (surfaced with
measured data), not part of the FLUSH-correctness fix.

---

## 31.8 Tests

- `tests/test_durability.c` (Area G) — the content differential:
  `committed_write_survives_crash`, `uncommitted_write_rolls_back_atomic`, and
  `crash_during_data_commit_is_atomic` (sweeps a power-cut across every device
  op of a data commit; each survivor reads exactly old XOR exactly new).
  Passes unchanged over the CF-4 B ordering.
- `tests/test_crash_inject.c` — structural recovery (mountable-or-clean-error;
  deferred-free sweep; R154 wedge-on-failed-commit). Passes unchanged.
- CF-4 B (`tests/test_sync.c`): `sync_cf4b_dirty_commit_two_fsyncs` (the
  exactly-2 witness — a swallowed barrier would read < 2),
  `sync_cf4b_clean_commit_skips` (0 writes / 0 fsyncs / gens unchanged +
  remount verify), `sync_cf4b_first_commit_of_session_writes`,
  `sync_cf4b_inject_fail_then_retry` (the fsyncgate axis: injected failure at
  every device op + in-process retry + remount verify).
- CF-4 B (`tests/test_bootstrap.c`): `bootstrap_cf4b_defer_single_cow`,
  `bootstrap_cf4b_defer_cancel_then_retry`,
  `bootstrap_cf4b_plain_commit_inside_bdev_window_refused`, and
  `bootstrap_cf4b_torn_staged_pair_falls_back` (torn staged header AND
  valid-header-torn-bitmap both fall back per R7a — the §31.2 crash-matrix
  outcomes constructed by direct slot scribble).
- CF-4 C (`tests/test_fs.c`, §31.2.2): `fs_cf4c_unlink_defers_reclaim`
  (unlink does NOT commit — gen unchanged — and moves blocks to PENDING, then
  two commits sweep), `fs_cf4c_reclaim_on_enospc_after_unlink` (the
  availability guarantee: fill near-full, unlink deferred, rewrite the volume
  with no commit → the reserve-path backstop reclaims + succeeds;
  non-vacuous — `data_free_blocks < a_blocks` after the unlink proves the
  reclaim is load-bearing, and neutering `fs_reclaim_on_enospc_locked` fails
  it), `fs_cf4c_reclaim_on_enospc_after_truncate` (the closed latent gap),
  `fs_cf4c_loop_freedom_genuinely_full` (a genuinely-full pool returns clean
  STM_ENOSPC, not wedged, no hang). `tests/bench_create_many.c` CHURN — the
  extent-unlink collapse (47,000 → 15 µs/file host, gen_delta 888 → 0).
- `tests/bench_commit.c` (Area G) — the commit-throughput probe (31.7).

---

## 31.9 Known caveats

- **No no-AEAD FS mode.** `stm_fs_format_opts` requires a keyfile; the encrypted
  path is the only path. The charter's "+/- AEAD" throughput axis cannot be a
  FS-level toggle (the AEAD primitive's MB/s is measured by `test_crypto`; the
  data-vs-metadata commit delta is the available proxy). Per-dataset
  `encryption=off` is an unbuilt future design.
- **Per-commit overhead**: the barrier + clean-commit halves are CLOSED
  (CF-4 B, 31.7); the metadata re-COW density + the per-engine O(resident)
  flush cycle remain (31.7's tracked list).
- **Clean-commit gen semantics (CF-4 B)**: a content-identical
  `stm_sync_commit` returns STM_OK without advancing gens — callers must not
  infer "gens advanced" from a successful commit; gen-age counts REAL
  commits. Multi-device: a data-barrier failure on any live device fails the
  commit (matches the alloc-loop's per-device strictness; UB writes keep
  quorum tolerance).
- **No per-file fsync** (31.6).
- **bdev_thylacine durability rests on the device honoring `VIRTIO_BLK_T_FLUSH`.**
  QEMU's virtio-blk does (it issues `bdrv_flush`); a device that advertises
  FLUSH but ignores it would be non-compliant. The driver fails safe to the
  no-op only when FLUSH is *not advertised* (a genuinely cacheless device).
