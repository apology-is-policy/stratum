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
collapses to one phase). Sequence for an established pool (`auth_gen > 0`),
target gen `G = auth + 2`:

1. **Reservation UB** (`reservation_gen = auth + 1`) — a copy of the previous
   authoritative uberblock with the gen bumped, written to every device under
   quorum. This is the **rollback target** if the rest of the commit fails.
2. **Flush all metadata** at `G`:
   - keyschema commit
   - CAS auto-GC sweep (frees expired content-addressed entries)
   - per-device alloc commit (writes the allocator bitmap tree + grabs each
     device's tree root paddr/csum)
   - alloc-roots, per-dataset M-engine cascade flush (inode / dirent / xattr /
     extent records — folded into `main_csum` since v30), dataset / snapshot /
     CAS / repair-log index commits.
3. **The durable-bitmap barrier** — `stm_bootstrap_commit` (`src/bootstrap/pool.c`)
   COWs the in-RAM allocation bitmap to its alternate slot + **fsyncs**, then
   COWs the bootstrap header to its alternate slot + **fsyncs**. This is what
   makes the bitmap bits set during step 2 *durable*; it MUST run strictly
   before the final UB.
4. **Compute the Merkle root** over all persisted metadata trees.
5. **The commit point** — write the final UB at gen `G` to every device +
   **fsync** (`stm_sb_label_write` → `stm_bdev_write` + `stm_bdev_fsync`),
   under quorum.
6. **Post-commit** — advance the in-RAM `auth_gen` / `current_gen` / root
   pointers under `s->lock`.

The durability hinge is the ordering **{all data + bitmap + header durable}
→ {final UB durable}**:

- Crash after the bitmap/header fsync but before the final UB → the previous
  authoritative UB is still the highest-gen valid one; the new metadata nodes
  are unreferenced garbage, reclaimed by the next mount's mark-and-sweep.
- Crash after the final UB fsync → the new tree is live; every node it
  references was made durable in steps 2–3.

A failed `stm_sync_commit` **wedges** the fs (`stm_fs_commit`, R154 P2-1): the
inode engine's three-phase abort drops the in-RAM tree, so an in-process retry
would silently commit the reverted-to-previous-durable state. The wedge refuses
the retry with `STM_EWEDGED` (regression: `test_crash_inject.c::r154_*`).

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

Every durability barrier is `stm_bdev_fsync`. There are three per commit-phase
group: the bitmap fsync, the header fsync (both in `stm_bootstrap_commit`), and
the final-UB fsync (`stm_sb_label_write`). The barrier's strength is the
backend's:

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
host-independent):

| Scenario | fsyncs/commit | dev-KiB/commit | write-amp |
|---|---|---|---|
| empty (nothing dirty) | 6 | 128 | — |
| metadata (reserve) | 8 | 444 | — |
| data-4k | 10 | 652 | **163×** |
| data-64k | 10 | 712 | 11× |

**Findings (tracked Area-G perf debt → the concurrent-FS / Bε arc):**

- **No clean-commit short-circuit.** An empty commit (nothing dirty) still
  writes a full reservation+bitmap+header+UB cycle: 6 fsyncs + 128 KiB. A
  dirty-flag short-circuit (CLAUDE.md idempotency-on-retry) would make a
  redundant `Tsync` near-free — but it must account for the in-commit CAS GC +
  deferred-free sweeps, so it is a careful change, not a one-liner.
- **Large fixed per-commit overhead.** ~10 fsync barriers + ~650 KiB of metadata
  re-COW *independent of payload* → 163× write-amplification for a 4 KiB sync.
  This is the same per-commit-metadata-re-COW root as Area-S's S-2
  (metadata-region pressure) and is far outside BTRFS parity for a sync-heavy
  workload. The fix is a commit-path redesign (barrier batching: the ~10
  independent fsyncs → 2, one data-durable barrier + one UB-durable barrier;
  and metadata density) — crash-consistency-critical, so it is surfaced
  scripture-first to the metadata-density / Bε work, not point-patched.

The FLUSH negotiation (31.4) is also a throughput *enabler*: it lets the launch
use `cache=writeback` (writes batch in the device cache; only the ~10 fsyncs
become real barriers) instead of `cache=writethrough` (every write a synchronous
barrier). That default-posture change is a separate decision (surfaced with
measured data), not part of the FLUSH-correctness fix.

---

## 31.8 Tests

- `tests/test_durability.c` (Area G) — the content differential:
  `committed_write_survives_crash`, `uncommitted_write_rolls_back_atomic`, and
  `crash_during_data_commit_is_atomic` (sweeps a power-cut across every device
  op of a data commit; each survivor reads exactly old XOR exactly new).
- `tests/test_crash_inject.c` — structural recovery (mountable-or-clean-error;
  deferred-free sweep; R154 wedge-on-failed-commit).
- `tests/bench_commit.c` (Area G) — the commit-throughput probe (31.7).

---

## 31.9 Known caveats

- **No no-AEAD FS mode.** `stm_fs_format_opts` requires a keyfile; the encrypted
  path is the only path. The charter's "+/- AEAD" throughput axis cannot be a
  FS-level toggle (the AEAD primitive's MB/s is measured by `test_crypto`; the
  data-vs-metadata commit delta is the available proxy). Per-dataset
  `encryption=off` is an unbuilt future design.
- **Per-commit overhead (31.7)** is the open Area-G perf debt.
- **No per-file fsync** (31.6).
- **bdev_thylacine durability rests on the device honoring `VIRTIO_BLK_T_FLUSH`.**
  QEMU's virtio-blk does (it issues `bdrv_flush`); a device that advertises
  FLUSH but ignores it would be non-compliant. The driver fails safe to the
  no-op only when FLUSH is *not advertised* (a genuinely cacheless device).
