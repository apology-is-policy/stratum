# 28 — I/O-error handling and recovery

## Purpose

This is the as-built reference for **how Stratum survives a storage I/O
error** — the recovery model that turns a *transient* device fault into a
self-healed retry instead of permanent FS death, and the boundary at which a
*genuine* failure becomes an honest error code at the OS/userspace edge.

It was written as the Area F output of the Stratum Stabilization Arc
(`thylacine/docs/STRATUM-STABILIZATION.md`), triggered by the on-device Go
build: a `_pkg_.a` write storm tripped a virtio-blk hiccup, which the Thylacine
block backend latched into **permanent FS death**, which the dev9p boundary
then mis-reported (the rich `ENOSPC`/`EIO` collapsed to the kernel's generic
`-1` error sentinel, decoded as a single opaque error). Both defects are closed
here.

This doc is cross-cutting: it spans the block layer ([02 — Block device](02-block.md)),
the sync/commit path ([12 — sync] / the write path [26](26-fs-write-path.md)),
and the Thylacine-side dev9p 9P client. Read 02-block.md first for the bdev
vtable + the fault-injection machinery.

## The recovery model — three layers, because a single-device pool has no redundancy

Stratum's *primary* fault-tolerance is **redundancy**: `stm_sync_commit` skips a
`FAULTED` device "as long as quorum remains" (`src/sync/sync.c` R21 / P5-6 P1).
On a **mirror(n>=2)** pool a single device fault is absorbed by quorum.

The Thylacine boot pool is **single-device** (one virtio-blk). With no quorum
margin, a device fault has no redundancy fallback — so recovery is layered:

| Layer | Mechanism | On a *transient* fault | On a *genuine* (persistent) fault |
|---|---|---|---|
| **bdev** (`bdev_thylacine`), the transport | in-place device re-init + bounded retry | self-heals (the FS never sees EIO) | exhausts the budget -> latches -> surfaces STM_EIO |
| **bdev**, a request the device fails (IOERR) | no re-init, no latch: that request answers STM_EIO | the FS sees one STM_EIO and judges it (a drain's reader reads twice, then probes the device) | every read of that sector answers STM_EIO; every other request goes on |
| **FS extent write** (`fs_flush_all_locked`) | dirty buffer stays in-RAM, NOT wedged | a retried `stm_fs_commit` succeeds (data intact) | the caller sees STM_EIO; data still in RAM for a later retry |
| **FS commit** (`stm_sync_commit`) | wedge (integrity) + recover via remount | a transport hiccup: unreachable, the bdev layer self-heals first; a write or flush the device fails: wedge | wedge: a partial commit rolled back the in-RAM tree, so an in-process retry would silently lose mutations; the UB-ring rollback recovers on the next mount |

The **bdev layer is the load-bearing fix** for the single-device case: it makes
a transient virtio hiccup transparent to the FS, so the FS's *already-correct*
extent-write retry (the dirty buffer) actually completes instead of dying on a
permanently-latched device.

## Layer 1 — `bdev_thylacine` in-place re-init + bounded retry

`src/block/bdev_thylacine.c`. The driver issues one virtqueue request at a time
under `d->lock` (invariant B-2). The request submit/complete is factored into
three functions:

```c
static bool       reinit_device_locked(thyla_bdev *d);
static stm_status do_request_once(thyla_bdev *d, uint64_t lba,
                                   uint32_t sector_count, req_kind kind,
                                   bdev_fail_info *fi);
static stm_status do_request(thyla_bdev *d, uint64_t lba,
                              uint32_t sector_count, req_kind kind);
```

- **`do_request_once`** is the submit + IRQ-wait + completion check. It returns
  `STM_OK` on a clean completion, or `STM_EIO` on any failure **without
  latching** — the recovery/latch decision is `do_request`'s.
- **`reinit_device_locked`** recovers the device IN PLACE:
  ```c
  if (!init_device(d->slot_va, d->ring_pa)) return false;  // STATUS=0 = VIRTIO reset
  init_descriptors(THYLA_RING_USER_VA, d->ring_pa, d->data_pa);
  d->avail_idx = 0;
  d->reinit_count++;
  return true;
  ```
  `init_device` writes `STATUS=0` first — a full VIRTIO 1.2 reset (sec 4.2.3.1 /
  2.1): the device MUST re-initialise all state, **dropping any in-flight
  request and resetting its avail/used idx to 0**. `avail_idx` resets to 0 to
  match. The MMIO bank + DMA mappings persist (claimed once at open, invariant
  B-6); **only the device-side state machine + the rings reset** — the data DMA
  buffer (`THYLA_DATA_USER_VA`) is untouched, so a re-submit re-uses its bytes.
- **`do_request`** is the bounded-retry wrapper:
  ```c
  if (d->failed) return STM_EIO;            // already permanently dead
  for (uint32_t attempt = 0; ; attempt++) {
      stm_status s = do_request_once(...);
      if (s == STM_OK) return STM_OK;
      if (fi.own) return s;                 // the device failed this request alone
      if (attempt >= DO_REQUEST_MAX_REINIT) { d->failed = true; return STM_EIO; }
      if (!reinit_device_locked(d))         { d->failed = true; return STM_EIO; }
  }
  ```
  `DO_REQUEST_MAX_REINIT == 2` -> at most 3 attempts (1 + 2 re-inits). Each
  `do_request_once` is itself bounded (the `MAX_NON_USED_BUFFER_WAKES` spurious-
  wake cap + `t_irq_wait`), so there is no unbounded spin. Exhaustion — or a
  re-init that itself fails to re-negotiate — latches `d->failed`
  **permanently** (fail-closed; the genuinely-dead-device case).

### A request the device fails alone (X9, 2026-11-18)

`do_request_once` answers a request whose completion the ring confirms (used.idx
and the used id both match) by its status byte. `VIRTIO_BLK_S_IOERR` (a bad
sector, or the host's I/O error) and `VIRTIO_BLK_S_UNSUPP` are that request's
own outcome: the ring advances as for a success (`d->avail_idx = new_idx`), the
request answers `STM_EIO` or `STM_ENOTSUPPORTED`, and `do_request` returns it
with no re-init and no latch (`fi.own`). Any other status byte, the `0xff`
pre-poison included (the device never wrote it), breaks the protocol and takes
the transport path above.

Before, the status arm took the transport path: one bad sector re-initialised
the device twice, then latched it, so every later request on the device
answered `STM_EIO` for the life of the process. A re-submit cannot help a
request the device has answered, and for a flush it can hurt: a flush the
device failed may have lost cached writes, and a second flush after a reset
would report them durable. This matches Linux's virtio_blk (`virtblk_result`:
the status fails that request) and ZFS, where the retry and the device probe
live above the disk driver (`zio_vdev_io_assess`, `vdev_probe`). In Stratum
they live in the classifying readers (vote 146: read twice, then ask whether
the device still reads its labels).

What the FS sees: a read answers `STM_EIO` (a plain reader returns it; a
drain's merge read and promote judge it per `26-fs-write-path.md`); an extent
write answers `STM_EIO` and its run stays buffered (Layer 2); a commit's own
write or flush answers `STM_EIO` and the commit wedges (Layer 3), as ZFS
suspends a single-device pool on a failed write.

The first 32 such requests on a device each write one `BDEVDIAG: request-error`
line (arm `status`, `st` the status byte); the 33rd writes one saying later
ones go unshown (`BDEV_REQUEST_ERROR_LINES_MAX`), so a sector read again and
again cannot flood the console. `request_errors` counts them all.

### Why this is the recovery the latch always assumed (R4-F1)

The pre-fix latch was added (R4-F1) as a *safety* measure: after a request
fails, the avail/used ring state is uncertain (the device may have consumed a
published `avail.idx` whose completion we never matched), so refusing further
I/O prevents re-publishing a stale idx (-> device-sees-no-buffer hang) or
mis-matching a prior completion with a later request's wait (-> silent stale
read). The latch comment said "so Stratum tears down + re-opens (re-init resets
avail_idx)" — but **no caller ever drove that re-open**, so the latch was
permanent FS death. The fix realizes the *recovery half* in place: a re-init
**resyncs both ends to idx 0**, dissolving the "uncertain ring state" the latch
guarded against, so a re-submit is safe — and the latch is kept as the final
fallback for a device that cannot be re-initialised.

### Idempotency of a re-submit

A re-submit re-issues the *same* request:
- A **READ** re-reads the same LBA into the DMA buffer — trivially idempotent.
- A **WRITE** re-writes the same LBA from the **unchanged** data DMA buffer. In
  `op_write`, the `memcpy(DMA, p, chunk)` precedes `do_request`, and a re-init
  does not touch the data DMA, so the bytes are stable across an internal
  retry. The whole-sector-prefix loop's already-persisted chunks survive a
  later chunk's re-init (a device reset resets state, not the writethrough
  backing store); the tail RMW's read-then-overlay-then-write keeps the DMA
  contents stable across either op's internal retry.
- A **FLUSH** (Area G; `op_fsync` issues `VIRTIO_BLK_T_FLUSH` when the device
  negotiated `VIRTIO_BLK_F_FLUSH`) re-flushes — idempotent. It shares the
  `do_request` path, so a transient flush hiccup self-heals via the same
  bounded reinit recovery; only an exhausted budget latches + surfaces STM_EIO,
  which wedges the in-flight commit (fail-closed durability). A flush the
  device answers `VIRTIO_BLK_S_IOERR` is never re-submitted (see above): it
  answers STM_EIO at once and the commit wedges. The flush is a
  header→status descriptor chain with no data buffer; see
  `31-durability-commit.md` §31.4.

## Layer 3 — the FS commit wedge (integrity, not a defect)

A failed `stm_sync_commit` wedges the fs (`stm_fs_mark_wedged`; the `wedged`
atomic gates every mutating op via `FS_GUARD_WRITE`). This is **deliberate**
(R154): the inode engine's three-phase abort drops the in-RAM tree on a failed
commit, reverting to the previous durable root — an in-process retry would
silently commit that reverted tree, **losing every uncommitted mutation** (P2-1)
or durably resurrecting a just-freed inode (P1-1). `test_crash_inject.c::
r154_failed_commit_wedges_fs` pins it. There is **no in-process
clear_wedged/resume**; recovery is by **remount** (the UB-ring rollback picks
the last-good gen; `crash_inject_during_commit_recovers_clean`).

For the single-device boot pool, the bdev re-init (Layer 1) makes a transient
transport hiccup unreachable here (the device self-heals before the commit's
UB write fails). A write or flush the device fails (IOERR) does reach the
commit and wedges it, as a genuinely dead device does; permanent death pending
a remount is acceptable for both. See "Known caveats" for the SOTA gap.

## The errno boundary — honest error codes to userspace (#3)

`stratumd` reports a per-op error as a 9P **Rlerror** carrying a Linux-errno
`ecode`. The Thylacine kernel 9P client maps it to a negative kernel value
(`-(int)ecode` for `ecode` in `(0,4095]`, or `-P9_E_IO` on transport death),
where `P9_E_* == T_E_* == POSIX errno`. Pre-#3, the Thylacine
`dev9p_read`/`dev9p_write` Dev methods collapsed any `rc != 0` to `-1`, and the
generic `sys_{read,write}_for_proc` re-collapsed any negative dev return to
`-1` — the kernel's **generic error sentinel**. So the go-build's
`STM_ENOSPC`/`STM_EIO` reached userspace as that one opaque sentinel (the
pouch/native boundary decodes `-1` to **EIO** — `errno.h` forbids a handler
returning `-T_E_PERM=1`, so `-1` is *not* EPERM), masking the real cause.

The fix propagates the real `-errno` faithfully through the whole chain:
`dev9p_{read,write}` -> `(long)rc` ; `sys_{read,write}_for_proc` -> `(s64)n` on
`n<0` ; the syscall handlers propagate it; the pouch boundary-line maps
`[-4095,-2] -> errno`. The change is a **no-op for every Dev that returns the
legacy `-1` sentinel** (pipes, cons, devsrv, ...) — only dev9p now surfaces the
richer `ENOSPC`/`EACCES`/`EIO`. (`ENOSPC` = 28 is propagated by value even
though the Thylacine kernel has no named `T_E_NOSPC` constant; a future
errno-rollout sub-chunk can name it.)

Two residuals (Area F focused audit, P3, both v1.0-acceptable):
- **EPERM (ecode=1) collides with the `-1` sentinel.** A server-supplied
  `Rlerror(ecode=1)` maps to `-1`, indistinguishable from the generic sentinel,
  so it decodes to EIO — the one errno this v1.0 channel cannot convey. A wider
  channel (not overloading `-1`) is the full ER-rollout's job. Stratum does emit
  `STM_EPERM->ecode=1` on reachable paths (sealed-file / append-only refusals),
  so a real EPERM is reported as EIO until then.
- **Out-of-window clamp.** `sys_{read,write}_for_proc` clamp a negative
  `< -4095` to `-T_E_IO` before propagating, so a (hypothetical future) Dev
  returning outside pouch's `[-4095,-1]` error window cannot be mis-decoded as a
  fake-huge success count — defense-in-depth symmetric with the native decoder's
  saturation. Unreachable today (dev9p's `rc` is `map_error`-clamped to
  `[-4095,-1]`; every other Dev returns `>=0` or exactly `-1`).

## Tests

- **Stratum host** — `tests/test_fs.c::fs_io_transient_write_eio_flush_recovers`:
  arms the posix backend's transient fault (`stm_bdev_inject_fail_after(bdev,
  1)`) on the first extent write of a commit, asserts the commit fails + the fs
  is **NOT wedged** + a retried commit succeeds + the 20 KiB file is
  byte-intact. Non-vacuous: a wedge fails the not-wedged assertion; a dropped
  buffer fails the byte-check. Pins the Layer-2 contract the bdev re-init
  relies on. (The posix inject fires only on writes — 02-block.md — and is
  transient by construction, so it models exactly a *recovered* bdev.)
- **Thylacine kernel** — `kernel/test/test_dev9p.c::test_dev9p_write_read_propagate_errno`:
  a loopback responder returns `Rlerror(ENOSPC)` / `Rlerror(EIO)` for
  Twrite/Tread; asserts `dev9p.write` -> `-28` and `dev9p.read` -> `-5` (not the
  `-1` collapse). Non-vacuous (pre-fix returns `-1`).
- The `bdev_thylacine` re-init path itself is **Thylacine-only** (not
  host-compilable; `#error`-guarded on `__NR_mmio_create`). Its happy path is
  exercised by every Thylacine boot (the live stratumd drives virtio-blk
  through `do_request` -> `do_request_once`); its re-init path is verified by
  code review against the VIRTIO 1.2 reset semantics + the in-guest go-build
  E2E. The request-error path (X9) is verified on
  Thylacine with QEMU's blkdebug filter under the pool drive
  (`THYLACINE_POOL_BLKDEBUG` in Thylacine's `tools/run-vm.sh`), failing every
  read of one sector: label 3's commit-ring slot 0, which the mount's
  uberblock scan reads and skips on error. With this driver the boot reaches
  its login prompt; each of the sector's two reads writes one `request-error`
  line (`st=1`) and nothing re-inits. With the driver before it, the same
  sector re-inits the device twice and latches it, stratumd's mount fails
  (`rc=-5`), and the boot stops. A driver that drops the ring-index advance on
  the request-error path hangs the next request (stratumd never comes up).

## Error paths

| Return | Trigger | Caller expectation |
|---|---|---|
| `STM_EIO` (bdev) | a transport failure in `do_request_once` (arms 1-4, or a status byte that is none of OK, IOERR, UNSUPP) AND the recovery budget exhausted (or re-init failed) | the FS extent-write path retries (data in RAM); a commit wedges |
| `STM_EIO` (bdev) | the device completed the request with `VIRTIO_BLK_S_IOERR` (a bad sector) | that request only, the device is not latched: a drain's reader judges it per ref 26; an extent write keeps its run; a commit wedges |
| `STM_ENOTSUPPORTED` (bdev) | the device completed the request with `VIRTIO_BLK_S_UNSUPP` | that request only; a pool-wide error to the FS |
| `STM_EWEDGED` (fs) | a mutating op after a failed commit | refuse until remount (the integrity guard) |
| `-ENOSPC` / `-EIO` (dev9p) | Stratum Rlerror over 9P | userspace sees the honest errno (post-#3) |

## Performance characteristics

The recovery path is **off the hot path**: a healthy `do_request` returns after
one `do_request_once` with no re-init. A re-init costs a device reset +
re-negotiation (a handful of MMIO round-trips), bounded at 2 per failed
request. `reinit_count` is a diagnostic counter (single-writer under `d->lock`).
A request the device fails alone costs no re-init, and one line of stderr at
most.

## Known caveats / footguns

- **No in-process wedge resume (SOTA gap).** `stm_fs_mark_wedged` is one-way
  within a process lifetime; recovery requires unmount+remount (a stratumd
  restart on Thylacine). Mature COW filesystems offer an in-process *suspend +
  clear* (ZFS `failmode=wait` + `zpool clear`; BTRFS read-only + remount). The
  bdev re-init makes this gap unreachable for a *transient* transport hiccup
  (the device self-heals before the commit wedges), so it bites a
  genuinely-dead device and a commit write or flush the device fails (IOERR).
  A recoverable-suspend that lets a hard-but-recovered device resume
  without a restart is a tracked v1.x enhancement, not an Area F defect.
- **Stale-pool contamination.** A pool baked by a *buggy* Stratum (e.g.
  pre-Area-A, which had the #352/#355 extent-overwrite data-loss bugs) can
  contain extents that fail integrity (`STM_ECORRUPT`) on read by *any* reader.
  This is a property of the stale data, not the reader — re-bake the pool with
  the stabilized Stratum.
- **Cross/host version skew.** The Thylacine boot pool is baked by the *host*
  stratumd and read by the *cross* (in-guest) stratumd. Rebuild both in lockstep
  when the on-disk-touching layers change, so the reader matches the writer.
- The driver does not pipeline (one request per bdev, B-2); the re-init's
  single-in-flight assumption is exact.

## Status

- Layer 1 (`bdev_thylacine` re-init + bounded retry): **implemented**
  (Area F #2). Happy path boot-verified live; fault path code-reviewed +
  owed the in-guest go-build E2E.
- A request the device fails alone (X9): **implemented** (o1c, 2026-11-18);
  verified on Thylacine with one injected bad sector (see Tests).
- Layer 2 (FS extent-write recovery): **pre-existing + sound**; now pinned by
  `fs_io_transient_write_eio_flush_recovers`.
- Layer 3 (commit wedge + remount recovery): **pre-existing + sound** (R154).
- The dev9p errno boundary (#3): **implemented**; kernel-test-verified.
- In-process wedge resume: **v1.x enhancement** (the SOTA gap above).
