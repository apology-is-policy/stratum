# 28 — I/O-error handling and recovery

## Purpose

This is the as-built reference for **how Stratum survives a storage I/O
error**: the recovery model that retries a *transient* device fault below the
FS where a retry can clear it (a transport hiccup; a read or write the device
failed once), hands a fault that persists to the layer that can judge it
instead of killing the FS, and the boundary at which a *genuine* failure
becomes an honest error code at the OS/userspace edge.

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
| **bdev** (`bdev_thylacine`), the transport | in-place device re-init + bounded retry; a flush is re-inited, never re-submitted | self-heals (the FS never sees EIO), except a flush: STM_EIO, the commit wedges | exhausts the budget -> latches -> surfaces STM_EIO |
| **bdev**, a request the device fails (IOERR) | no re-init, no latch: a read or write is re-submitted twice on the consistent ring, then answers STM_EIO; a flush answers STM_EIO at once | a read or write self-heals (the FS never sees it); a flush: the commit wedges | that sector answers STM_EIO and the FS judges it (below); every other request goes on |
| **FS extent write** (`fs_flush_all_locked`) | dirty buffer stays in-RAM, NOT wedged | a retried `stm_fs_commit` succeeds (data intact) | the caller sees STM_EIO; data still in RAM for a later retry |
| **FS commit** (`stm_sync_commit`) | wedge (integrity) + recover via remount | a hiccup on a read or write: unreachable, the bdev layer heals it first; a failed flush (IOERR, or a completion the transport lost): wedge | wedge: a partial commit rolled back the in-RAM tree, so an in-process retry would silently lose mutations; the UB-ring rollback recovers on the next mount |
| **mount** (`stm_sb_mount_scan_ex`, `stm_bootstrap_open`) | fail closed where an acknowledged commit may sit behind an unreadable uberblock slot (ref 07 says which); reconcile a bootstrap bitmap open could not confirm | the driver's re-submit and the scan's two re-reads heal a one-time fault | the mount fails (STM_EIO; stratumd names the slot) rather than roll back past an acknowledged commit, and fails with the reconcile's error rather than hand out live nodes; both hold for a one-device pool (multi-device: enqueued) |

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
  bool flush = false;
  if (!init_device(d->slot_va, d->ring_pa, d->data_pa, &flush)) return false;
  if (flush != d->flush_supported) d->flush_supported = flush;
  d->avail_idx = 0;
  d->reinit_count++;
  return true;
  ```
  `init_device` writes `STATUS=0` first — a full VIRTIO 1.2 reset (sec 4.2.3.1 /
  2.1): the device MUST re-initialise all state, **dropping any in-flight
  request and resetting its avail/used idx to 0**; it then zeroes the ring
  page and rebuilds the descriptor chain before QUEUE_READY and DRIVER_OK
  (below). `avail_idx` resets to 0 to match. The MMIO bank + DMA mappings persist (claimed once at open, invariant
  B-6); **only the device-side state machine + the rings reset** — the data DMA
  buffer (`THYLA_DATA_USER_VA`) is untouched, so a re-submit re-uses its bytes.
- **`do_request`** is the bounded-retry wrapper:
  ```c
  if (d->failed) return STM_EIO;            // already permanently dead
  for (uint32_t attempt = 0; ; attempt++) {
      stm_status s = do_request_once(...);
      if (s == STM_OK) return STM_OK;
      if (fi.own) {                         // the device failed this request alone
          if (kind != REQ_FLUSH && resubmits < DO_REQUEST_MAX_RESUBMIT) {
              resubmits++; continue;        // the ring is consistent: no re-init
          }
          return s;
      }
      if (reinits >= DO_REQUEST_MAX_REINIT) { d->failed = true; return STM_EIO; }
      if (!reinit_device_locked(d))         { d->failed = true; return STM_EIO; }
      reinits++;
      if (kind == REQ_FLUSH) return STM_EIO; // re-inited, never re-submitted
  }
  ```
  `DO_REQUEST_MAX_REINIT == 2` -> at most 2 re-inits per request, and
  `DO_REQUEST_MAX_RESUBMIT == 2` -> at most 2 re-submits of a read or write
  the device failed alone. Each
  `do_request_once` caps wakes with no used buffer (`MAX_NON_USED_BUFFER_WAKES`)
  and looks at the device once a second while it does not answer: each
  `t_irq_wait` returns within 1 s, and then a used ring that moved with no
  interrupt seen completes the request (an `irq-late` line: a lost
  interrupt), and DEVICE_NEEDS_RESET in the status (VIRTIO 1.2 2.1.2; QEMU
  sets it on a malformed ring) takes the transport path as
  `arm=needs-reset`. Otherwise the wait has no end, as in Linux's virtio-blk
  (no blk-mq timeout handler, so its timer re-arms): a slow host is not a
  failed device, and a reset cannot hurry a request QEMU is still running
  (its reset drains it). A request outstanding 30 s gets one `slow` line and
  goes on waiting. So a slow host costs time, never a failed request (see
  Known caveats for a device that never answers). Exhaustion -- or a
  re-init that itself fails to re-negotiate — latches `d->failed`
  **permanently** (fail-closed; the genuinely-dead-device case).

### A request the device fails alone (X9, 2026-11-18)

`do_request_once` answers a request whose completion the ring confirms (used.idx
and the used id both match) by its status byte. Any non-OK status the device
wrote is that request's own outcome: `VIRTIO_BLK_S_IOERR` (a bad sector, or the
host's I/O error), `VIRTIO_BLK_S_UNSUPP`, or a value VIRTIO 1.2 5.2.6 does not
name (Linux's `virtblk_result` answers that one an I/O error too). The ring
advances as for a success (`d->avail_idx = new_idx`), the request answers
`STM_EIO` (UNSUPP too: the driver sends only request types the device offers,
so no caller has an "unsupported" to act on), and `fi.own` is set. Only the
`0xff` pre-poison, a status byte the device never wrote, takes the transport
path above.

`do_request` then re-submits a READ or WRITE on the same, consistent ring, up
to `DO_REQUEST_MAX_RESUBMIT` (2) times, with no re-init: a one-time fault
clears on a second try (ZFS's `zio_vdev_io_assess` retries every failed I/O
once before it reports one, data and metadata alike), and both are idempotent
(the same LBA, from the unchanged data DMA buffer). A request still failing
answers `STM_EIO` alone: no re-init, no latch. A FLUSH is never re-submitted: a
flush the device failed may have lost cached writes, and a second flush would
report them durable (the fsyncgate lesson); it answers `STM_EIO` at once and
the commit wedges (Layer 3).

Before, the status arm took the transport path: one bad sector re-initialised
the device twice, then latched it, so every later request on the device
answered `STM_EIO` for the life of the process, and the re-submits re-flushed a
failed flush. Linux's virtio_blk retries nothing in the driver (the status
fails the request; nothing resets the device); ZFS retries once above the
disk, then asks the device with `vdev_probe`. Stratum's classifying readers
add their own second read and device probe above this one (vote 146).

What the FS sees from a sector that keeps failing: a read answers `STM_EIO` (a
plain reader returns it; a drain's merge read and promote judge it per
`26-fs-write-path.md`; mount fails closed where the newest uberblock or the
newest bootstrap bitmap may be, see `07-sb-sync.md` and
`05-bootstrap-alloc.md`); an extent write answers `STM_EIO` and its run stays
buffered (Layer 2); a commit's own read, write or flush answers `STM_EIO` and
the commit wedges (Layer 3), as ZFS suspends a single-device pool on a failed
write.

Diagnostics: each failed submission writes one `BDEVDIAG` line (arm `status`,
`st` the status byte): `request-error (re-submitting)`, then `request-error`
for the one that answers. The first 32 per request kind (read, write, flush)
are written, then one saying later ones of that kind go unshown
(`BDEV_REQUEST_ERROR_LINES_MAX`): a sector read again and again cannot flood the
console, nor use up the lines a failed flush is owed. Transport `io-fail` and
`flush-lost` lines share a cap of 32 over the process
(`BDEV_TRANSPORT_LINES_MAX`); the latch lines are written once. Every line
carries `reinits=` and `reqerrs=` (submissions failed alone, all kinds).

A re-init waits for the reset to finish (VIRTIO 1.2 2.4.2: the driver should
consider a reset complete when it reads `device_status` back as 0; bounded by
`RESET_READBACK_MAX` reads), then zeroes the ring page and rebuilds the
descriptor chain before the device may read the ring (4.2.3.2 step 4). Left
as it was, the page holds `avail.idx` at the old count, every entry head 0
and the abandoned request's header, and a device may process the queue as
DRIVER_OK is written (QEMU kicks it as it starts ioeventfd): with more heads
than the queue's 16 it marks itself broken and the re-submit is never
answered; with fewer it runs the abandoned request again (a WRITE through the
data descriptor's length) and that completion answers the re-submit. The
data descriptor's length stays 0 until a request sets it. (o1c review round
2, F2.)

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
  negotiated `VIRTIO_BLK_F_FLUSH`) is never re-submitted. The device may have
  consumed and failed it (IOERR, or a completion the transport lost), and
  whether its cached writes reached the media is then unknown; a second flush
  could answer OK for writes the first one lost. A transport failure on a flush
  re-inits the device (so later requests work) and answers STM_EIO; an IOERR
  answers STM_EIO at once. Either wedges the in-flight commit (fail-closed
  durability). The flush is a header->status descriptor chain with no data
  buffer; see `31-durability-commit.md` section 31.4.

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

For the single-device boot pool, Layer 1 makes a transient hiccup on a read
or write unreachable here (a re-init, or a re-submit, heals it before the
commit sees it). A flush that fails, a read or write the device fails three
times, and a dead device do reach the commit and wedge it; permanent death
pending a remount is acceptable for each. See "Known caveats" for the SOTA
gap.

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
  (`THYLACINE_POOL_BLKDEBUG` in Thylacine's `tools/run-vm.sh`), failing reads
  of one sector. A ring slot of an older generation, which the mount's
  uberblock scan reads and skips: with this driver the boot reaches its login
  prompt and nothing re-inits; with the driver before it, the sector re-inits
  the device twice and latches it, stratumd's mount fails (`rc=-5`), and the
  boot stops; a driver that drops the ring-index advance on the request-error
  path hangs the next request. The newest generation's slot failing every
  read: the mount fails closed (STM_EIO) instead of mounting the generation
  before it; failing once: the driver's re-submit reads it and the newest
  generation mounts. Round 2's legs (stratum-private/o1cw/legs-r2.sh) add:
  the refusal line naming the newest final's slot (generation 159, label 3
  slot 33, its byte offset); a write failing once (one re-submit, login) and
  every write failing (three submissions, then the mount fails); and, with
  leg-only driver copies that force one transport failure, a re-init with the
  zeroed ring (a completed read treated as lost: re-init, re-submit, login), a
  flush whose completion is lost (re-init, one `flush-lost` line, the mount
  fails), and a doorbell never rung (on that driver `arm=irq-timeout` after
  30 s, re-init, re-submit, login; the wait now has no end). Round 3's legs
  (legs-r3.sh, legs-r3b.sh) add: the slot after the newest final (generation
  160) failing every read, where the one-device rule mounts generation 159
  and the mount's claim writes that slot (round 1's rule refused); a doorbell
  rung only after 35 s (one `slow` line at 30 s, then the completion, login,
  no re-init); and a head published out of the queue's range (QEMU: "Guest
  says index 16 is available", DEVICE_NEEDS_RESET, `arm=needs-reset`,
  re-init, re-submit, login). The stale-ring replay the zeroing closes was not
  reproduced: the round-1 driver with the same forced re-init still reached
  login (on HVF the vCPU republishes before QEMU's kick runs), so that fix
  rests on VIRTIO 1.2 4.2.3.2 and QEMU's sources, not on a red leg. No leg
  reaches the reset read-back's loop (QEMU's virtio-mmio reset is
  synchronous, so it exits on its first read) or the 33rd line of a cap.
- **Stratum host, the FS above the driver** (the posix backend answers a
  device error as the driver now does: one request, no latch):
  `test_sb.c::sb_mount_scan_*` and `test_sync.c::sync_mount_*` (the scan's
  fail-closed rule and its re-read), `test_sync.c::sync_mount_survives_one_unreadable_bootstrap_header_slot`,
  `sync_mount_refuses_a_fallen_back_bitmap_it_could_not_reconcile` and
  `sync_bootstrap_open_says_when_it_cannot_confirm_the_bitmap` (the bootstrap
  fallback), `test_fs.c::fs_a_bad_sector_with_label_0s_mirror_slot_unreadable_is_the_records`
  (the device probe's label loop). Round 2:
  `sb_mount_scan_one_device_refuses_where_a_newer_commit_may_be`,
  `sync_mount_refuses_only_the_unreadable_label_that_can_hide_a_commit`,
  `sync_mount_skips_the_unreadable_slot_of_a_generation_never_written` (the
  one-device rule), `sync_bootstrap_open_answers_eio_for_what_the_device_cannot_read`
  and `test_fs.c::fs_mount_names_the_uberblock_slot_it_refuses_on` (the
  refusal record). Round 3: `sb_mount_scan_one_device_knows_a_final_by_its_mark`,
  `sb_mount_scan_a_reread_at_best_plus_2_that_finds_newer_moves_best`,
  `sb_mount_scan_best_minus_1_at_an_older_lap_proves_nothing`,
  `sb_mount_scan_one_device_reads_blank_only_as_zeros`,
  `sb_mount_scan_reads_an_undecoded_successor_again`;
  `test_fs.c::fs_mount_takes_a_final_past_its_unreadable_successor` and
  `fs_mount_takes_a_noop_final_past_its_unreadable_successor` (the one-device
  rule on the path stratumd mounts through), `fs_mount_names_the_slot_the_open_refuses_on`
  and `fs_mount_zeroes_the_refusal_before_its_argument_check`;
  `test_sync_multi.c::sync_multi_a_device_that_refuses_is_not_a_stale_vote`
  (the strict rule on a pool of three).

## Error paths

| Return | Trigger | Caller expectation |
|---|---|---|
| `STM_EIO` (bdev) | a transport failure in `do_request_once` (arms 1-4, arm 6 = the device asked to be reset (DEVICE_NEEDS_RESET), or the `0xff` pre-poison: a status byte the device never wrote) AND the recovery budget exhausted (or re-init failed) | the FS extent-write path retries (data in RAM); a commit wedges |
| `STM_EIO` (bdev) | a transport failure on a flush (re-inited, not re-submitted) | the commit wedges |
| `STM_EIO` (bdev) | the device completed the request with a non-OK status it wrote (IOERR, UNSUPP, or one VIRTIO does not name): three times for a read or write, once for a flush | that request only, the device is not latched: a drain's reader judges it per ref 26; mount fails closed where the newest state may be; an extent write keeps its run; a commit wedges |
| `STM_EWEDGED` (fs) | a mutating op after a failed commit | refuse until remount (the integrity guard) |
| `-ENOSPC` / `-EIO` (dev9p) | Stratum Rlerror over 9P | userspace sees the honest errno (post-#3) |

## Performance characteristics

The recovery path is **off the hot path**: a healthy `do_request` returns after
one `do_request_once` with no re-init. A re-init costs a device reset +
re-negotiation (a handful of MMIO round-trips), bounded at 2 per failed
request. `reinit_count` is a diagnostic counter (single-writer under `d->lock`).
A request the device fails alone costs no re-init and at most two
re-submits (a read or write); each failed submission writes one line of
stderr, at most 32 per request kind over the process.

## Known caveats / footguns

- **No in-process wedge resume (SOTA gap).** `stm_fs_mark_wedged` is one-way
  within a process lifetime; recovery requires unmount+remount (a stratumd
  restart on Thylacine). Mature COW filesystems offer an in-process *suspend +
  clear* (ZFS `failmode=wait` + `zpool clear`; BTRFS read-only + remount). The
  bdev re-init and re-submit make this gap unreachable for a *transient* hiccup
  on a read or write (the device heals before the commit wedges), so it bites a
  genuinely-dead device, a failed flush, and a read or write the device fails
  three times.
- **One copy of each generation's uberblock per device.** A commit writes its
  final uberblock to one ring slot (label `gen % 4`, slot `gen % 63`), so one
  unreadable sector there hides the newest commit; the mount then fails closed
  rather than roll back (`07-sb-sync.md`), and stratumd names the slot. On one
  device it refuses at the slot after the newest generation only when that
  generation may be a reservation (a claim, which a session that crashed
  before its first commit leaves, reads as one); a refused mount writes
  nothing, so it goes on refusing while that sector stays unreadable.
  Recovery is then the operator's explicit choice to accept losing at most
  the newest commit (overwrite that slot with zeros; it then reads back zero
  and the mount takes the generation before). Writing each generation to two
  or more labels (ZFS writes all four) would let it mount, and an explicit
  opt-in mount could take the newest readable generation; both are enqueued
  for the operator. A multi-device pool can still roll back a commit
  acknowledged by exactly a quorum when one of those devices refuses
  (enqueued).
- **The device probe and a host page cache.** Under QEMU with
  `cache=writeback`, or a buffered host backend, the classifying readers'
  device probe can be answered from the host's page cache while reads that
  reach the device fail (ref 26).
- **A device that never answers.** The driver waits on a request with no end,
  as Linux's virtio-blk does, so a device that stops answering without
  asking for a reset holds stratumd, `d->lock` held, until it answers; the
  `slow` line at 30 s names the request.
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
- A request the device fails alone (X9): **implemented** (o1c, 2026-11-18),
  with its review round 1 closed the same day (the read and write re-submit,
  the flush never re-submitted, per-kind diagnostics, the reset read-back, and
  mount failing closed), round 2 (the ring zeroed on re-init, the one-device
  mount rule, the refusal named) and round 3 (a final known by its mark,
  blank only when zero, an undecoded slot read again, the open's refusal
  named, an IRQ wait with no end that still catches a lost interrupt and
  DEVICE_NEEDS_RESET) the same day; verified on Thylacine with injected bad
  sectors, the slot after the newest final unreadable, and leg-only forced
  faults (see Tests).
- Layer 2 (FS extent-write recovery): **pre-existing + sound**; now pinned by
  `fs_io_transient_write_eio_flush_recovers`.
- Layer 3 (commit wedge + remount recovery): **pre-existing + sound** (R154).
- The dev9p errno boundary (#3): **implemented**; kernel-test-verified.
- In-process wedge resume: **v1.x enhancement** (the SOTA gap above).
