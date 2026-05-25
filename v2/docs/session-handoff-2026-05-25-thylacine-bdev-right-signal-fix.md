# Session handoff: 2026-05-25 — `thylacine-pouch-arm` bdev_thylacine RIGHT_SIGNAL fix

**Scope**: one-line constant fix in `src/block/bdev_thylacine.c`. Tightens
the kobj-rights mirror to match the kernel's actual `RIGHT_SIGNAL` bit
position. Closes the bdev_thylacine read-I/O block in
P6-pouch-stratumd-boot sub-chunk 16b-γ-mount-close on the Thylacine OS
side. Stratum agent was paused during this change per the user's
coordination preference.

## What changed

Single file: `src/block/bdev_thylacine.c`. `T_RIGHT_SIGNAL`
re-defined from `(1u << 3)` to `(1u << 5)` to match the
kernel-side `RIGHT_SIGNAL` definition in
`thylacine/kernel/include/thylacine/handle.h`. The comment block
above the `T_RIGHT_*` macros is also updated to note that `(1u
<< 3)` is reserved for `RIGHT_TRANSFER` (not yet exercised by
this driver) and `(1u << 4)` for `RIGHT_DMA`. The previous
constant `(1u << 3)` was the kernel's `RIGHT_TRANSFER` bit, NOT
its `RIGHT_SIGNAL` bit. Both were valid bits in `RIGHT_ALL`, so
`t_irq_create` accepted the rights mask and the open path
proceeded without error. The downstream block was:
`sys_irq_wait_handler` gates on `slot->rights & RIGHT_SIGNAL` ==
`8 & 32` == 0, so every `t_irq_wait(d->irq_handle)` returned -1.
`do_request`'s `if (count < 0) return STM_EIO;` returned EIO
unconditionally; every `stm_bdev_read` failed at the IRQ wait;
`stm_sb_mount_scan` saw every label_read fail and returned
`STM_ENOENT`.

## What the fix unblocks

With the correct `RIGHT_SIGNAL` bit, `t_irq_create` now grants
the IRQ handle the actual signal right. `t_irq_wait` succeeds.
The full bdev read/write/fsync path runs end-to-end on Thylacine
under the in-process VirtIO 1.2 driver. The Thylacine session
verified by reading the STRATUM2 magic at pool.img offset 0x4000
through the bdev (Thylacine boot log line `bdev_thyla: post-read
data[0..16]= 53 54 52 41 54 55 4d 32 ...`), and observing
`stm_sb_mount_scan` decode the uberblock + return STM_OK and
proceed to the downstream mount flow.

Downstream of the bdev read fix, `stratumd` (under the
Thylacine-side pouch musl) reaches the `stm_pool_open` /
`stm_alloc_open_blank` / `stm_sync_create` chain after
`mount_scan` succeeds. There is a SEPARATE failure further down
the mount path that surfaces as an exit-1 path (not in this fix's
scope). The Thylacine session's joey probe still reports
`/srv/stratum-fs not bound` -- the Stratum-side mount path needs
follow-up investigation, but is unblocked from the bdev read I/O
which previously masked everything downstream.

## How the bug was found

A focused debugging session on the Thylacine side, with
diagnostic fprintfs added to and reverted from
`bdev_thylacine.c`'s `op_read` / `do_request` / IRQ-wait loop +
a kernel-side EL0 fault diagnostic showing the faulting Proc's
PID + ELR. The traces showed `t_irq_wait` returning `-1` for
every request, which led to comparing the `T_RIGHT_SIGNAL`
constant in `bdev_thylacine.c` against
`kernel/include/thylacine/handle.h`'s `RIGHT_SIGNAL` and
`libthyla_rs / libt`'s `T_RIGHT_SIGNAL` (both `(1u << 5)`).
The driver's constant was the lone outlier.

The Rust `usr/virtio-blk-rw` driver, which uses `libthyla_rs`'s
`T_RIGHT_SIGNAL = (1u << 5)`, was unaffected — that's why its
test (`/virtio-blk-rw` smoke binary on the Thylacine side) has
been passing for many sub-chunks without surfacing this. The
Thylacine session also confirmed the kernel's PROT bits +
descriptor offsets + virtqueue layout + IRQ delivery were all
correct.

## Merge guidance

The fix is a strict subset of the v1-spec'd rights mirror: the
correct constant. Cleanly mergeable to Stratum's `main` (or any
sibling Thylacine-port branch) as a one-line patch. The header
comment carries a hint pointing future readers to the kernel
authority -- `kernel/include/thylacine/handle.h` -- which is the
source of truth.

If the Stratum agent picks this up to merge forward: keep both
the comment + the constant change. The comment is binding
documentation of the rights-bit layout (it prevents a future
bug-equivalent from re-emerging).

## What the Thylacine session is committing on its side

Independent of this Stratum commit:
- Thylacine kernel: no change (the kernel already had
  `RIGHT_SIGNAL = (1u << 5)` correctly).
- Pouch musl patch series: NEW `0011-pouch-abort.patch`
  overrides musl's `src/exit/abort.c` to call `_Exit(127)`
  directly (skipping the `raise(SIGABRT) + a_crash()` chain,
  which would extinct the Thylacine kernel via the deliberate
  NULL-deref `a_crash()` macro under v1.0's
  FAULT_UNHANDLED_USER policy).
- `usr/joey/joey.c`: progressive per-retry pipe drain +
  post-failure bounded drain + final `t_wait_pid` for stratumd
  so a child zombie doesn't reparent to kproc with a wrong-pid
  conflict on the kproc-side wait_pid.

The Stratum-side commit (this branch) is independent and merges
cleanly even without the Thylacine-side changes — they fix
adjacent but disjoint problems.

## Test posture

Thylacine side: `BOOT_TIMEOUT=420 tools/test.sh` reports
`599/599 PASS` on the default build + UBSan matrix. Boot
banner `Thylacine boot OK` reached. `joey: stratumd-boot child
exit_status=1 (final drain)` reproducibly. No kernel
extinctions. The user's Thylacine session covers the Thylacine
side; this Stratum-side patch is the unblock of the bdev-read
half.

## Commit message (for this Stratum branch)

```
Thylacine bdev arm: fix T_RIGHT_SIGNAL constant (bit 5, not bit 3)

src/block/bdev_thylacine.c's T_RIGHT_SIGNAL mirror constant was
defined as (1u << 3), which is the Thylacine kernel's RIGHT_TRANSFER
bit, not RIGHT_SIGNAL (= (1u << 5) per kernel/include/thylacine/handle.h
and libthyla_rs / libt). The bug let t_irq_create succeed (the rights
mask was within RIGHT_ALL) but every subsequent t_irq_wait failed the
kernel's `slot->rights & RIGHT_SIGNAL` gate, returning -1; do_request's
`if (count < 0) return STM_EIO;` collapsed every read/write to EIO and
stm_sb_mount_scan saw every label_read fail.

Found via a Thylacine-side debugging session in
P6-pouch-stratumd-boot sub-chunk 16b-gamma-mount-close (the bdev read
I/O block of the boot pool mount path). See
docs/session-handoff-2026-05-25-thylacine-bdev-right-signal-fix.md
for the full diagnosis trail.

After the fix the bdev's full read/write/fsync path runs end-to-end
under the in-process VirtIO 1.2 driver. stm_sb_mount_scan decodes
the uberblock at pool.img label-0 slot-4 (STRATUM2 magic at offset
0x4000) and the mount path proceeds. A separate downstream failure
in pool_open / alloc_open / sync_create surfaces as a clean exit-1
(NOT in this fix's scope -- tracked on the Thylacine side as the
next sub-chunk's work).

Authored by the Thylacine session for P6-pouch-stratumd-boot 16b-gamma
on `thylacine-pouch-arm`. The Stratum agent was paused during this
work per the user's cross-project coordination preference.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```
