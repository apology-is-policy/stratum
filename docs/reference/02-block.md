# 02 — Block device

## Purpose

The floor of the stack. `stm_bdev` is a vtable-based abstraction over
raw storage. Every on-disk byte — uberblocks, btree nodes, extents,
bootstrap-pool bits — travels through this interface. The goal is to
hide backend specifics (POSIX pread/pwrite, Linux io_uring, future
libaio / DAX) behind one sync + async surface while preserving the
invariants the upper layers rely on.

The four invariants (documented at `include/stratum/block.h:12`):

1. **Writes are unordered without fsync.** Two writes submitted in
   order may land on media in any order.
2. **Reads see data before the last completed fsync.** Reads of
   in-flight post-fsync writes may see old or new bytes.
3. **Completions fire on arbitrary threads.** Callbacks must be
   thread-safe.
4. **Submission guarantees eventual completion.** Each op completes
   exactly once (success or failure) unless the device is torn down.

The abstraction is flat-byte-addressed (0 to device size). 4 KiB
block granularity is an allocator concern, not a bdev concern.

## Public API

### Lifecycle

```c
stm_bdev_open_opts stm_bdev_open_opts_default(void);
stm_status stm_bdev_open (const char *path, const opts*, stm_bdev **out);
void       stm_bdev_close(stm_bdev *d);
const stm_bdev_caps *stm_bdev_caps_of(const stm_bdev *d);
```

Open options:

| Field | Meaning |
|---|---|
| `backend` | `AUTO` (io_uring on Linux, POSIX elsewhere), `POSIX`, `IOURING`. |
| `direct` | `O_DIRECT` — bypass page cache. Typically false for file-backed tests. |
| `read_only` | Enforced at write-op time (rejected with `STM_EROFS`). |
| `queue_depth` | Async queue size. 0 → backend default (512). |
| `fixed_buffer_bytes` | io_uring only — fixed-buffer region size. |
| `posix_threads` | Thread-pool size on POSIX async. 0 → CPU count, capped 64. |
| `claimed_fd` | NULL, or where a descriptor the caller holds on the device is (`stm_bdev_claim_image` gives one): that open file is the device, `path` only names it, nothing is created, and `direct` cannot be asked. A negative one stands for none. The claim refuses a disk the system is using (mounted), `STM_EBUSY` with errno `EBUSY`: macOS opens no mounted disk's block node, and a claim of a raw node, whether it opened that node for writing or for reading alone, opens its block twin for reading as well (its device number checked against the raw node's, `STM_ESTALE` where it is another device), which a mounted disk refuses (measured: the raw node of a mounted slice opens read-write), and holds it locked beside its own: a disk's two nodes are two locks, and every claim of the disk meets on the block node's (measured on a RAM disk, each order of the two). The claim gives that second descriptor back as well (`out_hold_fd`), to be kept as long as the claim is. On Linux the claim also opens a block device exclusively (`O_EXCL`, by name, its device number checked against the first open, `STM_ESTALE` where the name led to another device between the two), holding the exclusion while its descriptor is open, and locks it before closing the first open, so udev, hearing of that close, finds it locked and leaves it be. On a Linux block device the lock retries for up to 5 s, as systemd's block-device locking contract asks: udev holds a shared lock on a whole disk while it processes an event, which a close after a write raises. Where it cannot be locked at all, `STM_ENOLCK` comes with the exclusive descriptor, still held. |

`stm_bdev_caps` reports the backend actually selected, logical size,
physical block size, max single-op size, whether TRIM / SQPOLL / DAX /
fixed-buffers are available. Caps are frozen after open, except the
size, which `stm_bdev_resize` moves.

### Sync ops

```c
stm_status stm_bdev_read    (d, offset, buf,       len);
stm_status stm_bdev_write   (d, offset, buf,       len);
stm_status stm_bdev_fsync   (d);
stm_status stm_bdev_fdatasync(d);
stm_status stm_bdev_discard (d, offset, len);     // TRIM; STM_ENOTSUPPORTED on unsupported
stm_status stm_bdev_resize  (d, new_size);        // grow only; ENOTSUPPORTED for non-file
```

Offsets are byte-flat. The backend auto-splits requests larger than
`caps->max_io_bytes`. Alignment to `caps->block_size` is required
only when `direct = true`.

A write whose span `[offset, offset + len)` is not within
`caps->size_bytes` is refused `STM_EINVAL` in `bdev.c`, before the
backend, and nothing is written; `STM_EROFS` on a read-only device comes
first; a write of no bytes fits anywhere. A `pwrite` past a file's end grows the file and leaves the size
behind it, where a block device refuses the same write; the bound makes
every backend refuse it (the Thylacine driver also bounds its own sector
span). The size is the handle's: from the open, or the last
`stm_bdev_resize` through it.

A read whose span is not within the same size fails `STM_EIO` in
`bdev.c`, before the backend, and reads nothing; a read of no bytes
fits. The device cannot supply bytes past its end, and `STM_EIO` is how
the replica readers know a replica the device could not read
(`sync_eio_unreadable` then asks whether the device reads its labels:
the pool's failure, or the record's, with another replica to try).
Before the bound the backends answered each their own way: posix a
short read's `STM_EIO`, or `STM_EINVAL` for an offset past 2^63, or the
file's bytes where it had grown past the handle's size; io_uring the
same for a synchronous read, and for an asynchronous one past the
file's end `STM_OK` with fewer bytes; the Thylacine
driver its sector bound's `STM_EINVAL`, which the readers take as the
device's error, so a read left with no good replica was the pool's
failure there and the record's on a host.

`stm_bdev_current_bytes` answers the device's size now: a regular
file's length (cut or grown under the handle, which `caps->size_bytes`
does not see), else `caps->size_bytes`. `stm_bdev_is_read_only` answers
whether every write would be refused `STM_EROFS`. The uberblock writer
asks both before and after its copies (07-sb-sync).

### Async ops

```c
typedef void (*stm_bdev_completion_cb)(const stm_op_result *res);

stm_status stm_bdev_submit_read (d, offset, buf,       len, cb, user);
stm_status stm_bdev_submit_write(d, offset, buf,       len, cb, user);
stm_status stm_bdev_submit_fsync(d,                          cb, user);

int        stm_bdev_poll_completions(d, max_events);      // non-blocking
int        stm_bdev_wait_completion (d, max_events);      // blocks for completions
```

Completions:

| Field | Meaning |
|---|---|
| `kind` | `STM_OP_READ` / `_WRITE` / `_FSYNC`. |
| `status` | `STM_OK` or negative status. |
| `bytes` | Bytes transferred (reads + writes). |
| `user` | Echoed back from submit. |

Result struct is stack-valid only for the duration of the callback;
copy if you need to retain.

`stm_bdev_submit_write` refuses a span past the device's end at the call,
as the synchronous write does, and the callback never runs.
`stm_bdev_submit_read` of a span past the end completes at once: the
callback runs with `STM_EIO` and no bytes before the call returns
`STM_OK` (as `stm_bdev_submit_fsync` on a read-only device completes at
once with `STM_OK`). A read inside the size but past a file cut under
the handle still reaches the backend, and fails `STM_EIO` with no bytes
on every backend.

A read or write completes whole or fails: on `STM_OK`, `bytes` is the
length asked. posix's worker loops `pread`/`pwrite` as the synchronous
path does; io_uring puts back what is left of a transfer the kernel did
part of (the op keeps its slot and stays in flight) and fails one that
moves nothing with bytes left `STM_EIO` (the end of a file cut under the
handle). Before OPEN-BUGS (w) io_uring completed a short transfer
`STM_OK` with fewer bytes. Every op a submit takes completes exactly
once: posix allocates an op's completion with it at the submit, so
memory that runs out refuses the submit `STM_ENOMEM` (before OPEN-BUGS
(x) a completion whose allocation failed was dropped, and a waiter for it
hung).

So a completion may run on the submitting thread before the submit
returns, and then leaves nothing for `stm_bdev_poll_completions` or
`stm_bdev_wait_completion` to deliver: posix's wait blocks until
another completion arrives, io_uring's and Thylacine's return 0. A
caller holds no lock across a submit that its callback takes, and
waits on the op's own state (block.h, invariant 3).

### Fixed buffers (zero-copy)

```c
stm_status stm_bdev_register_buffers(d, bufs[], nbufs, buf_len);
```

io_uring only. Registers pre-allocated buffers that subsequent
`submit_*_fixed` calls (not yet landed) can reference by index,
skipping the per-op copy into kernel memory. Returns
`STM_ENOTSUPPORTED` on POSIX.

## Implementation

Three source files under `src/block/`:

- `bdev.c` — vtable dispatch. Pointer-based fn table (one per backend);
  every public call indirects through the vtable. Adding a backend is
  a file-sized change.
- `posix.c` — POSIX backend. Sync ops use `pread`/`pwrite`. Async is
  simulated via a fixed thread pool that drains an internal queue;
  completion delivery is via per-device lockless queue + condvar. An
  op's one allocation, made at the submit, carries it through both
  queues.
  Its sizing (`op_current_size`) fstats a regular file.
  Its fsync on macOS is `F_FULLFSYNC` for a file; a disk answers that
  ENOTTY, so a disk's is `fsync` then `DKIOCSYNCHRONIZECACHE`.
- `iouring.c` — Linux io_uring backend. Sync ops issue a single SQE,
  wait in the same thread for its CQE. Async ops submit + return,
  driving completion via user-thread `poll_completions` +
  `wait_completion`; the thread reaping a short transfer's CQE submits
  its rest, for a sync op as for an async one. Optional SQPOLL + fixed buffers when the kernel
  supports it.

The vtable has one entry per operation — `open`, `close`, `caps`,
`read`, `write`, `fsync`, `fdatasync`, `discard`, `resize`,
`current_size` (optional: the size now; NULL answers `caps->size_bytes`), six
submit entry points, `poll_completions`, `wait_completion`,
`register_buffers`. New backends (DAX, libaio) plug in by filling out
the same table.

`STM_BDEV_BACKEND_AUTO` picks io_uring on Linux if `STM_ENABLE_IOURING`
was on at compile time AND `liburing` is linked AND the running kernel
exposes io_uring. Otherwise POSIX. The choice is sticky for the
lifetime of the device handle.

### Fault injection

`include/stratum/block_inject.h` exposes:

```c
void     stm_bdev_inject_fail_after(stm_bdev *d, int64_t n_ops);
uint32_t stm_bdev_inject_fired_count(const stm_bdev *d);
```

Arms a countdown in `bdev.c`, ahead of every backend: the N-th
state-changing op (write / fsync / fdatasync) after arming returns
`STM_EIO` without performing I/O. A write refused before it reaches the
device (read-only, or past the device's end) is not an op and leaves the
countdown as it was; a deferred barrier's fsync counts only when it is
issued. Used by `test_crash_inject` to synthesize torn-write scenarios.

Reads are faulted by their own countdown and byte ranges
(`stm_bdev_inject_read_fail_after`, `stm_bdev_inject_read_range`), in a
build with testing hooks only. A read past the device's end fails
before them and leaves the countdown as it was.

## Cross-layer integration

| Caller | Pattern |
|---|---|
| `sb` (label + uberblock I/O) | `stm_bdev_read` / `_write` + `_fsync`. No async. |
| `bootstrap` (header + bitmap slots) | Sync ops only. Slots A/B ping-pong for torn-write safety. |
| `btree_store` (AEAD-encrypted node serialization) | `stm_bdev_read` / `_write` of a 4 KiB ciphertext payload per node. |
| `sync` (commit protocol) | Sync `stm_bdev_write` + `_fsync`, one device after another (each uberblock through `stm_sb_ub_write_copies`); a quorum of devices must confirm. |
| `sync` (mirror read) | Sync `stm_bdev_read`; csum-verify above. |
| `scrub` (P5-5-α) | Per-block sync `stm_bdev_read`; failures counted. |

Note that `sync_commit`'s parallel fan-out currently uses **sync**
writes dispatched in sequence per device, not the async submit API.
The async machinery is present and tested (`test_bdev_async`) but the
commit protocol has not yet been converted to use it. Moving to async
is a Phase 6+ optimization.

## Spec cross-reference

Block is below every TLA+ spec — the specs reason about `paddr`,
`gen`, and commit actions, which map to `bdev_write` + `bdev_fsync`
sequences in the impl. No spec directly models block-layer ordering.

Relevant invariants enforced by the upper-layer specs and preserved
by bdev's contract:

- `sync.tla::DoFinal` — the commit point is an fsync that completes
  AFTER the uberblock write. If bdev violated invariant (2) and
  allowed a read to see unflushed bytes from a torn final-UB write,
  the spec would still hold — mount just rolls back to the previous
  commit.
- `quorum.tla::QuorumSafety` — requires that ≥quorum fsync
  completions are the commit point. Translates to: `submit_write` +
  `submit_fsync` pair per device, wait for N/2+1 successful fsync
  completions.

## Tests

| Suite | Coverage |
|---|---|
| `test_bdev` (see `tests/test_bdev.c`) | Sync roundtrip on file-backed bdev; caps sanity; resize; discard (no-op on file); a read past the end of a file cut under the handle, inside the handle's size, `STM_EIO` from the backend (a partial read that then meets the end, and one wholly past it; one ending at the cut read); a read past the handle's size fails `STM_EIO` before the backend though the file holds bytes there (grown under the handle; wholly past, straddling, wrapping past 2^64), reading nothing and observed by no I/O observer, a read ending at the end and one of no bytes past it accepted, an armed read failure not taken, counted or ranged; a write past the end refused `STM_EINVAL` (a new file's 0 bytes, straddling, wholly past, wrapping past 2^64), counted as no write, the file and caps unchanged, a write ending at the end accepted, read-only answering `STM_EROFS` first. |
| `test_bdev_async` (see `tests/test_bdev_async.c`) | Async submit + poll_completions on POSIX backend; fsync ordering; submit queue saturation; a submit past the end refused at the call with no callback, one ending at the end completing, a write of no bytes past the end fitting, sync and async; a read past the end of a file cut under the handle reaching the backend (no callback before the submit returns) and failing `STM_EIO` with no bytes on every backend; reads and writes the kernel does 512 bytes at a time (`stm_bdev_iouring_short_for_test`, io_uring) completing once, whole, async and sync, every short entry used; an op the posix backend took completing with no allocation left after its submit (`stm_bdev_posix_alloc_budget_for_test`), and a submit with none left refused `STM_ENOMEM`; a read past the handle's size (wholly past, straddling, wrapping past 2^64) completing at once with `STM_EIO`, no bytes and kind `STM_OP_READ`, its callback run once, before the submit returns, its buffer never written, though the file holds bytes there, one ending at the end completing. |
| `test_crash_inject` (separate module) | Uses `stm_bdev_inject_fail_after` to force write/fsync failures and verify sync's rollback + remount paths converge. ~168 cycles; TSan timeout 180s. |

## Status

- [x] POSIX backend. Sync + thread-pool async. Fault injection on
      write + fsync.
- [x] io_uring backend. Sync + async, optional SQPOLL, optional
      fixed buffers. Gated by `STM_ENABLE_IOURING=ON`.
- [x] Vtable dispatch.
- [x] `submit_*_fixed` (fixed-buffer async on io_uring): API stub;
      not yet implemented. Returns `STM_ENOTSUPPORTED` on call.
- [ ] libaio backend (compat for pre-io_uring Linux): planned,
      not started.
- [ ] DAX / PMEM backend: planned, not started (Phase 9+ when PMEM
      target exists).
- [x] Read-op fault injection: a countdown and byte ranges, in a
      build with testing hooks (`block_inject.h`).

## Known caveats

- **POSIX backend's `ftruncate`-on-open** for file-backed devices
  can silently grow an underlying file. If a caller truncates the
  file while the bdev is open, `stm_bdev_resize` to the original
  size will re-extend with zeros (scrub's io-fail test exploits this
  to stage read failures).
- **The write and read bounds are the handle's size.** A file truncated
  while a handle is open keeps the old size in `caps->size_bytes`, so a
  write between the new end and the old one still grows it back (and a
  read there gets a short read's `STM_EIO` from posix); one grown by
  another process is written and read only up to the size the handle
  has.
- **io_uring polling requires a user thread**. There is no internal
  thread that drains completions; if the caller stops calling
  `poll_completions` / `wait_completion`, submitted ops accumulate
  in the CQE ring and eventually block on submission.
- **Discard is a hint**, not a mandate. The backing store may silently
  ignore TRIM requests. Upper layers do not rely on physical release.
- **No async-cancel API**. Once submitted, an op completes (success
  or failure). Teardown blocks until all in-flight ops finish.
