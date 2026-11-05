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

`stm_bdev_caps` reports the backend actually selected, logical size,
physical block size, max single-op size, whether TRIM / SQPOLL / DAX /
fixed-buffers are available. Caps are frozen after open.

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

### Async ops

```c
typedef void (*stm_bdev_completion_cb)(const stm_op_result *res);

stm_status stm_bdev_submit_read (d, offset, buf,       len, cb, user);
stm_status stm_bdev_submit_write(d, offset, buf,       len, cb, user);
stm_status stm_bdev_submit_fsync(d,                          cb, user);

int        stm_bdev_poll_completions(d, max_events);      // non-blocking
int        stm_bdev_wait_completion (d, max_events);      // blocks until ≥1
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
  completion delivery is via per-device lockless queue + condvar.
  Host of fault-injection (`include/stratum/block_inject.h`).
- `iouring.c` — Linux io_uring backend. Sync ops issue a single SQE,
  wait in the same thread for its CQE. Async ops submit + return,
  driving completion via user-thread `poll_completions` +
  `wait_completion`. Optional SQPOLL + fixed buffers when the kernel
  supports it.

The vtable has one entry per operation — `open`, `close`, `caps`,
`read`, `write`, `fsync`, `fdatasync`, `discard`, `resize`, six
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

Arms a countdown on the POSIX backend — the N-th state-changing op
(write / fsync / fdatasync) after arming returns `STM_EIO` without
performing I/O. Used by `test_crash_inject` to synthesize torn-write
scenarios. POSIX-only; a no-op on other backends.

**Read ops do NOT fire inject** (posix.c:163). The P5-5-α scrub test
uses file truncation to force read failures instead (see
`tests/test_scrub.c::scrub_step_counts_io_error_as_failed`).

## Cross-layer integration

| Caller | Pattern |
|---|---|
| `sb` (label + uberblock I/O) | `stm_bdev_read` / `_write` + `_fsync`. No async. |
| `bootstrap` (header + bitmap slots) | Sync ops only. Slots A/B ping-pong for torn-write safety. |
| `btree_store` (AEAD-encrypted node serialization) | `stm_bdev_read` / `_write` of a 4 KiB ciphertext payload per node. |
| `sync` (commit protocol) | Fan-out parallel writes across devices via `stm_bdev_submit_write` + `_submit_fsync`; wait for quorum. |
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
| `test_bdev` (see `tests/test_bdev.c`) | Sync roundtrip on file-backed bdev; caps sanity; resize; discard (no-op on file); read past EOF returns STM_EIO via `posix_pread_full` short-read check. |
| `test_bdev_async` (see `tests/test_bdev_async.c`) | Async submit + poll_completions on POSIX backend; fsync ordering; submit queue saturation. |
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
- [ ] Read-op fault injection: intentionally not wired; scrub tests
      use file truncation instead.

## Known caveats

- **POSIX backend's `ftruncate`-on-open** for file-backed devices
  can silently grow an underlying file. If a caller truncates the
  file while the bdev is open, `stm_bdev_resize` to the original
  size will re-extend with zeros (scrub's io-fail test exploits this
  to stage read failures).
- **io_uring polling requires a user thread**. There is no internal
  thread that drains completions; if the caller stops calling
  `poll_completions` / `wait_completion`, submitted ops accumulate
  in the CQE ring and eventually block on submission.
- **Discard is a hint**, not a mandate. The backing store may silently
  ignore TRIM requests. Upper layers do not rely on physical release.
- **No async-cancel API**. Once submitted, an op completes (success
  or failure). Teardown blocks until all in-flight ops finish.
