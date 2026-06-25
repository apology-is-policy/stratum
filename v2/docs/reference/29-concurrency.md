# 29 — Concurrency model (as-built)

> Stratum Stabilization Arc, **Area D** ("heavy concurrent writes through one
> session"). As-built reference for the threading model, lock hierarchy, EBR
> reclamation, and the wait-free read path. Written 2026-06-25 from the Area D
> line-by-line audit + the ASan + bench ground truth. Companion specs:
> `specs/concurrency.tla`, `specs/concurrency_mvcc.tla`.

## 29.1 — Purpose + the one-paragraph model

Stratum's FS core (`stm_fs`) is **concurrency-capable**: it permits parallel
single-inode mutators (per-inode locks), wait-free metadata reads (EBR-pinned
MVCC), and serializes only the genuinely shared resources (the dirty buffer,
the per-dataset extent index, the allocator, the block device). Its model
mirrors a kernel FS's `i_rwsem` + RCU shape: **reads are wait-free; writes
serialize per-inode; disjoint inodes proceed in parallel**. The serialization a
Thylacine workload actually sees, however, comes from a layer ABOVE the core —
see §29.6.

## 29.2 — Threading model — where concurrency does and does not arise

`stratumd` is **thread-per-connection with serial per-connection processing**
(`src/cmd/stratumd/serve.c`): the accept loop spawns one detached worker
pthread per connection; each worker reads + handles one 9P request at a time
(`stm_9p_server_handle`), strictly serially. **Two requests on one connection
never execute concurrently server-side.** True concurrency on the FS core
therefore arises only across **multiple** connections (multiple workers).

Consequence for Thylacine (the only client): every Proc resolves through one
shared kernel dev9p mount = **one** connection = **one** serial worker, so a
single user's concurrent FS workload (`make -j`, parallel `go build`) is
serialized at the 9P server even though the kernel pipelines the wire (the #841
elected reader). The FS core's concurrency machinery sits **unused** at v1.0.

## 29.3 — Lock hierarchy (held in this order, never reversed)

From `src/fs/fs.c:23-79` (the authoritative comment):

```
fs->global  (rwlock; EX for compound ops, SH for per-inode + pure-read ops;
             writer-preference attr to prevent EX starvation, R133 P1-1)
   -> per-inode handle->mu        (PARALLEL-3 SH path; stm_inode_pin)
   -> dirty_buffer->mu            (global; src/dirty_buffer/dirty_buffer.c:59)
   -> sync->lock                  (src/sync/sync.c:163)
   -> alloc->lock                 (src/alloc/alloc.c:77)
   -> alloc's btree rwlock
```

Plus the per-dataset `extent_index->lock` (`src/extent/extent_index.c:146`) and
the one-in-flight `bdev d->lock` (`src/block/bdev_thylacine.c:209`, invariant
B-2). Documented deadlock-avoidance rules:

- **Never** `stm_fs_mark_wedged` under a held `fs->global` EX (recursive
  same-thread wrlock is POSIX-undefined; capture intent, unlock, then wedge —
  R133 P1-2).
- **Never** take `alloc->lock` then `sync->lock` (commit owns the reverse).
- Multi-inode ops pin in **ascending `(dataset_id, ino)` order**
  (`stm_inode_pin_two`/`_pin_many`; `src/stratum/inode.h:509`) — `NoCircularWait`.
- Dirty-buffer drain callbacks run **under `buf->mu`**; a callback must not
  re-enter the buffer.

## 29.4 — The three op classes (PARALLEL-3)

| Class | Lock taken | Concurrency |
|---|---|---|
| Compound ops (commit, snapshot, unmount, legacy writes) | `fs->global` **EX** | fully serialized |
| Single-inode mutators (chmod/chown/utimens/unlink/rename/reflink/truncate/write) | `fs->global` **SH** + per-inode pin(s) | parallel on disjoint inodes; serialized on the same inode |
| Pure reads (stat/read-INLINE/lookup/readlink/readdir/getxattr/...) | **none** (LF-3 wait-free): atomic wedge gate + EBR pin | fully wait-free |

A single-inode write holds `fs->global` SH; a commit takes EX, which drains the
SH holders first — so **writes and commit are mutually exclusive**, no quiesce
primitive needed.

## 29.5 — EBR + the wait-free read path

Wait-free reads (`src/fs/fs.c` `FS_GUARD_READ_LOCKLESS` sites) take no rwlock:
they `stm_ebr_enter`, atomic-acquire-load `mvcc_root`, descend, `stm_ebr_exit`.
EBR (`src/ebr/ebr.c`, `specs/concurrency_mvcc.tla`) keeps a COW-superseded node
alive until every reader that could observe it has exited its epoch; writers
`stm_ebr_retire` instead of freeing.

**R171 status (the lock-free-read UAF family — known, dispositioned, NOT
v1.0-reachable).** The wait-free read path has a documented P0 use-after-free
family (`src/btree_engine/engine.c:214-233`): a wait-free reader's leaf-value
memcpy can race the writer's **in-place** `eng_leaf_put` `free(old);val=new`
upsert (P0-1); the engine struct can be freed by rollback/`dataset_destroy`
under a reader (P0-2); `invalidate_memtree` can free the tree under a pinned
reader (P0-4). The shipped mitigation is the **R171 P1-1 SH-fallback** (a
wait-free read that observes a torn decode as `STM_ECORRUPT` retries under
`fs->global` SH). The **true closure is the unbuilt Phase 9.8 BE-write half**
(writers CAS-prepend onto the per-node delta chain + EBR-retire; chunks 7-11 +
9b — see `docs/phase-9.8-design.md` §5.1.1).

The family needs a concurrent reader+writer on ONE engine, which a single
serial connection never produces, so it is **unreachable at v1.0** (the boot,
the go-build) and reachable only under **multi-connection-same-dataset** (A-5b
multi-user, or any concurrent-FS-throughput lift). Ground truth (Area D): real
by construction yet it did **not** reproduce under direct ASan stress
(2,000,000 wait-free reads racing 2,000,000 same-inode writes, zero torn
reads). Disposition: **seam to the post-Go concurrent-FS arc** — schedule the
9.8 BE-write half before multi-connection-same-dataset ships.

## 29.6 — Throughput characterization

`tests/bench_concurrent_write.c` (N writers, distinct inodes, AEAD on,
non-sanitized build; env-knobbed `STM_BENCH_WRSZ`/`NWRITES`/`COMMIT`/`THREADS`).

**Multi-thread scaling (64 KiB records, commit/32):**

```
threads   agg_MB/s   scaling_vs_1
   1        ~62          1.00x
   2        ~60          ~0.96x
   4        ~54          ~0.86x
   8        ~58          ~0.93x   (run-to-run host noise; the point is: no gain)
```

Aggregate throughput is **flat** across thread count — concurrent writers all
funnel through the global `dirty_buffer->mu`, the per-dataset
`extent_index->lock`, the global `alloc->lock`, and the one-in-flight
`bdev d->lock`. The multi-connection (A-5b) write-scaling ceiling.

**Single-thread decomposition (the absolute number is per-extent-overhead-
bound, NOT crypto- or commit-bound):**

```
record size   commit cadence       MB/s
   64 KiB      every 32 (8 commits)  52.8
   64 KiB      end-only (1 commit)   51.7   <- commit cadence is IRRELEVANT
    1 MiB      every 8              166.2
    4 MiB      every 2              199.5   <- ~4x, approaching the AEAD ceiling
```

The dominant single-thread cost is a **fixed per-extent overhead** (extent-index
btree insert + a Merkle node + AEAD nonce/tag setup + alloc), independent of
write size. Small (64 KiB) records pay it on every write -> ~52 MB/s; 4 MiB
records amortize it -> ~200 MB/s, roughly the 2-pass XChaCha20-SIV software-AEAD
ceiling (so at large records it genuinely is approaching crypto-bound). fsync /
commit cadence is NOT the bottleneck (1 commit == 8 commits).

**Implication for the go-build (perf-debt, designed fix).** A `go build` is a
small-write storm (object files, `$WORK` intermediates) -> the
per-extent-overhead-bound ~52 MB/s regime, not the 200. The fix is the **9.8
BE-write half's Bε buffer** (batches N small updates into O(N/B) physical
writes -- `docs/phase-9.8-design.md` §5) -- the SAME work that closes R171 and
unlocks concurrency -- plus **Area S** (small-files/small-write batching). The
absolute crypto delta (with/without AEAD) is **Area E's** headline; Stratum has
no unencrypted mode (the keyfile gates everything), so isolating it needs a
cipher-bypass build (an Area E prerequisite).

## 29.7 — Tests + the TSan caveat

- `tests/test_compound_ops_concurrent.c` — the mature PARALLEL-3 suite
  (per-inode chmod/create-unlink/rename-NoCircularWait/reflink/cfr + a
  compound-op-vs-reader); **ASan-clean** (R132/R134-audited).
- `tests/test_concurrent_lf_read.c` (Area D) — the wait-free-read-vs-writer
  stress/characterization (the gap the suite above lacked); ASan-clean,
  permanent coverage. NOT a default gate.
- `tests/bench_concurrent_write.c` (Area D) — the §29.6 scaling probe.

**TSan caveat:** ThreadSanitizer is **broken on macOS arm64** after the 2026-06
OS update (it crashes inside `__tsan::SlotLock` dereferencing a null
ThreadState — a runtime defect, not a Stratum bug). So the data-race class that
ASan cannot catch (lost updates, non-crashing torn reads) is currently covered
by **adversarial code review + the mature suite + ASan**, not by TSan. Re-run
the concurrency suite under TSan on a Linux host or a fixed toolchain when
available.

## 29.8 — Known caveats / footguns

- The wait-free read path does NOT synchronize against `stm_fs_unmount`
  (R171 P1-3); callers MUST quiesce in-flight reads before unmount. stratumd's
  shutdown drains workers first, so the production obligation holds.
- The per-inode mutex is released between `stm_inode_lookup` and
  `stm_inode_set` (fs.c:3629-3632), but the caller's per-inode PIN excludes any
  other writer across that window — do not remove the pin.
- The dirty buffer is a single global mutex, not per-inode; concurrent writers
  to distinct inodes still serialize there (§29.6 is why).
