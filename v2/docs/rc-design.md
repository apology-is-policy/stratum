# RC — the stm_sync concurrency arc (design)

Status: **SCRIPTURE (ratified 2026-07-10; user votes in section 9). No code has
landed for this arc; this document binds the implementation.**

The successor to the CF arc (Thylacine `docs/CONCURRENT-FS.md`, CF-1..CF-5) and
the completion of the 9.8 concurrency story: retire `stm_sync.lock` as the
whole-op wrapper on the extent DATA path (reads AND writes), so the concurrency
the 9.8-BE/EBR arc built into the metadata engine — and the worker pool CF-2
built into stratumd — actually delivers parallel FS service to a parallel
client. Consumer: the Thylacine on-device `go build` (the perf mission's
oracle); beneficiary: every concurrent FS workload through a 9P mount.

## 1. The problem, quantified (2026-07-10 in-guest measurement)

Two instrumented boots (STMD26 server-side + DIAG23 guest-side; the cold-twin
gofmt bench):

- The guest OFFERS real concurrency: avg in-flight depth 1.6–1.9; 69–75% of 9P
  sends at depth >= 2; `rpc_ms`/wall = 1.75–1.9 (ops overlap in flight but
  serialize in service).
- Boot B (`--fs-workers 4`, the CF-2 pool ON): wall REGRESSED (+7% cold /
  +13% warm). **`s->lock` wait exploded 0.03 ms -> 141 ms cold (~4700x)**
  while the bdev `d->lock` wait stayed ~7 us — the workers never reach the
  device concurrently; `s->lock` single-files them one layer up.
- The serializer, pinned: `stm_sync_read_extent` (sync.c:6457) takes ONE
  exclusive `pthread_mutex_t` (`s->lock`, sync.c:208) across the ENTIRE read:
  extent-index lookup + CAS lookup + **the blocking bdev I/O** + **the AEAD
  decrypt** + the dcache probe/insert. Writes, truncate, punch, commit, and
  every admin op take the SAME mutex.

So today: N concurrent client requests -> N stratumd workers -> ONE mutex.
The pool pays handoff overhead for zero parallelism; with the pool off, the
same serialization just moves to the dispatch loop. Either way the service is
serial and every op queues behind its peers' device I/O and decrypt.

## 2. Ground truth — what is already built vs what this arc builds

Verified in-tree 2026-07-10 (survey memo; code over stale docs):

| Layer | State | Evidence |
|---|---|---|
| fs core | ALREADY CONCURRENT: `fs->global` rwlock (EX only for compounds); pure metadata reads WAIT-FREE (EBR, 9.8-LF-3: the 21 read ops incl. read-INLINE); single-inode mutators SH + per-inode pin (PARALLEL-3) | fs.c:1005, fs.c:2411 (INLINE wait-free), 29-concurrency.md |
| metadata engine | ALREADY CONCURRENT: readers descend delta-chain -> buffer -> base under an EBR pin; writers CAS-prepend + EBR-retire. R171 P0-1 (in-place upsert UAF) + P0-2 (engine-struct free) + P0-4 (memtree free) CLOSED (chunks 9/9b/10). **P0-3 (unmount vs wait-free readers, #1232) OPEN, production-mitigated** (stratumd drains before unmount) | engine.c; 29-concurrency.md section 29.7-29.8 |
| extent index | Has BOTH a serial (`stm_extent_lookup_at`, self-locks `idx->lock`) AND a wait-free EBR (`stm_extent_lookup_at_concurrent`, extent_index.c:2233) lookup. The sync read path uses the SERIAL one | sync.c:6083 |
| stratumd | The CF-2 per-connection worker pool is BUILT (fid pins, real Tflush, writer mutex, N=1 fallback) but DEFAULT-OFF because it regresses (this arc's problem) | serve.c, server.c |
| **stm_sync** | **THE GAP: one exclusive mutex wraps the whole extent data path.** Never touched by the concurrency arc; 29-concurrency.md does not even list it as a concurrency surface | sync.c:208, 6457, 5817 |
| bdev | B-2 one-in-flight per virtqueue (`d->lock`); measured ~7 us wait (host-page-cached pool) — NOT the current bottleneck; becomes real on hardware | bdev_thylacine.c:222 |

**Why `s->lock` is held across the blocking I/O: incidentally.** The layers it
wraps (extent index, CAS index, bdev, AEAD) each carry their own locks or are
thread-local. The ONLY sync-owned state the data path mutates is the **dcache**
(every miss inserts; sync.c:6299/6437), the **promote_cache**
(sync.c:5923-5925), and (on writes) the alloc/index reservations — each
separable. This also RULES OUT the shared-mode shortcut: a read is not
read-only w.r.t. `s->lock`'s state, so "readers take SH" would corrupt the
dcache. The lock must come OFF the path, with the state it protected moved to
its own fine-grained mechanisms.

**The s->lock site inventory (51 acquires in sync.c), grouped:**

- **Hot data path (the retirement targets):** `stm_sync_read_extent` (6457),
  `stm_sync_read_extent_at_snap` (6523), `stm_sync_write_extent` (5817),
  `stm_sync_truncate` (6593), `stm_sync_punch_range` (6923).
- **Compounds/admin (KEEP `s->lock`, exclusive + brief):** `stm_sync_commit`
  (2566; additionally under `fs->global` EX at the fs layer), the device
  family (attach/reserve_mirror/mirror_rw/evacuation/remove/replace), the
  keyschema family (add/rotate/sweep/install_dek/evict_dek/get_dek), the CAS
  GC sweep.
- **Scalar getters + test hooks:** brief locked reads (info/gen/serial/stats/
  drain-for-test) — unchanged; once the data path stops holding `s->lock` for
  whole ops, these no longer contend with it.

## 3. Prior art (brief — it collapsed the forks)

- **ZFS ARC:** hash-bucket locks + per-buffer refcounts; readers pin a buffer,
  copy outside the hash lock; eviction skips pinned buffers. The canonical
  decrypted-block-cache shape.
- **Linux page cache:** RCU/xarray lookup + per-page refcount + per-page lock;
  reclaim cannot free a page a reader holds.
- **In-tree:** Stratum already ships EBR (`src/ebr/`, 04-ebr.md) as THE
  reclamation idiom — the engine's readers run under epoch pins and writers
  retire superseded nodes. Applying the same idiom to the dcache is the
  least-new-machinery instantiation of the ARC/pagecache shape (epochs instead
  of per-buffer refcounts).
- **The write side:** WAFL/ZFS-style COW cores let data writes proceed
  concurrently and serialize only at allocation + index-insert points — which
  Stratum's alloc (`alloc->lock`) and extent index (`idx->lock`) already
  provide as self-locked leaves.

## 4. The design — staged, soundness first

### RC-1 — the EBR-pinned dcache (the highest-value single change)

Move the dcache OFF `s->lock` onto its own concurrency discipline
(user-voted: **EBR-pinned entries**):

- **Lookup (hit):** reader enters an EBR pin -> walks the (existing CF-5a)
  chained hash under a per-bucket guard or an atomic-published chain ->
  memcpys the plaintext OUT while pinned (no global lock; the pin guarantees
  the buffer cannot be freed under the copy) -> exits the pin.
- **Insert / evict / drain:** publish the new entry into its bucket
  (CAS-prepend or under the bucket lock); eviction UNLINKS the victim from the
  bucket, then **EBR-retires** the entry + its plaintext buffer — the free runs
  only after every pinned reader has exited its epoch (the engine's exact
  discipline; closes the evict-frees-under-reader UAF, invariant I-dcache-2's
  concurrent generalization).
- **Accounting** (`dcache_bytes`, hits/misses/tick): atomics.
- The CF-5a write-populate inserts through the same path.
- **RC-I1 (the invariant):** no dcache plaintext buffer is freed while any
  reader holds a reference obtained from a bucket walk; a lookup never
  observes a torn entry (publish is atomic: fully-initialized-before-linked).
- Every dcache accessor currently asserts/relies on `s->lock` (I-dcache-4,
  32-decrypted-extent-cache.md) — RC-1 rewrites that contract; the reference
  doc's as-built section updates with the impl.

### RC-2 — retire `s->lock` from the READ path

`stm_sync_read_extent{,_at_snap}` restructure:

1. **Brief locked prologue** (or lock-free equivalents): `s->wedged` check
   (atomic read), snapshot `s->current_gen` (relaxed atomic), resolve the DEK
   (see the DEK guard below).
2. **Extent lookup via the EBR `_concurrent` variant**
   (`stm_extent_lookup_at_concurrent`) — wait-free, matching the fs-core
   discipline; the serial `stm_extent_lookup_at` stays for the callers that
   still hold exclusivity.
3. **dcache probe** (RC-1 mechanism). Hit -> copy under pin -> done.
4. Miss: CAS lookup (self-locked, brief) -> scratch alloc -> **bdev read +
   AEAD decrypt fully UNLOCKED** (thread-local buffers; the bdev's own
   `d->lock` is the only device serialization) -> **dcache insert** (RC-1) ->
   copy out.
5. `promote_read_hit` stays self-locked on `idx->lock` (it is a write on the
   read path; if it contends, make the counter relaxed-atomic best-effort).
   The **promote_cache** gets its own small lock or per-entry atomics.

**The same-inode reader-pin (the fs.c:2314 forward-note, discharged here):**
retiring the coarse lock opens EXTENT-read vs same-inode truncate/write
interleaving mid-read. The fs layer carries the already-built PARALLEL-3
per-inode pin down: `stm_fs_read`'s extent arm takes the inode's read-side pin
(shared) so a truncate/punch/write on the SAME inode excludes mid-read
(disjoint inodes proceed fully parallel). **RC-I2:** a read observes either
the pre-image or the post-image of any same-inode mutation, never a mix.

**The DEK guard (the one genuinely NEW synchronization):** the read path
consults `s->deks`/keyschema (sync_dek_find, sync.c:6347) which
install/evict/rotate mutate. Mechanism: a seqlock (readers retry on a torn
window) or EBR-published DEK slots — chosen at impl for the smaller audit
surface; the admin mutators keep `s->lock` + the new guard's write side.
**RC-I3:** a reader never uses a torn or freed DEK; an evicted dataset's
reader fails closed (the A-5 evict contract — a post-logout read DENIES, the
CF-5a F1 lesson: evict must also drain/invalidate the dcache entries it
covers, which RC-1's drain provides).

**P0-3 re-verification:** unmount vs the new concurrent readers — the
stratumd drain (workers quiesce before unmount) must cover the RC read paths;
re-verify + document (or close #1232 properly if the drain shows a gap).

### RC-3 — retire `s->lock` from the WRITE path (user-voted scope)

`stm_sync_write_extent` / `stm_sync_truncate` / `stm_sync_punch_range`
restructure on the same pattern:

1. **Brief locked reservation:** alloc (self-locked `alloc->lock`) + any
   sync-scalar state; DEK resolve via the RC-2 guard.
2. **AEAD encrypt + bdev write UNLOCKED** (thread-local; the expensive parts —
   this is where concurrent writers to distinct extents overlap).
3. **Brief locked epilogue:** extent-index insert (self-locked `idx->lock` /
   the engine's CAS-prepend), the CF-5a dcache write-populate (RC-1 insert),
   accounting.
- The fs-layer per-inode pin (EX side) already serializes same-inode writers
  (PARALLEL-3); disjoint-inode writers overlap. The dirty-buffer funnel
  (`dirty_buffer->mu`) and `alloc->lock` REMAIN — they are self-locked leaves
  above/beside this path; widening them is a LATER arc (recorded seam), not
  RC. RC's win is overlapping the encrypt+device-write, not the buffer
  bookkeeping.
- **Commit exclusion unchanged:** `stm_sync_commit` keeps `s->lock` AND runs
  under `fs->global` EX — no read/write is in flight at the fs boundary
  during a commit (PARALLEL-3's compound class). **RC-I4:** the commit's
  quiesce envelope is preserved; no RC path holds a pin/lock across a commit
  boundary that could deadlock the EX acquisition.
- **R175-carried obligations go LIVE with concurrent writes** (from CF-2's
  design): (a) the serial range scans (inode seed/find_freed, extent
  collect/overlap, dirent unlink sweep, xattr list) hold `serial_mu` for whole
  walks — chain-growth/space-amp pressure under a scan-heavy pool (the
  #39/#40 family, NOT a UAF); close via `_concurrent` scan variants or a
  commit-cadence chain bound. (b) Engine `STM_EBUSY` (seal back-pressure)
  propagation: decide retry-at-dispatch vs propagate-to-client when the pool
  makes it reachable.

### RC-4 — turn the concurrency ON

- `--fs-workers N` default ON (min(4, ncpu)) in the Thylacine boot (joey's
  stratumd argv), measurement-gated: the A/B that regressed pre-RC must now
  WIN; if it does not, the gate holds the default OFF and the residual
  serializer gets hunted before shipping.
- Tflush / fid-pin / writer-mutex (CF-2's built discipline) re-verified under
  real concurrency.

### RC-5 — measure, gate, audit, close

- The STMD26/DIAG23 instruments re-measure the gofmt + build2 + fsbench set
  (s->lock wait must collapse; depth 1.6-1.9 must convert to overlapped
  service; the workers=4 A/B flips from regression to win).
- Focused adversarial audit per audit-bearing stage (RC-1, RC-2, RC-3 —
  the prosecutor list: the RC-I1..I4 invariants + the race list in section 5).
- The full crash/recovery suites + the Thylacine SMP gate (the boot mounts
  through this path) + host ctest matrix (default + gmalloc; the GCP
  ASan/LeakSan pass when refreshed).
- The as-built reference rewrites: 29-concurrency.md gains the sync-layer
  section (its omission is how this serializer went undocumented);
  32-decrypted-extent-cache.md rewrites for RC-1; 27-fs-read-path.md updates.

### Stage 2 (DEFERRED, out of this arc): bdev multi-outstanding

B-2 (one virtqueue request in flight) is ~7 us today (host page cache) —
irrelevant under QEMU-on-M2, load-bearing on real NVMe/SD hardware. A
descriptor-slot pool + per-request completion demux at `bdev_thylacine.c`,
measurement-gated on `br_wait` actually rising once RC makes concurrent reads
reach the device. Recorded seam; do not build speculatively.

## 5. The race list (what `s->lock` was preventing; each needs an owner)

| # | Race | Owner in RC |
|---|---|---|
| 1 | dcache lookup vs insert/evict/drain (every miss mutates) | RC-1 EBR pin + atomic publish (RC-I1) |
| 2 | promote_cache concurrent mutation | RC-2 own lock / atomics |
| 3 | promote_read_hit index write on the read path | existing self-locked `idx->lock` (or relaxed-atomic counter) |
| 4 | `s->current_gen` torn read | relaxed atomic (advisory heuristic) |
| 5 | extent-index lookup vs engine writers | the EBR `_concurrent` variant (built; R171-closed) |
| 6 | CAS-index lookup | existing self-locked `cas_lock` |
| 7 | DEK/keyschema read vs install/evict/rotate | RC-2 DEK guard (seqlock or EBR slots; RC-I3) |
| 8 | EXTENT read vs same-inode truncate/write mid-read | the fs-layer per-inode reader-pin (RC-I2; fs.c:2314 discharged) |
| 9 | unmount vs in-flight concurrent readers (P0-3 #1232) | re-verify the stratumd drain; close or re-document |
| 10 | commit vs in-flight reads/writes | `fs->global` EX (unchanged) + RC-I4 no-pin-across-commit |
| 11 | write-path alloc/index/dirty-buffer | existing self-locked leaves (unchanged; the funnel seam) |

## 6. Spec-first (user-voted YES — the 6th re-enable instance)

Extend the Stratum concurrency spec family BEFORE the impl:

- **`dcache_ebr.tla` (new, or an extension of the existing concurrency
  modules):** the RC-1 lifecycle — readers pin/copy/unpin; writers
  insert/evict/retire; the invariants NoUseAfterRetire (a pinned buffer is
  never freed), NoTornEntry (publish-before-link), plus a liveness witness
  (an evicted entry is eventually reclaimed once unpinned). Buggy cfgs:
  `evict_frees_pinned` (evict frees immediately instead of retiring — the UAF
  counterexample) + `link_before_init` (torn-entry publish).
- **The DEK guard:** either a small `dek_guard.tla` (reader-retry vs
  mutate-in-place; NoTornDEK + fail-closed-after-evict) or an arm of the same
  module.
- The read/write interleaving vs commit (RC-I4) is covered by the EXISTING
  `fs->global` discipline (PARALLEL-3, spec'd in the 9.5/9.8 family) — no new
  module; the SPEC-TO-CODE mapping records the composition.
- TLC green (clean cfgs) + the buggy counterexamples red are the pre-commit
  gate for RC-1/RC-2/RC-3.

## 7. What the arc does NOT do

- **No on-disk format change expected** (pure locking/lifetime). If one
  surfaces, it is escalated per standing policy (the CF-arc format grant was
  scoped to THAT arc and does NOT carry).
- **No 9P wire/ABI change; no Thylacine kernel bytes** (the kernel client is
  already concurrent; the boot flips a stratumd argv at RC-4).
- **No dirty_buffer->mu / alloc->lock widening** (the write-funnel seam — a
  later arc if measurement demands it).
- **No bdev multi-outstanding** (stage 2, deferred).
- **No weakening of commit exclusion** (`fs->global` EX; PARALLEL-3 classes
  unchanged).

## 8. Expected wins (honest, from the measurements)

- **Cold builds:** the server read path (~600 ms of the 2154 ms cold window;
  queueing-amplified at depth ~1.75) overlaps across workers — the bdev I/O
  and decrypt of N misses proceed concurrently. Write-side overlap (RC-3)
  additionally covers the cold build's flush-bearing writes (~100-395 us
  each). Estimate: -15-25% cold, more on higher-parallelism projects.
- **Warm builds:** modest direct win (post-CF-5a the warm server read total is
  ~55 ms) — the metadata-op overlap (~100-176 ms serial today) is the warm
  component. Estimate: ~-5-10% warm.
- **The real payoff is structural:** gofmt is small (91 pkgs); real projects
  generate deeper concurrency across more cold data, and host parity is
  unreachable through a serial server — a kernel FS serves `make -j`
  concurrently, and after RC, so does stratumd-over-9P. This also completes
  the NOVEL.md entry recorded at the CF scripture (the fully-concurrent-
  across-9P server on a lockless core).
- The workers=4 A/B (the regression that opened this investigation) is the
  acceptance test: it must flip to a win, or the arc has not done its job.

## 9. The ratified decisions (user votes, 2026-07-10)

1. **Scope: FULL `s->lock` retirement — reads AND writes** (RC-2 + RC-3;
   the reads-only carve was declined). Compounds/admin keep `s->lock`.
2. **dcache mechanism: EBR-pinned entries** (the in-tree reclamation idiom;
   readers copy under an epoch pin; evict retires).
3. **Spec-first: YES** — extend the Stratum concurrency specs (section 6)
   before the impl.
4. Staging RC-1 -> RC-2 -> RC-3 -> RC-4 -> RC-5; bdev multi-outstanding
   deferred to stage 2.

## 10. Stale-scripture fixes (ride the first RC commit)

The survey found these doc/code drifts (code is ground truth):

- `32-decrypted-extent-cache.md`: says 16 entries / 64 MiB — the code is 2048
  / 128 MiB + chained hash (CF-5a). Rewrite with RC-1.
- `phase-9.8-design.md` section 5.1.1: still describes chunk 10 / the R171
  write half as unbuilt — it IS built (29-concurrency.md section 29.7 + the
  code). Add a dated as-built correction note.
- `27-fs-read-path.md`: names the lock `fs->lock` — current code is the
  `fs->global` rwlock (SH for extent reads) + wait-free INLINE.
- `29-concurrency.md`: add the stm_sync layer as a first-class concurrency
  surface (its omission is why this serializer went unmapped until the
  2026-07-10 measurement).
