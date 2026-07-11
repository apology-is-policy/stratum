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

**Memory-order rule for every RC lock-free reader (the RC-1 audit F1
close):** the pin-before-observe StoreLoad edge is provided by
`stm_ebr_enter`'s trailing seq_cst fence (ebr.c), NOT by the reader's own
load orderings — acquire loads alone are UNSOUND on FEAT_LRCPC arm64
(STLR->LDAPR is unordered), which is how RC-1's first cut silently weakened
the engine's seq_cst-load idiom. RC-2's DEK-map published-pointer load and
any future EBR-protected reader may use acquire loads freely BECAUSE the
fence is in enter; never remove or weaken it.

**As-built (RC-2, 2026-07-10):**

- **Pin structure**: ONE pin covers the `_concurrent` extent lookup + the
  dcache probe (`sync_dcache_probe_pinned` — pure, no pin management; the
  record comes back BY VALUE so nothing tree-resident is referenced after
  the exit). The MISS path runs UNPINNED — a pin must never span the
  blocking bdev read (it would stall epoch advance globally); the HOT DEK
  resolve takes its own short pin inside `sync_extent_fetch_decrypt`. The
  RC-1 probe pins were hoisted, never nested (nested enter silently unpins).
- **STM_EBUSY** (a mid-walk engine seal): whole-op retry with a FRESH pin
  per attempt (the CF-2c contract, `STM_BTREE_ENGINE_EBUSY_RETRY_MAX`);
  exhaustion falls back to the serial locked path (different lookup
  machinery — cannot EBUSY), so a read never surfaces EBUSY.
- **The snap read** (`stm_sync_read_extent_at_snap`) went lock-free on the
  same dispatch: the frozen-root lookup is self-locked (`ex_lock(idx)`
  inside `stm_extent_index_lookup_at_root`), then the shared probe + fetch.
- **The under-lock decrypt entry survives**: truncate / migrate / snap-view
  / send compounds keep `sync_decrypt_extent_record_locked` (slice bounds →
  self-pinned probe → `sync_extent_fetch_decrypt(ebr=NULL)`), byte-
  equivalent to the pre-split body — the DEK resolve there is the borrowed
  `sync_dek_find` walk, safe under `s->lock` because publishing requires it.
- **The DEK guard**: COW snapshots per `dek_guard.tla` (see SPEC-TO-CODE
  for the full mapping). `sync_dek_remove_at`'s swap-with-last and
  `sync_dek_grow`'s realloc are DELETED — the modeled `inplace_mutate` /
  `free_old_map` bugs are gone by construction. Remove is newly ENOMEM-
  fallible (evict propagates; the keyschema sweep skips with a lingering
  in-RAM slot scrubbed at close). The pre-reserve contract survives as a
  staged unpublished buffer (`s->dek_staged`).
- **The reader-side pin is SHARED for real**: the PARALLEL-3 per-inode slot
  lock became a rwlock (`stm_inode_pin_shared` = rdlock; `stm_inode_pin` =
  wrlock, all mutators unchanged; glibc slots init
  PREFER_WRITER_NONRECURSIVE against reader streams starving a truncate).
  `stm_fs_read`'s regular-file EXTENT arm pins shared, RE-LOADS the inode
  value under the pin (the route-then-pin TOCTOU), and holds across the
  whole multi-extent + dirty-buffer-overlay read (RC-I2). ERRORCHECK
  posture note: a buggy same-thread double-pin is EDEADLK on macOS /
  deadlock on glibc instead of abort.
- **P0-3 (#1232) CLOSED, not just re-verified**: ground truth showed the
  assumed stratumd drain DID NOT EXIST for FS workers (the /ctl side had
  `worker_count`; the FS side was detached with "no ordered-shutdown
  contract"). Closed with the mirrored bracket: `fs_inflight` bump-before-
  spawn / drop-at-exit / `stratumd_fs_workers_drain()` in
  `stm_stratumd_run` after the accept loop exits, BEFORE ctl/scrub/fs
  teardown. Bounded by the per-connection idle timeout.
- **promote_cache** got its own leaf mutex (`s->promote_lock`; not held
  across the dataset_idx slow path; the insert re-verifies the property
  gen). `s->wedged` is `_Atomic bool`, `s->current_gen` `_Atomic uint64_t`
  (relaxed advisory snapshot on the read path).
- **Runtime witnesses**: `tests/test_rc2_concurrent.c` — the lock-free
  read/overwrite hammer (single-version content), the rotate + re-encrypt
  + sweep hammer (an install AND a remove publish per cycle under pinned
  readers; zero read failures), the fs-level RC-I2 single-version test
  (whole-file rewrite in ONE call = the atomicity unit; truncate churn),
  and the pin-mode semantics (SH||SH coexist, SH excludes EX, EX excludes
  SH).

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

#### As-built (RC-3, 2026-07-11)

- **The three-phase split landed on `stm_sync_write_extent` alone** —
  the workload's entire write volume. `sync_write_reserve_locked`
  (brief `s->lock`: DEK resolve [the borrowed under-lock walk — RC-2's
  publish-requires-the-lock argument], size math, replica reserves,
  the `write_gen` capture) → `sync_write_encrypt_store` (UNLOCKED:
  AEAD + per-replica `stm_bdev_write`; thread-local + self-locked
  leaves; a reservation pins its device slots against removal via the
  drained-probe) → `sync_write_index_commit_locked` (brief `s->lock`:
  the WHOLE cold-overlap bookend + `stm_extent_overwrite` + the gated
  dcache write-populate + drop/deref routing under ONE hold —
  scan-matches-overwrite atomicity vs every other extent mutator is
  byte-preserved). `stm_sync_write_extent_locked` composes the same
  helpers under its caller's single span for the truncate compound.
- **The captured-gen nonce argument**: `write_gen` (Phase-1, under the
  lock) feeds the encrypt nonce, the record stamp, and the dcache key.
  A phase-straddling commit (sync-layer-direct callers only — every
  fs-mediated write holds `fs->global` SH/EX across the call while
  commit runs EX) leaves the older stamp nonce-unique: the allocator's
  PENDING sweep (`free_gen < committed_gen`) forbids same-gen paddr
  reuse, and `stm_extent_overwrite` accepts `write_gen <=
  idx->current_txg`.
- **THE new obligation the split opens — key-sweep vs in-flight
  write**: `stm_sync_keyschema_sweep` prunes a RETIRED key with zero
  extent refs, and a Phase-2-in-flight write's resolved key is
  invisible to that gate. Un-checked, a rotate+sweep inside the window
  indexes a record whose durable wrapped key is GONE — silent data
  loss. Closed by the epilogue's keyschema re-validation
  (`stm_keyschema_lookup`, CURRENT-or-RETIRED = alive) under the SAME
  lock hold that indexes (the sweep runs entirely under `s->lock` — no
  TOCTOU), with a bounded whole-op retry (4) against the fresh CURRENT;
  each attempt reserves fresh paddrs, so every nonce is fresh;
  exhaustion (the rc3 hammer reached it under host contention — 4
  rotate+sweep collisions inside one op) degrades to the fully-locked
  body, which the sweep cannot interleave — a write NEVER surfaces a
  transient error (the RC-2 EBUSY-exhaustion → serial-fallback
  precedent). **Spec-first**:
  `specs/write_key_liveness.tla` (clean cfg TLC-green incl. the
  `EventuallyAllDone` retry-termination witness; +
  `write_key_liveness_no_revalidate_buggy.cfg` — TLC finds
  Resolve(K1) → Rotate → Sweep(K1) → CommitBuggy at depth 4, the
  executable counterexample). The locked compound path needs no check
  (its single span excludes the sweep — the pre-RC argument).
- **Evict-dek vs the two unlocked windows (the populate gates)**:
  evict removes only the in-RAM DEK slot (the keyschema entry
  persists), so a mid-window write still INDEXES
  (durable, decryptable-on-reinstall — the pre-RC outcome) but its
  plaintext must not outlive the DEK denial (the CF-5a F1 contract).
  The write populate is pre-gated on DEK-slot liveness (serialized —
  the epilogue holds `s->lock`). The SAME window existed on the RC-2
  read fetch (a pre-existing RC-2 latent, found at RC-3 design
  review): the fetch now inserts, re-checks slot liveness, and
  self-removes via `dcache_remove_key` — for the populating thread's
  own path the `dcache_wlock` hand-off covers every interleave (if
  the insert preceded the drain, the drain wipes it; if the drain
  preceded the insert, the wlock release/acquire edge makes the map
  publish visible to the re-check). **Residual (RC-3 audit F1)**: a
  THIRD reader's probe can hit the entry inside the
  [insert, self-remove] span — a transient of a few instructions,
  serving only bytes the allowed in-flight fetch concurrently holds;
  the indefinite residency the RC-2 latent allowed is gone. Exact
  denial needs a provisional (probe-invisible-until-validated)
  insert — the tracked RC-4 hardening (it touches the audited RC-1
  probe path, so it lands with its own focused round). COLD
  populates are un-gated by design: COLD decrypts under the
  pool-wide `metadata_key` — backing-path-consistent.
- **Truncate / punch keep their single-lock compounds.** Punch refuses
  crossing extents (`ENOTSUPPORTED`) — it is pure index work with no
  Phase-2 to unlock; already pattern-conformant. Truncate's
  crossing-extent re-encrypt stays inside the compound span its
  R41 P3-1/P3-2 + R55 P2-2 atomicity closures (peek-into accuracy,
  commit interleaving) depend on; its weight in the build workload is
  zero (truncate(0)/aligned shrinks have no crossing extent). The
  fine-grained-truncate extension remains the recorded sync.c seam.
  Same-ino compound stability vs the new concurrent writers is the
  fs-layer EX pin (write/truncate/punch/migrate all pin EX; reflink +
  commit run under `fs->global` EX).
- **Test seams**: `stm_sync_set_write_phase2_hook_for_test` +
  `stm_sync_set_read_prepopulate_hook_for_test` (sync_testing.h;
  compiled out of production — the Thylacine cross-build passes
  `TESTING_HOOKS=OFF`) land deterministic evict / rotate+sweep strikes
  inside the exact windows. Runtime witnesses:
  `tests/test_rc3_concurrent.c` (disjoint-writer hammer at both
  LE-boundary offsets; the deterministic key-liveness retry [pre-fix:
  read-back ECORRUPT]; the writers-vs-rotate+sweep hammer) +
  `tests/test_corvus_mount.c` (`corvus_rc3_write_evict_window` — write
  survives a mid-window logout, post-evict read denied, post-reinstall
  read verifies; `corvus_rc3_read_evict_window` — the #34 regression:
  the in-flight read is served, the stale populate self-removes, the
  second read is denied). All three gates proven non-vacuous by
  revert-probes.

### RC-4 — turn the concurrency ON

- `--fs-workers N` default ON (min(4, ncpu)) in the Thylacine boot (joey's
  stratumd argv), measurement-gated: the A/B that regressed pre-RC must now
  WIN; if it does not, the gate holds the default OFF and the residual
  serializer gets hunted before shipping.
- Tflush / fid-pin / writer-mutex (CF-2's built discipline) re-verified under
  real concurrency.

#### As-built (RC-4, 2026-07-11) — the gate ran and HELD the default OFF

The A/B ran post-RC-3 (joey argv `--fs-workers 4`, the CF-2a pool; six
instrumented guest boots, snapshot-restored pool before every boot, all
green: 1085/1085 in-kernel + full go4c probes + login E2E + 0 EXTINCTION).
Verdict: **the pre-RC regression is gone, but workers=4 does not WIN — the
default stays OFF (`--fs-workers` remains opt-in) and the Thylacine boot
argv is unchanged.**

Same-BUILD-day pairs (the load-bearing comparison; a cross-build pair hides
~10% binary-to-binary variance — A2 from the RC-3-close build was the worst
A sample on every axis and masked the signal in pooled means):

| window (ms)  | w=1 (A3, A4) | w=4 (B1, B2) | read                     |
|---|---|---|---|
| build cold   | 857, 845     | 945, 945     | +10-11%, ranges disjoint |
| build2-warm  | 561, 566     | 611, 616     | +9%, ranges disjoint     |
| gofmt-cold   | 1866, 2095   | 1928, 1890   | wash (inside A spread)   |
| gofmt-warm   | 864, 655     | 712, 704     | wash (inside A spread)   |

The residual-serializer hunt CONCLUDED with a named mechanism, not a
mystery. STMD26 per-window deltas: `re` (s->lock) wait = **0 under
workers** (pre-RC Boot B: 141 ms — the RC retirement holds under the
pool); bdev one-in-flight wait rose 0.006 ms -> ~27 ms cumulative (real
queueing — the stage-2 trigger fires — but ~27 ms is not load-bearing
under the host page cache); per-window bdev count/service byte-identical
across arms. **No lock remains.** What remains is the pool's per-op
dispatch handoff (reader->worker futex/condvar wake + writer-mutex reply
serialization) taxing the depth-1-dominated build windows ~9-11% (down
from the CF-2f 15-24% — RC removed the lock-contention component), while
the overlap gain on the deep windows (gofmt-cold ge2 = 68%) only just
cancels its own tax. The workers also compress within-arm variance
strikingly (B pairs all within 1.5%) — the pool removes head-of-line
blocking even where it does not win wall.

Discharged here: the CF-2 discipline re-verify under REAL concurrency —
the two workers=4 boots ran the pool live through the full boot + go
builds + session E2E (plus the deterministic host pool suite in the
73/73: Tflush-of-EXECUTING, dup-tag fatal, writer-mutex).

Recorded seams: (a) **adaptive dispatch** — execute inline when the queue
is empty / depth 1, dispatch only at depth >= 2 (the direct-handoff
hybrid); the candidate that would let the pool win the deep windows
without taxing the shallow ones; a design fork for the user at RC-5, not
silently built. (b) The A/B harness lesson: the worker count is baked
into the disk image via joey's argv, so every arm switch costs a rebuild
and cross-build pairs are confounded — a boot-time knob would make
future A/Bs same-binary. (c) The serve.c `fs_workers_resolve` comment
("flip the default back when clients can actually offer depth") remains
accurate as written.

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
