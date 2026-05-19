# Phase 9.6-impl-4b — engine store vtable + sync wiring + inode cutover — design

**Status**: design — for review. Stratum tip `fd3f188` (branch
`phase-9.6`). Companion to `phase-9.6-impl-4-cutover-design.md` §5 + §6
+ §10 — this note records the 4b-chunk decisions and **nails the two
things §6 explicitly deferred to "4b's design"**: the
`stm_bootstrap_commit`-vs-uberblock crash-safety ordering, and the
abort wiring.

4b is the first cutover sub-chunk and the highest-risk part of impl-4
(cutover doc §11 risk 1+2). It cuts the **inode** module off the
`btree_store` whole-tree-rebuild MVP onto the `btree_engine` COW
B+tree (complete + audited standalone through 4a / R149–R153), writes
the shared `stm_bootstrap`-backed engine store vtable, and wires the
engine into `stm_sync_commit`.

## 1. Sub-staging — 4b-i / 4b-ii / 4b-iii

The cutover doc §10 lists 4b as one chunk. 4b is large (it re-plumbs a
module's persistence and restructures `stm_sync_commit`). Per the same
§10 principle — "each piece builds, ctest-greens, and is audited
independently" — 4b is staged into three commits:

| Sub | Deliverable | State after |
|---|---|---|
| **4b-i** | The shared engine store vtable — `src/btree_engine/engine_store.c` + public header `include/stratum/engine_store.h`, in their own `stm_engine_store` library. Standalone; a direct unit test in `test_btree_engine.c`. No sync/inode change. | Engine still standalone; the production vtable proven. |
| **4b-ii** | The inode cutover — `records[]` retired, the engine is the store. `stm_inode_index_commit` keeps its **monolithic signature**, internally driving the single-shot `stm_btree_engine_commit` + a trailing `stm_bootstrap_commit`. `sync.c` **unchanged**. | inode is engine-backed; commit is incremental-COW; crash-safety **identical to today's `btree_store`**. |
| **4b-iii** | Split inode's commit into `commit_flush` / `commit_finalize` / `commit_abort`; rewire `stm_sync_commit` to the three-phase form; relocate `stm_bootstrap_commit` out of the inode module into sync. | The §6 target shape. |

R154 audits 4b-ii + 4b-iii together (4b-i is mechanical — its
soundness surface, paddr arithmetic, folds into R154's scope).

**Why stage.** 4b-ii is a large, mechanical, single-module rewrite;
4b-iii is a small, subtle, crash-safety-critical sync change.
Isolating them keeps each commit's blast radius scoped and each
independently bisectable. 4b-ii's intermediate state — inode
engine-backed, monolithic commit, sync untouched — is a **valid,
shippable posture**, not a broken half-state: the single-shot
`stm_btree_engine_commit` is flush-then-finalize in one call, leaves
no pending window, and either fully succeeds or fully self-reverts,
exactly as `btree_store`'s `stm_inode_index_commit` does today.

## 2. The engine store vtable (4b-i)

The engine talks to storage only through a `stm_btree_store_vtable`
(`reserve` / `free` / `write` / `read` — `btree_store.h`). The four
cutover modules each carry their own vtable today (`IN_STORE_VT` etc.,
`inode.c:401`), all reserving a **128-KiB legacy unit**
(`STM_BOOTSTRAP_UNIT_BLOCKS`). An engine node is **16 KiB**
(`STM_BTREE_ENGINE_NODE_SIZE` = `STM_BOOTSTRAP_NODE_BLOCKS` × 4 KiB).

4b-i writes **one shared engine store vtable** —
`src/btree_engine/engine_store.c` + the public header
`include/stratum/engine_store.h`, in their own `stm_engine_store`
library (so `stm_btree_engine` itself stays allocator-agnostic):

```c
typedef struct { stm_bootstrap *boot; stm_bdev *bdev; } stm_engine_store_ctx;
extern const stm_btree_store_vtable STM_ENGINE_STORE_VT;
```

- `reserve` → `stm_bootstrap_reserve(boot, STM_BOOTSTRAP_NODE_BLOCKS,
  /*hint=*/0, out_paddr)` — 16-KiB granularity, **not** the legacy
  128-KiB unit.
- `free` → `stm_bootstrap_free(boot, paddr, STM_BOOTSTRAP_NODE_BLOCKS,
  free_gen)`.
- `write` / `read` → `stm_bdev_write` / `_read` at
  `stm_paddr_offset(paddr) × STM_UB_SIZE`; `stm_paddr_device(paddr) !=
  0` → `STM_EINVAL` (device-0-only, MVP — identical to `in_store_*`).

One `STM_ENGINE_STORE_VT` instance serves all four engines (the per-
engine difference is the `vt_ctx` — a `{boot, bdev}` pair, identical
in shape across modules). The legacy `*_STORE_VT` stay until 4d (the
not-yet-cut-over modules still use them).

**Unit test (4b-i).** `test_btree_engine.c` gains a case that builds a
real `stm_bdev` + `stm_bootstrap` (the `test_inode.c` fixture
pattern), constructs `STM_ENGINE_STORE_VT` + ctx, and runs an engine
`create → insert → commit → reopen → verify → lookup` cycle against
it — proving the production vtable before 4b-ii's inode rewrite
depends on it.

## 3. The inode cutover (4b-ii) — the tree is the store

Per cutover doc §4: the module **stops keeping `records[]`**. The
`stm_inode_index` holds an `stm_btree_engine *`; every public op maps
onto the engine. `inode.tla`'s allocator state machine — alloc / free
/ link / unlink / materialize, the `(ino, si_gen)` tuple-uniqueness
invariant — is **unchanged**; only the storage under it swaps.

### 3.1 What `stm_inode_index` keeps / drops / gains

- **Drops**: `records[] / n_records / cap_records`, `find_record` /
  `find_record_c` / `find_freed_record` / `append_record`, the
  `dirty` flag (the engine tracks its own dirtiness),
  `in_build_btree_locked`, the `IN_STORE_VT` + `in_make_store_ctx`,
  the `btree_store` serialize / deserialize / free_tree calls.
- **Keeps**: the `lock` (the module's own mutex), `handle_buckets[]`
  (the P9.5-PARALLEL-3 per-inode lock pool — independent of
  `records[]`, untouched), `bdev` / `boot` / `metadata_key` /
  `pool_uuid` / `device_uuid` / `crypt_set` / `storage_set`,
  `dsstate[]` (see §3.3).
- **Gains**: `stm_btree_engine *eng`, the `stm_engine_store_ctx`
  (`{boot, bdev}`), the `stm_btree_crypt_ctx`.

### 3.2 Op mapping

- `lookup(ds, ino)` → `engine_lookup(key = ds‖ino)`; on a hit, decode
  the 256-byte value, apply the FREED filter (a FREED record reads
  back as `STM_ENOENT` for `stm_inode_lookup`, exactly as today).
- `set` → `engine_insert` (upsert) of the encoded 256-byte value.
- `alloc` / `alloc_anon` — pick the ino (AllocReused-from-FREED
  preferred, AllocFresh fallback — §3.3/§3.4), build the value,
  `engine_insert`.
- `free` / `link` / `unlink` / `materialize` — `engine_lookup` the
  record, mutate the value per the `inode.tla` action, `engine_insert`
  the result. "delete" is an **upsert of a FREED-flagged value** — the
  engine's `delete` is **not** used by inode (a FREED record must
  persist so AllocReused can re-issue the ino; cutover doc §3.1).
- `count_for_ds` → `scan_range` over `[ds‖0 .. ds‖UINT64_MAX]`,
  counting non-FREED.
- per-inode-lock `pin` re-validation ("(ds,ino) exists, not FREED") →
  `engine_lookup` + flag check (was `find_record`).

### 3.3 Derived scalar — `next_ino`

`dsstate[]` (a per-dataset `{dataset_id, next_ino}` array — small, not
file-count-scaling) **stays in RAM**. It is reconstructed at mount
from a one-time `engine_scan` (`in_rebuild_dsstate_from_records`'s
`max(ino)+1` logic, fed by the scan instead of the deserialize walk)
— O(records) at mount, **no regression** (today's `load_at`
deserialize is already a full walk). `dsstate` is **not persisted**
standalone — the mount scan is the source of truth, exactly as today.

### 3.4 AllocReused — the FREED-ino scan

`find_freed_record(ds)` (today: a linear `records[]` scan for a FREED
slot with `gen != UINT64_MAX`) → a `scan_range` over `[ds‖0 ..
ds‖UINT64_MAX]` with an early-stop callback that returns the first
FREED, non-`UINT64_MAX`-gen record. O(inodes-in-dataset) — the same
asymptotic cost as today's array scan; the engine's resident
node-tree walk replaces the array walk. **Forward-note** (carries the
cutover doc §4 forward-note): a per-dataset in-RAM FREED-ino freelist
would make AllocReused O(1) — a later optimisation, out of 4b scope;
4b's cutover is mechanical (cutover doc §8 risk-1 mitigation).

### 3.5 Engine lifecycle vs. the module lifecycle

`stm_btree_engine_create` / `_open` both need `vt` + `cx`, which are
set by `set_storage` (bdev/boot) + `set_crypt_ctx` (key/uuids) —
called *after* `stm_inode_index_create`. So the engine cannot exist at
`create` time. Resolution — an internal `in_ensure_engine(idx)`:

- **Fresh-format path** (`stm_sync_create`): `index_create` →
  `set_storage` → `set_crypt_ctx`; the first op that needs the engine
  (`alloc` or `commit`) calls `in_ensure_engine`, which —
  `idx->eng == NULL` and both contexts set — `stm_btree_engine_create`s
  an empty-leaf-root engine. This matches the engine's own
  lazy-`create` philosophy and today's behaviour (a fresh inode index
  is empty until the first commit serialises it).
- **Mount path** (`stm_sync_open`): `index_create` → `set_storage` →
  `set_crypt_ctx` → `load_at`. `stm_inode_index_load_at` calls
  `stm_btree_engine_open(vt, ctx, cx, tree_id, root_paddr, root_gen,
  root_csum, &idx->eng)` (lazy — no I/O) then `engine_scan` to rebuild
  `dsstate[]`. Subsequent ops find `idx->eng` already set.

`stm_inode_index_close` → `stm_btree_engine_destroy(idx->eng)` (NULL-
safe; an un-finalized flush implicitly aborts — header contract).

### 3.6 `stm_inode_index_commit` (4b-ii form — monolithic preserved)

```
in_ensure_engine(idx)                       // lazy-create on fresh path
stm_btree_engine_commit(eng, committed_gen, &paddr, csum)  // single-shot
stm_btree_engine_get_root(eng, &paddr, &gen, csum)         // authoritative triple
stm_bootstrap_commit(idx->boot, committed_gen)             // durable bitmap
→ out_root_paddr = paddr; out_root_csum = csum
```

- The engine's single-shot `commit` is incremental-COW (only dirty
  root-to-leaf paths rewritten) — the design §1.1 fix for the
  O(all-metadata) commit cost is realised here.
- A clean tree's `commit` is a no-op (writes nothing, returns the
  prior root at its prior gen) — `stm_inode_index_commit`'s explicit
  `!dirty` short-circuit is **subsumed** by the engine.
- `committed_gen` is `target_gen` from `stm_sync_commit` — strictly
  increasing across commits (`current_gen` advances by 2); `>
  eng->root_gen` always (§5.3), so the engine's monotonic-gen guard
  never fires.
- The trailing `stm_bootstrap_commit` preserves the **exact**
  monolithic `btree_store` shape (`inode.c:1185`) — sync sees no
  behavioural change at 4b-ii. It is removed in 4b-iii (§5).
- `stm_inode_index_get_gen` / `_get_root` → `stm_btree_engine_get_root`
  (the engine's gen out-param is the authoritative AEAD gen — a clean
  no-op commit keeps the root's prior gen, which sync must stamp).

## 4. `stm_sync_commit` wiring — 4b-ii vs 4b-iii

**4b-ii**: `stm_sync_commit` is **unchanged**. It calls
`stm_inode_index_commit(s->inode_idx, target_gen, &inode_paddr,
inode_csum)` (sync.c:2717) exactly as today — the function's signature
and contract are preserved; only its innards are engine-backed.

**4b-iii**: the inode portion of `stm_sync_commit` becomes three-phase
(§5).

## 5. Crash-safety — the `stm_bootstrap_commit` ordering (4b-iii)

This is what cutover doc §6 deferred to "4b's design + audit."

### 5.1 The two durable artifacts

A commit makes two independent durable artifacts consistent:

1. the **uberblock** — names the metadata-tree roots (`ub_inode_root`
   etc.), written by `write_ub_to_all_devices`.
2. the **bootstrap bitmap** — marks which 16-KiB nodes are allocated,
   made durable by `stm_bootstrap_commit` (`bootstrap.h`: COW the
   bitmap to the other slot + new header, fsync).

A crash *between* the two leaves whichever was written second stale.

### 5.2 Which order is crash-safe

The engine's `commit_flush` does `vt->reserve` (sets a bitmap bit
**in-RAM**) + `vt->write` (writes the node bytes straight to the
device — no bitmap involvement). The bitmap bit is durable **only**
after a `stm_bootstrap_commit`.

- **Case A — `stm_bootstrap_commit` before the UB write.** Crash
  between: durable UB = OLD roots, durable bitmap has the new paddrs
  SET. Next mount → old UB → old tree (intact, its paddrs bitmap-SET).
  The new nodes are SET-but-unreferenced → a bounded space **leak**,
  **no corruption**. ✓
- **Case B — UB write before `stm_bootstrap_commit`.** Crash between:
  durable UB = NEW roots, durable bitmap STALE (new paddrs **free**).
  Next mount → new UB → new tree; but the bitmap thinks the new
  paddrs are free → a later `reserve` re-hands one out → the new
  tree's node is overwritten → **corruption**. ✗

**Decision: `stm_bootstrap_commit` strictly precedes the final UB
write.** This is Case A — and it is **already** the order
`stm_sync_commit` runs today: every `*_index_commit` runs its
`stm_bootstrap_commit` in Phase 2, the final UB lands in Phase 3. 4b
*preserves* this ordering; it does not invent it. The
reserve-now / durable-via-a-later-`stm_bootstrap_commit` posture is
itself not novel — `stm_keyschema_commit` already works exactly this
way (sync.c:2487 comment: keyschema's tree-node reserves are made
durable by the *alloc-tree's* later `stm_bootstrap_commit`). 4b places
the inode engine in the same established slot.

### 5.3 The 4b-iii flow

```
Phase 2 (flush):
  ...keyschema, alloc, roots, dataset, snapshot, extent, repair_log, cas...
  inode: stm_inode_index_commit_flush(target_gen) → prospective (paddr,gen,csum)
  ...dirent, xattr (btree_store, 4b-iii — cut at 4c)...
  compute_merkle_root(... inode prospective csum ...)
  stm_bootstrap_commit(boot, target_gen)        // explicit durable-bitmap barrier
Phase 3 (final):
  build_uberblock(... inode prospective root ...)
  write_ub_to_all_devices                       // === commit point ===
  inode: stm_inode_index_commit_finalize()      // adopt root; vt->free superseded
  publish in-RAM state
Abort path (any error after the inode flush, before finalize):
  inode: stm_inode_index_commit_abort()
  return the error
```

`stm_inode_index_commit` splits into three module functions, each a
thin wrapper over the engine's `commit_flush` / `commit_finalize` /
`commit_abort` (+ `get_root` for the out-params).

The explicit `stm_bootstrap_commit(boot, target_gen)` in sync is the
durable-bitmap barrier for the engine-backed trees. At 4b-iii
dirent/xattr/extent/dataset/snapshot/cas are still `btree_store` and
still call `stm_bootstrap_commit` internally — the explicit call is
**redundant but cheap** (it advances `bitmap_gen` + fsyncs an
unchanged-or-near-unchanged bitmap; the sync.c:2613 comment already
notes this redundancy class). Those internal calls retire as 4c/4d cut
the remaining trees over; the explicit barrier is the call that
*stays* — the §6 "relocate `stm_bootstrap_commit` into sync, called
once" end state.

### 5.4 Crash-case walk-through

`commit_flush` ALWAYS opens a pending window on success (even for a
clean tree — `engine.c:791` sets `p->active` unconditionally), so sync
ALWAYS pairs the flush with exactly one finalize-or-abort. No
"did it flush?" branching.

| Crash window | durable UB | durable bitmap | Outcome |
|---|---|---|---|
| after flush, before `stm_bootstrap_commit` | old | old (new paddrs free) | old tree intact; new nodes bitmap-free + unreferenced — safe |
| after `stm_bootstrap_commit`, before UB | old | new paddrs SET | old tree intact; new nodes SET + unreferenced — **leaked** |
| after UB, before `commit_finalize` | new | new SET + superseded SET-not-PENDING | new tree intact; superseded nodes **leaked** (finalize's `vt->free` never ran) |
| after `commit_finalize` | new | new SET + superseded PENDING | consistent |

**No corruption in any window.** Two bounded-leak windows: (b) leaks
the freshly-flushed nodes, (c) leaks the superseded nodes — each ~the
dirty root-to-leaf path, a handful of 16-KiB nodes. This is a **strict
improvement** over today's `btree_store`, whose pre-UB crash window
leaks the *whole* freshly-rebuilt tree (`btree_store` rewrites every
node each commit). Leaks are crash-only, non-corrupting,
scrub-reclaimable; a persistent deferred-free log to close them is a
Phase 9.8-class concern (cutover doc §11 risk 4 neighbour).

The leaked-flushed-nodes case (b) is also **nonce-safe**: those nodes
carry `(paddr, gen=target_gen)` AEAD nonces, the next mount's
`MountGenBump` (`sync.tla`) bumps the live gen strictly past
`target_gen`, and any future `reserve` of one of those (bitmap-free)
paddrs writes it at a *higher* gen — `(paddr, higher_gen)` ≠
`(paddr, target_gen)`. This is exactly the `sync.tla`
`MaxDurableTxg`-includes-`disk_txgs` orphan-flush case.

### 5.5 Abort = crash-equivalent

`stm_btree_engine_commit_abort` discards the flush **and drops the
in-memory tree** (`invalidate_memtree`) — the uncommitted inode
mutations are lost; the next descent reloads the previous durable
root. A failed `commit_flush` self-reverts identically (no pending
window, tree dropped).

This differs from `btree_store`, whose `records[]` survives a failed
`stm_inode_index_commit` (the next commit retries from `records[]`).

**Decision: a `stm_sync_commit` failure after the inode flush is
crash-equivalent — the inode engine aborts (dropping uncommitted
mutations) and the fs must wedge.** Rationale:

- The engine's flush/finalize/abort split is *designed* this way —
  `commit_abort` is "the in-process realisation of a crash between
  flush and final" (reference/24 §Commit). Abort-but-keep-dirty would
  be a new engine capability, out of 4b scope and arguably never
  needed: a failed sync IS a crash-class event for a COW fs.
- A failed `stm_sync_commit` already wedges the fs in v2 (a wedged fs
  must be unmounted + remounted; remount reloads *everything* from the
  last durable UB — so the inode mutations are lost on a wedge-remount
  regardless of engine vs. `btree_store`). The engine's abort just
  realises that loss in-process instead of at remount.
- 4b-iii's audit (R154) **must verify** `stm_sync_commit`-failure →
  fs-wedge holds on every post-inode-flush error path. If any path
  returns a `stm_sync_commit` error *without* wedging and a caller
  retries, that is a finding — the inode engine's pending window would
  already be aborted (tree dropped) and a retry would commit a
  truncated inode tree.

The abort-gen contract (reference/24 "impl-4 integration contract") is
honoured: an aborted commit does not consume its gen; `s->current_gen`
is not advanced on a failed sync, so a retry reuses `target_gen`; no
`stm_bootstrap_commit(committed_gen > target_gen)` runs between an
abort and a retry (the explicit barrier is at `committed_gen ==
target_gen`, and the abort paths `return` before reaching it).

## 6. Spec assessment

Per CLAUDE.md spec-first: commit ordering is a load-bearing invariant,
so the spec is assessed **before** the impl. Conclusion — consistent
with cutover doc §9 — **no new spec; 4b composes three already-green
specs**:

- **`btree.tla`** — the engine's COW commit. `commit_flush` /
  `commit_finalize` / `commit_abort` realise `WriteNode` /
  `FinalCommit` / `Crash`; green through impl-2/3/4a. 4b changes
  *who calls* the engine, not the engine's COW mechanism — `btree.tla`
  is untouched.
- **`sync.tla`** — the multi-phase commit (`Freeze` / `Reserve` /
  `Flush` / `Final` / `Publish` + `Crash` / `Mount`). The engine's
  `commit_flush` is a durable-data-write — it slots into `sync.tla`'s
  `DoFlush` (abstracted as a single per-txg write; the engine writes N
  nodes at one gen — the all-or-nothing-at-`DoFinal` property is
  level-uniform, and `btree.tla` models the multi-node detail). The
  engine's prospective root → `pending_ub` → `DoFinal` (the commit
  point). `commit_finalize` is post-`DoFinal` deferred-free, which
  `sync.tla` does not model (it models no freeing / leaking).
  `commit_abort` is the `Crash`-before-`DoFinal` case. The
  flushed-but-unrooted-nodes nonce hazard (§5.4 case b) is exactly
  `sync.tla`'s `MaxDurableTxg`-includes-`disk_txgs` orphan-flush case
  — already covered.
- **`allocator.tla`** — the bitmap COW + `free_gen < committed_gen`
  deferred-free. The `stm_bootstrap_commit` is the bitmap-durability
  step; the superseded-paddr `vt->free` is deferred-free. Untouched.

**Why the `stm_bootstrap_commit`-before-UB ordering is audit-
prosecuted, not `sync.tla`-checked.** `sync.tla` abstracts the
allocator entirely (`DoFlush` "picks a free paddr"); modelling the
bitmap-vs-UB ordering would mean pulling `allocator.tla` into
`sync.tla` as one mega-spec — and `allocator.tla` already models the
bitmap. The ordering is a **localised two-step sequencing fact within
one function** (`stm_bootstrap_commit` before `write_ub_to_all_
devices` in `stm_sync_commit`) — and it is the **existing, audited**
order, not a new one (§5.2). TLA+ earns its keep on emergent
interleaving bugs, not linear sequencing within a single critical
section; the proportionate verification is a deterministic code-read,
which the R154 audit performs. This matches 4a's `delete`
spec-assessment outcome ("compose, no extension") and the cutover doc
§9 determination.

`btree.tla`'s comment block already states the corresponding
allocator-composition contract ("the allocator-bitmap commit is part
of the same final phase that publishes the root"); 4b honours it.

## 7. `STM_UB_VERSION`

The bump (28 → 29) is deferred to **4d** (cutover doc §7 / §10). After
4b the on-disk format is in-flight on the `phase-9.6` branch —
inode-tree engine-format, dirent/xattr/extent still `btree_store`;
neither v28 nor v29. This is acceptable: v2 is pre-release, dev pools
re-format, and a 4b-built pool read by 4b-built code is
self-consistent (format-write and format-read agree). The version
number is a mount-time gate against *cross-build* pools; 4d sets it
once the format settles. A reference-doc note records the in-flight
window.

## 8. Risks

1. **A large single-module rewrite** (inode.c, ~10 public functions
   re-pointed at the engine). Mitigation: the engine is proven
   standalone (R149–R153); `inode.tla`'s record semantics are
   unchanged (§3); 4b-ii ships behind the unchanged
   `stm_inode_index_commit` signature so `sync.c` and every inode
   caller are untouched; ctest's full inode + fs + sync suites gate it.
2. **`stm_bootstrap_commit` ordering** (§5). Mitigation: the order is
   the existing audited one; §5 walks every crash window; R154
   prosecutes it specifically.
3. **Abort = lost mutations** (§5.5). Mitigation: it is the engine's
   designed contract and the crash-equivalent of a failed sync; R154
   verifies failed-sync → fs-wedge.
4. **AllocReused FREED-scan cost** (§3.4) — O(inodes-in-dataset) per
   alloc, same asymptotics as today. Forward-noted: an O(1) freelist
   is a later optimisation.

## 9. Open questions

- **Q1 — `in_ensure_engine` timing.** Lazy-create on first engine-
  needing op (§3.5) vs. an explicit init call from `stm_sync_create`.
  Lazy is chosen (matches the engine's own lazy philosophy, no new
  public API); 4b-ii confirms no op reaches the engine before
  `set_storage`+`set_crypt_ctx` (sync.c orders them at create/open).
- **Q2 — does a failed `stm_sync_commit` always wedge the fs?** §5.5
  asserts it must; R154 verifies against every fs.c `stm_sync_commit`
  caller. If a non-wedging path exists it is a 4b-iii fix.
- **Q3 — 4c/4b audit folding.** Cutover doc §12 Q1. With 4b staged
  into i/ii/iii, R154 covers all of 4b; 4c gets its own (it cuts two
  more modules). Decide at 4c.

---

*4b design — for review. On sign-off: 4b-i (engine store vtable +
unit test), then 4b-ii (inode cutover, monolithic commit), then
4b-iii (three-phase sync wiring), then R154.*
