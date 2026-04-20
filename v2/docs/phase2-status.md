# Phase 2 — status and next-session guide

This file is the authoritative pickup guide for continuing Phase 2
work on the lock-free Bw-tree. Last update 2026-04-20 (after #176
landed). The `v2/docs/phase2-bw-tree-design.md` alongside is the
historical pre-implementation design note — left intact as a record
of the reasoning that led to the current code.

## TL;DR

The lock-free Bw-tree is a **balanced B+tree** now: root is a
BASE_INTERNAL delta with a pivot array, leaves are atomic-published
BASE_LEAF chains with SPLIT redirects. All four audit rounds R0-R3
passed and CI green on full matrix. Remaining Phase 2 scope is
MERGE (spec-first) and a fresh R4 audit round over the
internal-routing changes.

## What's landed (commits, tests, audits)

| Commit | What |
|---|---|
| `47ae395` | Lock-free Bw-tree MVP (single-node delta chain, CAS prepend, EBR-backed consolidation) — task #171 |
| `ff80c66` | Randomized single-threaded shadow-oracle test |
| `39426e6` | R1 audit fixes (chain_depth EBR pin + atomicization, posix.c null-deref, btree.c bool-as-int) |
| `38105e2` | Consolidator serialization + per-thread oracle stress |
| `f35ae64` | `structural.tla` — single-split SPLIT delta atomic-visibility spec |
| `e6e7b18` | SPLIT delta implementation + traverse_and_prepend + resolve_chain redirect |
| `72c1cb3` | Cascading-splits test (120 keys at target=8) |
| `72b9d80` | Concurrent-splits oracle test (per-thread disjoint key ranges) |
| `c6790c0` | R2 audit fixes (burned-ID mitigation via capacity bump, atomic_init, force_consolidate flag gate, shared `consolidate_or_split` helper) |
| `8d77a29` | Chain inheritance — re-splits carry the inherited SPLIT into the new sibling (superseded by #176) |
| `09c3636` | `structural.tla` extended to cover 2-level cascade (5120 states, depth 15) |
| `91a6a84` | `balanced.tla` — parent-pivot-update three-CAS spec (65536 states, depth 18) |
| `9b60510` | **#176: internal-node routing landed**. Root is BASE_INTERNAL with pivots; leaves are BASE_LEAF with multi-SPLIT chains. Chain inheritance dropped — parent routing supersedes. New tests (balanced_growth, large_scale_internal_routing). |

Also: several CI-fix commits for Linux `-Werror` / liboqs issues.
All CI matrix jobs (Linux gcc/clang × off/asan/tsan + macOS clang ×
off/asan/tsan + TLC per spec) green on tip. 14/14 tests pass on
default/ASan/TSan.

Audit rounds closed: R0 (pre-#171 substrate), R1 (MVP), R2 (SPLIT
protocol), R3 (chain inheritance). Cumulative do-not-report ledger is
`memory/audit_v2_r0_closed_list.md`.

## What's left in Phase 2

Option B (internal routing) landed in `9b60510`. Remaining options
are MERGE (spec-first, sizable) and the R4 audit.

### Option A: MERGE

Symmetric to SPLIT — allows a leaf that has shrunk (due to deletes)
to be reabsorbed into a sibling, releasing the sibling's
page-table ID.

**Design hazard**: the naive "post MERGE delta on the disappearing
node, redirect to its predecessor" protocol **livelocks** —
reader at R sees MERGE → goes to L → L still has SPLIT → goes to
R → MERGE → ... Requires careful ordering or a "sealed" marker
with well-defined fallback semantics.

Candidate protocols (tried during the session):

1. **Post MERGE on R first, then rebuild L.** Writers livelock
   between MERGE on R and SPLIT still on L.
2. **Rebuild L first, then post MERGE on R.** Writers at R between
   the two steps prepend to an orphaned chain. Writes lost.
3. **MERGE redirect points writers at L but marks them "retraverse
   once"** — prevents the livelock at the cost of
   retraversal-tracking per thread. Complex.
4. **Defer: only prune R when R is fully empty, and do it during L's
   consolidation with a SEAL-then-CAS two-step.** Cleanest. Still
   needs precise SEAL semantics (what does a reader/writer who
   arrives at a SEALED slot do?). Probably: retraverse from root,
   accepting whatever routing L has by then.

Option 4 is the recommended starting point. Write `merge.tla`
first. Verify that SEAL + CAS preserves LookupCorrectness under all
reader interleavings. Then code.

### Option B: internal-node routing (balanced B+tree) — LANDED

Shipped in `9b60510`. Root is a BASE_INTERNAL delta carrying a sorted
pivot array of `(sep_key, child_id)` entries; leaves are BASE_LEAF
chains (possibly with SPLIT deltas above the base). Two-level tree:
one internal root + up to 65535 leaves. Internal-node splits (making
the tree 3-level+) remain future work.

Spec: `v2/specs/balanced.tla` verifies the three-CAS protocol
(InstallSibling + PostSplit + UpdateParent) under all reader
interleavings. 65536 distinct states, depth 18, 4 invariants hold.

Key design choices baked into the implementation:
- **Chain inheritance dropped.** The parent's pivot array handles
  range routing, so a freshly split sibling X gets a clean
  [BASE_LEAF] chain — not [inherited SPLIT, BASE_LEAF].
- **Multi-SPLIT on leaves preserved.** A leaf that re-splits
  accumulates SPLITs newest-first with monotonically increasing
  seps. Lookups / writers walk newest-first and pick the SPLIT with
  the largest sep <= key. This handles stale-pivot readers who
  arrive at an old leaf via an outdated parent snapshot.
- **Parent updates are CAS-replace.** UpdateParent clones the
  BASE_INTERNAL with a new pivot and CASes the root slot. Serialized
  through `t->consolidating`; no other splitter races.

Chain depth after internal routing: bounded per-leaf (log N in
practice, not O(N/target)). 1024 keys at target=4 with sorted
inserts → max leaf depth 1. 6 threads × 400 disjoint keys at
target=4 → max leaf depth 9. See `btree_lf_balanced_growth` and
`btree_lf_large_scale_internal_routing`.

### Next steps

1. **R4 audit (task #175)** — scope is the internal-routing changes
   in `9b60510`. Preamble = cumulative R0-R3 closed list at
   `memory/audit_v2_r0_closed_list.md`. Focus surfaces: commit_split's
   three-step protocol, multi-SPLIT chain walk (resolve_leaf_chain,
   traverse_and_prepend), internal_clone_with_pivot ownership,
   build_leaf_chain ownership on failure (a leak bug caught during
   implementation), force_consolidate's tree walk, EBR interaction
   with the new BASE_INTERNAL retire path.

2. **MERGE (option A above)** — still requires `merge.tla` before
   code. Now that internal routing is in, MERGE semantics are
   clearer: a shrunk leaf can be absorbed into a sibling by
   (a) posting a MERGE marker on the victim leaf, (b) CAS-replacing
   the parent's BASE_INTERNAL with one that drops the pivot. Still
   have to nail down the redirect semantics during the window.

3. **10s+ TSAN stress (task #174 exit)** — may or may not need
   additional work; with contention now spread across many leaves,
   bumping STRESS_OPS from 3000 is plausible. Needs empirical
   validation under TSAN.

### Minor leftover

- Burned page-table IDs on commit_split CAS-failure — mitigated by
  65536-slot capacity; a freed-id pool is still future work. Low
  priority.

## How to verify current state

```bash
cd v2

# Default build + test (fast)
cmake -B build -S . -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure

# TSan
cmake -B build-tsan -S . -DSTM_SANITIZE=tsan \
    -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build-tsan -j
ctest --test-dir build-tsan --output-on-failure -R btree_lf

# TLC (requires /tmp/tla2tools.jar)
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
cd specs
java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
    -config structural.cfg structural.tla
# Expected: ~5120 distinct states, depth 15, no errors.

java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
    -config balanced.cfg balanced.tla
# Expected: 65536 distinct states, depth 18, no errors.
```

CI on push to `main` runs Linux gcc/clang × off/asan/tsan + macOS
clang × off/asan/tsan + TLC per spec. Watch it via `gh run list
--branch main --limit 1`.

## Trip hazards (do-not-re-do-list)

Keep this list in mind so next session doesn't burn cycles on
already-settled decisions:

1. **`(void)expr;` does NOT silence `warn_unused_result` on gcc 13.**
   Bind to a real variable: `int rc = expr; (void)rc;`.

2. **`atomic_init` is required for `_Atomic` fields** even if calloc
   zero-initializes them. C11 §7.17.2.1 says the state of an
   uninitialized atomic object is indeterminate; on lock-based-atomic
   platforms this is real UB. All four alloc_*_delta functions now
   call `atomic_init` for both `next` and `chain_depth`. Any new
   allocator must too.

3. **`force_consolidate` must hold `t->consolidating`.** Otherwise it
   races with `try_consolidate` on the commit_split CAS, burning a
   page-table ID per race (R2-3).

4. **commit_split's cleanup path does NOT use EBR retire.** It
   direct-frees the new allocations because `upper_id` is
   unreachable to readers until PostSplit's CAS succeeds. If you
   change the protocol so `upper_id` becomes reachable before the
   PostSplit CAS, the cleanup path becomes unsafe and must switch
   to EBR retire.

5. **Chain inheritance was REMOVED in #176.** Historical note: the
   right-chain MVP needed new siblings to inherit the parent's SPLIT
   so stale-pivot readers would still find keys routed onward. With
   internal routing (#176), the parent's pivot array handles
   routing directly; new siblings get a clean [BASE_LEAF] chain.
   The `inherited` parameter of commit_split was dropped.

6. **INSERTs above SPLIT invariant.** The writer's
   `traverse_and_prepend` walks chain newest-first and redirects on
   SPLIT *before* prepending. Therefore INSERT/DELETE deltas above a
   SPLIT in the chain are only ever for keys < sep. The reader and
   consolidator both rely on this. Any change to the writer's
   redirect logic must preserve this invariant.

7. **Consolidator is serialized per-tree**, not per-node. A
   tree-global flag. Simple but may limit throughput at high N.
   Not a correctness issue.

8. **Multi-SPLIT chains on leaves are correct by monotonicity.**
   When a leaf re-splits, each new SPLIT has a smaller sep than any
   existing SPLIT (splits partition a shrinking range). Newest-first
   chain walk sees seps in increasing order. Lookup/writer picks the
   SPLIT with the largest sep <= key — that's the most-specific
   sibling for key. Break the walk early on the first SPLIT with
   sep > key (older SPLITs have even larger seps, none will match
   either). If you add splits that DON'T preserve this monotonicity
   (e.g. a MERGE reorganization), the walk logic needs revisiting.

9. **BASE_INTERNAL is CAS-replaced atomically on UpdateParent.**
   Under `t->consolidating`, no other splitter races. The CAS
   contract assumes the old head is exactly the BASE_INTERNAL we
   read. If you add another code path that mutates the parent's
   slot (e.g. writer prepends on internal nodes), the CAS needs
   retry + rebuild.

10. **build_leaf_chain takes ownership of `leaf` only on SUCCESS.**
   On failure it detaches `leaf` from the partially-built base
   delta before freeing the delta, leaving the caller to free
   `leaf`. If you refactor this, double-check the caller's
   `stm_bt_node_free(new_base_node)` in consolidate_or_split's
   error path.

## Key files

```
v2/
├── include/stratum/
│   ├── btree.h          # public API (stm_btree_lf_*)
│   └── ebr.h            # EBR interface
├── src/btree/
│   ├── btree_lf.c       # lock-free tree — the primary target
│   ├── btree.c          # single-threaded Bε-tree (reused node
│   │                    #     format, unchanged)
│   ├── btree_mt.c       # rwlock fallback (not touched in Phase 2
│   │                    #     proper; still exists per ARCH §3.8)
│   ├── node.c / node.h  # stm_bt_node — shared leaf/pivot
│   │                    #     representation
│   └── CMakeLists.txt
├── src/ebr/
│   ├── ebr.c            # epoch-based reclamation
│   └── CMakeLists.txt
├── specs/
│   ├── balanced.tla     # internal-routing parent-update (#176)
│   ├── sync.tla         # four-phase commit
│   ├── concurrency.tla  # MVCC + delta chain + EBR
│   └── structural.tla   # SPLIT protocol + cascade (extended)
├── tests/
│   └── test_btree_lf.c  # 16 tests (incl. balanced_growth + large-scale)
└── docs/
    ├── phase2-bw-tree-design.md  # pre-implementation design note
    └── phase2-status.md           # THIS FILE
```

## Where to pick up

1. Read this file top to bottom.
2. Read `memory/audit_v2_r0_closed_list.md` for R0–R3 do-not-report.
3. The recommended next chunk is either:
   - **R4 audit** over the internal-routing changes in `9b60510`
     (scoped — cheapest unit of value).
   - **MERGE** — write `merge.tla` first. Use `balanced.tla` /
     `structural.tla` as templates for style.
4. Run the verification commands to confirm tip is green.
5. Start spec-first. Don't touch `btree_lf.c` until the spec is
   TLC-clean.
