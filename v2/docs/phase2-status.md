# Phase 2 — status and next-session guide

This file is the authoritative pickup guide for continuing Phase 2
work on the lock-free Bw-tree. Written 2026-04-20. The
`v2/docs/phase2-bw-tree-design.md` alongside is the historical
pre-implementation design note — left intact as a record of the
reasoning that led to the current code.

## TL;DR

The lock-free Bw-tree is functional with full concurrent correctness.
Four audit rounds have passed. Remaining Phase 2 scope is MERGE or
internal-node routing — both sizable and spec-first.

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
| `8d77a29` | Chain inheritance — re-splits carry the inherited SPLIT into the new sibling |
| `09c3636` | `structural.tla` extended to cover 2-level cascade (5120 states, depth 15) |

Also: several CI-fix commits for Linux `-Werror` / liboqs issues.
All CI matrix jobs (Linux gcc/clang × off/asan/tsan + macOS clang ×
off/asan/tsan + TLC per spec) green on tip. 14/14 tests pass on
default/ASan/TSan.

Audit rounds closed: R0 (pre-#171 substrate), R1 (MVP), R2 (SPLIT
protocol), R3 (chain inheritance). Cumulative do-not-report ledger is
`memory/audit_v2_r0_closed_list.md`.

## What's left in Phase 2

Both of these are sizable — each wants spec work **before** code.

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

### Option B: internal-node routing (balanced B+tree)

The biggest architectural improvement. The current tree, even with
chain inheritance, is a right-biased linked chain — lookup is O(N/
target) in the worst case. A real B+tree with internal nodes holding
multiple pivots would give O(log N) lookups.

Protocol sketch:

- New delta kind `STM_BT_LF_DELTA_BASE_INTERNAL` holding a sorted
  pivot array `stm_bt_lf_pivot[]` of `(sep_key, child_id)`.
- First leaf split transitions root from `BASE_LEAF` to
  `BASE_INTERNAL` with 2 pivots — a single CAS publishing the new
  content. Children (lower, upper) are fresh IDs.
- Subsequent leaf splits add a pivot to the parent via atomic CAS
  of `BASE_INTERNAL(pivots)` → `BASE_INTERNAL(pivots + new)`. This is
  serialized through the existing consolidating flag; only one
  splitter updates the parent at a time.
- Reader traversal: at BASE_INTERNAL, binary-search pivots to pick
  child. At BASE_LEAF, lookup directly.
- Writer traversal: same; prepend INSERT/DELETE only on leaves.
- SPLIT deltas still useful for atomic-visibility window between
  leaf split and parent-pivot-add — reader arriving at the child
  mid-split sees SPLIT, redirects. After parent update, SPLIT
  becomes redundant but harmless.

Needs `balanced.tla` spec with:
- `internal` node modeled as a pivot set.
- Leaf-split-with-parent-update as two CAS events (leaf's SPLIT
  delta + parent's rebuild).
- `LookupCorrectness` invariant across all intermediate states.

Implementation scope estimate: **400-600 LOC** in `btree_lf.c` plus
a substantive new spec plus tests. Can ship in a single focused
session.

### Minor leftover

- 10s+ TSAN stress target (task #174) is deferred. The MVP's
  serialized consolidator is the throughput bottleneck. Either
  internal routing (option B) or a per-node consolidator flag
  unblocks it.
- Burned page-table IDs on commit_split CAS-failure is mitigated by
  the 65536 capacity but not eliminated. A freed-id free-list would
  be a final fix. Low-priority.

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

5. **Chain inheritance's sep_key ownership.** On commit_split success,
   ownership of `inherited->sep_key` is transferred to the newly
   built `inherited_delta`. On cleanup, `inherited->sep_key` is
   either still caller-owned (if transfer didn't happen) or NULLed
   (if transfer did). The caller's final `if (preserved.sep_key)
   free(...)` handles both cases. Don't add another free without
   re-deriving the ownership state.

6. **INSERTs above SPLIT invariant.** The writer's
   `traverse_and_prepend` walks chain newest-first and redirects on
   SPLIT *before* prepending. Therefore INSERT/DELETE deltas above a
   SPLIT in the chain are only ever for keys < sep. The reader and
   consolidator both rely on this. Any change to the writer's
   redirect logic must preserve this invariant.

7. **Consolidator is serialized per-tree**, not per-node. A
   tree-global flag. Simple but may limit throughput at high N.
   Not a correctness issue.

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
│   ├── sync.tla         # four-phase commit
│   ├── concurrency.tla  # MVCC + delta chain + EBR
│   └── structural.tla   # SPLIT protocol + cascade (extended)
├── tests/
│   └── test_btree_lf.c  # 14 tests
└── docs/
    ├── phase2-bw-tree-design.md  # pre-implementation design note
    └── phase2-status.md           # THIS FILE
```

## Where to pick up

1. Read this file top to bottom.
2. Read `memory/audit_v2_r0_closed_list.md` for R0–R3 do-not-report.
3. Pick MERGE or internal routing. Both demand a fresh spec before
   code. Use `structural.tla` as the template for style.
4. Run the verification commands to confirm tip is green.
5. Start spec-first. Don't touch `btree_lf.c` until the spec is
   TLC-clean.
