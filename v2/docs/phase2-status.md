# Phase 2 — status and next-session guide

This file is the authoritative pickup guide for continuing Phase 2
work on the lock-free Bw-tree. Last update 2026-04-20 (after MERGE
landed in `83f4710`). The `v2/docs/phase2-bw-tree-design.md` alongside
is the historical pre-implementation design note — left intact as a
record of the reasoning that led to the current code.

## TL;DR

The lock-free Bw-tree is a **balanced B+tree with SPLIT and MERGE**:
root is a BASE_INTERNAL delta with a pivot array; leaves are atomic-
published BASE_LEAF chains with SPLIT redirects; empty leaves without
preserved SPLITs are reabsorbed into their left neighbor via the
SEAL-with-forward MERGE protocol. All five audit rounds R0-R5 are
closed. 21/21 tests green on default/ASan/TSan. The remaining Phase 2
open item is the per-node consolidator flag (modest refactor; unblocks
higher-throughput stress).

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
| `67da4f0` | R4 audit fixes: 512 KiB stack buffers → heap-alloc, force_consolidate thrash-guard, dead writes / redundant NULL loop cleanups. Closed R4 with 0 P0 / 0 P1 / 1 P2 / 5 P3. |
| `048520f` | **#174: multi-leaf concurrent stress**. 8 threads × 3000 ops on 1024-key × target=16 → ~64 leaves under contention. ~3s under TSan; total suite ~8s. Throughput ceiling reached at tree-global consolidator flag. |
| `91a6a84` → `83f4710` | **MERGE landed (#172 remainder)**. `merge.tla` spec (65536 states, depth 18). Implementation adds SEAL delta kind, `commit_merge` (four CAS: PurgeSplitOnL, SealR, UpdateParent, RetireR), `purge_split_on_l`, `try_merge` dispatch, and three tests. Eligibility: R's consolidated head is BASE_LEAF with 0 entries and no SPLITs above. Tests + TLC + Werror all green. R5 audit in progress. |

Also: several CI-fix commits for Linux `-Werror` / liboqs issues.
All CI matrix jobs (Linux gcc/clang × off/asan/tsan + macOS clang ×
off/asan/tsan + TLC per spec, including `merge`) green on tip.
21/21 tests pass on default/ASan/TSan.

Audit rounds closed: R0 (pre-#171 substrate), R1 (MVP), R2 (SPLIT
protocol), R3 (chain inheritance), R4 (internal routing in #176),
**R5 (MERGE)**. Cumulative do-not-report ledger is
`memory/audit_v2_r0_closed_list.md`.

## What's left in Phase 2

All structural ops (SPLIT + MERGE) have landed. Remaining scope is
the per-node consolidator flag (modest, unblocks throughput) plus any
R5 audit fixes.

### MERGE (landed)

Symmetric inverse of SPLIT. Reabsorbs an empty leaf into its left
neighbor. Four CAS events, serialized under `t->consolidating`:

  0. **PurgeSplitOnL** — L's chain had a SPLIT(sep, R) from when R
     was carved out of L. Merging without first removing that SPLIT
     would create a bounce (reader at L → SPLIT → R → SEAL → L →
     SPLIT …). The purge CASes L to a chain without the stale SPLIT.
     This step is implicit in `merge.tla`'s scenario (which models
     L1 without SPLIT); the implementation establishes the spec's
     precondition.

  1. **SealR** — CAS R's slot head from BASE_LEAF({}) to
     SEAL(forward=L). Writers who see SEAL retraverse from root or
     follow the forward; readers follow the forward.

  2. **UpdateParent** — CAS parent BASE_INTERNAL to drop the pivot
     at R's index. Fresh readers now route R's former range directly
     to L via the new pivots.

  3. **RetireR** — EBR-retire R's pre-SEAL chain. SEAL persists at
     R's slot indefinitely (no slot reclamation in this MVP — same
     burned-ID policy as commit_split).

**Eligibility** (enforced by `try_merge`): R's consolidated head must
be BASE_LEAF with nentries == 0 AND no preserved SPLIT deltas above.
R must not be the leftmost child of its parent (leftmost-merges would
require a different forward direction and aren't modeled by the spec).

**Spec**: `v2/specs/merge.tla`. 65,536 distinct states, depth 18.
Invariants: TypeOK, LookupCorrectness, ReaderResultsCorrect,
ProtocolStateValid, BaseInvariant. Step 0 (PurgeSplitOnL) is
documented as a precondition; its own correctness argument is a
CAS-swap between two LookupCorrectness-equivalent states (routing
k >= sep to empty R vs. falling through to L's BASE — both yield
ABSENT for R's range).

**MVP limitations (follow-up material):**
- Leaves with preserved SPLITs aren't merge-eligible. In a sorted-
  insert tree, only the rightmost leaf (freshly split off) has no
  SPLITs. Once it shrinks to empty, it's mergeable. Older leaves
  (lower halves of prior splits) accumulate SPLITs and stay in the
  tree even when empty. An EBR-aware SPLIT garbage-collector would
  unlock merge for them.
- Leftmost-child merges are unsupported. If a tree's leftmost child
  becomes empty, it can't be absorbed leftward (no left neighbor) nor
  easily absorbed rightward (requires promoting pivots[0].right_child
  to leftmost and dropping pivots[0]; spec doesn't model this).
- No slot reclamation — SEAL persists in R's slot forever. Bounded
  by merge count per session; practical cost is small.

### Internal-node routing (balanced B+tree) — LANDED

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

1. **R5 audit** — CLOSED 2026-04-20. 0 P0 / 0 P1 / 2 P2 / 3 P3.
   Both P2s fixed (R5-P2-1 dead fast-path in force_consolidate
   removed; R5-P2-2 lookup + traverse hop budgets bumped to page-
   table capacity). One P3 addressed (new concurrent merge TSan
   test). Two P3s flagged: merge.tla doesn't model step 0 purge
   (spec extension, not correctness), leftmost-merge unsupported
   (MVP scope). Full list in `memory/audit_v2_r0_closed_list.md`.

2. **Per-node consolidator flag** — the current `t->consolidating`
   is tree-global. Under the multi-leaf stress (`048520f`),
   chain depth on one leaf spiked past MAX_CHAIN=4096 because other
   leaves held the flag. Per-node flag would let chain-drain
   happen in parallel across leaves, unblocking higher-throughput
   stress (and the historical 10s+ target). Modest change — add
   `_Atomic bool consolidating` to the page-table slot or as a
   parallel array indexed by nid.

3. **Follow-ups unlocked by landed MERGE:**
   - EBR-aware SPLIT purge. When a parent pivot has been present
     long enough that all readers with stale pre-pivot snapshots
     have drained (bounded by EBR epoch advance), the
     corresponding SPLIT on the left leaf becomes safely
     removable. Unlocks merge for leaves that currently retain
     SPLITs.
   - Slot reclamation. SEAL slots persist forever in the current
     MVP. A freed-ID pool (also pending from R2-1) would let the
     slot count stay bounded under heavy delete workloads.
   - Leftmost-merge support. Requires a variant of MERGE that
     promotes `pivots[0].right_child` to leftmost and drops
     `pivots[0]`; needs its own spec extension.

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

java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
    -config merge.cfg merge.tla
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

11. **SEAL is terminal at R's slot.** commit_merge never CASes
   away R's SEAL head — SEAL persists for the tree's lifetime.
   Any future code that wants to "unseal" or reuse a slot must
   also update `enumerate_leaves` (it walks parent's pivots, so
   SEAL'd slots are naturally excluded) and carefully audit EBR
   retire timing.

12. **MERGE requires PurgeSplitOnL FIRST** (step 0 of the 4-step
   protocol, implicit in the 3-step merge.tla scenario). Without
   it, readers bounce between L's stale SPLIT(*, R) and R's
   SEAL(forward=L). commit_merge calls `purge_split_on_l` before
   SealR. If you ever reorder these, re-verify with a TSan run
   of `btree_lf_merge_rightmost_after_split`.

13. **Merge eligibility is strict**: consolidated BASE with 0
   entries AND 0 preserved SPLITs AND non-leftmost pivot. Leaves
   with preserved SPLITs aren't merge-eligible because the
   SPLITs redirect ranges to still-live siblings; MERGE doesn't
   transfer those redirects. An EBR-aware SPLIT purge would
   relax this (future work).

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
│   ├── merge.tla        # SEAL-with-forward MERGE (#172 closure)
│   ├── sync.tla         # four-phase commit
│   ├── concurrency.tla  # MVCC + delta chain + EBR
│   └── structural.tla   # SPLIT protocol + cascade (extended)
├── tests/
│   └── test_btree_lf.c  # 21 tests (incl. multi_leaf_stress #174 + 4 merge)
└── docs/
    ├── phase2-bw-tree-design.md  # pre-implementation design note
    └── phase2-status.md           # THIS FILE
```

## Where to pick up

1. Read this file top to bottom.
2. Read `memory/audit_v2_r0_closed_list.md` for R0–R5 do-not-report.
3. The recommended next chunk is **per-node consolidator flag**
   (modest refactor, no spec needed, unblocks higher-throughput
   stress). Follow-up opportunities listed under the "Next steps"
   section above.
4. Run the verification commands to confirm tip is green.
