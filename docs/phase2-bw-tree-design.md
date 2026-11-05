# Phase 2 — Lock-free Bw-tree design notes

**Status**: design intent for the next implementation chunk. Writes the plan
before the code, per ROADMAP-V2 §3.1 principle.

**Starting state**: commits through `7e8c499`. Single-threaded `stm_btree` and
rwlock-wrapped `stm_btree_mt` both land green; concurrency.tla is TLC-verified;
EBR is TSAN-clean. The lock-free Bw-tree will be a third implementation, not a
replacement — selected via compile-time flag alongside the rwlock fallback.

## Scope

Build an lock-free concurrent Bε-tree variant following the Bw-tree pattern
(Levandoski et al. 2013), integrated with:

- `stm_ebr` for safe reclamation of retired nodes / deltas
- The single-threaded `stm_bt_node` representation (reused for the "base"
  state of each logical node)
- The `concurrency.tla` invariants already proved at small scope

## Architecture

### Logical vs. physical nodes

The classic Bw-tree uses a **page table** mapping logical node IDs to physical
pointers. Parents hold IDs, not pointers. When a node is consolidated, the
page table entry is CAS-swapped to point at the new physical node — parents
don't need rewriting.

For Stratum v2, we'll adopt this pattern. One central page table per tree:

```c
struct stm_bt_page_table {
    _Atomic(stm_bt_physical *) *slots;   // slots[node_id] -> physical
    _Atomic uint64_t next_id;            // monotonic ID allocator
    size_t capacity;                     // grows via resize-with-CoW
};
```

`stm_bt_physical` has two flavors:
- **Base node**: owns the consolidated `stm_bt_node` (reused from single-threaded)
- **Delta record**: one pending op (insert / delete / split-announce / merge-announce)
  with `next` pointer to the rest of the chain

A logical node at any moment is represented by a chain:
`delta_n -> delta_{n-1} -> ... -> delta_1 -> base`
(LIFO: newest at head per ARCH §3.4.2)

The page table slot holds the CURRENT HEAD (newest delta, or the base if no
deltas). Readers atomically load the head and walk.

### Delta record layout

```c
typedef enum {
    STM_BT_DELTA_INSERT,     // (key, value) to insert
    STM_BT_DELTA_DELETE,     // (key) to delete
    STM_BT_DELTA_SPLIT,      // split announced, new sibling's node_id + separator key
    STM_BT_DELTA_MERGE,      // merge announced, absorbing sibling's content
    STM_BT_DELTA_CONSOLIDATED_BASE, // a fresh base; marks chain tail
} stm_bt_delta_kind;

typedef struct stm_bt_delta {
    stm_bt_delta_kind      kind;
    _Atomic(struct stm_bt_delta *) next;
    union {
        struct { uint8_t *key; uint32_t key_len; uint8_t *val; uint32_t val_len; } upsert;
        struct { uint8_t *key; uint32_t key_len; } del;
        struct { uint8_t *sep_key; uint32_t sep_key_len; uint64_t new_sibling_id; } split;
        struct { stm_bt_node *base; } consolidated;   // only for CONSOLIDATED_BASE kind
    } u;
    uint32_t chain_depth;    // hint; used to trigger consolidate
} stm_bt_delta;
```

### Reader path

```c
stm_status stm_bt_lf_lookup(stm_bt_lf_tree *t, key, key_len, ...) {
    stm_ebr_thread *me = stm_ebr_thread_current();
    stm_ebr_enter(me);

    // Walk from root node_id down to a leaf.
    uint64_t nid = atomic_load(&t->root_id);
    for (;;) {
        stm_bt_delta *head = atomic_load(&t->page_table->slots[nid]);

        // Walk the chain newest-first looking for our key.
        // INSERT/DELETE with matching key: return that outcome.
        // SPLIT delta: if our key >= separator, follow the new sibling.
        // MERGE delta: if the merge targets our subtree, adjust.
        // CONSOLIDATED_BASE: fall through to base lookup.
        ...

        if (base_is_leaf) { result = lookup_in_leaf_base(...); break; }
        nid = base_pivots_child_for(key);
    }

    stm_ebr_exit(me);
    return result;
}
```

Every pointer the reader dereferences is kept alive by the EBR epoch it
holds. Consolidation retires old chains only via `stm_ebr_retire`, so the
reader cannot encounter a freed delta.

### Writer path

```c
stm_status stm_bt_lf_insert(stm_bt_lf_tree *t, key, key_len, val, val_len) {
    stm_ebr_thread *me = stm_ebr_thread_current();
    stm_ebr_enter(me);

    // 1. Walk to the target node (same as reader).
    uint64_t target_nid = find_target_nid(key);

    // 2. Allocate a new INSERT delta.
    stm_bt_delta *d = alloc_delta_insert(key, key_len, val, val_len);

    // 3. CAS-prepend to page_table->slots[target_nid].
    stm_bt_delta *head;
    do {
        head = atomic_load(&t->page_table->slots[target_nid]);
        atomic_store(&d->next, head);
        d->chain_depth = (head ? head->chain_depth : 0) + 1;
    } while (!atomic_compare_exchange_weak(&t->page_table->slots[target_nid],
                                            &head, d));

    // 4. If chain_depth >= threshold, attempt consolidation (helping).
    if (d->chain_depth >= CONSOLIDATE_THRESHOLD) {
        try_consolidate(t, target_nid);
    }

    stm_ebr_exit(me);
    return STM_OK;
}
```

### Consolidation

The "helping" pattern: any writer whose prepend leaves `chain_depth ≥ 8`
attempts to consolidate. First success wins; others abandon.

```c
static void try_consolidate(stm_bt_lf_tree *t, uint64_t nid) {
    stm_bt_delta *old_head = atomic_load(&t->page_table->slots[nid]);
    // Walk the chain end-to-end, building a fresh consolidated base.
    stm_bt_node *new_base = build_consolidated_base(old_head);
    // Wrap as a CONSOLIDATED_BASE delta (chain_depth = 0).
    stm_bt_delta *new_head = wrap_as_base_delta(new_base);

    // CAS the slot. If it fails, another writer either prepended or
    // consolidated first — abandon (free new_base).
    if (!atomic_compare_exchange_strong(&t->page_table->slots[nid],
                                         &old_head, new_head)) {
        free_new_base(new_base);
        free(new_head);
        return;
    }

    // We won: retire the old chain via EBR.
    retire_chain(old_head);
}
```

### Split / merge (structural ops)

Bw-tree splits and merges are multi-step protocols where intermediate
states ARE visible via delta records. The helping pattern lets any thread
finish a partially-complete structural op.

**Split** (leaf grows past target_entries post-consolidation):

1. Allocate new sibling with upper half, assign fresh node_id. CAS-install in
   page_table.
2. Post SPLIT delta on the splitting node. Reader seeing this delta: if key
   >= separator, follow the new sibling instead of descending this node's
   base.
3. Post CHILD-ADD delta on the parent (separator key, new sibling's
   node_id). Reader seeing this delta on the parent routes correctly.

Any thread can "help finish" a split at stages 2 or 3 if it observes a
partial state. Formal atomic visibility is via the delta chain semantics:
readers who snapshot the head see either the pre-split or post-split view.

**Merge** is the mirror — more complex in practice because the disappearing
node must stay readable until every observer has moved past its epoch (EBR).

## Integration points

- **EBR**: every retired delta / base node goes through `stm_ebr_retire`
  with a per-kind destructor. Consolidation retires the old chain; structural
  ops retire the obsolete sibling. The EBR push-back/filter logic we fixed
  this session is relied on to be correct under concurrent retire + advance.
- **Single-threaded core**: `build_consolidated_base` reuses
  `stm_bt_node` layout, applying deltas to a copy of the old base. The
  flush-message-to-leaf helpers in `src/btree/btree.c` translate directly.
- **Concurrency spec**: the current `v2/specs/concurrency.tla` models the
  delta-chain + consolidate + EBR interaction. Before shipping, extend the
  spec with split/merge delta semantics (or add a sibling `structural.tla`)
  and re-verify.

## Bugs / gotchas learned this session (DO NOT RE-STEP ON)

1. **Spec: delta ID reuse collision**. My first concurrency.tla draft reused
   delta IDs from a fixed pool, masking a real bug: TLC reported a false
   positive where a retired ID reappeared. Fix: monotonic next_delta_id,
   matching heap-unique real addresses. Keep this pattern if extending the
   spec.

2. **EBR: 3-advance lag, not 2**. After a retire at epoch e, reclamation
   happens on advance from e+2 to e+3. Testing needs `advance_until_reclaimed(3)`
   helper. Bucket index is `(e-2) % 3` of the PRE-advance epoch.

3. **EBR: push-back race on bucket collision**. When an advance's steal_bucket
   races with a concurrent retire, the new retire may land in the
   being-drained bucket with a retire_epoch == current. Solution: each record
   carries retire_epoch; drain_list_filtered frees only records older than
   `safe_before = e - 1`, pushes others back. Reclaim eventually succeeds.

4. **EBR: test stop condition matters**. "Stop draining when pending_retires
   plateaus" is wrong — under push-back, progress shows as 0-freed for
   multiple advances before the epoch catches up. Use a fixed iteration bound
   or break on `g_freed >= retires`.

5. **CMake: platform detection order**. STM_PLATFORM_LINUX / _DARWIN must be
   set BEFORE any conditionals that consume them. Put the detection block near
   the top.

6. **CI: libsodium apt ships 1.0.18 on ubuntu-24.04**. AEGIS-256 requires
   1.0.19+. Build from source in CI.

7. **CI: feature-test macros on Linux**. `-std=c17` sets __STRICT_ANSI__,
   hiding pread/pwrite/posix_memalign etc. Set
   `_POSIX_C_SOURCE=200809L _XOPEN_SOURCE=700 _GNU_SOURCE _DEFAULT_SOURCE`
   on Linux only; macOS exposes these by default and setting POSIX macros
   there would HIDE macOS-specific symbols (F_FULLFSYNC etc.).

8. **macOS aligned_alloc**. Requires size to be a multiple of alignment. Use
   `posix_memalign` instead for cache-line-aligned heap structs.

9. **Werror pitfalls**. `(void)` cast doesn't silence
   `warn_unused_result` on all gcc versions; handle the return value
   explicitly. `-D_FORTIFY_SOURCE=2` conflicts with ASan's interceptors AND
   with macOS Sequoia's already-pre-defined version — gate on
   `STM_PLATFORM_DARWIN` and `STM_SANITIZE STREQUAL "off"`.

## Test strategy

Before shipping:

1. **Property-based**: mixed op workload (insert/lookup/delete), verify final
   tree matches a shadow `HashMap`-equivalent after N random ops × M threads.
2. **TSAN long run**: 8 threads × 10s (not the current 500-op-per-thread; go
   longer to expose memory-ordering races). Aim for zero TSAN reports.
3. **EBR interaction**: retire counts match free counts exactly. Instrument
   retires + frees with atomic counters, assert equality at teardown.
4. **Consolidation correctness**: force high chain depth, verify
   consolidate merges all deltas correctly. Check that the old chain is
   retired (not leaked).
5. **Structural op races**: two threads concurrently splitting the same
   node — only one's split should land; the other's CAS fails and it retries
   on the post-split state.

## File layout for next session

```
v2/src/btree/
    btree.c          (single-threaded; unchanged)
    btree_mt.c       (rwlock fallback; unchanged)
    btree_lf.c       (NEW — lock-free Bw-tree)
    node.c, node.h   (shared node layout)
    page_table.c     (NEW — logical ID → physical pointer table)

v2/include/stratum/
    btree.h          (add stm_btree_lf_* API, parallel to _mt)

v2/tests/
    test_btree_lf.c  (NEW — concurrent correctness + stress)
```

## Audit plan

Once the lock-free path is green under TSAN stress for 10s+, spawn an R1
audit per CLAUDE.md:
- Scope: `v2/src/btree/btree_lf.c`, `v2/src/btree/page_table.c`, any changes
  to `v2/src/ebr/*`.
- Preamble: `memory/audit_v2_r0_closed_list.md` (R0 findings — do not
  re-report).
- Focus: CAS ordering, ABA vulnerabilities, consolidation races, structural
  op atomic visibility.
