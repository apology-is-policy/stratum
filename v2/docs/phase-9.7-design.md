# Phase 9.7 — Snapshots, D1 (per-dataset metadata trees)

> Status: draft 2026-05-20. Supersedes the gap entries
> `project_snapshot_substrate_gap.md` (memory) and folds
> the ARCH §8.3 / §8.5 / §8.6 design intent into a concrete
> impl plan now that the **Phase 9.6 engine substrate** is live.
>
> Prerequisite: tip `5ea4816` on `phase-9.6` — the four metadata
> indices (extent + inode + dirent + xattr) all flow through
> `btree_engine`'s incremental-COW + deferred-free + three-phase
> commit substrate. STM_UB_VERSION at 29.

## 1 — Why this phase exists

A COW filesystem without working rollback is not a COW filesystem.
Phase 6 shipped the snapshot **index** (`stm_snapshot_entry`,
chain-prev, holds, the rollback-compromise marker from TLY-A5),
but every entry's `tree_root_paddr` is zero — no entry captures a
recoverable tree, because there was no per-dataset tree to capture.
The four metadata indices live in pool-global trees
(`ub_inode_root` / `ub_dirent_root` / `ub_xattr_root` /
`ub_extent_root`), keyed by `(dataset_id, …)` composite keys.

Consequences (`project_snapshot_substrate_gap.md`):

- **No rollback.** `stm_fs_rollback_snapshot` is a stub returning
  `STM_ENOTSUPPORTED`. Pool-global roots can't be swapped to roll
  back one dataset.
- **No readable snapshots.** `.snaps/<name>/` (ARCH §8.5.4) needs a
  recoverable tree the read view roots on; nothing roots one.
- **No real clones.** Clone-as-shared-root (ARCH §8.6) needs a
  per-dataset root the clone shares.

Phase 9.6's engine substrate solves the persistence-shape part of
the gap (a tree can be opened from a `(paddr, gen, csum)` triple,
the COW is incremental, the commit is three-phase). What 9.7 does
is **re-shape the trees** — pool-global → per-dataset — so each
dataset's snapshot has a single durable root to capture.

## 2 — Decision: D1 — one unified tree per dataset

User decision 2026-05-16 (recorded in
`project_snapshot_substrate_gap.md`), **cost-blind**:

> **D1 — one unified per-dataset tree.** Each dataset owns one
> `btree_engine` instance holding inodes + dirents + xattrs +
> extent records under **type-tagged keys**. The dataset entry
> gains `di_tree_root` + `di_root_gen` + `di_root_csum[32]`. The
> pool-global `ub_{inode,dirent,xattr,extent}_root` are retired.

**Rejected: D2** — four per-dataset trees behind a root-set
record. D2 was the cost-weighted pick (lower-effort cutover —
each module keeps its own tree; the dataset entry holds four
roots), but it makes a snapshot a **4-root tuple** whose
consistency every mount / recovery / verify / send / clone path
must re-prove. D1's snapshot is a **single root** — opening the
snapshot is one tree-open call, integrity-verifying the snapshot
is one tree-walk, send/recv enumerates one tree.

Cost-excluded, D1 wins. It's also the ZFS / btrfs shape — both
file systems use one tree per filesystem/objset, with
type-discriminated records, exactly because the structural
single-root makes everything downstream simpler.

### 2.1 — Type-tagged keys

Each per-dataset engine holds records of four kinds. Discriminated
by a **1-byte type tag** at the front of every key:

| Tag | Type | Key after tag | Value |
|---|---|---|---|
| `0x01` | INODE | `ino(8)` — inode id, big-endian | inode record (R71 P1-1 mirroring) |
| `0x02` | DIRENT | `dir_ino(8) ‖ hash(N)` — open-address chain | dirent record |
| `0x03` | XATTR | `ino(8) ‖ hash(N)` — open-address chain | xattr record |
| `0x04` | EXTENT | `ino(8) ‖ offset(8)` — both big-endian | extent record |

All multi-byte fields **big-endian** so lexicographic byte order
== logical order — a `scan_range` over `[0x01 ‖ ino, 0x02 ‖ 0]`
yields exactly that inode's dirents in id order (today already the
shape inside each module, just with the leading `dataset_id(8)`
the pool-global keys carry; the dataset_id drops because the tree
itself names the dataset).

A shared helper `stm_metakey_compose` / `stm_metakey_parse` in
`v2/src/metakey/` (NEW small lib) is the single chokepoint for the
encoding. Every module calls through it; no module reaches for the
tag byte directly. The tag values are an enum (`stm_metakey_kind`)
that the helper bounds-checks on parse — a foreign byte at the tag
position returns `STM_ECORRUPT` rather than mis-routing to the
wrong record-type's decoder. R71 P1-1 doctrine carry: the
writer-side tag byte and the decoder-side bounds check are
**symmetric**.

### 2.2 — What stays pool-global

Two trees stay pool-global because they describe **the pool itself**,
not per-dataset content:

- **`ub_main_root`** — the dataset index (`stm_dataset_entry`s).
- **`ub_snap_root`** — the snapshot index (`stm_snapshot_entry`s).

Both stay encrypted under the pool's metadata key. The per-dataset
engines each carry their own metadata key derived per ARCH §7.3 /
the key-schema (TLY-A3 makes per-dataset keys real for production
deployments — a CORVUS slot per dataset binds its DEK).

## 3 — The substrate shift (impl-1)

### 3.1 — Dataset entry on disk

`stm_dataset_entry` gains three fields, mirroring ARCH §8.3.2:

```c
typedef struct {
    /* existing */
    uint64_t id;
    uint64_t parent_id;
    uint32_t name_len;
    uint8_t  name[STM_DATASET_NAME_MAX + 1u];
    uint64_t created_txg;
    uint32_t flags;
    uint64_t next_ino;
    uint64_t origin_snap_id;

    /* NEW (9.7-impl-1) */
    uint64_t di_tree_root;          /* paddr of the dataset's engine root */
    uint64_t di_root_gen;           /* per-node birth-gen of the root */
    uint8_t  di_root_csum[32];      /* BLAKE3 csum of the root node ciphertext */
} stm_dataset_entry;
```

The triple is the dataset's **durable identity** — `stm_btree_engine_open(vt, ctx, cx, dataset_id, di_tree_root, di_root_gen, di_root_csum, ...)` rehydrates the engine at mount. The `di_root_gen` carries the per-node birth-gen the engine encodes in `bp_reserved2` (24-btree-engine.md §3.9); without it the AEGIS-256 decrypt would fail (the gen is an AEAD nonce input).

A freshly-created dataset has `di_tree_root == 0 / di_root_gen == 0 / di_root_csum == zeros`. The engine's `create` initialises an empty-leaf root in RAM; the dataset's first sync commits an actual paddr. The all-zero-triple is the "empty dataset" sentinel — the engine's `open` accepts it as a degenerate empty tree.

### 3.2 — Sync three-phase cascade scales to N datasets

Phase 9.6 closed with a fixed-cost 4-engine cascade. Under D1 the cascade is **M engines** where M is the count of PRESENT datasets. Each PRESENT dataset's engine participates in `flush` / `finalize` / `abort`.

Per-iteration cost is dominated by dirty datasets — a clean engine's `commit_flush` writes nothing, frees nothing (24-btree-engine.md §Commit). Typical pools have < 100 datasets; even a 10,000-dataset pool's clean-cascade cost is bounded by the per-engine clean-cycle minimum (one lock + a count_dirty pass returning 0).

The cascade walks PRESENT datasets in a deterministic order: ascending `dataset_id`. The monotone-prefix abort discipline generalises — if dataset K's flush fails, datasets 1..K-1 abort. The R154 Q2 wedge carry holds: if any dataset's `commit_finalize` fails post-UB-write, the fs wedges (a finalize is structurally-infallible in the engine; a partial-success on the M-way cascade is crash-equivalent).

After every dataset's finalize succeeds, sync writes one UB carrying the dataset index's root + the snap index's root. Per-dataset roots are not in the UB — they're in the dataset entries the dataset-index tree holds, so the UB reaches them transitively.

### 3.3 — UB retiring

The four pool-global metadata-tree fields in the uberblock are retired (kept as **reserved-zero-on-write, ignored-on-read** for one UB version, then carved into something else in 9.8). `STM_UB_VERSION` bumps **29 → 30**.

| Field | v29 | v30 |
|---|---|---|
| `ub_main_root` / `ub_main_root_gen` | live | live (unchanged) |
| `ub_snap_root` / `ub_snap_root_gen` | live | live (unchanged) |
| `ub_inode_root` / `ub_inode_root_gen` | live | reserved-zero |
| `ub_dirent_root` / `ub_dirent_root_gen` | live | reserved-zero |
| `ub_xattr_root` / `ub_xattr_root_gen` | live | reserved-zero |
| `ub_extent_root` / `ub_extent_root_gen` | live | reserved-zero |

Pre-release migration policy (memory `project_snapshot_substrate_gap.md`): **no converter**. A pre-9.7 pool is rejected at mount with `STM_EVERSION`. Stratum has not shipped; the discipline is clean breaks until 1.0.

### 3.4 — Mount-time loading

Order:

1. Pool open + UB read (existing).
2. Open the snapshot index from `ub_snap_root` (existing).
3. Open the dataset index from `ub_main_root` (existing) — populates the dataset table.
4. **NEW**: For each PRESENT dataset, no eager engine open. Each dataset's engine is opened **lazily** on first access (the engine's `open` is lazy — no I/O until first descent).
5. **NEW**: The fs's request router (today goes straight to one of the four pool-global engines) routes by `(dataset_id, kind)` → the dataset's engine. A cached `stm_btree_engine *` is held per dataset in the dataset table entry.

Lazy-open keeps mount cost O(1) in dataset count; eager-open every dataset's engine root would defeat the purpose of N-dataset scaling.

### 3.5 — Per-dataset crypto context

Each dataset's engine is encrypted under that dataset's metadata key. Currently the four pool-global engines share one `stm_btree_crypt_ctx`. Under D1, each engine has its own. The DEK comes from the dataset's key schema slot (TLY-A3 wired the production CORVUS path):

```c
stm_btree_engine_open(
    &STM_ENGINE_STORE_VT, &engine_store_ctx,
    &dataset_crypt_ctx,            /* per-dataset */
    dataset_id,                    /* engine's tree_id (covered by AEAD AD) */
    di_tree_root, di_root_gen, di_root_csum,
    &eng);
```

`tree_id == dataset_id` weaves the dataset id into the engine's AEAD additional-data. A tampered-with on-disk node whose `tree_id` field disagrees with the dataset-table's id fails decrypt — a cross-dataset-substitution attack is closed at the engine layer (already the engine's contract; just now exercised under per-dataset routing).

## 4 — Snapshot-aware COW (impl-2)

### 4.1 — The retention question

In Phase 9.6, `commit_finalize`'s `vt->free` pass hands each superseded paddr back to the bootstrap allocator (deferred-free, `free_gen` = the commit gen). No snapshot owns the superseded node, so it's safe to reclaim — once the next `stm_bootstrap_commit` runs with `committed_gen > free_gen`.

Under 9.7 a snapshot's captured root **reaches** a superseded subtree. Freeing that subtree would dangle the snapshot's reads:

```
  pre-mutation:
    di_tree_root ── root_v1 ── [shared subtree S]
                       │
                       └── leaf_old ── [dirent for "foo"]

  user renames "foo" → "bar":
    di_tree_root ── root_v2 ── [shared subtree S]
                       │
                       └── leaf_new ── [dirent for "bar"]
    (root_v1 superseded; leaf_old superseded)

  snap S0 was created BEFORE the rename:
    snap S0.tree_root → root_v1   ── still reaches leaf_old!

  finalize today: vt->free(leaf_old); vt->free(root_v1);
                  bootstrap_commit: leaf_old reclaimed.
                  S0 reads "foo" → leaf_old → STM_ECORRUPT.
```

`dead_list.tla` is exactly the spec that resolves this:

> *"On `OverwriteBlock(b)`, b is removed from `live_blocks`. If
> the most-recent snapshot exists, b is APPENDED to that snap's
> `snap_dead`. If no snap exists yet, b is freed immediately."*

Under 9.7 the engine's commit-finalize free pass goes **through** the dataset's dead-list. A superseded paddr is appended to the most-recent PRESENT snapshot's `snap_dead`; if no PRESENT snap exists in the dataset's chain, it's freed (the existing path).

### 4.2 — The retention mechanism

The engine's `vt->free` is allocator-agnostic — the engine itself only calls `vt->free(paddr, free_gen)`. The **vtable's** free implementation routes the paddr.

Today's `engine_store.c`'s `vt->free` is:

```c
static stm_status engine_store_free(void *ctx, uint64_t paddr, uint64_t free_gen) {
    stm_engine_store_ctx *esc = ctx;
    return stm_bootstrap_free(esc->bootstrap, paddr, free_gen);
}
```

Under 9.7 it becomes snapshot-aware:

```c
static stm_status engine_store_free(void *ctx, uint64_t paddr, uint64_t free_gen) {
    stm_engine_store_ctx *esc = ctx;
    /* If the dataset has a most-recent PRESENT snapshot, append
     * paddr to its dead-list; the dead-list owns the block until
     * snap-delete partitions it (dead_list.tla::SnapDelete). */
    if (esc->snap_idx && esc->dataset_id > 0) {
        uint64_t most_recent;
        stm_status s = stm_snapshot_index_most_recent_in_dataset(
            esc->snap_idx, esc->dataset_id, &most_recent);
        if (s == STM_OK && most_recent != STM_SNAP_NO_PREV) {
            return stm_snapshot_append_dead_paddr(
                esc->snap_idx, most_recent, paddr);
        }
    }
    /* No PRESENT snap — free immediately. */
    return stm_bootstrap_free(esc->bootstrap, paddr, free_gen);
}
```

The vtable's `ctx` gains a back-reference to the snapshot index + the dataset id this engine serves; `stm_engine_store_ctx` is a per-dataset struct.

### 4.3 — Spec composition

`dead_list.tla::OverwriteBlock` already covers this exactly. The action's pre-state checks for `most_recent_snap` and either appends to the snap's dead-list or frees. We're not changing the spec — we're realising in code the action it already models.

The buggy variant `BuggyOverwriteForgetsDead` (forgets to append + forgets to free → block evaporates) is the failure mode the new vtable code closes; the spec's existing TLC pass against the fixed config is the green light.

### 4.4 — Engine node n_gen as the verify witness

The engine carries each node's birth-gen (24-btree-engine.md §3.9) — `n_gen` per `eng_child`, stored in `bp_reserved2`. A snapshot captures its tree at `extent_txg = sync_gen_at_capture`. A node born **before** the snap (`n_gen ≤ snap.extent_txg`) is reachable from the snap's frozen view; a node born **after** is not.

This is the verify-time witness for the dead-list mechanism: `stm_btree_engine_verify` against a snapshot's captured root walks nodes whose `n_gen ≤ snap.extent_txg`; any node with `n_gen > snap.extent_txg` is an integrity violation (a snap's view can't reach a node born after the snap). Used by send/recv's incremental filter (P7-8 hooked this in for extent.gen; the same shape extends to engine nodes).

## 5 — Snapshot create captures real root (impl-3)

`stm_fs_create_snapshot` today (fs.c:6020) passes `tree_root_paddr=0` because the field doesn't exist on `stm_dataset_entry`. Under 9.7 the dataset entry has the triple; snap-create captures it atomically:

```c
stm_status stm_fs_create_snapshot(stm_fs *fs, uint64_t dataset_id,
                                     const char *name, uint64_t *out_id) {
    /* ... existing dirty-buffer drain (R128 P2-1) ... */

    /* Atomically: commit dataset's engine, capture root triple,
     * insert snap entry, all under one sync_commit boundary. */
    stm_status s = stm_fs_commit(fs);   /* runs the per-dataset cascade */
    if (s != STM_OK) return s;

    /* Post-commit: read the dataset's just-committed root. */
    stm_dataset_entry de;
    s = stm_fs_dataset_lookup(fs, dataset_id, &de);
    if (s != STM_OK) return s;

    /* Insert snap with the captured triple. */
    stm_snapshot_create_params p = {
        .dataset_id      = dataset_id,
        .name            = name,
        .tree_root_paddr = de.di_tree_root,
        .root_gen        = de.di_root_gen,
        .root_csum       = de.di_root_csum,
        .extent_txg      = stm_sync_current_gen(fs->sync),
    };
    return stm_snapshot_create(fs->snap_idx, &p, out_id);
}
```

`stm_snapshot_create`'s signature gains `root_gen` + `root_csum`; the on-disk snap-entry format gains the two fields.

> **As-built note (9.7-impl-3, R159 P3-2).** Two corrections to this
> section as originally drafted:
>
> 1. **Version.** `STM_UB_VERSION` landed at **32** for impl-3, not
>    30. The actual sequence is 29→30 (impl-1c) → 31 (impl-2-routing)
>    → 32 (impl-3). The snap-record fixed prefix grew 52→92 bytes —
>    `root_gen` at offset 52, `root_csum[32]` at offset 60, appended
>    so the v31 offsets 0..52 stay byte-identical.
> 2. **No `STM_SNAP_NO_TREE_ROOT` mount-refusal rule.** The original
>    draft proposed refusing, on mount with `STM_ECORRUPT`, any snap
>    entry whose `tree_root_paddr == STM_SNAP_NO_TREE_ROOT`. That
>    rule was **retired**: `STM_SNAP_NO_TREE_ROOT == 0`, and an
>    *empty dataset*'s `di_tree_root` is also 0, so the rule would
>    reject every legitimate snapshot of an empty dataset. impl-3
>    instead treats the captured triple as **opaque** — the snapshot
>    module stores it faithfully and never interprets it; the real
>    validation (root-node csum match) happens at
>    `stm_btree_engine_open` in the consuming chunks (impl-4
>    rollback / impl-5 readable `.snaps`). An all-zero
>    `(tree_root_paddr, root_gen, root_csum)` triple is the valid
>    "empty dataset" snapshot, mirroring the dataset entry's
>    empty-sentinel (R157 P2-2). A future impl-4/-5 mount path MUST
>    NOT reintroduce the refusal rule.

## 6 — Rollback mechanism (impl-4)

### 6.1 — Today's stub

`stm_fs_rollback_snapshot` (fs.c:6323) currently returns `STM_ENOTSUPPORTED`. The TLY-A5 work shipped the /ctl/ verb + admin gate + corvus-principal mark/unmark + the rollback-compromise consultation gate; the **mechanism** was deliberately stubbed.

### 6.2 — Real mechanism

The mechanism is structurally **swap-then-clean**:

```c
stm_status stm_fs_rollback_snapshot(stm_fs *fs, uint64_t dataset_id,
                                       uint64_t snap_id, bool force) {
    /* (1) Consultation gate (already in place from TLY-A5) */
    /* ... read snap entry, check STM_SNAP_FLAG_ROLLBACK_COMPROMISED ... */

    /* (2) Drain the dataset's dirty buffer (R128 P2-1 carry). */
    s = stm_fs_flush_dataset_locked(fs, dataset_id);
    if (s != STM_OK) return s;

    /* (3) Take fs->global EX (the rollback is a dataset-wide op). */

    /* (4) R9-1 doctrine — bump fs->gen BEFORE the allocator swap.
     *
     *     If the gen bump fails, the old_alloc still holds live
     *     refcounts for the pre-rollback paddrs at gen ≤ G, so the
     *     would-be-rolled-back paddrs don't get reused at the same
     *     gen. v1's stm_snap_rollback carried this doctrine; the
     *     v2 mechanism inherits it verbatim.
     */
    s = stm_sync_bump_gen_for_rollback(fs->sync);
    if (s != STM_OK) return s;   /* clean failure; fs not wedged */

    /* (5) Read the snap's captured triple. */
    stm_snapshot_entry snap;
    s = stm_snapshot_lookup(fs->snap_idx, snap_id, &snap);
    if (s != STM_OK) goto wedge;   /* mid-rollback failure; can't restore */

    /* (6) Swap di_tree_root in the dataset entry. */
    stm_dataset_entry de;
    s = stm_fs_dataset_lookup(fs, dataset_id, &de);
    if (s != STM_OK) goto wedge;

    /* The post-rollback dataset entry's triple = the snap's triple. */
    de.di_tree_root = snap.tree_root_paddr;
    de.di_root_gen  = snap.root_gen;
    memcpy(de.di_root_csum, snap.root_csum, 32);

    s = stm_fs_dataset_update_entry(fs, dataset_id, &de);
    if (s != STM_OK) goto wedge;

    /* (7) Discard the live engine's in-memory tree (the swap means
     *     a different durable root now governs; the in-RAM tree is
     *     out-of-date). The next access re-opens at the new root. */
    stm_btree_engine_destroy(de.engine);
    de.engine = NULL;   /* lazily reopened on next access */

    /* (8) Reclaim post-snap blocks via dead_list.tla::Rollback
     *     (NEW spec extension — §7 below). The blocks reachable from
     *     the OLD live root but NOT from the new live root (== the
     *     snap's root) become free. */
    s = stm_snapshot_rollback_reclaim(fs->snap_idx, fs->sync,
                                       dataset_id, snap_id);
    if (s != STM_OK) goto wedge;

    /* (9) Commit the dataset-table update + the reclaim through the
     *     three-phase cascade. */
    s = stm_fs_commit(fs);
    if (s != STM_OK) goto wedge;

    return STM_OK;

wedge:
    stm_fs_mark_wedged(fs, s);
    return s;
}
```

The R9-1 doctrine carry is **load-bearing**: gen-bump before swap. If the swap fails after the bump, the fs wedges (R154 Q2); if the bump fails before, the rollback is a clean no-op.

### 6.3 — What gets reclaimed

The post-snap blocks fall into two sets:

- **Reachable from old `di_tree_root` but NOT from new `di_tree_root`** (= the snap's root): these are the blocks the snap was COW'd away from. They're freed.
- **Reachable from new `di_tree_root` but NOT from old**: the snap's frozen view. Already on disk; not touched.

The set difference walks the OLD live tree, marking every paddr; then walks the snap tree, un-marking every paddr; what's left marked → free. `dead_list.tla::Rollback` (NEW action in the 9.7-spec extension) models this exactly.

A complication: the OLD live tree's dirty in-memory state was just dropped in step (7). The walk needs to come from the **durable** old root, not the in-memory tree. The pre-rollback durable root is captured at step (5)'s commit boundary — sync.c records the previous-committed `di_tree_root` per dataset on every successful finalize, exactly so this walk can run.

### 6.4 — The rollback-bump nonce invariant

v1's STRATUM.md §7 / §22 invariant `disk ss_gen > fs->gen` post-mount carries verbatim. The bump-then-swap pattern guarantees: every paddr written post-rollback is encrypted under `(paddr, write_gen=fs->gen)` where `fs->gen` is strictly higher than any pre-rollback write. Even though paddrs are reused (the swap surfaces older roots whose paddrs are now live again), the AEAD-nonce pair is fresh.

The pre-rollback paddrs are NOT freed for reuse at the **bumped** gen until the rollback's commit succeeds — the bump locks them at the old gen for refcount purposes. R9-1's exact discipline.

### 6.5 — As-built note (9.7-impl-4)

The §6.2 sketch above predates impl-1..3; the shipped mechanism deviates as follows (the *shape* — swap-then-clean, gen-bump-before-reuse, R154 Q2 wedge — is unchanged):

- **`stm_sync_bump_gen_for_rollback` does not exist.** v2's rollback swaps a metadata pointer (the dataset's engine-root triple); it does **not** roll back the allocator. The diverged blocks are not freed (they leak — see below), so the allocator never reissues a pre-rollback paddr at a stale gen. There is therefore no allocator swap to "bump before". The gen advance that keeps the AEAD nonce fresh is `stm_sync_commit`'s own (auth_gen += 2). R9-1's *intent* (no `(paddr, write_gen)` reuse) holds; its v1 *mechanism* (a standalone disk-gen bump) is subsumed by the commit.
- **The triple swap goes through `stm_dataset_index_set_engine_root`** (a new API), not direct `de.engine` mutation. It also drops the in-RAM engine so the M-cascade does not re-stamp the stale root.
- **Validation is validate-then-swap** (R160 P1-1): the snapshot's triple is verified BEFORE the destructive dirty-buffer drain, via `stm_dataset_index_verify_engine_at` (a new API) — it opens a *throwaway* read-only engine at the triple, `stm_btree_engine_verify`s it, and destroys it, touching no dataset slot. A bad triple refuses `STM_ECORRUPT` as a true no-op (fs not wedged, drain not yet run). An all-zero "empty dataset" triple verifies trivially. The original §6.2 sketch's swap-then-verify ordering was rejected at R160: validating after the drain would silently destroy the caller's un-committed writes (the drain pops them into the engine in-memory tree, which the swap then discards) while still reporting a "clean" refusal.
- **`stm_snapshot_rollback_reclaim` does not exist — block reclamation is deferred to 9.7-impl-4b.** impl-4 ships the swap only. The post-snapshot diverged engine nodes + data extents LEAK (stay allocated, untracked). This is a space cost, never a corruption: a leaked block stays allocated so the allocator never reissues it and the AEAD nonce stays unique. The target snapshot's own dead-lists ARE cleared (`stm_snapshot_clear_dead_lists`, a new API) — mandatory, since post-rollback the live tree IS the snapshot's tree and a dead-listed-but-now-live paddr would let a later `stm_snapshot_delete` free live storage.
- **v1.0 refuses rollback past a newer snapshot** (`STM_ENOTSUPPORTED`). The §7.2 `dead_list.tla::Rollback` action (delete newer snaps + free `newer_dead \ s_view`) needs the diverged-block walk that impl-4b introduces; until then the operator deletes newer snapshots explicitly (the existing `stm_fs_delete_snapshot` reclaims them correctly) and then rolls back. impl-4b lifts this limitation and realises `dead_list.tla::Rollback` in full.

### 6.6 — As-built note (9.7-impl-4b: metadata-node reclamation)

impl-4b ships the first tier of the block reclamation §6.5 deferred — the engine **metadata nodes**. After the swap + dead-list clear, the rollback runs `fs_rollback_reclaim_diverged_nodes` (fs.c):

- A new btree_engine primitive `stm_btree_engine_walk_paddrs` enumerates every on-disk block reachable from a tree's durable root — every NODE and every large-value spill-chain block — under the same Merkle + AEAD descent gate `stm_btree_engine_verify` applies. `stm_dataset_index_collect_engine_paddrs_at` wraps it in the throwaway-engine pattern of `verify_engine_at`.
- The rollback collects the node + spill paddrs of the pre-rollback live tree (`old_set`) and of the snapshot tree (`snap_set`), then bootstrap-frees `old_set \ snap_set` — the post-snapshot metadata-node divergence. This is the boot-tier projection of `dead_list.tla::Rollback`'s live-divergence term `live_blocks \ snap_view_blocks[s]`.
- **Safety**: incremental COW SHARES every unchanged subtree between the two roots; the shared nodes (`old ∩ snap`) ARE the snapshot's tree after the swap, so the `\ snap_set` filter is load-bearing — a block is freed only if it is in `old_set`, NOT in `snap_set`, AND both walks completed in full. Either walk failing ⇒ nothing freed (best-effort: an unreclaimed block leaks — a space cost, never a corruption).
- Correct only because impl-4 already refuses the rollback when a newer snapshot exists: with `s` the most-recent snapshot, every `old \ snap` block was allocated after `s` (COW only writes fresh paddrs), so no older snapshot references it.
- No `STM_UB_VERSION` bump — reclamation frees blocks through the existing bootstrap deferred-free; no on-disk format change.

Still deferred:

- **9.7-impl-4c** — the data-extent (`stm_alloc`) tier of the live divergence.
- **9.7-impl-4c-ii** — the cold-extent (`CAS`) tier of the live divergence (the CAS refcount is per-extent-record, so the reclaim is a counted multiset difference, not a set difference — its own chunk).
- **9.7-impl-4c-iii** — the snapshot's own cleared dead-list garbage (`snap_dead[s] \ s_view` — §7.2 `to_free`'s second term), which `stm_snapshot_clear_dead_lists` currently discards.
- **9.7-impl-4d** — lift the newer-snapshot refusal: delete every snapshot newer than the target and free `newer_dead \ s_view` (the third `to_free` term). This realises `dead_list.tla::Rollback` in full.

### 6.7 — As-built note (9.7-impl-4c: data-extent reclamation)

impl-4c ships the data-extent tier of the §6.6 deferred list — the `stm_alloc`-class **HOT-extent replica blocks**. After the swap + dead-list clear + the impl-4b metadata-node reclaim, the rollback runs `fs_rollback_reclaim_diverged_extents` (fs.c):

- A new dataset-index primitive `stm_dataset_index_scan_engine_range_at` is the third throwaway-engine wrapper (sibling of `verify_engine_at` / `collect_engine_paddrs_at`) — it runs `stm_btree_engine_scan_range` over an inclusive `[lo_key, hi_key]` range. The extent module's `stm_extent_index_collect_engine_data_paddrs_at` calls it with the EXTENT-subspace bounds, decodes each 108-byte value, and emits every HOT extent's replica paddrs (COLD extents decode + validate but contribute no paddr — the CAS tier is impl-4c-ii).
- The rollback collects the data paddrs of the pre-rollback live tree (`old_set`) and of the snapshot tree (`snap_set`), then `stm_alloc_free`s `old_set \ snap_set` — the data-tier projection of `dead_list.tla::Rollback`'s `live_blocks \ snap_view_blocks[s]`.
- **Reflink**: a HOT extent's replica paddr is emitted once per referencing extent. A paddr two reflink-siblings of the OLD tree share is deduped by sorting `old_set` (a double `stm_alloc_free` would corrupt the allocator); a paddr a snapshot-tree extent reflink-shares lands in `snap_set` and the set-difference excludes it. The set-difference handles cohabitation exactly.
- **Safety + best-effort + the newer-snapshot precondition**: identical to §6.6's `fs_rollback_reclaim_diverged_nodes` — a block is freed only if in `old_set`, NOT in `snap_set`, AND both walks completed in full; either walk failing ⇒ nothing freed.
- **Uncommitted-divergence leak window** (shared with impl-4b, not a regression): the reclaim walks the dataset entry's last-COMMITTED `de_old` triple. Post-snapshot writes still in the dirty buffer at rollback time are flushed by the rollback's own R128 P2-3 drain into the engine's in-RAM tree and then discarded by the swap — those just-allocated paddrs are in neither `de_old` nor `snap`, so they leak. A leak, never a corruption; a candidate for a future "discard the dirty buffer instead of draining it" optimization.
- No `STM_UB_VERSION` bump — reclamation frees blocks through the existing `stm_alloc` deferred-free; no on-disk format change.

## 7 — Spec extensions (9.7-spec)

### 7.1 — snapshot.tla rollback mechanism

Today's `Rollback(s)` action (snapshot.tla:352) is **the admission gate only** — it `UNCHANGED`s `live_tree_root`. The 9.7-spec extension makes the action mechanism-real:

```tla
Rollback(s) ==
    /\ s \in SnapIds
    /\ Present(s)
    /\ \E force \in BOOLEAN:
        \* Gate carry from TLY-A5. *)
        /\ \/ BuggyRollbackSkipsConsult
           \/ ~snap_compromised[s]
           \/ force
        /\ did_unsafe_rollback' =
               (did_unsafe_rollback \/ (snap_compromised[s] /\ ~force))

    \* NEW (9.7-spec): MECHANISM. *)
    /\ live_tree_root' = snap_tree_root[s]   \* The swap. *)
    /\ sync_gen' = sync_gen + 1               \* The gen bump. *)
    /\ UNCHANGED <<snap_state, snap_tree_root, snap_created_txg,
                   snap_extent_txg, snap_prev, snap_held,
                   snap_compromised, next_snap_id, current_txg,
                   most_recent_snap>>
```

New invariant `RollbackBumpsGen`: every state reachable via a `Rollback` transition has `sync_gen' > sync_gen`. Combined with the existing `ExtentTxgBoundedBySync`, the post-rollback extent_txg captures the bumped gen — a new snap taken immediately after rollback has a strictly-higher extent_txg.

A new buggy config `snapshot_rollback_skip_gen_bump_buggy.cfg` (`BuggyRollbackSkipsGenBump = TRUE`) drops the `sync_gen + 1` step — TLC trips `RollbackBumpsGen` immediately.

### 7.2 — dead_list.tla rollback action

The block-reclamation side. The existing spec models snap **delete** (per snap, partition into unique-and-freed vs shared-and-merged). Rollback is structurally different: the snap stays present, but the **live** tree's diverged blocks become free.

```tla
\* NEW action (9.7-spec extension).
Rollback(s) ==
    /\ s \in SnapIds
    /\ snap_state[s] = "PRESENT"
    \* The set of blocks COW'd onto live since s was created. *)
    /\ LET diverged_blocks ==
           { b \in BlockIds :
               b \in live_blocks /\ b \notin snap_view_blocks[s] }
       IN
        /\ freed' = freed \cup diverged_blocks
        /\ live_blocks' = snap_view_blocks[s]
        /\ snap_dead' =
            \* All dead-lists ABOVE s in the chain collapse into s's. *)
            [s2 \in SnapIds |->
              IF s2 = s \/ snap_created_txg[s2] <= snap_created_txg[s]
              THEN snap_dead[s2]
              ELSE {}]    \* younger snaps' dead-lists are gone; they were rolled past. *)
        \* All snaps younger than s are NOW deleted. *)
        /\ snap_state' =
            [s2 \in SnapIds |->
              IF snap_created_txg[s2] > snap_created_txg[s]
              THEN "ABSENT"
              ELSE snap_state[s2]]
```

This action lifts `snap_view_blocks[s]` as a model abstraction: the set of blocks reachable from s's frozen view. The MVP spec encodes it as a fixed mapping at SnapCreate; the impl realizes it via `stm_btree_engine_open(snap.root_paddr) + scan`.

A subtlety: **rollback deletes every snap newer than `s`**. ZFS semantics: rolling back to S0 destroys every snap taken after S0; their blocks are not preserved across the rollback (the user explicitly asked to "go back"). The spec models this with the `snap_state` update.

Two new buggy configs:

- `dead_list_rollback_forgets_to_free_buggy.cfg`: rollback doesn't add `diverged_blocks` to `freed` → `BlocksTrackedSomewhere` fires.
- `dead_list_rollback_keeps_newer_snaps_buggy.cfg`: rollback leaves newer-than-s snaps PRESENT → the spec's snap-chain ordering invariant fires (newer snaps' `created_txg > current_txg` after the gen bump).

### 7.3 — Spec verification gate

Both extensions get TLC-verified locally before 9.7-impl-1 starts. TLC tooling is available locally (memory `reference_tlc_tooling.md`):

```
cd v2/specs
"$(brew --prefix openjdk)/bin/java" -cp ~/tla2tools.jar tlc2.TLC \
    -config snapshot.cfg snapshot.tla
"$(brew --prefix openjdk)/bin/java" -cp ~/tla2tools.jar tlc2.TLC \
    -config dead_list.cfg dead_list.tla
```

The fixed configs must stay green; each new buggy config must trip exactly the named invariant.

## 8 — Readable .snaps (impl-5)

ARCH §8.5.4 says a snapshot is browsable as a synthetic read-only directory at `.snaps/<name>/` under the dataset's root. With per-dataset trees + captured snap roots, this becomes mechanical:

- A synthetic dirent at every dataset's root inode: `".snaps"` → an inode kind `STM_INODE_KIND_SNAPSHOT_PARENT` whose readdir enumerates the dataset's chain (every PRESENT snap with `prev_snap_id` walk from `most_recent_snap`).
- Each `.snaps/<name>` is a kind `STM_INODE_KIND_SNAPSHOT_VIEW` whose underlying tree is `stm_btree_engine_open(snap.tree_root_paddr, snap.root_gen, snap.root_csum)`.
- Every read path through the snapshot view goes through a **separate** engine handle from the live engine — they're independent trees, opened at different roots, sharing only the underlying `stm_bdev`.

The `STM_FS_GUARD_WRITE` macro carries: every write op through a snapshot inode returns `STM_EROFS` regardless of fs state. The snapshot views are structurally RO — there's no write path to the engine the snap roots.

Out of scope for impl-5: snapshot-bound 9p attach (a `Tattach` whose `aname` is `dataset@snap`). That's impl-5b or 9.7-readable-fids — needs the fid layer to know how to route to a snapshot view. For impl-5 a snapshot is reachable only through the live mount's `.snaps/` traversal.

## 9 — Clones (impl-6)

ARCH §8.6 / clone.tla: a clone is a fresh dataset whose `origin_snap_id != 0` and whose `di_tree_root` initialises to the **origin snapshot's captured root**:

```c
stm_status stm_fs_create_clone(stm_fs *fs, uint64_t origin_snap_id,
                                 const char *name, uint64_t parent_id,
                                 uint64_t *out_dataset_id) {
    /* Lookup snap; refuse if compromised (TLY-A5 marker doctrine). */
    stm_snapshot_entry snap;
    s = stm_snapshot_lookup(fs->snap_idx, origin_snap_id, &snap);
    if (s != STM_OK) return s;

    /* Create the dataset entry with di_tree_root = snap's root. */
    stm_dataset_entry de = {
        .parent_id        = parent_id,
        .name_len         = ...,
        .origin_snap_id   = origin_snap_id,
        .di_tree_root     = snap.tree_root_paddr,
        .di_root_gen      = snap.root_gen,
    };
    memcpy(de.di_root_csum, snap.root_csum, 32);
    /* ... finish entry; insert via dataset index. */

    /* Bump the snap's clone-ref so SnapDelete refuses
     * (clone.tla::CloneOriginPresent). */
    s = stm_snapshot_hold(fs->snap_idx, origin_snap_id);  /* fold into impl */
    return s;
}
```

The clone's first write COWs from the shared root (the engine's existing COW-on-mutation already implements this — the snap's root reaches every clean subtree; a write COWs along the root-to-leaf path; the snap's leaves remain shared until they're themselves mutated).

**Block lifetime**:

- Pre-clone-write blocks reachable from the origin snap: shared between snap and clone. Lifetime = max(snap, clone).
- Post-clone-write COW'd blocks: in the clone only.
- Snap-delete refused while the clone exists (clone.tla::SnapWithClonesUndeletable; already enforced).

The shared-root mechanism is "for free" — the engine's COW machinery handles it without any clone-specific logic. Clone-specific code is just the dataset entry creation + the snap hold-ref.

**Promote** (ARCH §8.6.2 / clone.tla::Promote): clears `origin_snap_id` to `NO_ORIGIN`. The clone becomes a free-standing dataset; the snap becomes deletable (assuming no other clones). Block lifetimes don't change at promote — the shared blocks are still shared with the snap until snap-delete. Promote is a metadata-only operation.

## 10 — Out of scope (deferred to later)

### 10.1 — Send/recv across snapshots

Phase 7's send/recv used `extent_txg` for incremental filtering across pool-global extents. Under per-dataset trees + per-dataset snap roots, the same filtering works — `snap.extent_txg` is the bound, and the engine's `scan_range` over `[lo_gen, hi_gen]` enumerates only the diverged nodes. This is **forward-noted to a 9.7-fold chunk** rather than 9.7-impl proper; the existing send/recv just needs its key encoder to learn the new type-tagged shape.

### 10.2 — Bε buffer + Bw lock-free (Phase 9.8)

Mission item 4 (lock-free metadata path) and the Bε write-optimisation lay on top of the 9.6 engine; they need 9.7's per-dataset roots in place but don't change the snapshot mechanism. Phase 9.8 is the next chunk past 9.7.

### 10.3 — Per-snapshot dirty-buffer state

The writeback dirty buffer (SWISS-4q-flush) is per-inode + per-dataset. A snapshot taken mid-flush forces a drain (already in place at R128 P2-1). The snapshot's view is the **committed** tree, not the in-flight buffer — preserved across 9.7 by the pre-snap drain.

## 11 — Phase order + audit gates

| Chunk | Output | Audit |
|---|---|---|
| 9.7-design | this doc | (none — design only) |
| 9.7-spec | snapshot.tla + dead_list.tla extensions + TLC green | (none — spec only) |
| 9.7-impl-1 | per-dataset substrate + STM_UB_VERSION 30 | R157 |
| 9.7-impl-2 | snapshot-aware COW free | R158 |
| 9.7-impl-3 | snap-create captures real root | R159 |
| 9.7-impl-4 | rollback mechanism (real) | R160 |
| 9.7-impl-5 | readable .snaps | R161 |
| 9.7-impl-6 | clones | R162 |

Each impl chunk follows the standing discipline: pre-flush, ctest green at the close, R-audit verdict before the next chunk starts. Reference doc (`v2/docs/reference/13-snapshot.md`) updated in the same commit per the Phase 9 reference-doc upkeep policy.

## 12 — Spec-to-code mapping

| Spec | New / changed actions | Impl site |
|---|---|---|
| `snapshot.tla::Rollback` | mechanism: `live_tree_root' = snap_tree_root[s]`, `sync_gen' = sync_gen + 1` | `stm_fs_rollback_snapshot` (impl-4) |
| `snapshot.tla::RollbackBumpsGen` | every Rollback bumps sync_gen | `stm_sync_bump_gen_for_rollback` (impl-4) |
| `dead_list.tla::Rollback` | diverged_blocks → freed; newer snaps → ABSENT | `stm_snapshot_rollback_reclaim` (impl-4) |
| `dead_list.tla::OverwriteBlock` (existing) | append-to-most-recent-snap-dead | `engine_store_free` (impl-2) |
| `snapshot.tla::SnapshotCreate` (existing) | captures `live_tree_root` | `stm_fs_create_snapshot` (impl-3) |
| `clone.tla::CloneCreate` (existing) | di_tree_root = snap.tree_root | `stm_fs_create_clone` (impl-6) |

Every impl call site gets a `/* SPEC: <module>.<action> */` comment matching the table — the SPEC-TO-CODE map carries verbatim through each chunk's commit.

## 13 — Risk + reversal

| Risk | Mitigation |
|---|---|
| Per-dataset tree scaling under N=10,000 datasets | Each clean engine is a O(1) flush; per-dataset open is lazy. Test gate: a 10k-dataset cold-mount benchmark in impl-1. |
| Snap-aware free regression (a freed-instead-of-dead-listed paddr) | dead_list.tla's `BlocksTrackedSomewhere` is the spec witness; a unit test exercises overwrite-with-snap-present, asserts the paddr lands in snap_dead. |
| Rollback fails mid-mechanism → wedged fs | R154 Q2 wedge carry. The R9-1 gen-bump-before-swap means a pre-swap failure is a clean no-op; post-swap failure wedges (correct — half-rolled-back is crash-equivalent). |
| Pre-9.7 pool refused at mount | Documented; pre-release deployments only. No converter; users reformat. |
| Type-tag encoding mistake (a foreign tag byte mis-routes) | `stm_metakey_parse` bounds-checks the tag; foreign byte → STM_ECORRUPT. R71 P1-1 writer-decoder symmetry. |

## 14 — References

- `v2/docs/reference/24-btree-engine.md` — engine API + per-node n_gen
- `v2/docs/reference/13-snapshot.md` — existing snapshot module
- `v2/specs/snapshot.tla` — lifecycle + TLY-A5 admission gate
- `v2/specs/dead_list.tla` — block reclamation on snap-delete
- `v2/specs/clone.tla` — clone-as-shared-root invariants
- `docs/STRATUM.md` §7 (v1) — R9-1 rollback-bump doctrine
- `project_snapshot_substrate_gap.md` (memory) — the gap that named this phase
