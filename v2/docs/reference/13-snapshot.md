# 13 — Snapshot index

## Purpose

Per-pool snapshot registry. Each entry is an immutable reference
to a dataset's tree-root paddr captured at create time, with
back-pointers along a per-dataset chain via `prev_snap_id`. The
snapshot index lives under `ub_snap_root`. ARCHITECTURE §8.5.

The snapshot module is the bridge between:

- **Sync** (constructs the index at sync_create / sync_open;
  hydrates from `ub_snap_root`; persists every commit), and
- **Dataset** (clones reference snapshots; `stm_snapshot_delete`
  consults the dataset module via a callback hook to enforce
  `clone.tla::SnapWithClonesUndeletable`).

In-RAM storage is a linear array of `snapshot_slot` (slots are
append-only; Delete marks ABSENT). On-disk: a btree_store-encoded,
AEAD-encrypted Bε-tree under `ub_snap_root`, keyed by le64
snapshot_id.

## Public API

### Lifecycle

```c
stm_status stm_snapshot_index_create (uint64_t current_txg, stm_snapshot_index **out);
void       stm_snapshot_index_close  (stm_snapshot_index *idx);
stm_status stm_snapshot_index_advance_txg (idx, new_txg);
stm_status stm_snapshot_index_current_txg (idx, *out_txg);
```

`_create` returns an empty index with `next_id = 1`, `current_txg`
seeded from caller. Marked dirty so the first commit will persist
even if no snapshots have been created (the empty btree is still
written so `ub_snap_root` becomes non-zero).

### Mutation

```c
stm_status stm_snapshot_create   (idx, dataset_id, name,
                                  tree_root_paddr, root_gen, root_csum,
                                  extent_txg, *out_id);
stm_status stm_snapshot_delete   (idx, snapshot_id,
                                  **out_freed_paddrs, *out_freed_count,
                                  **out_freed_cold_hashes, *out_freed_cold_count,
                                  **out_freed_boot_paddrs, *out_freed_boot_count);
stm_status stm_snapshot_hold     (idx, snapshot_id);
stm_status stm_snapshot_release  (idx, snapshot_id);
stm_status stm_snapshot_mark_compromised   (idx, snapshot_id);   /* TLY-A5 */
stm_status stm_snapshot_unmark_compromised (idx, snapshot_id);   /* TLY-A5 */
```

All run under an internal `PTHREAD_MUTEX_ERRORCHECK` mutex. Same
`must_lock` / `must_unlock` discipline as the dataset module.

`Create` auto-bumps `current_txg`, so each snapshot's
`created_txg` equals (post-bump) `current_txg`. `prev_snap_id` is
auto-stamped to the most-recent PRESENT snapshot of the same
`dataset_id` (or `STM_SNAP_NO_PREV = 0` if first).

`Create` also captures the dataset's per-dataset `btree_engine`
root as the `(tree_root_paddr, root_gen, root_csum)` triple
(9.7-impl-3). The fs-level wrapper `stm_fs_create_snapshot` reads
the triple from the dataset entry's `(di_tree_root, di_root_gen,
di_root_csum)` *after* a `stm_sync_commit`, so the captured root
is durable and reflects every write up to the snapshot point
(a failed commit wedges the fs — R154 Q2). The snapshot module
stores the triple opaquely — it is never interpreted here;
`stm_btree_engine_open` validates it at the consuming chunks
(9.7-impl-4 rollback / 9.7-impl-5 readable `.snaps`). `root_csum`
may be passed NULL (⇒ all-zero); an all-zero triple is the "empty
dataset" snapshot.

`extent_txg` (P7-8) is a caller-supplied value that the impl
captures verbatim into the entry. Production callers (sync-aware)
pass `stm_sync_current_gen(s)`; this is the value the next extent
write will stamp into `extent.gen`. Send/recv's incremental gen
filter then sits in the same counter space as `extent.gen`. Test/
bench callers without a sync handle may pass `0` — that disables
snap-bounded send for those snaps but leaves all other lifecycle
behavior unchanged. See `snapshot.tla::ExtentTxgBoundedBySync`
and `ChainExtentTxgOrdered` for the spec-level invariants.

`Delete` refuses with `STM_EBUSY` if `hold_count > 0` or if a
registered clone-check cb returns true (`clone.tla::SnapWith-
ClonesUndeletable`). On success BOTH dead-lists transfer to the
caller:

- `*out_freed_paddrs` + `*out_freed_count` — the paddr-tier dead-
  list. Caller owns the malloc'd array (`free()` it) and MUST
  reclaim every paddr through `stm_alloc_free` against the
  matching device's allocator. Use `stm_paddr_device(paddr)` to
  route.
- `*out_freed_cold_hashes` + `*out_freed_cold_count` (P7-CAS-4c)
  — the cold-tier dead-list, a flat byte buffer of N×32 bytes.
  Caller owns the buffer (`free()` it) and MUST iterate it in
  32-byte strides calling `stm_cas_deref(cas, hash)` per entry
  to release the CAS refcount. Composes the cold-tier mirror of
  the paddr-tier free path.
- `*out_freed_boot_paddrs` + `*out_freed_boot_count` (9.7-impl-2)
  — the bootstrap-tier dead-list of superseded engine NODE
  paddrs. Caller owns the malloc'd array (`free()` it) and MUST
  reclaim every paddr through `stm_bootstrap_free` — **not**
  `stm_alloc_free` (a distinct allocator class). The pair may be
  passed NULL/NULL by pre-9.7 callers to disable the output.

A clean-no-overwrites delete returns all three buffer pointers
NULL with their counts 0.

`Hold` / `Release` increment / decrement `hold_count`. Holds
persist across mount (matches ZFS semantics). Release of a
zero-count slot is `STM_EINVAL`.

### Rollback-compromise marker (TLY-A5)

`stm_snapshot_mark_compromised` / `_unmark_compromised` set / clear
bit 0 of the entry's existing `flags` field
(`STM_SNAP_FLAG_ROLLBACK_COMPROMISED`) — **no on-disk format
change**. A marked snapshot is one taken while the dataset's wrap
keys were live and those keys are now suspect; rolling back to it
would resurrect a compromised key chain (the "F13 hazard",
CORVUS-DESIGN §4.5). Both calls are idempotent — marking an
already-marked snap is `STM_OK` and leaves the index clean (dirty
flag set only on a real change). The bit becomes durable at the
next commit; the `/ctl/` admin verbs that drive these
(`mark-snapshot-compromised` / `unmark-snapshot-compromised`)
commit synchronously so it is durable on verb return.

The fs-level surface is `stm_fs_{mark,unmark}_snapshot_compromised`
(fs.h) — thin `fs->global` EX wrappers — and
`stm_fs_rollback_snapshot(fs, snapshot_id, force)`:

- **Consultation gate** (`snapshot.tla::RollbackBlockedIffCompromised`):
  if the target carries `STM_SNAP_FLAG_ROLLBACK_COMPROMISED` AND
  `force` is false, the call refuses with `STM_ECOMPROMISED` (-217)
  *before* the mechanism. The lookup + the flag check run under one
  `fs->global` EX hold, so a racing unmark is never torn.
- **Mechanism (9.7-impl-4)** — validate-then-swap. After the gate:
  (1) refuse `STM_ENOTSUPPORTED` if a newer snapshot of the dataset
  exists (the v1.0 limitation — see below); (2) **validate** the
  snapshot's captured `(di_tree_root, di_root_gen, di_root_csum)`
  triple via `stm_dataset_index_verify_engine_at` — a throwaway engine
  opened at the triple + `stm_btree_engine_verify`; a bad triple
  refuses `STM_ECORRUPT` (a true no-op, fs not wedged), an all-zero
  "empty dataset" triple verifies trivially; (3) drain every dirty
  buffer (`fs_flush_all_locked`) — the FIRST destructive step, so
  every refusal above is a true no-op (R160 P1-1: validating *after*
  the drain would silently destroy the caller's un-committed writes);
  (4) swap the dataset entry's triple to the snapshot's captured
  triple via `stm_dataset_index_set_engine_root` (which drops the live
  in-RAM engine, so the M-cascade skips the closed slot and the
  stamped triple persists); (5) `stm_snapshot_clear_dead_lists` on the
  target — post-rollback the live tree IS the snapshot's tree, so its
  dead-listed paddrs are live again and must not stay dead-listed;
  (6) `stm_sync_commit` (R154 Q2 — wedge on failure).
  The commit's gen advance is the AEAD-nonce bump: every
  post-rollback write lands at a strictly-higher gen, so reused
  snapshot paddrs never collide on `(paddr, write_gen)`. v2's rollback
  does **not** roll back the allocator, so there is no allocator swap
  to "bump before" (the v1 R9-1 doctrine is subsumed by the commit).
- **Metadata-node reclamation (9.7-impl-4b)** — after the swap +
  dead-list clear, the rollback reclaims the post-snapshot
  metadata-node divergence: `fs_rollback_reclaim_diverged_nodes` walks
  the pre-rollback live tree and the snapshot tree
  (`stm_dataset_index_collect_engine_paddrs_at` →
  `stm_btree_engine_walk_paddrs`), set-differences the node + spill
  paddr sets, and bootstrap-frees `old \ snap` — the boot-tier
  projection of `dead_list.tla::Rollback`'s live-divergence term. The
  COW-shared nodes (`old ∩ snap`) ARE the snapshot's tree post-swap
  and are never freed; if either walk fails the reclaim frees nothing
  (best-effort — an unreclaimed block leaks, a space cost, never a
  corruption: it stays allocated so the allocator never reissues it
  and the AEAD `(paddr, write_gen)` nonce stays unique).
- **Data-extent reclamation (9.7-impl-4c)** — the data-tier sibling of
  the above, run in the same pre-commit window:
  `fs_rollback_reclaim_diverged_extents` walks the EXTENT keyspace of
  both trees (`stm_extent_index_collect_engine_data_paddrs_at` →
  `stm_dataset_index_scan_engine_range_at` → `stm_btree_engine_scan_range`,
  decoding each value to its HOT replica paddrs), set-differences the
  data-paddr sets, and `stm_alloc_free`s `old \ snap` — the data-tier
  projection of the same live-divergence term. A paddr a HOT extent
  reflink-shares across the snapshot boundary lands in the snapshot
  set and is excluded; sorting `old` dedups a paddr two reflink-
  siblings of the OLD tree share. Same best-effort + walk-must-complete
  posture as the node reclaim.
- **Cold-extent reclamation (9.7-impl-4c-ii)** — the CAS-tier sibling,
  run in the same pre-commit window: `fs_rollback_reclaim_diverged_cold`
  walks the EXTENT keyspace of both trees
  (`stm_extent_index_collect_engine_cold_records_at`), merges the COLD
  record sets by `(ino, off)`, and `stm_cas_deref`s each old-tree COLD
  record that is NOT the same logical record as a snapshot-tree record
  at the same key. A **per-key structural merge, not a per-hash count
  subtraction** — content-defined dedup lets distinct records share a
  hash, so a count subtraction would cancel a diverged record against
  an unrelated snapshot record and leak its refcount. `link_gen` (the
  gen at which a record entered the live extent index) is the
  load-bearing record-identity discriminator. The derefs feed the
  rollback commit's CAS auto-GC sweep. Same best-effort +
  walk-must-complete posture; this reclaim NEVER over-derefs (a shared
  record always matches its snapshot counterpart, so it is never
  mis-classified as diverged).
- **Cleared dead-list garbage reclamation (9.7-impl-4c-iii)** — the
  final reclaim tier, run AFTER 4b/4c/4c-ii and BEFORE `clear_dead_lists`:
  `fs_rollback_reclaim_cleared_dead_list_garbage` reads S's three
  dead-lists (boot / data / cold) via the new non-destructive getters
  (`stm_snapshot_{bootstrap,_,cold}_dead_list_get`) and reclaims the
  entries S's frozen tree DOES NOT reference (`snap_dead[s] \ s_view` —
  the second `to_free` term of `dead_list.tla::Rollback`).
  - Boot + data tiers: set-difference on paddrs against the snapshot
    tree's node / data-paddr walks. Survivors → `stm_bootstrap_free` /
    `stm_alloc_free` at the sync's current gen.
  - Cold tier: per-key structural merge of OLD vs SNAP COLD records
    (same walks 4c-ii uses) to compute `snap_unique[hash]` (multiset of
    hashes whose snap-tree record at `(ino, off)` is NOT shared with the
    old tree). For each unique hash `H` on the cold dead-list, deref
    count = `dead_S(H) − snap_unique(H)` (clamped at 0). The counted
    subtraction is safe HERE — distinct from 4c-ii's live-divergence
    case — because every `snap_unique` record has a corresponding
    dead-list entry (its drop fired the snap-aware deref routing while
    S was most-recent), so `snap_unique(H) ≤ dead_S(H)` always holds
    per hash. NEVER over-derefs; under-derefs (clamp at 0) become a
    leak, consistent with the best-effort posture.
  - The case-(b) garbage on the dead-list — paddrs / records impl-2's
    COW routing dumped onto S's dead-list under "most-recent snap" but
    which S's tree NEVER referenced — is dispositioned here; the
    case-(a) resurrection entries are KEPT (their paddrs / hashes are
    live in the post-swap tree) and discarded by `clear_dead_lists`
    below without deref. With this tier the rollback realises the
    `to_free` minus the `newer_dead \ s_view` term in full; only the
    newer-snapshot cascade — 9.7-impl-4d — remains.
- **Newer-snapshot CASCADE reclamation (9.7-impl-4d)** — lifts the
  impl-4 `STM_ENOTSUPPORTED` refusal: a rollback past newer snapshots
  of the dataset is now supported and destroys those snapshots (ZFS
  rollback semantics). New API `stm_snapshot_collect_newer(idx,
  dataset_id, target_sid, **out_ids, *out_count)` returns the ascending
  list of PRESENT snap_ids strictly greater than the target. New
  helper `fs_rollback_reclaim_newer_snap_cascade` (fs.c):
  - Pre-validate (R160 P1-1 doctrine): every newer snap is
    `stm_snapshot_lookup`'d BEFORE the destructive drain; if any
    `hold_count > 0`, the rollback refuses `STM_EBUSY` as a true
    no-op.
  - Walks s.view's bootstrap paddrs + data paddrs + cold records +
    OLD-live's cold records ONCE (same APIs the 4b/4c/4c-ii reclaims
    use); computes `snap_unique` (records in s.view whose `(ino, off)`
    has a different identity in OLD-live; identical algorithm to
    4c-iii).
  - Per newer snap: `stm_snapshot_delete` → for each of the three
    dead-list buffers, filter by `\ s_view` (boot/data: set-difference
    on paddrs; cold: accumulated into a single aggregation buffer
    deferred to post-loop).
  - Post-loop cold-tier reclaim: counted subtraction `agg_cold(H) −
    snap_unique(H)` clamped at 0; identical merge-walk to 4c-iii.
    Safety (R165 P3-1 refined): snap_unique[H] partitions into
    case-(1)(H) (drop went to TARGET's cold_dead while target was
    most-recent BEFORE any newer snap existed) + case-(2)(H) (drop
    went to some newer snap's cold_dead). agg_cold[H] sums
    case-(2)(H) + case-(b)(H) (pure post-newer-snap garbage). So
    `agg_cold[H] − snap_unique[H] = case-(b)[H] − case-(1)[H]`,
    clamped at 0 → `deref = max(0, case-(b) − case-(1))`. NEVER
    over-derefs; under-derefs by `min(case-(1), case-(b))` when they
    share a hash via dedup (CAS-refcount leak — space cost, not
    corruption; case-(1) drops were already discharged by 4c-iii's
    `clear_dead_lists`, so the leak persists only until the next
    CAS-refcount scrub).
  - Best-effort per snap: a `stm_snapshot_delete` failure on one
    snap leaves the others reclaimed; the rollback itself still
    succeeds. Walks that fail wholesale skip their tier; leaked
    paddrs / cold refcounts are a space cost, never a corruption.
  - DISJOINT-SET property: `(OLD-live ∖ s.view) ∩ (newer_snap.dead_list)
    = ∅` — a paddr in OLD-live is still-allocated-not-yet-dropped, so
    cannot appear in any newer snap's dead-list. The live-divergence
    4b/4c reclaims and the 4d boot/data cascade therefore operate on
    DISJOINT paddr sets, no double-free risk.
  - With this tier, `dead_list.tla::Rollback`'s
    `to_free = (live ∖ s_view) ∪ (snap_dead[s] ∖ s_view) ∪ (newer_dead ∖ s_view)`
    is realised IN FULL. The v1.0 limitation forward-note retires.
  - Flow within the rollback: drain → swap → 4b → 4c → 4c-ii → 4c-iii
    on target → clear_dead_lists on target → **4d cascade** → commit.
    Every freed paddr / dereffed cold record rides the SAME commit,
    deferred via R50 P2-1's strict `free_gen < committed_gen` predicate
    so AEAD-nonce (paddr, write_gen) uniqueness holds.

### Dead-list (P6-deadlist + P7-CAS-4c cold-tier)

```c
/* Paddr-tier (P6). */
stm_status stm_snapshot_index_overwrite_block       (idx, dataset_id, paddr,
                                                     *out_should_free);
stm_status stm_snapshot_dead_list_count             (idx, snapshot_id, *out_count);

/* Cold-tier (P7-CAS-4c). */
stm_status stm_snapshot_index_overwrite_cold_block  (idx, dataset_id,
                                                     content_hash[32],
                                                     *out_should_deref);
stm_status stm_snapshot_cold_dead_list_count        (idx, snapshot_id, *out_count);

/* Cold-tier capacity pre-check (P7-CAS-4 R54 P3-2). */
stm_status stm_snapshot_index_cold_dead_list_reserve(idx, dataset_id,
                                                     n_to_append, *out_can_accept);

/* Bootstrap-tier (9.7-impl-2-routing). */
stm_status stm_snapshot_index_overwrite_bootstrap_block(idx, dataset_id, paddr,
                                                       *out_should_free);
stm_status stm_snapshot_bootstrap_dead_list_count   (idx, snapshot_id, *out_count);

/* Non-destructive content readers (9.7-impl-4c-iii). */
stm_status stm_snapshot_dead_list_get               (idx, snapshot_id,
                                                     **out_paddrs, *out_count);
stm_status stm_snapshot_bootstrap_dead_list_get     (idx, snapshot_id,
                                                     **out_paddrs, *out_count);
stm_status stm_snapshot_cold_dead_list_get          (idx, snapshot_id,
                                                     **out_hashes, *out_count);

/* Clear all three dead-lists in place — the rollback primitive (9.7-impl-4). */
stm_status stm_snapshot_clear_dead_lists            (idx, snapshot_id);
```

`overwrite_block` realizes `dead_list.tla::OverwriteBlock`. If the
dataset has no PRESENT snapshot, no snap holds the COW'd paddr —
`*out_should_free = true` tells the caller it's safe to free
immediately. Otherwise `paddr` is appended to the dataset's
most-recent snap's dead-list and `*out_should_free = false`.

Refusal codes:

- `STM_EINVAL` for `dataset_id == 0`, `paddr == 0`, or a paddr
  already tracked by some PRESENT snap's dead-list (R33 P2
  defense-in-depth — the alloc layer's live tracking is the
  de-jure prevention; this scan catches caller bugs upstream).
- `STM_ENOSPC` at the in-line cap `STM_SNAP_DEAD_LIST_MAX = 256`.
  Production-grade chunked dead-list is a future revision.
- `STM_ENOMEM` on realloc failure (existing dead-list preserved).

`dead_list_count` is read-only observability; returns the number
of paddrs tracked in `snapshot_id`'s dead-list.

`clear_dead_lists` (9.7-impl-4) frees + zeroes all three dead-lists
(paddr / cold / bootstrap) of a PRESENT snapshot in place; the
snapshot stays PRESENT. The cleared entries are **discarded**, not
transferred to the caller — a dead-list mixes paddrs the snapshot's
tree references (live after a rollback — MUST NOT be freed) with
intermediate COW garbage. The garbage was discharged by
9.7-impl-4c-iii's `fs_rollback_reclaim_cleared_dead_list_garbage`,
which read each dead-list via the `_get` getters BEFORE this clear
fires and freed / dereffed only the entries the snapshot's tree does
not reference (case-(b) garbage). What's left at this point is the
case-(a) resurrection entries — paddrs / hashes that are live again
post-swap — so this clear drops them WITHOUT a deref / free.
The rollback mechanism calls this on the rolled-back-to snapshot:
post-rollback the live tree is the snapshot's tree, so its
dead-listed paddrs are live again and must not stay dead-listed (a
later `stm_snapshot_delete` would otherwise free live storage). The
index is marked dirty only when an entry was actually cleared
(`STM_OK` no-op on an already-clear snapshot).

In `dead_list.tla`'s bounded single-ownership model `surviving =
S.dead ∩ successor.dead = ∅`, so `unique = S.dead`; SnapDelete
frees the entire dead-list and the predecessor-merge step is
empty. The C impl realizes that simplification.

The OverwriteBlock cb has no production callers in this chunk —
it's the API surface that P7's extent COW path will plug into
once the paddr→bptr resolver lands.

**Cold-tier mirror (P7-CAS-4c)**: `overwrite_cold_block` realizes
`dead_list.tla::OverwriteCold`. Mirror semantics — if the dataset
has no PRESENT snapshot, no snap holds the dropped cold extent's
CAS chunk; `*out_should_deref = true` tells the caller to call
`stm_cas_deref(cas, hash)` immediately. Otherwise the hash is
appended to the most-recent snap's cold-dead-list and
`*out_should_deref = false`; the deref obligation is held by the
snap until snap-delete fires it.

Refusal codes for `overwrite_cold_block`:

- `STM_EINVAL` for `dataset_id == 0`, all-zero hash (CAS sentinel,
  never live), or NULL idx / out / hash. **Per R54 P1-1 the
  within-snap dedup-defense scan is GONE** — the cold-dead-list
  is a multiset of hashes (distinct cold extents legitimately
  share a content_hash via dedup, intra-file dedup, FastCDC sub-
  chunking, etc.; a single COW operation can drop multiple cold
  records sharing one hash). dead_list.tla::ColdSingleOwnership is
  at the cold-extent-id level, not the hash level.
- `STM_ECORRUPT` if the most-recent snap slot is in a stale
  state (signals in-RAM index corruption — same shape as the
  paddr-tier API).
- `STM_ENOSPC` at the in-line cap `STM_SNAP_COLD_DEAD_LIST_MAX
  = 256`. Per P7-CAS-4 R54 P3-2 callers MUST pre-check capacity
  via `stm_snapshot_index_cold_dead_list_reserve` BEFORE mutating
  extent_idx; the COW caller (sync.c bookends) does so. Without
  the pre-check, a per-call STM_ENOSPC mid-bookend would silently
  lose the deref obligation and leak the CAS chunk (refcount
  stuck at 1).
- `STM_ENOMEM` on realloc failure (existing cold-dead-list
  preserved).

`cold_dead_list_count` is read-only observability; returns the
number of cold-extent hashes tracked in `snapshot_id`'s cold-dead-
list. Per R54 P3-3, `snapshot_id == 0` (pool sentinel) is rejected
with STM_EINVAL.

`cold_dead_list_reserve` is the P7-CAS-4 R54 P3-2 pre-check used by
the sync.c COW bookends. Returns `*out_can_accept = true` if the
most-recent PRESENT snap of `dataset_id` can absorb `n_to_append`
more entries without overflowing `STM_SNAP_COLD_DEAD_LIST_MAX`, OR
if there is no most-recent PRESENT snap (in which case the bookend
direct-derefs without consuming a list slot). The pre-check uses
saturating-sum arithmetic for defense-in-depth against
SIZE_MAX-shaped `n_to_append`.

Production callers wired in P7-CAS-4c + P7-CAS-4:

- `stm_sync_write_extent_locked` — pre-check via
  `cold_dead_list_reserve`(cox.n_hashes) BEFORE
  `stm_extent_overwrite`; bookend per-hash via
  `overwrite_cold_block`.
- `stm_sync_truncate` past-extent + crossing-extent cold-deref —
  same shape via `tcox.n_hashes`.

Reflink + migrate rollback paths keep direct `stm_cas_deref`
calls — those records were JUST inserted by the failing
operation and have not been captured by any snap yet, so
snap-routing doesn't apply.

P7-CAS-4 R54 P3-1 followed up by removing the dead `else
{ should_deref = true; }` fallback in both bookends — `s->snap_idx`
is unconditionally created at sync_create / sync_open, so the
fallback was unreachable.

### Read-only

```c
stm_status stm_snapshot_lookup            (idx, snapshot_id, *out_entry);
stm_status stm_snapshot_count             (idx, *out_count);
stm_status stm_snapshot_dataset_count     (idx, dataset_id, *out_count);
stm_status stm_snapshot_most_recent       (idx, dataset_id, *out_id);
stm_status stm_snapshot_iter              (idx, cb, ctx);

/* 9.7-impl-4d: enumerate PRESENT snap_ids of `dataset_id` strictly
 * greater than `target_snapshot_id`. Returned ids are sorted
 * ASCENDING; caller frees `*out_snap_ids`. Empty result returns
 * STM_OK with NULL/0. */
stm_status stm_snapshot_collect_newer     (idx, dataset_id,
                                           target_snapshot_id,
                                           **out_snap_ids, *out_count);
```

### Persistence (P6-persist)

```c
stm_status stm_snapshot_index_set_storage    (idx, bdev_0, boot_0);
stm_status stm_snapshot_index_set_crypt_ctx  (idx, key, pool_uuid, dev_uuid_0);
stm_status stm_snapshot_index_load_at        (idx, root_paddr, root_gen, csum);
stm_status stm_snapshot_index_commit         (idx, target_gen, *out_paddr, *out_csum);
stm_status stm_snapshot_index_get_root       (idx, *out_paddr, out_csum);
stm_status stm_snapshot_index_get_gen        (idx, *out_root_gen);
stm_status stm_snapshot_index_verify         (idx);
stm_status stm_snapshot_index_get_next_id    (idx, *out_next_id);
stm_status stm_snapshot_index_set_next_id    (idx, next_id);
```

Same shape + semantics as the dataset module's persistence API.
`load_at` runs the structural validator (`sp_validate_shadow`;
R31 P2-2): rejects zero ids, forward-pointing prev_snap_id,
prev_snap_id pointing at a wrong-dataset slot, sibling-name
collisions within a dataset, and **chain inversion** —
`extent_txg < prev's extent_txg` along the `prev_snap_id` chain
within a dataset (P7-8 added the field; `snapshot.tla::
ChainExtentTxgOrdered` is the corresponding invariant). The
chain-inversion path has a per-process producer-side check at
`stm_snapshot_create` (R40 P2-1) and the on-disk validator path
exercised by `fs_snap_chain_inversion_on_disk_refused_at_mount`
in test_fs (P7-14, closes R40 P3-3); see
`<stratum/snapshot_testing.h>` for the gated `_for_test` seam.

### Clone-dependency hook (P6-clone)

```c
typedef bool (*stm_snapshot_clone_check_cb)(uint64_t snapshot_id, void *ctx);

void stm_snapshot_index_set_clone_check_cb(idx, cb, ctx);
```

When a cb is registered, `stm_snapshot_delete` invokes
`cb(snapshot_id, ctx)` while holding `idx->lock`. If cb returns
true, delete refuses with `STM_EBUSY`. Without a cb (default),
delete uses today's hold-count-only semantics.

Lock-order contract: cb runs with `idx->lock` held (snap_idx
outer). cb MAY take other locks (e.g., dataset_idx) but MUST NOT
re-enter `stm_snapshot_*` (deadlock — ERRORCHECK aborts).

Sync.c registers a default cb at sync_create + sync_open that
queries `stm_dataset_clones_count_for_snap` to enforce
`clone.tla::SnapWithClonesUndeletable` through-stack. The cb is
explicitly un-registered in `stm_sync_close` BEFORE the dataset
index is freed (R32 P2-1 defensive hygiene).

The fs-layer wrappers that drive the cb live in `12-dataset.md`'s
"fs-level clone wrappers (9.7-impl-6e)" section:
`stm_fs_create_clone` takes the snap-hold + stamps the snap's
captured triple into the clone; `stm_fs_delete_snapshot` is the
sync.c-cb's gate (refuses STM_EBUSY when clones exist);
`stm_fs_rollback_snapshot`'s cascade pre-validate (§9.1.6) also
refuses STM_EBUSY when a newer snap of the target dataset has any
clone. Snap-of-clone is refused STM_ENOTSUPPORTED at the
`stm_fs_create_snapshot` entry BEFORE any destructive step
(R160 P1-1). Integration tests for the full surface live in
`tests/test_fs_clone.c` (9.7-impl-6f) — eight cases covering
create / share-root reads / COW divergence / arg validation /
all three refusals / promote stub.

The sync.c-internal `sync_clone_check_cb` is fail-CLOSED on
count-lookup error (refuses delete by returning true). A
historical design note in the 9.7-impl-6 series suggested fs.c
might install this cb at mount, but as of 9.7-impl-6e the
sync.c wiring is authoritative; fs.c does NOT install a sibling
cb (would race + override sync.c's fail-CLOSED with a less-safe
posture).

## On-disk encoding (v14+)

### Key

8 bytes le64 snapshot_id (always ≥ 1; `STM_SNAP_NO_PREV = 0` is the
sentinel for "first in chain", never used as a key).

### Value (variable length)

```
off                 size   field
  0                    8   dataset_id        (le64; ≠ 0)
  8                    8   tree_root_paddr   (le64; engine root paddr — 0 = empty dataset)
 16                    8   created_txg       (le64; ≤ idx->current_txg)
 24                    8   extent_txg        (le64; ≤ sync.current_gen at Create — P7-8)
 32                    8   prev_snap_id      (le64; STM_SNAP_NO_PREV for chain head)
 40                    4   hold_count        (le32; persists across mount)
 44                    4   flags             (le32)
 48                    2   name_len          (le16; 1..STM_SNAP_NAME_MAX)
 50                    2   pad               (zero)
 52                    8   root_gen          (le64; engine root birth-gen — 9.7-impl-3 v32)
 60                   32   root_csum         (uint8_t[32]; BLAKE3 of root node ct — v32)
 92                    L   name              (UTF-8, no NUL)
 92+L                  4   dead_count        (le32; 0..STM_SNAP_DEAD_LIST_MAX)
 96+L                8*N   dead_paddrs       (le64[N])  N = dead_count
 96+L+8N               4   cold_dead_count   (le32; 0..STM_SNAP_COLD_DEAD_LIST_MAX) — P7-CAS-4c v19
100+L+8N            32*M   cold_dead_hashes   (uint8_t[M][32])  M = cold_dead_count
100+L+8N+32M           4   boot_dead_count   (le32; 0..STM_SNAP_BOOTSTRAP_DEAD_LIST_MAX) — 9.7-impl-2 v31
104+L+8N+32M         8*K   boot_dead_paddrs  (le64[K])  K = boot_dead_count — engine NODE paddrs
```

Total: `96 + name_len + 8*N + 4 + 32*M + 4 + 8*K` bytes.
`SP_VAL_FIXED == 92`; `SP_DEAD_TAIL_FIXED == 4`;
`SP_COLD_TAIL_FIXED == 4`; `SP_COLD_HASH_BYTES == 32`;
`SP_BOOT_TAIL_FIXED == 4`; `SP_BOOT_PADDR_BYTES == 8`.

The `(tree_root_paddr@8, root_gen@52, root_csum@60)` triple is the
snapshot's captured per-dataset `btree_engine` root — a verbatim
copy of the dataset entry's `(di_tree_root, di_root_gen,
di_root_csum)` at Create time (9.7-impl-3). The snapshot module
treats the triple as opaque metadata: it is faithfully stored and
round-tripped, never interpreted. The real validation (root-node
csum match) happens at `stm_btree_engine_open` in the consuming
chunks (9.7-impl-4 rollback / 9.7-impl-5 readable `.snaps`). An
all-zero triple is the "empty dataset" snapshot.

Each STM_UB_VERSION bump that touches this layout is a HARD format
break: v13→v14 added extent_txg + dead-list tail; v18→v19
(P7-CAS-4c) appended the cold-dead tail; v30→v31 (9.7-impl-2)
appended the bootstrap-dead tail; v31→v32 (9.7-impl-3) grew the
fixed prefix 52→92 for root_gen + root_csum. A pool of the wrong
version is refused at mount via uniform STM_EBADVERSION (uberblock.c
version gate) before the snap decoder runs; the decoder's own
length checks are defense-in-depth against gross encoding drift.

### Crypt + Merkle

Same envelope as the dataset tree: AEGIS-256 under `metadata_key`,
nonce `paddr || gen || pool_uuid`, AD `pool_uuid || device_uuid_0`.
Merkle chain via BLAKE3 over node ciphertext, rooted at
`ub_snap_root.bp_csum` and folded into `ub_merkle_root`.

The snapshot tree's root carries `bp_kind = STM_BPTR_KIND_SNAP`
(value 5; reserved long before the C impl landed). The dataset
tree uses `STM_BPTR_KIND_DATASET = 9` (added in P6-clone).

## Spec cross-reference

| Spec | Pins |
|---|---|
| `snapshot.tla` | `SnapIdMonotonic` — ids only grow; never recycled. `BirthTxgMonotonic` — `created_txg ≤ current_txg`. `HoldPreventsDelete` — `hold_count > 0` blocks delete. `TreeRootImmutable` — once captured, the snap's `tree_root_paddr` cannot change. `ChainTxgOrdered` — along prev_snap_id chain (filtering ABSENT links), `created_txg` strictly decreases. `ChainAcyclic` — bounded walk along prev_snap_id never returns to the start. **`ExtentTxgBoundedBySync` (P7-8)** — every snap's captured `extent_txg ≤ sync_gen`. **`ChainExtentTxgOrdered` (P7-8)** — along prev_snap_id chain, `extent_txg` is non-decreasing (older has ≤ newer). Buggy demos: `snapshot_chain_disorder_buggy.cfg` (BuggyChainOutOfOrder), `snapshot_delete_held_buggy.cfg` (BuggyDeleteWithHold), `snapshot_extent_txg_unbounded_buggy.cfg` (BuggyExtentTxgUnbounded — P7-8 new). |
| `clone.tla` | `SnapWithClonesUndeletable` — operationally enforced via the cb hook. Snap deletion refused while any present clone references the snap. |
| `dead_list.tla` | `BlocksTrackedSomewhere` — every block ever written is in the live set, freed, or in some PRESENT snap's dead-list (the load-bearing "blocks aren't lost"). `NoDoubleFree` — a freed block never re-appears in any dead-list. `LiveDisjointFromDead/Freed`, `FreedDisjointFromDead`, `SnapIdMonotonic`. `OverwriteBlock` — COW into most_recent_snap.dead, or free directly if no snap exists. `SnapDelete` with `unique = S.dead − succ.dead → freed`; `surviving = S.dead ∩ succ.dead → migrate to pred.dead` (empty in single-ownership). |

## Implementation notes

- **prev_snap_id at Create**: walks slots[] for the most-recent
  PRESENT slot with matching `dataset_id`, captures its id. If
  none, sets to `STM_SNAP_NO_PREV`. (R29 P2-1: a documented
  divergence from `snapshot.tla` which keeps `most_recent_snap`
  past Delete; impl computes dynamically and skips ABSENT — both
  shapes preserve `ChainTxgOrdered`.)
- **Shadow swap on load**: `load_at` builds shadow `snapshot_slot[]`,
  validates structurally, atomic swaps. Failures leave the live
  index untouched.
- **txg sync at load (R31 P2-1)**: `current_txg` is bumped to
  `max(loaded created_txg)` to preserve `BirthTxgMonotonic` for
  post-mount Create.
- **ERRORCHECK mutex + must_lock helpers**: an iter callback that
  re-enters a snap_idx public API hits EDEADLK; `must_lock` aborts
  on non-zero return rather than silently corrupting state (R29
  self-audit P1).
- **clone-check cb invocation**: under `idx->lock`. cb may query
  external state (e.g., dataset module) with its own locks. Lock
  order: snap_idx outer, dataset_idx inner.
- **Dead-list memory ownership**: per-slot `dead_list` is a
  malloc'd `uint64_t[]`. Owned by the slot until either
  `stm_snapshot_delete` (transfers to the caller),
  `stm_snapshot_clear_dead_lists` (frees in place; slot stays
  PRESENT — the rollback path), `stm_snapshot_index_close` (frees),
  or `stm_snapshot_index_load_at` (frees old slots' lists pre-swap).
  `sp_validate_shadow` adds a paddr-disjoint check enforcing
  single-ownership.
- **Dead-list at append time**: `overwrite_block` rejects a paddr
  already tracked anywhere in the index (R33 P2). The alloc layer's
  live-tracking is the structural prevention; this is a
  defense-in-depth catch.

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_snapshot` | 58 | Lifecycle (create / delete / hold / release w/ all error paths); concurrent stress on per-dataset + same-dataset chains; SnapIdMonotonic / BirthTxgMonotonic / HoldPreventsDelete / TreeRootImmutable / ChainTxgOrdered / ChainAcyclic; persist roundtrip including persisted holds + ABSENT slots; idempotent commit; tamper detection (csum/key); next_id + current_txg seeding from on-disk + UB; **dead-list lifecycle** (overwrite no-snap → caller frees; overwrite with-snap → appended to most-recent; cross-dataset isolation; cap at STM_SNAP_DEAD_LIST_MAX → ENOSPC; duplicate paddr → EINVAL (R33 P2); arg validation; delete returns the dead-list and clears the slot; refused delete keeps the dead-list intact; persist roundtrip with non-empty dead-list; idempotent commit byte-identicality with dead-list); **bootstrap-tier dead-list** (9.7-impl-2 — overwrite/count/cap/dup/cross-tier APIs); **9.7-impl-3 tree-root triple** (`snap_create_captures_root_triple` — verbatim capture + NULL-csum⇒zero; `snapshot_persist_tree_root_triple_roundtrip` — triple survives v32 encode/decode); **9.7-impl-4 clear-dead-lists** (`snap_clear_dead_lists_empties_all_three` — paddr/cold/boot lists emptied, snap stays PRESENT, idempotent; `snap_clear_dead_lists_arg_validation`). |
| `test_sync` | included | Snap-delete cb integration covered through dataset persistence + clone tests (sync_snap_delete_refused_with_clone, sync_clone_state_survives_mount). |

## Status

- [x] Create / Delete / Hold / Release.
- [x] Per-dataset chain via prev_snap_id.
- [x] Hold count persists across mount.
- [x] Persistent storage (P6-persist).
- [x] Clone-check cb hook (P6-clone).
- [x] R31 atomic shadow-swap on load + structural validator.
- [x] Idempotent commit.
- [x] STM_BPTR_KIND_SNAP (=5) on `ub_snap_root`.
- [x] Block-level dead-list tracking (P6-deadlist; ROADMAP §9.2
      criterion 2). `Delete` is now O(dead_count) — the caller
      reclaims via `stm_alloc_free` per returned paddr. Chunked
      off-tree storage for very-large dead-lists is a future
      revision; in-line cap STM_SNAP_DEAD_LIST_MAX = 256.
- [ ] Production callers of `overwrite_block` (extent COW path) —
      lands with P7's paddr→bptr resolver.
- [x] Rollback-compromise marker (TLY-A5) — `STM_SNAP_FLAG_ROLLBACK_COMPROMISED`
      + `stm_snapshot_{mark,unmark}_compromised` + the fs-level
      consultation gate in `stm_fs_rollback_snapshot`.
- [x] Snapshot rollback (ARCH §8.10) — the `/ctl/` verb surface, the
      consultation gate, and `STM_ECOMPROMISED` shipped at
      TLY-A5-impl-2; the **swap mechanism** (per-dataset engine-root
      swap + validate + dead-list clear + commit) shipped at
      9.7-impl-4. Block reclamation of the post-snapshot divergence
      shipped at 9.7-impl-4b/4c/4c-ii/4c-iii (all three tiers).
      Rollback past newer snapshots shipped at 9.7-impl-4d (the
      newer-snapshot cascade). With 4d, the rollback realises
      `dead_list.tla::Rollback`'s `to_free` IN FULL.
- [x] Readable `.snaps/<name>/` mount surface (ARCH §8.5.4) — 9.7-impl-5.
      `.snaps` is a synthetic dir at every dataset's root (LOOKUP
      reachable; INVISIBLE in readdir of root at v1.0). Synthetic
      ino encoding (bit 63 = tag; bits 62..32 = snap_id; bits 31..0 =
      frozen_ino) routes reads through a throwaway-engine pattern
      against the snapshot's captured triple. Every write op
      refuses STM_EROFS via a synth-ino gate at the public entry.
      Scope: namespace + lookup + stat + readdir + readlink + INLINE
      file read. EXTENT (regular-file > 100B) read shipped at
      **9.7-impl-5b** via `stm_extent_index_lookup_at_root` (sibling
      of the impl-5 throwaway-engine primitives) + a shared
      `sync_decrypt_extent_record_locked` helper (the AEAD-decrypt
      body factored out of `stm_sync_read_extent_locked`) + a
      public `stm_sync_read_extent_at_snap`. HOT + COLD decrypt
      paths both work; size-clamp at fs.c masks block-padding past
      EOF.
- [ ] Snapshot send/recv via birth-txg incremental diffs — Phase 7.

## Known caveats

- **Single-leaf cap**: ~430 snapshot entries fit per 128-KiB leaf
  at ~300 byte average. Pools with many active snapshots need the
  multi-level extension.
- **Dead-list cap**: `STM_SNAP_DEAD_LIST_MAX = 256` paddrs per
  snap (in-line tail). Any snapshot whose lifetime spans more than
  256 COW events on its dataset hits STM_ENOSPC at append time.
  Real-world snapshots that sit for hours over busy datasets need
  chunked off-tree dead-list storage — deferred to a follow-on
  revision.
- **No production COW caller yet**: `stm_snapshot_index_overwrite_block`
  is API-complete and tested; the dataset-tree extent COW path
  that drives it lands with P7's paddr→bptr resolver. Until then,
  delete returns an empty dead-list (just clears the slot).
- **Most-recent skipping ABSENT (R29 P2-1)**: a Create after a
  Delete-of-most-recent links to the next-older PRESENT snap, not
  the just-deleted one. Spec models the historical chain
  including ABSENT links; impl prefers the cleaner present-only
  chain. Both satisfy `ChainTxgOrdered`.
- **R31 P1-1 contract**: same as dataset — no concurrent mutation
  during sync_commit / between EQUORUM retries. Documented in
  `stm_sync_snapshot_index` docstring.
