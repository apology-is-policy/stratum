# Spec-to-code mapping

The TLA+ specs in `v2/specs/` are the source of truth for protocol-level
invariants. Each spec variable and constant maps onto one or more structures
in the implementation. When the code changes, this mapping is updated in the
same PR; when the mapping is updated, the spec may need to follow.

## Conventions

- **Spec names are canonical.** The code uses names close to the spec.
- **Atomic steps in the spec** need not be atomic in code, but anything
  observable by a concurrent reader MUST happen in an order consistent
  with the spec's step order.
- **Unchanged variables** in a spec step translate to "the code MUST NOT
  write those fields in the corresponding path." Unintentional writes are
  common sources of invariant violations.
- **Crash boundaries** in the spec correspond to fsync points in code.
  Everything before a spec's Crash step must be durable; everything after
  may be lost.

## `sync.tla` ↔ v2 code (Phase 1 scope)

| Spec variable / constant | Code correspondent                                  | Notes |
|--------------------------|-----------------------------------------------------|-------|
| `Paddrs`                 | `uint64_t` offsets on `stm_bdev` (ARCH §4.4)        | No structural difference. |
| `MaxTxg`                 | bounded by `ub_gen` field in uberblock              | Runtime enforces the clamp check from v1 (carries forward to §5.4). |
| `UBSlots`                | `63` per label (ARCH §5.3); 4 labels → 252 slots    | Spec uses `UBSlots = 2` for state space; invariants are size-independent. |
| `txg`                    | `stm_fs::gen` (post-sync), `pool_state::cur_txg`    | Volatile, lives in memory only. |
| `phase`                  | commit coordinator state machine (§3.7.3)           | Implementation uses enum; spec uses string labels. |
| `pending_ub`             | in-RAM root pointer staged for the next Final       | Corresponds to `stm_sync_ctx::next_uberblock`. |
| `ub_ring`                | 63-slot uberblock ring per label, on-disk           | Code has 4 labels × 63 slots; spec collapses to one ring. Quorum lives in `quorum.tla` (Phase 5). |
| `disk[p]`                | bytes at offset `p` on the real block device        | Modelled abstractly as a tuple `(txg, seq, payload)`. |
| `nonces_seen`            | — (history variable only, not materialized in code) | Used to state the nonce uniqueness invariant. |
| `mounted`                | `stm_fs::mounted` flag                              | Runtime guard, ARCH §3.6.4. |
| Phase step `BeginFreeze` | `stm_sync_begin` freezes the writer pipeline        | See `src/sync/sync.c` (Phase 3). |
| Phase step `Reserve`     | `stm_alloc_reserve_txg`                             | Allocator hands out paddrs + seqs. |
| Phase step `DoFlush`     | async writes via `stm_bdev_submit_write` + fsync   | Phase 1 flush happens here. |
| Phase step `DoFinal`     | `stm_ub_write_next_slot` + fsync                    | Commit point. |
| Phase step `DoPublish`   | MVCC root swing + EBR epoch advance                 | §3.6. |
| Invariant `NonceUnique`  | upheld by End A serialization + SIV guard           | ARCH §7.4. |
| Invariant `MountGenBump` | `stm_fs_open` reads ub_ring, sets `gen = max+1`    | Carries forward from v1. |
| Invariant `CommitAtomic` | Final is the sole commit point                      | Phase 2 writes not visible until Phase 3 lands. |

## `nonce.tla` ↔ v2 code (stub, Phase 3)

To be filled in when we spec the full nonce construction + SIV guard.

## `allocator.tla` ↔ v2 code (stub, Phase 3)

To be filled in when we ship the allocator in Phase 3.

## `dcache_ebr.tla` ↔ v2 code (RC arc, spec-first — impl lands at RC-1)

Models the RC-1 EBR-pinned decrypted-extent cache (`docs/rc-design.md` §4).
Written and TLC-verified BEFORE the implementation (the arc is spec-first,
user-voted 2026-07-10); the code column names the RC-1 targets in
`src/sync/sync.c` and is finalized in the RC-1 PR.

| Spec variable / action | Code correspondent (RC-1)                             | Notes |
|------------------------|-------------------------------------------------------|-------|
| `entry[e]` record      | a heap-allocated immutable dcache entry (struct + plaintext buffer) | Fresh allocation per insert; NEVER rewritten in place — the pre-RC fixed `s->dcache[]` slot-rewrite shape is retired (slot reuse under a lock-free reader is the ABA/wrong-key hazard the model designs out). |
| `entry[e].init`        | all entry fields + plaintext fully written             | Must happen-before the bucket link (release store). |
| `entry[e].linked`      | reachable from the `dcache_hash[]` bucket chain        | Link = atomic head publish; unlink keeps the victim's next pointer intact for in-flight walkers (below the model's abstraction; audit obligation). |
| `entry[e].retired`     | passed to `stm_ebr_retire(entry, destructor)`          | The destructor memzeroes the plaintext (secret hygiene) then frees. |
| `entry[e].reclaimed`   | the destructor has run                                 | Only after every covering epoch pin exits. |
| `reader_ref[t]`        | a reader's pointer into the entry, held between the bucket-walk match and the plaintext memcpy | Held only within the reader's `stm_ebr_enter`/`_exit` window (by code structure of the lookup function). |
| `reader_epoch[t]`      | `stm_ebr_thread` pin state (`stm_ebr_enter`/`_exit`)   | The model's atomic ReaderEnter is realized by enter's seq_cst store + trailing seq_cst fence (RC-1 audit F1): the pin is globally visible before the reader's first shared load. |
| `ring` / `AdvanceEpoch`| the EBR retire ring / `stm_ebr_try_advance`            | Advance driven from the retire paths (insert/evict), matching the model's pending-gated advance. |
| `insert_pending`       | the dcache writer mutex (insert/evict/drain serialize) | Readers never take it. |
| `Evict(e)`             | LRU evict on pressure; `dcache_drain` = iterated evict | Drain (evict-dek, close) MUST use the same unlink+retire path — the CF-5a F1 fail-closed contract. |
| Inv `NoUseAfterReclaim`| RC-I1 (rc-design §4): no plaintext freed under a copy  | Buggy cfg `evict_frees_pinned`. |
| Inv `NoTornEntry` / `LinkedImpliesInit` | publish ordering: init-then-link      | Buggy cfg `link_before_init`. |
| Inv `LinkedNeverReclaimed` | unlink-before-retire                               | Buggy cfg `retire_still_linked`. |
| Prop `EventuallyReclaimed` | no permanent entry/buffer leak once unpinned       | Liveness witness (rc-design §6). |

## `dek_guard.tla` ↔ v2 code (RC arc, spec-first — impl LANDED at RC-2)

Models the RC-2 DEK read guard (`docs/rc-design.md` §4, "The DEK guard").
Resolves the scripture's deferred mechanism fork to EBR-published immutable
DEK-map snapshots (COW publish + EBR retire) — the seqlock alternative is
unsound over `sync_dek_grow`'s realloc-moving array (a retrying reader
dereferences freed memory), and COW+EBR reuses the RC-1 idiom.

| Spec variable / action | Code correspondent (RC-2, `src/sync/sync.c`)          | Notes |
|------------------------|-------------------------------------------------------|-------|
| `map_slots[m]`         | `struct sync_dek_map` (count + cap + flexible slots)  | Built full, then published; never mutated after publish. `s->deks`/`dek_count`/`dek_cap` are retired. |
| `published`            | `s->dek_map` (`sync_dek_map *_Atomic`)                | `dek_map_publish_locked` = release exchange; readers acquire-load via `dek_map_load` under an EBR pin (`sync_dek_lookup_copy_pinned`); the pin-publish edge is stm_ebr_enter's trailing seq_cst fence (RC-1 audit F1). |
| `Install(d)`/`Evict(d)`| `sync_dek_insert` / `sync_dek_remove` (reached by add/rotate/sweep/`stm_sync_install_dek`/`stm_sync_evict_dek`) | Admin mutators KEEP `s->lock` among themselves; each builds a copy (insert may consume the `s->dek_staged` pre-allocation — the infallible-insert-after-grow contract), publishes, retires the old map. Remove is newly ENOMEM-fallible (COW copy); evict propagates, the sweep skips (lingering slot scrubbed at close). |
| `map_ring` / `AdvanceEpoch` | `stm_ebr_retire(old, dek_map_destroy)` + `stm_ebr_try_advance` | The destructor memzeroes header+cap slots before free (secret hygiene; satisfies the RC-1 F2 destructor lock contract). Retire-ENOMEM leaks WITHOUT scrubbing (zeroing under a possibly-pinned reader corrupts an in-flight copy — the RC-1 posture). |
| `rd_map[t]`            | `sync_dek_lookup_copy_pinned`'s loaded map pointer     | Valid only within the caller's pin. Under-`s->lock` readers (`sync_dek_find`, borrowed pointer) need no pin: publish requires `s->lock`, so the loaded map cannot be retired. |
| `rd_want`/`rd_slot`/`rd_got` | the walk match + the 32-byte DEK memcpy inside `sync_dek_lookup_copy_pinned` | Find and copy are one pinned window — the guard the model demands. |
| `evicted` (ghost)      | — (history variable)                                   | States the fail-closed contract. |
| Inv `ReaderGetsWanted` | RC-I3 NoTornDEK: matched (dataset,key) never yields other key material | Buggy cfg `inplace_mutate` = the retired swap-with-last (`sync_dek_remove_at`, now deleted — remove builds a fresh ordered copy, so the modeled bug is gone by construction). Runtime witness: `tests/test_rc2_concurrent.c::rc2_dek_rotate_sweep_hammer`. |
| Inv `ReaderMapAlive`   | RC-I3: no reader dereferences a freed map (realloc/free UAF) | Buggy cfg `free_old_map`. The realloc-moving `sync_dek_grow` is retired (grow now stages an unpublished buffer). |
| Inv `PublishedExcludesEvicted` | RC-I3 fail-closed-after-evict (the A-5 post-logout contract; the dcache-plaintext half is RC-1's drain) | Buggy cfg `evict_no_publish`. `stm_sync_evict_dek` → `sync_dek_remove` publishes the without-entry map before returning. |

## `write_key_liveness.tla` ↔ v2 code (RC arc, spec-first — impl LANDED at RC-3)

Models RC-3's one genuinely new synchronization obligation
(`docs/rc-design.md` "RC-3" as-built): the three-phase write's unlocked
Phase 2 makes the resolved CURRENT key prunable mid-op — the sweep's
zero-refs gate cannot see an un-indexed in-flight write. The fix pins the
key with an epilogue re-validation atomic (same `s->lock` hold) with the
index insert, retrying the whole op against the fresh CURRENT.

| Spec variable / action | Code correspondent (RC-3, `src/sync/sync.c`)          | Notes |
|------------------------|-------------------------------------------------------|-------|
| `Resolve(w)`           | `sync_write_reserve_locked` → `sync_resolve_current_dek_locked` (Phase 1, under `s->lock`) | The reservation/nonce mechanics are below the model (prose: PENDING forbids same-gen paddr reuse). |
| `w_key[w] # 0` (the window) | the writer between `sync_write_reserve_locked` and the epilogue lock — `sync_write_encrypt_store` in flight | The unlocked span the model isolates. |
| `Rotate` / `Sweep(k)`  | `stm_sync_rotate_dataset_key` / `stm_sync_keyschema_sweep` (each atomic under `s->lock`) | `Sweep`'s `k \notin indexed` guard = `sync_extent_refs_for_key_locked` == 0. |
| `CommitChecked(w)`     | the epilogue's `stm_keyschema_lookup` (CURRENT-or-RETIRED = alive) + `sync_write_index_commit_locked`, ONE `s->lock` hold | No TOCTOU: the sweep also runs entirely under `s->lock`; a key alive at the check is alive past the insert, and later sweeps count the indexed record. |
| `RetryDeadKey(w)`      | the pruned arm: unlock → `sync_write_reserve_rollback` → the retry loop's next attempt re-resolves | Bounded (4); exhaustion degrades to the fully-locked body (sweep-immune — the RC-2 fallback precedent), so no transient escapes. Model has no bound — `EventuallyAllDone` proves the retry cannot livelock (rotations are finite); the impl's locked fallback guarantees the same termination unconditionally. |
| `CommitBuggy(w)`       | the naive split (no re-validation)                     | Buggy cfg `no_revalidate`: TLC finds Resolve(K1) → Rotate → Sweep(K1) → CommitBuggy at depth 4 — the executable counterexample of the race found at RC-3 design review. |
| Inv `NoDeadKeyIndexed` | every indexed record's `key_id` has a durable keyschema entry | Runtime witnesses: `tests/test_rc3_concurrent.c::rc3_write_key_liveness_retry` (deterministic, the phase-2 hook) + `rc3_writers_vs_rotate_sweep_hammer`. |
| (out of model)         | the evict-dek populate gates                           | Evict does not prune the keyschema → not a `Sweep`; its hazard is dcache-plaintext-past-the-DEK-denial, closed by the populate gates (rc-design RC-3 as-built) + `tests/test_corvus_mount.c::corvus_rc3_{write,read}_evict_window`. |

## Change process

1. Propose the code change.
2. If the change affects spec-modeled behavior, update the spec FIRST.
3. Run TLC on the spec — all invariants must hold.
4. Implement the code change; update this mapping table.
5. CI re-runs TLC; PR must include both spec diff and mapping diff.

Failure to update spec or mapping when touching spec-modeled code blocks PR merge.
