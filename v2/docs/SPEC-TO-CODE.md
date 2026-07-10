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

## `dek_guard.tla` ↔ v2 code (RC arc, spec-first — impl lands at RC-2)

Models the RC-2 DEK read guard (`docs/rc-design.md` §4, "The DEK guard").
Resolves the scripture's deferred mechanism fork to EBR-published immutable
DEK-map snapshots (COW publish + EBR retire) — the seqlock alternative is
unsound over `sync_dek_grow`'s realloc-moving array (a retrying reader
dereferences freed memory), and COW+EBR reuses the RC-1 idiom.

| Spec variable / action | Code correspondent (RC-2)                             | Notes |
|------------------------|-------------------------------------------------------|-------|
| `map_slots[m]`         | an immutable heap DEK-map array (replaces mutable `s->deks`) | Built full, then published; never mutated after publish. |
| `published`            | an atomic pointer to the current map                   | Readers acquire-load it under an EBR pin. |
| `Install(d)`/`Evict(d)`| `stm_sync_install_dek` / `stm_sync_evict_dek` / rotate | Admin mutators KEEP `s->lock` among themselves; each builds a copy, publishes, retires the old map. |
| `map_ring` / `AdvanceEpoch` | `stm_ebr_retire(old_map, destructor)`             | The destructor memzeroes all key material before free (secret hygiene; below the model's abstraction — audit obligation). |
| `rd_map[t]`            | the reader's loaded map pointer                        | Valid only within the pin. |
| `rd_want`/`rd_slot`/`rd_got` | `sync_dek_find`'s match + the 32-byte DEK memcpy | Find and copy are separate steps — the window the guard closes. |
| `evicted` (ghost)      | — (history variable)                                   | States the fail-closed contract. |
| Inv `ReaderGetsWanted` | RC-I3 NoTornDEK: matched (dataset,key) never yields other key material | Buggy cfg `inplace_mutate` = today's swap-with-last (`sync_dek_remove_at`) minus `s->lock`. |
| Inv `ReaderMapAlive`   | RC-I3: no reader dereferences a freed map (realloc/free UAF) | Buggy cfg `free_old_map`. |
| Inv `PublishedExcludesEvicted` | RC-I3 fail-closed-after-evict (the A-5 post-logout contract; the dcache-plaintext half is RC-1's drain) | Buggy cfg `evict_no_publish`. |

## Change process

1. Propose the code change.
2. If the change affects spec-modeled behavior, update the spec FIRST.
3. Run TLC on the spec — all invariants must hold.
4. Implement the code change; update this mapping table.
5. CI re-runs TLC; PR must include both spec diff and mapping diff.

Failure to update spec or mapping when touching spec-modeled code blocks PR merge.
