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

## Change process

1. Propose the code change.
2. If the change affects spec-modeled behavior, update the spec FIRST.
3. Run TLC on the spec — all invariants must hold.
4. Implement the code change; update this mapping table.
5. CI re-runs TLC; PR must include both spec diff and mapping diff.

Failure to update spec or mapping when touching spec-modeled code blocks PR merge.
