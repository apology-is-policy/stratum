# Phase 4 — status and pickup guide

Authoritative pickup guide for Phase 4 (integrity + crypto). Last
update 2026-04-21 (after P4-1 — Merkle scaffold — landed).
Companion to `phase3-status.md`, which documents the persistence
layer Phase 4 builds on.

## TL;DR

Phase 4 = ARCH §7 "Cryptography and integrity". Merkle integrity
and encryption unify at the AEAD level — AEAD tags ARE integrity on
encrypted blocks. For MVP we land Merkle first (unencrypted metadata
integrity), then encryption (AEAD data extents + AEAD metadata nodes
+ per-dataset keys).

| Commit | What | Tests |
|---|---|---|
| `54b3c8b` | **P4-1: Merkle integrity scaffold**. Wires existing per-node BLAKE3 self-csums into a chain: internal-node bp_csum fields carry child csums; allocator-tree root csum propagates into `ub_alloc_root.bp_csum`; `ub_merkle_root = BLAKE3(main_csum(0) ‖ alloc_csum ‖ snap_csum(0) ‖ cas_csum(0) ‖ salt)` per ARCH §7.11.3. Per-pool salt generated at format time from `/dev/urandom`, stored in new `ub_merkle_root_salt[32]` field (STM_UB_VERSION bumped 1→2). Mount verifies recomputed Merkle root against stored value AND verifies tree-root node self-csum against `bp_csum`. Tamper detection confirmed by `sync_tamper_tree_node_surfaces_on_mount`. | 3 new sync tests; 20 suites green |

## Remaining Phase 4 work

Rough ordering, subject to revision as dependencies clarify:

### P4-2: Read-path Merkle on ALL paddr-keyed lookups

Not strictly needed for Phase 4 exit (P4-1 verifies on mount; per-read
verification is what ARCH §7.13.2 calls the "default" mode). Currently
only the root + immediate children are checked. A future chunk can
wire per-read verification as blocks are fetched — but since Phase 3's
stm_alloc_lookup doesn't load fresh blocks per call, the urgency is
low. Revisit after crypto lands.

### P4-3: AEAD on metadata nodes (stm_btnode)

Node encode flow becomes: serialize → AEAD-encrypt → write. Decode:
read → AEAD-decrypt (tag = BLAKE3 of pre-encrypt bytes) → validate.

Blocker: key hierarchy is not yet in place. Either:
- Land a placeholder per-pool metadata key first (all metadata
  encrypted under one key), then refine in P4-4 with per-dataset keys;
  or
- Land key hierarchy (P4-4) first and then add encryption at the
  write path once keys exist.

### P4-4: Per-dataset key hierarchy + PQ-hybrid wrap

Per ARCH §7.3. Each dataset has its own AEAD key, derived from a
wrap-key stored in `ub_key_schema[512]`. Wrap key is ML-KEM-768 +
X25519 hybrid (stm_hybrid from Phase 1). Requires:
- Dataset concept (doesn't exist yet in v2 — only a single flat pool).
  Can land a "dummy dataset 0" first.
- Key agent process (stratum-keyagent) for wrap/unwrap.
- 9P protocol between daemon and agent (ARCH §7.9).

### P4-5: AEAD on data extents

Write path: compress → BLAKE3(plaintext) → AEAD-encrypt with
(paddr, write_gen) as nonce + pool/dataset/ino/offset as AD.
Read path: reverse. Tag binding ensures cross-context confusion
fails.

Requires extent manager (doesn't exist yet — Phase 6?). May slip to
a later phase if extent layer depends on Phase 6 dataset model.

### P4-6: merkle.tla

Formal spec of hash propagation under COW. Proves that
`ub_merkle_root` in any committed UB transitively covers every
reachable metadata block. Sequenced with the actual Merkle work
landing in P4-1..P4-3.

### P4-7: R8 full-stack audit

After P4-3 (AEAD on metadata) or P4-5 (AEAD on data) lands, spawn an
R8 audit covering:
- Nonce uniqueness across all new write paths.
- AD binding (no cross-context tag acceptance).
- Merkle chain covers every metadata block reachable from any UB.
- Key-agent side-channel resistance (if P4-4 is in).
- Mount-time + on-read + scrub verify paths.

## Build + verify commands

```bash
cd v2

# Default build + all 20 suites
cmake -B build -S . -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure

# TSan (crash_inject suite takes ~40 s under TSan)
cmake -B build-tsan -S . -DSTM_SANITIZE=tsan \
    -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build-tsan -j
ctest --test-dir build-tsan --output-on-failure

# ASan
cmake -B build-asan -S . -DSTM_SANITIZE=asan \
    -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Trip hazards carrying into Phase 4

From Phase 3's load-bearing invariants + new P4-specific ones:

- **Nonce uniqueness** (AEAD): every `(paddr, write_gen)` pair unique
  across the pool's lifetime. stm_sync's `current_gen = durable_gen + 1`
  at mount enforces `current_gen > any_durable_gen`, so a write at
  gen G is unique from any prior write at gen G' < G.
- **AEAD-AD binding**: every AEAD call must include paddr in AD so
  replaying ciphertext at a different paddr is rejected. Also include
  dataset_id (once datasets exist).
- **Merkle chain under COW**: every metadata write produces a new
  paddr with a new self-csum, which propagates into parent bp_csum
  in the same commit. The per-commit fsync barrier ensures the whole
  chain becomes durable atomically. Don't introduce any path that
  writes a metadata block without updating its parent bptr.
- **`ub_merkle_root_salt` is permanent**: stored in the UB, never
  rotated. Regenerating it would invalidate all existing Merkle
  roots. Treat as format-time-only.
- **Format-stability lock**: any new on-disk field goes in reserved
  regions (`ub_reserved`, `ub_key_schema`, `ub_roster`, etc.). Field
  layout changes require STM_UB_VERSION bumps.

## References

1. `v2/docs/phase4-status.md` — this file.
2. `v2/docs/phase3-status.md` — persistence / exit context.
3. `docs/ARCHITECTURE.md §7` — full integrity+crypto design.
4. `docs/ROADMAP-V2.md §7` — phase deliverables + exit criteria.
5. `memory/audit_v2_r0_closed_list.md` — what NOT to re-report.
6. `v2/specs/` — TLA+ specs; `merkle.tla` arrives with P4-6.
