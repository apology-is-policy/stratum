# Phase 4 — status and pickup guide

Authoritative pickup guide for Phase 4 (integrity + crypto). Last
update 2026-04-21 (after P4-3b — AEAD on metadata nodes — landed).
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
| `54b3c8b` → `ee3600c` | **P4-1 + R8: Merkle integrity scaffold**. Wires existing per-node BLAKE3 self-csums into a chain: internal-node bp_csum fields carry child csums; allocator-tree root csum propagates into `ub_alloc_root.bp_csum`; `ub_merkle_root = BLAKE3(main_csum(0) ‖ alloc_csum ‖ snap_csum(0) ‖ cas_csum(0) ‖ salt)` per ARCH §7.11.3. Per-pool salt from libsodium CSPRNG at format, stored in new `ub_merkle_root_salt[32]` (STM_UB_VERSION 1→2). Mount verifies recomputed Merkle root against stored value AND tree-root node self-csum against `bp_csum`. R8 audit closed: 1 P0 (free_tree segfault on multi-leaf) + 2 P1 (BLAKE3 OOM bypass; NULL-csum trap) + 3 P2 (substitution test, libsodium switch, rename). | 4 new sync tests; 20 suites green |
| `65c4c76` | **P4-6: `merkle.tla` formal spec**. Models the Merkle chain under COW: honest WriteLeaf / WriteInternal / Commit actions plus adversarial Tamper. Proves `CommittedTreeWellFormed` (stored csums = recomputed at commit time) and `TamperDetectableAtCommittedRoot` (any byte edit reachable from root makes recompute ≠ stored merkle_root). TLC clean: 83169 distinct states, depth 10. | Spec-only |
| `cb9671f` | **P4-3a: metadata-key lifecycle**. Per-pool 32-byte metadata-encryption key. Generated at sync_create from libsodium CSPRNG, persisted at `ub_key_schema[0..32]` on every commit, recovered at sync_open. Reserved tail `ub_key_schema[32..512]` stays zero for P4-4's key-hierarchy layout. | 1 new sync test |
| `fc52dbe` | **P4-3b: AEAD on metadata nodes**. AEGIS-256 wraps every emitted btnode image at the `btree_store` boundary. On-disk layout: ciphertext occupies `[0..STM_BTNODE_SIZE - 32)`, AEAD tag fills the trailing 32 bytes (repurposes the slot the P4-1 plaintext self-csum used to live in; `STM_AEAD_TAG_LEN_AEGIS256 == STM_BTNODE_CSUM_SIZE` ensures exact fit). `bp_csum` semantics unchanged: `BLAKE3(on-disk[0..STM_BTNODE_SIZE - 32))` — now covers ciphertext. Nonce = paddr(8 LE) ‖ gen(8 LE) ‖ pool_uuid(16 LE). AD = pool_uuid(16 LE) ‖ device_uuid(16 LE). Mandatory for v2 pools — no unencrypted path. `stm_alloc` gains a crypt-ctx setter; `stm_sync_{create,open}` installs it from the pool key before the first commit / tree load. Old-tree free path threads the prior tree's gen so AEAD decrypt can enumerate internal-node children. | 7 new btree_store tests (encrypted round-trip, tag tamper, wrong key / gen / pool_uuid / device_uuid, NULL cx); 20 suites green |
| `ca8d47b` | **R9 audit fixes**. P0-1: mount-claim UB closes the nonce-reuse-across-crash-recovery hazard. New `ub_alloc_root_gen` field preserves the AEAD nonce on the tree when a mount advances ub_gen without rewriting the tree. Format bump STM_UB_VERSION 2→3. P1-1: `stm_crypto_init` at top of sync_create/open. P1-2: `stm_btree_store_free_tree` now takes `expected_root_csum` and Merkle-verifies before AEAD decrypt. P2-1: `stm_btree_store_serialize` rolls back reserved paddrs on emit failure. P2-2: dangling key-pointer nulled after OOM. | 2 new sync tests (mount-claim advance, load_tree_at-without-cx); 20 suites green on default/ASan/TSan; 7 TLA+ specs clean |
| `dc357ad` | **P4-2: scrubber**. New `stm_btree_store_verify` + `stm_alloc_verify` + `stm_fs_verify`: walks the on-disk allocator tree, re-reads every node, checks Merkle chain + AEAD tags without mutating state. Safe to call on live pools (including RO / wedged). Intended for admin-invoked scrubs and as a separate detection surface from mount-time Merkle (in-flight bit rot or external tamper surfaces on next scrub without waiting for unmount). | 3 new sync tests (clean, empty pool, post-commit tamper detection); 20 suites green |
| `<next>` | **P4-5 stub: data-extent AEAD round-trip**. New `src/extent/` module exposing `stm_ad_extent` (ARCH §7.6.1 — 56-byte AD: magic ‖ version ‖ pool_uuid ‖ dataset_id ‖ ino ‖ offset ‖ content_kind) + `stm_extent_encrypt` / `stm_extent_decrypt`. Nonce construction matches P4-3b's metadata wrapper (paddr ‖ gen ‖ pool_uuid) — see phase4-status.md "Known deltas from ARCH" for the nonce-layout subset rationale. No extent manager, no on-disk index — the caller owns paddrs. Scope is the crypto surface alone; full extent layer is Phase 6 (dataset model + tree + content-defined chunking). Satisfies ROADMAP §7.2's "encrypted writes round-trip correctly with AEGIS-256 and XChaCha20-SIV" exit bullet. | 11 new tests: round-trip per mode; AD field-by-field tamper rejects (pool_uuid / dataset_id / ino / offset / content_kind); nonce tamper (paddr / gen); tag tamper; AD packed-size pinned to 56. 21 suites green |

## Remaining Phase 4 work

Rough ordering, subject to revision as dependencies clarify:

### P4-2: Scrubber (LANDED as of `<next>`)

Per-read verification wasn't directly applicable because Phase 3's
`stm_alloc_lookup` serves from the in-RAM tree — no fresh reads to
hook. Re-scoped to a scrubber primitive: `stm_alloc_verify` (+
`stm_fs_verify`) re-reads every allocator-tree node from disk and
runs the full Merkle + AEAD verification chain. Side-effect-free;
safe on live / RO / wedged pools. Intended for:
- admin-invoked scrubs
- a separate detection surface for in-flight bit rot or tamper
  (surfaces on next scrub rather than waiting for unmount)

A future "scrub mode" daemon (background periodic scrub) is a
Phase-8 concern but plugs into this primitive.

### P4-4: Janus + key-schema sub-tree (design committed; implementation pending)

Agreed-on-the-run 2026-04-21 (see ARCH §7.7.3 + §7.9, NOVEL §3.10,
ROADMAP §7.1 for the committed design):

- **Agent name: `janus`**, two-faced daemon (9P on one side, backends on
  the other). Single binary, not prefixed.
- **Key-schema sub-tree**, rooted from `ub_key_schema`. Reuses
  `stm_btnode` + `stm_btree_store` + AEGIS-256 machinery. Fifth input
  to `ub_merkle_root` after main / alloc / snap / cas. Scales to
  arbitrary dataset + rotation counts (1192-byte PQ-hybrid wrapped
  keys don't fit the 512-byte uberblock field; a tree scales
  naturally). See ARCH §7.7.3 for the on-disk layout.
- **Merkle formula change**: `BLAKE3(main || alloc || snap || cas ||
  keyschema || salt)`. Empty roots contribute zeros (today cas is
  zero; keyschema will also be zero until P4-4a lands, then populates).
- **Formal model required**: `key_schema.tla` proving rotation
  atomicity + retired-key retention. ~150-200 lines. Lands with P4-4a.

Implementation split (per the decision thread):

1. **P4-4a — on-disk key-schema sub-tree**. Layout, tree operations
   (insert / lookup / rotate), Merkle integration. In-process unwrap
   using the Phase 1 stm_hybrid primitive; wrap-key source is a file
   (the "file" backend from ARCH §7.9.3's list). Ends with: no
   plaintext key on disk.
2. **P4-4b — janus daemon**. Separate binary, 9P synthetic FS,
   SO_PEERCRED auth, passphrase backend.
3. **P4-4c — per-dataset keys**. Generalize from one pool key to the
   dataset-keyed sub-tree; rotation plumbing per ARCH §7.7.

### P4-3: AEAD on metadata nodes (stm_btnode)

Split into two landings:

**P4-3a (LANDED)** — per-pool metadata key lifecycle. Generates a
32-byte key at sync_create from libsodium CSPRNG, persists in
`ub_key_schema[0..32]` at every commit, recovers at sync_open. Key
is unused by the write path so far; infrastructure only. Reserved
tail `ub_key_schema[32..512]` stays zero for P4-4's wrapped-key
hierarchy.

**P4-3b (LANDED at `fc52dbe`)** — AEAD wrapper at the
btree_store serialize / deserialize boundary. Design decisions
(recorded pre-land; what was actually implemented matches except
for two wrinkles captured at the end of this section):

- **Wrapper location**: btree_store, NOT btnode. Keeps btnode
  plaintext-only; encryption is a transport concern.
- **On-disk layout for encrypted metadata node**:
  ```
  [0 .. STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE)   = ciphertext
  [STM_BTNODE_SIZE - STM_BTNODE_CSUM_SIZE .. END) = AEAD tag (32 B)
  ```
  Trailing 32 bytes repurpose the P4-1 "self-csum" slot to store
  the AEAD tag. `btnode_verify_csum` is bypassed for encrypted
  nodes — the AEAD tag verification replaces it.
- **bp_csum semantics (unchanged from P4-1)**:
  `BLAKE3(on-disk-bytes[0..STM_BTNODE_SIZE-STM_BTNODE_CSUM_SIZE))`
  — covers the ciphertext. The AEAD tag is NOT part of bp_csum;
  tag tamper is caught by AEAD decrypt, byte tamper in the
  ciphertext is caught by Merkle chain.
- **AEAD choice**: AEGIS-256. 32-byte tag (fits the repurposed
  slot exactly), high-throughput, nonce-misuse-resistant enough
  for our unique-per-write-paddr-gen nonce.
- **Nonce (32 bytes)**: `paddr (8) || gen (8) || pool_uuid (16)`.
  Guarantees uniqueness under the gen-monotonicity invariant
  (sync.tla's MountGenBump: gen strictly increases on every
  commit AND bumps past durable-max on mount). Two writes at the
  same paddr under the same gen are impossible — stm_bootstrap's
  deferred-free prevents paddr reuse within a commit.
- **AD (32 bytes)**: `pool_uuid (16) || device_uuid (16)`. Paddr
  and gen go in nonce (not AD) because AEGIS binds all of them
  to the tag equivalently. Including device_uuid in AD ensures a
  node written to device X cannot be replayed at device Y
  (relevant for multi-device Phase 5).
- **Feature flag vs. mandatory**: mandatory for v2.0 — every
  metadata node is encrypted. No unencrypted-pool path in code
  means no branching on read/write. Saves complexity and matches
  the ARCH §7 mission commitment to PQ-default.
- **Migration**: v1→v2 uberblock version bump (already done in
  P4-1) rejects v1 pools, so there's no backward-compat concern.

Integration surfaces (as landed):
- `src/btree_store/serialize.c`:
  - `emit_leaf` / `emit_internal`: after `stm_btnode_*_encode`,
    reserve the paddr, AEAD-encrypt bytes `[0..STM_BTNODE_SIZE - 32)`
    in place (via heap scratch — see below), which also stamps the
    AEAD tag at `[STM_BTNODE_SIZE - 32..STM_BTNODE_SIZE)`. THEN
    compute `bp_csum = BLAKE3(ciphertext)` and populate `out_csum`.
  - `stm_btree_store_deserialize`: after `vt->read`, verify
    `BLAKE3(ciphertext)` matches `expected_root_csum`, AEAD-decrypt,
    then restore the plaintext self-csum (see below) so
    `btnode_verify_csum` (called transitively from `_leaf_decode`
    and `_internal_decode`) passes.
- `src/alloc/alloc.c`: `stm_alloc_load_tree_at` now takes `root_gen`.
  `stm_alloc` stashes `metadata_key + pool_uuid + device_uuid` via a
  new `stm_alloc_set_crypt_ctx` and a new `current_tree_gen` field so
  the NEXT commit's `free_tree` can decrypt the OLD tree under its
  original gen. `stm_alloc_commit` wipes the key on close with
  `stm_ct_memzero`.
- `src/sync/sync.c`: `stm_sync_create` and `stm_sync_open` install
  the crypt ctx on the alloc handle before the first commit / load.
  `stm_sync_open` threads `durable_gen` as the root_gen.
- No changes to `btnode.c` / `btnode_common.c` — the plaintext
  btnode layout is preserved. The decrypt path reconstructs the
  plaintext self-csum from ciphertext so btnode's existing
  `btnode_verify_csum` keeps working without special-casing.

Two implementation notes worth preserving:

1. **AEGIS-256 aliasing**: libsodium's `crypto_aead_aegis256_encrypt`
   does NOT guarantee correctness under aliased `pt` / `ct` buffers.
   Empirical result with aliased buffers: decrypted plaintext comes
   back as zeros (the state-update step reads plaintext AFTER the
   ciphertext write, which clobbers subsequent input reads). The
   wrapper in `crypt.c` allocates a heap scratch, memcpy's the input
   into it, runs the AEAD against disjoint buffers, and
   `stm_ct_memzero`'s the scratch before `free`. One malloc per node
   emit is in the noise relative to the 128 KiB copy.

2. **Plaintext self-csum restoration**: after AEAD decrypt, the
   trailing 32 bytes of the node image still hold the AEAD tag
   (decrypt only writes the first CT_LEN bytes). `btnode_verify_csum`
   — called from every leaf/internal decode path — expects those
   bytes to be the plaintext self-csum. `restore_plaintext_self_csum`
   zeros them and writes BLAKE3 of the plaintext region.
   Double-verification (AEAD+Merkle already guarantee plaintext
   integrity) but keeps self-csum semantics single-sourced in btnode.

R9 audit triggers after P4-3b lands.

### P4-4: Per-dataset key hierarchy + PQ-hybrid wrap

Per ARCH §7.3. Each dataset has its own AEAD key, derived from a
wrap-key stored in `ub_key_schema[512]`. Wrap key is ML-KEM-768 +
X25519 hybrid (stm_hybrid from Phase 1). Requires:
- Dataset concept (doesn't exist yet in v2 — only a single flat pool).
  Can land a "dummy dataset 0" first.
- Key agent process (stratum-keyagent) for wrap/unwrap.
- 9P protocol between daemon and agent (ARCH §7.9).

### P4-5: AEAD on data extents (STUB LANDED; full impl deferred)

Phase 4 stub landed as `src/extent/` + `tests/test_extent.c`. Covers
the exit-criterion "encrypted writes round-trip correctly with
AEGIS-256 and XChaCha20-SIV" at the crypto-surface level:

- `stm_ad_extent` struct + packing matches ARCH §7.6.1 exactly.
- `stm_extent_encrypt` / `_decrypt` with nonce = (paddr, gen,
  pool_uuid) and AD = packed stm_ad_extent.
- Both AEGIS-256 and XChaCha20-SIV round-trip.
- Five AD fields + two nonce fields + the tag are each independently
  proven to bind via tamper tests.

What the stub DOESN'T do — deferred to Phase 6 extent manager:

- Extent index (tree mapping (dataset, ino, offset) → paddr).
- Variable-sized extents / content-defined chunking.
- Compression (§11) preceding encryption.
- Integration with stm_fs's reserve/free path.
- Cross-device extent placement.

When the extent manager lands (Phase 6), callers switch from using
the crypto surface directly to a higher-level write/read API;
these primitives stay exactly as they are — they're the crypto
layer, not the storage layer.

### P4-6: merkle.tla

LANDED. Formal spec of hash propagation under COW. Models honest
protocol (WriteLeaf / WriteInternal / Commit) plus adversarial
Tamper. Proves:

- `CommittedTreeWellFormed` — after any Commit, stored root_csum
  = recomputed, stored merkle_root = PoolMerkleRoot(root_csum).
- `TamperDetectableAtCommittedRoot` — byte edits to any paddr
  reachable from the committed root make recompute ≠ stored.

TLC clean: 83169 distinct states, depth 10. Multi-level recursion
beyond depth 2 (chunk 5c cap, R8-P3-4) is deliberately not
modeled; when multi-level support lands the spec extends
mechanically.

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

# All TLA+ specs (includes merkle after P4-6)
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
cd specs
for s in sync concurrency structural balanced merge allocator merkle; do
    echo "== $s =="
    java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
        -config $s.cfg $s.tla 2>&1 | tail -3
done
```

## Known deltas from ARCH §7 (owed follow-ups)

- **AD layout narrower than ARCH §7.6.2** (flagged R9 P3). P4-3b
  shipped with `AD = pool_uuid || device_uuid`. ARCH specifies
  `magic || version || pool_uuid || tree_id || node_level ||
  dataset_id || reserved`. Safe today (single tree, single dataset,
  single device) but MUST widen before (a) multiple trees land
  (snap / CAS / main), (b) datasets become selectable, or (c)
  multi-device commits (Phase 5). Widening is additive: the new
  fields bind the AD more narrowly, rejecting cross-context reads
  that today's AD would incorrectly accept.
- **Nonce layout narrower than ARCH §7.4.1**. ARCH:
  `paddr(8) || txg(8) || seq_in_txg(4) || reserved(4) ||
  pool_uuid-high(8)`. P4-3b: `paddr(8) || gen(8) || pool_uuid(16)`.
  The missing `seq_in_txg` field is harmless today because
  `stm_bootstrap`'s deferred-free prevents paddr reuse within a
  gen. Would need adding only if a future path writes multiple
  distinct blocks to the same paddr within one gen (no such path
  exists).

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
