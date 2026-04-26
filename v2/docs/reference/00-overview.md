# 00 — Overview

## Layer cake (bottom-up)

Stratum v2 is organized as a stack of narrow-waist abstractions. Each
layer depends only on the layers below it; upward arrows are visible
control / ownership flow.

```
┌──────────────────────────────────────────────────────────────────────────┐
│ fs       — POSIX-adjacent FS surface (single-device; Phase 6 will own   │
│            per-dataset metadata).                                         │
├──────────────────────────────────────────────────────────────────────────┤
│ scrub    — background integrity sweep (P5-5-α: verify-only).             │
├──────────────────────────────────────────────────────────────────────────┤
│ sync     — multi-device commit coordinator.  Writes uberblock rings,     │
│            drives quorum, hosts the per-dataset key schema.  Composes    │
│            alloc + alloc_roots + keyschema + pool.                       │
├──────────────────────────────────────────────────────────────────────────┤
│ pool     — roster of devices, per-pool rwlock, device lifecycle (add /   │
│            remove / replace / fail / rejoin / evacuate).                 │
├──────────────────────────────────────────────────────────────────────────┤
│ alloc        — data-area allocator.  Bε-tree of allocated ranges.        │
│ alloc_roots  — per-device alloc-tree roots object (enables mirror(n)).   │
│ keyschema    — per-dataset DEK registry (CURRENT / RETIRED / PRUNING).   │
├──────────────────────────────────────────────────────────────────────────┤
│ bootstrap — bitmap-managed allocator for tree nodes (recursion break).   │
│ btree_store — AEAD-encrypted node serialization + Merkle bp_csum chain. │
│ btnode     — on-disk node encoding (4 KiB fixed).                        │
├──────────────────────────────────────────────────────────────────────────┤
│ btree      — single-threaded Bε-tree (msg-buffered internal nodes).     │
│ btree_mt   — rwlock-wrapped variant.                                     │
│ btree_lf   — lock-free Bw-tree (MVP: internal-node routing + splits +   │
│              MERGE + EBR-backed retire).                                │
├──────────────────────────────────────────────────────────────────────────┤
│ ebr      — epoch-based reclamation (3 epochs + retire rings).           │
│ sb       — superblock (uberblock) layout + label regions.                │
├──────────────────────────────────────────────────────────────────────────┤
│ crypto   — AEGIS-256 / XChaCha20-SIV AEAD, HKDF-SHA256, Argon2id,        │
│            X25519, ML-KEM-768, PQ-hybrid wrap, CSPRNG.                    │
│ hash     — BLAKE3-256, xxHash3-64 / -128.                               │
│ block    — stm_bdev (POSIX / io_uring backends) + fault injection.       │
│ util     — stm_status codes, LE-encoded primitives.                      │
└──────────────────────────────────────────────────────────────────────────┘
```

Out-of-tree (v1 reference): `docs/STRATUM.md`. Experimental / planned
(not yet implemented in v2): **extent manager** (P6), **namespace**
(datasets, snapshots, clones — P6), **CAS + dedup** (P7), **RS/LRC
erasure coding** (post-P5), **9P / FUSE surfaces** (Phase 8+).

## Cross-cutting concerns

### Nonce uniqueness (load-bearing)

Every AEAD encryption at the metadata layer uses a 32-byte nonce
built as `paddr || gen || pool_uuid` (see `src/btree_store/crypt.c`
`build_nonce`). Uniqueness is guaranteed by three independent
constructs composed together:

- `paddr` uniqueness within a commit is enforced by `bootstrap` +
  `alloc`'s deferred-free (`allocator.tla: NoReuseInSameGen`).
- `gen` monotonicity is enforced by `sync.tla`'s MountGenBump +
  `quorum.tla`'s AuthoritativeMono across crash / rollback /
  multi-device fanout.
- `pool_uuid` scopes the entire nonce space to one pool — cross-pool
  replay is impossible.

Extended to multi-device pools in P5-3: the paddr's top 16 bits
encode `device_id`, so per-device allocator trees produce distinct
paddrs even when two trees independently reserve the same offset.
`metadata_nonce.tla` pins the full invariant; its buggy config
(without the device_id stamp) demonstrates the pre-fix collision
at depth 5.

### Lock order (global)

```
    POOL  (rwlock)    ← outer
    SYNC  (mutex)
    ALLOC (mutex)
    BTREE (rwlock)    ← leaf
```

Any reversal is a deadlock. The contract is codified in
`include/stratum/pool.h` "Per-pool lock" section. Key implications:

- Pool mutators (add / remove / begin_evacuation /
  finish_evacuation / fail / rejoin) take pool.wrlock internally.
- Pool readers that dereference pointer-returning accessors
  (`stm_pool_device_info`, `stm_pool_device_bdev`) must hold
  pool.rdlock.
- Sync's commit + mirror write/read + evacuation_step all wrap their
  critical section in pool.rdlock BEFORE taking sync's mutex.
- Safe-removal wrappers (`stm_sync_remove_device`,
  `stm_sync_finish_evacuation`) atomically hold pool.wrlock +
  sync.lock to compose add/attach/commit/detach in one step.

Scrub joins this order (sc.lock → pool.rdlock → sync.lock →
alloc.lock) and picks up the same contract.

### Commit protocol (multi-device)

`sync_commit` is a 2-phase protocol when `auth_gen > 0` (the fresh
pool's first commit is 1-phase):

```
1. Reservation — write UB at gen=auth+1 to every device in parallel.
                 Require quorum (⌊N/2⌋+1) fsync confirmations.
                 Pre-flush roots; becomes the rollback target.
2. Flush       — persist dirty data, key-schema, alloc trees, and
                 alloc-roots. Per-block writes do NOT require quorum
                 at this step; they're anchored by the final UB.
3. Final       — write UB at gen=auth+2 to every device in parallel.
                 Require quorum. Commit point. Post-flush roots +
                 post-flush Merkle root.
4. Publish     — in-RAM auth_gen := auth+2. current_gen := auth+2
                 (for "next commit's gen").
```

Each commit advances `auth_gen` by 2. Mount-claim advances by 1.

Quorum is checked from the sorted gen list: the auth is the highest
G such that `|{d : ub_device[d].gen >= G}| >= quorum`. Orphan gens
(at G' > auth but held by fewer than quorum devices) are overwritten
by the next commit or mount-claim at auth+1.

`quorum.tla` pins:
- `QuorumSafety` (phase=Published → ≥quorum devices at target_gen)
- `AuthoritativeMono` (committed gens never regress)
- `CommitAtomic` (auth ≥ 2 × commits_done)
- `OrphansNotAuthoritative`
- `ContentQuorumAtGen` (R14: content-level agreement, not just gen count)
- `MountGenBumpMulti`

### Superblock versioning

`STM_UB_VERSION` is the on-disk format version byte. Mount refuses
any version other than the current one.

| Version | Bump reason |
|---|---|
| 4 → 5 | P5-1: populate roster fields (`ub_device_count`, `ub_roster[2048]`, `ub_roster_hash`). |
| 5 → 6 | P5-3b: `ub_alloc_root` now points at the pool-level alloc-roots object (`STM_BPTR_KIND_ALLOC_ROOTS`) instead of a single alloc tree. |
| 6 → 7 | P5-3c: per-alloc-roots entry gains per-tree `root_gen` (value layout 40 → 48 bytes); needed for per-device independent-commit-gen handling. |
| 7 → 8 | P5-durable-cursors: `ub_scrub_state[64]` carved from `ub_reserved` to persist scrub state across mount (ARCH §7.14.1; closes Phase 5 exit criterion 4 / scrub-durable aspect of #3). |
| 8 → 9 | P6-persist: `ub_main_root_gen` (le64) + `ub_snap_root_gen` (le64) carved from `ub_reserved` to track AEAD gens for the dataset + snapshot index trees (ARCH §8.3.2 / §8.5.2). Symmetric to `ub_alloc_root_gen`. New bptr kind `STM_BPTR_KIND_DATASET = 9`; `STM_BPTR_KIND_SNAP = 5` reused for the snapshot tree root. v8 pools refused at v9 mount via uniform `STM_EBADVERSION`. |
| 9 → 10 | P6-clone: dataset on-disk value layout grows by 8 bytes for `origin_snap_id` (le64 at offset 56). New fixed prefix is 64 bytes (was 56); total = 64 + name_len. Non-clone datasets carry `STM_DATASET_NO_ORIGIN` (0). v9 pools refused at v10 mount via uniform `STM_EBADVERSION` — the dataset value layout shift would mis-decode otherwise. Uberblock layout itself unchanged. |

Current: `STM_UB_VERSION == 10` (see `include/stratum/super.h`).

### Merkle-rooted integrity

Every metadata node (allocator tree, alloc-roots tree, key-schema,
bootstrap-pool image) is AEAD-encrypted at rest with an in-band
`bp_csum` that chains up through the uberblock. The uberblock's
`ub_merkle_root` is the root of this chain. `merkle.tla` pins the
structural properties. Extent (data) integrity is per-extent:
AEAD tag for encrypted datasets; xxHash3-64 (`se_xxh` field) for
unencrypted. Data integrity is NOT in the Merkle chain — it's
checked at the extent boundary on every read.

## Phase status (as-built)

| Phase | Status | Highlights | See |
|---|---|---|---|
| 1 | ✅ complete | Crypto + hash + block + TLA spec infrastructure; initial sync/alloc. | phase1-status.md (historical, n/a) |
| 2 | ✅ complete | Bε-tree + Bw-tree MVP + EBR + R0-R5 audits. | phase2-status.md, phase2-bw-tree-design.md |
| 3 | ✅ complete | Single-device sync + uberblock + persistent allocator + R6-R12 audits. | phase3-status.md |
| 4 | ✅ complete | AEAD-AD + per-extent integrity + keyschema + PQ-hybrid wrap + janus + R13-R14b audits. | phase4-status.md |
| 5 | 🚧 in progress | P5-1..P5-5-α landed. R15-R19 audits closed. R20 in flight on P5-5-α. | phase5-status.md |
| 6 | ⏳ planned | Extent manager + dataset / snapshot / clone namespace. | docs/ROADMAP-V2.md §9 |

## Test posture

- 28 test suites (single-device unit + multi-device integration).
- Three sanitizer configurations, all green: default, ASan, TSan.
- TSan timeout bumped to 180s for `test_crash_inject` (has ~168
  format+mount cycles).
- 13 TLA+ spec modules verify fixed configs.
- 6 buggy-config demos confirm the invariants actually fire when
  violated (regression protection for the invariants themselves).

## Build + CI

Local invocation (from the repo root):

```bash
cd v2
cmake -B build -S . -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure
```

CI (`.github/workflows/v2-ci.yml`, copy at
`v2/ci/github-actions.yml`): Linux gcc/clang × off/asan/tsan, macOS
clang × off/asan/tsan, TLC per spec. Triggered by pushes to main +
PRs touching `v2/`.

For TLA+:

```bash
curl -sL -o /tmp/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"   # macOS brew path
cd v2/specs
java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
    -config <name>.cfg <name>.tla
```

See `CLAUDE.md` for the audit-triggering change policy and the
spec-first discipline.
