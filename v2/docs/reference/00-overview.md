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
| 10 → 11 | P6-deadlist: snapshot on-disk value layout grows by a tail `le32 dead_count + le64 paddrs[N]` (per-snap incremental dead-list, dead_list.tla). Per entry: 48 + name_len + 8*N bytes (was 44 + name_len). `STM_SNAP_DEAD_LIST_MAX = 256` paddrs/snap caps in-line; chunked off-tree storage deferred. v10 pools refused at v11 mount via uniform `STM_EBADVERSION` — v10 decoders rejected trailing bytes after `name`. Uberblock layout itself unchanged. |
| 11 → 12 | P7-3: `ub_extent_root` (64-byte stm_bptr at offset 3128) + `ub_extent_root_gen` (le64 at offset 3192) carved from the head of `ub_reserved`. Anchors the extent-index Bε-tree (ARCH §11.6, extent.tla); same envelope as ub_main_root / ub_snap_root (btree_store-encoded, AEAD-encrypted). New `STM_BPTR_KIND_EXTENT_TREE = 10`. The Merkle root chain folds in a 6th csum (extent_csum) — v11 pools' Merkle roots were 5-input, so any v11 UB at v12 would fail Merkle recompute even before the version check. v11 pools refused at v12 mount via uniform `STM_EBADVERSION`. |
| 12 → 13 | P7-6: extent-record value layout grows 32 → 64 bytes with up to 4 replica paddrs per ARCH §11.6.1 (replica list per extent). New `extent.tla` invariant `LiveReplicasDisjoint` (replica paddrs across live extents are mutually disjoint at the device level). `stm_sync_write_extent` reserves N=mirror_n replicas across N distinct devices, encrypts ONCE under (replicas[0], gen), writes bytewise-identical ciphertext+tag to each replica. Scrub β cb realizes bptr.tla's full ScanRead × RewriteReplica matrix. v12 pools' 32-byte values length-rejected by v13 decoder. New buggy demo `extent_replica_collision_buggy.cfg`. |
| 13 → 14 | P7-8: snapshot-record value layout grows 8 bytes (new `extent_txg` field at offset 24..32; captures `sync.current_gen` at SnapshotCreate). Send/recv's incremental gen filter aligns with `extent.gen` instead of using `created_txg` (different counter space). `snapshot.tla` extended with separate `sync_gen` counter + new invariants `ExtentTxgBoundedBySync` and `ChainExtentTxgOrdered`. New buggy demo `snapshot_extent_txg_unbounded_buggy.cfg`. SP_VAL_FIXED 44 → 52; v13 entries length-rejected by v14 decoder. Refused via uniform STM_EBADVERSION. |
| 14 → 15 | P7-10: extent-record value layout reuses the always-zero `xxh` slot at offset 56 for `key_id` (le64) — names which DEK in the dataset's keyschema decrypts the extent. EX_VAL_LEN unchanged at 64 bytes. `stm_sync_create` auto-installs the root dataset's DEK at format time. Sync write/read/scrub-cb/send paths resolve DEK by `(dataset_id, key_id)` instead of using the per-pool `metadata_key`; receiver re-encrypts under its own pool's CURRENT DEK. `stm_sync_keyschema_sweep` refuses to prune a RETIRED key with live extent references (closes the long-standing P4-4c TODO; maps to key_schema.tla::PruneSafety). `extent.tla::ExtentRec` gains `key_id ∈ KeyIds`; new bound config `extent_keyids.cfg` (MaxKeyIds=2 at the pre-P7-9 bound) realizes spanning-rotation states. v14 pools refused at v15 mount via uniform STM_EBADVERSION (their offset-56 bytes are 0; semantically "key_id=0" but no per-dataset DEK exists in v14 keyschemas). |
| 15 → 16 | P7-15: repair-log persistence (ARCH §7.15.4 / bptr.tla::LogIntegrity). Three new fields carved from the head of `ub_reserved`: `ub_repair_log_root` (64-byte stm_bptr at offset 3200), `ub_repair_log_root_gen` (le64 at offset 3264), `ub_repair_log_next_seq` (le64 at offset 3272); `ub_reserved` shrinks 864 → 784 bytes. Anchors a single-leaf btnode-encoded plaintext + Merkle-covered tree (matches keyschema's shape; bp_csum = btnode self-csum), append-only, keyed by 8-byte big-endian seq_id, 32-byte fixed value. New `STM_BPTR_KIND_REPAIR_LOG = 11`. Production scrub β cb emits one entry per Phase-3 rewrite (success + failure paths). The Merkle root chain folds in a 7th csum (`repair_log_csum`) — closes the asymmetry vs keyschema's existing Merkle coverage so an offline tamper of the audit trail surfaces at the mount-time Merkle recompute. v15 pools refused at v16 mount via uniform STM_EBADVERSION (their offset-3200 bytes are zero; tamper-then-mount comes up with an empty repair-log — degraded but not dangerous). |
| 16 → 17 | P7-16: reflinks (ARCH §11.12 / §8.6.3, extent.tla::Reflink + SharedReplicasAreCohabit). Extent on-disk value 64 → 96 bytes by adding `origin_dataset_id` (le64 at offset 64), `origin_ino` (le64 at offset 72), `origin_off` (le64 at offset 80), and 8 reserved bytes at offsets 88..95. The origin triple names the (ds, ino, off) at which the AEAD ciphertext was first encrypted; reflink-siblings sharing the same paddrs reconstruct the same AEAD AD at read/scrub/send time so AEGIS-256 verify succeeds. For non-reflinked extents origin equals the live (dataset_id, ino, off) — the prior write-/read-path semantics are unchanged. The decoder requires `origin_dataset_id != 0 && origin_ino != 0` and bytes 88..95 all-zero (anti-tamper). Spec replaces `LiveReplicasDisjoint` with `SharedReplicasAreCohabit`: paddr-share permitted ONLY when the whole replica set + gen + key_id + origin tuple matches (legitimate reflink siblings); partial overlap or whole-share-with-mismatched-tuple still refused. v16 pools' 64-byte extent values length-rejected by v17 decoder. Refused via uniform STM_EBADVERSION. New buggy demo `reflink_rotates_origin_buggy.cfg`. New STM_EXDEV error code (-18) for cross-dataset reflinks (deferred per ARCH §11.12.3 same-key requirement). No uberblock field changes. |
| 17 → 18 | P7-CAS: cold-tier index foundation (ARCH §6.9 / §7.6.3 / §12.10, NOVEL #3, cas.tla). Adds `ub_cas_index_root_gen` (le64 at offset 3280) carved from the head of `ub_reserved` (which shrinks 784 → 776). The tree-root bptr field `ub_cas_index_root` was already at offset 288 (carved at v3 in the metadata-roots block alongside ub_main_root / ub_alloc_root / ub_snap_root, but unused until now). Tree's bp_kind is `STM_BPTR_KIND_CAS` (= 6, also carved at v3). Extent record value layout adds a 1-byte `kind` discriminator at on-disk offset 0: 0x01 = HOT (paddr-addressed), 0x02 = COLD (hash-addressed). HOT shifts n_replicas from byte 0 to byte 1 (bytes 2..7 reserved zero); paddrs at 8..39, gen/dlen/clen_and_comp/key_id/origin/link_gen at 40..95 (unchanged from v17). COLD replaces bytes 1..39 with reserved (1..7) + content_hash[32] (8..39); bytes 40..95 same as HOT. CAS index value layout (64 bytes): n_replicas + paddrs[4] + refcount + length + gen. Migration / rehydration paths deferred to P7-CAS-2; this version establishes the index lifecycle + persistence + format. v17 pools refused at v18 mount via uniform STM_EBADVERSION (no in-place forward-compat at the value layer — v17's byte-0 was n_replicas not kind). The Merkle root chain's CAS slot (zero before this commit) is now populated by the CAS index's tree csum. New AEAD AD struct `stm_ad_cas` (56 bytes — magic + version + pool_uuid + content_hash) per ARCH §7.6.3. New cas.tla spec + 6 buggy demos. |

| 18 → 19 | P7-CAS-4c: snap_idx ↔ CAS hash refcount integration (ARCH §6.9 / NOVEL #3). Per-snap value layout grows past the existing dead_paddrs[] tail with `cold_dead_count` (le32) + `cold_dead_hashes[N][32]` where N ≤ STM_SNAP_COLD_DEAD_LIST_MAX = 256. Closes the long-deferred P7-CAS-2 forward-note that snapshots-with-cold-extents could see dangling-hash reads after auto-GC reclaimed the chunk. The cold-dead-list is a MULTISET of hashes (R54 P1-1) — distinct cold extents legitimately share content_hash via dedup, intra-file dedup, or FastCDC sub-chunking. v18 pools refused at v19 mount via STM_EBADVERSION. No uberblock field changes.

| 19 → 20 | P7-CAS-8: STM_PROP_COUNT 3 → 4 — adds `STM_PROP_TIERING` (INHERITABLE; per-dataset tiering opt-in for the migration-policy heuristic's pass-all wrapper). Dataset value layout grows past the local_value[] tail: `origin_snap_id` moves from offset 56 to offset 64 (= `32 + 8 * STM_PROP_COUNT`); `DS_VAL_FIXED` grows from 64 to 72. Pool-defaults value length grows from 24 to 32 bytes (= `8 * STM_PROP_COUNT`). The local_set bitmap (le16 at offset 28..29) gains a 4th significant bit; bitmap-mask validation rejects bits beyond `STM_PROP_COUNT - 1`. v19 pools refused at v20 mount via uniform STM_EBADVERSION (no in-place forward-compat at the value layer — same posture as v17→v18 and v18→v19 bumps). No uberblock field changes. property.tla unchanged (it is parametric over the property set; the existing INHERITABLE-class invariants already cover the new property).

Current: `STM_UB_VERSION == 20` (see `include/stratum/super.h`).

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
| 5 | ✅ complete | Multi-device pool + roster + quorum + scrub-α/β/γ. R15-R26 audits closed. Tagged `phase-5-complete` at `461e68e`. | phase5-status.md |
| 6 | ✅ namespace feature-complete | Dataset / snapshot / clone / property / dead-list C impls + persistence. ROADMAP §9.2 5/5 exit criteria met. R27-R33 closed. | phase6-status.md |
| 7 | 🚧 cold-tier MVP feature-complete + orchestration end-to-end + migration policy v1 + per-dataset opt-in + send/recv cold + on-wire dedup | P7-prework FastCDC + P7-1..P7-16 + P7-CAS index foundation (UB v17→v18) + P7-CAS-2 migration data plane + P7-CAS-3 R50 P2-1/P2-3 close + cold-extent reflink + P7-CAS-4a crossing-cold truncate + P7-CAS-4b FastCDC sub-chunking + P7-CAS-4c snap_idx ↔ CAS hash refcount integration (UB v18→v19) + P7-CAS-4 background-GC semantics + P7-CAS-5 out-of-band CAS GC entry point + P7-CAS-6 scrub-orchestrator wrapper + P7-CAS-7 migration-policy heuristic v1 (`stm_fs_migrate_policy_step`) + P7-CAS-8 per-dataset `STM_PROP_TIERING` opt-in + multi-dataset wrapper `stm_fs_migrate_policy_pass_all` (UB v19→v20; STM_PROP_COUNT 3 → 4) + P7-CAS-9 send/recv with cold extents (`STM_SEND_FLAG_COLD` wire-format extension + `stm_sync_recv_cold_extent` receiver primitive; storage-at-rest dedup preserved on target) + P7-CAS-10 out-of-band chunk store wire shape (STM_SEND_VERSION 1→2; new STM_SEND_REC_CHUNK record kind + 3 sync APIs `stm_sync_recv_cold_chunk` / `stm_sync_recv_cold_extent_ref` / `stm_sync_recv_cold_chunk_release`; sender dedupes by hash + emits each unique chunk once; receiver tracks `chunks_seen` + drains at `recv_close`; on-wire dedup ratio mirrors at-rest dedup ratio). R27, R34–R61 closed. Recordsize lift (cross-extent FastCDC), promotion (cold→hot) heuristic, and learned migration policy v2 deferred. | phase7-status.md |

## Test posture

- 33 test suites (single-device unit + multi-device integration).
- Three sanitizer configurations, all green: default, ASan, TSan.
- TSan timeout bumped to 180s for `test_crash_inject` (has ~168
  format+mount cycles).
- 20 TLA+ spec modules verify 24 fixed configs.
- 24 buggy-config demos confirm the invariants actually fire when
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
