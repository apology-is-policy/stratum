# Stratum v2 — technical reference

This document is the **as-built** reference for Stratum v2. It
describes what exists in the v2 tree today, where the relevant code
lives, which invariants the TLA+ specs pin, and how the subsystems
compose. It is not a roadmap and not a design document — see
`docs/ARCHITECTURE.md` for design intent and `docs/ROADMAP-V2.md`
for phased scope.

## How to read this

The reference is split by subsystem, one file per layer of the stack.
Each file follows the same template:

- **Purpose** — one paragraph on what the layer does and where it
  sits in the stack.
- **Public API** — every exported function with its contract.
- **Implementation** — structure + invariants + known caveats.
- **Spec cross-reference** — TLA+ modules that pin invariants for
  this layer; SPEC-TO-CODE mapping entries.
- **Tests** — which suites exercise the layer and what they cover.
- **Status** — what's implemented today vs. what's stubbed or
  deferred. Commit hashes cite the landing points.

When a section describes a detail enforced by a spec, the spec's
action / invariant name is in `backticks`. When a section cites a
file, the form is `path/to/file.c:line` so editors can jump there.

## Audience

- Engineers landing changes to the subsystem under discussion.
- Reviewers validating that a change matches the documented contract.
- Auditors checking that invariants still hold.

If you are here to learn Stratum from scratch, start with
`docs/VISION.md` → `docs/ARCHITECTURE.md` → here. This reference
assumes you know what a Bε-tree is and why we want PQ-hybrid wrap.

## Snapshot

- **Tip**: post-R47-hash-fixup pending. Substantive `c02cba8` +
  R47 close `82fe30e`.
  **P7-15 repair-log persistence — closes R38 P3-1 (the long-
  deferred audit gap from P7-6 noting that the production scrub
  β cb's replica rewrites had no on-disk audit trail per ARCH
  §7.15.4 / bptr.tla::LogIntegrity). New `src/repair_log/`
  module implements a single-leaf btnode-encoded, plaintext +
  Merkle-covered append-only log keyed by monotonic seq_id with
  a 32-byte fixed value layout (timestamp_ns + target/source
  paddrs + replica indices + corruption type + verification
  result). Three new uberblock fields carved from `ub_reserved`:
  `ub_repair_log_root` (stm_bptr at offset 3200), `ub_repair_log_
  root_gen` (le64 at 3264), `ub_repair_log_next_seq` (le64 at
  3272); `ub_reserved` shrinks 864 → 784 bytes. New bptr kind
  `STM_BPTR_KIND_REPAIR_LOG = 11`. Scrub β cb gains per-rewrite
  emit (both success and failure paths); Phase 1 split adds a
  parallel `replica_io_err[]` array so the bptr.tla read_outcome
  tag (CSUM_FAIL vs IO_ERR) propagates to the log entry's `type`
  field. Format break STM_UB_VERSION 15 → 16. R47 P2-1 folded
  `repair_log_csum` into `compute_merkle_root` as the 7th input
  so an offline tamper of the audit trail surfaces as a Merkle
  mismatch at mount (closes the asymmetry vs keyschema's existing
  Merkle coverage). R47 fixes inline: P2-1 (Merkle gap) + P3-1
  (cap collision halts sync_commit — moved to emit-time STM_ERANGE
  with `STM_REPAIR_LOG_MAX_ENTRIES = 2048` constant) + P3-2
  (tampered paddr device → STM_ECORRUPT not STM_EINVAL) + P3-3
  (iter docstring claim) + P3-4 (iter cb re-entry warning).
  P3-5 (reference-doc gap) deferred to this hash-fixup per the
  three-commit pattern (R42 P3-2 precedent). 34 ctest suites
  green default + ASan + TSan; new test_repair_log suite (7
  tests) + 1 new test_fs integration test. test_crash_inject
  timeout bumped 180s → 300s for TSan headroom.**
  Prior: P7-14 snap chain-ordering regression `01b5233` + R46
  close `485f0ef` + hash fixup `9dd2d9a`.
  **P7-14 snap chain-ordering regression — closes R40 P3-3 (the
  long-standing audit deferral noting there was no on-disk
  regression test for `sp_validate_shadow`'s
  `ChainExtentTxgOrdered` validator). New gated test-only API
  `stm_snapshot_create_for_test` lives in
  `<stratum/snapshot_testing.h>` and bypasses ONLY the R40 P2-1
  in-process check (all other arg validation runs); same shape
  as `stm_snapshot_create` minus the chain-ordering refusal.
  R40 P2-1's in-process check has its own test
  (`snap_create_in_process_chain_ordering_refused`); the on-disk
  validator path is exercised by
  `fs_snap_chain_inversion_on_disk_refused_at_mount` — full
  format → mount → install one valid + one chain-inverted snap
  via `_for_test` → fs_commit → unmount → remount → expect
  STM_ECORRUPT from sp_validate_shadow. Refactored
  `stm_snapshot_create`'s body into a static
  `snapshot_create_inner` helper that takes a `skip_chain_check`
  flag; both public functions collapse to one-line forwards
  (single source of truth for arg validation). R46 P2-1 hardened
  the test seam: gated `_for_test` symbol behind the new
  `STRATUM_BUILD_TESTING_HOOKS` CMake option (default ON for the
  in-tree dev/test build, opt-out for production via
  `-DSTRATUM_BUILD_TESTING_HOOKS=OFF`). Verified out-of-tree:
  with HOOKS=OFF, `nm libstm_snapshot.a` shows the production
  `stm_snapshot_create` only — the bypass symbol is absent from
  the archive, so production code can't even mistakenly
  extern-declare it. R46 fixes: P2-1 + P3-1 (tightened on-disk
  assertion to STM_ECORRUPT — propagation chain doesn't wrap)
  + P3-2 (prelude consolidation) + P3-3 (added NULL-name,
  NULL-out_id, oversize-name to _for_test test) + P3-4 (chain-
  inversion rejection added to reference/13-snapshot.md
  validator-rejection prose). No format break, no spec change.
  test_snapshot 41 → 43; test_fs 40 → 41. 33 ctest suites green
  default + ASan + TSan in isolated runs.**
  Prior: P7-13 fs_create_dataset `e6a751c` + R45 close `f30db5e`
  + hash fixup `5f65f37`.
  **P7-13 fs_create_dataset — bundles `stm_dataset_create_child` +
  `stm_sync_add_dataset_key` into one fs-level API under
  `fs->lock`. Removes the test_fs restriction "only ds=1 (root)
  writes work without explicit DEK install"; the freshly-created
  id is immediately usable for `stm_fs_write` / `stm_fs_read`.
  R45 P2-1 made wrap-key source implicit: the fs handle retains
  `keyfile_path` / `janus_socket` strdup'd at mount, and the
  create call reuses the SAME source per-call (load → use → wipe).
  Per-call overrides have no documented use case (ARCH §7.7
  defines wrap keys as pool-wide), and accepting one would let a
  caller silently persist an unwrappable CURRENT entry that R42
  P1-1's hard-fail-on-CURRENT-unwrap-failure would turn into a
  permanent mount refusal — the substantive commit's
  `stm_fs_create_dataset_opts` was removed in the R-close pass to
  close that footgun by construction. Atomicity: on
  `stm_sync_add_dataset_key` failure the freshly-created leaf is
  rolled back via `stm_dataset_destroy` (infallible-by-spec for a
  non-root no-children leaf under fs->lock). No format break, no
  spec change. test_fs 31 → 40 (9 net new tests). R45 audit:
  0 P0 + 0 P1 + 1 P2 + 4 P3 — P2-1 + P3-1 (docstring drift) +
  P3-2 (dead defensive wedge) + P3-4 (test gaps: name-length +
  multi-call sequencing) all fixed inline; P3-3 (next_id burn on
  STM_ERANGE rollback) cosmetic at any realistic scale, deferred.**
  Prior: P7-12 truncate fault-free Phase 3 `5eba5de` +
  R44 close `bb5e088` + hash fixup `31ace1c`.
  **P7-12 truncate fault-free Phase 3 — closes R41 P3-1 case (b)
  (the one gap left open by P7-11). Adds `stm_extent_truncate_peek`
  (pure-read count of past-extents + total replicas) and
  `stm_extent_truncate_into` (truncate using caller-provided
  pre-allocated buffers; never allocates internally). `stm_sync_
  truncate` now peek-counts past-extents and pre-allocates Phase 3
  buffers BEFORE Phase 2's overwrite — any ENOMEM surfaces with
  the index unchanged. Phase 3's `_into` cannot fail with ENOMEM;
  composed with P7-11's single-lock-span, the whole truncate is
  atomic w.r.t. concurrent commit/write AND ENOMEM-safe. No format
  break, no spec change. test_extent_index 51 → 55. R44 audit:
  0 P0 + 0 P1 + 0 P2 + 4 P3 — green signal; P3-1 SPEC-TO-CODE
  refinement rows + P3-2 misleading comment + P3-4 zero-before-
  validate convention all fixed inline; P3-3 end-to-end
  ENOMEM-injection test continues R43 P3-2's deferral (needs
  malloc-failure harness, not in v2's test infra yet).**
  Prior: P7-11 truncate _locked atomicity refactor `0a59ab2` +
  R43 close `9af916e` + hash fixup `d874a04`.
  **P7-11 truncate _locked atomicity refactor — `stm_sync_truncate`
  now holds `sync->lock` across all three phases (lookup → read+
  re-encrypt → past-extent drop + drop-route) under one acquisition.
  Closes **R41 P3-1 case (a)** (concurrent `stm_sync_commit` between
  Phase 2 and Phase 3 splits the on-disk view) and **R41 P3-2**
  (scrub-flavored variant). The R41 P3-1 case (b) (Phase 3
  `stm_extent_truncate` STM_ENOMEM after Phase 2 succeeded → partial
  in-RAM state committable by next sync_commit) is **NOT** closed by
  this chunk and remains documented as a deferred POSIX-atomicity
  gap. Refactors `stm_sync_write_extent` / `stm_sync_read_extent`
  into thin public-wrapper + internal `_locked` variant pairs;
  Phase 2 of truncate uses the `_locked` variants under the outer
  lock-hold. Lock-graph unchanged: `sync.lock` OUTER → `extent_idx.lock`
  + per-device `alloc.lock` INNER. No format break, no spec change.
  Trade-off: lock-hold extends across decrypt + encrypt + bdev I/O
  for the crossing extent's prefix; cascades scrub-step latency
  through the verify cb's brief s->lock takes. R43 audit: 0 P0 +
  0 P1 + 0 P2 + 4 P3 — P3-1 (case-(b) docstring overreach) +
  P3-3 (scrub-step throughput cascade) fixed inline via docstring
  honesty pass; P3-2 (regression test for case (b)) deferred until
  the case-(b) fix lands; P3-4 (pre-existing pool.rdlock omission
  on _write/_read_extent_locked's bdev access) explicitly out of
  scope for R43, surfaced for future-chunk pickup.**
  Prior: `394150a` (**P7-10 per-dataset DEKs** — every extent
  now carries a `key_id` field naming which DEK in the dataset's
  keyschema decrypts it; sync resolves DEK by `(dataset_id, key_id)`
  instead of using `metadata_key`. `stm_sync_create` auto-installs
  the root dataset's DEK at format time alongside the pool metadata
  key. Production scrub β cb + send/recv pick the DEK by the
  extent's stamped `key_id` — RETIRED keys remain reachable so
  pre-rotation extents stay decryptable. `stm_sync_keyschema_sweep`
  refuses to prune any RETIRED key with live extent references
  (closes the long-standing P4-4c TODO; maps to
  key_schema.tla::PruneSafety). Format break STM_UB_VERSION
  14 → 15: extent on-disk value's offset-56 slot — the always-zero
  `xxh` field in v13/v14 — is repurposed for `key_id` (le64).
  Spec extension: `extent.tla::ExtentRec` gains `key_id ∈ KeyIds`;
  Write/Overwrite/Truncate stamp it. extent.cfg holds `MaxKeyIds=1`
  to preserve the P7-9 partial-shrink coverage at 838164 states;
  new `extent_keyids.cfg` runs MaxKeyIds=2 at the pre-P7-9 bound
  (67304 distinct states; 5s wall) so spanning-rotation scenarios
  exist in TLC.
  Prior: P7-9 truncate partial-extent split `5530a0e`
  (`stm_sync_truncate` shrinks crossing extent under fresh
  `(paddr_0, current_gen)` nonce). P7-8 snap-gen alignment
  `73019c4` (UB v13 → v14, `extent_txg` field). P7-7 send/recv
  MVP `1122d32`. P7-6 replica-list extension `a958af6` (UB v12
  → v13). Phase 5 tagged `phase-5-complete` at `461e68e`.
  Spec posture: **20 modules / 24 fixed configs / 24 buggy demos**
  (added `extent_keyids.cfg`; no new buggy cfg in P7-10).
- **Phases**: 1–5 complete; Phase 6 namespace layer feature-
  complete; **Phase 7 progressing**.
  Spec scaffolds: P6-1 (bptr.tla) `032db86`; P6-2 (dataset.tla)
  `75f6a3f`; P6-3 (snapshot.tla) `8813027`; P6-4 (property.tla)
  `2b6f248`; P6-5 (clone.tla) `3db8b5e`; P6-6 (dead_list.tla)
  `d568ff7`. C impls: P6-2 dataset `6dbf8f0` + R28 `bdb888b`;
  P6-3 snapshot `34d89f5` + R29 `000d394`; P6-4 property `3527fe2`
  + R30 `8be3628`; P6-persist `348d165` + R31 `bffee62`; P6-clone
  `ee45a0d` + R32 `4503405`; P6-deadlist C impl
  `18b9289` + R33 `d4efeeb`. P6-perf bench `d4c6708`.
  Phase 7 entry: P7-1 spec scaffold (extent.tla) `4eace52`.
  P7-2 extent C impl `732b20e` + R34 close `433d2dd`.
  P7-3 extent persistence `b223975` (R35 audit clean).
  P7-4 fs.c/sync.c COW integration `bb2d666` + R36 close
  `64a6278` — POSIX-shape stm_fs_write / stm_fs_read;
  sync_drop_paddr_locked composes extent.tla::Overwrite +
  dead_list.tla::OverwriteBlock + allocator.tla::Free;
  advance_txg per sync_commit (R35 forward note acted on).
  P7-5 production scrub cb `38e6799` + R37 close `fc5f619` —
  paddr→bptr resolver; AEAD-verify; mapped to bptr.tla's
  NReplicas=1 corner.
  **P7-6 replica-list extension `2eb898d` + R38 close
  `8d0c172` (this commit) — extent record value layout grows
  32B → 64B with up to 4 replica paddr slots (P7-6 / v13).
  `stm_sync_write_extent` reserves N=mirror_n replicas across
  N distinct devices, encrypts ONCE under (replicas[0], gen) and
  copies bytewise-identical ciphertext+tag to every replica.
  `stm_sync_read_extent` walks replicas (first AEAD-OK wins).
  `sync_scrub_verify_cb` realizes bptr.tla's full ScanRead ×
  RewriteReplica matrix: per-replica csum-gate, pick first OK
  source, rewrite non-OK replicas, verify writeback.
  STM_UB_VERSION 12 → 13. Spec extension: extent.tla gains
  `replicas` field, `MaxReplicasPerExtent` constant, and
  `LiveReplicasDisjoint` + `ReplicasNonEmpty` +
  `ReplicaCountBounded` invariants; new buggy demo
  `extent_replica_collision_buggy.cfg`**.
  P7-7 send/recv MVP `a42d84d` + R39 close `73e9f20`
  — new `src/send_recv/` module. Wire format: framed records (16B
  framing + body); HEADER once, EXTENT* with plaintext payload,
  END with BLAKE3 csum over prior bytes. Send decrypts source's
  extents under source pool's metadata_key; recv re-encrypts
  under target's. Single-dataset full-send only at MVP; the
  incremental send was API-wired but with a best-effort filter.
  **P7-9 truncate partial-extent split `ad95a5d` + R41 close
  `5530a0e` (this commit) — closes the long-standing MVP gap
  where `stm_extent_truncate` dropped only fully-past-truncation
  extents, leaving any crossing extent at original full length
  with a stale AEAD-tag-failing read on bytes past `new_size`.
  New `stm_sync_truncate(s, ds, ino, new_size)` reads + decrypts
  the crossing extent's full plaintext, re-encrypts the kept
  `[0, new_size - off)` prefix under FRESH `(paddr_0,
  current_gen)` AEAD nonce via `stm_sync_write_extent`'s overwrite
  path (which drops + drop-routes the original's replicas
  through dead-list / free per the COW pattern), then drops every
  extent past `new_size` via `stm_extent_truncate` + per-paddr
  `sync_drop_paddr_locked`. Spec refinement in
  `extent.tla::Truncate`: branch (a) keeps the existing drop-
  only behavior when no extent crosses; branch (b) replaces the
  single crossing extent (NoOverlapWithinIno guarantees ≤ 1)
  with a shrunk extent at the same off, len = `new_size - off`,
  fresh replicas disjoint from `used_paddrs`, gen = `current_txg`.
  Re-encrypting under fresh paddrs prevents `(paddr, gen)` reuse
  that would otherwise share a nonce between the original full
  ciphertext and the new shrunk-prefix's plaintext. No format
  break. test_fs grows 20 → 26 (6 new tests: crossing-shrink,
  boundary no-op, truncate-to-zero, past-EOF no-op, snapshot
  dead-list routing, args validation). 33 ctest suites green
  default + ASan + TSan in isolated runs. R41 audit:
  0 P0 + 0 P1 + 0 P2 + 5 P3 — P3-3 strict dead-list count + P3-4
  TLC bound bump + P3-5 rec.len defense check fixed inline;
  P3-1/P3-2 documented as known atomicity gaps (deferred to a
  future _locked refactor of write_extent / read_extent).**
  P7-8 snap-gen alignment `4f40743` + R40 close `c9c29ee`
  — closes the P7-7 incremental gap. New 8-byte
  `extent_txg` field on every snapshot entry, captured from
  `sync.current_gen` at SnapshotCreate. Send filters by
  `extent_txg` (same counter space as `extent.gen`) — filter is
  now authoritative when callers follow the documented bracketed
  pattern `commit → snap_create → commit`. Format break v13 → v14
  (snapshot record value layout: SP_VAL_FIXED 44 → 52 with the
  new field at offset 24..32). Spec change: new variable
  `sync_gen` distinct from `current_txg`; `Write` bumps `sync_gen`
  only; `SnapshotCreate` captures `sync_gen` as `snap_extent_txg`;
  invariants `ExtentTxgBoundedBySync` + `ChainExtentTxgOrdered`;
  buggy variant `BuggyExtentTxgUnbounded` + companion config.
  C surface: `stm_snapshot_entry` gains `extent_txg` field;
  `stm_snapshot_create` signature gains `extent_txg` arg + R40
  P2-1 chain-ordering validation under idx->lock; structural
  validator extended; new accessor `stm_sync_current_gen`. R40
  audit: 0 P0 + 0 P1 + 1 P2 + 6 P3 (P2-1 + P3-1/2/4/5/7 fixed
  inline; P3-3 + P3-6 deferred per audit close commit).
  **P7-10 per-dataset DEKs `a3610f2` + R42 close `394150a`
  (this commit) — every extent
  now carries a `key_id` field naming which DEK in the dataset's
  keyschema decrypts it; sync layer resolves DEK by
  `(dataset_id, key_id)` instead of using the per-pool
  `metadata_key`. `stm_sync_create` auto-installs the root
  dataset's DEK as keyschema entry `(1, 0, CURRENT)` alongside
  the pool metadata key `(0, 0)`; non-root datasets continue to
  use `stm_sync_add_dataset_key`. The production scrub β cb and
  send/recv resolve DEK by the extent's stamped `key_id` —
  RETIRED keys remain reachable so pre-rotation extents stay
  decryptable. `stm_sync_keyschema_sweep` walks the extent index
  and refuses to prune any RETIRED key with live extent
  references (closes the long-standing P4-4c TODO; maps to
  key_schema.tla::PruneSafety; the operator can sweep again after
  extents migrate via overwrite / re-encrypt sweep). Format break
  STM_UB_VERSION 14 → 15: extent on-disk value's offset-56 slot
  (the always-zero `xxh` field in v13/v14) is repurposed for
  `key_id` (le64); EX_VAL_LEN stays 64. v14 pools fail at
  uberblock version check before the value layer is reached.
  Spec extension: `extent.tla::ExtentRec` gains `key_id ∈ KeyIds`;
  `Write/Overwrite/Truncate` stamp it. `extent.cfg` holds
  `MaxKeyIds=1` to preserve the P7-9 partial-shrink coverage at
  838164 states; new `extent_keyids.cfg` runs MaxKeyIds=2 at the
  pre-P7-9 bound (67304 distinct states; 5s wall) so
  spanning-rotation scenarios — distinct extents under distinct
  key_ids — are realized in TLC. R42 audit:
  0 P0 + 1 P1 + 2 P2 + 5 P3 — P1-1 mount-fail on tampered CURRENT
  + P2-1 send DEK snapshot at init + scrub race-tolerant OK +
  P2-2 wedged/RO guards on sweep/add/rotate + P3-1 spec invariant
  comment + P3-3 super.h docstring + P3-4 helper docstring fixed
  inline; P3-2 docs-with-substantive-commit + P3-5 extent_full.cfg
  deferred per project conventions.**
  Phase 7 pre-work FastCDC `5cb8900` + R27 close `a2ffd38`.
  Pending: CAS / reflinks (Phase 7 §10.1, §10.4);
  repair log persistence; truncate `_locked` atomicity refactor.
- **Tests**: 33 suites × (default + ASan + TSan, serial) green
  (P7-10 grows test_fs 26 → 31 with four new per-dataset DEK
  tests + R42 P2-2 wedged/RO refuse test; test_keyschema_rotate
  15 → 17 with two new root-DEK tests).
  test_sync_multi 42; test_pool 48; test_scrub 34 (30 + 4 P7-6
  replica-walk); test_alloc 32; test_cdc 12; test_dataset 57;
  test_snapshot 41; test_sync 24;
  test_extent_index 51 (32 in-RAM + 6 persist + 4 lookup_by_paddr +
  9 P7-6 multi-replica); test_fs 31 (P7-10: 4 per-dataset DEK
  tests covering rotation-roundtrip, sweep-refuses-with-refs,
  sweep-after-overwrite-drops-ref, unprovisioned-ds-refused;
  R42 P2-2: keyschema-mutators-refuse-on-RO);
  test_send_recv 13 (4 arg validation + 1 full-send roundtrip +
  1 incremental + 1 swap-rejection + 1 equal-extent_txg + 5
  wire/state-machine error paths).
- **Specs**: 20 TLA+ modules clean (23 fixed configs: legacy +
  scrub_beta + scrub_durable + scrub_beta_durable + bptr +
  dataset + snapshot + property + clone + dead_list + extent) +
  24 buggy-demo configs fire as expected
  (snapshot_extent_txg_unbounded_buggy added in P7-8).
- **LOC**: ~32 KLOC across 24 src/ modules (extent module gains
  `extent_index.c` alongside the Phase 4 `extent.c` AEAD wrapper)
  + 28 public headers.

For phase-level status see `v2/docs/phase{2,3,4,5}-status.md`. The
reference below covers the as-built layers in bottom-up order.

## Contents

| File | Layer | Size guide |
|---|---|---|
| [00-overview.md](reference/00-overview.md) | Layer cake + cross-cutting concerns | medium |
| [01-crypto.md](reference/01-crypto.md) | AEAD, KDF, BLAKE3, PQ-hybrid wrap | large |
| [02-block.md](reference/02-block.md) | stm_bdev backends + fault injection | medium |
| [03-btree.md](reference/03-btree.md) | Single-threaded + rwlock + Bw-tree lock-free | large |
| [04-ebr.md](reference/04-ebr.md) | Epoch-based reclamation | small |
| [05-bootstrap-alloc.md](reference/05-bootstrap-alloc.md) | Two-region allocator | large |
| [06-keyschema.md](reference/06-keyschema.md) | Per-dataset key state machine | medium |
| [07-sb-sync.md](reference/07-sb-sync.md) | Uberblock layout + multi-device commit | large |
| [08-pool-redundancy.md](reference/08-pool-redundancy.md) | Roster + mirror + device lifecycle | large |
| [09-scrub.md](reference/09-scrub.md) | Verify-only sweep + state machine | medium |
| [10-specs.md](reference/10-specs.md) | TLA+ spec catalog + SPEC-TO-CODE dictionary | medium |
| [11-glossary.md](reference/11-glossary.md) | Terms, acronyms, invariant names | small |
| [12-dataset.md](reference/12-dataset.md) | Dataset hierarchy + properties + clones | large |
| [13-snapshot.md](reference/13-snapshot.md) | Snapshot index + clone-check hook | medium |
| [14-extent.md](reference/14-extent.md) | Extent index (P7-2 MVP + P7-3 persistence + P7-4 fs/sync COW path) | medium |

This is a live document — every phase-chunk commit that touches a
subsystem updates the corresponding section in the same PR.

## Document maintenance

When a chunk lands (bug fix, refactor, new module), the author is
responsible for:

1. Updating the relevant reference/NN-*.md section(s).
2. Checking the [Snapshot](#snapshot) figures (tip / phase / test /
   spec counts) still match reality.
3. If the chunk introduces or refutes an invariant, updating
   `10-specs.md`'s SPEC-TO-CODE table.
4. If a new term or acronym enters the lexicon, updating
   `11-glossary.md`.

Reference sections are PR-first like any code change; the audit
policy in `CLAUDE.md` ("spec-first for load-bearing invariants")
extends here: a change to a documented invariant updates the spec
FIRST, then the reference, then the code. If the three disagree,
the spec wins.
