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

- **Tip**: `<TBD-P7-7-fixup>` (**P7-7 send/recv MVP** — full-send
  byte-stream protocol with HEADER + EXTENT records + END+csum;
  `stm_send_init/_next/_close` produces wire bytes, `stm_recv_init/
  _apply/_finish/_close` consumes them; recv re-encrypts each extent
  under the target pool's metadata key — no cross-pool nonce reuse;
  BLAKE3 end-of-stream csum gates authenticity; new module
  `src/send_recv/`). Prior: P7-6 replica-list extension —
  extent records grow 32B → 64B with up to 4 replica paddrs;
  `stm_sync_write_extent` allocates N replicas across N devices;
  scrub β cb walks replicas + repairs corrupt ones per bptr.tla's
  full `ScanRead` × `RewriteReplica` matrix; `STM_UB_VERSION`
  12 → 13). Phase 5 tagged `phase-5-complete` at `461e68e`.
  Spec posture: **20 modules / 23 fixed configs / 23 buggy demos**
  (extent.tla extended with `replicas` field + `LiveReplicasDisjoint`
  invariant; new `extent_replica_collision_buggy.cfg`).
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
  **P7-7 send/recv MVP `<TBD-substantive>` + R39 close `<TBD-close>`
  (this commit) — new `src/send_recv/` module. Wire format: framed
  records (16B framing + body); HEADER once, EXTENT* with plaintext
  payload, END with BLAKE3 csum over prior bytes. Send decrypts
  source's extents under source pool's metadata_key; recv re-
  encrypts under target's. Single-dataset full-send only at MVP;
  incremental send is API-wired but the snap-bounded gen filter is
  best-effort until snap.created_txg ↔ sync.current_gen alignment
  lands (anticipated v13 → v14 format break).** No format break in
  P7-7; STM_UB_VERSION stays at 13.
  Phase 7 pre-work FastCDC `5cb8900` + R27 close `a2ffd38`.
  Pending: CAS / reflinks (Phase 7 §10.1, §10.4); per-dataset DEKs;
  incremental send alignment.
- **Tests**: 33 suites × (default + ASan + TSan, serial) green
  (P7-7 adds test_send_recv = 10 tests).
  test_sync_multi 42; test_pool 48; test_scrub 34 (30 + 4 P7-6
  replica-walk); test_alloc 32; test_cdc 12; test_dataset 57;
  test_snapshot 41; test_sync 24;
  test_extent_index 51 (32 in-RAM + 6 persist + 4 lookup_by_paddr +
  9 P7-6 multi-replica); test_fs 20; test_send_recv 10 (4 arg
  validation + 1 full-send roundtrip + 5 wire/state-machine error
  paths).
- **Specs**: 20 TLA+ modules clean (23 fixed configs: legacy +
  scrub_beta + scrub_durable + scrub_beta_durable + bptr +
  dataset + snapshot + property + clone + dead_list + extent) +
  23 buggy-demo configs fire as expected (extent_replica_collision_buggy
  added in P7-6).
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
