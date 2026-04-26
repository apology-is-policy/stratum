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

- **Tip**: `d4efeeb` (P6-deadlist C impl: snapshot
  module gains in-line dead-list under `stm_snapshot_index_*`,
  `stm_snapshot_delete` now returns the freed-paddr list, format
  bumped 10 → 11 for the snapshot value tail). Phase 5 tagged
  `phase-5-complete` at `461e68e`. Spec posture: **19 modules /
  22 fixed configs / 19 buggy demos**.
- **Phases**: 1–5 complete; **Phase 6 progressing**.
  Spec scaffolds: P6-1 (bptr.tla) `032db86`; P6-2 (dataset.tla)
  `75f6a3f`; P6-3 (snapshot.tla) `8813027`; P6-4 (property.tla)
  `2b6f248`; P6-5 (clone.tla) `3db8b5e`; P6-6 (dead_list.tla)
  `d568ff7`. C impls: P6-2 dataset `6dbf8f0` + R28 `bdb888b`;
  P6-3 snapshot `34d89f5` + R29 `000d394`; P6-4 property `3527fe2`
  + R30 `8be3628`; P6-persist `348d165` + R31 `bffee62`; P6-clone
  `ee45a0d` + R32 `4503405`; **P6-deadlist C impl
  `18b9289` + R33 `d4efeeb` (this commit)**.
  Phase 7 pre-work FastCDC `5cb8900` + R27 close `a2ffd38`.
  Pending: production scrub cb (still blocked on paddr→bptr
  resolver, which arrives with extents); sync.c integration of
  OverwriteBlock cb (production callers come with extents in P7);
  perf bench harness.
- **Tests**: 31 suites × (default + ASan + TSan, serial) green.
  test_sync_multi 42; test_pool 48; test_scrub 30; test_alloc 32;
  test_cdc 12; test_dataset 57; test_snapshot 40; test_sync 24.
- **Specs**: 19 TLA+ modules clean (22 fixed configs: legacy +
  scrub_beta + scrub_durable + scrub_beta_durable + bptr +
  dataset + snapshot + property + clone + dead_list) + 19
  buggy-demo configs fire as expected.
- **LOC**: ~31 KLOC across 26 src/ modules + 28 public headers.

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
