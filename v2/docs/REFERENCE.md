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

- **Tip**: `a6249eb` (R26 / P5-durable-cursors scope close —
  γ scrub durable cursor + STM_UB_VERSION 7→8 fully audited.
  R26 closed clean at 0 P0 / 1 P1 (β + γ-reopen
  CallbackSetExclusivity) / 3 P2 / 5 P3, all addressed.
  **Phase 5 substantively complete**: exit criteria 1, 3, 4, 5 met;
  #2 (LRC vs RS) explicitly post-v2.0 per ROADMAP §8.6.).
- **Phases**: 1–4 complete; Phase 5 substantively complete after
  P5-durable-cursors lands (γ closes the in-Phase-5 work; remaining
  P6 carry-overs documented in ROADMAP §9.6, post-v2.0 carry-overs
  in §14).
- **Tests**: 28 suites × (default + ASan + TSan, serial) green.
  test_sync_multi 42; test_pool 47; test_scrub 29; test_alloc 32.
- **Specs**: 13 TLA+ modules clean (15 fixed configs: legacy + scrub_beta + scrub_durable)
  + 6 buggy-demo configs fire as expected.
- **LOC**: ~26 KLOC across 21 src/ modules + 25 public headers.

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
