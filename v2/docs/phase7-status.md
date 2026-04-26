# Phase 7 — status and pickup guide

Authoritative pickup guide for Phase 7 (Cold tier + features).
**Phase 7 not yet entered**; ROADMAP §10.4 dependencies require
Phase 6 (namespaces) to land first.

This document scaffolds the **P7 pre-work** that can begin in
parallel with Phase 6 — items that don't depend on P6 deliverables
and can therefore be built independently of the namespace layer.

## P7 pre-work: FastCDC chunking (P6-independent)

ROADMAP §10.1 lists FastCDC under `src/cdc/` as a Phase 7
deliverable. The chunking algorithm itself has no P6 dependency
— it's a pure-function content-defined chunker. The integration
into the CAS tier (which DOES need P6) is a separate concern.

### Why pre-work is safe

- FastCDC is a deterministic algorithm operating on a byte stream.
- Output: chunk boundaries (offsets) + content hashes per chunk.
- No dependency on extents, datasets, snapshots, or CAS index.
- The library can be tested standalone with synthetic byte streams.

### Recommended scope for the pre-work chunk

- **Spec**: optional. FastCDC's correctness properties are
  testable rather than spec-needed (deterministic, shift-resistant
  per NOVEL #3, average chunk size ≈ target, min/max bounded).
  A cdc.tla spec could pin the shift-resistant property if
  desired; lower priority than other P6 specs.
- **Impl**: `v2/src/cdc/cdc.{h,c}` — FastCDC implementation per
  the canonical Yu/Yi/Zhang algorithm with Gear hashing. Configurable
  avg / min / max chunk size. NOVEL #3 mentions 8 MiB average as
  the default target.
- **Tests**: `v2/tests/test_cdc.c` — determinism (same input →
  same boundaries); shift-resistance (insert N bytes at start,
  verify > (1 - small_fraction) of post-shift chunk boundaries
  match the original); chunk-size distribution within bounds.
- **Reference doc**: new `v2/docs/reference/12-cdc.md` (numbering
  TBD depending on what Phase 6 adds first).

### NOT in scope for pre-work

- CAS index tree (needs bptr).
- Migration engine (needs dataset/extent infrastructure).
- Rehydration-on-write (touches the write path, depends on P6
  extent manager).

## Phase 7 status (overall)

- [ ] FastCDC pre-work — **available now, P6-independent**.
- [ ] CAS tier — blocked on P6.
- [ ] Send / recv — blocked on P6 (birth-txg from snapshots).
- [ ] Reflinks — blocked on P6 (dataset/file abstraction).
- [ ] Migration engine — blocked on P6 + CAS tier.

## ROADMAP §10.2 exit criteria

Status: untouched. Phase 7 not yet entered.

- [ ] Cold-tier dedup achieves target 3-5× on VM-image test set.
- [ ] Migration policy heuristic produces reasonable hot/cold
      placement on synthetic workloads.
- [ ] Send + receive roundtrip preserves data + metadata +
      snapshots.
- [ ] Reflink is O(extent count) not O(data size).

## Operational notes

- Pre-work chunks land into the v2 tree under `src/cdc/` with a
  CMake target. They participate in the standard test matrix
  (default + ASan + TSan).
- FastCDC pre-work doesn't bump `STM_UB_VERSION` (no on-disk
  format change at this stage; CAS tier integration in proper
  Phase 7 will).
- The pre-work isn't gated by P6 entry; once the user signs off
  on it, an autonomous chunk can land.
