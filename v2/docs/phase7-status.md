# Phase 7 — status and pickup guide

Authoritative pickup guide for Phase 7 (extent layer + cold tier
+ features). **Phase 7 ENTERED 2026-04-26** at `4eace52` after
Phase 6 namespace layer landed feature-complete (`a4add6d`).

ROADMAP §10 lists FastCDC + CAS + send/recv + reflinks as the §10.1
deliverables. Hot-tier extent records — the missing data layer
between datasets and stored bytes — are a P7 prerequisite that
ROADMAP §10 implicitly assumes; no §10 deliverable can land
without them. P7 entry begins with `extent.tla` and the
extent-module C impl.

This document also scaffolds the **P7 pre-work** that began in
parallel with Phase 6 — items that didn't depend on P6 deliverables
and were built independently of the namespace layer.

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

- [x] **FastCDC pre-work** — landed at `5cb8900`; R27 close
      `a2ffd38` (0 P0 / 1 P1 / 4 P2 / 4 P3, all addressed
      except P2-4 / P3-2 / P3-4 deferred per audit close commit
      message). `src/cdc/cdc.{h,c}` + 12 tests on `tests/test_cdc.c`
      covering arg validation, determinism, shift-resistance (90%
      boundary match after 71-byte prepend), chunk-size
      distribution, forced-cutoff path, edge cases. Default + ASan
      + TSan all green.
- [x] **P7-1 spec scaffold: `extent.tla`** — landed at `4eace52`.
      Per-(ds, ino) extent layout: Write / Overwrite / Truncate /
      DeleteFile / AdvanceTxg actions; load-bearing invariant
      `NoOverlapWithinIno` plus LengthPositive / BirthTxgBound /
      AllExtentsInBounds / PaddrFreshness. Three buggy variants
      (`extent_overlap_buggy`, `extent_zero_length_buggy`,
      `extent_overwrite_forgets_drop_buggy`) all fire as designed.
      TLC: 1216 distinct states / depth 6 (MaxDatasets=1, MaxInos=2,
      MaxFileBlocks=2, MaxPaddrs=3, MaxTxg=1). Spec posture
      19/22/19 → 20/23/22.
- [x] **P7-2 extent C impl** — landed at `732b20e`; R34 close
      `433d2dd` (0 P0 / 0 P1 / 4 P2 / 4 P3 — P2-1 (out-arg
      zeroing on idx==NULL), P2-3 (iter cb pointer-retain doc),
      P3-1 (iter return-code doc) + P3-2 (advance_txg NULL test)
      fixed inline; P2-2 (concurrent-stress scope) + P2-4
      (cb-NULL-check pre-lock; already correct) + P3-3 (size_t
      overflow guard) + P3-4 (mutexattr return code) deferred per
      audit close commit message). New `src/extent/extent_index.c`
      module
      realizing extent.tla against an in-RAM map; the AEAD wrap
      helpers in `src/extent/extent.c` (Phase 4) coexist
      unchanged. Public API surface: `stm_extent_index_create /
      _close / _current_txg / _advance_txg`, `stm_extent_write /
      _overwrite / _truncate / _delete_file / _lookup_at / _iter
      / _count / _count_for_ino`. ERRORCHECK mutex with must_lock /
      must_unlock contract. `test_extent_index` 32 tests covering
      lifecycle + every spec action + every documented error
      path + concurrent stress. Default + ASan + TSan all green.
- [x] **P7-3 extent persistence** — landed at `b223975` (R35 audit
      clean: 0 P0 / 0 P1 / 0 P2 / 5 P3 deferred — bundled into
      substantive). STM_UB_VERSION 11 → 12. New UB
      fields `ub_extent_root` (64-byte stm_bptr at offset 3128) +
      `ub_extent_root_gen` (le64 at offset 3192) carved from the
      head of `ub_reserved`. New `STM_BPTR_KIND_EXTENT_TREE = 10`.
      Single unified Bε-tree under `ub_extent_root` keyed by
      `(le64 ds || le64 ino || le64 off)`, valued by 32-byte
      ARCH §11.6.1 record. Same envelope as ub_main_root /
      ub_snap_root: btree_store-encoded, AEAD-encrypted with
      nonce `paddr || gen || pool_uuid` + AD `pool_uuid ||
      device_uuid_0`. Idempotent commit via internal dirty flag;
      atomic shadow-swap on load_at; structural validator
      enforcing NoOverlapWithinIno + paddr-disjointness on the
      loaded shadow. MVP cap: 24-bit length (≤ 16 MiB - 1, far
      above any realistic recordsize). xxh = 0 (AEAD tag is
      integrity); compression = 0 (no compression in MVP).
      Sync.c wire-in: `stm_extent_index *extent_idx` field +
      mirror fields, `compute_merkle_root` extended to fold
      extent_csum, `build_uberblock` extended with extent_root
      params, hydration on `sync_open` from ub_extent_root,
      commit on `sync_commit`, close on `sync_close`. New
      accessor `stm_sync_extent_index`. v11 pools refused at v12
      mount via uniform STM_EBADVERSION (existing handler).
- [ ] **P7-4 dataset COW path integration** — pending. fs.c / sync.c
      integration: extent writes trigger
      `stm_snapshot_index_overwrite_block(paddr)` on each dropped
      paddr from `_overwrite` / `_truncate` / `_delete_file`
      (composes with dead_list.tla via the C-impl boundary).
- [ ] **P7-5 production scrub cb** — pending. Now unblocks (paddr→
      bptr resolver becomes implementable via extent walk over the
      persistent extent index). Integration concern only.
- [ ] CAS tier — pending; needs extent layer + integration.
- [ ] Send / recv — pending; needs extent layer + birth-txg from
      snapshots (already in place from P6).
- [ ] Reflinks — pending; needs extent layer + refcount-bump path.
- [ ] Migration engine — pending; needs CAS tier.

## ROADMAP §10.2 exit criteria

Status: untouched. Phase 7 not yet entered.

- [ ] Cold-tier dedup achieves target 3-5× on VM-image test set.
- [ ] Migration policy heuristic produces reasonable hot/cold
      placement on synthetic workloads.
- [ ] Send + receive roundtrip preserves data + metadata +
      snapshots.
- [ ] Reflink is O(extent count) not O(data size).

## Operational notes

- Pre-work chunks landed into the v2 tree under `src/cdc/` with
  CMake target; participate in the standard test matrix (default
  + ASan + TSan).
- P7-1 spec scaffold landed; no STM_UB_VERSION bump (spec-only).
- P7-2 (extent C impl) WILL bump STM_UB_VERSION when persistence
  comes in — likely 11→12 when the extent btree's value layout
  is committed. Format-break user signoff required per CLAUDE.md.
- Audit-per-change pattern: R34 closed P7-2 at `433d2dd`. R35
  reserved for the next P7 chunk.
