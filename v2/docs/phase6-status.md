# Phase 6 — status and pickup guide

Authoritative pickup guide for Phase 6 (Namespaces). **Phase 6
entered 2026-04-26** after Phase 5 substantively complete (tag
`phase-5-complete` at `461e68e`). Companion to `phase5-status.md`,
which documents the multi-device + redundancy layer Phase 6 builds
on.

## TL;DR

Phase 6 = ARCH §6 (namespace layer) + ROADMAP-V2 §9. Adds:

- Dataset hierarchy (subvolumes, properties, inheritance).
- Snapshot mechanics via birth-txg (O(1) snapshot create).
- Clones (writable snapshots).
- Dead-list maintenance for snapshot delete.
- The bptr layer that all of the above rests on.

Phase 6 also picks up three P5 carry-overs per ROADMAP §9.6:

- **Production scrub verify-callback** (bptr-aware): plug a
  real `stm_scrub_set_verify_cb` cb that walks the replica list,
  verifies AEAD/csum, rewrites the bad device, emits the repair-
  log entry. Closes the production aspect of P5 exit criterion #3.
- **P5-4c-β reconstruct**: FAULTED → new replace via bptr
  iteration. Today STM_ENOTSUPPORTED.
- **P5-4d-β reconcile**: bring stale FAULTED-rejoined content
  current via bptr-driven catch-up. Today depends on majority-
  quorum mirror_read.

| Commit | What | Tests |
|---|---|---|
| `032db86` | P6-1 spec scaffold: `bptr.tla` (production scrub cb protocol) + 1 fixed cfg + 2 buggy cfgs. Spec-only landing per CLAUDE.md spec-first; production cb impl waits for paddr→bptr resolver. | TLC: bptr 29 states/depth 8 clean; 2 buggy demos fire NoSilentCorruption + WriteVerifyMandatory respectively. Total spec posture: 14 modules / 17 fixed cfgs / 8 buggy cfgs. |

## ROADMAP §9.2 exit criteria status

Status as of Phase 6 entry (2026-04-26):

- [ ] Snapshot create < 10 ms regardless of dataset size.
- [ ] Snapshot delete's work proportional to blocks freed, not
      total tree.
- [ ] Clone + writes + COW produce correct divergence.
- [ ] Property inheritance resolves correctly across multi-level
      datasets.
- [ ] Datasets survive mount/unmount round-trips.

## Recommended P6 entry path

Per the post-P5 handoff (`memory/project_v2_next_session.md`),
the leverage-maximizing first chunk is **production-default scrub
verify-callback (option B)**:

- Closes the last piece of P5 exit criterion #3 (scrub
  detect+repair production aspect).
- Establishes the **bptr layer** (`stm_bptr` resolution +
  walking + replica iteration) that all subsequent P6 work
  (dataset index, snapshot mechanics, dead-list) depends on.
- Naturally unblocks the other two §9.6 carry-overs (P5-4c-β +
  P5-4d-β reconstruct/reconcile) as a follow-on.

After the bptr layer + scrub cb land, the natural P6-1 chunk is
the **dataset index tree** — small, isolated, mostly btree wiring
with a new key/value layout (dataset_id → dataset metadata
record).

## Spec-first work

Per CLAUDE.md, every load-bearing P6 invariant gets a TLA+ spec
before code. Candidate specs:

- `dataset.tla` — dataset index tree's structural invariants;
  `parent_dataset_id` chain forms a forest (no cycles); birth-txg
  ≤ current commit gen.
- `snapshot.tla` — snapshot create is structurally O(1) (no tree
  copy); birth-txg-based incremental diff is correct;
  dead-list maintenance is incremental (not delete-walk).
- `bptr.tla` — replica-list walking + AEAD-csum verification +
  rewrite-bad-replica protocol. Captures the production scrub cb
  logic at the spec level.

## Phase 6 deliverables (ROADMAP §9.1, abridged)

- **Dataset layer** (`src/dataset/`): index tree + property
  system + create/destroy/rename/move.
- **Snapshot mechanics**: birth-txg in every tree node + extent
  record; snapshot index tree; visibility via `.snaps/<name>/`;
  holds.
- **Dead-list maintenance**: per-snapshot dead lists +
  incremental updates on COW.
- **Clones**: O(1) create, promote, destroy.
- **Tests**: snapshot create < 10ms; snapshot delete proportional
  to freed blocks; clone divergence; property inheritance.

## Phase 6 dependencies

- Phase 3 persistence ✅
- Phase 4 crypto (per-dataset keys) ✅
- Phase 5 multi-device + redundancy ✅ (substantively complete)

## Parallel opportunities

ROADMAP §9.5: dataset + snapshot + clone lifecycles can be built
in parallel with dead-list implementation.

**P7 pre-work parallel** (NEW): FastCDC chunking (`src/cdc/`,
ROADMAP §10.1) is genuinely P6-independent — it's a pure
algorithm + module. Can be developed standalone in parallel with
P6 work, ready to plug into the CAS tier when Phase 7 starts.
See `phase7-status.md` for the FastCDC pre-work plan.

## Operational notes

- Format breaks (e.g., new `ub_dataset_root` field for the
  dataset index) require user signoff per CLAUDE.md autonomy
  rules. STM_UB_VERSION currently 8.
- Audit-per-change applies: every chunk gets its own audit round
  starting at R27.
- Reference doc upkeep: per CLAUDE.md, every commit that touches
  documented surface updates the relevant `v2/docs/reference/NN-*.md`
  in the same PR. Phase 6 will introduce new reference files
  (probably 12-dataset.md, 13-snapshot.md, 14-bptr.md).
- Two-commit close pattern: substantive close + hash fixup.
- Spec-first per CLAUDE.md.
