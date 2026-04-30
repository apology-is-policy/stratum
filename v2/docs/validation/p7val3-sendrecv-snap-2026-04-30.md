# P7-VAL-3: send/recv roundtrip with snapshots (2026-04-30)

## Validates

ROADMAP §10.2 exit criterion 3:
> Send + receive roundtrip preserves data + metadata + snapshots.

## Verdict

**MET.** Three new integration tests in `tests/test_send_recv.c` exercise
the full set of preservation properties end-to-end:

- **Data**: every byte written on the source reads back identical on
  the receiver across multiple ino-grain overwrites and snapshot brackets.
- **Metadata**: extent KIND (HOT vs COLD) survives the roundtrip; CAS
  cross-ino dedup grouping survives (one shared chunk on source → one
  shared chunk on receiver with refcount 2).
- **Snapshots**: full + chained-incremental (snap → snap → snap) flow
  produces a receiver state that matches the source's LIVE state at
  every step. The receiver's snapshot graph is built by the caller via
  `stm_snapshot_create` after each `recv_finish + sync_commit` — the
  zfs-style backup pattern.

All three tests pass under default + AddressSanitizer + ThreadSanitizer.

## Environment

- **Tip**: P7-VAL-2 close `12d1d00` plus the new tests in this chunk.
- **Platform**: macOS dev box (Darwin 25.4.0). Tests are
  in-process — `pipe_send_to_recv` directly forwards `stm_send_next`
  output buffers to `stm_recv_apply`, no actual wire transport. The
  send/recv state machine is fully exercised; what's deliberately not
  tested is wire-format byte stability across protocol versions
  (covered by separate `p7cas10_v1_stream_refused_by_v2_receiver` +
  `p7cas16_v2_stream_refused_by_v3_receiver` tests).
- **Compiler**: clang (Xcode), `-DSTRATUM_BUILD_TESTING_HOOKS=ON`.

## Tests added

### 1. `p7val3_full_then_chained_incremental_roundtrip`

Establishes the canonical multi-step send-pipeline:

```
source:                          receiver:
  write A_1 → commit
  snap_1   → commit
  write A_1' + B → commit
  snap_2   → commit
  write A_1'' + C → commit
  snap_3   → commit
                                   full send (source LIVE state)
                                   verify A_1'', B, C
  write B' + D → commit
  snap_4   → commit
                                   incremental(snap_3 → snap_4)
                                   verify A_1'', B', C, D
                                   create receiver snap_4_replica
  write C' → commit
  snap_5   → commit
                                   incremental(snap_4 → snap_5)
                                   verify A_1'', B', C', D
```

After each apply the receiver's bytes match the source's LIVE state
across every ino. Demonstrates that the snapshot graph on the source
serves as a stable reference for incremental sends, and that the
receiver can replicate the source's snapshot graph via caller-driven
`stm_snapshot_create` after each `recv_finish`.

### 2. `p7val3_roundtrip_preserves_hot_cold_extent_kinds`

Source contains:
- ino 1: one HOT extent → migrated to COLD (1 record total)
- ino 2: one HOT extent → never migrated (1 HOT record)
- ino 3: two non-contiguous HOT extents → migrated to COLD (2 records)

(Sparse offsets on ino 3 force the per-extent migrate fallback —
P7-CAS-17's cross-extent FastCDC requires contiguity, so two
non-contiguous extents produce two distinct COLD records rather
than collapsing to one.)

After full send → recv, the receiver's extent index has identical
kind counts per ino:

```
src: ino 1 = 0 HOT / 1 COLD     →   recv: ino 1 = 0 HOT / 1 COLD
src: ino 2 = 1 HOT / 0 COLD     →   recv: ino 2 = 1 HOT / 0 COLD
src: ino 3 = 0 HOT / 2 COLD     →   recv: ino 3 = 0 HOT / 2 COLD
```

The `STM_SEND_FLAG_COLD` wire-format bit (P7-CAS-9) and the
`STM_SEND_REC_CHUNK` out-of-band record (P7-CAS-10) carry the kind
metadata across the wire correctly.

### 3. `p7val3_roundtrip_preserves_cross_ino_cold_dedup`

Two source inos write byte-identical content; both migrated to COLD;
on source they collapse to one CAS chunk with refcount 2.

After full send → recv, the receiver's CAS index has **exactly one
entry** (refcount 2) — the on-the-wire dedup property from P7-CAS-10
preserves the cross-ino cold-tier dedup grouping at rest on the
target, not just at the wire layer.

This is the strongest version of the dedup-preservation property:
the target ends up with the same dedup compression as the source,
not redundantly-stored copies.

## Pre-existing tests covered by this validation

The new tests build on top of an extensive existing suite:

- `full_send_roundtrip_three_extents` — basic full send roundtrip.
- `incremental_send_filters_by_extent_txg` — snapshot-bracketed
  incremental filter using `extent_txg = sync.current_gen`.
- `incremental_send_includes_reflink_in_window` — reflink survives
  send.
- `p7cas9_*` (5 tests) — COLD extent send/recv, including the
  hash-mismatch refusal path.
- `p7cas10_*` (10 tests) — chunk-store wire shape, including
  pre-populated target dedup, orphan-chunk reclamation, and refusal
  of malformed streams.
- `p7cas16_*` (2 tests) — recordsize-bumped (8 MiB) send/recv
  roundtrip + version-refusal.

Combined with the new P7-VAL-3 tests, `test_send_recv` now contains
**40 tests** covering arg validation, full + incremental send, COLD
+ HOT extent kinds, cross-ino dedup, multi-snapshot chains, version
gating, and adversarial wire-corruption.

## Methodology

Tests run via the standard ctest harness:

```
cmake --build build --target test_send_recv
build/tests/test_send_recv
```

Reproducibility verified across three sanitizer modes (default
build, ASan, TSan) — all 38 tests in test_send_recv green
under each.

## Cost

Local macOS dev box, tests run in ~10 sec total. $0.

## What this does NOT validate

- **Wire-stable cross-version replay** — covered by separate
  protocol-version refusal tests (`p7cas10_v1_stream_refused_by_v2_receiver`,
  `p7cas16_v2_stream_refused_by_v3_receiver`) but no
  forward-compat-replay test exists.
- **Long-running send under concurrent source writes** — the
  stale-paddr race documented in send_recv.h §MVP caveats applies;
  tested at the unit level via `p7cas9_*` but not in a full chaotic-
  workload integration test (Phase 9 territory).
- **Resumable receive** — not in scope per send_recv.h §"Out of
  scope (future chunks)".
- **Cross-host wire transport** — the bench is in-process. Real
  network transport (chunked TCP framing, partial sends, slow
  receivers) is Phase 8 client-interface work.
- **Compression on the wire** — also Phase 8+.
