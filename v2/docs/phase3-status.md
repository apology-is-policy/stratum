# Phase 3 — status and next-session guide

Authoritative pickup guide for Phase 3 (persistence + allocator). Last
update 2026-04-21 (after chunk 6 / four-phase commit protocol
landed). Companion to `phase2-status.md`, which remains the reference
for the Bw-tree layer Phase 3 builds on.

## TL;DR

Phase 3 is in progress. Eleven chunks landed (R7d audit in-flight on
chunk 6):

| Commit | What | Tests |
|---|---|---|
| `4d87fb7` | Uberblock format (4 KiB struct, BLAKE3 csum) + label layout + `stm_bptr` + encode/decode | 12 sb tests |
| `2290d49` | Device-backed label I/O + mount_scan (single-device authoritative selection) | +5 bdev-backed tests |
| `cf52a1f` | `allocator.tla` spec: refcount + deferred-free safety. TLC clean (3729 states, depth 16) | — |
| `37a3be7` → `dd86a63` | **Chunk 4a + R7a**: bootstrap-pool allocator (bitmap-managed, ping-pong hdr+bm slots, PENDING deferred-free matching `allocator.tla`'s Commit rule). R7a closed (0 P0 / 2 P1 / 3 P2 / 3-of-6 P3). | 18 bootstrap tests |
| `3d9bcd0` | **Chunk 4b-1**: rename bootstrap module (stm_alloc → stm_bootstrap) to free the `stm_alloc` name for the main allocator. Pure mechanical refactor. | 18 bootstrap tests |
| `6651830` → `14afe3c` | **Chunk 4b-2 + R7b**: `stm_alloc` top-level allocator. Wraps `stm_bootstrap` + `stm_btree_mt`; data-area tree keyed by BE-packed u64 start_block, value {le32 length_blocks; le32 refcount}. R7b closed (0 P0 / 3 P1 / 3 P2 / 6-of-7 P3). | 15 alloc tests |
| `bd52837` | **Chunk 5a**: `stm_btnode` leaf node codec. Fixed 128 KiB layout: header (128 B) + packed entries + BLAKE3-256 csum. | 13 btnode-leaf tests |
| `1aae3f2` | **Chunk 5b**: `stm_btnode` internal node codec. Pivots + N+1 child bptrs (64 B each). Message buffer deferred. | +7 btnode-internal tests |
| `0d99eb5` | **Chunk 5c**: `stm_btree_store` serialize/deserialize + free_tree via an I/O vtable. Two-level depth cap; snapshot-style rewrite-on-commit. | 5 btree_store tests |
| `033bb3f` → `17e08be` | **Chunk 5d + R7c**: `stm_alloc` integration — tree now persists across mount. R7c closed (0 P0 / 2 P1 / 6 P2; btnode common-helper consolidation). | +3 alloc persistence tests |
| `00d796e` | **Chunk 6**: `stm_sync` — four-phase commit protocol (sync.tla-aligned). Ring rotation `(gen % 4, gen % 63)`, MountGenBump on open, ub_alloc_root now authoritative. | 8 sync tests |

Phase 2 is complete (SPLIT + MERGE + per-node consolidator + SCAN + R0-R6
audits). Phase 3 chunks remaining:

1. **Allocator acceleration** — 4a (bootstrap) + 4b (tree) +
   5 (serialization) + 6 (commit protocol) all landed.
   Remaining allocator sub-chunks:
   - **Chunk 4c**: SDArray in-RAM bitmap for O(1) allocation queries.
   - **Chunk 4d**: xor filter for negative lookups.
   - **Chunk 4e**: R7 full-stack audit (after 4c+4d).
2. **Mount / unmount integration (chunk 7)** — the end-to-end
   user-facing lifecycle: `stm_fs_open` / `stm_fs_mount` /
   `stm_fs_unmount` wiring labels + sync + allocator. Single-device
   round-trip. Main tree (ub_main_root) is still zero until a
   higher-level FS ABI lands post-Phase-3.
3. **Crash-injection fuzzer (chunk 8)** — Phase 3 exit criterion.
   Inject partial writes at every commit phase; verify mount
   recovers to a consistent state.
4. **R7 audit series** — R7a (bootstrap), R7b (alloc 4b), R7c
   (chunk 5 serialization), R7d (chunk 6 sync) all closed or
   in-flight as they land; full R7 at end of 4c/4d for in-RAM
   acceleration.

## You have autonomy

The user has explicitly given autonomous operating permission under
the same terms used throughout Phase 2: **"proceed autonomously
unless there's a decision point that you feel needs my input or you
are forced to diverge from the architecture for good reasons."**

Concretely this means:

- **Commit and push to `main`** when a chunk is complete with tests
  green on default / ASan / TSan / Werror. The user expects forward
  momentum between sessions.
- **Spawn R-audit agents in the background** per CLAUDE.md policy
  when you touch a surface on the audit-trigger list. R6 was the
  last; R7 is yours for whatever substantive code you land in P3.
  Include the R0-R6 closed list (`memory/audit_v2_r0_closed_list.md`)
  as a do-not-report preamble in the agent prompt.
- **Update the closed list** after each audit round so future rounds
  can skip the preamble.
- **Propose scope amendments to the roadmap** when they're the right
  call (as happened with Phase 2's node serialization → Phase 3
  move). Keep amendments surgical and write the rationale inline in
  `docs/ROADMAP-V2.md`.
- **Update `phase3-status.md`** and the memory pointer files as
  chunks land.

Ask for user input only on genuine decision points: architectural
pivots, irreversible actions, scope debates where the answer isn't
obvious from `docs/ARCHITECTURE.md`.

## Build + verify commands

```bash
cd v2

# Default build + all 11 suites
cmake -B build -S . -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure

# TSan
cmake -B build-tsan -S . -DSTM_SANITIZE=tsan \
    -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build-tsan -j
ctest --test-dir build-tsan --output-on-failure

# ASan
cmake -B build-asan -S . -DSTM_SANITIZE=asan \
    -DSTM_ENABLE_IOURING=OFF -DSTM_ENABLE_PQ=OFF
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure

# Long-form TSan stress (1 hour; 2s default when env unset)
STM_BT_LF_LONG_SEC=3600 ctest --test-dir build-tsan -R btree_lf --timeout 4000

# All TLA+ specs
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
cd specs
for s in sync concurrency structural balanced merge allocator; do
    echo "== $s =="
    java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
        -config $s.cfg $s.tla 2>&1 | tail -3
done

# Opt-in benchmarks (throughput + scaling)
cmake -B build-bench -S . -DSTM_BUILD_BENCHES=ON
cmake --build build-bench -j
build-bench/bench/bench_btree_lf
```

Expected TLC results:
- `sync.tla` — 4-phase commit, single-device. Clean under defaults.
- `concurrency.tla` — MVCC + EBR + deltas. 3150 states, 4 invariants.
- `structural.tla` — SPLIT atomic visibility + cascade. ~5120 states.
- `balanced.tla` — parent-pivot update. 65536 states, depth 18.
- `merge.tla` — empty-leaf reabsorb. 65536 states, depth 18.
- `allocator.tla` — refcount + deferred-free. 3729 states, depth 16.

## Next chunk — mount/unmount integration (chunk 7)

Chunk 6 landed: stm_sync implements the four-phase commit protocol
per sync.tla; ub_alloc_root now authoritative; MountGenBump wired.

### Chunk 7 (next): mount / unmount integration.

Chunk 6 delivered the low-level machinery (create/open/commit/close)
but doesn't yet wire a user-facing FS lifecycle. Chunk 7 scope:

- **`stm_fs`** top-level handle aggregating stm_alloc + stm_sync +
  (future) main-tree + (future) crypto state.
- **`stm_fs_mount(path, opts, out_fs)`** — opens bdev, creates or
  opens the allocator, opens the sync layer, returns a ready
  handle.
- **`stm_fs_unmount(fs)`** — final commit, close sync, close
  allocator, close bdev.
- **Wedged / read-only runtime guards** (from v1 heritage per
  CLAUDE.md's invariants list) — `STM_FS_GUARD_READ` /
  `STM_FS_GUARD_WRITE` macros at every public entry.
- **Single-device round-trip** is the first acceptance test:
  mount → reserve → commit → unmount → mount → observe state.

Post-chunk-7, the stm_alloc user_data slot becomes dead weight and
can be removed in a cleanup pass.

### Chunk 4c: In-RAM succinct bitmap (SDArray).
- Performance structure. `src/alloc/sdarray.c`. Approximate
  "is block X allocated" in O(1). Reduces tree walks.
- Target: ~20 MiB RAM per TiB of data.

### Chunk 4d: xor filter for negative lookups.
- 9 bits per allocated range, <1% false-positive rate. Fast
  "is this paddr in any live range?"

### Chunk 4e: R7 full-stack audit.
- Closes the allocator subsystem's audit rounds after the in-RAM
  acceleration structures are in place.

### Chunk 8: Crash-injection fuzzer (Phase 3 exit criterion).
- Inject partial writes at every commit phase; verify mount
  recovers to a consistent state.

### MVP restrictions carrying forward:
- Single-block bootstrap bitmap → bootstrap pool capped at 4 GiB.
- Single-device: paddrs return device = 0. The allocator-roots
  object (per §6.3.2) will add device indirection once we move to
  multi-device.
- Two-level allocator-tree depth cap from chunk 5c.
- Snapshot-style tree serialization (every commit rewrites every
  node) — incremental is a post-Phase-3 optimization.

## Trip hazards carried in from phases 1 and 2

See `phase2-status.md` for the full list of 15 Bw-tree-layer trip
hazards. A few that survive into Phase 3:

1. **`atomic_init` on every `_Atomic` field** even if calloc zeroed
   the memory (C11 §7.17.2.1). All the Bw-tree allocators do this;
   new allocator code must too.
2. **Lock order is slot → structural.** Applies to the Bw-tree.
   If the allocator uses `stm_btree_lf` for its tree, it inherits
   this order. Any allocator-specific lock must be orthogonal or
   acquired before the slot lock.
3. **Bootstrap pool non-recursion is load-bearing.** Allocator-tree
   nodes live in the bootstrap pool and never produce allocator-tree
   entries. If you ever see "allocate block for allocator-tree
   growth → update allocator-tree to record the allocation", you've
   slipped into the recursion ARCH §6.5 explicitly forbids.
4. **Format stability.** `stm_uberblock` is 4096 bytes wedged by
   `_Static_assert`. New fields go in `ub_reserved[1056]` and bump
   `STM_UB_VERSION` per §5.2's feature-flag dance. Never change
   field offsets in-place.
5. **Deferred-free is a safety property**, not a performance
   optimization. Skipping or shortening it corrupts MVCC reads by
   readers with snapshot < free_gen. `allocator.tla`'s
   `FreeGenClearedAfterReclamation` is the formal statement.
6. **Stm_bdev's fsync is not free.** Commit-protocol chunks should
   batch fsyncs (one per device per phase, not one per block).

## Known P3 ambiguities to watch for

- **Label geometry vs bootstrap-pool start.** ARCH §5.3.1 says
  labels at bytes 0 / 256K / end-512K / end-256K. ARCH §6.5.1
  diagrams the bootstrap pool as starting "at 1 MiB". 1 MiB is
  after labels 0+1 (which end at 512K) with a 512K gap. Verify
  whether this is intentional reservation margin or a doc mismatch.
  Single source of truth should be encoded in a constant, e.g.,
  `STM_BOOTSTRAP_OFFSET = (uint64_t)STM_LABEL_SIZE * 4`.
- **Stm_bptr semantics at Phase 4 vs Phase 3.** The bptr struct is
  64 bytes with room for Merkle csum + flags. Phase 3 populates
  only paddr + kind. Phase 4 wires the Merkle field. Coordinate
  carefully so that format stability is preserved.
- **Mount-time txg advance.** sync.tla's Mount bumps live txg past
  every durable txg — the nonce-uniqueness invariant (§7.4).
  Phase 3 mount code must call this. Currently `stm_sb_mount_scan`
  only selects the authoritative uberblock; the bump-past-scanned-
  max needs to be wired in the mount-integration chunk.

## References in order of likely usefulness

1. `v2/docs/phase3-status.md` — this file.
2. `v2/docs/phase2-status.md` — Bw-tree trip hazards that survive.
3. `docs/ARCHITECTURE.md` §5 (uberblock / quorum), §6 (allocator),
   §3.7 (commit protocol), §7.4 (nonces).
4. `docs/ROADMAP-V2.md` §6 — Phase 3 deliverables and exit criteria.
5. `memory/audit_v2_r0_closed_list.md` — what NOT to re-report in
   R7.
6. `v2/specs/sync.tla` — abstract commit protocol with NonceUnique,
   MountGenBump, UBMonotonic, CommitAtomic invariants.
7. `v2/specs/allocator.tla` — refcount + deferred-free.
8. `v2/include/stratum/super.h` — uberblock + label layout + bptr.
9. `CLAUDE.md` — audit-triggering-changes policy and general
   operating notes.

## Where to pick up

1. Read this file.
2. Read `memory/MEMORY.md`, then `memory/project_v2_next_session.md`
   for the latest compact state.
3. Run the verification commands; confirm tip is green.
4. Scope the allocator chunk (4a is the recommended first sub-chunk).
5. Write tests alongside code, commit when green, push to `main`.
6. Spawn R7 audit in the background when you land the allocator
   implementation; fix P0/P1/P2 findings before exit.

Welcome to Phase 3.
