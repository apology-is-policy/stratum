# Phase 3 — status and next-session guide

Authoritative pickup guide for Phase 3 (persistence + allocator). Last
update 2026-04-20 (after chunk 4b-2 / stm_alloc landed). Companion
to `phase2-status.md`, which remains the reference for the Bw-tree
layer Phase 3 builds on.

## TL;DR

Phase 3 is in progress. Six chunks landed:

| Commit | What | Tests |
|---|---|---|
| `4d87fb7` | Uberblock format (4 KiB struct, BLAKE3 csum) + label layout + `stm_bptr` + encode/decode | 12 sb tests |
| `2290d49` | Device-backed label I/O + mount_scan (single-device authoritative selection) | +5 bdev-backed tests |
| `cf52a1f` | `allocator.tla` spec: refcount + deferred-free safety. TLC clean (3729 states, depth 16) | — |
| `37a3be7` → `dd86a63` | **Chunk 4a + R7a**: bootstrap-pool allocator (bitmap-managed, ping-pong hdr+bm slots, PENDING deferred-free matching `allocator.tla`'s Commit rule). R7a closed (0 P0 / 2 P1 / 3 P2 / 3-of-6 P3). | 18 bootstrap tests |
| `3d9bcd0` | **Chunk 4b-1**: rename bootstrap module (stm_alloc → stm_bootstrap) to free the `stm_alloc` name for the main allocator. Pure mechanical refactor. | 18 bootstrap tests |
| `6651830` | **Chunk 4b-2**: `stm_alloc` top-level allocator. Wraps `stm_bootstrap` + `stm_btree_mt`; data-area tree keyed by BE-packed u64 start_block, value {le32 length_blocks; le32 refcount}. Reserve/free/ref/commit match `allocator.tla` semantics. **Data-area tree is in-RAM** — node persistence + bootstrap-backed node placement deferred to chunk 5. | 14 alloc tests |

Phase 2 is complete (SPLIT + MERGE + per-node consolidator + SCAN + R0-R6
audits). Phase 3 chunks remaining:

1. **Allocator implementation** — 4a (bootstrap pool) + 4b (data-area
   tree, in-RAM) landed. Remaining sub-chunks:
   - **Chunk 5** (formerly "node serialization"): on-disk Bε-tree node
     encode/decode with Merkle-hash field + BLAKE3 csum. Once this
     lands, chunk 5 also wires the `reserve_for_node` callback so
     allocator-tree NODES live in the bootstrap pool per ARCH §6.5.
     Unblocks persistent data-area allocator state across mount.
   - **Chunk 4c**: SDArray in-RAM bitmap for O(1) allocation queries.
   - **Chunk 4d**: xor filter for negative lookups.
   - **Chunk 4e**: R7 full-stack audit (after 4c+4d).
2. **Four-phase commit implementation** — wire the protocol sync.tla
   abstracts. Uberblock ring rotation + fsync discipline.
3. **Mount / unmount integration** — put labels + commit + allocator
   together; single-device round-trip. Data-area tree persistence
   goes live here (depends on chunk 5).
4. **Crash-injection fuzzer** — Phase 3 exit criterion. Inject partial
   writes at every commit phase; verify mount recovers to a
   consistent state.
5. **R7 audit** — adversarial soundness pass per CLAUDE.md before
   Phase 3 exit. R7a (bootstrap-only scope) closed with chunk 4a;
   R7b (stm_alloc scope) runs with chunk 4b; full R7 at the end of
   allocator work.

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

## Next chunk — Bε-tree node serialization (chunk 5)

Chunk 4a + 4b landed across `37a3be7` / `dd86a63` (bootstrap pool +
R7a audit) and `3d9bcd0` / `6651830` (rename + stm_alloc data-area
tree). Everything is in-RAM from a tree perspective. The bootstrap
pool IS durable (it has its own format; survives mount/unmount);
the data-area tree is NOT.

**Chunk 4a + 4b: LANDED (2026-04-20).** Bootstrap pool + stm_alloc
with reserve/free/ref/commit. R7a closed; R7b runs with chunk 4b.

### Chunk 5 (next): Bε-tree node serialization.

This is the work that makes the data-area allocator tree durable and
wires the `reserve_for_node` callback so allocator-tree NODES live in
the bootstrap pool (ARCH §6.5) rather than malloc.

Scope:
- **On-disk node format** (ARCH §3, §5.4 bptr):
  - Leaf node: header + packed entries + BLAKE3-256 csum + (future)
    Merkle hash field. Size: one or more multiples of 128 KiB
    (STM_BOOTSTRAP_UNIT_BLOCKS × 4 KiB).
  - Internal node: header + pivot bptrs + csum.
  - Encode/decode honoring le* endianness convention.
- **Node-placement callback** wired through stm_btree or a thin
  "persistent btree" wrapper. Interface sketch:

    typedef struct {
        stm_status (*reserve)(void *ctx, uint64_t nblocks,
                              uint64_t hint, uint64_t *out_paddr);
        stm_status (*free)   (void *ctx, uint64_t paddr,
                              uint64_t free_gen);
        stm_status (*read)   (void *ctx, uint64_t paddr,
                              void *buf, size_t len);
        stm_status (*write)  (void *ctx, uint64_t paddr,
                              const void *buf, size_t len);
    } stm_btree_store_vtable;

  stm_alloc provides an impl that routes reserve/free to
  stm_bootstrap_reserve/free and read/write to the bdev.
- **stm_alloc_open reads allocator-tree root from the uberblock.**
  Currently a no-op; becomes a real walk after chunk 5 + the
  four-phase commit protocol wires the allocator root into the
  uberblock's `ub_alloc_root` bptr.

Don't confuse the scope: chunk 5 is STRICTLY the btree
serialization layer + allocator wiring. Four-phase commit (which
touches uberblock ring rotation) is a separate chunk. Mount/unmount
integration (which reads `ub_alloc_root` and reconstructs the tree)
comes after both.

### Chunk 4c: In-RAM succinct bitmap (SDArray).
- Performance structure. `src/alloc/sdarray.c`. Approximate
  "is block X allocated" in O(1). Reduces tree walks.
- Target: ~20 MiB RAM per TiB of data. Revisit if initial
  straight-bitmap impl already lands within the Phase 3 exit
  budget (25 MiB/TiB per roadmap §6.2).

### Chunk 4d: xor filter for negative lookups.
- 9 bits per allocated range, <1% false-positive rate. Fast
  "is this paddr in any live range?"

### Chunk 4e: R7 full-stack audit.
- Per CLAUDE.md policy: changes to sync / allocator / crypto /
  tree-write paths trigger a focused soundness audit before merge.
- Prompt template is in the R5/R6 audit spawns in git history
  (commits `83f4710` → `a1299fb` → `8941a2a`). Include R0-R7b
  closed list as the do-not-report preamble.

### MVP restrictions carrying forward:
- Single-block bootstrap bitmap → bootstrap pool capped at 4 GiB.
- Single-device: paddrs return device = 0. The allocator-roots
  object (per §6.3.2) will add device indirection once we move to
  multi-device.

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
