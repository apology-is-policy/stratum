# Phase 3 — status and next-session guide

Authoritative pickup guide for Phase 3 (persistence + allocator). Last
update 2026-04-20 (after chunk 4a / bootstrap pool landed). Companion
to `phase2-status.md`, which remains the reference for the Bw-tree
layer Phase 3 builds on.

## TL;DR

Phase 3 is in progress. Four chunks landed:

| Commit | What | Tests |
|---|---|---|
| `4d87fb7` | Uberblock format (4 KiB struct, BLAKE3 csum) + label layout + `stm_bptr` + encode/decode | 12 sb tests |
| `2290d49` | Device-backed label I/O + mount_scan (single-device authoritative selection) | +5 bdev-backed tests |
| `cf52a1f` | `allocator.tla` spec: refcount + deferred-free safety. TLC clean (3729 states, depth 16) | — |
| `37a3be7` | **Chunk 4a**: bootstrap-pool allocator (bitmap-managed, ping-pong hdr+bm slots, PENDING deferred-free matching `allocator.tla`'s Commit rule) | 16 alloc tests |

Phase 2 is complete (SPLIT + MERGE + per-node consolidator + SCAN + R0-R6
audits). Phase 3 chunks remaining:

1. **Allocator implementation** — 4a (bootstrap pool) landed. Remaining:
   4b allocator Bε-tree, 4c SDArray in-RAM, 4d xor filter, 4e R7 full audit.
   ARCH §6.
2. **Bε-tree node serialization** — moved from Phase 2. Encode/decode
   with Merkle-hash field + csum. ARCH §5.4 bptr + §3 node format.
3. **Four-phase commit implementation** — wire the protocol sync.tla
   abstracts. Uberblock ring rotation + fsync discipline.
4. **Mount / unmount integration** — put labels + commit + allocator
   together; single-device round-trip.
5. **Crash-injection fuzzer** — Phase 3 exit criterion. Inject partial
   writes at every commit phase; verify mount recovers to a
   consistent state.
6. **R7 audit** — adversarial soundness pass per CLAUDE.md before
   Phase 3 exit. R7a (bootstrap only, see §"Next chunk") runs with
   chunk 4a; full R7 at the end of allocator work.

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

## Next chunk — allocator tree (chunk 4b)

Chunk 4a landed at `37a3be7` with 16 tests green on default / ASan /
TSan. API, layout, and semantics are in `include/stratum/alloc.h`.
The bootstrap pool is bitmap-managed at 128 KiB (32-block) granularity,
with ping-pong header + bitmap slots for torn-write safety and BLAKE3-256
self-csums on each header slot plus a bitmap csum recorded in the
header. The deferred-free machinery stamps PENDING entries with
caller-supplied `free_gen`; `stm_alloc_commit(committed_gen)` sweeps
`free_gen < committed_gen` exactly as `allocator.tla` specifies. Commit
COWs the bitmap then the header, fsync'd between writes; a crash at any
point recovers cleanly via the older-slot fallback.

MVP restrictions (carry into 4b):
- Single-block bitmap → bootstrap pool capped at 4 GiB. Extend with
  multi-block bitmaps when a device needs more.
- Single-device: paddrs return device = 0. The allocator-roots object
  (per §6.3.2) will add device indirection.

**Chunk 4a was audited as R7a.** See audit-closed-list for findings.
**Chunk 4a: Bootstrap pool — LANDED (2026-04-20).**

**Chunk 4b: Allocator tree (Bε-tree rooted).**
- Reuse existing `stm_btree` (single-threaded) or `stm_btree_lf`
  (concurrent). Concurrent makes sense since the allocator is
  accessed from any commit participant. Key: u64 start_block,
  value: `struct stm_alloc_entry { le32 length_blocks; le32
  refcount; }`.
- Glue: allocator-tree reads go through the btree API; writes go
  through the tree's message-buffer (or direct writes at commit
  reservation time).
- Integration with bootstrap pool: allocator-tree NODES live in
  the bootstrap pool. Tree-INSERT doesn't recurse into the allocator.
- Node placement contract: the btree layer must be parameterized
  with an allocator callback (`reserve_for_node` / `free_node`) so
  that Bε-tree page writes consume bootstrap-pool units rather than
  allocator-tree ranges. Prototype: a thin wrapper around
  `stm_alloc_reserve(a, STM_BOOTSTRAP_UNIT_BLOCKS, hint, &paddr)`.

**Chunk 4c: In-RAM succinct bitmap (SDArray).**
- Performance structure. `src/alloc/sdarray.c`. Approximate
  "is block X allocated" in O(1). Reduces tree walks.
- Target: ~20 MiB RAM per TiB of data. Revisit if initial
  straight-bitmap impl already lands within the Phase 3 exit
  budget (25 MiB/TiB per roadmap §6.2).

**Chunk 4d: xor filter for negative lookups.**
- 9 bits per allocated range, <1% false-positive rate. Fast
  "is this paddr in any live range?"

**Chunk 4e: R7 audit.**
- Per CLAUDE.md policy: changes to sync / allocator / crypto /
  tree-write paths trigger a focused soundness audit before merge.
- Prompt template is in the R5/R6 audit spawns in git history
  (commits `83f4710` → `a1299fb` → `8941a2a`). Include R0-R6
  closed list as the do-not-report preamble.

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
