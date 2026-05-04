# CLAUDE.md

Operating notes for Claude when working on Stratum.

## Mission

Stratum is aiming to be a first-class peer of ZFS and btrfs — not a demo, not a hobby project, a production-grade COW filesystem that a POSIX-compatible OS can be built on. Beyond peer status, Stratum is intended to pioneer in a chosen set of areas where the state of the art is ripe for advance:

1. **Formally verified sync + crash-safety protocol.** TLA+ (or similar) specification of the three-phase sync, allocator invariants, and AEAD nonce machinery, proved correct under arbitrary write reordering. No mainline filesystem has this.
2. **Post-quantum encryption as default.** ML-KEM-768 + XChaCha20-Poly1305 hybrid wrap keys. Stratum ships PQ-ready out of the box.
3. **Content-defined extent boundaries.** Rolling-hash chunking at the extent layer (shift-resistant dedup for real-world data patterns — VMs, container images, backups). No production filesystem integrates this.
4. **Lock-free metadata path.** The Bε-tree's message-buffer model is an unusually good fit for lock-free operation. Pair with MVCC readers for zero-contention reads.
5. **Merkle-rooted metadata integrity.** Tamper-evident semantics stronger than per-block csums: any offline edit to any metadata block is cryptographically detectable.
6. **Tiered storage with learned migration.** Beyond heuristic hot/cold tiering — access-pattern models for policy decisions.
7. **io_uring-native, zero-copy write path.** Designed for 2026+ NVMe workloads, not retrofitted from POSIX block I/O.

These are long-horizon commitments. The existing code is a **foundation, not the destination**. Components will be preserved where they still serve the vision (Bε-tree core, crypto primitives, xxHash helpers) and rewritten where they don't (superblock layout, allocator, namespace model, block-device abstraction). Salvage rate of the existing ~20 KLOC is expected to be 30–50%. That's fine. The cost of preserving code against architectural constraints it doesn't fit is higher than the cost of rewriting it right.

## Design-first policy (Phase 0)

Architectural decisions compound. A wrong choice in the concurrency model, storage pool layout, or namespace structure becomes irrevocable once thousands of lines of code depend on it. **Phase 0 — active as of 2026-04-19 — pauses implementation of new features until major architectural decisions are specified in writing.**

Phase 0 outputs (all go into `docs/` — written, reviewed, versioned):

- `docs/VISION.md` — target workloads, scale targets, property ranking (perf / reliability / security / concurrency / portability). Identifies the non-goals.
- `docs/COMPARISON.md` — feature matrix vs ZFS, btrfs, bcachefs. Three columns: match, lead, deliberately-not-doing. Annotated with *why* for each.
- `docs/NOVEL.md` — the committed novel angles from the mission list. For each: concrete scope, what "done" looks like, dependencies on other decisions.
- `docs/ARCHITECTURE.md` — the foundational decisions:
    - Concurrency model (MVCC + lock-free readers / fine-grained writer locks / something else)
    - Storage pool model (device roster, redundancy domains, nonce construction under multi-device)
    - Namespace model (subvolumes, datasets, property inheritance, per-dataset encryption keys)
    - Allocator model (tree-embedded vs side channel; relation to sync)
    - Superblock / quorum model (per-device uberblock trees, commit ordering across devices)
    - Block-device abstraction (io_uring-native, DAX-compatible, zero-copy affordances)
    - Integrity model (Merkle root placement, verification cadence)
    - Crypto model (per-dataset keys, PQ wrap, key rotation, rekey)
- `docs/ROADMAP-V2.md` — the phased plan that builds on the above. Replaces the prior SOTA roadmap.

Only after `ARCHITECTURE.md` is signed off does implementation resume — likely from a mostly-fresh tree in a sibling directory (`stratum-v2/` or similar), with salvageable components ported one at a time with their own justification.

**Process notes during Phase 0:**
- Every design decision gets a written rationale. Assume we'll need to justify it in a year when the context has faded.
- Assume every decision gets challenged. The mission is ambitious enough that "we chose X because it was easier" isn't a legitimate answer for foundational choices.
- Design sessions produce documents, not code. No implementation pressure during Phase 0.
- Load-bearing invariants identified during design become candidates for formal specification (TLA+ / Alloy / similar). The spec is the source of truth; code is an implementation of the spec.

## Spec-first policy (applies to every new feature, not just Phase 0)

**If a feature touches a load-bearing invariant — concurrency, commit ordering, nonce uniqueness, quorum, redundancy, crypto key derivation, cache coherence, torn-write recovery — the TLA+ (or similar) model comes BEFORE the implementation.** Write the spec, let TLC chew on it, and let the invariant violations (if any) surface at the spec level where they cost minutes, not at runtime where they cost commits.

Concrete pattern that's repeatedly paid off on this project:
1. Propose the feature in prose (problem + shape).
2. **Model the mechanism in TLA+** — state, actions, invariants. TLC with small bounds (typically Devices≤3, Commits≤3, Retries≤1).
3. Iterate until TLC is green under the invariants you'd want the impl to uphold. If a bug shows up, fix the design BEFORE writing code.
4. Implement against the model. Cross-reference each impl step to the corresponding spec action in comments. Keep the SPEC-TO-CODE mapping current.
5. When the impl surfaces a new mechanism the spec didn't cover, extend the spec FIRST, then update the impl.

Historical receipts:
- `quorum.tla` (P5-0) caught two bugs before a line of P5-2 code was written: orphan-gen mount acceptance (fixed via `OrphansNotAuthoritative`) and over-strict `LiveCoordMonotonic` that would fail in the transient between-writes state.
- `quorum.tla` with `IdempotentRetry=FALSE` + `MaxRetries≥2` demonstrated the R14 P1 content-divergence bug at the spec level — the invariant fired before anyone had coded the offending path.
- Skipping this step for P5-3b/c left the per-tree-gen divergence bug (fold of alloc_commit's R7c P2-5 short-circuit + the roots-object value layout) for a test to catch at runtime, not the model. An extension of `quorum.tla` that captures per-device tree gens + idempotent-commit would have caught it before the first compile.

**If you cannot articulate the invariant formally, you don't understand it well enough to implement it.**

Features that clearly benefit (not exhaustive): multi-device commit, quorum protocols, key rotation, scrub orchestration, refcount/snapshot graph mutations, MVCC readers vs writers, anything that persists a reservation-then-commit or multi-phase write, anything that uses crypto nonces over a shared key, anything with more than one device state machine in play.

Features that usually don't (pure computation, test helpers, config parsing, CLI glue): skip the spec; just write + test. Use judgment.

## Audit-triggering changes

**Applies to**: any change to the current codebase during Phase 0 (e.g. bug fixes to the foundation) AND to Stratum v2 code once implementation resumes. The policy survives the redesign — the invariants are filesystem invariants, not stratum-v1 invariants.

Stratum v1 went through 15 rounds of adversarial soundness audits (R0–R14, commits `bb39db8` → `405c4fb`) that landed ~60 corruption-class fixes. The invariants those audits established are load-bearing and non-obvious — many will carry forward to v2. **Any change to the surfaces below MUST spawn a focused soundness audit against the changed code before merge** — not as ceremony, but because each round has surfaced a previously-invisible bug, and the pattern is that regressions in these areas are not caught by the test suite.

**Trigger list** — changes to any of these require an audit round:

| Surface | Files | Why |
|---|---|---|
| Crypto nonce construction / key handling | `src/crypto/crypto.c`, `include/stratum/crypto.h` | AEAD nonce uniqueness is the single most expensive invariant; past rounds found nonce-reuse across mount, across rollback, across UINT64_MAX wrap |
| Sync / rollback / mount-bump flow | `src/fs/fs.c::stm_fs_sync`, `stm_fs_open_impl`, `stm_fs_gen_bump_disk`, `src/snap/snap.c::stm_snap_rollback` | Invariant `disk ss_gen > fs->gen` is maintained by a delicate three-phase dance (see `docs/STRATUM.md` §7) |
| Btree write paths | `src/btree/btree.c::stm_btree_write_node`, `split_root`, `split_child`, `stm_btree_flush`, `src/btree/msg.c` | Torn-write recovery, pivot pre-reserve, and the two-phase flush commit are easy to break |
| Superblock layout / validation | `src/fs/fs.c` mount SB parsing, `include/stratum/super.h` | SB is plaintext + unkeyed xxHash3; every counter field needs adversarial-tamper defense |
| 9P wire handling (v1) | `src/p9/p9.c` | Every `body` pointer read needs a `body_len` bound; silent Rread with count=0 hides errors |
| 9P codec (v2 / janus) | `v2/src/p9/server.c`, `v2/src/p9/wire.h`, `v2/include/stratum/p9.h` | (v2-only) Generic vops-based 9P2000 codec used by janus's `/keys/` synthetic FS. Inherits R11-R14 audit lessons: bounds-checking on every wire read, fid leak avoidance on failed Tattach, partial-Twalk doesn't bind newfid, mode-gating on read/write. |
| 9P2000.L filesystem server (v2) | `v2/src/9p/server.c`, `v2/src/9p/wire.h`, `v2/include/stratum/9p.h` | (P9-9P-1; v2-only) Filesystem-bound 9P2000.L server that takes a live `stm_fs *` and dispatches every op to `stm_fs_*`. Composes against `v2/specs/fid.tla` — every Tread/Twrite/Tgetattr/Tsetattr/Tlock/... handler MUST verify the fid's cached_gen against the inode's current `si_gen` via `verify_fid_fresh` BEFORE forwarding to stm_fs (the IOReject gate from fid.tla); every Twalk / Tattach binding MUST snapshot current `si_gen` at bind time (the WalkBindsWithCurrentGen invariant). Five buggy configs enumerate the runtime-gate failure modes the reviewer must explicitly rule out — staleness gate skipped (confused-deputy attack), bind-time gen-snapshot wrong, Tclunk leaks fid, Tdetach leaks fids, IOReject fires falsely. Every fid that has held byte-range locks must call `stm_fs_release_lock_owner(owner_id)` at clunk + at Tdetach (composes against locks.tla::ReleaseOwner). |
| FUSE callbacks | `src/cmd/fuse.c` | Same concerns as 9P: every callback is a trust boundary from kernel VFS. Single-threaded loop assumed — multi-threading would need locking. |
| Btree node cache | `src/btree/cache.c`, `stm_btree_read_node`, `stm_btree_write_node` | Cache correctness depends on invalidate-on-write + COW-fresh-paddr invariant. Any future path that writes a node without going through `stm_btree_write_node` breaks the contract silently. |
| Extent write ordering | `src/fs/fs.c::stm_fs_write`, `extent_write_data`, `extent_read_data` | Insert-before-free, ebuf tail-zero, partial-extent old-lookup are all audit-derived |
| Public API contracts | `include/stratum/fs.h`, `stm_fs_open_ro` vs `stm_fs_open` | RO vs RW contract depends on runtime guards; new accessors can create bypass surfaces |
| Inode allocator | `v2/src/inode/inode.c`, `v2/include/stratum/inode.h` | (P8-POSIX-1; v2-only — no v1 analog) The (ino, si_gen) tuple-uniqueness-across-time invariant from `v2/specs/inode.tla` underpins stale-fid detection in 9P (ARCH §11.3.2), per-file derived keys (§7.3.3), and NFS file handles. A buggy reuse path that doesn't bump gen exposes confused-deputy attacks. The two `inode_*_buggy.cfg` configs enumerate the failure modes the reviewer must rule out. [R69 P3-9: row uses explicit v2/ prefix since this surface only exists in v2.] |
| Dirent layer | `v2/src/dirent/dirent.c`, `v2/include/stratum/dirent.h` | (P8-POSIX-2; v2-only) Open-addressing chain integrity from `v2/specs/dirent.tla`. Three buggy configs (`dirent_unlink_uses_empty_buggy.cfg`, `dirent_create_overwrites_no_probe_buggy.cfg`, `dirent_lookup_stops_on_tombstone_buggy.cfg`) enumerate the canonical chain-integrity failure modes — silent loss of colliding-name reachability via missing-tombstone, silent overwrite of colliding occupant via no-probe-walk, and read-side analog of unlink-uses-empty. Writer-side guards must mirror decoder-side guards (R71 P1-1 lesson — same posture as the inode allocator). |
| Xattr layer | `v2/src/xattr/xattr.c`, `v2/include/stratum/xattr.h` | (P8-POSIX-6; v2-only) Open-addressing chain integrity from `v2/specs/xattr.tla` — structurally isomorphic to dirent.tla's write-side, keyed at `ino` instead of `dir_ino`. Three buggy configs (`xattr_unlink_uses_empty_buggy.cfg`, `xattr_create_overwrites_no_probe_buggy.cfg`, `xattr_lookup_stops_on_tombstone_buggy.cfg`) enumerate the canonical failure modes. Writer-side guards must mirror decoder-side guards on BOTH `name_len` AND `value_len` (R71 P1-1 + R77 P1-1 lesson — the OOB-read shape from inline data extends to xattr value records, so symmetric bounds must hold at both ≤ STM_XATTR_NAME_MAX (255) and ≤ STM_XATTR_VALUE_MAX (64 KiB) at every trust boundary). Tree-root introductions bind into Merkle chain in lockstep — `xattr_csum` is the 10th input to `compute_merkle_root`. |

**How to run an audit round:**

1. Spawn an Opus 4.7 soundness-prosecutor agent (general-purpose subagent, `run_in_background: true`).
2. In the prompt, include `memory/audit_r15_closed_list.md` contents as the "already fixed — do not re-report" preamble.
3. Scope the prompt to the surface you changed — e.g. "re-audit the changes in `src/snap/snap.c` commits X..Y for nonce-uniqueness / torn-write / wedge-state regressions."
4. Wait for the completion notification. Fix any P0/P1/P2 findings before merge.

## Invariants that must hold

See `docs/STRATUM.md` §22 "Soundness invariants" for the full list. The load-bearing ones:

- **Nonce uniqueness**: `disk ss_gen > fs->gen` at all times post-mount. Every write encrypts under `(paddr, write_gen=fs->gen)` and those pairs must be globally unique across the volume's lifetime.
- **Sync is three-phase**: reservation (G+1, pre-flush root) → flush at gen G → final (G+2, post-flush root). `fs->gen` advances by 1 per sync. Any refactor must preserve the invariant across every torn-write-or-crash boundary.
- **Rollback-bump before allocator swap**: if the bump write fails, `old_alloc` must still hold live refcounts for pre-rollback paddrs so they don't get reused at the same gen.
- **Wedged / read-only containment**: `fs->wedged` and `fs->read_only` are runtime-enforced at every public API entry. New public APIs must call `STM_FS_GUARD_READ` / `STM_FS_GUARD_WRITE`.
- **Counter clamps at mount**: `ss_gen`, `ss_next_ino`, `ss_next_snap_id` all rejected if near UINT64_MAX; walk-derived raises from on-disk tree contents.

## Technical reference upkeep (v2 only)

The v2 tree carries a comprehensive as-built reference at `v2/docs/REFERENCE.md` (top-level index + maintenance policy) and `v2/docs/reference/00..11.md` (per-subsystem deep dives). Every chunk that lands in v2/ MUST update the relevant reference section in the **same PR / commit** that lands the code.  Concretely:

- **New module / new public API** → add or extend the corresponding `reference/NN-*.md` section.
- **Change to a documented invariant or contract** → update the section, and (per the spec-first policy above) update the spec FIRST.
- **New TLA+ spec or buggy config** → update `reference/10-specs.md`'s catalog.
- **New term / acronym / state name** → add to `reference/11-glossary.md`.
- **`STM_UB_VERSION` bump or feature-flag change** → update `reference/00-overview.md`'s UB-versioning table.
- **Snapshot drift** (test count, spec count, tip hash in `REFERENCE.md`) — refresh in the close commit.

The reference is intentionally distinct from `docs/ARCHITECTURE.md` (design intent, including unimplemented work) and `docs/ROADMAP-V2.md` (phased plan): it documents what EXISTS in the tree right now, with `file:line` citations.  When the three disagree, the spec wins, the reference is corrected, and ARCHITECTURE.md gets an issue noted for cross-check.

If a chunk's diff doesn't include a reference-doc update, the reviewer should ask whether it was intentional (e.g., pure bug fix that doesn't change documented surface) or an oversight.

## Regression testing

- Every audit finding that can be made to fail without the fix should land a regression test. See `tests/test_fs.c::test_fs_sync_two_phase_gen_invariant`, `test_fs_mount_bump_encrypted`, `test_fs_write_gap_is_zeroed*`, `tests/test_snap.c::test_snap_rollback_bumps_gen_encrypted`, `tests/test_p9.c::test_p9_wire_validation`, `test_p9_fid_cache_and_dup` for the pattern.
- Before committing, run all 11 C suites + 10 Rust integration tests: `cmake --build build && for t in types key block node btree fs compress crypto snap p9 alloc; do build/tests/test_$t; done && (cd tui && cargo test --test integration --release)`.

## Clangd false positives

The CMake build is the source of truth. Clangd emits many "file not found" / "undeclared identifier" diagnostics in `src/` and `include/` because it doesn't see the cmake-generated compile commands for this tree. Ignore those and trust `cmake --build build`.

## Session-state files

- Built binaries deploy to `/Users/northkillpd/projects/dist/{stratum,stratum-tui}` and must be re-signed after deploy: `codesign --force --sign - <path>`.
- Tasks tracked via the in-conversation task list; one task per audit finding, per-round re-audit task as a checkpoint.
