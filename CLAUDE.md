# CLAUDE.md

Operating notes for Claude when working on Stratum.

## Audit-triggering changes

Stratum went through 15 rounds of adversarial soundness audits (R0–R14, commits `bb39db8` → `405c4fb`) that landed ~60 corruption-class fixes. The invariants those audits established are load-bearing and non-obvious. **Any change to the surfaces below MUST spawn a focused soundness audit against the changed code before merge** — not as ceremony, but because each round has surfaced a previously-invisible bug, and the pattern is that regressions in these areas are not caught by the test suite.

**Trigger list** — changes to any of these require an audit round:

| Surface | Files | Why |
|---|---|---|
| Crypto nonce construction / key handling | `src/crypto/crypto.c`, `include/stratum/crypto.h` | AEAD nonce uniqueness is the single most expensive invariant; past rounds found nonce-reuse across mount, across rollback, across UINT64_MAX wrap |
| Sync / rollback / mount-bump flow | `src/fs/fs.c::stm_fs_sync`, `stm_fs_open_impl`, `stm_fs_gen_bump_disk`, `src/snap/snap.c::stm_snap_rollback` | Invariant `disk ss_gen > fs->gen` is maintained by a delicate three-phase dance (see `docs/STRATUM.md` §7) |
| Btree write paths | `src/btree/btree.c::stm_btree_write_node`, `split_root`, `split_child`, `stm_btree_flush`, `src/btree/msg.c` | Torn-write recovery, pivot pre-reserve, and the two-phase flush commit are easy to break |
| Superblock layout / validation | `src/fs/fs.c` mount SB parsing, `include/stratum/super.h` | SB is plaintext + unkeyed xxHash3; every counter field needs adversarial-tamper defense |
| 9P wire handling | `src/p9/p9.c` | Every `body` pointer read needs a `body_len` bound; silent Rread with count=0 hides errors |
| Extent write ordering | `src/fs/fs.c::stm_fs_write`, `extent_write_data`, `extent_read_data` | Insert-before-free, ebuf tail-zero, partial-extent old-lookup are all audit-derived |
| Public API contracts | `include/stratum/fs.h`, `stm_fs_open_ro` vs `stm_fs_open` | RO vs RW contract depends on runtime guards; new accessors can create bypass surfaces |

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

## Regression testing

- Every audit finding that can be made to fail without the fix should land a regression test. See `tests/test_fs.c::test_fs_sync_two_phase_gen_invariant`, `test_fs_mount_bump_encrypted`, `test_fs_write_gap_is_zeroed*`, `tests/test_snap.c::test_snap_rollback_bumps_gen_encrypted`, `tests/test_p9.c::test_p9_wire_validation`, `test_p9_fid_cache_and_dup` for the pattern.
- Before committing, run all 11 C suites + 10 Rust integration tests: `cmake --build build && for t in types key block node btree fs compress crypto snap p9 alloc; do build/tests/test_$t; done && (cd tui && cargo test --test integration --release)`.

## Clangd false positives

The CMake build is the source of truth. Clangd emits many "file not found" / "undeclared identifier" diagnostics in `src/` and `include/` because it doesn't see the cmake-generated compile commands for this tree. Ignore those and trust `cmake --build build`.

## Session-state files

- Built binaries deploy to `/Users/northkillpd/projects/dist/{stratum,stratum-tui}` and must be re-signed after deploy: `codesign --force --sign - <path>`.
- Tasks tracked via the in-conversation task list; one task per audit finding, per-round re-audit task as a checkpoint.
