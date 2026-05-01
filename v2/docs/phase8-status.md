# Phase 8 — status and pickup guide

Authoritative pickup guide for Phase 8 (POSIX surface — inodes,
dirents, xattr, ACLs, statx, small-file inline, reflink wrapper,
the full set of POSIX file/dir operations).

**Phase 8 ENTERED 2026-04-30** at `bea7f82` after the user
surfaced that ARCHITECTURE §11 (POSIX surface) was a missing
phase under the prior 10-phase ROADMAP numbering. Phase 8 was
inserted; client interfaces shifted to Phase 9. Tag
`phase-7-complete` (at `1759caf`) still marks the Phase 7 → 8
boundary.

ROADMAP §11 lists the deliverables and §11.2 the exit criteria.
ARCHITECTURE §11 is the design document — the on-disk shape is
fully committed there (256-byte `stm_inode`, hash-indexed B-tree
dirents keyed by `(dir_ino, STM_KEY_DIRENT, fnv1a(name))`, tagged
data union extent / inline / symlink / device, `si_gen` for
ino-reuse detection, inline data ≤100 bytes for small files).
This phase implements §11.

## Why this phase exists

Phase 7 built the data plane (extent records keyed by `(ds, ino,
off, len)`, FastCDC, CAS tier, send/recv, reflinks) and the
namespace plane (datasets, snapshots, clones, dead-list). What's
missing is the **filesystem semantics layer** — the inode metadata
and directory entry storage that turns a (dataset, ino, byte-
offset) byte store into a POSIX-shape file/directory tree:

- `stm_fs_lookup(parent_ino, name) → child_ino` — name resolution
- `stm_fs_create_file` / `stm_fs_mkdir` / `stm_fs_unlink` /
  `stm_fs_rmdir` / `stm_fs_rename` — directory mutations
- `stm_fs_stat` / `stm_fs_chmod` / `stm_fs_chown` / `stm_fs_utimens`
  — metadata ops
- `stm_fs_readdir` — directory traversal
- `stm_fs_link` / `stm_fs_symlink` / `stm_fs_readlink` — links
- xattr + POSIX ACLs
- modern POSIX features (`O_TMPFILE`, `F_SEAL_*`, `statx`)

v1's `src/fs/fs.c` had this layer; v2 has a flat (ds, ino, off)
extent API. Phase 8's job is the v2 reimplementation per ARCH
§11 — extending the prior 88-byte v1 inode to the 256-byte v2
inode and porting the hash-indexed dirent shape.

Phase 9 (client interfaces) is gated on Phase 8 exit: 9P's Twalk
/ Tcreate / Treaddir / Topen / Tstat have nothing to forward to
without this layer.

## Sub-chunk plan

Each sub-chunk is its own substantive + R-close + hash-fixup
cycle (per CLAUDE.md three-commit pattern) where the audit-trigger
surface applies. New surfaces added to CLAUDE.md's trigger list
during this phase:

- `src/inode/` — inode tree write paths.
- `src/dirent/` — dirent btree mutations + hash-collision chain
  walks (single-byte invariant violations here are how
  ext4 + xfs have historically had silent-corruption regressions).
- `src/fs/fs.c` for any new public POSIX op API additions.

| Sub-chunk | Scope | TLA+ scaffold | Audit trigger |
|---|---|---|---|
| **P8-POSIX-1** *(spec scaffold + substantive landed; R69 audit running)* | `stm_inode` struct + in-memory allocator (alloc-fresh-only). New `include/stratum/inode.h` (256-byte struct stm_inode_value per ARCH §11.3, with v2 simplification: 16-byte (paddr, gen) extent-tree-root vs ARCH's 57-byte stm_bptr). New `src/inode/inode.c` (allocator with pthread_mutex_t-guarded records[] + per-dataset next_ino[]). 19 tests in test_inode.c green default + ASan + TSan. AllocReused (with gen bump per inode.tla) deferred to P8-POSIX-1b. | **`inode.tla` LANDED** — alloc / free / generation invariants; healthy 879025 distinct states / depth 25; two buggy variants (BuggyReuseNoGenBump, BuggyDoubleAllocate) fire as designed. | new surface (`src/inode/inode.c` + `include/stratum/inode.h` joined CLAUDE.md trigger list at substantive landing) |
| **P8-POSIX-1b** *(closed; R70 + R71 + R71b audits run + applied)* | Per-pool inode tree persistence backed by btree_store (mirrors `stm_extent_index`'s load_at + commit shape). Format break **STM_UB_VERSION 23 → 24** (new `ub_inode_root` + `ub_inode_root_gen` fields in per-device payload; `ub_reserved` 776 → 704). AllocReused path with gen bump per `inode.tla::AllocReused`; FREED state encoded inline via `STM_INO_FLAG_FREED` in `si_flags`. **R70 verdict: 1 P0 + 0 P1 + 2 P2 + 8 P3** — all addressed inline. **R70 P0-1: `inode_csum` folded into the Merkle chain** (closes the same shape as R47 P2-1's repair_log_csum binding — without it an offline-write attacker could swap the inode tree by recomputing `ub_csum` alone). **R71 verdict on the R70 close: 0 P0 + 1 P1 + 2 P2 + 10 P3** — all P0/P1/P2 applied inline. **R71 P1-1: `stm_inode_set` rejects nlink=0 on ALLOCATED records** (closes the silent-commit-then-wedge surface left by R70's asymmetric decoder-only FREED ⇔ nlink invariant — the writer-side guard now mirrors the decoder's check). R71 P2-1 (latch comment split) + P2-2 (get_root docstring drift) fixed. R71 P3-1 through P3-10 forward-noted (mostly regression-test coverage gaps for invariants pinned at audit time). **R71b verdict on the R69-close gap (`6ebf295` retroactive): 0 P0 + 0 P1 + 0 P2 + 2 P3** — clean. R71b P3-1 (cap-doubling guard tightened to bound the `* sizeof` multiplication in `get_or_create_dsstate` + `append_record`) + P3-2 (state-preservation-after-rejection assertion in `inode_set_refuses_unknown_data_kind`) applied inline. test_inode 32 → 36; test_sync 24 → 25. | composes over `inode.tla` (no spec extension required) | inode (existing surface) + sync.c (commit hookup) + uberblock layout (format break) + Merkle root chain (R70 P0-1) |
| **P8-POSIX-2** *(closed; R72 audit run + applied)* | Dirent layer. Per-pool hash-indexed B-tree per ARCH §11.4: key `(le64 dataset_id || le64 dir_ino || le64 hash_probe)` where `hash_probe = fnv1a64(name) + probe_offset`. Probe-chain (cap 64) for collisions per ARCH §11.4.2. Format break **STM_UB_VERSION 24 → 25** (new `ub_dirent_root` + `ub_dirent_root_gen` fields; `ub_reserved` 704 → 632; new `STM_BPTR_KIND_DIRENT_TREE = 13`). Merkle binding extended to 9th input (`dirent_csum`) in lockstep with the field introduction (R70 P0-1 lesson). Open-addressing primitives `stm_dirent_alloc` / `_lookup` / `_unlink` / `_count_for_dir` per dirent.tla; tombstones encoded inline via `STM_DIRENT_FLAG_TOMBSTONE`. Writer-side guards symmetric with decoder-side guards (R71 P1-1 lesson) — alloc rejects every shape the decoder rejects (zero ino / zero name_len / invalid child_type / oversized name). **R72 verdict: 0 P0 + 0 P1 + 1 P2 + 5 P3** — clean; disciplines from R70/R71/R71b transferred correctly. R72 P2-1 (sync-level integration coverage gap, analog of R70 P2-1 for inode) closed inline by `sync_dirent_persistence_roundtrip` test in test_sync.c covering set_storage / set_crypt_ctx / load_at order / bp_kind check / csum mirror / build_uberblock with the dirent triple / 9-input Merkle binding across both 1-phase fresh-pool commit + 2-phase across-mount commit, plus tombstone-slot-reuse post-load (R72 P3-2 folded in). R72 P3-1 (forced-FNV-collision regression test), P3-3 (chain-exhaustion STM_ENOSPC coverage), P3-4 (uint64-wrap cosmetic), P3-5 (byte-layout pin) forward-noted into P8-POSIX-2b's audit. 15 tests in test_dirent.c + sync_dirent_persistence_roundtrip in test_sync.c green default + ASan + TSan. Higher-level fs APIs (stm_fs_lookup / _create_file / _mkdir / _unlink / _rmdir) deferred to P8-POSIX-2b — they compose dirent + inode at the per-fs lock layer. | **`dirent.tla` LANDED** — open-addressing chain integrity (581 healthy states / depth 7); 3 buggy variants `BuggyUnlinkUsesEmpty` (82 states), `BuggyCreateOverwritesNoProbe` (14 states), `BuggyLookupStopsOnTombstone` (84 states) all fire as designed. **No spec extension required** for persistence (composes via `btree_store`). | new surface (`src/dirent/` + `include/stratum/dirent.h` joined CLAUDE.md trigger list at substantive landing) + sync.c (commit hookup + Merkle binding) + uberblock layout (format break v24 → v25) + Merkle root chain (9th csum) |
| **P8-POSIX-2b** *(closed; R73 audit run + applied)* | fs.c POSIX wrappers composing dirent + inode at the per-fs lock layer: `stm_fs_lookup` / `_create_file` / `_mkdir` / `_unlink` / `_rmdir`. Lock chain: `fs->lock → inode_idx mutex / dirent_idx mutex` (siblings, no cross-locking). Atomicity: create-paths roll back the freshly-allocated inode if dirent-link fails (no orphans on failure). MVP single-link semantics — unlink frees the inode unconditionally; hard links + nlink decrement defer to P8-POSIX-3 (`P8-POSIX-3-TODO:` markers added inline at the cascade-free site for grep-discoverability). POSIX name validation: 1..255 bytes, no NUL/'/'; "." and ".." reserved. New error codes `STM_ENOTDIR / STM_EISDIR / STM_ENOTEMPTY` (POSIX-aligned values). **R73 verdict: 0 P0 + 0 P1 + 1 P2 + 7 P3** — composition is sound. R73 P2-1 (rmdir leaks orphan tombstones at freed dir_ino) closed inline by new `stm_dirent_drop_for_dir` primitive called from rmdir before inode_free; P3-5 (rmdir-with-tombstones test) folded into the same close as `fs_p2b_r73_p2_1_rmdir_cleans_orphan_tombstones`; P3-6 (P8-POSIX-3-TODO comment) applied. R73 P3-1 (forced FNV-collision test for tombstone-walk), P3-2 (uint8_t > 255u dead-code), P3-3 + P3-4 (R72 forward-noted concerns still uncovered: forced collision + chain exhaustion at wrapper layer), P3-7 (per-API arg-validation matrix coverage gap) all forward-noted into P8-POSIX-3's audit close. test_dirent 15 → 17 (drop_for_dir tests); test_fs 170 → 171. | composes over `inode.tla` + `dirent.tla` (no spec extension required for MVP single-link semantics; nlink + hard-link atomicity invariants land at P8-POSIX-3) | composes 2 trigger surfaces: inode allocator + dirent layer + Public API contracts (5 new fs.h decls + 1 new dirent.h primitive) |
| **P8-POSIX-3** *(closed; R74 audit run + applied)* | Metadata ops + nlink + hard links. New fs APIs: `stm_fs_stat` (returns full 256-byte stm_inode_value), `stm_fs_chmod` (preserves S_IFMT bits; rejects type-mismatch), `stm_fs_chown` (UINT32_MAX = leave-unchanged, POSIX `chown(-1)` semantics), `stm_fs_utimens` (atime + mtime + caller-supplied ctime; nsec validated < 1e9), `stm_fs_link` (same-dataset hard link; signature precludes cross-dataset; hard-link-on-directory refused with STM_ENOTSUPPORTED per POSIX). New inode-layer APIs: `stm_inode_link` (nlink++) + `stm_inode_unlink` (nlink--; cascade-free atomically when nlink reaches 0 — models inode.tla::Unlink). The MVP single-link unconditional `stm_inode_free` from P8-POSIX-2b's unlink/rmdir wrappers has been replaced by `stm_inode_unlink`'s cascade-free path. **R74 verdict: 0 P0 + 0 P1 + 0 P2 + 4 P3** — clean. R74 P3-1 (cross-dataset STM_EXDEV unreachable in single-`dataset_id` signature) + R74 P3-2 (STM_EPERM ↛ STM_ENOTSUPPORTED docstring drift) closed inline via docstring tightening; R74 P3-3 (rollback failure swallowed in stm_fs_link's (void)-cast — defense-in-depth gap, theoretical only under fs->lock) annotated inline with future-mark-wedged note; R74 P3-4 (utimens 0/0 epoch sentinel collision — placeholder until P8-POSIX-7 statx clock integration) forward-noted. test_fs 171 → 178; test_inode 36 → 40. | **`inode.tla` EXTENDED** — adds `nlink` shadow var + Link/Unlink actions + `LinkedAllocatedHasPositiveNlink` + `FreedHasZeroNlink` invariants. New `BuggyUnlinkLeavesZeroNlink` config (fires LinkedAllocatedHasPositiveNlink). Healthy 9.87M states / 2.96M distinct (Inos=3, MaxGen=3, MaxNlink=2). | inode (allocator + new link/unlink) + fs (5 new public APIs) |
| **P8-POSIX-4** | `stm_fs_readdir` with stable cookies + restartable iteration + tombstone handling. | extends `dirent.tla` (cookie stability under concurrent insert/delete) | dirent |
| **P8-POSIX-5** | Inline data optimization: ≤100B files store in `si_inline_data`. Inline-to-extent transition on first write past the threshold (atomic via existing extent COW). | extends `inode.tla` (inline ↔ extent transition) | inode + extent write path |
| **P8-POSIX-6** | xattr keyspace `(ino, STM_KEY_XATTR, fnv1a(name)) → value`. POSIX ACLs (`system.posix_acl_access` + `system.posix_acl_default`) via xattr. | `xattr.tla` (collision chain mirroring dirent) | new surface |
| **P8-POSIX-7** | Full modern POSIX surface (no hedged subset; per ROADMAP §11.1's commitment to complete coverage). May subdivide into 7a/7b/... at impl time: **(7a)** `O_TMPFILE` + every `F_SEAL_*` flag (`SEAL`, `SHRINK`, `GROW`, `WRITE`, `FUTURE_WRITE`) + `statx(2)` shape with btime + nanosecond timestamps. **(7b)** Every `FALLOC_FL_*` flag (`KEEP_SIZE`, `PUNCH_HOLE`, `COLLAPSE_RANGE`, `ZERO_RANGE`, `INSERT_RANGE`, `UNSHARE_RANGE`) — extent-tree manipulation primitives for COLLAPSE/INSERT land alongside; UNSHARE composes with the CAS rehydrate path. **(7c)** `name_to_handle_at(2)` + `open_by_handle_at(2)` over the `(dataset_id, ino, si_gen)` tuple; stale-handle detection via the `inode.tla`-pinned `si_gen` uniqueness invariant. **(7d)** Advisory locking (`flock(2)` + `fcntl(2)` `F_SETLK`/`F_GETLK`/`F_OFD_SETLK`); per-inode lock table with deadlock detection. **(7e)** `posix_fadvise(2)` pass-through to `STM_PROP_TIERING` advisory layer. | composes over inode.tla; `(7d)` introduces a `locks.tla` extension for the per-inode lock table's deadlock-freedom invariant. | inode + dirent + sync |
| **P8-POSIX-8** | Symlinks. Inline target ≤100B; longer via extent tree. `stm_fs_symlink` / `stm_fs_readlink`. | composes over inode.tla | inode |
| **P8-POSIX-9** | `stm_fs_rename` + `renameat2(2)` flag set: `RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_WHITEOUT`. Atomicity under concurrent dirent mutations in source + target dirs. Cross-directory rename. Cross-dataset rename refused with EXDEV. Same-name target replacement. | extends `dirent.tla` (rename atomicity, including `RENAME_EXCHANGE` two-slot atomic swap) | dirent + sync |
| **P8-POSIX-10** | `copy_file_range` reflink wrapper over existing `stm_fs_reflink` (P7-16). `stm_fs_truncate` inode wrapper over existing extent-level `stm_sync_truncate` (P7-9). | composes over existing reflink + truncate | inode + dirent |
| **P8-POSIX-11** | Tests + audit + xfstests integration prep. Property-based tests for the file/dir/xattr/ACL layer. Regression suite for ARCH §11 corner cases. | — | full P8 surface |

## Exit criteria (ROADMAP §11.2)

- [ ] All POSIX file/dir ops produce semantically correct results
      matching ext4/XFS/APFS for a representative test corpus.
- [ ] Hash-collision chain works correctly with ≥1k dirents per
      directory.
- [ ] Hard link nlink remains correct under concurrent create/unlink.
- [ ] Inline-to-extent transition recovers correctly across crash
      boundaries.
- [ ] `statx` returns nanosecond timestamps + btime.
- [ ] POSIX ACL roundtrip preserves grants/denies bit-exact.
- [ ] `inode.tla` + `dirent.tla` (+ likely `xattr.tla`) pin the
      load-bearing invariants under TLC.
- [ ] xfstests subset (file/dir/xattr/ACL portion) green on
      Stratum-backed mount once Phase 9 (FUSE) lands; in Phase 8
      the equivalent verification runs against the `stm_fs_*` API
      directly.

## Posture going in

Inheriting from Phase 7 exit (`1759caf` + P8-NS-1 spec at `bea7f82`):

| | |
|---|---|
| STM_UB_VERSION | 23 (last bumped at P7-CAS-16). Phase 8 will likely bump for the inode tree on-disk format addition (probably v23 → v24 at P8-POSIX-1). |
| STM_SEND_VERSION | 3 |
| Spec posture | 22 modules / 26 fixed cfgs / 38 buggy cfgs (after P8-NS-1's namespace.tla landed). Phase 8 adds `inode.tla`, `dirent.tla`, probably `xattr.tla` — projected 24-25 modules at Phase 8 exit. |
| ctest | 35 suites green default + ASan + TSan |
| test_fs | 159 |
| test_send_recv | 40 |
| Audits closed | R0 — R68 |

## Format break expectations

P8-POSIX-1 will add a NEW per-dataset on-disk surface (the inode
tree). This is a format break — STM_UB_VERSION 23 → 24. v23 pools
won't have an inode tree; mounting them on v24 would need either
a migration step or a refusal at mount. Probably refusal at
mount with STM_EBADVERSION (mirroring P7-CAS-16's pattern), since
v23 → v24 represents adding a load-bearing structural layer
rather than extending an existing record shape.

Format-break signoff required per CLAUDE.md before P8-POSIX-1
substantive lands.

## Operational notes

- Spec-first (CLAUDE.md): inode and dirent invariants are
  load-bearing. `inode.tla` lands BEFORE P8-POSIX-1 substantive,
  `dirent.tla` lands BEFORE P8-POSIX-2 substantive.
- Audit-per-change: `src/inode/` and `src/dirent/` join the
  CLAUDE.md trigger list as soon as the first chunk lands. The
  v1 `src/p9/p9.c` audit pattern (R6, R12 specifically) carries
  forward — silent dirent-tree corruption is the canonical
  failure mode here.
- Memory primer roll at every chunk close: MEMORY.md index +
  project_v2_active.md tip / lineage table + project_v2_next_session.md.
