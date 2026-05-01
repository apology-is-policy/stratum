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
| **P8-POSIX-1b** *(closed; R70 audit run + applied)* | Per-pool inode tree persistence backed by btree_store (mirrors `stm_extent_index`'s load_at + commit shape). Format break **STM_UB_VERSION 23 → 24** (new `ub_inode_root` + `ub_inode_root_gen` fields in per-device payload; `ub_reserved` 776 → 704). AllocReused path with gen bump per `inode.tla::AllocReused`; FREED state encoded inline via `STM_INO_FLAG_FREED` in `si_flags`. R70 audit verdict: 1 P0 + 0 P1 + 2 P2 + 8 P3 — all addressed inline. **R70 P0-1: `inode_csum` folded into the Merkle chain** (closes the same shape as R47 P2-1's repair_log_csum binding — without it an offline-write attacker could swap the inode tree by recomputing `ub_csum` alone). R70 P2-1 added end-to-end sync-level roundtrip coverage in `test_sync.c`. R70 P2-2 + P3-1 / P3-2 / P3-3 / P3-4 / P3-5 / P3-6 / P3-8 all fixed inline (FREED-record-at-UINT64_MAX skip in alloc; reject ino==UINT64_MAX in load decoder; FREED ⇔ nlink invariant at decode; memcmp guard in Set; idx_lock(idx) consistency; bound-once latch on set_storage / set_crypt_ctx; `stm_sync_inode_index` accessor published alongside the get_root contract clarification). P3-7 forward-noted (bootstrap_commit fsync amortization across all indices). test_inode 32 → 35; test_sync 24 → 25. | composes over `inode.tla` (no spec extension required for persistence; AllocReused already modeled) | inode (existing surface) + sync.c (commit hookup) + uberblock layout (format break) + Merkle root chain (R70 P0-1) |
| **P8-POSIX-2** | Dirent layer. Hash-indexed B-tree per ARCH §11: key `(dir_ino, STM_KEY_DIRENT, fnv1a(name))`. Probe-chain for collisions. `stm_fs_lookup` / `stm_fs_create_file` / `stm_fs_mkdir` / `stm_fs_unlink` / `stm_fs_rmdir`. | `dirent.tla` — collision chain + lookup correctness + create/unlink atomicity | new surface |
| **P8-POSIX-3** | Metadata ops: `stm_fs_stat` / `stm_fs_chmod` / `stm_fs_chown` / `stm_fs_utimens`. nlink tracking. Hard links (`stm_fs_link`). | extends `inode.tla` (nlink under create / link / unlink races) | inode + dirent |
| **P8-POSIX-4** | `stm_fs_readdir` with stable cookies + restartable iteration + tombstone handling. | extends `dirent.tla` (cookie stability under concurrent insert/delete) | dirent |
| **P8-POSIX-5** | Inline data optimization: ≤100B files store in `si_inline_data`. Inline-to-extent transition on first write past the threshold (atomic via existing extent COW). | extends `inode.tla` (inline ↔ extent transition) | inode + extent write path |
| **P8-POSIX-6** | xattr keyspace `(ino, STM_KEY_XATTR, fnv1a(name)) → value`. POSIX ACLs (`system.posix_acl_access` + `system.posix_acl_default`) via xattr. | `xattr.tla` (collision chain mirroring dirent) | new surface |
| **P8-POSIX-7** | Modern POSIX: `O_TMPFILE` (orphan inode + `linkat` materialization), `F_SEAL_*` flags, `statx(2)` shape with btime + nanosecond timestamps, `fallocate(FALLOC_FL_KEEP_SIZE)` + `FALLOC_FL_PUNCH_HOLE`. | composes over inode.tla | inode + dirent |
| **P8-POSIX-8** | Symlinks. Inline target ≤100B; longer via extent tree. `stm_fs_symlink` / `stm_fs_readlink`. | composes over inode.tla | inode |
| **P8-POSIX-9** | `stm_fs_rename`. Atomicity under concurrent dirent mutations in source + target dirs. Cross-directory rename. Cross-dataset rename refused with EXDEV. Same-name target replacement. | extends `dirent.tla` (rename atomicity) | dirent + sync |
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
