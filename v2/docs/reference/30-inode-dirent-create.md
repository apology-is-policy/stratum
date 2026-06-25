# 30 — Inode / dirent create path (as-built)

> Stratum Stabilization Arc, **Area S** ("Pleiades" — many-small-files
> throughput). As-built reference for the small-file create path: inode
> allocation, directory-entry insertion, inline storage, and the metadata
> region that bounds them. Written 2026-06-25 from the Area S line-by-line
> audit + the create-throughput bench ground truth. Companion: `tests/
> bench_create_many.c`, `tests/test_pleiades.c`, `specs/inode.tla`,
> `specs/dirent.tla`.

## 30.1 — Purpose + the one-paragraph model

A `go build` (and any source-tree extraction, `git clone`, or toolchain
unpack) is a **storm of small files**: thousands of create / write / unlink
across nested directories. This is the metadata path, not the data path —
each create allocates an inode, links a dirent, and (for ≤100-byte files)
stores the content inline in the inode, touching **no extent and no data-area
block**. The cost is therefore dominated by btree-engine inserts + the dirent
probe walk + the per-commit metadata flush, **not** file-data bandwidth (§30.6).

## 30.2 — The create path

`stm_fs_create_file` (`src/fs/fs.c:2772`) → `fs_create_inode_and_link`
(`src/fs/fs.c:2645`), under `fs->global` SH + a parent pin + a fresh-child pin
(PARALLEL-3 CREATE shape):

1. Pin parent, load its dir value (`fs_load_parent_dir`).
2. **Allocate the inode** — `stm_inode_alloc` (§30.3). Writes the inode record
   (gen 0 fresh, or `prior_gen+1` reused; zero timestamps).
3. Pin the fresh child; **read it back** — `stm_inode_lookup` — to recover
   `si_gen` for the dirent's `child_gen` field.
4. **Stamp create times** (btime/atime/mtime/ctime, POSIX-7a) into the read-back
   value and **re-write** it — `stm_inode_set`.
5. **Link the dirent** — `stm_dirent_alloc` (§30.4). On failure, the inode is
   freed (full rollback).

> **Per-create metadata work** = TWO inode btree inserts to the same key
> (alloc at step 2, the timestamp-stamped rewrite at step 4) + one read-back
> lookup (step 3) + one dirent insert (step 5). Folding steps 2–4 into a single
> stamped insert (have `stm_inode_alloc` return the gen so the read-back is
> unnecessary, and construct the final value once) is a tracked throughput seam
> — **S-3** (§30.7). It is layering-sensitive: the inode layer allocs a bare
> record; the FS layer owns the POSIX timestamp policy (`fs.c:2729`).

## 30.3 — The inode allocator (the O(1) reuse-gate, Area S fix)

`stm_inode_alloc` → `in_alloc_common` (`src/inode/inode.c`). Models
`inode.tla`'s **AllocReused → AllocFresh** fallback:

- **AllocReused** (preferred): reuse a FREED ino, `si_gen += 1` (preserves the
  `(ino, gen)` tuple-uniqueness invariant; a `gen == UINT64_MAX` slot is
  skipped — `in_freed_cb` — so the +1 never wraps).
- **AllocFresh**: `ino = next_ino`, gen 0, bump `next_ino` (the high-water mark,
  lazily seeded past every stored record on first use — `in_seed_dsstate_locked`).

**The fix (S-1/S-1b — the O(N²) → O(1) reuse-gate).** Before Area S, *every*
alloc called `in_find_freed`, a `stm_btree_engine_scan_range` over the WHOLE
inode keyspace looking for a FREED ino, early-stopping only at the first one.
A fresh-create storm (no freed inos) scanned **all N existing inodes per
alloc → O(N²)** for N creates; a recreate-after-mass-unlink storm was likewise
O(N²) on the reuse path (each scan re-walked the consumed prefix). Two in-RAM
per-dataset (`stm_inode_dsstate`) fields close it:

- **`freed_count`** — the number of FREED records in the dataset. **Gates** the
  scan: `in_find_freed` runs only when `freed_count > 0`. When it is 0 the scan
  would find nothing anyway, so the gate is behavior-identical, just O(1).
  Seeded by the existing mount scan (`in_seed_cb` counts FREED records for
  free); `++` on free / cascade-unlink; `--` on AllocReused.
- **`freed_scan_lo`** — a cursor with the invariant **"no FREED record has
  ino < freed_scan_lo."** `in_find_freed` starts the scan here instead of ino 0,
  so consuming freed inos in key order does not re-walk the consumed prefix.
  Lowered to `ino` on a free below it; advanced to the consumed ino on reuse;
  seeded to the min FREED ino. Always ≥ 1 and ≤ every FREED ino, so the scan is
  **never broader than the old from-0 scan** (strictly never worse).

**Behavior preservation.** `freed_scan_lo ≤` every FREED ino, so the scan from
the cursor returns the *same lowest FREED ino* the old from-0 scan did — reuse
order (lowest-first) is byte-identical. The gate skips the scan only when
`freed_count == 0` ⟺ no FREED record exists ⟺ the scan would find nothing
⟺ AllocFresh, which `inode.tla` always permits. **A stale count/cursor is
safe-degraded**: the only failure mode is "skip a possible reuse" → AllocFresh
(model-valid, just grows `next_ino`); it can never mis-allocate (no live ino
re-handed-out, no gen reuse), and a remount's seed re-derives both fields.

**FREED-producer completeness.** All inode-record writes go through
`in_engine_put` (inode.c-only — no recv/migrate/snapshot/clone bypass; a clone's
seed re-counts the copied engine). The FREED bit is OR-set in exactly two
places — `stm_inode_free` and `stm_inode_unlink`'s cascade — both maintain
`freed_count`/`freed_scan_lo` (guarded `if (s && s->seeded)`; an unseeded free
is counted by the later lazy seed, so the tally is exactly-once).

## 30.4 — The directory (dirent open-addressing)

`stm_dirent_alloc` (`src/dirent/dirent.c:514`). Each dataset has one dirent
btree-engine keyed `(dir_ino, hash_probe)`; entries use **open addressing**:
`hash_base = fnv1a64(name)`, probe `hash_base + k` for `k ∈ [0, STM_DIRENT_
PROBE_MAX=64)`. The walk tracks the first install-eligible slot (EMPTY /
TOMBSTONE / same-name WHITEOUT) but keeps walking to detect EEXIST; it
**early-terminates only at an EMPTY slot**. A tombstone is a reusable install
slot but a chain-occupying slot for lookup (no compaction back to EMPTY).

**Throughput + ceiling caveats** (§30.7): a heavily-churned directory (many
tombstones, no EMPTY within a 64-probe window) makes every alloc walk all 64
`di_engine_get` probes; and 64 *simultaneously-live* different-named entries
colliding in one window return STM_ENOSPC. For non-adversarial names (the
go-build's `_pkg_.a` / `go_asm.h` / `importcfg`) FNV-1a over 2⁶⁴ makes both
astronomically unlikely — verified by `test_pleiades` (2000 files in one dir,
all create + readdir-complete + lookup-each).

## 30.5 — Inline storage + the metadata region

**Inline.** A regular file ≤ `STM_INODE_INLINE_MAX = 100` bytes
(`include/stratum/inode.h`) stores its content in the inode's `inline_data[]`
(`fs.c:1960` inline write fast-path; wait-free inline read `fs.c:2360`) — no
extent, no data-area block. Crossing 100 bytes transitions to a single extent
(`fs.c:1981`). `test_pleiades` pins the 99/100/101-byte boundary round-trip.

**Metadata region.** Inode + dirent + allocator btree nodes are COW'd into the
**bootstrap region**, NOT the data area (a create-only workload leaves
`stm_fs_stats.data_allocated_blocks == 0`). Production auto-sizes it
`default_bootstrap_for(device_bytes) = device/16`, floor 8 MiB, ceiling 256 MiB
(`src/cmd/stratum-mkfs/run.c:65`). This is the documented metadata-density limit
(§30.7 S-2).

## 30.6 — Throughput characterization

`tests/bench_create_many.c` (create N files in a dir; env knobs
`STM_BENCH_NFILES`/`FSIZE`/`COMMIT`/`DIRS`/`CHURN`/`BOOT_MB`/`VERBOSE`;
non-sanitized build).

**S-1 fix — fresh-create rate (create-only, single commit), before vs after:**

```
   N      before us/file   after us/file   speedup
  5000        33.2             15.0          2.2x
 10000        52.2              9.5          5.5x
 20000        99.3              7.6           13x
 40000       192.8              7.8           25x
 80000       498.8              8.4           59x
```

Before, per-file cost *doubled when N doubled* (the O(N²) signature); after, it
is **flat** (~8 µs/file, O(1) per create). The reuse path (recreate-after-mass-
unlink) tracks the same shape: before 33→58→95 µs/file (5k/10k/20k), after
13→10→8.8 (the `freed_scan_lo` cursor; churn_ratio ≈ 1.0 — reuse ≈ fresh).

**S-2 — per-commit metadata amplification (NOT the S-1 fix; tracked seam).**
Committing *frequently* re-COWs the growing metadata tree each commit:
commit-every-2000 runs ~125 µs/file vs ~52 µs/file single-commit (20k files), and
at an under-sized bootstrap (8 MiB on a 512 MB device = device/64, below
production's device/16) the multi-commit case exhausts the metadata region
(STM_ENOSPC). At production-representative bootstrap (32 MiB = device/16) the
same 20k-file / 10-commit workload **succeeds**. So the ENOSPC is bootstrap
under-sizing, not an acute defect; the *throughput* amplification is real and
redesign-class (§30.7).

## 30.7 — Known caveats / tracked perf debt

- **S-2 [redesign-class, tracked].** All FS metadata is confined to the
  fixed-at-format bootstrap region (device/16, ceiling 256 MiB), and frequent
  commits re-COW the growing tree (per-commit metadata write-amplification). The
  *proper* fix is server-side metadata-density work — larger default extents,
  btree fanout tuning, and/or batching small metadata updates (the Bε buffer of
  Stratum phase 9.8 / the Thylacine concurrent-FS arc) — explicitly forward-noted
  at `run.c:67`. Bounds a *very* metadata-heavy or per-file-fsync workload, not
  the v1.0 go-build at production bootstrap sizing.
- **S-3 [point-fixable, tracked].** The create path writes the inode twice
  (alloc + timestamp-stamp) + reads it back. Folding to one stamped insert
  (alloc returns gen) removes a btree insert + a lookup per create. Layering-
  sensitive (the inode layer must not learn FS timestamp policy); a clean
  realization passes the initial timestamps to the alloc or returns the gen so
  the FS builds the final value once. The Area S audit confirmed the fold is
  sound + layering-safe (the gen is already allocator-computed) and is now the
  *largest* remaining per-create cost (a root-to-leaf btree COW per redundant
  insert) — the recommended next Area-S create-path optimization.
- **Inline threshold = 100 bytes.** Files 101 B–4 KiB pay a full extent + AEAD
  tag + alloc despite being sub-block. Raising the threshold is an on-disk inode
  format change (tracked, not v1.0).
- **gen == UINT64_MAX FREED slot.** Counted in `freed_count` but skipped by
  `in_freed_cb` (no gen wrap), so it can pin `freed_count > 0` and re-enable the
  per-alloc scan for that dataset. Reachable only after 2⁶⁴ alloc/free cycles on
  one ino — practically impossible — and degrades to the pre-fix O(N) scan, never
  incorrect.
- **Rollback leaves the dsstate stale (Area S audit F1).** The snapshot-rollback
  engine-root swap (`stm_fs_rollback_snapshot` → `stm_dataset_index_set_engine_
  root`) does NOT re-seed the in-RAM inode dsstate, so `next_ino` / `freed_count`
  / `freed_scan_lo` reflect the discarded post-snapshot tree after a rollback.
  **Safe-degraded** (pre-existing for `next_ino`): the scan reads the LIVE
  engine, and `next_ino` stays a monotone high-water mark ≥ the rolled-back
  tree's max, so AllocFresh never re-issues a live ino. The robust fix
  (invalidate `seeded=false` at `set_engine_root`) is the inode twin of Area-D's
  `eng->root` F2 — tracked on the phase-9.8 ledger, fixed with the concurrent-FS
  arc (where the multi-connection model must also re-validate the monotonicity).
- **The reuse-gate complexity bound.** The `freed_scan_lo` cursor is amortized-
  O(1) for the sequential / storm reuse patterns (the measured common case, §30.6)
  and **strictly never worse than the pre-fix from-0 scan**; the adversarial
  worst case (a free-high-while-cursor-low interleave a real workload does not
  produce) is O(N) per alloc — equal to, never worse than, pre-fix. A true freed-
  ino min-heap would close the residual but is unwarranted for v1.0.
- **Dirent 64-probe ENOSPC ceiling.** A directory with 64 simultaneously-live
  different-named entries colliding in one FNV-1a window returns STM_ENOSPC.
  Astronomically unlikely for non-adversarial names; a hostile-name workload is a
  separate hardening concern.

## 30.8 — Tests

- `tests/test_pleiades.c` (Area S) — 2000 files in one dir (create + readdir
  completeness + lookup-each), chain integrity at N=1000 (unlink-half), churn
  (create/unlink/recreate same names), inline 99/100/101-byte boundary.
- `tests/test_inode.c :: inode_reuse_scattered_lowest_first` (Area S) — pins the
  `freed_count` gate + `freed_scan_lo` cursor: scattered out-of-order frees →
  lowest-first reuse (gen-bumped) → drain-to-fresh → free-below-cursor still
  found. Plus the pre-existing `inode_reuse_gen_monotonic_across_cycles`.
- `tests/bench_create_many.c` (Area S) — the §30.6 create-throughput probe (the
  permanent perf regression for the O(1) reuse-gate).
