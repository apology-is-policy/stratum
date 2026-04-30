# v2 benchmarks

Opt-in benchmark binaries. Not built by default; not run by ctest.

## Build

```
cmake -B build-bench -S . -DSTM_BUILD_BENCHES=ON
cmake --build build-bench -j
```

## Run

```
# Bw-tree benchmarks: single-writer throughput + multi-reader scaling.
build-bench/bench/bench_btree_lf

# Snapshot benchmarks: ROADMAP §9.2 #1 + #2.
build-bench/bench/bench_snapshot

# Dedup ratio benchmark: ROADMAP §10.2 #1 (P7-VAL-1).
build-bench/bench/bench_dedup --help
build-bench/bench/bench_dedup --files=20 --base-mib=10 --mod-percent=20
```

Output on an 8-core Apple Silicon (M-series, 4P+4E):

```
Bw-tree benchmarks (hw.ncpu=8)

Single-writer insert throughput:
  single-writer insert:  100000 keys in 0.598s  (167099 ops/s, target=64)
  single-writer insert:  100000 keys in 0.311s  (321641 ops/s, target=256)

Multi-reader lookup scaling:
  multi-reader lookup scaling (N=50000 keys, 200000 lookups/thread, target=64):
    t= 1:    472123 lookups/s  (100.0% of linear)
    t= 2:    938914 lookups/s  ( 99.4% of linear)
    t= 4:   1811323 lookups/s  ( 95.9% of linear)
    t= 8:   2282115 lookups/s  ( 60.4% of linear)
```

Snapshot benchmarks on the same host:

```
snap_create — per-op latency vs in-pool snapshot population
(ROADMAP §9.2 #1: < 10 ms regardless of dataset size)
  N_snaps=       10          5183 ns/op       192938 ops/s  (0.0052 ms/op  ok)
  N_snaps=      100          6340 ns/op       157729 ops/s  (0.0063 ms/op  ok)
  N_snaps=     1000         11559 ns/op        86513 ops/s  (0.0116 ms/op  ok)
  N_snaps=    10000         35276 ns/op        28348 ops/s  (0.0353 ms/op  ok)
  N_snaps=   100000        910400 ns/op         1098 ops/s  (0.9104 ms/op  ok)

snap_delete — per-op latency vs dead-list size
  dead=   0           25.0 ns/op
  dead=  32           20.0 ns/op
  dead= 128           40.0 ns/op
  dead= 256           25.0 ns/op

overwrite_block — throughput (R33 P2 dup-paddr defense scan cost)
  N_dead=  32           31 ns/op     31999756 ops/s
  N_dead= 128           39 ns/op     25599805 ops/s
  N_dead= 256           62 ns/op     16000111 ops/s
```

## Interpreting scaling numbers

Per-thread scaling percentages are relative to t=1 throughput. ≥ 95%
at t=2/4 indicates the lock-free / EBR design delivers on its
low-contention promise. The drop at t=8 on Apple M-series is
performance-vs-efficiency core asymmetry — half the threads are
running on slower efficiency cores, distorting the metric. On a
uniform 32-core Linux host, scaling should remain ≥ 90% per the
Phase 2 exit criterion.

## Interpreting snapshot numbers

Two ROADMAP §9.2 criteria:

- **#1: snap_create < 10 ms regardless of dataset size.** The
  snapshot module never walks the dataset btree — `stm_snapshot_create`
  stores only the dataset's tree-root paddr. So dataset SIZE (number
  of blocks / keys in the dataset) doesn't enter the picture. The
  visible scaling axis is in-pool snapshot count: `most_recent_locked`
  walks the linear-array index O(N). Even at N=100k the per-op
  latency is < 1 ms, comfortably under the 10 ms criterion.
  Production-scale pools may eventually want an O(log N) index
  (sorted array or per-dataset hash) — deferred until a real
  pool surfaces ≥ 100k snapshots.

- **#2: snap_delete proportional to blocks freed, not total tree.**
  The snap module's portion of delete is genuinely O(1): a pointer
  swap that hands the dead_list buffer to the caller. Per-paddr
  reclaim work (the O(K) part) lives in the caller's `stm_alloc_free`
  loop. The bench numbers here measure the snap-module slice only —
  they're constant-time as expected.

The `overwrite_block` numbers exercise the R33 P2 single-ownership
defense scan that walks all PRESENT slots' dead-lists for the
appended paddr. Cost grows linearly with total dead entries; at
N_dead=256 it's still 62 ns/op. Bounded by `STM_SNAP_DEAD_LIST_MAX`
× n_snaps; production-grade chunked dead-list (deferred) will
need a sorted-merge or hash replacement here.

## Interpreting dedup numbers (P7-VAL-1)

ROADMAP §10.2 exit criterion 1: "Cold-tier dedup achieves target
3-5× on VM-image test set." `bench_dedup` ingests a deterministic
synthetic VM-image corpus (a shared `base` byte stream + N files
each derived from base by overwriting `mod_percent` of bytes in
scattered regions), runs `stm_fs_migrate_to_cold` per file, and
reports

    dedup_ratio = bytes_written / sum_of_cas_chunk_lengths

The ratio is dominated by three knobs:

- **`--files=N`** — more files share the base's content-defined
  chunks. Ratio ≈ `N / (1 + (mod_percent/100) × N)` minus a small
  constant for boundary chunks at modification edges.
- **`--mod-percent=P`** — the fraction of each file overwritten
  with file-unique content. Lower P = more shared chunks per file
  = higher ratio. ROADMAP cites "80% overlap" → P = 20.
- **`--avg-chunk-kib=A`** — FastCDC chunk granularity. Smaller
  chunks track modifications more precisely (fewer wasted bytes
  in boundary chunks) but add proportional CAS-index overhead.
  Default 64 KiB.

Headline configurations on an 8-core Apple Silicon (~1 sec/MiB
ingest, ~0.2 GB/s sustained):

```
files= 10  base= 10 MiB  mod=10%   →  4.43×  (100 MiB → 23 MiB)
files= 20  base= 10 MiB  mod=20%   →  3.21×  (200 MiB → 62 MiB)
files= 50  base= 10 MiB  mod=15%   →  4.59×  (500 MiB → 109 MiB)
```

All three pass ROADMAP §10.2 #1's lower bound (3×). The 5× target
is achievable at `--mod-percent=10` or `--files=100`. The bench
exits 0 if `dedup_ratio >= 3.0` and 1 otherwise so CI can flag
regressions.

### Determinism + reproducibility

The corpus is generated from fixed seeds keyed by the file index;
identical `(--files, --base-mib, --mod-percent)` always produce
identical bytes → identical CAS chunks → identical ratio. A run
on macOS and a run on Ubuntu/GCP under the same parameters report
the same numbers byte-for-byte.

### Test-hooks dependency

The bench links via `stm_fs_sync_for_test` + `stm_sync_set_cdc_params_for_test`
so it can install non-default FastCDC params (the production default
of 8 MiB avg / 2 MiB min would force K=1 chunk per recordsize-bound
extent, defeating the test). Both seams are gated behind
`STRATUM_BUILD_TESTING_HOOKS` (ON by default; production opt-out
disables the bench's link).

### Scaling up: GCP runs

For larger corpora (20-50 GiB to demonstrate the ratio at production
scale), see the `--pool-mib` flag and the run script.

## Sustained stress

The `test_btree_lf` binary also contains `btree_lf_long_stress` — a
duration-parameterized concurrent stress test (inserts, deletes,
lookups, periodic force_consolidate). Default is 2 seconds; bump via
env var:

```
# Run 30 seconds under TSan.
cmake -B build-tsan -S . -DSTM_SANITIZE=tsan
cmake --build build-tsan -j
STM_BT_LF_LONG_SEC=30 ctest --test-dir build-tsan -R btree_lf --timeout 200

# Nightly-scale run under TSan (1 hour).
STM_BT_LF_LONG_SEC=3600 ctest --test-dir build-tsan -R btree_lf --timeout 4000
```

Assertion is "no crash / no UB." ASan / TSan / UBSAN detect the rest.
