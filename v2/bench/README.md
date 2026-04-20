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

## Interpreting scaling numbers

Per-thread scaling percentages are relative to t=1 throughput. ≥ 95%
at t=2/4 indicates the lock-free / EBR design delivers on its
low-contention promise. The drop at t=8 on Apple M-series is
performance-vs-efficiency core asymmetry — half the threads are
running on slower efficiency cores, distorting the metric. On a
uniform 32-core Linux host, scaling should remain ≥ 90% per the
Phase 2 exit criterion.

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
