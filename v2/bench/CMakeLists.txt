# Benchmark targets. Not built by default; enable with
# -DSTM_BUILD_BENCHES=ON. Benchmarks are not test targets — they print
# results to stdout, don't fail the build, and aren't invoked by ctest.

add_executable(bench_btree_lf bench_btree_lf.c)
target_link_libraries(bench_btree_lf
    PRIVATE stratum stm_warnings stm_sanitize)

add_executable(bench_snapshot bench_snapshot.c)
target_link_libraries(bench_snapshot
    PRIVATE stratum stm_warnings stm_sanitize)

# P7-VAL-1: dedup ratio benchmark for ROADMAP §10.2 exit criterion 1.
# Drives full-stack ingest + migrate via stm_fs_*. Uses the
# stm_fs_sync_for_test seam to install FastCDC override params and to
# read CAS index totals — relies on STRATUM_BUILD_TESTING_HOOKS being
# ON (the default; production opt-out is -DSTRATUM_BUILD_TESTING_HOOKS=OFF).
add_executable(bench_dedup bench_dedup.c)
target_link_libraries(bench_dedup
    PRIVATE stratum stm_warnings stm_sanitize)
