# Benchmark targets. Not built by default; enable with
# -DSTM_BUILD_BENCHES=ON. Benchmarks are not test targets — they print
# results to stdout, don't fail the build, and aren't invoked by ctest.

add_executable(bench_btree_lf bench_btree_lf.c)
target_link_libraries(bench_btree_lf
    PRIVATE stratum stm_warnings stm_sanitize)
