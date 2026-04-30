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

# Linker note: stm_sync and stm_scrub form a genuine static-library
# cycle (stm_scrub PUBLIC-deps on stm_sync; stm_sync's wrapper
# stm_sync_scrub_step_with_cas_gc + stm_sync_scrub_install_production_cb
# call back into stm_scrub_step / stm_scrub_consume_completion_signal).
# Apple ld auto-rescans archives so this resolves; Linux ld single-
# passes. CMake's `$<LINK_GROUP:RESCAN,...>` generator expression
# rejects on Apple ld at configure time, so gate on Linux. The two
# archives wrapped here are the cycle pair; the rest of stratum's
# deps are linear.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(bench_dedup PRIVATE
        "$<LINK_GROUP:RESCAN,stm_sync,stm_scrub>")
endif()

# P7-VAL-2: reflink complexity benchmark for ROADMAP §10.2 exit criterion 4
# ("Reflink is O(extent count) not O(data size)"). Sweeps two axes — extent
# count at fixed extent size, then extent size at fixed extent count — and
# reports per-extent wall-clock. Verdict: per-extent cost roughly constant
# across both axes proves the complexity claim. Same Linux ld cycle gating
# as bench_dedup.
add_executable(bench_reflink_complexity bench_reflink_complexity.c)
target_link_libraries(bench_reflink_complexity
    PRIVATE stratum stm_warnings stm_sanitize)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(bench_reflink_complexity PRIVATE
        "$<LINK_GROUP:RESCAN,stm_sync,stm_scrub>")
endif()
