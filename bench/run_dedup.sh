#!/usr/bin/env bash
# P7-VAL-1 dedup benchmark sweep. Builds the bench (if not built),
# runs it across a sweep of configurations, and writes a CSV
# summary. Designed to run on Linux / GCP for the ROADMAP §10.2
# validation target; works on macOS too for development.
#
# Usage:
#   ./run_dedup.sh [scale]
#
# scale = 'tiny' | 'small' | 'medium' | 'large' (default 'small')
#
#   tiny     — 4 configs × ~10 MiB each, ~10 sec total. Smoke check.
#   small    — 4 configs × ~100 MiB each, ~1 min total. CI-scale.
#   medium   — 4 configs × ~1 GiB each, ~10 min total. Local validation.
#   large    — 4 configs × ~10 GiB each, ~1 hr total. GCP-scale.
#
# All scales test the same parameter sweep (varying N, mod%, chunk size);
# they only differ in absolute corpus size. Larger scales give more
# confidence in the ratio's stability with realistic disk traffic.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
V2_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${V2_ROOT}/build-bench"
OUT_CSV="${SCRIPT_DIR}/dedup_results_$(date +%Y%m%d_%H%M%S).csv"

scale="${1:-small}"

case "$scale" in
    tiny)   base_mib=4   ;;
    small)  base_mib=10  ;;
    medium) base_mib=40  ;;
    large)  base_mib=64  ;;
    *)      echo "scale must be tiny|small|medium|large" >&2; exit 2 ;;
esac

echo "Stratum dedup bench — scale=$scale base_mib=$base_mib"
echo "Pool path: /tmp/stratum_dedup_bench_$$.bin"
echo "Output CSV: $OUT_CSV"
echo

# Build if needed.
if [[ ! -x "$BUILD_DIR/bench/bench_dedup" ]]; then
    echo "Building bench_dedup..."
    cmake -B "$BUILD_DIR" -S "$V2_ROOT" \
        -DSTM_BUILD_BENCHES=ON \
        -DSTM_ENABLE_IOURING=OFF \
        -DSTM_ENABLE_PQ=OFF \
        > /dev/null
    cmake --build "$BUILD_DIR" -j --target bench_dedup > /dev/null
    echo "Built."
    echo
fi

BENCH="$BUILD_DIR/bench/bench_dedup"

# Header row.
echo "scale,files,base_mib,mod_percent,avg_chunk_kib,total_written_bytes,unique_stored_bytes,cas_chunk_count,dedup_ratio,elapsed_sec" > "$OUT_CSV"

# Sweep:
#   1. (N=10, mod=10%, avg=64 KiB)  — high-overlap baseline; expect ≥ 4×
#   2. (N=20, mod=20%, avg=64 KiB)  — ROADMAP-cited 80% overlap; expect ≥ 3×
#   3. (N=50, mod=15%, avg=64 KiB)  — bigger fleet
#   4. (N=20, mod=20%, avg=32 KiB)  — finer chunking
configs=(
    "10 10 64"
    "20 20 64"
    "50 15 64"
    "20 20 32"
)

pool_path="/tmp/stratum_dedup_bench_$$.bin"
keyfile_path="/tmp/stratum_dedup_bench_$$.key"

for cfg in "${configs[@]}"; do
    read -r n_files mod_pct chunk_kib <<< "$cfg"
    echo "--- files=$n_files mod=$mod_pct% chunk=$chunk_kib KiB base=$base_mib MiB ---"

    output=$("$BENCH" \
        --files="$n_files" \
        --base-mib="$base_mib" \
        --mod-percent="$mod_pct" \
        --avg-chunk-kib="$chunk_kib" \
        --pool-path="$pool_path" \
        --keyfile="$keyfile_path" \
        2>&1) || true

    # Parse the DEDUP_BENCH_RESULT block.
    total_written=$(echo "$output" | awk -F'=' '/total_written/{gsub(/ /,""); split($2, a, "("); print a[1]}')
    unique_bytes=$(echo "$output" | awk -F'=' '/unique_stored_bytes/{gsub(/ /,""); split($2, a, "("); print a[1]}')
    cas_count=$(echo "$output" | awk -F'=' '/cas_chunk_count/{gsub(/ /,""); print $2}')
    ratio=$(echo "$output" | awk -F'=' '/dedup_ratio/{gsub(/ /,""); print $2}')
    elapsed=$(echo "$output" | awk -F'=' '/elapsed_seconds/{gsub(/ /,""); print $2}')

    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
        "$scale" "$n_files" "$base_mib" "$mod_pct" "$chunk_kib" \
        "$total_written" "$unique_bytes" "$cas_count" "$ratio" "$elapsed" \
        >> "$OUT_CSV"

    echo "  total_written=$total_written  unique=$unique_bytes  ratio=$ratio  elapsed=${elapsed}s"
done

# Cleanup pool + key file (--keep wasn't passed, so they should be gone
# already, but guard against bench crash).
rm -f "$pool_path" "$keyfile_path"

echo
echo "Results: $OUT_CSV"
echo
echo "Summary:"
column -t -s, "$OUT_CSV" | sed -n '1p;2,$p'
