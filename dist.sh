#!/bin/sh
# Build the stratum binary, the manager and every daemon in one executable, into dist/.
set -e

PROJ="$(cd "$(dirname "$0")" && pwd)"

echo "Building the C libraries..."
# In a directory of its own: a binary that ships carries no tests and none of the
# test hooks, which are on by default, and build/ keeps whatever a test build set.
# From nothing, every time: a kept cache would keep options this script does not
# pass, and the manager links every archive it finds there, a stale one too.
rm -rf "${PROJ:?}/build-dist"
cmake -B "$PROJ/build-dist" -S "$PROJ" -DCMAKE_BUILD_TYPE=Release -DSTM_BUILD_TESTS=OFF -DSTRATUM_BUILD_TESTING_HOOKS=OFF
cmake --build "$PROJ/build-dist"

echo "Building the stratum binary..."
(cd "$PROJ/tools/stratum" && STM_BUILD_DIR="$PROJ/build-dist" cargo build --release)

mkdir -p "$PROJ/dist"
# Beside it and then over it: a daemon still running the old binary keeps a plain cp from writing.
cp "$PROJ/tools/stratum/target/release/stratum" "$PROJ/dist/stratum.new"
mv -f "$PROJ/dist/stratum.new" "$PROJ/dist/stratum"

echo "Done."
ls -lh "$PROJ/dist/"
echo ""
echo "Usage:"
echo "  dist/stratum                  choose or create a volume"
echo "  dist/stratum mkfs IMAGE ...   create a file-based volume"
echo "  dist/stratum tui --vol IMAGE  open it in the file manager"
