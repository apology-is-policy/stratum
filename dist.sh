#!/bin/sh
# Build the stratum binary, the manager and every daemon in one executable, into dist/.
set -e

PROJ="$(cd "$(dirname "$0")" && pwd)"

echo "Building the C libraries..."
# The test hooks are on by default; a binary that ships carries none of them.
cmake -B "$PROJ/build" -S "$PROJ" -DCMAKE_BUILD_TYPE=Release -DSTM_BUILD_TESTS=OFF -DSTRATUM_BUILD_TESTING_HOOKS=OFF
cmake --build "$PROJ/build"

echo "Building the stratum binary..."
(cd "$PROJ/tools/stratum" && STM_BUILD_DIR="$PROJ/build" cargo build --release)

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
