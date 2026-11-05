#!/bin/sh
# Build the stratum binary, the manager and every daemon in one executable, into dist/.
set -e

PROJ="$(cd "$(dirname "$0")" && pwd)"

echo "Building the C libraries..."
cmake -B "$PROJ/build" -S "$PROJ" -DCMAKE_BUILD_TYPE=Release -DSTM_BUILD_TESTS=OFF
cmake --build "$PROJ/build"

echo "Building the stratum binary..."
(cd "$PROJ/tools/stratum" && STM_BUILD_DIR="$PROJ/build" cargo build --release)

mkdir -p "$PROJ/dist"
cp "$PROJ/tools/stratum/target/release/stratum" "$PROJ/dist/stratum"

echo "Done."
ls -lh "$PROJ/dist/"
echo ""
echo "Usage:"
echo "  dist/stratum                  choose or create a volume"
echo "  dist/stratum mkfs IMAGE ...   create a file-based volume"
echo "  dist/stratum tui --vol IMAGE  open it in the file manager"
