#!/bin/sh
# Build both binaries and place them in dist/
set -e

PROJ="$(cd "$(dirname "$0")" && pwd)"

echo "Building C library and stratum CLI..."
cmake -B "$PROJ/build" -DCMAKE_BUILD_TYPE=Release "$PROJ"
cmake --build "$PROJ/build" --target stratum

echo "Building Rust TUI..."
cd "$PROJ/tui"
cargo build --release

echo "Assembling dist/..."
mkdir -p "$PROJ/dist"
cp "$PROJ/build/stratum"                  "$PROJ/dist/stratum"
cp "$PROJ/tui/target/release/stratum-tui" "$PROJ/dist/stratum-tui"

echo "Done."
ls -lh "$PROJ/dist/"
echo ""
echo "Usage:"
echo "  dist/stratum mkfs mydata.stm 256M"
echo "  dist/stratum-tui mydata.stm"
