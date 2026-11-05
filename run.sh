#!/usr/bin/env bash
# v2 dev launcher — builds + mkfs (if needed) + stratumd (bg) + TUI (fg).
#
# Defaults:
#   image    /tmp/stratum-dev.stm     (override: $STM_IMG)
#   keyfile  $image.key
#   socket   /tmp/stratum-dev.sock    (override: $STM_SOCK)
#   size     64M                      (override: $STM_SIZE)
#
# Usage:
#   ./run.sh                  # full launch
#   ./run.sh fs               # FS-only: stratumd + drop you at a stratum-fs prompt-style shell
#   ./run.sh wipe             # remove image + keyfile + socket
#
# On exit (TUI quits or Ctrl-C) stratumd is killed. The image + keyfile
# persist across runs; pass `wipe` first if you want a clean slate.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
TUI_TARGET="$ROOT/tui/target/release"

IMG="${STM_IMG:-/tmp/stratum-dev.stm}"
KEY="${IMG}.key"
SOCK="${STM_SOCK:-/tmp/stratum-dev.sock}"
SIZE="${STM_SIZE:-64M}"

# ── helpers ────────────────────────────────────────────────────────────
say()   { printf "[run.sh] %s\n" "$*" >&2; }
die()   { say "error: $*"; exit 1; }
have()  { test -x "$1"; }

cleanup() {
    if [[ -n "${STRATUMD_PID:-}" ]] && kill -0 "$STRATUMD_PID" 2>/dev/null; then
        say "stopping stratumd (pid $STRATUMD_PID)"
        kill -TERM "$STRATUMD_PID" 2>/dev/null || true
        # Give it a moment to sync + clean up
        for _ in 1 2 3 4 5; do
            kill -0 "$STRATUMD_PID" 2>/dev/null || break
            sleep 0.2
        done
        kill -KILL "$STRATUMD_PID" 2>/dev/null || true
    fi
    rm -f "$SOCK" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ── subcommand: wipe ───────────────────────────────────────────────────
if [[ "${1:-}" == "wipe" ]]; then
    rm -fv "$IMG" "$KEY" "$SOCK"
    exit 0
fi

# ── build (if needed) ──────────────────────────────────────────────────

MKFS="$BUILD/src/cmd/stratum-mkfs/stratum-mkfs"
DAEMON="$BUILD/src/cmd/stratumd/stratumd"
TUI="$TUI_TARGET/stratum-tui"

if ! have "$MKFS" || ! have "$DAEMON"; then
    say "building C tree (cmake)..."
    [[ -d "$BUILD" ]] || cmake -B "$BUILD" -S "$ROOT"
    cmake --build "$BUILD" --target stratum-mkfs stratumd stratum-fs
fi

if ! have "$TUI"; then
    say "building TUI (cargo)..."
    ( cd "$ROOT/tui" && cargo build --release )
fi

# ── mkfs (if needed) ───────────────────────────────────────────────────

if [[ ! -f "$IMG" ]]; then
    say "creating volume $IMG (size=$SIZE)..."
    "$MKFS" "$IMG" --size "$SIZE"
else
    say "using existing $IMG"
fi

# ── stratumd (bg) ──────────────────────────────────────────────────────

rm -f "$SOCK"
say "starting stratumd on $SOCK..."
"$DAEMON" "$IMG" --listen "$SOCK" --keyfile "$KEY" &
STRATUMD_PID=$!

# Wait for the socket to appear (or stratumd to die).
for _ in $(seq 1 50); do
    [[ -S "$SOCK" ]] && break
    if ! kill -0 "$STRATUMD_PID" 2>/dev/null; then
        die "stratumd exited before socket appeared (see output above)"
    fi
    sleep 0.1
done
[[ -S "$SOCK" ]] || die "stratumd never created socket $SOCK"
say "stratumd ready (pid $STRATUMD_PID)"

# ── subcommand: fs (drop into a sub-shell with stratum-fs in PATH) ─────

if [[ "${1:-}" == "fs" ]]; then
    export PATH="$BUILD/src/cmd/stratum-fs:$PATH"
    export STRATUM_SOCKET="$SOCK"
    say "launching shell with STRATUM_SOCKET=$SOCK + stratum-fs in PATH"
    say "(exit shell to stop stratumd)"
    "${SHELL:-/bin/sh}" -i || true
    exit 0
fi

# ── default: TUI (fg) ──────────────────────────────────────────────────

say "launching TUI (q quits)..."
"$TUI" "$SOCK"
