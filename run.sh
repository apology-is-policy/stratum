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
#   ./run.sh wipe             # remove image + keyfile
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
    # The socket is stratumd's to remove, and it does at its end: one still at the
    # path now may be another daemon's.
    [[ -n "${LOG:-}" ]] && rm -f "$LOG"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ── subcommand: wipe ───────────────────────────────────────────────────
if [[ "${1:-}" == "wipe" ]]; then
    # Not the socket: a dead daemon's is cleared by the next start, and a running
    # daemon's is not this script's to take.
    rm -fv "$IMG" "$KEY"
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

# ── mkfs (if needed) ───────────────────────────────────────────────────

if [[ ! -f "$IMG" ]]; then
    say "creating volume $IMG (size=$SIZE)..."
    "$MKFS" "$IMG" --size "$SIZE"
else
    say "using existing $IMG"
fi

# ── stratumd (bg) ──────────────────────────────────────────────────────

# No rm of the socket: stratumd clears a dead daemon's and refuses a running one's.
say "starting stratumd on $SOCK..."
LOG="$(mktemp "${TMPDIR:-/tmp}/stratum-dev-log.XXXXXX")"
"$DAEMON" "$IMG" --listen "$SOCK" --keyfile "$KEY" 2> >(tee "$LOG" >&2) &
STRATUMD_PID=$!

# Wait for stratumd's own word that it serves (or for it to die): a socket at the
# path says nothing, it may be another daemon's.
for _ in $(seq 1 50); do
    grep -qs 'bound and ready' "$LOG" && break
    if ! kill -0 "$STRATUMD_PID" 2>/dev/null; then
        die "stratumd exited before it was ready (see output above)"
    fi
    sleep 0.1
done
grep -qs 'bound and ready' "$LOG" || die "stratumd was not ready after 5 s"
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

if ! have "$TUI"; then
    say "building TUI (cargo)..."
    ( cd "$ROOT/tui" && cargo build --release )
fi

say "launching TUI (q quits)..."
"$TUI" "$SOCK"
