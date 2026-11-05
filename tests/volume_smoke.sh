#!/bin/bash
# A file-based volume end to end, through the packaged binary: create it under a passphrase, copy a
# tree in, and check the three promises an encrypted container makes. Nothing readable reaches the
# file, the wrong passphrase opens nothing, and the bytes come back the same after a remount.
#
#   tests/volume_smoke.sh path/to/stratum
set -u
B=${1:?usage: volume_smoke.sh path/to/stratum}
[ -x "$B" ] || { echo "FAIL: $B is not executable"; exit 2; }

D=$(mktemp -d "${TMPDIR:-/tmp}/stratum-volume.XXXXXX") || exit 2
V=$D/vol.stm
S=$D/s.sock
SP=
PASS='correct horse battery staple'
MARK=STRATUM_PLAINTEXT_MARKER_7c41
BAD=0

cleanup() {
    [ -n "$SP" ] && kill -KILL "$SP" 2>/dev/null
    rm -rf "${D:?}"
}
trap cleanup EXIT

ok() { echo "ok: $*"; }
no() { echo "FAIL: $*"; BAD=1; }

serve() {
    rm -f "$S"
    printf '%s\n' "$1" | "$B" serve "$V" --listen "$S" --passphrase-stdin > "$D/serve.log" 2>&1 &
    SP=$!
    for _ in $(seq 1 100); do
        [ -S "$S" ] && return 0
        kill -0 "$SP" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}
# A daemon that exits uncleanly has not unmounted, so a remount after it would prove nothing.
stop() {
    kill -TERM "$SP" 2>/dev/null
    wait "$SP" 2>/dev/null
    rc=$?
    SP=
    rm -f "$S"
    [ "$rc" = 0 ] || no "the daemon exited $rc on TERM"
}
F() { "$B" fs -s "$S" "$@"; }

mkdir -p "$D/host/deep/er"
printf '%s one\n' "$MARK" > "$D/host/a.txt"
printf '%s two\n' "$MARK" > "$D/host/deep/er/b.txt"
dd if=/dev/urandom of="$D/host/big.bin" bs=1048576 count=8 2>/dev/null

printf '%s\n' "$PASS" | "$B" mkfs "$V" --size 256M --passphrase-stdin > "$D/mkfs.log" 2>&1 \
    && ok "mkfs" || { no "mkfs: $(tail -1 "$D/mkfs.log")"; exit 1; }

serve "$PASS" && ok "served" || { no "serve: $(tail -1 "$D/serve.log")"; exit 1; }
F mkdir /in || no "mkdir"
F put "$D/host" /in/host > "$D/put.log" 2>&1 || no "put: $(tail -1 "$D/put.log")"
# A mutating command commits before it reports success, so a kill now must lose nothing.
kill -KILL "$SP" 2>/dev/null
wait "$SP" 2>/dev/null
SP=
rm -f "$S"

# The control is one variable away: the same search over a file that does hold the marker.
in_image=$(LC_ALL=C grep -c "$MARK" "$V")
in_source=$(LC_ALL=C grep -c "$MARK" "$D/host/a.txt")
[ "$in_source" = 1 ] || no "the search cannot find the marker in the source file ($in_source)"
[ "$in_image" = 0 ] && ok "no plaintext marker in the image" || no "the marker is in the image, $in_image lines"

if serve 'not the passphrase'; then
    no "the wrong passphrase was accepted"
    stop
else
    ok "wrong passphrase refused"
    wait "$SP" 2>/dev/null
    SP=
fi

serve "$PASS" || { no "remount: $(tail -1 "$D/serve.log")"; exit 1; }
for f in a.txt deep/er/b.txt big.bin; do
    F read "/in/host/$f" > "$D/out"
    cmp -s "$D/out" "$D/host/$f" && ok "same bytes past a kill and a remount: $f" || no "differs past a kill and a remount: $f"
done
F mv /in/host/a.txt /in/host/moved.txt || no "mv"
F rm /in/host/deep/er/b.txt || no "rm"
stop

serve "$PASS" || { no "second remount: $(tail -1 "$D/serve.log")"; exit 1; }
F read /in/host/moved.txt > "$D/out"
cmp -s "$D/out" "$D/host/a.txt" && ok "a move held past a remount" || no "the move was lost"
if F read /in/host/deep/er/b.txt > "$D/out" 2>/dev/null; then no "a removed file came back"; else ok "a removal held past a remount"; fi
stop

exit $BAD
