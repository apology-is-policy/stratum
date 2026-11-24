#!/bin/bash
# A disk formatted end to end. A disk cannot be resized, so stratum-mkfs formats it whole: it refuses
# a --size that is not the disk's and writes nothing, and the pool it makes serves, takes a file and
# gives it back after a remount. The disk is a RAM disk this run attaches and detaches (macOS hdiutil,
# no root); where none can be had the run says it skipped and checks nothing.
#
#   tests/mkfs_disk_smoke.sh path/to/stratum           the one binary (mkfs, serve, fs)
#   tests/mkfs_disk_smoke.sh path/to/build/src/cmd     a build's stratum-mkfs, stratumd, stratum-fs
set -u
B=${1:?usage: mkfs_disk_smoke.sh path/to/stratum | path/to/build/src/cmd}
if [ -d "$B" ]; then
    B=$(cd "$B" && pwd)
    MKFS() { "$B/stratum-mkfs/stratum-mkfs" "$@"; }
    SERVE() { "$B/stratumd/stratumd" "$@"; }
    FS() { "$B/stratum-fs/stratum-fs" "$@"; }
elif [ -x "$B" ]; then
    case "$B" in /*) ;; *) B=$PWD/$B ;; esac
    MKFS() { "$B" mkfs "$@"; }
    SERVE() { "$B" serve "$@"; }
    FS() { "$B" fs "$@"; }
else
    echo "FAIL: $B is neither the stratum binary nor a build's src/cmd"
    exit 2
fi

D=$(mktemp -d "${TMPDIR:-/tmp}/stratum-disk.XXXXXX") || exit 2
S=$D/s.sock
K=$D/disk.key
PASS='correct horse battery staple'
SP=
DEV=
BAD=0
CHECKS=0
SKIPPED=0
ok() { echo "ok: $*"; CHECKS=$((CHECKS + 1)); }
no() { echo "FAIL: $*"; BAD=1; CHECKS=$((CHECKS + 1)); }
skipped() { echo "note: skipped: $*"; SKIPPED=$((SKIPPED + 1)); }

cleanup() {
    [ -n "$SP" ] && kill -KILL "$SP" 2>/dev/null
    [ -n "$DEV" ] && hdiutil detach "$DEV" > /dev/null 2>&1
    rm -rf "${D:?}"
}
trap cleanup EXIT

# 32768 sectors of 512 bytes: 16 MiB, the smallest volume mkfs makes.
SECTORS=32768
BYTES=$((SECTORS * 512))
if [ "$(uname -s)" = Darwin ] && command -v hdiutil > /dev/null 2>&1; then
    DEV=$(hdiutil attach -nomount "ram://$SECTORS" 2> "$D/attach.log" | awk '/^\/dev\// { print $1; exit }')
fi
if [ -z "$DEV" ]; then
    skipped "no RAM disk to be had on $(uname -s) ($(tail -1 "$D/attach.log" 2>/dev/null))"
    echo "-- $CHECKS checks, $SKIPPED skipped"
    exit 0
fi
echo "note: the disk is $DEV, $BYTES bytes"

disk_hash() { dd if="$DEV" bs=1048576 2>/dev/null | shasum | cut -d' ' -f1; }
keys_left() { ls "$D" | LC_ALL=C grep -c 'key' ; }

serve() {
    rm -f "$S"
    printf '%s\n' "$PASS" | SERVE "$DEV" --listen "$S" --keyfile "$K" --passphrase-stdin > "$D/serve.log" 2>&1 &
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

# A size that is not the disk's: refused before anything is written, and no key is left.
H0=$(disk_hash)
printf '%s\n' "$PASS" | MKFS "$DEV" --size 32M --keyfile "$K" --passphrase-stdin > "$D/m1.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q "is a disk of $BYTES bytes" "$D/m1.log" \
        && [ "$(disk_hash)" = "$H0" ] && [ "$(keys_left)" = 0 ]; then
    ok "a --size that is not the disk's is refused, and nothing is written"
else
    no "mkfs --size 32M on a $BYTES-byte disk: rc=$rc, keys left $(keys_left): $(tail -1 "$D/m1.log")"
fi

# The disk whole, and the pool it makes serves, keeps a file and gives it back after a remount.
printf '%s\n' "$PASS" | MKFS "$DEV" --keyfile "$K" --passphrase-stdin > "$D/m2.log" 2>&1
rc=$?
if [ "$rc" = 0 ] && LC_ALL=C grep -q "formatting $DEV ($BYTES bytes)" "$D/m2.log"; then
    ok "a disk is formatted whole"
else
    no "mkfs of the whole disk: rc=$rc: $(tail -1 "$D/m2.log")"
fi
if serve; then
    printf 'on a disk\n' | FS -s "$S" write /disk.txt > /dev/null 2>&1 || no "writing /disk.txt"
    stop
    if serve; then
        got=$(FS -s "$S" read /disk.txt 2>/dev/null)
        [ "$got" = "on a disk" ] && ok "the disk's pool gives a file back after a remount" \
            || no "after a remount /disk.txt reads [$got]"
        stop
    else
        no "serve after the remount: $(tail -1 "$D/serve.log")"
    fi
else
    no "serve the formatted disk: $(tail -1 "$D/serve.log")"
fi

# The disk's own size named: formatted (over the pool, so forced).
printf '%s\n' "$PASS" | MKFS "$DEV" --size "$BYTES" --keyfile "$K" --passphrase-stdin --force > "$D/m3.log" 2>&1
rc=$?
if [ "$rc" = 0 ] && serve; then
    ok "a --size that is the disk's formats it"
    stop
else
    no "mkfs --size $BYTES --force: rc=$rc: $(tail -1 "$D/m3.log")"
fi

echo "-- $CHECKS checks, $SKIPPED skipped, $([ "$BAD" = 0 ] && echo all passed || echo FAILED)"
exit "$BAD"
