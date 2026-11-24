#!/bin/bash
# A disk formatted end to end. A disk cannot be resized, so stratum-mkfs formats it whole: it refuses
# a --size that is not the disk's before it reads the disk, and writes nothing; it refuses to keep a
# disk's key in /dev; the pool it makes serves, takes a file and gives it back after a remount; a disk
# whose size is no multiple of 64 KiB formats too, and with a --bootstrap and no --size is held to its
# own size, not to the size a file would be made at; a disk a daemon serves is refused a format and a
# second daemon, and on macOS through either of its two nodes, the raw one formatting and serving too,
# and holding the block node when it is opened for reading alone;
# a disk the system has mounted is refused, --force or not, by mkfs and by the daemon (on macOS through
# its raw node too); and on Linux a claim waits out a moment's shared lock, as udev takes, and refuses
# one held for good once it has waited some seconds.
#
# The disks are made by this run and taken away again: RAM disks on macOS (hdiutil, no root), loop
# devices on Linux, which need root, or STRATUM_TEST_SUDO=1 and sudo without a password (asked for
# and not to be had, the run fails). Elsewhere, and on Linux with neither, the run says on its last
# line that it skipped, and checks nothing.
#
#   tests/mkfs_disk_smoke.sh path/to/stratum           the one binary (mkfs, serve, fs)
#   tests/mkfs_disk_smoke.sh path/to/build/src/cmd     a build's stratum-mkfs, stratumd, stratum-fs
set -u
B=${1:?usage: mkfs_disk_smoke.sh path/to/stratum | path/to/build/src/cmd}
# SERVE and MKFSX exec: each runs as a background pipeline element, where $! must be the
# program a signal reaches, not the subshell bash forks for a function.
if [ -d "$B" ]; then
    B=$(cd "$B" && pwd)
    MKFS() { "$B/stratum-mkfs/stratum-mkfs" "$@"; }
    MKFSX() { exec "$B/stratum-mkfs/stratum-mkfs" "$@"; }
    SERVE() { exec "$B/stratumd/stratumd" "$@"; }
    FS() { "$B/stratum-fs/stratum-fs" "$@"; }
elif [ -x "$B" ]; then
    case "$B" in /*) ;; *) B=$PWD/$B ;; esac
    MKFS() { "$B" mkfs "$@"; }
    MKFSX() { exec "$B" mkfs "$@"; }
    SERVE() { exec "$B" serve "$@"; }
    FS() { "$B" fs "$@"; }
else
    echo "FAIL: $B is neither the stratum binary nor a build's src/cmd"
    exit 2
fi

D=$(mktemp -d "${TMPDIR:-/tmp}/stratum-disk.XXXXXX") || exit 2
S=$D/s.sock
K=$D/disk.key
PASS='correct horse battery staple'
OS=$(uname -s)
AS=
SP=
DEVS=
MOUNTED=
BAD=0
CHECKS=0
SKIPPED=0
ok() { echo "ok: $*"; CHECKS=$((CHECKS + 1)); }
no() { echo "FAIL: $*"; BAD=1; CHECKS=$((CHECKS + 1)); }
skipped() { echo "note: skipped: $*"; SKIPPED=$((SKIPPED + 1)); }
finish() {
    echo "-- $CHECKS checks, $SKIPPED skipped, $([ "$BAD" = 0 ] && echo all passed || echo FAILED)"
    exit "$BAD"
}

unmount() {
    [ -n "$MOUNTED" ] || return 0
    if [ "$OS" = Darwin ]; then
        diskutil unmount "$MOUNTED" > /dev/null 2>&1 || diskutil unmount force "$MOUNTED" > /dev/null 2>&1
    else
        $AS umount "$D/mnt" > /dev/null 2>&1
    fi
    MOUNTED=
}
cleanup() {
    [ -n "$SP" ] && kill -KILL "$SP" 2>/dev/null
    unmount
    for dev in $DEVS; do
        if [ "$OS" = Darwin ]; then
            hdiutil detach "$dev" > /dev/null 2>&1 || hdiutil detach -force "$dev" > /dev/null 2>&1
        else
            $AS losetup -d "$dev" > /dev/null 2>&1
        fi
    done
    rm -rf "${D:?}"
}
trap cleanup EXIT

# A disk of $1 sectors of 512 bytes, its node in $DEV and in $DEVS, which cleanup takes away.
attach() {
    DEV=
    if [ "$OS" = Darwin ]; then
        hdiutil attach -nomount "ram://$1" > "$D/attach.out" 2> "$D/attach.log" || return 1
        DEV=$(awk '/^\/dev\/disk[0-9]+/ { print $1; exit }' "$D/attach.out")
        # Attached and not understood would leave a disk nothing takes away.
        [ -n "$DEV" ] || { echo "FAIL: hdiutil attached what this run cannot read:"; cat "$D/attach.out"; exit 2; }
    else
        truncate -s $(( $1 * 512 )) "$D/disk$1.img" || return 1
        DEV=$($AS losetup --find --show "$D/disk$1.img" 2> "$D/attach.log") || { DEV=; return 1; }
        [ -n "$DEV" ] || return 1
        DEVS="$DEVS $DEV"
        $AS chown "$(id -u)" "$DEV" || return 1
        return 0
    fi
    DEVS="$DEVS $DEV"
}

case "$OS" in
Darwin) command -v hdiutil > /dev/null 2>&1 || { echo "FAIL: macOS without hdiutil"; exit 2; } ;;
Linux)
    if [ "$(id -u)" = 0 ]; then AS=
    elif [ "${STRATUM_TEST_SUDO:-0}" != 1 ]; then AS=none
    elif sudo -n true 2>/dev/null; then AS="sudo -n"
    else
        no "STRATUM_TEST_SUDO=1 asks for sudo without a password, and there is none"
        finish
    fi
    if [ "$AS" = none ]; then
        AS=
        skipped "a disk: a loop device needs root, or STRATUM_TEST_SUDO=1 and sudo without a password"
        finish
    fi
    ;;
*)
    skipped "a disk: this run makes one on macOS and Linux only, not on $OS"
    finish
    ;;
esac

# 32768 sectors of 512 bytes: 16 MiB, the smallest volume mkfs makes.
SECTORS=32768
BYTES=$((SECTORS * 512))
attach $SECTORS || { no "no $BYTES-byte disk to be had: $(tail -1 "$D/attach.log")"; finish; }
A=$DEV
echo "note: disk A is $A, $BYTES bytes"

disk_hash() { dd if="$1" bs=1048576 2>/dev/null | shasum | cut -d' ' -f1; }
keys_left() { ls "$D" | LC_ALL=C grep -c 'key' ; }

# serve IMAGE [OPTION...]: a daemon on IMAGE, its options after the run's own.
serve() {
    rm -f "$S"
    printf '%s\n' "$PASS" | SERVE "$1" --listen "$S" --keyfile "$K" --passphrase-stdin "${@:2}" \
        > "$D/serve.log" 2>&1 &
    SP=$!
    for _ in $(seq 1 100); do
        [ -S "$S" ] && return 0
        kill -0 "$SP" 2>/dev/null || { SP=; return 1; }
        sleep 0.1
    done
    # A daemon that never listened is not left behind for the next one to hide.
    kill -KILL "$SP" 2>/dev/null
    wait "$SP" 2>/dev/null
    SP=
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
# A second daemon on $1 beside the one serving, which has to stop by itself, refused as another
# daemon's: its log is $D/$2.log. One still running after 20 s is killed, and is a finding.
second_serve() {
    rm -f "$D/s2.sock"
    printf '%s\n' "$PASS" | SERVE "$1" --listen "$D/s2.sock" --keyfile "$K" --passphrase-stdin \
        > "$D/$2.log" 2>&1 &
    local p=$! rc
    for _ in $(seq 1 200); do
        kill -0 "$p" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$p" 2>/dev/null; then
        kill -KILL "$p" 2>/dev/null
        wait "$p" 2>/dev/null
        echo "still running after 20 s" >> "$D/$2.log"
        return 1
    fi
    wait "$p"
    rc=$?
    [ "$rc" != 0 ] && LC_ALL=C grep -q "already open in another stratumd" "$D/$2.log"
}
# Milliseconds, where date can say them (GNU date: Linux).
ms() { echo $(( $(date +%s%N) / 1000000 )); }
# mkfs_refused LOG ARG...: a forced format with the run's passphrase that a claim has to refuse,
# its status in $rc. One still running after 20 s is killed, and is a finding: rc 124, and the log
# says so.
mkfs_refused() {
    local log=$1 p
    shift
    printf '%s\n' "$PASS" | MKFSX "$@" --passphrase-stdin --force > "$log" 2>&1 &
    p=$!
    for _ in $(seq 1 200); do
        kill -0 "$p" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$p" 2>/dev/null; then
        kill -KILL "$p" 2>/dev/null
        wait "$p" 2>/dev/null
        echo "still running after 20 s" >> "$log"
        rc=124
        return
    fi
    wait "$p"
    rc=$?
}

# No key beside a disk: it would be in /dev, on Linux kept in memory and gone at the next boot.
H0=$(disk_hash "$A")
printf '%s\n' "$PASS" | MKFS "$A" --passphrase-stdin > "$D/m0.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q "has no directory of its own" "$D/m0.log" \
        && [ "$(disk_hash "$A")" = "$H0" ] && [ ! -e "$A.key" ]; then
    ok "a disk with no --keyfile is refused, and nothing is written"
else
    no "mkfs of a disk with no --keyfile: rc=$rc: $(tail -1 "$D/m0.log")"
fi

# A size that is not the disk's: refused before the disk is read or written, and no key is left.
printf '%s\n' "$PASS" | MKFS "$A" --size 32M --keyfile "$K" --passphrase-stdin > "$D/m1.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q "is a disk of $BYTES bytes" "$D/m1.log" \
        && ! LC_ALL=C grep -q "to see that it is empty" "$D/m1.log" \
        && [ "$(disk_hash "$A")" = "$H0" ] && [ "$(keys_left)" = 0 ]; then
    ok "a --size that is not the disk's is refused before the disk is read, and nothing is written"
else
    no "mkfs --size 32M on a $BYTES-byte disk: rc=$rc, keys left $(keys_left): $(tail -1 "$D/m1.log")"
fi

# The disk whole, and the pool it makes serves, keeps a file and gives it back after a remount.
printf '%s\n' "$PASS" | MKFS "$A" --keyfile "$K" --passphrase-stdin > "$D/m2.log" 2>&1
rc=$?
if [ "$rc" = 0 ] && LC_ALL=C grep -q "formatting $A ($BYTES bytes," "$D/m2.log"; then
    ok "a disk is formatted whole"
else
    no "mkfs of the whole disk: rc=$rc: $(tail -1 "$D/m2.log")"
fi
if serve "$A"; then
    printf 'on a disk\n' | FS -s "$S" write /disk.txt > /dev/null 2>&1 || no "writing /disk.txt"
    stop
    if serve "$A"; then
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

# Over the pool, forced: a size that is not the disk's still writes nothing, and the pool still
# opens with its key.
H1=$(disk_hash "$A")
printf '%s\n' "$PASS" | MKFS "$A" --size 32M --keyfile "$D/other.key" --passphrase-stdin --force \
    > "$D/m3.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q "is a disk of $BYTES bytes" "$D/m3.log" \
        && [ "$(disk_hash "$A")" = "$H1" ] && serve "$A"; then
    got=$(FS -s "$S" read /disk.txt 2>/dev/null)
    [ "$got" = "on a disk" ] && ok "a forced --size that is not the disk's leaves the pool as it was" \
        || no "after a refused forced format /disk.txt reads [$got]"
    stop
else
    no "mkfs --size 32M --force over the pool: rc=$rc: $(tail -1 "$D/m3.log"); serve: $(tail -1 "$D/serve.log")"
fi

# The disk's own size named: formatted anew (over the pool, so forced): /disk.txt is gone.
printf '%s\n' "$PASS" | MKFS "$A" --size "$BYTES" --keyfile "$K" --passphrase-stdin --force > "$D/m4.log" 2>&1
rc=$?
if [ "$rc" = 0 ] && LC_ALL=C grep -q "formatting $A ($BYTES bytes," "$D/m4.log" && serve "$A"; then
    printf 'fresh\n' | FS -s "$S" write /fresh.txt > /dev/null 2>&1
    got=$(FS -s "$S" read /fresh.txt 2>/dev/null)
    if [ "$got" != fresh ]; then
        no "after a format of the disk's own size the pool does not keep a file: /fresh.txt reads [$got]"
    elif FS -s "$S" read /disk.txt > /dev/null 2>&1; then
        no "after a format of the disk's own size /disk.txt is still there"
    else
        ok "a --size that is the disk's formats it anew"
    fi
    stop
else
    no "mkfs --size $BYTES --force: rc=$rc: $(tail -1 "$D/m4.log")"
fi

# A disk a daemon serves is claimed: a format, forced or not, and a second daemon are refused, and
# the pool it serves keeps its file. On Linux the claim waits some seconds for a lock it could take
# for udev's before it calls the holder another claim.
if serve "$A"; then
    printf 'claimed\n' | FS -s "$S" write /claimed.txt > /dev/null 2>&1 || no "writing /claimed.txt"
    t0=0
    [ "$OS" = Linux ] && t0=$(ms)
    mkfs_refused "$D/c1.log" "$A" --keyfile "$D/other.key"
    el=0
    [ "$OS" = Linux ] && el=$(( $(ms) - t0 ))
    if [ "$rc" != 0 ] && LC_ALL=C grep -q "is open in a running stratumd" "$D/c1.log" \
            && { [ "$OS" != Linux ] || [ "$el" -ge 4500 ]; }; then
        ok "a disk a daemon serves is not formatted, --force or not"
    else
        no "mkfs --force of a disk a daemon serves: rc=$rc after $el ms: $(tail -1 "$D/c1.log")"
    fi
    got=
    second_serve "$A" c2 && got=$(FS -s "$S" read /claimed.txt 2>/dev/null)
    if [ "$got" = claimed ]; then
        ok "a second daemon on a disk one serves is refused, and the pool keeps its file"
    else
        no "a second daemon on a disk one serves: $(tail -1 "$D/c2.log"); /claimed.txt reads [$got]"
    fi
    stop
else
    no "serve the disk to claim it: $(tail -1 "$D/serve.log")"
fi

# macOS: a disk's raw node and block node are two nodes and one disk, so a daemon on either keeps a
# format and a second daemon off the other. The raw node formats whole and serves.
if [ "$OS" = Darwin ]; then
    RA=/dev/r${A#/dev/}
    printf '%s\n' "$PASS" | MKFS "$RA" --keyfile "$K" --passphrase-stdin --force > "$D/r1.log" 2>&1
    rc=$?
    if [ "$rc" = 0 ] && LC_ALL=C grep -q "formatting $RA ($BYTES bytes," "$D/r1.log" && serve "$RA"; then
        printf 'raw\n' | FS -s "$S" write /raw.txt > /dev/null 2>&1
        got=$(FS -s "$S" read /raw.txt 2>/dev/null)
        [ "$got" = raw ] && ok "a disk's raw node is formatted whole and serves" \
            || no "through the raw node /raw.txt reads [$got]"
        mkfs_refused "$D/r2.log" "$A" --keyfile "$D/other.key"
        if [ "$rc" != 0 ] && LC_ALL=C grep -q "is open in a running stratumd" "$D/r2.log" \
                && second_serve "$A" r3; then
            ok "a daemon on the raw node keeps a format and a second daemon off the block node"
        else
            no "with $RA served, mkfs --force $A: rc=$rc: $(tail -1 "$D/r2.log"); a second daemon on $A: $(tail -1 "$D/r3.log")"
        fi
        stop
    else
        no "mkfs and serve of the raw node $RA: rc=$rc: $(tail -1 "$D/r1.log"); serve: $(tail -1 "$D/serve.log")"
    fi
    if serve "$A"; then
        got=$(FS -s "$S" read /raw.txt 2>/dev/null)
        mkfs_refused "$D/r4.log" "$RA" --keyfile "$D/other.key"
        if [ "$got" = raw ] && [ "$rc" != 0 ] && LC_ALL=C grep -q "is open in a running stratumd" "$D/r4.log" \
                && second_serve "$RA" r5; then
            ok "a daemon on the block node keeps a format and a second daemon off the raw node"
        else
            no "with $A served (/raw.txt [$got]), mkfs --force $RA: rc=$rc: $(tail -1 "$D/r4.log"); a second daemon on $RA: $(tail -1 "$D/r5.log")"
        fi
        stop
    else
        no "serve $A after its raw node's format: $(tail -1 "$D/serve.log")"
    fi
    # A raw node this user cannot write is claimed for reading alone, and still holds the block
    # node: a daemon on it, read-only, keeps a format and a second daemon off the block node.
    chmod u-w "$RA"
    if [ -w "$RA" ]; then
        chmod u+w "$RA"
        skipped "a raw node claimed for reading alone: $RA stays writable to this user with its write bit off (root?)"
    elif serve "$RA" --read-only; then
        chmod u+w "$RA"
        got=$(FS -s "$S" read /raw.txt 2>/dev/null)
        mkfs_refused "$D/r6.log" "$A" --keyfile "$D/other.key"
        if [ "$got" = raw ] && [ "$rc" != 0 ] && LC_ALL=C grep -q "is open in a running stratumd" "$D/r6.log" \
                && second_serve "$A" r7; then
            ok "a daemon on a raw node opened for reading alone keeps a format and a second daemon off the block node"
        else
            no "with $RA served read-only (/raw.txt [$got]), mkfs --force $A: rc=$rc: $(tail -1 "$D/r6.log"); a second daemon on $A: $(tail -1 "$D/r7.log")"
        fi
        stop
    else
        chmod u+w "$RA"
        no "serve $RA --read-only with its write bit off: $(tail -1 "$D/serve.log")"
    fi
fi

# udev holds a shared lock on a whole disk while it processes an event, which a close after a
# write raises; a claim waits that out rather than take udev for a running daemon, and a lock held
# for good it calls another claim's once it has waited some seconds.
if [ "$OS" = Linux ]; then
    rm -f "$D/held"
    flock --shared "$A" sh -c ': > "$1"; sleep 1' sh "$D/held" &
    FP=$!
    for _ in $(seq 1 50); do [ -e "$D/held" ] && break; sleep 0.1; done
    printf '%s\n' "$PASS" | MKFS "$A" --keyfile "$K" --passphrase-stdin --force > "$D/m4b.log" 2>&1
    rc=$?
    wait "$FP" 2>/dev/null
    if [ -e "$D/held" ] && [ "$rc" = 0 ] && LC_ALL=C grep -q "formatting $A ($BYTES bytes," "$D/m4b.log"; then
        ok "a disk under a moment's shared lock, as udev takes, is formatted once it is let go"
    else
        no "mkfs under a moment's shared lock (held: $([ -e "$D/held" ] && echo yes || echo never)): rc=$rc: $(tail -1 "$D/m4b.log")"
    fi
    # The same lock held past the wait: refused after it, before the holder lets go.
    rm -f "$D/held"
    flock --shared "$A" sh -c ': > "$1"; sleep 9' sh "$D/held" &
    FP=$!
    for _ in $(seq 1 50); do [ -e "$D/held" ] && break; sleep 0.1; done
    t0=$(ms)
    mkfs_refused "$D/m4c.log" "$A" --keyfile "$K"
    el=$(( $(ms) - t0 ))
    wait "$FP" 2>/dev/null
    if [ -e "$D/held" ] && [ "$rc" != 0 ] && LC_ALL=C grep -q "is open in a running stratumd" "$D/m4c.log" \
            && [ "$el" -ge 4500 ] && [ "$el" -lt 8500 ]; then
        ok "a disk under a shared lock held for good is refused once the claim has waited"
    else
        no "mkfs under a shared lock held for good: rc=$rc after $el ms: $(tail -1 "$D/m4c.log")"
    fi
fi

# 300000 sectors: no multiple of 64 KiB, so a sixteenth of it is no whole number of 4 KiB blocks
# until the default bootstrap is rounded down.
SECTORS_B=300000
BYTES_B=$((SECTORS_B * 512))
if attach $SECTORS_B; then
    E=$DEV
    printf '%s\n' "$PASS" | MKFS "$E" --keyfile "$K" --passphrase-stdin --force > "$D/m5.log" 2>&1
    rc=$?
    if [ "$rc" = 0 ] && LC_ALL=C grep -q "formatting $E ($BYTES_B bytes," "$D/m5.log" && serve "$E"; then
        ok "a disk of $BYTES_B bytes is formatted whole"
        stop
    else
        no "mkfs of a $BYTES_B-byte disk: rc=$rc: $(tail -1 "$D/m5.log"); serve: $(tail -1 "$D/serve.log")"
    fi

    # 68 MiB of bootstrap is more than the 64 MiB a file is made at with no --size, and less than
    # this disk, which is the size it is held to.
    printf '%s\n' "$PASS" | MKFS "$E" --bootstrap 68M --keyfile "$K" --passphrase-stdin --force \
        > "$D/m5b.log" 2>&1
    rc=$?
    if [ "$rc" = 0 ] \
            && LC_ALL=C grep -q "formatting $E ($BYTES_B bytes, 71303168 of them the bootstrap pool)" "$D/m5b.log"; then
        ok "a disk with --bootstrap 68M and no --size is held to its own size"
    else
        no "mkfs --bootstrap 68M of a $BYTES_B-byte disk: rc=$rc: $(tail -1 "$D/m5b.log")"
    fi

    # Mounted by the system: refused by mkfs, --force or not, and by the daemon; unmounted, the
    # same forced format goes ahead.
    if [ "$OS" = Darwin ]; then
        diskutil eraseVolume HFS+ STMDISKTEST "$E" > "$D/mount.log" 2>&1 && MOUNTED=$E
    else
        mkdir -p "$D/mnt" && $AS mkfs.ext4 -q -F "$E" > "$D/mount.log" 2>&1 \
            && $AS mount "$E" "$D/mnt" >> "$D/mount.log" 2>&1 && MOUNTED=$E
    fi
    if [ -z "$MOUNTED" ]; then
        no "the system would not mount $E: $(tail -1 "$D/mount.log")"
    else
        printf '%s\n' "$PASS" | MKFS "$E" --keyfile "$K" --passphrase-stdin --force > "$D/m6.log" 2>&1
        rc=$?
        if [ "$rc" != 0 ] && LC_ALL=C grep -q "the system is using" "$D/m6.log" \
                && mount | LC_ALL=C grep -q "^$E "; then
            ok "a disk the system has mounted is not formatted, --force or not"
        else
            no "mkfs --force of a mounted disk: rc=$rc: $(tail -1 "$D/m6.log")"
        fi
        # macOS opens the raw node of a mounted disk read-write (measured); its block twin it refuses.
        if [ "$OS" = Darwin ]; then
            R=/dev/r${E#/dev/}
            printf '%s\n' "$PASS" | MKFS "$R" --keyfile "$K" --passphrase-stdin --force > "$D/m6r.log" 2>&1
            rc=$?
            if [ "$rc" != 0 ] && LC_ALL=C grep -q "the system is using" "$D/m6r.log" \
                    && mount | LC_ALL=C grep -q "^$E "; then
                ok "the raw node of a disk the system has mounted is not formatted"
            else
                no "mkfs --force of the raw node $R of a mounted disk: rc=$rc: $(tail -1 "$D/m6r.log")"
            fi
        fi
        if serve "$E"; then
            no "the daemon served a disk the system has mounted"
            stop
        elif LC_ALL=C grep -q "the system is using" "$D/serve.log"; then
            ok "the daemon refuses a disk the system has mounted"
        else
            no "the daemon on a mounted disk: $(tail -1 "$D/serve.log")"
        fi
        unmount
        printf '%s\n' "$PASS" | MKFS "$E" --keyfile "$K" --passphrase-stdin --force > "$D/m7.log" 2>&1
        rc=$?
        if [ "$rc" = 0 ] && serve "$E"; then
            ok "unmounted, the same forced format goes ahead"
            stop
        else
            no "mkfs --force of the disk unmounted: rc=$rc: $(tail -1 "$D/m7.log")"
        fi
    fi
else
    no "no $BYTES_B-byte disk to be had: $(tail -1 "$D/attach.log")"
fi

finish
