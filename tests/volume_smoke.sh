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
    printf '%s\n' "$1" | "$B" serve "$V" --listen "$S" --keyfile "$V.key" --passphrase-stdin > "$D/serve.log" 2>&1 &
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
# A daemon that has to stop by itself. Its log is $1, the passphrase on its stdin $2. A hang is a finding, not a wait.
refused() {
    log=$1; pass=$2; shift 2
    printf '%s\n' "$pass" | "$B" serve "$@" > "$log" 2>&1 &
    pid=$!
    for _ in $(seq 1 300); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        return 1
    fi
    wait "$pid"
    [ $? != 0 ]
}

mkdir -p "$D/host/deep/er"
printf '%s one\n' "$MARK" > "$D/host/a.txt"
printf '%s two\n' "$MARK" > "$D/host/deep/er/b.txt"
dd if=/dev/urandom of="$D/host/big.bin" bs=1048576 count=8 2>/dev/null

printf '%s\n' "$PASS" | "$B" mkfs "$V" --size 256M --passphrase-stdin > "$D/mkfs.log" 2>&1 \
    && ok "mkfs" || { no "mkfs: $(tail -1 "$D/mkfs.log")"; exit 1; }

serve "$PASS" && ok "served" || { no "serve: $(tail -1 "$D/serve.log")"; exit 1; }
stop

# With no key source named, serve finds the key mkfs left beside the image, and says so when it is not there.
printf '%s\n' "$PASS" | "$B" serve "$V" --listen "$S" --passphrase-stdin > "$D/serve.log" 2>&1 &
SP=$!
for _ in $(seq 1 100); do [ -S "$S" ] && break; kill -0 "$SP" 2>/dev/null || break; sleep 0.1; done
[ -S "$S" ] && ok "serve found the key beside the image" || no "serve with no key named: $(tail -1 "$D/serve.log")"
stop
mv "$V.key" "$V.key.aside"
"$B" serve "$V" --listen "$S" > "$D/nokey.log" 2>&1 &
NK=$!
for _ in $(seq 1 100); do kill -0 "$NK" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$NK" 2>/dev/null; then
    kill -KILL "$NK" 2>/dev/null
    no "serve with no key kept running"
fi
wait "$NK"
rc=$?
mv "$V.key.aside" "$V.key"
if [ "$rc" != 0 ] && LC_ALL=C grep -q -e '--keyfile' "$D/nokey.log"; then ok "serve with no key says what is missing"; else no "serve with no key: rc=$rc: $(tail -1 "$D/nokey.log")"; fi

# A lifeline number naming nothing must not be taken to mean the manager has gone.
if STRATUM_LIFELINE_FD=99 serve "$PASS" && sleep 1 && F ls / > /dev/null 2>&1 && kill -0 "$SP" 2>/dev/null; then
    ok "a daemon does not stop for a lifeline number that names nothing"
else
    no "a lifeline number that names nothing ended the daemon: $(tail -1 "$D/serve.log")"
fi
stop
# An open descriptor that is no pipe reads its end at once, and that is not the manager going.
if STRATUM_LIFELINE_FD=9 serve "$PASS" 9</dev/null && sleep 1 && F ls / > /dev/null 2>&1 && kill -0 "$SP" 2>/dev/null; then
    ok "a daemon does not stop for a lifeline number that names no pipe"
else
    no "a lifeline number naming /dev/null ended the daemon: $(tail -1 "$D/serve.log")"
fi
stop

serve "$PASS" || { no "serve again: $(tail -1 "$D/serve.log")"; exit 1; }
# write -n makes a new file or nothing: a name that is there keeps its bytes.
printf 'kept\n' | F write /keepme.txt > /dev/null 2>&1 || no "seeding /keepme.txt"
if printf 'other\n' | F write -n /keepme.txt > "$D/wn.log" 2>&1; then
    no "write -n over a file that is there answered success"
else
    [ "$(F read /keepme.txt)" = kept ] && ok "write -n refuses a name that is there, and keeps its bytes" \
        || no "write -n changed a file that was there"
fi
printf 'fresh\n' | F write -n /fresh.txt > /dev/null 2>&1 && [ "$(F read /fresh.txt)" = fresh ] \
    && ok "write -n makes a new file" || no "write -n did not make a new file"
# An input that fails to read is a failed write, and -n leaves nothing behind.
if F write -n /fromdir.txt < "$D" > "$D/wd.log" 2>&1; then
    no "a write whose input could not be read answered success"
elif F stat /fromdir.txt > /dev/null 2>&1; then
    no "a failed write -n left its file"
else
    ok "a write whose input fails is refused, and leaves nothing"
fi
# A read whose output fails says so, where a full disk can be had.
if [ -w /dev/full ]; then
    if F read /keepme.txt > /dev/full 2> "$D/rf.log"; then
        no "a read into a full disk answered success"
    else
        ok "a read whose output fails is refused"
    fi
else
    echo "note: no /dev/full here, so a read into a full disk is not tried"
fi
# The same anywhere: with no room for a byte and SIGXFSZ ignored, every write fails.
if ( trap '' XFSZ; ulimit -f 0; F read /keepme.txt > "$D/capped" ) 2> "$D/rc.log"; then
    no "a read whose output cannot be written answered success"
else
    ok "a read whose output cannot be written is refused"
fi
# A new file and a new directory are born with the mode given, and a file whose mode
# leaves out its owner's write still takes its bytes.
printf 'ro\n' | F write -n -m 400 /born400.txt > "$D/wm.log" 2>&1 \
    && [ "$(F read /born400.txt)" = ro ] && F stat /born400.txt | LC_ALL=C grep -q '^mode: *0400$' \
    && ok "write -m gives a new file its mode, and still writes it" \
    || no "write -m 400: $(tail -1 "$D/wm.log"); $(F stat /born400.txt 2>&1 | LC_ALL=C grep '^mode')"
F mkdir -m 700 /born700 > "$D/mm.log" 2>&1 && F stat /born700 | LC_ALL=C grep -q '^mode: *0700$' \
    && ok "mkdir -m gives a new directory its mode" \
    || no "mkdir -m 700: $(tail -1 "$D/mm.log"); $(F stat /born700 2>&1 | LC_ALL=C grep '^mode')"
# Two daemons on one image would each write commits the other knows nothing of.
printf '%s\n' "$PASS" | "$B" serve "$V" --listen "$D/second.sock" --keyfile "$V.key" --passphrase-stdin > "$D/second.log" 2>&1 &
SECOND=$!
for _ in $(seq 1 100); do kill -0 "$SECOND" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$SECOND" 2>/dev/null; then
    no "a second daemon opened a volume already in use"
    kill -KILL "$SECOND" 2>/dev/null
elif LC_ALL=C grep -q 'already open' "$D/second.log"; then
    ok "a second daemon on one volume is refused, and says why"
else
    no "the second daemon stopped without saying why: $(tail -1 "$D/second.log")"
fi
wait "$SECOND" 2>/dev/null
F ls / > /dev/null || no "the refusal disturbed the first daemon"
# Naming a volume to mkfs again must not lose it, least of all under its daemon.
kh=$(cksum < "$V.key")
if "$B" mkfs "$V" --size 256M > "$D/again.log" 2>&1; then
    no "mkfs over a volume in use answered success"
elif LC_ALL=C grep -q 'running stratumd' "$D/again.log"; then
    ok "mkfs over a volume in use is refused, and says why"
else
    no "mkfs over a volume in use stopped without saying why: $(tail -1 "$D/again.log")"
fi
if printf '%s\n' "$PASS" | "$B" mkfs "$V" --size 256M --force --passphrase-stdin > "$D/again.log" 2>&1; then
    no "--force reached past a daemon using the volume"
elif LC_ALL=C grep -q 'running stratumd' "$D/again.log"; then
    ok "--force does not reach past a daemon, and says why"
else
    no "--force past a daemon stopped without saying why: $(tail -1 "$D/again.log")"
fi
[ "$(cksum < "$V.key")" = "$kh" ] && ok "the key is untouched by a refused mkfs" || no "a refused mkfs replaced the key"
F ls / > /dev/null || no "the refused mkfs disturbed the daemon"
F mkdir /in || no "mkdir"
F put "$D/host" /in/host > "$D/put.log" 2>&1 || no "put: $(tail -1 "$D/put.log")"
# A mutating command commits before it reports success, so a kill now must lose nothing.
kill -KILL "$SP" 2>/dev/null
wait "$SP" 2>/dev/null
SP=
rm -f "$S"

# With no daemon, a pool at the path and a key that opens something are still not to be lost by accident.
vh=$(cksum < "$V"); kh=$(cksum < "$V.key")
if "$B" mkfs "$V" --size 256M > "$D/again.log" 2>&1; then
    no "mkfs over an existing volume answered success"
elif LC_ALL=C grep -q 'already holds data' "$D/again.log"; then
    ok "mkfs over an existing volume is refused, and says why"
else
    no "mkfs over an existing volume stopped without saying why: $(tail -1 "$D/again.log")"
fi
[ "$(cksum < "$V")" = "$vh" ] && ok "the refused mkfs left the volume's bytes alone" || no "a refused mkfs changed the volume"
if printf '%s\n' other | "$B" mkfs "$D/new.stm" --size 64M --keyfile "$V.key" --passphrase-stdin > "$D/again.log" 2>&1; then
    no "a new volume replaced another volume's key"
elif LC_ALL=C grep -q 'already exists' "$D/again.log"; then
    ok "a new volume naming an existing key with a passphrase is refused, and says why"
else
    no "the refusal over a key did not say why: $(tail -1 "$D/again.log")"
fi
[ "$(cksum < "$V.key")" = "$kh" ] && ok "another volume's key survives" || no "another volume's key was replaced"
# A key used as it is decides who can open the volume: one others can read or write is refused before
# anything is made, and with --force used; the user's own, read by no one else, is used (the control).
"$B" mkfs "$D/raw.stm" --size 64M < /dev/null > "$D/raw.log" 2>&1 || no "a volume with no passphrase: $(tail -1 "$D/raw.log")"
chmod 644 "$D/raw.stm.key"
if "$B" mkfs "$D/shared.stm" --size 64M --keyfile "$D/raw.stm.key" < /dev/null > "$D/shared.log" 2>&1; then
    no "a key others can read was used"
elif LC_ALL=C grep -q 'others can read or write it' "$D/shared.log" && [ ! -e "$D/shared.stm" ]; then
    ok "a key others can read is refused before anything is made, and says why"
else
    no "the refusal of a key others can read: $(tail -1 "$D/shared.log"); image left: $([ -e "$D/shared.stm" ] && echo yes || echo no)"
fi
if "$B" mkfs "$D/shared.stm" --size 64M --force --keyfile "$D/raw.stm.key" < /dev/null > "$D/shared.log" 2>&1 \
        && LC_ALL=C grep -q 'using existing keyfile' "$D/shared.log"; then
    ok "with --force a key others can read is used"
else
    no "--force over a key others can read: $(tail -1 "$D/shared.log")"
fi
chmod 600 "$D/raw.stm.key"
if "$B" mkfs "$D/own.stm" --size 64M --keyfile "$D/raw.stm.key" < /dev/null > "$D/own.log" 2>&1 \
        && LC_ALL=C grep -q 'using existing keyfile' "$D/own.log"; then
    ok "the user's own key, read by no one else, is used as it is"
else
    no "the user's own key: $(tail -1 "$D/own.log")"
fi

# A link another user owns does not decide where the key goes: in a shared sticky directory whoever left
# it would hold the key, which the kernel's protected_symlinks keeps from a path it follows itself, and
# mkfs reads the links itself. Refused with a passphrase and without; --force, the control, follows it,
# as a link of the user's own is followed (below). Only root or sudo can give a link another owner, and
# sudo is tried only when STRATUM_TEST_SUDO=1 asks for it: where the user is not in sudoers even a try
# is logged as an incident.
if [ "$(id -u)" = 0 ]; then as=""
elif [ "${STRATUM_TEST_SUDO:-0}" = 1 ] && sudo -n true 2>/dev/null; then as="sudo -n"
else as=none; fi
if [ "$as" = none ]; then
    echo "note: a key name that is another user's link: making one needs root, or STRATUM_TEST_SUDO=1 and sudo without a password"
else
    mkdir "$D/theirs"
    ln -s "$D/theirs/k" "$D/planted.stm.key"
    $as chown -h nobody "$D/planted.stm.key"
    if [ "$(stat -c %u "$D/planted.stm.key" 2>/dev/null || stat -f %u "$D/planted.stm.key")" = "$(id -u)" ]; then
        no "the planted link is still the user's: it proves nothing"
    fi
    for how in "with a passphrase" "without one"; do
        if [ "$how" = "with a passphrase" ]; then
            printf '%s\n' other | "$B" mkfs "$D/planted.stm" --size 64M --passphrase-stdin > "$D/planted.log" 2>&1
        else
            "$B" mkfs "$D/planted.stm" --size 64M < /dev/null > "$D/planted.log" 2>&1
        fi
        rc=$?
        if [ "$rc" != 0 ] && LC_ALL=C grep -q 'another user owns' "$D/planted.log"; then
            ok "a key name that is another user's link is refused $how, and says why"
        else
            no "a key name that is another user's link $how: rc=$rc: $(tail -1 "$D/planted.log")"
        fi
        [ -z "$(ls -A "$D/theirs")" ] && [ ! -e "$D/planted.stm" ] && ok "that refusal $how made no key and no image" \
            || no "a refused key link $how left: $(ls -A "$D/theirs" | tr '\n' ' ')$(ls "$D/planted.stm" 2>/dev/null)"
    done
    if printf '%s\n' other | "$B" mkfs "$D/planted.stm" --size 64M --force --passphrase-stdin > "$D/planted.log" 2>&1 \
            && [ -s "$D/theirs/k" ]; then
        ok "with --force the key is made where another user's link points"
    else
        no "--force over another user's key link: $(tail -1 "$D/planted.log")"
    fi
    # The same link to a key of the user's own, which is used as it is: refused when the volume is
    # claimed, before the key would be read, with a passphrase and without.
    ln -s "$D/raw.stm.key" "$D/reuse.stm.key"
    $as chown -h nobody "$D/reuse.stm.key"
    for how in "with a passphrase" "without one"; do
        if [ "$how" = "with a passphrase" ]; then
            printf '%s\n' other | "$B" mkfs "$D/reuse.stm" --size 64M --passphrase-stdin > "$D/reuse.log" 2>&1
        else
            "$B" mkfs "$D/reuse.stm" --size 64M < /dev/null > "$D/reuse.log" 2>&1
        fi
        rc=$?
        if [ "$rc" != 0 ] && LC_ALL=C grep -q 'another user owns' "$D/reuse.log" && [ ! -e "$D/reuse.stm" ]; then
            ok "another user's link to an existing key is refused $how, before anything is made"
        else
            no "another user's link to an existing key $how: rc=$rc: $(tail -1 "$D/reuse.log"); image: $(ls "$D/reuse.stm" 2>/dev/null)"
        fi
    done
fi
[ ! -e "$D/new.stm" ] && ok "that refusal left no empty image" || no "that refusal left an image behind"

# A format cannot shrink a file. Asking for it must fail before any key is touched.
if printf '%s\n' other | "$B" mkfs "$V" --size 64M --force --passphrase-stdin > "$D/again.log" 2>&1; then
    no "a format smaller than the file answered success"
elif LC_ALL=C grep -q 'cannot shrink' "$D/again.log"; then
    ok "a format smaller than the file is refused, and says why"
else
    no "a format smaller than the file stopped without saying why: $(tail -1 "$D/again.log")"
fi
[ "$(cksum < "$V.key")" = "$kh" ] && ok "that refusal kept the key" || no "a format that could not run replaced the key"
[ "$(cksum < "$V")" = "$vh" ] && ok "that refusal kept the volume" || no "a format that could not run changed the volume"

# Nothing ends /dev/zero, so a scan would read it for ever, and a format could not size it.
perl -e 'alarm 30; exec @ARGV' "$B" mkfs /dev/zero --size 64M --force --keyfile "$D/zero.key" > "$D/zero.log" 2>&1
rc=$?
if LC_ALL=C grep -q 'neither a file nor a disk' "$D/zero.log" && [ "$rc" != 0 ]; then
    ok "a device nothing can size is refused, and says why"
else
    no "mkfs on /dev/zero, rc=$rc: $(tail -1 "$D/zero.log")"
fi
perl -e 'alarm 30; exec @ARGV' "$B" mkfs /dev/zero --size 64M --keyfile "$D/zero.key" > "$D/zero2.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && [ "$rc" != 142 ] && LC_ALL=C grep -q 'neither a file nor a disk' "$D/zero2.log"; then
    ok "that refusal does not wait on a scan first"
else
    no "mkfs on /dev/zero without --force, rc=$rc: $(tail -1 "$D/zero2.log")"
fi
[ ! -e "$D/zero.key" ] && ok "those refusals made no key" || no "a refused format on /dev/zero made a key"
# Past the size check a format can still fail, and the key it would have replaced has to be there afterwards.
if printf '%s\n' other | "$B" mkfs "$V" --size 9000000000G --force --passphrase-stdin > "$D/again.log" 2>&1; then
    no "an impossible size over a volume answered success"
fi
# Only a run that made its new key failed late enough to matter here.
LC_ALL=C grep -q 'the new key is at' "$D/again.log" \
    || no "the late failure stopped before its new key: $(tail -1 "$D/again.log")"
[ "$(cksum < "$V.key")" = "$kh" ] && ok "a format that failed late kept the key it would have replaced" || no "a format that failed late replaced the key"

# A format that fails late leaves what it found, and nothing it made, so a retry just works.
printf 'not a key' > "$D/late.stm.key"
chmod 600 "$D/late.stm.key"
if "$B" mkfs "$D/late.stm" --size 64M > "$D/late.log" 2>&1; then
    no "a garbage key formatted a volume"
else
    [ ! -e "$D/late.stm" ] && ok "a failed format over a bad key leaves no image" || no "a failed format left an image"
    [ "$(cat "$D/late.stm.key")" = 'not a key' ] && ok "a failed format leaves a key it found" || no "a failed format changed a key it found"
fi
rm -f "$D/late.stm.key"
if printf '%s\n' other | "$B" mkfs "$D/late.stm" --size 9000000000G --passphrase-stdin > "$D/late.log" 2>&1; then
    no "an impossible size formatted a volume"
else
    LC_ALL=C grep -q 'the new key is at' "$D/late.log" \
        || no "that failure stopped before its new key: $(tail -1 "$D/late.log")"
    left=$(ls "$D" | LC_ALL=C grep -c '^late\.stm')
    [ "$left" = 0 ] && ok "a failed format leaves neither image nor new key" || no "a failed format left $left files: $(ls "$D" | LC_ALL=C grep '^late\.stm' | head -3)"
fi
printf '%s\n' other | "$B" mkfs "$D/late.stm" --size 64M --passphrase-stdin > "$D/late.log" 2>&1 \
    && [ -s "$D/late.stm.key" ] && ok "the same command with a size that fits formats, and leaves its key" \
    || no "the retry after a failed format: $(tail -1 "$D/late.log")"
[ -z "$(ls "$D" | LC_ALL=C grep -F '.key.new.')" ] && ok "no temporary key is left behind" || no "a temporary key was left behind"

# A key named through a symlink is written where the link points, and the link stays.
mkdir -p "$D/keys"
ln -s "$D/keys/linked.key" "$D/linked.key"
if "$B" mkfs "$D/linked.stm" --size 64M --keyfile "$D/linked.key" > "$D/lk.log" 2>&1 \
    && [ -L "$D/linked.key" ] && [ -s "$D/keys/linked.key" ]; then
    ok "a key named through a link lands where it points, and the link stays"
else
    no "a key named through a link: $(tail -1 "$D/lk.log"); the link there: $([ -L "$D/linked.key" ] && echo yes || echo no)"
fi
# A relative link is read from the link's own directory, wherever mkfs runs.
mkdir -p "$D/keys2"
ln -s keys2/rel.key "$D/rel.key"
if (cd / && "$B" mkfs "$D/rel.stm" --size 64M --keyfile "$D/rel.key") > "$D/rk.log" 2>&1 \
    && [ -L "$D/rel.key" ] && [ -s "$D/keys2/rel.key" ]; then
    ok "a key named through a relative link lands where it points"
else
    no "a key named through a relative link: $(tail -1 "$D/rk.log")"
fi
# A file already at the temporary key's name, perhaps a killed run's only key, is left as it was.
# exec keeps the shell's pid, which is the one the name is made from.
printf 'only key' > "$D/held.placeholder"
if sh -c 'cp "$1" "$2.new.$$"; exec "$3" mkfs "$4" --size 64M --keyfile "$2"' sh \
        "$D/held.placeholder" "$D/held.key" "$B" "$D/held.stm" > "$D/held.log" 2>&1; then
    no "mkfs over a file at its temporary key's name answered success"
else
    held=$(ls "$D" | LC_ALL=C grep -F 'held.key.new.' | head -1)
    if [ -n "$held" ] && [ "$(cat "$D/$held")" = 'only key' ]; then
        ok "a file at the temporary key's name is left as it was"
    else
        no "a file at the temporary key's name was changed or removed: $(tail -1 "$D/held.log")"
    fi
fi
rm -f "$D"/held.*

# A byte anywhere is data, not just in the first MiB.
for at in 2097152 67108863; do
    rm -f "$D/z.stm"
    dd if=/dev/zero of="$D/z.stm" bs=1 count=0 seek=67108864 2>/dev/null
    printf 'X' | dd of="$D/z.stm" bs=1 seek="$at" conv=notrunc 2>/dev/null
    if "$B" mkfs "$D/z.stm" --size 64M > "$D/z.log" 2>&1; then
        no "mkfs formatted over a file with a byte at $at"
    elif LC_ALL=C grep -q 'already holds data' "$D/z.log"; then
        ok "a byte at $at is data"
    else
        no "mkfs stopped at a byte at $at without saying why: $(tail -1 "$D/z.log")"
    fi
done
# The control: --force, and a fresh sparse file, each do format, so a refusal above was about the data.
"$B" mkfs "$D/force.stm" --size 64M > "$D/f1.log" 2>&1 || no "the control's first mkfs: $(tail -1 "$D/f1.log")"
fh=$(cksum < "$D/force.stm")
"$B" mkfs "$D/force.stm" --size 64M --force > "$D/f2.log" 2>&1 && [ "$(cksum < "$D/force.stm")" != "$fh" ] \
    && ok "--force formats over a volume" || no "--force did not format: $(tail -1 "$D/f2.log")"
: > "$D/empty.stm"
"$B" mkfs "$D/empty.stm" --size 64M > "$D/f3.log" 2>&1 && ok "mkfs takes an empty file" || no "mkfs refused an empty file: $(tail -1 "$D/f3.log")"
dd if=/dev/zero of="$D/sparse.stm" bs=1 count=0 seek=67108864 2>/dev/null
"$B" mkfs "$D/sparse.stm" --size 64M > "$D/f4.log" 2>&1 && ok "mkfs takes a sparse file" || no "mkfs refused a sparse file: $(tail -1 "$D/f4.log")"
# --force with a passphrase over a volume with no daemon: the new key is the one that opens it.
fk=$(cksum < "$D/force.stm.key")
if printf '%s\n' second | "$B" mkfs "$D/force.stm" --size 64M --force --passphrase-stdin > "$D/f5.log" 2>&1; then
    [ "$(cksum < "$D/force.stm.key")" != "$fk" ] && ok "--force with a passphrase replaces the key" || no "--force with a passphrase kept the old key"
    OV=$V; V=$D/force.stm
    if serve second; then ok "the replaced key opens the volume"; stop; else no "the replaced key does not open it: $(tail -1 "$D/serve.log")"; fi
    V=$OV
else
    no "--force with a passphrase: $(tail -1 "$D/f5.log")"
fi

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
    LC_ALL=C grep -q 'stratumd: wrong passphrase for ' "$D/serve.log" && ok "the wrong passphrase is called that" \
        || no "the wrong passphrase was not called that: $(tail -2 "$D/serve.log" | head -1)"
fi

# The control for that line: the right passphrase for a key that opens some other volume is not a wrong passphrase.
if refused "$D/wrongkey.log" other "$V" --listen "$S" --keyfile "$D/late.stm.key" --passphrase-stdin; then
    if LC_ALL=C grep -q 'wrong passphrase' "$D/wrongkey.log"; then
        no "another volume's key was called a wrong passphrase"
    elif LC_ALL=C grep -q 'integrity check' "$D/wrongkey.log"; then
        ok "another volume's key is not called a wrong passphrase"
    else
        no "another volume's key: $(tail -1 "$D/wrongkey.log")"
    fi
else
    no "another volume's key opened it, or the daemon hung: $(tail -1 "$D/wrongkey.log")"
fi

# A key that is not one at all, and a name that is not there.
if refused "$D/nokey2.log" x "$V" --listen "$S" --keyfile "$D/host/a.txt" --passphrase-stdin; then
    LC_ALL=C grep -q 'cannot read' "$D/nokey2.log" && ok "a file that is no key is called that" || no "a file that is no key: $(tail -1 "$D/nokey2.log")"
else
    no "a file that is no key opened it, or the daemon hung: $(tail -1 "$D/nokey2.log")"
fi
if refused "$D/nokey3.log" x "$V" --listen "$S" --keyfile "$D/not-there" --passphrase-stdin; then
    LC_ALL=C grep -q 'no such keyfile' "$D/nokey3.log" && ok "a missing key is called that" || no "a missing key: $(tail -1 "$D/nokey3.log")"
else
    no "a missing key opened it, or the daemon hung: $(tail -1 "$D/nokey3.log")"
fi
if refused "$D/typo.log" x "$D/typo.stm" --listen "$S" --keyfile "$V.key"; then
    LC_ALL=C grep -q 'no such image' "$D/typo.log" && ok "a mistyped image is called that" || no "a mistyped image: $(tail -1 "$D/typo.log")"
else
    no "a mistyped image served, or the daemon hung: $(tail -1 "$D/typo.log")"
fi
[ ! -e "$D/typo.stm" ] && ok "a mistyped image leaves no file" || no "a mistyped image made a file"

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
