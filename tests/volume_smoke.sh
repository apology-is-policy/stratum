#!/bin/bash
# A file-based volume end to end, through the packaged binary: create it under a passphrase, copy a
# tree in, and check the three promises an encrypted container makes. Nothing readable reaches the
# file, the wrong passphrase opens nothing, and the bytes come back the same after a remount.
#
#   tests/volume_smoke.sh path/to/stratum
set -u
B=${1:?usage: volume_smoke.sh path/to/stratum}
[ -x "$B" ] || { echo "FAIL: $B is not executable"; exit 2; }
# One check runs it from another directory.
case "$B" in /*) ;; *) B=$PWD/$B ;; esac
HERE=$(cd "$(dirname "$0")" && pwd)

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
# A group of checks this run could not make: said where it is skipped and counted at the end, so a
# run that skipped is not read as one that checked. A note that is not a skip does not say "skipped".
SKIPPED=0
skipped() { echo "note: skipped: $*"; SKIPPED=$((SKIPPED + 1)); }
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
    echo "note: no /dev/full here: the size limit below tries the same"
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
elif LC_ALL=C grep -q '^stratum-mkfs: keyfile .* can be read or written by others' "$D/shared.log" && [ ! -e "$D/shared.stm" ]; then
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
# --key-as-is is the narrow way past that refusal: the key is used, and nothing else of what --force
# does comes with it. Over a volume that is there it still refuses, beside --passphrase-stdin it is
# refused before a passphrase is read (with none to read, a read that came first is what would
# fail), and what is no regular file is still no key (further down).
kh2=$(cksum < "$D/raw.stm.key")
if "$B" mkfs "$D/asis.stm" --size 64M --key-as-is --keyfile "$D/raw.stm.key" < /dev/null > "$D/asis.log" 2>&1 \
        && LC_ALL=C grep -q 'using existing keyfile' "$D/asis.log" && [ -s "$D/asis.stm" ]; then
    ok "with --key-as-is a key others can read is used"
else
    no "--key-as-is over a key others can read: $(tail -1 "$D/asis.log")"
fi
ah=$(cksum < "$D/asis.stm")
"$B" mkfs "$D/asis.stm" --size 64M --key-as-is --keyfile "$D/raw.stm.key" < /dev/null > "$D/asis2.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q 'already holds data' "$D/asis2.log" && [ "$(cksum < "$D/asis.stm")" = "$ah" ]; then
    ok "--key-as-is does not format over a volume that is there"
else
    no "--key-as-is over a volume that is there: rc=$rc: $(tail -1 "$D/asis2.log")"
fi
"$B" mkfs "$D/asis3.stm" --size 64M --key-as-is --passphrase-stdin --keyfile "$D/raw.stm.key" < /dev/null > "$D/asis3.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q -e '--key-as-is uses a key file that is there' "$D/asis3.log" && [ ! -e "$D/asis3.stm" ]; then
    ok "--key-as-is beside --passphrase-stdin is refused before a passphrase is read"
else
    no "--key-as-is before a passphrase is read: rc=$rc: $(tail -1 "$D/asis3.log"); image left: $([ -e "$D/asis3.stm" ] && echo yes || echo no)"
fi
printf '%s\n' other | "$B" mkfs "$D/asis4.stm" --size 64M --key-as-is --passphrase-stdin --keyfile "$D/raw.stm.key" > "$D/asis4.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q -e '--key-as-is uses a key file that is there' "$D/asis4.log" && [ ! -e "$D/asis4.stm" ]; then
    ok "--key-as-is with a passphrase is refused, and says why"
else
    no "--key-as-is with a passphrase: rc=$rc: $(tail -1 "$D/asis4.log"); image left: $([ -e "$D/asis4.stm" ] && echo yes || echo no)"
fi
[ "$(cksum < "$D/raw.stm.key")" = "$kh2" ] && ok "the key those four named is as it was" || no "--key-as-is changed the key it named"
chmod 600 "$D/raw.stm.key"
if "$B" mkfs "$D/own.stm" --size 64M --keyfile "$D/raw.stm.key" < /dev/null > "$D/own.log" 2>&1 \
        && LC_ALL=C grep -q 'using existing keyfile' "$D/own.log"; then
    ok "the user's own key, read by no one else, is used as it is"
else
    no "the user's own key: $(tail -1 "$D/own.log")"
fi
# Over an image that is there the key is asked about before the image is read, which on an empty
# disk is all of it: own.stm holds data now, and the key's refusal still comes first.
[ -s "$D/own.stm" ] || no "own.stm is not there: the order proves nothing"
chmod 644 "$D/raw.stm.key"
"$B" mkfs "$D/own.stm" --size 64M --keyfile "$D/raw.stm.key" < /dev/null > "$D/own.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q '^stratum-mkfs: keyfile .* can be read or written by others' "$D/own.log"; then
    ok "over an image that is there, a key others can read is refused before the image is read"
else
    no "a key others can read, over an image that is there: rc=$rc: $(tail -1 "$D/own.log")"
fi
chmod 600 "$D/raw.stm.key"
# What is at the key's name and is no regular file is no key to use.
mkdir -m 700 "$D/dir.key"
"$B" mkfs "$D/dirkey.stm" --size 64M --keyfile "$D/dir.key" < /dev/null > "$D/dirkey.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q '^stratum-mkfs: keyfile .* is not a regular file' "$D/dirkey.log" && [ ! -e "$D/dirkey.stm" ]; then
    ok "a directory at the key's name is refused before anything is made, and says why"
else
    no "a directory at the key's name: rc=$rc: $(tail -1 "$D/dirkey.log"); image left: $([ -e "$D/dirkey.stm" ] && echo yes || echo no)"
fi
"$B" mkfs "$D/dirkey.stm" --size 64M --key-as-is --keyfile "$D/dir.key" < /dev/null > "$D/dirkey.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q '^stratum-mkfs: keyfile .* is not a regular file' "$D/dirkey.log" && [ ! -e "$D/dirkey.stm" ]; then
    ok "with --key-as-is too, a directory at the key's name is no key"
else
    no "--key-as-is and a directory at the key's name: rc=$rc: $(tail -1 "$D/dirkey.log"); image left: $([ -e "$D/dirkey.stm" ] && echo yes || echo no)"
fi

# A link left at the key's name while mkfs is looking at it. No second process can leave one
# between two of mkfs's own system calls, so a small library loaded into mkfs does it, just before
# the call it is told (tests/plant_at_look.c). mkfs looks at the name, reads a link it finds there
# and looks at it again, and then asks what the name reaches: once before it makes the image and
# once after. It opens the name to see whether a key is there to use, looks once more where it
# makes one, and a last time when the new key has taken the name. A link it found is one it asked
# about. One left after it looked must not be followed.
case "$(uname -s)" in
    Darwin) PLANT_LIB=$D/plant.dylib; PLANT_HOW=-dynamiclib ;;
    *)      PLANT_LIB=$D/plant.so;    PLANT_HOW="-shared -fPIC" ;;
esac
# planted TAG MOMENT [TO [OVER [AS]]]: mkfs for $D/pl-TAG.stm with the key name $D/pl-TAG.key, and
# a link to TO (a key of the user's own unless given) left at that name just before MOMENT. OVER
# not empty: it replaces what is there. AS a uid: mkfs is told that user owns it. The library is
# named on the command itself: through env(1) macOS would drop it, as it does on the way through
# any system binary.
planted() {
    if [ "$(uname -s)" = Darwin ]; then
        DYLD_INSERT_LIBRARIES="$PLANT_LIB" STM_PLANT_AT="$D/pl-$1.key" STM_PLANT_ON="$2" STM_PLANT_TO="${3:-$D/pl-own.key}" \
            STM_PLANT_OVER="${4:-}" STM_PLANT_AS="${5:-}" \
            STM_PLANT_LOG="$D/pl-$1.plant" "$B" mkfs "$D/pl-$1.stm" --size 64M --keyfile "$D/pl-$1.key" < /dev/null > "$D/pl-$1.log" 2>&1
    else
        LD_PRELOAD="$PLANT_LIB" STM_PLANT_AT="$D/pl-$1.key" STM_PLANT_ON="$2" STM_PLANT_TO="${3:-$D/pl-own.key}" \
            STM_PLANT_OVER="${4:-}" STM_PLANT_AS="${5:-}" \
            STM_PLANT_LOG="$D/pl-$1.plant" "$B" mkfs "$D/pl-$1.stm" --size 64M --keyfile "$D/pl-$1.key" < /dev/null > "$D/pl-$1.log" 2>&1
    fi
}
moments() { tr '\n' ' ' < "$D/pl-$1.plant" 2>/dev/null; }
# plant_run NAME=VALUE... -- ARGS: "$B" ARGS with the library loaded and told those settings.
plant_run() {
    (
        while [ "$1" != -- ]; do export "$1"; shift; done
        shift
        if [ "$(uname -s)" = Darwin ]; then export DYLD_INSERT_LIBRARIES="$PLANT_LIB"; else export LD_PRELOAD="$PLANT_LIB"; fi
        exec "$B" "$@"
    )
}
# opens VOLUME KEY: whether that key opens that volume, by a daemon that comes up on it.
opens() {
    rm -f "$D/opens.sock"
    "$B" serve "$1" --listen "$D/opens.sock" --keyfile "$2" < /dev/null > "$D/opens.log" 2>&1 &
    op=$!
    up=1
    for _ in $(seq 1 100); do
        [ -S "$D/opens.sock" ] && { up=0; break; }
        kill -0 "$op" 2>/dev/null || break
        sleep 0.1
    done
    kill -TERM "$op" 2>/dev/null
    wait "$op" 2>/dev/null
    rm -f "$D/opens.sock"
    return $up
}
# The directory as the system names it: where mkfs says a key is, it says it so.
DP=$(cd "$D" && pwd -P)
if ! command -v cc > /dev/null 2>&1; then
    skipped "a link left at the key's name while mkfs looks: the library that leaves it needs a C compiler"
elif ! cc $PLANT_HOW -o "$PLANT_LIB" "$HERE/plant_at_look.c" -ldl > "$D/plant-build.log" 2>&1; then
    no "the library that leaves a link while mkfs looks did not build: $(head -1 "$D/plant-build.log")"
elif ! "$B" mkfs "$D/pl-own.stm" --size 64M --keyfile "$D/pl-own.key" < /dev/null > "$D/pl-own.log" 2>&1; then
    no "a key of the user's own for the planted links: $(tail -1 "$D/pl-own.log")"
else
    # Nothing left: what the library sees says which moment is which below. If mkfs comes to look
    # more or fewer times, this is the check that says so, and those under it need their moments
    # named again. Looks 1 and 2 are the claim before the image is made, 3 and 4 the claim after;
    # the open is where a key that is there is taken up for use; look 5 is where a new key's place
    # is asked about, 6 what the name reaches once the key has taken it.
    planted none nothing; rc=$?
    if [ "$rc" = 0 ] && [ "$(moments none)" = "look:1 look:2 look:3 look:4 open:1 look:5 look:6 " ] \
            && LC_ALL=C grep -q 'generated keyfile' "$D/pl-none.log"; then
        ok "the library sees each time mkfs reads the key's links and looks at the key"
    else
        no "mkfs's looks at its key, as the library saw them: rc=$rc: $(moments none): $(tail -1 "$D/pl-none.log")"
    fi
    # The control: a link that is there at the first look is read and asked about, is the user's
    # own, and is followed.
    planted first look:1; rc=$?
    if [ "$rc" = 0 ] && LC_ALL=C grep -q '^planted before look:1: done$' "$D/pl-first.plant" \
            && LC_ALL=C grep -q '^readlink:1$' "$D/pl-first.plant" \
            && LC_ALL=C grep -q 'using existing keyfile' "$D/pl-first.log" && [ -s "$D/pl-first.stm" ]; then
        ok "a link of the user's own that mkfs read at the key's name is followed"
    else
        no "a link there before mkfs read the key's links: rc=$rc: $(moments first): $(tail -1 "$D/pl-first.log")"
    fi
    # The same link at the same look, and another user's as far as mkfs is told: refused when the
    # volume is claimed.
    planted theirs look:1 "" "" "$(( $(id -u) + 1 ))"; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before look:1: done$' "$D/pl-theirs.plant" \
            && LC_ALL=C grep -q 'reached through a symlink another user owns' "$D/pl-theirs.log" && [ ! -e "$D/pl-theirs.stm" ]; then
        ok "another user's link at the key's name is refused when the volume is claimed, and nothing is made"
    else
        no "another user's link at the key's name when the volume is claimed: rc=$rc: $(moments theirs): $(tail -1 "$D/pl-theirs.log"); image left: $([ -e "$D/pl-theirs.stm" ] && echo yes || echo no)"
    fi
    # Left after the claim's last look for links at the name, before it asks what the name reaches.
    planted claim look:4; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before look:4: done$' "$D/pl-claim.plant" \
            && LC_ALL=C grep -q 'does not lead where its links were read to end' "$D/pl-claim.log" && [ ! -e "$D/pl-claim.stm" ]; then
        ok "a link left after the claim read the key's links is not followed, and nothing is made"
    else
        no "a link left after the claim read the key's links: rc=$rc: $(moments claim): $(tail -1 "$D/pl-claim.log"); image left: $([ -e "$D/pl-claim.stm" ] && echo yes || echo no)"
    fi
    # Left after the claim, before the open that decides whether there is a key to use.
    planted use open:1; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before open:1: done$' "$D/pl-use.plant" \
            && LC_ALL=C grep -q 'turned up after the volume was claimed' "$D/pl-use.log" && [ ! -e "$D/pl-use.stm" ]; then
        ok "a link left between the claim and the use of the key is not followed, and nothing is made"
    else
        no "a link left between the claim and the use: rc=$rc: $(moments use): $(tail -1 "$D/pl-use.log"); image left: $([ -e "$D/pl-use.stm" ] && echo yes || echo no)"
    fi
    # Left where the new key's place is asked about, and another user's as far as mkfs is told.
    # Nothing else asks at that moment: the claim found the name free, and so did the use.
    planted ask look:5 "$D/pl-ask.to" "" "$(( $(id -u) + 1 ))"; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before look:5: done$' "$D/pl-ask.plant" \
            && LC_ALL=C grep -q 'reached through a symlink another user owns' "$D/pl-ask.log" && [ ! -e "$D/pl-ask.stm" ] \
            && ! ls "$D"/pl-ask.to* > /dev/null 2>&1; then
        ok "another user's link left where the new key's place is asked about is refused, and nothing is made"
    else
        no "another user's link left where the new key's place is asked about: rc=$rc: $(moments ask): $(tail -1 "$D/pl-ask.log"); image left: $([ -e "$D/pl-ask.stm" ] && echo yes || echo no); at its target: $(ls "$D"/pl-ask.to* 2>/dev/null | wc -l | tr -d ' ')"
    fi
    # A link of the user's own is at the name, and another takes its place between mkfs's look at
    # it and its reading of it: the one read is not the one that was asked about.
    ln -s "$D/pl-own.key" "$D/pl-swap.key"
    planted swap readlink:1 "$D/pl-swap.to" over; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before readlink:1: done$' "$D/pl-swap.plant" \
            && LC_ALL=C grep -q 'changed while it was being read' "$D/pl-swap.log" && [ ! -e "$D/pl-swap.stm" ] \
            && ! ls "$D"/pl-swap.to* > /dev/null 2>&1; then
        ok "a link replaced between mkfs's look at it and its reading of it is not followed, and nothing is made"
    else
        no "a link replaced between mkfs's look at it and its reading of it: rc=$rc: $(moments swap): $(tail -1 "$D/pl-swap.log"); image left: $([ -e "$D/pl-swap.stm" ] && echo yes || echo no); at its target: $(ls "$D"/pl-swap.to* 2>/dev/null | wc -l | tr -d ' ')"
    fi
    # A key is at the name, and a link to another key takes its place after the claim's last look
    # for links. Both are keys of the user's own: what the name reaches is still not what was
    # looked at.
    cp "$D/pl-own.key" "$D/pl-taken.key" && chmod 600 "$D/pl-taken.key"
    planted taken look:4 "" over; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before look:4: done$' "$D/pl-taken.plant" \
            && LC_ALL=C grep -q 'does not lead where its links were read to end' "$D/pl-taken.log" && [ ! -e "$D/pl-taken.stm" ]; then
        ok "a link to another key put in a key's place after the claim looked at it is not followed, and nothing is made"
    else
        no "a link to another key put in a key's place after the claim looked at it: rc=$rc: $(moments taken): $(tail -1 "$D/pl-taken.log"); image left: $([ -e "$D/pl-taken.stm" ] && echo yes || echo no)"
    fi
    # A key is at the name and passes the claim, and a link to another key takes its place before
    # the key is opened for use. The other is a key of the user's own too, and passes all that is
    # asked of a key: it is still not the file the claim asked about.
    cp "$D/pl-own.key" "$D/pl-reuse.key" && chmod 600 "$D/pl-reuse.key"
    planted reuse open:1 "" over; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before open:1: done$' "$D/pl-reuse.plant" \
            && LC_ALL=C grep -qF "since the volume was claimed, keyfile $D/pl-reuse.key leads to another file than the one that was asked about" "$D/pl-reuse.log" \
            && [ ! -e "$D/pl-reuse.stm" ]; then
        ok "a link to another key put in a key's place between the claim and the key's use is not followed, and nothing is made"
    else
        no "a link to another key put in a key's place between the claim and its use: rc=$rc: $(moments reuse): $(tail -1 "$D/pl-reuse.log"); image left: $([ -e "$D/pl-reuse.stm" ] && echo yes || echo no)"
    fi
    # A link to nothing left inside the claim passes it, as the free name does: nothing is there
    # either way. It is asked about where the new key's place is, and another user's, as far as
    # mkfs is told, is refused there.
    planted nowhere look:4 "$D/pl-nowhere.to" "" "$(( $(id -u) + 1 ))"; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before look:4: done$' "$D/pl-nowhere.plant" \
            && LC_ALL=C grep -q 'reached through a symlink another user owns' "$D/pl-nowhere.log" && [ ! -e "$D/pl-nowhere.stm" ] \
            && ! ls "$D"/pl-nowhere.to* > /dev/null 2>&1; then
        ok "another user's link to nothing left inside the claim is refused where the new key's place is asked about, and nothing is made"
    else
        no "another user's link to nothing left inside the claim: rc=$rc: $(moments nowhere): $(tail -1 "$D/pl-nowhere.log"); image left: $([ -e "$D/pl-nowhere.stm" ] && echo yes || echo no); at its target: $(ls "$D"/pl-nowhere.to* 2>/dev/null | wc -l | tr -d ' ')"
    fi
    # Once the new key has taken its place, the name has to reach it: mkfs followed the links by
    # their text, and every later command is given the name. Here the name is a link of the
    # user's own to where the key is to go, and another link put over it just before mkfs asks
    # stands in for a name the kernel follows another way. The volume is formatted by then, so
    # it stays, and so does the key, where mkfs says it is. The name being a link, mkfs
    # looks at it three times in each claim and twice where the new key's place is asked
    # about: this is its ninth look.
    ln -s "$D/pl-name.to" "$D/pl-name.key"
    planted name look:9 "" over; rc=$?
    if [ "$rc" = 2 ] && LC_ALL=C grep -q '^planted before look:9: done$' "$D/pl-name.plant" \
            && LC_ALL=C grep -qF "its key is $DP/pl-name.to, but the name $D/pl-name.key does not lead to it" "$D/pl-name.log" \
            && [ -s "$D/pl-name.stm" ] && [ -f "$D/pl-name.to" ] && [ ! -L "$D/pl-name.to" ] \
            && ! LC_ALL=C grep -q '^generated keyfile' "$D/pl-name.log"; then
        ok "a key name that does not lead to the key mkfs made is said, with where the key is, and the volume and the key are kept"
    else
        no "a key name that does not lead to the key mkfs made: rc=$rc: $(moments name): $(tail -1 "$D/pl-name.log"); image left: $([ -s "$D/pl-name.stm" ] && echo yes || echo no); key where it was put: $([ -f "$D/pl-name.to" ] && echo yes || echo no)"
    fi
    # Where the links lead is asked again where the new key is made, of the directory itself:
    # a link of the user's own left after the claim, into a directory others can change, is
    # refused there, and mkfs says the claim had not seen it.
    mkdir "$D/pl-open"
    chmod 777 "$D/pl-open"
    planted dirs look:5 "$D/pl-open/pl.key"; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^planted before look:5: done$' "$D/pl-dirs.plant" \
            && LC_ALL=C grep -qF "stratum-mkfs: since the volume was claimed, keyfile $D/pl-dirs.key is led by its links to the directory $D/pl-open, which others can change, going by its mode" "$D/pl-dirs.log" \
            && [ ! -e "$D/pl-dirs.stm" ] && [ -z "$(ls -A "$D/pl-open")" ]; then
        ok "a link left after the claim that leads the new key into a directory others can change is refused where the key is made, and nothing is made"
    else
        no "a link left after the claim into a directory others can change: rc=$rc: $(moments dirs): $(tail -1 "$D/pl-dirs.log"); image left: $([ -e "$D/pl-dirs.stm" ] && echo yes || echo no); in the directory: $(ls -A "$D/pl-open" | tr '\n' ' ')"
    fi
    # The new key is made through its directory's descriptor, so it is in the directory
    # that was asked about, wherever the path to it leads by then, and the volume is
    # formatted with that key read back through the descriptor that made it. Here the name is
    # a link of the user's own into a directory of the user's, and once that directory is open
    # and has been asked about it is moved away and another made at its path, as the owner of
    # a directory above it could do. Nothing is made in the directory now at the path. The
    # volume is made, its key takes its name in the directory that was moved, and mkfs says
    # where that is and that the name does not lead there. The library watches the directory
    # the key was named in, whose third look is the one where the key is made; the open before
    # it is of the image, which this run makes there and holds its directory to remove it by.
    mkdir "$D/pl-kept"
    chmod 755 "$D/pl-kept"
    ln -s "pl-kept/k.key" "$D/pl-moved.key"
    plant_run STM_PLANT_AT="$D" STM_PLANT_ON=look:3 STM_PLANT_MOVE="$D/pl-kept" STM_PLANT_LOG="$D/pl-moved.plant" \
        -- mkfs "$D/pl-moved.stm" --size 64M --keyfile "$D/pl-moved.key" < /dev/null > "$D/pl-moved.log" 2>&1; rc=$?
    if [ "$rc" = 2 ] && [ "$(moments moved)" = "look:1 look:2 open:1 moved before look:3: done " ] \
            && LC_ALL=C grep -qF "$D/pl-moved.stm is formatted and its key is $DP/pl-kept.away/k.key, but the name $D/pl-moved.key does not lead to it" "$D/pl-moved.log" \
            && [ -z "$(ls -A "$D/pl-kept")" ] && [ "$(ls -A "$D/pl-kept.away")" = k.key ] \
            && opens "$D/pl-moved.stm" "$D/pl-kept.away/k.key"; then
        ok "a key's directory moved away once it was asked about gets no key at its path: the key is in the directory that was asked about, mkfs says where, and it opens the volume"
    else
        no "a key's directory moved away once it was asked about: rc=$rc: $(moments moved): $(tail -1 "$D/pl-moved.log"); at its path: $(ls -A "$D/pl-kept" 2>/dev/null | tr '\n' ' '); moved away: $(ls -A "$D/pl-kept.away" 2>/dev/null | tr '\n' ' '); the daemon on it: $(tail -1 "$D/opens.log" 2>/dev/null)"
    fi
    # The same, and whoever moved the directory away leaves a key of theirs in the one at its
    # path, under the name mkfs made its own by. A format that came back to the path for its
    # key would wrap the volume under theirs. The key mkfs made is the one that opens it.
    mkdir "$D/pl-put"
    chmod 755 "$D/pl-put"
    ln -s "pl-put/k.key" "$D/pl-theirs-put.key"
    plant_run STM_PLANT_AT="$D" STM_PLANT_ON=look:3 STM_PLANT_MOVE="$D/pl-put" STM_PLANT_PUT="$D/pl-own.key" STM_PLANT_PUT_AS=k.key.new. \
        STM_PLANT_LOG="$D/pl-theirs-put.plant" \
        -- mkfs "$D/pl-theirs-put.stm" --size 64M --keyfile "$D/pl-theirs-put.key" < /dev/null > "$D/pl-theirs-put.log" 2>&1; rc=$?
    put=$(ls -A "$D/pl-put" 2>/dev/null | LC_ALL=C grep -c '^k\.key\.new\.[0-9][0-9]*$')
    if [ "$rc" = 2 ] && [ "$(moments theirs-put)" = "look:1 look:2 open:1 moved before look:3: done " ] && [ "$put" = 1 ] \
            && [ "$(ls -A "$D/pl-put.away")" = k.key ] \
            && opens "$D/pl-theirs-put.stm" "$D/pl-put.away/k.key" && ! opens "$D/pl-theirs-put.stm" "$D/pl-own.key"; then
        ok "a key of another's left at the path of the key mkfs made is not the one the volume is made with"
    else
        no "a key of another's left at the path of the key mkfs made: rc=$rc: $(moments theirs-put): $(tail -1 "$D/pl-theirs-put.log"); theirs left at the path: $put; moved away: $(ls -A "$D/pl-put.away" 2>/dev/null | tr '\n' ' '); the daemon last tried: $(tail -1 "$D/opens.log" 2>/dev/null)"
    fi
    # A file another user owns at the image's name is theirs to remove, and the volume with
    # it: an empty one left at a free name is not formatted into. No test can make another
    # user's file without being root, so mkfs is told it runs as another user, and the empty
    # file, the real user's, is to it another's. The control is the same file with mkfs told
    # nothing, which is formatted.
    : > "$D/pl-img.stm"
    if [ "$(uname -s)" = Darwin ]; then
        DYLD_INSERT_LIBRARIES="$PLANT_LIB" STM_PLANT_EUID=$(($(id -u) + 1)) "$B" mkfs "$D/pl-img.stm" --size 64M < /dev/null > "$D/pl-img.log" 2>&1; rc=$?
    else
        LD_PRELOAD="$PLANT_LIB" STM_PLANT_EUID=$(($(id -u) + 1)) "$B" mkfs "$D/pl-img.stm" --size 64M < /dev/null > "$D/pl-img.log" 2>&1; rc=$?
    fi
    if [ "$rc" != 0 ] && LC_ALL=C grep -qF "stratum-mkfs: $D/pl-img.stm belongs to another user, who could remove the volume" "$D/pl-img.log" \
            && [ -f "$D/pl-img.stm" ] && [ ! -s "$D/pl-img.stm" ] && [ ! -e "$D/pl-img.stm.key" ]; then
        ok "an empty file at the image's name that is not the user's is not formatted into, and no key is made"
    else
        no "an empty file at the image's name that is not the user's: rc=$rc: $(tail -1 "$D/pl-img.log"); bytes in it: $(wc -c < "$D/pl-img.stm" | tr -d ' '); key made: $([ -e "$D/pl-img.stm.key" ] && echo yes || echo no)"
    fi
    if [ "$(uname -s)" = Darwin ]; then
        DYLD_INSERT_LIBRARIES="$PLANT_LIB" "$B" mkfs "$D/pl-img.stm" --size 64M < /dev/null > "$D/pl-img-own.log" 2>&1; rc=$?
    else
        LD_PRELOAD="$PLANT_LIB" "$B" mkfs "$D/pl-img.stm" --size 64M < /dev/null > "$D/pl-img-own.log" 2>&1; rc=$?
    fi
    if [ "$rc" = 0 ] && [ -s "$D/pl-img.stm" ] && [ -f "$D/pl-img.stm.key" ]; then
        ok "the same empty file, the user's own, is formatted"
    else
        no "the user's own empty file at the image's name: rc=$rc: $(tail -1 "$D/pl-img-own.log")"
    fi
    # A link at the image's name is followed by the claim's open, so it is asked about as a
    # key's links are. One the user owns, into the directory the image was named in, is
    # followed: the control. The same link, another user's as far as mkfs is told, is not.
    : > "$D/im-file.stm"
    ln -s "$D/im-file.stm" "$D/im-theirs.stm"
    plant_run STM_PLANT_AT="$D/im-theirs.stm" STM_PLANT_AS="$(( $(id -u) + 1 ))" STM_PLANT_LOG="$D/im-theirs.plant" \
        -- mkfs "$D/im-theirs.stm" --size 64M < /dev/null > "$D/im-theirs.log" 2>&1; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -qF "stratum-mkfs: image $D/im-theirs.stm is reached through a symlink another user owns, who would decide where the volume goes" "$D/im-theirs.log" \
            && [ ! -s "$D/im-file.stm" ] && [ ! -e "$D/im-theirs.stm.key" ]; then
        ok "another user's link at the image's name is not followed: the file it leads to is not formatted, and no key is made"
    else
        no "another user's link at the image's name: rc=$rc: $(tail -1 "$D/im-theirs.log"); bytes in the file: $(wc -c < "$D/im-file.stm" | tr -d ' '); key made: $([ -e "$D/im-theirs.stm.key" ] && echo yes || echo no)"
    fi
    plant_run STM_PLANT_AT="$D/im-theirs.stm" STM_PLANT_LOG="$D/im-own.plant" \
        -- mkfs "$D/im-theirs.stm" --size 64M < /dev/null > "$D/im-own.log" 2>&1; rc=$?
    if [ "$rc" = 0 ] && [ -s "$D/im-file.stm" ] && [ -L "$D/im-theirs.stm" ] && opens "$D/im-theirs.stm" "$D/im-theirs.stm.key"; then
        ok "the same link, the user's own, is followed: the file it leads to is formatted, and its key opens it by the link"
    else
        no "the user's own link at the image's name: rc=$rc: $(tail -1 "$D/im-own.log"); bytes in the file: $(wc -c < "$D/im-file.stm" | tr -d ' ')"
    fi
    # A link of the user's own that leads the image into a directory others can change.
    mkdir "$D/im-open"
    chmod 777 "$D/im-open"
    : > "$D/im-open/v.stm"
    ln -s "$D/im-open/v.stm" "$D/im-led.stm"
    "$B" mkfs "$D/im-led.stm" --size 64M < /dev/null > "$D/im-led.log" 2>&1; rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -qF "stratum-mkfs: image $D/im-led.stm is led by its links to the directory $D/im-open, which others can change, going by its mode" "$D/im-led.log" \
            && LC_ALL=C grep -qF "could remove the volume, or put an older copy of it back; name the image itself" "$D/im-led.log" \
            && [ ! -s "$D/im-open/v.stm" ] && [ ! -e "$D/im-led.stm.key" ]; then
        ok "a link that leads the image into a directory others can change is not followed, and no key is made"
    else
        no "a link that leads the image into a directory others can change: rc=$rc: $(tail -1 "$D/im-led.log"); bytes in the file: $(wc -c < "$D/im-open/v.stm" | tr -d ' ')"
    fi
    # A link at the image's name with a second name: any user may have given it either.
    : > "$D/im-two-file.stm"
    if ln -s "im-two-file.stm" "$D/im-first.lnk" && ln -P "$D/im-first.lnk" "$D/im-two.stm" 2> /dev/null && [ -L "$D/im-two.stm" ]; then
        "$B" mkfs "$D/im-two.stm" --size 64M < /dev/null > "$D/im-two.log" 2>&1; rc=$?
        if [ "$rc" != 0 ] && LC_ALL=C grep -qF "stratum-mkfs: image $D/im-two.stm is reached through a symlink that has another name besides this one" "$D/im-two.log" \
                && [ ! -s "$D/im-two-file.stm" ] && [ ! -e "$D/im-two.stm.key" ]; then
            ok "a link at the image's name that has a second name is not followed, and no key is made"
        else
            no "a link at the image's name that has a second name: rc=$rc: $(tail -1 "$D/im-two.log"); bytes in the file: $(wc -c < "$D/im-two-file.stm" | tr -d ' ')"
        fi
    else
        skipped "a link at the image's name with two names: none can be made here (ln -P gives a link no second name)"
    fi
    # The claim opens the name and then reads the links at it: the file it has open has to be
    # the one the links are read to end in. Here the name is an empty file of the user's own,
    # and just before the claim's look at it, which follows its open, a link of the user's own
    # takes its place, to another empty file. The link passes all that is asked of a link, and
    # nothing was asked of it when the file was opened: neither file is formatted.
    : > "$D/im-swap.stm"
    : > "$D/im-swap-to.stm"
    plant_run STM_PLANT_AT="$D/im-swap.stm" STM_PLANT_ON=look:1 STM_PLANT_TO="$D/im-swap-to.stm" STM_PLANT_OVER=over STM_PLANT_LOG="$D/im-swap.plant" \
        -- mkfs "$D/im-swap.stm" --size 64M < /dev/null > "$D/im-swap.log" 2>&1; rc=$?
    if [ "$rc" != 0 ] && [ "$(tr '\n' ' ' < "$D/im-swap.plant")" = "open:1 planted before look:1: done readlink:1 look:2 " ] \
            && LC_ALL=C grep -qF "stratum-mkfs: image $D/im-swap.stm does not lead where its links were read to end" "$D/im-swap.log" \
            && [ ! -s "$D/im-swap-to.stm" ] && [ -z "$(ls "$D" | LC_ALL=C grep -F 'im-swap.stm.over')" ] && [ ! -e "$D/im-swap.stm.key" ]; then
        ok "a link put at the image's name between the claim's open and its reading of the links is not followed, and nothing is formatted"
    else
        no "a link put at the image's name between the claim's open and its reading of the links: rc=$rc: $(tr '\n' ' ' < "$D/im-swap.plant" 2>/dev/null): $(tail -1 "$D/im-swap.log"); bytes where it leads: $(wc -c < "$D/im-swap-to.stm" | tr -d ' ')"
    fi
    # The format and the mount go through the descriptor the claim holds, so the volume is made
    # in the file that was asked about, wherever the name leads by then. Here the name is a
    # link of the user's own to an empty file of theirs, and once the volume is claimed another
    # link takes its place, to a second empty file: the file a format that opened the name
    # again would write. The library watches the key's name, whose fifth look comes after the
    # claim and before the format, and leaves the link at the image's. Nothing is written to
    # the second file, mkfs says the name leads elsewhere, and no key is left.
    : > "$D/im-a.stm"
    : > "$D/im-b.stm"
    ln -s "$D/im-a.stm" "$D/im-race.stm"
    plant_run STM_PLANT_AT="$D/im-race.stm.key" STM_PLANT_ON=look:5 STM_PLANT_LINK="$D/im-race.stm" STM_PLANT_TO="$D/im-b.stm" STM_PLANT_OVER=over \
        STM_PLANT_LOG="$D/im-race.plant" \
        -- mkfs "$D/im-race.stm" --size 64M < /dev/null > "$D/im-race.log" 2>&1; rc=$?
    if [ "$rc" = 2 ] && LC_ALL=C grep -q '^planted before look:5: done$' "$D/im-race.plant" \
            && LC_ALL=C grep -qF "stratum-mkfs: $D/im-race.stm does not lead to the file it led to when the volume was claimed" "$D/im-race.log" \
            && [ ! -s "$D/im-b.stm" ] && [ -s "$D/im-a.stm" ] && [ "$(readlink "$D/im-race.stm")" = "$D/im-b.stm" ] \
            && [ ! -e "$D/im-race.stm.key" ] && [ -z "$(ls "$D" | LC_ALL=C grep -F 'im-race.stm.key.new.')" ]; then
        ok "an image name led elsewhere once the volume was claimed: the file that was claimed is the one formatted, nothing is written where the name leads, and no key is left"
    else
        no "an image name led elsewhere once the volume was claimed: rc=$rc: $(tr '\n' ' ' < "$D/im-race.plant" 2>/dev/null): $(tail -1 "$D/im-race.log"); bytes where the name leads now: $(wc -c < "$D/im-b.stm" | tr -d ' '); in the file claimed: $(wc -c < "$D/im-a.stm" | tr -d ' '); key left: $(ls "$D" | LC_ALL=C grep -c 'im-race.stm.key')"
    fi
    # An image this run made is removed, should the run fail, through the directory it was made
    # in and never by its path: the path may lead to another file by then, and a removal by it
    # would take a file mkfs never made. Here the name is free, in a directory of the user's
    # own, and just before mkfs's last look at the name that directory is moved away and
    # another made at its path, holding a file of the user's under the image's name, as the
    # owner of a directory above it could do. mkfs says the name leads elsewhere, the file at
    # the name is as it was, and the image mkfs made and formatted is gone from the directory
    # that was moved, with the key it made. A name that was free is opened twice, the second
    # time to make it, and looked at once, last.
    mkdir "$D/im-dir"
    printf 'a file of the user that mkfs never made\n' > "$D/im-decoy"
    plant_run STM_PLANT_AT="$D/im-dir/vol.stm" STM_PLANT_ON=look:1 STM_PLANT_MOVE="$D/im-dir" STM_PLANT_PUT="$D/im-decoy" STM_PLANT_PUT_AT=vol.stm \
        STM_PLANT_LOG="$D/im-moved.plant" \
        -- mkfs "$D/im-dir/vol.stm" --size 64M --keyfile "$D/im-moved.key" < /dev/null > "$D/im-moved.log" 2>&1; rc=$?
    if [ "$rc" = 2 ] && [ "$(tr '\n' ' ' < "$D/im-moved.plant")" = "open:1 open:2 moved before look:1: done " ] \
            && LC_ALL=C grep -qF "stratum-mkfs: $D/im-dir/vol.stm does not lead to the file it led to when the volume was claimed" "$D/im-moved.log" \
            && cmp -s "$D/im-decoy" "$D/im-dir/vol.stm" && [ -z "$(ls -A "$D/im-dir.away")" ] \
            && [ ! -e "$D/im-moved.key" ] && [ -z "$(ls "$D" | LC_ALL=C grep -F 'im-moved.key.new.')" ]; then
        ok "a made image's directory moved away before the last look: the image mkfs made is removed from the directory it was made in, and the file now at its path is not touched"
    else
        no "a made image's directory moved away before the last look: rc=$rc: $(tr '\n' ' ' < "$D/im-moved.plant" 2>/dev/null): $(tail -1 "$D/im-moved.log"); at its path: $(ls -A "$D/im-dir" 2>/dev/null | tr '\n' ' '); in the directory moved: $(ls -A "$D/im-dir.away" 2>/dev/null | tr '\n' ' '); key left: $(ls "$D" | LC_ALL=C grep -c 'im-moved.key')"
    fi
    # The same where the name itself is taken over: a link of the user's own, to a file of
    # theirs, is put over the image mkfs made, just before the last look. The image has no
    # name left to be removed by, mkfs says so, and the link and the file it leads to are as
    # they were put.
    printf 'another file of the user that mkfs never made\n' > "$D/im-over-to"
    plant_run STM_PLANT_AT="$D/im-over.stm" STM_PLANT_ON=look:1 STM_PLANT_TO="$D/im-over-to" STM_PLANT_OVER=over STM_PLANT_LOG="$D/im-over.plant" \
        -- mkfs "$D/im-over.stm" --size 64M --keyfile "$D/im-over.key" < /dev/null > "$D/im-over.log" 2>&1; rc=$?
    if [ "$rc" = 2 ] && [ "$(tr '\n' ' ' < "$D/im-over.plant")" = "open:1 open:2 planted before look:1: done " ] \
            && LC_ALL=C grep -q '^stratum-mkfs: the image this run made has no name any more' "$D/im-over.log" \
            && [ "$(readlink "$D/im-over.stm")" = "$D/im-over-to" ] && [ "$(cat "$D/im-over-to")" = 'another file of the user that mkfs never made' ] \
            && [ ! -e "$D/im-over.key" ] && [ -z "$(ls "$D" | LC_ALL=C grep -F 'im-over.key.new.')" ]; then
        ok "a link put over a made image before the last look is not removed by the image's name, and mkfs says the image has no name left"
    else
        no "a link put over a made image before the last look: rc=$rc: $(tr '\n' ' ' < "$D/im-over.plant" 2>/dev/null): $(tail -1 "$D/im-over.log"); at the name: $(ls -l "$D/im-over.stm" 2>&1 | cut -c1-160); key left: $(ls "$D" | LC_ALL=C grep -c 'im-over.key')"
    fi
    # A daemon mounts through the descriptor its lock is on, so the image it serves is the one
    # it locked. Two volumes under one key, each holding a file that says which it is, and a
    # name that is a link to the first. A daemon started on the name locks the first; the link
    # is then put over with one to the second, just before the daemon's last look at the name,
    # which comes after the lock and before the mount. A mount that opened the name again would
    # serve the second with its lock on the first, and a second daemon could open either.
    # The daemon itself is what is put behind: a function put behind is a shell around it, and
    # a TERM to that shell would leave the daemon serving.
    sd_up() {
        rm -f "$D/sd.sock"
        (
            for set in "$@"; do export "$set"; done
            if [ "$(uname -s)" = Darwin ]; then export DYLD_INSERT_LIBRARIES="$PLANT_LIB"; else export LD_PRELOAD="$PLANT_LIB"; fi
            exec "$B" serve "$D/sd-name.stm" --listen "$D/sd.sock" --keyfile "$D/sd.key"
        ) < /dev/null > "$D/sd-serve.log" 2>&1 &
        SP=$!
        for _ in $(seq 1 100); do
            [ -S "$D/sd.sock" ] && return 0
            kill -0 "$SP" 2>/dev/null || return 1
            sleep 0.1
        done
        return 1
    }
    sd_down() {
        kill -TERM "$SP" 2>/dev/null
        wait "$SP" 2>/dev/null
        sd_rc=$?
        SP=
        rm -f "$D/sd.sock"
    }
    sd_made=1
    for which in a b; do
        rm -f "$D/sd-name.stm"
        "$B" mkfs "$D/sd-$which.stm" --size 64M --keyfile "$D/sd.key" < /dev/null > "$D/sd-mkfs-$which.log" 2>&1 \
            && ln -s "$D/sd-$which.stm" "$D/sd-name.stm" && sd_up STM_PLANT_LOG="$D/sd-mark-$which.plant" \
            && printf '%s\n' "$which" | "$B" fs -s "$D/sd.sock" write -n /which.txt > /dev/null 2>&1 || sd_made=0
        sd_down
    done
    rm -f "$D/sd-name.stm"
    ln -s "$D/sd-a.stm" "$D/sd-name.stm"
    sd_seen=
    if [ "$sd_made" = 1 ] && sd_up STM_PLANT_AT="$D/sd-name.stm" STM_PLANT_LOG="$D/sd-none.plant"; then
        sd_seen=$("$B" fs -s "$D/sd.sock" read /which.txt 2>/dev/null)
    fi
    sd_down
    # The daemon's looks at the name, as the library saw them with nothing left: the last is
    # the one to leave the link before, and an open of the name, the lock's, comes before it.
    sd_last=$(LC_ALL=C grep -n '^look:[0-9][0-9]*$' "$D/sd-none.plant" 2>/dev/null | tail -1)
    sd_open=$(LC_ALL=C grep -n '^open:1$' "$D/sd-none.plant" 2>/dev/null | head -1)
    if [ "$sd_seen" != a ] || [ -z "$sd_last" ] || [ -z "$sd_open" ] || [ "${sd_open%%:*}" -ge "${sd_last%%:*}" ]; then
        no "a daemon on a link to a volume, nothing left: made=$sd_made, served: '$sd_seen', its looks: $(tr '\n' ' ' < "$D/sd-none.plant" 2>/dev/null): $(tail -1 "$D/sd-serve.log")"
    else
        sd_seen=
        if sd_up STM_PLANT_AT="$D/sd-name.stm" STM_PLANT_ON="${sd_last#*:}" STM_PLANT_TO="$D/sd-b.stm" STM_PLANT_OVER=over STM_PLANT_LOG="$D/sd-led.plant"; then
            sd_seen=$("$B" fs -s "$D/sd.sock" read /which.txt 2>/dev/null)
        fi
        sd_down
        if [ "$sd_seen" = a ] && [ "$sd_rc" = 0 ] && LC_ALL=C grep -q "^planted before ${sd_last#*:}: done\$" "$D/sd-led.plant" \
                && [ "$(readlink "$D/sd-name.stm")" = "$D/sd-b.stm" ]; then
            ok "a daemon serves the image it locked, where its name was led to another between the lock and the mount"
        else
            no "a daemon whose image's name was led to another between the lock and the mount served '$sd_seen' (a is the one it locked): $(tr '\n' ' ' < "$D/sd-led.plant" 2>/dev/null): $(tail -1 "$D/sd-serve.log")"
        fi
    fi
    # The run that makes a corvus dataset and serves nothing mounts as the serving daemon does,
    # through the descriptor its lock is on. There is nothing to ask it which volume it has, so
    # the second volume here is under a key of its own, and which was mounted shows in how the
    # run fails: a volume under another key is refused at the mount, and past the mount the run
    # fails at the corvus daemon, which is not there. With the name led to the second volume
    # from the start the mount is refused. Led there between the lock and the mount, the mount
    # is of the first, the one that was locked, and the run gets past it.
    sd_prov() {
        sd_prov_log=$1; shift
        (
            for set in "$@"; do export "$set"; done
            if [ "$(uname -s)" = Darwin ]; then export DYLD_INSERT_LIBRARIES="$PLANT_LIB"; else export LD_PRELOAD="$PLANT_LIB"; fi
            exec "$B" serve "$D/sd-name.stm" --keyfile "$D/sd.key" --provision-corvus-dataset made --corvus-dataset-path /made \
                --corvus-socket "$D/sd-no-corvus.sock" --corvus-session-token-file "$D/sd-token"
        ) < /dev/null > "$sd_prov_log" 2>&1
    }
    past_the_mount() {
        LC_ALL=C grep -q "^stratumd: provisioning: create corvus dataset 'made' failed" "$1" \
            && ! LC_ALL=C grep -q '^stratumd: provisioning: mount of ' "$1"
    }
    printf '%033d' 0 > "$D/sd-token"
    chmod 600 "$D/sd-token"
    "$B" mkfs "$D/sd-c.stm" --size 64M --keyfile "$D/sd-c.key" < /dev/null > "$D/sd-mkfs-c.log" 2>&1; sd_c=$?
    rm -f "$D/sd-name.stm"
    ln -s "$D/sd-a.stm" "$D/sd-name.stm"
    sd_prov "$D/sd-prov-none.log" STM_PLANT_AT="$D/sd-name.stm" STM_PLANT_LOG="$D/sd-prov-none.plant"
    sdp_last=$(LC_ALL=C grep -n '^look:[0-9][0-9]*$' "$D/sd-prov-none.plant" 2>/dev/null | tail -1)
    sdp_open=$(LC_ALL=C grep -n '^open:1$' "$D/sd-prov-none.plant" 2>/dev/null | head -1)
    rm -f "$D/sd-name.stm"
    ln -s "$D/sd-c.stm" "$D/sd-name.stm"
    sd_prov "$D/sd-prov-c.log"
    rm -f "$D/sd-name.stm"
    ln -s "$D/sd-a.stm" "$D/sd-name.stm"
    if [ "$sd_made" != 1 ] || [ "$sd_c" != 0 ] || ! past_the_mount "$D/sd-prov-none.log" \
            || ! LC_ALL=C grep -q '^stratumd: provisioning: mount of ' "$D/sd-prov-c.log" \
            || [ -z "$sdp_last" ] || [ -z "$sdp_open" ] || [ "${sdp_open%%:*}" -ge "${sdp_last%%:*}" ]; then
        no "a provisioning run on a link to a volume, nothing left: made=$sd_made, the second volume: $sd_c, its looks: $(tr '\n' ' ' < "$D/sd-prov-none.plant" 2>/dev/null): on the first: $(tail -2 "$D/sd-prov-none.log" | head -1); on the second: $(tail -2 "$D/sd-prov-c.log" | head -1)"
    else
        sd_prov "$D/sd-prov-led.log" STM_PLANT_AT="$D/sd-name.stm" STM_PLANT_ON="${sdp_last#*:}" STM_PLANT_TO="$D/sd-c.stm" STM_PLANT_OVER=over STM_PLANT_LOG="$D/sd-prov-led.plant"
        if past_the_mount "$D/sd-prov-led.log" && LC_ALL=C grep -q "^planted before ${sdp_last#*:}: done\$" "$D/sd-prov-led.plant" \
                && [ "$(readlink "$D/sd-name.stm")" = "$D/sd-c.stm" ]; then
            ok "a provisioning run mounts the image it locked, where its name was led to another between the lock and the mount"
        else
            no "a provisioning run whose image's name was led to another between the lock and the mount: $(tr '\n' ' ' < "$D/sd-prov-led.plant" 2>/dev/null): $(tail -2 "$D/sd-prov-led.log" | head -1)"
        fi
    fi
fi

# A link that cannot be read cannot be asked where it leads, and the kernel follows it all the
# same. Only a system that keeps a mode on a link can make one: macOS does, Linux does not.
ln -s "$D/raw.stm.key" "$D/unread.key"
if chmod -h 000 "$D/unread.key" 2> /dev/null && ! readlink "$D/unread.key" > /dev/null 2>&1; then
    "$B" mkfs "$D/unread.stm" --size 64M --keyfile "$D/unread.key" < /dev/null > "$D/unread.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q 'is reached through a link that cannot be read' "$D/unread.log" && [ ! -e "$D/unread.stm" ]; then
        ok "a link at the key's name that cannot be read is refused, and nothing is made"
    else
        no "a link at the key's name that cannot be read: rc=$rc: $(tail -1 "$D/unread.log"); image left: $([ -e "$D/unread.stm" ] && echo yes || echo no)"
    fi
    # Forced, nobody is asked. With no key to make, the name is only opened, and the kernel
    # follows the link, mode or no mode: the key behind it is used. A new key is not sent
    # through a link whose text cannot be read: it takes the link's place.
    "$B" mkfs "$D/unread-f.stm" --size 64M --force --keyfile "$D/unread.key" < /dev/null > "$D/unread-f.log" 2>&1
    rc=$?
    if [ "$rc" = 0 ] && LC_ALL=C grep -q 'using existing keyfile' "$D/unread-f.log" && [ -s "$D/unread-f.stm" ] && [ -L "$D/unread.key" ]; then
        ok "with --force the key behind a link that cannot be read is used, and the link stays"
    else
        no "with --force, a key behind a link that cannot be read: rc=$rc: $(tail -1 "$D/unread-f.log")"
    fi
    behind=$(cksum < "$D/raw.stm.key")
    printf '%s\n' "$PASS" | "$B" mkfs "$D/unread-p.stm" --size 64M --force --passphrase-stdin --keyfile "$D/unread.key" > "$D/unread-p.log" 2>&1
    rc=$?
    if [ "$rc" = 0 ] && [ ! -L "$D/unread.key" ] && [ -f "$D/unread.key" ] && [ "$(cksum < "$D/raw.stm.key")" = "$behind" ] \
            && LC_ALL=C grep -q '^generated encrypted keyfile' "$D/unread-p.log"; then
        ok "with --force a new key takes the place of a link that cannot be read, and the key behind it stays as it was"
    else
        no "with --force and a passphrase, a link that cannot be read: rc=$rc: $(tail -1 "$D/unread-p.log"); still a link: $([ -L "$D/unread.key" ] && echo yes || echo no)"
    fi
else
    echo "note: a link that cannot be read: none can be made here (a link keeps no mode, or this user reads it all the same), so there is nothing to check"
fi

# A link with two names. Its owner is the user, and whoever gave it its second name need not
# be: where nothing forbids it, any user can give a link of the user's or root's a name of
# their choosing, and its text would lead the key from there. So it is not followed. With one
# name again, the same link is: the control.
if ! "$B" mkfs "$D/two-own.stm" --size 64M --keyfile "$D/two-own.key" < /dev/null > "$D/two-own.log" 2>&1; then
    no "a key of the user's own for the link with two names: $(tail -1 "$D/two-own.log")"
elif ln -s "two-own.key" "$D/two-first.lnk" && ln -P "$D/two-first.lnk" "$D/two.key" 2> /dev/null && [ -L "$D/two.key" ]; then
    "$B" mkfs "$D/two.stm" --size 64M --keyfile "$D/two.key" < /dev/null > "$D/two.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q 'is reached through a symlink that has another name besides this one' "$D/two.log" && [ ! -e "$D/two.stm" ]; then
        ok "a link at the key's name that has a second name is refused, and nothing is made"
    else
        no "a link at the key's name that has a second name: rc=$rc: $(tail -1 "$D/two.log"); image left: $([ -e "$D/two.stm" ] && echo yes || echo no)"
    fi
    rm "$D/two-first.lnk"
    if "$B" mkfs "$D/two.stm" --size 64M --keyfile "$D/two.key" < /dev/null > "$D/two-one.log" 2>&1 \
            && LC_ALL=C grep -q 'using existing keyfile' "$D/two-one.log" && [ -s "$D/two.stm" ]; then
        ok "the same link with one name again is followed"
    else
        no "the same link with one name again: $(tail -1 "$D/two-one.log")"
    fi
else
    skipped "a link with two names: none can be made here (ln -P gives a link no second name)"
fi

# Where the links lead. A link of the user's own is followed, and where it leads the key out
# of the directory it was named in, the directory it leads to is asked about: a link of the
# user's or root's that once had a second name can be put anywhere by whoever gave it that
# name, and nothing in the link tells. One others can change is refused, for a new key and
# for one that is there, with --key-as-is too. The user's own with nobody else let to write,
# and a sticky one, where others add names and take none away, are followed (the controls),
# and so is a link that keeps the key in the directory it was named in, whatever that
# directory's mode, since the user chose it. --force follows any.
mkdir "$D/led-open" "$D/led-own" "$D/led-sticky" "$D/led-same"
chmod 777 "$D/led-open" "$D/led-same"; chmod 755 "$D/led-own"; chmod 1777 "$D/led-sticky"
ln -s "led-open/k.key" "$D/led-open.key"
"$B" mkfs "$D/led-open.stm" --size 64M --keyfile "$D/led-open.key" < /dev/null > "$D/led-open.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -qF "stratum-mkfs: keyfile $D/led-open.key is led by its links to the directory $D/led-open, which others can change, going by its mode" "$D/led-open.log" \
        && [ ! -e "$D/led-open.stm" ] && [ -z "$(ls -A "$D/led-open")" ]; then
    ok "a key link that leads into a directory others can change is refused before anything is made"
else
    no "a key link into a directory others can change: rc=$rc: $(tail -1 "$D/led-open.log"); image left: $([ -e "$D/led-open.stm" ] && echo yes || echo no); in the directory: $(ls -A "$D/led-open" | tr '\n' ' ')"
fi
printf '%s\n' "$PASS" | "$B" mkfs "$D/led-open-p.stm" --size 64M --passphrase-stdin --keyfile "$D/led-open.key" > "$D/led-open-p.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -qF "is led by its links to the directory $D/led-open, which others can change" "$D/led-open-p.log" \
        && [ ! -e "$D/led-open-p.stm" ] && [ -z "$(ls -A "$D/led-open")" ]; then
    ok "the same with a passphrase"
else
    no "a key link into a directory others can change, with a passphrase: rc=$rc: $(tail -1 "$D/led-open-p.log")"
fi
for kind in own sticky; do
    ln -s "led-$kind/k.key" "$D/led-$kind.key"
    if "$B" mkfs "$D/led-$kind.stm" --size 64M --keyfile "$D/led-$kind.key" < /dev/null > "$D/led-$kind.log" 2>&1 \
            && [ -f "$D/led-$kind/k.key" ] && [ -L "$D/led-$kind.key" ] && LC_ALL=C grep -q '^generated keyfile' "$D/led-$kind.log"; then
        ok "a key link that leads into a directory of the user's that is $( [ $kind = own ] && echo "nobody else's to write" || echo sticky ) is followed"
    else
        no "a key link into the user's $kind directory: $(tail -1 "$D/led-$kind.log")"
    fi
done
ln -s "k2.key" "$D/led-same/k.key"
if "$B" mkfs "$D/led-same.stm" --size 64M --keyfile "$D/led-same/k.key" < /dev/null > "$D/led-same.log" 2>&1 \
        && [ -f "$D/led-same/k2.key" ] && [ -L "$D/led-same/k.key" ]; then
    ok "a key link that keeps the key in the directory it was named in is followed, whatever that directory's mode"
else
    no "a key link that keeps the key in its directory: $(tail -1 "$D/led-same.log")"
fi
cp "$D/led-own/k.key" "$D/led-open/have.key"
chmod 600 "$D/led-open/have.key"
ln -s "led-open/have.key" "$D/led-have.key"
"$B" mkfs "$D/led-have.stm" --size 64M --keyfile "$D/led-have.key" < /dev/null > "$D/led-have.log" 2>&1
rc=$?
"$B" mkfs "$D/led-have-as.stm" --size 64M --key-as-is --keyfile "$D/led-have.key" < /dev/null > "$D/led-have-as.log" 2>&1
rc2=$?
if [ "$rc" != 0 ] && [ "$rc2" != 0 ] && [ ! -e "$D/led-have.stm" ] && [ ! -e "$D/led-have-as.stm" ] \
        && LC_ALL=C grep -qF "is led by its links to the directory $D/led-open, which others can change" "$D/led-have.log" \
        && LC_ALL=C grep -qF "is led by its links to the directory $D/led-open, which others can change" "$D/led-have-as.log"; then
    ok "a key that is there, reached through a link into a directory others can change, is not used, with --key-as-is neither"
else
    no "a key reached through a link into a directory others can change: rc=$rc and, with --key-as-is, $rc2: $(tail -1 "$D/led-have.log") / $(tail -1 "$D/led-have-as.log")"
fi
rm "$D/led-open/have.key"
# A directory the user may write and search but not read still takes a new key: its
# descriptor is then one for the search alone. Root reads any directory, so run as root this
# shows only that the key is made.
mkdir "$D/led-wx"
chmod 300 "$D/led-wx"
"$B" mkfs "$D/led-wx.stm" --size 64M --keyfile "$D/led-wx/k.key" < /dev/null > "$D/led-wx.log" 2>&1
rc=$?
chmod 700 "$D/led-wx"
if [ "$rc" = 0 ] && [ -f "$D/led-wx/k.key" ] && [ -s "$D/led-wx.stm" ] && LC_ALL=C grep -q '^generated keyfile' "$D/led-wx.log"; then
    ok "a new key is made in a directory the user can write and search but not read"
else
    no "a new key in a directory that cannot be read: rc=$rc: $(tail -1 "$D/led-wx.log")"
fi
if "$B" mkfs "$D/led-open-f.stm" --size 64M --force --keyfile "$D/led-open.key" < /dev/null > "$D/led-open-f.log" 2>&1 \
        && [ -f "$D/led-open/k.key" ] && [ -s "$D/led-open-f.stm" ]; then
    ok "with --force the link into a directory others can change is followed"
else
    no "with --force, a key link into a directory others can change: $(tail -1 "$D/led-open-f.log")"
fi

# The links at the key's name are asked about one by one, seven at most. More than that are refused, not
# left for a stat to follow unasked: eight of the user's own, to a key of the user's own, and seven, the
# control, which are followed.
ln -s "$D/raw.stm.key" "$D/hop8"
for i in 7 6 5 4 3 2 1; do ln -s "$D/hop$((i + 1))" "$D/hop$i"; done
"$B" mkfs "$D/chained.stm" --size 64M --keyfile "$D/hop1" < /dev/null > "$D/chained.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && LC_ALL=C grep -q '^stratum-mkfs: keyfile .* is reached through more than seven links' "$D/chained.log" && [ ! -e "$D/chained.stm" ]; then
    ok "a key behind eight links is refused before anything is made, and says why"
else
    no "a key behind eight links: rc=$rc: $(tail -1 "$D/chained.log"); image left: $([ -e "$D/chained.stm" ] && echo yes || echo no)"
fi
if "$B" mkfs "$D/chained7.stm" --size 64M --keyfile "$D/hop2" < /dev/null > "$D/chained7.log" 2>&1 && [ -s "$D/chained7.stm" ]; then
    ok "a key behind seven links of the user's own is used"
else
    no "a key behind seven links of the user's own: $(tail -1 "$D/chained7.log")"
fi
# A link another user owns does not decide where the key goes: in a shared sticky directory whoever left
# it would hold the key, which the kernel's protected_symlinks keeps from a path it follows itself, and
# mkfs reads the links itself. Refused with a passphrase and without; --force, the control, follows it,
# as a link of the user's own is followed (below). Only root or sudo can give a link another owner, and
# sudo is tried only when STRATUM_TEST_SUDO=1 asks for it: where the user is not in sudoers even a try
# is logged as an incident.
if [ "$(id -u)" = 0 ]; then as=""
elif [ "${STRATUM_TEST_SUDO:-0}" != 1 ]; then as=none
elif sudo -n true 2>/dev/null; then as="sudo -n"
else
    # Asked for and not to be had is a failure, not a skip: a gate that sets it means these to run.
    no "STRATUM_TEST_SUDO=1 asks for sudo without a password, and there is none"
    as=none
fi
if [ "$as" = none ]; then
    skipped "another user's key link, key, image file and directory: making one needs root, or STRATUM_TEST_SUDO=1 and sudo without a password"
else
    # A key another user owns is theirs, whatever its mode: with no passphrase it is not used.
    # Read by no one else, only its owner tells it from the user's own. As root the same is seen
    # from the other side below: a key that is not root's.
    cp "$D/raw.stm.key" "$D/theirs.key"
    chmod 600 "$D/theirs.key"
    $as chown nobody "$D/theirs.key"
    if [ "$(stat -c %u "$D/theirs.key" 2>/dev/null || stat -f %u "$D/theirs.key")" = "$(id -u)" ]; then
        no "theirs.key is still the user's: it proves nothing"
    fi
    "$B" mkfs "$D/owned.stm" --size 64M --keyfile "$D/theirs.key" < /dev/null > "$D/owned.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q '^stratum-mkfs: keyfile .* belongs to another user' "$D/owned.log" && [ ! -e "$D/owned.stm" ]; then
        ok "a key another user owns is refused before anything is made, and says why"
    else
        no "a key another user owns: rc=$rc: $(tail -1 "$D/owned.log"); image left: $([ -e "$D/owned.stm" ] && echo yes || echo no)"
    fi
    # Its owner is what --key-as-is is told to pass over, where the key can be read at all.
    cp "$D/raw.stm.key" "$D/theirs-read.key"
    chmod 644 "$D/theirs-read.key"
    $as chown nobody "$D/theirs-read.key"
    if [ "$(stat -c %u "$D/theirs-read.key" 2>/dev/null || stat -f %u "$D/theirs-read.key")" = "$(id -u)" ]; then
        no "theirs-read.key is still the user's: it proves nothing"
    fi
    if "$B" mkfs "$D/owned-asis.stm" --size 64M --key-as-is --keyfile "$D/theirs-read.key" < /dev/null > "$D/owned-asis.log" 2>&1 \
            && LC_ALL=C grep -q 'using existing keyfile' "$D/owned-asis.log" && [ -s "$D/owned-asis.stm" ]; then
        ok "with --key-as-is a key another user owns, which the user can read, is used"
    else
        no "--key-as-is over a key another user owns: $(tail -1 "$D/owned-asis.log")"
    fi
    if [ -n "$as" ]; then
        # Root can read any key, so there the owner is the only thing between it and the volume.
        $as "$B" mkfs "$D/rooted.stm" --size 64M --keyfile "$D/raw.stm.key" < /dev/null > "$D/rooted.log" 2>&1
        rc=$?
        if [ "$rc" != 0 ] && LC_ALL=C grep -q '^stratum-mkfs: keyfile .* belongs to another user' "$D/rooted.log" && [ ! -e "$D/rooted.stm" ]; then
            ok "as root, a key the user owns is refused before anything is made, and says why"
        else
            no "as root, a key the user owns: rc=$rc: $(tail -1 "$D/rooted.log"); image left: $([ -e "$D/rooted.stm" ] && echo yes || echo no)"
        fi
    fi
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
        if [ "$rc" != 0 ] && LC_ALL=C grep -q 'reached through a symlink another user owns' "$D/planted.log"; then
            ok "a key name that is another user's link is refused $how, and says why"
        else
            no "a key name that is another user's link $how: rc=$rc: $(tail -1 "$D/planted.log")"
        fi
        [ -z "$(ls -A "$D/theirs")" ] && [ ! -e "$D/planted.stm" ] && ok "that refusal $how made no key and no image" \
            || no "a refused key link $how left: $(ls -A "$D/theirs" | tr '\n' ' ')$(ls "$D/planted.stm" 2>/dev/null)"
    done
    # --key-as-is is about a key that is there, not about whose link leads to one.
    "$B" mkfs "$D/planted.stm" --size 64M --key-as-is < /dev/null > "$D/planted.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -q 'reached through a symlink another user owns' "$D/planted.log" \
            && [ -z "$(ls -A "$D/theirs")" ] && [ ! -e "$D/planted.stm" ]; then
        ok "--key-as-is does not follow another user's link, and makes nothing"
    else
        no "--key-as-is and another user's key link: rc=$rc: $(tail -1 "$D/planted.log"); left: $(ls -A "$D/theirs" | tr '\n' ' ')$(ls "$D/planted.stm" 2>/dev/null)"
    fi
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
        if [ "$rc" != 0 ] && LC_ALL=C grep -q 'reached through a symlink another user owns' "$D/reuse.log" && [ ! -e "$D/reuse.stm" ]; then
            ok "another user's link to an existing key is refused $how, before anything is made"
        else
            no "another user's link to an existing key $how: rc=$rc: $(tail -1 "$D/reuse.log"); image: $(ls "$D/reuse.stm" 2>/dev/null)"
        fi
    done
    # An empty file another user owns, left at the image's free name where anyone may write it:
    # its owner could remove the volume, so it is not formatted into. Run as root this is the
    # same from the other side, a file that is not root's.
    : > "$D/theirs.stm"
    chmod 666 "$D/theirs.stm"
    $as chown nobody "$D/theirs.stm"
    "$B" mkfs "$D/theirs.stm" --size 64M < /dev/null > "$D/theirs-img.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -qF "stratum-mkfs: $D/theirs.stm belongs to another user, who could remove the volume" "$D/theirs-img.log" \
            && [ ! -s "$D/theirs.stm" ] && [ ! -e "$D/theirs.stm.key" ]; then
        ok "another user's empty file at the image's name is not formatted into, and no key is made"
    else
        no "another user's empty file at the image's name: rc=$rc: $(tail -1 "$D/theirs-img.log"); bytes in it: $(wc -c < "$D/theirs.stm" | tr -d ' ')"
    fi
    # A link of the user's own that leads the key into another user's directory: whoever owns
    # the directory could remove the key, whatever its mode says of others.
    mkdir "$D/led-theirs"
    chmod 755 "$D/led-theirs"
    $as chown nobody "$D/led-theirs"
    ln -s "led-theirs/k.key" "$D/led-theirs.key"
    "$B" mkfs "$D/led-theirs.stm" --size 64M --keyfile "$D/led-theirs.key" < /dev/null > "$D/led-theirs.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] && LC_ALL=C grep -qF "is led by its links to the directory $D/led-theirs, which belongs to another user" "$D/led-theirs.log" \
            && [ ! -e "$D/led-theirs.stm" ]; then
        ok "a key link that leads into another user's directory is refused before anything is made"
    else
        no "a key link into another user's directory: rc=$rc: $(tail -1 "$D/led-theirs.log"); image left: $([ -e "$D/led-theirs.stm" ] && echo yes || echo no)"
    fi
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
    # Only a failure past the claim is the late one: a refusal at the claim leaves the same behind.
    LC_ALL=C grep -q 'could not be loaded as a key' "$D/late.log" \
        || no "the bad key was not refused where it is loaded: $(tail -1 "$D/late.log")"
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

[ "$SKIPPED" = 0 ] || echo "skipped: $SKIPPED group(s) of checks this run could not make (each a \"note: skipped:\" line above)"
exit $BAD
