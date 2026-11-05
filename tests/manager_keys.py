#!/usr/bin/env python3
"""The manager through a real terminal: keys in, screen out, bytes checked outside the manager.

tools/stratum's own tests go through `stratum fs`, so nothing else presses F5. This is what an operator
does with an encrypted volume: unlock it, copy in, copy out, make and delete a directory, quit, and find
the same bytes after a remount.

    tests/manager_keys.py path/to/stratum [--show]

--show prints the screen after each step. On a failure the screen is printed regardless.
KEYS_ONLY=leg,leg runs only those legs, each of which takes (stratum, root).
"""
import codecs
import fcntl
import os
import pty
import re
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time

COLS, ROWS = 140, 44
F4, F5, F7, F10 = b'\x1bOS', b'\x1b[15~', b'\x1b[18~', b'\x1b[21~'
F8, F9 = b'\x1b[19~', b'\x1b[20~'
SHIFT_F5, SHIFT_F7 = b'\x1b[15;2~', b'\x1b[18;2~'
RIGHT, LEFT = b'\x1b[C', b'\x1b[D'
TAB, DOWN, UP, ENTER, ESC = b'\t', b'\x1b[B', b'\x1b[A', b'\r', b'\x1b'
PASS = 'correct horse battery staple'
CSI = re.compile(r'\x1b\[([?0-9;<=>]*)[ -/]*([@-~])')
OSC = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')

SHOW = False
FAILED = []


class Failure(Exception):
    pass


class Screen:
    """Just enough of a terminal for ratatui: moves, clears and text. Attributes are dropped."""

    def __init__(self):
        self.cells = [[' '] * COLS for _ in range(ROWS)]
        self.r = self.c = 0
        self.pending = ''
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')

    def put(self, ch):
        if self.c >= COLS:
            self.c = 0
            self.r = min(self.r + 1, ROWS - 1)
        self.cells[self.r][self.c] = ch
        self.c += 1

    def csi(self, params, final):
        nums = [int(p) if p.isdigit() else 0 for p in params.lstrip('?').split(';')] if params else []
        first = nums[0] if nums else 0
        if final in 'Hf':
            self.r = min(max((nums[0] if nums else 1) - 1, 0), ROWS - 1)
            self.c = min(max((nums[1] if len(nums) > 1 else 1) - 1, 0), COLS - 1)
        elif final == 'J':
            if first == 2 or first == 3:
                self.cells = [[' '] * COLS for _ in range(ROWS)]
            elif first == 0:
                self.cells[self.r][self.c:] = [' '] * (COLS - self.c)
                for r in range(self.r + 1, ROWS):
                    self.cells[r] = [' '] * COLS
        elif final == 'K':
            if first == 0:
                self.cells[self.r][self.c:] = [' '] * (COLS - self.c)
            elif first == 2:
                self.cells[self.r] = [' '] * COLS
        elif final == 'A':
            self.r = max(self.r - max(first, 1), 0)
        elif final == 'B':
            self.r = min(self.r + max(first, 1), ROWS - 1)
        elif final == 'C':
            self.c = min(self.c + max(first, 1), COLS - 1)
        elif final == 'D':
            self.c = max(self.c - max(first, 1), 0)
        elif final == 'G':
            self.c = min(max(first - 1, 0), COLS - 1)

    def feed(self, data):
        s = self.pending + self.decoder.decode(data)
        self.pending = ''
        i = 0
        while i < len(s):
            ch = s[i]
            if ch == '\x1b':
                m = CSI.match(s, i)
                if m:
                    self.csi(m.group(1), m.group(2))
                    i = m.end()
                    continue
                m = OSC.match(s, i)
                if m:
                    i = m.end()
                    continue
                if i + 2 >= len(s):
                    self.pending = s[i:]
                    return
                if s[i + 1] == '[' or s[i + 1] == ']':
                    self.pending = s[i:]
                    return
                i += 3 if s[i + 1] in '()' else 2
                continue
            if ch == '\r':
                self.c = 0
            elif ch == '\n':
                self.r = min(self.r + 1, ROWS - 1)
            elif ch == '\b':
                self.c = max(self.c - 1, 0)
            elif ch >= ' ':
                self.put(ch)
            i += 1

    def text(self):
        return '\n'.join(''.join(row).rstrip() for row in self.cells)


class Term:
    def __init__(self, argv):
        self.screen = Screen()
        self.rc = None
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            # What a login terminal gives a program. A harness started with `&` or nohup
            # ignores INT, QUIT and HUP, and the manager keeps an ignore it inherits.
            for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGHUP):
                signal.signal(sig, signal.SIG_DFL)
            os.environ['TERM'] = 'xterm-256color'
            os.execv(argv[0], argv)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLS, 0, 0))

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            ready, _, _ = select.select([self.fd], [], [], min(left, 0.1))
            if ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    data = b''
                if not data:
                    return
                self.screen.feed(data)

    def send(self, keys):
        os.write(self.fd, keys)

    def expect(self, pattern, timeout=30):
        end = time.monotonic() + timeout
        rx = re.compile(pattern)
        while time.monotonic() < end:
            self.pump(0.1)
            if rx.search(self.screen.text()):
                return
        raise Failure(f'the screen never showed {pattern!r} in {timeout} s')

    def exited(self, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.pump(0.1)
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.rc = os.waitstatus_to_exitcode(status)
                return True
        return False

    def kill(self):
        if self.rc is None:
            # TERM first: the manager stops its daemons on it, and a KILL strands them.
            try:
                os.kill(self.pid, signal.SIGTERM)
                if not self.exited(15):
                    os.kill(self.pid, signal.SIGKILL)
                    os.waitpid(self.pid, 0)
            except (OSError, ChildProcessError):
                pass
            self.rc = -9
        # A manager that strands its daemons fails its own leg. Here it must not also fail the next
        # leg, which needs the volume these still hold.
        session = f'stratum-{self.pid}/'
        for pid in daemons_of(session):
            os.kill(int(pid), signal.SIGTERM)
        end = time.monotonic() + 30
        while daemons_of(session) and time.monotonic() < end:
            time.sleep(0.2)

    def show(self, label):
        if SHOW:
            print(f'--- {label}\n{self.screen.text()}\n---', flush=True)


def shows(segment, name):
    """name as a whole cell, after its kind icon (ui.rs: '/' a directory, '@' a link):
    vol.stm is not vol.stm.key."""
    return re.search(r'(?:^|\s)[/@]?' + re.escape(name) + r'(?:\s|$)', segment) is not None


def row_in_left_panel(term, name):
    for r, line in enumerate(term.screen.text().split('\n')):
        if shows(line[:COLS // 2], name):
            return r
    raise Failure(f'{name} is not in the left panel')


def first_entry_row(term, names):
    """The topmost row holding any of names: a listing need not hold them all."""
    rows = []
    for name in names:
        try:
            rows.append(row_in_left_panel(term, name))
        except Failure:
            pass
    if not rows:
        raise Failure(f'none of {names} is in the left panel')
    return min(rows)


# Every checking daemon, since a leg can fail while one is running and it has no lifeline.
SERVED = []


class Volume:
    def __init__(self, stratum, root):
        self.b, self.v, self.sock, self.proc = stratum, f'{root}/vol.stm', f'{root}/check.sock', None

    def mkfs(self):
        subprocess.run([self.b, 'mkfs', self.v, '--size', '256M', '--passphrase-stdin'], input=PASS + '\n',
                       text=True, check=True, capture_output=True)

    def serve(self):
        if os.path.exists(self.sock):
            os.unlink(self.sock)
        self.proc = subprocess.Popen([self.b, 'serve', self.v, '--listen', self.sock, '--keyfile', self.v + '.key', '--passphrase-stdin'],
                                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     text=True)
        SERVED.append(self.proc)
        self.proc.stdin.write(PASS + '\n')
        self.proc.stdin.close()
        end = time.monotonic() + 30
        while not os.path.exists(self.sock):
            if self.proc.poll() is not None or time.monotonic() > end:
                raise Failure(f'the checking daemon did not come up, rc={self.proc.poll()}')
            time.sleep(0.05)

    def stop(self):
        self.proc.terminate()
        if self.proc.wait(timeout=60) != 0:
            raise Failure(f'the checking daemon exited {self.proc.returncode}')

    def fs(self, sock, *args, data=None):
        return subprocess.run([self.b, 'fs', '-s', sock, *args], input=data, capture_output=True, timeout=120)


def same(volume, sock, p9, host):
    got = volume.fs(sock, 'read', p9)
    with open(host, 'rb') as f:
        want = f.read()
    return got.returncode == 0 and got.stdout == want


def wait_same(volume, sock, p9, host, what, timeout=60):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if same(volume, sock, p9, host):
            print(f'ok: {what}', flush=True)
            return
        time.sleep(0.2)
    raise Failure(f'{what}: the volume never held the same bytes at {p9}')


# passphrase.rs: the first four bytes of a keyfile sealed under a passphrase, little-endian.
KEYFILE_SEALED = 0x31504650

# The panels' column heading, which the editor never draws.
IN_PANEL = r'Modified\s+Size'


def read_env(path):
    """The manager writes this file for a shell to source, so its values are quoted."""
    with open(path) as f:
        pairs = (line.strip().split('=', 1) for line in f if '=' in line)
        return {k: shlex.split(v)[0] for k, v in pairs}


def goto(term, cursor_row, name):
    """Move the left panel's cursor to name. The caller knows where the cursor is."""
    row = row_in_left_panel(term, name)
    key = DOWN if row > cursor_row else UP
    for _ in range(abs(row - cursor_row)):
        term.send(key)
        term.pump(0.1)
    return row


def admin_legs(term, vol, sock):
    """The /ctl admin path, on the daemon the manager itself started. Nothing else exercises these arguments."""
    ctl = os.path.join(os.path.dirname(sock), 'stratumd-ctl.sock')
    term.send(F9)
    term.expect(r'press N to create', timeout=15)
    term.send(b'n')
    term.expect(r'Snapshot name')
    term.send(ENTER)
    term.expect(r'Snapshot created|exit -?\d+', timeout=60)
    term.show('after F9, N, Enter')
    said = 'Snapshot created' in term.screen.text()
    listed = vol.fs(ctl, 'ls', '/datasets/1/snapshots').stdout.strip()
    record(said and listed, 'F9 N made a snapshot, and said so', f'F9 N: reported success={said}, the daemon lists {listed[:60]!r}')
    term.send(ENTER)
    term.pump(0.5)
    term.send(ESC)
    term.pump(0.5)

    term.send(SHIFT_F5)
    term.expect(r'Integrity', timeout=15)
    term.pump(2.0)
    # The pane opens with the menu focused, and its keys go to the content.
    term.send(TAB)
    term.pump(0.3)
    term.send(F8)
    term.expect(r'Start a pool scrub|not attached', timeout=15)
    term.show('Integrity, after F8')
    term.send(RIGHT)
    term.pump(0.2)
    term.send(ENTER)
    term.expect(r'Scrub start: queued|exit -?\d+|not attached', timeout=30)
    term.show('after the scrub request')
    record('Scrub start: queued' in term.screen.text(), 'the scrub request was accepted', 'the scrub request was refused')
    term.send(ENTER)
    term.pump(0.5)
    term.send(ESC)
    term.pump(0.5)


def daemons_of(session):
    return subprocess.run(['pgrep', '-f', session], capture_output=True, text=True).stdout.split()


def death_legs(stratum, vol, host, root):
    """However the manager ends, the volume must not stay unlocked behind it."""
    ends = (('SIGTERM', lambda t: os.kill(t.pid, signal.SIGTERM)),
            ('SIGINT', lambda t: os.kill(t.pid, signal.SIGINT)),
            ('SIGKILL', lambda t: os.kill(t.pid, signal.SIGKILL)),
            ('its terminal closing', lambda t: os.close(t.fd)))
    for i, (how, end) in enumerate(ends):
        env_file = f'{root}/env-death{i}'
        term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file])
        closed = False
        try:
            term.expect(r'Passphrase for')
            term.send(PASS.encode() + ENTER)
            term.expect(r'from_vol\.txt', timeout=60)
            session = os.path.dirname(read_env(env_file)['STRATUMD_SOCK'])
            # The control: the same search finds them while the manager lives.
            before = daemons_of(session)
            if len(before) < 3:
                raise Failure(f'the search finds {before} before {how}: it proves nothing')
            end(term)
            closed = how == 'its terminal closing'
            limit = time.monotonic() + 30
            left = before
            while left and time.monotonic() < limit:
                time.sleep(0.2)
                left = daemons_of(session)
            record(not left, f'{how}: the daemons stopped and the volume locked',
                   f'{how}: daemons {left} still serve the volume, unlocked, with no manager')
            if how in ('SIGTERM', 'SIGINT'):
                ended = term.exited(15)
                record(ended and term.rc == 0, f'{how}: the manager ended cleanly', f'{how}: the manager ended={ended} rc={term.rc}')
                cooked = termios.tcgetattr(term.fd)[3] & termios.ICANON
                record(cooked, f'{how}: the terminal is out of raw mode', f'{how}: the terminal was left raw')
            if closed:
                end_at = time.monotonic() + 15
                gone = False
                while not gone and time.monotonic() < end_at:
                    gone = os.waitpid(term.pid, os.WNOHANG)[0] != 0
                    time.sleep(0.1)
                record(gone, 'its terminal closing: the manager ended', 'its terminal closing: the manager still runs, with no terminal')
                if not gone:
                    os.kill(term.pid, signal.SIGKILL)
                    os.waitpid(term.pid, 0)
            if how != 'SIGKILL':
                record(not os.path.exists(session), f'{how}: the session directory is gone', f'{how}: the session directory stayed')
            for pid in left:
                os.kill(int(pid), signal.SIGTERM)
            limit = time.monotonic() + 30
            while daemons_of(session) and time.monotonic() < limit:
                time.sleep(0.2)
            vol.serve()
            vol.stop()
            print(f'ok: after {how} the volume mounts and unmounts cleanly', flush=True)
        finally:
            if not closed:
                term.kill()


def save_in_editor(term, vol, sock, path, want, what):
    """Save and quit, then read the file outside the manager. A refused save quits without it, so the next leg runs."""
    term.send(b':wq' + ENTER)
    try:
        term.expect(IN_PANEL, timeout=30)
        closed = True
    except Failure:
        closed = False
        term.show(f'no panel after saving {what}')
        if term.exited(1):
            raise Failure(f'saving {what} ended the manager, exit {term.rc}, and the edit with it')
        # Apart: a key straight after Escape reads as that key with Alt held.
        term.send(ESC)
        term.pump(0.3)
        term.send(b':q!' + ENTER)
        term.expect(IN_PANEL, timeout=15)
    got = vol.fs(sock, 'read', path).stdout
    record(closed and got == want, f'the editor saved {what}',
           f'saving {what}: {len(want)} bytes wanted, the file holds {len(got)}, the editor closed={closed}')
    term.show(f'after saving {what}')


def editor_legs(stratum, vol, host, env_file):
    """Save through the manager's editor, and read the bytes back outside it."""
    # Over the 64 KiB a single client write carries, so a save must span writes.
    big = b''.join(b'line %06d of a file too long for one write\n' % i for i in range(2500))
    assert len(big) > 100 * 1024
    vol.serve()
    # No final newline: the editor keeps a file's last newline, so only this one saves to nothing.
    not_text = b'caf\xe9 \xff\xfe not utf-8\n'
    for name, body in (('/big_text.txt', big), ('/not_text.bin', not_text), ('/one_line.txt', b'hello')):
        r = vol.fs(vol.sock, 'write', name, data=body)
        if r.returncode != 0:
            raise Failure(f'seeding {name} failed: {r.stderr[:200]}')
    vol.stop()

    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file])
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'one_line\.txt', timeout=60)
        term.show('editor session')
        env = read_env(env_file)
        sock = env['STRATUMD_SOCK']
        cursor = first_entry_row(term, ['big_text.txt', 'from_vol.txt', 'madeit', 'not_text.bin', 'one_line.txt', 'tree', '.snaps'])

        cursor = goto(term, cursor, 'big_text.txt')
        term.send(F4)
        term.expect(r'line 000000')
        term.send(b'iX' + ESC)
        term.pump(0.3)
        save_in_editor(term, vol, sock, '/big_text.txt', b'X' + big, 'a file over 64 KiB')

        cursor = goto(term, cursor, 'not_text.bin')
        term.send(F4)
        term.expect(r'read-only')
        term.show('a file that is not text')
        term.send(b':w' + ENTER)
        term.expect(r'Read-only mode')
        term.send(b':q!' + ENTER)
        term.expect(IN_PANEL, timeout=15)
        got = vol.fs(sock, 'read', '/not_text.bin').stdout
        record(got == not_text, 'a file that is not text opens read-only and survives :w',
               f'a file that is not text: {len(not_text)} bytes wanted, the file holds {len(got)}')

        cursor = goto(term, cursor, 'one_line.txt')
        term.send(F4)
        term.expect(r'hello')
        term.send(b'dd')
        term.pump(0.3)
        save_in_editor(term, vol, sock, '/one_line.txt', b'', 'an emptied file')

        term.send(F10)
        if not term.exited(60):
            raise Failure('F10 did not quit after the editor legs')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def record(ok, good, bad):
    if ok:
        print(f'ok: {good}', flush=True)
    else:
        FAILED.append(bad)
        print(f'FAIL: {bad}', flush=True)


def press_enter_until(term, pattern, limit=8):
    """Enter walks the wizard's fields, and on OK submits, however many fields there are."""
    rx = re.compile(pattern)
    for _ in range(limit):
        term.send(ENTER)
        term.pump(0.4)
        if rx.search(term.screen.text()):
            return True
    return False


def fill_wizard(term, name, passphrase, confirm):
    """Name, then the passphrase twice, and submit. OK's Enter runs mkfs with the manager blocked."""
    term.send(SHIFT_F7)
    term.expect(r'Create Stratum Volume')
    term.send(name + ENTER + ENTER + ENTER)
    term.pump(0.3)
    term.send(passphrase + ENTER)
    term.pump(0.3)
    term.send(confirm)
    term.send(ENTER)
    term.pump(0.3)
    term.send(ENTER)


def wizard_legs(stratum, vol, root):
    """Shift+F7 in the manager: what an operator reaches for to make a volume."""
    w = f'{root}/wizard'
    os.makedirs(w)
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.pump(3)
        term.send(SHIFT_F7)
        term.expect(r'Create Stratum Volume')
        term.send(b'empty')
        press_enter_until(term, r'Enter a passphrase|Created ')
        term.show('the wizard with an empty passphrase')
        made = os.path.exists(f'{w}/empty.stm')
        record(not made and 'Enter a passphrase' in term.screen.text(),
               'the wizard refused an empty passphrase',
               'the wizard took an empty passphrase and made a volume with a plaintext keyfile' if made
               else 'the wizard neither refused an empty passphrase nor made a volume')
        term.send(ENTER if made else ESC)
        term.pump(0.5)

        fill_wizard(term, b'differ', PASS.encode(), b'something else')
        term.expect(r'The two passphrases differ')
        record(not os.path.exists(f'{w}/differ.stm'), 'the wizard refused two different passphrases',
               'the wizard made a volume from two different passphrases')
        term.send(ESC)
        term.pump(0.5)

        # A key left beside a name not in use may still open something, wherever its volume went.
        stale = b'a key whose volume has been moved away'
        with open(f'{w}/stale.stm.key', 'wb') as f:
            f.write(stale)
        fill_wizard(term, b'stale', PASS.encode(), PASS.encode())
        term.expect(r'mkfs failed', timeout=30)
        term.show('the wizard over a key already there')
        with open(f'{w}/stale.stm.key', 'rb') as f:
            kept = f.read() == stale
        record(kept and not os.path.exists(f'{w}/stale.stm'), 'the wizard refused to replace a key already there',
               f'the wizard over a key already there: key kept={kept}, volume made={os.path.exists(f"{w}/stale.stm")}')
        term.send(ESC)
        term.pump(0.5)

        term.send(SHIFT_F7)
        term.expect(r'Create Stratum Volume')
        term.send(b'sealed' + ENTER + ENTER + ENTER)
        term.pump(0.3)
        term.send(PASS.encode() + ENTER)
        term.pump(0.3)
        term.send(PASS.encode())
        # Confirm's Enter moves to OK, and OK's runs mkfs with the manager blocked, so one more Enter
        # would queue, dismiss the result and start opening the volume.
        term.send(ENTER)
        term.pump(0.3)
        term.send(ENTER)
        term.expect(r'Created ', timeout=60)
        term.show('the wizard with a passphrase')
        with open(f'{w}/sealed.stm.key', 'rb') as f:
            magic = struct.unpack('<I', f.read(4))[0]
        record(magic == KEYFILE_SEALED, 'the wizard sealed the keyfile', f'the wizard left a keyfile with magic {magic:#x}')
        term.send(ENTER)
        term.pump(0.5)

        term.send(F10)
        if not term.exited(60):
            raise Failure('F10 did not quit the wizard session')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    made = Volume(stratum, w)
    made.v, made.sock = f'{w}/sealed.stm', f'{w}/check.sock'
    made.serve()
    r = made.fs(made.sock, 'write', '/x', data=b'x')
    made.stop()
    record(r.returncode == 0, 'the wizard\'s volume opens with its passphrase', 'the wizard\'s volume does not open')


def landing_legs(stratum, root):
    """`stratum` with no arguments, with a recent path whose 38th byte falls inside a character."""
    config = f'{os.environ["HOME"]}/.config/stratum'
    os.makedirs(config)
    with open(f'{config}/recents', 'w', encoding='utf-8') as f:
        f.write('/volumes/' + 'é' * 30 + '/v.stm\n')

    term = Term([stratum])
    try:
        term.pump(1)
        drew = 'Choose [' in term.screen.text()
        record(drew, 'the landing screen drew a recent path that is not ASCII',
               'the landing screen died on a recent path that is not ASCII')
        term.show('landing')
        if not drew:
            return
        path = f'{root}/landing.stm'
        term.send(b'n' + ENTER)
        term.expect(r'New volume path')
        term.send(path.encode() + ENTER)
        term.pump(0.5)
        if 'NOT IMPLEMENTED' in term.screen.text():
            record(False, '', 'the landing screen\'s New is not implemented')
            return
        term.expect(r'Size')
        term.send(b'64M' + ENTER)
        term.expect(r'Passphrase:')
        term.send(PASS.encode() + ENTER)
        term.expect(r'Passphrase again')
        term.send(PASS.encode() + ENTER)
        term.expect(r'Passphrase for', timeout=60)
        term.send(PASS.encode() + ENTER)
        term.pump(3)
        term.show('landing, after New')
        term.send(F10)
        record(term.exited(60) and term.rc == 0 and os.path.exists(path),
               'the landing screen made a volume and opened it',
               f'New on the landing screen did not finish: rc={term.rc}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def mid_session_legs(stratum, root):
    """Enter on a volume in a host panel: the daemon starts mid-session, and has to stop as well as one from launch."""
    w = f'{root}/mid'
    os.makedirs(w)
    vol = Volume(stratum, w)
    vol.mkfs()
    vol.serve()
    r = vol.fs(vol.sock, 'write', '/seen_in_volume.txt', data=b'seen\n')
    if r.returncode != 0:
        raise Failure(f'seeding the volume failed: {r.stderr[:200]}')
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.pump(3)
        # A panel lists in the filesystem's order, which ext4 does not keep by name.
        pick(term, 'vol.stm', ['vol.stm', 'vol.stm.key', 'check.sock'])
        term.send(ENTER)
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'already open', timeout=70)
        term.show('a volume in use elsewhere')
        print('ok: mid-session, a volume in use elsewhere says so', flush=True)
        vol.stop()

        term.send(b'not the passphrase' + ENTER)
        term.expect(r'wrong passphrase', timeout=70)
        term.show('the wrong passphrase mid-session')
        print('ok: mid-session, the wrong passphrase says so', flush=True)

        # One attempt's reason must not be blamed on the next one.
        vol.serve()
        term.send(PASS.encode() + ENTER)
        term.expect(r'already open', timeout=70)
        record('wrong passphrase' not in term.screen.text(),
               'mid-session, a failure after a wrong passphrase is called what it is',
               'mid-session, a wrong passphrase was blamed on a later attempt')
        vol.stop()

        term.send(PASS.encode() + ENTER)
        term.expect(r'seen_in_volume', timeout=70)
        term.pump(1.5)
        if not daemons_of(vol.v):
            raise Failure('the volume showed, and then no daemon was serving it')
        term.show('the volume open mid-session')
        print('ok: mid-session, the right passphrase opens it', flush=True)

        began = time.monotonic()
        term.send(F10)
        if not term.exited(60):
            raise Failure('F10 did not quit with a volume open mid-session')
        took = time.monotonic() - began
        left = daemons_of(vol.v)
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()
    # Its worker stays while the slate stays, so stopping the daemon first runs out the KILL's clock.
    record(took < 10, f'mid-session, F10 quit in {took:.1f} s', f'mid-session, F10 took {took:.1f} s: the daemon was stopped while its client lived')
    record(not left, 'mid-session, F10 stopped the daemon', f'mid-session, daemons {left} outlived F10')
    vol.serve()
    vol.stop()
    print('ok: after a mid-session open the volume mounts and unmounts cleanly', flush=True)


def wrong_passphrase_leg(stratum, vol, host):
    """The wrong passphrase must end the manager with an error, not hang or open it."""
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host])
    try:
        term.expect(r'Passphrase for')
        term.send(b'not the passphrase' + ENTER)
        if not term.exited(60):
            raise Failure('the wrong passphrase left the manager running')
        if term.rc == 0:
            raise Failure('the manager exited 0 on the wrong passphrase')
        print(f'ok: the wrong passphrase refused, exit {term.rc}', flush=True)
        record(re.search(r'(?i)wrong passphrase', term.screen.text()), 'and it says that was the reason',
               'the manager stopped without saying the passphrase was wrong')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    # The control, one variable away: the keys are right, so a refusal above was about the passphrase.
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host])
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'from_vol\.txt', timeout=60)
        print('ok: the same command with the right passphrase opens it', flush=True)
        term.send(F10)
        if not term.exited(60):
            raise Failure('F10 did not quit after the right passphrase')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


# The conflict dialog's options, counted from the left.
SKIP, SKIP_ALL, OVERWRITE, OVERWRITE_ALL, KEEP_BOTH = 0, 1, 2, 3, 4


def slurp(path):
    """None for a file that is not there, so a leg says so rather than ending the run."""
    try:
        with open(path, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def spit(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def mode_of(path):
    return os.stat(path).st_mode & 0o777


def stm_mode(vol, sock, p9):
    m = re.search(rb'^mode:\s+([0-7]+)$', vol.fs(sock, 'stat', p9).stdout, re.M)
    return int(m[1], 8) if m else None


def rows_in_panel(term, names, right):
    rows, start, end = {}, *((COLS // 2, COLS) if right else (0, COLS // 2))
    for r, line in enumerate(term.screen.text().split('\n')):
        for name in names:
            if name not in rows and shows(line[start:end], name):
                rows[name] = r
    return rows


def pick(term, name, names, right=False):
    """Put the focused panel's cursor on name. names is everything that panel lists."""
    for _ in names:
        term.send(UP)
        term.pump(0.05)
    term.send(UP)
    term.pump(0.2)
    # Inside a directory the first row is '..', above every name.
    rows = rows_in_panel(term, list(names) + ['/..'], right)
    if name not in rows:
        raise Failure(f'{name} is not in the panel, which shows {sorted(rows)}')
    for _ in range(rows[name] - min(rows.values())):
        term.send(DOWN)
        term.pump(0.05)
    term.pump(0.2)


def answer_conflict(term, option, nth=None):
    """nth names the item the question is about, so a dialog still on screen is not answered twice."""
    term.expect(r'Destination exists' + (rf' \({nth}/' if nth else ''))
    for _ in range(option):
        term.send(RIGHT)
        term.pump(0.05)
    term.send(ENTER)


def copy_summary(term, what):
    """(copied, skipped, failed, the screen). Dismisses the dialog, so the next one is seen fresh."""
    term.expect(r'Copy: \d+ copied', timeout=120)
    # The match can come mid-repaint, half the summary drawn over the progress dialog.
    m = None
    for _ in range(20):
        term.pump(0.15)
        text = term.screen.text()
        m = re.search(r'Copy: (\d+) copied . (\d+) skipped . (\d+) failed', text)
        if m and 'cancel batch' not in text:
            break
    term.show(what)
    if not m:
        raise Failure(f'{what}: the summary did not read as one')
    term.send(ENTER)
    term.pump(0.4)
    return int(m[1]), int(m[2]), int(m[3]), text


def host_copy_refusals(stratum, root):
    """Both panels start in one directory, which is how F5 Overwrite came to delete the source."""
    w = f'{root}/same'
    os.makedirs(f'{w}/dirone/inner')
    spit(f'{w}/xfile.txt', b'source\n')
    spit(f'{w}/dirone/a.txt', b'a\n')
    names = ['xfile.txt', 'dirone']
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'xfile\.txt', timeout=30)
        term.pump(0.5)
        pick(term, 'xfile.txt', names)
        term.send(F5)
        term.expect(r'Source and destination are the same')
        term.show('F5 over itself')
        term.send(ENTER)
        term.pump(0.3)
        record(slurp(f'{w}/xfile.txt') == b'source\n', 'F5 of a file over itself says so and keeps it',
               'F5 of a file over itself changed it')

        pick(term, 'dirone', names)
        term.send(F5)
        term.expect(r'Source and destination are the same')
        term.send(ENTER)
        term.pump(0.3)
        record(slurp(f'{w}/dirone/a.txt') == b'a\n', 'F5 of a directory over itself says so and keeps it',
               'F5 of a directory over itself changed it')

        # The other panel inside the directory: the copy would land in itself.
        term.send(TAB)
        term.pump(0.3)
        pick(term, 'dirone', names, right=True)
        term.send(ENTER)
        term.pump(0.6)
        term.send(TAB)
        term.pump(0.3)
        pick(term, 'dirone', names)
        term.send(F5)
        term.expect(r'cannot be copied into itself')
        term.show('a directory into itself')
        term.send(ENTER)
        term.pump(0.3)
        record(not os.path.exists(f'{w}/dirone/dirone'), 'a directory is not copied into itself',
               'a directory was copied into itself')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def host_copy_legs(stratum, root):
    """F5 between host directories. Whatever is asked for, what was there is not lost by failing."""
    w = f'{root}/copy'
    sub = f'{w}/subdest'
    os.makedirs(sub)
    os.makedirs(f'{w}/dirone/inner')
    os.makedirs(f'{w}/treeone/shut')
    spit(f'{w}/xfile.txt', b'source\n')
    spit(f'{w}/dirone/a.txt', b'a\n')
    spit(f'{w}/dirone/inner/b.txt', b'b\n')
    spit(f'{w}/treeone/ok.txt', b'ok\n')
    os.symlink('ok.txt', f'{w}/treeone/lnk')
    names = ['xfile.txt', 'subdest', 'dirone', 'treeone']
    root_user = os.geteuid() == 0
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'xfile\.txt', timeout=30)
        term.pump(0.5)
        term.send(TAB)
        term.pump(0.3)
        pick(term, 'subdest', names, right=True)
        term.send(ENTER)
        term.pump(0.6)
        term.send(TAB)
        term.pump(0.3)

        # The control for everything below: the same keys, with nothing in the way.
        pick(term, 'xfile.txt', names)
        os.chmod(f'{w}/xfile.txt', 0o640)
        term.send(F5)
        copied, skipped, failed, _ = copy_summary(term, 'F5 into an empty directory')
        record((copied, skipped, failed) == (1, 0, 0) and slurp(f'{sub}/xfile.txt') == b'source\n',
               'F5 copies a file', f'F5 of a file: {copied} copied, {skipped} skipped, {failed} failed')
        record(mode_of(f'{sub}/xfile.txt') == 0o640, 'a copy keeps who may read the file',
               f'a copy of a 0640 file came out {mode_of(f"{sub}/xfile.txt"):o}')

        if root_user:
            print('note: running as root, so an unreadable source cannot be made here', flush=True)
        else:
            spit(f'{sub}/xfile.txt', b'old\n')
            os.chmod(f'{w}/xfile.txt', 0)
            term.send(F5)
            answer_conflict(term, OVERWRITE)
            _, _, failed, _ = copy_summary(term, 'Overwrite with an unreadable source')
            os.chmod(f'{w}/xfile.txt', 0o644)
            record(failed == 1 and slurp(f'{sub}/xfile.txt') == b'old\n',
                   'an Overwrite that cannot read its source keeps the old destination',
                   f'an Overwrite with an unreadable source: {failed} failed, destination {slurp(f"{sub}/xfile.txt")!r}')

        term.send(F5)
        answer_conflict(term, OVERWRITE)
        copied, _, failed, _ = copy_summary(term, 'Overwrite')
        record((copied, failed) == (1, 0) and slurp(f'{sub}/xfile.txt') == b'source\n',
               'Overwrite replaces the file', f'Overwrite: {copied} copied, {failed} failed')

        spit(f'{sub}/xfile.txt', b'old\n')
        term.send(F5)
        answer_conflict(term, KEEP_BOTH)
        copy_summary(term, 'KeepBoth')
        record(slurp(f'{sub}/xfile.txt') == b'old\n' and slurp(f'{sub}/xfile-2.txt') == b'source\n',
               'KeepBoth keeps both', 'KeepBoth did not keep both')

        # A directory in the way, with a file of its own in it.
        os.makedirs(f'{sub}/dirone')
        spit(f'{sub}/dirone/old.txt', b'old\n')
        os.chmod(f'{w}/dirone/inner', 0o700)
        pick(term, 'dirone', names)
        term.send(F5)
        answer_conflict(term, KEEP_BOTH)
        copy_summary(term, 'KeepBoth on a directory')
        record(os.path.exists(f'{sub}/dirone-2/inner/b.txt') and not os.path.exists(f'{sub}/dirone/a.txt'),
               "a directory kept under a new name takes its contents along",
               "a directory's contents did not follow its new name")
        record(mode_of(f'{sub}/dirone-2/inner') == 0o700, 'a new directory keeps who may look in it',
               f'a 0700 directory came out {mode_of(f"{sub}/dirone-2/inner"):o}')

        term.send(F5)
        answer_conflict(term, SKIP)
        _, skipped, _, _ = copy_summary(term, 'Skip on a directory')
        record(skipped == 4 and not os.path.exists(f'{sub}/dirone/a.txt'),
               'Skip on a directory skips what is under it', f'Skip on a directory: {skipped} skipped')

        term.send(F5)
        answer_conflict(term, OVERWRITE)
        _, _, failed, _ = copy_summary(term, 'Overwrite on a directory')
        record(failed == 0 and os.path.exists(f'{sub}/dirone/old.txt') and os.path.exists(f'{sub}/dirone/inner/b.txt'),
               'Overwrite on a directory merges, and deletes nothing',
               f'Overwrite on a directory: {failed} failed, old.txt there: {os.path.exists(f"{sub}/dirone/old.txt")}')

        # What a walk cannot copy has to show in the count.
        if not root_user:
            os.chmod(f'{w}/treeone/shut', 0)
        pick(term, 'treeone', names)
        term.send(F5)
        _, skipped, failed, text = copy_summary(term, 'a tree with a symlink and a shut directory')
        record(skipped >= 1 and 'not copied' in text, 'a symlink in a tree is counted and explained',
               f'a symlink in a tree: {skipped} skipped, explained: {"not copied" in text}')
        if not root_user:
            record(failed >= 1, 'a directory the walk cannot read is counted as failed',
                   'a directory the walk could not read went uncounted')
        record(slurp(f'{sub}/treeone/ok.txt') == b'ok\n', 'the rest of that tree is copied', 'the rest of that tree is not there')

        left = [n for _, _, fs in os.walk(w) for n in fs if n.startswith('.stratum-copy-')]
        record(not left, 'no copy left a temporary file', f'temporary files left: {left}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()
        if os.path.exists(f'{w}/xfile.txt'):
            os.chmod(f'{w}/xfile.txt', 0o644)
        os.chmod(f'{w}/treeone/shut', 0o755)


def copy_engine_legs(stratum, root):
    """Where a copy writes, and what a link or a planted name can make of that."""
    # Names unlike the header's words, so a row is never taken for the header.
    w = f'{root}/engine'
    for d in ('src/linkdir/sub', 'src/skiptree/sub', 'dst/linkdir', 'dst/skiptree/sub', 'elsewhere'):
        os.makedirs(f'{w}/{d}')
    spit(f'{w}/src/plain.txt', b'plain\n')
    spit(f'{w}/elsewhere/victim.txt', b'victim\n')
    # A merge into a destination whose subdirectory is a link back into the source.
    spit(f'{w}/src/linkdir/f', b'F')
    spit(f'{w}/src/linkdir/sub/f', b'S')
    os.symlink(f'{w}/src/linkdir', f'{w}/dst/linkdir/sub')
    # SkipAll answered at a file, then a directory that is there, holding something new.
    spit(f'{w}/src/skiptree/a.txt', b'new\n')
    spit(f'{w}/src/skiptree/sub/new.txt', b'new\n')
    spit(f'{w}/dst/skiptree/a.txt', b'old\n')
    top, src_names = ['src', 'dst', 'elsewhere'], ['plain.txt', 'linkdir', 'skiptree']
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'elsewhere', timeout=30)
        term.pump(0.5)
        pick(term, 'src', top)
        term.send(ENTER)
        term.pump(0.6)
        term.send(TAB)
        term.pump(0.3)
        pick(term, 'dst', top, right=True)
        term.send(ENTER)
        term.pump(0.6)
        term.send(TAB)
        term.pump(0.3)

        # The temp's name is this process's id and a count from 0.
        planted = [f'{w}/dst/.stratum-copy-{term.pid}-{n}' for n in range(64)]
        for p in planted:
            os.symlink(f'{w}/elsewhere/victim.txt', p)
        pick(term, 'plain.txt', src_names)
        term.send(F5)
        _, _, failed, _ = copy_summary(term, 'a temp name planted ahead of the copy')
        record(slurp(f'{w}/elsewhere/victim.txt') == b'victim\n', 'a planted temp name does not steer a copy into another file',
               f'a planted temp name let the copy write elsewhere: {slurp(f"{w}/elsewhere/victim.txt")!r}')
        record(failed == 1 and os.path.islink(planted[0]), 'that copy fails, and leaves the planted name alone',
               f'that copy: {failed} failed, the planted name there: {os.path.islink(planted[0])}')
        for p in planted:
            if os.path.islink(p):
                os.unlink(p)

        pick(term, 'linkdir', src_names)
        term.send(F5)
        answer_conflict(term, OVERWRITE_ALL, nth=1)
        _, _, failed, _ = copy_summary(term, 'a link in the destination back into the source')
        record(slurp(f'{w}/src/linkdir/f') == b'F' and slurp(f'{w}/src/linkdir/sub/f') == b'S',
               'a link in the destination does not lead a copy over its source',
               f'the source now reads {slurp(f"{w}/src/linkdir/f")!r} and {slurp(f"{w}/src/linkdir/sub/f")!r}')
        record(failed >= 1, 'the directory behind that link is counted as failed', f'behind that link: {failed} failed')

        pick(term, 'skiptree', src_names)
        term.send(F5)
        answer_conflict(term, OVERWRITE, nth=1)
        answer_conflict(term, SKIP_ALL, nth=2)
        copy_summary(term, 'SkipAll at a file, then a directory that is there')
        record(slurp(f'{w}/dst/skiptree/sub/new.txt') == b'new\n' and slurp(f'{w}/dst/skiptree/a.txt') == b'old\n',
               'a SkipAll answered at a file still merges into a directory that is there',
               f'after SkipAll at a file: new.txt {slurp(f"{w}/dst/skiptree/sub/new.txt")!r}, a.txt {slurp(f"{w}/dst/skiptree/a.txt")!r}')

        # A pipe is no file: its open would wait for a writer that never comes.
        os.mkfifo(f'{w}/src/pipe')
        term.pump(1.5)
        pick(term, 'pipe', src_names + ['pipe'])
        term.send(F5)
        term.expect(r'Nothing valid in selection|Copy: \d+ copied', timeout=30)
        record('Nothing valid' in term.screen.text(), 'a pipe is left out of a copy, not read',
               'a pipe was taken for a file')
        term.send(ENTER)
        term.pump(0.3)
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def volume_copy_legs(stratum, root):
    """The same promises on a volume, and a name in it that must not steer a copy."""
    base = f'{root}/copyvol'
    host = f'{base}/host'
    os.makedirs(host)
    spit(f'{host}/keptfile.txt', b'new\n')
    spit(f'{host}/overfile.txt', b'new\n')
    spit(f'{host}/secretfile.txt', b'secret\n')
    os.chmod(f'{host}/secretfile.txt', 0o600)
    os.makedirs(f'{host}/privdir')
    os.chmod(f'{host}/privdir', 0o700)
    os.symlink(f'{host}/privdir', f'{host}/linkedname')
    # Names the panels cannot show as they are: a tab at the top, a newline further down.
    spit(f'{host}/tab\tname', b'tab\n')
    os.makedirs(f'{host}/nldir')
    spit(f'{host}/nldir/plain.txt', b'plain\n')
    spit(f'{host}/nldir/bad\nname', b'bad\n')
    vol = Volume(stratum, base)
    vol.mkfs()
    vol.serve()
    # It reads as two lines, and so as two entries, to a reader that splits on them.
    hostile = '/hostile/innocent\n- escaped'
    for args, data in ((('write', '/keptfile.txt'), b'old\n'), (('write', '/overfile.txt'), b'old\n'),
                       (('mkdir', '/hostile'), None), (('write', '/hostile/plain.txt'), b'plain\n'),
                       (('write', hostile), b'bad\n'),
                       (('write', '/shutfile.txt'), b'shut\n'), (('chmod', '640', '/shutfile.txt'), None),
                       (('mkdir', '/shutdir'), None), (('chmod', '700', '/shutdir'), None),
                       (('write', '/linkedname'), b'keep\n')):
        r = vol.fs(vol.sock, *args, data=data)
        if r.returncode != 0:
            raise Failure(f'seeding {args}: {r.stderr[:200]}')
    if b'\0' not in vol.fs(vol.sock, 'ls', '-0', '/hostile').stdout:
        raise Failure('ls -0 printed no NUL')
    vol.stop()

    host_names = ['keptfile.txt', 'overfile.txt', 'secretfile.txt', 'privdir', 'linkedname',
                  'tab\ufffdname', 'nldir']
    vol_names = ['keptfile.txt', 'overfile.txt', 'keptfile-2.txt', 'hostile', '.snaps',
                 'shutfile.txt', 'shutdir', 'secretfile.txt', 'privdir', 'linkedname']
    env_file = f'{base}/env'
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file])
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'hostile', timeout=60)
        term.pump(0.5)
        sock = read_env(env_file)['STRATUMD_SOCK']
        def on_vol(p9):
            return vol.fs(sock, 'read', p9).stdout

        term.send(TAB)
        term.pump(0.3)
        pick(term, 'keptfile.txt', host_names, right=True)
        term.send(F5)
        answer_conflict(term, KEEP_BOTH)
        copy_summary(term, 'KeepBoth on a volume')
        record(on_vol('/keptfile.txt') == b'old\n' and on_vol('/keptfile-2.txt') == b'new\n',
               'KeepBoth on a volume keeps both', 'KeepBoth on a volume did not keep both')

        pick(term, 'overfile.txt', host_names, right=True)
        if os.geteuid() != 0:
            os.chmod(f'{host}/overfile.txt', 0)
            term.send(F5)
            answer_conflict(term, OVERWRITE)
            _, _, failed, _ = copy_summary(term, 'Overwrite on a volume, unreadable source')
            os.chmod(f'{host}/overfile.txt', 0o644)
            record(failed == 1 and on_vol('/overfile.txt') == b'old\n',
                   'an Overwrite on a volume that cannot read its source keeps the old file',
                   f'an Overwrite on a volume: {failed} failed, file {on_vol("/overfile.txt")!r}')

        term.send(F5)
        answer_conflict(term, OVERWRITE)
        copied, _, failed, _ = copy_summary(term, 'Overwrite on a volume')
        record((copied, failed) == (1, 0) and on_vol('/overfile.txt') == b'new\n',
               'Overwrite on a volume replaces the file', f'Overwrite on a volume: {copied} copied, {failed} failed')
        record(b'.stratum-copy-' not in vol.fs(sock, 'ls', '/').stdout, 'no copy left a temporary file in the volume',
               'a temporary file was left in the volume')

        # Whichever way a file crosses, the same people may read it. 0640 is neither
        # what a volume gives a new file nor what a copy gives a file with no mode to go by.
        pick(term, 'secretfile.txt', host_names, right=True)
        term.send(F5)
        copy_summary(term, 'a private file into a volume')
        got = stm_mode(vol, sock, '/secretfile.txt')
        record(got == 0o600, 'a private file stays private in a volume', f'a 0600 file in a volume reads {got!r}')
        pick(term, 'privdir', host_names, right=True)
        term.send(F5)
        copy_summary(term, 'a private directory into a volume')
        got = stm_mode(vol, sock, '/privdir')
        record(got == 0o700, 'a private directory stays private in a volume', f'a 0700 directory in a volume reads {got!r}')

        # Read as a file, a link to a directory gave the write a directory to read: an
        # empty file, reported copied, in place of the volume's.
        pick(term, 'linkedname', host_names, right=True)
        term.send(F5)
        term.expect(r'Nothing valid in selection|Destination exists')
        # The refusal itself: past it, four later checks each keep the volume file too.
        refused = 'Nothing valid in selection' in term.screen.text()
        if refused:
            term.send(ENTER)
            term.pump(0.3)
        else:
            answer_conflict(term, OVERWRITE)
            copy_summary(term, 'a link to a directory over a volume file')
        record(refused and on_vol('/linkedname') == b'keep\n',
               'a link to a directory is left out of a copy into a volume, and the volume file stays',
               f'a link to a directory: refused={refused}, the volume file reads {on_vol("/linkedname")!r}')

        # Shown with a stand-in, a name would be acted on as the stand-in: another file,
        # or none.
        pick(term, 'tab\ufffdname', host_names, right=True)
        term.send(F5)
        term.expect(r'Nothing valid in selection|Copy: \d+ copied|Destination exists')
        refused = 'Nothing valid in selection' in term.screen.text()
        term.send(ENTER)
        term.pump(0.5)
        record(refused, 'a name with a control character is refused, not copied under its stand-in',
               'a name with a control character was acted on under its stand-in')
        pick(term, 'nldir', host_names, right=True)
        term.send(F5)
        _, _, failed, _ = copy_summary(term, 'a directory holding a name with a newline')
        inside = vol.fs(sock, 'ls', '-0', '/nldir').stdout
        record(failed == 1 and b'plain.txt' in inside and b'bad' not in inside,
               'a name with a newline is not copied into a volume, and is counted failed',
               f'a name with a newline: {failed} failed, the volume directory lists {inside!r}')

        term.send(TAB)
        term.pump(0.3)
        pick(term, 'shutfile.txt', vol_names)
        term.send(F5)
        copy_summary(term, 'a 0640 file out of a volume')
        record(mode_of(f'{host}/shutfile.txt') == 0o640, 'a file out of a volume keeps who may read it',
               f'a 0640 file out of a volume came out {mode_of(f"{host}/shutfile.txt"):o}')
        pick(term, 'shutdir', vol_names)
        term.send(F5)
        copy_summary(term, 'a 0700 directory out of a volume')
        record(mode_of(f'{host}/shutdir') == 0o700, 'a directory out of a volume keeps who may look in it',
               f'a 0700 directory out of a volume came out {mode_of(f"{host}/shutdir"):o}')

        pick(term, 'hostile', vol_names)
        term.send(F5)
        _, _, failed, _ = copy_summary(term, 'a name that reads as two lines')
        record(failed == 1, 'a name with a newline in it is counted once, as failed',
               f'a name with a newline in it: {failed} failed')
        out = f'{host}/hostile'
        record(os.path.exists(f'{out}/plain.txt'), 'the names around it are copied', 'the name beside it was not copied')
        listed = sorted(os.listdir(out)) if os.path.isdir(out) else []
        record(listed == ['plain.txt'], 'nothing else came out of that directory', f'that directory also made: {listed}')

        term.send(F10)
        if not term.exited(60):
            raise Failure('F10 did not quit')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()
        os.chmod(f'{host}/overfile.txt', 0o644)


def selection_legs(stratum, root):
    """A selection is indices, so a listing that changes under it must not leave them pointing at other files."""
    w = f'{root}/sel'
    os.makedirs(w)
    files = ['onefile.txt', 'twofile.txt', 'threefile.txt', 'gonefile.txt']
    for name in files:
        spit(f'{w}/{name}', name.encode())
    names = files + ['madedir']

    # The control, one variable away: with the listing unchanged the mark stays and F8 acts on it.
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'onefile\.txt', timeout=30)
        term.pump(0.5)
        pick(term, 'twofile.txt', names)
        term.send(b' ')
        term.pump(1.0)
        term.send(F8)
        term.expect(r'Delete 1 items')
        term.show('F8 with a mark and the same listing')
        print('ok: a mark survives while the listing stays the same', flush=True)
        # Esc is a No: the question's own footer calls it cancel.
        term.send(ESC)
        term.pump(2.0)
        record(os.path.exists(f'{w}/twofile.txt'), 'Esc at the delete question deletes nothing',
               'Esc at the delete question deleted the marked file')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'onefile\.txt', timeout=30)
        term.pump(0.5)
        pick(term, 'twofile.txt', names)
        term.send(b' ')
        term.pump(0.5)
        term.send(F7)
        term.expect(r'New directory name')
        term.send(b'madedir' + ENTER)
        term.expect(r'madedir', timeout=30)
        term.pump(1.0)
        term.send(F8)
        term.expect(r'Delete this|Delete \d+ items')
        term.show('F8 after the listing changed under a mark')
        text = term.screen.text()
        record('Delete this' in text and 'items' not in text,
               'a mark does not outlive the listing it was made in',
               'F8 still acted on a mark made in an older listing')
        term.send(ENTER)
        term.pump(0.3)
        left = sorted(n for n in os.listdir(w))
        record(left == sorted(names), 'answering No deleted nothing', f'after No the directory holds {left}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    # Yes, the one answer that deletes, so the Esc above is not a delete that never works.
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'onefile\.txt', timeout=30)
        term.pump(0.5)
        pick(term, 'gonefile.txt', names)
        term.send(b' ')
        term.pump(0.5)
        term.send(F8)
        term.expect(r'Delete 1 items')
        term.send(LEFT)
        term.pump(0.2)
        term.send(ENTER)
        for _ in range(50):
            term.pump(0.2)
            if not os.path.exists(f'{w}/gonefile.txt'):
                break
        record(not os.path.exists(f'{w}/gonefile.txt'), 'Yes at the delete question deletes',
               'Yes at the delete question left the file')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def p9_mkdir(sock, parents, name):
    """A raw Tmkdir: `stratum fs` takes its paths as text, and these names are not."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect(sock)

    def recv(n):
        b = b''
        while len(b) < n:
            got = s.recv(n - len(b))
            if not got:
                raise Failure('the daemon closed the 9P connection')
            b += got
        return b

    def rpc(mtype, body, tag=1):
        s.sendall(struct.pack('<IBH', 7 + len(body), mtype, tag) + body)
        size, rtype = struct.unpack('<IB', recv(5))
        rest = recv(size - 5)
        if rtype == 7:
            raise Failure(f'9P message {mtype} refused: errno {struct.unpack("<I", rest[2:6])[0]}')
        if rtype != mtype + 1:
            raise Failure(f'9P message {mtype} answered with type {rtype}')
        return rest[2:]

    def s9(b):
        return struct.pack('<H', len(b)) + b

    try:
        rpc(100, struct.pack('<I', 65536) + s9(b'9P2000.L'), tag=0xFFFF)
        rpc(104, struct.pack('<II', 0, 0xFFFFFFFF) + s9(b'') + s9(b'') + struct.pack('<I', 0xFFFFFFFF))
        rpc(110, struct.pack('<IIH', 0, 1, len(parents)) + b''.join(s9(p) for p in parents))
        rpc(72, struct.pack('<I', 1) + s9(name) + struct.pack('<II', 0o755, os.getgid()))
        rpc(120, struct.pack('<I', 1))
        rpc(50, struct.pack('<II', 0, 0))
    finally:
        s.close()


def unreadable_name_legs(stratum, root):
    """A name that is not UTF-8 is not somewhere the manager goes, and from inside one nothing lands at the root."""
    base = f'{root}/badname'
    os.makedirs(base)
    vol = Volume(stratum, base)
    vol.mkfs()
    vol.serve()
    for args, data in ((('mkdir', '/victim'), None), (('write', '/victim/keepme'), b'keep\n')):
        r = vol.fs(vol.sock, *args, data=data)
        if r.returncode != 0:
            raise Failure(f'seeding {args}: {r.stderr[:200]}')
    p9_mkdir(vol.sock, [], b'caf\xe9')
    p9_mkdir(vol.sock, [b'caf\xe9'], b'victim')
    vol.stop()

    shown = 'caf\ufffd'
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', base])
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'victim', timeout=60)
        term.pump(0.5)
        pick(term, shown, [shown, 'victim', '.snaps'])
        term.send(ENTER)
        term.pump(1.5)
        term.show('Enter on a name that is not UTF-8')
        if shown in rows_in_panel(term, [shown], False):
            print('ok: the manager does not go into a directory whose name is not UTF-8', flush=True)
        else:
            # Two defences: in here, the actions must refuse rather than build from the root.
            print('note: it went in, so its actions must refuse', flush=True)
            pick(term, 'victim', ['victim'])
            term.send(b' ')
            term.pump(0.5)
            term.send(F8)
            term.expect(r'location cannot be read|Delete')
            term.show('F8 inside it')
            if 'location cannot be read' in term.screen.text():
                print('ok: inside it, F8 refuses for want of a location', flush=True)
                term.send(ENTER)
            else:
                term.send(LEFT)
                term.pump(0.1)
                term.send(ENTER)
                term.pump(3.0)
        term.pump(0.5)
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()
    vol.serve()
    try:
        kept = vol.fs(vol.sock, 'read', '/victim/keepme').stdout
    finally:
        vol.stop()
    record(kept == b'keep\n', "the root's own victim directory is untouched",
           f'the root\'s /victim/keepme now reads {kept!r}')


def files_left(path):
    """-1 once the directory is gone, so a poll never ends the run."""
    try:
        return len(os.listdir(path))
    except FileNotFoundError:
        return -1


def delete_batch_legs(stratum, root):
    """A delete runs one item at a time. A quit key mid-batch asks, and holds the batch while
    it asks: Esc stops it after the item in hand, Go on lets it finish. A bare Esc stops it."""
    w = f'{root}/delbatch'
    many = 20000
    dirs = ['bulkone', 'bulktwo']
    held = ['heldone', 'heldtwo']
    names = ['bulkzero'] + dirs + held
    for d in names:
        os.makedirs(f'{w}/{d}')
        for i in range(many):
            open(f'{w}/{d}/f{i:05d}', 'wb').close()
    asked = r'held while this shows'

    def start_delete(term, chosen):
        term.expect(re.escape(chosen[0]), timeout=30)
        term.pump(0.5)
        for d in chosen:
            pick(term, d, names)
            term.send(b' ')
            term.pump(0.3)
        term.send(F8)
        term.expect(rf'Delete {len(chosen)} items')
        term.send(LEFT)
        term.pump(0.1)
        term.send(ENTER)
        # Once an item is under way: before that, Esc stops a batch with nothing running.
        end = time.monotonic() + 30
        while time.monotonic() < end and all(files_left(f'{w}/{d}') == many for d in chosen):
            time.sleep(0.01)

    def asks(term):
        """True when the question came; False when the item ended before the key was read."""
        term.expect(asked + r'|Delete: \d+ deleted', timeout=10)
        if re.search(asked, term.screen.text()):
            return True
        print('note: the batch ended before the key was read, so this leg proves nothing', flush=True)
        return False

    term = Term([stratum, 'tui', '--host', w])
    try:
        start_delete(term, ['bulkzero'])
        term.send(b'\x11')
        if asks(term):
            record(not term.exited(1), 'Ctrl-Q mid-delete asks, and does not quit', 'Ctrl-Q quit in the middle of a delete')
            term.send(RIGHT)   # a quit key starts on Stop; Go on is next
            term.pump(0.1)
            term.send(ENTER)
            term.expect(r'Delete: \d+ deleted', timeout=120)
            left = files_left(f'{w}/bulkzero')
            record(left == -1, 'Go on lets the delete finish', f'after Go on, bulkzero holds {left} files')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    term = Term([stratum, 'tui', '--host', w])
    try:
        start_delete(term, dirs)
        term.send(ESC)
        term.expect(r'Delete: \d+ deleted', timeout=120)
        term.show('after Esc mid-delete')
        m = re.search(r'Delete: (\d+) deleted', term.screen.text())
        intact = [d for d in dirs if files_left(f'{w}/{d}') == many]
        record(len(intact) == 1, 'Esc mid-delete stops the batch after the item in hand',
               f'after Esc mid-delete, the intact directories are {intact}')
        record(m is not None and m[1] == '1', 'the item in hand when Esc came is counted',
               f'the summary after Esc reads {m and m[0]!r}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    # The question says Esc stops the batch, so one Esc must: closing it alone let the
    # batch run on and delete the rest.
    term = Term([stratum, 'tui', '--host', w])
    try:
        start_delete(term, held)
        term.send(b'\x03')
        if asks(term):
            term.send(ESC)
            term.expect(r'Delete: \d+ deleted', timeout=120)
            term.show('after Ctrl-C and one Esc mid-delete')
            intact = [d for d in held if files_left(f'{w}/{d}') == many]
            record(len(intact) == 1, 'one Esc on the question Ctrl-C asks stops the delete after the item in hand',
                   f'after Ctrl-C and one Esc, the intact directories are {intact}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def run(stratum, root):
    host = f'{root}/host'
    tree = f'{host}/tree'
    os.makedirs(f'{tree}/deep')
    with open(f'{tree}/a.txt', 'w') as f:
        f.write('one\n')
    with open(f'{tree}/deep/b.txt', 'w') as f:
        f.write('two\n')
    with open(f'{tree}/big.bin', 'wb') as f:
        f.write(os.urandom(3 << 20))

    vol = Volume(stratum, root)
    vol.mkfs()
    vol.serve()
    r = vol.fs(vol.sock, 'write', '/from_vol.txt', data=b'came from the volume\n')
    if r.returncode != 0:
        raise Failure(f'seeding the volume failed: {r.stderr[:200]}')
    vol.stop()
    print('ok: a sealed volume with one file in it', flush=True)

    env_file = f'{root}/env'
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file])
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'from_vol\.txt', timeout=60)
        term.expect(r'tree', timeout=30)
        term.show('unlocked')
        print('ok: unlocked with the passphrase; both panels drawn', flush=True)

        env = read_env(env_file)
        sock = env['STRATUMD_SOCK']

        # The right panel holds the host, and its cursor starts on the only entry.
        term.send(TAB)
        term.pump(0.3)
        term.send(F5)
        term.expect(r'Copy: \d+ copied', timeout=120)
        term.show('after F5 host to volume')
        text = term.screen.text()
        if not re.search(r'Copy: \d+ copied . 0 skipped . 0 failed', text):
            raise Failure('the copy reported something other than clean success')
        for rel in ('a.txt', 'deep/b.txt', 'big.bin'):
            wait_same(vol, sock, f'/tree/{rel}', f'{tree}/{rel}', f'F5 copied {rel} into the volume')
        term.send(ENTER)
        term.pump(0.5)

        # Back the other way: the volume's own file, onto the host.
        term.send(TAB)
        term.pump(0.5)
        term.show('focus back on the volume')
        steps = row_in_left_panel(term, 'from_vol.txt') - first_entry_row(term, ['from_vol.txt', 'tree', '.snaps'])
        for _ in range(steps):
            term.send(DOWN)
            term.pump(0.1)
        term.send(F5)
        term.expect(r'Copy: \d+ copied', timeout=60)
        term.show('after F5 volume to host')
        with open(f'{host}/from_vol.txt', 'rb') as f:
            if f.read() != b'came from the volume\n':
                raise Failure('F5 out of the volume wrote different bytes')
        print('ok: F5 copied a file out of the volume', flush=True)
        term.send(ENTER)
        term.pump(0.5)

        term.send(F7)
        term.expect(r'New directory name')
        term.send(b'madeit' + ENTER)
        term.expect(r'madeit', timeout=30)
        listing = vol.fs(sock, 'ls', '/')
        if b'madeit' not in listing.stdout:
            raise Failure('F7 drew a directory the volume does not hold')
        print('ok: F7 made a directory in the volume', flush=True)
        term.show('after F7')

        admin_legs(term, vol, sock)

        term.send(F10)
        if not term.exited(60):
            raise Failure('F10 did not quit')
        if term.rc != 0:
            raise Failure(f'the manager exited {term.rc}')
        print('ok: F10 quit cleanly', flush=True)
        # Now, because term.kill stops strays, and the lifeline would stop them soon after.
        session = os.path.dirname(env['STRATUMD_SOCK'])
        left, session_left = daemons_of(session), os.path.exists(session)
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    record(not left and not session_left, 'F10 stopped its daemons and removed its session',
           f'after F10, daemons {left} and the session directory exists={session_left}')

    vol.serve()
    try:
        for rel in ('a.txt', 'deep/b.txt', 'big.bin'):
            if not same(vol, vol.sock, f'/tree/{rel}', f'{tree}/{rel}'):
                raise Failure(f'past a remount, /tree/{rel} differs')
        print('ok: the same bytes past a remount', flush=True)
        if b'madeit' not in vol.fs(vol.sock, 'ls', '/').stdout:
            raise Failure('past a remount, the directory is gone')
    finally:
        vol.stop()

    # One leg's failure must not hide what the rest would have shown.
    for leg, args in ((selection_legs, (stratum, root)),
                      (host_copy_refusals, (stratum, root)),
                      (host_copy_legs, (stratum, root)),
                      (copy_engine_legs, (stratum, root)),
                      (volume_copy_legs, (stratum, root)),
                      (unreadable_name_legs, (stratum, root)),
                      (delete_batch_legs, (stratum, root)),
                      (death_legs, (stratum, vol, host, root)),
                      (editor_legs, (stratum, vol, host, f'{root}/env2')),
                      (wrong_passphrase_leg, (stratum, vol, host)),
                      (wizard_legs, (stratum, vol, root)),
                      (mid_session_legs, (stratum, root)),
                      (landing_legs, (stratum, root))):
        try:
            leg(*args)
        except (Failure, OSError) as e:
            record(False, '', f'{leg.__name__}: {e}')


def main():
    global SHOW
    args = [a for a in sys.argv[1:] if a != '--show']
    SHOW = '--show' in sys.argv
    if len(args) != 1:
        sys.exit(__doc__)
    stratum = os.path.abspath(args[0])
    # A private directory is 0700 whatever the umask; under 077 a mode never given would
    # read 0700 too, and the mode legs would see nothing.
    os.umask(0o022)
    root = tempfile.mkdtemp(prefix='stratum-keys.')
    # The landing screen keeps its recent volumes under HOME, which must not be the operator's.
    os.environ['HOME'] = root
    try:
        only = os.environ.get('KEYS_ONLY')
        if only:
            for name in only.split(','):
                try:
                    globals()[name](stratum, root)
                except (Failure, OSError) as e:
                    record(False, '', f'{name}: {e}')
        else:
            run(stratum, root)
    except (Failure, subprocess.SubprocessError, OSError) as e:
        print(f'FAIL: {e}')
        return 1
    finally:
        for proc in SERVED:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
        shutil.rmtree(root, ignore_errors=True)
    if FAILED:
        print(f'FAIL: {len(FAILED)} leg(s) above')
        return 1
    print('PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
