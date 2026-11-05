#!/usr/bin/env python3
"""The manager through a real terminal: keys in, screen out, bytes checked outside the manager.

tools/stratum's own tests go through `stratum fs`, so nothing else presses F5. This is what an operator
does with an encrypted volume: unlock it, copy in, copy out, make and delete a directory, quit, and find
the same bytes after a remount.

    tests/manager_keys.py path/to/stratum [--show]

--show prints the screen after each step. On a failure the screen is printed regardless.
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
RIGHT = b'\x1b[C'
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


def row_in_left_panel(term, name):
    for r, line in enumerate(term.screen.text().split('\n')):
        if name in line[:COLS // 2]:
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
        term.pump(0.5)
        term.send(ESC)
        term.pump(0.3)
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
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.pump(3)
        # vol.stm sorts first, and the cursor starts there.
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

        term.send(PASS.encode() + ENTER)
        limit = time.monotonic() + 70
        while not daemons_of(vol.v) and time.monotonic() < limit:
            term.pump(0.2)
        if not daemons_of(vol.v):
            raise Failure('the right passphrase started no daemon for the volume')
        term.pump(1.5)
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
    for leg, args in ((death_legs, (stratum, vol, host, root)),
                      (editor_legs, (stratum, vol, host, f'{root}/env2')),
                      (wrong_passphrase_leg, (stratum, vol, host)),
                      (wizard_legs, (stratum, vol, root)),
                      (mid_session_legs, (stratum, root)),
                      (landing_legs, (stratum, root))):
        try:
            leg(*args)
        except Failure as e:
            record(False, '', f'{leg.__name__}: {e}')


def main():
    global SHOW
    args = [a for a in sys.argv[1:] if a != '--show']
    SHOW = '--show' in sys.argv
    if len(args) != 1:
        sys.exit(__doc__)
    stratum = os.path.abspath(args[0])
    root = tempfile.mkdtemp(prefix='stratum-keys.')
    # The landing screen keeps its recent volumes under HOME, which must not be the operator's.
    os.environ['HOME'] = root
    try:
        run(stratum, root)
    except (Failure, subprocess.SubprocessError, OSError) as e:
        print(f'FAIL: {e}')
        return 1
    finally:
        shutil.rmtree(root, ignore_errors=True)
    if FAILED:
        print(f'FAIL: {len(FAILED)} leg(s) above')
        return 1
    print('PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
