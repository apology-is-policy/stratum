#!/usr/bin/env python3
"""The manager through a real terminal: keys in, screen out, bytes checked outside the manager.

tools/stratum's own tests go through `stratum fs`, so nothing else presses F5. This is what an operator
does with an encrypted volume: unlock it, copy in, copy out, make and delete a directory, quit, and find
the same bytes after a remount.

    tests/manager_keys.py path/to/stratum [--show]

--show prints the screen after each step. On a failure the screen is printed regardless.
KEYS_ONLY=leg,leg runs only those legs, each given what its parameters name (a sealed volume and a host
tree for vol and host).
"""
import codecs
import fcntl
import glob
import inspect
import os
import pty
import re
import resource
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

    def __init__(self, onlcr=False):
        self.cells = [[' '] * COLS for _ in range(ROWS)]
        self.r = self.c = 0
        # Bytes off a pipe never met a terminal's output processing: shown as a terminal
        # would show them, each line starts at the left edge, not where the last one ended.
        self.onlcr = onlcr
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
                if self.onlcr:
                    self.c = 0
            elif ch == '\b':
                self.c = max(self.c - 1, 0)
            elif ch >= ' ':
                self.put(ch)
            i += 1

    def text(self):
        return '\n'.join(''.join(row).rstrip() for row in self.cells)


class Term:
    def __init__(self, argv, output_to_pipe=False, ignored=(), blocked=(), pending=()):
        # Before the fork: a session directory of this manager's is no older.
        self.started = time.time()
        self.screen = Screen()
        # Everything sent to the terminal: the emulator's private modes are not on the screen.
        self.raw = bytearray()
        # The pipe is not the terminal, and no reader sees the two interleaved: on one shared
        # screen a line from one moves the other's text, and can split it across the wrap.
        self.piped = Screen(onlcr=True) if output_to_pipe else None
        self.rc = None
        # The manager's stdout and stderr on a pipe the test can close, with the terminal
        # left as it is: its output can then go while the terminal stays.
        self.out = None
        if output_to_pipe:
            r, w = os.pipe()
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            # What a login terminal gives a program. A harness started with `&` or nohup
            # ignores INT, QUIT and HUP, and the manager keeps an ignore it inherits.
            for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGHUP):
                signal.signal(sig, signal.SIG_DFL)
            for sig in ignored:
                signal.signal(sig, signal.SIG_IGN)
            # exec keeps the mask, and a supervisor that waits on signals blocks some.
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
            # exec keeps what is pending too: sent between a supervisor's fork and its exec.
            for sig in pending:
                os.kill(os.getpid(), sig)
            os.environ['TERM'] = 'xterm-256color'
            # A failed exec must not leave a second harness running the legs.
            try:
                if output_to_pipe:
                    os.dup2(w, 1)
                    os.dup2(w, 2)
                    os.close(r)
                    os.close(w)
                os.execv(argv[0], argv)
            finally:
                os._exit(127)
        if output_to_pipe:
            os.close(w)
            self.out = r
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLS, 0, 0))

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return
            fds = [self.fd] + ([self.out] if self.out is not None else [])
            ready, _, _ = select.select(fds, [], [], min(left, 0.1))
            if self.out is not None and self.out in ready:
                data = os.read(self.out, 65536)
                if data:
                    self.piped.feed(data)
                else:
                    self.cut_output()
            if self.fd in ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    data = b''
                if not data:
                    return
                self.raw += data
                self.screen.feed(data)

    def cut_output(self):
        """From here on, each write to the manager's stdout or stderr fails with EPIPE."""
        if self.out is not None:
            os.close(self.out)
            self.out = None

    def send(self, keys):
        os.write(self.fd, keys)

    def expect(self, pattern, timeout=30):
        end = time.monotonic() + timeout
        rx = re.compile(pattern)
        while time.monotonic() < end:
            self.pump(0.1)
            if self.showing(rx):
                return
        raise Failure(f'the screen never showed {pattern!r} in {timeout} s')

    def showing(self, rx):
        return any(rx.search(s.text()) for s in (self.screen, self.piped) if s is not None)

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
            # TERM is blocked while it starts; there a hangup ends it, at the prompt too.
            try:
                os.kill(self.pid, signal.SIGTERM)
                if not self.exited(15):
                    session = session_dir_of(self.pid, wait=0) or SESSION_DIRS.get(self.pid)
                    os.close(self.fd)
                    end = time.monotonic() + 15
                    while os.waitpid(self.pid, os.WNOHANG)[0] == 0:
                        if time.monotonic() > end:
                            os.kill(self.pid, signal.SIGKILL)
                            os.waitpid(self.pid, 0)
                            # A KILL leaves the directory, outside the run's temporary root.
                            for d in {session, *session_dir_guesses(self.pid, self.started)} - {None}:
                                shutil.rmtree(d, ignore_errors=True)
                            break
                        time.sleep(0.1)
            except (OSError, ChildProcessError):
                pass
            self.rc = -9
        # A manager that strands its daemons fails its own leg. Here it must not also fail the next
        # leg, which needs the volume these still hold.
        # mkdtemp's six characters follow the pid.
        session = f'stratum-{self.pid}-[^/]*/'
        for pid in session_daemons(session):
            os.kill(int(pid), signal.SIGTERM)
        end = time.monotonic() + 30
        while session_daemons(session) and time.monotonic() < end:
            time.sleep(0.2)

    def show(self, label):
        if SHOW:
            print(f'--- {label}\n{self.screen.text()}\n---', flush=True)
            if self.piped is not None:
                print(f'--- {label}, the pipe\n{self.piped.text()}\n---', flush=True)


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


# Every checking daemon, since a leg can fail while one is running. Each also holds
# the read end of this pipe, as the manager's daemons hold the manager's, so none
# outlives a harness killed before its finally runs, by a timeout's alarm say.
SERVED = []
LIFELINE_R, LIFELINE_W = os.pipe()


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
                                     text=True, pass_fds=(LIFELINE_R,),
                                     env=dict(os.environ, STRATUM_LIFELINE_FD=str(LIFELINE_R)))
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


def daemons_of(pattern):
    return subprocess.run(['pgrep', '-f', pattern], capture_output=True, text=True).stdout.split()


def session_daemons(session):
    # With its slash, stratum-1234 does not also match stratum-12345.
    return daemons_of(session.rstrip('/') + '/')


# Each manager's session directory as session_dir_of last found it, for when its host-fs has gone.
SESSION_DIRS = {}


def session_dir_of(pid, wait=10):
    """The manager's session directory, read off its host-fs's --listen: worked out from the
    environment instead, it would differ from std's on macOS with TMPDIR unset."""
    end = time.monotonic() + wait
    while True:
        # -ww: the --listen comes last, and an exported COLUMNS would cut the line before it.
        r = subprocess.run(['ps', '-ww', '-A', '-o', 'ppid=,command='], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            ppid, _, command = line.strip().partition(' ')
            m = re.search(r' host-fs .* --listen (.+)/host-fs\.sock', f' {command.strip()}')
            if ppid == str(pid) and m:
                SESSION_DIRS[pid] = m.group(1)
                return m.group(1)
        if time.monotonic() >= end:
            return None
        time.sleep(0.1)


def session_dir_guesses(pid, since):
    """Where the directory would be, from the environment alone: for one whose host-fs has gone.
    std's temporary directory on macOS with TMPDIR unset is the user's own, not Python's /tmp.
    Only one made since `since`: a manager ended by SIGKILL leaves its own, and pids come round."""
    bases = {os.environ.get('XDG_RUNTIME_DIR'), os.environ.get('TMPDIR'), tempfile.gettempdir()}
    if sys.platform == 'darwin':
        r = subprocess.run(['getconf', 'DARWIN_USER_TEMP_DIR'], capture_output=True, text=True)
        bases.add(r.stdout.strip() if r.returncode == 0 else None)
    bases -= {None, ''}
    found = {d for b in bases for d in glob.glob(f"{b.rstrip('/')}/stratum-{pid}-*") if os.path.isdir(d)}
    # The change time, which no one sets by hand; a second's slack for a coarse file clock.
    return {d for d in found if os.stat(d).st_ctime >= since - 1}


def resize_leg(stratum, vol, host, root):
    """A resize is drawn at once, whatever mask the manager's parent left: with WINCH blocked
    the screen would keep its old size until the next key."""
    narrow = COLS - 20
    for how, blocked in (('a resize', ()), ('a resize, WINCH blocked by its parent', (signal.SIGWINCH,))):
        term = Term([stratum, 'tui', '--vol', vol.v, '--host', host], blocked=blocked)
        try:
            term.expect(r'Passphrase for')
            term.send(PASS.encode() + ENTER)
            term.expect(r'from_vol\.txt', timeout=60)
            # Quiet first: the last of the start's own draws would read the new size anyway.
            quiet_by = time.monotonic() + 15
            shown = term.screen.text()
            while time.monotonic() < quiet_by:
                term.pump(1.5)
                if term.screen.text() == shown:
                    break
                shown = term.screen.text()
            else:
                raise Failure(f'{how}: the screen never went quiet: it proves nothing')
            if not any(row[narrow:].strip() for row in term.screen.text().split('\n')):
                raise Failure(f'{how}: nothing drawn past column {narrow} before the resize: it proves nothing')
            fcntl.ioctl(term.fd, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, narrow, 0, 0))
            end = time.monotonic() + 5
            drawn = False
            while not drawn and time.monotonic() < end:
                term.pump(0.2)
                rows = term.screen.text().split('\n')
                drawn = any(r.strip() for r in rows) and not any(r[narrow:].strip() for r in rows)
            record(drawn, f'{how}: the screen was drawn again at its new width',
                   f'{how}: the screen kept its old width')
        finally:
            term.kill()


def death_legs(stratum, vol, host, root):
    """However the manager ends, the volume must not stay unlocked behind it."""
    term_ = lambda t: os.kill(t.pid, signal.SIGTERM)
    ends = (('SIGTERM', term_, ()),
            ('SIGINT', lambda t: os.kill(t.pid, signal.SIGINT), ()),
            ('SIGKILL', lambda t: os.kill(t.pid, signal.SIGKILL), ()),
            ('its terminal closing', lambda t: os.close(t.fd), ()),
            # The screen must not take on the mask its parent left: TERM would never come.
            ('SIGTERM, blocked by its parent', term_, (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)))
    for i, (how, end, blocked) in enumerate(ends):
        env_file = f'{root}/env-death{i}'
        term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file],
                    blocked=blocked)
        closed = False
        try:
            term.expect(r'Passphrase for')
            term.send(PASS.encode() + ENTER)
            term.expect(r'from_vol\.txt', timeout=60)
            session = os.path.dirname(read_env(env_file)['STRATUMD_SOCK'])
            # The control: the same search finds them while the manager lives.
            before = session_daemons(session)
            if len(before) < 3:
                raise Failure(f'the search finds {before} before {how}: it proves nothing')
            end(term)
            closed = how == 'its terminal closing'
            limit = time.monotonic() + 30
            left = before
            while left and time.monotonic() < limit:
                time.sleep(0.2)
                left = session_daemons(session)
            record(not left, f'{how}: the daemons stopped and the volume locked',
                   f'{how}: daemons {left} still serve the volume, unlocked, with no manager')
            if how.startswith(('SIGTERM', 'SIGINT')):
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
            else:
                # Nothing runs on a KILL to remove it, and it lies outside the run's root.
                shutil.rmtree(session, ignore_errors=True)
            for pid in left:
                os.kill(int(pid), signal.SIGTERM)
            limit = time.monotonic() + 30
            while session_daemons(session) and time.monotonic() < limit:
                time.sleep(0.2)
            vol.serve()
            vol.stop()
            print(f'ok: after {how} the volume mounts and unmounts cleanly', flush=True)
        finally:
            if not closed:
                term.kill()


def output_gone_leg(stratum, vol, host, root):
    """Its output going, as it does when its terminal closes, but with no watcher to race:
    the terminal stays, so only the UI thread can see it. Whatever the manager's last
    write fails on, it must not panic past the code that puts the session away."""
    how = 'its output going'
    env_file = f'{root}/env-output-gone'
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file],
                output_to_pipe=True)
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'from_vol\.txt', timeout=60)
        session = os.path.dirname(read_env(env_file)['STRATUMD_SOCK'])
        before = session_daemons(session)
        if len(before) < 3:
            raise Failure(f'the search finds {before} before {how}: it proves nothing')
        term.cut_output()
        # Tab moves the focus, which always draws, into the closed pipe. Down on a
        # panel's last entry does nothing, and the leg would wait on a chance redraw.
        term.send(TAB)
        ended = term.exited(30)
        # Its draw fails, and that error is its end: rc 1. A panic would be 101.
        record(ended and term.rc == 1, f'{how}: the manager ended on the failed draw, rc 1',
               f'{how}: the manager ended={ended} rc={term.rc}')
        limit = time.monotonic() + 30
        left = session_daemons(session)
        while left and time.monotonic() < limit:
            time.sleep(0.2)
            left = session_daemons(session)
        record(not left, f'{how}: the daemons stopped and the volume locked',
               f'{how}: daemons {left} still serve the volume, unlocked, with no manager')
        record(not os.path.exists(session), f'{how}: the session directory is gone',
               f'{how}: the session directory stayed')
        for pid in left:
            os.kill(int(pid), signal.SIGTERM)
        limit = time.monotonic() + 30
        while session_daemons(session) and time.monotonic() < limit:
            time.sleep(0.2)
        vol.serve()
        vol.stop()
        print(f'ok: after {how} the volume mounts and unmounts cleanly', flush=True)
    finally:
        term.kill()


def stuck_daemon_leg(stratum, vol, host, root):
    """A daemon that does not stop on SIGTERM is killed after 30 s. The manager says so on its
    stderr, and with its output gone that must not panic it before it has put the rest away."""
    how = 'a daemon stuck, the output gone'
    env_file = f'{root}/env-stuck'
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file],
                output_to_pipe=True)
    stuck = None
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'from_vol\.txt', timeout=60)
        session = os.path.dirname(read_env(env_file)['STRATUMD_SOCK'])
        before = session_daemons(session)
        host_fs = [p for p in before
                   if ' host-fs ' in subprocess.run(['ps', '-ww', '-o', 'command=', '-p', p],
                                                    capture_output=True, text=True).stdout]
        if len(before) < 3 or len(host_fs) != 1:
            raise Failure(f'the search finds {before}, host-fs {host_fs}, before {how}: it proves nothing')
        # host-fs is stopped last, so slate and stratumd have stopped before the message.
        stuck = int(host_fs[0])
        os.kill(stuck, signal.SIGSTOP)
        term.cut_output()
        os.kill(term.pid, signal.SIGTERM)
        began = time.monotonic()
        ended = term.exited(100)
        took = time.monotonic() - began
        record(ended and term.rc == 0, f'{how}: the manager killed it and ended cleanly',
               f'{how}: the manager ended={ended} rc={term.rc}')
        # Only the 30 s deadline in stop_child ends a stop of a stopped process.
        record(30 <= took < 90, f'{how}: the manager waited out its 30 s first ({took:.1f} s)',
               f'{how}: the manager ended {took:.1f} s after the SIGTERM, not after the 30 s deadline')
        left = session_daemons(session)
        record(not left, f'{how}: no daemon is left', f'{how}: daemons {left} still run, with no manager')
        record(not os.path.exists(session), f'{how}: the session directory is gone',
               f'{how}: the session directory stayed')
        for pid in left:
            os.kill(int(pid), signal.SIGKILL)
        limit = time.monotonic() + 30
        while session_daemons(session) and time.monotonic() < limit:
            time.sleep(0.2)
        vol.serve()
        vol.stop()
        print(f'ok: after {how} the volume mounts and unmounts cleanly', flush=True)
    finally:
        if stuck is not None:
            try:
                os.kill(stuck, signal.SIGCONT)
            except ProcessLookupError:
                pass
        term.kill()


def headless_output_gone_leg(stratum, vol, host, root):
    """Headless, the manager prints a line when the signal that ends it comes. After a HUP its
    stderr may have gone with the terminal, and that line must not panic it before the stop."""
    how = 'headless, the output gone'
    env_file = f'{root}/env-headless'
    term = Term([stratum, 'tui', '--headless', '--vol', vol.v, '--host', host,
                 '--print-env-to', env_file], output_to_pipe=True)
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'send SIGTERM', timeout=60)
        # In front, done with the terminal once up: echo back then, not only at the end.
        modes = tty_modes(term)
        record(all(modes.values()), f'{how}: once up, the terminal was given back as it was',
               f'{how}: once up, the terminal is {modes}')
        session = os.path.dirname(read_env(env_file)['STRATUMD_SOCK'])
        before = session_daemons(session)
        if len(before) < 3:
            raise Failure(f'the search finds {before} before {how}: it proves nothing')
        term.cut_output()
        os.kill(term.pid, signal.SIGTERM)
        ended = term.exited(60)
        record(ended and term.rc == 0, f'{how}: the manager ended cleanly',
               f'{how}: the manager ended={ended} rc={term.rc}')
        limit = time.monotonic() + 30
        left = session_daemons(session)
        while left and time.monotonic() < limit:
            time.sleep(0.2)
            left = session_daemons(session)
        record(not left, f'{how}: the daemons stopped and the volume locked',
               f'{how}: daemons {left} still serve the volume, unlocked, with no manager')
        record(not os.path.exists(session), f'{how}: the session directory is gone',
               f'{how}: the session directory stayed')
        for pid in left:
            os.kill(int(pid), signal.SIGTERM)
        limit = time.monotonic() + 30
        while session_daemons(session) and time.monotonic() < limit:
            time.sleep(0.2)
        vol.serve()
        vol.stop()
        print(f'ok: after {how} the volume mounts and unmounts cleanly', flush=True)
    finally:
        term.kill()


def headless_int_ignored_leg(stratum, vol, host, root):
    """Started as a shell's `&` starts it, with INT ignored: Ctrl-C at the terminal is not for it.
    Blocked since startup, an ignored INT stays pending on Linux, and sigwait would take it."""
    how = 'headless, INT ignored'
    env_file = f'{root}/env-headless-int'
    term = Term([stratum, 'tui', '--headless', '--vol', vol.v, '--host', host, '--print-env-to', env_file],
                ignored=(signal.SIGINT,))
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'send SIGTERM', timeout=60)
        session = os.path.dirname(read_env(env_file)['STRATUMD_SOCK'])
        term.send(b'\x03')
        stopped = term.exited(3)
        record(not stopped, f'{how}: Ctrl-C left it running', f'{how}: Ctrl-C stopped it, rc {term.rc}')
        if not stopped:
            # The control: the same manager does stop when asked.
            os.kill(term.pid, signal.SIGTERM)
            ended = term.exited(60)
            record(ended and term.rc == 0 and 'caught signal 15' in term.screen.text(),
                   f'{how}: SIGTERM then stopped it cleanly', f'{how}: after SIGTERM ended={ended} rc={term.rc}')
        limit = time.monotonic() + 30
        while session_daemons(session) and time.monotonic() < limit:
            time.sleep(0.2)
    finally:
        term.kill()


def prompt_end_legs(stratum, vol, host, root):
    """At the passphrase prompt the session directory and host-fs already exist. Ended
    there, by its terminal closing, by Ctrl-\\ or by a QUIT, the manager must not leave them."""
    def close(term):
        os.close(term.fd)

    def quit_key(term):
        # A key at the prompt, as in the screen's passphrase dialog, not a signal: it gives up
        # at once, with no Enter.
        term.send(b'\x1c')

    def quit_sent(term):
        # A QUIT sent by kill does not end the read; the passphrase and Enter do.
        os.kill(term.pid, signal.SIGQUIT)
        time.sleep(0.5)
        try:
            term.send(PASS.encode() + ENTER)
        except OSError:
            pass  # QUIT's default action has ended the manager, and the terminal's other side with it

    def hup_sent(term):
        # A HUP sent by kill, the terminal still there, as a supervisor can send it.
        os.kill(term.pid, signal.SIGHUP)
        time.sleep(0.5)
        try:
            term.send(PASS.encode() + ENTER)
        except OSError:
            pass

    def typed_then_close(term):
        # Typed, never submitted. With HUP ignored, as nohup leaves it, only the read's
        # end can tell the manager the terminal has gone.
        term.send(PASS.encode())
        time.sleep(0.5)
        os.close(term.fd)

    cases = (('its terminal closing at the prompt', close, (), ()),
             ('Ctrl-\\ at the prompt', quit_key, (), ()),
             ('a QUIT sent at the prompt', quit_sent, (), ()),
             # Blocked, it would wait for the screen, after the volume was unlocked.
             ('a QUIT sent at the prompt, blocked by its parent', quit_sent, (), (signal.SIGQUIT,)),
             ('a HUP sent at the prompt, blocked by its parent', hup_sent, (), (signal.SIGHUP,)),
             ('its terminal closing before Enter, HUP ignored', typed_then_close, (signal.SIGHUP,), ()))
    for i, (how, end, ignored, blocked) in enumerate(cases):
        env_file = f'{root}/env-prompt{i}'
        term = Term([stratum, 'tui', '--vol', vol.v, '--host', host, '--print-env-to', env_file],
                    ignored=ignored, blocked=blocked)
        closed = False
        try:
            term.expect(r'Passphrase for')
            session = session_dir_of(term.pid)
            before = session_daemons(session) if session else []
            if not session or not os.path.isdir(session) or not before:
                raise Failure(f'{how}: session directory {session}, daemons {before}, '
                              'before the end: it proves nothing')
            end(term)
            closed = end in (close, typed_then_close)
            if closed:
                limit = time.monotonic() + 30
                while term.rc is None and time.monotonic() < limit:
                    pid, status = os.waitpid(term.pid, os.WNOHANG)
                    if pid:
                        term.rc = os.waitstatus_to_exitcode(status)
                    else:
                        time.sleep(0.1)
            else:
                # It reads the terminal as it waits: on macOS an exit waits for the
                # terminal's output to be read.
                term.exited(30)
            rc = term.rc
            # An error return is rc 1; HUP's or QUIT's default action would be -1 or -3.
            record(rc == 1, f'{how}: the manager ended with an error, rc 1', f'{how}: the manager ended with rc {rc}')
            if not closed:
                # Ended at the prompt, not by stratumd's start wait a moment later: the
                # volume was never unlocked with a passphrase typed only to get out.
                want = 'prompt was given up' if end is quit_key else 'asked to stop at the passphrase prompt'
                said = want in term.screen.text()
                record(said, f'{how}: it stopped at the prompt, before stratumd',
                       f'{how}: it did not say {want!r}')
            limit = time.monotonic() + 30
            left = session_daemons(session)
            while left and time.monotonic() < limit:
                time.sleep(0.2)
                left = session_daemons(session)
            record(not left, f'{how}: host-fs stopped', f'{how}: daemons {left} still run, with no manager')
            record(not os.path.exists(session), f'{how}: the session directory is gone',
                   f'{how}: the session directory stayed')
            # Written once slate is up: its absence says the session ended before that. That it
            # ended at the prompt, before stratumd, is the rc and the message's to say.
            record(not os.path.exists(env_file), f'{how}: the session ended before slate',
                   f'{how}: the session reached slate, so the volume was unlocked')
            for pid in left:
                os.kill(int(pid), signal.SIGTERM)
        finally:
            if closed and term.rc is None:
                try:
                    os.kill(term.pid, signal.SIGKILL)
                    os.waitpid(term.pid, 0)
                except (OSError, ChildProcessError):
                    pass
                term.rc = -9
            if not closed:
                term.kill()


def missing_binary_leg(stratum, vol, host, root):
    """The manager starts each daemon from its own binary. If that has gone by the time
    stratumd starts, the start fails, and host-fs and the directory must not stay."""
    how = 'its binary gone before stratumd starts'
    copy = f'{root}/stratum-copy'
    shutil.copy2(stratum, copy)
    term = Term([copy, 'tui', '--vol', vol.v, '--host', host])
    try:
        term.expect(r'Passphrase for')
        session = session_dir_of(term.pid)
        before = session_daemons(session) if session else []
        if not session or not os.path.isdir(session) or not before:
            raise Failure(f'{how}: session directory {session}, daemons {before}, '
                          'before the end: it proves nothing')
        os.unlink(copy)
        term.send(PASS.encode() + ENTER)
        ended = term.exited(30)
        # Which failure: the spawn, not some other one.
        said = 'spawn stratumd' in term.screen.text()
        record(ended and term.rc == 1 and said, f'{how}: the manager ended on the failed spawn',
               f'{how}: the manager ended={ended} rc={term.rc}, said spawn stratumd={said}')
        limit = time.monotonic() + 30
        left = session_daemons(session)
        while left and time.monotonic() < limit:
            time.sleep(0.2)
            left = session_daemons(session)
        record(not left, f'{how}: host-fs stopped', f'{how}: daemons {left} still run, with no manager')
        record(not os.path.exists(session), f'{how}: the session directory is gone',
               f'{how}: the session directory stayed')
        for pid in left:
            os.kill(int(pid), signal.SIGTERM)
    finally:
        term.kill()
        if os.path.exists(copy):
            os.unlink(copy)

def start_wait_stop_leg(stratum, vol, host, root):
    """Ctrl-\\ in stratumd's start, a wait of up to 60 s: the stop ends the session there, and is
    named as a stop, not as a daemon that failed to start. stratumd is held stopped from the
    moment it appears, so no socket can end the wait first, however fast the key comes."""
    how = 'Ctrl-\\ in the stratumd start'
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host])
    try:
        term.expect(r'Passphrase for')
        session = session_dir_of(term.pid)
        if not session:
            raise Failure(f'{how}: no session directory found: it proves nothing')
        sock = f'{session}/stratumd.sock'
        term.send(PASS.encode() + ENTER)
        limit = time.monotonic() + 10
        held = daemons_of(sock)
        while not held and time.monotonic() < limit:
            # Read as a terminal does: a terminal given back with TCSAFLUSH waits for its output
            # to be read.
            term.pump(0.005)
            held = daemons_of(sock)
        for pid in held:
            os.kill(int(pid), signal.SIGSTOP)
        if not held or os.path.exists(sock):
            raise Failure(f'{how}: stratumd held={held}, its socket made={os.path.exists(sock)} '
                          'before the stop: it proves nothing')
        # The passphrase taken, the key being derived: cooked, so Ctrl-\ works, but a key typed
        # now, the passphrase again say, is not shown.
        lflag = termios.tcgetattr(term.fd)[3]
        modes = {m: bool(lflag & getattr(termios, m)) for m in ('ECHO', 'ICANON', 'ISIG')}
        record(modes == {'ECHO': False, 'ICANON': True, 'ISIG': True},
               f'{how}: echo held off, the terminal cooked, while stratumd starts',
               f'{how}: the terminal while stratumd starts: {modes}')
        term.send(b'again')
        term.pump(0.3)
        record(not term.showing(re.compile('again')), f'{how}: a key typed then is not shown',
               f'{how}: a key typed while stratumd started was shown')
        term.send(b'\x1c')
        asked = time.monotonic()
        # Past the 60 s start timeout: a wait that does not end on the stop ends there instead,
        # and the stop, seen afterwards, would still be named.
        ended = term.exited(90)
        took = time.monotonic() - asked
        said = 'asked to stop while stratumd started' in term.screen.text()
        record(ended and term.rc == 1 and said and took < 30,
               f'{how}: the manager stopped in the wait, rc 1, in {took:.1f} s',
               f'{how}: the manager ended={ended} rc={term.rc} after {took:.1f} s, named the stop={said}')
        if ended:
            lflag = termios.tcgetattr(term.fd)[3]
            modes = {m: bool(lflag & getattr(termios, m)) for m in ('ECHO', 'ICANON', 'ISIG')}
            record(all(modes.values()), f'{how}: the terminal was given back with echo',
                   f'{how}: the terminal was left {modes}')
        for pid in held:
            try:
                os.kill(int(pid), signal.SIGCONT)
            except ProcessLookupError:
                pass
        limit = time.monotonic() + 30
        left = session_daemons(session)
        while left and time.monotonic() < limit:
            time.sleep(0.2)
            left = session_daemons(session)
        record(not left, f'{how}: the daemons stopped', f'{how}: daemons {left} still run, with no manager')
        record(not os.path.exists(session), f'{how}: the session directory is gone',
               f'{how}: the session directory stayed')
        for pid in left:
            os.kill(int(pid), signal.SIGTERM)
    finally:
        term.kill()


def pending_hup_leg(stratum, vol, host, root):
    """A HUP its parent blocked and that came before exec: the manager starts with it pending.
    It must ask to stop, as one sent later does, not end by the default action."""
    how = 'a HUP pending at the start, blocked by its parent'
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', host],
                blocked=(signal.SIGHUP,), pending=(signal.SIGHUP,))
    try:
        ended = term.exited(30)
        if not ended and term.showing(re.compile('Passphrase for')):
            # The stop came after host-fs was up: it takes effect at Enter.
            term.send(PASS.encode() + ENTER)
            ended = term.exited(30)
        said = 'asked to stop' in term.screen.text()
        record(ended and term.rc == 1 and said, f'{how}: the manager asked to stop, rc 1',
               f'{how}: the manager ended={ended} rc={term.rc}, said "asked to stop"={said}')
        left = sorted(session_dir_guesses(term.pid, term.started))
        record(not left, f'{how}: no session directory stayed', f'{how}: {left} stayed')
    finally:
        term.kill()


# A shell's job control, in one pty session: the job in a group of its own, given the terminal
# to start; SIGUSR1 takes the terminal back, as Ctrl-Z then `bg` leave it; SIGUSR2 gives it
# back and continues the job, as `fg`. Only a parent in the same session lets a job stop on
# SIGTTOU: the harness's own child is a session leader, whose group is orphaned. --tostop sets
# `stty tostop` first; --editor, as bash with readline does, puts back the mode it saved at the
# start with echo and canonical mode off each time it takes the terminal, and that mode whole
# when it gives the terminal at `fg`, where a shell such as dash leaves the mode as it finds
# it. As bash and zsh do, `fg` continues the job only if it is stopped. --behind starts the job
# behind, as `&` does.
# --report=PATH appends each stop of the job, with its signal, and each continue to PATH: on
# the screen each would overwrite the last. A continue the job stops again just after may be
# reported as the stop alone.
JOB_SHELL = r"""
import os, signal, subprocess, sys, termios
flags = set()
while sys.argv[1].startswith('--'):
    flags.add(sys.argv.pop(1))
report = None
for f in flags:
    if f.startswith('--report='):
        report = os.open(f[len('--report='):], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
if '--tostop' in flags:
    a = termios.tcgetattr(0)
    a[3] |= termios.TOSTOP
    termios.tcsetattr(0, termios.TCSANOW, a)
sane = termios.tcgetattr(0)
editor = termios.tcgetattr(0)
editor[3] &= ~(termios.ECHO | termios.ICANON)
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(w)
    os.setpgid(0, 0)
    os.read(r, 1)
    signal.signal(signal.SIGTTOU, signal.SIG_DFL)
    os.execv(sys.argv[1], sys.argv[1:])
os.close(r)
try:
    os.setpgid(pid, pid)
except OSError:
    pass
if '--behind' in flags:
    if '--editor' in flags:
        termios.tcsetattr(0, termios.TCSANOW, editor)
else:
    os.tcsetpgrp(0, pid)
os.write(w, b'x')
os.close(w)
def behind(*_):
    os.tcsetpgrp(0, os.getpgrp())
    if '--editor' in flags:
        termios.tcsetattr(0, termios.TCSANOW, editor)
    os.write(1, b'[behind %d]\r\n' % (os.tcgetpgrp(0) == os.getpgrp()))
def front(*_):
    if '--editor' in flags:
        termios.tcsetattr(0, termios.TCSANOW, sane)
    os.tcsetpgrp(0, pid)
    state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout
    if 'T' in state:
        os.killpg(pid, signal.SIGCONT)
def forward(sig, _):
    os.kill(pid, sig)
signal.signal(signal.SIGUSR1, behind)
signal.signal(signal.SIGUSR2, front)
for sig in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(sig, forward)
while True:
    _, status = os.waitpid(pid, 0 if report is None else os.WUNTRACED | os.WCONTINUED)
    if os.WIFSTOPPED(status):
        os.write(report, b'stopped %d\n' % os.WSTOPSIG(status))
    elif os.WIFCONTINUED(status):
        os.write(report, b'continued\n')
    else:
        break
if '--read-after' in flags:
    import time
    os.tcsetpgrp(0, os.getpgrp())
    a = termios.tcgetattr(0)
    a[3] &= ~termios.ICANON
    a[6][termios.VMIN], a[6][termios.VTIME] = 0, 0
    termios.tcsetattr(0, termios.TCSANOW, a)
    time.sleep(0.3)
    try:
        left = os.read(0, 65536)
    except OSError:
        left = b''
    os.write(1, b'[left %d]\r\n' % len(left))
sys.exit(os.waitstatus_to_exitcode(status) & 0xff)
"""


# The shell's line-editor mode, as JOB_SHELL --editor sets it: distinct from the terminal's own
# (all three on) and from the hold's (echo off, canonical).
EDITOR_MODES = {'ECHO': False, 'ICANON': False, 'ISIG': True}


def tty_modes(term):
    lflag = termios.tcgetattr(term.fd)[3]
    return {m: bool(lflag & getattr(termios, m)) for m in ('ECHO', 'ICANON', 'ISIG')}


def state_of(pid):
    return subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()


def cpu_seconds(pid):
    """The user and system time `pid` has had, every thread's."""
    try:
        with open(f'/proc/{pid}/stat') as f:
            fields = f.read().rpartition(')')[2].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
    except FileNotFoundError:
        pass
    # [[dd-]hh:]mm:ss.cc
    spent = subprocess.run(['ps', '-o', 'time=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
    days, _, clock = spent.rpartition('-')
    seconds = 0.0
    for part in clock.split(':'):
        seconds = seconds * 60 + float(part)
    return seconds + (int(days) * 86400 if days else 0)


def wait_state(term, pid, want, timeout):
    """`pid`'s state once it shows `want`, or when the time is up. The terminal is read meanwhile:
    one given back with TCSAFLUSH waits for its output to be read."""
    limit = time.monotonic() + timeout
    state = state_of(pid)
    while want not in state and time.monotonic() < limit:
        term.pump(0.05)
        state = state_of(pid)
    return state


def hold_stratumd(term, how, sock):
    """stratumd held stopped from the moment it appears, deriving the key, its socket not yet
    made, and echo held off: the unlock, which nothing can end first however slow the test."""
    limit = time.monotonic() + 10
    held = daemons_of(sock)
    while not held and time.monotonic() < limit:
        term.pump(0.005)
        held = daemons_of(sock)
    for pid in held:
        os.kill(int(pid), signal.SIGSTOP)
    echo = tty_modes(term)['ECHO']
    if not held or os.path.exists(sock) or echo:
        raise Failure(f'{how}: stratumd held={held}, socket made={os.path.exists(sock)}, echo on={echo}: '
                      'not in the unlock, it proves nothing')
    return held


def job_behind(term, how):
    os.kill(term.pid, signal.SIGUSR1)
    term.expect(r'\[behind \d\]')
    if '[behind 1]' not in term.screen.text():
        raise Failure(f'{how}: the job shell did not take the terminal: it proves nothing')


def wait_quiet(term, how, quiet=1.0, limit=15):
    """Once the screen has written nothing for `quiet` seconds: its start's own draws are over."""
    end = time.monotonic() + limit
    seen = len(term.raw)
    while time.monotonic() < end:
        term.pump(quiet)
        if len(term.raw) == seen:
            return
        seen = len(term.raw)
    raise Failure(f'{how}: the screen never went quiet: it proves nothing')


def wait_until(term, what, timeout):
    """`what()` once true, or when the time is up. The terminal is read meanwhile: one set
    with TCSAFLUSH waits for its output to be read."""
    limit = time.monotonic() + timeout
    got = what()
    while not got and time.monotonic() < limit:
        term.pump(0.05)
        got = what()
    return got


HELD_MODES = {'ECHO': False, 'ICANON': True, 'ISIG': True}
# The emulator's private modes as the shell needs them: the main screen, no mouse reports, the
# cursor shown.
SHELL_PRIVATE = {'1049': 'l', '1000': 'l', '25': 'h'}


# A cell placed: how the screen draws, and nothing a shell or the screen's way out writes.
DRAWN = re.compile(rb'\x1b\[\d+;\d+H')


def private_modes(term):
    """The last set of each private mode the screen uses, as sent to the terminal."""
    last = {}
    for m in re.finditer(rb'\x1b\[\?(1049|1000|25)([hl])', bytes(term.raw)):
        last[m.group(1).decode()] = m.group(2).decode()
    return last
RAW_MODES = {'ECHO': False, 'ICANON': False, 'ISIG': False}


def ctrl_z(term, how, manager):
    """Ctrl-Z while echo is held: the job stops with the terminal given back, echo on (echo held
    off before it is the control, in hold_stratumd)."""
    term.send(b'\x1a')
    state = wait_state(term, manager, 'T', 10)
    if 'T' not in state:
        raise Failure(f'{how}: Ctrl-Z did not stop it, its state {state!r}: it proves nothing')
    modes = tty_modes(term)
    record(all(modes.values()), f'{how}: the terminal was given back at the stop, echo on',
           f'{how}: the terminal at the stop: {modes}')


def continued(term, how, manager):
    if not wait_until(term, lambda: 'T' not in state_of(manager), 10):
        raise Failure(f'{how}: it was not continued: it proves nothing')


def held_again(term, how):
    held = wait_until(term, lambda: tty_modes(term) == HELD_MODES, 5)
    record(held, f'{how}: continued in front, echo is held off again',
           f'{how}: continued in front, the terminal is {tty_modes(term)}')


def headless_behind_leg(stratum, vol, host, root):
    """Headless, under job control while stratumd derives the key. However the unlock ends, it
    must neither stop on SIGTTOU to give the terminal back nor set the mode under the shell,
    which has its own by then; continued in front, echo is held off again; a TERM, a shell's
    `kill %1`, must end it."""
    def moved(term, how, manager):
        job_behind(term, how)
        return False

    def ctrl_z_then_bg(term, how, manager):
        # A shell that keeps no mode of its own, dash say, leaves the one the job had at its stop.
        ctrl_z(term, how, manager)
        job_behind(term, how)
        os.killpg(os.getpgid(manager), signal.SIGCONT)
        return False

    def ctrl_z_then_fg(term, how, manager):
        ctrl_z(term, how, manager)
        os.kill(term.pid, signal.SIGUSR2)
        continued(term, how, manager)
        held_again(term, how)
        return True

    def ctrl_z_bg_then_fg(term, how, manager):
        # The continue alone: nothing stops it on the way back to the front.
        ctrl_z_then_bg(term, how, manager)
        continued(term, how, manager)
        os.kill(term.pid, signal.SIGUSR2)
        held_again(term, how)
        return True

    def tstp_behind(term, how, manager):
        # A stop sent to it behind, as `kill -TSTP %1`: the shell has the terminal, and it is
        # not set under it.
        ctrl_z_then_bg(term, how, manager)
        continued(term, how, manager)
        os.kill(manager, signal.SIGTSTP)
        state = wait_state(term, manager, 'T', 10)
        if 'T' not in state:
            raise Failure(f'{how}: the TSTP did not stop it, its state {state!r}: it proves nothing')
        modes = tty_modes(term)
        record(modes == EDITOR_MODES, f'{how}: stopped behind, the shell\'s mode was left alone',
               f'{how}: stopped behind, the terminal is {modes}, not the shell\'s {EDITOR_MODES}')
        os.killpg(os.getpgid(manager), signal.SIGCONT)
        return False

    # Under `stty tostop` a write from behind stops the job: neither its daemons, each in a group
    # of its own and so never in front, nor the manager behind may write that way.
    cases = (('headless, in front, tostop set', ('--tostop',), PASS, None),
             ('headless, moved behind during the unlock, tostop set', ('--tostop',), PASS, moved),
             ('headless, Ctrl-Z during the unlock, then bg', (), PASS, ctrl_z_then_bg),
             ('headless, Ctrl-Z during the unlock, then fg', (), PASS, ctrl_z_then_fg),
             ('headless, Ctrl-Z during the unlock, bg, then fg', (), PASS, ctrl_z_bg_then_fg),
             ('headless, a TSTP sent behind during the unlock', (), PASS, tstp_behind),
             ('headless, moved behind during the unlock, the passphrase wrong', (), 'not the passphrase', moved))
    for how, flags, passphrase, job in cases:
        term = Term([sys.executable, '-I', '-c', JOB_SHELL, '--editor', *flags, stratum, 'tui', '--headless',
                     '--vol', vol.v, '--host', host])
        manager, held, session = None, [], None
        try:
            term.expect(r'Passphrase for')
            manager = child_running(term.pid, 'tui')
            session = session_dir_of(manager) if manager else None
            if not session:
                raise Failure(f'{how}: manager {manager}, session {session}: it proves nothing')
            term.send(passphrase.encode() + ENTER)
            held = hold_stratumd(term, how, f'{session}/stratumd.sock')
            front = job(term, how, manager) if job else True
            for pid in held:
                os.kill(int(pid), signal.SIGCONT)
            if passphrase == PASS:
                up = wait_until(term, lambda: 'daemons running' in term.screen.text(), 60)
                state = state_of(manager)
                daemons = {pid: state_of(int(pid)) for pid in session_daemons(session)}
                record(up and 'T' not in state, f'{how}: it came up, not stopped for the terminal',
                       f'{how}: up={up}, its state {state!r}, its daemons {daemons}')
                modes = tty_modes(term)
                if front:
                    record(all(modes.values()), f'{how}: once up, the terminal was given back as it was',
                           f'{how}: once up, the terminal is {modes}')
                else:
                    record(modes == EDITOR_MODES, f'{how}: the shell\'s mode was left as the shell set it',
                           f'{how}: the terminal is {modes}, not the shell\'s {EDITOR_MODES}')
                os.kill(manager, signal.SIGTERM)
                ended = term.exited(30)
                record(ended, f'{how}: a TERM ended it', f'{how}: a TERM did not end it')
            else:
                ended = term.exited(60)
                said = bool(re.search(r'(?i)wrong passphrase', term.screen.text()))
                state = '' if ended else state_of(manager)
                record(ended and term.rc == 1 and said, f'{how}: it ended with the error, rc 1',
                       f'{how}: ended={ended} rc={term.rc}, said wrong passphrase={said}, its state {state!r}')
                modes = tty_modes(term)
                record(modes == EDITOR_MODES, f'{how}: the shell\'s mode was left as the shell set it',
                       f'{how}: the terminal is {modes}, not the shell\'s {EDITOR_MODES}')
            limit = time.monotonic() + 30
            left = session_daemons(session)
            while left and time.monotonic() < limit:
                time.sleep(0.2)
                left = session_daemons(session)
            record(not left and not os.path.exists(session), f'{how}: the daemons stopped, the session directory went',
                   f'{how}: daemons {left}, session directory stayed={os.path.exists(session)}')
        except Failure:
            print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
            raise
        finally:
            job_cleanup(term, held, session)


def job_cleanup(term, held, session):
    for pid in held:
        try:
            os.kill(int(pid), signal.SIGCONT)
        except ProcessLookupError:
            pass
    if term.rc is None:
        # As `fg`: a manager stopped behind gives the terminal back, then a TERM ends it.
        try:
            os.kill(term.pid, signal.SIGUSR2)
        except ProcessLookupError:
            pass
        term.pump(1)
    term.kill()
    if session:
        for pid in session_daemons(session):
            os.kill(int(pid), signal.SIGTERM)


def screen_behind_leg(stratum, vol, host, root):
    """The screen, moved behind while stratumd derives the key. It needs the terminal, so it stops
    behind until `fg` and gives the mode back before the screen saves the one it finds: the
    screen's end then leaves the terminal as it was, echo on. Without that, the screen's own mode
    set is what stops behind, and once in front it saves the held mode the job shell left in
    place, and puts that back at its end. A stop asked while it waits behind, a shell's `kill %1`
    or `kill -HUP %1` (each sent with a continue, as a shell sends them to a stopped job), ends it
    there with the terminal left to the shell."""
    def fg_then_quit(term, how, manager):
        os.kill(term.pid, signal.SIGUSR2)
        term.expect(r'MkDir', timeout=60)
        term.send(F10)
        ended = term.exited(60)
        modes = tty_modes(term)
        record(ended and term.rc == 0 and all(modes.values()),
               f'{how}: after fg and F10 the terminal was given back as it was',
               f'{how}: ended={ended} rc={term.rc}, the terminal was left {modes}')

    def asked_to_stop(sig):
        def stop(term, how, manager):
            os.kill(manager, sig)
            os.killpg(os.getpgid(manager), signal.SIGCONT)
            ended = term.exited(30)
            said = 'asked to stop before the screen' in term.screen.text()
            state = '' if ended else state_of(manager)
            record(ended and term.rc == 1 and said, f'{how}: it ended there, rc 1, and said so',
                   f'{how}: ended={ended} rc={term.rc}, said so={said}, its state {state!r}')
            modes = tty_modes(term)
            record(modes == EDITOR_MODES, f'{how}: the shell\'s mode was left as the shell set it',
                   f'{how}: the terminal is {modes}, not the shell\'s {EDITOR_MODES}')
        return stop

    cases = (('the screen, moved behind during the unlock', (), fg_then_quit),
             ('the screen, waiting behind for fg, sent a TERM', ('--editor',), asked_to_stop(signal.SIGTERM)),
             ('the screen, waiting behind for fg, sent a HUP', ('--editor',), asked_to_stop(signal.SIGHUP)))
    for how, flags, then in cases:
        term = Term([sys.executable, '-I', '-c', JOB_SHELL, *flags, stratum, 'tui', '--vol', vol.v, '--host', host])
        manager, held, session = None, [], None
        try:
            term.expect(r'Passphrase for')
            manager = child_running(term.pid, 'tui')
            session = session_dir_of(manager) if manager else None
            if not session:
                raise Failure(f'{how}: manager {manager}, session {session}: it proves nothing')
            term.send(PASS.encode() + ENTER)
            held = hold_stratumd(term, how, f'{session}/stratumd.sock')
            job_behind(term, how)
            for pid in held:
                os.kill(int(pid), signal.SIGCONT)
            state = wait_state(term, manager, 'T', 60)
            if 'T' not in state:
                raise Failure(f'{how}: it never stopped behind, its state {state!r}: it proves nothing')
            then(term, how, manager)
            if session:
                limit = time.monotonic() + 30
                while session_daemons(session) and time.monotonic() < limit:
                    time.sleep(0.2)
                record(not session_daemons(session) and not os.path.exists(session),
                       f'{how}: the daemons stopped, the session directory went',
                       f'{how}: daemons {session_daemons(session)}, session directory stayed={os.path.exists(session)}')
        except Failure:
            print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
            raise
        finally:
            job_cleanup(term, held, session)


def screen_job_control_leg(stratum, vol, host, root):
    """The screen under job control, as vim is. A TSTP from outside (raw mode reads Ctrl-Z as a
    key) puts the terminal back before it stops, and `fg` takes it raw again. Stopped by a STOP,
    which nothing can catch, then continued behind by `bg`, it stops again rather than draw from
    behind; a `kill -HUP %1` there ends it with the terminal left to the shell, not stopped for
    it and not set under it. It never reads or draws from behind, where the kernel would stop it
    inside the call and a HUP could not end it: not with a key waiting at the continue, not with
    the terminal taken from under it running, not with a pass under way at the stop."""
    def tstp_then_fg(term, how, manager):
        os.kill(manager, signal.SIGTSTP)
        state = wait_state(term, manager, 'T', 10)
        if 'T' not in state:
            raise Failure(f'{how}: the TSTP did not stop it, its state {state!r}: it proves nothing')
        modes = tty_modes(term)
        record(all(modes.values()), f'{how}: stopped, the terminal was put back first',
               f'{how}: stopped, the terminal is {modes}')
        os.kill(term.pid, signal.SIGUSR2)
        raw = wait_until(term, lambda: tty_modes(term) == RAW_MODES, 10)
        record(raw, f'{how}: after fg the screen took the terminal again',
               f'{how}: after fg the terminal is {tty_modes(term)}')
        term.send(F10)
        ended = term.exited(60)
        modes = tty_modes(term)
        private = private_modes(term)
        record(ended and term.rc == 0 and all(modes.values()) and private == SHELL_PRIVATE,
               f'{how}: F10 then gave the terminal back as it was',
               f'{how}: ended={ended} rc={term.rc}, the terminal was left {modes}, its private modes {private}')

    report = os.path.join(root, 'job-report')

    def reports():
        try:
            with open(report) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    ttin, ttou = f'stopped {int(signal.SIGTTIN)}', f'stopped {int(signal.SIGTTOU)}'

    def stopped_by_hand(term, how, manager):
        os.kill(manager, signal.SIGSTOP)
        stop = f'stopped {int(signal.SIGSTOP)}'
        if not wait_until(term, lambda: reports() == [stop], 10):
            raise Failure(f'{how}: the shell saw {reports()}, not {[stop]}: it proves nothing')

    def stop_bg_hup(term, how, manager, key=False):
        stopped_by_hand(term, how, manager)
        job_behind(term, how)
        if key:
            # Input for the shell: the screen must not read it from behind.
            term.send(b'x')
        os.killpg(os.getpgid(manager), signal.SIGCONT)
        # It stops again within a tick of the continue, too soon for a poll of its state to see
        # it running. A second stop can only follow a continue, and SIGTTOU is the stop a job
        # behind takes for the terminal.
        again = wait_until(term, lambda: ttou in reports()[1:], 10)
        record(again and ttin not in reports(), f'{how}: continued behind, it stopped again on SIGTTOU rather than draw from behind',
               f'{how}: continued behind, the shell saw {reports()[1:]}, no {ttou!r} alone; its state {state_of(manager)!r}')
        # Left on, the mouse reports would reach the shell as keys while it waits there.
        term.pump(0.3)
        private = private_modes(term)
        record(again and private == SHELL_PRIVATE,
               f'{how}: stopped behind, it had first given back the alternate screen, the mouse and the cursor',
               f'{how}: stopped behind with its private modes {private}, not {SHELL_PRIVATE}')
        hup_ends_it(term, how, manager)

    def behind_running_hup(term, how, manager):
        # The shell takes the terminal from under the screen, running, and input follows at once,
        # inside the screen's wait. Quiet first: a redraw after it would reach the draw's own look.
        wait_quiet(term, how)
        os.kill(term.pid, signal.SIGUSR1)
        limit = time.monotonic() + 10
        while os.tcgetpgrp(term.fd) != term.pid and time.monotonic() < limit:
            pass
        term.send(b'x')
        term.expect(r'\[behind \d\]')
        if '[behind 1]' not in term.screen.text():
            raise Failure(f'{how}: the job shell did not take the terminal: it proves nothing')
        stopped = wait_until(term, lambda: ttou in reports(), 10)
        record(stopped and ttin not in reports(), f'{how}: it stopped on SIGTTOU rather than read from behind',
               f'{how}: the shell saw {reports()}, no {ttou!r} alone; its state {state_of(manager)!r}')
        hup_ends_it(term, how, manager)

    def mid_pass_bg_hup(term, how, manager):
        # slate held stopped: a resize starts a pass that waits on it, before its draw. Stopped
        # there and continued behind, then slate let go, the pass must not draw from behind; under
        # tostop such a draw would stop it inside the write.
        slate = child_running(manager, 'slate')
        if slate is None:
            raise Failure(f'{how}: no slate under the manager: it proves nothing')
        # Quiet first: a start-up draw read after the resize would look like the resize's.
        wait_quiet(term, how)
        held.append(slate)
        os.kill(slate, signal.SIGSTOP)
        if 'T' not in wait_state(term, slate, 'T', 10):
            raise Failure(f'{how}: slate did not stop: it proves nothing')
        resized = len(term.raw)
        fcntl.ioctl(term.fd, termios.TIOCSWINSZ, struct.pack('HHHH', ROWS, COLS - 20, 0, 0))
        term.pump(1)
        if DRAWN.search(bytes(term.raw[resized:])):
            raise Failure(f'{how}: the resize was drawn with slate stopped, so no pass waits on it: it proves nothing')
        stopped_by_hand(term, how, manager)
        job_behind(term, how)
        behind = len(term.raw)
        os.killpg(os.getpgid(manager), signal.SIGCONT)
        # macOS reports no continue to the shell: its state says it.
        if not wait_until(term, lambda: 'T' not in state_of(manager), 10):
            raise Failure(f'{how}: not continued, its state {state_of(manager)!r}: it proves nothing')
        os.kill(slate, signal.SIGCONT)
        again = wait_until(term, lambda: ttou in reports()[1:], 10)
        drawn = DRAWN.search(bytes(term.raw[behind:]))
        record(again and not drawn, f'{how}: the pass drew nothing from behind, and it stopped on SIGTTOU',
               f'{how}: drawn from behind={bool(drawn)}, the shell saw {reports()}; its state {state_of(manager)!r}')
        hup_ends_it(term, how, manager)

    def hup_ends_it(term, how, manager):
        os.kill(manager, signal.SIGHUP)
        os.killpg(os.getpgid(manager), signal.SIGCONT)
        ended = term.exited(30)
        state = '' if ended else state_of(manager)
        record(ended, f'{how}: a HUP ended it behind', f'{how}: a HUP did not end it, its state {state!r}')
        modes = tty_modes(term)
        record(modes == EDITOR_MODES, f'{how}: the shell\'s mode was left as the shell set it',
               f'{how}: the terminal is {modes}, not the shell\'s {EDITOR_MODES}')
        # The mode is the shell's; the alternate screen, the mouse reports and the hidden
        # cursor are the screen's, and only the screen takes them back.
        private = private_modes(term)
        record(private == SHELL_PRIVATE, f'{how}: it left the main screen, mouse reports off, the cursor shown',
               f'{how}: its private modes were left {private}, not {SHELL_PRIVATE}')

    held = []
    cases = (('the screen, a TSTP from outside, then fg', (), tstp_then_fg),
             ('the screen, a STOP, bg, then kill -HUP', ('--editor', f'--report={report}'), stop_bg_hup),
             ('the screen, tostop set, a STOP, bg, then kill -HUP', ('--editor', '--tostop', f'--report={report}'),
              stop_bg_hup),
             ('the screen, a STOP, bg with a key waiting, then kill -HUP', ('--editor', f'--report={report}'),
              lambda term, how, manager: stop_bg_hup(term, how, manager, key=True)),
             ('the screen, put behind running with a key waiting, then kill -HUP', ('--editor', f'--report={report}'),
              behind_running_hup),
             ('the screen, tostop set, a STOP mid-pass, bg, then kill -HUP', ('--editor', '--tostop', f'--report={report}'),
              mid_pass_bg_hup))
    for how, flags, then in cases:
        if os.path.exists(report):
            os.unlink(report)
        held.clear()
        term = Term([sys.executable, '-I', '-c', JOB_SHELL, *flags, stratum, 'tui', '--vol', vol.v, '--host', host])
        manager, session = None, None
        try:
            term.expect(r'Passphrase for')
            manager = child_running(term.pid, 'tui')
            session = session_dir_of(manager) if manager else None
            term.send(PASS.encode() + ENTER)
            term.expect(r'MkDir', timeout=60)
            if tty_modes(term) != RAW_MODES:
                raise Failure(f'{how}: the screen is up but the terminal is {tty_modes(term)}: it proves nothing')
            then(term, how, manager)
        except Failure:
            print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
            raise
        finally:
            job_cleanup(term, held, session)


def screen_started_behind_leg(stratum, root):
    """The screen started behind, as `&` starts it: its first mode set stops until `fg`, as any
    program's does, and it then comes up (on macOS that set fails with EINTR after the stop,
    which the screen library does not retry). A `kill %1` while it waits ends it there, with the
    terminal left to the shell."""
    w = f'{root}/behind'
    os.makedirs(w, exist_ok=True)

    def fg_then_quit(term, how, manager):
        os.kill(term.pid, signal.SIGUSR2)
        term.expect(r'MkDir', timeout=60)
        term.send(F10)
        ended = term.exited(60)
        modes = tty_modes(term)
        record(ended and term.rc == 0 and all(modes.values()), f'{how}: after fg it came up, and F10 gave the terminal back',
               f'{how}: ended={ended} rc={term.rc}, the terminal was left {modes}')

    def kill_while_waiting(term, how, manager):
        os.kill(manager, signal.SIGTERM)
        os.killpg(os.getpgid(manager), signal.SIGCONT)
        ended = term.exited(30)
        said = 'asked to stop before the screen' in term.screen.text()
        state = '' if ended else state_of(manager)
        record(ended and term.rc == 1 and said, f'{how}: it ended there, rc 1, and said so',
               f'{how}: ended={ended} rc={term.rc}, said so={said}, its state {state!r}')
        modes = tty_modes(term)
        record(modes == EDITOR_MODES, f'{how}: the shell\'s mode was left as the shell set it',
               f'{how}: the terminal is {modes}, not the shell\'s {EDITOR_MODES}')

    # Under tostop the end behind must stop for nothing either: not the last word, not the
    # watcher's probe of the terminal.
    cases = (('the screen started behind, then fg', (), fg_then_quit),
             ('the screen started behind, sent a TERM while it waits', (), kill_while_waiting),
             ('the screen started behind, tostop set, sent a TERM while it waits', ('--tostop',), kill_while_waiting))
    for how, flags, then in cases:
        term = Term([sys.executable, '-I', '-c', JOB_SHELL, '--behind', '--editor', *flags, stratum, 'tui', '--host', w])
        manager = None
        try:
            limit = time.monotonic() + 10
            while manager is None and time.monotonic() < limit:
                term.pump(0.05)
                manager = child_running(term.pid, 'tui')
            if manager is None:
                raise Failure(f'{how}: no manager under the job shell: it proves nothing')
            state = wait_state(term, manager, 'T', 30)
            if 'T' not in state or 'MkDir' in term.screen.text() or tty_modes(term) != EDITOR_MODES:
                raise Failure(f'{how}: its state {state!r}, the terminal {tty_modes(term)}: not stopped behind before '
                              'the screen, it proves nothing')
            then(term, how, manager)
        except Failure:
            print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
            raise
        finally:
            job_cleanup(term, [], None)


# Runs a program in a session of its own, its descriptors still on the terminal, as `setsid`
# and `su -c` do: the terminal is not its controlling one.
SETSID = r"""
import os, sys
pid = os.fork()
if pid == 0:
    os.setsid()
    os.execv(sys.argv[1], sys.argv[1:])
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status) & 0xff)
"""


def setsid_screen_leg(stratum, root):
    """The screen on a terminal that is not its controlling one: no shell job-controls it, so the
    screen owns it and gives it back at its end, the mode and the private modes."""
    how = 'the screen on a terminal not its controlling one'
    w = f'{root}/setsid'
    os.makedirs(w, exist_ok=True)
    term = Term([sys.executable, '-I', '-c', SETSID, stratum, 'tui', '--host', w])
    manager = None
    try:
        term.expect(r'MkDir', timeout=60)
        manager = child_running(term.pid, 'tui')
        if tty_modes(term) != RAW_MODES or manager is None:
            raise Failure(f'{how}: the screen is up, the terminal {tty_modes(term)}, manager {manager}: it proves nothing')
        term.send(F10)
        ended = term.exited(60)
        modes = tty_modes(term)
        private = private_modes(term)
        record(ended and term.rc == 0 and all(modes.values()) and private == SHELL_PRIVATE,
               f'{how}: F10 gave it back as it was',
               f'{how}: ended={ended} rc={term.rc}, the terminal was left {modes}, its private modes {private}')
    finally:
        if manager is not None and term.rc is None:
            try:
                os.kill(manager, signal.SIGTERM)
            except ProcessLookupError:
                pass
        term.kill()


# Runs a program with core dumps allowed up to the hard limit, as a shell's `ulimit -c
# unlimited` leaves it.
CORE_ALLOWED = r"""
import os, resource, sys
hard = resource.getrlimit(resource.RLIMIT_CORE)[1]
resource.setrlimit(resource.RLIMIT_CORE, (hard, hard))
os.execv(sys.argv[1], sys.argv[1:])
"""


def input_spin_leg(stratum, root):
    """Input the screen's own wait sees and crossterm does not report must not spin the screen:
    it waits out the rest of each tick. Two ways there. On macOS a key typed while the terminal
    was canonical, which the screen's mode change at `fg` moves without a wakeup. On Linux input
    past crossterm's read of 1024 bytes, which its edge-triggered poll does not report again.
    Each case first shows its input stuck, or notes that this system cannot make it so; and after
    the measure, that a key still gets an answer: a wait that hung would burn no CPU either."""
    w = f'{root}/spin-host'
    os.makedirs(w, exist_ok=True)
    with open(f'{w}/onefile.txt', 'w') as f:
        f.write('one\n')

    def idle(term, how, manager):
        wait_quiet(term, how)
        before = cpu_seconds(manager)
        term.pump(2)
        used = cpu_seconds(manager) - before
        record(used < 0.25, f'{how}: idle after it, {used:.2f} s of CPU in 2 s',
               f'{how}: it spun, {used:.2f} s of CPU in 2 s')

    def dialog(term, how):
        # Keys typed into a field do nothing else.
        term.expect(r'onefile\.txt', timeout=30)
        term.send(F7)
        term.expect(r'New directory name')
        wait_quiet(term, how)

    how = 'a key typed while stopped, then fg'
    term = Term([sys.executable, '-I', '-c', JOB_SHELL, stratum, 'tui', '--host', w])
    try:
        dialog(term, how)
        manager = child_running(term.pid, 'tui')
        if manager is None:
            raise Failure(f'{how}: no manager under the job shell: it proves nothing')
        os.kill(manager, signal.SIGTSTP)
        if 'T' not in wait_state(term, manager, 'T', 10):
            raise Failure(f'{how}: the TSTP did not stop it: it proves nothing')
        if not tty_modes(term)['ICANON']:
            raise Failure(f'{how}: stopped, the terminal is {tty_modes(term)}, not canonical: it proves nothing')
        term.send(b'zq')
        os.kill(term.pid, signal.SIGUSR2)
        if not wait_until(term, lambda: tty_modes(term) == RAW_MODES, 10):
            raise Failure(f'{how}: after fg the terminal is {tty_modes(term)}: it proves nothing')
        wait_quiet(term, how)
        if 'zq' in term.screen.text():
            print(f'note: {how}: the screen read the key at fg here, so nothing is stuck to measure', flush=True)
        else:
            idle(term, how, manager)
            term.send(b'jx')
            answered = wait_until(term, lambda: 'zqjx' in term.screen.text(), 2)
            record(answered, f'{how}: and a key after it reached the field, the stuck one first',
                   f'{how}: a key after it got no answer in 2 s')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    how = '3000 bytes at once'
    term = Term([stratum, 'tui', '--host', w])
    try:
        dialog(term, how)
        taken = paste(term, b'a' * 3000)
        if taken <= 1024:
            # macOS holds about 1 KB of input for a pty: crossterm reads it all at once.
            print(f'note: {how}: the terminal took {taken} bytes, one read for crossterm, so nothing is stuck to measure', flush=True)
        else:
            wait_quiet(term, how)
            read = field_count(term)
            if read >= taken:
                raise Failure(f'{how}: the field holds all {taken} bytes, so nothing is stuck: it proves nothing')
            idle(term, how, term.pid)
            term.send(b'b')
            more = wait_until(term, lambda: field_count(term) > read, 2)
            record(more, f'{how}: and a key after it let more of them through ({read} then {field_count(term)})',
                   f'{how}: a key after it got no answer in 2 s ({read} read of {taken})')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def paste(term, data):
    """Writes `data` to the terminal at once, as a paste comes; returns how much it took."""
    flags = fcntl.fcntl(term.fd, fcntl.F_GETFL)
    fcntl.fcntl(term.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    try:
        return os.write(term.fd, data)
    except BlockingIOError:
        return 0
    finally:
        fcntl.fcntl(term.fd, fcntl.F_SETFL, flags)


def field_count(term):
    """How many characters the F7 field has been given: its kept 255 and its count over them."""
    m = re.search(r'\(\+(\d+) over\)', term.screen.text())
    return 255 + int(m.group(1)) if m else 0


def leftover_input_leg(stratum, root):
    """Input crossterm was never told of (T5.19) must not become the shell's when the screen
    ends, where the rest of a paste would run as commands: a TERM ends the screen with input
    stuck, and the job shell then reads what the terminal still holds. The two ways to stuck
    input of input_spin_leg; each first shows its input stuck, or notes it cannot be here."""
    w = f'{root}/leftover-host'
    os.makedirs(w, exist_ok=True)
    with open(f'{w}/onefile.txt', 'w') as f:
        f.write('one\n')

    def start(how):
        term = Term([sys.executable, '-I', '-c', JOB_SHELL, '--read-after', stratum, 'tui', '--host', w])
        term.expect(r'onefile\.txt', timeout=30)
        term.send(F7)
        term.expect(r'New directory name')
        wait_quiet(term, how)
        manager = child_running(term.pid, 'tui')
        if manager is None:
            raise Failure(f'{how}: no manager under the job shell: it proves nothing')
        return term, manager

    def left_at_the_end(term, how, manager):
        # A tick or more for the screen's wait to find it stuck.
        term.pump(0.5)
        os.kill(manager, signal.SIGTERM)
        if not wait_until(term, lambda: re.search(rb'\[left \d+\]', bytes(term.raw)), 15):
            raise Failure(f'{how}: the job shell never said what was left: it proves nothing')
        left = int(re.search(rb'\[left (\d+)\]', bytes(term.raw)).group(1))
        record(left == 0, f'{how}: the shell found nothing of it left',
               f'{how}: the shell found {left} bytes of it left, as typed input')

    how = 'a key typed while stopped, then fg, then TERM'
    term, manager = start(how)
    try:
        os.kill(manager, signal.SIGTSTP)
        if 'T' not in wait_state(term, manager, 'T', 10):
            raise Failure(f'{how}: the TSTP did not stop it: it proves nothing')
        term.send(b'zq')
        os.kill(term.pid, signal.SIGUSR2)
        if not wait_until(term, lambda: tty_modes(term) == RAW_MODES, 10):
            raise Failure(f'{how}: after fg the terminal is {tty_modes(term)}: it proves nothing')
        wait_quiet(term, how)
        if 'zq' in term.screen.text():
            print(f'note: {how}: the screen read the key at fg here, so nothing is stuck', flush=True)
        else:
            left_at_the_end(term, how, manager)
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    how = '3000 bytes at once, then TERM'
    term, manager = start(how)
    try:
        taken = paste(term, b'a' * 3000)
        if taken <= 1024:
            print(f'note: {how}: the terminal took {taken} bytes, one read for crossterm, so nothing is stuck', flush=True)
        else:
            wait_quiet(term, how)
            if field_count(term) >= taken:
                raise Failure(f'{how}: the field holds all {taken} bytes, so nothing is stuck: it proves nothing')
            left_at_the_end(term, how, manager)
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def escape_prefix_leg(stratum, root):
    """A sequence crossterm cannot finish, ESC O as many terminals send Alt+O, must not hold the
    screen in a read: a TERM then ends it, with no key after. One that a later read finishes
    still counts: ESC [, then 18~, is F7."""
    w = f'{root}/escape-host'
    os.makedirs(w, exist_ok=True)
    with open(f'{w}/onefile.txt', 'w') as f:
        f.write('one\n')
    how = 'ESC O, then TERM'
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'onefile\.txt', timeout=30)
        wait_quiet(term, how)
        term.send(b'\x1b[')
        term.pump(0.5)
        term.send(b'18~')
        term.expect(r'New directory name', timeout=10)
        print(f'ok: {how}: ESC [ and then 18~ in a later read made F7', flush=True)
        term.send(ESC)
        if not wait_until(term, lambda: 'New directory name' not in term.screen.text(), 10):
            raise Failure(f'{how}: Esc did not close the dialog: it proves nothing')
        wait_quiet(term, how)
        term.send(b'\x1bO')
        term.pump(1)
        if os.waitpid(term.pid, os.WNOHANG)[0]:
            raise Failure(f'{how}: ESC O ended it: it proves nothing')
        os.kill(term.pid, signal.SIGTERM)
        ended = term.exited(5)
        state = '' if ended else state_of(term.pid)
        record(ended, f'{how}: the TERM ended it with no key after',
               f'{how}: the TERM did not end it in 5 s, its state {state!r}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    # The terminal's node shut to its user, as after su to another one: on Linux /dev/tty is
    # the same terminal. macOS cannot watch /dev/tty, and there the freeze stays (T0.78).
    how = 'ESC O, then TERM, the terminal node shut'
    if not sys.platform.startswith('linux'):
        print(f'note: {how}: Linux only, where /dev/tty stands in for the node', flush=True)
        return
    term = Term(['/bin/sh', '-c', 't=$(tty); chmod 000 "$t"; [ -r "$t" ] || echo node-shut; exec "$0" tui --host "$1"',
                 stratum, w])
    try:
        term.expect(r'onefile\.txt', timeout=30)
        if b'node-shut' not in term.raw:
            raise Failure(f'{how}: the node stayed open to its user: it proves nothing')
        wait_quiet(term, how)
        term.send(b'\x1bO')
        term.pump(1)
        if os.waitpid(term.pid, os.WNOHANG)[0]:
            raise Failure(f'{how}: ESC O ended it: it proves nothing')
        os.kill(term.pid, signal.SIGTERM)
        ended = term.exited(5)
        state = '' if ended else state_of(term.pid)
        record(ended, f'{how}: the TERM ended it with no key after',
               f'{how}: the TERM did not end it in 5 s, its state {state!r}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def editor_escape_leg(stratum, root):
    """A file's text shown in the editor sends no control character to the terminal: the OSC in
    it that would set the window title arrives as '?' and plain text, the BEL that ends it too."""
    w = f'{root}/hostile-host'
    os.makedirs(w, exist_ok=True)
    with open(f'{w}/hostile.txt', 'wb') as f:
        f.write(b'before\x1b]2;PWNED\x07after\n')
    how = 'F3 on a file holding an OSC'
    term = Term([stratum, 'tui', '--host', w])
    try:
        term.expect(r'hostile\.txt', timeout=30)
        pick(term, 'hostile.txt', ['hostile.txt'])
        start = len(term.raw)
        term.send(b'\x1bOR')
        term.expect(r'after', timeout=10)
        term.pump(0.5)
        sent = bytes(term.raw[start:])
        osc, bel = b'\x1b]2;' in sent, b'\x07' in sent
        shown = 'before?]2;PWNED?after' in term.screen.text()
        record(not osc and not bel and shown,
               f'{how}: the terminal got no control from it, and it shows as text',
               f'{how}: OSC sent={osc}, BEL sent={bel}, shown as text={shown}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def unprintable_volume_leg(stratum, vol, host, root):
    """A volume whose name holds a control character is opened nowhere, and nothing said about
    it sends that character to the terminal: not the passphrase prompt, not an error. The same
    volume under a plain name prompts, one variable away. The landing screen's New refuses such
    a path too."""
    d = f'{root}/unprintable'
    os.makedirs(d, exist_ok=True)
    plain, hostile = f'{d}/plain.stm', f'{d}/x\x1b]2;PWNED\x07.stm'
    for name in (plain, hostile):
        os.symlink(vol.v, name)
        os.symlink(vol.v + '.key', name + '.key')

    def clean(term):
        sent = bytes(term.raw)
        return b'\x1b]2;' not in sent and b'\x07' not in sent

    how = 'a volume named with an OSC'
    term = Term([stratum, 'tui', '--vol', plain, '--host', host])
    try:
        term.expect(r'Passphrase for plain\.stm', timeout=30)
        print(f'ok: {how}: the same volume under a plain name asks for its passphrase', flush=True)
    finally:
        term.kill()
    term = Term([stratum, 'tui', '--vol', hostile, '--host', host])
    try:
        ended = term.exited(30)
        refused = b'holds a control character' in bytes(term.raw)
        record(ended and refused and clean(term), f'{how}: refused, and the terminal got none of its controls',
               f'{how}: ended={ended} refused={refused}, controls kept from the terminal={clean(term)}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    for how, argv in (('a keyfile named with an OSC', ['--vol', plain, '--keyfile', hostile + '.key']),
                      ('a --host named with an OSC', ['--host', f'{d}/h\x1b]2;PWNED\x07'])):
        if 'host' in how:
            os.makedirs(argv[1], exist_ok=True)
        else:
            argv += ['--host', host]
        term = Term([stratum, 'tui', *argv])
        try:
            ended = term.exited(30)
            refused = b'holds a control character' in bytes(term.raw)
            record(ended and refused and clean(term), f'{how}: refused, and the terminal got none of its controls',
                   f'{how}: ended={ended} refused={refused}, controls kept from the terminal={clean(term)}')
        finally:
            term.kill()

    # The landing screen: a recent volume kept from before, a choice typed, a path typed.
    config = f'{os.environ["HOME"]}/.config/stratum'
    os.makedirs(config, exist_ok=True)
    recents = f'{config}/recents'
    with open(recents, 'w', encoding='utf-8') as f:
        f.write('/v/x\x1b]2;PWNED\x07.stm\n')
    how = 'the landing screen, a recent volume named with an OSC'
    term = Term([stratum])
    try:
        term.expect(r'Choose \[')
        listed = clean(term)
        term.send(b'o' + ENTER)
        term.expect(r'Volume path')
        relisted = clean(term)
        term.send(f'{d}/typed\x1b]2;PWNED\x07.stm'.encode() + ENTER)
        refused = wait_until(term, lambda: b'holds a control character' in bytes(term.raw), 10)
        with open(recents, encoding='utf-8') as f:
            kept = f.read() == '/v/x\x1b]2;PWNED\x07.stm\n'
        record(listed and relisted and refused and clean(term) and kept,
               f'{how}: listed twice and a typed one refused, none of their controls sent, the typed one not kept',
               f'{how}: clean in the chooser={listed}, in Open={relisted}; refused={refused}, '
               f'clean at the end={clean(term)}, recents unchanged={kept}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()
    how = 'the landing screen, a choice typed with an OSC'
    term = Term([stratum])
    try:
        term.expect(r'Choose \[')
        term.send(b'\x1b]2;PWNED\x07' + ENTER)
        said = wait_until(term, lambda: b'unrecognized choice' in bytes(term.raw), 10)
        record(said and clean(term), f'{how}: refused, and none of its controls sent back',
               f'{how}: said so={said}, controls kept from the terminal={clean(term)}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    how = "the landing screen's New, a path with an OSC"
    term = Term([stratum])
    try:
        term.expect(r'Choose \[')
        term.send(b'n' + ENTER)
        term.expect(r'New volume path')
        term.send(f'{d}/new\x1b]2;PWNED\x07.stm'.encode() + ENTER)
        refused = wait_until(term, lambda: b'holds a control character' in bytes(term.raw), 10)
        record(refused and clean(term), f'{how}: refused, and the terminal got none of its controls',
               f'{how}: refused={refused}, controls kept from the terminal={clean(term)}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def core_dumps_off_leg(stratum, vol, host, root):
    """No stratum process dumps core, a passphrase or a key in it: started with dumps allowed,
    the manager and each daemon it starts run with the core limit at 0 and not dumpable. Only
    Linux shows another process's, in /proc; elsewhere the unit test covers the function."""
    how = 'started with core dumps allowed'
    if not os.path.exists('/proc/self/limits'):
        print(f'note: {how}: no /proc to read another process\'s limits from, leg skipped', flush=True)
        return
    if resource.getrlimit(resource.RLIMIT_CORE)[1] == 0 or os.getuid() == 0:
        raise Failure(f'{how}: the hard core limit is 0, or the harness runs as root: it proves nothing')

    def core_limit(pid):
        with open(f'/proc/{pid}/limits') as f:
            return next(line.split()[4:6] for line in f if line.startswith('Max core file size'))

    def dumpable(pid):
        # Linux gives the entries in /proc/<pid> of a process that is not dumpable to root;
        # the directory itself keeps the owner's uid either way.
        return os.stat(f'/proc/{pid}/status').st_uid == os.getuid()

    hard = resource.getrlimit(resource.RLIMIT_CORE)[1]
    allowed = ['unlimited'] * 2 if hard == resource.RLIM_INFINITY else [str(hard)] * 2
    # The controls, one variable away each: the same start, a program that keeps the limit and
    # stays dumpable, and one that turns its own dumpable flag off.
    undumpable = 'import ctypes, time; ctypes.CDLL(None).prctl(4, 0, 0, 0, 0); print(flush=True); time.sleep(30)'
    controls = [subprocess.Popen([sys.executable, '-I', '-c', CORE_ALLOWED, '/bin/sleep', '30']),
                subprocess.Popen([sys.executable, '-I', '-c', CORE_ALLOWED, sys.executable, '-I', '-c', undumpable],
                                 stdout=subprocess.PIPE)]
    try:
        controls[1].stdout.readline()
        limit = time.monotonic() + 10
        while not os.path.exists(f'/proc/{controls[0].pid}/limits') or core_limit(controls[0].pid) != allowed:
            if time.monotonic() > limit:
                raise Failure(f'{how}: the control never ran with the core limit at {allowed}: it proves nothing')
            time.sleep(0.05)
        if not dumpable(controls[0].pid) or dumpable(controls[1].pid):
            raise Failure(f'{how}: dumpable={dumpable(controls[0].pid)} for the control that is, '
                          f'{dumpable(controls[1].pid)} for the one that is not: it proves nothing')
    finally:
        for c in controls:
            c.kill()
            c.wait()
    env_file = f'{root}/env-core'
    term = Term([sys.executable, '-I', '-c', CORE_ALLOWED, stratum, 'tui', '--headless', '--vol', vol.v,
                 '--host', host, '--print-env-to', env_file])
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'send SIGTERM', timeout=60)
        session = os.path.dirname(read_env(env_file)['STRATUMD_SOCK'])
        pids = [str(term.pid)] + session_daemons(session)
        if len(pids) < 4:
            raise Failure(f'{how}: the search finds {pids}: it proves nothing')
        seen = {pid: (core_limit(pid), dumpable(pid)) for pid in pids}
        record(all(lim == ['0', '0'] and not dump for lim, dump in seen.values()),
               f'{how}: the manager and its daemons run with the core limit at 0, not dumpable',
               f'{how}: (core limit, dumpable) by pid: {seen}')
    finally:
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
    os.makedirs(config, exist_ok=True)
    with open(f'{config}/recents', 'w', encoding='utf-8') as f:
        f.write('/volumes/' + '\u00e9' * 30 + '/v.stm\n')

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
        # The screen's key row: a key sent before the screen has the terminal is dropped with
        # what was typed while the key was derived.
        term.expect(r'MkDir', timeout=60)
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


# Runs a program with SIGCHLD ignored, which exec keeps: as a parent that ignored it leaves it.
CHLD_IGNORED = r"""
import os, signal, sys
signal.signal(signal.SIGCHLD, signal.SIG_IGN)
os.execv(sys.argv[1], sys.argv[1:])
"""


def children_waited_for_leg(stratum, root):
    """Started with SIGCHLD ignored, which would have the kernel reap each child unseen and every
    wait fail: the landing screen's New still waits for mkfs, and opens the volume it made. Linux
    keeps the ignore across exec and reaps; macOS reaps for an ignore set in the process itself
    (the unit test), but not once exec has run, so only Linux tells the two apart here."""
    how = 'started with SIGCHLD ignored'
    path = f'{root}/chld.stm'
    term = Term([sys.executable, '-I', '-c', CHLD_IGNORED, stratum])
    try:
        term.pump(1)
        term.send(b'n' + ENTER)
        term.expect(r'New volume path')
        term.send(path.encode() + ENTER)
        term.expect(r'Size')
        term.send(b'64M' + ENTER)
        term.expect(r'Passphrase:')
        term.send(PASS.encode() + ENTER)
        term.expect(r'Passphrase again')
        term.send(PASS.encode() + ENTER)
        term.expect(r'Passphrase for|No child processes', timeout=60)
        waited = 'Passphrase for' in term.screen.text()
        record(waited, f'{how}: the landing screen waited for mkfs and went on to open the volume',
               f'{how}: the wait for mkfs failed: {term.screen.text()[-300:]!r}')
        if not waited:
            return
        term.send(PASS.encode() + ENTER)
        term.expect(r'MkDir', timeout=60)
        term.send(F10)
        record(term.exited(60) and term.rc == 0, f'{how}: F10 ended it, rc 0',
               f'{how}: F10 did not end it: rc={term.rc}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def child_running(pid, word):
    """The pid of a child of `pid` whose command line holds `word` as a word, or None."""
    r = subprocess.run(['ps', '-ww', '-A', '-o', 'pid=,ppid=,command='], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and fields[1] == str(pid) and f' {word} ' in f' {fields[2]} ':
            return int(fields[0])
    return None


def landing_stop_legs(stratum, root):
    """A stop on the landing screen's New, where the terminal is not as it was: at either
    passphrase prompt (no echo, every key read as it comes) and while mkfs derives the key (echo
    held off). It must end the manager with the terminal given back, not by the signal's default
    action, and say what it left: nothing, from a prompt; a volume, if mkfs finished."""
    def sent_at(sig, prompt):
        def at(term, path):
            # Taken at Enter. Whether it has ended before then is no test: on macOS a process
            # ended by a signal can still be exiting, waiting on its terminal, well after.
            if prompt == 'Passphrase again':
                term.send(PASS.encode() + ENTER)
                term.expect(r'Passphrase again')
            os.kill(term.pid, sig)
            term.pump(0.5)
            try:
                term.send(PASS.encode() + ENTER)
            except OSError:
                pass  # the default action has ended the manager, and the terminal's other side with it
            return ['asked to stop at the passphrase prompt'], None, (False, False, False)
        return at

    def to_mkfs(term, path):
        term.send(PASS.encode() + ENTER)
        term.expect(r'Passphrase again')
        term.send(PASS.encode() + ENTER)
        limit = time.monotonic() + 10
        mkfs = child_running(term.pid, 'mkfs')
        while mkfs is None and time.monotonic() < limit:
            # Read as a terminal does: a terminal given back with TCSAFLUSH waits for its output
            # to be read.
            term.pump(0.005)
            mkfs = child_running(term.pid, 'mkfs')
        if mkfs is None:
            raise Failure('mkfs was not seen running: it proves nothing')
        # Held where it has made both files and derives the key, the slow part: its own
        # cleanup would remove them, and a signal's default action never runs it.
        if not wait_until(term, lambda: os.path.exists(f'{path}.key.new.{mkfs}'), 10):
            raise Failure(f'mkfs never made {path}.key.new.{mkfs}: it proves nothing')
        os.kill(mkfs, signal.SIGSTOP)
        modes = tty_modes(term)
        record(modes == {'ECHO': False, 'ICANON': True, 'ISIG': True},
               'echo held off, the terminal cooked, while the landing screen\'s mkfs runs',
               f'the terminal while the landing screen\'s mkfs runs: {modes}')
        return mkfs

    def ctrl_c_in_mkfs(term, path):
        mkfs = to_mkfs(term, path)
        term.send(b'\x03')
        term.pump(0.5)
        # Linux keeps the Ctrl-C pending on the stopped mkfs until it continues, and it ends it
        # then; macOS has ended it already.
        try:
            os.kill(mkfs, signal.SIGCONT)
        except ProcessLookupError:
            pass
        return ['ended mkfs before it finished, so', f'it left {path} and {path}.key.new.{mkfs}'], mkfs, (True, False, True)

    def term_in_mkfs(term, path):
        # To the manager alone: mkfs goes on, and makes the volume.
        mkfs = to_mkfs(term, path)
        os.kill(term.pid, signal.SIGTERM)
        term.pump(0.5)
        os.kill(mkfs, signal.SIGCONT)
        return ['was made, and was not opened'], mkfs, (True, True, False)

    def mkfs_killed_alone(term, path):
        # No stop asked: mkfs ended by a signal of its own, its cleanup never run. The manager
        # names what it left, and goes no further.
        mkfs = to_mkfs(term, path)
        os.kill(mkfs, signal.SIGKILL)
        return ([f'signal {int(signal.SIGKILL)} ended mkfs before it finished, so', f'it left {path} and {path}.key.new.{mkfs}'],
                mkfs, (True, False, True), 0)

    cases = (('SIGTERM at the landing screen\'s passphrase prompt', sent_at(signal.SIGTERM, 'Passphrase:'), ()),
             ('a HUP at the landing screen\'s passphrase prompt, blocked by its parent',
              sent_at(signal.SIGHUP, 'Passphrase:'), (signal.SIGHUP,)),
             ('SIGTERM at the landing screen\'s second passphrase prompt',
              sent_at(signal.SIGTERM, 'Passphrase again'), ()),
             ('Ctrl-C while the landing screen\'s mkfs runs', ctrl_c_in_mkfs, ()),
             ('SIGTERM to the manager alone while the landing screen\'s mkfs runs', term_in_mkfs, ()),
             ('mkfs killed alone while the landing screen waits for it', mkfs_killed_alone, ()))
    for i, (how, case, blocked) in enumerate(cases):
        path = f'{root}/landing-stop{i}.stm'
        term = Term([stratum], blocked=blocked)
        mkfs = None
        try:
            term.expect(r'Choose \[')
            term.send(b'n' + ENTER)
            term.expect(r'New volume path')
            term.send(path.encode() + ENTER)
            term.expect(r'Size')
            term.send(b'64M' + ENTER)
            term.expect(r'Passphrase:')
            try:
                said, mkfs, left, *rc = case(term, path)
            except Failure as e:
                raise Failure(f'{how}: {e}') from None
            # A stop asked ends it with 1; mkfs's own end is told, and is not the manager's error.
            want = rc[0] if rc else 1
            ended = term.exited(30)
            # Wrapped at the screen's edge, a long path moves the words across rows.
            shown = re.sub(r'\s', '', term.screen.text())
            named = all(re.sub(r'\s', '', s) in shown for s in said)
            record(ended and term.rc == want and named, f'{how}: the manager ended, rc {want}, and said so',
                   f'{how}: the manager ended={ended} rc={term.rc}, said {said!r}={named}')
            if ended:
                modes = tty_modes(term)
                record(all(modes.values()), f'{how}: the terminal was given back as it was',
                       f'{how}: the terminal was left {modes}')
            there = (os.path.exists(path), os.path.exists(f'{path}.key'),
                     mkfs is not None and os.path.exists(f'{path}.key.new.{mkfs}'))
            record(there == left, f'{how}: the volume, its key and a new key there: {left}, as said',
                   f'{how}: the volume, its key and a new key there: {there}, not {left}')
        except Failure:
            print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
            raise
        finally:
            # Only while that number is still this mkfs: once reaped, it could be anyone's.
            if mkfs is not None and path in subprocess.run(
                    ['ps', '-ww', '-p', str(mkfs), '-o', 'command='], capture_output=True, text=True).stdout:
                for sig in (signal.SIGCONT, signal.SIGKILL):
                    try:
                        os.kill(mkfs, sig)
                    except ProcessLookupError:
                        pass
            term.kill()
            for f in (path, f'{path}.key', *([f'{path}.key.new.{mkfs}'] if mkfs else [])):
                if os.path.exists(f):
                    os.remove(f)


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
    spit(f'{host}/tabmate.txt', b'mate\n')
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
                  'tab\ufffdname', 'tabmate.txt', 'nldir']
    vol_names = ['keptfile.txt', 'overfile.txt', 'keptfile-2.txt', 'hostile', '.snaps',
                 'shutfile.txt', 'shutdir', 'secretfile.txt', 'privdir', 'linkedname', 'tabmate.txt']
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
        # or none. Beside a plain file the batch runs, and its summary says which refusal
        # it was: a stand-in left to fail as a missing file would read "No such file".
        for n in ('tab\ufffdname', 'tabmate.txt'):
            pick(term, n, host_names, right=True)
            term.send(b' ')
            term.pump(0.3)
        term.send(F5)
        copied, _, failed, text = copy_summary(term, 'a stand-in name beside a plain file')
        why = 'will not copy' in text
        record(copied == 1 and failed == 1 and why and on_vol('/tabmate.txt') == b'mate\n',
               'a name with a control character is refused, not copied under its stand-in',
               f'a stand-in beside a plain file: {copied} copied, {failed} failed, reason named: {why}')
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
    # U+0085, a C1 control: shown with U+FFFD standing in, as one below U+0020 is.
    p9_mkdir(vol.sock, [], b'n\xc2\x85l')
    vol.stop()

    shown = 'caf\ufffd'
    c1 = 'n\ufffdl'
    listed = [shown, c1, 'victim', '.snaps']
    term = Term([stratum, 'tui', '--vol', vol.v, '--host', base])
    try:
        term.expect(r'Passphrase for')
        term.send(PASS.encode() + ENTER)
        term.expect(r'victim', timeout=60)
        term.pump(0.5)
        pick(term, c1, listed)
        term.send(ENTER)
        term.pump(1.5)
        record(c1 in rows_in_panel(term, [c1], False), 'the manager does not go into a directory whose name holds a C1 control',
               'Enter went into a directory whose name holds a C1 control')
        pick(term, shown, listed)
        term.send(ENTER)
        term.pump(1.5)
        term.show('Enter on a name that is not UTF-8')
        stayed = shown in rows_in_panel(term, [shown], False)
        record(stayed, 'the manager does not go into a directory whose name is not UTF-8',
               'Enter went into a directory whose name is not UTF-8')
        if not stayed:
            # Two defences: in here, the actions must refuse rather than build from the root.
            pick(term, 'victim', ['victim'])
            term.send(b' ')
            term.pump(0.5)
            term.send(F8)
            term.expect(r'location cannot be read|Delete')
            term.show('F8 inside it')
            unread = 'location cannot be read' in term.screen.text()
            record(unread, 'inside it, F8 refuses for want of a location', 'inside it, F8 offered to delete')
            if unread:
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
    """A delete runs one item at a time. A quit key mid-batch asks, and no new item starts
    while it asks: Stop (its first answer) or Esc stops the batch after the item in hand, Go on
    lets it finish. A bare Esc stops it. A copy's question stops a copy the same way."""
    w = f'{root}/delbatch'
    many = 20000
    dirs = ['bulkone', 'bulktwo']
    held = ['heldone', 'heldtwo']
    goon = ['goonone', 'goontwo']
    stop = ['stopone', 'stoptwo']
    names = goon + stop + dirs + held

    def fill(d, n):
        os.makedirs(f'{w}/{d}')
        for i in range(n):
            open(f'{w}/{d}/f{i:06d}', 'wb').close()

    # The bare Esc leg needs an item to outlast a key's trip through the loop: grow its
    # items until deleting one is measured to take that long here.
    bare = many
    while True:
        fill('calib', bare)
        t0 = time.monotonic()
        shutil.rmtree(f'{w}/calib')
        item_s = time.monotonic() - t0
        if item_s >= 1.5 or bare >= 16 * many:
            break
        bare *= 2
    print(f'note: deleting {bare} files takes {item_s:.2f} s here', flush=True)
    count = {d: bare if d in dirs else many for d in names}
    for d in names:
        fill(d, count[d])
    asked = r'wait while this shows'

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
        while time.monotonic() < end and all(files_left(f'{w}/{d}') == count[d] for d in chosen):
            time.sleep(0.01)

    def asks(term):
        """True when the question came; False when the item ended before the key was read."""
        term.expect(asked + r'|Delete: \d+ deleted', timeout=10)
        if re.search(asked, term.screen.text()):
            return True
        print('note: the batch ended before the key was read, so this leg proves nothing', flush=True)
        return False

    # Two items each, so that Stop and Go on end differently.
    term = Term([stratum, 'tui', '--host', w])
    try:
        start_delete(term, goon)
        term.send(b'\x11')
        if asks(term):
            record(not term.exited(1), 'Ctrl-Q mid-delete asks, and does not quit', 'Ctrl-Q quit in the middle of a delete')
            term.send(RIGHT)   # a quit key starts on Stop; Go on is next
            term.pump(0.1)
            term.send(ENTER)
            term.expect(r'Delete: \d+ deleted', timeout=120)
            left = {d: files_left(f'{w}/{d}') for d in goon}
            record(all(n == -1 for n in left.values()), 'Go on lets the delete finish',
                   f'after Go on, the directories hold {left} files')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    # Enter takes the question's first answer for a quit key, which must be Stop.
    term = Term([stratum, 'tui', '--host', w])
    try:
        start_delete(term, stop)
        term.send(b'\x03')
        if asks(term):
            term.pump(0.1)
            term.send(ENTER)
            term.expect(r'Delete: \d+ deleted', timeout=120)
            intact = [d for d in stop if files_left(f'{w}/{d}') == count[d]]
            record(len(intact) == 1, 'Enter on the question a quit key asks stops the delete after the item in hand',
                   f'after Ctrl-C and Enter, the intact directories are {intact}')
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
        intact = [d for d in dirs if files_left(f'{w}/{d}') == count[d]]
        if item_s < 1.0:
            print(f'note: an item here may end before Esc is read; intact {intact}, proves nothing', flush=True)
        else:
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
            intact = [d for d in held if files_left(f'{w}/{d}') == count[d]]
            record(len(intact) == 1, 'one Esc on the question Ctrl-C asks stops the delete after the item in hand',
                   f'after Ctrl-C and one Esc, the intact directories are {intact}')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()

    # The same question over a copy: one Esc stops it after the item in hand, so the
    # second directory never arrives whole.
    c = f'{root}/copybatch'
    small = 300
    parts = ['cone', 'ctwo']
    for d in parts:
        os.makedirs(f'{c}/csrc/{d}')
        for i in range(small):
            spit(f'{c}/csrc/{d}/f{i:03d}', b'x' * 4096)
    os.makedirs(f'{c}/cdst')
    top = ['cdst', 'csrc']
    term = Term([stratum, 'tui', '--host', c])
    try:
        term.expect(r'csrc', timeout=30)
        term.pump(0.5)
        pick(term, 'csrc', top)
        term.send(ENTER)
        term.pump(0.6)
        term.send(TAB)
        term.pump(0.3)
        pick(term, 'cdst', top, right=True)
        term.send(ENTER)
        term.pump(0.6)
        term.send(TAB)
        term.pump(0.3)
        for d in parts:
            pick(term, d, parts)
            term.send(b' ')
            term.pump(0.3)
        term.send(F5)
        end = time.monotonic() + 30
        while time.monotonic() < end and files_left(f'{c}/cdst/cone') <= 0:
            time.sleep(0.01)
        term.send(b'\x03')
        term.expect(asked + r'|Copy: \d+ copied', timeout=10)
        if not re.search(asked, term.screen.text()):
            print('note: the copy ended before the key was read, so this leg proves nothing', flush=True)
        else:
            term.send(ESC)
            copied, _, _, _ = copy_summary(term, 'after Ctrl-C and one Esc mid-copy')
            got = max(files_left(f'{c}/cdst/ctwo'), 0)
            record(got < small, 'one Esc on the question a copy asks stops it after the item in hand',
                   f'after Ctrl-C and one Esc, ctwo holds {got} of {small} files; {copied} copied in all')
    except Failure:
        print(f'--- screen at the failure\n{term.screen.text()}\n---', flush=True)
        raise
    finally:
        term.kill()


def helper_checks():
    """The helpers that find a manager's session directory, on what they are given rather than
    on a manager: a miss in either strands a directory outside the run's root."""
    # The --listen ends a host-fs line, and procps cuts a line at an exported COLUMNS.
    listen = '/' + 'd' * 150
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)',
                              'host-fs', 'h' * 100, '--listen', f'{listen}/host-fs.sock'])
    columns = os.environ.get('COLUMNS')
    os.environ['COLUMNS'] = '80'
    try:
        found = session_dir_of(os.getpid(), wait=5)
    finally:
        child.kill()
        child.wait()
        if columns is None:
            os.environ.pop('COLUMNS')
        else:
            os.environ['COLUMNS'] = columns
        SESSION_DIRS.pop(os.getpid(), None)
    if found != listen:
        raise Failure(f'session_dir_of read {found!r} off a ps line ending in {listen}/host-fs.sock')
    # With TMPDIR unset std uses the user's temporary directory on macOS, and Python /tmp; on Linux
    # both use /tmp.
    if sys.platform == 'darwin':
        user = subprocess.run(['getconf', 'DARWIN_USER_TEMP_DIR'], capture_output=True, text=True).stdout.strip()
    else:
        user = '/tmp'
    fake = 4_000_000 + os.getpid()
    made = f"{user.rstrip('/')}/stratum-{fake}-aB3xYz"
    since = time.time()
    os.mkdir(made)
    saved = {k: os.environ.pop(k) for k in ('TMPDIR', 'XDG_RUNTIME_DIR') if k in os.environ}
    tempfile.tempdir = None
    try:
        got = session_dir_guesses(fake, since)
        # One variable away: the same directory, older than the manager asked about.
        older = session_dir_guesses(fake, since + 5)
    finally:
        os.environ.update(saved)
        tempfile.tempdir = None
        os.rmdir(made)
    if made not in got:
        raise Failure(f'with TMPDIR unset the guesses {got} miss {made}')
    if older:
        raise Failure(f'the guesses {older} take a directory made before the manager started')
    print('ok: the session directory helpers find it off a long ps line and with TMPDIR unset, and not one older', flush=True)


def screen_checks():
    """The terminal and the pipe through Term.pump as a leg's run feeds them, from fds that
    share no line discipline: neither may move or split what the other shows."""
    term = Term.__new__(Term)
    term.screen, term.piped, term.raw = Screen(), Screen(onlcr=True), bytearray()
    pty_r, pty_w = os.pipe()
    out_r, out_w = os.pipe()
    term.fd, term.out = pty_r, out_r
    try:
        # A line ending at column 127, as host-fs's serving line can with a long session path,
        # then the prompt.
        os.write(out_w, b'x' * 127 + b'\n')
        os.write(pty_w, b'Passphrase for vol.stm: ')
        term.pump(0.3)
        # Lines on the pipe whose lengths, each starting where the last ended, would carry
        # the next one's start to column 130.
        os.write(out_w, b'y' * 70 + b'\n' + b'z' * 73 + b'\n' + b'        send SIGTERM (Ctrl-C) to shut down.\n')
        term.pump(0.3)
        for pattern in (r'Passphrase for', r'send SIGTERM'):
            if not term.showing(re.compile(pattern)):
                raise Failure(f'the screens lost {pattern!r}:\n{term.screen.text().strip()}\n'
                              f'--- the pipe\n{term.piped.text().strip()}')
    finally:
        for fd in (pty_r, pty_w, out_r, out_w):
            os.close(fd)
    print('ok: the terminal and the pipe each keep their own text whole', flush=True)


def sealed_volume(stratum, root):
    """For a leg run alone: a sealed volume holding from_vol.txt, and a host tree."""
    host = f'{root}/host'
    os.makedirs(f'{host}/tree/deep', exist_ok=True)
    with open(f'{host}/tree/a.txt', 'w') as f:
        f.write('one\n')
    vol = Volume(stratum, root)
    vol.mkfs()
    vol.serve()
    r = vol.fs(vol.sock, 'write', '/from_vol.txt', data=b'came from the volume\n')
    if r.returncode != 0:
        raise Failure(f'seeding the volume failed: {r.stderr[:200]}')
    vol.stop()
    return vol, host


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
        left, session_left = session_daemons(session), os.path.exists(session)
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
                      (output_gone_leg, (stratum, vol, host, root)),
                      (stuck_daemon_leg, (stratum, vol, host, root)),
                      (headless_output_gone_leg, (stratum, vol, host, root)),
                      (headless_int_ignored_leg, (stratum, vol, host, root)),
                      (resize_leg, (stratum, vol, host, root)),
                      (prompt_end_legs, (stratum, vol, host, root)),
                      (missing_binary_leg, (stratum, vol, host, root)),
                      (start_wait_stop_leg, (stratum, vol, host, root)),
                      (pending_hup_leg, (stratum, vol, host, root)),
                      (headless_behind_leg, (stratum, vol, host, root)),
                      (screen_behind_leg, (stratum, vol, host, root)),
                      (screen_job_control_leg, (stratum, vol, host, root)),
                      (core_dumps_off_leg, (stratum, vol, host, root)),
                      (screen_started_behind_leg, (stratum, root)),
                      (setsid_screen_leg, (stratum, root)),
                      (input_spin_leg, (stratum, root)),
                      (leftover_input_leg, (stratum, root)),
                      (escape_prefix_leg, (stratum, root)),
                      (editor_escape_leg, (stratum, root)),
                      (unprintable_volume_leg, (stratum, vol, host, root)),
                      (editor_legs, (stratum, vol, host, f'{root}/env2')),
                      (wrong_passphrase_leg, (stratum, vol, host)),
                      (wizard_legs, (stratum, vol, root)),
                      (mid_session_legs, (stratum, root)),
                      (landing_legs, (stratum, root)),
                      (children_waited_for_leg, (stratum, root)),
                      (landing_stop_legs, (stratum, root))):
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
        screen_checks()
        helper_checks()
        only = os.environ.get('KEYS_ONLY')
        if only:
            given = {'stratum': stratum, 'root': root, 'env_file': f'{root}/env2'}
            for name in only.split(','):
                try:
                    leg = globals()[name]
                    wants = list(inspect.signature(leg).parameters)
                    if ('vol' in wants or 'host' in wants) and 'vol' not in given:
                        given['vol'], given['host'] = sealed_volume(stratum, root)
                    leg(*[given[w] for w in wants])
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
