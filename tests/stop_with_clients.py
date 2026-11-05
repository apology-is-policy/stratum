#!/usr/bin/env python3
"""A daemon told to stop does not wait for clients that have not gone.

Each leg starts a daemon on one volume, gives it a client on the 9P socket or the /ctl/ socket, sends
TERM and times the exit. A client either keeps talking, which no idle timeout can end, or sits idle,
which only the idle timeout would otherwise end. Every leg first proves the client was being served,
and the volume must mount again afterwards.

    tests/stop_with_clients.py path/to/stratum
"""
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

# Past this the daemon has not stopped for the client's sake: the idle timeout alone takes 30 s.
BOUND_S = 15.0
RVERSION = 101


def tversion():
    version = b'9P2000.L'
    body = struct.pack('<BHI', 100, 0xffff, 65536) + struct.pack('<H', len(version)) + version
    return struct.pack('<I', 4 + len(body)) + body


class Client:
    """Reads whole frames, so a reply cut short at the stop is seen as one."""

    def __init__(self, path, talking):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(path)
        self.talking = talking
        self.replies = 0
        self.end = None
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def read_exact(self, n):
        out = b''
        while len(out) < n:
            piece = self.sock.recv(n - len(out))
            if not piece:
                return out
            out += piece
        return out

    def ask(self):
        self.sock.sendall(tversion())
        head = self.read_exact(4)
        if not head:
            return 'closed between replies'
        if len(head) < 4:
            return 'cut short inside a reply header'
        size = struct.unpack('<I', head)[0]
        rest = self.read_exact(size - 4)
        if len(rest) < size - 4:
            return 'cut short inside a reply'
        if rest[0] != RVERSION:
            return 'answered type %d' % rest[0]
        self.replies += 1
        return None

    def run(self):
        try:
            self.end = self.ask()
            while self.end is None and self.talking:
                self.end = self.ask()
            if self.end is None:
                # Idle: nothing more is sent, so only the daemon can end this read.
                self.end = 'closed between replies' if self.sock.recv(1) == b'' else 'sent an unasked byte'
        except (BrokenPipeError, ConnectionResetError):
            self.end = 'closed between replies'

    def close(self):
        self.sock.close()


class Daemon:
    def __init__(self, binary, work, workers, extra=()):
        self.fs_sock = os.path.join(work, 'f.sock')
        self.ctl_sock = os.path.join(work, 'c.sock')
        for path in (self.fs_sock, self.ctl_sock):
            if os.path.exists(path):
                os.unlink(path)
        self.log = open(os.path.join(work, 'serve.log'), 'wb')
        argv = [binary, 'serve', os.path.join(work, 'vol.stm'), '--listen', self.fs_sock,
                '--ctl-listen', self.ctl_sock, '--fs-workers', str(workers)] + list(extra)
        self.proc = subprocess.Popen(argv, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 60
        while not (os.path.exists(self.fs_sock) and os.path.exists(self.ctl_sock)):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('the daemon did not come up, rc=%s' % self.proc.poll())
            time.sleep(0.02)

    def stop_timed(self):
        started = time.monotonic()
        self.proc.send_signal(signal.SIGTERM)
        try:
            rc = self.proc.wait(BOUND_S)
        except subprocess.TimeoutExpired:
            return None, BOUND_S
        return rc, time.monotonic() - started

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def wait_for(cond, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def main():
    binary = os.path.abspath(sys.argv[1])
    work = tempfile.mkdtemp(prefix='stm-stop.')
    failures = []

    def ok(text):
        print('ok: %s' % text, flush=True)

    def no(text):
        print('FAIL: %s' % text, flush=True)
        failures.append(text)

    daemon = None
    try:
        made = subprocess.run([binary, 'mkfs', os.path.join(work, 'vol.stm'), '--size', '64M'],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if made.returncode != 0:
            no('mkfs: %s' % made.stdout[-200:])
            return 1

        # With no client at all, so that a slow stop further down is about the client.
        daemon = Daemon(binary, work, 1)
        rc, took = daemon.stop_timed()
        daemon.kill()
        if rc == 0:
            ok('no client: stopped in %.2f s' % took)
        else:
            no('no client: rc=%s after %.2f s' % (rc, took))

        for workers in (1, 4):
            for name, attr in (('9P', 'fs_sock'), ('/ctl/', 'ctl_sock')):
                for talking in (True, False):
                    what = '%s client %s, %d worker%s' % (name, 'talking' if talking else 'idle',
                                                          workers, '' if workers == 1 else 's')
                    daemon = Daemon(binary, work, workers)
                    client = Client(getattr(daemon, attr), talking)
                    need = 200 if talking else 1
                    if not wait_for(lambda: client.replies >= need, 30):
                        no('%s: only %d replies before any stop, ended %r' % (what, client.replies, client.end))
                        client.close()
                        daemon.kill()
                        continue
                    alive = daemon.proc.poll() is None
                    rc, took = daemon.stop_timed()
                    if rc == 0 and alive:
                        ok('%s: stopped in %.2f s after %d replies' % (what, took, client.replies))
                    else:
                        no('%s: rc=%s after %.2f s' % (what, rc, took))
                    daemon.kill()
                    client.thread.join(BOUND_S)
                    if client.thread.is_alive():
                        no('%s: the client was never told' % what)
                    elif client.end == 'closed between replies':
                        ok('%s: the client saw the end between whole replies' % what)
                    else:
                        no('%s: the client saw: %s' % (what, client.end))
                    client.close()

        # A client that asks and never reads: its replies fill both sockets, and the daemon's
        # write blocks with a request in hand. --idle-timeout 0 is how the manager runs it.
        for workers, (name, attr) in ((w, l) for w in (1, 4) for l in (('9P', 'fs_sock'), ('/ctl/', 'ctl_sock'))):
            what = '%s client not reading, %d worker%s' % (name, workers, '' if workers == 1 else 's')
            daemon = Daemon(binary, work, workers, ('--idle-timeout', '0'))
            sock = socket.socket(socket.AF_UNIX)
            sock.connect(getattr(daemon, attr))
            sock.setblocking(False)
            frames = tversion() * 4096
            off, stalls = 0, 0
            deadline = time.monotonic() + 20
            while stalls < 50 and time.monotonic() < deadline:
                if off == len(frames):
                    off = 0
                try:
                    off += sock.send(frames[off:off + 65536])
                    stalls = 0
                except BlockingIOError:
                    stalls += 1
                    time.sleep(0.02)
            served = bool(select.select([sock], [], [], 0)[0])
            if stalls < 50 or not served:
                no('%s: never filled the socket (stalls %d, replies waiting %s)' % (what, stalls, served))
                sock.close()
                daemon.kill()
                continue
            alive = daemon.proc.poll() is None
            rc, took = daemon.stop_timed()
            if rc == 0 and alive:
                ok('%s: stopped in %.2f s' % (what, took))
            else:
                no('%s: rc=%s after %.2f s, running before the stop: %s' % (what, rc, took, alive))
            daemon.kill()
            sock.close()

        # One client leaving ends nothing: the leg above would pass for a daemon that stops at any hangup.
        daemon = Daemon(binary, work, 1)
        client = Client(daemon.fs_sock, False)
        wait_for(lambda: client.replies >= 1, 30)
        client.close()
        time.sleep(0.5)
        if daemon.proc.poll() is None:
            ok('a client leaving does not stop the daemon')
        else:
            no('a client leaving stopped the daemon, rc=%s' % daemon.proc.returncode)

        # A write in progress: the stop may cut it off, and must say so or finish it, and must lose the volume to neither.
        source = os.path.join(work, 'big.bin')
        with open(source, 'wb') as out:
            out.write(os.urandom(8 << 20))
        # The control: the same command with no stop works, so a failure below is about the stop.
        with open(source, 'rb') as src:
            first = subprocess.run([binary, 'fs', '-s', daemon.fs_sock, 'write', '/first.bin'],
                                   stdin=src, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        back = subprocess.run([binary, 'fs', '-s', daemon.fs_sock, 'read', '/first.bin'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        with open(source, 'rb') as src:
            whole = src.read()
        if first.returncode == 0 and back.stdout == whole:
            ok('the same write with no stop comes back whole')
        else:
            no('the same write with no stop: rc=%d, %d bytes back: %s' % (first.returncode, len(back.stdout), first.stdout[-120:]))
        put = subprocess.Popen([binary, 'fs', '-s', daemon.fs_sock, 'write', '/big.bin'],
                               stdin=open(source, 'rb'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.05)
        rc, took = daemon.stop_timed()
        if rc == 0:
            ok('a write in progress: stopped in %.2f s' % took)
        else:
            no('a write in progress: rc=%s after %.2f s' % (rc, took))
        daemon.kill()
        try:
            put_rc = put.wait(BOUND_S)
        except subprocess.TimeoutExpired:
            put.kill()
            put.wait()
            put_rc = None
            no('the writer was never told the daemon had stopped')
        daemon = Daemon(binary, work, 1)
        got = subprocess.run([binary, 'fs', '-s', daemon.fs_sock, 'read', '/big.bin'],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if put_rc == 0:
            if got.returncode == 0 and got.stdout == whole:
                ok('the writer answered success and the file is whole after a remount')
            else:
                no('the writer answered success and the file is not whole: rc=%d, %d bytes' % (got.returncode, len(got.stdout)))
        elif put_rc is not None:
            ok('the writer answered failure (rc=%d) and the volume mounts, %d bytes there' % (put_rc, len(got.stdout)))
        rc, took = daemon.stop_timed()
        if rc == 0:
            ok('the volume mounts and stops after all of that')
        else:
            no('the last stop: rc=%s after %.2f s' % (rc, took))
    finally:
        if daemon:
            daemon.kill()
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
