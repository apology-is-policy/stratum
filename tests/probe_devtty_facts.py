#!/usr/bin/env python3
# /dev/tty on this system, measured: a child leads a session with a pty for its controlling terminal that nothing
# reads. Its /dev/tty opened as a shell's `> /dev/tty` opens it: what ttyname, fstat and tcgetsid say of it; the
# name opened again; then a non-blocking open of /dev/tty, and of the pty's name, filled: does the write refuse
# (EAGAIN) or wait (an alarm says), and what does poll answer, how fast?
import ctypes, errno, fcntl, os, select, signal, termios, time
libc = ctypes.CDLL(None, use_errno=True)
m, s = os.openpty()
pty_name = os.ttyname(s)
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    out = []

    def say(x):
        out.append(x)

    class Waited(Exception):
        pass

    def alarm(*_):
        raise Waited()

    signal.signal(signal.SIGALRM, alarm)
    try:
        os.setsid()
        fcntl.ioctl(s, termios.TIOCSCTTY, 0)
        say('getsid(0)=%d getpgrp=%d pid=%d' % (os.getsid(0), os.getpgrp(), os.getpid()))
        sh = os.open('/dev/tty', os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        st = os.fstat(sh)
        try:
            tn = os.ttyname(sh)
        except OSError as e:
            tn = 'ERR %s' % errno.errorcode.get(e.errno, e.errno)
        ctypes.set_errno(0)
        sid = libc.tcgetsid(sh)
        say("shell's /dev/tty: rdev %d,%d ttyname=%s tcgetsid=%d (errno %s) isatty=%d" % (
            os.major(st.st_rdev), os.minor(st.st_rdev), tn, sid, errno.errorcode.get(ctypes.get_errno(), 0),
            os.isatty(sh)))
        if not tn.startswith('ERR'):
            try:
                again = os.open(tn, os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
                st2 = os.fstat(again)
                say('its name opened again: rdev %d,%d (same rdev: %s)' % (
                    os.major(st2.st_rdev), os.minor(st2.st_rdev), st2.st_rdev == st.st_rdev))
                os.close(again)
            except OSError as e:
                say('its name opened again: ERR %s' % errno.errorcode.get(e.errno, e.errno))
        ctypes.set_errno(0)
        sid2 = libc.tcgetsid(s)
        say('the pty slave: tcgetsid=%d (errno %s)' % (sid2, errno.errorcode.get(ctypes.get_errno(), 0)))
        for path in ('/dev/tty', pty_name):
            fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK | os.O_NOCTTY)
            st = os.fstat(fd)
            put, refused = 0, None
            t0 = time.monotonic()
            while time.monotonic() - t0 < 3:
                signal.alarm(2)
                try:
                    put += os.write(fd, b'x' * 1024)
                except Waited:
                    refused = 'WAITED 2 s IN THE WRITE'
                    break
                except OSError as e:
                    refused = errno.errorcode.get(e.errno, e.errno)
                    break
                finally:
                    signal.alarm(0)
            polls = []
            p = select.poll()
            p.register(fd, select.POLLOUT)
            for _ in range(3):
                a = time.monotonic()
                ev = p.poll(100)
                polls.append('%s in %.1f ms' % (ev, (time.monotonic() - a) * 1000))
            signal.alarm(2)
            try:
                os.write(fd, b'y')
                again = 'took it'
            except Waited:
                again = 'WAITED 2 s IN THE WRITE'
            except OSError as e:
                again = errno.errorcode.get(e.errno, e.errno)
            finally:
                signal.alarm(0)
            say('%s non-blocking (rdev %d,%d): put %d then %s; poll: %s; write again: %s' % (
                path, os.major(st.st_rdev), os.minor(st.st_rdev), put, refused, ' | '.join(polls), again))
            os.close(fd)
    except Exception as e:
        say('child error: %r' % (e,))
    os.write(w, ('\n'.join(out) + '\n').encode())
    os._exit(0)
os.close(w)
# Nothing read while the child fills and polls the first open; then the master is drained.
time.sleep(3)
buf = b''
deadline = time.monotonic() + 20
os.set_blocking(m, False)
os.set_blocking(r, False)
while time.monotonic() < deadline:
    try:
        while os.read(m, 65536):
            pass
    except OSError:
        pass
    try:
        chunk = os.read(r, 65536)
        if not chunk:
            break
        buf += chunk
    except BlockingIOError:
        pass
    time.sleep(0.05)
os.waitpid(pid, 0)
print('POLLOUT=%d POLLNVAL=%d POLLERR=%d POLLHUP=%d' % (select.POLLOUT, select.POLLNVAL, select.POLLERR, select.POLLHUP))
print(buf.decode(errors='replace'))
