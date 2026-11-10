# How much of a paste a pty takes in at once with no reader, and whether TCIFLUSH on the slave
# empties all of it: a second write after the discard takes as much again if it did.
import fcntl, os, pty, sys, termios, tty
m, s = pty.openpty()
tty.setraw(s)
fcntl.fcntl(m, fcntl.F_SETFL, fcntl.fcntl(m, fcntl.F_GETFL) | os.O_NONBLOCK)
def fill():
    total = 0
    while True:
        try:
            n = os.write(m, b'a' * 4096)
        except BlockingIOError:
            return total
        if n == 0:
            return total
        total += n
first = fill()
termios.tcflush(s, termios.TCIFLUSH)
second = fill()
termios.tcflush(s, termios.TCIFLUSH)
fcntl.fcntl(s, fcntl.F_SETFL, fcntl.fcntl(s, fcntl.F_GETFL) | os.O_NONBLOCK)
try:
    left = len(os.read(s, 1 << 20))
except BlockingIOError:
    left = 0
print(f'{sys.platform}: taken at once {first} bytes; after the discard {second} more; left after a second discard {left}')
