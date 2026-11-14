#!/usr/bin/env python3
# How long a 100 ms nanosleep and a poll with a 100 ms timeout take on this machine (each 30 times), and a 1 ms
# nanosleep: does a sleep here oversleep, and does poll's timeout?
import ctypes, select, statistics, time
libc = ctypes.CDLL(None, use_errno=True)


class timespec(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_nsec', ctypes.c_long)]


def nanosleep(ms):
    ts = timespec(0, int(ms * 1e6))
    libc.nanosleep(ctypes.byref(ts), None)


def measure(name, f, n=30):
    took = []
    for _ in range(n):
        a = time.monotonic()
        f()
        took.append((time.monotonic() - a) * 1000)
    print('%-26s n=%d min %.1f median %.1f max %.1f ms' % (name, n, min(took), statistics.median(took), max(took)))


measure('nanosleep 100 ms', lambda: nanosleep(100))
measure('poll timeout 100 ms', lambda: select.poll().poll(100))
measure('nanosleep 1 ms', lambda: nanosleep(1), 200)
measure('nanosleep 64 ms', lambda: nanosleep(64))
