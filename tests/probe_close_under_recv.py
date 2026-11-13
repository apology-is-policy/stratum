#!/usr/bin/env python3
"""What a close() does to a recv() another thread is waiting in, and what the peer sees of it.
One connected pair; a thread waits in recv on one end; the main thread closes that end (or stops
sending on it first); the other end is polled for the end of the stream."""
import select
import socket
import sys
import threading
import time


def once(how):
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    seen = {}

    def reader():
        try:
            seen['recv'] = repr(a.recv(1))
        except OSError as e:
            seen['recv'] = 'OSError %d %s' % (e.errno, e.strerror)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    time.sleep(0.3)
    if how == 'close':
        a.close()
    elif how == 'shut_wr':
        a.shutdown(socket.SHUT_WR)
    elif how == 'shut_rdwr+close':
        a.shutdown(socket.SHUT_RDWR)
        t.join(2)
        a.close()
    peer_eof = None
    if select.select([b], [], [], 2.0)[0]:
        peer_eof = b.recv(1) == b''
    if how == 'shut_wr':
        b.close()  # the peer, having read the end, closes: what the waiting read returns on
    t.join(2)
    print('%s %-15s: the waiting recv: %s; the peer read the end within 2 s: %s'
          % (sys.platform, how, 'still waiting' if t.is_alive() else seen.get('recv'), peer_eof))


for how in ('close', 'shut_wr', 'shut_rdwr+close'):
    once(how)
