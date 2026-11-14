#!/usr/bin/env python3
# STM_PROBE_LOG read per manager: what it opened and why, the first refused writes, how many, the give-up.
import collections, sys
by = collections.OrderedDict()
for line in open(sys.argv[1], errors='replace'):
    pid, _, rest = line.rstrip('\n').partition(' ')
    by.setdefault(pid, []).append(rest)
for pid, lines in by.items():
    writes = [l for l in lines if l.startswith('write ') and ' refused=' in l and 'held after' not in l]
    print('== pid %s: %d lines, %d refused-write lines' % (pid, len(lines), len(writes)))
    for l in lines:
        if not l.startswith('write ') or 'held after' in l or ' error ' in l:
            print('   ' + l[:260])
    for l in writes[:6] + (['   ...'] if len(writes) > 7 else []) + writes[-1:] if len(writes) > 6 else writes:
        print('   ' + l[:260])
