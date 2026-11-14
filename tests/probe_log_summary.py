#!/usr/bin/env python3
# STM_PROBE_LOG (pid, ms, text) per manager: what it opened, the give-up, and the wall time from the first refused
# write after the stop was asked to the give-up, against the wait counted (waited_ms).
import collections, re, sys
by = collections.OrderedDict()
for line in open(sys.argv[1], errors='replace'):
    parts = line.rstrip('\n').split(' ', 2)
    if len(parts) < 3 or not parts[1].isdigit():
        continue
    by.setdefault(parts[0], []).append((int(parts[1]), parts[2]))
for pid, lines in by.items():
    print('== pid %s: %d lines' % (pid, len(lines)))
    first_asked = None
    for ms, l in lines:
        if 'asked=true' in l and first_asked is None:
            first_asked = (ms, l)
        if not l.startswith('write ') or 'held after' in l or ' error ' in l:
            print('   %d %s' % (ms, l[:230]))
            m = re.search(r'held after refused=(\d+) waited_ms=(\d+)', l)
            if m and first_asked:
                print('   -> from the first refusal after the asking (%s) to the give-up: %d ms wall, %s ms counted'
                      % (first_asked[1].split(' asked')[0][-14:], ms - first_asked[0], m.group(2)))
