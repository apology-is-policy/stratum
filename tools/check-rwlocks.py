#!/usr/bin/env python3
"""Every reader-writer lock in src/ is an stm_rwlock: a pthread_rwlock_ name
in code outside the gate (src/util/rwlock.c) fails, since a library lock
may prefer readers (musl's, glibc's default) and let them starve a writer.
Comments and strings are not code."""
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = {ROOT / 'src/util/rwlock.c'}


def code_of(src):
    out, i, n = [], 0, len(src)
    while i < n:
        if src.startswith('/*', i):
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append('\n' * src.count('\n', i, j))
            i = j
        elif src.startswith('//', i):
            j = src.find('\n', i)
            i = n if j < 0 else j
        elif src[i] in '"\'':
            q, j = src[i], i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == '\\' else 1
            out.append(q + q)
            i = j + 1
        else:
            out.append(src[i])
            i += 1
    return ''.join(out)


def uses():
    found, scanned = [], 0
    for p in sorted((ROOT / 'src').rglob('*')):
        if p.suffix not in ('.c', '.h') or p in GATE:
            continue
        scanned += 1
        code = code_of(p.read_text(errors='replace'))
        for k, line in enumerate(code.splitlines(), 1):
            if re.search(r'\bpthread_rwlock\w*', line):
                found.append('%s:%d: %s' % (p.relative_to(ROOT), k,
                                             line.strip()))
    return found, scanned


def main():
    found, scanned = uses()
    if scanned < 100:
        print('check-rwlocks: scanned only %d files under %s' %
              (scanned, ROOT / 'src'))
        return 1
    if found:
        print('check-rwlocks: a library rwlock outside src/util/rwlock.c '
              '(use stm_rwlock):')
        print('\n'.join(found))
        return 1
    print('check-rwlocks: %d files, every rwlock is an stm_rwlock' % scanned)
    return 0


sys.exit(main())
