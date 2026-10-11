# Same-size truncate timestamp repair — October 11

Owner and reviewer: Astra, single-agent self-review under the operator's
explicit workflow. This is not an independent audit. Parent checkpoint is
7cc86d9, which retains the separate sparse-growth repair.

## Trigger and correction

Native Ninja 1.13.2 compiles and links an ordinary-user C program, but its next
unchanged invocation relinks. Runtime4's raw `-d explain` trace reports recorded
output mtime1791723488 less than object mtime1791723530. Ninja refreshes an
empty build lock file with fopen("wb") before each edge; Stratum's same-size
truncate short-circuit retained the first edge's timestamp. The subsequent
invocation recreates the lock, so the third run happens to be clean.

POSIX ftruncate requires mtime/ctime updates on successful regular-file
truncation; O_TRUNC on an existing empty file also requires them. The former
R81 P3-5 regression pinned a contrary assumption. Its clock-advance assertions
are corrected rather than silently removed. The zero-length-write no-stamp
regression is unchanged. Normative links are in reference/16-inode.md.

## Mechanism review

The repair stays inside the existing SH global guard and per-inode pin. The
pre-flush still precedes lookup/validation; inode_set publishes timestamps
through the same internally locked path as other truncate branches and
advances the established metadata version when the record actually changes.
The shared out label always unpins/unlocks and propagates publication errors.
No new allocation, extent mutation, data layout, API, nonce or lock ordering.
The same-size branch remains before size-changing seal checks intentionally:
seals still forbid the same writes/growth/shrink as before, while unchanged
bytes/length can receive metadata timestamps. atime/btime and all seal bits
are preserved. No claim of timestamp monotonicity across wall-clock changes.

Existing inode Set models metadata publication; timestamps are not state in
that model. No new model or changed model outcome is claimed for this fix.

## Verification

Evidence is in Thylacine Astra `work/oct11-native-tools/`.
- Baseline7cc86d9 plus new regression:224 pass,1 fail; oldmtime456 is retained.
- New regression: empty, nonempty inline, sealed extent, unchanged metadata
  except modification clocks/version, byte readback and commit/remount.
- First wider test attempt exposes the old R81 expectation and is stopped by
  the disk guard. That attempt is retained and is not a passing gate.
- After the contract/test correction and scratch reclamation: all73 CTest
  suites pass serially; all225 phase8 tests pass LLVM22 ASan+UBSan.
- Rebuilt Pouch storage daemon succeeds with explicit external source path.
- Source-matched guest runtime5: uid1000 native compile/run, immediate no-op
  incremental builds before/after a header change, depfile-driven rebuild,
  two-job mutual-start barrier, and child exit7 propagation all verified.
  The first script incorrectly expected Ninja exit1. Its raw failed assertion
  remains; a separately hashed same-guest tail confirms the correct exit7,
  absent failed output and sync exit0. No compilation was rerun for this fix.
- The runner subsequently stopped on its conservative disk guard after the
  tail's FOLLOWUP-END. `runtime5/result.json` records stage-level evidence,
  not a clean whole-harness pass. Completed scratch disks were reclaimed with
  hashes; original fixture, initrd, source receipts and outputs are retained.
  The earlier parallel host attempt briefly outran its 64MiB guard margin;
  final host verification was serial and the guest guard margin was raised
  to256MiB. Future broad jobs need more free headroom, not a lower floor.

The earlier kernel50-boot matrix applies only to its recorded kernel/source;
this filesystem-userspace repair does not acquire new whole-OS qualification.
Ninja's descriptor and signal compatibility gaps remain open and independent.
