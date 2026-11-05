# R172 audit findings — R171 close (3264887)

Scope: 3264887 ("R171 close: SH-fallback for wait-free reads + doctrine carry").

R171 audited the 9.8-LF-3 series and surfaced 4 P0 + 4 P1 + 6 P2 + 10 P3
findings. The R171 close commit landed three classes of fix:

  1. SH-fallback at every wait-free read entry (P1-1 / P1-2 / P2-6
     closure). On `STM_ECORRUPT` from the wait-free path, drop EBR +
     acquire `fs->global` SH + retry through the serial subsystem call.
  2. Documentation updates for the LF-3 contract (P1-3 + P3-3 + P3-6).
  3. Typo fix (P3-1).

The four P0 UAF surfaces (P0-1 leaf-value, P0-2 engine struct, P0-3
fs lifetime, P0-4 mvcc_root) are EXPLICITLY DEFERRED — three to
BE-prepend (#1218) and the dedicated R171-followup chunk, one to
unmount-quiesce work. R172 does NOT re-report these.

The R172 audit asks: did the close commit's SH-fallback strategy
actually close the P1 it was designed to close, and did the fix
introduce any new bugs? Findings below.

## P0 (critical)

(none — the SH-fallback strategy does not introduce new UAFs or
deadlocks; the remaining UAF surfaces are the documented R171 P0s
that are explicitly deferred.)

## P1 (severe)

### P1-1: `stm_fs_listxattr` returns STM_ERANGE to the caller on a NORMAL writer-adds-xattr race; the SH-fallback strategy does not catch this case

`v2/src/fs/fs.c:5722-5734` (the wait-free listxattr's materialize
pass):

  ```c
  stm_status ls = stm_xattr_list_concurrent(xidx, ebr, dataset_id, ino,
                                               batch, n_total, &got);
  /* R171 P1-2: count-vs-materialize TOCTOU under same-engine
   * writer → treat count-mismatch as STM_ECORRUPT + fall back. */
  if (ls == STM_ECORRUPT || (ls == STM_OK && got != n_total)) {
      free(batch);
      batch = NULL;
      need_fallback = true;
  } else if (ls != STM_OK) {
      free(batch);
      stm_ebr_exit(ebr);
      return ls;        /* <-- HERE: STM_ERANGE propagated to caller */
  }
  ```

The R171 close commit claims the listxattr fallback "also closes P1-2
count-vs-materialize TOCTOU by collapsing both passes into the
fallback when wait-free returns STM_ECORRUPT". This is INCOMPLETE.

`stm_xattr_list_concurrent` returns STM_ERANGE (not STM_ECORRUPT and
not STM_OK with got != n_total) when `c.n_total > max_entries`. See
`v2/src/xattr/xattr.c:1077`:

  ```c
  *out_total = c.n_total;
  if (max_entries == 0u) return STM_OK;          /* probe-only */
  if (max_entries < c.n_total) return STM_ERANGE;
  return STM_OK;
  ```

The callback at `xattr.c:944-963` increments `c.n_total` for EVERY
live record (no early-stop), even past `out_cap`. So a writer that
ADDS an xattr between the wait-free's first pass (count) and second
pass (materialize) makes the second pass see `c.n_total = N+1 >
max_entries = N` and return STM_ERANGE.

The fs.c check at line 5726 has three branches:
- `ls == STM_ECORRUPT` → fall back ✓
- `ls == STM_OK && got != n_total` → fall back ✓
- otherwise: `else if (ls != STM_OK)` → return `ls` directly

STM_ERANGE falls into the third branch and propagates to the caller.

**This is a NORMAL race condition** — under same-engine concurrent
writer adding xattrs, `stm_fs_listxattr` returns STM_ERANGE to the
9P server / TUI / /ctl/ caller, who treats it as "your buffer is too
small" (POSIX listxattr ERANGE semantic) and may retry with a
larger buffer, looping forever as long as the writer keeps adding
xattrs faster than the reader can retry. Or the caller may surface
STM_ERANGE as a hard error.

**Reproduction**: pair a writer thread doing
`stm_fs_setxattr(... "user.a%d", ..., value)` in a loop with a
reader thread doing `stm_fs_listxattr(... NULL, 0, ...)` on the same
inode. The reader will see STM_ERANGE roughly proportional to
contention rate.

**Fix sketch**: extend the wait-free check to ALSO fall back on
STM_ERANGE from the materialize pass:

  ```c
  if (ls == STM_ECORRUPT || ls == STM_ERANGE
      || (ls == STM_OK && got != n_total)) {
      free(batch);
      batch = NULL;
      need_fallback = true;
  } else if (ls != STM_OK) { ... }
  ```

Note: STM_ERANGE from the materialize pass with `max_entries =
n_total` is a TOCTOU symptom (counts diverged between passes), NOT a
real "buffer too small" condition (the buffer was sized to match
n_total). The wait-free path's two-pass shape is the cause; the SH
fallback's two-pass is excluded by SH-vs-EX (writers take EX), so the
fallback path correctly sees `got == n_total` always.

Cite: `v2/src/fs/fs.c:5722-5734`, `v2/src/xattr/xattr.c:1067-1078`,
`v2/src/xattr/xattr.c:944-963`.

### P1-2: SH-fallback strategy catches only the STM_ECORRUPT subclass of torn-reads; torn-reads that pass validation but produce spurious non-ECORRUPT errors are NOT caught

The R171 close commit's central claim: "On `STM_ECORRUPT` from the
wait-free path (transient torn-state under same-engine concurrent
writer), the reader drops EBR + acquires `fs->global` SH + retries
via the serial subsystem call ... The user-visible result is a
slow-path retry on contention, not propagation of a spurious
STM_ECORRUPT."

This is INCOMPLETE. The SH-fallback is gated on `STM_ECORRUPT` ONLY
(not on any other status). But torn-reads from the LF-2 substrate
(P0-1 leaf-value UAF) can produce:

  (a) **STM_OK with stale-but-coherent bytes**: the reader's memcpy
      from a freed-and-reallocated buffer reads bytes that happen to
      be a previous coherent version of the same inode (allocator
      reuse, tcache hit on a 256-byte slot). `in_validate_value`
      passes (same dataset_id/ino). The wait-free reader returns OK
      with stale data. POSIX-acceptable (read concurrent with write
      returns either-old-or-new).

  (b) **STM_OK with byte-coherent garbage from a different lifetime
      of the same inode**: the freed buffer contained bytes from a
      prior FREED → ALLOCATED cycle that had been INLINE-mode with
      `si_data_kind = INLINE` and `si_data_len = 50` but had
      different timestamps / mode / si_size from the current
      lifetime. The reader sees this as a valid INLINE inode and may
      return wrong data.

  (c) **STM_ENOTDIR on a real directory's torn parent-mode read**:
      `stm_fs_lookup` line 2299 and `stm_fs_name_to_handle` line 4404
      check `(pmode & S_IFMT) != S_IFDIR` and return STM_ENOTDIR if
      so. A torn read of the parent's si_mode field (e.g., if a
      writer is in the middle of `stm_inode_set` and the wait-free
      reader sees stale-byte si_mode that happens to have bits NOT
      indicating S_IFDIR — extremely narrow, but theoretically
      reachable via the P0-1 UAF window) returns STM_ENOTDIR for a
      directory that IS a directory.

  (d) **OOB-stack-read on torn INLINE si_size > STM_INODE_INLINE_MAX**:
      `stm_fs_read`'s wait-free INLINE branch (line 2113-2126) checks
      `iv.si_data_len <= STM_INODE_INLINE_MAX` but does NOT verify
      `iv.si_size <= STM_INODE_INLINE_MAX`. A torn read where the
      bytes pass validation but have `si_data_kind = INLINE`,
      `si_data_len <= 100`, and `si_size > 100` (theoretically
      reachable from the P0-1 UAF window if the freed buffer's bytes
      come from a different lifetime of the same inode when it had
      been EXTENT-mode with large si_size) would do
      `memcpy(buf, iv.si_data.inline_data + off, cur_size - off)`
      where `cur_size - off` could be hundreds of bytes past the
      100-byte inline_data array's end. **OOB-read past inline_data's
      end into stack memory of `iv`'s adjacent struct fields and
      possibly past the 256-byte struct's stack frame**, leaking
      stack contents into the caller's buffer.

      The serial path `fs_read_regular_locked` (`fs.c:1866-1875`) has
      the same shape, but the serial path is excluded from torn reads
      by `idx_lock`. So this gap is specifically a wait-free
      regression.

  (e) **Spurious STM_ENOENT** on lookup or open_by_handle when a
      torn `STM_INO_FLAG_FREED` bit happens to be set in stale bytes.
      `stm_inode_lookup_concurrent` line 938 returns STM_ENOENT when
      `STM_INO_FLAG_FREED` is set. `in_validate_value` line 261-263
      enforces FREED → nlink=0, but a torn (nlink=0, FREED=1) combo
      could pass validation while the inode is alive (the writer
      hadn't yet finished updating its bytes). Caller sees ENOENT for
      a live inode.

In each case, the SH-fallback's STM_ECORRUPT gate fails to fire, and
the spurious result propagates to the caller. The R171 commit
message's framing ("turns visible symptom from STM_ECORRUPT into
slow-path retry") is correct for the specific subclass that DOES
fire STM_ECORRUPT through `in_validate_value`, but understates the
non-ECORRUPT symptom classes.

**Realistic reachability**: most of these (b/c/d/e) require very
narrow byte coherence on freed-buffer contents. Modern allocators
(jemalloc / tcmalloc / glibc) reuse 256-byte slots quickly under
contention, so adversarial heap pressure could produce bytes that
pass validation but mismatch reality. ASan-managed allocators may
unmap freed slots, in which case the reader's memcpy faults instead
— probably surfacing as STM_EBACKEND or STM_ECORRUPT (caught by
fallback) rather than the spurious-success scenarios above. Without
ASan, the spurious-success scenarios are theoretically reachable but
hard to reproduce deterministically.

**Severity**: P1 because the spurious-success scenarios can leak
data (stale bytes or stack contents into caller's buffer) or cause
hard-to-diagnose application errors. The OOB-stack-read in (d) is
the most acute — it can leak adjacent stack memory through the
caller's buffer.

**Fix sketch**: this is fundamentally the P0-1 UAF surface;
BE-prepend's CAS-prepend writer is the true closure. As a stopgap,
the wait-free read paths could add cross-field consistency checks
post-decode (e.g., for INLINE: `iv.si_size <= STM_INODE_INLINE_MAX`;
for the FREED bit + nlink combo: extra paranoia). But each added
check is just a wider STM_ECORRUPT net; the SH-fallback only handles
that one path.

The most actionable fix: add the `si_size <= STM_INODE_INLINE_MAX`
check for INLINE-mode regular files in `stm_fs_read`'s wait-free
branch (and the same in `fs_read_regular_locked` for defense-in-depth,
even though the serial path can't see the torn). On violation:
fall through to SH-rdlock path (treat as torn-state and let the
serial re-read decide).

Cite: `v2/src/fs/fs.c:2099-2128` (stm_fs_read INLINE wait-free
branch — missing si_size <= INLINE_MAX check), `v2/src/fs/fs.c:2299`
(lookup parent-dir check), `v2/src/fs/fs.c:4404` (name_to_handle
parent-dir check), `v2/src/inode/inode.c:229-266` (in_validate_value
— doesn't check si_size <= si_data_len for INLINE), `v2/src/inode/
inode.c:938` (FREED filter).

## P2 (substantive)

### P2-1: `stm_fs_open_by_handle` post-fallback `stm_inode_next_ino` runs OUTSIDE both EBR and SH; uses post-SH-unlock `iidx` value

`v2/src/fs/fs.c:4554-4575`:

  ```c
  stm_ebr_enter(ebr);
  stm_status ls = stm_inode_lookup_concurrent(iidx, ebr, ds, ino, &v);
  stm_ebr_exit(ebr);
  if (ls == STM_ECORRUPT) {
      pthread_rwlock_rdlock(&fs->global);
      FS_GUARD_READ(fs);
      iidx = stm_sync_inode_index(fs->sync);
      ...
      ls = stm_inode_lookup(iidx, ds, ino, &v);
      pthread_rwlock_unlock(&fs->global);    /* <-- SH unlocked */
  }
  if (ls == STM_ENOENT) {
      uint64_t next_ino = 0;
      stm_status ns = stm_inode_next_ino(iidx, ds, &next_ino);  /* <-- uses iidx outside both EBR + SH */
      ...
  }
  ```

After the SH unlock at line 4566, line 4572's `stm_inode_next_ino`
uses `iidx` without holding any guard. The comment at 4569 says
"stm_inode_next_ino takes its own subsystem-internal mutex; safe
without fs->global". TRUE for inode-index consistency. NOT true for
inode-index LIFETIME — if `stm_fs_unmount` races, `iidx` is freed
between SH-unlock and next_ino call.

This composes with the documented R171 P0-3 (unmount-quiesce), so
it's not a NEW UAF. But the SH-fallback REINTRODUCES the gap that
the prior `stm_inode_lookup` call closes (the call was inside the
SH block). A version of the fallback that hoisted `stm_inode_next_ino`
inside the SH block would close this specific gap (without solving
the broader P0-3) — and the existing wait-free `iidx` at line 4542
already has the same gap, so the SH-fallback's symmetry is the
existing posture.

**Fix sketch**: defer to P0-3 closure (forward-noted to a dedicated
chunk).

Cite: `v2/src/fs/fs.c:4554-4575`, `v2/src/fs/fs.c:4569` (the
"safe without fs->global" comment that elides the lifetime issue).

### P2-2: `stm_fs_listxattr` SH-fallback's "treat count-mismatch as STM_ECORRUPT" residual check is structurally unreachable under SH-vs-EX

`v2/src/fs/fs.c:5773-5778` (fallback block):

  ```c
  ls2 = stm_xattr_list(xidx, dataset_id, ino, batch, n_total, &got);
  pthread_rwlock_unlock(&fs->global);
  if (ls2 != STM_OK || got != n_total) {
      free(batch);
      return (ls2 != STM_OK) ? ls2 : STM_ECORRUPT;
  }
  ```

The fallback holds `fs->global` SH across BOTH the count probe AND
the materialize pass. All xattr-writers (`stm_fs_setxattr`,
`stm_fs_removexattr`) take fs->global EX, which is excluded by SH.
Between the fallback's pass 1 (line 5753) and pass 2 (line 5773),
NO writer can mutate the xattr index. So `got == n_total` is
guaranteed under SH.

The `got != n_total` branch at line 5775 is defensive-only — under
the SH-vs-EX contract it never fires. The branch is harmless but
the comment at line 5724 ("the writer's serial idx-mutex excludes
us from the torn window") is INACCURATE: it's the fs->global SH-vs-
EX exclusion, NOT the xattr-index's internal mutex, that closes
the TOCTOU window.

If a future writer is ported to SH (e.g., a hypothetical setxattr
port that takes SH + per-inode pin), the SH-fallback's two-pass
shape STOPS being safe — the idx-internal mutex is released between
the two passes, and another SH-holding writer could fire setxattr
between them. The R171 close commit's listxattr fallback presumes
EX-vs-SH exclusion will hold; this should be documented as a
forward-compat constraint.

**Fix sketch**: update the comment at line 5724 to credit the
correct exclusion mechanism. Add a forward-note that listxattr's
SH-fallback assumes all xattr-writers hold EX (not SH). When the
PARALLEL-3 impl-N or future ports lift xattr-writers to SH, the
fallback must be revisited (e.g., wrap both passes in a per-inode
pin, or use a single-pass primitive).

Cite: `v2/src/fs/fs.c:5724` (comment), `v2/src/fs/fs.c:5775`
(defensive check), `v2/src/fs/fs.c:5514,5825` (xattr writers hold
wrlock — confirmed at the time of audit).

### P2-3: Per-fallback re-resolution of `iidx` / `xidx` / `didx` is defensive-only; same pointer values, same lifetime gap

Every SH-fallback block re-fetches the subsystem indices:

  ```c
  iidx = stm_sync_inode_index(fs->sync);
  xidx = stm_sync_xattr_index(fs->sync);    /* if applicable */
  didx = stm_sync_dirent_index(fs->sync);   /* if applicable */
  if (!iidx || ...) { unlock; return STM_EINVAL; }
  ```

The wait-free path's iidx is the SAME pointer (set once at mount
in `stm_sync_open`, immutable). The re-fetch is defensive belt-and-
suspenders; the !iidx check is unreachable in normal operation.

This is fine for clarity but adds 3-5 lines per fallback × 10
fallbacks = 30-50 lines of effectively dead code. A helper macro
would reduce this:

  ```c
  #define FS_SH_FALLBACK_RESOLVE_IDXS(fs, var_iidx, var_xidx, var_didx) ...
  ```

But the explicit form is more readable for an audit. Minor P2.

**Fix sketch**: leave as-is until the duplication grows.

Cite: `v2/src/fs/fs.c:3315`, `:4019`, `:4334`, `:4451-4452`,
`:4560`, `:5641-5642`, `:5742-5743`, `:5368-5369`, `:2328-2329`,
`:3315`.

### P2-4: Reader-stale-data semantics for non-ECORRUPT torn reads not documented in the public API contract

`v2/include/stratum/fs.h` docstrings for `stm_fs_stat`, `_lookup`,
`_readlink`, etc. don't mention the LF-3 wait-free torn-read
semantic. The R171 close commit added a block to `fs.c:35-66`'s
lock-hierarchy comment about the LF-3 regime, but the header file's
public API contract is unchanged.

Callers (9P server, /ctl/, slate, TUI) reading the public docstring
assume:
- STM_OK: succeeded, out-params valid.
- STM_ECORRUPT: filesystem corruption detected; volume is suspect.

Under LF-3:
- STM_OK: succeeded with EITHER current-or-stale bytes (POSIX
  semantics for read-concurrent-with-write).
- STM_ECORRUPT: still means filesystem corruption (the SH-fallback
  retries and the serial path confirms).

POSIX-aligned, but callers that treat STM_ECORRUPT as "volume is
toast" need to know that under LF-3, STM_ECORRUPT is reserved for
the SERIAL path's verdict — the wait-free path's STM_ECORRUPT is
transient and now invisible to callers (thanks to the fallback).

**Fix sketch**: add a paragraph to each LF-3 reader's docstring in
`fs.h` documenting the wait-free + SH-fallback semantic. Forward-
noted; not urgent.

Cite: `v2/include/stratum/fs.h`.

### P2-5: `stm_fs_read` INLINE wait-free branch silently falls through to SH on torn `si_data_len > MAX`, but the FALLBACK SH path may have writer's coherent post-mutation state — possible "double-decode" of the same data via two different read paths

`v2/src/fs/fs.c:2102-2133` (wait-free INLINE):

  ```c
  if ((mode & (uint32_t)S_IFMT) == (uint32_t)S_IFREG
      && iv.si_data_kind == STM_DATA_INLINE) {
      if (iv.si_data_len <= STM_INODE_INLINE_MAX) {
          /* serve from inline_data */
          memcpy(buf, iv.si_data.inline_data + off, copy_n);
          ...
          return STM_OK;
      }
      /* torn data_len > MAX → fall through to SH path. */
  }
  ```

If the wait-free read returns STM_OK with stale bytes, the caller
sees stale data. If the wait-free read returns STM_ECORRUPT, the
fallback fires. If the wait-free read returns torn `si_data_len >
MAX` (R171 P2-6), the fall-through to SH fires.

But there's a subtle case: the WAIT-FREE PATH MAY HAVE COPIED bytes
into `buf` BEFORE the torn `si_data_len > MAX` was detected. Wait —
actually no: the fall-through happens BEFORE the memcpy (line 2112
gates the memcpy block). So `buf` is untouched on the torn
fall-through. ✓

But the OOB-read concern from P1-2 (d) is also relevant here. Both
torn `si_data_len > MAX` AND torn `si_size > MAX` need to be
handled — but only the former is caught.

**Fix sketch**: in the wait-free INLINE branch, also gate the
memcpy on `cur_size <= STM_INODE_INLINE_MAX`. If `cur_size > MAX`,
fall through to SH.

Cite: `v2/src/fs/fs.c:2102-2128`.

### P2-6: `engine.c` docstring update at lines 199-202 is internally inconsistent with the R171 update at lines 206-228

`v2/src/btree_engine/engine.c:199-202`:

  ```
   *   - Serial-path callers (lookup / insert / delete / scan /
   *     commit_flush) — rely on the fs.c-level `fs->global` EX lock OR
   *     a test discipline of single-threaded use. They do NOT take
   *     commit_mu.
  ```

This is the OLD claim that serial-path callers (writers) hold EX.

`v2/src/btree_engine/engine.c:206-208`:

  ```
   * R171 update post-LF-3: serial-path writers (commit_flush, insert,
   * delete) now hold `fs->global` SH (PARALLEL-3 impl-5/6) and
   * wait-free readers hold NO `fs->global` lock at all.
  ```

The R171 update directly contradicts the lines 199-202 block. A
reader unfamiliar with the project's history (e.g., a new
contributor) would be confused.

**Fix sketch**: rewrite the lines 199-202 block to reflect post-
PARALLEL-3 impl-5/6 reality ("serial-path writers hold `fs->global`
SH"), or delete it and merge with the R171 update.

Cite: `v2/src/btree_engine/engine.c:199-208`.

## P3 (light)

### P3-1: Multiple wait-free read paths skip the parent-mode validation on STM_ECORRUPT but propagate STM_ENOTDIR on torn-mode-bits

`v2/src/fs/fs.c:2298-2302` (stm_fs_lookup):
`v2/src/fs/fs.c:4403-4407` (stm_fs_name_to_handle):

  ```c
  if (ps == STM_OK) {
      uint32_t pmode = stm_load_le32(pv.si_mode);
      if ((pmode & (uint32_t)S_IFMT) != (uint32_t)S_IFDIR) {
          stm_ebr_exit(ebr);
          return STM_ENOTDIR;
      }
  }
  ```

If the wait-free read returns STM_OK with TORN si_mode that doesn't
match S_IFDIR (despite the parent being a real directory), the call
returns STM_ENOTDIR without falling back. The SH-fallback only fires
on STM_ECORRUPT.

Reachability is narrow (requires byte-coherence on stale mode bits),
but the SH-fallback gate isn't comprehensive.

**Fix sketch**: deliberately route the STM_ENOTDIR-from-wait-free
path through the fallback too. Or treat all wait-free non-OK
returns from the parent lookup as fallback candidates. Pre-existing
analysis matches the P1-2 framing.

Cite: as above.

### P3-2: The R171 docstring at engine.c lines 206-225 over-claims "Stopgap: SH-fallback at every public reader (R171 P1-1) turns the visible symptom into a slow-path retry"

This statement is correct for the STM_ECORRUPT subclass of torn
reads. It is INCOMPLETE for the non-ECORRUPT classes documented in
this R172 audit's P1-2 + P2-5. A more accurate framing:

  "Stopgap: SH-fallback at every public reader (R171 P1-1) catches
   the STM_ECORRUPT subclass of torn reads (the in_validate_value
   surface) — other torn-read symptoms (stale-coherent bytes,
   spurious STM_ENOTDIR/ENOENT, potential OOB-stack-reads on
   inconsistent si_size + si_data_len for INLINE) propagate
   to the caller as visible regressions and require BE-prepend
   for true closure."

**Fix sketch**: tighten the docstring at the next docstring update.

Cite: `v2/src/btree_engine/engine.c:213-217`.

### P3-3: The R171 close commit's CLAUDE.md / scripture row update isn't included in this commit

R171 P1-3 + P3-3 closure documented the wait-free path's regime in
`fs.c:35-66` (lock-hierarchy comment) and `fs.c:209-228` (struct
stm_fs atomic-wedged comment). But CLAUDE.md's trust-list "Sync /
rollback / mount-bump flow" row + "Inode allocator" row + other
relevant rows still don't mention the LF-3 caller obligation
(reader-quiesce-before-unmount).

The R171 close commit's body mentioned this would be done; the
diff doesn't show CLAUDE.md changes.

**Fix sketch**: add a CLAUDE.md row update in the next chunk.

Cite: `CLAUDE.md` (not modified in 3264887).

### P3-4: `stm_fs_listxattr` fallback never zeroes `n_total` between wait-free + fallback passes

`v2/src/fs/fs.c:5691` declares `size_t n_total = 0;`. The wait-free
path's `stm_xattr_list_concurrent(NULL, 0, &n_total)` writes
n_total. If the wait-free path got past this call but later set
need_fallback, n_total retains the wait-free value.

The fallback path at line 5754 calls `stm_xattr_list(NULL, 0,
&n_total)`. The serial `stm_xattr_list` zeroes `*out_total` at
entry (`xattr.c:973`). So n_total is OVERWRITTEN by the fallback.

But the fallback could fail BEFORE this call (e.g., line 5752 if
`stm_inode_lookup` fails). In that case, n_total retains the wait-
free value but the function returns early with `ps2` (not OK), so
the value doesn't propagate.

Minor — defensive belt-and-suspenders. The serial path's zero-init
makes the fallback path correct.

**Fix sketch**: none needed; document the contract.

### P3-5: `stm_fs_open_by_handle`'s post-fallback `stm_inode_next_ino` documentation could mention the LF-3 caller-quiesce obligation

`v2/src/fs/fs.c:4569`:

  ```
  /* stm_inode_next_ino takes its own subsystem-internal mutex;
   * safe without fs->global. */
  ```

True for inode-index CONSISTENCY (subsystem internal mutex
serializes vs concurrent next_ino + alloc/free). NOT true for
inode-index LIFETIME — concurrent unmount can free iidx and the
next_ino call UAFs.

The R171 P0-3 documentation in `fs.c:209-228` covers the wedge gate,
but this specific call site's comment should reference the LF-3
caller-quiesce obligation.

**Fix sketch**: extend the comment.

Cite: `v2/src/fs/fs.c:4569`.

### P3-6: `stm_fs_lookup`'s `lookup_fallback:` label is C99-safe but stylistically jarring

`v2/src/fs/fs.c:2309-2348`. The goto-with-label pattern is unique
within fs.c (most other ports use `need_fallback` flags). The C99
rule allows the goto since `pv2` is declared after the label inside
braces (not jumping past a VLA initialization). Stylistically
inconsistent with the rest of the SH-fallback ports.

**Fix sketch**: refactor to use `need_fallback` flag for consistency.

Cite: `v2/src/fs/fs.c:2293-2348`.

### P3-7: `stm_fs_getxattr`'s initial `stm_status s = STM_ECORRUPT;` sentinel pattern requires careful reading

`v2/src/fs/fs.c:5620-5628`:

  ```c
  stm_status s = STM_ECORRUPT;
  if (is == STM_OK) {
      s = stm_xattr_get_concurrent(...);
  }
  stm_ebr_exit(ebr);
  if (is != STM_OK && is != STM_ECORRUPT) return is;
  if (is == STM_OK && s != STM_ECORRUPT) return s;
  ```

The initial `s = STM_ECORRUPT` is a sentinel meaning "we didn't run
stm_xattr_get_concurrent because inode lookup failed first". The
post-call `s` value is whatever `stm_xattr_get_concurrent` returned.
The fall-through condition `is == STM_OK && s == STM_ECORRUPT` is
EITHER "real STM_ECORRUPT from xattr_get" OR (unreachably) "sentinel
because we didn't run xattr_get".

The unreachability of the sentinel branch is correct but takes a
moment of analysis. A comment would help:

  ```c
  /* If is != OK, s stays at the STM_ECORRUPT sentinel — we never
   * called stm_xattr_get_concurrent. The (is != OK && is != ECORRUPT)
   * branch above peels off the non-fallback errors (ENOENT, ENOMEM,
   * etc.) first; the only ways to reach the fallback are (is == OK
   * && s == ECORRUPT) or (is == ECORRUPT, s irrelevant). */
  ```

**Fix sketch**: add the comment.

Cite: `v2/src/fs/fs.c:5620-5628`.

### P3-8: `stm_fs_listxattr` fallback's redundant `*out_size = 0` overlaps with serial path's entry zero-init

`v2/src/fs/fs.c:5645`:

  ```c
  if (out_size) *out_size = 0;     /* redundant with serial's entry zero-init */
  s = stm_xattr_get(...);
  ```

Wait, this is in `stm_fs_getxattr` not listxattr. `stm_xattr_get` at
`xattr.c:686` does `if (out_size) *out_size = 0;` at entry. The
fs.c-level zero at line 5645 is redundant. Harmless but unnecessary.

**Fix sketch**: drop the redundant zero.

Cite: `v2/src/fs/fs.c:5645`, `v2/src/xattr/xattr.c:686`.

### P3-9: The R171 close commit's verification claim "ctest 64/64 GREEN excluding the flake-prone test_compound_ops_concurrent" omits a coverage statement

The close commit's tests don't exercise the new fallback paths
deterministically. The existing LF-3d tests don't hit the SH-
fallback because they run disjoint-engine scenarios (which produce
STM_OK from the wait-free path). A dedicated regression test that
INJECTS STM_ECORRUPT from the wait-free path (perhaps via a fault-
injection hook in stm_btree_engine_lookup_concurrent) would
deterministically exercise the fallback.

The flake test (test_compound_ops_concurrent) presumably DOES
exercise the fallback under stress, but the flake nature means
coverage is non-deterministic.

**Fix sketch**: add a fault-injection seam that forces
STM_ECORRUPT on the next wait-free read, then unit-test each
ported reader's fallback path. Forward-noted.

### P3-10: The R171 close commit doesn't add an end-to-end test for the listxattr count-vs-materialize TOCTOU closure

The close commit message states "P1-2 count-vs-materialize TOCTOU
[is closed] by collapsing both passes into the fallback when wait-
free returns STM_ECORRUPT". But there's no regression test that
pairs a writer adding xattrs with a concurrent listxattr. The
existing `lf3d_listxattr_stable_vs_chmod_disjoint_inode` tests a
disjoint inode chmod (which doesn't touch xattr); a true TOCTOU
test would do `setxattr(... "user.a%d", ...)` in the writer thread.

Combined with P1-1 (the STM_ERANGE gap), such a test would
deterministically catch both the partial-closure of P1-2 and the
new P1-1 gap.

**Fix sketch**: add `lf3d_listxattr_vs_setxattr_same_inode_xattr_toctou`.

## Summary

Severity counts: P0=0, P1=2, P2=6, P3=10.

The R171 close commit's SH-fallback strategy successfully closes the
P1-1 STM_ECORRUPT-propagation gap for the SPECIFIC subclass of
torn reads that surface as STM_ECORRUPT via `in_validate_value`. The
strategy is sound for that subclass: drop EBR, acquire fs->global
SH, retry through the serial path; the serial path's idx-mutex
plus the SH-vs-EX exclusion serializes against same-engine writers.

The two new P1 findings are:

  - **P1-1**: `stm_fs_listxattr`'s P1-2 closure (count-vs-materialize
    TOCTOU) is INCOMPLETE: the wait-free check at line 5726 catches
    STM_ECORRUPT + `got != n_total`, but NOT STM_ERANGE. A normal
    writer-adds-xattr-between-passes race produces STM_ERANGE from
    `stm_xattr_list_concurrent`, which propagates to the caller. Trivial
    fix: extend the check to include STM_ERANGE.

  - **P1-2**: the SH-fallback strategy is gated on STM_ECORRUPT only.
    Other torn-read symptoms (stale-coherent bytes returning STM_OK,
    spurious STM_ENOTDIR/STM_ENOENT, potential OOB-stack-read on
    inconsistent INLINE si_size + si_data_len) are NOT caught. Each
    is narrow reachability via the documented R171 P0-1 UAF surface,
    but the R171 commit message's framing ("turns visible symptom
    into slow-path retry") overstates the coverage. BE-prepend is
    the true closure.

The six P2 findings are mostly defensive / documentation cleanups
that should land alongside the P0 closures.

**Suggested triage**:

1. **P1-1 STM_ERANGE gap**: 1-line fix in `fs.c:5726`. Land
   immediately as a follow-up to 3264887.

2. **P1-2 si_size > INLINE_MAX OOB**: add the `cur_size <=
   STM_INODE_INLINE_MAX` check in stm_fs_read's wait-free INLINE
   branch (P2-5). Same regression test exposes both the wait-free
   and serial path gaps. The serial path can also OOB if on-disk
   corruption produces INLINE + si_size > 100 (extend
   `in_validate_value` to enforce this for INLINE/SYMLINK kinds).

3. **P2-2 documentation drift**: rewrite the listxattr fallback's
   comment at line 5724 to credit fs->global SH-vs-EX (not the idx
   mutex) for the exclusion, with a forward-compat note for future
   SH writers.

4. **P2-6 engine.c docstring inconsistency**: merge the OLD claim
   (lines 199-202) into the R171 update (lines 206-228) so there's
   a single coherent statement.

5. **Test coverage gaps (P3-9, P3-10)**: add fault-injection +
   deterministic-race regression tests for the new fallback paths
   so future refactors don't silently break them.

6. **CLAUDE.md row update (P3-3)**: include in next commit.

The R171 P0 UAFs (engine-struct, fs-lifetime, leaf-value, mvcc_root)
remain outstanding and BE-prepend dependent; this R172 audit does
not re-report them. The crown-jewel framing for LF-3 should remain
tempered until BE-prepend + the dedicated R171-followup chunk land,
per the R171 close commit's own framing.
