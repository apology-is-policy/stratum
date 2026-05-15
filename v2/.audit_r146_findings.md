# Audit R146 — TLY-A5 snapshot rollback-compromise

Scope: commits 2829c59, 86b2f53, e74d387, 9e81643.
Surfaces: snapshot.c/.h, fs.c/.h, ctl synfs.c/ctl.h, stratumd run.c/serve.c,
types.h, lp9/server.c, util/status.c.

Verdict: no auth-bypass, no marker-bypass, no torn-marker corruption found.
The consultation gate, the qid kind switch, the corvus-principal asymmetry,
and the `force`-token parsers all hold up under adversarial review. Findings
are robustness / doc-drift class.

---

## P0 — none

The marker-bypass surface was prosecuted hard:

- A rollback of a compromised snap without `force` cannot proceed. The gate is
  inside `stm_fs_rollback_snapshot` itself (fs.c) — not just /ctl/ — under one
  `fs->global` EX hold; lookup + flag-test + refusal are atomic vs a racing
  unmark/mark/delete. A forged qid that skips `vops_lopen` still hits the
  `vops_write` defense-in-depth `ctl_caller_is_admin` re-check, then the fs-API
  gate. No path reaches the (stubbed) mechanism on a marked snap unforced.
- `force`-token parsing in both the unmark and rollback handlers is sound:
  `force` requires a literal `force` + (space|tab); `forceX`, `force` with no
  id, `force ` (trailing only), embedded NUL all degrade to EINVAL via
  `parse_snapshot_id`. `parse_snapshot_id` rejects leading-zero, non-digit,
  overflow, len>20, empty. No confusion between forced/non-forced branches.
- qid `kind:8` high-byte invariant preserved; `qid_kind` bounds-checks
  `k < KIND_MAX`; all six vops switches (materialize/getattr/walk/readdir/
  lopen/write) handle kinds 29/30/31; `_Static_assert(KIND_MAX == 32)` and the
  KIND_META designated-initializer table are complete.

## P1 — none

## P2

### P2-1 — failed `mark`/`unmark` verb still persists the flag on the next commit
`v2/src/ctl/synfs.c` ~3540-3555 (mark/unmark write handler).

`stm_fs_mark_snapshot_compromised` mutates the in-RAM index (`e.flags |= …`,
`idx->dirty = true`) and returns STM_OK. The handler then calls
`stm_fs_commit`; if the commit fails, the handler surfaces the commit error
(`rc = crc; return rc;`) — but the in-RAM bit is already set and the index is
already `dirty`. Any *subsequent* successful commit from an unrelated op (a
file write, a later snapshot verb) will persist the marker the operator was
told "failed". For `mark` this fails safe (a marker that sticks despite a
reported error is the conservative direction). For `unmark` it fails *unsafe*:
the operator sees "unmark failed" but the compromise flag has actually been
cleared in RAM and will be persisted later — a rollback that should be gated
becomes silently allowed.

Why tests miss it: the test suite never injects a `stm_fs_commit` failure
after a successful index mutation; all mark/unmark tests run on a healthy fs.

Suggested fix: on commit failure in the unmark path, re-apply the bit
(`stm_fs_mark_snapshot_compromised` again) before returning the error, OR
document that mark/unmark are not transactional and the verb's return code
only reflects "the in-RAM change is durable-on-next-commit", not "no change
on failure". The mark handler's own comment ("durable the moment the verb
returns OK") is the load-bearing claim; the unmark side has no such guarantee
and should not be presented symmetrically.

### P2-2 — snapshot id is never bound to the dataset in the qid path
`v2/src/ctl/synfs.c` mark/unmark/rollback handlers; `v2/src/fs/fs.c`
`stm_fs_rollback_snapshot`, `stm_fs_mark_snapshot_compromised`.

`/ctl/datasets/<dsid>/rollback-snapshot` (and mark/unmark) parse `snap_id`
from the body and forward it to `stm_fs_*` with no check that the snapshot's
`dataset_id` equals `dsid` from the qid. The snapshot index is pool-global.
An admin who walks `/ctl/datasets/1/rollback-snapshot` can roll back a
snapshot belonging to dataset 7. The `/ctl/events` audit line records
`dataset=<dsid-from-qid>` — which is *wrong*: it logs dataset 1 when the snap
was actually dataset 7's. The forensic record is misleading.

`fs.h`'s doc for `stm_fs_rollback_snapshot` even claims `STM_ENOENT
(snapshot unknown / wrong dataset)` — but the function has no dataset
parameter and cannot detect "wrong dataset". Doc asserts a check that does
not exist.

This is a *pre-existing pattern* (`hold-snapshot` / `release-snapshot` /
`delete-snapshot` already do this), so it is not a regression introduced by
A5 — but A5 adds a destructive verb (rollback) and a security verb (mark) to
the same broken-binding surface, raising the stakes, and ships a fs.h doc
that overstates the check.

Why tests miss it: every test uses dataset_id 1 with a single dataset; the
cross-dataset case is never exercised.

Suggested fix (lowest-risk): after `stm_snapshot_lookup` in
`stm_fs_rollback_snapshot`, compare `entry.dataset_id` against a new
`dataset_id` parameter and return STM_ENOENT on mismatch; thread `dsid` from
the qid into the call. At minimum, correct the fs.h doc to drop the "wrong
dataset" clause, and log `entry.dataset_id` (not the qid `dsid`) in the
audit line so the record is truthful. Consider a follow-up chunk to fix the
whole snapshot-verb family.

## P3

### P3-1 — design-spec'd `mark` reason text was dropped from the impl
`v2/docs/thylacine-a5-design.md` §6 specs the `mark-snapshot-compromised`
body as `<sid>` **or** `<sid> <reason>`, with a "`mark` reason validation
(R99 P2-1 line-injection doctrine)" paragraph requiring length-bound +
control-byte refusal, the reason flowing into `/ctl/events`. The impl's mark
handler accepts only `<sid>`: any trailing reason text makes
`parse_snapshot_id` reject the whole token with EINVAL. The "who/when/**why**"
audit goal in §3 ("the *why* is in `/ctl/events`") is unmet — the events line
has no reason field. Either the impl should parse + sanitize + log the
reason, or the design doc + §3 should be amended to record that the reason
text was deliberately dropped from A5.

### P3-2 — `STM_ECOMPROMISED` → EACCES wire mapping is lossy but acceptable
`v2/src/lp9/server.c:117`. A compromised-refused rollback and a genuine
permission denial both surface to a 9P client as `Rlerror(EACCES)`. The
`/ctl/events` line distinguishes them (`result=err:ecompromised` vs
`err:eaccess`) and `stm_strerror` is correct, so an operator reading logs is
not confused — but a 9P client that only sees the ecode cannot tell "you may
not do this" from "this snapshot is dangerous to roll back to". EROFS or a
dedicated mapping would be more honest. Forward-note only; EACCES is a
defensible "refusal" bucket and matches the comment's intent.

### P3-3 — fs.h `stm_fs_rollback_snapshot` doc lists STM_ENOENT "wrong
dataset" (see P2-2) — code cannot return it. Correct the contract comment.

---

Summary: 0 P0, 0 P1, 2 P2, 3 P3.

---

## R146 close

Both P2s fixed; P3s reconciled.

- **P2-1 fixed** — `stm_fs_{mark,unmark}_snapshot_compromised` gained a
  `bool *out_changed` out-param (computed from the pre-toggle flag
  state under the same `fs->global` EX hold). The /ctl/ mark/unmark
  handler now (a) commits ONLY when `changed` — an idempotent no-op
  has nothing to persist — and (b) on commit failure REVERTS the
  in-RAM toggle via the inverse call, so RAM matches the un-persisted
  on-disk state and no later unrelated commit can silently persist a
  change the operator was told failed. The unsafe-unmark direction is
  closed.
- **P2-2 fixed** — `stm_fs_{mark,unmark}_snapshot_compromised` +
  `stm_fs_rollback_snapshot` gained a `dataset_id` parameter; the impl
  resolves the snapshot via `stm_snapshot_lookup` and refuses
  STM_ENOENT when `entry.dataset_id != dataset_id`. The /ctl/ handlers
  thread the qid-path `dsid` into the call. A `/ctl/datasets/1/...`
  verb can no longer reach dataset 7's snapshots; the audit log's
  `dataset=` field is now truthful (a successful verb implies the
  binding held).
- **P3-3 fixed** — the fs.h "wrong dataset" STM_ENOENT clause is now
  accurate (the code performs the check).
- **P3-1 reconciled** — `thylacine-a5-design.md` §6 amended to record
  that the `mark` reason text was deliberately dropped from v1.0
  (who/when/what is logged; the free-text why is forward-noted to a
  v1.x chunk with the R99 line-injection rule attached).
- **P3-2** — `STM_ECOMPROMISED → EACCES` wire mapping left as-is
  (audit ruled it acceptable; the precise status reaches `/ctl/events`
  + `stm_strerror`).

Regression tests (test_ctl.c): `ctl_a5_r146_snapshot_is_dataset_bound`
(wrong-dataset mark/unmark/rollback → STM_ENOENT; dataset_id==0 →
STM_EINVAL) + `ctl_a5_r146_mark_reports_changed` (`out_changed` true
on a real flip, false on an idempotent no-op). The commit-failure
revert path itself has no test — no `stm_fs_commit` fault-injection
seam exists; covered by review + the `out_changed` test which pins
the load-bearing half. ctest 61/61 GREEN; test_ctl 149/149.
