# TLY-A5 — snapshot rollback compromise marking (design)

Status: **design**. Spec-first chunk; the implementation is gated on a
small extension of `snapshot.tla` (TLY-A5-spec).

Bilateral context: `THYLACINE-V1-PLAN.md` §6 (revised 2026-05-15).
Thylacine ask A5 — when corvus detects that a session's keys may be
compromised, a snapshot taken under those keys must be *markable* so a
later rollback to it is refused-by-default (the F13 hazard:
`CORVUS-DESIGN.md` §4.5 — rolling back resurrects an old, possibly
compromised, wrap chain as live state).

## 1. Premise correction (load-bearing)

An earlier `THYLACINE-V1-PLAN.md` draft assumed v2 snapshot rollback
already existed (`stm_snap_rollback` "carry from v1"). It does not.
`stm_snap_rollback` is **v1-only**. v2 metadata lives in *pool-global*
trees keyed by `(dataset_id, …)`; the dataset descriptor has no
`di_tree_root`; a v2 snapshot records `extent_txg` (a generation
number) with `tree_root_paddr = 0` and roots no recoverable tree. Real
per-dataset rollback needs a foundational re-architecture — **Phase
9.7** (`docs/ROADMAP-V2.md`, amendment 2026-05-15), scheduled
post-Thylacine.

**A5 therefore ships marker-first** (user decision 2026-05-15): the
compromise marker — the security-relevant deliverable — is built in
full; the rollback verb's *surface* is built in full; the rollback
*mechanism* (`stm_fs_rollback_snapshot`) is a stub returning
`STM_ENOTSUPPORTED`. When Phase 9.7 lands, only the stub body is
replaced — every gate around it is already in place.

## 2. What ships in A5

| Piece | Status in A5 |
|---|---|
| Compromise-marker flag (persistent) | **real** |
| `mark-compromised` / `unmark-compromised` admin verbs | **real** |
| corvus-principal gate (`--corvus-admin-uid`) | **real** |
| snapshot info-kind "compromised" line | **real** |
| `rollback-snapshot` `/ctl/` verb surface + admin gate | **real** |
| rollback marker-consultation gate (refuse-on-marked-unless-`force`) | **real** |
| TUI rollback double-confirm dialog | **real** (UI; calls the verb) |
| `stm_fs_rollback_snapshot` data mutation | **stub** — `STM_ENOTSUPPORTED` (Phase 9.7) |

## 3. Marker storage — no on-disk format change

The marker is a single bit in the **existing** `stm_snapshot_entry.flags`
field (`snapshot.h:127`, currently "future: ro / locked / …"):

```c
#define STM_SNAP_FLAG_ROLLBACK_COMPROMISED  0x1u
```

`flags` already round-trips through the snapshot-index encode/decode +
commit, so setting a bit in it is **not** a format change — no
`STM_UB_VERSION` bump. (Contrast TLY-A3-keyslot, which carved a new
byte and did bump.) A pre-A5 pool has `flags == 0` for every snap →
decodes as not-compromised, the correct default.

### Reason text — audit log, not on-disk

`mark-compromised` accepts a free-text reason. It is **not** persisted
in a new on-disk structure (the THYLACINE-V1-PLAN's earlier "sidecar
btree keyed by snap_id" idea is dropped — it would be a new
Merkle-covered tree for a forensic string). Instead the reason flows
to the **`/ctl/events` audit log**, which already exists and is the
correct home for "who marked snap S compromised, when, and why."
Persistent on-disk state is exactly the one flag bit. The info kind
reports `compromised: yes|no`; the *why* is in `/ctl/events`.

## 4. Snapshot-module API (TLY-A5-impl-1)

New in `snapshot.h` / `snapshot.c`:

```c
/* Set / clear STM_SNAP_FLAG_ROLLBACK_COMPROMISED on a PRESENT snap.
 * STM_ENOENT if the snap is unknown / ABSENT. Idempotent (marking an
 * already-marked snap, or unmarking an unmarked one, is STM_OK with
 * no state change — callers detect "real change" via the flag). */
stm_status stm_snapshot_mark_compromised  (stm_snapshot_index *idx,
                                             uint64_t snapshot_id);
stm_status stm_snapshot_unmark_compromised(stm_snapshot_index *idx,
                                             uint64_t snapshot_id);
```

The flag is read back via the existing `stm_snapshot_lookup` (it
returns the whole `stm_snapshot_entry`, `flags` included). No new
read accessor needed.

**Invariant preservation**: `mark` / `unmark` touch only `flags`.
They do NOT touch `snapshot_id`, `dataset_id`, `created_txg`,
`extent_txg`, `prev_snap_id`, `hold_count`, or `tree_root_paddr` — so
every existing `snapshot.tla` invariant (ChainTxgOrdered,
ChainExtentTxgOrdered, HoldPreventsDelete, SnapIdMonotonic, …) is
trivially preserved. The spec extension proves this non-perturbation.

## 5. fs.c wrappers (TLY-A5-impl-1 + impl-2)

```c
/* impl-1 */
stm_status stm_fs_mark_snapshot_compromised  (stm_fs *fs, uint64_t snapshot_id);
stm_status stm_fs_unmark_snapshot_compromised(stm_fs *fs, uint64_t snapshot_id);

/* impl-2 — STUB until Phase 9.7 */
stm_status stm_fs_rollback_snapshot(stm_fs *fs, uint64_t snapshot_id);
```

`stm_fs_rollback_snapshot` v1.0 body: validate `snapshot_id` exists +
`FS_GUARD_WRITE` + return `STM_ENOTSUPPORTED`. The existence check is
real so the caller gets `STM_ENOENT` vs `STM_ENOTSUPPORTED` correctly;
the *mutation* is what's stubbed. A header comment cites Phase 9.7.

mark/unmark take `fs->global` EX (dataset-wide snapshot-index mutation,
same posture as `stm_fs_create_snapshot` — snapshot ops are
dataset-scope, not per-inode; see CLAUDE.md PARALLEL-3 impl-5 residual
EX-takers list). They drain nothing (no extent-tree touch) and commit
via the standard `stm_sync_commit` path so the flag bit is durable.

## 6. /ctl/ kinds (TLY-A5-impl-1b + impl-2)

Three new writable kinds, all **dataset-level write-only files**
(see refinement note below), inheriting the P9-CTL-1d writable-kind
doctrine (admin gate at vops_lopen + defense-in-depth re-check at
vops_write + zero-byte Twrite refusal + KIND_META mode bits +
per-conn sessions die-with-conn):

| Kind | Path | Body | Gate |
|---|---|---|---|
| `mark-snapshot-compromised` | `/ctl/datasets/<id>/mark-snapshot-compromised` | `<sid>` or `<sid> <reason>` | admin **OR** corvus-admin-uid |
| `unmark-snapshot-compromised` | `/ctl/datasets/<id>/unmark-snapshot-compromised` | `force <sid>` | admin only |
| `rollback-snapshot` | `/ctl/datasets/<id>/rollback-snapshot` | `<sid>` or `force <sid>` | admin only |

> **2026-05-15 impl-1b refinement.** An earlier draft put the verbs
> under a per-snapshot directory
> (`/ctl/datasets/<id>/snapshots/<sid>/mark-compromised`). But every
> existing snapshot verb in `/ctl/` — `create-snapshot`,
> `delete-snapshot`, `hold-snapshot`, `release-snapshot` — is a
> dataset-level write-only file that takes the snap id in the body;
> `/ctl/datasets/<id>/snapshots/<sid>` is a *leaf* info file, not a
> directory. Making `<sid>` a directory would be a tree-shape change
> against the grain of the whole surface. A5 uses the dataset-level
> form — `mark-snapshot-compromised` clones the `hold-snapshot` kind
> exactly. (`rollback-snapshot` was already dataset-level.)

The existing `KIND_DATASET_SNAPSHOT_INFO` (kind 28, S5-PRE-C)
materializer gains a `compromised: yes|no` line.

**`unmark` body discipline** (Q15): unmark requires the literal body
`force` — clearing a compromise flag is itself a sensitive act, so it
is not a bare no-arg verb. Audit-logged.

**`mark` reason text — DEFERRED** (R146 P3-1 reconciliation). An
earlier draft of this section accepted a `<sid> <reason>` body and
specified R99 P2-1 line-injection validation for the reason. The
v1.0 impl ships `<sid>`-only: `mark-snapshot-compromised` records
who (uid) + when (`/ctl/events` timestamp) + what (verb + snap-id),
which satisfies the audit-trail goal; the free-text *why* is not
captured. A future v1.x chunk may add the reason field — at which
point the R99 line-injection rule (max length + control-byte
refusal, since it flows into the line-oriented `/ctl/events` log)
applies. §3's "the *why* is in `/ctl/events`" goal is amended to
"the *who/when/what*"; the *why* is forward-noted.

## 7. Corvus principal — `--corvus-admin-uid` (TLY-A5-impl-1)

New stratumd CLI arg `--corvus-admin-uid <uid>`. Plumbed into
`stm_stratumd_opts` and `stm_ctl` (a new `corvus_admin_uid` field set
once at startup, immutable — same posture as `admin_uid`). The
`mark-compromised` kind's gate admits the caller iff
`caller_uid == admin_uid || caller_uid == corvus_admin_uid`. Every
other admin kind (including `unmark-compromised` and
`rollback-snapshot`) stays strict-admin-only.

Rationale for the asymmetry: corvus, on detecting a session-key
compromise, must be able to *raise* the flag autonomously (that is the
A5 security goal). Only the human operator may *clear* it or *force
through* it — corvus cannot un-raise its own alarm. Default unset
(`corvus_admin_uid` absent) → only `admin_uid` is admitted (back-compat
for non-Thylacine deployments).

## 8. Rollback marker-consultation gate (TLY-A5-impl-2)

The `rollback-snapshot` write handler:

1. Parse the body. Two accepted forms: `<sid>` (decimal) or
   `force <sid>`. Anything else → `STM_EINVAL`.
2. Look up `<sid>` in the dataset's snapshot set. `STM_ENOENT` if
   absent / wrong dataset.
3. **Consultation gate**: if the snap has
   `STM_SNAP_FLAG_ROLLBACK_COMPROMISED` set AND the body was not the
   `force` form → refuse with a typed error (`STM_ECOMPROMISED`, a new
   code) and an audit-log line. This is the load-bearing invariant
   `RollbackBlockedIffCompromised` — it fires *before* the stub, so it
   is genuinely exercised + tested in A5.
4. Call `stm_fs_rollback_snapshot(fs, sid)` → returns
   `STM_ENOTSUPPORTED` (v1.0 stub).

So in A5: a rollback of a non-marked snap reaches the stub and returns
"not yet implemented"; a rollback of a marked snap without `force` is
refused at step 3; with `force` it reaches the stub. Every gate is
real; only step 4's mutation is deferred.

## 9. TUI (TLY-A5-impl-2)

`tui.rs::handle_snap_list_key` — the R/Enter arm currently shows a
static "rollback not implemented" info dialog (the SWISS-6 v1.1c
stub). A5 replaces it with a real double-confirm `Confirm` dialog →
`ConfirmAction::RollbackSnapshot { dataset_id, snap_id }` →
`spawn_ctl_job` writing `<sid>` to `/ctl/datasets/<id>/rollback-snapshot`.
v1.0: the job surfaces the stub's `STM_ENOTSUPPORTED` as a clean
error dialog ("Rollback lands in Phase 9.7"). When Phase 9.7 lands,
the same UI path works unchanged against the real backend. A marked
snap shows a `[compromised]` tag in the list (from the info kind).

## 10. Spec scope (TLY-A5-spec)

Extend `snapshot.tla` (do NOT fork a new file):

- New state: a `compromised` flag per snapshot; `MarkCompromised` /
  `UnmarkCompromised` actions; a `Rollback` action gated on the flag.
- New invariant **`RollbackBlockedIffCompromised`** — a rollback to a
  compromised snapshot is reachable ONLY via the `force` path; a
  non-forced rollback of a compromised snap never proceeds.
- **`unmark`-races-`rollback`**: model the interleaving where `unmark`
  and a non-forced `rollback` race; prove the rollback either sees the
  pre-unmark (blocked) or post-unmark (allowed) state, never a torn
  in-between — the snapshot-index mutation is serialized under
  `fs->global` EX so this holds trivially, but the spec pins it.
- **Marker non-perturbation**: confirm the `compromised` flag does not
  perturb `ChainTxgOrdered` / `ChainExtentTxgOrdered` /
  `HoldPreventsDelete` / `SnapIdMonotonic` / `BirthTxgMonotonic`.
- One buggy config: a rollback handler that skips the consultation →
  trips `RollbackBlockedIffCompromised`.

The rollback *mechanism* (tree-swap, birth-txg block reclamation) is
NOT specced here — that spec belongs to Phase 9.7.

## 11. New error code

`STM_ECOMPROMISED` (next free negative value after `STM_ECORVUS*`) —
"operation refused: target snapshot is marked rollback-compromised."
Surfaced by the `rollback-snapshot` consultation gate on a non-forced
request.

## 12. Chunk plan

| Chunk | Deliverable |
|---|---|
| **TLY-A5-design** | This doc. |
| **TLY-A5-spec** | `snapshot.tla` extension (§10) + buggy config. |
| **TLY-A5-impl-1a** ✓ (`2829c59`) | Marker C API: `STM_SNAP_FLAG_ROLLBACK_COMPROMISED` + `stm_snapshot_{mark,unmark}_compromised` + fs.c wrappers + unit tests. |
| **TLY-A5-impl-1b** ✓ (`86b2f53`) | `mark-snapshot-compromised` / `unmark-snapshot-compromised` dataset-level `/ctl/` kinds (clone `hold-snapshot`) + the `KIND_DATASET_SNAPSHOT_INFO` "compromised" line. |
| **TLY-A5-impl-1c** ✓ | corvus-principal gate — `--corvus-admin-uid` CLI → `stm_stratumd_opts.corvus_admin_uid` → `stm_ctl::corvus_admin_uid` (via `stm_ctl_set_corvus_admin_uid`). `ctl_caller_may_mark_compromised` admits that uid alongside admin at `vops_lopen` + the `vops_write` defense-in-depth re-check, for `mark-snapshot-compromised` ONLY; `unmark` + every other admin kind stay strict-admin. `--corvus-admin-uid` requires `--ctl-listen`. 3 regression tests in `test_ctl.c`. |
| **TLY-A5-impl-2** ✓ | `rollback-snapshot` `/ctl/` kind (KIND 31; strict-admin) + the consultation gate (lives in `stm_fs_rollback_snapshot(fs, sid, force)` — load-bearing at the fs API boundary, not just /ctl/) + `STM_ECOMPROMISED = -217` + the Phase-9.7-stubbed mechanism (`STM_ENOTSUPPORTED`) + TUI: F9-snapshot-dialog R/Enter is now a default-No `Confirm` → `ConfirmAction::RollbackSnapshot` → `spawn_ctl_job`. 4 regression tests in `test_ctl.c`. |
| **TLY-A5-test** | ✓ — covered inline: marker round-trip (test_snapshot.c, impl-1a); mark/unmark gate + corvus-principal admit/refuse (test_ctl.c, impl-1c — 3 tests); consultation gate marked-refused / force-reaches-stub / non-admin+corvus refused (test_ctl.c, impl-2 — 4 tests). The dedicated chunk is folded into the impl chunks. |
| **TLY-A5-docs** ✓ | `OS-INTEGRATION.md` §8 (v1.0-status note + marker subsection) + `reference/13-snapshot.md` (marker + rollback gate + Status) + `reference/22-ctl.md` + `reference/21-stratumd.md` + CLAUDE.md /ctl/ row clause (20). |
| **R146** | Audit — marker-bypass, unauthorised mark, corvus-principal scope, stub fail-safe posture, the consultation gate. |

## 13. Forward-note — Phase 9.7 hand-off

When Phase 9.7 builds real rollback, the only code change in *this*
surface is `stm_fs_rollback_snapshot`'s body (the `STM_ENOTSUPPORTED`
return becomes the real tree-swap + birth-txg reclamation + gen-bump).
The marker, the consultation gate, `STM_ECOMPROMISED`, the `/ctl/`
verb, the admin gate, and the TUI are all already correct. Phase 9.7
MUST also: (a) preserve the `force`-gate semantics; (b) carry the v1
R9-1 "rollback-bump before allocator swap" nonce-uniqueness invariant
(`ARCHITECTURE.md` §12.6.2); (c) re-audit the marker consultation
against the now-live mutation.
