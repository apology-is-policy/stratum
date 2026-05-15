# TLY-A2 — Multi-stratumd-per-pool design

**Status**: signed off. Option A (coordinator daemon) per user 2026-05-14. This
document is the architectural commit ahead of TLY-A2-spec / TLY-A2-impl-1..5.

**Bilateral contract reference**: `STRATUM-API-V1.md §4` (Thylacine-side ask),
`THYLACINE-V1-PLAN.md §4` (Stratum-side plan). `CORVUS-DESIGN.md §3 D4` (Order C
boot + per-user stratumd lifecycle; structural mitigation of audit F16).

---

## 1. Mission

Each logged-in Thylacine user runs **their own** `stratumd` process scoped to
their dataset. Killing `stratumd-michael` evicts michael's DEK from RAM by
construction (the kernel-OS-level mitigation of audit F16; invariant C-5).
Without multi-stratumd-per-pool, Thylacine collapses to a single-user model
(one stratumd serves everyone — DEK cross-contamination — killing it logs
out everyone) OR per-user pools (admin nightmare).

The catch: every existing Stratum subsystem (allocator, journal, sync, /ctl/,
scrub) assumes a single-process owner of the pool device. Multi-process
coordination has to be added WITHOUT regressing the load-bearing invariants
captured in `quorum.tla`, `sync.tla`, `allocator.tla`, etc.

## 2. Topology — Option A (coordinator daemon)

```
                ┌──────────────────────────────────────┐
                │  /var/lib/stratum/pool.stm           │
                └─────────────────┬────────────────────┘
                                  │ exclusive open
                ┌─────────────────▼────────────────────┐
                │  stratumd-coord (PID 1000)           │
                │  - mounts stm_fs                     │
                │  - owns allocator / journal / sync   │
                │  - serves /ctl/ (sole listener)      │
                │  - serves FS-socket (9P2000.L)       │
                │     ↑ accept loop                    │
                └─┬───────────┬──────────────┬─────────┘
                  │           │              │
                  │ AF_UNIX   │ AF_UNIX      │ AF_UNIX
                  │ 9P2000.L  │ 9P2000.L     │ 9P2000.L
        ┌─────────▼─┐    ┌────▼──────┐    ┌──▼────────┐
        │stratumd-  │    │stratumd-  │    │stratumd-  │
        │system     │    │michael    │    │susan      │
        │--client   │    │--client   │    │--client   │
        │--datasets-│    │--datasets-│    │--datasets-│
        │allowed    │    │allowed    │    │allowed    │
        │system     │    │users/m... │    │users/s... │
        └─┬─────────┘    └─┬─────────┘    └─┬─────────┘
          │ 9P2000.L       │ 9P2000.L       │ 9P2000.L
          │ to kernel      │ to kernel      │ to kernel
        /sysroot         /home/michael    /home/susan
```

**`stratumd-coord`** is `stratumd` invoked in coordinator mode (`--role coord`).
It does what the existing stratumd already does — mounts `stm_fs`, listens on
the FS-socket + /ctl/-socket, runs accept loops. NOT a kernel-mountable surface
directly; clients dial it.

**`stratumd-<user>` (client mode)** is `stratumd` invoked in client mode
(`--role client --coordinator-socket <path>`). It does NOT mount a pool. It:

1. Dials the coordinator FS-socket with a `stm_9p_client` connection (or, in
   the simpler shape — see §3 — a raw frame forwarder).
2. Accepts client connections on its own FS-socket (the kernel mounts here).
3. For every Tattach from the kernel, validates `aname` against the configured
   `--datasets-allowed` patterns; refuses non-matches with Rerror(EACCES).
4. Forwards every subsequent T-msg to the coordinator over the dialed
   connection; pipes the coordinator's R-msg back to the kernel.

The per-user stratumd is therefore a **bounded 9P proxy with Tattach
interception**. Almost no new logic — most of the bytes get copied through
length-prefix-framed.

## 3. Wire format — 9P2000.L over AF_UNIX (no new wire)

**Decision: no new wire format.** The coordinator already speaks 9P2000.L on
its FS-socket; we reuse it as the inter-stratumd transport.

**Frame forwarding shape**:

- Per-user stratumd has TWO 9P endpoints per kernel client:
  - **Upstream** (kernel → us): the existing `stm_9p_server`-backed FS-socket.
  - **Downstream** (us → coord): a raw forwarder OR `stm_9p_client`-backed
    connection.
- For the v1.0 shape: **raw forwarder**. Per Tversion + Tattach is intercepted
  (parsed enough to validate `aname` against patterns + to clamp msize); every
  other Txx is copied byte-for-byte downstream, every Rxx is copied
  byte-for-byte upstream. The per-conn fid namespace is independent on each
  9P connection, so kernel-side fid numbers naturally don't alias coordinator-
  side fids (the kernel's fids live in the per-user stratumd's upstream
  server's fid table; the coordinator's fids live in the coordinator-side
  server's fid table; the per-user stratumd's downstream connection has its
  OWN fid namespace).

  Wait — that's not quite right. The per-user stratumd's UPSTREAM server has
  one fid namespace per kernel connection. The DOWNSTREAM client has one fid
  namespace per coordinator connection. The proxy must MAP between them. The
  simplest map: identity. The proxy passes kernel-side fid X as coordinator-
  side fid X verbatim. Since both sides are independent 9P connections, this
  collision-free as long as both endpoints accept the value.

  **Conclusion**: raw forwarder, identity fid map. No new client library code.
  The proxy is ~300 lines.

**Why no new wire?**
- Trust boundaries: every wire we add is a new audit surface. 9P2000.L is
  already audited (R92 / R93 / R94 / fid.tla / namespace.tla); reusing it
  inherits the discipline.
- Performance: Unix-socket 9P is fast; the proxy hop adds ~10 μs.
- Future kernel-native module path: once Stratum has a kernel module, the
  per-user stratumd dissolves into "the kernel module subscribes to the
  coordinator's FS-socket directly" — same wire, fewer hops. The forward-
  compat story is one substitution.

**Per-user stratumd serves the same 9P2000.L the kernel expects** — no
recompilation of the kernel client; no version coordination beyond Tversion.

## 4. Authentication — bilateral SO_PEERCRED + dataset patterns

**Layer 1 — kernel → per-user stratumd**: existing `stm_stratumd_serve_client`
posture (SO_PEERCRED stamping on the upstream server; admin gating on /ctl/).
For Thylacine's boot flow, the per-user stratumd is launched by joey-or-login
with the same uid as the user; the kernel-side 9P client connects as that
same uid; SO_PEERCRED match is the default.

**Layer 2 — per-user stratumd → coordinator**: SO_PEERCRED on the coordinator
FS-socket. The coordinator sees the per-user stratumd's uid (which is the
end-user's uid, since the per-user stratumd doesn't drop privileges to its
own dedicated user — it IS the user's process). The coordinator enforces:

- The dialing client's uid MUST match a configured per-user-uid allow-list.
  For `stratumd-system`, the operator adds an explicit `uid=0:...` entry —
  uid 0 has NO hardcoded bypass (R141 P2-3 close: the original "OR be 0"
  wording was a hint about which entry to add; the impl enforces strict
  table-membership, which is the safer posture).
- The Tattach `aname` from the dialing client MUST be matchable to the
  configured `<uid> → <pattern set>` table on the coordinator.

So the coordinator has its OWN copy of the `--datasets-allowed` policy,
indexed by uid. The per-user stratumd ALSO enforces (defense-in-depth — its
own `--datasets-allowed` flag). Both layers must consent for a Tattach to
succeed.

**Configuration**: the coordinator's policy is supplied via repeated CLI
flags: `--user-policy uid=1001:users/michael,users/michael/**`,
`--user-policy uid=1002:users/susan,users/susan/**`,
`--user-policy uid=0:system,system/**`. v1.0 hardcoded; v1.1 can read from
a policy file that admin tooling updates atomically.

## 5. Per-user stratumd lifecycle

```
stratumd --role client \
         --coordinator-socket /var/run/stratum-coord.sock \
         --listen /var/run/stratum-michael.sock \
         --datasets-allowed users/michael \
         --datasets-allowed users/michael/** \
         --corvus-user michael \
         --corvus-notify-socket /srv/corvus/notify
```

(The `--corvus-*` args are the TLY-A4 corvus consumer; one consumer thread
per per-user stratumd, scoped to that user's session.)

**Boot sequence**:
1. Parse args + install signal handlers (existing `run.c`).
2. Dial the coordinator socket; perform Tversion negotiation (msize clamped
   to STM_9P_MSIZE_MAX).
3. Bind the upstream listen socket.
4. Spawn the corvus notify consumer thread (existing TLY-A4 path).
5. Run the upstream accept loop. Every accepted upstream connection spawns a
   detached worker per the existing SWISS-4g pattern. The worker:
   - Establishes a new downstream connection to the coordinator (one
     per upstream connection — the per-conn fid namespace contract).
   - Forwards Tversion to the coord and pipes Rversion back.
   - Forwards Tattach AFTER validating `aname` against `--datasets-allowed`;
     refusal returns Rerror(EACCES) directly to the kernel without ever
     touching the coord.
   - Pipes all subsequent Txx → coord; Rxx → kernel until either side
     closes.

**Shutdown**: stop_flag observed → upstream accept loop exits → existing
worker join discipline → corvus consumer joined → coordinator connections
closed (downstream fd close triggers coord's per-conn cleanup).

The per-user stratumd itself MOUNTS NOTHING. It is a pure proxy. `stm_fs *
fs` in `stm_stratumd_opts` is unused in client mode (refused at start with
STM_EINVAL if non-NULL).

## 6. Coordinator lifecycle

Identical to existing stratumd modulo two new policy bits:

- `--role coord` flag (default; back-compat: existing single-process
  stratumd is `--role coord` implicit).
- `--user-policy uid=N:pat1,pat2,...` repeatable flag.

The coordinator's existing FS-socket accept loop handles per-user stratumd
connections the same way it would handle any 9P client. The new policy
enforcement lives in a wrapper around `stm_9p_server_handle`:

- On Tattach: extract caller uid (already stamped per R97 P2-2); look up
  user policy; refuse with Rerror(EACCES) if `aname` doesn't match any
  pattern.
- All other ops: unchanged.

The /ctl/ socket on the coordinator is admin-only; per-user stratumds do
NOT connect to /ctl/ (they have no /ctl/ surface to expose to their
kernel client). Q6 of the bilateral contract — "the merged /ctl/events
view" — is realized by: each per-user stratumd writes its own log file
at `/var/log/stratumd/<pool-uuid>.<pid>.log`; the coordinator's
`/ctl/events` reflects coordinator-internal events only. v1.1 may add a
log-aggregation surface; v1.0 documents per-process log files.

## 7. Pattern matching — `--datasets-allowed`

Q4 of the bilateral contract: glob `*` (one level) + `**` (recursive).

Concrete semantics on a pattern `P` and a candidate `aname` (`/`-separated
path):

- `P` is split into components.
- Component `*` matches any single non-`/` component.
- Component `**` matches zero-or-more components (greedy).
- All other components match literally.

Examples:

| Pattern             | Matches                          | Refuses          |
|---------------------|----------------------------------|------------------|
| `users/michael`     | `users/michael`                  | `users/michael/secret`, `users/susan` |
| `users/michael/**`  | `users/michael`, `users/michael/notes`, `users/michael/a/b/c` | `users/susan` |
| `users/*`           | `users/michael`, `users/susan`   | `users/michael/secret` |
| `users/**`          | `users/michael`, `users/michael/secret`, `users/anna/photos/2024` | `system` |

`**` greediness is fine because there's no ambiguity — patterns are
checked one-by-one, first-match-wins.

**Refused at Tattach time, NOT at runtime**. Once the kernel has attached
successfully, subsequent Twalks under that root are constrained by the
attached fid's binding (the existing 9P server discipline at
`v2/specs/namespace.tla`). New Tattaches (mounting a different dataset
from the same client connection) re-trigger the pattern check.

**Cross-dataset ops (Q5)**: deferred to v1.x. v1.0 enforces single-dataset-
per-attach. Operations like `link(src, dst)` across two distinct datasets
fail with EXDEV.

## 8. Crash recovery

**Per-user stratumd crashes**:
- Kernel client's upstream connection closes (process exit closes fds).
- Per-user stratumd's worker pthreads close their downstream connections
  on exit.
- Coordinator observes downstream EOF, cleans up that connection's fids
  via existing `stm_9p_server_destroy` (one server per connection — fid
  namespace dies with the connection).
- Other per-user stratumds (system, susan) UNAFFECTED — their downstream
  connections are independent.
- joey reaps the crashed stratumd; restart re-attaches the kernel's mount
  point (or surfaces the EIO to user space depending on Thylacine's
  policy).

**Coordinator crashes**:
- All per-user stratumds observe downstream EOF; their upstream connections
  surface EIO to the kernel.
- Pool is dirty; restart goes through the existing single-process recovery
  (sync.tla's mount discipline + quorum.tla for multi-device).
- The crash recovery story is identical to today's single-process stratumd
  because the coordinator IS the single-process stratumd from the
  pool's perspective. No new failure modes vs current v2.0.

**Allocator wedging**: if a downstream operation triggers
`stm_fs_mark_wedged(fs)`, the coordinator's fs is wedged for ALL clients
(by design — the pool itself is wedged). Per-user stratumds see
STM_EWEDGED on subsequent ops and surface to their kernel clients.

## 9. Spec scope (TLY-A2-spec)

New spec at `v2/specs/multi_stratumd.tla` modelling:

- N per-user stratumds (clients) connected to one coordinator.
- Each client has a pattern-set (`--datasets-allowed`).
- Coordinator has a per-uid policy (`--user-policy`).
- Allocator coordination is **trivially serialized** in this model because
  the coordinator's fs->lock already provides single-threaded mutation
  semantics from the pool's perspective. The interesting invariants are
  about the AUTH layer, not the allocator.

**Invariants**:

- `TattachPatternEnforced` — every successful Tattach (any client, any
  uid) satisfies both layers: the per-user stratumd's local pattern set
  AND the coordinator's per-uid policy.
- `CrossClientIsolation` — no client's Twalk / Tread / Twrite ever
  returns data from a dataset its pattern set doesn't admit. (Composes
  against `namespace.tla::ConstrainedToAttachedSubtree`.)
- `ClientCrashIsolation` — a client's transition to "Crashed" never
  causes another client's in-flight op to fail (subject to allocator-
  level wedging — see invariant 5).
- `CoordinatorOwnsDevice` — at most one process holds the device's
  exclusive open. (Trivially true under Option A's design but explicit
  for spec composition with `quorum.tla`.)
- `WedgePropagation` — when the coordinator's fs is wedged, every
  client's next op observes STM_EWEDGED. (Composes the existing
  wedge-state-runtime-gate.)

**Buggy variants** (≥ 3 per the plan):

1. `multi_stratumd_pattern_skipped_buggy.cfg` — the coordinator's per-uid
   policy is elided; only the client-side pattern check runs. Trips
   `TattachPatternEnforced` when a misconfigured client passes a
   too-permissive pattern set.
2. `multi_stratumd_aliased_fids_buggy.cfg` — the per-user stratumd uses
   a SHARED downstream connection across kernel clients (instead of
   per-conn). Trips `CrossClientIsolation` via fid namespace aliasing
   (kernel client A's fid X is bound to a path uploaded by kernel
   client B in the buggy regime).
3. `multi_stratumd_crash_propagates_buggy.cfg` — a client's crash
   marks the coordinator's fs wedged (instead of just cleaning up
   that client's fids). Trips `ClientCrashIsolation`.

## 10. Impl chunking (TLY-A2-impl-1..5)

| Chunk | Deliverable | Audit |
|---|---|---|
| **TLY-A2-spec** | `v2/specs/multi_stratumd.tla` + 3 buggy cfgs + spec rationale section in this design doc | (no audit — spec only) |
| **TLY-A2-tlc** | TLC verify green (tooling-gated; folds into #958/#966/#973 forward-noted list) | (no audit — tooling) |
| **TLY-A2-impl-1** | Coordinator mode: `--role coord` flag (back-compat default), `--user-policy` parsing, coordinator-side Tattach pattern enforcement wrapper around `stm_9p_server_handle`. NO client mode yet — coord works standalone as today's stratumd does. | R139 |
| **TLY-A2-impl-2** ✓ | Client mode: `--role client --coordinator-socket <path>`, raw-frame proxy module (`v2/src/cmd/stratumd/proxy_9p.{h,c}`), Tattach interception (Tversion forwards verbatim), `--datasets-allowed` reuses impl-1's `dataset_pattern.{h,c}` matcher. Tests: `tests/test_proxy_9p.c` — 7 parser unit + 3 e2e bilateral. | R140 |
| **TLY-A2-impl-3** ✓ | Authentication bilateral: (a) coord refuses unknown-uid at accept (early refusal, not just per-Tattach); (b) per-user stratumd `--coordinator-uid <N>` opt-in for downstream-side SO_PEERCRED check (defense against socket-bind impersonation). 3 new tests (unknown-uid accept refusal + coord-uid match admits + coord-uid mismatch refused). | R141 |
| **TLY-A2-impl-4** | Crash recovery: per-conn cleanup verification under client crash, coord crash, simultaneous-multiple-client. Tests: kill -9 patterns + reconnection. | R142 |
| **TLY-A2-impl-5** | Per-pool stress (folds STRATUM-API-V1.md §4.6 "72-hour stress"): 4 clients concurrent writes for short duration in CI + an opt-in long-form sweep gated on GCP compute. | R143 |

Cumulative new test files: `test_proxy_9p.c` (raw forwarder), `test_dataset_pattern.c`
(pattern matcher), `test_multi_stratumd.c` (end-to-end), `test_multi_stratumd_crash.c`
(kill -9 sweep).

## 11. Trust boundaries (carries into CLAUDE.md)

A new CLAUDE.md trigger row at TLY-A2-impl-1's substantive landing. Anticipated
clauses:

1. Per-user stratumd proxy framing — every 4-byte length prefix bound-checked
   against negotiated msize on BOTH sides; out-of-range disconnects.
2. Tattach `aname` validation — bound against STM_9P_MAX_WNAME; pattern match
   uses literal-byte comparison (no regex; no shell glob). R99 P2-1 carry —
   names containing control bytes refused before pattern match (the kernel
   client shouldn't send them but the proxy is the right gate).
3. Bilateral auth — both layers enforce; either layer refusing the Tattach
   produces Rerror(EACCES); failure logged on both sides.
4. fid identity-map across the proxy — verify spec composition with
   `namespace.tla::ConstrainedToAttachedSubtree`. A buggy proxy that
   translates fids breaks this composition.
5. SO_PEERCRED on downstream — refuse-by-default on resolution failure
   (R95 P2-2 carry).
6. Signal-mask discipline — every per-conn proxy worker pthread blocks
   SIGINT/SIGTERM/SIGHUP/SIGQUIT (R113 P1-1 carry).
7. /ctl/ on coord only — per-user stratumds have NO /ctl/ surface; their
   kernel clients' attempts to walk /ctl/ are refused at Tattach if
   `--datasets-allowed` doesn't include the `ctl` namespace (currently
   ctl isn't a "dataset" in stm_fs's model — it's served via a separate
   socket). This needs a clarification: the per-user stratumd's
   FS-socket serves the FS-9P only; /ctl/ on a separate socket is
   coord-only.

## 12. Open questions to track during impl

1. **Coordinator-side per-uid policy storage**: v1.0 hardcoded via CLI
   flags; v1.1 may need a config file format. Probably JSON with an
   admin verb on /ctl/ to reload.
2. **Per-user stratumd resource caps**: Q7 of the plan deferred to
   Thylacine's cgroups. If the coord wants to cap clients on memory /
   open-fid count / concurrent-attach, add it under `--user-policy`.
3. **Twrite latency vs flush amortisation**: under writeback aggregation,
   the proxy hop adds one extra serialisation point per Twrite. If
   benchmarks show this matters, the proxy can collapse multiple kernel
   Twrites into a single coord Twrite. Forward-noted to A2 v1.1.
4. **Cross-dataset operations (Q5)**: deferred to v1.x. Once landed, the
   pattern set may need to admit *pairs* (src, dst) — or the operation
   needs to go through coord directly via /ctl/.
5. **Auth backend pluggability**: the coordinator's per-uid policy is
   one approach; a SASL / factotum auth backend is another. v1.0 sticks
   with SO_PEERCRED-derived; pluggability deferred to a separate chunk.

## 13. Risks recap

- **Scope creep on impl-3**: the bilateral-auth layer is small but the
  coordinator-side policy table adds state. Mitigation: lock the policy
  shape early; if it grows past ~50 lines of code, slow down and audit
  ahead of impl-4.
- **Spec scope**: `multi_stratumd.tla` composes against
  `namespace.tla` + `fid.tla` + `compound_ops.tla`. Composition can
  blow up the state space. Mitigation: small constants (N=2 clients,
  Fids={f1,f2}); decline to model fs-level invariants again — assume
  them as composed contracts.
- **TLC tooling-gate**: per #973's carry, TLC verify is currently
  manual on this machine. Same carry-note: spec ships; TLC verify
  is forward-noted.
- **Wire-format temptation**: a reviewer may suggest a fresh binary
  wire for performance reasons. Resist; the audit cost dwarfs the
  perf benefit. If/when perf becomes the constraint, the coord can
  expose a fast-path side channel without abandoning 9P as the
  primary protocol.

---

**Next action**: TLY-A2-spec (`v2/specs/multi_stratumd.tla`). Expected ~half a
day of TLA+ work. Document state at `v2/docs/THYLACINE-V1-PLAN.md` updated
post-spec.
