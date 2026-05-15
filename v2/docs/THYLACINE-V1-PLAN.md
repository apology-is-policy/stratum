# Thylacine v1.0 Integration — Stratum-side Execution Plan

Companion to `~/projects/thylacine/docs/STRATUM-API-V1.md` (the Thylacine-side spec). This document is the **Stratum-side execution plan**: how each Thylacine ask is chunked, sequenced, and gated against the project's spec-first / audit-trigger discipline (CLAUDE.md §"Audit-triggering changes" and §"Spec-first policy").

Six asks: A1–A5 are v1.0 hard deps; A6 is explicitly v1.x deferred per Thylacine's own scoping.

**Status at the time this plan is filed**: PARALLEL-3 impl-5 has just shipped (`d03bc9a`). The next active workstream is one of {impl-6, P9-LIB-2 async, this Thylacine integration}. This plan re-prioritises in favour of Thylacine integration because A1 is the smallest item and unblocks Thylacine's largest architectural milestone (boot-into-real-Stratum-root).

---

## 0. Bilateral contract — accepted shape

After reading STRATUM-API-V1.md end-to-end, the Stratum-side accepts the asks as specified, with the following **negotiated answers** to the open questions Thylacine raised (Q1–Q18). These bind both sides; if Thylacine disagrees, we negotiate before implementation locks.

### Resolved open questions

| Q | Answer |
|---|---|
| **Q1** (pool_serial in /ctl/) | Yes, but admin-gated and truncated. New kind `KIND_POOL_SERIAL_INFO` under `/ctl/pools/<uuid>/`, admin-only, surfaces first 8 hex chars only. Full serial logged once at mount in stratumd's audit log. |
| **Q2** (`stratum pool migrate-serial`) | v1.x. Out of v1.0. Pre-existing pools work via the all-zero-as-unbound carve-out. |
| **Q3** (centralised audit log) | Yes — Stratum has `/ctl/events`. `STM_ESERIAL` events land there with the **full** serial (admin-readable) AND with the truncated serial in stderr (public). |
| **Q4** (pattern syntax) | Glob `*` (one level) + `**` (recursive) as Thylacine proposed. Path-prefix simpler but the explicit difference matters for `users/*` vs `users/**`. |
| **Q5** (cross-dataset ops) | Defer to v1.x. The pattern enforcement gate is at attach time (Tattach's `aname` checked against pattern set). |
| **Q6** (multi-stratumd audit log) | Per-stratumd log file at `/var/log/stratumd/<pool-uuid>.<pid>.log`; the `/ctl/events` API surfaces a merged view via the daemon that **owns** /ctl/. The "ctl-owner" stratumd is one specific instance per pool (see §4.3 below). |
| **Q7** (per-stratumd resource caps) | Optional; defer. Thylacine handles via cgroups / Plan-9-Proc handles. |
| **Q8** (session token opacity) | Opaque to Stratum. Stratum reads N bytes from the file and replays. No parsing. |
| **Q9** (UNWRAP retry policy) | 3 retries: 100ms / 500ms / 2s. Then exit non-zero. |
| **Q10** (corvus health check) | The UNWRAP request itself is the check. No separate ping verb. |
| **Q11** (wire protocol version) | Yes — add `protocol_version u8 = 1` after `verb_id`. Stratum sends v=1; corvus refuses unknown with BadFormat. |
| **Q12** (strict vs tolerant notify) | Tolerant with 30s default, configurable via `--corvus-notify-mode {strict,tolerant}` and `--corvus-notify-timeout <seconds>`. |
| **Q13** (notify sequence number) | Defer. Corvus-restart events are rare; strict/tolerant policy covers the gap. |
| **Q14** (pending writes on eviction) | Drain on user-initiated logout (the `SESSION_CLOSED` notify). Abort on `ADMIN_FORCE_EVICT` (forward-noted; not in v1.0). |
| **Q15** (unmark verb) | Yes. `mark-rollback-compromised` is reversible via `unmark-rollback-compromised` with `--force-unmark`; audit-logged. |
| **Q16** (corvus admin principal) | New `/ctl/admin/corvus-mark` writable kind, scoped to a corvus-specific UID configured at stratumd startup via `--corvus-admin-uid <uid>`. Refused for any other caller. |
| **Q17** (rekey API shape) | Deferred to v1.x. Will coordinate when corvus's ROTATE_KEY lands. |
| **Q18** (rekey perf) | Deferred to v1.x. |

### Net of the negotiation

Nothing about the asks is rejected. Two clarifications worth flagging back to Thylacine:

1. **Q6 multi-stratumd audit log**: Stratum's `/ctl/` is a synthetic FS surfaced by ONE process per pool. Under multi-stratumd, ONE of the per-user stratumds (or a dedicated "coordinator" stratumd) owns `/ctl/`; the others write to a per-process log file. The merged view of `/ctl/events` aggregates these. See §4.3 for the coordinator-stratumd design choice.
2. **A5 dependency**: A5 (rollback marker) requires the rollback verb itself to exist. SWISS-6 v1.1c is the pending rollback verb. The Stratum-side rollback machinery already exists (carry from v1; `stm_snap_rollback`); the v2 surfacing is what's pending. A5 may need to fold SWISS-6 v1.1c in as a prerequisite OR ship together.

---

## 1. Execution sequence

Thylacine's recommended order is A1 → A4 → A2 → A3 → A5 → A6. Stratum-side adopts this verbatim with one note: **A1 ships standalone first**; everything else is post-A1.

| Order | Ask | Stratum scope | Approx. impl chunks | Audit round |
|---|---|---|---|---|
| 1 | A1 — pool_serial + binding | Small | 1 (single commit) | R137 |
| 2 | A4 — SESSION_CLOSED notify consumer | Small | 2 (consumer + tests) | R138 |
| 3 | A2 — multi-stratumd-per-pool | Large | 5–7 (spec → impl phases) | R139 .. R143 |
| 4 | A3 — corvus UNWRAP wire | Medium | 3 (codec + integration + CLI) | R144 |
| 5 | A5 — snapshot rollback marker | Medium | 2 (storage + admin verb) | R145 |
| 6 | A6 — per-dataset rekey | v1.x | deferred | — |

Total estimated chunk count: ~13–16 substantive chunks across A1–A5. At the cadence of the project (1 ship + 1 audit cycle per chunk), this is **6–8 sessions** of focused work.

---

## 2. A1 — Pool serial binding

### Scope

A single field in the superblock + a CLI arg + a comparison gate at mount.

### Stratum-side design decisions

- **Storage**: carve `ub_pool_serial[16]` from the head of `ub_reserved` (currently 560 bytes at offset 3504 per `v2/include/stratum/super.h:707`). This follows the established convention (every PHA8 / R-series field addition has carved from `ub_reserved` without bumping `STM_UB_VERSION`). Net effect: `ub_reserved` shrinks 560 → 544 bytes. **No UB version bump required.**
- **Feature flag**: not needed. Pre-existing pools have `ub_pool_serial = {0}` because the entire `ub_reserved` block is zeroed at format time. The all-zero-as-unbound semantic the spec requests works for free.
- **Persistence + integrity**: `ub_pool_serial` is covered by the existing `ub_csum` xxHash3 over the superblock. Tamper-detection on the field is inherited. **No new audit surface for tamper.**
- **`stm_pool_create`** writes 16 CSPRNG bytes at format time (or accepts caller-supplied via the public API).
- **`stm_fs_mount`** reads `ub_pool_serial` post-uberblock-validation and compares against the caller-supplied expected value (per the comparison matrix in §3.3 of the ask).
- **New error**: `STM_ESERIAL` added to `types.h` (next free slot after `STM_EBACKEND = -207`).
- **/ctl/ surface** (Q1): new admin-gated kind `KIND_POOL_SERIAL_INFO` under `/ctl/pools/<uuid>/serial-info`. Surfaces the first 8 hex chars; admin-only.
- **Audit log**: mismatch logs to `/ctl/events` with the **full** serial (admin readable); stderr gets the truncated serial.

### Chunks

| Chunk | Deliverable |
|---|---|
| **TLY-A1-impl** | Superblock field + CSPRNG at create + comparison at mount + `STM_ESERIAL` + CLI args + `/ctl/` surface. Single commit. |
| **TLY-A1-test** | 7 tests from §3.6 of the ask, in `tests/test_super.c` and `tests/test_fs.c`. |
| **TLY-A1-docs** | Update `OS-INTEGRATION.md` §5 (encryption) with the bind-pool-serial section; update `REFERENCE.md` superblock layout table. |
| **R137** | Audit on TLY-A1-impl. Adversarial categories per ask §3.8: serial confusion, partial-write hazard, endianness consistency. |

### Spec-first verdict

Not needed. The change is a single 16-byte read + bytewise compare. No load-bearing invariant beyond what `ub_csum` already protects. (Per the project policy, "if you cannot articulate the invariant formally, you don't understand it well enough" — here the invariant is `disk.ub_pool_serial == caller.expected` and the compare is trivial.)

---

## 3. A4 — SESSION_CLOSED notify consumer

### Scope

A new long-running consumer thread inside stratumd that subscribes to corvus's `/srv/corvus/notify` Unix socket, parses `SESSION_CLOSED` frames, and triggers DEK eviction + clean unmount of affected datasets.

### Stratum-side design decisions

- **Implemented in stratumd** (`v2/src/cmd/stratumd/`), not in the libstratum-9p client. The notify channel is daemon-internal; userland tools don't need it.
- **Threading**: one dedicated `pthread_t` per-stratumd-instance with signal mask blocking SIGINT/SIGTERM/SIGHUP/SIGQUIT (R113 P1-1 doctrine). Daemon shutdown signals the thread via the existing stop-flag + a `pthread_cond_signal` on a new `notify_cv`.
- **Frame parser**: bounded byte-counts, length validation, integer overflow checks. Same trust-boundary discipline as the lp9/9P codec.
- **Eviction discipline**: on `SESSION_CLOSED { user="michael" }`:
  1. Locate all currently-mounted datasets whose dataset_id resolves to a path matching `users/michael` OR `users/michael/**`.
  2. For each: drain in-flight writes (`stm_fs_commit` synchronously); `explicit_bzero` the DEK cache slot; mark dataset RO; unmount.
  3. If this stratumd's `--datasets-allowed` matches ONLY michael's namespace → exit with status 0 after eviction completes.
- **DEK cache**: a new `stm_dek_cache` module under `v2/src/dek_cache/` (forward-noted; doesn't exist yet — at v2.0 DEKs are derived per-mount and held in `stm_sync`'s private state). The cache becomes load-bearing once corvus UNWRAP lands (§5); A4 ships the eviction discipline ahead of the cache to keep the cleanup-window shut.
- **Tolerant mode (Q12)**: configurable timeout. If the notify socket EOFs (corvus down), stratumd waits up to `--corvus-notify-timeout` (default 30s) for a re-subscribe; if it times out → strict-mode behaviour (evict + unmount + exit).
- **New error**: `STM_ECORVUSGONE` (notify socket closed, no recovery within timeout). Logged to `/ctl/events`.
- **CLI args**:
  - `--corvus-notify-socket <path>` (default `/srv/corvus/notify`)
  - `--corvus-notify-mode {strict,tolerant}` (default `tolerant`)
  - `--corvus-notify-timeout <seconds>` (default 30)

### Chunks

| Chunk | Deliverable |
|---|---|
| **TLY-A4-impl** | Notify consumer thread + frame parser + eviction discipline + CLI args. |
| **TLY-A4-test** | 6 tests from §6.5 of the ask. Faked corvus emitter for tests. |
| **TLY-A4-docs** | Update `OS-INTEGRATION.md` §4 (boot lifecycle) with the corvus-aware boot sequence. |
| **R138** | Audit. Categories: notify-frame parsing (malformed frame from hostile impersonator), eviction race (DEK accessed during wipe), unmount integrity. |

### Spec-first verdict

**Soft yes**. The eviction-ordering invariant ("DEK is zeroed before unmount returns; unmount drains all in-flight writes before evict") is load-bearing for the audit posture Thylacine asks for ("logout = data sealed"). A small `eviction.tla` spec would model the (notify-arrive → drain → wipe → unmount → exit) sequence and the failure modes (corvus dies mid-drain; unmount fails mid-drain). 2–3 buggy configs. ~1 day of TLA+ work.

Decision: write the spec at chunk start; ship with the impl. Lift to mandatory if the audit (R138) finds an invariant violation.

---

## 4. A2 — Multi-stratumd-per-pool

This is the largest item — it changes the fundamental concurrency posture of stratumd from "one process per pool" to "many processes per pool". Mandatory spec-first.

### Stratum-side design decisions

This is a fork in the road. Two viable approaches:

**Option A — Pool-level coordinator daemon**. A small `stratumd-coord` process owns the pool device (exclusive open). The per-user stratumds dial it and forward allocator/journal/commit ops over a Unix socket. This is the simplest correctness story (single-writer to the device is preserved) but adds an extra hop.

**Option B — Pool-internal shared lock**. Each stratumd opens the pool device directly. Coordination via `flock(2)` on the device fd + a shared-memory region for the allocator's in-RAM state. More complex; preserves zero-hop performance.

**Recommendation**: **Option A** (coordinator daemon). Reasoning:

- Stratum's existing pool/sync/alloc code assumes a single-process owner. Refactoring to Option B touches the allocator, the sync layer, the journal, the cache — invasive. Option A keeps the single-process model and the coordinator IS that process; the per-user stratumds are FUSE-like clients of the coordinator.
- The coordinator can also own `/ctl/` (resolves Q6 cleanly: one process emits `/ctl/events`).
- This is also the model that maps cleanest to a future kernel-native stratum module (the module IS the coordinator).
- The audit posture is cleaner: cross-process race classes collapse to "client-server RPC under SO_PEERCRED authentication," which the project already has spec'd (`namespace.tla`, `ctl_conn.tla`).

If Thylacine prefers Option B (lower latency at the per-user stratumd level), we negotiate. Option A is the Stratum-side default.

### Option A architectural sketch

```
                ┌─────────────────────────────────┐
                │  /var/lib/stratum/pool.stm      │  ← actual device
                └───────────────┬─────────────────┘
                                │ exclusive open
                ┌───────────────▼─────────────────┐
                │  stratumd-coord (PID 1000)      │
                │  - owns device                  │
                │  - owns alloc / journal / sync  │
                │  - serves /ctl/                 │
                │  - hub for per-user clients     │
                └─┬─────────────┬─────────────┬───┘
                  │ Unix sock   │ Unix sock   │
        ┌─────────▼─┐    ┌──────▼──────┐    ┌─▼──────────┐
        │stratumd-  │    │stratumd-    │    │stratumd-   │
        │system     │    │michael      │    │susan       │
        │(serves    │    │(serves      │    │(serves     │
        │ system)   │    │ users/      │    │ users/     │
        │           │    │ michael)    │    │ susan)     │
        └───────────┘    └─────────────┘    └────────────┘
              │                │                  │
       /sysroot mount    /home/michael mount  /home/susan mount
```

The per-user stratumds are **fronts**: they speak 9P2000.L to the kernel client, but every actual block I/O / allocator op / commit gets forwarded to the coordinator.

### `--datasets-allowed` enforcement

Implemented at **Tattach time** in the per-user stratumd. The `aname` in Tattach is checked against the pattern set; non-match → Rerror(EACCES). Subsequent Twalks are constrained to the attached dataset's subtree (already enforced; see `reference/20-9p.md`).

### Coordinator wire format

Internal — not user-facing. We can use libstratum-9p as the wire (9P2000.L from the per-user stratumd, fronting onto a coordinator-internal "block op" interface). OR a fresh binary protocol. Decision deferred to the design-doc phase.

### Chunks

| Chunk | Deliverable |
|---|---|
| **TLY-A2-design** | Design doc at `v2/docs/thylacine-multi-stratumd-design.md`. Locks in Option A vs B, the coordinator wire, the spec scope. |
| **TLY-A2-spec** | New `specs/multi_stratumd.tla` modelling: per-user stratumd → coordinator RPC; allocator coordination; crash recovery across processes. ≥3 buggy configs. |
| **TLY-A2-tlc** | TLC verify (tooling-gated; carry the same caveat as #973). |
| **TLY-A2-impl-1** | `stratumd --coordinator` mode (boots the coordinator; no clients yet). |
| **TLY-A2-impl-2** | `stratumd --client --coordinator-socket <path>` mode + `--datasets-allowed` pattern matching + Tattach-time gate. |
| **TLY-A2-impl-3** | Coordinator-side allocator-RPC + journal-RPC + commit-RPC. The bulk of the work. |
| **TLY-A2-impl-4** | Crash recovery: one client crashes → coordinator releases its in-flight tx; other clients unaffected. |
| **TLY-A2-impl-5** | 72-hour stress test (from ask §4.6). |
| **R139..R143** | One audit round per impl chunk. |

This is **5 substantive impl chunks + 3 design/spec chunks**. At project cadence: ~4 weeks of focused work, possibly more.

### Alternative — defer A2 to v1.1

This is the largest item by far. If Thylacine can accept a v1.0 single-stratumd model with **per-connection caller-credential enforcement** (which we already have via SO_PEERCRED on `/ctl/`), the per-user stratumd model becomes a v1.1 chunk. The eviction story degrades from "kill the process = DEK gone" (structural) to "SIGUSR1 to a thread = DEK zeroed" (cooperative).

I'd propose Thylacine considers this trade. If the audit posture genuinely requires the structural mitigation, we do A2 in full. If cooperative-eviction-plus-SO_PEERCRED is acceptable, we save 4 weeks and ship A1+A3+A4+A5 in v1.0.

**Decision needed from Thylacine before implementation starts.**

---

## 5. A3 — corvus UNWRAP wire

### Scope

A new key-agent client library that speaks the corvus binary wire format. Wires up at mount-time of an encrypted dataset.

### Stratum-side design decisions

- **New module**: `v2/src/corvus_client/` + `v2/include/stratum/corvus_client.h`. Pure C, no Rust dependencies. Sibling to (NOT replacing) the existing janus client.
- **Wire**: per ask §5.2 with the `protocol_version u8 = 1` byte added (Q11 carry).
- **Frame encoder + decoder** with strict bound-checks. Same trust-boundary discipline as the lp9 codec (R111 doctrine carry — caller-cap on every server-supplied count).
- **Token handling**: read 33 bytes from `--corvus-session-token-file`, `mlock`+`MADV_DONTDUMP` the buffer, `explicit_bzero` on shutdown. Never log.
- **DEK caching**: extends to A4's eviction discipline. Once cached, the DEK is held in mlock'd RAM under the dataset's `stm_dataset` private state.
- **Mount-time integration**: in `stm_fs_mount`, the dataset-decrypt path checks if a wrapped-DEK blob is present in the dataset metadata; if so, sends UNWRAP to corvus; on success, the DEK is used for AEAD/decryption.
- **Retry policy (Q9)**: 3 retries at 100ms / 500ms / 2s. Then exit non-zero with `STM_ECORVUSAUTH` (BadAuth) / `STM_ECORVUSPERM` (PermissionDenied) / `STM_ECORVUSGONE` (transport).
- **CLI args**:
  - `--corvus-socket <path>` (default `/srv/corvus/ops/unwrap`)
  - `--corvus-session-token-file <path>` (no default; required when an encrypted dataset is mounted)

### Chunks

| Chunk | Deliverable |
|---|---|
| **TLY-A3-impl-1** | ✓ `libstratum-corvus.a` codec + token loader. Unit tests for frame encode/decode, bound checks, token loading. (`1eb7480`) |
| **TLY-A3-impl-2** | ✓ Transport (`stm_corvus_unwrap_once`) + retry policy (`stm_corvus_unwrap`, Q9 backoff schedule). Error matrix from ask §5.5. Fake-corvus pthread harness, 13 transport/retry tests. (`58a7253`) |
| **TLY-A3-impl-3** | **Mount-time integration + CLI args.** Re-scoped out of impl-2 — the §5.3 data-flow ("`stm_fs_mount` consults a per-dataset wrapped-DEK blob → UNWRAP → DEK feeds AEAD") needs a prerequisite that does NOT yet exist: a place to store the per-dataset `{key_id, wrapped_dek}`. Stratum's current encryption derives DEKs from a master key + dataset_id; there is no per-dataset wrapped-DEK store. impl-3 must FIRST make a design micro-decision (corvus-style keyfile variant vs new dataset-metadata field), THEN wire the mount path + CLI args (`--corvus-socket`, `--corvus-session-token-file`). |
| **TLY-A3-test** | 7 tests from ask §5.7 (faked corvus) — happy path / wrong-user / bad-token / offline / restart / wire-edge / large-blob. Folds into impl-3 (needs the mount path). The transport/retry layer's 13 tests already cover the wire-format-edge + offline + restart classes at the primitive level. |
| **TLY-A3-docs** | Update `OS-INTEGRATION.md` §5 with the corvus integration path. Folds into impl-3. |
| **R144** | Audit. Categories: wire-format injection, session-token leak, DEK lifetime. Scopes impl-1 + impl-2 (codec + transport); re-runs against impl-3 when the mount path lands. |

### Spec-first verdict

Not needed for the codec itself. The DEK lifecycle invariant (cached → evicted → wiped, never logged) is covered by the existing audit posture for crypto-nonce / key-handling (CLAUDE.md trigger list row).

---

## 6. A5 — Snapshot rollback compromise marking

> **2026-05-15 revision — premise correction.** An earlier draft of
> this section claimed "Stratum's snapshot rollback machinery exists
> at the C API level (`stm_snap_rollback` carry from v1); the v2
> surfacing is pending." **That is false.** `stm_snap_rollback` is a
> **v1-only** function. v2 has NO snapshot rollback — `snapshot.h`
> lists it as explicitly out-of-scope, and v2's metadata lives in
> *pool-global* trees keyed by `(dataset_id, …)` (`ub_inode_root`,
> `ub_dirent_root`, `ub_xattr_root`, `ub_extent_root`), NOT the
> per-dataset `di_tree_root` that `ARCHITECTURE.md` §8.5/§12.6
> assumes. v2 snapshots today capture only `extent_txg` (a
> generation number) with `tree_root_paddr = 0` — they do birth-txg
> accounting for *delete* but root no recoverable past tree. Real
> per-dataset rollback needs per-dataset metadata trees, which is a
> foundational re-architecture — see the post-TLY phase in
> `docs/ROADMAP-V2.md`. **A5 therefore ships marker-first with a
> stubbed rollback verb** (decision 2026-05-15).

### Scope (marker-first)

A5 ships the **compromise marker** — the security-relevant deliverable
— in full, and the **rollback verb surface** with a stubbed backend.
The marker is what Thylacine's F13 concern needs: a way to flag a
snapshot as compromised so a future rollback refuses it. The marker,
the mark/unmark verbs, the corvus-principal gate, and the
rollback-verb's marker-consultation gate are all REAL and tested. The
rollback verb's *data mutation* is a stub (`stm_fs_rollback_snapshot`
returns `STM_ENOTSUPPORTED`); the marker-consultation gate fires
before the stub, so the `rollback-blocked-iff-compromised` invariant
is genuinely exercised.

Real rollback lands in the post-TLY **Snapshot Completion** phase
(per-dataset metadata trees + O(1) rollback per `ARCHITECTURE.md`
§8.5/§12.6). When it lands, only the stub body is replaced — the
`/ctl/` verb surface, admin gate, marker consultation, force-prefix
parsing, and TUI double-confirm are all already in place from A5.

### Stratum-side design decisions

- **Marker storage**: a bit in the existing `stm_snapshot_entry.flags`
  field (`STM_SNAP_FLAG_ROLLBACK_COMPROMISED`) — no on-disk format
  change, no UB-version bump. Persistent in the snapshot index.
- **Reason text**: NOT stored in a new on-disk structure. The
  mark-compromised reason flows to the `/ctl/events` audit log (which
  already exists) — the persistent state is just the flag bit. (Final
  call in TLY-A5-design.)
- **Admin verbs** (new `/ctl/` kinds, admin-gated):
  - `/ctl/datasets/<id>/snapshots/<sid>/mark-compromised` — write `<reason-text>` to mark.
  - `/ctl/datasets/<id>/snapshots/<sid>/unmark-compromised` — write `force` to unmark (Q15).
  - `/ctl/datasets/<id>/rollback-snapshot` — write `<sid>` to roll back. If the snap is marked, refuses unless body is `force <sid>` (Q15). v1.0: on a non-marked / forced request the backend stub returns `STM_ENOTSUPPORTED` with a clear message.
- **Listing**: extends the existing `/ctl/datasets/<id>/snapshots/<sid>` info kind with a "compromised" line.
- **Corvus principal** (Q16): new CLI arg `--corvus-admin-uid <uid>`. The mark-compromised kind admits writes from THAT uid in addition to the regular admin uid. No other caller is admitted.

### Chunks

| Chunk | Deliverable |
|---|---|
| **TLY-A5-design** | Design doc — marker-first scope; records the snapshot-substrate gap + the post-TLY Snapshot Completion phase. |
| **TLY-A5-spec** | `snapshot.tla` extension — `rollback-blocked-iff-compromised` invariant + the unmark-races-rollback case + marker non-perturbation of existing invariants. |
| **TLY-A5-impl-1** | Compromise marker — `flags` bit + `mark-compromised` / `unmark-compromised` admin verbs + corvus-principal gate (`--corvus-admin-uid`) + the snapshots info-kind "compromised" line. |
| **TLY-A5-impl-2** | `/ctl/datasets/<id>/rollback-snapshot` verb surface — admin gate + marker consultation (refuse-on-marked-unless-`force`) + `stm_fs_rollback_snapshot` STUB (`STM_ENOTSUPPORTED`) + TUI double-confirm (replaces the SWISS-6 v1.1c stub dialog). |
| **TLY-A5-test** | tests from ask §7.6 (adapted — rollback success cases become stub-return assertions). |
| **TLY-A5-docs** | Update `OS-INTEGRATION.md` §8 (snapshots) + reference docs. |
| **R146** | Audit. Categories: marker-bypass (rollback path doesn't consult the flag), unauthorised mark (attacker writes mark), corvus-principal scope, the stub's fail-safe posture. |

### Spec-first verdict

**Yes.** `snapshot.tla` already exists; the extension covers the
`rollback-blocked-iff-compromised` invariant + the unmark-races-rollback
case + confirms the marker flag does not perturb the existing
chain/hold/txg invariants. The rollback *mechanism* itself is NOT
specced here — that spec belongs to the post-TLY Snapshot Completion
phase, where the per-dataset-tree rollback algorithm is designed.

---

## 7. Cross-cutting Stratum-side discipline

### CLAUDE.md trigger-list additions

Each ask adds a new audit-trigger surface. To be added to CLAUDE.md trigger list as part of each chunk's close:

| Surface | Trigger row to add |
|---|---|
| Pool serial binding | After "Superblock layout / validation" — `--bind-pool-serial`, `STM_ESERIAL`, `/ctl/pools/<uuid>/serial-info` |
| corvus client | New row — `v2/src/corvus_client/`, `v2/include/stratum/corvus_client.h` |
| Notify consumer | New row — stratumd's notify-consumer thread |
| Multi-stratumd coordinator | New row — `v2/src/cmd/stratumd-coord/` (or whatever the coord path becomes) |
| Snapshot compromise marker | After "Snapshot index" — marker field + admin verbs |

### Memory file additions

- New memory file `project_thylacine_v1.md` — tracks the Thylacine integration tip, the bilateral contract status, and the dependency chain (Stratum-side asks ↔ Thylacine P5-* chunks).
- Update `project_v2_active.md` workstream line to reflect Thylacine integration as the active phase.

### Documentation discipline

Per the ask §9.4:
- `OS-INTEGRATION.md` updates per chunk (already enumerated above).
- New `reference/24-corvus-client.md` (new module reference doc).
- New `reference/25-multi-stratumd.md` if A2 is implemented.
- Mirror copy of STRATUM-API-V1.md into `v2/docs/` for tree-local discoverability. (Pull from Thylacine's tree; keep up to date as the contract evolves.)

### Audit posture

Every chunk gets a closing audit round (R137..R145+). Adversarial categories per ask are spelled out in STRATUM-API-V1.md and inherited.

---

## 8. Immediate next actions

In strict order — start TODAY:

1. **Mirror STRATUM-API-V1.md into `v2/docs/STRATUM-API-V1.md`** (tree-local copy; one-way sync from Thylacine's tree).
2. **Send §0 negotiated-answers + §4 A2-decision-needed back to Thylacine** for sign-off. **This blocks the A2 chunking** — without Thylacine's verdict on Option A vs deferring A2 to v1.1, we don't commit to the 4-week scope.
3. **Start TLY-A1-impl** in parallel with the negotiation — A1 is uncontroversial and unblocks Thylacine's P5-stratumd-bringup regardless of the A2 outcome. Concrete first commit:
   - Add `ub_pool_serial[16]` to `v2/include/stratum/super.h` carved from `ub_reserved`.
   - `stm_pool_create` writes CSPRNG bytes.
   - `stm_fs_mount` reads + accepts `expected_pool_serial` pointer in mount opts (NULL = no check).
   - `stratumd --bind-pool-serial <hex>` arg parsing.
   - `STM_ESERIAL = -208` in types.h.
   - 7 tests from §3.6.
   - `/ctl/pools/<uuid>/serial-info` admin kind.
   - R137 audit.
4. **After A1 ships**, **start TLY-A4-impl** (notify consumer — independent of A2). Small, mostly self-contained.
5. **After A4 ships**, **wait for Thylacine's A2 verdict** before chunking A2. Meanwhile, **TLY-A3-impl-1** (the corvus codec) can start — it's independent of the coordinator model.

### Tasks to create

After Thylacine signs off on §0 negotiated answers:

- TLY-A1-impl (single-commit substantive chunk)
- R137 audit
- TLY-A4-impl-1 (notify consumer)
- TLY-A4-impl-2 (eviction discipline + tests)
- R138 audit
- TLY-A2-design (gated on Thylacine decision)
- TLY-A2-spec (gated on TLY-A2-design)
- TLY-A2-tlc (tooling-gated)
- TLY-A2-impl-1..5 (gated on spec)
- R139..R143 (one per impl chunk)
- TLY-A3-impl-1 (codec; can start anytime post-A1)
- TLY-A3-impl-2 (mount integration; gated on A2 if A2 ships)
- R144 audit
- TLY-A5-impl-1 (folded with SWISS-6 v1.1c)
- TLY-A5-impl-2 (marker + admin verbs)
- TLY-A5-impl-3 (rollback consultation)
- R145 audit

---

## 9. Risks

1. **A2 scope creep**. The largest risk. If Thylacine insists on per-process structural eviction at v1.0 AND the coordinator-daemon model surfaces unexpected complexity (e.g., the journal coordination is harder than estimated), the timeline slips. Mitigation: defer A2 to v1.1 per §4's "Alternative" discussion.
2. **`pool_serial` partial-write hazard** (per ask §3.8). Mitigated by it living in the existing superblock under `ub_csum` — same fsync discipline as every other ub_ field.
3. **corvus wire format evolution**. We commit to v=1 of the wire; future versions are corvus's call. If Thylacine bumps the wire mid-v1.0, Stratum follows.
4. **Notify-Spoor model assumptions**. The ask describes Spoors (Plan-9-like duplex channels). On Linux we implement with Unix sockets. If Thylacine's Spoor semantics differ from plain Unix-socket semantics in a load-bearing way, we'd need to revisit.
5. **Multi-process audit log integrity** (Q6). Per-process log files + a merged view via `/ctl/events` is the simplest answer. If Thylacine needs stronger guarantees (e.g., total ordering across writers), we revisit.

---

## 10. References

- Thylacine spec: `~/projects/thylacine/docs/STRATUM-API-V1.md`
- `CORVUS-DESIGN.md` (Thylacine tree) — wire format, invariants, lifecycle.
- Stratum `OS-INTEGRATION.md` — Stratum-side OS-author manual; updated per chunk.
- Stratum `CLAUDE.md` — audit-trigger list (gets new rows per chunk).
- Stratum `v2/docs/REFERENCE.md` + `reference/*.md` — as-built per-subsystem references.
- Stratum `v2/specs/*.tla` — formal specs (extensions per A2, A4, A5).

---

**Document state**: living plan. Updated as chunks ship and the bilateral contract evolves. Filed at the same moment PARALLEL-3 impl-5 closed (Stratum tip `d03bc9a`).

**Next action**: send the §0 negotiation + §4 A2-decision question back to Thylacine. Start TLY-A1-impl in parallel.
