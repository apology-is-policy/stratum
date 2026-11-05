# Stratum API — v1.0 Thylacine Integration

Concrete specification of the Stratum-side changes Thylacine needs for v1.0 boot + post-pivot operation. Each ask names the motivation (with cross-references to `CORVUS-DESIGN.md` and `ARCHITECTURE.md`), the API shape (CLI args / pool superblock fields / 9P wire frames), the behavioural contract, the error model, the test matrix, and the open questions worth discussing before Stratum-side implementation locks.

This document is the Thylacine-side spec — it states what Thylacine *needs*. Stratum is the source of truth on Stratum-side architecture; Michal shapes the implementation. Where shape is genuinely Thylacine-facing (wire frames consumed by Thylacine code, CLI args Thylacine's installer invokes), this doc is binding. Where shape is Stratum-internal (which file owns the pool superblock, how multi-stratumd coordination locks are structured), this doc is suggestive — Michal's choice wins.

The Thylacine-side commitments are also enumerated (§10) so the contract is bilateral.

---

## 1. Mission

Thylacine v1.0 boots into a Stratum-backed root, runs encrypted per-user datasets, and gates everything privileged through `corvus` (the Thylacine-native key agent). Per `CORVUS-DESIGN.md §3 D4`, the post-pivot stack is:

```
joey (init, post-pivot)
  ├── stratumd-system (mounts the system pool; one process; system-pool only)
  ├── corvus           (key agent; owns user wrap chains; mlock'd RAM)
  ├── login            (console / Halcyon)
  └── stratumd-michael (per-user; one process per logged-in user; owns user dataset)
      ├── stratumd-susan
      └── ...
```

Five Stratum-side capabilities make this work; one more is reserved for v1.x. Without these, Thylacine v1.0 either degrades to a single-user model (no multi-stratumd) or accepts a security regression (no pool-serial binding → swap-the-disk evil-maid succeeds).

The asks are independent enough that each can land as its own Stratum-side chunk; they share Thylacine's audit posture across §13 of `CORVUS-DESIGN.md`.

---

## 2. Priority and sequencing

Ordered by Thylacine's critical path: the smallest item ships first and unblocks Thylacine's biggest architectural moment (boot into Stratum root).

| # | Ask | Unblocks Thylacine chunk | Stratum scope | Hard dep at v1.0? |
|---|---|---|---|---|
| **A1** | `--bind-pool-serial` + `pool_serial` superblock field | P5-stratumd-bringup (boot into real Stratum root; not stub) | tiny | YES — boot security regression without it |
| **A2** | Multi-stratumd-per-pool (datasets-allowed scoping) | P5-login (per-user stratumd spawning) | medium | YES — single-user fallback otherwise |
| **A3** | corvus-validated UNWRAP wire | P5-corvus-bringup | medium | YES — no encrypted user datasets otherwise |
| **A4** | Session-close → DEK eviction notify | P5-login (logout flow + crash recovery) | small | YES — logout integrity hole otherwise |
| **A5** | Snapshot rollback compromise marking | P5-corvus-bringup (closes C-13) | medium | NO — defence in depth; can ship after v1.0 |
| **A6** | Per-dataset key rotation hooks (cryptographic forward secrecy) | v1.x corvus ROTATE_KEY verb | large | NO — explicitly v1.x per CORVUS-DESIGN §11 |

Suggested implementation order on Stratum side: **A1 → A4 → A2 → A3 → A5 → A6**. A1 + A4 are small + independent and unblock the most. A2 + A3 are the substantive lifts. A5 + A6 are defences that can land asynchronously.

If Stratum is bandwidth-constrained: **A1 alone unblocks P5-stratumd-bringup**. Thylacine can use a kernel-internal stratumd-stub for P5-stratumd-stub-bringup without any Stratum changes; the real stratumd integration needs A1 minimum.

---

## 3. A1 — Pool serial binding

### 3.1 Motivation

Per `CORVUS-DESIGN.md §3 D2` + invariant **C-14**: at v1.0 the system pool is integrity-only (no AEAD), but `boot_key` is cryptographically bound to a unique serial written in the pool's superblock. `stratumd-system` refuses to mount on serial mismatch.

The attack this defends against: **physical-disk evil-maid swaps the pool device**. The attacker reads `/boot/system.key` from the unencrypted ESP, crafts their own pool with attacker-known contents, and powers the machine on. Without serial binding, `stratumd-system` happily mounts the attacker's pool against the legit key. The attacker substitutes binaries, harvests user passphrases on next login, exfiltrates user data.

With serial binding, `stratumd-system` reads the on-disk `pool_serial` and refuses to mount unless it matches the value bound at install time. The attacker can't fake the serial without already having physical access to the real pool. The real pool is the security boundary.

This does NOT defend against the attacker modifying the on-disk bootloader / kernel / initrd — see `CORVUS-DESIGN.md §3 D6` (v1.0 explicit acceptance; Secure Boot in v1.1).

### 3.2 Pool superblock field

A new field in the pool superblock:

```
pool_serial: u8[16]    // 128 bits of CSPRNG entropy, fixed at pool create time
```

**Properties**:
- Written exactly once, at pool create.
- Never mutated during the pool's lifetime.
- 128 bits is generous; 64 bits would suffice (no birthday-style collision concern — this is a binding identifier, not a hash).
- Stored at a fixed offset Michal chooses; preferably in the un-encrypted superblock header (must be readable before any decryption).

**Compatibility with existing pools**: an all-zero `pool_serial` means "unbound" — stratumd ignores `--bind-pool-serial` if the on-disk value is all zeros. This lets Thylacine deployments on pre-existing Stratum pools continue to work; only freshly-created pools (where Thylacine controls install) get a non-zero serial.

A `stratum pool set-serial <hex>` migration tool (v1.x, no Thylacine dep) lets pre-existing pools opt in to binding without a full re-create. The migration writes the serial to a previously-all-zero superblock field. Migration cannot be reversed — once bound, the pool is permanently bound to that serial.

### 3.3 stratumd CLI

```
stratumd --pool <device> --bind-pool-serial <32-hex-chars> [other args...]
```

`--bind-pool-serial` is **optional**:
- If absent: stratumd reads the on-disk `pool_serial` but does not compare; mount succeeds regardless.
- If present: stratumd decodes the arg as 16 bytes (hex), reads on-disk `pool_serial`, compares byte-for-byte:
  - Both all-zero (unbound pool): mount succeeds with a one-line warning ("pool is unbound; --bind-pool-serial value ignored").
  - On-disk all-zero but arg non-zero: mount fails with `STM_ESERIAL` (don't silently mount an unbound pool when binding was requested).
  - Both non-zero and equal: mount succeeds.
  - Both non-zero but unequal: mount fails with `STM_ESERIAL`.

Thylacine's `stratumd-system` always passes `--bind-pool-serial` in production. The arg is sourced from `/boot/system.key.salt` on the ESP (per `CORVUS-DESIGN.md §3 D2`'s install layout).

### 3.4 Error semantics

A new error code:

```
STM_ESERIAL    // pool serial mismatch with --bind-pool-serial value
```

Logged at WARN+ level on stratumd's stderr:
```
stratumd: pool serial mismatch (expected=<first-8-hex>... observed=<first-8-hex>...);
          refusing to mount per --bind-pool-serial discipline
```

Only the first 8 hex chars are logged for confidentiality (full serial is in stratumd's audit log if any). Stratumd exits with a non-zero status; Thylacine's joey treats `STM_ESERIAL` as a halt condition and drops to recovery.

### 3.5 Install-time discipline

The `stratum pool create` flow gains:

```
stratum pool create --pool <device> [--pool-serial <32-hex>]
```

- If `--pool-serial` is provided: use the supplied 16 bytes.
- If absent: CSPRNG-generate 16 bytes, write them to the superblock, and print to stdout in this exact format (for the installer to capture):

```
pool-serial: <32-hex-chars>
```

Thylacine's installer uses the explicit-supply mode: it generates `pool_serial` via its own CSPRNG, passes it to both `stratum pool create --pool-serial X` and the wrap-key derivation (`HKDF(install_salt, pool_serial || install_uuid || master_secret) → boot_key`). The two ends produce the same `pool_serial` deterministically.

### 3.6 Test matrix

| Test | Setup | Expected |
|---|---|---|
| Bound mount happy | Pool with serial=X; mount `--bind-pool-serial X` | Mount succeeds |
| Bound mount mismatch | Pool with serial=X; mount `--bind-pool-serial Y` | `STM_ESERIAL` |
| Unbound pool, no arg | Pool with serial=0; mount without arg | Mount succeeds |
| Unbound pool, arg given | Pool with serial=0; mount `--bind-pool-serial X` | `STM_ESERIAL` (don't silently allow) |
| Tampered serial | Pool with serial=X; rewrite to Y on disk; mount `--bind-pool-serial X` | `STM_ESERIAL` |
| All-zero arg | Pool with serial=X; mount `--bind-pool-serial 0000...0000` | `STM_ESERIAL` |
| `stratum pool create` produces serial | `stratum pool create --pool /dev/X` (no --pool-serial) | Stdout includes `pool-serial: <32-hex>`; pool's superblock matches |

### 3.7 Open questions

- **Q1**: Is `pool_serial` exposed via `/ctl/`? Useful for diagnostics but reveals the binding anchor. Recommendation: gate behind an admin verb; truncate to first 8 hex chars in non-admin views.
- **Q2**: Should `stratum pool migrate-serial` exist at v1.0? Thylacine doesn't need it (we control install); answer probably "v1.x, low-priority."
- **Q3**: Logging — does Stratum already have a centralised audit log? If so, the `STM_ESERIAL` event should also land there with the full serial (so an admin can diagnose without rebooting).

### 3.8 Audit posture

Stratum-side, this lands as a new audit-trigger surface (per Stratum's own audit policy):
- Pool superblock format change (field add).
- Mount-path serial check.
- CLI arg parsing.

Suggested adversarial categories: serial confusion (bound pool reads tampered superblock that flips serial mid-read), partial-write hazard (`pool_serial` written but install crashes — Stratum needs the field to be in a fsync'd-before-anything-else region), endianness consistency.

---

## 4. A2 — Multi-stratumd-per-pool

### 4.1 Motivation

Per `CORVUS-DESIGN.md §3 D4` (Order C, audit-driven Option A): each logged-in user runs their **own** `stratumd` process scoped to their dataset. corvus's UNWRAP verb checks `peer_proc.user == owner_of(dataset)`. Killing `stratumd-michael` evicts michael's DEK from RAM by construction (structural mitigation of audit F16); the multi-process design replaces a single shared-stratumd model that was rejected for capability-leak reasons.

Without multi-stratumd-per-pool, Thylacine collapses to either:
- One stratumd serving all users (DEK cache cross-contamination; killing it logs out everyone).
- One pool per user (no shared system pool; complicates install + admin operations).

Neither is acceptable for v1.0 production.

### 4.2 stratumd CLI

```
stratumd --pool <device> \
         --datasets-allowed <pattern> [--datasets-allowed <pattern> ...] \
         --bind-pool-serial <hex> \
         [other args]
```

`--datasets-allowed` is **repeatable**. Each pattern restricts the set of datasets this stratumd can mount + serve. Pattern syntax:

```
users/michael               # exact match (one dataset)
users/michael/**            # michael's dataset + any nested datasets under it
users/*                     # any first-level user dataset (no nesting)
system                      # exact match
system/**                   # system + any nested
```

If `--datasets-allowed` is absent: stratumd serves all datasets in the pool (back-compat mode for existing single-stratumd deployments).

If `--datasets-allowed` is present: stratumd refuses to mount, read, or write any dataset not matching at least one pattern. Refused calls return `STM_EDATASETNOTALLOWED`.

Thylacine's per-user stratumd invocations look like:

```
stratumd --pool /dev/main \
         --datasets-allowed users/michael \
         --datasets-allowed users/michael/** \
         --bind-pool-serial <hex>
```

`stratumd-system` looks like:

```
stratumd --pool /dev/main \
         --datasets-allowed system \
         --datasets-allowed system/** \
         --bind-pool-serial <hex>
```

### 4.3 Coordination model

Multiple stratumd processes share one block device. Stratum's existing transaction model must accommodate:

- **Allocator / free-space**: pool-level coordination required. Options:
  - Process-level lock on the allocator (one process at a time can allocate; serialise via a shared semaphore in the pool superblock or a Stratum-side coordination daemon). Simplest; likely adequate for v1.0 workloads.
  - Per-extent locks (finer-grained; more complex; not needed at v1.0).
- **Journal / write-ahead log**: similar — needs pool-level coordination.
- **Read-only operations**: should be unrestricted (each stratumd serves its own datasets' reads concurrently).

Stratum-side design decision; this doc doesn't prescribe.

### 4.4 Crash recovery

If `stratumd-michael` crashes mid-transaction:
- Other stratumds must continue serving their datasets without interruption.
- michael's in-flight writes either commit fully or roll back fully (no partial state).
- The pool's allocator + journal recover automatically (no pool-wide remount required).
- Restart of `stratumd-michael` resumes service without manual intervention.

Stratum's existing single-process crash recovery handles in-flight transaction reversal; the multi-process case requires that one crashing process doesn't wedge other stratumds' transactions.

### 4.5 Error semantics

New error codes:

```
STM_EDATASETNOTALLOWED    // dataset not in --datasets-allowed pattern set
STM_EPOOLLOCKED           // pool-level lock held by another stratumd; retry
```

`STM_EDATASETNOTALLOWED` is a hard failure (no retry); the caller misconfigured patterns.

`STM_EPOOLLOCKED` is transient (allocator / journal contention); the stratumd-side retry policy is "exponential backoff up to N ms then return STM_EPOOLLOCKED to the caller." Thylacine doesn't generally surface this — it indicates Stratum-internal contention.

### 4.6 Test matrix

| Test | Setup | Expected |
|---|---|---|
| Concurrent mount happy | 3 stratumds: system + michael + susan; same pool | All 3 mount + serve concurrently |
| Cross-dataset refusal | stratumd-michael tries to mount `users/susan` | `STM_EDATASETNOTALLOWED` |
| Cross-dataset wire-level refusal | stratumd-michael serves `users/michael`; a client connects + tries to Twalk to `users/susan` | Server refuses (root-relative walk constrained to allowed datasets) |
| Crash recovery | stratumd-michael writes mid-transaction; kill -9; restart | Transaction rolls back; pool not wedged for system + susan |
| Concurrent allocator | 2 stratumds simultaneously allocate from system pool | Both succeed; no allocator corruption |
| Pattern matching | `--datasets-allowed users/*` mounts users/anna, refuses users/anna/secret | Behaviour matches pattern's nesting depth |
| All-allowed back-compat | stratumd without `--datasets-allowed` | Serves all datasets in pool (existing behaviour preserved) |
| 72-hour stress | 4 stratumds concurrent writes for 72 hours | No data corruption; consistent post-recovery state |

### 4.7 Open questions

- **Q4**: Pattern syntax — is `users/*` vs `users/**` the right convention? Glob-style is widely understood; alternative is path-prefix-only (`users/`).
- **Q5**: What about `bind` mounts and inter-dataset operations? E.g., does `stratumd-michael` need to read `users/shared` if a future shared-dataset feature exists? Recommendation: defer cross-dataset operations to v1.x (they're not in the v1.0 user-isolation model).
- **Q6**: Audit log — does multi-stratumd require multi-writer audit log? If Stratum's audit log is per-stratumd, each process writes its own file; if pool-wide, coordination is needed.
- **Q7**: Resource caps — does Stratum want per-stratumd memory / connection / FD caps? Thylacine has its own resource caps at the OS layer (per-Proc handles), so Stratum-side caps are optional.

### 4.8 Audit posture

This becomes a substantial new audit-trigger surface on Stratum side:
- Pool-level coordination layer (locks, journal, allocator).
- Per-stratumd dataset-restriction enforcement (read, write, walk, mount).
- Crash-recovery across multiple processes.

Adversarial categories: cross-stratumd race (one process commits while another is in the middle of a read; can one see a partial intermediate state?), lock-leak on crash (does a crashing stratumd release its allocator lock?), pattern-bypass (can a stratumd with `users/michael` access `users/michael/.../usersusan/...` via crafted dataset names?), audit-log integrity across writers.

---

## 5. A3 — corvus UNWRAP wire

### 5.1 Motivation

Per `CORVUS-DESIGN.md §6.4` (binary frame wire format) + §13.2: per-user stratumd needs to request DEK unwrap from corvus. The request flows from `stratumd-michael` to corvus over a Spoor; corvus verifies `session.user == owner_of(dataset)` (invariant **C-7**) and returns the DEK.

Stratum's existing janus integration (in `stratum/v2/src/janus/`) speaks janus's binary format. Corvus speaks a **different** wire — Thylacine-native binary frames with state-file magic `CRVS` (distinct from janus's `JPAS`). Stratum needs a "key agent client" library that can speak corvus's wire when stratumd runs under Thylacine.

The wire is fully specified in `CORVUS-DESIGN.md §6.4`. This section restates the parts Stratum implements.

### 5.2 Wire frames Stratum sends

**UNWRAP** (verb_id = 4):

```
[0]       verb_id            u8  = 4
[1..3)    payload_len        u16 LE
[3..36)   token              33 bytes ("s" + 32-char hex; 128 bits CSPRNG)
[36]      dataset_len        u8
[37..)    dataset            dataset_len bytes (utf-8; e.g., "users/michael")
[37+dl..) key_id             u64 LE
[..]      wrapped_len        u16 LE
[..]      wrapped            wrapped_len bytes (the AEAD-wrapped DEK blob; opaque to corvus)
```

Total frame size: 3 + 33 + 1 + dataset_len + 8 + 2 + wrapped_len bytes. Max ~256 bytes for typical sizes.

**Response**:

```
[0]       status             u8  (0=OK, 1=BadAuth, 2=PermissionDenied, 3=NotFound, 4=RateLimited, 5=BadFormat, 6=InternalError)
[1..3)    payload_len        u16 LE
[3..)     payload            on status=0: 32 bytes = unwrapped DEK
                             on status≠0: 0 bytes
```

### 5.3 Where Stratum needs to send UNWRAP

When `stratumd-michael` is asked to mount `users/michael`:
1. stratumd reads the dataset metadata; sees it's encrypted; finds the wrapped_dek + key_id.
2. stratumd reads its session_token from a process-local file (Thylacine installs it; see §10).
3. stratumd sends UNWRAP `{ token, dataset="users/michael", key_id, wrapped }` to corvus.
4. corvus responds with `{ status=0, dek=<32 bytes> }`.
5. stratumd caches the DEK in mlock'd RAM; mounts the dataset.

The "where to send" is `/srv/corvus/ops/unwrap` — a Spoor that stratumd opens before mount. The Spoor is established via the 9P attach flow (stratumd's Proc opens `/srv/corvus/` from its kernel namespace; this is automatic post-pivot if `/srv/corvus/` is in the territory).

Wire transport: Spoor read/write (9P over the corvus Spoor). The frame is the payload of a single Twrite + the response is the payload of a Tread reply. From stratumd's perspective, this is a synchronous request/response over a duplex Spoor.

### 5.4 Where Thylacine installs the session token

When `joey-or-login` rforks `stratumd-michael`, it makes the session token available to the child:
- v1.0: pre-create a file in the child's namespace at `/var/run/stratumd/session-token` containing the 33-byte token. stratumd reads it once at startup and `explicit_bzero`s the file.
- Alternative: pass via env var (`THYLA_CORVUS_SESSION_TOKEN`). Simpler; less robust against fork-and-leak hazards. Recommendation: file with mode 0400 owned by the stratumd user.

Stratum's stratumd needs to know where to look. Suggested: a CLI arg `--corvus-session-token-file <path>` so Thylacine can control the location.

### 5.5 Error handling

| corvus status | Stratum action |
|---|---|
| 0 (OK) | cache DEK; mount dataset |
| 1 (BadAuth) | session token invalid / expired; treat as fatal; exit |
| 2 (PermissionDenied) | session doesn't own this dataset (configuration bug or attacker); treat as fatal; exit |
| 3 (NotFound) | corvus has no record of this dataset; treat as fatal; exit |
| 4 (RateLimited) | corvus is throttling; retry with backoff (this shouldn't happen for legitimate UNWRAP — RateLimited is for AUTH; if it does, fail closed) |
| 5 (BadFormat) | wire format violation; treat as Stratum bug; exit |
| 6 (InternalError) | corvus internal failure; retry once with backoff; if persistent, exit |

### 5.6 Lifecycle

The UNWRAP request is sent **once per dataset mount**. The DEK is cached in stratumd's RAM for the dataset's lifetime. On unmount (or stratumd shutdown), the DEK is `explicit_bzero`d from RAM. If corvus dies + restarts, stratumd's cached DEK is still valid for already-mounted datasets; new datasets require a re-UNWRAP after the user re-authenticates.

### 5.7 Test matrix

| Test | Setup | Expected |
|---|---|---|
| Happy path | Mount michael's encrypted dataset; valid session | DEK returned; mount succeeds |
| Wrong-user UNWRAP | stratumd-michael tries to UNWRAP users/susan | corvus returns PermissionDenied; stratumd refuses to mount |
| Bad session token | stratumd's token is corrupted | corvus returns BadAuth; stratumd exits |
| corvus offline | corvus crashes between mount + UNWRAP | UNWRAP times out (Spoor I/O); stratumd retries N times then exits |
| corvus restart mid-mount | corvus restarts during DEK cache lifetime | Cached DEK still valid for mounted dataset; no impact |
| Wire-format edge | corvus rejects malformed frame | BadFormat; stratumd exits with diagnostic |
| Large wrapped blob | wrapped_len near u16 max | Handled correctly (or rejected with clear error) |

### 5.8 Open questions

- **Q8**: Should the session token be opaque-to-Stratum (Stratum stores + replays without parsing) or partially-structured (e.g., Stratum knows the user name encoded in it)? Recommendation: opaque. corvus is the only authority; Stratum's job is to relay the token unchanged.
- **Q9**: What's Stratum's per-mount retry policy if corvus is briefly unavailable (e.g., during a restart)? Suggested: 3 retries with 100ms / 500ms / 2s backoff, then exit.
- **Q10**: Does Stratum need a corvus-side health check before sending UNWRAP? Or is the request itself the check? Recommendation: request is the check; no separate ping.
- **Q11**: Wire protocol versioning — should the UNWRAP frame carry a version byte for future evolution? Recommendation: yes. Add `protocol_version u8 = 1` after `verb_id`. corvus refuses unknown versions with BadFormat.

### 5.9 Audit posture

Stratum-side: a new audit-trigger surface around the corvus key-agent client:
- Wire format encode + decode (frame bound checks, length validation, integer overflow).
- Session token handling (don't leak in logs; explicit_bzero on shutdown).
- DEK caching discipline (mlock; don't write to swap; don't log).

Adversarial categories: wire-format injection (malformed frame from a hostile corvus impersonator), session token leak (logs, core dumps, swap), DEK lifetime (cached after user logout if eviction notify doesn't arrive — see A4).

---

## 6. A4 — Session-close → DEK eviction notification

### 6.1 Motivation

Per `CORVUS-DESIGN.md §13.3`: when a user logs out, corvus emits a notification to the affected stratumd(s). Each stratumd `explicit_bzero`s its DEK cache for the affected session's user and unmounts that user's datasets. Without this notification, killing corvus doesn't propagate to stratumd's RAM — DEKs linger and the user's data is still accessible to the running stratumd process even after logout.

This closes a real audit-bearing gap: the user expects "I logged out → my data is sealed." Multi-stratumd helps (structural — kill stratumd-michael → DEK gone) but corvus + stratumd both need to participate in the protocol.

### 6.2 Notify mechanism

corvus serves a `/srv/corvus/notify` Spoor. stratumds subscribe by opening it for reading. corvus emits one notification frame per session-close event:

**Frame format** (also binary, consistent with corvus's wire style):

```
[0]       notify_kind        u8  = 1 (SESSION_CLOSED)
[1..3)    payload_len        u16 LE
[3..36)   token              33 bytes (the closed session's token)
[36]      user_len           u8
[37..)    user               user_len bytes (utf-8; e.g., "michael")
```

Future notify_kind values:
- `2` = USER_KEY_ROTATED (v1.x; per-dataset rekeying)
- `3` = ADMIN_FORCE_EVICT (v1.x; hostowner-driven eviction)

Stratumd receives the frame, identifies whether it serves any datasets owned by `user`, and:
1. `explicit_bzero` the DEK cache entry for each affected dataset.
2. Unmount the dataset cleanly (flush in-flight writes; release Stratum-side locks).
3. If the stratumd serves ONLY datasets owned by the closed user (the typical Thylacine case), exit cleanly after eviction.

### 6.3 Subscription model

A stratumd that calls `stratumd --datasets-allowed users/michael ...` subscribes to corvus's notify Spoor at startup. If corvus is offline at startup, stratumd retries open with backoff (10 attempts; then exits).

If corvus crashes mid-session: the notify Spoor closes (read returns EOF or EPIPE). stratumd treats this as "corvus is down; I cannot receive eviction signals." Two options:
- **Strict mode**: stratumd immediately evicts all DEKs + unmounts + exits (fail-closed). Most secure; potentially disruptive (legitimate corvus restart causes all logged-in users to lose mounted data).
- **Tolerant mode**: stratumd holds DEKs but stops accepting NEW mounts; waits for corvus to come back. If a new corvus comes up within a timeout (e.g., 30 seconds), stratumd re-subscribes to notify and continues. If not, fall back to strict.

Recommendation: tolerant mode with a 30-second corvus-restart timeout. Configurable via `--corvus-notify-mode {strict,tolerant}` if Michal wants flexibility.

### 6.4 Lifecycle

```
                                                stratumd-michael
                                                ├── DEK cached for users/michael
                                                └── subscribes /srv/corvus/notify

user logs out
  ↓
login → corvus: SESSION_CLOSE { token }
  ↓
corvus:
  ├── wipe keypair + cached DEKs for session
  ├── emit notify frame { kind=SESSION_CLOSED, token, user="michael" }
  └── close session

stratumd-michael:
  ├── reads notify frame
  ├── explicit_bzero DEK cache for users/michael
  ├── unmount users/michael (Stratum-side: flush, release locks)
  └── exit cleanly

joey:
  └── reaps stratumd-michael
```

### 6.5 Test matrix

| Test | Setup | Expected |
|---|---|---|
| Happy logout | michael logged in with mounted dataset; logout | stratumd-michael unmounts + exits within <1s |
| Cross-user no-op | susan also logged in with separate stratumd; michael logs out | stratumd-susan unaffected |
| corvus restart mid-session | corvus crashes + restarts within 30s while michael is logged in | stratumd-michael resubscribes; eviction works on next logout |
| corvus down beyond timeout | corvus down for 60s | stratumd-michael evicts + unmounts + exits per strict/tolerant policy |
| Race: logout during mount | michael mounts dataset while logout is in flight | mount fails cleanly OR completes + immediately unmounts; no partial state |
| Multiple notifies | rapid logout/login cycle | stratumd processes notifies in order |

### 6.6 Open questions

- **Q12**: Strict vs tolerant default — which does Thylacine want? Recommendation: tolerant with 30s timeout (covers legitimate corvus restarts; still fails closed eventually).
- **Q13**: Should notify carry a sequence number for crash-recovery (detect missed notifications)? Probably overkill at v1.0; a missed notification is a corvus-restart event which strict/tolerant handles.
- **Q14**: What about pending writes during eviction? Stratum-side: how does unmount drain in-flight writes vs abort them? Recommendation: drain on user-initiated logout; abort on force-close (admin verb).

### 6.7 Audit posture

Stratum-side: small new surface — notify-Spoor consumer + eviction discipline. Audit categories: notify-frame parsing (malformed frame from a hostile corvus impersonator), eviction race (DEK accessed by an in-flight read while being wiped), unmount integrity (incomplete unmount leaves in-memory state).

---

## 7. A5 — Snapshot rollback compromise marking

### 7.1 Motivation

Per `CORVUS-DESIGN.md` invariant **C-13** + §13.4: when a user rotates their passphrase, corvus emits an admin verb to Stratum: "prior snapshots of `/var/lib/corvus/users/<user>/` contain a now-compromised wrap and should not be used as rollback targets."

The attack: hostowner with `stratum rollback` access can roll back `/var/lib/corvus/users/michael/` to a snapshot taken BEFORE michael's passphrase rotation. The reverted snapshot has the OLD wrap chain; the OLD passphrase (now known to an attacker) unlocks michael's data again. Forward secrecy is broken.

Defence: corvus marks the relevant snapshots as compromised; Stratum's `stratum rollback` consults the marker and either refuses the rollback or prompts the operator with a warning + explicit override.

### 7.2 Admin verb shape

```
stratum-admin dataset mark-rollback-compromised \
    --dataset <dataset> \
    --snapshot <snapshot-name> [--snapshot <snapshot-name> ...] \
    --reason "<one-line text>"
```

Marks listed snapshots as rollback-compromised. The marker is persistent in the dataset's metadata (survives reboot, pool-export/import, etc.).

corvus invokes this internally when:
- A user's passphrase changes (mark all snapshots of `/var/lib/corvus/users/<user>/` taken since the last passphrase change).
- A user is deleted (mark all snapshots involving the user; the user's keypair is gone, so the wrap is dead anyway, but the marker is good hygiene).

### 7.3 Rollback behaviour

When `stratum rollback <snapshot>` is invoked on a snapshot marked compromised:

```
stratum: snapshot <snapshot-name> is marked rollback-compromised
         reason: <text>
         marked at: <timestamp>
         confirm with --force-rollback to proceed (corvus may refuse to re-attach)
```

If `--force-rollback` is provided: proceed but log a WARN+ audit event. corvus's own discipline (independent of Stratum) is to refuse to re-attach to a wrap chain known to be compromised; that's enforced corvus-side regardless of Stratum's behaviour.

### 7.4 Listing markers

A new admin verb:

```
stratum-admin dataset list-rollback-compromised --dataset <dataset>
```

Lists all marked snapshots for a dataset. Output format: tab-separated `<snapshot-name>\t<timestamp>\t<reason>`.

### 7.5 Programmatic access

corvus needs to invoke `mark-rollback-compromised` from its own process. Stratum should expose an admin verb endpoint on `/srv/stratum-ctl/admin` (the existing admin Spoor) that corvus can write to. Wire format: TBD by Stratum, but a JSON-shaped frame is fine (this is admin path, not user-facing performance-critical).

### 7.6 Test matrix

| Test | Setup | Expected |
|---|---|---|
| Mark + rollback | Mark snapshot S; `stratum rollback S` | Refused with warning |
| Force rollback | Mark S; `stratum rollback S --force-rollback` | Proceeds with audit log entry |
| List markers | Mark 3 snapshots; list | All 3 returned with reason + timestamp |
| Survival | Mark; export/import pool | Marker persists |
| corvus integration | Rotate passphrase; check Stratum marker list | Pre-rotation snapshots marked |

### 7.7 Open questions

- **Q15**: Is `mark-rollback-compromised` reversible (an unmark verb)? Recommendation: yes, for false positives, but require `--force-unmark` and audit-log the event.
- **Q16**: What's the privilege model for the corvus → Stratum admin verb? corvus runs as a system user with limited caps; Stratum's `/srv/stratum-ctl/` is typically hostowner-only. Need a corvus-specific principal that's narrower than full hostowner but broad enough to mark snapshots. Recommendation: a corvus-specific capability that's gated to the mark + unmark verbs only.

### 7.8 Audit posture

Stratum-side: marker persistence, rollback-path consultation, principal authorization for the corvus-driven invocation. Adversarial categories: marker-bypass (rollback path doesn't consult marker; or marker storage is unauthenticated), unauthorised mark (an attacker with write access marks legitimate snapshots to deny rollback).

---

## 8. A6 — Per-dataset key rotation (v1.x)

### 8.1 Motivation

Per `CORVUS-DESIGN.md §11` + audit finding F14 resolution: real cryptographic forward secrecy at the dataset level requires rekeying — Stratum reads all dataset content under the old DEK, decrypts, re-encrypts under a new DEK, writes back. Stratum's `Treflink` + the planned rotate API are the building blocks. corvus's ROTATE_KEY verb (defined in `CORVUS-DESIGN.md §6.4`) calls into Stratum.

At v1.0 we explicitly **do not** offer cryptographic forward secrecy — `SESSION_CLOSE` is a RAM-wipe (invariant C-5), not a key rotation. v1.x lands this.

### 8.2 Scope

This is a substantial Stratum lift (cryptographic content rewrite + atomic transition + offline data handling). Out of v1.0 scope on both sides. Thylacine commits to:
- Define `corvus ROTATE_KEY` verb (already done in §6.4 of CORVUS-DESIGN).
- Coordinate with Stratum on the rekey API contract when it lands upstream.

This section is a placeholder so the ask is enumerated. No v1.0 deliverable.

### 8.3 Open questions

- **Q17**: Stratum-side rekey API shape — admin verb? in-kernel-9P op? Define when v1.x rekey lands.
- **Q18**: Performance — for very large datasets, in-place rekey may take hours. Online vs offline semantics? Stratum design decision.

---

## 9. Cross-cutting concerns

### 9.1 Format-version handling

Both `pool_serial` (A1) and snapshot markers (A5) add to the pool's on-disk format. Per Stratum's existing format-version discipline:

- **A1 — `pool_serial` field**: 16 bytes; preferably in unused space in the existing superblock. If superblock layout is full, this is a v2.x format change with a feature flag (`feat_pool_serial`). v1.x pools without the flag treat all reads as unbound. Thylacine deployments require `feat_pool_serial`; the installer creates pools with the flag set.
- **A5 — marker storage**: dataset-metadata extension. Similar feature-flag approach if metadata layout is full.

Neither requires breaking changes if implemented with feature flags + zero-default semantics.

### 9.2 Audit posture (Stratum-side new surfaces)

Each ask becomes a new audit-trigger surface on Stratum side (per Stratum's own audit policy). Suggested adversarial categories per item are in each section's "Audit posture" subsection.

Cross-cutting:
- Wire-format frames (A3, A4, A5 corvus → Stratum admin verb): frame bound checks, integer overflow, length validation, principal authentication on admin verbs.
- Pool format additions (A1, A5): partial-write hazard, fsync ordering, feature-flag handling on import.
- Multi-process coordination (A2, A4): lock leaks, race windows, crash recovery across processes.

### 9.3 Test matrix coverage

Per ask, the test matrices are spelled out. Cross-cutting integration tests:

- **Boot integration**: pool with `pool_serial = X`; `stratumd-system --bind-pool-serial X --datasets-allowed system --datasets-allowed system/**`; Thylacine joey forks stratumd-system, kernel mounts /sysroot, pivot succeeds. (A1 + A2 cross.)
- **Login flow**: corvus + stratumd-michael + per-user UNWRAP; cold-boot from no-state to user-shell at `$HOME = /home/michael`. (A2 + A3 cross.)
- **Logout flow**: corvus emits SESSION_CLOSED; stratumd-michael unmounts cleanly; pool re-mountable on next login. (A2 + A4 cross.)
- **Rollback defence**: passphrase change → snapshot marked → rollback refused. (A5; cross with corvus.)

### 9.4 Documentation discipline

Stratum-side documentation each ask warrants:
- `OS-INTEGRATION.md` updates for v1.0 multi-stratumd + bind-pool-serial.
- A new `docs/reference/` entry per significant ask.
- Updates to `stratum/v2/docs/REFERENCE.md` Tip line per chunk.
- (Optional) A `STRATUM-API-V1.md` mirror in Stratum's tree referencing this doc.

---

## 10. What Thylacine commits to (the bilateral contract)

The asks above are what Stratum provides; the following is what Thylacine guarantees in return.

### 10.1 Pool serial discipline

- The installer generates `pool_serial` via Thylacine's CSPRNG and stores it at install time.
- `stratumd-system` is always invoked with `--bind-pool-serial X` matching the install-time value.
- If the installer's CSPRNG is reseeded between install and rekey (v1.x), the install-time `pool_serial` is preserved (it's the binding anchor; CSPRNG state is not).
- Thylacine never modifies `/boot/system.key.salt` after install except via the documented kernel-update + rekey paths.

### 10.2 Multi-stratumd discipline

- Each per-user stratumd is invoked with `--datasets-allowed users/<user>` and `--datasets-allowed users/<user>/**` (covers nested datasets when v1.x adds them).
- `stratumd-system` is invoked with `--datasets-allowed system` + `system/**` (no user datasets in system-pool's allow list).
- Thylacine never tries to mount a dataset outside its stratumd's allowed list; if a user accidentally tries (e.g., `mount users/susan` from michael's shell), the error is handled OS-side, not by relying on Stratum's refusal.

### 10.3 corvus wire discipline

- Thylacine generates session tokens via the kernel CSPRNG (`SYS_GETRANDOM`); tokens are 128 bits.
- Tokens are stored only in mlock'd RAM (corvus) and a kernel-protected token file (`/var/run/stratumd/session-token`).
- Stratumd is supplied the token file path via `--corvus-session-token-file`.
- The token file is mode 0400 owned by the stratumd's user.
- corvus's wire is **the** wire — Thylacine doesn't expect Stratum to speak janus's wire when running under Thylacine.

### 10.4 Eviction discipline

- joey + login coordinate the SESSION_CLOSE flow.
- corvus emits the SESSION_CLOSED notification before login returns control to its caller.
- Thylacine's stratumd consumer (the kernel 9P client) handles the unmount cleanly; in-flight syscalls on the user's territory are drained or aborted.

### 10.5 Rollback marker discipline

- corvus invokes `mark-rollback-compromised` synchronously with the passphrase rotation.
- The rotation is not considered complete until the marker call returns success.
- If the marker call fails, the passphrase rotation is also failed (atomic; user is told to retry).

### 10.6 v1.x rekey discipline

- Thylacine will not rely on cryptographic forward secrecy at v1.0.
- When v1.x rekey lands, corvus's ROTATE_KEY verb invokes Stratum's API per a coordinated contract.

### 10.7 Audit cooperation

- Thylacine's audit-trigger surface (`ARCHITECTURE.md §25.4`) names Stratum-touching surfaces (the kernel 9P client, `/srv/corvus/`, `/srv/stratum-ctl/` consumption).
- For cross-cutting integration audits (boot path, login flow, logout flow), Thylacine + Stratum coordinate audit rounds — single-prosecutor spans both surfaces.

---

## 11. Coordination protocol

This doc is the Thylacine-side spec. Stratum is the source of truth on Stratum-side implementation. Workflow:

1. **Michal reads this doc** → identifies items already partly in Stratum (e.g., maybe a `pool_serial`-like field already exists under another name), open questions to resolve, scope concerns.
2. **Michal pushes back** on items Stratum can't do as specified, OR adds items Stratum needs Thylacine to do in return.
3. **Update this doc** with negotiated shape (Thylacine-side commit; user signoff).
4. **Stratum chunks the work** per Stratum's normal process; Thylacine side waits at the dependency boundary.
5. **Integration**: when Stratum lands an ask, Thylacine consumes it in the corresponding chunk (A1 → P5-stratumd-bringup-real; A2 → P5-stratumd-multi-consumer; etc.).

For substantive disagreement (e.g., Stratum proposes a different wire shape than corvus's `CRVS`-magic binary frames): negotiate via design-doc PR (Thylacine-side updates to `CORVUS-DESIGN.md` + this doc; Stratum-side updates to its OS-INTEGRATION.md). User signoff binds both sides.

---

## 12. Cross-references

Thylacine:
- `CORVUS-DESIGN.md §3 D2` — boot-key device binding rationale.
- `CORVUS-DESIGN.md §3 D4` — Order C boot + per-user stratumd model.
- `CORVUS-DESIGN.md §6.4` — corvus wire frame format (the binary that this doc asks Stratum to consume).
- `CORVUS-DESIGN.md §9` — C-1..C-20 invariants; C-7, C-13, C-14, C-18 directly affected by this doc.
- `CORVUS-DESIGN.md §11` — v1.x deferrals; A6 here is the cryptographic forward secrecy item.
- `CORVUS-DESIGN.md §13` — high-level Stratum API additions list (this doc is the detailed version).
- `ARCHITECTURE.md §5.1` — boot chain.
- `ARCHITECTURE.md §14.3a` — Stratum mount lifecycle.
- `ARCHITECTURE.md §15` — capabilities (CAP_HOSTOWNER + console-attachment).

Stratum:
- `stratum/v2/docs/OS-INTEGRATION.md` — Stratum's existing OS integration manual. This doc adds the Thylacine-specific items.
- `stratum/v2/docs/REFERENCE.md` — Stratum's as-built reference.
- `stratum/v2/docs/reference/20-9p.md` — 9P wire semantics.
- `stratum/v2/docs/reference/22-ctl.md` — `/ctl/` admin surface trust boundary.
- `stratum/v2/src/janus/backend_passphrase.c` — design influence (not consumed by corvus).

External:
- Plan 9 `factotum(4)` — historical reference for the key-agent shape.
- Linux fscrypt — per-directory keys reference.
- ZFS native encryption — per-dataset DEKs, KEK wrapping.

---

## 13. Implementation order recap

| # | Stratum chunk | Thylacine chunk it unblocks | Dep |
|---|---|---|---|
| 1 | A1: `--bind-pool-serial` + `pool_serial` superblock field + `STM_ESERIAL` | P5-stratumd-bringup (real, not stub) | — |
| 2 | A4: corvus notify Spoor consumer + eviction discipline | P5-login (logout flow) | A1 (optional ordering) |
| 3 | A2: multi-stratumd-per-pool + `--datasets-allowed` | P5-login (per-user stratumd) | A1 (real bringup first) |
| 4 | A3: corvus UNWRAP wire (Stratum-side) | P5-corvus-bringup | A2 (per-user stratumd context) |
| 5 | A5: snapshot rollback compromise marking | P5-corvus-bringup C-13 closure | A3 (corvus must exist) |
| 6 | A6: per-dataset key rotation hooks | v1.x corvus ROTATE_KEY | A3 |

Minimum-viable-path: ship A1 alone and Thylacine unblocks the boot-into-Stratum-root milestone. Everything else is the post-pivot stack.

---

The thylacine runs again.
