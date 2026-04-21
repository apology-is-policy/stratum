# P4-4b priming — janus daemon

**For the next Claude instance after compaction.** Working playbook
for landing Phase 4 chunk P4-4b (the `janus` key-agent daemon).
Delete this doc once P4-4b + its R11 audit close.

## Start here (first 5 minutes)

1. Verify tip + working tree clean:
   ```bash
   cd /Users/northkillpd/projects/stratum && git log --oneline -8 && git status
   ```
   Expected tip: at least `bed67c8` (P4-4a) plus whatever R10 fixes
   landed. Any uncommitted changes → investigate before proceeding.

2. Verify green on default:
   ```bash
   cd v2 && ctest --test-dir build --output-on-failure 2>&1 | tail -5
   ```
   Should be 21/21 suites (or 22/22 if R10 added a regression test).

3. Read, in this order:
   - `v2/docs/phase4-status.md` §P4-4a (landed), §P4-4 (implementation plan).
   - `docs/ARCHITECTURE.md §7.9` (janus protocol — the source of truth).
   - `docs/NOVEL.md §3.10` (janus as factotum-style agent — NOVEL #10).
   - `memory/audit_v2_r0_closed_list.md` through R10 (do-not-report).

4. **Confirm autonomy.** User authorized autonomous operation on
   2026-04-21: "proceed autonomously until there is a decision point
   that the architecture or roadmap documents don't resolve or
   whether there's something unclear." That directive covers the
   entire P4-4b chunk; surface only genuine architectural ambiguities.

## Context snapshot (what's already landed)

Phase 4 so far, in order:
- `54b3c8b`–`ee3600c` P4-1 Merkle scaffold + R8 fixes.
- `65c4c76`        P4-6 `merkle.tla`.
- `cb9671f`        P4-3a metadata-key lifecycle (plaintext).
- `fc52dbe`        P4-3b AEAD on metadata nodes.
- `ca8d47b`        R9 audit fixes (mount-claim UB, nonce-reuse-under-crash closed).
- `dc357ad`        P4-2 scrubber (stm_fs_verify).
- `eeea92d`        P4-5 stub (data-extent AEAD round-trip).
- `d37b374`        ARCH + ROADMAP design commits for P4-4 (janus + sub-tree).
- `bed67c8`        **P4-4a** — key-schema sub-tree + in-process unwrap.
- `<R10 fixes>`    R10 findings closed (check closed-list for the commit hash).

Tip as of writing: `<R10 fix commit>` (above `bed67c8`); check
`git log --oneline -5` for the current tip. R10 closed with 1 P1 +
4 P2 + 2 P3 fixed — notable: `stm_hybrid_wrap` / `_unwrap` now
take an AD parameter (R10 P2-2), and sync.c binds `pool_uuid ‖
dataset_id ‖ key_id` into it. Any new caller of `stm_hybrid_*`
MUST pass a matching wrap-AD / unwrap-AD pair.

STM_UB_VERSION is **4**. STM_BPTR_KIND_KEYSCHEMA = 7. Metadata key
stored PQ-hybrid-wrapped inside a Merkle-chained sub-tree rooted from
`ub_key_schema`. Fifth Merkle root input live.

Keyfile backend (ARCH §7.9.3 "file") is the current wrap-key source.
`stm_keyfile_generate` / `_load`, file format = magic 'KFIL' +
version + hybrid_pk + hybrid_sk. **P4-4b replaces this backend with
passphrase (Argon2id) via janus; the keyfile stays as a fallback
for automation.**

## P4-4b design recap (ARCH §7.9 + NOVEL §3.10)

Single binary named `janus`. No `stratum-` prefix (ARCH §7.9).

**Architecture**:
- Separate process from the filesystem.
- 9P synthetic filesystem exposed over a Unix socket.
- Default socket path: `/var/run/janus.sock` (configurable).
- `SO_PEERCRED` auth on Linux; capability token optional.
- Pluggable backends (ARCH §7.9.3): passphrase (MVP), TPM, PKCS#11,
  YubiKey, file. P4-4b targets passphrase + file; the other three
  are Phase-4-exit follow-ups or later.

**9P synthetic FS layout** (ARCH §7.9.1):
```
/janus/
├── pools/<pool_uuid>/
│   ├── wrap-key-info
│   ├── datasets/<dataset_id>/
│   │   ├── wrapped-key
│   │   └── unwrap
│   └── rotate-wrap
├── backends/
│   ├── passphrase/
│   ├── tpm/ ...
└── audit-log
```

**Key insight:** the FS doesn't send DEKs to janus. It sends a
*wrapped* DEK + request-to-unwrap, and janus uses the wrap-key
material it holds to do the unwrap. janus returns the raw DEK.
Wrap keys never leave janus.

**Security boundary:** the janus process is the blast radius for
key material. A compromised FS process can only request unwraps
(and hold DEKs in its own address space); it can't exfiltrate the
wrap key. This justifies the process-split: the whole point of
"factotum-style" is that key-wielding code runs in a narrower TCB
than key-using code.

## Implementation plan (step-by-step)

### 1. 9P server primitives

Check if `v1`'s 9P machinery is reusable here:
```bash
ls /Users/northkillpd/projects/stratum/src/p9/ 2>/dev/null
```
If so, port the wire codec + server loop. Otherwise, a minimal 9P
server is ~500 LOC. Either way, goal: a functional 9P server that
accepts Tversion / Tauth / Tattach / Twalk / Topen / Tread / Twrite /
Tclunk / Tstat / Tremove. Don't implement features we don't need.

Libraries: consider `libixp` or `lib9p` if we want to avoid
reinventing. Historical preference is hand-rolled for control; check
`docs/NOVEL.md` for project posture.

### 2. Synthetic FS layer

Above the 9P server, a synthetic-FS abstraction: each file is a
function-pointer pair `{read, write}`. Fits the
`/janus/pools/<uuid>/datasets/<id>/unwrap` tree.

Key files:
- `wrap-key-info` — read-only, returns backend name + parameters.
- `wrapped-key` — read returns the wrapped bytes currently on disk;
  write accepts a new wrapped blob (for rotation, P4-4c).
- `unwrap` — write-then-read pattern. Client writes request context
  (pool_uuid, dataset_id, wrapped blob). Reads the result.
- `rotate-wrap` — client writes a command (generate / reset) and
  reads the result.
- `audit-log` — append-only; reads return the log.

### 3. Backends

**passphrase** (MVP, ARCH §7.9.3):
- Interactive prompt at backend-init time (systemd-style ask-password
  socket, or stdin if launched by hand).
- Argon2id KDF: salt stored in janus's state dir; parameters from
  `stm_argon2id_params_interactive` (Phase 1 primitive).
- Derives the hybrid SK.

**file** (fallback, already exists):
- Load hybrid keys from a keyfile per `stm_keyfile_load`.
- Used for automation / container contexts.

The backend is chosen at janus startup via config or CLI flag.

### 4. FS-side client library

Replace the in-process `stm_hybrid_unwrap` call in `stm_sync_open`
with an RPC to janus. The FS-side API (`stm_janus_client`?):
- `stm_janus_connect(socket_path)` → opaque handle.
- `stm_janus_unwrap(handle, pool_uuid, dataset_id, wrapped, wrapped_len, out_dek, out_dek_len)`.
- `stm_janus_disconnect(handle)`.

Keep the `stm_hybrid_keys` / keyfile path as a fallback; select at
`stm_fs_mount` via a new opt. Documented semantics:

- **janus socket provided**: use janus (preferred).
- **keyfile path provided**: use in-process unwrap (existing path).
- **both provided**: fail — ambiguous.
- **neither**: fail — unencrypted pools don't exist.

### 5. Lifecycle

- `stm_fs_format` with janus: FS generates the hybrid keypair, sends
  the public key to janus via `rotate-wrap`, and gets an opaque
  "wrap key id" back. Public key also retained locally for the
  initial wrap. Private key stays in janus.
- `stm_fs_mount` with janus: FS reads the wrapped DEK from its own
  pool's key-schema, sends it to janus's `unwrap` file with context,
  receives the raw DEK.
- Crash semantics: janus dying mid-mount should cause the mount to
  fail cleanly (STM_EBACKEND or similar).

### 6. Tests

- **Integration**: spawn janus as a child process, point the FS at
  its socket, run format + mount + commit.
- **Backend round-trips**: passphrase backend (use a known
  passphrase), file backend (use the keyfile).
- **Failure modes**: janus crashed; wrong backend config; socket
  permission denied.
- **Audit log**: verify every unwrap is logged.

### 7. TLA+ (if warranted)

Do we need `janus_protocol.tla`? Consider:
- Protocol state machine: connect → auth → unwrap → disconnect. Is
  there subtle concurrency to formalize?
- Probably yes for multi-client case (multiple FS processes talking
  to janus concurrently).

Small scope — ~100 lines.

### 8. R11 audit

Spawn an R11 audit post-P4-4b. Focus:
- Process-boundary enforcement.
- Socket auth.
- Timing side channels in backend code.
- Race conditions between concurrent 9P clients.
- Audit-log integrity.
- Passphrase entry / KDF soundness.

### 9. ARCH / ROADMAP updates

- `docs/ROADMAP-V2.md §7.2`: tick off "Janus + daemon integrated;
  passphrase backend works."
- `docs/phase4-status.md`: P4-4b landing row.

### 10. Delete this priming doc after P4-4b lands.

## Verification commands

```bash
cd /Users/northkillpd/projects/stratum/v2

# Default
cmake --build build -j && ctest --test-dir build --output-on-failure

# ASan
cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure

# TSan
cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure --timeout 180

# All TLA+ specs
export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
cd specs
for s in sync concurrency structural balanced merge allocator merkle key_schema; do
    echo "== $s =="
    java -cp /tmp/tla2tools.jar tlc2.TLC -workers auto -deadlock \
        -config $s.cfg $s.tla 2>&1 | tail -3
done
```

## Trip hazards + load-bearing invariants

1. **No plaintext pool key on disk** (P4-4a property). Janus must not
   cause a regression: the FS-side client sends a wrapped DEK to
   janus and gets a raw DEK back over the 9P socket — the raw DEK
   exists in FS RAM briefly to `stm_alloc_set_crypt_ctx`, then stays
   there for the pool's mounted lifetime. Never persists. `stm_hybrid_keys_wipe`
   still runs on the stack-local fallback path.

2. **`SO_PEERCRED` is Linux-only.** macOS uses `LOCAL_PEERCRED` /
   `LOCAL_PEEREPID` — different API. For the MVP, either:
   (a) Guard SO_PEERCRED behind `#ifdef __linux__` and skip auth
       on macOS (acceptable for dev; document).
   (b) Implement both.
   ARCH §7.9.2 leaves flexibility here.

3. **9P wire handling must be bounds-checked.** v1's R14+ audits
   found multiple 9P wire-parsing bugs (missing bounds checks on
   `body` pointers). Carry those lessons forward. See
   `memory/audit_r15_closed_list.md` for the v1 preamble.

4. **Socket lifecycle + crash behavior.** If janus exits between
   mount and the next unwrap (extents-reading, if it happens
   per-request), the FS must not wedge. Design for reconnect or
   fail loudly.

5. **Passphrase entry.** systemd's `ask-password` socket is the
   idiomatic Linux path; on macOS `security`(1). For MVP, read
   passphrase from stdin if no ask-password is available.

6. **Argon2id parameters.** Use `stm_argon2id_params_interactive`
   (~100ms on laptop per Phase 1). The janus daemon parameters are
   persisted to a config file; rotating them is a wrap-key rotation
   in disguise.

7. **janus state directory.** Needs to survive reboot. Default
   `/var/lib/janus/` with mode 0700. Contains:
   - per-pool backend config (backend name, parameters).
   - Argon2id salt (per pool).
   - audit log.
   - NOT the wrap key (that's derived from the passphrase per mount).

8. **Cross-pool isolation.** Janus handles multiple pools
   simultaneously. Each pool's state is separate; wrap keys never
   cross pools.

## Decision points (escalate if hit)

- Should janus run as root or as a dedicated user? ARCH doesn't say.
  Opinion: dedicated user (`janus`), with the FS running as any user
  permitted in the config. Escalate for confirmation if needed.

- What wire format for the unwrap RPC specifically? ARCH §7.9.1
  sketches the file tree but not the byte-level protocol. Natural
  option: a small binary request/response struct serialized into the
  9P Twrite / Tread message body.

- Should we implement TPM / PKCS#11 / YubiKey backends in P4-4b, or
  only passphrase + file? ROADMAP §7.2 demands "passphrase backend
  works" — that's the minimum. Defer the others to a follow-up
  chunk unless the user directs otherwise.

## Closing checklist

- [ ] Implement 9P server + synthetic FS.
- [ ] Passphrase backend (Argon2id).
- [ ] FS-side client library.
- [ ] Integration tests.
- [ ] (Optional) `janus_protocol.tla`.
- [ ] Commit + push.
- [ ] Spawn R11.
- [ ] R11 findings → fix, commit, update closed-list.
- [ ] ARCH / ROADMAP doc updates.
- [ ] Delete this priming doc.
