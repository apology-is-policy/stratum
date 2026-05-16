# TLY-A3-keyslot-wrap — corvus WRAP (provisioning-time DEK sealing)

**Status**: design-first. Spec-first applies — this touches crypto key
sealing; `key_schema.tla` gets a small extension BEFORE impl.
**Predecessor**: TLY-A3-keyslot-impl-3b (`2ff2f09`) — mount-time UNWRAP
wiring. This chunk series closes that doc's §10 open question.
**Bilateral**: depends on `STRATUM-API-V1.md` §5.2 (WRAP frame) + §5.10
(WRAP semantics). Resolved with Thylacine 2026-05-16.
**Scope**: **Stratum side only.** The corvus parser change and the
thylacine-doc edits below are handled by a separate Thylacine-side
agent — they are listed here as the cross-repo dependency, not as
Stratum work.

## 1. The gap this closes

`thylacine-keyslot-design.md §10` left the WRAP path as an open
bilateral question: `STRATUM-API-V1.md` specced only UNWRAP, so nothing
could *produce* a corvus-sealed DEK envelope. impl-3b shipped only the
mount-time UNWRAP routing; CORVUS keyslots could be *consumed* but only
*created* via the test-only `stm_sync_keyschema_insert_for_test` seam
against a fake corvus. STRATUM-API-V1.md now specs WRAP. This series
builds the production WRAP path.

## 2. Verified ground truth (the wire)

corvus's shipped request decoder (`~/projects/thylacine/usr/corvus/
src/main.rs:1417`) reads a **3-byte** frame header today
(`verb_id + payload_len`). Per the 2026-05-16 reconciliation, the
corvus wire is moving to a **4-byte versioned request header**
(`verb_id + protocol_version + payload_len`) — `§5.8 Q11` promoted to
normative. **The corvus parser change + §5.2/§5.10/§6.2 doc edits are
Thylacine-side work, in progress by another agent.**

Stratum's existing UNWRAP codec is **already 4-byte** (`corvus_client.h`
line 32: "after Q11 protocol_version byte added"; `STM_CORVUS_REQUEST_MAX
= 4u + ...`). So Stratum's UNWRAP needs **no functional change** — it is
already built to the post-Q11 target. WRAP is built to the same 4-byte
header.

**Cross-repo gating**: until corvus lands its 4-byte decoder, Stratum's
4-byte UNWRAP/WRAP are incompatible with *shipped* corvus. Stratum's
fake-corvus test harness is 4-byte (matches Stratum), so every Stratum
chunk below is independently buildable + testable. Real-corvus
integration testing is gated on corvus's 4-byte landing — forward-noted,
not a blocker for this series.

## 3. The WRAP wire (Stratum's view)

**Request** Stratum sends (verb_id = 10, 4-byte header):

```
[0]            verb_id           u8 = 10
[1]            protocol_version  u8 = 1
[2..4)         payload_len       u16 LE  (count of bytes [4..end))
[4..37)        token             33 bytes (session token, relayed verbatim)
[37]           dataset_len       u8  (1..255)
[38..38+dl)    dataset           dl bytes (utf-8 corvus dataset path)
[38+dl..46+dl) key_id            u64 LE
[46+dl..48+dl) dek_len           u16 LE  (must == 32)
[48+dl..)      dek               32 bytes (PLAINTEXT DEK to seal)
```

**Response** (3-byte header — responses are unversioned, corvus→client):

```
[0]      status        u8  (0=OK ... 6=InternalError — same enum as UNWRAP)
[1..3)   payload_len   u16 LE
[3..)    payload       on status=0: the DEK envelope (~1217 bytes,
                        opaque to Stratum); on status≠0: 0 bytes
```

## 4. Auth — nothing Stratum-side

`§5.10`: WRAP needs a stronger credential than UNWRAP (C-7 normal path,
or `CAP_HOSTOWNER` admin path for provisioning a not-yet-logged-in
user). **"From Stratum's side this changes nothing on the wire"** —
Stratum relays whatever session token the provisioning flow supplies;
corvus evaluates the credential. Stratum implements zero credential
logic — same posture as UNWRAP.

## 5. The dataset-path binding (the on-disk change)

`§5.10`: corvus's stable, AEAD-AD-bound identity is the **UTF-8 dataset
path string** (`users/<name>`). There is no decimal `dataset_id` on the
corvus wire. Stratum's mount-time UNWRAP currently sends the decimal
`dataset_id` as a provisional binding (`sync.c:551-554` says so
explicitly) — that is wrong against real corvus and must be fixed.

The keyschema is keyed internally by numeric `(dataset_id, key_id)` —
that stays. The fix: the **CORVUS keyslot's value gains a
`corvus_dataset_path` field** (the path string). Mount reads it back
and sends it to UNWRAP; provisioning writes it from the WRAP call.

- On-disk format change → `STM_UB_VERSION` 27 → 28 (exact-match gate,
  per `thylacine-keyslot-design.md §10` Q-KS1 — full version bump, no
  feature flag). User authorized format changes for this session.
- The field is `dataset_path_len u8 + dataset_path` (≤ 255 utf-8
  bytes). **CORVUS slots carry it; non-CORVUS slots write
  `dataset_path_len = 0`** (no path bytes) — keeps the decoder uniform.
- Placement in the keyschema entry value is pinned in the impl chunk
  (after `wrapper_identity`, before/around `wrapped`); the layout
  is no longer "8 + wrapped_len" — that note in the old design's §10
  is superseded.

## 6. The provisioning flow

At dataset creation of a corvus-encrypted dataset:

1. Generate a fresh 32-byte DEK (CSPRNG).
2. `stm_corvus_wrap(token, dataset_path, key_id, dek)` → 1217-byte
   envelope.
3. `stm_keyschema_insert_wrapped(...)` with `wrapper = CORVUS`,
   `corvus_dataset_path = dataset_path`, `wrapped = envelope`,
   `state = CURRENT`.
4. The DEK is also installed into the live `sync->deks` map (so the
   freshly-created dataset is immediately writable without a remount).
5. `explicit_bzero` the plaintext DEK once both (3) and (4) consumed it.

This replaces the test-only `stm_sync_keyschema_insert_for_test` seam's
role for production CORVUS slots.

**Operator surface** — decided: a `stratumd` provisioning path, not a
`/ctl/` verb. Rationale: dataset provisioning is a startup/creation-time
operator action that already needs the session token + corvus socket
config (`--corvus-socket` / `--corvus-session-token-file`, already on
stratumd from impl-3b); a `/ctl/` runtime verb would have to re-plumb
all of that and re-solve the token-handling trust boundary at a second
surface. v1.0: a stratumd CLI path (exact flag pinned in the
provisioning impl chunk). A `/ctl/` verb is forward-noted for v1.x if
runtime keyslot management is wanted.

## 7. Decisions recorded in this note

- **Envelope is opaque to Stratum.** The WRAP-response decoder accepts a
  payload in `(0, STM_KEYSCHEMA_WRAPPED_MAX]` (1280) and stores it
  verbatim — it does NOT hard-check `== 1217`. corvus's envelope carries
  its own `envelope_version` byte and may evolve; Stratum treats it as
  an opaque blob (same posture as UNWRAP's `wrapped` input). Zero-length
  payload on `status=OK` is refused (`STM_EPROTOCOL`). A future envelope
  exceeding 1280 is a keyschema-cap bump — forward-noted.
- **WRAP retry policy = reuse UNWRAP's.** `§5.10` is silent on a WRAP
  retry policy. Adopt the `§5.5 Q9` schedule symmetrically: 3 retries,
  100/500/2000 ms, same retry-eligible (transport / RATE_LIMITED /
  INTERNAL_ERROR) vs fatal (BAD_AUTH / PERM_DENIED / NOT_FOUND /
  BAD_FORMAT / EPROTOCOL) split. Reuse `stm_corvus_transport_opts`. If
  Thylacine later specs a distinct WRAP policy it is a one-line change.
  **(Confirm-with-Thylacine candidate — not a blocker.)**
- **DEK-in-request-frame confidentiality (R138 doctrine extension).**
  The WRAP *request* carries the **plaintext DEK** on the wire — a new
  exposure UNWRAP never had (UNWRAP sends an opaque wrapped blob). The
  transport MUST `stm_ct_memzero` the encoded request buffer (which
  holds token + DEK) after `write_all` completes, before `free` — the
  R138 P1-1 token-zeroing rule extended to the DEK. The DEK never
  appears in a log.
- **No new `STM_E*` codes.** WRAP reuses the `STM_ECORVUS*` family from
  UNWRAP (`status_to_stm` already maps the full status enum).

## 8. Spec scope (key_schema.tla extension)

Extend `key_schema.tla` (do NOT fork) with a `Wrap` action and one new
invariant — small, in the spirit of the impl-3b `MountResolvesKeyBeforeData`
extension:

- **`Wrap` action** — models provisioning: creates a CORVUS slot bound
  to a `(dataset_path, key_id)` pair, state CURRENT.
- **New invariant `UnwrapUsesWrapBinding`** — for any mount that
  resolves a CORVUS slot, the `(dataset_path, key_id)` Stratum sends to
  UNWRAP equals the `(dataset_path, key_id)` recorded by the `Wrap`
  that created the slot. This is load-bearing: if mount sent a
  different path, corvus's envelope-AD check fails → an unmountable
  pool. (Models the §5 binding fix at the spec level.)
- **Non-perturbation check** — adding `corvus_dataset_path` to the slot
  value does not perturb `ExactlyOneCurrent` / `RotationAtomic` /
  `MonotonicKeyIds` / `MountResolvesKeyBeforeData` / `TypeOK`.
- **Buggy config** — one: a mount that sends a path differing from the
  Wrap binding → trips `UnwrapUsesWrapBinding`.

## 9. Impl chunking (each its own commit + audit discipline)

| # | Chunk | Content |
|---|---|---|
| 1 | **wrap-design** | This doc. Update `thylacine-keyslot-design.md §10` to point here. **(this chunk)** |
| 2 | **wrap-spec** | `key_schema.tla` extension §8 + buggy cfg. `reference/10-specs.md` catalog entry. |
| 3 | **wrap-pathbind** | keyschema CORVUS slot value gains `corvus_dataset_path`; `STM_UB_VERSION` 27→28; encode/decode; mount-time UNWRAP sends the stored path (fixes the provisional decimal binding at `sync.c:551`). On-disk format change. Reference + super.h version-history upkeep. |
| 4 | **wrap-client** | `stm_corvus_encode_wrap` + `stm_corvus_decode_wrap_response` + size helper (corvus_client.{h,c}); `stm_corvus_wrap_once` + `stm_corvus_wrap` transport+retry; DEK-in-frame zeroing. Unit tests against the 4-byte fake corvus. |
| 5 | **wrap-provision** | The §6 provisioning flow + the stratumd CLI path. e2e test: provision a CORVUS dataset → unmount → remount → UNWRAP resolves. Retires the test-only insert seam's production role. |
| 6 | **audit** | Fresh round (R-series) scoping the whole WRAP path: the format change, DEK-in-frame confidentiality, the provisioning path (per keyslot-design §7 "the migration path itself is an audit target"), and `UnwrapUsesWrapBinding` impl fidelity. |

Sequencing: 2 → 3 → 4 → 5 → 6. wrap-pathbind (3) precedes wrap-client (4)
because it also fixes the existing UNWRAP provisional binding and is
independently valuable; wrap-client + wrap-provision then build the
production seal path on top.

## 10. Cross-repo dependency (Thylacine-side, NOT Stratum work)

For reference only — handled by the Thylacine-side agent:

- corvus request decoder `[0u8;3]` → `[0u8;4]`; validate
  `protocol_version == 1` else `BAD_FORMAT`.
- Every corvus *requester* (incl. Thylacine's login client for
  AUTH/SESSION_CLOSE/USER_CREATE) emits the 4-byte header.
- `STRATUM-API-V1.md` §5.2 + §5.10 frame diagrams → 4-byte; §6.2 notify
  documented as deliberately staying 3-byte; Q11 promoted to normative.
- corvus audit surface (`corvus.tla` + buggy cfgs) re-triggered.

Stratum will request a comms round with the Thylacine agent (via the
user) before real-corvus integration testing, to confirm corvus's
4-byte decoder + the WRAP C-7 path are landed.
