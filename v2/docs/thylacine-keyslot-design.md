# TLY-A3-keyslot — corvus-wrapped DEK storage design

Status: **design**, reframed after Q-KS2/Q-KS3 verification (see §4).
Spec-first chunk; the implementation is gated on a small extension of
`key_schema.tla` (TLY-A3-keyslot-spec).

Bilateral context: `STRATUM-API-V1.md §5` (the corvus UNWRAP ask).
The codec + transport are already LIVE — `v2/src/corvus_client/`,
TLY-A3-impl-1 (`1eb7480`) + impl-2 (`58a7253`) + R144 close
(`b948cf8`). This chunk wires the UNWRAP into the mount path.

> **Process note** — an earlier draft of this doc carried two
> load-bearing sections (snapshot-atomicity, send/recv keyslot
> shipping) written against *assumed* architecture. The Q-KS2/Q-KS3
> verification in §4 showed both assumptions were wrong. This doc is
> the reframe: the verified facts now precede the scope, and the
> scope is the smaller, real chunk.

## 1. Problem

`STRATUM-API-V1.md §5.3`: when stratumd mounts an encrypted dataset
it must (1) find that dataset's `{key_id, wrapped_dek}`, (2) send
UNWRAP to corvus, (3) receive the 32-byte DEK, (4) mount. Steps 2–4
are LIVE (`stm_corvus_unwrap`). Step 1 — *where the wrapped DEK
lives, and how the mount path reaches it* — is what this chunk
resolves.

## 2. Decision: reuse the existing pool-global `keyschema` module

The `keyschema` module (`v2/include/stratum/keyschema.h`,
`v2/specs/key_schema.tla`, Phase 4 chunk P4-4a) is **already** the
keyslot table this ask needs:

| Need (from the corvus ask) | keyschema today |
|---|---|
| Per-dataset *set* of slots, not a singleton | entries keyed by `(dataset_id, key_id)` |
| Rotation: old + new coexist during re-wrap | `state` ∈ {CURRENT, RETIRED, PRUNING}; `key_schema.tla::RotationAtomic` |
| Multi-wrap (user keypair + recovery phrase + escrow) | multiple `key_id`s per `dataset_id` |
| Integrity-covered, readable before the DEK exists | node plaintext + Merkle-covered via `bp_csum`; wrapped bytes AEAD-sealed by `stm_hybrid`; no DEK needed to read it |
| "Current key" lookup | `stm_keyschema_lookup_current(ks, dataset_id, …)` |
| Bounded wrapped-blob size | `STM_KEYSCHEMA_WRAPPED_MAX = 1280` |

We keep it **pool-global**; `ub_key_schema` is NOT retired. (An
earlier draft proposed relocating it into the dataset descriptor for
snapshot/send-recv atomicity; §4 shows that atomicity is not a
TLY-A3 concern at all, so the relocation buys nothing and would
retire a working, TLA+-pinned, audit-passed module for a placement
intuition.)

This refines `ARCHITECTURE.md` §7.3.2 / §7.7.3 / §8.3.2 only in that
`di_key_slot` stays "an index into `ub_key_schema`"; no ARCH text
change needed — note a cross-reference to this doc when ARCH is next
revised.

## 3. What this chunk builds (reframed scope)

Additive, on top of the existing keyschema module:

1. **`wrapper_identity` on the keyslot entry** — a small tag
   distinguishing how a slot's blob is wrapped: `PASSPHRASE` (legacy
   keyfile / Argon2id), `JANUS` (the existing janus agent), `CORVUS`
   (this ask). Lets the mount path route a slot to the right
   unwrapper. On-disk: one LE byte in the per-entry encoding, behind
   the feature flag (§7).
2. **A `CORVUS` slot kind** — its blob is the corvus-format wrapped
   DEK; `wrap_params` carries corvus's `key_id` registry index (the
   `u64` the UNWRAP verb already takes). corvus stays a *pure UNWRAP
   consumer*; Stratum owns the storage.
3. **Mount-time UNWRAP wiring** — `stm_keyschema_lookup_current(ds)`
   → wrapped blob → route by `wrapper_identity` → `stm_corvus_unwrap`
   → 32-byte DEK → AEAD context. CLI: `--corvus-socket` (default
   `/srv/corvus/ops/unwrap`), `--corvus-session-token-file`. The
   UNWRAP outcome is determined at mount/attach time — **fail-fast**
   (§5).
4. **DEK lifecycle** — DEK cached in mlock'd RAM under per-dataset
   state; `explicit_bzero` on unmount AND on the TLY-A4 eviction
   path. Inherits clauses 4+5 of the CLAUDE.md "corvus UNWRAP client
   (v2)" trigger row.
5. **The send-side `get_dek` touchpoint** — see §6. Small but it is
   the one place the send path depends on corvus, so it is named
   explicitly rather than folded into "mount wiring".

## 4. Verified code facts (Q-KS2 / Q-KS3)

These were checked against the tree before the spec, because the
spec's faithfulness depends on the real architecture, not an assumed
one.

### Q-KS2 — is the keyschema-vs-data independent-commit hazard live? **No.**

- `keyschema` commits in the **same sync transaction** as everything
  else: `sync.c:2424` calls `stm_keyschema_commit` in the same flush
  as `alloc_commit` at `target_gen` (`sync.c:2344`), and
  `keyschema_root_csum` is folded into `compute_merkle_root`
  (`sync.c:601`, `:632`) alongside the dataset/extent/cas/snap roots.
  One uberblock, one Merkle root — no torn data-vs-keyschema commit
  at the pool level.
- **v2 has no snapshot rollback** — `snapshot.h:43` lists "Snapshot
  rollback (ARCH §8.10)" as out-of-scope. It arrives with A5 /
  SWISS-6 v1.1c.
- `stm_snapshot_entry` captures `tree_root_paddr` + `extent_txg`
  only — no keyschema generation. But with the pool commit atomic,
  no rollback, and the DEK constant across passphrase rotation
  (rotation re-wraps the *same* DEK), nothing tears today.

→ snapshot-atomicity is **not a live-bug closure**. It is
pre-emptive design for a rollback that does not exist yet. **Moved
to A5** (§5).

### Q-KS3 — what does send/recv ship? **Plaintext; recv re-encrypts — by design.**

- `send.c:17-19`: "Each EXTENT record carries the extent's
  **PLAINTEXT bytes** (decrypted from the source pool's key)."
- `recv.c:18-21`: HOT EXTENT "**re-encrypts under the receiver pool's
  CURRENT DEK** … no key sharing across pools, no nonce reuse hazard
  across pools." recv's precondition: the target dataset already has
  its own CURRENT DEK in the receiver's keyschema.

send/recv **deliberately never ships wrap material** — it solves the
cross-pool key problem by re-encryption. The earlier "ship the
`(dataset_id, *)` keyschema entries inline, opaque on recv, never
re-key" design was the exact inverse of the real architecture.

→ there is **no send/recv stream extension to build**, and no
`RecvPreservesWrap` invariant (recv re-keys by design; an invariant
asserting wrap-preservation would be modeling fiction — green TLC,
false confidence). **§5-ship-keyslots is dropped.** The one real
send-side corvus dependency survives as §6.

## 5. Explicitly out of scope (moved / dropped)

- **snapshot-atomicity → A5.** When A5 lands snapshot rollback, a
  snapshot must capture a keyschema generation consistent with its
  `di_tree_root`, or a rollback resurrects an inconsistent
  data/keyslot pair. **Open tension A5 must resolve** (recorded here
  so it is not lost): capturing keyslots *with* a snapshot keeps a
  pruned-keyslot snapshot decryptable, but rollback then *restoring*
  those keyslots re-creates the F13 hazard (CORVUS-DESIGN §4.5 — old
  compromised wrap chain becomes live again). Decryptability vs
  forward-secrecy-on-rollback is a genuine rollback-design decision;
  it belongs to whoever owns A5, not TLY-A3.
- **send/recv keyslot shipping → dropped.** Cross-pool is already
  solved by recv-side re-encryption (§4 Q-KS3).
- **`RecvPreservesWrap` invariant → dropped.** It would assert a
  property the code deliberately violates.

## 6. The send-side `stm_sync_get_dek` touchpoint

`send` decrypts each extent to plaintext using the source dataset's
DEK, resolved via `stm_sync_get_dek` (`send.c:49`; the DEKs are
snapshotted into the send handle's mlock'd RAM at `send_init`,
`send.c:88-96`). Today that DEK is derived/keyschema-resident and
directly available.

When a source dataset's CURRENT keyslot is a `CORVUS` slot, the DEK
is not directly available — it must be obtained by running an UNWRAP
against corvus, exactly as the mount path does. So `send_init`'s DEK
snapshot step gains the same route-by-`wrapper_identity` →
`stm_corvus_unwrap` resolution as the mount path. This is the **one**
place `send` depends on corvus. It is small (reuses the mount path's
resolver) but it is a distinct dependency and is called out so it is
not missed during impl. recv is unaffected — it re-encrypts under the
receiver's own DEK and never touches source wrap material.

## 7. Migration + on-disk format

- **No re-derive, no re-encrypt.** Existing encrypted datasets keep
  their current derived DEK value. Migration ADDS a keyschema slot
  whose blob wraps that same DEK under corvus's keypair. Zero
  data-block churn; the dataset's extents are untouched.
- **The migration path itself is an audit target.** Adding a `CORVUS`
  slot touches the wrap chain, so the one-time migration MUST (a)
  land behind the same format-flag gate as the steady-state feature,
  and (b) get the Stratum-side soundness audit — the spec proves the
  steady-state keyschema invariants, NOT the one-time
  add-a-slot-to-an-existing-derived-DEK operation. The TLY-A3-keyslot
  audit round (§9) explicitly scopes the migration path.
- The `wrapper_identity` byte is a per-entry encoding change → an
  `STM_UB_VERSION`-class on-disk format change. Gate behind a
  feature flag; tier decided at impl per Q-KS1 (§10). Format-break
  escalation + compat-tier discipline applies; this chunk is itself
  an audit-trigger surface (crypto key handling).
- The deliberate split is unchanged: the **system/boot dataset**
  stays on the file backend + `.key` sidecar (initramfs feeds
  `stratumd-system` non-interactively, before corvus exists — the
  sidecar's physical separability earns its keep there and only
  there). **User datasets** get corvus-wrapped keyschema slots.

## 8. Spec scope (TLY-A3-keyslot-spec)

Extend `key_schema.tla` (do NOT fork a new file — the existing spec
already models the keyslot set; this is a small extension):

- New assertion **`MountResolvesKeyBeforeData`** — for any mount of
  a dataset whose CURRENT keyslot is a `CORVUS` slot, the UNWRAP
  outcome is determined BEFORE any data block of that dataset is
  observable. An un-unwrappable slot aborts the mount with **no data
  served — never a half-mount.** This is the one new load-bearing
  invariant.
- **`wrapper_identity` non-perturbation check** — confirm that
  adding the `wrapper_identity` field does not perturb the existing
  `ExactlyOneCurrent` / `RotationAtomic` / `MonotonicKeyIds` /
  `PruneSafety` / `TypeOK` invariants. A non-perturbation result is
  a legitimate, valuable spec outcome — it proves the additive
  change is inert w.r.t. the proven properties.
- **Buggy config**: one — a mount that serves data before resolving
  the `CORVUS` slot → trips `MountResolvesKeyBeforeData`. No buggy
  configs for the dropped §5 content.

## 9. Impl chunking (TLY-A3-keyslot-impl)

Each sub-chunk its own commit + audit-trigger discipline:

1. **3a — format + flag** ✓ (`2d68c08`): `wrapper_identity` byte in
   the keyschema entry encoding; `STM_UB_VERSION` 26 → 27.
2. **3b — mount wiring + CLI** ✓: `sync_unwrap_cb` routes a `CORVUS`
   slot through `stm_corvus_unwrap` at `stm_sync_open` time,
   fail-fast (`MountResolvesKeyBeforeData`); `stm_corvus_mount_cfg`
   threaded through `stm_sync_open`; `--corvus-socket` +
   `--corvus-session-token-file` on stratumd; token loaded into an
   mlock'd buffer for the mount and `stm_ct_memzero`'d after; the
   unwrapped DEK lands in the sync DEK map (zeroed at unmount /
   A4 eviction by the existing `sync_dek_wipe_all`). The §6
   `send_init` `get_dek` touchpoint needed NO code — the corvus DEK
   is in `sync->deks` after mount, so `stm_sync_get_dek` serves it
   transparently (verified). Tests: `test_corvus_mount.c` (4 e2e
   cases: resolve / no-corvus / corvus-reject / unreachable) against
   a fake corvus; CORVUS slots injected via the test-only
   `stm_sync_keyschema_insert_for_test` seam (no production WRAP
   path exists — §10).
3. **audit**: fresh round scoping the format change, the
   `MountResolvesKeyBeforeData` impl, the DEK mount-time lifecycle,
   and the test-only keyschema-insert seam.

   The pre-3b plan listed a "migration pass that adds a `CORVUS`
   slot to an existing dataset's current DEK" under 3a; that is the
   WRAP path and is blocked on the §10 bilateral question — it is
   NOT part of 3a/3b. impl-3b ships only the mount-time UNWRAP
   routing; producing a CORVUS-sealed blob is future work.

(The earlier 3-sub-chunk plan had a separate snapshot/send-recv
chunk; that is gone — §4/§5.)

## 10. Open question

- **Q-KS1 — RESOLVED at impl-3a.** The compat-tier framing
  (ro-compat vs incompat feature flag) does not apply: the v2 tree
  does **not** use the `ub_flags_*` feature-flag fields — they are
  vestigial. Every on-disk format change is a full `STM_UB_VERSION`
  bump with an exact-match gate (`version != STM_UB_VERSION →
  STM_EBADVERSION`; super.h's ~20-entry version history is all "full
  version bump, no feature flag"). So impl-3a bumps **STM_UB_VERSION
  26 → 27**. The `wrapper_identity` byte is carved from the
  keyschema entry value's reserved bytes (offset 2; the layout stays
  8 + wrapped_len), so the change is byte-back-compatible — but the
  semantic break (a pre-TLY-A3 binary has no wrapper_identity concept
  and would misroute a CORVUS slot) is what the version bump gates.
  The exact-match check is strictly stronger than an incompat flag:
  a v26 binary refuses a v27 pool outright. `STM_KS_WRAPPER_LEGACY =
  0` is the back-compat default a pre-TLY-A3 zero byte decodes to.

Q-KS2 and Q-KS3 are answered above (§4).

- **WRAP path — RESOLVED 2026-05-16.** The §9 forward-note "producing
  a CORVUS-sealed blob is future work, blocked on the bilateral
  question" is closed: `STRATUM-API-V1.md` §5.2 + §5.10 now spec the
  corvus WRAP verb (verb_id=10) and answer the dataset-binding
  question (the stable identity is the UTF-8 dataset path string, not
  a decimal id). The production WRAP path — provisioning-time DEK
  sealing, the keyschema dataset-path binding fix, and the
  `STM_UB_VERSION` 27 → 28 bump that carries it — is designed in
  `thylacine-keyslot-wrap-design.md` (chunk series TLY-A3-keyslot-wrap).
