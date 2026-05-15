# TLY-A3-keyslot — corvus-wrapped DEK storage design

Status: **design** (TLY-A3-keyslot-design). Spec-first chunk; the
implementation is gated on `keyslot`-extension of `key_schema.tla`
(TLY-A3-keyslot-spec) which is in turn gated on this doc.

Bilateral context: `STRATUM-API-V1.md §5` (the corvus UNWRAP ask).
The codec + transport are already LIVE — `v2/src/corvus_client/`,
TLY-A3-impl-1 (`1eb7480`) + impl-2 (`58a7253`) + R144 close
(`b948cf8`). This chunk wires the UNWRAP into the mount path.

## 1. Problem

`STRATUM-API-V1.md §5.3`: when stratumd mounts an encrypted dataset
it must (1) find that dataset's `{key_id, wrapped_dek}`, (2) send
UNWRAP to corvus, (3) receive the 32-byte DEK, (4) mount. Steps 2–4
are LIVE (`stm_corvus_unwrap`). Step 1 — *where the wrapped DEK
lives* — is what this chunk resolves.

## 2. Decision: reuse the existing pool-global `keyschema` module

The `keyschema` module (`v2/include/stratum/keyschema.h`,
`v2/specs/key_schema.tla`, Phase 4 chunk P4-4a) is **already** the
keyslot table this ask needs:

| Need (from the corvus ask) | keyschema today |
|---|---|
| Per-dataset *set* of slots, not a singleton | entries keyed by `(dataset_id, key_id)` |
| Rotation: old + new coexist during re-wrap | `state` ∈ {CURRENT, RETIRED, PRUNING}; `key_schema.tla::RotationAtomic` |
| Multi-wrap (user keypair + recovery phrase + escrow) | multiple `key_id`s per `dataset_id` |
| Integrity-covered, readable before the DEK exists | node is plaintext + Merkle-covered via `bp_csum`; wrapped bytes AEAD-sealed by `stm_hybrid`; no DEK needed to read it |
| "Current key" lookup | `stm_keyschema_lookup_current(ks, dataset_id, …)` |
| Bounded wrapped-blob size | `STM_KEYSCHEMA_WRAPPED_MAX = 1280` (PQ-hybrid wrap of a 32-byte DEK ≈ 1192 B) |

The module persists as a single-leaf-now / btree-later node rooted
at the uberblock's `ub_key_schema`; `key_schema.tla` already pins
`ExactlyOneCurrent`, `PruneSafety`, `MonotonicKeyIds`,
`RotationAtomic`, `TypeOK`.

**We keep it pool-global. `ub_key_schema` is not retired.** An
earlier draft of this design proposed relocating the table into each
dataset descriptor (`di_tree_root` region) for snapshot/send-recv
atomicity. That was reasoning from the corvus side before the
keyschema module's existence was known. Retiring a working,
TLA+-pinned, Merkle-covered, audit-passed module to satisfy a
*placement* intuition is the wrong trade: pool-global vs
in-descriptor is a storage location, not a semantic, and the only
property the relocation bought — atomicity with snapshot/send-recv —
is delivered directly by §4 + §5 below without moving anything.

This refines `ARCHITECTURE.md` §7.3.2 / §7.7.3 / §8.3.2: the
`di_key_slot` field stays "an index into `ub_key_schema`"; no ARCH
text change is needed, but §8.3.2's wording should gain a
cross-reference to this doc when ARCHITECTURE.md is next revised
(noted for cross-check per CLAUDE.md's spec-wins / reference-corrected
discipline).

## 3. What this chunk builds

Additive, on top of the existing module:

1. **`wrapper_identity` on the keyslot entry** — a small tag
   distinguishing how a slot's blob is wrapped: `PASSPHRASE` (legacy
   keyfile / Argon2id), `JANUS` (the existing janus agent), `CORVUS`
   (this ask). Lets the mount path route a slot to the right
   unwrapper. On-disk: one LE byte, in the per-entry encoding,
   behind the feature flag (§6).
2. **A `CORVUS` slot kind** — its blob is the corvus-format wrapped
   DEK; `wrap_params` carries corvus's `key_id` registry index (the
   `u64` the UNWRAP verb already takes). corvus stays a *pure UNWRAP
   consumer*; Stratum owns the storage.
3. **send/recv stream extension** (§5) — ship the source dataset's
   `(dataset_id, *)` keyschema entries inline.
4. **snapshot-atomicity guarantee** (§4) — the load-bearing
   invariant.
5. **Mount-time wiring** — `stm_keyschema_lookup_current(ds)` →
   wrapped blob → (route by `wrapper_identity`) → `stm_corvus_unwrap`
   → 32-byte DEK → AEAD context. CLI: `--corvus-socket` (default
   `/srv/corvus/ops/unwrap`), `--corvus-session-token-file`. DEK
   cached in mlock'd RAM under per-dataset state; `explicit_bzero`
   on unmount AND on the TLY-A4 eviction path.

## 4. Load-bearing requirement A — snapshot atomicity

A dataset snapshot MUST capture that dataset's keyschema slice at the
**same Merkle-consistent commit point** as the dataset's
`di_tree_root`. The keyschema sub-tree currently commits via
`stm_keyschema_commit` and plants its root in `ub_key_schema`; the
dataset's data commits via its own `di_tree_root`. If those two
advance independently, a snapshot can capture **data at version N**
and **keyslots at version N±1**.

Why that is a real hazard, not a nicety: it reintroduces the
snapshot-rollback-after-passphrase-change attack (`CORVUS-DESIGN`
§4.5, audit **F13**). Roll a dataset's data back to a snapshot whose
captured keyslots predate a passphrase rotation, and the old
(now-compromised) wrap chain is live again against current data.

**The invariant** (`key_schema.tla` must gain it — treat as
load-bearing, NOT an impl detail):

> For every snapshot S of dataset D, the keyschema entries visible
> through S are exactly the `(D, *)` entries that were CURRENT/
> RETIRED at the txg of S's `di_tree_root` — never a later or
> earlier keyschema generation.

Implementation shape (to be confirmed against `sync.c`'s commit
ordering during impl): the keyschema commit and the dataset-tree
commit must land in the **same sync transaction** — one `fs->gen`
advance, one Merkle root. The three-phase sync already serializes a
single commit point; the requirement is that the keyschema root and
the affected `di_tree_root` are both folded into THAT root, and a
snapshot records the `ub_key_schema` generation alongside the
`di_tree_root` it pins.

**Spec faithfulness requirement** (review note): the spec must model
the torn **read**, not merely the torn write. `SnapshotKeyslotAtomicity`
has to hold under the buggy config where keyschema commits in a
*separate* transaction, and the counterexample TLC produces under
that config must be exactly a snapshot observing `(data@N,
keys@N±1)`. If the buggy config cannot produce that trace, the
invariant is not pinning the real hazard and the spec is wrong. The
"fold into one sync transaction" shape is the fix; the spec's job is
to prove the un-folded version *fails*, with the F13-shaped
counterexample as the evidence.

## 5. Load-bearing requirement B — send/recv completeness + ownership

`send` of dataset D MUST include D's `(dataset_id, *)` keyschema
entries inline in the stream (the existing send/recv code already
references keyschema — TLY-A3-keyslot-impl confirms current
behavior and extends it). Three rules the spec + impl must pin:

1. **Opaque on recv.** `recv` treats the shipped entries as opaque
   wrapped blobs. It MUST NOT re-wrap, re-key, or otherwise touch
   the wrap material — the receiving pool has no business handling
   corvus-owned (or janus-owned) wrap secrets. recv inserts the
   blobs verbatim into the target pool's keyschema under the same
   `(dataset_id, key_id, state, wrapper_identity)`.
2. **Atomic with the data stream.** The keyslot entries and the
   dataset's data must materialize at recv as one commit — the §4
   invariant applies symmetrically on the receive side (a recv
   that commits data then crashes before the keyslots, or vice
   versa, must not leave a mountable-but-mismatched dataset).
3. **Cross-pool validity story.** A `CORVUS`/`JANUS` slot is
   wrapped under an agent keypair that may not exist on the target
   pool. recv into a *different* pool therefore yields a dataset
   whose corvus slots are **present but un-unwrappable there**. The
   defined behavior: recv SUCCEEDS (the blobs travel; data is
   intact), but a subsequent mount on the target fails cleanly at
   the UNWRAP step (corvus on the target returns NotFound/PermDenied
   → `STM_ECORVUSNOTFOUND`/`STM_ECORVUSPERM`, already fatal-classed)
   rather than corrupting or silently mounting unencrypted. A
   `PASSPHRASE` slot remains valid cross-pool (the passphrase is the
   user's, not the pool's). v1.x may add a recv-side "re-key under
   the target's agent" admin flow; v1.0 does not — recv never
   touches wrap material (rule 1).

   **Fail-fast, before any data is served** (review note): the
   UNWRAP must be attempted — and its failure surfaced — at
   mount/attach time, NOT lazily on first block access. A mount
   that fails halfway (some blocks served, then a key error) is
   strictly worse than one that refuses up front. The mount path
   resolves the dataset's CURRENT `CORVUS` slot through
   `stm_corvus_unwrap` as part of `stm_fs_mount` / dataset-attach,
   and a non-OK result aborts the mount before the dataset is
   readable. This **fail-fast-at-mount** property gets its own
   spec assertion (§7) — it is a distinct guarantee from
   `RecvPreservesWrap` (which only covers the opaque-on-recv half)
   and from the corvus client's own error classing.

## 6. Migration + on-disk format

- **No re-derive, no re-encrypt.** Existing encrypted datasets keep
  their current derived DEK value. Migration ADDS a keyschema slot
  whose blob wraps that same DEK under corvus's keypair. Zero
  data-block churn; the dataset's extents are untouched.
- **The migration path itself is an audit target** (review note).
  Adding a `CORVUS` slot touches the wrap chain, so the one-time
  migration MUST (a) land behind the same format-flag gate as the
  steady-state feature, and (b) get the Stratum-side soundness
  audit — not only the spec. The spec proves the steady-state
  keyschema invariants; it does NOT cover the one-time
  add-a-slot-to-an-existing-derived-DEK operation. The TLY-A3-keyslot
  audit round (§8) explicitly scopes the migration path.
- The `wrapper_identity` byte is a per-entry encoding change to the
  keyschema node format → an `STM_UB_VERSION`-class on-disk format
  change. Gate it behind a feature flag: **ro-compat** is the right
  tier (an old reader can still mount + read a pool whose keyschema
  has the new byte *if* it can ignore unknown wrapper kinds — but
  to be safe against a pre-flag reader misparsing the entry, confirm
  the entry layout's forward-compat at impl time; if the byte can't
  be added forward-compatibly, escalate to **incompat**). The
  format-break escalation + compat-tier discipline applies; this
  chunk is itself an audit-trigger surface (crypto key handling).
- The deliberate split is unchanged: the **system/boot dataset**
  stays on the file backend + `.key` sidecar (initramfs must feed
  `stratumd-system` non-interactively, before corvus exists — the
  sidecar's physical separability earns its keep there and only
  there). **User datasets** get corvus-wrapped keyschema slots.

## 7. Spec scope (TLY-A3-keyslot-spec)

Extend `key_schema.tla` (do NOT fork a new `keyslot.tla` — the
existing spec already models the keyslot set; this is an extension):

- New invariant **`SnapshotKeyslotAtomicity`** (§4) — a snapshot's
  observed keyschema generation equals its `di_tree_root`
  generation.
- New invariant **`RecvPreservesWrap`** (§5 rule 1) — a recv'd
  entry's wrapped blob + `wrapper_identity` are byte-identical to
  the sent entry; no action re-wraps.
- New assertion **`MountResolvesKeyBeforeData`** (§5 rule 3
  fail-fast) — for any mount of a dataset with a `CORVUS` CURRENT
  slot, the UNWRAP outcome is determined BEFORE any data block of
  that dataset is observable; an un-unwrappable slot aborts the
  mount with no data served. Distinct from `RecvPreservesWrap`.
- Carry the existing `ExactlyOneCurrent` / `RotationAtomic` /
  `MonotonicKeyIds` / `PruneSafety` / `TypeOK` unchanged; confirm
  the `wrapper_identity` addition doesn't perturb them.
- Buggy configs: (a) keyschema commits independently of the
  dataset tree → trips `SnapshotKeyslotAtomicity`, and the TLC
  counterexample MUST be exactly a snapshot reading `(data@N,
  keys@N±1)` — if the trace isn't that shape, the config or the
  invariant is wrong (§4 faithfulness requirement); (b) recv
  re-wraps under the target agent → trips `RecvPreservesWrap`;
  (c) a torn recv (data committed, keyslots not) → trips the
  atomicity invariant on the receive side; (d) a mount that serves
  data before resolving the `CORVUS` slot → trips
  `MountResolvesKeyBeforeData`.

## 8. Impl chunking (TLY-A3-keyslot-impl)

Each sub-chunk its own commit + audit-trigger discipline:

1. **3a — format + flag**: `wrapper_identity` byte in the keyschema
   entry encoding; `STM_UB_VERSION` bump; ro-compat (or incompat)
   feature flag; migration pass that adds a `CORVUS` slot to an
   existing dataset's current DEK.
2. **3b — snapshot/send-recv atomicity**: fold the keyschema commit
   into the dataset-tree commit point; extend send/recv to ship +
   verbatim-insert `(dataset_id, *)` entries; the cross-pool mount-
   fails-cleanly path.
3. **3c — mount wiring + CLI**: route a `CORVUS` slot through
   `stm_corvus_unwrap`; `--corvus-socket` + `--corvus-session-token-file`;
   DEK mlock'd cache + `explicit_bzero` on unmount + A4 eviction.
4. **audit**: fresh round scoping the format change, the atomicity
   invariant's impl, the send/recv ownership rules, and the DEK
   mount-time lifecycle.

## 9. Open questions

**Q-KS2 and Q-KS3 are answered BEFORE the spec** (review note) —
the spec's faithfulness depends on modeling today's real behavior,
not an assumed one.

- **Q-KS2** (priority — answer first): is the independent-commit
  hazard LIVE in today's `sync.c`? Does the keyschema commit land
  in the same sync transaction / Merkle root as the dataset-tree
  commit, or can it advance separately? **If it is live, that is a
  finding in its own right** — it would mean current snapshots can
  already tear data-vs-keys, independent of any corvus work — and
  it MUST be flagged separately (its own audit finding / fix),
  not allowed to ride silently inside TLY-A3. If it is already
  coupled, impl-3b is a confirm-and-pin rather than a fix.
- **Q-KS3** (answer before the spec): what do `send.c` / `recv.c`
  ship re keyschema *today*? `RecvPreservesWrap`'s faithfulness
  depends on modeling the actual stream. If send/recv already ships
  `(dataset_id, *)` entries, impl-3b is smaller than estimated.
- **Q-KS1** (decided at impl-3a against the real entry encoding):
  compat tier. Lean: if the `wrapper_identity` byte can be added
  such that an old reader sees existing slots as `PASSPHRASE`-kind
  and simply does not understand `CORVUS`-kind slots → **ro-compat**
  is justifiable. If an old reader would miswrap or misroute a slot
  → **incompat**. Do not pre-commit; decide on the encoding.
