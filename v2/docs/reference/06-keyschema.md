# 06 — Keyschema (per-dataset DEK registry)

## Purpose

Registers every dataset's wrapped Data Encryption Key (DEK) in a
single pool-level Bε-tree sub-tree. Each entry tracks one key's
state across the lifecycle (`CURRENT` → `RETIRED` → `PRUNING` →
deleted) per ARCHITECTURE §7.7.

The keyschema is the bridge between:

- **Crypto** (which produces + consumes wrapped blobs via
  `stm_hybrid_wrap` / `_unwrap`), and
- **Sync** (which persists the schema tree as part of every commit
  and surfaces per-dataset keys via `stm_sync_get_dek`).

Wrapped key material never hits disk in plaintext: the schema
node's leaf bytes contain already-encrypted `stm_hybrid` blobs.
The schema node itself is plaintext Merkle-covered (the value is
the wrapped blob, not the raw DEK, so it doesn't need a second
AEAD layer).

## Public API

### Lifecycle

```c
stm_status stm_keyschema_create(stm_bdev *d, stm_bootstrap *boot, stm_keyschema **out);
stm_status stm_keyschema_open  (stm_bdev *d, stm_bootstrap *boot, stm_keyschema **out);
void       stm_keyschema_close(stm_keyschema *ks);
```

The caller supplies the device + the bootstrap-pool handle so the
schema can reserve its node from the bootstrap region (alongside
alloc-tree nodes). `_create` and `_open` are aliases that differ
only in semantics: a freshly-created pool calls `_create` then
commits an empty node; a remount calls `_open` then `_load_at` to
decode the durable schema.

### Persistence

```c
stm_status stm_keyschema_load_at(stm_keyschema *ks,
                                  uint64_t root_paddr,
                                  const uint8_t expected_csum[32]);

stm_status stm_keyschema_commit (stm_keyschema *ks,
                                  uint64_t committed_gen,
                                  uint64_t *out_root_paddr,
                                  uint8_t   out_root_csum[32]);

stm_status stm_keyschema_get_root(const stm_keyschema *ks,
                                   uint64_t *out_root_paddr,
                                   uint8_t  out_root_csum[32]);
```

`commit` serializes the current in-RAM map to a fresh single-leaf
node, writes through the bootstrap pool, frees the previous node
at `committed_gen` (allocator.tla deferred-free pattern), and
returns the new bptr. Idempotent when the schema is clean (R14b
P2-1): returns the cached root without writing. The idempotency is
load-bearing — it keeps two consecutive commits producing byte-
identical `ub_key_schema[512]` bytes, satisfying quorum.tla's
`ContentQuorumAtGen` invariant across retries.

### Entry manipulation

```c
stm_status stm_keyschema_insert_wrapped(ks, dataset_id, key_id, state,
                                          wrapper, wrapped, wrapped_len,
                                          corvus_dataset_path,
                                          corvus_dataset_path_len);

stm_status stm_keyschema_lookup         (ks, dataset_id, key_id,
                                          &state, &wrapper,
                                          out_buf, out_cap, &len);

stm_status stm_keyschema_lookup_current (ks, dataset_id,
                                          &key_id, &wrapper,
                                          out_buf, out_cap, &len);

/* TLY-A3-keyslot-wrap: read a CORVUS slot's recorded corvus path. */
stm_status stm_keyschema_get_corvus_path(ks, dataset_id, key_id,
                                          out_path, out_cap, &len);

size_t     stm_keyschema_count          (const stm_keyschema *ks);
```

### `wrapper_identity` (TLY-A3-keyslot, STM_UB_VERSION 26 → 27)

Every entry carries a `stm_keyschema_wrapper` tag — `LEGACY` (0),
`PASSPHRASE` (1), `JANUS` (2), `CORVUS` (3) — recording how the
wrapped-DEK blob is sealed, so the mount path can route a `CORVUS`
slot through `stm_corvus_unwrap` and a local slot through the
keyfile/janus path. `insert_wrapped` and `rotate` take it as a
parameter; `lookup` / `lookup_current` return it via a NULL-able
`*out_wrapper`.

On disk the tag is byte [2] of the entry value. It is carved from
what was a 6-byte reserved block written zero, so a pre-TLY-A3 entry
decodes as `LEGACY` — the back-compat default, which the mount path
treats exactly like `PASSPHRASE`. `decode_val` refuses any byte
outside {0,1,2,3} as `STM_ECORRUPT`. At STM_UB_VERSION 26 → 27 the
layout was byte-identical (`KS_VAL_HDR_LEN` stayed 8); the bump gated
the *semantic* break (a pre-TLY-A3 binary would misroute a `CORVUS`
slot). See `v2/docs/thylacine-keyslot-design.md`.

### corvus dataset-path binding (TLY-A3-keyslot-wrap, STM_UB_VERSION 27 → 28)

A `CORVUS` slot records the **corvus dataset-path** — the UTF-8
string corvus binds into the DEK envelope's AEAD-AD and the value the
mount-time UNWRAP must send back (`STRATUM-API-V1.md` §5.10). Byte [3]
of the entry value (also previously reserved-zero) is
`corvus_dataset_path_len`, and the path bytes (1..255) are stored
immediately after the 8-byte header, BEFORE the wrapped blob:

```
state(1) || flags(1) || wrapper_identity(1) || corvus_path_len(1)
  || reserved(4) || corvus_dataset_path(0..255) || wrapped(variable)
```

A `CORVUS` slot MUST carry a non-empty path; every other wrapper MUST
carry a zero-length one — `insert_wrapped` / `rotate` enforce this
(`STM_EINVAL`), `decode_val` re-checks it (`STM_ECORRUPT`). Unlike the
26 → 27 bump this is a genuine *layout* change (the wrapped blob
shifts by `corvus_path_len` bytes), so the 27 → 28 bump gates a v27
binary mis-slicing a v28 value. `stm_keyschema_get_corvus_path` reads
the recorded path back; `sync_unwrap_cb` uses it so the UNWRAP sends
corvus the WRAP-recorded binding (`key_schema.tla::UnwrapUsesWrapBinding`).
See `v2/docs/thylacine-keyslot-wrap-design.md`.

### Mount-time unwrap routing (TLY-A3-keyslot-impl-3b)

`stm_keyschema_iter`'s callback signature carries the per-entry
`wrapper` (`stm_keyschema_iter_cb` gained a `stm_keyschema_wrapper`
parameter). `stm_sync_open`'s `sync_unwrap_cb` uses it: a `CORVUS`
entry routes through `stm_corvus_unwrap` (the corvus key agent),
every other tag routes through the local keyfile/janus path. The
unwrap runs inside `stm_sync_open`, before `stm_fs_mount` returns a
usable handle — so a CURRENT corvus slot that won't unwrap aborts
the mount with no data served (`key_schema.tla::MountResolvesKey-
BeforeData`); RETIRED/PRUNING corvus slots soft-skip on failure,
exactly like a local-unwrap failure. corvus config reaches
`stm_sync_open` via the optional `stm_corvus_mount_cfg` parameter
(NULL = no corvus). `stm_fs_mount` builds it from
`stm_fs_mount_opts.corvus_socket` + `.corvus_session_token_file`
(the 33-byte session token is loaded into an mlock'd buffer for the
duration of the mount and then `stm_ct_memzero`'d). The corvus
dataset-name binding is v1.0 provisional — see
`v2/docs/thylacine-keyslot-design.md` §10.

### Rotation + sweep

```c
stm_status stm_keyschema_next_key_id(ks, dataset_id, &out_key_id);

stm_status stm_keyschema_sweep_pruning(ks, dataset_id, out_pruned_keys[], size_t cap,
                                          size_t *out_pruned_count);
```

Rotation is orchestrated by sync (`stm_sync_rotate_dataset_key`):

1. Call `stm_keyschema_next_key_id(ds)` for the new key_id.
2. Retire the existing CURRENT entry (state flip).
3. Generate a new DEK, wrap under the pool wrap key.
4. `stm_keyschema_insert_wrapped(ds, new_key_id, CURRENT, blob, len)`.
5. Commit.

Sweep is orchestrated by `stm_sync_keyschema_sweep`:

1. Walk every RETIRED entry for `dataset_id`.
2. **P7-10**: for each, count extent references via the in-RAM
   extent index (`stm_extent_iter_ds` + filter by `key_id`). If
   any live extent stamps that `(dataset_id, key_id)`, the entry
   is left in RETIRED — closes the long-standing P4-4c TODO and
   maps to `key_schema.tla::PruneSafety` ("a pruned key never had
   outstanding refs"). The operator can sweep again after extents
   migrate to a newer key (overwrite — drops the old key_id ref;
   future bg re-encrypt sweep — same outcome).
3. RETIRED entries with zero refs transition through PRUNING and
   are then removed; the in-RAM DEK is wiped via `sync_dek_remove`.

The walk runs under sync's lock, so it sees a consistent snapshot:
no concurrent extent-mutation can change the count between the
walk and the prune. Cost is O(extents) per sweep call; future
optimization could maintain refcount-by-key_id incrementally.

## Entry state machine

```
             create + wrap         rotate
      IDLE ─────────────────▶ CURRENT ──────────▶ RETIRED
                                  │                  │
                         (dataset_id=0 refused)      │ sweep()
                         (metadata key, no rotate)   │
                                                     ▼
                                                  PRUNING
                                                     │
                                          (ref-count = 0)
                                                     │
                                                     ▼
                                                  deleted
```

Enforced at the `insert_wrapped` boundary and by sync-layer
wrappers (`stm_sync_add_dataset_key`, `_rotate_dataset_key`,
`_keyschema_sweep`). `dataset_id == 0` is special: it's the pool's
metadata-encryption key and cannot rotate because rotating it
would leave existing metadata nodes un-decryptable under the new
key. Metadata-key rotation (with an accompanying re-encrypt sweep)
is deferred (ARCH §7.7.3).

### On-disk encoding

Single-leaf Bε-tree node (btnode format, 128 KiB max payload):

- **Key** (16 bytes): `le64 dataset_id || le64 key_id`.
- **Value** (8 + path + ≤1280 bytes): `le8 state || le8 flags || le8 wrapper_identity || le8 corvus_path_len || reserved[4] || corvus_dataset_path[0..255] || wrapped[]` — `KS_VAL_HDR_LEN` is the 8-byte fixed header; the length is implicit in the btnode value-length (no `wrapped_len` field).

Up to ~107 entries per leaf at `STM_KEYSCHEMA_WRAPPED_MAX = 1280`;
multi-level tree extension lands when entry count exceeds this.

Node itself is plaintext (no AEAD envelope — the wrapped bytes are
already encrypted by `stm_hybrid`), with a BLAKE3 self-csum over
the node body that chains up through the uberblock's
`ub_key_schema.ks_root.bp_csum`.

## Spec cross-reference

| Spec | Pins |
|---|---|
| `key_schema.tla` | State-machine transitions: `CURRENT → RETIRED → PRUNING → deleted` are the only paths. `MonotonicKeyIds` — key_ids never recycle. `UniqueCurrentPerDataset` — at most one CURRENT entry per dataset. `DEKReferenceSafe` — a RETIRED entry's DEK stays in RAM so readers of extents encrypted under it can still decrypt. |

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_keyschema_rotate` | 15 | Full rotate / sweep / lookup lifecycle; multiple datasets coexisting; retired-blob not swappable into CURRENT slot (AD binding); sweep refuses until PRUNING; idempotent commit produces byte-identical bytes; tamper detection (wrong csum / wrong key / wrong pool_uuid in AD); `dataset_id == 0` rejected for rotate. |
| `test_alloc_roots` + `test_sync_multi` | several | End-to-end integration: rotate at commit time; ub_key_schema header roundtrips; remount decodes schema; sync_get_dek pulls correct DEK after rotate. |

## Status

- [x] Create / open / close / load_at / commit.
- [x] Insert / lookup / lookup_current / count.
- [x] Key-id monotonic next-id.
- [x] Rotation driven by sync.
- [x] Sweep RETIRED → PRUNING → deletable (Phase 6 ref-check TBD).
- [x] Idempotent commit (R14b P2-1).
- [x] AD-binding (`pool_uuid || dataset_id || key_id`) via R10 P2-2.
- [x] On-disk Merkle-covered, plaintext-node + wrapped-value format.
- [x] Dataset_id = 0 refused for rotate (metadata key).
- [ ] Multi-level schema tree when entries exceed single-leaf cap
      (~107 entries). Extension via existing btree_store machinery;
      single-leaf is MVP.
- [ ] Extent-refcount-aware PRUNING → deletable transition
      (Phase 6 extent manager).

## Known caveats

- **Single-leaf cap**: ~107 entries. Pools with >100 datasets need
  the multi-level extension. Not a hard blocker — a single dataset
  can carry many files / inodes without adding schema entries.
- **DEK in RAM for retired keys**: `stm_sync` keeps every unwrapped
  DEK in its `sync_dek_slot` map so readers of extents encrypted
  under retired keys can still decrypt. The map only shrinks on
  `sweep_pruning`. Long-running rotation-heavy pools will grow the
  in-RAM DEK map; in practice this is capped at "active datasets ×
  rotation history", typically tens of entries.
- **Format is not rolling**: a schema commit ALWAYS writes a fresh
  node, paying the bootstrap-pool write cost every time. Idempotent
  commit avoids this when state is clean, but any non-empty
  mutation rewrites. Future optimization: in-place delta log.
