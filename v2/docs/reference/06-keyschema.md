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
                                          wrapped, wrapped_len);

stm_status stm_keyschema_lookup         (ks, dataset_id, key_id,
                                          &state, out_buf, out_cap, &len);

stm_status stm_keyschema_lookup_current (ks, dataset_id,
                                          &key_id, out_buf, out_cap, &len);

size_t     stm_keyschema_count          (const stm_keyschema *ks);
```

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

1. Transition every RETIRED entry for `dataset_id` → PRUNING.
2. Future extent-manager GC marks PRUNING → deletable when no
   extent references the key.
3. `stm_keyschema_sweep_pruning` deletes the PRUNING entries
   whose DEK count hit zero.

For P4-4c, extent refcounting doesn't exist yet — `stm_sync_keyschema_sweep`
treats RETIRED → deletable immediately. Revisits when Phase 6's
extent manager lands.

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
- **Value** (3 + ≤1280 bytes): `le8 state || le8 pad || le16 wrapped_len || wrapped[]`.

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
