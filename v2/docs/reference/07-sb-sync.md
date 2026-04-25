# 07 — Superblock + sync (commit protocol)

## Purpose

Two tightly coupled modules:

- **`sb`** — the on-disk superblock layout: 4-region label layout,
  4 KiB uberblock structure, commit-ring slot addressing, encode /
  decode / csum. Pure format. No I/O of its own — it speaks bytes
  to `bdev` via sync.
- **`sync`** — the commit-protocol coordinator: drives the 2-phase
  multi-device quorum commit, manages the uberblock ring rotation,
  hosts the per-dataset keyschema, mediates between alloc + pool +
  keyschema during commit and mount.

Together these implement ARCHITECTURE §5 (Superblock + quorum) and
§3.7 (Commit protocol).

## Label + ring layout (sb)

```
Per-device regions (ARCH §5.3.1):

  [ Label 0 | Label 1 |   margin   | Bootstrap pool | data area | Label 2 | Label 3 ]
  ^         ^         ^            ^                ^           ^         ^
  0         256K      512K         1 MiB            bpool_end   end-512K  end-256K

Each label (256 KiB) is 63 uberblock slots + 1 mirror slot:

  Slot 0:  ub_gen % slots_per_label == 0 landing pad
  Slot 1:  ub_gen % slots_per_label == 1 landing pad
  ...
  Slot 62: ub_gen % slots_per_label == 62 landing pad
  Slot 63: pool-config mirror (reserved; currently unused)
```

Layout constants (`include/stratum/super.h:103-107`):

| Constant | Value | Meaning |
|---|---|---|
| `STM_UB_SIZE` | 4096 | One uberblock. |
| `STM_LABEL_SIZE` | 256 KiB (64 × UB) | One label region. |
| `STM_LABELS_PER_DEVICE` | 4 | 2 at head, 2 at tail. |
| `STM_UB_SLOTS_PER_LABEL` | 63 | Commit-ring slots. |
| `STM_UB_MIRROR_SLOT` | 63 | Pool-config mirror (future). |
| `STM_DEVICE_MIN_BYTES` | 8 MiB | Minimum device size. |

Ring rotation per commit:

```
label = gen % STM_LABELS_PER_DEVICE          // 0..3
slot  = gen % STM_UB_SLOTS_PER_LABEL         // 0..62
```

Consecutive commits land on different labels. After 4 × 63 = 252
commits the `(label, slot)` pair wraps, but by then the history is
dense and mount-time selection always picks the newest valid
uberblock.

## Uberblock format (4096 bytes)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 8 | `ub_magic` | `0x324d555441525453` (ASCII "STRATUM2"). |
| 8 | 4 | `ub_version` | Currently `STM_UB_VERSION = 8`. |
| 12–20 | 12 | feature flags | `compat` / `ro_compat` / `incompat` (ARCH §5.2). |
| 24 | 16 | `ub_pool_uuid` | Pool identity. |
| 40 | 16 | `ub_device_uuid` | This device's identity. |
| 56 | 8 | `ub_gen` | Monotonic per-commit counter. |
| 64 | 8 | `ub_txg` | Transaction-group counter (currently == gen). |
| 72 | 8 | `ub_roster_hash` | le64 truncation of BLAKE3 over `ub_roster[2048]`. |
| 80 | 2 | `ub_device_count` | Roster size. |
| 82 | 2 | `ub_device_id` | This device's slot in the roster. |
| 96 | 64 | `ub_main_root` | Main FS tree root bptr (future). |
| 160 | 64 | `ub_alloc_root` | v7+: points at alloc-roots object (`STM_BPTR_KIND_ALLOC_ROOTS`). |
| 224 | 64 | `ub_snap_root` | Snapshot tree root (future). |
| 288 | 64 | `ub_cas_index_root` | CAS index root (future). |
| 352 | 32 | `ub_merkle_root` | Root of the Merkle chain over all metadata. |
| 384–416 | 32 | pool counters | `next_ino`, `next_dataset_id`, `next_snap_id`, `total_blocks`. |
| 416 | 8 | `ub_free_blocks` | Free-block accounting. |
| 424 | 1 | `ub_redundancy_kind` | `NONE / MIRROR / RS / LRC`. |
| 425 | 15 | `ub_redundancy_params` | Mode-specific parameters. |
| 440 | 512 | `ub_key_schema` | Header + bptr into keyschema sub-tree. |
| 952 | 1 | `ub_device_class` | `SSD / HDD / PMEM / ZNS`. |
| 953 | 1 | `ub_device_role` | `DATA / LOG / CACHE / SPARE`. |
| 960 | 2048 | `ub_roster[2048]` | 64 × 32 B roster entries. |
| 3008 | 32 | `ub_merkle_root_salt` | Per-pool random salt. |
| 3040 | 8 | `ub_alloc_root_gen` | Gen at which alloc-root tree was encrypted. |
| 3048 | 64 | `ub_scrub_state` | v8: durable scrub state (P5-durable-cursors). Layout: u8 state + u8 reserved + le16 cursor_device_id + 4 reserved + le64 cursor_start_block + le64 ×6 counters (verified, failed, repaired, unrepairable, ranges_processed, snapshot_cursor). Pack/unpack via `stm_ub_scrub_state_pack/_unpack`. Refreshed at every `sync_commit` if a scrub handle is bound (cb registered via `stm_sync_set_scrub_persist_cb`); otherwise round-trips. |
| 3112 | 952 | `ub_reserved` | Future fields. |
| 4064 | 32 | `ub_csum` | BLAKE3 over bytes [0, 4064). |

`_Static_assert(sizeof(stm_uberblock) == 4096)` catches accidental
padding on build.

### Roster entry (32 B each, 64-entry fixed array)

```
[0..16)   uuid[16]
[16..24)  size_bytes (le64)
[24..25)  role                 (stm_device_role)
[25..26)  class                (stm_device_class)
[26..27)  state                (stm_device_state)
[27..32)  reserved
```

`ub_roster_hash` (le64 truncation of BLAKE3-256 over the 2048-byte
roster array) provides a quick-check at mount: the in-RAM pool
must have a matching `roster_hash` or sync refuses to proceed
(P5-1 roster-consistency check).

### Block pointer (stm_bptr, 64 B)

```
bp_paddr    (le64)         // (device_id << 48) | block_offset
bp_kind     (u8)           // stm_bptr_kind — INTERNAL / LEAF / EXTENT / ALLOC / SNAP / CAS / KEYSCHEMA / ALLOC_ROOTS
bp_flags    (u8)
bp_reserved1[6]
bp_csum[32]                // BLAKE3-256 over referenced node/extent (AEAD tag for encrypted targets)
bp_reserved2[16]
```

Paddr = (16-bit device, 48-bit offset-in-blocks). Top 16 bits
encode which device holds the block. Helpers:
`stm_paddr_make(dev, offset)`, `stm_paddr_device(p)`,
`stm_paddr_offset(p)`.

### Encoding / decoding

```c
// Encode stm_uberblock struct → 4 KiB buffer. Finalizes ub_csum.
stm_status stm_ub_encode(const stm_uberblock *ub, void *buf, size_t buf_len);

// Decode 4 KiB → struct. Verifies magic, version, csum.
// Returns STM_ENOENT on magic-mismatch (empty slot),
//         STM_EBADVERSION on version mismatch,
//         STM_ECORRUPT on csum mismatch,
//         STM_EINVAL on size-mismatch.
stm_status stm_ub_decode(const void *buf, size_t buf_len, stm_uberblock *out_ub);
```

`ub_encode` zeroes `ub_csum`, BLAKE3s the rest, writes the digest.
`ub_decode` rejects `ub_gen == 0` (R14 P3-3 — zero-gen sentinel),
checks version == `STM_UB_VERSION` strictly (no forward-compat).

### Label scanning

```c
// Compute the byte offsets of the 4 label regions given device size.
stm_status stm_label_offsets(uint64_t dev_size, uint64_t out_offsets[STM_LABELS_PER_DEVICE]);

// Read a single uberblock from (label, slot). Fast-path for targeted reads.
stm_status stm_sb_label_read(stm_bdev *d, uint32_t label, uint32_t slot, stm_uberblock *out);
stm_status stm_sb_label_write(stm_bdev *d, uint32_t label, uint32_t slot, const stm_uberblock *ub);

// Scan every (label, slot) on a device, return the single uberblock with
// highest valid ub_gen. Used at mount. Returns STM_ENOENT if no valid UB.
stm_status stm_sb_mount_scan(stm_bdev *d,
                              stm_uberblock *out, uint32_t *out_lbl, uint32_t *out_slot);
```

## Commit protocol (sync)

### Multi-device 2-phase (P5-2, quorum-backed)

```
Fresh pool (auth_gen == 0):   1-phase — write UB at gen=1 to all devices.
Subsequent commits:           2-phase.

Phase 1: Reservation
    For each pool device in parallel:
        compute (label, slot) for gen = auth+1
        build per-device UB (shared bytes + per-device uuid, device_id)
        stm_bdev_write(bd, offset_of(label, slot), ub)
        stm_bdev_fsync(bd)
    Wait for quorum = floor(N/2) + 1 confirmations.
    If sub-quorum: abort; return STM_EQUORUM.
    (Reservation UB content = previous authoritative UB's content
     with gen bumped — pre-flush roots; rollback target.)

Phase 2: Flush
    stm_keyschema_commit(ks, target_gen)     // persist key-schema if dirty
    For each attached alloc in allocs[]:
        stm_alloc_commit(alloc, target_gen)   // persist per-device tree
    stm_alloc_roots_commit(roots, target_gen) // persist pool-level roots object
    // Bootstrap pools' bitmap states become durable here via
    // stm_alloc_commit's internal bootstrap_commit.

Phase 3: Final
    Build final UB: post-flush roots + post-flush Merkle.
    Same per-device fan-out as Phase 1.
    Wait for quorum confirmations.
    If sub-quorum: abort; in-RAM state unchanged (rollback UB at auth+1 is durable).

Phase 4: Publish
    auth_gen := auth + 2
    current_gen := auth + 2       // "next commit's final gen"
```

Each commit advances `auth_gen` by 2. Mount-claim advances by 1.

### Mount flow

```
1. For each device in pool: stm_sb_mount_scan → (highest valid ub_gen, ub).
2. Compute authoritative gen:
     sort valid gens desc
     auth = gens[quorum - 1]        // kth largest, where k = floor(N/2)+1
   Quorum < k: return STM_EQUORUM.
3. Content-quorum check (R14 P1):
     Group visible UBs at auth_gen by byte-equal shared fields.
     Largest group must be ≥ quorum, else ContentQuorumAtGen violated.
     Devices outside the quorum group are orphans (ARCH §5.8) — their
     UBs at auth_gen are discarded, overwritten by next commit.
4. Roster consistency:
     ub_pool_uuid == pool.uuid
     ub_device_uuid == pool.devices[ub.device_id].uuid
     ub_roster_hash == BLAKE3(pool.roster_bytes)
   Any mismatch → STM_EROSTER.
5. MountGenBump + claim:
     claim_gen = auth + 1
     For each online device: write a claim UB at claim_gen (quorum required).
     auth_gen := claim_gen.
     current_gen := claim_gen + 2                // next commit's target
6. stm_keyschema_load_at(&ub_key_schema.ks_root)
7. stm_alloc_roots_load(ub.ub_alloc_root)
   For each roots-object entry (dev, tree_paddr, csum, tree_gen):
       stm_alloc_load_tree_at(allocs[dev], tree_paddr, tree_gen, csum)
```

`MountGenBump` (sync.tla) is the invariant: every mount must advance
the durable gen past any in-flight gens that could have been written
by a previous process. Prevents crash-recovery nonce reuse.

### Uberblock build helper

```c
static stm_status build_uberblock(stm_sync *s, uint64_t gen, uint16_t target_device_id,
                                   stm_uberblock *ub);
```

Fills in shared bytes (pool_uuid, roster, counters, merkle_root,
bptrs) from sync's in-RAM state, then stamps per-device bytes
(`ub_device_uuid`, `ub_device_id`). Used for both reservation and
final UBs — the two differ only in `ub_gen` and the root bptrs
(pre-flush vs post-flush).

Critical: reservation UB carries the PREVIOUS authoritative UB's
roots (pre-flush state). Final UB carries the NEW roots (post-
flush). The reservation is the rollback target — if Phase 3 fails,
the reservation UB at auth+1 is the pool's durable state.

### Attach APIs for multi-device

```c
stm_status stm_sync_attach_alloc(stm_sync *s, uint16_t device_id, stm_alloc *alloc);

stm_status stm_sync_reserve_mirror(stm_sync *s, uint64_t nblocks,
                                      size_t n_replicas, uint64_t out_paddrs[]);

stm_status stm_sync_mirror_write(stm_sync *s, const uint64_t paddrs[],
                                    size_t n, const void *buf, size_t len,
                                    size_t *out_confirmed);

stm_status stm_sync_mirror_read (stm_sync *s, const uint64_t paddrs[],
                                    size_t n, void *buf, size_t len,
                                    const uint8_t expected_csum[32]);
```

See [08-pool-redundancy.md](08-pool-redundancy.md) for the mirror
protocol details.

### Per-dataset keys

```c
stm_status stm_sync_add_dataset_key    (s, dataset_id, wk_or_janus, &new_key_id);
stm_status stm_sync_rotate_dataset_key (s, dataset_id, wk_or_janus, &new_key_id, &old_key_id);
stm_status stm_sync_keyschema_sweep    (s, dataset_id, &pruned_count);
stm_status stm_sync_get_dek            (s, dataset_id, key_id, dek_out[32]);
size_t     stm_sync_dek_count          (const stm_sync *s);
```

`wk_or_janus` is a union — exactly one must be non-NULL. `wk` is
the in-process keyfile path; `janus` routes through the remote
unwrap daemon (see [janus](#janus-interaction) below).

### Scrub + device-lifecycle composition

```c
stm_pool  *stm_sync_pool (const stm_sync *s);        // P5-5-α scrub
stm_alloc *stm_sync_alloc(const stm_sync *s, uint16_t dev);

stm_status stm_sync_evacuation_step (s, target, survivor, &old_paddr, &new_paddr);
stm_status stm_sync_remove_device   (s, device_id, redundancy_floor);
stm_status stm_sync_finish_evacuation(s, device_id);
stm_status stm_sync_replace_device_online(s, old_id, new_device, new_alloc, floor, &new_id);
```

See [08-pool-redundancy.md](08-pool-redundancy.md).

## Lock composition

`sync` owns an internal `pthread_mutex_t`. Global lock order (from
`pool.h`):

```
POOL  (rwlock)   ← outer
SYNC  (mutex)
ALLOC (mutex)
```

Every sync API that touches pool state wraps the critical section:

```c
stm_pool_lock_shared(s->pool);      // POOL OUTER
pthread_mutex_lock(&s->lock);       // SYNC INNER
... do work ...
pthread_mutex_unlock(&s->lock);
stm_pool_unlock_shared(s->pool);
```

Safe-removal wrappers (`stm_sync_remove_device`,
`stm_sync_finish_evacuation`) hold pool.wrlock + sync.lock
atomically so add / attach / commit / detach composes in one step.

## Spec cross-reference

| Spec | Pins |
|---|---|
| `sync.tla` | Single-device four-phase commit (legacy; superseded by quorum.tla in P5-2 but kept for spec-to-code clarity). `DoFlush / DoFinal / DoPublish`, `MountGenBump`. |
| `quorum.tla` | Multi-device 2-phase + mount-claim. `QuorumSafety`, `AuthoritativeMono`, `CommitAtomic`, `OrphansNotAuthoritative`, `ContentQuorumAtGen`, `LiveCoordTargetValid`, `QuorumDurability`, `MountGenBumpMulti`. Fixed config: 36839 states at depth 35. Buggy config (`IdempotentRetry=FALSE`, `MaxRetries≥2`) reproduces R14 P1 content-divergence at spec level. |
| `merkle.tla` | Merkle chain integrity: tamper of any covered node changes `ub_merkle_root`. |

## Tests

| Suite | Count | Coverage |
|---|---|---|
| `test_sb` | 18 | Encode / decode roundtrip; csum tamper rejected; magic tamper → STM_ENOENT; version tamper → STM_EBADVERSION; zero-gen rejected; label offsets; label_read / label_write; mount_scan picks highest valid. |
| `test_sync` | 19 | Single-device commit + remount; MountGenBump; alloc-root tree encoded under correct key; version boundary refusals. |
| `test_sync_multi` | 42 | 3-device quorum roundtrip; 1-of-3 device loss tolerated; sub-quorum refused (STM_EQUORUM); orphan-ahead-of-quorum ignored; content-quorum tested; alloc-roots indirection; v5/v6/v7 version refusals (the v5 test exercises one prior version; impl rejects all non-`STM_UB_VERSION` uniformly); mirror(2) + mirror(3) roundtrips + tampered-replica fallback; reserve refuses NONE profile; attach_alloc arg validation; RO pool refuses write ops; wedge refusal; keyschema idempotent commit produces byte-identical UBs; replace_device_online resume from step-3 commit failure; same-uuid-different-alloc refused; slot-0 spoofing refused; multi-retry converges; **commit succeeds with one FAULTED device** (R21 P1); replace-claim blocks concurrent mutators on the claimed slot via sync-wrapper bypass-closed (R23 P3-4). |

## Status

- [x] Uberblock encode / decode / csum / magic / version.
- [x] Label offsets + label read / write / mount_scan.
- [x] Single-device 4-phase commit (P3).
- [x] Multi-device 2-phase quorum commit (P5-2).
- [x] Content-quorum agreement check (R14).
- [x] Mount-claim + MountGenBump.
- [x] Attach-alloc + reserve-mirror + mirror_write + mirror_read.
- [x] Per-dataset key add / rotate / sweep / get_dek.
- [x] Device-lifecycle composition (evac / remove / replace / fail / rejoin).
- [x] Wedge + read-only guards.
- [x] Per-pool rwlock composition (P5-4b-ii-β).
- [x] Scrub accessors (`stm_sync_pool`, `stm_sync_alloc`).
- [ ] **RS / LRC redundancy profiles**: `STM_RED_RS`, `STM_RED_LRC`
      refused with `STM_ENOTSUPPORTED` at create-time. Post-P5 work.
- [ ] **Async commit fan-out**: sync ops today. `block.h` async API
      is wired but sync_commit doesn't use it. Phase 6+ perf pass.
- [ ] **Pool-config mirror** in slot 63: reserved, unused.
- [ ] **Dynamic metadata primary**: sync hard-codes device 0 as the
      metadata primary (keyschema lives on device 0's bootstrap,
      alloc-roots lives on device 0). Cannot remove device 0 today
      (`STM_ENOTSUPPORTED`). Refactor deferred to post-P5.

## Janus interaction

The `janus` module (`src/janus/`, `include/stratum/janus.h`) is the
remote key-wrap daemon client. Every key operation in sync can
route either through `wk` (in-process keyfile) or `janus` (9P
over Unix socket to a separate daemon process). The two paths
are mutually exclusive per call — `sync_create` / `_open` /
`_add_dataset_key` / `_rotate_dataset_key` all take both and refuse
unless exactly one is non-NULL.

Janus provides stronger security (the daemon can hold the wrap
SK in a separately-privileged process; the filesystem never sees
it in plaintext). Keyfile is simpler (good for local tests).

Not in scope for this reference — see ARCHITECTURE §7.7.3 for the
daemon design.

## Known caveats

- **First commit is 1-phase** (`auth == 0`). Subsequent commits are
  2-phase. The asymmetry is unusual but intentional — there's no
  pre-flush state to preserve on rollback for a fresh pool.
- **Per-device tree gens can diverge** when `stm_alloc_commit`
  short-circuits on a clean tree (R7c P2-5). `ub_alloc_root_gen`
  (v3→) and per-entry `root_gen` in the alloc-roots object
  (v6→v7) carry the correct gen for AEAD decryption at mount.
- **Content-quorum check is byte-level** on shared UB bytes — any
  non-determinism in `build_uberblock` (e.g. uninitialized padding)
  would cause false divergence. Tests pin that UBs are byte-
  identical across devices at the same gen.
- **Mount-claim requires quorum** — if a majority of devices are
  down or corrupt at mount time, mount fails. ARCH §5.11 describes
  a future emergency-mount mode that accepts sub-quorum with admin
  opt-in; not yet implemented.
- **`ub_reserved[1016]`** is the migration reserve for future
  format fields. Adding a field carves from this region, bumps
  `STM_UB_VERSION`, and gates the v(n)→v(n+1) migration at mount.
