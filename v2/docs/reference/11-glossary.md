# 11 — Glossary

Terms, acronyms, and invariant names used across the codebase and
this reference. Cross-referenced to the reference chapter that
documents them in depth.

## Primitives

| Term | Meaning | See |
|---|---|---|
| **AEAD** | Authenticated Encryption with Associated Data. Symmetric cipher + MAC bundle — encrypt binds a ciphertext to a key, nonce, and associated data such that tamper is detectable. | [01-crypto](01-crypto.md) |
| **AEGIS-256** | Hardware-accelerated AEAD used by default on CPUs with AES-NI or ARMv8 crypto extensions. 32-byte key, 32-byte nonce, 32-byte tag. | [01-crypto](01-crypto.md) |
| **AD** | Associated Data — unencrypted bytes bound to a ciphertext via the AEAD MAC. Stratum uses it to tie metadata-node ciphertexts to `(pool_uuid, device_uuid)` so cross-device replay fails. | [01-crypto](01-crypto.md) |
| **ASan** | AddressSanitizer. Compile-time instrumentation catching heap / stack / use-after-free bugs. One of three CI matrix configurations. | [00-overview](00-overview.md) |
| **Argon2id** | Memory-hard passphrase-to-key function. Used to derive the wrap-key-derivation seed at pool create / rekey. | [01-crypto](01-crypto.md) |
| **BLAKE3** | Cryptographic hash (32 B output, tree-friendly, ~2–6 GB/s/core). Stratum's Merkle chain, bp_csum values, and truncated node csums are BLAKE3. | [01-crypto](01-crypto.md) |
| **bdev** | `stm_bdev` — the block device abstraction. One per physical device / loopback file. | [02-block](02-block.md) |
| **Bε-tree** | Bounded-epsilon tree. B+tree variant with message buffers at internal nodes, amortizing writes across levels. Stratum's metadata data structure. | [03-btree](03-btree.md) |
| **bp_csum** | BLAKE3-256 over a block pointer's target. Stored inside `stm_bptr`, forms the Merkle chain. For AEAD-encrypted targets, the AEAD tag acts as bp_csum. | [07-sb-sync](07-sb-sync.md) |
| **bptr** | `stm_bptr`, 64-byte block pointer: paddr + kind + flags + csum. | [07-sb-sync](07-sb-sync.md) |
| **Bw-tree** | Lock-free Bε-tree variant with CAS-built delta chains. Readers walk chains pinned by EBR; writers CAS-prepend. | [03-btree](03-btree.md) |
| **CAS** (atomic) | Compare-and-swap atomic primitive. Used ubiquitously in the Bw-tree. | [03-btree](03-btree.md) |
| **CAS** (storage) | Content-addressable storage — future dedup tier. Not confused with the above from context. | ARCH §7.16 |
| **CSPRNG** | Cryptographically-secure pseudo-random number generator. `stm_random_bytes` wraps libsodium's `randombytes_buf`. | [01-crypto](01-crypto.md) |
| **DEK** | Data Encryption Key. Per-dataset symmetric key. Wrapped blob on disk, unwrapped in RAM when a dataset is open. | [06-keyschema](06-keyschema.md) |
| **EBR** | Epoch-Based Reclamation. Lock-free memory-reclamation scheme enabling `btree_lf` to retire old chains safely. | [04-ebr](04-ebr.md) |
| **HKDF-SHA256** | RFC 5869 key derivation function. Used to derive the PQ-hybrid wrap key from the X25519 + ML-KEM-768 shared secrets. | [01-crypto](01-crypto.md) |
| **HMAC-SIV** | Stratum's XChaCha20-SIV construction — HMAC-SHA256 acts as the SIV tag generator over the full nonce, AD, and plaintext. | [01-crypto](01-crypto.md) |
| **HPKE** | Hybrid Public-Key Encryption (RFC 9180). Stratum's hybrid wrap is HPKE-inspired but not spec-compliant. | [01-crypto](01-crypto.md) |
| **io_uring** | Linux async I/O submission ring. One of the `stm_bdev` backends. | [02-block](02-block.md) |
| **jaanus** | Remote key-wrap daemon. Mutually exclusive with the in-process keyfile path for any key op. | [07-sb-sync](07-sb-sync.md) |
| **Merkle chain** | Hash of hashes: each metadata node's bp_csum covers its children, ultimately chaining to `ub_merkle_root`. Tamper of any covered node changes the root. | [01-crypto](01-crypto.md), [07-sb-sync](07-sb-sync.md) |
| **MLKEM-768** | ML-KEM-768 (NIST FIPS 203). Post-quantum key-encapsulation mechanism used in the hybrid wrap. Optional — graceful fallback to zero-padded slots if liboqs absent. | [01-crypto](01-crypto.md) |
| **Nonce** | In AEAD context, the 32-byte input that must be unique per `(key, op)` pair. Stratum's metadata-nonce layout: `paddr || gen || pool_uuid`. | [01-crypto](01-crypto.md) |
| **paddr** | Physical address — 64-bit value = `(16-bit device_id << 48) | 48-bit block_offset`. | [07-sb-sync](07-sb-sync.md) |
| **Poly1305** | 16-byte MAC used by XChaCha20-Poly1305. Used in `stm_hybrid_wrap`'s AEAD envelope. | [01-crypto](01-crypto.md) |
| **Roster** | The per-pool device list, up to 64 slots. Persisted in every uberblock's `ub_roster[2048]`. | [08-pool-redundancy](08-pool-redundancy.md) |
| **roster_hash** | le64 truncation of BLAKE3 over the 2048-byte roster. Witness for add/remove churn. | [08-pool-redundancy](08-pool-redundancy.md) |
| **TLA+** | Formal-specification language (Leslie Lamport). Stratum's 13 specs are TLA+. TLC model-checker verifies them at bounded scopes. | [10-specs](10-specs.md) |
| **TSan** | ThreadSanitizer. Compile-time instrumentation catching data races. CI matrix config. | [00-overview](00-overview.md) |
| **uberblock** | 4 KiB on-disk struct holding pool metadata roots + counters for one commit. 63 slots per label × 4 labels per device. | [07-sb-sync](07-sb-sync.md) |
| **wk** | `stm_hybrid_keys` — wrap keypair (PK + SK). 1216-byte PK, 2432-byte SK. In-process path (as opposed to janus). | [07-sb-sync](07-sb-sync.md) |
| **X25519** | Classical elliptic-curve DH. Classical half of the PQ-hybrid wrap. | [01-crypto](01-crypto.md) |
| **XChaCha20-SIV** | Stratum's custom nonce-misuse-resistant AEAD. 64-byte key (K_MAC ‖ K_ENC), 32-byte nonce, 16-byte tag. | [01-crypto](01-crypto.md) |
| **xxHash3** | Fast non-cryptographic hash. Used for `se_xxh` on unencrypted extents and in-memory structural hashing. | [01-crypto](01-crypto.md) |

## Protocol terms

| Term | Meaning | See |
|---|---|---|
| **auth_gen** | Most-recent committed final gen with quorum. 0 on fresh pool. Commits advance by 2; mount-claim by 1. | [07-sb-sync](07-sb-sync.md) |
| **commit ring** | The circular 63-slot-per-label × 4-label UB rotation. `label = gen % 4; slot = gen % 63`. | [07-sb-sync](07-sb-sync.md) |
| **content-quorum** | Byte-level agreement of shared UB fields across ≥quorum devices at `auth_gen`. Violating pools are rejected at mount (R14). | [07-sb-sync](07-sb-sync.md), [10-specs](10-specs.md) |
| **EvacuationAtomic** | Spec invariant (evac.tla): every block has ≥`MirrorN` replicas on non-REMOVED devices at every reachable state. | [10-specs](10-specs.md) |
| **gen** | Generation counter — monotonic per commit. 1 for fresh pool's first commit; `auth + 2` for subsequent commits. | [07-sb-sync](07-sb-sync.md) |
| **MountGenBump** | Spec invariant (sync.tla, quorum.tla): every mount must advance the durable gen past any in-flight gen from a previous process. Load-bearing for nonce uniqueness across crash recovery. | [10-specs](10-specs.md) |
| **orphan gen** | A gen at which fewer than quorum devices hold a valid UB; never authoritative; overwritten by the next commit. | [07-sb-sync](07-sb-sync.md) |
| **PENDING** | Alloc-tree entry state: `refcount == 0`, awaiting `sync_commit` sweep. Bitmap bit stays set. | [05-bootstrap-alloc](05-bootstrap-alloc.md) |
| **Quorum** | `⌊N/2⌋ + 1` of pool devices. Required for Phase 1 reservation + Phase 3 final + mount-claim. | [07-sb-sync](07-sb-sync.md) |
| **reservation UB** | Phase 1 UB at `gen = auth+1` carrying the PREVIOUS authoritative UB's roots. Rollback target if Phase 3 fails. | [07-sb-sync](07-sb-sync.md) |
| **safe removal** | Sync-layer wrappers that probe alloc drain before pool state transition. `stm_sync_remove_device`, `stm_sync_finish_evacuation`. | [08-pool-redundancy](08-pool-redundancy.md) |
| **verify-callback** | Caller-supplied per-block classification function (P5-5-β). Returns OK / REPAIRED / UNREPAIRABLE; encapsulates the bptr-aware redundancy iteration. Future P6 extent manager plugs the production cb. | [09-scrub](09-scrub.md) |
| **CallbackSetExclusivity** | Spec invariant (scrub.tla): the four scrub counters split cleanly by mode. α (no cb) keeps `repaired`/`unrepairable` at 0; β (cb installed) keeps `failed` at 0. | [10-specs](10-specs.md) |
| **wedge** | Runtime state where sync refuses all mutations because an in-flight rollback itself failed. `STM_EWEDGED`. | [07-sb-sync](07-sb-sync.md) |

## Device states

| State | Meaning |
|---|---|
| `UNSET` | Slot header before `add_device`; not a live state. |
| `ONLINE` | Normal operating state; participates in commit + mirror. |
| `OFFLINE` | Reserved; no current API emits. |
| `DEGRADED` | Reserved; no current API emits. |
| `FAULTED` | Admin- or fault-triggered. Excluded from `mirror_read`; bdev retained for rejoin. |
| `REMOVED` | Device detached from pool; bdev = NULL; UUID preserved for burned-UUID tracking. |
| `EVACUATING` | Draining its replicas onto survivors; excluded from new reserves. Transitions to REMOVED on `finish_evacuation`. |

## Status codes (selective)

| Code | Meaning |
|---|---|
| `STM_OK` | Success. |
| `STM_EINVAL` | Shape / arg validation. |
| `STM_ENOENT` | Not found (e.g. tree entry, UB slot). |
| `STM_EEXIST` | Duplicate (e.g. UUID collision in roster). |
| `STM_EBUSY` | Resource in wrong state to accept op (e.g. tree not drained for safe-remove). |
| `STM_ENOMEM` | Allocation failure. |
| `STM_EROFS` | Read-only pool refusing mutation. |
| `STM_EQUORUM` | Multi-device commit failed to reach quorum. |
| `STM_ECORRUPT` | On-disk corruption detected (csum / Merkle / format). |
| `STM_EBADTAG` | AEAD tag verification failed. |
| `STM_EBADVERSION` | On-disk format version unsupported. |
| `STM_ERANGE` | Caller buffer too small / value out of range. |
| `STM_ENOTSUPPORTED` | Feature reserved but not yet implemented (e.g. RS / LRC, dev 0 removal). |
| `STM_EWEDGED` | Sync handle wedged (post-rollback-of-rollback failure). |
| `STM_EIO` | Underlying block device I/O error. |

## Phase numbering

| Phase | Scope |
|---|---|
| 0 | Design docs (VISION / COMPARISON / NOVEL / ARCHITECTURE / ROADMAP-V2). |
| 1 | Crypto + hash + block + CMake + TLA+ infrastructure. |
| 2 | Bε-tree + Bw-tree + EBR + R0-R5 audits. |
| 3 | Single-device sync + uberblock + allocator + R6-R12 audits. |
| 4 | AEAD-AD + per-extent integrity + keyschema + PQ-hybrid wrap + janus + R13-R14b audits. |
| 5 | Multi-device pool + quorum commit + mirror(n) + device lifecycle + scrub (α + β) + R15-R23+ audits. |
| 6 | Namespace (datasets / snapshots / clones / dead-list). |
| 7 | Extent layer + cold-tier (CAS) + send/recv + reflinks. |
| 8 | 9P / FUSE surface. |
| 9+ | Post-MVP (RS/LRC, tiering, send/recv, encryption-at-rest-with-rotation sweep). |

## Audit round names

Each round audits a specific change surface. Closed-list preamble
files (in user memory) track which P0/P1/P2/P3 findings each round
resolved — auditors consult these so they don't re-report already-
closed items.

| Round | Scope | Tip at close |
|---|---|---|
| R0-R14b | v1 tree audits + R14b's P5-2 fix review. | (v1-era; see memory/audit_r15_closed_list.md + audit_v2_r0_closed_list.md) |
| R15 | P5-3 scope (mirror redundancy). | `dd8a275` |
| R16 | P5-4a scope (add_device + metadata_nonce.tla). | `a93ce5d` |
| R17 | P5-4b scope (remove + evacuation). | `350e144` |
| R18 | P5-4b-ii-β scope (per-pool rwlock). | `3c370c5` |
| R19 | P5-4c-α scope (replace_device_online). | `9207ae7` |
| R20 | P5-5-α scope (scrub verify-only). | `25d7c4a` |
| R21 | P5-6 full-phase audit. | `3edeb69` |
| R22 | P5-7 scope (replace resume from ADDED-ONLINE). | `e5fe085` |
| R23 | P5-8 scope (replace-in-flight claim + atomic resume). | `5468dac` |
| R24 | P5-5-β scope (scrub repair via cb). | `52503fe` |
| R25 | Backlog hygiene (R23 P3-2 + R20 P3-2/P3-3). | `cd6cb04` |
| R26 | P5-durable-cursors scope (γ scrub + STM_UB_VERSION 7→8). | `a6249eb` |
| R27 | P7-prework FastCDC content-defined chunking. | `a2ffd38` |
| R28 | P6-2 dataset-module C impl scope. | `bdb888b` |
| R29 | P6-3 snapshot-module C impl scope. | `000d394` |
| R30 | P6-4 property API on dataset module. | `8be3628` |
| R31 | P6-persist (dataset + snapshot persistent storage + UB v8→v9). | `bffee62` |
| R32 | P6-clone (clone C impl + UB v9→v10). | `4503405` |
| R33 | P6-deadlist C impl (snapshot dead-list + UB v10→v11). | `d4efeeb` |

## Phase 6 / clone terms

| Term | Meaning |
|---|---|
| **dataset** | A node in the pool's namespace forest. Each has a unique id, parent_id, name, and metadata (created_txg, flags, next_ino, properties). Root is id=1. ARCH §8.3. |
| **clone** | A dataset with a non-zero `origin_snap_id` referencing a snapshot. Structurally a regular dataset; the back-reference enables `clone.tla::SnapWithClonesUndeletable`. ARCH §8.6. |
| **promote** | Operation that clears a clone's `origin_snap_id` to `STM_DATASET_NO_ORIGIN`. After promote, the dataset is no longer a clone; the previously-referenced snap can be deleted if no other clones reference it. ARCH §8.6.2. |
| **CloneOriginPresent** | clone.tla invariant: every present clone's `origin_snap_id` references a present snapshot. Operationally enforced via the snap-delete cb. |
| **SnapWithClonesUndeletable** | clone.tla invariant: a snapshot with one or more present clones cannot be deleted. Enforced through-stack via `stm_snapshot_index_set_clone_check_cb` registered by sync to query `stm_dataset_clones_count_for_snap`. |
| **NO_ORIGIN / NO_PARENT / NO_PREV** | Sentinel values (all `((uint64_t)0)`) for absent references in dataset / snapshot fields. Disambiguate by FIELD they occupy, not by value. |
| **`ub_main_root` / `ub_snap_root`** | Uberblock bptrs for the dataset / snapshot index trees. Populated post-P6-persist (`348d165`); content kinds `STM_BPTR_KIND_DATASET` (=9) and `STM_BPTR_KIND_SNAP` (=5). |
| **`ub_main_root_gen` / `ub_snap_root_gen`** | AEAD gen trackers (le64) for the corresponding trees, symmetric to `ub_alloc_root_gen`. Required for mount-claim UBs that advance `ub_gen` past orphan writes without rewriting the trees. |
| **dead-list** | Per-snapshot list of blocks that have been COW'd-away from the live dataset since the snapshot was created. On snapshot delete, blocks UNIQUE to the snap (not in successor's dead-list) are freed; SURVIVING blocks (in both S's and successor's dead-list) migrate to predecessor's dead-list. Algorithm is O(blocks COW'd during S's lifetime), not O(tree). ARCH §8.5.5; spec `dead_list.tla`. |
| **next_dead** | Synonym for the per-snapshot dead-list (ZFS terminology). The "next" reflects "next snapshot to be deleted will free or migrate these blocks". |
| **most_recent_snap** | The newest PRESENT snapshot. New COW'd blocks are added to its dead-list. After SnapDelete of the most-recent, recomputed by walking PRESENT snaps. |

## Phase 7 / extent terms

| Term | Meaning |
|---|---|
| **extent record** | The 32-byte per-extent metadata `(paddr, write_gen, dlen, clen+comp, xxh)` that maps a logical file byte range to a physical paddr. Lives in a per-(dataset, ino) Bε-tree keyed by file offset. ARCH §11.6.1; spec `extent.tla`. |
| **extent tree** | The per-inode Bε-tree of `(file_offset → extent_record)` mappings. One per inode per dataset. Keyed by `(ino, type=DATA, offset)`. ARCH §11.6.2. |
| **NoOverlapWithinIno** | extent.tla load-bearing invariant: no two extents in the same `(ds, ino)` cover overlapping byte ranges. A read at any offset resolves to exactly one extent or a hole. |
| **PaddrFreshness** | extent.tla invariant: every extent's paddr is in `used_paddrs`, which grows monotonically. With Write/Overwrite refusing previously-used paddrs, no two extents share a paddr at any time. Composes with allocator.tla::NoReuseInSameGen for end-to-end (paddr, gen)-pair nonce uniqueness. |
| **OverwriteBlock cb (extent → snapshot)** | When extent.tla::Overwrite drops an extent, the C impl calls `stm_snapshot_index_overwrite_block(paddr)` to either route the paddr into the most-recent snap's dead-list or signal the caller to free directly. The composition between extent.tla and dead_list.tla is realized at the C-impl boundary. |

## Policy terms

| Term | Meaning |
|---|---|
| **audit-triggering change** | A change to one of the surfaces listed in CLAUDE.md requires spawning an adversarial soundness audit before merge. |
| **spec-first policy** | Any feature touching a load-bearing invariant models in TLA+ FIRST; code implements against the verified spec. |
| **closed list** | File-per-round in user memory tracking P0/P1/P2/P3 findings that were resolved. Auditors consult these to avoid re-reporting. |
| **idempotent commit** | A commit pattern where a clean-state commit returns the previous (paddr, csum) without writing new bytes. Preserves quorum's `ContentQuorumAtGen` across retries. |
| **burned UUID** | A device UUID that was once in the pool roster and is now REMOVED. Cannot be re-added — would collide with historical AEAD nonces written under that device's metadata_key. |
