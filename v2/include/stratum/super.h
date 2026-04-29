/* SPDX-License-Identifier: ISC */
/*
 * Superblock / uberblock on-disk format.
 *
 * ARCHITECTURE §5: the pool's per-device label layout + the 4 KiB
 * uberblock that sits in every ring slot. Each commit produces a new
 * uberblock; mount selects the authoritative one by gen + quorum.
 *
 * This header is the canonical format definition. Any change to field
 * positions or sizes is a format change, bumping STM_UB_VERSION and
 * requiring the feature-flags dance described in ARCHITECTURE §5.2
 * (compat / ro-compat / incompat). We use _Static_assert below to
 * wedge the struct sizes so accidental padding changes get caught at
 * compile time.
 *
 * Endianness: every multi-byte number is little-endian. Access via
 * stm_load_le* / stm_store_le* in types.h; never cast directly.
 *
 * Phase 3 MVP (this file) defines the layout + encode/decode. The
 * semantics of individual fields (tree roots, roster management,
 * merkle root) fill in as subsequent Phase 3 and Phase 4 work lands.
 * Unused fields in Phase 3 tests are zeroed.
 */
#ifndef STRATUM_V2_SUPER_H
#define STRATUM_V2_SUPER_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================= */
/* Constants.                                                                 */
/* ========================================================================= */

/* 8-byte magic at the head of every uberblock. ASCII "STRATUM2" — as an
 * on-disk little-endian uint64 the bytes read S,T,R,A,T,U,M,2 in order
 * when viewed with `xxd` on the raw block. */
#define STM_UB_MAGIC          UINT64_C(0x324d555441525453) /* "STRATUM2" */

/* Format version. Bumped on incompatible layout changes.
 *
 * v1 → v2 (Phase 4 chunk P4-1): carved ub_merkle_root_salt[32]
 * from ub_reserved (unchanged offset; field size shrunk). v1 pools
 * had this region zero, so v2 readers cannot treat a v1 uberblock
 * as having a populated salt — hence the version bump.
 *
 * v2 → v3 (Phase 4 chunk P4-3b R9 P0-1): carved
 * ub_alloc_root_gen[8 bytes le64] from ub_reserved. Records the
 * gen at which ub_alloc_root's tree was AEAD-encrypted — may
 * differ from ub_gen when a mount-claim UB advances the gen
 * counter past orphan metadata writes without rewriting the tree.
 * v2 pools had this region zero, which AEAD-decrypts as nonce
 * gen=0 — would fail-loud at mount, but the version bump makes
 * the intent explicit and refuses v2 mounts up-front.
 *
 * v3 → v4 (Phase 4 chunk P4-4a): ub_key_schema[512] repurposed
 * from a raw bytes slot holding a plaintext pool key into a
 * structured header + bptr pointing at a Merkle-chained key-schema
 * sub-tree (ARCH §7.7.3). Wrapped dataset keys now live in the
 * sub-tree, never on disk in plaintext. Pool mounts now require a
 * keyfile (the "file" backend; janus replaces this in P4-4b).
 *
 * v4 → v5 (Phase 5 chunk P5-1): ub_roster[2048], ub_roster_hash,
 * ub_device_count, ub_device_id, ub_device_class, ub_device_role
 * become mandatory and populated for every pool (ARCH §4.3, §5.13).
 * A v5 pool's uberblock carries the full device roster on every
 * device — any single device is sufficient to reconstruct pool
 * membership (and to mount under emergency recovery per ARCH §5.11).
 * Degenerate single-device pools (N=1) carry a 1-entry roster.
 * Multi-device commit semantics land in P5-2; P5-1 is spec + roster
 * persistence only. v4 pools had these fields zero — unambiguous
 * rejection at v5 mount. No feature-flag allocation; the version
 * bump alone gates the format change per ARCH §5.9.
 *
 * v5 → v6 (Phase 5 chunk P5-3b): `ub_alloc_root` now points at the
 * pool-level allocator-roots object (ARCH §6.1), NOT at a single
 * device's allocator tree. The roots object is itself a small
 * Bε-tree stored on device 0's bootstrap pool, keyed by device_id
 * and valued with each device's alloc-tree root (paddr + csum). The
 * bp_kind at ub_alloc_root changes from STM_BPTR_KIND_ALLOC (a leaf
 * of the allocator tree) to STM_BPTR_KIND_ALLOC_ROOTS (the roots
 * object). v5 pools loaded under v6 code would try to interpret the
 * alloc-tree leaf as a roots object → AEAD-decrypt-pass but value
 * format mismatch, catching at entry-decode time. The version bump
 * gates this unambiguously up-front. No feature-flag allocation
 * (version bump alone per ARCH §5.9).
 *
 * v6 → v7 (Phase 5 chunk P5-3c + R15 F6): roots-object leaf value
 * layout extends 40 → 48 bytes (per-entry le64 `root_gen` appended
 * after paddr + csum). Each device's alloc tree may be encrypted at
 * a gen different from the roots object's own gen when alloc_commit's
 * R7c P2-5 short-circuits on a clean tree; the per-entry gen lets
 * mount-time attach_alloc pass the correct AEAD nonce. A v6 pool's
 * 40-byte leaf values would length-check-fail at the v7 reader's
 * decode_val (AR_VAL_LEN = 48 assertion). Version bump gates this
 * up-front with STM_EBADVERSION at mount, same policy as v5 → v6.
 * Feature-flag bump unnecessary (full version bump per ARCH §5.9).
 *
 * v7 → v8 (Phase 5 P5-durable-cursors): `ub_scrub_state[64]` carved
 * from the head of `ub_reserved`, persisting the in-RAM scrub state
 * across mount (ARCH §7.14.1, ROADMAP §8.2 criterion 4). On every
 * sync_commit the current scrub (state, cursor_device_id,
 * cursor_start_block, blocks_verified, blocks_failed, blocks_repaired,
 * blocks_unrepairable, ranges_processed, snapshot_cursor) is written
 * to this region; on mount the state is restored. Evacuation does
 * NOT need its own durable region — it's already implicitly durable
 * via roster (`ub_roster[]` carries device_state) + per-device
 * alloc tree (carries the un-evacuated blocks). v7 pools had this
 * region zero (interpretable as IDLE/zero — but the version bump
 * makes intent explicit and refuses v7 mounts up-front per ARCH §5.9).
 *
 * v8 → v9 (Phase 6 P6-persist): `ub_main_root_gen` (le64) and
 * `ub_snap_root_gen` (le64) carved from `ub_reserved`, recording the
 * AEAD gen at which `ub_main_root` and `ub_snap_root` were last
 * serialized. Symmetric to `ub_alloc_root_gen` (P4-3b R9 P0-1):
 * a sync_open mount-claim UB that advances `ub_gen` past orphan-
 * data writes WITHOUT rewriting the dataset/snapshot trees keeps
 * those trees decryptable by feeding the prior gen into the AEAD
 * nonce (ARCH §3.9.1 nonce-uniqueness). v8 pools had `ub_main_root`
 * and `ub_snap_root` guaranteed-zero (no v8 code populated them),
 * so the v8 → v9 upgrade is content-clean: load path checks
 * `paddr == 0 → no commit yet`. The version bump gates the new
 * field meaning explicitly. No feature-flag bump (full version
 * bump per ARCH §5.9).
 *
 * v9 → v10 (Phase 6 P6-clone): the dataset-tree on-disk value
 * layout grows by 8 bytes for `origin_snap_id` (le64). New layout:
 * `parent_id || created_txg || next_ino || flags || local_set_bitmap
 *  || name_len || local_value[STM_PROP_COUNT] || origin_snap_id ||
 *  name`. Total: 64 + name_len bytes (was 56 + name_len). Non-clone
 * datasets carry `origin_snap_id == 0` (STM_DATASET_NO_ORIGIN
 * sentinel). v9 pools' value layout doesn't accommodate the new
 * field — old decoder length-checks would refuse v10 entries. The
 * version bump gates the new field meaning explicitly. No
 * feature-flag bump (full version bump per ARCH §5.9).
 *
 * v10 → v11 (Phase 6 P6-deadlist): the snapshot-tree on-disk value
 * layout grows by a tail of `le32 dead_count || le64 paddrs[N]`
 * recording the snapshot's incremental dead-list (ARCH §8.5.5,
 * dead_list.tla). New tail per entry: 4 + 8 * dead_count bytes
 * (was 0). Pre-deadlist snapshots carry `dead_count == 0`. v10
 * pools' decoder rejected trailing bytes after `name`, so the v10
 * → v11 upgrade is content-clean (v10 entries with empty dead-list
 * decode identically except for the trailing dead_count = 0 word).
 * The `STM_SNAP_DEAD_LIST_MAX` cap (256 paddrs / snapshot) bounds
 * the in-line tail; chunked storage for very-large dead-lists is
 * deferred to a future extent-aware revision. The version bump
 * gates the new field meaning explicitly. No feature-flag bump
 * (full version bump per ARCH §5.9).
 *
 * v11 → v12 (Phase 7 P7-3): `ub_extent_root` (64-byte stm_bptr) +
 * `ub_extent_root_gen` (le64) carved from the head of `ub_reserved`
 * to anchor the persistent extent index (ARCH §11.6, extent.tla).
 * The extent index is a btree_store-encoded, AEAD-encrypted Bε-tree
 * on device 0; keys are (le64 dataset_id || le64 ino || le64 off),
 * values are 32-byte ARCH §11.6.1 records. v11 pools had this
 * region zero (no v11 code populated extents), so the v11 → v12
 * upgrade is content-clean: `ub_extent_root.bp_paddr == 0` is
 * unambiguously "no commit yet" at load time. The version bump
 * gates the new field meaning explicitly + refuses v11 mounts at
 * v12 to prevent decoders without the extent index from booting
 * a pool whose extents would otherwise be lost on next sync.
 * No feature-flag bump (full version bump per ARCH §5.9).
 *
 * v12 → v13 (Phase 7 P7-6): the extent-tree on-disk value grows
 * 32 → 64 bytes to carry up to STM_EXTENT_MAX_REPLICAS=4 replica
 * paddrs per extent (extent.tla's `replicas` field). New layout:
 *   off 0  : u8  n_replicas (1..4)
 *   off 1  : u8  reserved[7] (zero)
 *   off 8  : le64 paddr_0 (always non-zero)
 *   off 16 : le64 paddr_1 (zero if n_replicas < 2)
 *   off 24 : le64 paddr_2 (zero if n_replicas < 3)
 *   off 32 : le64 paddr_3 (zero if n_replicas < 4)
 *   off 40 : le64 write_gen
 *   off 48 : le32 dlen
 *   off 52 : le32 clen_and_comp
 *   off 56 : le64 xxh
 * The C impl AEAD-encrypts each extent's plaintext once with
 * (paddr_0, gen) as nonce and writes bytewise-identical
 * ciphertext+tag to every paddr_i. The scrub β cb's replica-walk
 * (bptr.tla::ScanRead × RewriteReplica) reads each replica
 * independently, csum-gates per-replica, and rewrites bad replicas
 * from a verified source. v12 pools' 32-byte values would be
 * length-rejected by the v13 decoder (size mismatch) — refuses
 * v12 mounts at v13 via the existing STM_EBADVERSION handler. No
 * feature-flag bump (full version bump per ARCH §5.9).
 *
 * P7-8 (v14, this commit): the per-snapshot value layout grew 8
 * bytes — a new `extent_txg` field captures `sync.current_gen` at
 * SnapshotCreate so send/recv's incremental gen filter can
 * authoritatively bound `extent.gen`. Pre-P7-8 the snap-bounded
 * filter used `created_txg` (snap-index counter), which lives in
 * a different counter space than `extent.gen` (sync gen) — the
 * filter was best-effort only. v13 pools' 48-byte fixed-prefix
 * snapshot values would be length-rejected by the v14 decoder
 * (52-byte fixed prefix); refused via STM_EBADVERSION at mount.
 * Format break, no feature flag.
 *
 * v15 (P7-10, 2026-04): per-dataset DEK enforcement on extents.
 * Extent record gains a `key_id` field (8 bytes le64 at on-disk
 * value offset 56, repurposing the always-zero `xxh` slot from v14)
 * naming which DEK in the dataset's keyschema was used to encrypt
 * the extent. stm_sync_write_extent / _read_extent now resolve the
 * DEK via (dataset_id, key_id) instead of using the per-pool
 * metadata_key. Untampered v14 pools fail at the uberblock version
 * check (`uberblock.c` `version != STM_UB_VERSION` → STM_EBADVERSION)
 * before the extent value layer is reached. Tamper-then-mount
 * scenario (an attacker flips ub_version 14→15 and recomputes
 * ub_csum + the Merkle chain): mount completes, but v14 keyschemas
 * do not have per-dataset DEKs at all (only the pool metadata key
 * (0,0) and any rotated entries from `stm_sync_add_dataset_key`
 * callers; root dataset (1,0) is auto-installed only by v15's
 * sync_create), so writes/reads to ds≥1 fail STM_ECORRUPT/STM_ENOENT
 * at runtime — same DoS posture as a (1,0) wrapped-blob tamper
 * (see R42 P1-1 mount-time hard-fail).
 * Format break, no feature flag.
 *
 * v16 (P7-15, prior commit): repair-log persistence (ARCH §7.15.4 /
 * bptr.tla::LogIntegrity). Adds three fields carved from the head
 * of `ub_reserved`: `ub_repair_log_root` (16-byte stm_bptr, 64
 * bytes total), `ub_repair_log_root_gen` (le64), and
 * `ub_repair_log_next_seq` (le64). Repair events emitted by the
 * production scrub β cb (csum-fail / IO-err on a replica → rewrite
 * from a verified source) persist as append-only entries in a
 * single-leaf btnode rooted at `ub_repair_log_root`. Plaintext +
 * Merkle-covered (matches keyschema sub-tree shape); tree's
 * bp_kind is `STM_BPTR_KIND_REPAIR_LOG`. v15 pools fail at the
 * version check (STM_EBADVERSION) before reaching the new fields.
 * Tamper-then-mount: a v15 pool whose ub_version is flipped to 16
 * + ub_csum recomputed has zeroed `ub_repair_log_root` (sat in
 * `ub_reserved`); load_at treats `root_paddr == 0` as the empty-
 * pool case and seeds the in-RAM index from `ub_repair_log_next_seq`
 * (also previously zero), so the tampered pool comes up with an
 * empty repair-log — no corruption hazard, just a forensic gap
 * for any pre-flip events. Format break, no feature flag.
 *
 * v17 (P7-16, this commit): reflinks (ARCH §11.12 / §8.6.3,
 * extent.tla::Reflink + SharedReplicasAreCohabit). Extent value
 * grows 64 → 96 bytes by adding the (origin_dataset_id, origin_ino,
 * origin_off) triple at offsets 64..87 plus 8 reserved bytes at
 * 88..95. The origin fields name the (ds, ino, off) at which the
 * AEAD ciphertext was first encrypted, so reflink-siblings sharing
 * the same paddrs reconstruct the same AEAD AD at read/scrub time.
 * For freshly-written extents origin equals the live (dataset_id,
 * ino, off) — non-reflinked extents are unchanged in semantics.
 * No uberblock field changes. v16 pools fail at the version check
 * (STM_EBADVERSION) before reaching the new extent value layout.
 * Tamper-then-mount: a v16 pool whose ub_version is flipped to 17
 * has on-disk extent records still at v16's 64-byte value layout;
 * the v17 decoder requires 96-byte values and refuses with
 * STM_ECORRUPT. Format break, no feature flag.
 *
 * v18 (P7-CAS, this commit): content-addressed cold tier (ARCH §6.9 /
 * §7.6.3 / §12.10, NOVEL #3, cas.tla). The CAS-tier index tree root
 * uses the existing `ub_cas_index_root` field at offset 288 (carved
 * out in the original metadata-roots block at v3 alongside
 * `ub_main_root` / `ub_alloc_root` / `ub_snap_root`, but unused
 * until now); the tree's bp_kind is STM_BPTR_KIND_CAS (= 6, also
 * carved at v3). Adds one new uberblock field carved from the head
 * of `ub_reserved`: `ub_cas_index_root_gen` (le64) at offset 3280.
 * Extent value gains a 1-byte `kind` discriminator at value offset 0:
 *   0x01 = HOT (paddr-addressed, v17 layout for bytes 1..95).
 *   0x02 = COLD (hash-addressed; bytes 1..7 reserved zero, bytes
 *           8..39 carry the BLAKE3-256 chunk hash, bytes 40..95
 *           identical to HOT — gen, dlen, clen_and_comp, key_id,
 *           origin triple, link_gen).
 * v17 pools fail at the version check (STM_EBADVERSION) before the
 * new layouts are reached. Tamper-then-mount: a v17 pool whose
 * ub_version is flipped to 18 has zero `ub_cas_index_root` (the
 * field existed at v17 but was never populated) and zero
 * `ub_cas_index_root_gen` (sits in what was ub_reserved); load_at
 * treats root_paddr==0 as the empty cold-tier case and the index
 * comes up empty — no corruption hazard. Pre-existing v17 extent
 * records (n_replicas in byte 0, range 1..4) decode at v18 only if
 * a fresh `kind` byte happens to fall in 1..4. v17 had no `kind`
 * byte at all — byte 0 was n_replicas — so v17→v18 in-place is NOT
 * forward-compat at the value layer; v18 mounts of v17 pools rely
 * on the SB version check rejecting first. Format break, no feature
 * flag.
 *
 * v19 (P7-CAS-4c, this commit): per-snapshot cold-dead-list — closes
 * the snap_idx ↔ CAS hash refcount integration gap (P7-CAS-2 deferral:
 * snapshots with cold-extent captures could see dangling-hash reads
 * after auto-GC reclaimed the chunk). Snapshot value layout extends
 * past the existing dead_paddrs[] tail with `cold_dead_count` (le32)
 * + `cold_dead_hashes[N][32]` where N = cold_dead_count. Total per-
 * snap value: 56 + name_len + 8*dead_count + 4 + 32*cold_dead_count
 * (was 56 + name_len + 8*dead_count). When the cold-dead-list is
 * empty the tail is just 4 bytes (cold_dead_count=0). New constant
 * STM_SNAP_COLD_DEAD_LIST_MAX = 256 caps the per-snap cold-dead-list
 * length analogous to STM_SNAP_DEAD_LIST_MAX. No new uberblock fields.
 * v18 pools fail at the version check; tamper-then-mount drift at
 * the snap value layer is rejected by the snap-decoder's length
 * check (the encoded length doesn't match v19 expectations). Format
 * break, no feature flag.
 *
 * v19 → v20 (P7-CAS-8): STM_PROP_COUNT 3 → 4 — adds STM_PROP_TIERING
 * (INHERITABLE; per-dataset tiering opt-in for the migration-policy
 * heuristic's pass-all wrapper). Dataset value layout grows past
 * the local_value[] tail: origin_snap_id moves from offset 56 to
 * offset 64; DS_VAL_FIXED grows from 64 to 72. Pool-defaults value
 * length grows from 24 to 32 bytes. v19 pools refused at v20 mount
 * via uniform STM_EBADVERSION (no in-place forward-compat at the
 * value layer — same posture as v17→v18 and v18→v19 bumps). No
 * uberblock field changes.
 *
 * v20 → v21 bump (P7-CAS-11): extent record value layout grows past
 * the link_gen tail with `read_count` (le32 at offset 96..100) +
 * `last_read_gen` (le64 at offset 100..108). EX_VAL_LEN 96 → 108.
 * Promotion (cold→hot) heuristic v1: the read_count tracks how many
 * times a COLD extent has been read since last_read_gen via a
 * windowed-count scheme; the promote-policy step reads these fields
 * to select COLD extents whose access frequency justifies the
 * storage doubling of converting back to HOT. HOT extents always
 * have read_count == 0 AND last_read_gen == 0; the on-disk decoder
 * enforces this via bytes-96..108-zero anti-tamper. v20 pools'
 * 96-byte extent records length-rejected by v21 decoder. Refused
 * via uniform STM_EBADVERSION at SB version check. No uberblock
 * field changes. */
#define STM_UB_VERSION        21u

/* Fixed sizes. */
#define STM_UB_SIZE           4096u                      /* one uberblock */
#define STM_LABEL_SIZE        (64u * STM_UB_SIZE)        /* 256 KiB */
#define STM_LABELS_PER_DEVICE 4u
#define STM_UB_SLOTS_PER_LABEL 63u                       /* commit ring */
#define STM_UB_MIRROR_SLOT    63u                        /* pool-config mirror */

/* Minimum device size: 4 × labels + some user-data breathing room.
 * Labels are 2 × 256 KiB at head + 2 × 256 KiB at tail, so 1 MiB each
 * end. 8 MiB minimum is conservative. */
#define STM_DEVICE_MIN_BYTES  (8u * 1024u * 1024u)

/* Redundancy kinds for ub_redundancy_kind. */
typedef enum {
    STM_RED_NONE    = 0,
    STM_RED_MIRROR  = 1,
    STM_RED_RS      = 2,
    STM_RED_LRC     = 3,
} stm_redundancy_kind;

/* Device class / role (ARCH §4). */
typedef enum {
    STM_DEV_CLASS_UNSET = 0,
    STM_DEV_CLASS_SSD   = 1,
    STM_DEV_CLASS_HDD   = 2,
    STM_DEV_CLASS_PMEM  = 3,
    STM_DEV_CLASS_ZNS   = 4,
} stm_device_class;

typedef enum {
    STM_DEV_ROLE_UNSET = 0,
    STM_DEV_ROLE_DATA  = 1,
    STM_DEV_ROLE_LOG   = 2,
    STM_DEV_ROLE_CACHE = 3,
    STM_DEV_ROLE_SPARE = 4,
} stm_device_role;

/* Device availability state (ARCH §4.3.1). ONLINE is the normal
 * mount-time state; the others describe transitions driven by
 * failures or admin actions. Persisted in the roster byte of the
 * uberblock — P5-1 writes ONLINE unconditionally since multi-device
 * fault handling lands in P5-4. */
typedef enum {
    STM_DEV_STATE_UNSET      = 0,
    STM_DEV_STATE_ONLINE     = 1,
    STM_DEV_STATE_OFFLINE    = 2,
    STM_DEV_STATE_DEGRADED   = 3,
    STM_DEV_STATE_FAULTED    = 4,
    STM_DEV_STATE_REMOVED    = 5,
    /* P5-4b-ii: draining in preparation for removal. Still holds data
     * (its alloc tree is non-empty until evacuation completes) but is
     * excluded from new mirror reservations and from sync_commit's
     * fan-out. Transitions: ONLINE -> EVACUATING -> REMOVED.
     * See v2/specs/evac.tla (EvacuationAtomic, AtMostOneEvacuating). */
    STM_DEV_STATE_EVACUATING = 6,
} stm_device_state;

/* ========================================================================= */
/* Block pointer (stm_bptr) — 64 bytes.                                       */
/* ========================================================================= */

/*
 * A block pointer identifies one stripe on the pool.
 *
 * ARCH §4.4: paddr is (16-bit device, 48-bit offset). Offset is in
 * 4 KiB blocks, so addressable range per device is 2^48 × 4 KiB = 1 EiB.
 * Device field is 0 for single-device pools.
 *
 * csum is BLAKE3-256 over the referenced stripe's content (AEAD-AD
 * input in Phase 4; plain-content in Phase 3 tests).
 *
 * `kind` tags the target: leaf, internal, extent, etc. `flags` carries
 * per-kind bits (e.g. "compressed"). Reserved bytes pad to 64 and give
 * space for format growth without bumping STM_UB_VERSION.
 */
typedef enum {
    STM_BPTR_KIND_NONE        = 0,   /* null pointer */
    STM_BPTR_KIND_INTERNAL    = 1,   /* Bε-tree internal node */
    STM_BPTR_KIND_LEAF        = 2,   /* Bε-tree leaf node */
    STM_BPTR_KIND_EXTENT      = 3,   /* user-data extent */
    STM_BPTR_KIND_ALLOC       = 4,   /* allocator tree node */
    STM_BPTR_KIND_SNAP        = 5,   /* snapshot-index tree node */
    STM_BPTR_KIND_CAS         = 6,   /* CAS-tier index node */
    STM_BPTR_KIND_KEYSCHEMA   = 7,   /* key-schema sub-tree node (ARCH §7.7.3) */
    STM_BPTR_KIND_ALLOC_ROOTS = 8,   /* allocator-roots object (ARCH §6.1, P5-3b) */
    STM_BPTR_KIND_DATASET     = 9,   /* dataset-index tree root (ARCH §8.3.2, P6-persist) */
    STM_BPTR_KIND_EXTENT_TREE = 10,  /* extent-index tree root (ARCH §11.6, P7-3) */
    STM_BPTR_KIND_REPAIR_LOG  = 11,  /* repair-log tree root (ARCH §7.15.4, P7-15) */
} stm_bptr_kind;

typedef struct {
    le64    bp_paddr;              /* packed (device<<48) | offset */
    uint8_t bp_kind;               /* stm_bptr_kind */
    uint8_t bp_flags;
    uint8_t bp_reserved1[6];       /* pad to 16 */
    uint8_t bp_csum[32];           /* BLAKE3-256 of target */
    uint8_t bp_reserved2[16];      /* future growth */
} stm_bptr;

_Static_assert(sizeof(stm_bptr) == 64, "stm_bptr must be 64 bytes");

/* Paddr packing: top 16 bits device, low 48 bits block offset. */
static inline uint64_t stm_paddr_make(uint16_t device, uint64_t block_offset) {
    return ((uint64_t)device << 48) | (block_offset & ((UINT64_C(1) << 48) - 1));
}
static inline uint16_t stm_paddr_device(uint64_t paddr) {
    return (uint16_t)(paddr >> 48);
}
static inline uint64_t stm_paddr_offset(uint64_t paddr) {
    return paddr & ((UINT64_C(1) << 48) - 1);
}

/* ========================================================================= */
/* Uberblock (stm_uberblock) — 4096 bytes.                                    */
/* ========================================================================= */

typedef struct {
    /* Identity */
    le64    ub_magic;                           /*   0 :  8 — STM_UB_MAGIC  */
    le32    ub_version;                         /*   8 :  4 */
    le32    ub_flags_compat;                    /*  12 :  4 */
    le32    ub_flags_ro_compat;                 /*  16 :  4 */
    le32    ub_flags_incompat;                  /*  20 :  4 */
    le64    ub_pool_uuid[2];                    /*  24 : 16 */
    le64    ub_device_uuid[2];                  /*  40 : 16 */

    /* Transaction state */
    le64    ub_gen;                             /*  56 :  8 — monotonic per commit */
    le64    ub_txg;                             /*  64 :  8 — transaction group counter */
    le64    ub_roster_hash;                     /*  72 :  8 */
    le16    ub_device_count;                    /*  80 :  2 */
    le16    ub_device_id;                       /*  82 :  2 */
    uint8_t ub_reserved_hdr[12];                /*  84 : 12 — align to 96 */

    /* Metadata roots */
    stm_bptr ub_main_root;                      /*  96 : 64 — main fs tree */
    stm_bptr ub_alloc_root;                     /* 160 : 64 — allocator tree */
    stm_bptr ub_snap_root;                      /* 224 : 64 — snapshot tree */
    stm_bptr ub_cas_index_root;                 /* 288 : 64 — CAS tier index */

    /* Integrity */
    uint8_t ub_merkle_root[32];                 /* 352 : 32 */

    /* Pool-wide counters */
    le64    ub_next_ino;                        /* 384 :  8 */
    le64    ub_next_dataset_id;                 /* 392 :  8 */
    le64    ub_next_snap_id;                    /* 400 :  8 */
    le64    ub_total_blocks;                    /* 408 :  8 */
    le64    ub_free_blocks;                     /* 416 :  8 */

    /* Default redundancy profile (§4.5) */
    uint8_t ub_redundancy_kind;                 /* 424 :  1 */
    uint8_t ub_redundancy_params[15];           /* 425 : 15 */

    /* Key schema (§7.7.3) — header + bptr into the key-schema
     * sub-tree. Layout inside these 512 bytes is managed via
     * stm_ub_key_schema_pack / _unpack (see below). */
    uint8_t ub_key_schema[512];                 /* 440 : 512 */

    /* Device class / role */
    uint8_t ub_device_class;                    /* 952 :  1 */
    uint8_t ub_device_role;                     /* 953 :  1 */
    uint8_t ub_reserved_mid[6];                 /* 954 :  6 — align to 960 */

    /* Compact roster (up to 64 devices × 32 B each) */
    uint8_t ub_roster[2048];                    /* 960 : 2048 */

    /* Merkle root salt — 32 bytes random per pool, seeded at format
     * time from a CSPRNG. Mixes into the ub_merkle_root computation
     * (§7.11.3) to prevent certain precomputation attacks. Stable
     * across the pool's lifetime; never rotated. */
    uint8_t ub_merkle_root_salt[32];            /* 3008 : 32 */

    /* Gen at which `ub_alloc_root`'s tree was AEAD-encrypted
     * (P4-3b). Usually equals `ub_gen`, but may be strictly less
     * when `stm_sync_open` writes a "mount-claim" UB that advances
     * the durable gen past any orphan-data writes without
     * rewriting the tree. The AEAD nonce on every tree-node read
     * uses THIS field, not ub_gen, so a mount-claim UB keeps the
     * existing tree decryptable. */
    le64    ub_alloc_root_gen;                  /* 3040 :  8 */

    /* Durable scrub state (P5-durable-cursors, v8). 64 bytes packed
     * with explicit field ordering: state (u8), cursor_device_id
     * (u16, after 1-byte alignment), cursor_start_block (le64),
     * blocks_{verified,failed,repaired,unrepairable} (le64 each),
     * ranges_processed (le64), snapshot_cursor (le64).
     * Format: see stm_ub_scrub_state below for the unpacked C view. */
    uint8_t ub_scrub_state[64];                 /* 3048 :  64 */

    /* Gen at which `ub_main_root`'s tree (dataset index, ARCH §8.3.2)
     * was AEAD-encrypted (P6-persist, v9). Symmetric to
     * `ub_alloc_root_gen`: usually equals `ub_gen`, but may be strictly
     * less when `stm_sync_open` writes a "mount-claim" UB that advances
     * the durable gen past any orphan-data writes without rewriting
     * the dataset tree. The AEAD nonce on every dataset tree-node read
     * uses THIS field, not ub_gen. Zero before the first commit. */
    le64    ub_main_root_gen;                   /* 3112 :  8 */

    /* Gen at which `ub_snap_root`'s tree (snapshot index, ARCH §8.5.2)
     * was AEAD-encrypted (P6-persist, v9). Same semantics as
     * `ub_main_root_gen` for the snapshot tree. Zero before the first
     * commit. */
    le64    ub_snap_root_gen;                   /* 3120 :  8 */

    /* Extent-index tree root (P7-3, v12). Bptr to the
     * btree_store-encoded, AEAD-encrypted Bε-tree under
     * `ub_extent_root` on device 0. Keys: (le64 dataset_id || le64
     * ino || le64 offset). Values: 32-byte ARCH §11.6.1 record. The
     * tree's bp_kind is `STM_BPTR_KIND_EXTENT_TREE`. Zero before the
     * first commit. ARCH §11.6, spec extent.tla. */
    stm_bptr ub_extent_root;                    /* 3128 : 64 */

    /* Gen at which `ub_extent_root`'s tree was AEAD-encrypted (P7-3,
     * v12). Same semantics as `ub_main_root_gen` / `ub_snap_root_gen`.
     * Zero before the first commit. */
    le64    ub_extent_root_gen;                 /* 3192 :  8 */

    /* Repair-log tree root (P7-15, v16). Bptr to the single-leaf
     * btnode-encoded, plaintext + Merkle-covered tree under
     * `ub_repair_log_root` on device 0. Keys: 8-byte big-endian
     * seq_id. Values: 32-byte ARCH §7.15.4 record (timestamp +
     * paddrs + corruption type + verification result). The tree's
     * bp_kind is `STM_BPTR_KIND_REPAIR_LOG`. Zero before the first
     * commit. ARCH §7.15.4, spec bptr.tla::LogIntegrity. */
    stm_bptr ub_repair_log_root;                /* 3200 : 64 */

    /* Gen at which `ub_repair_log_root`'s tree was last serialized
     * (P7-15, v16). Plaintext nodes don't take an AEAD nonce, but
     * the gen is recorded for symmetry with the other tree-root
     * gen trackers and for future-proofing if the repair log
     * graduates to AEAD-encrypted multi-leaf encoding. Zero before
     * the first commit. */
    le64    ub_repair_log_root_gen;             /* 3264 :  8 */

    /* Monotonic seq_id allocator for the repair log (P7-15, v16).
     * Persisted on every commit so post-mount emits continue from
     * the durable view (rather than restarting from 0, which would
     * let new entries collide with persisted seq_ids).
     *
     * Invariant: `ub_repair_log_next_seq` > seq_id of every entry
     * persisted in `ub_repair_log_root`'s tree. Cross-checked at
     * `stm_repair_log_index_load_at` time (a tampered counter set
     * lower than an existing entry's seq surfaces as STM_ECORRUPT
     * during the load). Zero before the first commit. */
    le64    ub_repair_log_next_seq;             /* 3272 :  8 */

    /* Gen at which `ub_cas_index_root`'s tree (CAS-tier index, P7-CAS,
     * v18) was AEAD-encrypted. Same semantics as `ub_extent_root_gen`
     * / `ub_repair_log_root_gen`. The tree root itself lives at
     * `ub_cas_index_root` (offset 288, in the metadata-roots block,
     * carved at v3 but unused until v18). Zero before the first cold-
     * tier commit. ARCH §6.9, NOVEL #3, spec cas.tla. */
    le64    ub_cas_index_root_gen;              /* 3280 :  8 */

    /* Reserved for future fields + alignment to csum. */
    uint8_t ub_reserved[776];                   /* 3288 : 776 */

    /* Checksum: BLAKE3-256 over the rest of the uberblock with this
     * field zeroed. Self-verifying; a blob whose first 4064 bytes
     * hash to ub_csum is structurally valid. */
    uint8_t ub_csum[32];                        /* 4064 : 32 */
} stm_uberblock;

_Static_assert(sizeof(stm_uberblock) == 4096, "stm_uberblock must be 4096 bytes");
_Static_assert(offsetof(stm_uberblock, ub_alloc_root_gen) == 3040,
               "ub_alloc_root_gen must be at offset 3040 (v8 layout)");
_Static_assert(offsetof(stm_uberblock, ub_scrub_state) == 3048,
               "ub_scrub_state must be at offset 3048 (v8 layout)");
_Static_assert(offsetof(stm_uberblock, ub_main_root_gen) == 3112,
               "ub_main_root_gen must be at offset 3112 (v9 layout)");
_Static_assert(offsetof(stm_uberblock, ub_snap_root_gen) == 3120,
               "ub_snap_root_gen must be at offset 3120 (v9 layout)");
_Static_assert(offsetof(stm_uberblock, ub_extent_root) == 3128,
               "ub_extent_root must be at offset 3128 (v12 layout)");
_Static_assert(offsetof(stm_uberblock, ub_extent_root_gen) == 3192,
               "ub_extent_root_gen must be at offset 3192 (v12 layout)");
_Static_assert(offsetof(stm_uberblock, ub_repair_log_root) == 3200,
               "ub_repair_log_root must be at offset 3200 (v16 layout)");
_Static_assert(offsetof(stm_uberblock, ub_repair_log_root_gen) == 3264,
               "ub_repair_log_root_gen must be at offset 3264 (v16 layout)");
_Static_assert(offsetof(stm_uberblock, ub_repair_log_next_seq) == 3272,
               "ub_repair_log_next_seq must be at offset 3272 (v16 layout)");
_Static_assert(offsetof(stm_uberblock, ub_cas_index_root) == 288,
               "ub_cas_index_root must be at offset 288 (v3 layout)");
_Static_assert(offsetof(stm_uberblock, ub_cas_index_root_gen) == 3280,
               "ub_cas_index_root_gen must be at offset 3280 (v18 layout)");
_Static_assert(offsetof(stm_uberblock, ub_reserved) == 3288,
               "ub_reserved must be at offset 3288 (v18 layout)");
_Static_assert(offsetof(stm_uberblock, ub_csum) == 4064,
               "ub_csum must be at offset 4064");

/* ========================================================================= */
/* Durable scrub state (P5-durable-cursors, packs into ub_scrub_state[64]).   */
/* ========================================================================= */

/* The unpacked view of `stm_uberblock.ub_scrub_state[64]`. Use
 * stm_ub_scrub_state_pack / _unpack to convert between this and the
 * on-disk byte form. Layout is little-endian; matches the spec
 * variables in v2/specs/scrub.tla under the γ extension. */
typedef struct {
    uint8_t  scrub_state;            /* stm_scrub_state enum value */
    uint16_t cursor_device_id;
    uint64_t cursor_start_block;
    uint64_t blocks_verified;
    uint64_t blocks_failed;
    uint64_t blocks_repaired;
    uint64_t blocks_unrepairable;
    uint64_t ranges_processed;
    uint64_t snapshot_cursor;
} stm_ub_scrub_state;

/* Pack `state` into the 64-byte on-disk region. Always writes 64
 * bytes; trailing region zeroed for alignment + future growth. */
void stm_ub_scrub_state_pack(const stm_ub_scrub_state *state,
                              uint8_t out[64]);

/* Unpack the 64-byte on-disk region into `*out`. No validation —
 * the UB-level csum already covers integrity. The fresh-pool case
 * (all-zero region) unpacks to {scrub_state=0 (IDLE), all counters
 * zero}, which matches scrub.tla's Init. */
void stm_ub_scrub_state_unpack(const uint8_t in[64],
                                 stm_ub_scrub_state *out);

/* ========================================================================= */
/* Key-schema header (packed into ub_key_schema[512], P4-4a).                 */
/* ========================================================================= */

/* "TSCH" — key-schema Tree header magic. Four ASCII bytes appearing
 * at the head of ub_key_schema distinguish a v4+ populated schema
 * header from (a) a v3 uberblock's raw 32-byte plaintext key
 * prefix, or (b) an all-zero "never-formatted" region. */
#define STM_UB_KEY_SCHEMA_MAGIC    UINT32_C(0x48435354)
#define STM_UB_KEY_SCHEMA_VERSION  1u

/* Logical layout inside ub_key_schema[512]:
 *
 *   [0..4)      magic 'TSCH'              (le32)
 *   [4..8)      version                   (le32)
 *   [8..16)     feature-flag bits         (le64)
 *   [16..80)    stm_bptr → schema root    (64 bytes)
 *   [80..512)   reserved (zero-filled)    (432 bytes)
 *
 * Schema nodes themselves are plaintext Merkle-covered (ARCH §7.7.3);
 * the sensitive bytes — wrapped dataset keys inside the leaf — are
 * already encrypted under the pool's wrap key via stm_hybrid. */
typedef struct {
    uint32_t  ks_magic;
    uint32_t  ks_version;
    uint64_t  ks_flags;
    stm_bptr  ks_root;             /* zero-initialized = "no schema tree yet" */
} stm_ub_key_schema_hdr;

/* Pack a header into the 512-byte slot. Fills reserved tail with
 * zeros so consecutive commits produce byte-identical uberblocks
 * when the schema state is unchanged. */
void stm_ub_key_schema_pack(const stm_ub_key_schema_hdr *hdr,
                              uint8_t out[512]);

/* Unpack. Returns STM_OK on valid magic + version, STM_EBADVERSION
 * otherwise. A freshly-zeroed slot (magic == 0) is NOT valid —
 * callers should only attempt unpack on a pool that was formatted
 * as v4+. */
STM_MUST_USE
stm_status stm_ub_key_schema_unpack(const uint8_t in[512],
                                      stm_ub_key_schema_hdr *out);

/* ========================================================================= */
/* Encode / decode.                                                           */
/* ========================================================================= */

/*
 * Encode an uberblock into `buf` (must be at least STM_UB_SIZE bytes).
 * Writes every field in little-endian and finalizes ub_csum as the
 * BLAKE3-256 of bytes [0, STM_UB_SIZE - 32). Caller keeps ownership
 * of both `ub` (read-only) and `buf` (written).
 */
STM_MUST_USE
stm_status stm_ub_encode(const stm_uberblock *ub, void *buf, size_t buf_len);

/*
 * Decode `buf` (STM_UB_SIZE bytes expected) into `*out_ub`. Verifies:
 *   - buf_len == STM_UB_SIZE.
 *   - ub_magic matches STM_UB_MAGIC.
 *   - ub_version is supported (== STM_UB_VERSION; future: feature-flag check).
 *   - ub_csum matches BLAKE3-256 over bytes [0, STM_UB_SIZE - 32).
 *
 * R13 P2-1: status taxonomy for failures:
 *   - STM_ENOENT:      magic mismatch (slot is empty / uninitialized).
 *   - STM_EBADVERSION: version mismatch (slot holds a pool at an
 *                     incompatible format version).
 *   - STM_ECORRUPT:    csum mismatch (tampering or bit-rot).
 *   - STM_ERANGE:      buf_len != STM_UB_SIZE.
 * Feature-flag checks are a Phase-3-later addition (need the pool-
 * config context to decide).
 */
STM_MUST_USE
stm_status stm_ub_decode(const void *buf, size_t buf_len, stm_uberblock *out_ub);

/* Compute just the csum of an encoded buffer (bytes [0, size-32) →
 * BLAKE3-256 into out[32]). Exposed for tests and emergency tools. */
void stm_ub_csum(const void *buf, size_t buf_len, uint8_t out[32]);

/* ========================================================================= */
/* Label placement.                                                           */
/* ========================================================================= */

/*
 * Populate `offsets[STM_LABELS_PER_DEVICE]` with the byte offsets of
 * each label on a device of `device_bytes` total size.
 *
 *   offsets[0] = 0
 *   offsets[1] = STM_LABEL_SIZE
 *   offsets[2] = device_bytes - 2 * STM_LABEL_SIZE
 *   offsets[3] = device_bytes - STM_LABEL_SIZE
 *
 * Returns STM_EINVAL if device_bytes < STM_DEVICE_MIN_BYTES.
 */
STM_MUST_USE
stm_status stm_label_offsets(uint64_t device_bytes,
                              uint64_t offsets[STM_LABELS_PER_DEVICE]);

/*
 * Offset (bytes) of commit-ring slot `slot_idx` (0..STM_UB_SLOTS_PER_LABEL-1)
 * within a label whose head is at byte `label_offset`. Slot sizes are
 * STM_UB_SIZE. The mirror slot (STM_UB_MIRROR_SLOT) is accessed the same
 * way but is reserved for pool-config snapshots, not commit rotation.
 */
STM_MUST_USE
stm_status stm_ub_slot_offset(uint64_t label_offset, uint32_t slot_idx,
                               uint64_t *out_byte_offset);

/* Round-robin slot for commit gen `gen`: gen mod STM_UB_SLOTS_PER_LABEL. */
static inline uint32_t stm_ub_ring_slot(uint64_t gen) {
    return (uint32_t)(gen % STM_UB_SLOTS_PER_LABEL);
}

/* ========================================================================= */
/* Device-backed label I/O.                                                   */
/* ========================================================================= */

typedef struct stm_bdev stm_bdev;   /* forward from block.h */

/*
 * Encode `ub` and write it to (label_idx, slot_idx) on `d`. Fsyncs
 * before returning. Caller must ensure label_idx < STM_LABELS_PER_DEVICE
 * and slot_idx <= STM_UB_MIRROR_SLOT.
 */
STM_MUST_USE
stm_status stm_sb_label_write(stm_bdev *d, uint32_t label_idx,
                               uint32_t slot_idx, const stm_uberblock *ub);

/*
 * Read the uberblock at (label_idx, slot_idx) from `d` and decode it
 * into `*out_ub`. Returns STM_ECORRUPT on csum failure,
 * STM_EBADVERSION on magic/version mismatch.
 */
STM_MUST_USE
stm_status stm_sb_label_read(stm_bdev *d, uint32_t label_idx,
                              uint32_t slot_idx, stm_uberblock *out_ub);

/*
 * Scan all STM_LABELS_PER_DEVICE labels × STM_UB_SLOTS_PER_LABEL
 * commit-ring slots on `d`, pick the uberblock with the highest valid
 * `ub_gen`, and hand it back via `*out_ub`. Also reports which label +
 * slot position it came from (useful for diagnostics and for deciding
 * where to write the NEXT commit's ring slot).
 *
 * Returns STM_ENOENT if no valid uberblock is found on the device
 * (fresh / never-mounted / irrecoverably corrupt). Per-slot
 * STM_ECORRUPT / STM_EBADVERSION failures are NOT errors — they're
 * expected for unused slots and get silently filtered out.
 *
 * Single-device: this is the authoritative mount-time selection.
 * Multi-device pools (Phase 5) will add a quorum layer on top.
 */
STM_MUST_USE
stm_status stm_sb_mount_scan(stm_bdev *d, stm_uberblock *out_ub,
                              uint32_t *out_label_idx,
                              uint32_t *out_slot_idx);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_SUPER_H */
