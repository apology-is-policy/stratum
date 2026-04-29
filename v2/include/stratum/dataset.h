/* SPDX-License-Identifier: ISC */
/*
 * Pool-wide dataset hierarchy + index (P6-2 C impl scaffold).
 *
 *   see docs/ARCHITECTURE.md §8 — namespace model.
 *   see docs/ARCHITECTURE.md §8.3 — dataset hierarchy + index tree.
 *   see docs/ARCHITECTURE.md §8.9 — rename / move semantics.
 *   see v2/specs/dataset.tla — formal model of structural invariants.
 *   see docs/ROADMAP-V2.md §9.1 — Phase 6 dataset-layer deliverable.
 *
 * Datasets form a tree rooted at id 1 ("the root dataset", typically the
 * pool name e.g. "tank"). Each dataset has a u64 id, a parent_id (0 for
 * root), a UTF-8 name (≤255 bytes), and metadata (created_txg, flags,
 * next_ino). Names are unique within a parent's children but may repeat
 * across the tree — full path is the unique identifier.
 *
 * This module provides the ATOMIC operations on the dataset index:
 * Create, Destroy, Rename, Move. The spec for these operations is
 * `v2/specs/dataset.tla`; load-bearing invariants:
 *
 *   - ForestStructure: every PRESENT dataset's chain of PRESENT
 *     parents reaches RootId by bounded depth. No cycles, no orphan
 *     subtrees.
 *   - SiblingNameUnique: among PRESENT siblings (same parent), names
 *     are pairwise distinct. Path resolution is deterministic.
 *   - IdMonotonic: ids assigned strictly increasing; never recycled
 *     after Destroy. Per ARCH §8.3.1 ids are stable across renames.
 *   - BirthTxgMonotonic: every dataset's created_txg ≤ current_txg.
 *   - RootInvariant: root (id=1) is always present, parent=0,
 *     undestroyable / unrenameable / unmoveable.
 *
 * Storage backend (this chunk): in-RAM linear array of stm_dataset_entry.
 * O(n) lookup; acceptable for the MVP dataset population (a typical
 * pool has < 1000 datasets). Persistent storage (btree under ub_main_root
 * per ARCH §8.3.2) is wired in a follow-on chunk.
 *
 * Out of scope for this chunk:
 *   - Property inheritance (separate chunk; see v2/specs/property.tla).
 *   - Snapshots and clones (separate chunks; see snapshot.tla).
 *   - Persistent storage (this chunk is in-RAM only; persistence comes
 *     when ub_main_root is wired up).
 *   - Secondary name→id index (path-based lookup).
 *   - Per-9P-connection namespace composition (runtime concern).
 *
 * Thread safety: every public API holds an internal pthread_mutex_t for
 * the duration of the call. Multiple threads may call concurrently;
 * ordering is serialized.
 *
 * Lifetime: stm_dataset_index is heap-allocated by stm_dataset_index_create
 * and released by stm_dataset_index_close. Caller is responsible for
 * pairing.
 */
#ifndef STRATUM_V2_DATASET_H
#define STRATUM_V2_DATASET_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;       typedef struct stm_bdev       stm_bdev;
struct stm_bootstrap;  typedef struct stm_bootstrap  stm_bootstrap;

/* Dataset id 1 is the root dataset, created at index init time.
 * Parent id 0 is the sentinel "no parent" (only root has it). */
#define STM_DATASET_ROOT_ID      ((uint64_t)1)
#define STM_DATASET_NO_PARENT    ((uint64_t)0)

/* Maximum name length per component (excluding NUL terminator).
 * Matches ARCH §8.3 "Max name length per component: 255 bytes". */
#define STM_DATASET_NAME_MAX     255u

/* Origin-snapshot sentinel. A dataset with `origin_snap_id ==
 * STM_DATASET_NO_ORIGIN` is a regular dataset; non-zero means it's a
 * clone of the referenced snapshot (clone.tla::IsClone). Snapshot ids
 * start at 1, so 0 is unambiguous. Matches `clone.tla::NoOrigin`.
 *
 * Note that NO_PARENT (parent_id sentinel) and NO_ORIGIN
 * (origin_snap_id sentinel) deliberately share the value 0. Each
 * sentinel disambiguates by FIELD it occupies, not by value: parent_id
 * vs origin_snap_id are distinct columns of the dataset entry, and 0
 * is the natural "absence" value for both. STM_SNAP_NO_PREV (snapshot
 * prev-chain sentinel) follows the same convention. */
#define STM_DATASET_NO_ORIGIN    ((uint64_t)0)

/*
 * Property identifiers for per-dataset properties (ARCH §8.4).
 *
 * MVP coverage: one inheritable, one non-inheritable, one immutable —
 * exercises every property.tla resolution path. The full canonical
 * list (ARCH §8.4.2 Table) is added incrementally; the on-disk layout
 * (di_local_props[128] bit-vector + values per ARCH §8.4.3) is wired
 * in the persistent-storage chunk.
 *
 * Kinds:
 *   - INHERITABLE   — effective(d, p) walks parent chain to find
 *                       nearest local set; pool default if none.
 *   - NONINHERITABLE — effective(d, p) is local-or-default; never
 *                       walks parent chain (matches property.tla).
 *   - IMMUTABLE     — set ONCE per dataset; subsequent Set / Clear
 *                       refused with STM_EINVAL. Encryption is the
 *                       canonical example (ARCH §8.4.2).
 */
typedef enum {
    STM_PROP_COMPRESS    = 0,   /* INHERITABLE   */
    STM_PROP_QUOTA       = 1,   /* NONINHERITABLE */
    STM_PROP_ENCRYPTION  = 2,   /* IMMUTABLE     */
    /* P7-CAS-8 (UB v19→v20): tiering opt-in. Boolean encoded as
     * uint64_t value (0 = disabled, non-zero = enabled). INHERITABLE
     * — children inherit the parent's tiering preference unless
     * locally overridden. The migration-policy pass-all wrapper
     * `stm_fs_migrate_policy_pass_all` enumerates every dataset and
     * runs the per-dataset policy step on each that resolves
     * STM_PROP_TIERING != 0. */
    STM_PROP_TIERING     = 3,   /* INHERITABLE   */
    STM_PROP_COUNT       = 4
} stm_property;

typedef enum {
    STM_PROP_KIND_INHERITABLE     = 0,
    STM_PROP_KIND_NONINHERITABLE  = 1,
    STM_PROP_KIND_IMMUTABLE       = 2
} stm_property_kind;

/* Classifier — pure function over the enum. */
stm_property_kind stm_property_kind_of(stm_property p);

/*
 * Per-dataset entry. Mirrors ARCH §8.3.2 stm_dataset_index_entry but
 * omits di_tree_root + di_key_slot + di_local_props which are added
 * in follow-on chunks (extents + key schema + property system).
 *
 * `name` is null-terminated; `name_len` is the byte count excluding
 * the NUL.
 */
typedef struct {
    uint64_t id;                  /* unique, monotonically assigned */
    uint64_t parent_id;           /* STM_DATASET_NO_PARENT for root */
    uint32_t name_len;            /* bytes, excluding NUL; ≤ STM_DATASET_NAME_MAX */
    uint8_t  name[STM_DATASET_NAME_MAX + 1u]; /* UTF-8 + NUL */
    uint64_t created_txg;         /* txg at creation; ≤ current_txg */
    uint32_t flags;               /* future: encrypted / readonly / ... */
    uint64_t next_ino;            /* dataset's next-inode counter */
    /* Clone origin (P6-clone, v10). STM_DATASET_NO_ORIGIN for non-clone
     * datasets; non-zero references a snapshot in the pool's
     * snapshot index. A clone is structurally a regular dataset that
     * carries this back-reference; clone.tla::CloneOriginPresent
     * holds because Snapshot.Delete refuses while any clone
     * references the snap. */
    uint64_t origin_snap_id;
} stm_dataset_entry;

struct stm_dataset_index;
typedef struct stm_dataset_index stm_dataset_index;

/*
 * Create a new dataset index. Initializes the root dataset (id 1, name
 * "" by convention since the path-prefix is the pool name) at the given
 * txg. `current_txg` becomes the index's monotonic txg counter; later
 * operations can advance it via stm_dataset_index_advance_txg.
 *
 * On success `*out` holds the new index. STM_EINVAL on NULL out.
 */
STM_MUST_USE
stm_status stm_dataset_index_create(uint64_t current_txg,
                                      stm_dataset_index **out);

/*
 * Release the index. Frees all entries. Caller must ensure no
 * concurrent access.
 */
void stm_dataset_index_close(stm_dataset_index *idx);

/*
 * Advance the internal txg counter. New datasets created after this
 * carry created_txg = the new value. Refuses regression
 * (new_txg < current_txg) with STM_EINVAL.
 *
 * Models ARCH §8.5.1 birth-txg tracking — txg only ever advances.
 */
STM_MUST_USE
stm_status stm_dataset_index_advance_txg(stm_dataset_index *idx,
                                           uint64_t new_txg);

/*
 * Read the current txg. Always STM_OK on valid args.
 */
STM_MUST_USE
stm_status stm_dataset_index_current_txg(const stm_dataset_index *idx,
                                            uint64_t *out_txg);

/*
 * Create a new dataset as a child of `parent_id`.
 *
 * Preconditions (returned errors):
 *   - parent_id refers to a PRESENT dataset (else STM_ENOENT).
 *   - name has length 1..STM_DATASET_NAME_MAX (else STM_EINVAL).
 *   - name does not collide with an existing PRESENT sibling
 *     (else STM_EEXIST).
 *
 * On success, *out_id holds the new dataset's id. created_txg is set
 * to the index's current txg (which auto-bumps by 1 — every Create
 * advances the spec's "current_txg" model).
 *
 * Models dataset.tla::Create.
 */
STM_MUST_USE
stm_status stm_dataset_create_child(stm_dataset_index *idx,
                                       uint64_t parent_id,
                                       const char *name,
                                       uint64_t *out_id);

/*
 * Destroy dataset `id`. Refused if:
 *   - id is STM_DATASET_ROOT_ID (root undestroyable; STM_EINVAL).
 *   - id is not PRESENT (STM_ENOENT).
 *   - id has any PRESENT children (STM_EBUSY — caller must destroy
 *     children first).
 *
 * The slot is marked ABSENT; the id is NOT recycled
 * (next_dataset_id only grows). Models dataset.tla::Destroy.
 */
STM_MUST_USE
stm_status stm_dataset_destroy(stm_dataset_index *idx, uint64_t id);

/*
 * Rename dataset `id` to `new_name`. Refused if:
 *   - id is STM_DATASET_ROOT_ID (root unrenameable; STM_EINVAL).
 *   - id is not PRESENT (STM_ENOENT).
 *   - new_name length is invalid (STM_EINVAL).
 *   - new_name collides with another PRESENT sibling (STM_EEXIST).
 *
 * Models dataset.tla::Rename.
 */
STM_MUST_USE
stm_status stm_dataset_rename(stm_dataset_index *idx, uint64_t id,
                                const char *new_name);

/*
 * Move dataset `id` to be a child of `new_parent_id`. Refused if:
 *   - id is STM_DATASET_ROOT_ID (root unmoveable; STM_EINVAL).
 *   - id == new_parent_id (self-move; STM_EINVAL).
 *   - id is not PRESENT or new_parent_id is not PRESENT (STM_ENOENT).
 *   - new_parent_id is a descendant of id (would create a cycle;
 *     STM_EINVAL).
 *   - id's name collides with a PRESENT sibling under new_parent_id
 *     (STM_EEXIST).
 *
 * Models dataset.tla::Move.
 */
STM_MUST_USE
stm_status stm_dataset_move(stm_dataset_index *idx, uint64_t id,
                              uint64_t new_parent_id);

/*
 * Look up dataset `id`. On success *out is filled with a copy of the
 * entry. STM_ENOENT if id is not PRESENT (or never allocated).
 */
STM_MUST_USE
stm_status stm_dataset_lookup(const stm_dataset_index *idx, uint64_t id,
                                stm_dataset_entry *out);

/*
 * Count PRESENT datasets. Always STM_OK on valid args.
 */
STM_MUST_USE
stm_status stm_dataset_count(const stm_dataset_index *idx,
                                size_t *out_count);

/*
 * Count PRESENT children of `parent_id`. Returns 0 (with STM_OK) if
 * parent has no children. STM_ENOENT if parent_id is not PRESENT.
 */
STM_MUST_USE
stm_status stm_dataset_children_count(const stm_dataset_index *idx,
                                         uint64_t parent_id,
                                         size_t *out_count);

/*
 * Iterate every PRESENT dataset, in increasing-id order. The callback
 * is invoked with a pointer to a temporary copy of the entry (caller
 * must not retain the pointer). Returning false from the callback
 * terminates iteration early.
 *
 * The iteration holds the index's mutex for the duration; the callback
 * MUST NOT call back into stm_dataset_* on the same index (deadlock —
 * ERRORCHECK mutex aborts on EDEADLK).
 */
typedef bool (*stm_dataset_iter_cb)(const stm_dataset_entry *entry,
                                       void *ctx);

STM_MUST_USE
stm_status stm_dataset_iter(const stm_dataset_index *idx,
                              stm_dataset_iter_cb cb, void *ctx);

/*
 * Set the pool-wide default for property `p`. Used as the fallback
 * when no ancestor has a local value. Defaults default to 0 at
 * index_create time; callers can override for the canonical
 * "lz4 / 8 MiB / aegis-256" defaults from ARCH §8.4.2.
 *
 * Returns STM_OK on valid args; STM_EINVAL on NULL idx or
 * out-of-range property.
 */
STM_MUST_USE
stm_status stm_dataset_set_pool_default(stm_dataset_index *idx,
                                           stm_property p, uint64_t value);

/*
 * Set property `p` on dataset `id` to `value`.
 *
 * Refusals (per property.tla):
 *   - id is STM_DATASET_ROOT_ID: allowed (root carries pool-wide
 *     property defaults via local override).
 *   - id is not PRESENT: STM_ENOENT.
 *   - p is out-of-range: STM_EINVAL.
 *   - p is IMMUTABLE and already-locally-set on this dataset:
 *     STM_EINVAL (set-once enforcement; matches
 *     property.tla::ImmutableEncryption).
 *
 * Models property.tla::SetProperty.
 *
 * R30 P2-1: SPEC-TO-CODE divergence on the IMMUTABLE-at-Create
 * pattern. The spec property.tla models CreateChild as taking an
 * `immutable_vals` argument and atomically initializing each
 * IMMUTABLE property's local_set + local_value at creation; its
 * SetProperty then refuses every IMMUTABLE-property attempt. The C
 * API splits this into stm_dataset_create_child + a follow-up
 * stm_dataset_set_property; the FIRST set on an IMMUTABLE property
 * is allowed (modeling "declared at creation" per ARCH §8.4.2),
 * subsequent sets refuse. Long-run safety property (ImmutableEncryption
 * — a set IMMUTABLE never mutates) holds in both shapes; the C
 * impl exposes a transient state where a freshly-created dataset's
 * IMMUTABLE property has no local set and effective() returns the
 * inherited / pool-default value. Callers wanting "atomic at
 * creation" semantics should set the IMMUTABLE before exposing the
 * dataset id to other observers.
 */
STM_MUST_USE
stm_status stm_dataset_set_property(stm_dataset_index *idx, uint64_t id,
                                       stm_property p, uint64_t value);

/*
 * Clear property `p` on dataset `id`. Refusals same shape as Set,
 * plus: clearing an IMMUTABLE property always refused.
 *
 * Models property.tla::ClearProperty.
 */
STM_MUST_USE
stm_status stm_dataset_clear_property(stm_dataset_index *idx, uint64_t id,
                                         stm_property p);

/*
 * Compute the effective value of property `p` on dataset `id` per
 * the resolution algorithm (property.tla::Effective):
 *
 *   - If local_set[id][p]: return local value.
 *   - If p is NONINHERITABLE: return pool default.
 *   - If parent is RootId's parent (no parent): return pool default.
 *   - Else: recurse to parent.
 *
 * STM_ENOENT if id is not PRESENT. STM_EINVAL on NULL out / OOR p.
 */
STM_MUST_USE
stm_status stm_dataset_effective_property(const stm_dataset_index *idx,
                                              uint64_t id, stm_property p,
                                              uint64_t *out_value);

/* ========================================================================= */
/* Clone API (P6-clone, v10).                                                 */
/* ========================================================================= */

/*
 * Create a clone — a new dataset that originates from `origin_snap_id`.
 *
 * `parent_id` + `name` semantics are identical to stm_dataset_create_child
 * (sibling-name unique under parent; created_txg auto-bumps).
 *
 * Preconditions in addition to create_child:
 *   - origin_snap_id != STM_DATASET_NO_ORIGIN (else STM_EINVAL — use
 *     create_child for non-clones).
 *
 * The dataset module does NOT verify that origin_snap_id refers to a
 * PRESENT snapshot — that cross-module check belongs to the caller
 * (typically sync layer). The dataset's persistent state simply
 * records the origin reference; clone.tla::CloneOriginPresent is
 * preserved by snapshot.tla::SnapshotDelete refusing while any clone
 * references the snap (see stm_snapshot_index_set_clone_check_cb).
 *
 * Models clone.tla::CloneCreate.
 */
STM_MUST_USE
stm_status stm_dataset_create_clone(stm_dataset_index *idx,
                                       uint64_t parent_id,
                                       const char *name,
                                       uint64_t origin_snap_id,
                                       uint64_t *out_id);

/*
 * Promote dataset `id`. Refused if:
 *   - id is not PRESENT (STM_ENOENT).
 *   - id is not a clone (origin_snap_id == STM_DATASET_NO_ORIGIN);
 *     STM_EINVAL.
 *
 * Effect: clears `origin_snap_id` to STM_DATASET_NO_ORIGIN. The
 * dataset becomes a regular (non-clone) dataset. The previously-
 * referenced snapshot is no longer held by this clone — it can be
 * deleted if no other clone still references it.
 *
 * Models clone.tla::Promote (MVP semantics: just clears the origin
 * dependency; full snap-chain reshuffling per ARCH §8.6.2 is a
 * future extension flagged in clone.tla "OUT OF SCOPE").
 */
STM_MUST_USE
stm_status stm_dataset_promote(stm_dataset_index *idx, uint64_t id);

/*
 * Count PRESENT clones whose origin_snap_id == snapshot_id. Used by
 * sync layer to enforce clone.tla::SnapWithClonesUndeletable: refuse
 * snapshot delete if any clone references it. Always STM_OK on
 * valid args; *out_count == 0 if no clones reference the snap.
 */
STM_MUST_USE
stm_status stm_dataset_clones_count_for_snap(const stm_dataset_index *idx,
                                                uint64_t snapshot_id,
                                                size_t *out_count);

/* ========================================================================= */
/* Persistence (P6-persist).                                                  */
/* ========================================================================= */

/*
 * The dataset index is persisted as a btree_store-encoded, AEAD-encrypted
 * tree under `ub_main_root`. The tree's keyspace mixes:
 *   - Dataset entries:       key = le64 dataset_id (≥ 1), value = packed entry.
 *   - Pool-property defaults: key = le64 0, value = STM_PROP_COUNT × le64
 *                              (32 bytes at v20; 24 bytes at v19; 8 × N).
 *
 * On-disk per-dataset value (variable length, name_len bytes for the name).
 * v20 layout (current):
 *
 *   off  size  field
 *    0    8   parent_id (le64)
 *    8    8   created_txg (le64)
 *   16    8   next_ino (le64)
 *   24    4   flags (le32)
 *   28    2   local_set_bitmap (le16) — bits 0..STM_PROP_COUNT-1 = local_set[]
 *   30    2   name_len (le16) — 0..STM_DATASET_NAME_MAX
 *   32   32   local_value[STM_PROP_COUNT] (4 × le64 at v20, in property-id order)
 *   64    8   origin_snap_id (le64) — STM_DATASET_NO_ORIGIN (0) for non-clones (v10)
 *   72    L   name (UTF-8, no NUL)   L = name_len
 *
 * Total: 72 + name_len bytes (v20).
 *
 * Format-break history:
 *   v9  → v10: added origin_snap_id at offset 56 (P6-clone). Total
 *              became 64 + name_len bytes.
 *   v19 → v20: STM_PROP_COUNT 3 → 4 (P7-CAS-8 STM_PROP_TIERING).
 *              local_value grows from 24 to 32 bytes; origin_snap_id
 *              moves from offset 56 to offset 64; total 72 + name_len.
 *
 * The on-disk encoder/decoder express origin_snap_id's offset as
 * `32 + 8 * STM_PROP_COUNT` so future STM_PROP_COUNT bumps slide it
 * without code duplication. Bumping STM_PROP_COUNT requires a
 * UB-version bump (v19 pools refused at v20 mount via uniform
 * STM_EBADVERSION).
 *
 * Crypt + I/O follow the alloc_roots pattern: AEAD nonce
 * paddr‖gen‖pool_uuid, AD pool_uuid‖device_uuid_0, idempotent commit
 * via internal dirty flag.
 */

/*
 * Bind storage (device 0's bdev + bootstrap).  Borrowed pointers — caller
 * must keep them live for the index's lifetime.  Mandatory before
 * _load_at / _commit.
 *
 * STM_EINVAL on NULL idx / bdev / boot.
 */
STM_MUST_USE
stm_status stm_dataset_index_set_storage(stm_dataset_index *idx,
                                            stm_bdev *bdev_0,
                                            stm_bootstrap *boot_0);

/*
 * Install crypt context.  metadata_key (32 bytes) is borrowed — must
 * outlive the index.  pool_uuid + device_uuid_0 are copied.  Mandatory
 * before _load_at / _commit.
 *
 * STM_EINVAL on NULL.
 */
STM_MUST_USE
stm_status stm_dataset_index_set_crypt_ctx(stm_dataset_index *idx,
                                              const uint8_t *metadata_key,
                                              const uint64_t pool_uuid[2],
                                              const uint64_t device_uuid_0[2]);

/*
 * Hydrate the index from on-disk state.  Wipes every existing slot
 * (including the fresh-from-create root) and replaces with the on-disk
 * contents.  Sets dirty=false on success.
 *
 * `root_paddr` MUST be non-zero (the caller checks for "no commit yet"
 * by inspecting the UB before invoking).  `root_gen` is the AEAD gen at
 * which the tree was last serialized (= ub_main_root_gen).
 * `expected_csum` is the Merkle link from ub_main_root.bp_csum.
 *
 * Returns STM_OK on full hydration; STM_ECORRUPT on Merkle mismatch
 * or malformed entries; STM_EBADTAG on AEAD failure; STM_EINVAL on
 * missing storage / crypt ctx; STM_ENOTSUPPORTED if the on-disk tree
 * exceeds btree_store's 2-level cap.
 */
STM_MUST_USE
stm_status stm_dataset_index_load_at(stm_dataset_index *idx,
                                        uint64_t root_paddr, uint64_t root_gen,
                                        const uint8_t expected_csum[32]);

/*
 * Serialize current state, AEAD-encrypt, write a fresh root, free the
 * previous root's nodes (if any), return new (paddr, csum).
 *
 * Idempotent when clean (dirty=false + prior commit exists): returns
 * cached values without on-disk activity.  Mandatory for
 * quorum.tla::ContentQuorumAtGen under retry — sync_commit may invoke
 * us multiple times at the same target_gen and every call must produce
 * byte-identical UB bytes across devices.
 *
 * `committed_gen` is the AEAD gen for the new root AND the free_gen for
 * reclaiming the previous root.  Mirrors stm_alloc_roots_commit.
 */
STM_MUST_USE
stm_status stm_dataset_index_commit(stm_dataset_index *idx,
                                       uint64_t committed_gen,
                                       uint64_t *out_root_paddr,
                                       uint8_t out_root_csum[32]);

/*
 * Durable root paddr + csum as last persisted by _commit / _load_at.
 * Both zero before any commit.
 */
STM_MUST_USE
stm_status stm_dataset_index_get_root(const stm_dataset_index *idx,
                                         uint64_t *out_root_paddr,
                                         uint8_t out_root_csum[32]);

/*
 * Gen at which the durable root was AEAD-encrypted.  May differ from
 * the current commit's gen when _commit idempotent-shortcircuits.
 * 0 before any commit.  Stamped into ub_main_root_gen.
 */
STM_MUST_USE
stm_status stm_dataset_index_get_gen(const stm_dataset_index *idx,
                                        uint64_t *out_root_gen);

/*
 * Walk the on-disk tree's Merkle + AEAD chain without mutating
 * in-RAM state.  STM_OK trivially if no commit has persisted yet
 * (root_paddr == 0).  Symmetric to stm_alloc_roots_verify.
 */
STM_MUST_USE
stm_status stm_dataset_index_verify(const stm_dataset_index *idx);

/*
 * Override the next-id counter used for monotonic dataset id assignment.
 * Used by sync_open after load_at to seed from ub_next_dataset_id (since
 * the on-disk tree only carries assigned ids, not the next-id counter).
 *
 * Refuses regression (STM_EINVAL if `next_id` is less than any present
 * dataset id + 1).  STM_OK on valid args.
 */
STM_MUST_USE
stm_status stm_dataset_index_set_next_id(stm_dataset_index *idx,
                                            uint64_t next_id);

/*
 * Read the next-id counter.  Stamped into ub_next_dataset_id at commit.
 */
STM_MUST_USE
stm_status stm_dataset_index_get_next_id(const stm_dataset_index *idx,
                                            uint64_t *out_next_id);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_DATASET_H */
