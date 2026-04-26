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

/* Dataset id 1 is the root dataset, created at index init time.
 * Parent id 0 is the sentinel "no parent" (only root has it). */
#define STM_DATASET_ROOT_ID      ((uint64_t)1)
#define STM_DATASET_NO_PARENT    ((uint64_t)0)

/* Maximum name length per component (excluding NUL terminator).
 * Matches ARCH §8.3 "Max name length per component: 255 bytes". */
#define STM_DATASET_NAME_MAX     255u

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
    STM_PROP_COUNT       = 3
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

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_DATASET_H */
