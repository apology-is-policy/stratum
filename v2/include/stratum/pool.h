/* SPDX-License-Identifier: ISC */
/*
 * Pool layer (Phase 5 chunk P5-1).
 *
 *   see docs/ARCHITECTURE.md §4.3   — pool composition + device roster.
 *   see docs/ARCHITECTURE.md §5.13  — compact roster in uberblock.
 *   see v2/specs/quorum.tla         — multi-device commit model (P5-0).
 *
 * `stm_pool` is the top-level handle for a Stratum pool. It aggregates
 * up to STM_POOL_DEVICES_MAX block devices plus pool-wide identity
 * (UUID, roster hash, redundancy profile — though redundancy beyond
 * STM_RED_NONE only lands at P5-3).
 *
 * Phase 5 chunk P5-1 (this file) is the degenerate-N=1 foundation:
 * every existing single-device code path still works by wrapping one
 * `stm_bdev` in a pool with a 1-entry roster. Multi-device commit
 * semantics (quorum write + mount) land in P5-2. Device lifecycle
 * (add/remove/replace) lands in P5-4.
 *
 * Roster format (2048 bytes of ub_roster, up to 64 × 32-byte slots):
 *
 *   slot[i][ 0..15]  uuid                (le64 pair)
 *   slot[i][16..23]  size_bytes          (le64)
 *   slot[i][   24]   role                (stm_device_role)
 *   slot[i][   25]   class               (stm_device_class)
 *   slot[i][   26]   state               (stm_device_state)
 *   slot[i][27..31]  reserved (zero)
 *
 * Slot index == device_id. Populated slots pack at [0..device_count);
 * the rest is zero. `ub_roster_hash` (le64) is the first 8 bytes of
 * BLAKE3-256 over the full 2048-byte encoded roster, interpreted as
 * little-endian. This is a roster-state witness (per ARCH §4.3.2 it
 * advances on add/remove), NOT a tamper check — ub_csum already
 * covers the full UB cryptographically.
 *
 * Note on hash semantics: state transitions (ONLINE → DEGRADED, etc.)
 * change the encoded roster bytes and therefore the hash. ARCH §4.3.2
 * is most naturally read as "hash advances on add/remove"; for P5-1
 * MVP we fold state into the hash (simpler, no divergent encodings).
 * If multi-device reconciliation in P5-2+ wants an identity-only
 * hash, we'll split it then.
 */
#ifndef STRATUM_V2_POOL_H
#define STRATUM_V2_POOL_H

#include <stratum/types.h>
#include <stratum/super.h>

#ifdef __cplusplus
extern "C" {
#endif

struct stm_bdev;
typedef struct stm_bdev stm_bdev;

/* Hard cap on devices in one pool. ARCH §5.13: 64-slot roster in the
 * uberblock; beyond that we'd need a spill-to-separate-object design.
 * The roster encoding below uses 32 bytes per slot × 64 slots = 2048
 * bytes, matching ub_roster[2048]. */
#define STM_POOL_DEVICES_MAX            64u

/* Per-slot size in ub_roster[2048]. */
#define STM_POOL_ROSTER_SLOT_SIZE       32u

/* Full encoded roster size (matches ub_roster[...]). */
#define STM_POOL_ROSTER_BYTES  (STM_POOL_DEVICES_MAX * STM_POOL_ROSTER_SLOT_SIZE)
_Static_assert(STM_POOL_ROSTER_BYTES == 2048u,
               "pool roster layout must match ub_roster[2048]");

/* ========================================================================= */
/* Per-device record (as held in RAM + as persisted in the roster).           */
/* ========================================================================= */

typedef struct {
    uint64_t         uuid[2];        /* stable device identity (ARCH §4.3.1) */
    uint64_t         size_bytes;     /* pool-join-time size                   */
    stm_device_role  role;
    stm_device_class class_;         /* `class` is a C++ keyword; trailing _  */
    stm_device_state state;
    stm_bdev        *bdev;           /* borrowed; caller owns the lifetime    */
} stm_pool_device;

/* ========================================================================= */
/* Opaque handle.                                                             */
/* ========================================================================= */

typedef struct stm_pool stm_pool;

/* ========================================================================= */
/* Open options.                                                              */
/* ========================================================================= */

typedef struct {
    uint64_t        pool_uuid[2];

    /* 1..STM_POOL_DEVICES_MAX entries. Slot index in the array ==
     * device_id that will land in the uberblock's paddr top-16-bits. */
    size_t          device_count;
    stm_pool_device devices[STM_POOL_DEVICES_MAX];

    /* R16 F5 P2: when true, the pool handle refuses structural
     * mutation APIs (add_device, future remove/replace) with
     * STM_EROFS. Mirrors `stm_sync.read_only` — fs_mount plumbs
     * its RO opt through to both. Pools mounted read/write leave
     * this false. */
    bool            read_only;
} stm_pool_open_opts;

/*
 * Construct a pool handle from `opts`. Validates:
 *   - device_count in [1, STM_POOL_DEVICES_MAX];
 *   - every LIVE device slot (state != REMOVED) has non-NULL bdev;
 *   - REMOVED slots (P5-4b-i) have NULL bdev and keep their UUID
 *     for burned-UUID tracking;
 *   - every device's uuid is non-zero (all-zero is the reserved
 *     "unset" marker) and unique within the roster (live OR removed
 *     — burned UUIDs are still duplicates);
 *   - role / class / state are in range.
 *
 * On success, stm_pool_roster_hash(p) is finalized. The caller keeps
 * ownership of each stm_bdev; stm_pool_close does NOT close them.
 */
STM_MUST_USE
stm_status stm_pool_open(const stm_pool_open_opts *opts, stm_pool **out);

/*
 * Release the pool handle. Does NOT close the underlying stm_bdevs —
 * they are borrowed, caller owns their lifecycle.
 *
 * Lifetime contract (R13 P2-1): every stm_sync / stm_alloc handle
 * that borrowed this pool (via stm_sync_create / stm_sync_open)
 * MUST be closed BEFORE stm_pool_close. Those handles cache a
 * borrowed stm_pool * and dereference it on every commit; closing
 * the pool first produces a use-after-free on the next commit.
 * stm_fs_unmount respects this order (sync → alloc → pool → bdev);
 * direct callers should mirror it.
 */
void stm_pool_close(stm_pool *p);

/* ========================================================================= */
/* Accessors.                                                                 */
/* ========================================================================= */

/* Total roster size — INCLUDES REMOVED slots per P5-4b-i. Use this
 * when iterating by device_id [0, count) so REMOVED slots are
 * encountered (caller filters on state). For "how many devices can
 * accept I/O" use stm_pool_live_device_count. */
size_t                   stm_pool_device_count(const stm_pool *p);

/* Count of non-REMOVED devices in the roster (P5-4b-i). This is
 * the right denominator for quorum arithmetic: ⌊live/2⌋+1 quorum.
 * Equals stm_pool_device_count pre-any-remove; strictly less after
 * the first remove. */
size_t                   stm_pool_live_device_count(const stm_pool *p);

stm_bdev *               stm_pool_device_bdev(stm_pool *p, uint16_t device_id);
const stm_pool_device *  stm_pool_device_info(const stm_pool *p, uint16_t device_id);

/* Pool UUID (2× uint64, little-endian on disk). Pointer is valid for
 * the lifetime of `p`. */
const uint64_t *stm_pool_uuid(const stm_pool *p);

/* Current roster hash (le64 truncation of BLAKE3-256 over the encoded
 * 2048-byte roster). Stable across the lifetime of `p` for MVP;
 * device add/remove/fault in P5-4 will mutate it. */
uint64_t stm_pool_roster_hash(const stm_pool *p);

/* ========================================================================= */
/* Roster encoding (on-disk format).                                          */
/* ========================================================================= */

/*
 * Write the pool's roster into the 2048-byte buffer. Populated slots
 * pack at slots [0 .. device_count), remaining bytes zeroed.
 * Deterministic: two pools with identical opts produce byte-identical
 * encodings, so two pool handles can compare roster_hash by equality.
 */
void stm_pool_roster_encode(const stm_pool *p,
                              uint8_t out[STM_POOL_ROSTER_BYTES]);

/*
 * Decode a roster blob into `out_devs` (length = device_count). `bdev`
 * slots in out_devs are left NULL (the decoder has no way to bind to
 * live bdevs — that's the mounter's job). Returns:
 *   - STM_EINVAL if expected_count is 0 or > STM_POOL_DEVICES_MAX;
 *   - STM_ECORRUPT if a populated slot has a zero UUID;
 *   - STM_ECORRUPT if slots >= expected_count carry non-zero bytes
 *     (stale roster slot remnants — indistinguishable from tampering
 *     at this layer; ub_csum would catch actual tampering).
 */
STM_MUST_USE
stm_status stm_pool_roster_decode(const uint8_t in[STM_POOL_ROSTER_BYTES],
                                    uint16_t expected_count,
                                    stm_pool_device out_devs[STM_POOL_DEVICES_MAX]);

/*
 * Standalone hash computation over an already-encoded roster blob.
 * Returns the le64 truncation of BLAKE3-256(in).
 */
uint64_t stm_pool_roster_hash_of_bytes(
    const uint8_t in[STM_POOL_ROSTER_BYTES]);

/* ========================================================================= */
/* Device lifecycle (Phase 5 chunk P5-4).                                     */
/*                                                                             */
/* See docs/ARCHITECTURE.md §4.7.1 (add), §4.7.2 (remove), §4.7.3 (replace). */
/* Formal model: v2/specs/device_lifecycle.tla.                               */
/*                                                                             */
/* Serialization contract (P5-4a MVP): the caller MUST serialize device-     */
/* lifecycle calls with respect to any concurrent sync_commit on the same   */
/* pool. Sync-side calls iterate the pool's device array on every commit;   */
/* a concurrent mutation interleaves unsafely. Use an external lock, or     */
/* add-before-sync-create.                                                   */
/*                                                                             */
/* A per-pool internal lock that sync also holds is deferred to P5-4b —     */
/* requires a wider sync refactor to acquire the pool lock around commits. */
/* ========================================================================= */

/*
 * Append `new_device` to the pool's roster (ARCH §4.7.1). The new
 * device joins at index = current device_count, advances
 * roster_hash, and is picked up by the NEXT sync_commit (the commit
 * writes an UB whose ub_roster / ub_device_count / ub_roster_hash
 * reflect the expanded membership).
 *
 * Preconditions:
 *   - `new_device->bdev` non-NULL.
 *   - `new_device->uuid` non-zero AND not already present in the
 *     roster (each device's UUID is unique per ARCH §4.3.1).
 *   - `new_device->role` / `class_` in range.
 *   - Current device_count < STM_POOL_DEVICES_MAX.
 *
 * State coercion (R16 F1): the spec's AddDevice(d) action transitions
 * the device to ONLINE unconditionally. This API IGNORES
 * `new_device->state` and installs STM_DEV_STATE_ONLINE. A caller
 * that wants to FAIL/DEGRADE a device after adding goes through the
 * FailDevice / DegradeDevice APIs (P5-4d).
 *
 * Size verification (R16 F2): `new_device->size_bytes` is IGNORED.
 * The pool reads the size from `stm_bdev_caps_of(new_device->bdev)`
 * directly. This avoids on-disk roster entries with size_bytes
 * disagreeing with the bdev's actual size.
 *
 * The caller retains ownership of new_device->bdev; the pool
 * borrows it for the pool's lifetime (symmetric with stm_pool_open).
 *
 * Does NOT exercise any other device on the pool (no reads, no
 * writes) — fast. The new device is ONLINE but empty: a subsequent
 * mirror_write or rebalance populates its storage. Sync-layer:
 * attach a fresh stm_alloc for this device via stm_sync_attach_alloc
 * before the next commit that targets it for mirror reservations.
 *
 * **Caller-serialization contract (R16 F4 — strengthened):** the
 * caller MUST guarantee no concurrent `stm_sync_commit` on this
 * pool runs during `stm_pool_add_device`'s duration. Sync's commit
 * reads `device_count`, encodes the roster, and reads `roster_hash`
 * across multiple calls; an interleaving `add_device` leaves the
 * UB with `ub_device_count` disagreeing with `ub_roster` or
 * `ub_roster_hash`, which remount rejects as STM_ECORRUPT and
 * wedges the pool. There is currently NO internal lock enforcing
 * this — a per-pool lock that sync also holds is P5-4b work.
 * Enforce externally: call add_device on the same thread that owns
 * sync, BEFORE sync_create, or BETWEEN sync_commit calls under an
 * application-level lock.
 *
 * **Burned-UUID tracking (R16 F3 — P5-4b precondition):** this
 * function's UUID uniqueness walk covers only the LIVE roster.
 * Once `stm_pool_remove_device` (P5-4b) lands, the same UUID must
 * stay rejected here even after remove — re-using a UUID that
 * previously identified a device in the pool would collide with
 * the AEAD nonce invariant (R15 F1) for any metadata written
 * under the historical device. P5-4b must persist REMOVED slots
 * in the roster AND this walk must iterate through them.
 *
 * Returns:
 *   STM_OK           — device added; roster_hash advanced.
 *   STM_EROFS        — pool was opened read_only.
 *   STM_EINVAL       — shape violation on new_device.
 *   STM_ENOSPC       — roster is full (device_count == STM_POOL_DEVICES_MAX).
 *   STM_EEXIST       — new_device->uuid matches an existing roster entry.
 */
STM_MUST_USE
stm_status stm_pool_add_device(stm_pool *p, const stm_pool_device *new_device);

/*
 * Mark device `device_id` as REMOVED (ARCH §4.7.2). P5-4b-i is the
 * "metadata half" of remove — it transitions the roster slot to
 * REMOVED, clears its `bdev` pointer, and preserves the UUID so
 * subsequent `stm_pool_add_device` walks refuse to re-add it
 * (burned-UUID; R16 F3).
 *
 * Evacuation of allocated blocks (the "data half" — reading the
 * target device's content and mirror-writing to remaining devices)
 * is P5-4b-ii scope. Today this function enforces that ONLY a
 * device with NO allocated data may be removed. The caller's
 * alloc-layer contract: verify the device's alloc tree is empty
 * before calling this, or get STM_EINVAL / STM_EBUSY (future).
 *
 * Preconditions:
 *   - device_id < stm_pool_device_count(p).
 *   - Slot state is ONLINE or FAULTED (already REMOVED → EINVAL).
 *   - `stm_pool_live_device_count(p) - 1 >= redundancy_floor`
 *     (spec's RedundancyPreservedOnRemove invariant). Caller
 *     supplies the floor from the sync handle's redundancy
 *     profile — typically `profile.mirror_n` for MIRROR, 1 for
 *     NONE. Mismatch → STM_EINVAL.
 *
 * Post-condition: slot at `device_id` has state=REMOVED,
 * bdev=NULL, UUID preserved. `device_count` UNCHANGED (REMOVED
 * slots persist in the roster). `live_device_count` decremented.
 * `roster_hash` advances.
 *
 * Caller-serialization contract (same as `stm_pool_add_device`):
 * serialize against concurrent sync_commit externally. Internal
 * per-pool lock lands in P5-4b-ii.
 *
 * RO pools: returns STM_EROFS.
 *
 * Returns:
 *   STM_OK           — slot marked REMOVED; roster_hash advanced.
 *   STM_EROFS        — pool is read_only.
 *   STM_EINVAL       — device_id out of range, slot already REMOVED,
 *                       or redundancy_floor would be violated.
 */
STM_MUST_USE
stm_status stm_pool_remove_device(stm_pool *p, uint16_t device_id,
                                     size_t redundancy_floor);

/*
 * Begin evacuation of `device_id` (P5-4b-ii-α). Transitions the slot
 * from ONLINE/FAULTED to EVACUATING, clamped by two invariants from
 * v2/specs/evac.tla:
 *
 *   * AtMostOneEvacuating — at most one slot is EVACUATING at a time.
 *     A second call while another slot is draining returns STM_EBUSY.
 *   * RedundancyPreservedDuringEvacuation — post-remove live count
 *     (live - 1) must still clear `redundancy_floor`. Arithmetic
 *     identical to stm_pool_remove_device.
 *
 * The caller drives the drain with `stm_sync_evacuation_step` until
 * STM_ENODATA, then finalizes with `stm_pool_finish_evacuation`. The
 * sequence must complete within one mount session: on crash recovery
 * during EVACUATING, the next mount sees the state byte in the
 * uberblock's roster and must decide whether to resume the drain or
 * abort-and-rollback. P5-4b-ii-α leaves that choice to the operator;
 * the recovery loop lands with P5-4d (reconcile / fail / rejoin).
 *
 * RO pools refuse (STM_EROFS). An already-EVACUATING slot refuses
 * (STM_EINVAL — use evacuation_step or finish_evacuation, not double
 * begin). Same caller-serialization contract as add_device /
 * remove_device — serialize against concurrent sync_commit until
 * P5-4b-ii-β lands the per-pool lock.
 */
STM_MUST_USE
stm_status stm_pool_begin_evacuation(stm_pool *p, uint16_t device_id,
                                        size_t redundancy_floor);

/*
 * Finalize an evacuation (P5-4b-ii-α). Transitions EVACUATING to
 * REMOVED. No redundancy re-check — that happened at begin.
 *
 * Precondition (checked by caller, not enforced here): sync's
 * evacuation_step returned STM_ENODATA for this device, i.e., the
 * alloc tree is drained. Callers that skip this check and call
 * finish with live data still on the device leave the post-remove
 * block pointers dangling (sync's mirror_read will fail to find the
 * target's replicas and must rely on surviving copies). The spec's
 * NoTargetReplicasAfterComplete invariant encodes this precondition.
 *
 * Post: slot state = REMOVED, bdev = NULL, UUID preserved (burned).
 */
STM_MUST_USE
stm_status stm_pool_finish_evacuation(stm_pool *p, uint16_t device_id);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_POOL_H */
