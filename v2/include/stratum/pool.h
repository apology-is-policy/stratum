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
} stm_pool_open_opts;

/*
 * Construct a pool handle from `opts`. Validates:
 *   - device_count in [1, STM_POOL_DEVICES_MAX];
 *   - every device slot has non-NULL bdev;
 *   - every device's uuid is non-zero (all-zero is the reserved
 *     "unset" marker) and unique within the roster;
 *   - role / class / state are in range.
 *
 * On success, stm_pool_roster_hash(p) is finalized. The caller keeps
 * ownership of each stm_bdev; stm_pool_close does NOT close them.
 */
STM_MUST_USE
stm_status stm_pool_open(const stm_pool_open_opts *opts, stm_pool **out);

void stm_pool_close(stm_pool *p);

/* ========================================================================= */
/* Accessors.                                                                 */
/* ========================================================================= */

size_t                   stm_pool_device_count(const stm_pool *p);
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

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_POOL_H */
