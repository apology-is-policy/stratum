/* SPDX-License-Identifier: ISC */
/*
 * Pool layer (Phase 5 chunk P5-1).
 *
 *   see include/stratum/pool.h  — surface + on-disk roster encoding.
 *   see docs/ARCHITECTURE.md §4.3, §5.13.
 *
 * P5-1 scope:
 *   - stm_pool_open / _close — construct handle from opts, validate,
 *     precompute the roster hash.
 *   - Roster encode/decode/hash primitives, shared with sync.c so the
 *     uberblock's ub_roster / ub_roster_hash fields are populated
 *     from one source of truth.
 *
 * What this module deliberately does NOT do:
 *   - Open block devices. Callers open bdevs (stm_bdev_open_posix /
 *     _iouring) and hand them over; the pool borrows them. This keeps
 *     lifecycle symmetric with sync/alloc/keyschema (all borrowers).
 *   - Multi-device commit. Sync (P5-2) drives that.
 *   - Device add/remove/replace. P5-4.
 *   - Redundancy (mirror / RS / LRC). P5-3 onward.
 */

#include <stratum/pool.h>
#include <stratum/hash.h>
#include <stratum/block.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Slot byte offsets within a 32-byte roster entry (mirrors pool.h docstring). */
#define OFF_UUID0       0u
#define OFF_UUID1       8u
#define OFF_SIZE_BYTES  16u
#define OFF_ROLE        24u
#define OFF_CLASS       25u
#define OFF_STATE       26u
/* 27..31 reserved (zero). */

struct stm_pool {
    uint64_t        pool_uuid[2];
    size_t          device_count;
    stm_pool_device devices[STM_POOL_DEVICES_MAX];
    uint64_t        roster_hash;  /* cached: recomputed on any mutation */
    bool            read_only;    /* R16 F5 P2: RO pools refuse mutation */
    /* R16 F4 / P5-4b-ii-β: per-pool rwlock. Writers (add / remove /
     * begin_evac / finish_evac) take the exclusive side; readers
     * (sync_commit's pool-read phase, reserve_mirror's device
     * selection, evac_step's survivor pick) take the shared side via
     * the public stm_pool_lock_* APIs. Lock order (global): POOL
     * OUTER, SYNC INNER — every composite critical section takes
     * pool first. Deadlock-by-reversal is a contract violation. */
    pthread_rwlock_t lock;
    /* P5-8: replace-in-flight claim. UINT16_MAX = unclaimed; else the
     * slot id claimed by an in-flight stm_sync_replace_device_online.
     * Protected by the rwlock above. Non-_locked mutators refuse
     * STM_EBUSY when their target slot matches the claim. */
    uint16_t         replace_claim;
};

/* ========================================================================= */
/* Encode / decode / hash primitives.                                         */
/* ========================================================================= */

static void encode_slot(uint8_t *slot /* 32 bytes */,
                         const stm_pool_device *d)
{
    le64 u0 = stm_store_le64(d->uuid[0]);
    le64 u1 = stm_store_le64(d->uuid[1]);
    le64 sz = stm_store_le64(d->size_bytes);
    memcpy(slot + OFF_UUID0,      u0.v, 8);
    memcpy(slot + OFF_UUID1,      u1.v, 8);
    memcpy(slot + OFF_SIZE_BYTES, sz.v, 8);
    slot[OFF_ROLE]  = (uint8_t)d->role;
    slot[OFF_CLASS] = (uint8_t)d->class_;
    slot[OFF_STATE] = (uint8_t)d->state;
    /* bytes [27..31] left untouched — caller must pre-zero the full
     * 2048-byte buffer. */
}

static void encode_all(const stm_pool_device *devs, size_t count,
                        uint8_t out[STM_POOL_ROSTER_BYTES])
{
    memset(out, 0, STM_POOL_ROSTER_BYTES);
    for (size_t i = 0; i < count; i++) {
        encode_slot(out + i * STM_POOL_ROSTER_SLOT_SIZE, &devs[i]);
    }
}

uint64_t stm_pool_roster_hash_of_bytes(const uint8_t in[STM_POOL_ROSTER_BYTES])
{
    stm_blake3_hash h;
    stm_blake3(in, STM_POOL_ROSTER_BYTES, &h);
    /* Little-endian load of the first 8 bytes of the digest. */
    le64 tmp;
    memcpy(tmp.v, h.bytes, 8);
    return stm_load_le64(tmp);
}

static uint64_t hash_of_devs(const stm_pool_device *devs, size_t count)
{
    uint8_t buf[STM_POOL_ROSTER_BYTES];
    encode_all(devs, count, buf);
    return stm_pool_roster_hash_of_bytes(buf);
}

/* ========================================================================= */
/* Public encode / decode.                                                    */
/* ========================================================================= */

void stm_pool_roster_encode(const stm_pool *p,
                              uint8_t out[STM_POOL_ROSTER_BYTES])
{
    encode_all(p->devices, p->device_count, out);
}

stm_status stm_pool_roster_decode(const uint8_t in[STM_POOL_ROSTER_BYTES],
                                    uint16_t expected_count,
                                    stm_pool_device out_devs[STM_POOL_DEVICES_MAX])
{
    if (expected_count == 0 || expected_count > STM_POOL_DEVICES_MAX) {
        return STM_EINVAL;
    }
    /* Parse populated slots. */
    for (uint16_t i = 0; i < expected_count; i++) {
        const uint8_t *slot = in + (size_t)i * STM_POOL_ROSTER_SLOT_SIZE;
        le64 u0, u1, sz;
        memcpy(u0.v, slot + OFF_UUID0,      8);
        memcpy(u1.v, slot + OFF_UUID1,      8);
        memcpy(sz.v, slot + OFF_SIZE_BYTES, 8);
        uint64_t uuid0 = stm_load_le64(u0);
        uint64_t uuid1 = stm_load_le64(u1);
        if (uuid0 == 0 && uuid1 == 0) {
            /* Populated slot must have a non-zero UUID. */
            return STM_ECORRUPT;
        }
        out_devs[i].uuid[0]    = uuid0;
        out_devs[i].uuid[1]    = uuid1;
        out_devs[i].size_bytes = stm_load_le64(sz);
        out_devs[i].role       = (stm_device_role)  slot[OFF_ROLE];
        out_devs[i].class_     = (stm_device_class) slot[OFF_CLASS];
        out_devs[i].state      = (stm_device_state) slot[OFF_STATE];
        out_devs[i].bdev       = NULL;
        /* R13 P2-3: reserved bytes [27..31] of a populated slot must
         * be zero. The encoder zeros them (via the outer memset);
         * non-zero bytes here indicate either a buggy writer or a
         * tamper attempt. Symmetric with the unused-slots-must-be-zero
         * check below. */
        for (size_t b = 27; b < STM_POOL_ROSTER_SLOT_SIZE; b++) {
            if (slot[b] != 0) return STM_ECORRUPT;
        }
    }
    /* Unused slots must be zero. A leftover non-zero slot would mean
     * either a prior device was never cleanly zeroed on remove (buggy
     * P5-4) or an attacker overwrote the post-count region of ub_roster.
     * ub_csum would already catch the attacker case; the bug case is
     * still worth flagging loudly. */
    for (size_t i = expected_count; i < STM_POOL_DEVICES_MAX; i++) {
        const uint8_t *slot = in + i * STM_POOL_ROSTER_SLOT_SIZE;
        for (size_t b = 0; b < STM_POOL_ROSTER_SLOT_SIZE; b++) {
            if (slot[b] != 0) return STM_ECORRUPT;
        }
    }
    return STM_OK;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

static bool uuid_is_zero(const uint64_t u[2]) {
    return u[0] == 0 && u[1] == 0;
}

static bool role_in_range(stm_device_role r) {
    switch (r) {
        case STM_DEV_ROLE_UNSET:
        case STM_DEV_ROLE_DATA:
        case STM_DEV_ROLE_LOG:
        case STM_DEV_ROLE_CACHE:
        case STM_DEV_ROLE_SPARE:
            return true;
    }
    return false;
}

static bool class_in_range(stm_device_class c) {
    switch (c) {
        case STM_DEV_CLASS_UNSET:
        case STM_DEV_CLASS_SSD:
        case STM_DEV_CLASS_HDD:
        case STM_DEV_CLASS_PMEM:
        case STM_DEV_CLASS_ZNS:
            return true;
    }
    return false;
}

static bool state_in_range(stm_device_state s) {
    switch (s) {
        case STM_DEV_STATE_UNSET:
        case STM_DEV_STATE_ONLINE:
        case STM_DEV_STATE_OFFLINE:
        case STM_DEV_STATE_DEGRADED:
        case STM_DEV_STATE_FAULTED:
        case STM_DEV_STATE_REMOVED:
        case STM_DEV_STATE_EVACUATING:
            return true;
    }
    return false;
}

stm_status stm_pool_open(const stm_pool_open_opts *opts, stm_pool **out)
{
    if (!opts || !out) return STM_EINVAL;
    if (opts->device_count == 0 ||
        opts->device_count > STM_POOL_DEVICES_MAX) {
        return STM_EINVAL;
    }

    /* Validate every device slot. P5-4b-i: REMOVED slots are
     * persisted in the roster with NULL bdev; live slots must have
     * bdev non-NULL. Every slot keeps its UUID (REMOVED slots' UUIDs
     * are "burned" — cannot be re-added, per spec's AddDevice ABSENT
     * guard + R16 F3 tightening). */
    for (size_t i = 0; i < opts->device_count; i++) {
        const stm_pool_device *d = &opts->devices[i];
        if (!state_in_range(d->state))  return STM_EINVAL;
        /* R21 (P5-6 P2-4): device 0 is the metadata primary (sync
         * hard-codes it for keyschema / alloc-roots I/O). Every
         * runtime mutator refuses dev 0 transitions (fail / remove /
         * begin_evacuation all return STM_ENOTSUPPORTED) — guard the
         * open boundary symmetrically so an operator constructing a
         * pool handle with dev 0 pre-marked FAULTED / OFFLINE /
         * EVACUATING / DEGRADED cannot bypass the invariant. Only
         * ONLINE is accepted at slot 0. The dynamic-metadata-primary
         * refactor (post-P5) relaxes this. */
        if (i == 0 && d->state != STM_DEV_STATE_ONLINE) return STM_EINVAL;
        if (d->state == STM_DEV_STATE_REMOVED) {
            /* REMOVED: bdev must be NULL, UUID preserved. */
            if (d->bdev != NULL) return STM_EINVAL;
        } else {
            /* Live (ONLINE / FAULTED / DEGRADED / OFFLINE / EVACUATING):
             * bdev non-NULL. EVACUATING is still readable and its
             * alloc tree is still live — data-half of remove_device
             * (P5-4b-ii) drains it range-by-range. */
            if (!d->bdev) return STM_EINVAL;
        }
        if (uuid_is_zero(d->uuid)) return STM_EINVAL;
        if (!role_in_range(d->role))   return STM_EINVAL;
        if (!class_in_range(d->class_)) return STM_EINVAL;
        /* Uniqueness of UUID — covers REMOVED slots too (their UUIDs
         * remain burned so a new device cannot re-use them). */
        for (size_t j = 0; j < i; j++) {
            const stm_pool_device *e = &opts->devices[j];
            if (e->uuid[0] == d->uuid[0] && e->uuid[1] == d->uuid[1]) {
                return STM_EINVAL;
            }
        }
    }

    stm_pool *p = calloc(1, sizeof *p);
    if (!p) return STM_ENOMEM;

    /* rwlock init — must land BEFORE any publish of `p`.
     *
     * R18 P2-1: on Linux, the default rwlock attrs favor readers,
     * allowing writer starvation under sustained sync-side traffic.
     * Set writer preference explicitly where the attr is available.
     * macOS / other POSIX: default attrs already give reasonable
     * scheduler fairness; pass NULL. */
#if defined(__linux__) && defined(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setkind_np(&attr,
        PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    int rc = pthread_rwlock_init(&p->lock, &attr);
    pthread_rwlockattr_destroy(&attr);
#else
    int rc = pthread_rwlock_init(&p->lock, NULL);
#endif
    if (rc != 0) { free(p); return STM_ENOMEM; }

    p->pool_uuid[0] = opts->pool_uuid[0];
    p->pool_uuid[1] = opts->pool_uuid[1];
    p->device_count = opts->device_count;
    p->read_only    = opts->read_only;
    for (size_t i = 0; i < opts->device_count; i++) {
        p->devices[i] = opts->devices[i];
    }
    p->roster_hash    = hash_of_devs(p->devices, p->device_count);
    p->replace_claim  = STM_POOL_REPLACE_CLAIM_NONE;

    *out = p;
    return STM_OK;
}

void stm_pool_close(stm_pool *p)
{
    if (!p) return;
    /* Caller must not call close while any other thread holds the
     * lock — POSIX says destroying a locked rwlock is UB. The
     * lifetime contract (pool.h) requires every sync handle to be
     * closed before the pool; sync handles are the lock's primary
     * users on the read side.
     *
     * R18 P2-5: loud-fail on contract violation. Try acquiring the
     * exclusive side; if we can't, abort with a diagnostic. This
     * converts a silent heap corruption (destroy-while-locked UB)
     * into a visible crash. trywrlock returns 0 if acquired, EBUSY
     * if held, or other errno for malformed rwlock. The subsequent
     * destroy is then safe. */
    int trc = pthread_rwlock_trywrlock(&p->lock);
    if (trc != 0) {
        fprintf(stderr,
                "stm_pool_close: rwlock held at destroy time "
                "(trywrlock=%d); contract violation — a sync or "
                "other borrower was not closed before the pool.\n",
                trc);
        abort();
    }
    pthread_rwlock_unlock(&p->lock);
    (void)pthread_rwlock_destroy(&p->lock);
    /* Borrowers of stm_bdev — we don't close them; wiping the roster
     * is belt-and-braces against lingering pointers. */
    memset(p->devices, 0, sizeof p->devices);
    free(p);
}

/* ========================================================================= */
/* P5-4b-ii-β: per-pool lock API.                                             */
/* ========================================================================= */

void stm_pool_lock_shared(stm_pool *p) {
    if (p) (void)pthread_rwlock_rdlock(&p->lock);
}

void stm_pool_unlock_shared(stm_pool *p) {
    if (p) (void)pthread_rwlock_unlock(&p->lock);
}

void stm_pool_lock_exclusive(stm_pool *p) {
    if (p) (void)pthread_rwlock_wrlock(&p->lock);
}

void stm_pool_unlock_exclusive(stm_pool *p) {
    if (p) (void)pthread_rwlock_unlock(&p->lock);
}

/* ========================================================================= */
/* P5-8: replace-in-flight claim.                                             */
/* ========================================================================= */

stm_status stm_pool_set_replace_claim_locked(stm_pool *p, uint16_t slot)
{
    if (!p) return STM_EINVAL;
    if ((size_t)slot >= p->device_count) return STM_EINVAL;
    /* Idempotent on same-slot: if the claim is already held on `slot`,
     * return OK without changing state. This lets a replace retry
     * reclaim its own prior partial-state claim cleanly. A claim on
     * a DIFFERENT slot refuses STM_EBUSY (someone else's replace is
     * in flight; we cannot start ours). */
    if (p->replace_claim == slot) return STM_OK;
    if (p->replace_claim != STM_POOL_REPLACE_CLAIM_NONE) return STM_EBUSY;
    p->replace_claim = slot;
    return STM_OK;
}

stm_status stm_pool_set_replace_claim(stm_pool *p, uint16_t slot)
{
    if (!p) return STM_EINVAL;
    pthread_rwlock_wrlock(&p->lock);
    stm_status s = stm_pool_set_replace_claim_locked(p, slot);
    pthread_rwlock_unlock(&p->lock);
    return s;
}

void stm_pool_clear_replace_claim_locked(stm_pool *p)
{
    if (!p) return;
    p->replace_claim = STM_POOL_REPLACE_CLAIM_NONE;
}

void stm_pool_clear_replace_claim(stm_pool *p)
{
    if (!p) return;
    pthread_rwlock_wrlock(&p->lock);
    p->replace_claim = STM_POOL_REPLACE_CLAIM_NONE;
    pthread_rwlock_unlock(&p->lock);
}

uint16_t stm_pool_replace_claim(const stm_pool *p)
{
    if (!p) return STM_POOL_REPLACE_CLAIM_NONE;
    stm_pool *mp = (stm_pool *)p;
    pthread_rwlock_rdlock(&mp->lock);
    uint16_t v = mp->replace_claim;
    pthread_rwlock_unlock(&mp->lock);
    return v;
}

/* Internal: returns true iff the public-API mutator on `target_slot`
 * should refuse with STM_EBUSY due to an active replace claim. Caller
 * must already hold pool.wrlock (mutators do this). */
static inline bool claim_blocks(const stm_pool *p, uint16_t target_slot)
{
    return p->replace_claim != STM_POOL_REPLACE_CLAIM_NONE &&
           p->replace_claim == target_slot;
}

/* ========================================================================= */
/* Accessors.                                                                 */
/* ========================================================================= */

size_t stm_pool_device_count(const stm_pool *p) {
    return p ? p->device_count : 0;
}

size_t stm_pool_live_device_count(const stm_pool *p) {
    if (!p) return 0;
    size_t live = 0;
    for (size_t i = 0; i < p->device_count; i++) {
        if (p->devices[i].state != STM_DEV_STATE_REMOVED) live++;
    }
    return live;
}

stm_bdev *stm_pool_device_bdev(stm_pool *p, uint16_t device_id) {
    if (!p || device_id >= p->device_count) return NULL;
    return p->devices[device_id].bdev;
}

const stm_pool_device *stm_pool_device_info(const stm_pool *p, uint16_t device_id) {
    if (!p || device_id >= p->device_count) return NULL;
    return &p->devices[device_id];
}

const uint64_t *stm_pool_uuid(const stm_pool *p) {
    return p ? p->pool_uuid : NULL;
}

uint64_t stm_pool_roster_hash(const stm_pool *p) {
    return p ? p->roster_hash : 0;
}

/* ========================================================================= */
/* Device lifecycle — P5-4.                                                   */
/* ========================================================================= */

stm_status stm_pool_add_device_locked(stm_pool *p,
                                          const stm_pool_device *new_device)
{
    /* Caller MUST hold pool's exclusive lock. The public
     * stm_pool_add_device wrapper below does the locking. */
    if (!p || !new_device) return STM_EINVAL;

    /* R16 F5 P2: RO pools refuse structural mutation. Same policy as
     * stm_sync's mirror-write / commit refusing under read_only. */
    if (p->read_only) return STM_EROFS;

    if (!new_device->bdev) return STM_EINVAL;
    if (uuid_is_zero(new_device->uuid)) return STM_EINVAL;
    if (!role_in_range(new_device->role))   return STM_EINVAL;
    if (!class_in_range(new_device->class_)) return STM_EINVAL;
    /* R16 F1 P1: state is coerced to ONLINE below; we intentionally do
     * NOT validate new_device->state here (the caller's value is
     * discarded). The spec's AddDevice(d) transitions to ONLINE
     * unconditionally — FAULTED / REMOVED states must be reached via
     * the dedicated transitions (fail/remove), never via add. */

    /* R16 F2 P1: derive size_bytes from the bdev, not the caller's
     * input. Avoids on-disk roster entries whose size_bytes disagrees
     * with the bdev's actual size. */
    const stm_bdev_caps *caps = stm_bdev_caps_of(new_device->bdev);
    if (!caps) return STM_EINVAL;

    /* Roster capacity check. STM_POOL_DEVICES_MAX matches the 64-slot
     * ub_roster[2048] layout; beyond that, the on-disk format doesn't
     * fit. */
    if (p->device_count >= STM_POOL_DEVICES_MAX) return STM_ENOSPC;

    /* UUID uniqueness against the current roster. Every device's UUID
     * is unique across the pool's lifetime (ARCH §4.3.1). P5-4a MVP
     * checks the live roster only; burned-UUID tracking for REMOVED
     * devices lands with P5-4b remove + replace (needs the REMOVED
     * slot persistence). Documented as a P5-4b precondition in pool.h.
     *
     * AddDeviceIdempotent from device_lifecycle.tla: AddDevice(d) is
     * rejected when d is already ONLINE or FAULTED — enforced here by
     * the UUID uniqueness check (ABSENT devices aren't in the array at
     * all, so they're trivially not duplicates). */
    for (size_t i = 0; i < p->device_count; i++) {
        if (p->devices[i].uuid[0] == new_device->uuid[0] &&
             p->devices[i].uuid[1] == new_device->uuid[1]) {
            return STM_EEXIST;
        }
    }

    /* Build the canonical slot: caller-supplied uuid / role / class
     * plus derived bdev + size_bytes + coerced state=ONLINE. */
    stm_pool_device slot = *new_device;
    slot.size_bytes = caps->size_bytes;
    slot.state      = STM_DEV_STATE_ONLINE;

    /* Append + rehash. Matches the TLA model's AddDevice action. */
    p->devices[p->device_count] = slot;
    p->device_count++;
    p->roster_hash = hash_of_devs(p->devices, p->device_count);

    return STM_OK;
}

stm_status stm_pool_add_device(stm_pool *p, const stm_pool_device *new_device)
{
    if (!p) return STM_EINVAL;
    pthread_rwlock_wrlock(&p->lock);
    /* P5-8: an in-flight replace claims the slot it just added. Until
     * the replace completes (clears the claim), reject external add too —
     * the new slot index would collide if the claim's slot is at the
     * tail. Strict refusal keeps the invariant simple. */
    if (p->replace_claim != STM_POOL_REPLACE_CLAIM_NONE) {
        pthread_rwlock_unlock(&p->lock);
        return STM_EBUSY;
    }
    stm_status s = stm_pool_add_device_locked(p, new_device);
    pthread_rwlock_unlock(&p->lock);
    return s;
}

stm_status stm_pool_remove_device_locked(stm_pool *p, uint16_t device_id,
                                              size_t redundancy_floor)
{
    /* Caller MUST hold pool's exclusive lock. */
    if (!p) return STM_EINVAL;

    /* R16 F5 symmetric: RO pools refuse structural mutation. */
    if (p->read_only) return STM_EROFS;

    if ((size_t)device_id >= p->device_count) return STM_EINVAL;

    /* R17 P1-1: device 0 is the metadata primary (sync_open hard-codes
     * it at pool.c:1163 for keyschema + alloc-roots). Removing it
     * makes the pool unmountable. Until sync_open picks a dynamic
     * primary (post-P5-4c), reject at the boundary. */
    if (device_id == 0) return STM_ENOTSUPPORTED;

    stm_pool_device *slot = &p->devices[device_id];
    /* Slot must be LIVE to be removed. REMOVED → already burned.
     * EVACUATING → caller must finish the in-flight evacuation via
     * stm_pool_finish_evacuation (the data-half of remove). Pre
     * P5-4b-ii this state was unreachable so the check was absent;
     * now that evacuation is explicit, route accidental direct
     * remove calls on draining devices to EINVAL so they don't skip
     * the evacuation step and leak live data. */
    if (slot->state == STM_DEV_STATE_REMOVED)    return STM_EINVAL;
    if (slot->state == STM_DEV_STATE_EVACUATING) return STM_EINVAL;

    /* R17 P2-2: refuse when any OTHER slot is EVACUATING. Concurrent
     * remove + in-flight evacuation is a live-count accounting hazard
     * (begin_evac checked live-1 against floor with a live count
     * that now is stale by this remove). Mirror AtMostOneEvacuating's
     * spirit to the remove path. */
    for (size_t i = 0; i < p->device_count; i++) {
        if (p->devices[i].state == STM_DEV_STATE_EVACUATING) {
            return STM_EBUSY;
        }
    }

    /* Spec's RedundancyPreservedOnRemove (device_lifecycle.tla):
     * post-remove live count must remain >= redundancy_floor.
     * Caller supplies the floor from the sync handle's profile
     * (typically profile.mirror_n for MIRROR, 1 for NONE). The
     * pool layer is oblivious to profile semantics — the arithmetic
     * contract lives with the caller.
     *
     * The buggy variant of this guard was demonstrated by
     * device_lifecycle_buggy.cfg: removing without the check drops
     * the roster below the redundancy floor → counterexample at
     * depth 2. We enforce in-code by explicitly computing live
     * count and refusing if (live - 1) < floor. */
    size_t live = 0;
    for (size_t i = 0; i < p->device_count; i++) {
        if (p->devices[i].state != STM_DEV_STATE_REMOVED) live++;
    }
    /* `live` includes the slot we're about to remove. After the
     * transition the count decrements by 1. */
    if (live == 0) return STM_EINVAL;   /* impossible: slot is live */
    if ((live - 1) < redundancy_floor) return STM_EINVAL;

    /* Transition: state=REMOVED, bdev=NULL, UUID preserved. The
     * slot becomes a burned-UUID tombstone: future add_device sees
     * the UUID in its uniqueness walk and refuses re-add. size_bytes,
     * role, class remain historical (harmless — slot's role in the
     * pool is done). */
    slot->state = STM_DEV_STATE_REMOVED;
    slot->bdev  = NULL;

    /* Recompute roster_hash. The changed state byte + cleared bdev
     * ptr (which doesn't affect encoding — bdev isn't on-disk) mean
     * the encoded bytes change → new hash. */
    p->roster_hash = hash_of_devs(p->devices, p->device_count);

    return STM_OK;
}

stm_status stm_pool_remove_device(stm_pool *p, uint16_t device_id,
                                      size_t redundancy_floor)
{
    if (!p) return STM_EINVAL;
    pthread_rwlock_wrlock(&p->lock);
    if (claim_blocks(p, device_id)) {
        pthread_rwlock_unlock(&p->lock);
        return STM_EBUSY;
    }
    stm_status s = stm_pool_remove_device_locked(p, device_id, redundancy_floor);
    pthread_rwlock_unlock(&p->lock);
    return s;
}

/* ========================================================================= */
/* P5-4b-ii: evacuation state-machine half.                                  */
/* ========================================================================= */

stm_status stm_pool_begin_evacuation_locked(stm_pool *p, uint16_t device_id,
                                                size_t redundancy_floor)
{
    /* Caller MUST hold pool's exclusive lock. */
    if (!p) return STM_EINVAL;
    if (p->read_only) return STM_EROFS;
    if ((size_t)device_id >= p->device_count) return STM_EINVAL;

    /* R17 P1-1: device 0 is the metadata primary (sync_open hard-codes
     * it). Draining and removing it leaves the pool unmountable. Same
     * guard as stm_pool_remove_device. */
    if (device_id == 0) return STM_ENOTSUPPORTED;

    stm_pool_device *slot = &p->devices[device_id];
    /* Only ONLINE / FAULTED are eligible. REMOVED is a burned tombstone;
     * EVACUATING is the one we're about to become — double-begin is a
     * caller bug (should call evacuation_step instead). */
    if (slot->state != STM_DEV_STATE_ONLINE &&
        slot->state != STM_DEV_STATE_FAULTED) {
        return STM_EINVAL;
    }

    /* AtMostOneEvacuating (evac.tla): at most one EVACUATING slot at a
     * time. The spec's AtMostOneEvacuating invariant encodes this as
     * "|{d : device_state[d] = EVACUATING}| <= 1"; we enforce by
     * walking the roster and refusing a second begin. Sync's
     * evacuation_step discovers the target via this state byte; two
     * concurrent evacuations would race on which survivor receives
     * which block. */
    for (size_t i = 0; i < p->device_count; i++) {
        if (p->devices[i].state == STM_DEV_STATE_EVACUATING) {
            return STM_EBUSY;
        }
    }

    /* RedundancyPreservedDuringEvacuation (evac.tla): the post-remove
     * live count must still clear redundancy_floor. The check must
     * fire HERE (at begin) rather than at finish, because once we
     * flip the state byte to EVACUATING, sync's reserve_mirror routes
     * around us and new writes depend on the floor holding. The
     * arithmetic is identical to remove_device: (live - 1) >= floor,
     * where `live` includes the slot we're about to drain. */
    size_t live = 0;
    for (size_t i = 0; i < p->device_count; i++) {
        if (p->devices[i].state != STM_DEV_STATE_REMOVED) live++;
    }
    if (live == 0) return STM_EINVAL;   /* impossible: slot is live */
    if ((live - 1) < redundancy_floor) return STM_EINVAL;

    slot->state = STM_DEV_STATE_EVACUATING;
    p->roster_hash = hash_of_devs(p->devices, p->device_count);
    return STM_OK;
}

stm_status stm_pool_begin_evacuation(stm_pool *p, uint16_t device_id,
                                         size_t redundancy_floor)
{
    if (!p) return STM_EINVAL;
    pthread_rwlock_wrlock(&p->lock);
    if (claim_blocks(p, device_id)) {
        pthread_rwlock_unlock(&p->lock);
        return STM_EBUSY;
    }
    stm_status s = stm_pool_begin_evacuation_locked(p, device_id,
                                                       redundancy_floor);
    pthread_rwlock_unlock(&p->lock);
    return s;
}

stm_status stm_pool_finish_evacuation_locked(stm_pool *p, uint16_t device_id)
{
    /* Caller MUST hold pool's exclusive lock. */
    if (!p) return STM_EINVAL;
    if (p->read_only) return STM_EROFS;
    if ((size_t)device_id >= p->device_count) return STM_EINVAL;

    stm_pool_device *slot = &p->devices[device_id];
    /* Must be in the EVACUATING state — this API is ONLY the finalize
     * step of a begin/step/finish sequence. Callers who want to abort
     * an in-progress evacuation would use a separate cancel API (not
     * provided in P5-4b-ii-α; survivor copies would need cleanup
     * before rolling EVACUATING back to ONLINE). */
    if (slot->state != STM_DEV_STATE_EVACUATING) return STM_EINVAL;

    /* No redundancy re-check: begin_evacuation already established
     * (live - 1) >= floor. The caller's contract is that they must
     * not drop the floor between begin and finish (no concurrent
     * add/remove below the floor). If FailDevice lands on a survivor
     * during evacuation, device_lifecycle.tla's FailDevice action
     * keeps it in the live count (FAULTED still counts toward the
     * roster), so the check at begin is robust.
     *
     * Note: this is NOT the place to check "alloc tree empty" — that's
     * the sync layer's concern. sync's evacuation_step returns
     * STM_ENODATA when the tree is drained; the caller then invokes
     * this function. If a caller calls us with data still on the
     * target, sync's reserve_mirror already refuses to allocate to
     * an EVACUATING/REMOVED device, so the remaining data becomes
     * unreachable (readable via mirror_read from survivors, but no
     * fresh writes land there). Future: enforce emptiness by giving
     * pool a borrowed view into sync's allocs[]. */

    slot->state = STM_DEV_STATE_REMOVED;
    slot->bdev  = NULL;
    p->roster_hash = hash_of_devs(p->devices, p->device_count);
    return STM_OK;
}

stm_status stm_pool_finish_evacuation(stm_pool *p, uint16_t device_id)
{
    if (!p) return STM_EINVAL;
    pthread_rwlock_wrlock(&p->lock);
    if (claim_blocks(p, device_id)) {
        pthread_rwlock_unlock(&p->lock);
        return STM_EBUSY;
    }
    stm_status s = stm_pool_finish_evacuation_locked(p, device_id);
    pthread_rwlock_unlock(&p->lock);
    return s;
}

/* ========================================================================= */
/* P5-4d-α: FailDevice / RejoinDevice state transitions.                     */
/* ========================================================================= */

stm_status stm_pool_fail_device_locked(stm_pool *p, uint16_t device_id)
{
    /* Caller MUST hold pool's exclusive lock. */
    if (!p) return STM_EINVAL;
    if (p->read_only) return STM_EROFS;
    if ((size_t)device_id >= p->device_count) return STM_EINVAL;

    /* R17 P1-1: dev 0 is the metadata primary. Failing it would
     * strand the pool — sync_open hard-codes dev 0. Refuse until a
     * dynamic-primary mechanism lands. */
    if (device_id == 0) return STM_ENOTSUPPORTED;

    stm_pool_device *slot = &p->devices[device_id];
    /* Only ONLINE → FAULTED. EVACUATING / REMOVED / already FAULTED
     * have no business transitioning via this path. */
    if (slot->state != STM_DEV_STATE_ONLINE) return STM_EINVAL;

    slot->state = STM_DEV_STATE_FAULTED;
    p->roster_hash = hash_of_devs(p->devices, p->device_count);
    return STM_OK;
}

stm_status stm_pool_fail_device(stm_pool *p, uint16_t device_id)
{
    if (!p) return STM_EINVAL;
    pthread_rwlock_wrlock(&p->lock);
    if (claim_blocks(p, device_id)) {
        pthread_rwlock_unlock(&p->lock);
        return STM_EBUSY;
    }
    stm_status s = stm_pool_fail_device_locked(p, device_id);
    pthread_rwlock_unlock(&p->lock);
    return s;
}

stm_status stm_pool_rejoin_device_locked(stm_pool *p, uint16_t device_id)
{
    /* Caller MUST hold pool's exclusive lock. */
    if (!p) return STM_EINVAL;
    if (p->read_only) return STM_EROFS;
    if ((size_t)device_id >= p->device_count) return STM_EINVAL;

    stm_pool_device *slot = &p->devices[device_id];
    /* Only FAULTED → ONLINE. Note the rejoined device's content may
     * be stale (content-gen lags pool_gen); reconcile lands in
     * P5-4d-β. Pre-β, mirror_read falls back to other replicas when
     * the stale content's csum fails. */
    if (slot->state != STM_DEV_STATE_FAULTED) return STM_EINVAL;

    slot->state = STM_DEV_STATE_ONLINE;
    p->roster_hash = hash_of_devs(p->devices, p->device_count);
    return STM_OK;
}

stm_status stm_pool_rejoin_device(stm_pool *p, uint16_t device_id)
{
    if (!p) return STM_EINVAL;
    pthread_rwlock_wrlock(&p->lock);
    if (claim_blocks(p, device_id)) {
        pthread_rwlock_unlock(&p->lock);
        return STM_EBUSY;
    }
    stm_status s = stm_pool_rejoin_device_locked(p, device_id);
    pthread_rwlock_unlock(&p->lock);
    return s;
}
