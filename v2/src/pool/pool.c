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

    /* Validate every device slot. */
    for (size_t i = 0; i < opts->device_count; i++) {
        const stm_pool_device *d = &opts->devices[i];
        if (!d->bdev) return STM_EINVAL;
        if (uuid_is_zero(d->uuid)) return STM_EINVAL;
        if (!role_in_range(d->role))   return STM_EINVAL;
        if (!class_in_range(d->class_)) return STM_EINVAL;
        if (!state_in_range(d->state))  return STM_EINVAL;
        /* Uniqueness of UUID. */
        for (size_t j = 0; j < i; j++) {
            const stm_pool_device *e = &opts->devices[j];
            if (e->uuid[0] == d->uuid[0] && e->uuid[1] == d->uuid[1]) {
                return STM_EINVAL;
            }
        }
    }

    stm_pool *p = calloc(1, sizeof *p);
    if (!p) return STM_ENOMEM;

    p->pool_uuid[0] = opts->pool_uuid[0];
    p->pool_uuid[1] = opts->pool_uuid[1];
    p->device_count = opts->device_count;
    for (size_t i = 0; i < opts->device_count; i++) {
        p->devices[i] = opts->devices[i];
    }
    p->roster_hash = hash_of_devs(p->devices, p->device_count);

    *out = p;
    return STM_OK;
}

void stm_pool_close(stm_pool *p)
{
    if (!p) return;
    /* Borrowers of stm_bdev — we don't close them; wiping the roster
     * is belt-and-braces against lingering pointers. */
    memset(p->devices, 0, sizeof p->devices);
    free(p);
}

/* ========================================================================= */
/* Accessors.                                                                 */
/* ========================================================================= */

size_t stm_pool_device_count(const stm_pool *p) {
    return p ? p->device_count : 0;
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
