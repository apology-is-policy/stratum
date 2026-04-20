/* SPDX-License-Identifier: ISC */
/*
 * Device-backed label I/O.
 *
 * Reads and writes uberblocks from/to fixed byte offsets on an
 * stm_bdev. Mount-time scan selects the highest valid ub_gen across
 * all 4 labels × 63 commit-ring slots.
 *
 * ARCHITECTURE §5.3.1 (label placement), §5.5.3 (mount-time
 * authoritative selection — single-device variant here; multi-device
 * quorum joins in Phase 5).
 */

#include <stratum/super.h>
#include <stratum/block.h>

#include <string.h>

/* Compute the byte offset of (label_idx, slot_idx) on a device whose
 * size is captured via stm_bdev_caps_of. */
static stm_status compute_offset(stm_bdev *d, uint32_t label_idx,
                                   uint32_t slot_idx,
                                   uint64_t *out_byte_offset)
{
    if (!d) return STM_EINVAL;
    if (label_idx >= STM_LABELS_PER_DEVICE) return STM_EINVAL;

    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    if (!caps) return STM_EINVAL;

    uint64_t label_offsets[STM_LABELS_PER_DEVICE];
    stm_status s = stm_label_offsets(caps->size_bytes, label_offsets);
    if (s != STM_OK) return s;

    return stm_ub_slot_offset(label_offsets[label_idx], slot_idx,
                                out_byte_offset);
}

stm_status stm_sb_label_write(stm_bdev *d, uint32_t label_idx,
                               uint32_t slot_idx, const stm_uberblock *ub)
{
    if (!ub) return STM_EINVAL;

    uint64_t byte_offset = 0;
    stm_status s = compute_offset(d, label_idx, slot_idx, &byte_offset);
    if (s != STM_OK) return s;

    /* Encode to a local 4 KiB buffer, then write. Separating encode
     * from write keeps the caller's `ub` const and means a failed
     * write doesn't leave a half-encoded struct lying around. */
    uint8_t buf[STM_UB_SIZE];
    s = stm_ub_encode(ub, buf, sizeof buf);
    if (s != STM_OK) return s;

    s = stm_bdev_write(d, byte_offset, buf, sizeof buf);
    if (s != STM_OK) return s;

    /* fsync to make the write durable before returning. The commit
     * protocol will batch this across many slots in Phase 3 chunk N;
     * here it's the simple per-call fsync. */
    return stm_bdev_fsync(d);
}

stm_status stm_sb_label_read(stm_bdev *d, uint32_t label_idx,
                              uint32_t slot_idx, stm_uberblock *out_ub)
{
    if (!out_ub) return STM_EINVAL;

    uint64_t byte_offset = 0;
    stm_status s = compute_offset(d, label_idx, slot_idx, &byte_offset);
    if (s != STM_OK) return s;

    uint8_t buf[STM_UB_SIZE];
    s = stm_bdev_read(d, byte_offset, buf, sizeof buf);
    if (s != STM_OK) return s;

    return stm_ub_decode(buf, sizeof buf, out_ub);
}

stm_status stm_sb_mount_scan(stm_bdev *d, stm_uberblock *out_ub,
                              uint32_t *out_label_idx,
                              uint32_t *out_slot_idx)
{
    if (!d || !out_ub) return STM_EINVAL;

    bool    have_any       = false;
    uint64_t best_gen      = 0;
    uint32_t best_label    = 0;
    uint32_t best_slot     = 0;
    stm_uberblock best_ub;

    /* Scan every label × every commit-ring slot. We deliberately
     * skip the mirror slot (STM_UB_MIRROR_SLOT) since it carries a
     * pool-config snapshot rather than a commit, and mount-time
     * selection is about commits. */
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        for (uint32_t si = 0; si < STM_UB_SLOTS_PER_LABEL; si++) {
            stm_uberblock candidate;
            stm_status s = stm_sb_label_read(d, li, si, &candidate);
            if (s != STM_OK) {
                /* Expected: unused slots, corrupted slots. Skip. */
                continue;
            }
            uint64_t gen = stm_load_le64(candidate.ub_gen);
            if (!have_any || gen > best_gen) {
                best_gen    = gen;
                best_label  = li;
                best_slot   = si;
                best_ub     = candidate;
                have_any    = true;
            }
        }
    }

    if (!have_any) return STM_ENOENT;

    *out_ub = best_ub;
    if (out_label_idx) *out_label_idx = best_label;
    if (out_slot_idx)  *out_slot_idx  = best_slot;
    return STM_OK;
}
