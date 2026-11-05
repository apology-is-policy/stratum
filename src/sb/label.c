/* SPDX-License-Identifier: ISC */
/*
 * Label placement helpers.
 *
 * ARCHITECTURE §5.3.1. Every device carries four labels at fixed
 * offsets: two at the head (byte 0 and byte 256 KiB) and two at the
 * tail (256 KiB-before-end and end). Each label is 256 KiB (= 64 ×
 * 4 KiB slots). Multiple labels protect against localized damage
 * (controller scribble, cable-induced torn writes, partial firmware
 * rewrite).
 */

#include <stratum/super.h>

stm_status stm_label_offsets(uint64_t device_bytes,
                              uint64_t offsets[STM_LABELS_PER_DEVICE])
{
    if (!offsets) return STM_EINVAL;
    if (device_bytes < STM_DEVICE_MIN_BYTES) return STM_EINVAL;
    /* 2 × LABEL_SIZE at head + 2 × LABEL_SIZE at tail must fit with
     * a non-zero gap in the middle for pool data. */
    if (device_bytes < 4u * (uint64_t)STM_LABEL_SIZE) return STM_EINVAL;

    offsets[0] = 0;
    offsets[1] = (uint64_t)STM_LABEL_SIZE;
    offsets[2] = device_bytes - 2u * (uint64_t)STM_LABEL_SIZE;
    offsets[3] = device_bytes - (uint64_t)STM_LABEL_SIZE;
    return STM_OK;
}

stm_status stm_ub_slot_offset(uint64_t label_offset, uint32_t slot_idx,
                               uint64_t *out_byte_offset)
{
    if (!out_byte_offset) return STM_EINVAL;
    /* Commit ring is slots 0..STM_UB_SLOTS_PER_LABEL-1; the mirror
     * slot (STM_UB_MIRROR_SLOT) sits just past the ring. Both are
     * accessed by the same arithmetic; callers use the constants to
     * pick which. */
    if (slot_idx > STM_UB_MIRROR_SLOT) return STM_EINVAL;
    *out_byte_offset = label_offset + (uint64_t)slot_idx * (uint64_t)STM_UB_SIZE;
    return STM_OK;
}
