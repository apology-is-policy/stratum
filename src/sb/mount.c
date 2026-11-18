/* SPDX-License-Identifier: GPL-3.0-or-later */
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

/* *out_unreadable: the device failed the read itself, as against a slot
 * that read and did not decode. *out_zero: the slot read back all zero. */
static stm_status label_read_ex(stm_bdev *d, uint32_t label_idx,
                                uint32_t slot_idx, stm_uberblock *out_ub,
                                bool *out_unreadable, bool *out_zero)
{
    *out_unreadable = false;
    *out_zero = false;
    if (!out_ub) return STM_EINVAL;

    uint64_t byte_offset = 0;
    stm_status s = compute_offset(d, label_idx, slot_idx, &byte_offset);
    if (s != STM_OK) return s;

    uint8_t buf[STM_UB_SIZE];
    s = stm_bdev_read(d, byte_offset, buf, sizeof buf);
    if (s != STM_OK) {
        *out_unreadable = true;
        return s;
    }

    uint8_t any = 0;
    for (size_t i = 0; i < sizeof buf; i++) any |= buf[i];
    *out_zero = any == 0;
    return stm_ub_decode(buf, sizeof buf, out_ub);
}

stm_status stm_sb_label_read(stm_bdev *d, uint32_t label_idx,
                              uint32_t slot_idx, stm_uberblock *out_ub)
{
    bool unreadable = false;
    bool zero = false;
    return label_read_ex(d, label_idx, slot_idx, out_ub, &unreadable, &zero);
}

/* Re-reads of an unreadable slot that could hold a newer commit. */
static const uint32_t SB_SCAN_REREADS = 2u;

typedef enum {
    SB_SLOT_VALID = 0,   /* decoded */
    SB_SLOT_BLANK,       /* read back all zero: never written (format
                          * zeroes the labels) */
    SB_SLOT_UNDECODED,   /* read; did not decode: torn, or a durable
                          * generation gone bad */
    SB_SLOT_UNREADABLE   /* the device failed the read */
} sb_slot_state;

static uint8_t sb_slot_classify(stm_status s, bool unreadable, bool zero)
{
    if (unreadable)      return (uint8_t)SB_SLOT_UNREADABLE;
    if (s == STM_OK)     return (uint8_t)SB_SLOT_VALID;
    if (s == STM_ENOENT && zero) return (uint8_t)SB_SLOT_BLANK;
    return (uint8_t)SB_SLOT_UNDECODED;
}

/* The state of slot(gen), read again if the device failed it (up to
 * SB_SCAN_REREADS times) or it did not decode (once: a read that came back
 * wrong with no error). A slot that decoded in the scan holds a generation
 * no newer than best; *newer is set when a re-read decodes one above
 * best_gen into *cand. */
static sb_slot_state sb_successor(stm_bdev *d,
                                  uint8_t st[STM_LABELS_PER_DEVICE][STM_UB_SLOTS_PER_LABEL],
                                  uint64_t gen, uint64_t best_gen,
                                  stm_uberblock *cand, bool *newer)
{
    uint32_t li = stm_sb_ring_label_for_gen(gen);
    uint32_t si = stm_sb_ring_slot_for_gen(gen);
    *newer = false;
    sb_slot_state was = (sb_slot_state)st[li][si];
    if (was != SB_SLOT_UNREADABLE && was != SB_SLOT_UNDECODED)
        return was;
    uint32_t tries = was == SB_SLOT_UNREADABLE ? SB_SCAN_REREADS : 1u;
    for (uint32_t r = 0; r < tries; r++) {
        bool unreadable = false;
        bool zero = false;
        stm_status s = label_read_ex(d, li, si, cand, &unreadable, &zero);
        if (unreadable) continue;
        st[li][si] = sb_slot_classify(s, false, zero);
        *newer = s == STM_OK && stm_load_le64(cand->ub_gen) > best_gen;
        return (sb_slot_state)st[li][si];
    }
    return was;
}

/* Every final stamps ub_repair_log_root_gen with its own generation; a
 * reservation and a mount's claim carry the one they were built from,
 * which is older (sync.c). True of every writer of this version: one that
 * changes the stamp changes this proof. */
_Static_assert(STM_UB_VERSION == 33u,
               "re-check that only a final has ub_repair_log_root_gen == ub_gen");
static const uint32_t SB_FINAL_MARK_SINCE = 33u;

/* best is a final when its mark says so, or when best-1 decodes with
 * another merkle_root (a reservation and a claim carry their
 * predecessor's trees unchanged). A v32 uberblock was written by code
 * not in this tree, so only its trees count. Anything less proves
 * nothing: a claim reads as a reservation. */
static bool sb_best_is_final(stm_bdev *d, const stm_uberblock *best,
                             uint64_t best_gen)
{
    if (stm_load_le32(best->ub_version) >= SB_FINAL_MARK_SINCE &&
        stm_load_le64(best->ub_repair_log_root_gen) == best_gen)
        return true;
    if (best_gen < 2u) return false;
    uint64_t g = best_gen - 1u;
    stm_uberblock prev;
    bool unreadable = false;
    bool zero = false;
    if (label_read_ex(d, stm_sb_ring_label_for_gen(g),
                      stm_sb_ring_slot_for_gen(g), &prev,
                      &unreadable, &zero) != STM_OK)
        return false;
    if (stm_load_le64(prev.ub_gen) != g) return false;
    return memcmp(prev.ub_merkle_root, best->ub_merkle_root,
                  sizeof prev.ub_merkle_root) != 0;
}

static stm_status sb_refuse(stm_bdev *d, uint64_t gen, uint64_t best_gen,
                            stm_sb_scan_refusal *why)
{
    if (why) {
        why->gen       = gen;
        why->label_idx = stm_sb_ring_label_for_gen(gen);
        why->slot_idx  = stm_sb_ring_slot_for_gen(gen);
        why->best_gen  = best_gen;
        if (compute_offset(d, why->label_idx, why->slot_idx,
                           &why->byte_offset) != STM_OK)
            why->byte_offset = 0;
    }
    return STM_EIO;
}

stm_status stm_sb_mount_scan_ex(stm_bdev *d, bool one_device,
                                stm_uberblock *out_ub,
                                uint32_t *out_label_idx,
                                uint32_t *out_slot_idx,
                                stm_sb_scan_refusal *why)
{
    if (why) memset(why, 0, sizeof *why);
    if (!d || !out_ub) return STM_EINVAL;

    bool    have_any       = false;
    bool    saw_bad_version = false;   /* R13 P2-1: distinguishes a
                                         * pre-bump-version pool from
                                         * an empty device. */
    uint64_t best_gen      = 0;
    uint32_t best_label    = 0;
    uint32_t best_slot     = 0;
    stm_uberblock best_ub;
    uint8_t  st[STM_LABELS_PER_DEVICE][STM_UB_SLOTS_PER_LABEL];
    bool     any_unread    = false;

    /* Scan every label × every commit-ring slot. We deliberately
     * skip the mirror slot (STM_UB_MIRROR_SLOT) since it carries a
     * pool-config snapshot rather than a commit, and mount-time
     * selection is about commits. */
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        for (uint32_t si = 0; si < STM_UB_SLOTS_PER_LABEL; si++) {
            stm_uberblock candidate;
            bool unreadable = false;
            bool zero = false;
            stm_status s = label_read_ex(d, li, si, &candidate, &unreadable,
                                         &zero);
            st[li][si] = sb_slot_classify(s, unreadable, zero);
            if (s != STM_OK) {
                /* Expected: unused slots, corrupted slots. Skip --
                 * but remember a version mismatch so we can surface
                 * it as a distinct error if no slot decoded OK, and a
                 * slot the device could not read at all. */
                if (unreadable) any_unread = true;
                else if (s == STM_EBADVERSION) saw_bad_version = true;
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

    /* R13 P2-1: if we found NO valid UB but at least one slot was a
     * well-formed pool at an incompatible version, report that rather
     * than STM_ENOENT. STM_ENOENT is the "nothing here; reformat
     * freshly" path — misleading an admin into reformatting a pool
     * that just needs an upgrade would be destructive. */
    if (!have_any) {
        if (saw_bad_version) return STM_EBADVERSION;
        return any_unread ? STM_EIO : STM_ENOENT;
    }

    /* Each generation's UB is in one ring slot. A commit newer than
     * best can only follow it: at best+1 (when best is a reservation,
     * best+1 is its final; otherwise a reservation or a claim with
     * best's trees) or at best+2 (the final after a reservation at
     * best+1). If the device cannot read the slot where it would be,
     * mounting best would roll the pool back past it and the mount's
     * claim at best+1 would overwrite it: re-read, and refuse while it
     * stays unreadable. A re-read that finds a newer generation moves
     * best, and its own successors are checked.
     *
     * One device writes its generations in order, each after the last
     * is durable, so it refuses at best+1 only when best may be a
     * reservation (a claim, with nothing behind it, reads as one), and
     * at best+2 only when best+1 neither decoded as an older generation
     * nor read back zero. A device of a multi-device pool can miss a
     * generation's write while quorum holds, so there either slot
     * unreadable refuses. */
    for (;;) {
        stm_uberblock cand;
        bool newer = false;
        uint64_t g1 = best_gen + 1u;
        uint64_t g2 = best_gen + 2u;
        sb_slot_state s1 = sb_successor(d, st, g1, best_gen, &cand, &newer);
        if (newer) {
            best_gen   = stm_load_le64(cand.ub_gen);
            best_label = stm_sb_ring_label_for_gen(g1);
            best_slot  = stm_sb_ring_slot_for_gen(g1);
            best_ub    = cand;
            continue;
        }
        if (one_device && (s1 == SB_SLOT_VALID || s1 == SB_SLOT_BLANK))
            break;
        if (s1 == SB_SLOT_UNREADABLE &&
            !(one_device && sb_best_is_final(d, &best_ub, best_gen)))
            return sb_refuse(d, g1, best_gen, why);
        sb_slot_state s2 = sb_successor(d, st, g2, best_gen, &cand, &newer);
        if (newer) {
            best_gen   = stm_load_le64(cand.ub_gen);
            best_label = stm_sb_ring_label_for_gen(g2);
            best_slot  = stm_sb_ring_slot_for_gen(g2);
            best_ub    = cand;
            continue;
        }
        if (s2 == SB_SLOT_UNREADABLE)
            return sb_refuse(d, g2, best_gen, why);
        break;
    }

    *out_ub = best_ub;
    if (out_label_idx) *out_label_idx = best_label;
    if (out_slot_idx)  *out_slot_idx  = best_slot;
    return STM_OK;
}

stm_status stm_sb_mount_scan(stm_bdev *d, stm_uberblock *out_ub,
                              uint32_t *out_label_idx,
                              uint32_t *out_slot_idx)
{
    return stm_sb_mount_scan_ex(d, false, out_ub, out_label_idx,
                                out_slot_idx, NULL);
}
