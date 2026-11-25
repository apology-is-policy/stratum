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

/* Labels 0 and 1 lie at the head of the device, at offsets its size does
 * not change; labels 2 and 3 end at its layout (label.c). */
static const uint32_t SB_HEAD_LABELS = 2u;
_Static_assert(STM_LABELS_PER_DEVICE == 4u,
               "the scan learns the layout from the head labels before the tail");

/* Compute the byte offset of (label_idx, slot_idx) in the device's
 * layout (stm_bdev_layout_bytes: the size its roster entry recorded, not
 * the size it has now). A head label's offset needs no layout, so a
 * handle laid out at a size no layout can have still reads its head. */
static stm_status compute_offset(stm_bdev *d, uint32_t label_idx,
                                   uint32_t slot_idx,
                                   uint64_t *out_byte_offset)
{
    if (!d) return STM_EINVAL;
    if (label_idx >= STM_LABELS_PER_DEVICE) return STM_EINVAL;

    uint64_t label_offsets[STM_LABELS_PER_DEVICE];
    if (label_idx < SB_HEAD_LABELS) {
        label_offsets[label_idx] = (uint64_t)label_idx * STM_LABEL_SIZE;
    } else {
        stm_status s = stm_label_offsets(stm_bdev_layout_bytes(d),
                                         label_offsets);
        if (s != STM_OK) return s;
    }

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

/* STM_ERANGE when the device is shorter than its layout, by its file's
 * length now or by the size its handle has: its labels 2 and 3 are gone,
 * or lie past every write the handle makes. */
static stm_status sb_device_short(stm_bdev *d)
{
    uint64_t now = 0;
    stm_status s = stm_bdev_current_bytes(d, &now);
    if (s != STM_OK) return s;
    uint64_t layout = stm_bdev_layout_bytes(d);
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    if (now < layout || !caps || caps->size_bytes < layout) return STM_ERANGE;
    return STM_OK;
}

/* Write `ub` to slot `slot_idx` of every label (its STM_UB_COPIES copies),
 * then fsync once. Every copy is attempted, so a failed one leaves the
 * others written; STM_OK only when STM_UB_COPIES_REQUIRED copies were
 * written and the fsync succeeded, else the first failure. A short device
 * (STM_ERANGE, sb_device_short) takes no copy: the write cannot be made,
 * and copies in labels 0 and 1 would be read as this generation's vote if
 * its tail came back. Asked again after the copies, so a cut made while
 * they were written does not confirm: they reach at most the end of label
 * 3's last ring slot, STM_UB_SIZE short of the layout. */
stm_status stm_sb_ub_write_copies(stm_bdev *d, uint32_t slot_idx,
                                  const stm_uberblock *ub)
{
    if (!ub || slot_idx >= STM_UB_SLOTS_PER_LABEL) return STM_EINVAL;
    if (stm_bdev_is_read_only(d)) return STM_EROFS;
    stm_status s = sb_device_short(d);
    if (s != STM_OK) return s;

    uint8_t buf[STM_UB_SIZE];
    s = stm_ub_encode(ub, buf, sizeof buf);
    if (s != STM_OK) return s;

    stm_status first = STM_OK;
    uint32_t written = 0;
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        uint64_t byte_offset = 0;
        stm_status w = compute_offset(d, li, slot_idx, &byte_offset);
        if (w == STM_OK) w = stm_bdev_write(d, byte_offset, buf, sizeof buf);
        if (w == STM_OK) written++;
        else if (first == STM_OK) first = w;
    }
    stm_status f = stm_bdev_fsync(d);
    if (written >= STM_UB_COPIES_REQUIRED && f == STM_OK)
        return sb_device_short(d);
    return first != STM_OK ? first : f;
}

/* *out_unreadable: the device failed the read itself, as against a slot
 * that read and did not decode. *out_zero: the slot read back all zero.
 * *out_version, if asked: the version of an uberblock another build wrote
 * (stm_ub_is_newer, stm_ub_is_older), 0 when the slot holds none. */
static stm_status label_read_ex(stm_bdev *d, uint32_t label_idx,
                                uint32_t slot_idx, stm_uberblock *out_ub,
                                bool *out_unreadable, bool *out_zero,
                                uint32_t *out_version)
{
    *out_unreadable = false;
    *out_zero = false;
    if (out_version) *out_version = 0;
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
    s = stm_ub_decode(buf, sizeof buf, out_ub);
    if (out_version && s == STM_EBADVERSION &&
        (stm_ub_is_newer(buf, sizeof buf) || stm_ub_is_older(buf, sizeof buf)))
        *out_version = stm_load_le32(((const stm_uberblock *)buf)->ub_version);
    return s;
}

stm_status stm_sb_label_read(stm_bdev *d, uint32_t label_idx,
                              uint32_t slot_idx, stm_uberblock *out_ub)
{
    bool unreadable = false;
    bool zero = false;
    return label_read_ex(d, label_idx, slot_idx, out_ub, &unreadable, &zero,
                         NULL);
}

/* Reads of a copy that could hold a newer commit, the scan's included,
 * and how many of them must come back wrong with no error (all zero, or
 * bytes that are not that slot's uberblock) before the copy settles as
 * blank or undecoded. */
static const uint32_t SB_SLOT_READS_MAX = 3u;
static const uint32_t SB_SLOT_WRONG_SETTLES = 2u;

typedef enum {
    SB_SLOT_VALID = 0,   /* decoded, as the uberblock of a generation
                          * whose ring slot this is */
    SB_SLOT_BLANK,       /* read back all zero, twice: never written
                          * (format zeroes the labels) */
    SB_SLOT_UNDECODED,   /* read back wrong twice, not both times zero:
                          * torn, or a durable generation gone bad */
    SB_SLOT_UNREADABLE,  /* the device failed the reads */
    SB_SLOT_NEWER,       /* a newer build's uberblock, at one read: the
                          * pool is not this build's to mount */
    /* The scan's one read of a copy, not yet settled: */
    SB_SLOT_READ_ZERO,
    SB_SLOT_READ_WRONG,
    SB_SLOT_READ_FAILED
} sb_slot_state;

/* One read of copy (li, si); *s, if not NULL, is its status, and *version
 * the version of another build's uberblock there (SB_SLOT_NEWER above
 * this build's; an older one reads as wrong). A decode counts only in its
 * generation's ring slot, in any label: every writer puts gen's uberblock
 * at slot(gen) of every label (stm_sb_ub_write_copies), so another
 * generation's uberblock here came from a misdirected read or write and
 * says nothing of this slot. */
static sb_slot_state sb_slot_read(stm_bdev *d, uint32_t li, uint32_t si,
                                  stm_uberblock *ub, stm_status *s,
                                  uint32_t *version)
{
    bool unreadable = false;
    bool zero = false;
    uint32_t other = 0;
    stm_status rs = label_read_ex(d, li, si, ub, &unreadable, &zero, &other);
    if (s) *s = rs;
    if (version) *version = other;
    if (unreadable) return SB_SLOT_READ_FAILED;
    if (other > STM_UB_VERSION) return SB_SLOT_NEWER;
    if (rs == STM_OK)
        return stm_sb_ring_slot_for_gen(stm_load_le64(ub->ub_gen)) == si
                   ? SB_SLOT_VALID : SB_SLOT_READ_WRONG;
    return rs == STM_ENOENT && zero ? SB_SLOT_READ_ZERO : SB_SLOT_READ_WRONG;
}

/* Copy (li, si), the scan's read counted, read again until it settles:
 * valid at a decode (into *ub); newer at a newer build's uberblock (its
 * version in *version); blank once SB_SLOT_WRONG_SETTLES reads came back
 * all zero; undecoded once that many came back wrong, not all of them
 * zero; unreadable when SB_SLOT_READS_MAX reads brought none of those.
 * Called only on a copy the scan's read left unsettled. */
static sb_slot_state sb_copy_settle(stm_bdev *d, uint8_t *st, uint32_t li,
                                    uint32_t si, stm_uberblock *ub,
                                    uint32_t *version)
{
    uint32_t zeros = (sb_slot_state)*st == SB_SLOT_READ_ZERO ? 1u : 0u;
    uint32_t wrong = (sb_slot_state)*st == SB_SLOT_READ_WRONG ? 1u : 0u;
    for (uint32_t r = 1; r < SB_SLOT_READS_MAX; r++) {
        sb_slot_state now = sb_slot_read(d, li, si, ub, NULL, version);
        if (now == SB_SLOT_NEWER || now == SB_SLOT_VALID) {
            *st = (uint8_t)now;
            return now;
        }
        if (now == SB_SLOT_READ_ZERO) zeros++;
        else if (now == SB_SLOT_READ_WRONG) wrong++;
        if (zeros + wrong >= SB_SLOT_WRONG_SETTLES) {
            sb_slot_state settled = wrong ? SB_SLOT_UNDECODED : SB_SLOT_BLANK;
            *st = (uint8_t)settled;
            return settled;
        }
    }
    *st = (uint8_t)SB_SLOT_UNREADABLE;
    return SB_SLOT_UNREADABLE;
}

/* What slot(gen) says of a commit newer than best_gen, each copy the scan
 * left unsettled read again until it settles:
 *   SB_SLOT_NEWER       a copy holds a newer build's uberblock (*version,
 *                       its label in *at);
 *   SB_SLOT_VALID       with *later, a copy decoded a generation above
 *                       best_gen (the highest into *cand, its label in
 *                       *at); without, STM_UB_SETTLE_COPIES copies hold an
 *                       older generation of this slot (the ring came
 *                       round) or read back blank, so gen was never
 *                       acknowledged;
 *   SB_SLOT_UNREADABLE  fewer settle it and a copy stays unreadable (the
 *                       first in *at);
 *   SB_SLOT_UNDECODED   fewer settle it and the others are torn or gone
 *                       bad.
 * A copy that decoded at an earlier read holds a generation no later than
 * best_gen: best is the highest decoded. */
static sb_slot_state sb_successor(stm_bdev *d,
                                  uint8_t st[STM_LABELS_PER_DEVICE][STM_UB_SLOTS_PER_LABEL],
                                  uint64_t gen, uint64_t best_gen,
                                  stm_uberblock *cand, bool *later,
                                  uint32_t *version, uint32_t *at)
{
    uint32_t si = stm_sb_ring_slot_for_gen(gen);
    *later = false;
    *version = 0;
    *at = 0;
    uint32_t settled = 0;
    bool unreadable = false;
    uint32_t unreadable_at = 0;
    uint64_t top = best_gen;
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        sb_slot_state c = (sb_slot_state)st[li][si];
        if (c == SB_SLOT_READ_ZERO || c == SB_SLOT_READ_WRONG ||
            c == SB_SLOT_READ_FAILED) {
            stm_uberblock ub;
            uint32_t v = 0;
            c = sb_copy_settle(d, &st[li][si], li, si, &ub, &v);
            if (c == SB_SLOT_NEWER) {
                *version = v;
                *at = li;
                return SB_SLOT_NEWER;
            }
            if (c == SB_SLOT_VALID && stm_load_le64(ub.ub_gen) > top) {
                top = stm_load_le64(ub.ub_gen);
                *cand = ub;
                *later = true;
                *at = li;
                continue;
            }
        }
        if (c == SB_SLOT_VALID || c == SB_SLOT_BLANK) {
            settled++;
        } else if (c == SB_SLOT_UNREADABLE && !unreadable) {
            unreadable = true;
            unreadable_at = li;
        }
    }
    if (*later || settled >= STM_UB_SETTLE_COPIES) return SB_SLOT_VALID;
    if (unreadable) {
        *at = unreadable_at;
        return SB_SLOT_UNREADABLE;
    }
    return SB_SLOT_UNDECODED;
}

/* Every final stamps ub_repair_log_root_gen with its own generation; a
 * reservation and a mount's claim carry the one they were built from,
 * which is older (sync.c). The writers of the one version the decode
 * accepts stamp it so: a writer that changes the stamp, or a version
 * range that admits another writer, changes this proof. */
_Static_assert(STM_UB_VERSION == 35u && STM_UB_VERSION_MIN_COMPAT == 35u,
               "re-check that only a final has ub_repair_log_root_gen == ub_gen");

/* The scan's pick among differing copies of one generation (the first
 * pass and sb_successor) and sb_best_is_final trust that a confirmed write
 * replaced every copy: with fewer copies required, an earlier failed
 * attempt's copy of the same generation could outlive the confirmed one,
 * and nothing in the uberblock orders the two. */
_Static_assert(STM_UB_COPIES_REQUIRED == STM_UB_COPIES,
               "fewer copies required needs a same-generation discriminator "
               "in the uberblock, used wherever copies of a generation differ");

/* best is a final when its mark says so, or when a copy of best-1 decodes
 * as that generation and no copy that does carries best's merkle_root (a
 * reservation and a claim carry their predecessor's trees unchanged; the
 * copies of the final a reservation follows all agree, that final's write
 * having succeeded, STM_UB_COPIES_REQUIRED). Anything less proves nothing:
 * a claim reads as a reservation. *prev_newer, *prev_at: the version and
 * label of a newer build's uberblock read at slot(best-1), 0 when there is
 * none. */
static bool sb_best_is_final(stm_bdev *d, const stm_uberblock *best,
                             uint64_t best_gen, uint32_t *prev_newer,
                             uint32_t *prev_at)
{
    *prev_newer = 0;
    *prev_at = 0;
    if (stm_load_le64(best->ub_repair_log_root_gen) == best_gen)
        return true;
    if (best_gen < 2u) return false;
    uint64_t g = best_gen - 1u;
    uint32_t si = stm_sb_ring_slot_for_gen(g);
    bool other = false;
    bool same = false;
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        stm_uberblock prev;
        bool unreadable = false;
        bool zero = false;
        uint32_t version = 0;
        stm_status rs = label_read_ex(d, li, si, &prev, &unreadable, &zero,
                                      &version);
        if (version > STM_UB_VERSION) {
            *prev_newer = version;
            *prev_at = li;
            return false;
        }
        if (rs != STM_OK || stm_load_le64(prev.ub_gen) != g) continue;
        if (memcmp(prev.ub_merkle_root, best->ub_merkle_root,
                   sizeof prev.ub_merkle_root) != 0)
            other = true;
        else
            same = true;
    }
    return other && !same;
}

static stm_status sb_refuse(stm_bdev *d, uint64_t gen, uint32_t li,
                            uint64_t best_gen, stm_sb_scan_refusal *why)
{
    if (why) {
        why->gen       = gen;
        why->label_idx = li;
        why->slot_idx  = stm_sb_ring_slot_for_gen(gen);
        why->best_gen  = best_gen;
        if (compute_offset(d, why->label_idx, why->slot_idx,
                           &why->byte_offset) != STM_OK)
            why->byte_offset = 0;
    }
    return STM_EIO;
}

/* The uberblock at copy (li, si) records no valid size for its device, or
 * another size than the layout labels 2 and 3 were read by. */
static stm_status sb_refuse_layout(stm_bdev *d, uint32_t li, uint32_t si,
                                   uint64_t gen, stm_sb_scan_refusal *why)
{
    if (why) {
        why->label_idx = li;
        why->slot_idx  = si;
        why->best_gen  = gen;
        if (compute_offset(d, li, si, &why->byte_offset) != STM_OK)
            why->byte_offset = 0;
    }
    return STM_ECORRUPT;
}

/* Lay the device out at the size the newest uberblock of its head labels
 * records for it (`head`, at copy (li, si); NULL when none decoded, and
 * the layout stays as it was), before labels 2 and 3 are read: where a
 * device that grew has blank space, or one that shrank has data, at its
 * current end. A device smaller than its recorded size refuses; its
 * layout is set first, so a writer that runs anyway (a pool carrying on
 * without the device) aims past the device's end, never at the data at
 * its current end; stm_sb_ub_write_copies writes such a device nothing. */
static stm_status sb_layout(stm_bdev *d, const stm_uberblock *head,
                            uint32_t li, uint32_t si,
                            stm_sb_scan_refusal *why)
{
    if (!head) return STM_OK;
    uint64_t gen = stm_load_le64(head->ub_gen);
    uint64_t recorded = 0;
    if (stm_ub_device_bytes(head, &recorded) != STM_OK)
        return sb_refuse_layout(d, li, si, gen, why);
    stm_bdev_set_layout_bytes(d, recorded);
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    if (!caps) return STM_EINVAL;
    if (recorded <= caps->size_bytes) return STM_OK;
    if (why) {
        why->label_idx      = li;
        why->slot_idx       = si;
        why->best_gen       = gen;
        why->recorded_bytes = recorded;
        why->device_bytes   = caps->size_bytes;
        if (compute_offset(d, li, si, &why->byte_offset) != STM_OK)
            why->byte_offset = 0;
    }
    return STM_ERANGE;
}

/* Copy (li, si) holds an uberblock of `version`, which this build does
 * not read. */
static stm_status sb_refuse_version(stm_bdev *d, uint32_t li, uint32_t si,
                                    uint32_t version, uint64_t best_gen,
                                    stm_sb_scan_refusal *why)
{
    if (why) {
        why->gen       = 0;
        why->label_idx = li;
        why->slot_idx  = si;
        why->best_gen  = best_gen;
        why->version   = version;
        if (compute_offset(d, li, si, &why->byte_offset) != STM_OK)
            why->byte_offset = 0;
    }
    return STM_EBADVERSION;
}

/* Nothing has decoded yet: read again each copy of labels [lo, hi) the
 * scan's one read left unsettled, until it settles (sb_copy_settle). A
 * read can come back zero or wrong with no error, and a device whose every
 * copy did so once would answer as blank: a known vote of nothing, past
 * which a multi-device pool would mount over a commit the device holds
 * (stm_sync_open_ex), and a one-device pool would read as fresh. A decode
 * is best (the highest); true at a newer build's uberblock (its copy and
 * version in *newer_*), which ends the pass. */
static bool sb_settle_unread(stm_bdev *d,
                             uint8_t st[STM_LABELS_PER_DEVICE][STM_UB_SLOTS_PER_LABEL],
                             uint32_t lo, uint32_t hi, bool *have_any,
                             uint64_t *best_gen, uint32_t *best_label,
                             uint32_t *best_slot, stm_uberblock *best_ub,
                             uint32_t *newer_label, uint32_t *newer_slot,
                             uint32_t *newer_version)
{
    for (uint32_t li = lo; li < hi; li++) {
        for (uint32_t si = 0; si < STM_UB_SLOTS_PER_LABEL; si++) {
            sb_slot_state c = (sb_slot_state)st[li][si];
            if (c != SB_SLOT_READ_ZERO && c != SB_SLOT_READ_WRONG &&
                c != SB_SLOT_READ_FAILED)
                continue;
            stm_uberblock ub;
            uint32_t v = 0;
            c = sb_copy_settle(d, &st[li][si], li, si, &ub, &v);
            if (c == SB_SLOT_NEWER) {
                *newer_label   = li;
                *newer_slot    = si;
                *newer_version = v;
                return true;
            }
            if (c != SB_SLOT_VALID) continue;
            uint64_t gen = stm_load_le64(ub.ub_gen);
            if (!*have_any || gen > *best_gen) {
                *best_gen   = gen;
                *best_label = li;
                *best_slot  = si;
                *best_ub    = ub;
                *have_any   = true;
            }
        }
    }
    return false;
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
                                         * pool of another version from
                                         * an empty device. */
    uint64_t best_gen      = 0;
    uint32_t best_label    = 0;
    uint32_t best_slot     = 0;
    stm_uberblock best_ub;
    uint8_t  st[STM_LABELS_PER_DEVICE][STM_UB_SLOTS_PER_LABEL];
    bool     any_unread    = false;
    bool     any_misplaced = false;
    bool     saw_newer     = false;
    uint32_t newer_label   = 0;
    uint32_t newer_slot    = 0;
    uint32_t newer_version = 0;
    bool     saw_older     = false;
    uint32_t older_label   = 0;
    uint32_t older_slot    = 0;
    uint32_t older_version = 0;

    /* Scan every label x every commit-ring slot, every copy of every
     * generation the ring holds. We deliberately skip the mirror slot
     * (STM_UB_MIRROR_SLOT) since it carries a pool-config snapshot rather
     * than a commit, and mount-time selection is about commits. Copies of
     * one generation that differ came from a write that failed (a
     * successful one writes every copy, STM_UB_COPIES_REQUIRED), after
     * which the fs wrote nothing until a remount, so each names an intact
     * tree; the first in label order is taken. On a multi-device pool the
     * device was outvoted instead and its pick is only its vote: the
     * content-quorum check (sync.c) treats a dissenting device as an
     * orphan.
     *
     * The head labels come first: their newest uberblock gives the layout
     * the tail labels are read by (sb_layout). A newer build's uberblock
     * there refuses below, its layout not this build's to compute. When
     * nothing in them decoded at one read, their copies are read again
     * until they settle (sb_settle_unread) before the layout is taken, and
     * the tail's after the pass. */
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        if (li == SB_HEAD_LABELS) {
            if (saw_newer) break;
            if (!have_any &&
                sb_settle_unread(d, st, 0, SB_HEAD_LABELS, &have_any,
                                 &best_gen, &best_label, &best_slot, &best_ub,
                                 &newer_label, &newer_slot, &newer_version)) {
                saw_newer = true;
                break;
            }
            stm_status ls = sb_layout(d, have_any ? &best_ub : NULL,
                                      best_label, best_slot, why);
            if (ls != STM_OK) return ls;
        }
        for (uint32_t si = 0; si < STM_UB_SLOTS_PER_LABEL; si++) {
            stm_uberblock candidate;
            stm_status s = STM_OK;
            uint32_t version = 0;
            sb_slot_state now = sb_slot_read(d, li, si, &candidate, &s,
                                             &version);
            st[li][si] = (uint8_t)now;
            if (now != SB_SLOT_VALID) {
                /* Expected: unused slots, corrupted slots. Skip --
                 * but remember a version mismatch so we can surface
                 * it as a distinct error if no slot decoded OK, a
                 * slot the device could not read at all, and one
                 * that held another generation's uberblock; and the
                 * first slot that held a newer build's, and the first
                 * that held an older one's. */
                if (now == SB_SLOT_NEWER && !saw_newer) {
                    saw_newer     = true;
                    newer_label   = li;
                    newer_slot    = si;
                    newer_version = version;
                }
                if (version != 0 && version < STM_UB_VERSION_MIN_COMPAT &&
                    !saw_older) {
                    saw_older     = true;
                    older_label   = li;
                    older_slot    = si;
                    older_version = version;
                }
                if (now == SB_SLOT_READ_FAILED) any_unread = true;
                else if (s == STM_EBADVERSION) saw_bad_version = true;
                else if (s == STM_OK) any_misplaced = true;
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

    if (!have_any && !saw_newer &&
        sb_settle_unread(d, st, SB_HEAD_LABELS, STM_LABELS_PER_DEVICE,
                         &have_any, &best_gen, &best_label, &best_slot,
                         &best_ub, &newer_label, &newer_slot, &newer_version))
        saw_newer = true;

    /* A newer build wrote this pool: its commits may lie past every
     * generation this build can read, wherever its layout puts them, so
     * mounting what it can read would roll the pool back and the claim
     * would overwrite one of them. Refuse, at any slot and generation and
     * read-only too: stricter than ZFS, which judges the best uberblock
     * alone. An uberblock below STM_UB_VERSION_MIN_COMPAT is residue and
     * says nothing while anything decodes. */
    if (saw_newer)
        return sb_refuse_version(d, newer_label, newer_slot, newer_version,
                                 best_gen, why);

    /* R13 P2-1: if we found NO valid UB but at least one slot was a
     * well-formed pool at an incompatible version, report that rather
     * than STM_ENOENT. STM_ENOENT is the "nothing here; reformat
     * freshly" path -- an admin should hear that another build's pool is
     * here before deciding to reformat it. */
    if (!have_any) {
        if (saw_older)
            return sb_refuse_version(d, older_label, older_slot,
                                     older_version, 0, why);
        if (saw_bad_version) return STM_EBADVERSION;
        bool unreadable = any_unread;
        for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++)
            for (uint32_t si = 0; si < STM_UB_SLOTS_PER_LABEL; si++)
                if (st[li][si] == (uint8_t)SB_SLOT_UNREADABLE) unreadable = true;
        if (unreadable) return STM_EIO;
        /* An uberblock out of its slot is still a pool, never a fresh
         * device. */
        return any_misplaced ? STM_ECORRUPT : STM_ENOENT;
    }

    /* Each generation's UB is in one ring slot, in every label. A commit
     * newer than best can only follow it: at best+1 (when best is a
     * reservation, best+1 is its final; otherwise a reservation or a
     * claim with best's trees) or at best+2 (the final after a
     * reservation at best+1). If the device cannot read that slot's
     * copies, mounting best would roll the pool back past it and the
     * mount's claim at best+1 would overwrite it: re-read, and refuse
     * while it stays unknown (sb_successor). A re-read that finds a newer
     * generation moves best, and its own successors are checked; one that
     * finds a newer build's uberblock, there or at best-1, refuses as the
     * first pass does.
     *
     * A read can come back wrong with no error, so a copy settles as
     * blank or undecoded only after two such reads (sb_copy_settle).
     *
     * One device writes its generations in order, each after the last
     * is durable, so it refuses at best+1 only when best may be a
     * reservation (a claim, with nothing behind it, reads as one), and
     * at best+2 only when best+1 was not settled (its copies neither held
     * an older generation of their own slot nor read back zero). A device
     * of a multi-device pool can miss a generation's write while quorum
     * holds, so there either slot unreadable refuses, and so does any
     * other (below). */
    for (;;) {
        stm_uberblock cand;
        bool later = false;
        uint32_t version = 0;
        uint32_t at = 0;
        uint64_t g1 = best_gen + 1u;
        uint64_t g2 = best_gen + 2u;
        sb_slot_state s1 = sb_successor(d, st, g1, best_gen, &cand, &later,
                                        &version, &at);
        if (s1 == SB_SLOT_NEWER)
            return sb_refuse_version(d, at, stm_sb_ring_slot_for_gen(g1),
                                     version, best_gen, why);
        if (later) {
            best_gen   = stm_load_le64(cand.ub_gen);
            best_label = at;
            best_slot  = stm_sb_ring_slot_for_gen(g1);
            best_ub    = cand;
            continue;
        }
        if (one_device && s1 == SB_SLOT_VALID)
            break;
        if (s1 == SB_SLOT_UNREADABLE) {
            uint32_t prev_newer = 0;
            uint32_t prev_at = 0;
            bool final = one_device &&
                         sb_best_is_final(d, &best_ub, best_gen, &prev_newer,
                                          &prev_at);
            if (prev_newer)
                return sb_refuse_version(d, prev_at,
                                         stm_sb_ring_slot_for_gen(best_gen - 1u),
                                         prev_newer, best_gen, why);
            if (!final) return sb_refuse(d, g1, at, best_gen, why);
        }
        sb_slot_state s2 = sb_successor(d, st, g2, best_gen, &cand, &later,
                                        &version, &at);
        if (s2 == SB_SLOT_NEWER)
            return sb_refuse_version(d, at, stm_sb_ring_slot_for_gen(g2),
                                     version, best_gen, why);
        if (later) {
            best_gen   = stm_load_le64(cand.ub_gen);
            best_label = at;
            best_slot  = stm_sb_ring_slot_for_gen(g2);
            best_ub    = cand;
            continue;
        }
        if (s2 == SB_SLOT_UNREADABLE)
            return sb_refuse(d, g2, at, best_gen, why);
        break;
    }

    /* A device of a multi-device pool can miss writes while quorum holds
     * (FAULTED, or a write that failed), so its generations need not be
     * contiguous: the newest it confirmed can be in any slot, best+1 and
     * best+2 only the nearest. Every other slot must settle or decode no
     * newer than best; one that stays unreadable could hold a newer
     * commit, and mounting best would roll the pool back past it, so the
     * device refuses (an unknown vote, stm_sync_open_ex). A re-read that
     * finds a newer generation moves best and every slot is asked again
     * (a copy settled once stays settled). */
    if (!one_device) {
        for (uint32_t k = 1; k < STM_UB_SLOTS_PER_LABEL; k++) {
            uint64_t g = best_gen + k;
            if (g < best_gen) break;
            stm_uberblock cand;
            bool later = false;
            uint32_t version = 0;
            uint32_t at = 0;
            sb_slot_state sk = sb_successor(d, st, g, best_gen, &cand, &later,
                                            &version, &at);
            if (sk == SB_SLOT_NEWER)
                return sb_refuse_version(d, at, stm_sb_ring_slot_for_gen(g),
                                         version, best_gen, why);
            if (later) {
                best_gen   = stm_load_le64(cand.ub_gen);
                best_label = at;
                best_slot  = stm_sb_ring_slot_for_gen(g);
                best_ub    = cand;
                k = 0;
                continue;
            }
            if (sk == SB_SLOT_UNREADABLE)
                return sb_refuse(d, g, at, best_gen, why);
        }
    }

    /* Every uberblock of the device records the same size (a device keeps
     * the size it joined with), so one that records another came from
     * somewhere else: residue of a pool laid out at another size, or data
     * at a tail read by a layout the head labels did not give. Residue
     * recording the layout's own size is not told apart here. */
    uint64_t recorded = 0;
    if (stm_ub_device_bytes(&best_ub, &recorded) != STM_OK ||
        recorded != stm_bdev_layout_bytes(d))
        return sb_refuse_layout(d, best_label, best_slot, best_gen, why);

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

/* Every copy is read, so a newer build's uberblock in any of them refuses
 * as the scan would; of differing copies of gen the first in label order
 * is taken. */
stm_status stm_sb_gen_read(stm_bdev *d, uint64_t gen, stm_uberblock *out_ub,
                           stm_sb_scan_refusal *why)
{
    if (!d || !out_ub) return STM_EINVAL;
    uint32_t si = stm_sb_ring_slot_for_gen(gen);
    bool found = false;
    bool unsettled = false;
    bool newer = false;
    uint32_t newer_label = 0, newer_version = 0;
    for (uint32_t li = 0; li < STM_UB_COPIES; li++) {
        stm_uberblock ub;
        uint32_t v = 0;
        sb_slot_state c = sb_slot_read(d, li, si, &ub, NULL, &v);
        if (c == SB_SLOT_READ_ZERO || c == SB_SLOT_READ_WRONG ||
            c == SB_SLOT_READ_FAILED) {
            uint8_t st = (uint8_t)c;
            c = sb_copy_settle(d, &st, li, si, &ub, &v);
        }
        if (c == SB_SLOT_NEWER) {
            if (!newer) {
                newer_label   = li;
                newer_version = v;
            }
            newer = true;
        } else if (c == SB_SLOT_VALID && stm_load_le64(ub.ub_gen) == gen) {
            if (!found) *out_ub = ub;
            found = true;
        } else if (c != SB_SLOT_VALID && c != SB_SLOT_BLANK) {
            unsettled = true;
        }
    }
    if (newer) {
        if (why) memset(why, 0, sizeof *why);
        return sb_refuse_version(d, newer_label, si, newer_version, 0, why);
    }
    if (found) return STM_OK;
    return unsettled ? STM_EIO : STM_ENOENT;
}
