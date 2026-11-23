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
 * that read and did not decode. *out_zero: the slot read back all zero.
 * *out_newer, if asked: the version of a newer build's uberblock
 * (stm_ub_is_newer), 0 when the slot holds none. */
static stm_status label_read_ex(stm_bdev *d, uint32_t label_idx,
                                uint32_t slot_idx, stm_uberblock *out_ub,
                                bool *out_unreadable, bool *out_zero,
                                uint32_t *out_newer)
{
    *out_unreadable = false;
    *out_zero = false;
    if (out_newer) *out_newer = 0;
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
    if (out_newer && s == STM_EBADVERSION && stm_ub_is_newer(buf, sizeof buf))
        *out_newer = stm_load_le32(((const stm_uberblock *)buf)->ub_version);
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

/* Reads of a slot that could hold a newer commit, the scan's included,
 * and how many of them must come back wrong with no error (all zero, or
 * bytes that are not that slot's uberblock) before the slot settles as
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
    /* The scan's one read of a slot, not yet settled: */
    SB_SLOT_READ_ZERO,
    SB_SLOT_READ_WRONG,
    SB_SLOT_READ_FAILED
} sb_slot_state;

/* One read of slot (li, si); *s, if not NULL, is its status, and
 * *version the newer build's version when the slot is SB_SLOT_NEWER. A
 * decode counts only in its generation's ring slot: every writer puts
 * gen's uberblock at ring(gen) (sync.c), so another generation's
 * uberblock here came from a misdirected read or write and says nothing
 * of this slot. */
static sb_slot_state sb_slot_read(stm_bdev *d, uint32_t li, uint32_t si,
                                  stm_uberblock *ub, stm_status *s,
                                  uint32_t *version)
{
    bool unreadable = false;
    bool zero = false;
    uint32_t newer = 0;
    stm_status rs = label_read_ex(d, li, si, ub, &unreadable, &zero, &newer);
    if (s) *s = rs;
    if (version) *version = newer;
    if (unreadable) return SB_SLOT_READ_FAILED;
    if (newer) return SB_SLOT_NEWER;
    if (rs == STM_OK) {
        uint64_t gen = stm_load_le64(ub->ub_gen);
        if (stm_sb_ring_label_for_gen(gen) == li &&
            stm_sb_ring_slot_for_gen(gen) == si)
            return SB_SLOT_VALID;
        return SB_SLOT_READ_WRONG;
    }
    return rs == STM_ENOENT && zero ? SB_SLOT_READ_ZERO : SB_SLOT_READ_WRONG;
}

/* The state of slot(gen), the scan's read counted and the slot read again
 * until it settles: valid at a decode; newer at a newer build's
 * uberblock, its version in *version; blank once SB_SLOT_WRONG_SETTLES
 * reads came back all zero; undecoded once that many came back wrong, not
 * all of them zero; unreadable when SB_SLOT_READS_MAX reads brought
 * none of those. A slot that decoded in the scan holds a generation no
 * later than best (the ring came round); *later is set when a re-read
 * decodes one above best_gen into *cand. */
static sb_slot_state sb_successor(stm_bdev *d,
                                  uint8_t st[STM_LABELS_PER_DEVICE][STM_UB_SLOTS_PER_LABEL],
                                  uint64_t gen, uint64_t best_gen,
                                  stm_uberblock *cand, bool *later,
                                  uint32_t *version)
{
    uint32_t li = stm_sb_ring_label_for_gen(gen);
    uint32_t si = stm_sb_ring_slot_for_gen(gen);
    *later = false;
    *version = 0;
    uint32_t zeros = 0;
    uint32_t wrong = 0;
    switch ((sb_slot_state)st[li][si]) {
    case SB_SLOT_READ_ZERO:   zeros = 1; break;
    case SB_SLOT_READ_WRONG:  wrong = 1; break;
    case SB_SLOT_READ_FAILED: break;
    default:                  return (sb_slot_state)st[li][si];
    }
    for (uint32_t r = 1; r < SB_SLOT_READS_MAX; r++) {
        sb_slot_state now = sb_slot_read(d, li, si, cand, NULL, version);
        if (now == SB_SLOT_NEWER) {
            st[li][si] = (uint8_t)SB_SLOT_NEWER;
            return SB_SLOT_NEWER;
        }
        if (now == SB_SLOT_VALID) {
            st[li][si] = (uint8_t)SB_SLOT_VALID;
            *later = stm_load_le64(cand->ub_gen) > best_gen;
            return SB_SLOT_VALID;
        }
        if (now == SB_SLOT_READ_ZERO) zeros++;
        else if (now == SB_SLOT_READ_WRONG) wrong++;
        if (zeros + wrong >= SB_SLOT_WRONG_SETTLES) {
            sb_slot_state settled = wrong ? SB_SLOT_UNDECODED : SB_SLOT_BLANK;
            st[li][si] = (uint8_t)settled;
            return settled;
        }
    }
    st[li][si] = (uint8_t)SB_SLOT_UNREADABLE;
    return SB_SLOT_UNREADABLE;
}

/* Every final stamps ub_repair_log_root_gen with its own generation; a
 * reservation and a mount's claim carry the one they were built from,
 * which is older (sync.c). The writers of both versions the decode
 * accepts stamp it so (none of them changed from v32 to v33): a writer
 * that changes the stamp, or a version range that admits another
 * writer, changes this proof. */
_Static_assert(STM_UB_VERSION == 33u && STM_UB_VERSION_MIN_COMPAT == 32u,
               "re-check that only a final has ub_repair_log_root_gen == ub_gen");

/* best is a final when its mark says so, or when best-1 decodes with
 * another merkle_root (a reservation and a claim carry their
 * predecessor's trees unchanged). Anything less proves nothing: a claim
 * reads as a reservation. *prev_newer: the version of a newer build's
 * uberblock read at slot(best-1), 0 when it held none. */
static bool sb_best_is_final(stm_bdev *d, const stm_uberblock *best,
                             uint64_t best_gen, uint32_t *prev_newer)
{
    *prev_newer = 0;
    if (stm_load_le64(best->ub_repair_log_root_gen) == best_gen)
        return true;
    if (best_gen < 2u) return false;
    uint64_t g = best_gen - 1u;
    stm_uberblock prev;
    bool unreadable = false;
    bool zero = false;
    if (label_read_ex(d, stm_sb_ring_label_for_gen(g),
                      stm_sb_ring_slot_for_gen(g), &prev,
                      &unreadable, &zero, prev_newer) != STM_OK)
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

/* Slot (li, si) holds an uberblock of `version`, a newer build's. */
static stm_status sb_refuse_newer(stm_bdev *d, uint32_t li, uint32_t si,
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
    bool     any_misplaced = false;
    bool     saw_newer     = false;
    uint32_t newer_label   = 0;
    uint32_t newer_slot    = 0;
    uint32_t newer_version = 0;

    /* Scan every label × every commit-ring slot. We deliberately
     * skip the mirror slot (STM_UB_MIRROR_SLOT) since it carries a
     * pool-config snapshot rather than a commit, and mount-time
     * selection is about commits. */
    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
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
                 * first slot that held a newer build's. */
                if (now == SB_SLOT_NEWER && !saw_newer) {
                    saw_newer     = true;
                    newer_label   = li;
                    newer_slot    = si;
                    newer_version = version;
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

    /* A newer build wrote this pool: its commits may lie past every
     * generation this build can read, wherever its layout puts them, so
     * mounting what it can read would roll the pool back and the claim
     * would overwrite one of them. Refuse, at any slot and generation and
     * read-only too: stricter than ZFS, which judges the best uberblock
     * alone. An uberblock below STM_UB_VERSION_MIN_COMPAT is residue and
     * says nothing; one at MIN_COMPAT decodes and is a candidate. */
    if (saw_newer)
        return sb_refuse_newer(d, newer_label, newer_slot, newer_version,
                               best_gen, why);

    /* R13 P2-1: if we found NO valid UB but at least one slot was a
     * well-formed pool at an incompatible version, report that rather
     * than STM_ENOENT. STM_ENOENT is the "nothing here; reformat
     * freshly" path — misleading an admin into reformatting a pool
     * that just needs an upgrade would be destructive. */
    if (!have_any) {
        if (saw_bad_version) return STM_EBADVERSION;
        if (any_unread) return STM_EIO;
        /* An uberblock out of its slot is still a pool, never a fresh
         * device. */
        return any_misplaced ? STM_ECORRUPT : STM_ENOENT;
    }

    /* Each generation's UB is in one ring slot. A commit newer than
     * best can only follow it: at best+1 (when best is a reservation,
     * best+1 is its final; otherwise a reservation or a claim with
     * best's trees) or at best+2 (the final after a reservation at
     * best+1). If the device cannot read the slot where it would be,
     * mounting best would roll the pool back past it and the mount's
     * claim at best+1 would overwrite it: re-read, and refuse while it
     * stays unreadable. A re-read that finds a newer generation moves
     * best, and its own successors are checked; one that finds a newer
     * build's uberblock, there or at best-1, refuses as the first pass
     * does.
     *
     * A read can come back wrong with no error, so a slot settles as
     * blank or undecoded only after two such reads (sb_successor).
     *
     * One device writes its generations in order, each after the last
     * is durable, so it refuses at best+1 only when best may be a
     * reservation (a claim, with nothing behind it, reads as one), and
     * at best+2 only when best+1 neither decoded as an older generation
     * of its own slot (the ring came round) nor read back zero twice. A
     * device of a multi-device pool can miss a generation's write while
     * quorum holds, so there either slot unreadable refuses. */
    for (;;) {
        stm_uberblock cand;
        bool later = false;
        uint32_t version = 0;
        uint64_t g1 = best_gen + 1u;
        uint64_t g2 = best_gen + 2u;
        sb_slot_state s1 = sb_successor(d, st, g1, best_gen, &cand, &later,
                                        &version);
        if (s1 == SB_SLOT_NEWER)
            return sb_refuse_newer(d, stm_sb_ring_label_for_gen(g1),
                                   stm_sb_ring_slot_for_gen(g1), version,
                                   best_gen, why);
        if (later) {
            best_gen   = stm_load_le64(cand.ub_gen);
            best_label = stm_sb_ring_label_for_gen(g1);
            best_slot  = stm_sb_ring_slot_for_gen(g1);
            best_ub    = cand;
            continue;
        }
        if (one_device && (s1 == SB_SLOT_VALID || s1 == SB_SLOT_BLANK))
            break;
        if (s1 == SB_SLOT_UNREADABLE) {
            uint32_t prev_newer = 0;
            bool final = one_device &&
                         sb_best_is_final(d, &best_ub, best_gen, &prev_newer);
            if (prev_newer)
                return sb_refuse_newer(d,
                                       stm_sb_ring_label_for_gen(best_gen - 1u),
                                       stm_sb_ring_slot_for_gen(best_gen - 1u),
                                       prev_newer, best_gen, why);
            if (!final) return sb_refuse(d, g1, best_gen, why);
        }
        sb_slot_state s2 = sb_successor(d, st, g2, best_gen, &cand, &later,
                                        &version);
        if (s2 == SB_SLOT_NEWER)
            return sb_refuse_newer(d, stm_sb_ring_label_for_gen(g2),
                                   stm_sb_ring_slot_for_gen(g2), version,
                                   best_gen, why);
        if (later) {
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
