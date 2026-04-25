/* SPDX-License-Identifier: ISC */
/*
 * Uberblock encode/decode with BLAKE3-256 csum.
 *
 * ARCHITECTURE §5.4. The on-disk layout is defined by the packed
 * stm_uberblock struct in <stratum/super.h>; encode/decode here is a
 * bytewise pass that honors the little-endian convention and zeroes
 * the csum field before hashing so encode and decode agree.
 */

#include <stratum/super.h>
#include <stratum/hash.h>

#include <string.h>

void stm_ub_csum(const void *buf, size_t buf_len, uint8_t out[32])
{
    if (buf_len < STM_UB_SIZE) {
        memset(out, 0, 32);
        return;
    }
    /* Hash the first (size - 32) bytes; the trailing 32 bytes are the
     * csum itself, which must be zero during the hash computation. */
    stm_blake3_hash h;
    stm_blake3(buf, STM_UB_SIZE - 32, &h);
    memcpy(out, h.bytes, 32);
}

stm_status stm_ub_encode(const stm_uberblock *ub, void *buf, size_t buf_len)
{
    if (!ub || !buf) return STM_EINVAL;
    if (buf_len < STM_UB_SIZE) return STM_ERANGE;

    /* The struct is already in on-disk layout (le* accessors, fixed
     * sizes, _Static_assert'd at 4096). Copy verbatim. */
    memcpy(buf, ub, STM_UB_SIZE);

    /* Zero the csum field before hashing so the hash covers a known
     * state. */
    memset((uint8_t *)buf + offsetof(stm_uberblock, ub_csum), 0, 32);

    /* Hash and write csum. */
    uint8_t csum[32];
    stm_ub_csum(buf, STM_UB_SIZE, csum);
    memcpy((uint8_t *)buf + offsetof(stm_uberblock, ub_csum), csum, 32);

    return STM_OK;
}

stm_status stm_ub_decode(const void *buf, size_t buf_len, stm_uberblock *out_ub)
{
    if (!buf || !out_ub) return STM_EINVAL;
    if (buf_len != STM_UB_SIZE) return STM_ERANGE;

    const stm_uberblock *on_disk = (const stm_uberblock *)buf;

    /* Magic + version checks first — they fail fast on obviously
     * wrong buffers (uninitialized disk, wrong offset, etc.).
     *
     * R13 P2-1: magic mismatch and version mismatch return DIFFERENT
     * status codes so mount_scan can tell "blank slot" from "slot
     * holds a pool at an incompatible version". STM_ENOENT = "nothing
     * here"; STM_EBADVERSION = "something here, wrong version". */
    uint64_t magic = stm_load_le64(on_disk->ub_magic);
    if (magic != STM_UB_MAGIC) return STM_ENOENT;
    uint32_t version = stm_load_le32(on_disk->ub_version);
    if (version != STM_UB_VERSION) return STM_EBADVERSION;

    /* R14 P3-3: ub_gen == 0 is not a valid committed UB. The first
     * durable UB a pool ever writes is at gen=1 (fresh first commit
     * or mount-claim). A slot carrying magic+version but gen=0 is
     * either corrupt or an attacker-forged UB trying to pose as
     * committed state. Reject explicitly so `compute_auth_gen`
     * doesn't need to special-case a 0 sentinel. */
    uint64_t gen_field = stm_load_le64(on_disk->ub_gen);
    if (gen_field == 0) return STM_ECORRUPT;

    /* Recompute csum over a copy with the csum field zeroed. We must
     * not mutate the caller's buffer, and can't safely zero an in-
     * place stack copy smaller than 4096 — so stage the hash region. */
    uint8_t staged[STM_UB_SIZE];
    memcpy(staged, buf, STM_UB_SIZE);
    memset(staged + offsetof(stm_uberblock, ub_csum), 0, 32);

    uint8_t expected[32];
    stm_ub_csum(staged, STM_UB_SIZE, expected);

    /* Constant-time compare is overkill (this is integrity, not auth
     * with secret key material), but it costs nothing here. */
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= (uint8_t)(expected[i] ^ on_disk->ub_csum[i]);
    }
    if (diff != 0) return STM_ECORRUPT;

    /* All checks passed; hand back the struct. */
    memcpy(out_ub, buf, STM_UB_SIZE);
    return STM_OK;
}

/* ========================================================================= */
/* Key-schema header packing (P4-4a, ARCH §7.7.3).                            */
/* ========================================================================= */

void stm_ub_key_schema_pack(const stm_ub_key_schema_hdr *hdr,
                              uint8_t out[512])
{
    memset(out, 0, 512);
    le32 magic   = stm_store_le32(hdr->ks_magic);
    le32 version = stm_store_le32(hdr->ks_version);
    le64 flags   = stm_store_le64(hdr->ks_flags);
    memcpy(out + 0, magic.v,   4);
    memcpy(out + 4, version.v, 4);
    memcpy(out + 8, flags.v,   8);
    /* stm_bptr is a packed struct — copy directly. */
    memcpy(out + 16, &hdr->ks_root, sizeof hdr->ks_root);
    /* [80..512) stays zero from the memset above. */
}

stm_status stm_ub_key_schema_unpack(const uint8_t in[512],
                                      stm_ub_key_schema_hdr *out)
{
    le32 magic_le, version_le;
    le64 flags_le;
    memcpy(magic_le.v,   in + 0, 4);
    memcpy(version_le.v, in + 4, 4);
    memcpy(flags_le.v,   in + 8, 8);

    uint32_t magic   = stm_load_le32(magic_le);
    uint32_t version = stm_load_le32(version_le);
    if (magic   != STM_UB_KEY_SCHEMA_MAGIC)   return STM_EBADVERSION;
    if (version != STM_UB_KEY_SCHEMA_VERSION) return STM_EBADVERSION;

    out->ks_magic   = magic;
    out->ks_version = version;
    out->ks_flags   = stm_load_le64(flags_le);
    memcpy(&out->ks_root, in + 16, sizeof out->ks_root);
    return STM_OK;
}

/* ========================================================================= */
/* Durable scrub state packing (P5-durable-cursors, v8).                      */
/* ========================================================================= */

/* On-disk layout (64 bytes) inside ub_scrub_state[]:
 *   off  size   field
 *   0    1      scrub_state (u8 enum)
 *   1    1      reserved (zero)
 *   2    2      cursor_device_id (le16)
 *   4    4      reserved (zero)
 *   8    8      cursor_start_block  (le64)
 *  16    8      blocks_verified     (le64)
 *  24    8      blocks_failed       (le64)
 *  32    8      blocks_repaired     (le64)
 *  40    8      blocks_unrepairable (le64)
 *  48    8      ranges_processed    (le64)
 *  56    8      snapshot_cursor     (le64)
 *  64    -      total
 */
void stm_ub_scrub_state_pack(const stm_ub_scrub_state *state,
                              uint8_t out[64])
{
    memset(out, 0, 64);
    out[0] = state->scrub_state;
    /* out[1] reserved */
    le16 cd  = stm_store_le16(state->cursor_device_id);
    memcpy(out + 2, cd.v, 2);
    /* out[4..8) reserved */
    le64 csb = stm_store_le64(state->cursor_start_block);
    le64 bv  = stm_store_le64(state->blocks_verified);
    le64 bf  = stm_store_le64(state->blocks_failed);
    le64 br  = stm_store_le64(state->blocks_repaired);
    le64 bu  = stm_store_le64(state->blocks_unrepairable);
    le64 rp  = stm_store_le64(state->ranges_processed);
    le64 sc  = stm_store_le64(state->snapshot_cursor);
    memcpy(out + 8,  csb.v, 8);
    memcpy(out + 16, bv.v,  8);
    memcpy(out + 24, bf.v,  8);
    memcpy(out + 32, br.v,  8);
    memcpy(out + 40, bu.v,  8);
    memcpy(out + 48, rp.v,  8);
    memcpy(out + 56, sc.v,  8);
}

void stm_ub_scrub_state_unpack(const uint8_t in[64],
                                 stm_ub_scrub_state *out)
{
    out->scrub_state = in[0];
    le16 cd;
    memcpy(cd.v, in + 2, 2);
    out->cursor_device_id = stm_load_le16(cd);
    le64 csb, bv, bf, br, bu, rp, sc;
    memcpy(csb.v, in + 8,  8);
    memcpy(bv.v,  in + 16, 8);
    memcpy(bf.v,  in + 24, 8);
    memcpy(br.v,  in + 32, 8);
    memcpy(bu.v,  in + 40, 8);
    memcpy(rp.v,  in + 48, 8);
    memcpy(sc.v,  in + 56, 8);
    out->cursor_start_block  = stm_load_le64(csb);
    out->blocks_verified     = stm_load_le64(bv);
    out->blocks_failed       = stm_load_le64(bf);
    out->blocks_repaired     = stm_load_le64(br);
    out->blocks_unrepairable = stm_load_le64(bu);
    out->ranges_processed    = stm_load_le64(rp);
    out->snapshot_cursor     = stm_load_le64(sc);
}
