/* SPDX-License-Identifier: ISC */
/*
 * Per-dataset metadata-tree key encoding (Phase 9.7 — D1 per-dataset trees).
 *
 *   see docs/phase-9.7-design.md §2.1 — type-tagged keys.
 *   see docs/ARCHITECTURE.md §8.5 — per-dataset metadata trees.
 *
 * Under D1, each dataset owns one stm_btree_engine instance holding
 * inodes + dirents + xattrs + extent records under a SINGLE keyspace
 * discriminated by a 1-byte type tag at the front of every key. The
 * dataset itself names the tree, so the leading (dataset_id, ...)
 * composite-key prefix the pool-global engines carried at v29 drops.
 *
 * This module is the SINGLE chokepoint for the tag-byte encoding +
 * decoding. Every per-dataset-engine module (inode, dirent, xattr,
 * extent_index) calls through stm_metakey_compose at the writer-side
 * and stm_metakey_parse at the decoder-side. No module reaches for
 * the tag byte directly — the helper bounds-checks on parse so a
 * foreign byte at the tag position returns STM_ECORRUPT rather than
 * mis-routing to the wrong record-type's decoder.
 *
 * R71 P1-1 doctrine carry: writer-side tag byte and decoder-side
 * bounds check are SYMMETRIC. The same enum, the same bounds, the
 * same rejection class. A future record-kind addition adds an enum
 * value AND extends both bounds in lockstep.
 *
 * The helper itself is pure ASCII byte-shuffling — no allocation, no
 * crypto, no I/O. Tests cover roundtrip + every refusal class. The
 * design intent is that this lib never grows past O(100) lines —
 * complexity that wants to live here belongs in the calling module's
 * per-kind body codec instead (e.g., inode value encode/decode stays
 * in v2/src/inode/, not here).
 *
 * Spec composition: the type-tag is part of the key the engine sees.
 * btree.tla treats the key as opaque bytes; the lex-order invariant
 * holds because the tag byte is at offset 0 and dominates the sort —
 * `[0x01 ‖ ino]` < `[0x02 ‖ ...]` regardless of the rest. A
 * scan_range over `[0x01 ‖ 0]` .. `[0x02 ‖ 0]` is exactly the inode
 * subtree of the dataset's engine.
 */
#ifndef STRATUM_V2_METAKEY_H
#define STRATUM_V2_METAKEY_H

#include <stratum/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Per-dataset metadata-tree record kinds.
 *
 * Values are chosen so the lexicographic byte order matches the
 * "natural" iteration order at the engine layer: inodes first, then
 * dirents, then xattrs, then extents. A scan_range over a single tag
 * byte's worth of keys enumerates that one record type.
 *
 * The values are STABLE across versions (a v30 pool's tag bytes are
 * the v30 spec; a future per-kind addition gets a NEW tag value, not
 * a reordering). Adding a kind requires:
 *   1. Adding the enum value here.
 *   2. Extending STM_METAKEY_KIND_MAX below.
 *   3. Extending the kind-validity check in stm_metakey_compose +
 *      stm_metakey_parse (one line each, currently expressed as
 *      `kind >= STM_METAKEY_KIND_MIN && kind <= STM_METAKEY_KIND_MAX`).
 *   4. Bumping STM_UB_VERSION if the new kind affects on-disk layout.
 */
typedef enum {
    STM_METAKEY_KIND_INODE   = 0x01,
    STM_METAKEY_KIND_DIRENT  = 0x02,
    STM_METAKEY_KIND_XATTR   = 0x03,
    STM_METAKEY_KIND_EXTENT  = 0x04,
} stm_metakey_kind;

/* Validity bounds — readers and writers consult these in lockstep
 * (R71 P1-1 doctrine carry). */
#define STM_METAKEY_KIND_MIN  STM_METAKEY_KIND_INODE
#define STM_METAKEY_KIND_MAX  STM_METAKEY_KIND_EXTENT

/* The tag byte occupies exactly one byte at the front of every
 * composed key. Per-kind body sizes are caller-defined; this lib
 * doesn't know them. */
#define STM_METAKEY_TAG_LEN   ((size_t)1)

/*
 * Compose: write the tag byte at out[0], then copy body[0..body_len)
 * to out[1..1+body_len). Returns the total length written via
 * *out_len.
 *
 * Refusals:
 *   - kind outside [STM_METAKEY_KIND_MIN, STM_METAKEY_KIND_MAX]:
 *     STM_EINVAL. The caller passed an unknown enum value (or a raw
 *     byte cast to the enum). This is the writer-side equivalent of
 *     the decoder-side bounds check.
 *   - out == NULL or out_len == NULL: STM_EINVAL.
 *   - body == NULL && body_len > 0: STM_EINVAL.
 *   - out_cap < STM_METAKEY_TAG_LEN + body_len: STM_ENOSPC. The
 *     caller's buffer is too small; no bytes are written.
 *
 * On success: STM_OK, *out_len == STM_METAKEY_TAG_LEN + body_len.
 *
 * body_len == 0 is legal (a degenerate "tag-only" key). The lib
 * itself doesn't ascribe meaning to body shape — that's the calling
 * module's contract.
 */
STM_MUST_USE
stm_status stm_metakey_compose(stm_metakey_kind kind,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);

/*
 * Parse: read the tag byte at in[0], expose the body via
 * *out_body / *out_body_len.
 *
 * On success the body pointer is a non-owning view into the input
 * buffer — the caller MUST NOT outlive `in`.
 *
 * Refusals:
 *   - in == NULL: STM_EINVAL.
 *   - in_len < STM_METAKEY_TAG_LEN (no room for the tag): STM_ECORRUPT.
 *   - in[0] outside [STM_METAKEY_KIND_MIN, STM_METAKEY_KIND_MAX]:
 *     STM_ECORRUPT. The on-disk tag byte names a record kind this
 *     binary doesn't know about — refuse-loud rather than mis-route.
 *     R71 P1-1 doctrine carry; symmetric to the compose-side check.
 *   - out_kind == NULL or out_body == NULL or out_body_len == NULL:
 *     STM_EINVAL.
 *
 * On success: STM_OK, *out_kind set, *out_body = in + 1,
 * *out_body_len = in_len - 1.
 */
STM_MUST_USE
stm_status stm_metakey_parse(const uint8_t *in, size_t in_len,
                                stm_metakey_kind *out_kind,
                                const uint8_t **out_body,
                                size_t *out_body_len);

#ifdef __cplusplus
}
#endif
#endif /* STRATUM_V2_METAKEY_H */
