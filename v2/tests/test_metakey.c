/* SPDX-License-Identifier: ISC */
/*
 * Type-tagged metadata-key codec (9.7-impl-1a).
 *
 * Covers the public API in stratum/metakey.h:
 *
 *   - Composition + parse roundtrip for every kind in
 *     [STM_METAKEY_KIND_MIN, STM_METAKEY_KIND_MAX] across body sizes
 *     including the degenerate body_len = 0 case.
 *   - Refusal classes:
 *       * compose with OOR kind → STM_EINVAL (writer-side bounds).
 *       * compose with NULL out / NULL out_len → STM_EINVAL.
 *       * compose with NULL body + body_len > 0 → STM_EINVAL.
 *       * compose with under-sized buffer → STM_ENOSPC.
 *       * parse with NULL in → STM_EINVAL.
 *       * parse with empty input → STM_ECORRUPT (no room for tag).
 *       * parse with OOR tag byte → STM_ECORRUPT (decoder-side bounds).
 *       * parse with NULL out args → STM_EINVAL.
 *   - Adversarial: the tag-byte refusal class covers every byte
 *     outside the valid kind range (0x00, 0x05..0xFF). R71 P1-1
 *     doctrine carry: a foreign byte does NOT mis-route.
 */
#include "tharness.h"
#include <stratum/metakey.h>

#include <string.h>

/* Compose-then-parse roundtrip. Asserts the tag arrives intact and
 * the body is byte-identical at the parse side. */
static void roundtrip_one(stm_metakey_kind kind,
                          const uint8_t *body, size_t body_len) {
    uint8_t buf[256];
    size_t  buf_len = 0;
    STM_ASSERT_OK(stm_metakey_compose(kind, body, body_len,
                                          buf, sizeof buf, &buf_len));
    STM_ASSERT_EQ(buf_len, STM_METAKEY_TAG_LEN + body_len);
    STM_ASSERT_EQ((unsigned)buf[0], (unsigned)kind);
    if (body_len > 0) {
        STM_ASSERT_MEM_EQ(buf + STM_METAKEY_TAG_LEN, body, body_len);
    }

    stm_metakey_kind out_kind = (stm_metakey_kind)0;
    const uint8_t *out_body = NULL;
    size_t out_body_len = 0;
    STM_ASSERT_OK(stm_metakey_parse(buf, buf_len, &out_kind,
                                        &out_body, &out_body_len));
    STM_ASSERT_EQ((unsigned)out_kind, (unsigned)kind);
    STM_ASSERT_EQ(out_body_len, body_len);
    if (body_len > 0) {
        STM_ASSERT_MEM_EQ(out_body, body, body_len);
    }
    /* Non-owning view: parse returns a pointer INTO buf. */
    STM_ASSERT_TRUE(out_body == buf + STM_METAKEY_TAG_LEN);
}

STM_TEST(metakey_roundtrip_inode_typical_body) {
    /* Inode key body = 8-byte big-endian inode id. */
    const uint8_t body[8] = { 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x2a };
    roundtrip_one(STM_METAKEY_KIND_INODE, body, sizeof body);
}

STM_TEST(metakey_roundtrip_dirent_typical_body) {
    /* Dirent body = 8-byte dir_ino + N-byte hash. */
    const uint8_t body[16] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01,
        0xde,0xad,0xbe,0xef, 0xca,0xfe,0xba,0xbe
    };
    roundtrip_one(STM_METAKEY_KIND_DIRENT, body, sizeof body);
}

STM_TEST(metakey_roundtrip_xattr_typical_body) {
    const uint8_t body[16] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07,
        0xfe,0xed,0xfa,0xce, 0xc0,0xff,0xee,0x00
    };
    roundtrip_one(STM_METAKEY_KIND_XATTR, body, sizeof body);
}

STM_TEST(metakey_roundtrip_extent_typical_body) {
    /* Extent body = 8-byte ino + 8-byte offset, both big-endian. */
    const uint8_t body[16] = {
        0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x11,
        0x00,0x00,0x00,0x00, 0x00,0x01,0x00,0x00
    };
    roundtrip_one(STM_METAKEY_KIND_EXTENT, body, sizeof body);
}

STM_TEST(metakey_roundtrip_empty_body) {
    /* Degenerate body_len = 0 is legal (a tag-only key). */
    roundtrip_one(STM_METAKEY_KIND_INODE,  NULL, 0);
    roundtrip_one(STM_METAKEY_KIND_DIRENT, NULL, 0);
    roundtrip_one(STM_METAKEY_KIND_XATTR,  NULL, 0);
    roundtrip_one(STM_METAKEY_KIND_EXTENT, NULL, 0);
}

STM_TEST(metakey_compose_out_oor_kind_einval) {
    uint8_t buf[16]; size_t buf_len = 0;
    /* Cast a foreign byte through the enum — the writer-side bounds
     * check refuses-loud rather than encoding a corrupt tag. */
    STM_ASSERT_ERR(stm_metakey_compose((stm_metakey_kind)0x00, NULL, 0,
                                            buf, sizeof buf, &buf_len),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_metakey_compose((stm_metakey_kind)0x05, NULL, 0,
                                            buf, sizeof buf, &buf_len),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_metakey_compose((stm_metakey_kind)0xff, NULL, 0,
                                            buf, sizeof buf, &buf_len),
                   STM_EINVAL);
}

STM_TEST(metakey_compose_null_out_einval) {
    size_t buf_len = 0;
    STM_ASSERT_ERR(stm_metakey_compose(STM_METAKEY_KIND_INODE, NULL, 0,
                                            NULL, 16, &buf_len),
                   STM_EINVAL);
}

STM_TEST(metakey_compose_null_out_len_einval) {
    uint8_t buf[16];
    STM_ASSERT_ERR(stm_metakey_compose(STM_METAKEY_KIND_INODE, NULL, 0,
                                            buf, sizeof buf, NULL),
                   STM_EINVAL);
}

STM_TEST(metakey_compose_null_body_nonzero_len_einval) {
    uint8_t buf[16]; size_t buf_len = 0;
    STM_ASSERT_ERR(stm_metakey_compose(STM_METAKEY_KIND_INODE, NULL, 8,
                                            buf, sizeof buf, &buf_len),
                   STM_EINVAL);
}

STM_TEST(metakey_compose_undersize_buffer_enospc) {
    uint8_t buf[1]; /* exactly one byte — no room for body. */
    size_t buf_len = 0;
    const uint8_t body[8] = {0};
    STM_ASSERT_ERR(stm_metakey_compose(STM_METAKEY_KIND_INODE,
                                            body, sizeof body,
                                            buf, sizeof buf, &buf_len),
                   STM_ENOSPC);
    /* Defense: zero-cap buffer can't even fit the tag. */
    STM_ASSERT_ERR(stm_metakey_compose(STM_METAKEY_KIND_INODE,
                                            NULL, 0,
                                            buf, 0, &buf_len),
                   STM_ENOSPC);
}

STM_TEST(metakey_parse_null_in_einval) {
    stm_metakey_kind k; const uint8_t *body = NULL; size_t body_len = 0;
    STM_ASSERT_ERR(stm_metakey_parse(NULL, 8, &k, &body, &body_len),
                   STM_EINVAL);
}

STM_TEST(metakey_parse_empty_ecorrupt) {
    /* in_len < tag length → no room for the tag byte. */
    stm_metakey_kind k; const uint8_t *body = NULL; size_t body_len = 0;
    const uint8_t empty[1] = {0};
    STM_ASSERT_ERR(stm_metakey_parse(empty, 0, &k, &body, &body_len),
                   STM_ECORRUPT);
}

STM_TEST(metakey_parse_oor_tag_ecorrupt) {
    /* Sweep every byte outside [0x01, 0x04]. The R71 P1-1 doctrine
     * carry: the decoder must refuse-loud rather than mis-route to
     * the wrong record-type's decoder. */
    stm_metakey_kind k; const uint8_t *body = NULL; size_t body_len = 0;
    uint8_t buf[4] = {0};
    for (unsigned tag = 0; tag < 256; tag++) {
        if (tag >= (unsigned)STM_METAKEY_KIND_MIN
         && tag <= (unsigned)STM_METAKEY_KIND_MAX) continue;
        buf[0] = (uint8_t)tag;
        STM_ASSERT_ERR(stm_metakey_parse(buf, sizeof buf, &k, &body, &body_len),
                       STM_ECORRUPT);
    }
}

STM_TEST(metakey_parse_null_out_args_einval) {
    uint8_t buf[4] = { (uint8_t)STM_METAKEY_KIND_INODE, 0, 0, 0 };
    stm_metakey_kind k; const uint8_t *body = NULL; size_t body_len = 0;
    STM_ASSERT_ERR(stm_metakey_parse(buf, sizeof buf, NULL, &body, &body_len),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_metakey_parse(buf, sizeof buf, &k, NULL, &body_len),
                   STM_EINVAL);
    STM_ASSERT_ERR(stm_metakey_parse(buf, sizeof buf, &k, &body, NULL),
                   STM_EINVAL);
}

STM_TEST(metakey_parse_tag_only_ok) {
    /* The minimal valid composed key is exactly one byte (the tag). */
    uint8_t buf[1] = { (uint8_t)STM_METAKEY_KIND_DIRENT };
    stm_metakey_kind k; const uint8_t *body = NULL; size_t body_len = 0;
    STM_ASSERT_OK(stm_metakey_parse(buf, sizeof buf, &k, &body, &body_len));
    STM_ASSERT_EQ((unsigned)k, (unsigned)STM_METAKEY_KIND_DIRENT);
    STM_ASSERT_EQ(body_len, (size_t)0);
    STM_ASSERT_TRUE(body == buf + 1);
}

/* Lex-order property: the tag byte dominates the sort. A key with
 * tag T1 < T2 compares less than a key with tag T2, regardless of
 * body bytes. This is the property the engine layer's scan_range
 * relies on to enumerate one record-type at a time. */
STM_TEST(metakey_tag_dominates_lex_order) {
    uint8_t k_inode[16]; size_t k_inode_len = 0;
    uint8_t k_extent[16]; size_t k_extent_len = 0;

    /* Even with a HIGH-valued inode body and a LOW-valued extent
     * body, the tag byte forces inode < extent. */
    const uint8_t body_high[8] = { 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff };
    const uint8_t body_low [8] = { 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00 };

    STM_ASSERT_OK(stm_metakey_compose(STM_METAKEY_KIND_INODE,
                                          body_high, sizeof body_high,
                                          k_inode, sizeof k_inode, &k_inode_len));
    STM_ASSERT_OK(stm_metakey_compose(STM_METAKEY_KIND_EXTENT,
                                          body_low, sizeof body_low,
                                          k_extent, sizeof k_extent, &k_extent_len));
    STM_ASSERT_EQ(k_inode_len, k_extent_len);
    int cmp = memcmp(k_inode, k_extent, k_inode_len);
    STM_ASSERT_TRUE(cmp < 0);
}

STM_TEST_MAIN("metakey")
