/* SPDX-License-Identifier: ISC */
#include "tharness.h"
#include <stratum/types.h>

STM_TEST(le16_roundtrip) {
    uint16_t values[] = { 0, 1, 0x00FF, 0xFF00, 0xDEAD, 0xFFFF };
    for (size_t i = 0; i < STM_ARRAY_LEN(values); i++) {
        le16 enc = stm_store_le16(values[i]);
        uint16_t dec = stm_load_le16(enc);
        STM_ASSERT_EQ(dec, values[i]);
    }
}

STM_TEST(le32_roundtrip) {
    uint32_t values[] = { 0, 1, 0xDEADBEEFu, 0xFFFFFFFFu, 0x80000000u };
    for (size_t i = 0; i < STM_ARRAY_LEN(values); i++) {
        le32 enc = stm_store_le32(values[i]);
        uint32_t dec = stm_load_le32(enc);
        STM_ASSERT_EQ(dec, values[i]);
    }
}

STM_TEST(le64_roundtrip) {
    uint64_t values[] = { 0, 1, 0xDEADBEEFCAFEBABEull,
                          0xFFFFFFFFFFFFFFFFull, 0x8000000000000000ull };
    for (size_t i = 0; i < STM_ARRAY_LEN(values); i++) {
        le64 enc = stm_store_le64(values[i]);
        uint64_t dec = stm_load_le64(enc);
        STM_ASSERT(dec == values[i]);
    }
}

STM_TEST(le16_byte_order) {
    le16 v = stm_store_le16(0x1234);
    STM_ASSERT_EQ(v.v[0], 0x34);
    STM_ASSERT_EQ(v.v[1], 0x12);
}

STM_TEST(le32_byte_order) {
    le32 v = stm_store_le32(0x12345678);
    STM_ASSERT_EQ(v.v[0], 0x78);
    STM_ASSERT_EQ(v.v[1], 0x56);
    STM_ASSERT_EQ(v.v[2], 0x34);
    STM_ASSERT_EQ(v.v[3], 0x12);
}

STM_TEST(strerror_covers_all_codes) {
    stm_status codes[] = {
        STM_OK, STM_EINVAL, STM_ENOMEM, STM_ENOSPC, STM_EOVERFLOW, STM_ERANGE,
        STM_EIO, STM_ENOENT, STM_EEXIST, STM_EACCES, STM_EBUSY, STM_EAGAIN,
        STM_ENODEV, STM_EROFS, STM_ECORRUPT, STM_EBADTAG, STM_EBADVERSION,
        STM_EBADFEATURE, STM_EWEDGED, STM_ENOTSUPPORTED, STM_EPROTOCOL,
        STM_EBACKEND,
    };
    for (size_t i = 0; i < STM_ARRAY_LEN(codes); i++) {
        const char *s = stm_strerror(codes[i]);
        STM_ASSERT(s != NULL);
        STM_ASSERT(s[0] != '\0');
    }
}

STM_TEST_MAIN("types")
