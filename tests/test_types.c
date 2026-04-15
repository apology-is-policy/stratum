#include "test_main.h"
#include "stratum/types.h"
#include "stratum/key.h"
#include "stratum/bptr.h"
#include "stratum/inode.h"
#include "stratum/msg.h"
#include "stratum/node.h"
#include "stratum/super.h"
#include "stratum/snapshot.h"
#include "stratum/space.h"

/* Verify all on-disk struct sizes are exactly as specified */
STM_TEST(test_struct_sizes)
{
    STM_ASSERT_EQ(sizeof(le64), 8u);
    STM_ASSERT_EQ(sizeof(le32), 4u);
    STM_ASSERT_EQ(sizeof(le16), 2u);
    STM_ASSERT_EQ(sizeof(struct stm_key), 17u);
    STM_ASSERT_EQ(sizeof(struct stm_bptr), 57u);
    STM_ASSERT_EQ(sizeof(struct stm_inode), 88u);
    STM_ASSERT_EQ(sizeof(struct stm_msg), 30u);
    STM_ASSERT_EQ(sizeof(struct stm_node_hdr), 64u);
    STM_ASSERT_EQ(sizeof(struct stm_superblock), 512u);
    STM_ASSERT_EQ(sizeof(struct stm_snapshot), 88u);
    STM_ASSERT_EQ(sizeof(struct stm_space_entry), 32u);
}

/* Verify endian round-trip: cpu → le → cpu is identity */
STM_TEST(test_le64_roundtrip)
{
    uint64_t vals[] = { 0, 1, 0xFF, 0xDEADBEEFCAFEBABEULL, UINT64_MAX };
    for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
        le64 le = cpu_to_le64(vals[i]);
        uint64_t back = le64_to_cpu(le);
        STM_ASSERT_EQ(back, vals[i]);
    }
}

STM_TEST(test_le32_roundtrip)
{
    uint32_t vals[] = { 0, 1, 0xFF, 0xDEADBEEF, UINT32_MAX };
    for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
        le32 le = cpu_to_le32(vals[i]);
        uint32_t back = le32_to_cpu(le);
        STM_ASSERT_EQ(back, vals[i]);
    }
}

STM_TEST(test_le16_roundtrip)
{
    uint16_t vals[] = { 0, 1, 0xFF, 0xBEEF, UINT16_MAX };
    for (size_t i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
        le16 le = cpu_to_le16(vals[i]);
        uint16_t back = le16_to_cpu(le);
        STM_ASSERT_EQ(back, vals[i]);
    }
}

/* Verify on-disk byte representation is little-endian */
STM_TEST(test_le64_byte_order)
{
    le64 le = cpu_to_le64(UINT64_C(0x0102030405060708));
    uint8_t *bytes = (uint8_t *)&le;
    STM_ASSERT_EQ(bytes[0], 0x08);
    STM_ASSERT_EQ(bytes[1], 0x07);
    STM_ASSERT_EQ(bytes[2], 0x06);
    STM_ASSERT_EQ(bytes[3], 0x05);
    STM_ASSERT_EQ(bytes[4], 0x04);
    STM_ASSERT_EQ(bytes[5], 0x03);
    STM_ASSERT_EQ(bytes[6], 0x02);
    STM_ASSERT_EQ(bytes[7], 0x01);
}

STM_TEST(test_le32_byte_order)
{
    le32 le = cpu_to_le32(UINT32_C(0x01020304));
    uint8_t *bytes = (uint8_t *)&le;
    STM_ASSERT_EQ(bytes[0], 0x04);
    STM_ASSERT_EQ(bytes[1], 0x03);
    STM_ASSERT_EQ(bytes[2], 0x02);
    STM_ASSERT_EQ(bytes[3], 0x01);
}

/* Verify bptr null sentinel */
STM_TEST(test_bptr_null)
{
    struct stm_bptr bp = stm_bptr_null();
    STM_ASSERT(stm_bptr_is_null(&bp));

    bp.bp_paddr = cpu_to_le64(42);
    STM_ASSERT(!stm_bptr_is_null(&bp));
}

/* Verify magic constant */
STM_TEST(test_magic)
{
    le64 le = cpu_to_le64(STM_MAGIC);
    uint8_t *bytes = (uint8_t *)&le;
    STM_ASSERT_EQ(bytes[0], 'S');
    STM_ASSERT_EQ(bytes[1], 'T');
    STM_ASSERT_EQ(bytes[2], 'R');
    STM_ASSERT_EQ(bytes[3], 'A');
    STM_ASSERT_EQ(bytes[4], 'T');
    STM_ASSERT_EQ(bytes[5], 'U');
    STM_ASSERT_EQ(bytes[6], 'M');
    STM_ASSERT_EQ(bytes[7], '\0');
}

int main(void)
{
    STM_SUITE("types");
    STM_RUN(test_struct_sizes);
    STM_RUN(test_le64_roundtrip);
    STM_RUN(test_le32_roundtrip);
    STM_RUN(test_le16_roundtrip);
    STM_RUN(test_le64_byte_order);
    STM_RUN(test_le32_byte_order);
    STM_RUN(test_bptr_null);
    STM_RUN(test_magic);
    printf("all passed\n");
    return 0;
}
