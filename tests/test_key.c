#include "test_main.h"
#include "stratum/key.h"

STM_TEST(test_key_roundtrip)
{
    struct stm_key_cpu cpu = { .ino = 42, .type = STM_KEY_DATA, .offset = 8192 };
    struct stm_key disk = stm_key_from_cpu(&cpu);
    struct stm_key_cpu back = stm_key_to_cpu(&disk);
    STM_ASSERT_EQ(back.ino, 42u);
    STM_ASSERT_EQ(back.type, STM_KEY_DATA);
    STM_ASSERT_EQ(back.offset, 8192u);
}

STM_TEST(test_key_cmp_by_ino)
{
    struct stm_key a = stm_key_from_cpu(&(struct stm_key_cpu){ 1, STM_KEY_INODE, 0 });
    struct stm_key b = stm_key_from_cpu(&(struct stm_key_cpu){ 2, STM_KEY_INODE, 0 });
    STM_ASSERT(stm_key_cmp(&a, &b) < 0);
    STM_ASSERT(stm_key_cmp(&b, &a) > 0);
    STM_ASSERT_EQ(stm_key_cmp(&a, &a), 0);
}

STM_TEST(test_key_cmp_by_type)
{
    struct stm_key a = stm_key_from_cpu(&(struct stm_key_cpu){ 1, STM_KEY_INODE, 0 });
    struct stm_key b = stm_key_from_cpu(&(struct stm_key_cpu){ 1, STM_KEY_DIRENT, 0 });
    struct stm_key c = stm_key_from_cpu(&(struct stm_key_cpu){ 1, STM_KEY_DATA, 0 });
    STM_ASSERT(stm_key_cmp(&a, &b) < 0);
    STM_ASSERT(stm_key_cmp(&b, &c) < 0);
    STM_ASSERT(stm_key_cmp(&a, &c) < 0);
}

STM_TEST(test_key_cmp_by_offset)
{
    struct stm_key a = stm_key_from_cpu(&(struct stm_key_cpu){ 1, STM_KEY_DATA, 0 });
    struct stm_key b = stm_key_from_cpu(&(struct stm_key_cpu){ 1, STM_KEY_DATA, 4096 });
    STM_ASSERT(stm_key_cmp(&a, &b) < 0);
    STM_ASSERT(stm_key_cmp(&b, &a) > 0);
}

STM_TEST(test_key_ordering_ino_dominates)
{
    /* ino=1, type=XATTR should be less than ino=2, type=INODE */
    struct stm_key a = stm_key_from_cpu(&(struct stm_key_cpu){ 1, STM_KEY_XATTR, UINT64_MAX });
    struct stm_key b = stm_key_from_cpu(&(struct stm_key_cpu){ 2, STM_KEY_INODE, 0 });
    STM_ASSERT(stm_key_cmp(&a, &b) < 0);
}

STM_TEST(test_key_cmp_equal)
{
    struct stm_key a = stm_key_from_cpu(&(struct stm_key_cpu){ 100, STM_KEY_DIRENT, 999 });
    struct stm_key b = stm_key_from_cpu(&(struct stm_key_cpu){ 100, STM_KEY_DIRENT, 999 });
    STM_ASSERT_EQ(stm_key_cmp(&a, &b), 0);
}

int main(void)
{
    STM_SUITE("key");
    STM_RUN(test_key_roundtrip);
    STM_RUN(test_key_cmp_by_ino);
    STM_RUN(test_key_cmp_by_type);
    STM_RUN(test_key_cmp_by_offset);
    STM_RUN(test_key_ordering_ino_dominates);
    STM_RUN(test_key_cmp_equal);
    printf("all passed\n");
    return 0;
}
