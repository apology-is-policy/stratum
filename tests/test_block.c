#include "test_main.h"
#include "stratum/block.h"

#include <unistd.h>

static const char *test_path = "/tmp/stratum_test_block.img";

static void cleanup(void)
{
    unlink(test_path);
}

STM_TEST(test_file_backend_create)
{
    struct stm_block_dev dev;
    int rc = stm_file_backend_open(test_path, 1, 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);

    uint64_t sz = 0;
    rc = stm_block_size(&dev, &sz);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(sz, 1024u * 1024u);

    stm_block_close(&dev);
    cleanup();
}

STM_TEST(test_file_backend_write_read)
{
    struct stm_block_dev dev;
    int rc = stm_file_backend_open(test_path, 1, 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);

    /* Write a pattern at offset 4096 */
    uint8_t wbuf[512];
    for (int i = 0; i < 512; i++)
        wbuf[i] = (uint8_t)(i & 0xFF);

    rc = stm_block_write(&dev, 4096, wbuf, 512);
    STM_ASSERT_EQ(rc, 0);

    rc = stm_block_sync(&dev);
    STM_ASSERT_EQ(rc, 0);

    /* Read it back */
    uint8_t rbuf[512];
    memset(rbuf, 0, sizeof(rbuf));
    rc = stm_block_read(&dev, 4096, rbuf, 512);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, 512);

    stm_block_close(&dev);
    cleanup();
}

STM_TEST(test_file_backend_reopen)
{
    struct stm_block_dev dev;
    int rc = stm_file_backend_open(test_path, 1, 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);

    uint8_t wbuf[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    rc = stm_block_write(&dev, 0, wbuf, 4);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_block_sync(&dev);
    STM_ASSERT_EQ(rc, 0);
    stm_block_close(&dev);

    /* Reopen existing file */
    rc = stm_file_backend_open(test_path, 0, 0, &dev);
    STM_ASSERT_EQ(rc, 0);

    uint8_t rbuf[4] = {0};
    rc = stm_block_read(&dev, 0, rbuf, 4);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, 4);

    uint64_t sz = 0;
    stm_block_size(&dev, &sz);
    STM_ASSERT_EQ(sz, 1024u * 1024u);

    stm_block_close(&dev);
    cleanup();
}

STM_TEST(test_file_backend_boundary_write)
{
    struct stm_block_dev dev;
    uint64_t size = 8192;
    int rc = stm_file_backend_open(test_path, 1, size, &dev);
    STM_ASSERT_EQ(rc, 0);

    /* Write at the end of the file */
    uint8_t wbuf[4] = { 0xCA, 0xFE, 0xBA, 0xBE };
    rc = stm_block_write(&dev, size - 4, wbuf, 4);
    STM_ASSERT_EQ(rc, 0);

    uint8_t rbuf[4] = {0};
    rc = stm_block_read(&dev, size - 4, rbuf, 4);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, 4);

    stm_block_close(&dev);
    cleanup();
}

int main(void)
{
    STM_SUITE("block");
    STM_RUN(test_file_backend_create);
    STM_RUN(test_file_backend_write_read);
    STM_RUN(test_file_backend_reopen);
    STM_RUN(test_file_backend_boundary_write);
    printf("all passed\n");
    return 0;
}
