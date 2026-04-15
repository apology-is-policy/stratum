#include "test_main.h"
#include "stratum/btree.h"
#include "stratum/block.h"
#include "stratum/key.h"
#include "stratum/bptr.h"
#include "stratum/inode.h"

#include <unistd.h>
#include <errno.h>

static const char *img = "/tmp/stratum_test_btree.img";
static void cleanup(void) { unlink(img); }

/* helper: make a key */
static struct stm_key mk_key(uint64_t ino, uint8_t type, uint64_t off)
{
    struct stm_key_cpu kc = { .ino = ino, .type = type, .offset = off };
    return stm_key_from_cpu(&kc);
}

/* ── basic insert + lookup ──────────────────────────────────────────── */

STM_TEST(test_btree_insert_lookup)
{
    struct stm_block_dev dev;
    struct stm_btree *tree;
    struct stm_bptr root = stm_bptr_null();

    int rc = stm_file_backend_open(img, 1, 64 * 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);

    rc = stm_btree_open(&dev, root, 0, &tree);
    STM_ASSERT_EQ(rc, 0);

    /* insert 3 inodes */
    uint32_t i;
    for (i = 1; i <= 3; i++) {
        struct stm_key k = mk_key(i, STM_KEY_INODE, 0);
        struct stm_inode ino;
        memset(&ino, 0, sizeof(ino));
        ino.si_ino = cpu_to_le64(i);
        ino.si_mode = cpu_to_le32(0755);
        rc = stm_btree_insert(tree, &k, &ino, sizeof(ino), i);
        STM_ASSERT_EQ(rc, 0);
    }

    /* lookup each */
    for (i = 1; i <= 3; i++) {
        struct stm_key k = mk_key(i, STM_KEY_INODE, 0);
        struct stm_inode found;
        uint32_t vlen = sizeof(found);
        rc = stm_btree_lookup(tree, &k, &found, &vlen);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(le64_to_cpu(found.si_ino), (uint64_t)i);
    }

    /* lookup non-existent */
    {
        struct stm_key k = mk_key(999, STM_KEY_INODE, 0);
        struct stm_inode found;
        uint32_t vlen = sizeof(found);
        rc = stm_btree_lookup(tree, &k, &found, &vlen);
        STM_ASSERT_EQ(rc, -ENOENT);
    }

    stm_btree_close(tree);
    stm_block_close(&dev);
    cleanup();
}

/* ── many inserts (triggers leaf splits + tree growth) ──────────────── */

STM_TEST(test_btree_many_inserts)
{
    struct stm_block_dev dev;
    struct stm_btree *tree;
    struct stm_bptr root = stm_bptr_null();
    uint32_t count = 2000;

    int rc = stm_file_backend_open(img, 1, 256 * 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_btree_open(&dev, root, 0, &tree);
    STM_ASSERT_EQ(rc, 0);

    uint32_t i;
    for (i = 0; i < count; i++) {
        struct stm_key k = mk_key(i + 1, STM_KEY_INODE, 0);
        uint64_t val = (uint64_t)(i + 1) * 1000;
        rc = stm_btree_insert(tree, &k, &val, sizeof(val), i + 1);
        STM_ASSERT_EQ(rc, 0);
    }

    /* tree should have grown beyond height 1 */
    STM_ASSERT(stm_btree_height(tree) >= 1);

    /* verify all values */
    for (i = 0; i < count; i++) {
        struct stm_key k = mk_key(i + 1, STM_KEY_INODE, 0);
        uint64_t got = 0;
        uint32_t vlen = sizeof(got);
        rc = stm_btree_lookup(tree, &k, &got, &vlen);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(got, (uint64_t)(i + 1) * 1000);
    }

    stm_btree_close(tree);
    stm_block_close(&dev);
    cleanup();
}

/* ── delete ─────────────────────────────────────────────────────────── */

STM_TEST(test_btree_delete)
{
    struct stm_block_dev dev;
    struct stm_btree *tree;
    struct stm_bptr root = stm_bptr_null();

    int rc = stm_file_backend_open(img, 1, 64 * 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_btree_open(&dev, root, 0, &tree);
    STM_ASSERT_EQ(rc, 0);

    struct stm_key k1 = mk_key(1, STM_KEY_INODE, 0);
    struct stm_key k2 = mk_key(2, STM_KEY_INODE, 0);
    uint32_t v1 = 100, v2 = 200;

    stm_btree_insert(tree, &k1, &v1, sizeof(v1), 1);
    stm_btree_insert(tree, &k2, &v2, sizeof(v2), 2);

    rc = stm_btree_delete(tree, &k1, 3);
    STM_ASSERT_EQ(rc, 0);

    uint32_t got, vlen;
    vlen = sizeof(got);
    STM_ASSERT_EQ(stm_btree_lookup(tree, &k1, &got, &vlen), -ENOENT);

    vlen = sizeof(got);
    STM_ASSERT_EQ(stm_btree_lookup(tree, &k2, &got, &vlen), 0);
    STM_ASSERT_EQ(got, 200u);

    stm_btree_close(tree);
    stm_block_close(&dev);
    cleanup();
}

/* ── overwrite ──────────────────────────────────────────────────────── */

STM_TEST(test_btree_overwrite)
{
    struct stm_block_dev dev;
    struct stm_btree *tree;
    struct stm_bptr root = stm_bptr_null();

    int rc = stm_file_backend_open(img, 1, 64 * 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_btree_open(&dev, root, 0, &tree);
    STM_ASSERT_EQ(rc, 0);

    struct stm_key k = mk_key(1, STM_KEY_DATA, 0);
    uint32_t v1 = 111, v2 = 222;

    stm_btree_insert(tree, &k, &v1, sizeof(v1), 1);
    stm_btree_insert(tree, &k, &v2, sizeof(v2), 2);

    uint32_t got, vlen = sizeof(got);
    rc = stm_btree_lookup(tree, &k, &got, &vlen);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(got, 222u);

    stm_btree_close(tree);
    stm_block_close(&dev);
    cleanup();
}

/* ── flush + reopen ─────────────────────────────────────────────────── */

STM_TEST(test_btree_flush_reopen)
{
    struct stm_block_dev dev;
    struct stm_btree *tree;
    struct stm_bptr root = stm_bptr_null();
    uint16_t height;

    int rc = stm_file_backend_open(img, 1, 64 * 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_btree_open(&dev, root, 0, &tree);
    STM_ASSERT_EQ(rc, 0);

    uint32_t i;
    for (i = 1; i <= 100; i++) {
        struct stm_key k = mk_key(i, STM_KEY_INODE, 0);
        stm_btree_insert(tree, &k, &i, sizeof(i), i);
    }

    rc = stm_btree_flush(tree);
    STM_ASSERT_EQ(rc, 0);

    root = stm_btree_root(tree);
    height = stm_btree_height(tree);
    STM_ASSERT(!stm_bptr_is_null(&root));

    stm_btree_close(tree);
    stm_block_close(&dev);

    /* reopen */
    rc = stm_file_backend_open(img, 0, 0, &dev);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_btree_open(&dev, root, height, &tree);
    STM_ASSERT_EQ(rc, 0);

    for (i = 1; i <= 100; i++) {
        struct stm_key k = mk_key(i, STM_KEY_INODE, 0);
        uint32_t got, vlen = sizeof(got);
        rc = stm_btree_lookup(tree, &k, &got, &vlen);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(got, i);
    }

    stm_btree_close(tree);
    stm_block_close(&dev);
    cleanup();
}

int main(void)
{
    STM_SUITE("btree");
    STM_RUN(test_btree_insert_lookup);
    STM_RUN(test_btree_many_inserts);
    STM_RUN(test_btree_delete);
    STM_RUN(test_btree_overwrite);
    STM_RUN(test_btree_flush_reopen);
    printf("all passed\n");
    return 0;
}
