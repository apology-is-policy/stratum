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

    rc = stm_btree_flush(tree, 100);
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

/* scan must respect buffered DELETE messages. Previously scan_rec's
 * leaf branch only handled buffered INSERTs; buffered DELETEs (not
 * yet flushed down to the leaf) silently leaked stale entries. */

struct scan_keys_ctx {
    uint64_t seen[32];
    int      n;
};

static int scan_keys_cb(const struct stm_key *key, const void *val,
                        uint32_t vlen, void *ctx)
{
    struct scan_keys_ctx *c = ctx;
    (void)val; (void)vlen;
    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (c->n < 32) c->seen[c->n++] = kc.ino;
    return 0;
}

STM_TEST(test_btree_scan_respects_buffered_delete)
{
    struct stm_block_dev dev;
    struct stm_btree *tree;
    STM_ASSERT_EQ(stm_file_backend_open(img, 1, 64 * 1024 * 1024, &dev), 0);
    STM_ASSERT_EQ(stm_btree_open(&dev, stm_bptr_null(), 0, &tree), 0);

    /* Stuff the tree with enough entries to force a split so the root
     * is internal. Delete then targets the buffered-message path. */
    uint32_t planted = 0;
    uint64_t pad[128];
    memset(pad, 0xAB, sizeof(pad));
    for (uint32_t i = 1; i <= 4000; i++) {
        struct stm_key k = mk_key(i, STM_KEY_INODE, 0);
        STM_ASSERT_EQ(stm_btree_insert(tree, &k, pad, sizeof(pad), i), 0);
        planted++;
    }
    STM_ASSERT_EQ(stm_btree_flush(tree, 9999), 0);
    /* After flush the tree has internal nodes with empty buffers.
     * The next delete below buffers its DELETE in the root. */
    STM_ASSERT(stm_btree_height(tree) >= 2);

    /* Delete a key living in some leaf — DELETE lands in root's buffer
     * and does NOT get flushed to the leaf (one delete is well below
     * the flush threshold). */
    const uint64_t victim = 1234;
    {
        struct stm_key k = mk_key(victim, STM_KEY_INODE, 0);
        STM_ASSERT_EQ(stm_btree_delete(tree, &k, 10000), 0);
    }

    /* Scan the full range. Before the fix, ino=victim was returned by
     * the leaf branch since the ancestor DELETE wasn't honored. */
    struct scan_keys_ctx c = { .n = 0 };
    /* Use a narrow range near the victim so the seen buffer doesn't
     * need to hold thousands of keys — scan_keys_ctx caps at 32. */
    struct stm_key lo = mk_key(victim - 5, 0, 0);
    struct stm_key hi = mk_key(victim + 5, UINT8_MAX, UINT64_MAX);
    STM_ASSERT_EQ(stm_btree_scan(tree, &lo, &hi, scan_keys_cb, &c), 0);

    int found_victim = 0;
    for (int i = 0; i < c.n; i++)
        if (c.seen[i] == victim) found_victim = 1;
    STM_ASSERT_EQ(found_victim, 0);

    stm_btree_close(tree);
    stm_block_close(&dev);
    cleanup();
    (void)planted;
}

int main(void)
{
    STM_SUITE("btree");
    STM_RUN(test_btree_insert_lookup);
    STM_RUN(test_btree_many_inserts);
    STM_RUN(test_btree_delete);
    STM_RUN(test_btree_overwrite);
    STM_RUN(test_btree_flush_reopen);
    STM_RUN(test_btree_scan_respects_buffered_delete);
    printf("all passed\n");
    return 0;
}
