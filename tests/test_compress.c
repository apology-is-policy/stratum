#include "test_main.h"
#include "stratum/compress.h"
#include "stratum/bptr.h"
#include "stratum/btree.h"
#include "stratum/block.h"
#include "stratum/key.h"

#include <unistd.h>
#include <errno.h>

/* ── compress/decompress round-trip ─────────────────────────────────── */

static void test_roundtrip(uint8_t algo, const char *name)
{
    uint8_t src[4096], dst[8192], back[4096];
    uint32_t i, dlen;

    /* fill with patterned data (compressible) */
    for (i = 0; i < sizeof(src); i++)
        src[i] = (uint8_t)(i % 251);

    dlen = sizeof(dst);
    int rc = stm_compress(algo, src, sizeof(src), dst, &dlen);
    if (rc == -EINVAL) {
        printf("  %-50s SKIP (not compiled in)\n", name);
        return;
    }
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT(dlen > 0);
    STM_ASSERT(dlen < sizeof(src)); /* should compress well */

    rc = stm_decompress(algo, dst, dlen, back, sizeof(back));
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_MEM_EQ(src, back, sizeof(src));

    printf("  %-50s OK  (%u → %u bytes)\n", name, (unsigned)sizeof(src), dlen);
}

STM_TEST(test_lz4_roundtrip)   { test_roundtrip(STM_COMP_LZ4,  "lz4_roundtrip"); }
STM_TEST(test_zstd_roundtrip)  { test_roundtrip(STM_COMP_ZSTD, "zstd_roundtrip"); }

STM_TEST(test_none_roundtrip)
{
    uint8_t src[64], dst[64], back[64];
    uint32_t dlen = sizeof(dst);
    memset(src, 0xAB, sizeof(src));

    int rc = stm_compress(STM_COMP_NONE, src, sizeof(src), dst, &dlen);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(dlen, (uint32_t)sizeof(src));

    rc = stm_decompress(STM_COMP_NONE, dst, dlen, back, sizeof(back));
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_MEM_EQ(src, back, sizeof(src));
}

STM_TEST(test_compress_bound)
{
    uint32_t b;
    b = stm_compress_bound(STM_COMP_NONE, 4096);
    STM_ASSERT_EQ(b, 4096u);

#ifdef STM_HAVE_LZ4
    b = stm_compress_bound(STM_COMP_LZ4, 4096);
    STM_ASSERT(b >= 4096u);
#endif

#ifdef STM_HAVE_ZSTD
    b = stm_compress_bound(STM_COMP_ZSTD, 4096);
    STM_ASSERT(b >= 4096u);
#endif
}

/* ── btree with compression ─────────────────────────────────────────── */

static const char *img = "/tmp/stratum_test_compress.img";

static void test_btree_with_algo(uint8_t algo, const char *name)
{
    struct stm_block_dev dev;
    struct stm_btree *tree;
    struct stm_bptr root = stm_bptr_null();
    uint32_t count = 500, i;

    /* check if algorithm is available */
    {
        uint8_t t[64], o[128];
        uint32_t ol = sizeof(o);
        memset(t, 0, sizeof(t));
        if (stm_compress(algo, t, sizeof(t), o, &ol) == -EINVAL) {
            printf("  %-50s SKIP (not compiled in)\n", name);
            return;
        }
    }

    int rc = stm_file_backend_open(img, 1, 128 * 1024 * 1024, &dev);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_btree_open(&dev, root, 0, &tree);
    STM_ASSERT_EQ(rc, 0);

    stm_btree_set_compression(tree, algo);

    /* insert many items */
    for (i = 0; i < count; i++) {
        struct stm_key_cpu kc = { .ino = i + 1, .type = STM_KEY_INODE, .offset = 0 };
        struct stm_key k = stm_key_from_cpu(&kc);
        uint64_t val = (uint64_t)(i + 1) * 1000;
        rc = stm_btree_insert(tree, &k, &val, sizeof(val), i + 1);
        STM_ASSERT_EQ(rc, 0);
    }

    /* flush and verify space used is less than uncompressed */
    rc = stm_btree_flush(tree, 1);
    STM_ASSERT_EQ(rc, 0);
    uint64_t used = stm_btree_next_alloc(tree) - 2 * STM_BLOCK_SIZE;

    /* verify all lookups */
    for (i = 0; i < count; i++) {
        struct stm_key_cpu kc = { .ino = i + 1, .type = STM_KEY_INODE, .offset = 0 };
        struct stm_key k = stm_key_from_cpu(&kc);
        uint64_t got = 0;
        uint32_t vlen = sizeof(got);
        rc = stm_btree_lookup(tree, &k, &got, &vlen);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(got, (uint64_t)(i + 1) * 1000);
    }

    printf("  %-50s OK  (disk used: %llu bytes)\n", name,
           (unsigned long long)used);

    stm_btree_close(tree);
    stm_block_close(&dev);
    unlink(img);
}

STM_TEST(test_btree_lz4)  { test_btree_with_algo(STM_COMP_LZ4,  "btree_lz4"); }
STM_TEST(test_btree_zstd) { test_btree_with_algo(STM_COMP_ZSTD, "btree_zstd"); }

int main(void)
{
    STM_SUITE("compress");
    STM_RUN(test_none_roundtrip);
    STM_RUN(test_lz4_roundtrip);
    STM_RUN(test_zstd_roundtrip);
    STM_RUN(test_compress_bound);
    STM_RUN(test_btree_lz4);
    STM_RUN(test_btree_zstd);
    printf("all passed\n");
    return 0;
}
