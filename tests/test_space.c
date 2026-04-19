#include "test_main.h"
#include "stratum/space.h"
#include "stratum/block.h"
#include "stratum/bptr.h"

#include <unistd.h>
#include <errno.h>

static const char *img = "/tmp/stratum_test_space.img";
static void cleanup(void) { unlink(img); }

/* Open a fresh space tree on a fresh 16 MiB image. Caller closes both. */
static void fresh(struct stm_block_dev *dev, struct stm_space **sp)
{
    cleanup();
    int rc = stm_file_backend_open(img, 1, 16 * 1024 * 1024, dev);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_space_open(dev, stm_bptr_null(), 0, sp);
    STM_ASSERT_EQ(rc, 0);
}

/* ── insert + lookup roundtrip ─────────────────────────────────────── */

STM_TEST(test_space_insert_lookup)
{
    struct stm_block_dev dev;
    struct stm_space *sp;
    fresh(&dev, &sp);

    STM_ASSERT_EQ(stm_space_insert(sp, 100, 8, /*gen=*/1), 0);

    uint64_t count = 0;
    uint32_t refcount = 0;
    STM_ASSERT_EQ(stm_space_lookup(sp, 100, &count, &refcount), 0);
    STM_ASSERT_EQ(count, 8u);
    STM_ASSERT_EQ(refcount, 1u);

    /* Key not present. */
    STM_ASSERT_EQ(stm_space_lookup(sp, 200, &count, &refcount), -ENOENT);

    /* Insert over an existing range → -EEXIST (caller should use ref). */
    STM_ASSERT_EQ(stm_space_insert(sp, 100, 8, 2), -EEXIST);

    /* Zero-count insert rejected. */
    STM_ASSERT_EQ(stm_space_insert(sp, 300, 0, 2), -EINVAL);

    stm_space_close(sp);
    stm_block_close(&dev);
    cleanup();
}

/* ── ref / unref / delete at zero ──────────────────────────────────── */

STM_TEST(test_space_refcount_lifecycle)
{
    struct stm_block_dev dev;
    struct stm_space *sp;
    fresh(&dev, &sp);

    STM_ASSERT_EQ(stm_space_insert(sp, 50, 4, 1), 0);

    /* Bump to 3 via two refs. */
    STM_ASSERT_EQ(stm_space_ref(sp, 50, 1), 0);
    STM_ASSERT_EQ(stm_space_ref(sp, 50, 1), 0);
    uint32_t rc_val;
    STM_ASSERT_EQ(stm_space_lookup(sp, 50, NULL, &rc_val), 0);
    STM_ASSERT_EQ(rc_val, 3u);

    /* Unref down to 1 — still present. */
    STM_ASSERT_EQ(stm_space_unref(sp, 50, 1), 0);
    STM_ASSERT_EQ(stm_space_unref(sp, 50, 1), 0);
    STM_ASSERT_EQ(stm_space_lookup(sp, 50, NULL, &rc_val), 0);
    STM_ASSERT_EQ(rc_val, 1u);

    /* Final unref deletes the entry → lookup returns -ENOENT. */
    STM_ASSERT_EQ(stm_space_unref(sp, 50, 1), 0);
    STM_ASSERT_EQ(stm_space_lookup(sp, 50, NULL, &rc_val), -ENOENT);

    /* ref / unref on nonexistent range → -ENOENT. */
    STM_ASSERT_EQ(stm_space_ref(sp, 50, 1), -ENOENT);
    STM_ASSERT_EQ(stm_space_unref(sp, 999, 1), -ENOENT);

    stm_space_close(sp);
    stm_block_close(&dev);
    cleanup();
}

/* ── find_gap: empty tree, between ranges, trailing gap, ENOSPC ───── */

STM_TEST(test_space_find_gap_basic)
{
    struct stm_block_dev dev;
    struct stm_space *sp;
    fresh(&dev, &sp);

    /* Empty tree — first gap is at 0. */
    uint64_t out = 0;
    STM_ASSERT_EQ(stm_space_find_gap(sp, /*total=*/1000, /*hint=*/0,
                                     /*count=*/10, &out), 0);
    STM_ASSERT_EQ(out, 0u);

    /* Populate: ranges at [100,108), [200,205), [500,510). */
    STM_ASSERT_EQ(stm_space_insert(sp, 100, 8, 1), 0);
    STM_ASSERT_EQ(stm_space_insert(sp, 200, 5, 1), 0);
    STM_ASSERT_EQ(stm_space_insert(sp, 500, 10, 1), 0);

    /* hint=0, need 50 → first gap [0,100) fits. */
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 0, 50, &out), 0);
    STM_ASSERT_EQ(out, 0u);

    /* hint=150, need 30 → gap [150,200) is 50 blocks, fits. Return 150. */
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 150, 30, &out), 0);
    STM_ASSERT_EQ(out, 150u);

    /* hint=150, need 60 → [150,200) is only 50; next gap [205,500)=295 fits.
     * Return 205. */
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 150, 60, &out), 0);
    STM_ASSERT_EQ(out, 205u);

    /* hint=600, need 200 → trailing gap [600, 1000) is 400 blocks, fits. */
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 600, 200, &out), 0);
    STM_ASSERT_EQ(out, 600u);

    /* hint=0, need 600 → no single gap fits (largest is [510,1000)=490). */
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 0, 600, &out), -ENOSPC);

    /* count exceeding total size → -EINVAL (caller bug, not a space issue). */
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 0, 1001, &out), -EINVAL);

    stm_space_close(sp);
    stm_block_close(&dev);
    cleanup();
}

/* ── find_gap wraparound ───────────────────────────────────────────── */

STM_TEST(test_space_find_gap_wraparound)
{
    struct stm_block_dev dev;
    struct stm_space *sp;
    fresh(&dev, &sp);

    /* Allocate [500, 950). Leaves a big hole [0,500), a tiny tail [950,1000). */
    STM_ASSERT_EQ(stm_space_insert(sp, 500, 450, 1), 0);

    /* hint=600 (inside the allocated region), need=200. Tail gap
     * [950,1000) is only 50 blocks → doesn't fit. Wraparound to
     * [0,500) → fits; return 0. */
    uint64_t out = 0xdeadbeef;
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 600, 200, &out), 0);
    STM_ASSERT_EQ(out, 0u);

    /* hint=600, need=30. Tail gap fits first (start at max(950,600)=950). */
    STM_ASSERT_EQ(stm_space_find_gap(sp, 1000, 600, 30, &out), 0);
    STM_ASSERT_EQ(out, 950u);

    stm_space_close(sp);
    stm_block_close(&dev);
    cleanup();
}

/* ── walk produces entries in key order ────────────────────────────── */

struct collect_ctx {
    uint64_t  starts[8];
    uint64_t  counts[8];
    uint32_t  refcounts[8];
    int       n;
};

static int collect_cb(uint64_t start, uint64_t count, uint32_t refcount, void *ctx)
{
    struct collect_ctx *c = ctx;
    if (c->n < 8) {
        c->starts[c->n]    = start;
        c->counts[c->n]    = count;
        c->refcounts[c->n] = refcount;
        c->n++;
    }
    return 0;
}

STM_TEST(test_space_walk_order)
{
    struct stm_block_dev dev;
    struct stm_space *sp;
    fresh(&dev, &sp);

    /* Insert in scrambled order; walk must yield sorted-by-start. */
    STM_ASSERT_EQ(stm_space_insert(sp, 300, 3, 1), 0);
    STM_ASSERT_EQ(stm_space_insert(sp, 100, 1, 1), 0);
    STM_ASSERT_EQ(stm_space_insert(sp, 200, 2, 1), 0);
    STM_ASSERT_EQ(stm_space_ref(sp, 200, 1), 0);      /* refcount 2 */

    struct collect_ctx c = { 0 };
    STM_ASSERT_EQ(stm_space_walk(sp, collect_cb, &c), 0);
    STM_ASSERT_EQ(c.n, 3);
    STM_ASSERT_EQ(c.starts[0], 100u);
    STM_ASSERT_EQ(c.starts[1], 200u);
    STM_ASSERT_EQ(c.starts[2], 300u);
    STM_ASSERT_EQ(c.counts[0], 1u);
    STM_ASSERT_EQ(c.counts[1], 2u);
    STM_ASSERT_EQ(c.counts[2], 3u);
    STM_ASSERT_EQ(c.refcounts[1], 2u);

    stm_space_close(sp);
    stm_block_close(&dev);
    cleanup();
}

/* ── persistence via commit + reopen ───────────────────────────────── */

STM_TEST(test_space_persistence)
{
    struct stm_block_dev dev;
    struct stm_space *sp;
    fresh(&dev, &sp);

    STM_ASSERT_EQ(stm_space_insert(sp, 42, 13, 7), 0);
    STM_ASSERT_EQ(stm_space_ref(sp, 42, 7), 0);
    STM_ASSERT_EQ(stm_space_commit(sp, 7), 0);

    /* Capture the root bptr + height so we can reopen on top of it. */
    struct stm_bptr root = stm_space_root(sp);
    uint16_t        height = stm_space_height(sp);

    stm_space_close(sp);

    /* Reopen from the committed root. */
    STM_ASSERT_EQ(stm_space_open(&dev, root, height, &sp), 0);
    uint64_t count = 0;
    uint32_t refcount = 0;
    STM_ASSERT_EQ(stm_space_lookup(sp, 42, &count, &refcount), 0);
    STM_ASSERT_EQ(count, 13u);
    STM_ASSERT_EQ(refcount, 2u);

    stm_space_close(sp);
    stm_block_close(&dev);
    cleanup();
}

int main(void)
{
    STM_SUITE("space");
    STM_RUN(test_space_insert_lookup);
    STM_RUN(test_space_refcount_lifecycle);
    STM_RUN(test_space_find_gap_basic);
    STM_RUN(test_space_find_gap_wraparound);
    STM_RUN(test_space_walk_order);
    STM_RUN(test_space_persistence);
    printf("all passed\n");
    return 0;
}
