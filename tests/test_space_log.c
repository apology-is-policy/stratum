#include "test_main.h"
#include "stratum/space.h"
#include "stratum/block.h"
#include "stratum/bptr.h"

#include <unistd.h>
#include <errno.h>

static const char *img = "/tmp/stratum_test_space_log.img";
static void cleanup(void) { unlink(img); }

/* ── test-local bump allocator for log chunks ─────────────────────── */

struct bump {
    uint64_t next;          /* byte paddr of next available chunk */
    uint64_t freed[128];    /* list of freed paddrs (for truncate tests) */
    int      nfreed;
};

/* Log chunks start past the first few blocks. Leave room for callers to
 * do whatever tree-level allocation they might also want. */
static void bump_init(struct bump *b) { b->next = 64 * 1024; b->nfreed = 0; }

static int bump_alloc(void *ctx, uint64_t *out_paddr)
{
    struct bump *b = ctx;
    *out_paddr = b->next;
    b->next += STM_SPACE_LOG_CHUNK_SIZE;
    return 0;
}

static void bump_free(void *ctx, uint64_t paddr)
{
    struct bump *b = ctx;
    if (b->nfreed < (int)(sizeof(b->freed) / sizeof(b->freed[0])))
        b->freed[b->nfreed++] = paddr;
}

static void open_dev(struct stm_block_dev *dev)
{
    cleanup();
    STM_ASSERT_EQ(stm_file_backend_open(img, 1, 16 * 1024 * 1024, dev), 0);
}

static struct stm_space_entry mkentry(uint8_t op, uint64_t paddr,
                                      uint64_t count, uint32_t refcount,
                                      uint64_t gen)
{
    struct stm_space_entry e = {0};
    e.se_op        = op;
    e.se_paddr     = cpu_to_le64(paddr);
    e.se_count     = cpu_to_le64(count);
    e.se_refcount  = cpu_to_le32(refcount);
    e.se_gen       = cpu_to_le64(gen);
    return e;
}

/* ── roundtrip: append → commit → reopen → walk ───────────────────── */

struct walk_collect {
    struct stm_space_entry entries[256];
    int n;
};

static int walk_collect_cb(const struct stm_space_entry *e, void *ctx)
{
    struct walk_collect *c = ctx;
    if (c->n < 256) c->entries[c->n++] = *e;
    return 0;
}

STM_TEST(test_space_log_roundtrip)
{
    struct stm_block_dev dev;
    open_dev(&dev);
    struct bump b;
    bump_init(&b);

    struct stm_space_log *log;
    STM_ASSERT_EQ(stm_space_log_open(&dev, 0, bump_alloc, &b, &log), 0);

    struct stm_space_entry e1 = mkentry(STM_SPACE_ALLOC, 100, 4, 1, 7);
    struct stm_space_entry e2 = mkentry(STM_SPACE_REF,   100, 0, 0, 7);
    struct stm_space_entry e3 = mkentry(STM_SPACE_FREE,  100, 0, 0, 7);
    STM_ASSERT_EQ(stm_space_log_append(log, &e1), 0);
    STM_ASSERT_EQ(stm_space_log_append(log, &e2), 0);
    STM_ASSERT_EQ(stm_space_log_append(log, &e3), 0);

    STM_ASSERT_EQ(stm_space_log_pending(log), 3u);

    uint64_t head = 0;
    STM_ASSERT_EQ(stm_space_log_commit(log, 7, &head), 0);
    STM_ASSERT(head != 0);
    STM_ASSERT_EQ(stm_space_log_pending(log), 0u);

    stm_space_log_close(log);

    /* Reopen from head — walk should yield the same three entries. */
    STM_ASSERT_EQ(stm_space_log_open(&dev, head, bump_alloc, &b, &log), 0);
    struct walk_collect wc = {0};
    STM_ASSERT_EQ(stm_space_log_walk(log, walk_collect_cb, &wc), 0);
    STM_ASSERT_EQ(wc.n, 3);
    STM_ASSERT_EQ(wc.entries[0].se_op, STM_SPACE_ALLOC);
    STM_ASSERT_EQ(wc.entries[1].se_op, STM_SPACE_REF);
    STM_ASSERT_EQ(wc.entries[2].se_op, STM_SPACE_FREE);
    STM_ASSERT_EQ(le64_to_cpu(wc.entries[0].se_paddr), 100u);
    STM_ASSERT_EQ(le64_to_cpu(wc.entries[0].se_count), 4u);

    stm_space_log_close(log);
    stm_block_close(&dev);
    cleanup();
}

/* ── chunk overflow: append > MAX_ENTRIES → multiple chunks ──────── */

struct count_ctx {
    uint32_t seen;
    int      monotonic;
};

static int count_cb(const struct stm_space_entry *e, void *ctx)
{
    struct count_ctx *c = ctx;
    if ((uint64_t)c->seen != le64_to_cpu(e->se_paddr)) c->monotonic = 0;
    c->seen++;
    return 0;
}

STM_TEST(test_space_log_chunk_overflow)
{
    struct stm_block_dev dev;
    open_dev(&dev);
    struct bump b;
    bump_init(&b);

    struct stm_space_log *log;
    STM_ASSERT_EQ(stm_space_log_open(&dev, 0, bump_alloc, &b, &log), 0);

    /* Append three chunks' worth of entries. */
    const uint32_t total = STM_SPACE_LOG_MAX_ENTRIES * 3 - 5;
    for (uint32_t i = 0; i < total; i++) {
        struct stm_space_entry e = mkentry(STM_SPACE_ALLOC, i, 1, 1, 42);
        STM_ASSERT_EQ(stm_space_log_append(log, &e), 0);
    }

    uint64_t head = 0;
    STM_ASSERT_EQ(stm_space_log_commit(log, 42, &head), 0);

    stm_space_log_close(log);

    /* Reopen + walk yields `total` entries, paddrs increasing 0..total-1. */
    STM_ASSERT_EQ(stm_space_log_open(&dev, head, bump_alloc, &b, &log), 0);
    struct count_ctx c = { .seen = 0, .monotonic = 1 };
    STM_ASSERT_EQ(stm_space_log_walk(log, count_cb, &c), 0);
    STM_ASSERT_EQ(c.seen, total);
    STM_ASSERT(c.monotonic);

    stm_space_log_close(log);
    stm_block_close(&dev);
    cleanup();
}

/* ── fold into empty tree: ALLOC + REF + FREE produce correct state ── */

STM_TEST(test_space_log_fold_basic)
{
    struct stm_block_dev dev;
    open_dev(&dev);
    struct bump b;
    bump_init(&b);

    struct stm_space_log *log;
    struct stm_space     *tree;
    STM_ASSERT_EQ(stm_space_log_open(&dev, 0, bump_alloc, &b, &log), 0);
    STM_ASSERT_EQ(stm_space_open(&dev, stm_bptr_null(), 0, &tree), 0);

    struct stm_space_entry ops[] = {
        mkentry(STM_SPACE_ALLOC, 100, 4, 1, 1),   /* paddr 100, count 4, rc 1 */
        mkentry(STM_SPACE_ALLOC, 200, 8, 1, 1),   /* paddr 200, count 8, rc 1 */
        mkentry(STM_SPACE_REF,   200, 0, 0, 1),   /* rc 200 → 2 */
        mkentry(STM_SPACE_FREE,  100, 0, 0, 1),   /* rc 100 → 0 → delete */
        mkentry(STM_SPACE_ALLOC, 300, 2, 1, 1),
    };
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++)
        STM_ASSERT_EQ(stm_space_log_append(log, &ops[i]), 0);

    STM_ASSERT_EQ(stm_space_log_fold_into(log, tree, 1), 0);

    /* Final tree state: 100 gone, 200 refcount=2 count=8, 300 refcount=1 count=2. */
    uint64_t count = 0; uint32_t rc = 0;
    STM_ASSERT_EQ(stm_space_lookup(tree, 100, &count, &rc), -ENOENT);
    STM_ASSERT_EQ(stm_space_lookup(tree, 200, &count, &rc), 0);
    STM_ASSERT_EQ(count, 8u);
    STM_ASSERT_EQ(rc, 2u);
    STM_ASSERT_EQ(stm_space_lookup(tree, 300, &count, &rc), 0);
    STM_ASSERT_EQ(count, 2u);
    STM_ASSERT_EQ(rc, 1u);

    stm_space_close(tree);
    stm_space_log_close(log);
    stm_block_close(&dev);
    cleanup();
}

/* ── truncate: commits, then truncates, sees empty log + freed chunks ─ */

STM_TEST(test_space_log_truncate)
{
    struct stm_block_dev dev;
    open_dev(&dev);
    struct bump b;
    bump_init(&b);

    struct stm_space_log *log;
    STM_ASSERT_EQ(stm_space_log_open(&dev, 0, bump_alloc, &b, &log), 0);

    /* Enough to force 2 chunks. */
    for (uint32_t i = 0; i < STM_SPACE_LOG_MAX_ENTRIES + 3; i++) {
        struct stm_space_entry e = mkentry(STM_SPACE_ALLOC, i, 1, 1, 5);
        STM_ASSERT_EQ(stm_space_log_append(log, &e), 0);
    }
    uint64_t head;
    STM_ASSERT_EQ(stm_space_log_commit(log, 5, &head), 0);

    stm_space_log_truncate(log, bump_free, &b);
    STM_ASSERT_EQ(stm_space_log_pending(log), 0u);

    /* Two chunks were allocated for the log; both should be freed. */
    STM_ASSERT_EQ(b.nfreed, 2);

    /* After truncate, a fresh commit yields 0 head (no entries). */
    uint64_t head2 = 0xdeadbeef;
    STM_ASSERT_EQ(stm_space_log_commit(log, 6, &head2), 0);
    STM_ASSERT_EQ(head2, 0u);

    stm_space_log_close(log);
    stm_block_close(&dev);
    cleanup();
}

/* ── reopen + append + recommit appends to existing chain ─────────── */

STM_TEST(test_space_log_reopen_append)
{
    struct stm_block_dev dev;
    open_dev(&dev);
    struct bump b;
    bump_init(&b);

    struct stm_space_log *log;
    STM_ASSERT_EQ(stm_space_log_open(&dev, 0, bump_alloc, &b, &log), 0);

    struct stm_space_entry e = mkentry(STM_SPACE_ALLOC, 111, 3, 1, 2);
    STM_ASSERT_EQ(stm_space_log_append(log, &e), 0);
    uint64_t head1 = 0;
    STM_ASSERT_EQ(stm_space_log_commit(log, 2, &head1), 0);

    stm_space_log_close(log);

    /* Reopen from head1, append another entry, commit again. Head should
     * advance (new chunk written); chain from new head walks 2 entries. */
    STM_ASSERT_EQ(stm_space_log_open(&dev, head1, bump_alloc, &b, &log), 0);
    STM_ASSERT_EQ(stm_space_log_pending(log), 0u);

    struct stm_space_entry e2 = mkentry(STM_SPACE_REF, 111, 0, 0, 3);
    STM_ASSERT_EQ(stm_space_log_append(log, &e2), 0);
    uint64_t head2 = 0;
    STM_ASSERT_EQ(stm_space_log_commit(log, 3, &head2), 0);
    STM_ASSERT(head2 != head1);

    stm_space_log_close(log);

    STM_ASSERT_EQ(stm_space_log_open(&dev, head2, bump_alloc, &b, &log), 0);
    struct walk_collect wc = {0};
    STM_ASSERT_EQ(stm_space_log_walk(log, walk_collect_cb, &wc), 0);
    STM_ASSERT_EQ(wc.n, 2);
    STM_ASSERT_EQ(wc.entries[0].se_op, STM_SPACE_ALLOC);
    STM_ASSERT_EQ(wc.entries[1].se_op, STM_SPACE_REF);

    stm_space_log_close(log);
    stm_block_close(&dev);
    cleanup();
}

int main(void)
{
    STM_SUITE("space_log");
    STM_RUN(test_space_log_roundtrip);
    STM_RUN(test_space_log_chunk_overflow);
    STM_RUN(test_space_log_fold_basic);
    STM_RUN(test_space_log_truncate);
    STM_RUN(test_space_log_reopen_append);
    printf("all passed\n");
    return 0;
}
