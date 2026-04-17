#include "test_main.h"
#include "stratum/fs.h"
#include "stratum/snap.h"

#include <unistd.h>
#include <errno.h>

static const char *img = "/tmp/stratum_test_snap.img";
static void cleanup(void) { unlink(img); }

/* ── create + list ──────────────────────────────────────────────────── */

struct snap_entry { uint64_t id; char name[64]; uint64_t gen; };
struct snap_list  { struct snap_entry e[16]; int count; };

static int collect_snap(uint64_t id, const char *name, uint64_t gen, void *ctx)
{
    struct snap_list *sl = ctx;
    if (sl->count < 16) {
        sl->e[sl->count].id = id;
        strncpy(sl->e[sl->count].name, name, 63);
        sl->e[sl->count].gen = gen;
        sl->count++;
    }
    return 0;
}

STM_TEST(test_snap_create_list)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    /* write some data first */
    uint64_t ino;
    stm_fs_create_file(fs, STM_ROOT_INO, "hello.txt", 0644, &ino);
    stm_fs_write(fs, ino, 0, "v1", 2);

    uint64_t snap_id1, snap_id2;
    int rc = stm_snap_create(fs, "backup-1", &snap_id1);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT(snap_id1 > 0);

    rc = stm_snap_create(fs, "backup-2", &snap_id2);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT(snap_id2 > snap_id1);

    /* list */
    struct snap_list sl;
    memset(&sl, 0, sizeof(sl));
    rc = stm_snap_list(fs, collect_snap, &sl);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(sl.count, 2);

    stm_fs_close(fs);
    cleanup();
}

/* ── name collision ─────────────────────────────────────────────────── */

STM_TEST(test_snap_name_collision)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    uint64_t id;
    int rc = stm_snap_create(fs, "dup", &id);
    STM_ASSERT_EQ(rc, 0);

    rc = stm_snap_create(fs, "dup", &id);
    STM_ASSERT_EQ(rc, -EEXIST);

    stm_fs_close(fs);
    cleanup();
}

/* ── read isolation: snapshot sees old data ──────────────────────────── */

STM_TEST(test_snap_read_isolation)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    uint64_t ino;
    stm_fs_create_file(fs, STM_ROOT_INO, "data.txt", 0644, &ino);
    stm_fs_write(fs, ino, 0, "old-value", 9);

    /* snapshot captures "old-value" */
    uint64_t snap_id;
    stm_snap_create(fs, "snap-v1", &snap_id);

    /* overwrite with new data */
    stm_fs_write(fs, ino, 0, "new-value", 9);
    stm_fs_sync(fs);

    /* verify current tree has new data */
    {
        char buf[32] = {0};
        uint32_t nr;
        stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nr);
        STM_ASSERT_EQ(nr, 9u);
        STM_ASSERT_MEM_EQ(buf, "new-value", 9);
    }

    /* read from the snapshot's tree — should see old data */
    {
        struct snap_list sl;
        memset(&sl, 0, sizeof(sl));
        stm_snap_list(fs, collect_snap, &sl);
        STM_ASSERT_EQ(sl.count, 1);
    }

    /* rollback to snapshot, then read */
    int rc = stm_snap_rollback(fs, snap_id);
    STM_ASSERT_EQ(rc, 0);

    {
        char buf[32] = {0};
        uint32_t nr;
        rc = stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nr);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(nr, 9u);
        STM_ASSERT_MEM_EQ(buf, "old-value", 9);
    }

    stm_fs_close(fs);
    cleanup();
}

/* ── persist across close/reopen ────────────────────────────────────── */

STM_TEST(test_snap_persist)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);

    /* create a snapshot */
    {
        struct stm_fs *fs;
        stm_fs_open(img, NULL, &fs);

        uint64_t ino;
        stm_fs_create_file(fs, STM_ROOT_INO, "f.txt", 0644, &ino);
        stm_fs_write(fs, ino, 0, "data", 4);

        uint64_t id;
        stm_snap_create(fs, "persist-snap", &id);
        stm_fs_sync(fs);
        stm_fs_close(fs);
    }

    /* reopen and verify snapshot survives */
    {
        struct stm_fs *fs;
        int rc = stm_fs_open(img, NULL, &fs);
        STM_ASSERT_EQ(rc, 0);

        struct snap_list sl;
        memset(&sl, 0, sizeof(sl));
        rc = stm_snap_list(fs, collect_snap, &sl);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(sl.count, 1);
        STM_ASSERT(strcmp(sl.e[0].name, "persist-snap") == 0);

        stm_fs_close(fs);
    }

    cleanup();
}

/* ── regression: first snap must not stomp on main tree ────────────── */
/*
 * Repro for the bug where ensure_snap_tree didn't wire the refcount
 * allocator, so the snap tree's first bump-allocation landed on a
 * block that the main tree already held. The corruption manifests
 * as a checksum/AEAD-tag mismatch on the main tree root after close
 * and reopen.
 */
STM_TEST(test_snap_create_doesnt_corrupt_main_tree)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);

    /* Round 1: write enough data to push main-tree allocations past
     * the mount-time bump cursor, then sync and close so the on-disk
     * ss_alloc_next is committed. */
    {
        struct stm_fs *fs;
        STM_ASSERT_EQ(stm_fs_open(img, NULL, &fs), 0);
        uint64_t ino;
        stm_fs_create_file(fs, STM_ROOT_INO, "seed.bin", 0644, &ino);
        char buf[200 * 1024];
        memset(buf, 'A', sizeof(buf));
        stm_fs_write(fs, ino, 0, buf, sizeof(buf));
        stm_fs_sync(fs);
        stm_fs_close(fs);
    }

    /* Round 2: reopen, create the first snapshot. Before the fix, this
     * path allocated snap-tree nodes via bump allocator from the stale
     * cursor — right on top of main-tree blocks. */
    uint64_t sid = 0;
    {
        struct stm_fs *fs;
        STM_ASSERT_EQ(stm_fs_open(img, NULL, &fs), 0);
        STM_ASSERT_EQ(stm_snap_create(fs, "S", &sid), 0);

        /* Write more data after the snap to exercise the main tree. */
        uint64_t ino;
        stm_fs_create_file(fs, STM_ROOT_INO, "post.bin", 0644, &ino);
        char buf[200 * 1024];
        memset(buf, 'B', sizeof(buf));
        stm_fs_write(fs, ino, 0, buf, sizeof(buf));
        stm_fs_sync(fs);
        stm_fs_close(fs);
    }

    /* Round 3: reopen. If the snap tree trampled main-tree blocks in
     * round 2, reopening fails immediately or the main-tree walk
     * returns -EIO. */
    {
        struct stm_fs *fs;
        STM_ASSERT_EQ(stm_fs_open(img, NULL, &fs), 0);

        /* Verify we can still read seed.bin. */
        uint64_t ino;
        STM_ASSERT_EQ(stm_fs_lookup(fs, STM_ROOT_INO, "seed.bin", &ino), 0);
        char buf[256];
        uint32_t nread = 0;
        STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread), 0);
        STM_ASSERT_EQ(nread, sizeof(buf));
        for (size_t i = 0; i < sizeof(buf); i++) STM_ASSERT_EQ(buf[i], 'A');

        /* And post.bin. */
        STM_ASSERT_EQ(stm_fs_lookup(fs, STM_ROOT_INO, "post.bin", &ino), 0);
        STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread), 0);
        STM_ASSERT_EQ(nread, sizeof(buf));
        for (size_t i = 0; i < sizeof(buf); i++) STM_ASSERT_EQ(buf[i], 'B');

        stm_fs_close(fs);
    }

    cleanup();
}

/* ── regression: rollback must not overwrite other snapshots ───────── */
/*
 * Bug: stm_snap_rollback's allocator rebuild only marked the main tree
 * and snap_tree's own metadata blocks — not the blocks reachable from
 * each individual saved snapshot. After rollback, any snapshot that
 * wasn't the rollback target had its private blocks marked free, so
 * subsequent writes silently overwrote them. Reading the untouched
 * snapshot afterward returned -EIO (csum / AEAD fail) or garbage.
 *
 * This test:
 *   - creates snapshot A capturing "v1"
 *   - writes "v2" (private blocks for A remain, pointed to by A's root)
 *   - creates snapshot B capturing "v2"
 *   - writes "v3" (private blocks for B remain)
 *   - rolls back to A (main tree is now "v1")
 *   - writes "v4" a few times to churn through the allocator
 *   - snapshot B must still be readable. Before the fix, B's private
 *     blocks had been reallocated and overwritten.
 */
STM_TEST(test_rollback_preserves_other_snapshots)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    /* Build the history. */
    uint64_t ino;
    stm_fs_create_file(fs, STM_ROOT_INO, "f.bin", 0644, &ino);

    char payload[200 * 1024];
    memset(payload, '1', sizeof(payload));
    stm_fs_write(fs, ino, 0, payload, sizeof(payload));

    uint64_t sid_a = 0;
    STM_ASSERT_EQ(stm_snap_create(fs, "A", &sid_a), 0);

    memset(payload, '2', sizeof(payload));
    stm_fs_write(fs, ino, 0, payload, sizeof(payload));

    uint64_t sid_b = 0;
    STM_ASSERT_EQ(stm_snap_create(fs, "B", &sid_b), 0);

    memset(payload, '3', sizeof(payload));
    stm_fs_write(fs, ino, 0, payload, sizeof(payload));
    stm_fs_sync(fs);

    /* Rollback to A. */
    STM_ASSERT_EQ(stm_snap_rollback(fs, sid_a), 0);

    /* Churn the allocator: if B's blocks are wrongly free, these writes
     * land right on top of them. */
    for (int i = 0; i < 8; i++) {
        memset(payload, '4' + (i & 3), sizeof(payload));
        stm_fs_write(fs, ino, 0, payload, sizeof(payload));
    }
    stm_fs_sync(fs);
    stm_fs_close(fs);

    /* Reopen, rollback to B, verify B's contents. */
    stm_fs_open(img, NULL, &fs);
    STM_ASSERT_EQ(stm_snap_rollback(fs, sid_b), 0);

    STM_ASSERT_EQ(stm_fs_lookup(fs, STM_ROOT_INO, "f.bin", &ino), 0);
    char buf[256];
    uint32_t nread = 0;
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_EQ(nread, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++) STM_ASSERT_EQ(buf[i], '2');

    stm_fs_close(fs);
    cleanup();
}

int main(void)
{
    STM_SUITE("snap");
    STM_RUN(test_snap_create_list);
    STM_RUN(test_snap_name_collision);
    STM_RUN(test_snap_read_isolation);
    STM_RUN(test_snap_persist);
    STM_RUN(test_snap_create_doesnt_corrupt_main_tree);
    STM_RUN(test_rollback_preserves_other_snapshots);
    printf("all passed\n");
    return 0;
}
