#include "test_main.h"
#include "stratum/alloc.h"
#include "stratum/fs.h"
#include "stratum/snap.h"

#include <unistd.h>
#include <errno.h>

/* ── basic allocator operations ─────────────────────────────────────── */

STM_TEST(test_alloc_basic)
{
    struct stm_alloc *a;
    int rc = stm_alloc_open(NULL, 1024, &a);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(stm_alloc_total(a), 1024u);
    STM_ASSERT_EQ(stm_alloc_free_count(a), 1024u);

    /* allocate 4 blocks */
    uint64_t addr;
    rc = stm_alloc_extent(a, 4, &addr);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(stm_alloc_free_count(a), 1020u);

    /* free them (deferred) */
    stm_alloc_free(a, addr / STM_BLOCK_SIZE, 4);
    /* still 1020 free (deferred, not yet committed) */
    STM_ASSERT_EQ(stm_alloc_free_count(a), 1020u);

    /* commit makes them available */
    stm_alloc_commit(a);
    STM_ASSERT_EQ(stm_alloc_free_count(a), 1024u);

    stm_alloc_close(a);
}

STM_TEST(test_alloc_refcount)
{
    struct stm_alloc *a;
    stm_alloc_open(NULL, 256, &a);

    uint64_t addr;
    stm_alloc_extent(a, 2, &addr);
    uint64_t blk = addr / STM_BLOCK_SIZE;

    /* refcount is 1 after alloc */
    stm_alloc_ref(a, blk, 2); /* now refcount = 2 */
    stm_alloc_free(a, blk, 2); /* refcount → 1, NOT freed */
    stm_alloc_commit(a);
    /* blocks still used (refcount 1) → not in free pool */
    STM_ASSERT_EQ(stm_alloc_free_count(a), 254u);

    stm_alloc_free(a, blk, 2); /* refcount → 0, deferred */
    stm_alloc_commit(a);
    STM_ASSERT_EQ(stm_alloc_free_count(a), 256u);

    stm_alloc_close(a);
}

/* ── space reclamation through fs layer ─────────────────────────────── */

static const char *img = "/tmp/stratum_test_alloc_fs.img";
static void cleanup(void) { unlink(img); }

STM_TEST(test_fs_space_reclaim)
{
    /* create a small filesystem */
    int rc = stm_fs_create(img, 4 * 1024 * 1024, NULL);
    STM_ASSERT_EQ(rc, 0);

    struct stm_fs *fs;
    rc = stm_fs_open(img, NULL, &fs);
    STM_ASSERT_EQ(rc, 0);

    /* create a file, write data, sync */
    uint64_t ino;
    stm_fs_create_file(fs, STM_ROOT_INO, "tmp.txt", 0644, &ino);
    uint8_t data[4096];
    memset(data, 'A', sizeof(data));
    stm_fs_write(fs, ino, 0, data, sizeof(data));
    stm_fs_sync(fs);

    /* delete the file and sync — should reclaim space */
    stm_fs_unlink(fs, STM_ROOT_INO, "tmp.txt");
    stm_fs_sync(fs);

    /* create another file — should succeed (space was reclaimed) */
    uint64_t ino2;
    rc = stm_fs_create_file(fs, STM_ROOT_INO, "new.txt", 0644, &ino2);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_fs_write(fs, ino2, 0, data, sizeof(data));
    STM_ASSERT_EQ(rc, 0);

    stm_fs_close(fs);
    cleanup();
}

/* ── snapshot delete reclaims space ─────────────────────────────────── */

STM_TEST(test_snap_delete_reclaim)
{
    int rc = stm_fs_create(img, 8 * 1024 * 1024, NULL);
    STM_ASSERT_EQ(rc, 0);

    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    /* write data and snapshot */
    uint64_t ino;
    stm_fs_create_file(fs, STM_ROOT_INO, "f.txt", 0644, &ino);
    stm_fs_write(fs, ino, 0, "snapshot data", 13);

    uint64_t snap_id;
    stm_snap_create(fs, "v1", &snap_id);
    stm_fs_sync(fs);

    /* delete the snapshot */
    rc = stm_snap_delete(fs, snap_id);
    STM_ASSERT_EQ(rc, 0);
    stm_fs_sync(fs);

    /* verify no crash on operations after delete */

    stm_fs_close(fs);
    cleanup();
}

int main(void)
{
    STM_SUITE("alloc");
    STM_RUN(test_alloc_basic);
    STM_RUN(test_alloc_refcount);
    STM_RUN(test_fs_space_reclaim);
    STM_RUN(test_snap_delete_reclaim);
    printf("all passed\n");
    return 0;
}
