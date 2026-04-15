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

int main(void)
{
    STM_SUITE("snap");
    STM_RUN(test_snap_create_list);
    STM_RUN(test_snap_name_collision);
    STM_RUN(test_snap_read_isolation);
    STM_RUN(test_snap_persist);
    printf("all passed\n");
    return 0;
}
