#include "test_main.h"
#include "stratum/fs.h"

#include <unistd.h>
#include <errno.h>

static const char *img = "/tmp/stratum_test_fs.img";
static void cleanup(void) { unlink(img); }

/* ── format + open + stat root ──────────────────────────────────────── */

STM_TEST(test_fs_create_open)
{
    int rc = stm_fs_create(img, 64 * 1024 * 1024, NULL);
    STM_ASSERT_EQ(rc, 0);

    struct stm_fs *fs;
    rc = stm_fs_open(img, NULL, &fs);
    STM_ASSERT_EQ(rc, 0);

    struct stm_inode root;
    rc = stm_fs_stat(fs, STM_ROOT_INO, &root);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(le64_to_cpu(root.si_ino), (uint64_t)STM_ROOT_INO);
    STM_ASSERT((le32_to_cpu(root.si_mode) & STM_S_IFMT) == (uint32_t)STM_S_IFDIR);

    stm_fs_close(fs);
    cleanup();
}

/* ── mkdir + readdir ────────────────────────────────────────────────── */

struct dir_entry {
    char name[256];
    uint64_t ino;
    uint8_t type;
};

struct dir_list {
    struct dir_entry entries[64];
    int count;
};

static int collect_dir(const char *name, uint64_t ino, uint8_t type, void *ctx)
{
    struct dir_list *dl = ctx;
    if (dl->count < 64) {
        strncpy(dl->entries[dl->count].name, name, 255);
        dl->entries[dl->count].ino = ino;
        dl->entries[dl->count].type = type;
        dl->count++;
    }
    return 0;
}

STM_TEST(test_fs_mkdir_readdir)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    uint64_t ino_a, ino_b;
    int rc = stm_fs_mkdir(fs, STM_ROOT_INO, "alpha", 0755, &ino_a);
    STM_ASSERT_EQ(rc, 0);
    rc = stm_fs_mkdir(fs, STM_ROOT_INO, "beta", 0755, &ino_b);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT(ino_a != ino_b);

    /* readdir */
    struct dir_list dl;
    memset(&dl, 0, sizeof(dl));
    rc = stm_fs_readdir(fs, STM_ROOT_INO, collect_dir, &dl);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(dl.count, 2);

    stm_fs_close(fs);
    cleanup();
}

/* ── lookup ─────────────────────────────────────────────────────────── */

STM_TEST(test_fs_lookup)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    uint64_t ino;
    stm_fs_mkdir(fs, STM_ROOT_INO, "docs", 0755, &ino);

    uint64_t found;
    int rc = stm_fs_lookup(fs, STM_ROOT_INO, "docs", &found);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(found, ino);

    rc = stm_fs_lookup(fs, STM_ROOT_INO, "nope", &found);
    STM_ASSERT_EQ(rc, -ENOENT);

    stm_fs_close(fs);
    cleanup();
}

/* ── file write + read ──────────────────────────────────────────────── */

STM_TEST(test_fs_file_io)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    uint64_t ino;
    int rc = stm_fs_create_file(fs, STM_ROOT_INO, "hello.txt", 0644, &ino);
    STM_ASSERT_EQ(rc, 0);

    const char *data = "Hello, Stratum filesystem!";
    rc = stm_fs_write(fs, ino, 0, data, (uint32_t)strlen(data));
    STM_ASSERT_EQ(rc, 0);

    char buf[256];
    uint32_t nread = 0;
    memset(buf, 0, sizeof(buf));
    rc = stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(nread, (uint32_t)strlen(data));
    STM_ASSERT_MEM_EQ(buf, data, strlen(data));

    /* check inode size */
    struct stm_inode st;
    stm_fs_stat(fs, ino, &st);
    STM_ASSERT_EQ(le64_to_cpu(st.si_size), (uint64_t)strlen(data));

    stm_fs_close(fs);
    cleanup();
}

/* ── large file spanning multiple chunks ────────────────────────────── */

STM_TEST(test_fs_large_write)
{
    stm_fs_create(img, 128 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    uint64_t ino;
    stm_fs_create_file(fs, STM_ROOT_INO, "big.bin", 0644, &ino);

    /* write 10 KiB of patterned data (spans 3 chunks at 4K each) */
    uint32_t size = 10240;
    uint8_t *wbuf = malloc(size);
    uint32_t i;
    for (i = 0; i < size; i++) wbuf[i] = (uint8_t)(i & 0xFF);

    int rc = stm_fs_write(fs, ino, 0, wbuf, size);
    STM_ASSERT_EQ(rc, 0);

    uint8_t *rbuf = calloc(1, size);
    uint32_t nread = 0;
    rc = stm_fs_read(fs, ino, 0, rbuf, size, &nread);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(nread, size);
    STM_ASSERT_MEM_EQ(wbuf, rbuf, size);

    /* partial read from middle of file */
    uint32_t mid_read = 0;
    memset(rbuf, 0, 100);
    rc = stm_fs_read(fs, ino, 5000, rbuf, 100, &mid_read);
    STM_ASSERT_EQ(rc, 0);
    STM_ASSERT_EQ(mid_read, 100u);
    STM_ASSERT_MEM_EQ(rbuf, wbuf + 5000, 100);

    free(wbuf);
    free(rbuf);
    stm_fs_close(fs);
    cleanup();
}

/* ── unlink ─────────────────────────────────────────────────────────── */

STM_TEST(test_fs_unlink)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);
    struct stm_fs *fs;
    stm_fs_open(img, NULL, &fs);

    uint64_t ino;
    stm_fs_create_file(fs, STM_ROOT_INO, "tmp.txt", 0644, &ino);

    int rc = stm_fs_unlink(fs, STM_ROOT_INO, "tmp.txt");
    STM_ASSERT_EQ(rc, 0);

    uint64_t found;
    rc = stm_fs_lookup(fs, STM_ROOT_INO, "tmp.txt", &found);
    STM_ASSERT_EQ(rc, -ENOENT);

    stm_fs_close(fs);
    cleanup();
}

/* ── sync + reopen persistence ──────────────────────────────────────── */

STM_TEST(test_fs_persist)
{
    stm_fs_create(img, 64 * 1024 * 1024, NULL);

    {
        struct stm_fs *fs;
        stm_fs_open(img, NULL, &fs);

        uint64_t ino;
        stm_fs_mkdir(fs, STM_ROOT_INO, "persist", 0755, &ino);
        stm_fs_create_file(fs, STM_ROOT_INO, "data.txt", 0644, &ino);
        stm_fs_write(fs, ino, 0, "saved", 5);

        int rc = stm_fs_sync(fs);
        STM_ASSERT_EQ(rc, 0);
        stm_fs_close(fs);
    }

    /* reopen and verify */
    {
        struct stm_fs *fs;
        int rc = stm_fs_open(img, NULL, &fs);
        STM_ASSERT_EQ(rc, 0);

        uint64_t dir_ino;
        rc = stm_fs_lookup(fs, STM_ROOT_INO, "persist", &dir_ino);
        STM_ASSERT_EQ(rc, 0);

        uint64_t file_ino;
        rc = stm_fs_lookup(fs, STM_ROOT_INO, "data.txt", &file_ino);
        STM_ASSERT_EQ(rc, 0);

        char buf[32] = {0};
        uint32_t nread = 0;
        rc = stm_fs_read(fs, file_ino, 0, buf, sizeof(buf), &nread);
        STM_ASSERT_EQ(rc, 0);
        STM_ASSERT_EQ(nread, 5u);
        STM_ASSERT_MEM_EQ(buf, "saved", 5);

        stm_fs_close(fs);
    }
    cleanup();
}

/* ── stress: copy-delete cycles ─────────────────────────────────── */

STM_TEST(test_fs_copy_delete_cycles)
{
    const char *path = "/tmp/stratum_test_cycles.img";
    struct stm_fs *fs;
    uint8_t *buf;
    int cycle, mb, rc;

    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 32ULL*1024*1024, NULL), 0);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    buf = malloc(1048576);
    STM_ASSERT(buf);
    memset(buf, 'Z', 1048576);

    for (cycle = 0; cycle < 10; cycle++) {
        uint64_t ino;
        STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "stress.bin", 0644, &ino), 0);
        for (mb = 0; mb < 100; mb++) {
            rc = stm_fs_write(fs, ino, (uint64_t)mb * 1048576, buf, 1048576);
            STM_ASSERT_EQ(rc, 0);
        }
        STM_ASSERT_EQ(stm_fs_sync(fs), 0);

        { /* verify read-back */
            uint8_t *rbuf = malloc(1048576);
            uint32_t nread;
            STM_ASSERT(rbuf);
            STM_ASSERT_EQ(stm_fs_read(fs, ino, 50*1048576, rbuf, 1048576, &nread), 0);
            STM_ASSERT_EQ(nread, (uint32_t)1048576);
            STM_ASSERT(rbuf[0] == 'Z' && rbuf[1048575] == 'Z');
            free(rbuf);
        }

        STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "stress.bin"), 0);
        STM_ASSERT_EQ(stm_fs_sync(fs), 0);
    }
    stm_fs_close(fs);

    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);
    stm_fs_close(fs);
    free(buf);
    unlink(path);
}

STM_TEST(test_fs_copy_delete_cycles_encrypted)
{
    const char *path = "/tmp/stratum_test_cycles_enc.img";
    const char *pass = "testpass";
    struct stm_fs *fs;
    uint8_t *buf;
    int cycle, mb, rc;

    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 32ULL*1024*1024, pass), 0);
    STM_ASSERT_EQ(stm_fs_open(path, pass, &fs), 0);

    buf = malloc(1048576);
    STM_ASSERT(buf);
    memset(buf, 'E', 1048576);

    for (cycle = 0; cycle < 10; cycle++) {
        uint64_t ino;
        STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "enc.bin", 0644, &ino), 0);
        for (mb = 0; mb < 100; mb++) {
            rc = stm_fs_write(fs, ino, (uint64_t)mb * 1048576, buf, 1048576);
            STM_ASSERT_EQ(rc, 0);
        }
        STM_ASSERT_EQ(stm_fs_sync(fs), 0);

        { /* verify */
            uint8_t *rbuf = malloc(1048576);
            uint32_t nread;
            STM_ASSERT(rbuf);
            STM_ASSERT_EQ(stm_fs_read(fs, ino, 50*1048576, rbuf, 1048576, &nread), 0);
            STM_ASSERT(rbuf[0] == 'E' && rbuf[1048575] == 'E');
            free(rbuf);
        }

        STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "enc.bin"), 0);
        STM_ASSERT_EQ(stm_fs_sync(fs), 0);
    }
    stm_fs_close(fs);

    STM_ASSERT_EQ(stm_fs_open(path, pass, &fs), 0);
    stm_fs_close(fs);
    free(buf);
    unlink(path);
}

/* Force an FNV1a dirent-hash collision: construct two names that hash to
 * slots such that deleting one used to break lookup of the other. Since
 * FNV1a collisions are hard to hand-craft, we go the pragmatic route:
 * create many names, unlink one in the middle, and verify all survivors
 * remain reachable. This exercises the tombstone probe-chain continuation
 * on whatever collisions happen to exist.
 *
 * Pre-tombstone behavior: the btree_delete cleared the slot, and any
 * names that had probed past it became unreachable. After tombstones,
 * the probe chain stays intact.
 */
STM_TEST(test_fs_unlink_preserves_probe_chain)
{
    const char *path = "/tmp/stratum_test_tombstones.img";
    struct stm_fs *fs;
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 16ULL*1024*1024, NULL), 0);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    /* Make a moderate directory; even without engineered collisions, with
     * enough entries the FNV1a hash space has some pair-collisions. */
    char nm[16];
    const int N = 100;
    for (int i = 0; i < N; i++) {
        snprintf(nm, sizeof(nm), "f%04d", i);
        uint64_t ino;
        STM_ASSERT_EQ(stm_fs_create_file(fs, 1, nm, 0644, &ino), 0);
    }

    /* Unlink every other file. */
    for (int i = 0; i < N; i += 2) {
        snprintf(nm, sizeof(nm), "f%04d", i);
        STM_ASSERT_EQ(stm_fs_unlink(fs, 1, nm), 0);
    }

    /* Every remaining file must still be reachable by name. */
    for (int i = 1; i < N; i += 2) {
        snprintf(nm, sizeof(nm), "f%04d", i);
        uint64_t dummy;
        int rc = stm_fs_lookup(fs, 1, nm, &dummy);
        STM_ASSERT_EQ(rc, 0);
    }

    /* And every unlinked file is gone. */
    for (int i = 0; i < N; i += 2) {
        snprintf(nm, sizeof(nm), "f%04d", i);
        uint64_t dummy;
        STM_ASSERT_EQ(stm_fs_lookup(fs, 1, nm, &dummy), -ENOENT);
    }

    /* Reuse a slot: create a new file with a name that hashes to a
     * tombstoned slot. Can't easily force the exact slot, so just
     * create + lookup + confirm it works. */
    uint64_t nino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "newfile", 0644, &nino), 0);
    uint64_t check;
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "newfile", &check), 0);
    STM_ASSERT_EQ(check, nino);

    stm_fs_close(fs);
    unlink(path);
}

/* stm_fs_unlink on a directory must refuse if the directory isn't empty.
 * Before the fix, the parent dirent was removed and the child's contents
 * (dirents + inodes + data) were silently orphaned. */
STM_TEST(test_fs_rmdir_refuses_nonempty)
{
    const char *path = "/tmp/stratum_test_rmdir.img";
    struct stm_fs *fs;
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 8ULL*1024*1024, NULL), 0);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t dino, fino;
    STM_ASSERT_EQ(stm_fs_mkdir(fs, 1, "d", 0755, &dino), 0);
    STM_ASSERT_EQ(stm_fs_create_file(fs, dino, "x.txt", 0644, &fino), 0);
    STM_ASSERT_EQ(stm_fs_write(fs, fino, 0, "hi", 2), 0);

    /* Non-empty → ENOTEMPTY */
    STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "d"), -ENOTEMPTY);

    /* Remove the child, then rmdir succeeds */
    STM_ASSERT_EQ(stm_fs_unlink(fs, dino, "x.txt"), 0);
    STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "d"), 0);

    /* "d" is gone */
    uint64_t dummy;
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "d", &dummy), -ENOENT);

    stm_fs_close(fs);
    unlink(path);
}

/* stm_fs_write must reject offset + len that would overflow uint64 */
STM_TEST(test_fs_write_overflow_guard)
{
    const char *path = "/tmp/stratum_test_ovf.img";
    struct stm_fs *fs;
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 8ULL*1024*1024, NULL), 0);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "f.bin", 0644, &ino), 0);

    char data[16] = "0123456789abcdef";
    /* offset + len wraps → must reject */
    int rc = stm_fs_write(fs, ino, UINT64_MAX - 4, data, 16);
    STM_ASSERT_EQ(rc, -EFBIG);

    /* exact fit (offset + len == UINT64_MAX) is allowed; the subsequent
     * extent allocations will fail at the allocator but the overflow
     * check itself must not trip. Stop after checking the reject path. */

    stm_fs_close(fs);
    unlink(path);
}

int main(void)
{
    STM_SUITE("fs");
    STM_RUN(test_fs_create_open);
    STM_RUN(test_fs_mkdir_readdir);
    STM_RUN(test_fs_lookup);
    STM_RUN(test_fs_file_io);
    STM_RUN(test_fs_large_write);
    STM_RUN(test_fs_unlink);
    STM_RUN(test_fs_persist);
    STM_RUN(test_fs_copy_delete_cycles);
    STM_RUN(test_fs_copy_delete_cycles_encrypted);
    STM_RUN(test_fs_write_overflow_guard);
    STM_RUN(test_fs_rmdir_refuses_nonempty);
    STM_RUN(test_fs_unlink_preserves_probe_chain);
    printf("all passed\n");
    return 0;
}
