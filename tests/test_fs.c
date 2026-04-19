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

/* Regression for R6-1: the partial-extent `had_old` path in stm_fs_write
 * used to leave ebuf[old_dlen .. inner] uninitialized, reading back residue
 * from any previous extent operation on any file. On encrypted volumes that
 * is cross-file plaintext leakage; on unencrypted it violates sparse-hole
 * semantics. Setup:
 *   1. Write file A, 128 KiB of 'A' pattern → ebuf primed with 'A'.
 *   2. Write file B with a short value (creates the extent), then a second
 *      write past the short tail but within the same 128 KiB extent
 *      boundary — exercises the `had_old` branch with inner > old_dlen.
 *   3. Read the gap. Must be zeros, not 'A'. */
STM_TEST(test_fs_write_gap_is_zeroed)
{
    const char *path = "/tmp/stratum_test_gap_zero.img";
    struct stm_fs *fs;
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 64ULL*1024*1024, NULL), 0);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t ino_a, ino_b;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "a.bin", 0644, &ino_a), 0);
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "b.bin", 0644, &ino_b), 0);

    /* File B: short write at offset 0 (ENOENT branch — memsets ebuf to 0,
     * which actually clears any residue, so we have to re-prime afterward). */
    STM_ASSERT_EQ(stm_fs_write(fs, ino_b, 0, "BB", 2), 0);

    /* Re-prime the shared extent_buf with 'A' via a full 128 KiB write to
     * file A. Full-extent path does not memset — memcpy overwrites the whole
     * extent — so ebuf is left holding all 'A'. */
    uint8_t *abuf = malloc(131072);
    STM_ASSERT(abuf);
    memset(abuf, 'A', 131072);
    STM_ASSERT_EQ(stm_fs_write(fs, ino_a, 0, abuf, 131072), 0);

    /* Gap-producing write on file B: inner=50000, old_dlen=2. Without the
     * R6-1 memset, ebuf[2..50000] retains 'A' from the step above and gets
     * encrypted into file B's new extent. With the fix, that region is zero. */
    STM_ASSERT_EQ(stm_fs_write(fs, ino_b, 50000, "XX", 2), 0);

    /* Read the gap. All bytes between offset 2 and offset 50_000 must be
     * zero — a sparse hole. If residue leaked, bytes will be 'A' (0x41). */
    uint8_t *rbuf = malloc(50000);
    STM_ASSERT(rbuf);
    memset(rbuf, 0xEE, 50000);
    uint32_t nread = 0;
    STM_ASSERT_EQ(stm_fs_read(fs, ino_b, 2, rbuf, 49998, &nread), 0);
    STM_ASSERT_EQ(nread, 49998u);
    int i;
    for (i = 0; i < 49998; i++) {
        if (rbuf[i] != 0) {
            fprintf(stderr, "leak at gap offset %d: byte=0x%02x\n",
                    i, rbuf[i]);
            STM_ASSERT(0);
        }
    }

    /* Sanity: the written bytes themselves survive. */
    uint8_t tail[2];
    STM_ASSERT_EQ(stm_fs_read(fs, ino_b, 50000, tail, 2, &nread), 0);
    STM_ASSERT_EQ(nread, 2u);
    STM_ASSERT(tail[0] == 'X' && tail[1] == 'X');

    free(abuf); free(rbuf);
    stm_fs_close(fs);
    unlink(path);
}

/* Encrypted variant of the above — the real damage from R6-1 is ciphertext
 * that decrypts to another file's plaintext. */
STM_TEST(test_fs_write_gap_is_zeroed_encrypted)
{
    const char *path = "/tmp/stratum_test_gap_zero_enc.img";
    const char *pass = "gapzero";
    struct stm_fs *fs;
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 64ULL*1024*1024, pass), 0);
    STM_ASSERT_EQ(stm_fs_open(path, pass, &fs), 0);

    uint64_t ino_a, ino_b;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "a.bin", 0644, &ino_a), 0);
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "b.bin", 0644, &ino_b), 0);

    STM_ASSERT_EQ(stm_fs_write(fs, ino_b, 0, "BB", 2), 0);

    uint8_t *abuf = malloc(131072);
    STM_ASSERT(abuf);
    memset(abuf, 'A', 131072);
    STM_ASSERT_EQ(stm_fs_write(fs, ino_a, 0, abuf, 131072), 0);

    STM_ASSERT_EQ(stm_fs_write(fs, ino_b, 50000, "XX", 2), 0);
    STM_ASSERT_EQ(stm_fs_sync(fs), 0);

    uint8_t *rbuf = malloc(50000);
    STM_ASSERT(rbuf);
    memset(rbuf, 0xEE, 50000);
    uint32_t nread = 0;
    STM_ASSERT_EQ(stm_fs_read(fs, ino_b, 2, rbuf, 49998, &nread), 0);
    STM_ASSERT_EQ(nread, 49998u);
    int i;
    for (i = 0; i < 49998; i++) {
        if (rbuf[i] != 0) {
            fprintf(stderr, "enc leak at gap offset %d: byte=0x%02x\n",
                    i, rbuf[i]);
            STM_ASSERT(0);
        }
    }

    free(abuf); free(rbuf);
    stm_fs_close(fs);
    unlink(path);
}

/* Regression for R7-1 (P0): verify the two-phase sync leaves both SB slots
 * at ss_gen >= gen used for the most recent writes, so that a crash mid-sync
 * (or a torn final-SB write) cannot leave the next mount reading a gen value
 * that aliases orphan ciphertexts' gen. We can't inject a crash in a unit
 * test, but we can inspect the on-disk SBs: after a successful sync, the
 * slot that lost the tiebreak (the reservation) should hold ss_gen_reserve
 * and the winner should hold ss_gen_final > ss_gen_reserve > any gen used
 * for writes. */
#include <sys/stat.h>
#include <fcntl.h>
STM_TEST(test_fs_sync_two_phase_gen_invariant)
{
    const char *path = "/tmp/stratum_test_two_phase.img";
    struct stm_fs *fs;
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 64ULL*1024*1024, NULL), 0);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "r7.bin", 0644, &ino), 0);
    STM_ASSERT_EQ(stm_fs_write(fs, ino, 0, "hello", 5), 0);
    STM_ASSERT_EQ(stm_fs_sync(fs), 0);

    /* Read both SBs and verify both are valid; the higher-gen one is the
     * final commit and the lower-gen one is the reservation from this sync
     * (or an earlier reservation if this was the first sync after mkfs). */
    int fd = open(path, O_RDONLY);
    STM_ASSERT(fd >= 0);
    uint8_t sb_a[512], sb_b[512];
    STM_ASSERT_EQ((int)pread(fd, sb_a, 512, 0), 512);
    STM_ASSERT_EQ((int)pread(fd, sb_b, 512, 4096), 512);
    close(fd);

    /* Extract ss_gen at offset 16 (after ss_magic=8 + ss_version=4 + ss_flags=4). */
    uint64_t gen_a, gen_b;
    memcpy(&gen_a, sb_a + 16, 8);
    memcpy(&gen_b, sb_b + 16, 8);
    /* gens differ by at least 1 (final vs reservation) and both are > 0. */
    STM_ASSERT(gen_a != 0 && gen_b != 0);
    STM_ASSERT(gen_a != gen_b);
    uint64_t lo = gen_a < gen_b ? gen_a : gen_b;
    uint64_t hi = gen_a < gen_b ? gen_b : gen_a;
    STM_ASSERT(hi == lo + 1);

    /* Three more sync cycles. Per R8-1, each sync advances the max disk
     * ss_gen by at least 1 (Phase 3 final at fs->gen_pre + 2; fs->gen
     * itself advances by 1). disk ss_gen must remain strictly greater
     * than fs->gen across every cycle. We can only observe disk here,
     * so assert strict monotonic advance. */
    uint64_t prev_hi = hi;
    int i;
    for (i = 0; i < 3; i++) {
        char buf[16];
        snprintf(buf, sizeof(buf), "cycle %d", i);
        STM_ASSERT_EQ(stm_fs_write(fs, ino, 0, buf, strlen(buf)), 0);
        STM_ASSERT_EQ(stm_fs_sync(fs), 0);

        fd = open(path, O_RDONLY);
        STM_ASSERT(fd >= 0);
        STM_ASSERT_EQ((int)pread(fd, sb_a, 512, 0), 512);
        STM_ASSERT_EQ((int)pread(fd, sb_b, 512, 4096), 512);
        close(fd);
        memcpy(&gen_a, sb_a + 16, 8);
        memcpy(&gen_b, sb_b + 16, 8);
        uint64_t cur_hi = gen_a > gen_b ? gen_a : gen_b;
        STM_ASSERT(cur_hi > prev_hi);
        prev_hi = cur_hi;
    }

    stm_fs_close(fs);
    unlink(path);
}

/* Regression for R8-1: on encrypted volumes, mount-time gen bump must
 * establish disk ss_gen STRICTLY GREATER than fs->gen (the write_gen used
 * for ciphertext). Without mount-bump, fs->gen == disk ss_gen after every
 * successful sync, and inter-sync writes (which encrypt at fs->gen) could
 * collide with orphans from a crashed prior session after remount.
 *
 * Probe: mkfs encrypted volume (fs->gen starts at 1, disk ss_gen=1 post
 * mkfs). Mount. Mount-bump writes disk ss_gen=2. Read disk. Assert max
 * ss_gen >= 2 even though NO sync has been called yet. */
STM_TEST(test_fs_mount_bump_encrypted)
{
    const char *path = "/tmp/stratum_test_mount_bump.img";
    const char *pass = "bumper";
    struct stm_fs *fs;
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 64ULL*1024*1024, pass), 0);

    /* Inspect SBs immediately after mkfs — before any mount. */
    int fd = open(path, O_RDONLY);
    STM_ASSERT(fd >= 0);
    uint8_t sb_a[512], sb_b[512];
    STM_ASSERT_EQ((int)pread(fd, sb_a, 512, 0), 512);
    STM_ASSERT_EQ((int)pread(fd, sb_b, 512, 4096), 512);
    close(fd);
    uint64_t gen_a_mkfs, gen_b_mkfs;
    memcpy(&gen_a_mkfs, sb_a + 16, 8);
    memcpy(&gen_b_mkfs, sb_b + 16, 8);
    uint64_t mkfs_max = gen_a_mkfs > gen_b_mkfs ? gen_a_mkfs : gen_b_mkfs;

    /* Mount — should trigger mount-bump (encrypted). */
    STM_ASSERT_EQ(stm_fs_open(path, pass, &fs), 0);

    /* Inspect SBs NOW — before any sync. Max ss_gen must have advanced
     * beyond the post-mkfs value. */
    fd = open(path, O_RDONLY);
    STM_ASSERT(fd >= 0);
    STM_ASSERT_EQ((int)pread(fd, sb_a, 512, 0), 512);
    STM_ASSERT_EQ((int)pread(fd, sb_b, 512, 4096), 512);
    close(fd);
    uint64_t gen_a_mounted, gen_b_mounted;
    memcpy(&gen_a_mounted, sb_a + 16, 8);
    memcpy(&gen_b_mounted, sb_b + 16, 8);
    uint64_t mounted_max = gen_a_mounted > gen_b_mounted
                         ? gen_a_mounted : gen_b_mounted;
    STM_ASSERT(mounted_max > mkfs_max);

    /* Do a write + sync. All session ciphertexts use write_gen = fs->gen
     * (= mkfs_max). Mount-bump ensured disk ss_gen > fs->gen. */
    uint64_t ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "r8.bin", 0644, &ino), 0);
    STM_ASSERT_EQ(stm_fs_write(fs, ino, 0, "pre-sync", 8), 0);
    /* Simulate a crash-equivalent by closing without sync — reopen must
     * still work. (stm_fs_close implicitly flushes any OS-level caches
     * but does not call stm_fs_sync.) */
    stm_fs_close(fs);

    /* Reopen — mount-bump again bumps disk ss_gen. On an encrypted
     * volume that never synced, the reopen must succeed and subsequent
     * writes must be at a gen different from mkfs's and different from
     * the previous session's fs->gen. */
    STM_ASSERT_EQ(stm_fs_open(path, pass, &fs), 0);

    fd = open(path, O_RDONLY);
    STM_ASSERT(fd >= 0);
    STM_ASSERT_EQ((int)pread(fd, sb_a, 512, 0), 512);
    STM_ASSERT_EQ((int)pread(fd, sb_b, 512, 4096), 512);
    close(fd);
    uint64_t gen_a_remounted, gen_b_remounted;
    memcpy(&gen_a_remounted, sb_a + 16, 8);
    memcpy(&gen_b_remounted, sb_b + 16, 8);
    uint64_t remounted_max = gen_a_remounted > gen_b_remounted
                           ? gen_a_remounted : gen_b_remounted;
    STM_ASSERT(remounted_max > mounted_max);

    stm_fs_close(fs);
    unlink(path);
}

/* Regression for R10-3: stm_fs_open_ro must enforce read-only contract at
 * runtime. Mutation APIs return -EROFS; read APIs succeed. */
STM_TEST(test_fs_open_ro_rejects_writes)
{
    const char *path = "/tmp/stratum_test_ro.img";
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 32ULL*1024*1024, NULL), 0);

    /* Seed some state via normal open. */
    {
        struct stm_fs *fs;
        STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);
        uint64_t ino;
        STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "seed.txt", 0644, &ino), 0);
        STM_ASSERT_EQ(stm_fs_write(fs, ino, 0, "data", 4), 0);
        STM_ASSERT_EQ(stm_fs_sync(fs), 0);
        stm_fs_close(fs);
    }

    /* Reopen RO. Reads must work, writes must be rejected with -EROFS. */
    struct stm_fs *fs;
    STM_ASSERT_EQ(stm_fs_open_ro(path, NULL, &fs), 0);

    /* Read succeeds. */
    uint64_t ino;
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "seed.txt", &ino), 0);
    char buf[16] = {0};
    uint32_t nread = 0;
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_EQ(nread, 4u);
    STM_ASSERT_MEM_EQ(buf, "data", 4);

    /* Mutations rejected. */
    uint64_t dummy;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "x.txt", 0644, &dummy), -EROFS);
    STM_ASSERT_EQ(stm_fs_mkdir(fs, 1, "d", 0755, &dummy), -EROFS);
    STM_ASSERT_EQ(stm_fs_write(fs, ino, 4, "more", 4), -EROFS);
    STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "seed.txt"), -EROFS);
    STM_ASSERT_EQ(stm_fs_sync(fs), -EROFS);

    stm_fs_close(fs);
    unlink(path);
}

/* POSIX Group A (SOTA #5): chmod / chown / utimes / truncate. */
STM_TEST(test_fs_posix_attr_mutations)
{
    const char *path = "/tmp/stratum_test_posix_attr.img";
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 32ULL*1024*1024, NULL), 0);
    struct stm_fs *fs;
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "attr.txt", 0644, &ino), 0);

    /* chmod: 0644 → 0600, preserving IFREG. */
    STM_ASSERT_EQ(stm_fs_chmod(fs, ino, 0600), 0);
    struct stm_inode in;
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_mode) & 07777, (uint32_t)0600);
    STM_ASSERT_EQ(le32_to_cpu(in.si_mode) & STM_S_IFMT, (uint32_t)STM_S_IFREG);

    /* chown: set to 1000:1000. */
    STM_ASSERT_EQ(stm_fs_chown(fs, ino, 1000, 1000), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_uid), 1000u);
    STM_ASSERT_EQ(le32_to_cpu(in.si_gid), 1000u);

    /* chown with -1 only changes the named field. */
    STM_ASSERT_EQ(stm_fs_chown(fs, ino, (uint32_t)-1, 2000), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_uid), 1000u);   /* unchanged */
    STM_ASSERT_EQ(le32_to_cpu(in.si_gid), 2000u);

    /* utimes: set only mtime, preserve atime. */
    uint64_t orig_atime = le64_to_cpu(in.si_atime_sec);
    STM_ASSERT_EQ(stm_fs_utimes(fs, ino, 0, 0, 0, 1, 1234567890ULL, 500), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le64_to_cpu(in.si_atime_sec), orig_atime);
    STM_ASSERT_EQ(le64_to_cpu(in.si_mtime_sec), 1234567890ULL);
    STM_ASSERT_EQ(le32_to_cpu(in.si_mtime_nsec), 500u);

    /* truncate extend: pure metadata; sparse read returns zero. */
    STM_ASSERT_EQ(stm_fs_truncate(fs, ino, 4096), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le64_to_cpu(in.si_size), 4096u);

    uint8_t rbuf[128];
    memset(rbuf, 0xAA, sizeof(rbuf));
    uint32_t nread = 0;
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, rbuf, sizeof(rbuf), &nread), 0);
    STM_ASSERT_EQ(nread, (uint32_t)sizeof(rbuf));
    for (size_t i = 0; i < sizeof(rbuf); i++) STM_ASSERT_EQ(rbuf[i], 0);

    /* truncate shrink — multi-extent file then truncate to non-aligned
     * size that lands inside an extent. Checks the read-modify-write
     * path for the straddling extent. */
    uint8_t *wbuf = malloc(256 * 1024);
    STM_ASSERT(wbuf);
    for (size_t i = 0; i < 256 * 1024; i++) wbuf[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_EQ(stm_fs_write(fs, ino, 0, wbuf, 256 * 1024), 0);

    /* Truncate to 150 KiB — straddles the second extent (131072..262143). */
    STM_ASSERT_EQ(stm_fs_truncate(fs, ino, 150 * 1024), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le64_to_cpu(in.si_size), (uint64_t)(150 * 1024));

    /* First 150 KiB must read back original bytes. */
    uint8_t *rfull = malloc(150 * 1024);
    STM_ASSERT(rfull);
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, rfull, 150 * 1024, &nread), 0);
    STM_ASSERT_EQ(nread, (uint32_t)(150 * 1024));
    STM_ASSERT_MEM_EQ(rfull, wbuf, 150 * 1024);
    free(rfull); free(wbuf);

    /* Beyond the truncation point: read returns 0 bytes (past EOF). */
    uint8_t tail[32];
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 150 * 1024, tail, sizeof(tail), &nread), 0);
    STM_ASSERT_EQ(nread, 0u);

    /* Truncate to aligned size (exactly one extent) — no straddle path. */
    STM_ASSERT_EQ(stm_fs_truncate(fs, ino, 128 * 1024), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le64_to_cpu(in.si_size), (uint64_t)(128 * 1024));

    /* Truncate to zero. */
    STM_ASSERT_EQ(stm_fs_truncate(fs, ino, 0), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le64_to_cpu(in.si_size), 0u);
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, tail, sizeof(tail), &nread), 0);
    STM_ASSERT_EQ(nread, 0u);

    /* Sync + reopen — the chmod/chown/utimes/truncate mutations must
     * round-trip through disk. */
    STM_ASSERT_EQ(stm_fs_sync(fs), 0);
    stm_fs_close(fs);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t ino2;
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "attr.txt", &ino2), 0);
    STM_ASSERT_EQ(ino2, ino);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    /* mtime is intentionally NOT checked across reopen — every
     * subsequent op (write, truncate) updates it to "now" per POSIX,
     * so the explicit 1234567890 we set earlier has been overwritten.
     * mode / uid / gid / size are all mutation-persistent. */
    STM_ASSERT_EQ(le32_to_cpu(in.si_mode) & 07777, (uint32_t)0600);
    STM_ASSERT_EQ(le32_to_cpu(in.si_uid), 1000u);
    STM_ASSERT_EQ(le32_to_cpu(in.si_gid), 2000u);
    STM_ASSERT_EQ(le64_to_cpu(in.si_size), 0u);

    stm_fs_close(fs);
    unlink(path);
}

/* POSIX Group B (SOTA #5): rename. */
STM_TEST(test_fs_posix_rename)
{
    const char *path = "/tmp/stratum_test_posix_rename.img";
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 32ULL*1024*1024, NULL), 0);
    struct stm_fs *fs;
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t a_ino, b_ino, dir_ino, file2_ino;

    /* Seed: /a with content "hello"; /b empty; /dir/ ; /dir/file2 */
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "a", 0644, &a_ino), 0);
    STM_ASSERT_EQ(stm_fs_write(fs, a_ino, 0, "hello", 5), 0);
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "b", 0644, &b_ino), 0);
    STM_ASSERT_EQ(stm_fs_write(fs, b_ino, 0, "world!!", 7), 0);
    STM_ASSERT_EQ(stm_fs_mkdir(fs, 1, "dir", 0755, &dir_ino), 0);
    STM_ASSERT_EQ(stm_fs_create_file(fs, dir_ino, "file2", 0644, &file2_ino), 0);
    STM_ASSERT_EQ(stm_fs_write(fs, file2_ino, 0, "inner", 5), 0);

    /* Case 1: rename /a → /c (target doesn't exist). Inode preserved,
     * old name gone, new name reachable. */
    STM_ASSERT_EQ(stm_fs_rename(fs, 1, "a", 1, "c"), 0);
    uint64_t chk;
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "a", &chk), -ENOENT);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "c", &chk), 0);
    STM_ASSERT_EQ(chk, a_ino);
    char buf[16] = {0};
    uint32_t nread = 0;
    STM_ASSERT_EQ(stm_fs_read(fs, a_ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_EQ(nread, 5u);
    STM_ASSERT_MEM_EQ(buf, "hello", 5);

    /* Case 2: rename-to-self — no-op success. */
    STM_ASSERT_EQ(stm_fs_rename(fs, 1, "c", 1, "c"), 0);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "c", &chk), 0);
    STM_ASSERT_EQ(chk, a_ino);

    /* Case 3: rename /c → /b (target exists as regular file). b's inode
     * should be gone; c's inode should now be reachable via "b". */
    STM_ASSERT_EQ(stm_fs_rename(fs, 1, "c", 1, "b"), 0);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "c", &chk), -ENOENT);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "b", &chk), 0);
    STM_ASSERT_EQ(chk, a_ino);   /* a's inode now lives at "b" */
    /* Old "b" inode must be fully reaped (target's nlink was 1). */
    struct stm_inode chk_in;
    STM_ASSERT_EQ(stm_fs_stat(fs, b_ino, &chk_in), -ENOENT);

    /* Case 4: rename into subdirectory. /b → /dir/nested. */
    STM_ASSERT_EQ(stm_fs_rename(fs, 1, "b", dir_ino, "nested"), 0);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "b", &chk), -ENOENT);
    STM_ASSERT_EQ(stm_fs_lookup(fs, dir_ino, "nested", &chk), 0);
    STM_ASSERT_EQ(chk, a_ino);
    /* Content preserved. */
    memset(buf, 0, sizeof(buf));
    STM_ASSERT_EQ(stm_fs_read(fs, a_ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_EQ(nread, 5u);
    STM_ASSERT_MEM_EQ(buf, "hello", 5);

    /* Case 5: rename over a non-empty directory — ENOTEMPTY. */
    /* First make /dir non-empty (it has "file2" and "nested"). */
    uint64_t foo_ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "foo", 0644, &foo_ino), 0);
    STM_ASSERT_EQ(stm_fs_rename(fs, 1, "foo", 1, "dir"), -ENOTEMPTY);
    /* foo and dir both survive. */
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "foo", &chk), 0);
    STM_ASSERT_EQ(chk, foo_ino);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "dir", &chk), 0);
    STM_ASSERT_EQ(chk, dir_ino);

    /* Case 6: rename non-existent source — ENOENT. */
    STM_ASSERT_EQ(stm_fs_rename(fs, 1, "does_not_exist", 1, "whatever"), -ENOENT);

    /* Case 7: sync + reopen, state persists. */
    STM_ASSERT_EQ(stm_fs_sync(fs), 0);
    stm_fs_close(fs);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);
    STM_ASSERT_EQ(stm_fs_lookup(fs, dir_ino, "nested", &chk), 0);
    STM_ASSERT_EQ(chk, a_ino);
    memset(buf, 0, sizeof(buf));
    STM_ASSERT_EQ(stm_fs_read(fs, a_ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_MEM_EQ(buf, "hello", 5);

    stm_fs_close(fs);
    unlink(path);
}

/* POSIX Group C (SOTA #5): extended attributes. */
struct xattr_collect {
    char names[16][64];
    int  count;
};
static int xattr_collect_cb(const char *name, void *ctx) {
    struct xattr_collect *c = ctx;
    if (c->count < 16) {
        strncpy(c->names[c->count], name, 63);
        c->names[c->count][63] = 0;
        c->count++;
    }
    return 0;
}
static int has_name(const struct xattr_collect *c, const char *needle) {
    for (int i = 0; i < c->count; i++)
        if (strcmp(c->names[i], needle) == 0) return 1;
    return 0;
}

STM_TEST(test_fs_posix_xattr)
{
    const char *path = "/tmp/stratum_test_posix_xattr.img";
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 32ULL*1024*1024, NULL), 0);
    struct stm_fs *fs;
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    uint64_t ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "x.txt", 0644, &ino), 0);

    /* set → get round-trip (default flags = create-or-replace). */
    const char *v1 = "value-one";
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.test",
                                   v1, (uint32_t)strlen(v1), 0), 0);
    char buf[64] = {0};
    uint32_t len = sizeof(buf);
    STM_ASSERT_EQ(stm_fs_xattr_get(fs, ino, "user.test", buf, &len), 0);
    STM_ASSERT_EQ(len, (uint32_t)strlen(v1));
    STM_ASSERT_MEM_EQ(buf, v1, strlen(v1));

    /* Size query — caller passes *inout_len = 0. */
    len = 0;
    STM_ASSERT_EQ(stm_fs_xattr_get(fs, ino, "user.test", NULL, &len), 0);
    STM_ASSERT_EQ(len, (uint32_t)strlen(v1));

    /* ERANGE when the caller's buffer is too small. */
    len = 4;
    STM_ASSERT_EQ(stm_fs_xattr_get(fs, ino, "user.test", buf, &len), -ERANGE);

    /* XATTR_CREATE on existing → EEXIST. */
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.test", v1, (uint32_t)strlen(v1), 1),
                  -EEXIST);

    /* XATTR_REPLACE on missing → ENODATA. */
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.missing", v1, (uint32_t)strlen(v1), 2),
                  -ENODATA);

    /* Replace the value — default flags. */
    const char *v2 = "new and different contents";
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.test",
                                   v2, (uint32_t)strlen(v2), 0), 0);
    memset(buf, 0, sizeof(buf));
    len = sizeof(buf);
    STM_ASSERT_EQ(stm_fs_xattr_get(fs, ino, "user.test", buf, &len), 0);
    STM_ASSERT_EQ(len, (uint32_t)strlen(v2));
    STM_ASSERT_MEM_EQ(buf, v2, strlen(v2));

    /* Multiple xattrs on the same inode — list must see all. */
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.alpha", "A", 1, 0), 0);
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.beta",  "BB", 2, 0), 0);
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.gamma", "CCC", 3, 0), 0);

    struct xattr_collect c = { .count = 0 };
    STM_ASSERT_EQ(stm_fs_xattr_list(fs, ino, xattr_collect_cb, &c), 0);
    STM_ASSERT_EQ(c.count, 4);
    STM_ASSERT(has_name(&c, "user.test"));
    STM_ASSERT(has_name(&c, "user.alpha"));
    STM_ASSERT(has_name(&c, "user.beta"));
    STM_ASSERT(has_name(&c, "user.gamma"));

    /* Remove one — list count drops, removed name gone, others remain. */
    STM_ASSERT_EQ(stm_fs_xattr_remove(fs, ino, "user.beta"), 0);
    memset(&c, 0, sizeof(c));
    STM_ASSERT_EQ(stm_fs_xattr_list(fs, ino, xattr_collect_cb, &c), 0);
    STM_ASSERT_EQ(c.count, 3);
    STM_ASSERT(!has_name(&c, "user.beta"));
    STM_ASSERT(has_name(&c, "user.alpha"));

    /* Get on removed → ENOENT (FUSE maps to ENODATA). */
    len = sizeof(buf);
    STM_ASSERT_EQ(stm_fs_xattr_get(fs, ino, "user.beta", buf, &len), -ENOENT);
    /* Remove on missing → ENOENT. */
    STM_ASSERT_EQ(stm_fs_xattr_remove(fs, ino, "user.beta"), -ENOENT);

    /* Large value (at the 64 KiB max): encode, round-trip, verify. */
    uint8_t *big = malloc(65536);
    STM_ASSERT(big);
    for (size_t i = 0; i < 65536; i++) big[i] = (uint8_t)(i & 0xFF);
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.big", big, 65536, 0), 0);
    uint8_t *readback = malloc(65536);
    STM_ASSERT(readback);
    memset(readback, 0, 65536);
    len = 65536;
    STM_ASSERT_EQ(stm_fs_xattr_get(fs, ino, "user.big", readback, &len), 0);
    STM_ASSERT_EQ(len, 65536u);
    STM_ASSERT_MEM_EQ(readback, big, 65536);

    /* Oversized value rejected. */
    STM_ASSERT_EQ(stm_fs_xattr_set(fs, ino, "user.toobig",
                                    big, 65537, 0), -E2BIG);

    free(big); free(readback);

    /* Sync + reopen — xattrs persist. */
    STM_ASSERT_EQ(stm_fs_sync(fs), 0);
    stm_fs_close(fs);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);
    uint64_t ino2;
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "x.txt", &ino2), 0);
    STM_ASSERT_EQ(ino2, ino);
    memset(buf, 0, sizeof(buf));
    len = sizeof(buf);
    STM_ASSERT_EQ(stm_fs_xattr_get(fs, ino, "user.test", buf, &len), 0);
    STM_ASSERT_EQ(len, (uint32_t)strlen(v2));
    STM_ASSERT_MEM_EQ(buf, v2, strlen(v2));
    memset(&c, 0, sizeof(c));
    STM_ASSERT_EQ(stm_fs_xattr_list(fs, ino, xattr_collect_cb, &c), 0);
    STM_ASSERT_EQ(c.count, 4);  /* test, alpha, gamma, big */

    stm_fs_close(fs);
    unlink(path);
}

/* POSIX Group D (SOTA #5): hardlinks. */
STM_TEST(test_fs_posix_hardlinks)
{
    const char *path = "/tmp/stratum_test_posix_hardlinks.img";
    unlink(path);
    STM_ASSERT_EQ(stm_fs_create(path, 32ULL*1024*1024, NULL), 0);
    struct stm_fs *fs;
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);

    /* Create /a with content, hardlink it to /b. */
    uint64_t ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "a", 0644, &ino), 0);
    STM_ASSERT_EQ(stm_fs_write(fs, ino, 0, "shared!", 7), 0);

    struct stm_inode in;
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_nlink), 1u);

    STM_ASSERT_EQ(stm_fs_link(fs, ino, 1, "b"), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_nlink), 2u);

    /* Both names resolve to the same inode; both read the same content. */
    uint64_t chk_a, chk_b;
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "a", &chk_a), 0);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "b", &chk_b), 0);
    STM_ASSERT_EQ(chk_a, ino);
    STM_ASSERT_EQ(chk_b, ino);

    char buf[16] = {0};
    uint32_t nread = 0;
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_MEM_EQ(buf, "shared!", 7);

    /* Writing through one name visible through the other (same inode). */
    STM_ASSERT_EQ(stm_fs_write(fs, ino, 0, "changed", 7), 0);
    memset(buf, 0, sizeof(buf));
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_MEM_EQ(buf, "changed", 7);

    /* Third link; nlink = 3. */
    STM_ASSERT_EQ(stm_fs_link(fs, ino, 1, "c"), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_nlink), 3u);

    /* Linking to an already-existing name → -EEXIST. */
    STM_ASSERT_EQ(stm_fs_link(fs, ino, 1, "a"), -EEXIST);

    /* Unlink one — nlink drops to 2, inode still there, data intact. */
    STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "a"), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_nlink), 2u);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "a", &chk_a), -ENOENT);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "b", &chk_b), 0);
    STM_ASSERT_EQ(chk_b, ino);
    memset(buf, 0, sizeof(buf));
    STM_ASSERT_EQ(stm_fs_read(fs, ino, 0, buf, sizeof(buf), &nread), 0);
    STM_ASSERT_MEM_EQ(buf, "changed", 7);

    /* Unlink second — nlink drops to 1. */
    STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "b"), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_nlink), 1u);

    /* Unlink the last remaining — inode fully reaped. */
    STM_ASSERT_EQ(stm_fs_unlink(fs, 1, "c"), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, ino, &in), -ENOENT);
    STM_ASSERT_EQ(stm_fs_lookup(fs, 1, "c", &chk_a), -ENOENT);

    /* Cannot hardlink a directory. */
    uint64_t dir_ino;
    STM_ASSERT_EQ(stm_fs_mkdir(fs, 1, "mydir", 0755, &dir_ino), 0);
    STM_ASSERT_EQ(stm_fs_link(fs, dir_ino, 1, "mydir_alias"), -EPERM);

    /* Sync + reopen — link count persists. */
    uint64_t x_ino;
    STM_ASSERT_EQ(stm_fs_create_file(fs, 1, "x", 0644, &x_ino), 0);
    STM_ASSERT_EQ(stm_fs_link(fs, x_ino, 1, "y"), 0);
    STM_ASSERT_EQ(stm_fs_sync(fs), 0);
    stm_fs_close(fs);
    STM_ASSERT_EQ(stm_fs_open(path, NULL, &fs), 0);
    STM_ASSERT_EQ(stm_fs_stat(fs, x_ino, &in), 0);
    STM_ASSERT_EQ(le32_to_cpu(in.si_nlink), 2u);

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
    STM_RUN(test_fs_write_gap_is_zeroed);
    STM_RUN(test_fs_write_gap_is_zeroed_encrypted);
    STM_RUN(test_fs_sync_two_phase_gen_invariant);
    STM_RUN(test_fs_mount_bump_encrypted);
    STM_RUN(test_fs_open_ro_rejects_writes);
    STM_RUN(test_fs_posix_attr_mutations);
    STM_RUN(test_fs_posix_rename);
    STM_RUN(test_fs_posix_xattr);
    STM_RUN(test_fs_posix_hardlinks);
    printf("all passed\n");
    return 0;
}
