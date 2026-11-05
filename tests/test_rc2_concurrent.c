/* SPDX-License-Identifier: ISC */
/*
 * RC-2 concurrent read path tests — s->lock retired from reads.
 *
 *   see v2/docs/rc-design.md "RC-2"   — the design this validates.
 *   see v2/specs/dek_guard.tla        — the DEK-map model; the rotate/
 *                                        sweep hammer is its runtime
 *                                        witness (Install/Evict churn
 *                                        under pinned readers).
 *   see v2/specs/dcache_ebr.tla       — the RC-1 model the read path
 *                                        composes with.
 *
 * Coverage:
 *   - rc2_sync_read_write_hammer: N lock-free readers slice-verify
 *     version-stamped extents while a writer overwrite-churns the same
 *     inos. Every successful read must be ENTIRELY one version's
 *     pattern — a mixed read, a torn DEK, or a stale-map wrong-key
 *     decrypt fails the content check (a wrong key cannot even pass
 *     AEAD verify; content mixing across the lookup/decrypt seam is
 *     what this asserts).
 *   - rc2_dek_rotate_sweep_hammer: readers on live extents while a
 *     mutator rotates the dataset key, re-encrypts every extent under
 *     the new CURRENT, and sweeps the retired key — the COW DEK map
 *     publishes an install AND a remove per cycle. Every read MUST
 *     succeed (a still-referenced key is never pruned; the sweep's
 *     refcount gate + the publish atomicity together guarantee a
 *     pinned reader never observes a map missing its extent's key).
 *   - rc2_fs_read_vs_mutate_single_version: fs-level RC-I2 — readers
 *     under the SHARED inode pin vs whole-file rewrite + truncate
 *     churn under the EXCLUSIVE pin. Every single stm_fs_read call
 *     returns bytes from exactly one version (pre- or post-image,
 *     never a mix), including across extent boundaries.
 *   - rc2_pin_shared_semantics: two SHARED pins on one inode coexist;
 *     an EXCLUSIVE pin waits for a SHARED holder and vice versa.
 *
 * Workers report through atomics (the harness failure flag is
 * thread-local); the main thread asserts.
 */

#include "tharness.h"
#include "test_fs_common.h"
#include <sys/stat.h>

#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/ebr.h>
#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/inode.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/sync.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ========================================================================= */
/* Raw-sync fixture (the test_dcache_concurrent shape).                       */
/* ========================================================================= */

static const uint64_t POOL_UUID[2]   = { 0x00c0ffee, 0x00decade };
static const uint64_t DEVICE_UUID[2] = { 0x11115555, 0x2222aaaa };

static char g_dev_path[256];

static void rc2_make_path(const char *tag)
{
    snprintf(g_dev_path, sizeof g_dev_path, "/tmp/stm_v2_rc2_%s_%d.bin",
             tag, (int)getpid());
    unlink(g_dev_path);
}

static stm_bdev *rc2_open_device(void)
{
    stm_bdev_open_opts bo = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    STM_ASSERT_OK(stm_bdev_open(g_dev_path, &bo, &d));
    STM_ASSERT_OK(stm_bdev_resize(d, TEST_DEVICE_BYTES));
    return d;
}

static stm_pool *rc2_make_pool(stm_bdev *bd)
{
    const stm_bdev_caps *caps = stm_bdev_caps_of(bd);
    STM_ASSERT(caps != NULL);
    stm_pool_open_opts opts;
    memset(&opts, 0, sizeof opts);
    opts.pool_uuid[0] = POOL_UUID[0];
    opts.pool_uuid[1] = POOL_UUID[1];
    opts.device_count = 1;
    opts.devices[0].uuid[0]    = DEVICE_UUID[0];
    opts.devices[0].uuid[1]    = DEVICE_UUID[1];
    opts.devices[0].size_bytes = caps->size_bytes;
    opts.devices[0].role       = STM_DEV_ROLE_DATA;
    opts.devices[0].class_     = STM_DEV_CLASS_SSD;
    opts.devices[0].state      = STM_DEV_STATE_ONLINE;
    opts.devices[0].bdev       = bd;
    stm_pool *p = NULL;
    STM_ASSERT_OK(stm_pool_open(&opts, &p));
    return p;
}

static stm_hybrid_keys g_rc2_wk;
static bool g_rc2_wk_init = false;

static const stm_hybrid_keys *rc2_wk(void)
{
    if (!g_rc2_wk_init) {
        STM_ASSERT_OK(stm_crypto_init());
        STM_ASSERT_OK(stm_hybrid_keygen(g_rc2_wk.pk, g_rc2_wk.sk));
        g_rc2_wk_init = true;
    }
    return &g_rc2_wk;
}

struct rc2_fixture {
    stm_bdev  *bd;
    stm_pool  *pool;
    stm_alloc *alloc;
    stm_sync  *sync;
};

static void rc2_fixture_open(struct rc2_fixture *f, const char *tag)
{
    rc2_make_path(tag);
    f->bd    = rc2_open_device();
    f->pool  = rc2_make_pool(f->bd);
    f->alloc = NULL;
    STM_ASSERT_OK(stm_alloc_create(f->bd, POOL_UUID, DEVICE_UUID,
                                     TEST_BOOTSTRAP_BYTES, &f->alloc));
    f->sync = NULL;
    STM_ASSERT_OK(stm_sync_create(f->pool, f->alloc, rc2_wk(), NULL,
                                    &f->sync));
}

static void rc2_fixture_close(struct rc2_fixture *f)
{
    stm_sync_close(f->sync);
    stm_alloc_close(f->alloc);
    stm_pool_close(f->pool);
    stm_bdev_close(f->bd);
    unlink(g_dev_path);
}

/* ========================================================================= */
/* Version-stamped patterns. pat(ino, ver, j) is position- AND version-
 * dependent, and the version is RECOVERABLE from any byte given (ino, j):
 * ver * 101 is invertible mod 256 (101 odd; inverse 109 since
 * 101 * 109 = 11009 = 43 * 256 + 1), so a reader can derive the version
 * from byte 0 and then verify EVERY byte belongs to that one version —
 * the single-version (no-mix) check.                                        */
/* ========================================================================= */

#define VER_INV_101 109u

static inline uint8_t rc2_pat(uint64_t ino, uint32_t ver, size_t j)
{
    return (uint8_t)((uint32_t)ino * 37u + ver * 101u + (uint32_t)j * 7u + 5u);
}

static void rc2_fill(uint8_t *b, uint64_t ino, uint32_t ver, size_t len)
{
    for (size_t j = 0; j < len; j++) b[j] = rc2_pat(ino, ver, j);
}

/* Fill for a write at file offset `base`: the pattern is FILE-absolute
 * so a read at offset X verifies with j0 = X — two extents of one ino
 * can never alias each other's content. */
static void rc2_fill_at(uint8_t *b, uint64_t ino, uint32_t ver,
                        size_t base, size_t len)
{
    for (size_t j = 0; j < len; j++) b[j] = rc2_pat(ino, ver, base + j);
}

/* Derive the version encoded at absolute offset `j0` of buffer byte 0. */
static inline uint8_t rc2_ver_of(uint64_t ino, size_t j0, uint8_t byte0)
{
    uint8_t base = (uint8_t)((uint32_t)ino * 37u + (uint32_t)j0 * 7u + 5u);
    return (uint8_t)((uint8_t)(byte0 - base) * VER_INV_101);
}

/* Verify b[0..n) is ENTIRELY version `ver` starting at absolute offset
 * `j0`. Returns the number of mismatching bytes. */
static size_t rc2_verify_ver(const uint8_t *b, uint64_t ino, uint32_t ver,
                             size_t j0, size_t n)
{
    size_t bad = 0;
    for (size_t j = 0; j < n; j++)
        if (b[j] != rc2_pat(ino, ver, j0 + j)) bad++;
    return bad;
}

/* ========================================================================= */
/* rc2_sync_read_write_hammer                                                 */
/* ========================================================================= */

#define RWH_INOS        8u
#define RWH_LEN         4096u
#define RWH_READERS     4
#define RWH_WRITES_MAX  120u          /* bounded: no commit mid-hammer, so
                                       * CoW space grows monotonically —
                                       * 120 * 2 * 4 KiB fits the 16 MiB dev. */
#define RWH_READS_MIN   4000u
#define RWH_READS_CAP   (4u * 1000u * 1000u)

/* Every ino carries an extent at BOTH offsets — one below and one at
 * the LE-key byte boundary. LE(65536) = 00 00 01.. lex-sorts BEFORE
 * LE(4096) = 00 10 00.., so every reader probe at 4096 exercises the
 * exact per-ino key-order disorder that the pre-fix concurrent lookup
 * turned into a false hole (the RC-2 audit F1 / the boot-found P0):
 * an ENOENT or a zero-filled read here counts as read_err/content_bad
 * and fails the hammer. The offset-0-only first cut of this test was
 * structurally blind to that bug class. */
static const uint64_t rwh_offs[2] = { 4096u, 65536u };

typedef struct {
    stm_sync       *s;
    atomic_bool    *stop;
    _Atomic size_t *reads_ok;
    _Atomic size_t *content_bad;
    _Atomic size_t *read_err;
} rwh_reader_ctx;

static void *rwh_reader(void *arg)
{
    rwh_reader_ctx *c = arg;
    uint8_t *buf = malloc(RWH_LEN);
    if (!buf) { atomic_fetch_add(c->read_err, 1u); return NULL; }
    uint32_t rr = 0;
    for (size_t i = 0;
         !(atomic_load(c->stop) && i >= RWH_READS_MIN) && i < RWH_READS_CAP;
         i++) {
        uint64_t ino = (uint64_t)(rr % RWH_INOS) + 1u;
        uint64_t off = rwh_offs[(rr >> 8) & 1u];
        rr = rr * 1103515245u + 12345u;
        size_t got = 0;
        stm_status rc = stm_sync_read_extent(c->s, 1u, ino, off,
                                                buf, RWH_LEN, &got);
        if (rc != STM_OK) {
            /* No error is legal here: the extents exist for the whole
             * hammer and their keys are never removed. A false hole
             * (the audit-F1 class) surfaces as... STM_OK-with-zeros,
             * caught by the content check below; any other rc lands
             * here. */
            atomic_fetch_add(c->read_err, 1u);
            continue;
        }
        if (got != RWH_LEN) { atomic_fetch_add(c->content_bad, 1u); continue; }
        uint8_t ver = rc2_ver_of(ino, (size_t)off, buf[0]);
        if (rc2_verify_ver(buf, ino, ver, (size_t)off, got) != 0)
            atomic_fetch_add(c->content_bad, 1u);
        else
            atomic_fetch_add(c->reads_ok, 1u);
    }
    free(buf);
    return NULL;
}

STM_TEST(rc2_sync_read_write_hammer) {
    struct rc2_fixture f;
    rc2_fixture_open(&f, "rwh");

    uint8_t *wbuf = malloc(RWH_LEN);
    STM_ASSERT(wbuf != NULL);

    /* Version 0 for every ino, at BOTH offsets (the LE-key-order pair). */
    for (uint64_t ino = 1; ino <= RWH_INOS; ino++) {
        for (size_t k = 0; k < 2; k++) {
            rc2_fill_at(wbuf, ino, 0u, (size_t)rwh_offs[k], RWH_LEN);
            STM_ASSERT_OK(stm_sync_write_extent(f.sync, 1u, ino,
                                                  rwh_offs[k],
                                                  wbuf, RWH_LEN));
        }
    }

    atomic_bool    stop        = false;
    _Atomic size_t reads_ok    = 0;
    _Atomic size_t content_bad = 0;
    _Atomic size_t read_err    = 0;

    rwh_reader_ctx rctx = { f.sync, &stop, &reads_ok, &content_bad,
                            &read_err };
    pthread_t readers[RWH_READERS];
    for (int i = 0; i < RWH_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&readers[i], NULL, rwh_reader, &rctx), 0);

    /* Overwrite churn: bump each ino's version round-robin, rewriting
     * BOTH offsets (each extent single-version per write; readers
     * verify per-extent, so the momentary cross-extent version skew is
     * fine). Stop on ENOSPC (the bounded-device end) — the iteration
     * floor below still guarantees a real interleaving window. */
    uint32_t ver[RWH_INOS + 1] = {0};
    size_t   writes_done = 0;
    for (size_t w = 0; w < RWH_WRITES_MAX; w++) {
        uint64_t ino = (uint64_t)(w % RWH_INOS) + 1u;
        uint32_t v   = ++ver[ino];
        bool enospc = false;
        for (size_t k = 0; k < 2; k++) {
            rc2_fill_at(wbuf, ino, v, (size_t)rwh_offs[k], RWH_LEN);
            stm_status rc = stm_sync_write_extent(f.sync, 1u, ino,
                                                    rwh_offs[k],
                                                    wbuf, RWH_LEN);
            if (rc == STM_ENOSPC) { enospc = true; break; }
            STM_ASSERT_OK(rc);
        }
        if (enospc) break;
        writes_done++;
        if ((w & 7u) == 7u) sched_yield();
    }

    atomic_store(&stop, true);
    for (int i = 0; i < RWH_READERS; i++)
        STM_ASSERT_EQ(pthread_join(readers[i], NULL), 0);

    stm_test_info("rc2 rwh: writes=%zu reads_ok=%zu content_bad=%zu err=%zu",
                  writes_done, atomic_load(&reads_ok),
                  atomic_load(&content_bad), atomic_load(&read_err));

    STM_ASSERT(writes_done >= 32u);
    STM_ASSERT(atomic_load(&reads_ok) >= RWH_READS_MIN);
    STM_ASSERT_EQ(atomic_load(&content_bad), 0u);
    STM_ASSERT_EQ(atomic_load(&read_err), 0u);

    free(wbuf);
    rc2_fixture_close(&f);
}

/* ========================================================================= */
/* rc2_dek_rotate_sweep_hammer                                                */
/* ========================================================================= */

#define DRH_INOS       4u
#define DRH_LEN        4096u
#define DRH_READERS    4
#define DRH_CYCLES_MAX 24u
#define DRH_READS_MIN  2000u
#define DRH_READS_CAP  (4u * 1000u * 1000u)

typedef struct {
    stm_sync       *s;
    atomic_bool    *stop;
    _Atomic size_t *reads_ok;
    _Atomic size_t *content_bad;
    _Atomic size_t *read_err;
} drh_reader_ctx;

static void *drh_reader(void *arg)
{
    drh_reader_ctx *c = arg;
    uint8_t *buf = malloc(DRH_LEN);
    if (!buf) { atomic_fetch_add(c->read_err, 1u); return NULL; }
    uint32_t rr = 7u;
    for (size_t i = 0;
         !(atomic_load(c->stop) && i >= DRH_READS_MIN) && i < DRH_READS_CAP;
         i++) {
        uint64_t ino = (uint64_t)(rr % DRH_INOS) + 1u;
        rr = rr * 1103515245u + 12345u;
        size_t got = 0;
        stm_status rc = stm_sync_read_extent(c->s, 1u, ino, 0u,
                                                buf, DRH_LEN, &got);
        if (rc != STM_OK) {
            /* THE invariant: a live extent's stamped key is never
             * pruned (the sweep refuses keys with refs), and a map
             * publish is atomic — so no read may ever fail, in any
             * interleaving with rotate + overwrite + sweep. An
             * ECORRUPT here = a reader observed a torn or stale-
             * beyond-the-pin map. */
            atomic_fetch_add(c->read_err, 1u);
            continue;
        }
        if (got != DRH_LEN) { atomic_fetch_add(c->content_bad, 1u); continue; }
        uint8_t ver = rc2_ver_of(ino, 0u, buf[0]);
        if (rc2_verify_ver(buf, ino, ver, 0u, got) != 0)
            atomic_fetch_add(c->content_bad, 1u);
        else
            atomic_fetch_add(c->reads_ok, 1u);
    }
    free(buf);
    return NULL;
}

STM_TEST(rc2_dek_rotate_sweep_hammer) {
    struct rc2_fixture f;
    rc2_fixture_open(&f, "drh");

    uint8_t *wbuf = malloc(DRH_LEN);
    STM_ASSERT(wbuf != NULL);

    for (uint64_t ino = 1; ino <= DRH_INOS; ino++) {
        rc2_fill(wbuf, ino, 0u, DRH_LEN);
        STM_ASSERT_OK(stm_sync_write_extent(f.sync, 1u, ino, 0u,
                                              wbuf, DRH_LEN));
    }

    atomic_bool    stop        = false;
    _Atomic size_t reads_ok    = 0;
    _Atomic size_t content_bad = 0;
    _Atomic size_t read_err    = 0;

    drh_reader_ctx rctx = { f.sync, &stop, &reads_ok, &content_bad,
                            &read_err };
    pthread_t readers[DRH_READERS];
    for (int i = 0; i < DRH_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&readers[i], NULL, drh_reader, &rctx), 0);

    /* Rotate + re-encrypt + sweep cycles. Each cycle: one COW INSTALL
     * publish (the rotate's new CURRENT), DRH_INOS overwrites moving
     * every live extent onto the new key, then a sweep that prunes the
     * old key — one COW REMOVE publish. Readers race every step. */
    uint32_t ver[DRH_INOS + 1] = {0};
    size_t   cycles_done = 0;
    for (size_t cyc = 0; cyc < DRH_CYCLES_MAX; cyc++) {
        uint64_t new_kid = 0, old_kid = 0;
        stm_status rc = stm_sync_rotate_dataset_key(f.sync, 1u, rc2_wk(),
                                                      NULL, &new_kid,
                                                      &old_kid);
        STM_ASSERT_OK(rc);

        bool enospc = false;
        for (uint64_t ino = 1; ino <= DRH_INOS; ino++) {
            uint32_t v = ++ver[ino];
            rc2_fill(wbuf, ino, v, DRH_LEN);
            rc = stm_sync_write_extent(f.sync, 1u, ino, 0u, wbuf, DRH_LEN);
            if (rc == STM_ENOSPC) { enospc = true; break; }
            STM_ASSERT_OK(rc);
        }
        if (enospc) break;

        size_t pruned = 0;
        STM_ASSERT_OK(stm_sync_keyschema_sweep(f.sync, 1u, &pruned));
        cycles_done++;
        sched_yield();
    }

    atomic_store(&stop, true);
    for (int i = 0; i < DRH_READERS; i++)
        STM_ASSERT_EQ(pthread_join(readers[i], NULL), 0);

    stm_test_info("rc2 drh: cycles=%zu reads_ok=%zu content_bad=%zu err=%zu",
                  cycles_done, atomic_load(&reads_ok),
                  atomic_load(&content_bad), atomic_load(&read_err));

    STM_ASSERT(cycles_done >= 8u);
    STM_ASSERT(atomic_load(&reads_ok) >= DRH_READS_MIN);
    STM_ASSERT_EQ(atomic_load(&content_bad), 0u);
    STM_ASSERT_EQ(atomic_load(&read_err), 0u);

    free(wbuf);
    rc2_fixture_close(&f);
}

/* ========================================================================= */
/* rc2_fs_read_vs_mutate_single_version (RC-I2)                               */
/* ========================================================================= */

#define FVM_CHUNK      8192u
#define FVM_CHUNKS     3u
#define FVM_FILE_LEN   (FVM_CHUNK * FVM_CHUNKS)
#define FVM_READERS    3
#define FVM_VERS_MAX   96u
#define FVM_READS_MIN  1500u
#define FVM_READS_CAP  (4u * 1000u * 1000u)

typedef struct {
    stm_fs         *fs;
    uint64_t        ino;
    atomic_bool    *stop;
    _Atomic size_t *reads_ok;
    _Atomic size_t *content_bad;
    _Atomic size_t *read_err;
} fvm_reader_ctx;

static void *fvm_reader(void *arg)
{
    fvm_reader_ctx *c = arg;
    uint8_t *buf = malloc(FVM_FILE_LEN);
    if (!buf) { atomic_fetch_add(c->read_err, 1u); return NULL; }
    for (size_t i = 0;
         !(atomic_load(c->stop) && i >= FVM_READS_MIN) && i < FVM_READS_CAP;
         i++) {
        size_t got = 0;
        stm_status rc = stm_fs_read(c->fs, 1u, c->ino, 0u,
                                       buf, FVM_FILE_LEN, &got);
        if (rc != STM_OK) {
            atomic_fetch_add(c->read_err, 1u);
            continue;
        }
        if (got == 0) { atomic_fetch_add(c->reads_ok, 1u); continue; }
        /* RC-I2: whatever ONE stm_fs_read call returned must be a
         * single version's bytes — a v/v+1 mix across an extent or
         * buffer-overlay boundary inside one call is the race the
         * shared pin excludes. (A short `got` is legal: extent-
         * boundary short reads + post-truncate EOF clamps.) */
        uint8_t ver = rc2_ver_of(c->ino, 0u, buf[0]);
        if (rc2_verify_ver(buf, c->ino, ver, 0u, got) != 0)
            atomic_fetch_add(c->content_bad, 1u);
        else
            atomic_fetch_add(c->reads_ok, 1u);
    }
    free(buf);
    return NULL;
}

STM_TEST(rc2_fs_read_vs_mutate_single_version) {
    make_tmp("rc2_fvm");
    stm_fs_format_opts fopts = default_format_opts();
    STM_ASSERT_OK(stm_fs_format(g_tmp_path, &fopts));
    stm_fs_mount_opts mopts = rw_mount_opts();
    stm_fs *fs = NULL;
    STM_ASSERT_OK(stm_fs_mount(g_tmp_path, &mopts, &fs));

    stm_inode_index *iidx = stm_sync_inode_index(stm_fs_sync_for_test(fs));
    STM_ASSERT(iidx != NULL);
    uint64_t root = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1u, (uint32_t)S_IFDIR | 0755u,
                                       0u, 0u, &root));
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_fs_create_file(fs, 1u, root,
                                       (const uint8_t *)"hammer", 6,
                                       0644u, 0u, 0u, &ino));

    uint8_t *wbuf = malloc(FVM_FILE_LEN);
    STM_ASSERT(wbuf != NULL);

    /* Version 0, written chunk-by-chunk so the extent layer holds
     * multiple extents (each write lands + flushes independently over
     * the churn below — the multi-extent mix surface). */
    rc2_fill(wbuf, ino, 0u, FVM_FILE_LEN);
    for (size_t k = 0; k < FVM_CHUNKS; k++)
        STM_ASSERT_OK(stm_fs_write(fs, 1u, ino, k * FVM_CHUNK,
                                     wbuf + k * FVM_CHUNK, FVM_CHUNK));

    atomic_bool    stop        = false;
    _Atomic size_t reads_ok    = 0;
    _Atomic size_t content_bad = 0;
    _Atomic size_t read_err    = 0;

    fvm_reader_ctx rctx = { fs, ino, &stop, &reads_ok, &content_bad,
                            &read_err };
    pthread_t readers[FVM_READERS];
    for (int i = 0; i < FVM_READERS; i++)
        STM_ASSERT_EQ(pthread_create(&readers[i], NULL, fvm_reader, &rctx), 0);

    /* Mutator churn: whole-file rewrite at v in ONE stm_fs_write call —
     * one call is the RC-I2 atomicity unit (the EXCLUSIVE pin spans
     * exactly one fs call; the file's state BETWEEN two calls is a
     * real committed state, so a multi-call rewrite would create
     * legitimately mixed intermediate images and the single-version
     * assertion would be over-strict). Every 8th cycle a truncate to
     * one chunk first — the truncate-vs-read interleaving the pin
     * excludes mid-read (a read then sees the full pre-image, the
     * truncated 8 KiB image, or the rewritten post-image; never a
     * blend). */
    size_t vers_done = 0;
    for (uint32_t v = 1; v <= FVM_VERS_MAX; v++) {
        rc2_fill(wbuf, ino, v, FVM_FILE_LEN);
        if ((v & 7u) == 0u) {
            stm_status tr = stm_fs_truncate(fs, 1u, ino, FVM_CHUNK);
            if (tr == STM_ENOSPC) { break; }
            STM_ASSERT_OK(tr);
        }
        stm_status rc = stm_fs_write(fs, 1u, ino, 0u, wbuf, FVM_FILE_LEN);
        if (rc == STM_ENOSPC) break;
        STM_ASSERT_OK(rc);
        vers_done++;
        sched_yield();
    }

    atomic_store(&stop, true);
    for (int i = 0; i < FVM_READERS; i++)
        STM_ASSERT_EQ(pthread_join(readers[i], NULL), 0);

    stm_test_info("rc2 fvm: vers=%zu reads_ok=%zu content_bad=%zu err=%zu",
                  vers_done, atomic_load(&reads_ok),
                  atomic_load(&content_bad), atomic_load(&read_err));

    STM_ASSERT(vers_done >= 8u);
    STM_ASSERT(atomic_load(&reads_ok) >= FVM_READS_MIN);
    STM_ASSERT_EQ(atomic_load(&content_bad), 0u);
    STM_ASSERT_EQ(atomic_load(&read_err), 0u);

    free(wbuf);
    STM_ASSERT_OK(stm_fs_unmount(fs));
    unlink(g_tmp_path);
}

/* ========================================================================= */
/* rc2_pin_shared_semantics                                                   */
/* ========================================================================= */

typedef struct {
    stm_inode_index *iidx;
    uint64_t         ino;
    bool             shared;
    atomic_bool      attempting;
    atomic_bool      acquired;
    atomic_bool      release;   /* main tells the thread to unpin + exit */
    stm_status       rc;
} pin_probe_ctx;

static void *pin_probe(void *arg)
{
    pin_probe_ctx *c = arg;
    stm_inode_handle *h = NULL;
    atomic_store(&c->attempting, true);
    c->rc = c->shared
        ? stm_inode_pin_shared(c->iidx, 1u, c->ino, &h)
        : stm_inode_pin(c->iidx, 1u, c->ino, &h);
    atomic_store(&c->acquired, true);
    if (c->rc == STM_OK) {
        while (!atomic_load(&c->release)) sched_yield();
        stm_inode_unpin(c->iidx, h);
    }
    return NULL;
}

/* Spin until the probe reports `attempting`, then yield `spins` times
 * asserting it has NOT acquired — the blocked-holder witness (cannot
 * false-fail: a genuinely blocked pin never sets `acquired`; an
 * un-blocked one sets it within a handful of yields). */
static void assert_probe_blocked(pin_probe_ctx *c, int spins)
{
    while (!atomic_load(&c->attempting)) sched_yield();
    for (int i = 0; i < spins; i++) {
        STM_ASSERT(!atomic_load(&c->acquired));
        sched_yield();
    }
}

STM_TEST(rc2_pin_shared_semantics) {
    struct rc2_fixture f;
    rc2_fixture_open(&f, "pins");

    stm_inode_index *iidx = stm_sync_inode_index(f.sync);
    STM_ASSERT(iidx != NULL);
    uint64_t ino = 0;
    STM_ASSERT_OK(stm_inode_alloc(iidx, 1u, (uint32_t)S_IFREG | 0644u,
                                       0u, 0u, &ino));

    /* SH || SH coexist: hold shared on the main thread; a second
     * shared pin must complete while we still hold ours. */
    stm_inode_handle *h_main = NULL;
    STM_ASSERT_OK(stm_inode_pin_shared(iidx, 1u, ino, &h_main));

    pin_probe_ctx sh2 = { .iidx = iidx, .ino = ino, .shared = true };
    pthread_t t;
    STM_ASSERT_EQ(pthread_create(&t, NULL, pin_probe, &sh2), 0);
    while (!atomic_load(&sh2.acquired)) sched_yield();
    STM_ASSERT_OK(sh2.rc);                 /* acquired while we hold SH */
    atomic_store(&sh2.release, true);
    STM_ASSERT_EQ(pthread_join(t, NULL), 0);

    /* SH excludes EX: an exclusive pin blocks until the shared holder
     * releases. */
    pin_probe_ctx ex = { .iidx = iidx, .ino = ino, .shared = false };
    STM_ASSERT_EQ(pthread_create(&t, NULL, pin_probe, &ex), 0);
    assert_probe_blocked(&ex, 2000);
    stm_inode_unpin(iidx, h_main);         /* release SH — EX proceeds */
    while (!atomic_load(&ex.acquired)) sched_yield();
    STM_ASSERT_OK(ex.rc);

    /* EX excludes SH: with the exclusive pin still held by the probe
     * thread, a shared pin blocks until it releases. */
    pin_probe_ctx sh3 = { .iidx = iidx, .ino = ino, .shared = true };
    pthread_t t2;
    STM_ASSERT_EQ(pthread_create(&t2, NULL, pin_probe, &sh3), 0);
    assert_probe_blocked(&sh3, 2000);
    atomic_store(&ex.release, true);       /* release EX — SH proceeds */
    STM_ASSERT_EQ(pthread_join(t, NULL), 0);
    while (!atomic_load(&sh3.acquired)) sched_yield();
    STM_ASSERT_OK(sh3.rc);
    atomic_store(&sh3.release, true);
    STM_ASSERT_EQ(pthread_join(t2, NULL), 0);

    rc2_fixture_close(&f);
}

STM_TEST_MAIN("rc2_concurrent")
