/* SPDX-License-Identifier: ISC */
/*
 * Top-level filesystem handle (Phase 3 chunk 7).
 *
 *   see include/stratum/fs.h for the surface.
 *
 * `stm_fs` is a thin orchestrator over stm_bdev + stm_alloc + stm_sync.
 * Its jobs:
 *
 *   1. Lifecycle: stm_fs_format writes a fresh pool; stm_fs_mount opens
 *      an existing one; stm_fs_unmount tears down (committing first
 *      unless RO or wedged).
 *   2. Runtime guards: FS_GUARD_READ / _WRITE enforce wedged +
 *      read_only state at every public entry.
 *   3. Single-mutex serialization for mutating ops. Matches the
 *      stm_alloc / stm_sync shape below.
 *
 * This chunk does NOT yet auto-wedge on specific errors — callers
 * detecting consistency violations must call stm_fs_mark_wedged
 * themselves. Auto-wedging policy arrives alongside the crash fuzzer
 * (chunk 8).
 *
 * Lock hierarchy (held in this order, never reversed):
 *
 *   fs->lock   →  sync->lock  →  alloc->lock  →  alloc's btree rwlock
 *
 * Public stm_fs entries acquire fs->lock then dispatch; stm_sync_commit
 * nests stm_alloc_commit under sync->lock. Every reader-path inside
 * stm_fs (stats_get) acquires the same order. Do not add a path that
 * takes alloc->lock and then sync->lock — the commit path already owns
 * the reverse, and crossing lock orders deadlocks.
 */

#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/dataset.h>
#include <stratum/dirent.h>
#include <stratum/inode.h>
#include <stratum/janus.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/sync.h>

#include <sys/stat.h>            /* S_IFMT / S_IFREG / S_IFDIR */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* In-RAM state.                                                              */
/* ========================================================================= */

struct stm_fs {
    pthread_mutex_t lock;

    stm_bdev  *bdev;         /* owned — closed at unmount */
    stm_pool  *pool;         /* owned — P5-1 N=1 wrapper over bdev */
    stm_alloc *alloc;        /* owned */
    stm_sync  *sync;         /* owned */

    /* P7-13 R45 P2-1: mount-time wrap-key source. Exactly one is
     * non-NULL; both freed at unmount. Retained so
     * stm_fs_create_dataset uses the SAME wrap source as the rest of
     * the pool — passing a different keyfile/janus would silently
     * persist an unwrappable CURRENT entry that bricks the next
     * mount per R42 P1-1's hard-fail-on-CURRENT-unwrap-failure
     * policy. ARCH §7.7 frames wrap keys as pool-wide; per-call
     * overrides have no documented use case, so binding to the
     * mount source removes the footgun by construction. */
    char *keyfile_path;      /* owned */
    char *janus_socket;      /* owned */

    bool read_only;
    bool wedged;
};

/* Guard macros. MUST be called while holding fs->lock. On the refusal
 * path they UNLOCK fs->lock and return from the enclosing function.
 * The caller's happy path is responsible for its own unlock; the guard
 * only takes ownership of the unlock when it bails.
 *
 * R7e-P0-1: a prior revision returned without unlocking, which turned
 * the very next mutex acquisition (from any API, including unmount)
 * into a deadlock — the bug that the removed RO/wedged end-to-end
 * tests had been tripping over and that was misdiagnosed as a POSIX-
 * bdev thread-pool hang.                                                */
#define FS_GUARD_READ(fs) do {                                             \
    if ((fs)->wedged) {                                                    \
        pthread_mutex_unlock(&(fs)->lock);                                 \
        return STM_EWEDGED;                                                \
    }                                                                      \
} while (0)

#define FS_GUARD_WRITE(fs) do {                                            \
    if ((fs)->wedged) {                                                    \
        pthread_mutex_unlock(&(fs)->lock);                                 \
        return STM_EWEDGED;                                                \
    }                                                                      \
    if ((fs)->read_only) {                                                 \
        pthread_mutex_unlock(&(fs)->lock);                                 \
        return STM_EROFS;                                                  \
    }                                                                      \
} while (0)

/* ========================================================================= */
/* Format.                                                                    */
/* ========================================================================= */

/*
 * R7e-P1-1: zero every byte of every label region before the first
 * uberblock lands. Prevents a reformat-over-existing-pool from leaving
 * stale high-gen uberblocks that would beat the new gen=1 at
 * stm_sb_mount_scan, wedging the pool on the first commit.
 *
 * Writes 4 × STM_LABEL_SIZE (= 4 × 256 KiB = 1 MiB) of zeros and fsyncs
 * once before returning. The cost is negligible vs. the rest of format
 * and small vs. typical device sizes.
 */
static stm_status format_wipe_labels(stm_bdev *d, uint64_t device_bytes)
{
    uint64_t label_offsets[STM_LABELS_PER_DEVICE];
    stm_status s = stm_label_offsets(device_bytes, label_offsets);
    if (s != STM_OK) return s;

    void *zeros = calloc(1, STM_LABEL_SIZE);
    if (!zeros) return STM_ENOMEM;

    for (uint32_t li = 0; li < STM_LABELS_PER_DEVICE; li++) {
        s = stm_bdev_write(d, label_offsets[li], zeros, STM_LABEL_SIZE);
        if (s != STM_OK) { free(zeros); return s; }
    }
    free(zeros);

    /* Make the wipe durable before any real uberblock lands; otherwise
     * a crash between wipe and first sync_commit could leave both stale
     * and new UBs on media, the stale one winning. */
    return stm_bdev_fsync(d);
}

stm_status stm_fs_format(const char *path, const stm_fs_format_opts *opts)
{
    if (!path || !opts) return STM_EINVAL;
    /* P4-4a: keyfile is mandatory. */
    if (!opts->keyfile_path) return STM_EINVAL;

    /* Load wrap keys up-front so an unreadable keyfile fails BEFORE
     * we touch the pool device. */
    stm_hybrid_keys wk;
    stm_status ks = stm_keyfile_load(opts->keyfile_path, &wk);
    if (ks != STM_OK) return ks;

    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    stm_bdev *d = NULL;
    stm_status s = stm_bdev_open(path, &bopts, &d);
    if (s != STM_OK) { stm_hybrid_keys_wipe(&wk); return s; }

    /* Resize if the caller asked for it (typical for loopback files
     * that start empty). */
    if (opts->device_size_bytes > 0) {
        s = stm_bdev_resize(d, opts->device_size_bytes);
        if (s != STM_OK) { stm_bdev_close(d); stm_hybrid_keys_wipe(&wk); return s; }
    }

    /* Wipe label regions before anything else writes to them. See
     * format_wipe_labels doc. Uses the bdev's actual size (post-resize). */
    const stm_bdev_caps *caps = stm_bdev_caps_of(d);
    if (!caps) { stm_bdev_close(d); stm_hybrid_keys_wipe(&wk); return STM_EIO; }
    s = format_wipe_labels(d, caps->size_bytes);
    if (s != STM_OK) { stm_bdev_close(d); stm_hybrid_keys_wipe(&wk); return s; }

    stm_alloc *a = NULL;
    s = stm_alloc_create(d, opts->pool_uuid, opts->device_uuid,
                          opts->bootstrap_size_bytes, &a);
    if (s != STM_OK) { stm_bdev_close(d); stm_hybrid_keys_wipe(&wk); return s; }

    /* P5-1: degenerate 1-device pool. Role/class default to
     * DATA/SSD for MVP — P5-4 will surface these as admin knobs. */
    stm_pool_open_opts popts;
    memset(&popts, 0, sizeof popts);
    popts.pool_uuid[0] = opts->pool_uuid[0];
    popts.pool_uuid[1] = opts->pool_uuid[1];
    popts.device_count = 1;
    popts.devices[0].uuid[0]    = opts->device_uuid[0];
    popts.devices[0].uuid[1]    = opts->device_uuid[1];
    popts.devices[0].size_bytes = caps->size_bytes;
    popts.devices[0].role       = STM_DEV_ROLE_DATA;
    popts.devices[0].class_     = STM_DEV_CLASS_SSD;
    popts.devices[0].state      = STM_DEV_STATE_ONLINE;
    popts.devices[0].bdev       = d;
    stm_pool *pool = NULL;
    s = stm_pool_open(&popts, &pool);
    if (s != STM_OK) { stm_alloc_close(a); stm_bdev_close(d); stm_hybrid_keys_wipe(&wk); return s; }

    stm_sync *sync = NULL;
    s = stm_sync_create(pool, a, &wk, NULL, &sync);
    if (s != STM_OK) { stm_pool_close(pool); stm_alloc_close(a); stm_bdev_close(d); stm_hybrid_keys_wipe(&wk); return s; }

    /* First commit: lays down the initial uberblock at gen=1 so a
     * subsequent stm_fs_mount finds something to read. */
    s = stm_sync_commit(sync);
    if (s != STM_OK) {
        stm_sync_close(sync);
        stm_pool_close(pool);
        stm_alloc_close(a);
        stm_bdev_close(d);
        stm_hybrid_keys_wipe(&wk);      /* R10 P1-1 */
        return s;
    }

    /* Tidy close. The format does NOT leave an open handle — caller
     * must stm_fs_mount afterward. */
    stm_sync_close(sync);
    stm_pool_close(pool);
    stm_alloc_close(a);
    stm_bdev_close(d);
    stm_hybrid_keys_wipe(&wk);
    return STM_OK;
}

/* ========================================================================= */
/* Mount.                                                                     */
/* ========================================================================= */

static stm_fs *fs_new(stm_bdev *d, stm_pool *pool,
                       stm_alloc *a, stm_sync *sync, bool ro,
                       const char *keyfile_path,
                       const char *janus_socket)
{
    stm_fs *fs = calloc(1, sizeof *fs);
    if (!fs) return NULL;
    if (pthread_mutex_init(&fs->lock, NULL) != 0) {
        free(fs);
        return NULL;
    }
    if (keyfile_path) {
        fs->keyfile_path = strdup(keyfile_path);
        if (!fs->keyfile_path) {
            pthread_mutex_destroy(&fs->lock);
            free(fs);
            return NULL;
        }
    }
    if (janus_socket) {
        fs->janus_socket = strdup(janus_socket);
        if (!fs->janus_socket) {
            free(fs->keyfile_path);
            pthread_mutex_destroy(&fs->lock);
            free(fs);
            return NULL;
        }
    }
    fs->bdev      = d;
    fs->pool      = pool;
    fs->alloc     = a;
    fs->sync      = sync;
    fs->read_only = ro;
    fs->wedged    = false;
    return fs;
}

stm_status stm_fs_mount(const char *path,
                         const stm_fs_mount_opts *opts,
                         stm_fs **out_fs)
{
    if (!path || !opts || !out_fs) return STM_EINVAL;

    /* P4-4b: exactly one key source. */
    int have_kf = opts->keyfile_path != NULL;
    int have_jn = opts->janus_socket != NULL;
    if (have_kf == have_jn) return STM_EINVAL;

    stm_hybrid_keys   wk = {0};
    stm_janus_client *janus = NULL;

    if (have_kf) {
        stm_status ks = stm_keyfile_load(opts->keyfile_path, &wk);
        if (ks != STM_OK) return ks;
    } else {
        stm_status js = stm_janus_client_connect(opts->janus_socket, &janus);
        if (js != STM_OK) return js;
    }

    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    bopts.read_only = opts->read_only;
    stm_bdev *d = NULL;
    stm_status s = stm_bdev_open(path, &bopts, &d);
    if (s != STM_OK) {
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    /* P5-1: peek the durable uberblock to discover the pool's
     * roster (pool_uuid, per-device uuid / role / class / state),
     * then construct an stm_pool handle that MATCHES the UB. Sync
     * will validate the match; a mismatch means either programmer
     * error here or tampered roster bytes in the UB. */
    stm_uberblock peek_ub;
    {
        uint32_t peek_lbl = 0, peek_slot = 0;
        s = stm_sb_mount_scan(d, &peek_ub, &peek_lbl, &peek_slot);
        if (s != STM_OK) {
            stm_bdev_close(d);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return s;
        }
    }
    uint16_t peek_device_count = stm_load_le16(peek_ub.ub_device_count);
    uint16_t peek_device_id    = stm_load_le16(peek_ub.ub_device_id);
    if (peek_device_count == 0 ||
        peek_device_count > STM_POOL_DEVICES_MAX ||
        peek_device_id >= peek_device_count) {
        stm_bdev_close(d);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_ECORRUPT;
    }
    stm_pool_device peek_devs[STM_POOL_DEVICES_MAX];
    memset(peek_devs, 0, sizeof peek_devs);
    s = stm_pool_roster_decode(peek_ub.ub_roster, peek_device_count, peek_devs);
    if (s != STM_OK) {
        stm_bdev_close(d);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }
    /* Bind THIS bdev into the slot that matches its uuid (the UB's
     * ub_device_id). P5-2 generalizes this to multi-device path
     * resolution; P5-1 has only the one slot. */
    peek_devs[peek_device_id].bdev = d;

    stm_pool_open_opts popts;
    memset(&popts, 0, sizeof popts);
    popts.pool_uuid[0] = stm_load_le64(peek_ub.ub_pool_uuid[0]);
    popts.pool_uuid[1] = stm_load_le64(peek_ub.ub_pool_uuid[1]);
    popts.device_count = peek_device_count;
    for (size_t i = 0; i < peek_device_count; i++) {
        popts.devices[i] = peek_devs[i];
    }
    /* P5-1 N=1: slots other than peek_device_id won't have bdevs
     * assigned, but there ARE none. For P5-2 multi-device, caller
     * supplies a path list and we bind each bdev in the loop above. */
    stm_pool *pool = NULL;
    s = stm_pool_open(&popts, &pool);
    if (s != STM_OK) {
        stm_bdev_close(d);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    stm_alloc *a = NULL;
    s = stm_alloc_open_blank(d, &a);
    if (s != STM_OK) {
        stm_pool_close(pool);
        stm_bdev_close(d);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    stm_sync *sync = NULL;
    s = stm_sync_open(pool, a,
                        have_kf ? &wk : NULL,
                        have_jn ? janus : NULL,
                        &sync);
    if (s != STM_OK) {
        stm_alloc_close(a);
        stm_pool_close(pool);
        stm_bdev_close(d);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    stm_fs *fs = fs_new(d, pool, a, sync, opts->read_only,
                          opts->keyfile_path, opts->janus_socket);
    if (!fs) {
        stm_sync_close(sync);
        stm_alloc_close(a);
        stm_pool_close(pool);
        stm_bdev_close(d);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_ENOMEM;
    }

    *out_fs = fs;
    /* The raw DEK is already installed in the allocator's crypt ctx —
     * the client is no longer needed. Disconnect after sync_open; the
     * keyfile's hybrid_sk is also wiped now that unwrap is done. */
    stm_hybrid_keys_wipe(&wk);
    if (janus) stm_janus_client_disconnect(janus);
    return STM_OK;
}

/* ========================================================================= */
/* Unmount.                                                                   */
/* ========================================================================= */

stm_status stm_fs_unmount(stm_fs *fs)
{
    if (!fs) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);

    stm_status commit_status = STM_OK;
    if (!fs->read_only && !fs->wedged) {
        /* Final commit makes everything durable. Propagate its
         * status so the caller knows if the unmount lost data. */
        commit_status = stm_sync_commit(fs->sync);
    }

    /* Close the stack regardless of commit result. Order matters:
     * sync borrows pool; pool borrows bdev. Close inside-out. */
    stm_sync_close(fs->sync);
    stm_alloc_close(fs->alloc);
    stm_pool_close(fs->pool);
    stm_bdev_close(fs->bdev);

    pthread_mutex_unlock(&fs->lock);
    pthread_mutex_destroy(&fs->lock);
    free(fs->keyfile_path);
    free(fs->janus_socket);
    free(fs);

    return commit_status;
}

/* ========================================================================= */
/* Operations.                                                                */
/* ========================================================================= */

stm_status stm_fs_reserve(stm_fs *fs, uint64_t nblocks, uint64_t hint_paddr,
                           uint64_t *out_paddr)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_alloc_reserve(fs->alloc, nblocks, hint_paddr, out_paddr);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_free(stm_fs *fs, uint64_t paddr, uint64_t free_gen)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_alloc_free(fs->alloc, paddr, free_gen);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_commit(stm_fs *fs)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_sync_commit(fs->sync);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

/* P7-4: POSIX-shape extent write/read. Thin wrappers over the sync
 * layer's stm_sync_write_extent / stm_sync_read_extent.
 *
 * R36 P0-1 + P1-2: hold fs->lock through the inner sync call.
 * Releasing fs->lock between guard and sync invocation opened a
 * use-after-free race against concurrent stm_fs_unmount (which
 * destroys sync's mutex while the released-fs-lock window was
 * about to dereference it) and a wedge-state-guard race (a
 * stm_fs_mark_wedged in the released window let the write through).
 * Lock hierarchy fs.lock OUTER → sync.lock INNER (fs.c:25) permits
 * this; matches the existing reserve/free/commit pattern.
 *
 * P8-POSIX-5: extended with inline-data dispatch. When the (ds, ino)
 * names a regular file (S_IFREG) recorded in the inode index, the
 * write/read path branches on `iv.si_data_kind`:
 *   - STM_DATA_INLINE + write fits ≤ STM_INODE_INLINE_MAX:
 *       update si_inline_data + si_data_len + si_size in place.
 *   - STM_DATA_INLINE + write would grow past inline cap:
 *       transition to STM_DATA_EXTENT (one-way per inode.tla's
 *       OneWayInlineToExtent invariant) — flush existing inline
 *       prefix to the extent layer, then write new bytes through
 *       the extent layer, then update inode kind.
 *   - STM_DATA_EXTENT: delegate to stm_sync_write_extent + bump
 *       si_size if the write grew the file.
 * Reads invert the dispatch — INLINE reads memcpy from
 * si_inline_data, EXTENT reads delegate.
 *
 * For (ds, ino) tuples NOT in the inode index, OR for inodes with
 * `si_mode` not S_IFREG (directory / symlink / device / unknown),
 * the legacy direct-extent path is used. This keeps the older P7-era
 * tests (which write extent data at hardcoded ino numbers without
 * allocating an inode first) working.
 */

/* Update si_size if `end_off` (= write_off + write_len) extends the
 * file. Returns updated value. Caller persists via stm_inode_set. */
static void fs_inode_bump_size(struct stm_inode_value *iv, uint64_t end_off)
{
    uint64_t cur_size = stm_load_le64(iv->si_size);
    if (end_off > cur_size) iv->si_size = stm_store_le64(end_off);
}

/* Inline-aware write for S_IFREG inode `iv` at (ds, ino). On entry:
 * caller holds fs->lock; iv has already been loaded. On STM_OK
 * return: inode + extent layer are in sync. */
static stm_status fs_write_regular_locked(stm_fs *fs, stm_inode_index *iidx,
                                                uint64_t ds, uint64_t ino,
                                                struct stm_inode_value *iv,
                                                uint64_t off,
                                                const void *buf, size_t len)
{
    uint8_t kind = iv->si_data_kind;
    uint64_t end_off = off + (uint64_t)len;

    /* R77 P1-1 defense-in-depth: bound si_data_len by inline cap on
     * the read of the existing inline prefix (memcpy at the inline
     * fast-path's zero-fill + the transition path's combined-buffer
     * build). Decoder + stm_inode_set both reject oversize already
     * — this is belt-and-suspenders for any layer that bypassed
     * either guard. */
    if (kind == STM_DATA_INLINE && iv->si_data_len > STM_INODE_INLINE_MAX) {
        return STM_ECORRUPT;
    }

    if (kind == STM_DATA_INLINE) {
        if (end_off <= (uint64_t)STM_INODE_INLINE_MAX) {
            /* Inline fast path. Zero-fill any gap from current
             * data_len up to off, then memcpy new bytes. */
            uint8_t cur_len = iv->si_data_len;
            if (off > cur_len) {
                memset(iv->si_data.inline_data + cur_len, 0,
                       (size_t)(off - cur_len));
            }
            if (len > 0u) {
                memcpy(iv->si_data.inline_data + off, buf, len);
            }
            uint8_t new_len = (uint8_t)((end_off > cur_len) ? end_off : cur_len);
            iv->si_data_len = new_len;
            fs_inode_bump_size(iv, end_off);
            return stm_inode_set(iidx, ds, ino, iv);
        }

        /* Transition: build a single block-aligned combined buffer
         * (existing inline prefix + user's bytes overlaid + zero pad)
         * and write it as one stm_sync_write_extent call at offset 0.
         * This is necessary because the extent layer requires both
         * `off` and `len` to be 4 KiB aligned (sync.h §1042-1046),
         * which sub-block user writes typically aren't.
         *
         * Constraint: aligned_size must fit in a single
         * sync_write_extent call (≤ STM_FS_RECORDSIZE_MAX = 8 MiB).
         * Larger transitions return STM_ERANGE — caller can split
         * the user write into smaller chunks, the first of which
         * triggers the transition and subsequent chunks land in the
         * EXTENT path. */
        uint64_t cur_size = stm_load_le64(iv->si_size);
        uint64_t new_size = (end_off > cur_size) ? end_off : cur_size;
        if (new_size > (uint64_t)STM_FS_RECORDSIZE_MAX) return STM_ERANGE;

        const uint64_t BLK = 4096u;
        uint64_t aligned_size = (new_size + BLK - 1u) & ~(BLK - 1u);
        if (aligned_size == 0u) aligned_size = BLK;  /* always at least one block */

        uint8_t *combined = calloc(1, (size_t)aligned_size);
        if (!combined) return STM_ENOMEM;

        if (iv->si_data_len > 0u) {
            memcpy(combined, iv->si_data.inline_data, iv->si_data_len);
        }
        if (len > 0u) {
            memcpy(combined + off, buf, len);
        }

        stm_status fs1 = stm_sync_write_extent(fs->sync, ds, ino,
                                                    /*off=*/0u,
                                                    combined,
                                                    (size_t)aligned_size);
        free(combined);
        if (fs1 != STM_OK) return fs1;

        /* Flip kind = EXTENT. The si_size stays at the LOGICAL value
         * (new_size, not the block-padded aligned_size) so reads past
         * the logical EOF return 0 bytes, matching POSIX semantics.
         *
         * R76 P3-1 (theoretical-only): `stm_inode_set` cannot fail in
         * this lock posture. Every `STM_E*` return from set
         * presupposes a state mutation only the allocator / free path
         * can perform (gen bump, FREED transition, nlink=0 transition,
         * data_kind set to unknown). All those paths are mutex-
         * excluded by fs->lock. The args we pass are derived from a
         * lookup performed under the same fs->lock with no
         * intervening release. So the post-extent-write inconsistency
         * (extent has data, inode still INLINE) is unreachable today.
         * Future maintainers: if you add an alloc path that doesn't
         * take fs->lock, this assumption breaks. */
        iv->si_data_kind = STM_DATA_EXTENT;
        iv->si_data_len = 0;
        memset(&iv->si_data, 0, sizeof iv->si_data);
        iv->si_size = stm_store_le64(new_size);
        return stm_inode_set(iidx, ds, ino, iv);
    }

    if (kind == STM_DATA_EXTENT) {
        /* Pure extent path. */
        stm_status ws = stm_sync_write_extent(fs->sync, ds, ino, off, buf, len);
        if (ws != STM_OK) return ws;
        uint64_t cur_size = stm_load_le64(iv->si_size);
        if (end_off > cur_size) {
            iv->si_size = stm_store_le64(end_off);
            /* R76 P3-2: same infallibility argument as P3-1 — the
             * lock posture excludes every STM_E* path through
             * stm_inode_set. */
            return stm_inode_set(iidx, ds, ino, iv);
        }
        return STM_OK;
    }

    /* SYMLINK / DEVICE / unknown: regular-file write rejected. The
     * caller (FUSE / 9P binding) maps this to an appropriate POSIX
     * errno at the syscall boundary. */
    return STM_ENOTSUPPORTED;
}

/* Inline-aware read for S_IFREG inode `iv`. */
static stm_status fs_read_regular_locked(stm_fs *fs,
                                              uint64_t ds, uint64_t ino,
                                              const struct stm_inode_value *iv,
                                              uint64_t off,
                                              void *buf, size_t len,
                                              size_t *out_read)
{
    uint8_t kind = iv->si_data_kind;
    uint64_t cur_size = stm_load_le64(iv->si_size);

    /* R77 P1-1 defense-in-depth: bound si_data_len by inline cap on
     * INLINE reads. */
    if (kind == STM_DATA_INLINE && iv->si_data_len > STM_INODE_INLINE_MAX) {
        return STM_ECORRUPT;
    }

    if (kind == STM_DATA_INLINE) {
        if (off >= cur_size) {
            if (out_read) *out_read = 0;
            return STM_OK;
        }
        size_t avail = (size_t)(cur_size - off);
        size_t copy_n = (len < avail) ? len : avail;
        if (copy_n > 0u) memcpy(buf, iv->si_data.inline_data + off, copy_n);
        if (out_read) *out_read = copy_n;
        return STM_OK;
    }
    if (kind == STM_DATA_EXTENT) {
        /* R76 P2-1: clamp the EXTENT-mode read by si_size. The
         * combined-buffer transition path block-pads writes up to
         * the next 4 KiB boundary, so the extent layer holds zero-
         * padded bytes past the logical EOF; without this clamp,
         * `stm_sync_read_extent` would surface those padding bytes
         * as if they were file content, diverging from the INLINE
         * path's POSIX-EOF semantics (and from `read(2)`'s
         * "returns up to EOF" contract). */
        if (off >= cur_size) {
            if (out_read) *out_read = 0;
            return STM_OK;
        }
        stm_status rs = stm_sync_read_extent(fs->sync, ds, ino, off,
                                                buf, len, out_read);
        if (rs == STM_OK && out_read) {
            uint64_t logical_avail = cur_size - off;
            if ((uint64_t)*out_read > logical_avail) {
                *out_read = (size_t)logical_avail;
            }
        }
        return rs;
    }
    return STM_ENOTSUPPORTED;
}

stm_status stm_fs_write(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                          uint64_t off, const void *buf, size_t len)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    /* Inline-aware dispatch only when (a) inode index is bound, (b)
     * the (ds, ino) names a real inode in the index, and (c) the
     * inode is a regular file (S_IFREG). Otherwise fall through to
     * the legacy direct-extent path so older tests + non-regular-
     * file writers (e.g., the dataset metadata test seam) keep
     * working. */
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (iidx) {
        struct stm_inode_value iv = {0};
        stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
        if (ls == STM_OK) {
            uint32_t mode = stm_load_le32(iv.si_mode);
            if ((mode & (uint32_t)S_IFMT) == (uint32_t)S_IFREG) {
                stm_status rs = fs_write_regular_locked(fs, iidx,
                                                              dataset_id, ino,
                                                              &iv, off, buf, len);
                pthread_mutex_unlock(&fs->lock);
                return rs;
            }
            /* Not a regular file — fall through. */
        }
        /* Inode not found — fall through. */
    }

    stm_status s = stm_sync_write_extent(fs->sync, dataset_id, ino, off,
                                            buf, len);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_read(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                         uint64_t off, void *buf, size_t len,
                         size_t *out_read)
{
    /* R76 P3-3: zero-init out_read BEFORE arg validation per the
     * R57 P3-5 / R58 P3-1 uniform out-param contract. Callers that
     * observe on STM_EINVAL get a defined value (0). */
    if (out_read) *out_read = 0;
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_READ(fs);

    /* Same dispatch shape as fs_write. */
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (iidx) {
        struct stm_inode_value iv = {0};
        stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
        if (ls == STM_OK) {
            uint32_t mode = stm_load_le32(iv.si_mode);
            if ((mode & (uint32_t)S_IFMT) == (uint32_t)S_IFREG) {
                stm_status rs = fs_read_regular_locked(fs, dataset_id, ino,
                                                            &iv, off, buf, len,
                                                            out_read);
                pthread_mutex_unlock(&fs->lock);
                return rs;
            }
        }
    }

    stm_status s = stm_sync_read_extent(fs->sync, dataset_id, ino, off,
                                           buf, len, out_read);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

/* ========================================================================= */
/* POSIX directory + file ops (P8-POSIX-2b).                                  */
/* ========================================================================= */

/* Validate a dirent name per POSIX:
 *   - non-empty, ≤ 255 bytes
 *   - no NUL or '/' byte
 *   - "." and ".." are reserved (synthesized at the path-walk layer,
 *     never stored as dirents)
 *
 * Returns STM_EINVAL on any rule violation; STM_OK if the name is a
 * legal dirent label. */
static stm_status fs_validate_dirent_name(const uint8_t *name, uint8_t name_len)
{
    if (!name) return STM_EINVAL;
    if (name_len == 0u || name_len > 255u) return STM_EINVAL;
    for (uint8_t i = 0; i < name_len; i++) {
        if (name[i] == '/' || name[i] == '\0') return STM_EINVAL;
    }
    if (name_len == 1u && name[0] == '.') return STM_EINVAL;
    if (name_len == 2u && name[0] == '.' && name[1] == '.') return STM_EINVAL;
    return STM_OK;
}

/* Look up `parent_ino` and verify it's a directory (S_IFDIR). On
 * STM_OK, the parent's inode value is in *out_pv. Caller already
 * holds fs->lock. */
static stm_status fs_load_parent_dir(stm_inode_index *iidx,
                                          uint64_t dataset_id, uint64_t parent_ino,
                                          struct stm_inode_value *out_pv)
{
    stm_status ps = stm_inode_lookup(iidx, dataset_id, parent_ino, out_pv);
    if (ps != STM_OK) return ps;             /* STM_ENOENT if missing */
    uint32_t pmode = stm_load_le32(out_pv->si_mode);
    if ((pmode & (uint32_t)S_IFMT) != (uint32_t)S_IFDIR) return STM_ENOTDIR;
    return STM_OK;
}

stm_status stm_fs_lookup(stm_fs *fs, uint64_t dataset_id,
                            uint64_t parent_ino,
                            const uint8_t *name, uint8_t name_len,
                            uint64_t *out_child_ino)
{
    if (!fs || !out_child_ino) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;

    *out_child_ino = 0;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_READ(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ps;
    }

    uint64_t child_ino = 0;
    stm_status ds = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          &child_ino, NULL, NULL);
    pthread_mutex_unlock(&fs->lock);
    if (ds == STM_OK) *out_child_ino = child_ino;
    return ds;
}

/* Common path for create_file / mkdir. `child_mode_type` is S_IFREG
 * or S_IFDIR; `child_dt_type` is STM_DT_REG or STM_DT_DIR. Caller
 * has already validated the name + verified mode's S_IFMT bits are
 * either zero or match `child_mode_type`. */
static stm_status fs_create_inode_and_link(stm_fs *fs,
                                                uint64_t dataset_id,
                                                uint64_t parent_ino,
                                                const uint8_t *name,
                                                uint8_t name_len,
                                                uint32_t mode,
                                                uint32_t uid, uint32_t gid,
                                                uint32_t child_mode_type,
                                                uint8_t  child_dt_type,
                                                uint64_t *out_child_ino)
{
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ps;
    }

    /* Allocate the new inode. The wrapper composes file-type bits
     * over caller-supplied permission bits; if the caller passed
     * S_IFMT bits, they must agree with `child_mode_type`. */
    uint32_t full_mode = (mode & 07777u) | child_mode_type;
    uint64_t child_ino = 0;
    stm_status as = stm_inode_alloc(iidx, dataset_id, full_mode, uid, gid,
                                       &child_ino);
    if (as != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return as;
    }

    /* Read back the alloc'd inode's gen for the dirent's child_gen
     * field — `stm_inode_alloc` stamps gen via AllocFresh (=0) or
     * AllocReused (= prior_gen + 1); the dirent records this so
     * stale-fid detection works across the lifecycle. */
    struct stm_inode_value cv = {0};
    stm_status cs = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
    if (cs != STM_OK) {
        /* Defensive: should never happen right after alloc. Roll back. */
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        pthread_mutex_unlock(&fs->lock);
        return cs;
    }
    uint64_t child_gen = stm_load_le64(cv.si_gen);

    /* Link in parent. Roll back the inode if the dirent fails. */
    stm_status ds = stm_dirent_alloc(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          child_ino, child_gen, child_dt_type);
    if (ds != STM_OK) {
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        pthread_mutex_unlock(&fs->lock);
        return ds;
    }

    *out_child_ino = child_ino;
    pthread_mutex_unlock(&fs->lock);
    return STM_OK;
}

stm_status stm_fs_create_file(stm_fs *fs, uint64_t dataset_id,
                                  uint64_t parent_ino,
                                  const uint8_t *name, uint8_t name_len,
                                  uint32_t mode, uint32_t uid, uint32_t gid,
                                  uint64_t *out_child_ino)
{
    if (!fs || !out_child_ino) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;
    /* Caller's S_IFMT bits must be 0 or S_IFREG; any other type is a
     * mode/API mismatch. */
    uint32_t mtype = mode & (uint32_t)S_IFMT;
    if (mtype != 0u && mtype != (uint32_t)S_IFREG) return STM_EINVAL;
    *out_child_ino = 0;
    return fs_create_inode_and_link(fs, dataset_id, parent_ino,
                                       name, name_len, mode, uid, gid,
                                       (uint32_t)S_IFREG, STM_DT_REG,
                                       out_child_ino);
}

stm_status stm_fs_mkdir(stm_fs *fs, uint64_t dataset_id,
                            uint64_t parent_ino,
                            const uint8_t *name, uint8_t name_len,
                            uint32_t mode, uint32_t uid, uint32_t gid,
                            uint64_t *out_child_ino)
{
    if (!fs || !out_child_ino) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;
    uint32_t mtype = mode & (uint32_t)S_IFMT;
    if (mtype != 0u && mtype != (uint32_t)S_IFDIR) return STM_EINVAL;
    *out_child_ino = 0;
    return fs_create_inode_and_link(fs, dataset_id, parent_ino,
                                       name, name_len, mode, uid, gid,
                                       (uint32_t)S_IFDIR, STM_DT_DIR,
                                       out_child_ino);
}

/* Common path for unlink / rmdir. `expect_dir` selects the type
 * filter: true → child must be S_IFDIR (rmdir), false → child must
 * NOT be S_IFDIR (unlink). On the rmdir path the child must also be
 * empty (count_for_dir == 0). */
static stm_status fs_unlink_inode_and_dirent(stm_fs *fs,
                                                  uint64_t dataset_id,
                                                  uint64_t parent_ino,
                                                  const uint8_t *name,
                                                  uint8_t name_len,
                                                  bool expect_dir)
{
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ps;
    }

    /* Resolve child_ino via dirent lookup. */
    uint64_t child_ino = 0;
    stm_status ds = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          &child_ino, NULL, NULL);
    if (ds != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ds;       /* STM_ENOENT if not linked */
    }

    /* Verify type. Read child's inode for both type discrimination
     * AND the rmdir empty-check. */
    struct stm_inode_value cv = {0};
    stm_status cs = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
    if (cs != STM_OK) {
        /* Dirent points at a missing inode — corruption. Refuse rather
         * than silently unlink the dirent (which would orphan the
         * dirent's slot). The pool needs scrub-level recovery. */
        pthread_mutex_unlock(&fs->lock);
        return cs;
    }
    uint32_t cmode = stm_load_le32(cv.si_mode);
    bool child_is_dir = ((cmode & (uint32_t)S_IFMT) == (uint32_t)S_IFDIR);
    if (expect_dir && !child_is_dir) {
        pthread_mutex_unlock(&fs->lock);
        return STM_ENOTDIR;
    }
    if (!expect_dir && child_is_dir) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EISDIR;
    }
    if (expect_dir) {
        size_t n = 0;
        stm_status cn = stm_dirent_count_for_dir(didx, dataset_id, child_ino, &n);
        if (cn != STM_OK) {
            pthread_mutex_unlock(&fs->lock);
            return cn;
        }
        if (n != 0u) {
            pthread_mutex_unlock(&fs->lock);
            return STM_ENOTEMPTY;
        }
    }

    /* Unlink the dirent first so a concurrent lookup can no longer
     * resolve to the about-to-be-freed inode. Then decrement nlink;
     * cascade-free fires only on the last reference.
     *
     * P8-POSIX-3: nlink-aware. stm_inode_unlink decrements si_nlink;
     * if it reaches 0, the inode atomically transitions to FREED
     * via the cascade path (per inode.tla::Unlink). Hard links
     * (stm_fs_link) bump nlink past 1; unlinking one dirent
     * decrements but keeps the inode reachable via the other
     * dirent(s) until they too unlink. */
    stm_status us = stm_dirent_unlink(didx, dataset_id, parent_ino,
                                          name, name_len);
    if (us != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return us;
    }

    /* P8-POSIX-2b R73 P2-1: rmdir cleans up every record keyed under
     * the freed dir's ino — both live (none, by the empty-check above)
     * and tombstones from prior unlinks of the dir's children. Without
     * this, a directory with churn (create-then-unlink across many
     * entries) leaves tombstones in the btree that survive rmdir. If
     * the dir's ino is later reused via AllocReused (with bumped
     * si_gen per inode.tla), the new directory inherits the orphan
     * tombstones and burns probe budget walking past them. The
     * cleanup is best-effort — a failure leaves the orphan tombstones
     * behind but doesn't break the rmdir's correctness.
     *
     * For directories at P8-POSIX-3: directories themselves should
     * never have nlink > 1 (POSIX hard-link-on-dir is forbidden), so
     * unlink-of-dir always cascade-frees on the rmdir path. */
    if (expect_dir) {
        (void)stm_dirent_drop_for_dir(didx, dataset_id, child_ino, NULL);
    }

    /* P8-POSIX-3: nlink-aware unlink. Decrement nlink; cascade-free
     * triggers atomically when nlink reaches 0. For the MVP-single-
     * link case (no hard links yet, every alloc has nlink=1) this
     * always cascades — same observable outcome as the prior
     * unconditional stm_inode_free, but with the nlink semantics
     * that hard-link-aware paths require. */
    bool freed = false;
    (void)stm_inode_unlink(iidx, dataset_id, child_ino, &freed);

    pthread_mutex_unlock(&fs->lock);
    return STM_OK;
}

stm_status stm_fs_unlink(stm_fs *fs, uint64_t dataset_id,
                            uint64_t parent_ino,
                            const uint8_t *name, uint8_t name_len)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;
    return fs_unlink_inode_and_dirent(fs, dataset_id, parent_ino,
                                          name, name_len,
                                          /*expect_dir=*/false);
}

stm_status stm_fs_rmdir(stm_fs *fs, uint64_t dataset_id,
                           uint64_t parent_ino,
                           const uint8_t *name, uint8_t name_len)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;
    return fs_unlink_inode_and_dirent(fs, dataset_id, parent_ino,
                                          name, name_len,
                                          /*expect_dir=*/true);
}

/* ========================================================================= */
/* P8-POSIX-3: metadata ops + hard links.                                     */
/* ========================================================================= */

stm_status stm_fs_stat(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                          struct stm_inode_value *out_value)
{
    if (!fs || !out_value) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_READ(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }
    stm_status s = stm_inode_lookup(iidx, dataset_id, ino, out_value);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_chmod(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                           uint32_t mode)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value v = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &v);
    if (ls != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ls;
    }
    /* Preserve the existing file-type bits. Caller may pass either a
     * mode with type bits zeroed (preserve current) or a mode that
     * matches the existing type. Mismatched type bits are rejected. */
    uint32_t cur_mode = stm_load_le32(v.si_mode);
    uint32_t cur_type = cur_mode & (uint32_t)S_IFMT;
    uint32_t new_type = mode & (uint32_t)S_IFMT;
    if (new_type != 0u && new_type != cur_type) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }
    uint32_t new_mode = cur_type | (mode & 07777u);
    v.si_mode = stm_store_le32(new_mode);

    stm_status ss = stm_inode_set(iidx, dataset_id, ino, &v);
    pthread_mutex_unlock(&fs->lock);
    return ss;
}

stm_status stm_fs_chown(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                           uint32_t uid, uint32_t gid)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value v = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &v);
    if (ls != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ls;
    }
    /* POSIX chown(-1, ...) semantics: UINT32_MAX leaves the field
     * unchanged. Both UINT32_MAX is a no-op. */
    if (uid != UINT32_MAX) v.si_uid = stm_store_le32(uid);
    if (gid != UINT32_MAX) v.si_gid = stm_store_le32(gid);

    stm_status ss = stm_inode_set(iidx, dataset_id, ino, &v);
    pthread_mutex_unlock(&fs->lock);
    return ss;
}

stm_status stm_fs_utimens(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              uint64_t atime_sec, uint32_t atime_nsec,
                              uint64_t mtime_sec, uint32_t mtime_nsec,
                              uint64_t ctime_sec, uint32_t ctime_nsec)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (atime_nsec >= 1000000000u || mtime_nsec >= 1000000000u ||
        ctime_nsec >= 1000000000u) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value v = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &v);
    if (ls != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ls;
    }
    v.si_atime_sec  = stm_store_le64(atime_sec);
    v.si_atime_nsec = stm_store_le32(atime_nsec);
    v.si_mtime_sec  = stm_store_le64(mtime_sec);
    v.si_mtime_nsec = stm_store_le32(mtime_nsec);
    /* POSIX semantics: ctime is updated to "now" on metadata change.
     * Without an in-tree clock yet, the wrapper requires the caller
     * to pass ctime explicitly; pass 0/0 to leave unchanged.
     * P8-POSIX-7's `statx` integration will replace this with an
     * automatic clock-source. */
    if (ctime_sec != 0u || ctime_nsec != 0u) {
        v.si_ctime_sec  = stm_store_le64(ctime_sec);
        v.si_ctime_nsec = stm_store_le32(ctime_nsec);
    }

    stm_status ss = stm_inode_set(iidx, dataset_id, ino, &v);
    pthread_mutex_unlock(&fs->lock);
    return ss;
}

stm_status stm_fs_link(stm_fs *fs, uint64_t dataset_id,
                          uint64_t src_parent_ino,
                          const uint8_t *src_name, uint8_t src_name_len,
                          uint64_t dst_parent_ino,
                          const uint8_t *dst_name, uint8_t dst_name_len)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || src_parent_ino == 0u || dst_parent_ino == 0u)
        return STM_EINVAL;
    stm_status nv1 = fs_validate_dirent_name(src_name, src_name_len);
    if (nv1 != STM_OK) return nv1;
    stm_status nv2 = fs_validate_dirent_name(dst_name, dst_name_len);
    if (nv2 != STM_OK) return nv2;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    /* Both parents must be directories. */
    struct stm_inode_value spv = {0};
    stm_status ps1 = fs_load_parent_dir(iidx, dataset_id, src_parent_ino, &spv);
    if (ps1 != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ps1;
    }
    /* If src and dst share parent, skip the second lookup; otherwise
     * verify dst parent is also a directory. */
    if (dst_parent_ino != src_parent_ino) {
        struct stm_inode_value dpv = {0};
        stm_status ps2 = fs_load_parent_dir(iidx, dataset_id, dst_parent_ino, &dpv);
        if (ps2 != STM_OK) {
            pthread_mutex_unlock(&fs->lock);
            return ps2;
        }
    }

    /* Resolve src dirent → child_ino. */
    uint64_t child_ino = 0;
    uint64_t child_gen = 0;
    uint8_t  child_type = 0;
    stm_status ds = stm_dirent_lookup(didx, dataset_id, src_parent_ino,
                                          src_name, src_name_len,
                                          &child_ino, &child_gen, &child_type);
    if (ds != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ds;     /* STM_ENOENT if src not linked */
    }

    /* POSIX forbids hard-link-on-directory. STM_ENOTSUPPORTED maps to
     * EPERM at the 9P/FUSE syscall-binding layer (R74 P3-2: types.h
     * does not currently define STM_EPERM; STM_ENOTSUPPORTED is the
     * closest existing code). */
    if (child_type == STM_DT_DIR) {
        pthread_mutex_unlock(&fs->lock);
        return STM_ENOTSUPPORTED;
    }

    /* Bump nlink first; rollback if dirent install fails. */
    stm_status ils = stm_inode_link(iidx, dataset_id, child_ino);
    if (ils != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ils;
    }
    stm_status das = stm_dirent_alloc(didx, dataset_id, dst_parent_ino,
                                          dst_name, dst_name_len,
                                          child_ino, child_gen, child_type);
    if (das != STM_OK) {
        /* Rollback the nlink bump. The unlink path's cascade-free
         * doesn't fire here because nlink was just bumped above 1.
         * R74 P3-3 forward-note: the rollback's `(void)`-cast on
         * stm_inode_unlink could theoretically swallow a STM_ECORRUPT
         * (nlink underflow). Under fs->lock held throughout, the
         * rollback can't actually fail — child_ino was just looked
         * up + linked above, so it's still ALLOCATED with nlink ≥ 2.
         * If the unreachable failure ever triggers, future-us should
         * stm_fs_mark_wedged the volume, since it indicates load-
         * bearing-invariant corruption (LinkedAllocatedHasPositiveNlink
         * from inode.tla). */
        bool freed_unused = false;
        (void)stm_inode_unlink(iidx, dataset_id, child_ino, &freed_unused);
        pthread_mutex_unlock(&fs->lock);
        return das;       /* STM_EEXIST if name already linked, etc. */
    }

    pthread_mutex_unlock(&fs->lock);
    return STM_OK;
}

/* ========================================================================= */
/* P8-POSIX-8: symlinks.                                                      */
/* ========================================================================= */

stm_status stm_fs_symlink(stm_fs *fs, uint64_t dataset_id,
                              uint64_t parent_ino,
                              const uint8_t *name, uint8_t name_len,
                              const uint8_t *target, uint16_t target_len,
                              uint32_t uid, uint32_t gid,
                              uint64_t *out_child_ino)
{
    /* R77 P3-1: zero-init out_child_ino BEFORE arg validation per
     * the R57 P3-5 / R76 P3-3 uniform out-param contract. */
    if (out_child_ino) *out_child_ino = 0;

    if (!fs || !out_child_ino) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;

    /* Validate target. Empty targets rejected per Linux symlink(2)
     * semantics ("symlink: target must be a non-empty string"). */
    if (!target) return STM_EINVAL;
    if (target_len == 0u) return STM_EINVAL;
    if (target_len > (uint16_t)STM_INODE_INLINE_MAX) return STM_ENAMETOOLONG;
    /* No NUL byte — symlink targets are paths (C-string-shaped); a
     * mid-string NUL would prematurely terminate them on read. */
    for (uint16_t i = 0; i < target_len; i++) {
        if (target[i] == 0u) return STM_EINVAL;
    }

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ps;
    }

    /* Allocate inode with mode = S_IFLNK | 0777 (POSIX convention —
     * symlink permission bits unused by the kernel; the resolved
     * target's perms gate access). */
    uint32_t full_mode = (uint32_t)S_IFLNK | 0777u;
    uint64_t child_ino = 0;
    stm_status as = stm_inode_alloc(iidx, dataset_id, full_mode, uid, gid,
                                       &child_ino);
    if (as != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return as;
    }

    /* Stamp the symlink target into the inode's data union. The
     * allocator left si_data_kind=STM_DATA_INLINE + si_data_len=0;
     * we override to SYMLINK + target_len + bytes. */
    struct stm_inode_value cv = {0};
    stm_status cs = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
    if (cs != STM_OK) {
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        pthread_mutex_unlock(&fs->lock);
        return cs;
    }
    cv.si_data_kind = STM_DATA_SYMLINK;
    cv.si_data_len  = (uint8_t)target_len;
    memset(&cv.si_data, 0, sizeof cv.si_data);
    memcpy(cv.si_data.symlink_target, target, (size_t)target_len);
    cv.si_size = stm_store_le64((uint64_t)target_len);
    stm_status sse = stm_inode_set(iidx, dataset_id, child_ino, &cv);
    if (sse != STM_OK) {
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        pthread_mutex_unlock(&fs->lock);
        return sse;
    }

    uint64_t child_gen = stm_load_le64(cv.si_gen);

    /* Link in parent. Roll back on failure. */
    stm_status ds = stm_dirent_alloc(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          child_ino, child_gen, STM_DT_LNK);
    if (ds != STM_OK) {
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        pthread_mutex_unlock(&fs->lock);
        return ds;
    }

    *out_child_ino = child_ino;
    pthread_mutex_unlock(&fs->lock);
    return STM_OK;
}

stm_status stm_fs_readlink(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              uint8_t *target_buf, size_t target_max,
                              size_t *out_len)
{
    /* Uniform out-param contract (R57 P3-5 / R58 P3-1): zero-init
     * BEFORE arg validation. */
    if (out_len) *out_len = 0;

    if (!fs || !target_buf || !out_len) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (target_max == 0u) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_READ(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ls;       /* STM_ENOENT */
    }

    uint32_t mode = stm_load_le32(iv.si_mode);
    if ((mode & (uint32_t)S_IFMT) != (uint32_t)S_IFLNK) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;       /* POSIX EINVAL on non-symlink readlink */
    }
    if (iv.si_data_kind != STM_DATA_SYMLINK) {
        /* Decoder-vs-mode mismatch: the inode says S_IFLNK but the
         * data union doesn't carry SYMLINK bytes. Treat as corrupt. */
        pthread_mutex_unlock(&fs->lock);
        return STM_ECORRUPT;
    }
    /* R77 P1-1 defense-in-depth: even though `stm_inode_set` and
     * `in_decode_value` now both bound si_data_len ≤
     * STM_INODE_INLINE_MAX for SYMLINK records, the reader checks
     * before the memcpy so a hypothetical bypass at either layer
     * (test seam, future refactor) can't OOB-read the union. */
    if (iv.si_data_len > STM_INODE_INLINE_MAX) {
        pthread_mutex_unlock(&fs->lock);
        return STM_ECORRUPT;
    }

    size_t actual_len = (size_t)iv.si_data_len;
    size_t copy_n = (target_max < actual_len) ? target_max : actual_len;
    if (copy_n > 0u) memcpy(target_buf, iv.si_data.symlink_target, copy_n);
    *out_len = actual_len;       /* full length, even if truncated */

    pthread_mutex_unlock(&fs->lock);
    return STM_OK;
}

/* ========================================================================= */
/* P8-POSIX-4: stm_fs_readdir.                                                */
/* ========================================================================= */

/* Synthesize a "." or ".." entry into out_entries[idx]. dot_kind = 1
 * for "." (single dot), 2 for ".." (double dot). The synthesized
 * child_ino is caller-provided (`dir_ino` for ".", `parent_ino` for
 * ".."). child_gen = 0 (synth entries never go stale; the dir's own
 * inode owns the gen bump). child_type = STM_DT_DIR. */
static void fs_readdir_synth_dot(stm_fs_dirent_entry *out_entry,
                                      uint64_t child_ino, uint8_t dot_kind)
{
    memset(out_entry, 0, sizeof *out_entry);
    out_entry->child_ino  = child_ino;
    out_entry->child_gen  = 0;
    out_entry->child_type = STM_DT_DIR;
    out_entry->name_len   = dot_kind;
    out_entry->name[0]    = '.';
    if (dot_kind == 2u) out_entry->name[1] = '.';
}

stm_status stm_fs_readdir(stm_fs *fs, uint64_t dataset_id,
                              uint64_t dir_ino, uint64_t parent_ino,
                              uint32_t flags,
                              uint64_t *cursor,
                              stm_fs_dirent_entry *out_entries,
                              size_t max_entries,
                              size_t *out_returned)
{
    /* R75 P3-1: zero-init out-param BEFORE arg validation per the
     * uniform R57 P3-5 / R58 P3-1 out-param contract. */
    if (out_returned) *out_returned = 0;

    if (!fs || !cursor || !out_entries || !out_returned) return STM_EINVAL;
    if (dataset_id == 0u || dir_ino == 0u || parent_ino == 0u) return STM_EINVAL;
    if (max_entries == 0u) return STM_EINVAL;
    /* Reject unknown flag bits (forward-compat guard). */
    if ((flags & ~(uint32_t)STM_FS_READDIR_FLAG_NO_DOTS) != 0u) return STM_EINVAL;

    /* R75 P2-1: cursor saturation sentinel. Mirror of the dirent-layer
     * guard — short-circuit the call when the cursor has already
     * saturated to UINT64_MAX from a prior emit at the maximum
     * representable probe. Without this, the dirent-layer's
     * underlying filter would re-emit a hostile record at
     * UINT64_MAX. */
    if (*cursor == UINT64_MAX) return STM_OK;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_READ(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_EINVAL;
    }

    /* Validate dir_ino exists + is a directory. */
    struct stm_inode_value dv = {0};
    stm_status ds = fs_load_parent_dir(iidx, dataset_id, dir_ino, &dv);
    if (ds != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        return ds;
    }

    bool no_dots = (flags & STM_FS_READDIR_FLAG_NO_DOTS) != 0u;
    uint64_t local_cursor = *cursor;
    size_t emitted = 0;

    /* Phase 0: emit "." (or skip + advance). */
    if (local_cursor == 0u) {
        if (!no_dots) {
            if (emitted < max_entries) {
                fs_readdir_synth_dot(&out_entries[emitted], dir_ino, 1);
                emitted++;
                local_cursor = 1u;
            }
            /* If max_entries == 0 we'd have rejected above; the
             * "no advance" branch isn't reachable. */
        } else {
            local_cursor = 1u;
        }
    }

    /* Phase 1: emit ".." (or skip + advance). */
    if (local_cursor == 1u) {
        if (!no_dots) {
            if (emitted < max_entries) {
                fs_readdir_synth_dot(&out_entries[emitted], parent_ino, 2);
                emitted++;
                local_cursor = 2u;
            }
        } else {
            local_cursor = 2u;
        }
    }

    /* Phase 2+: stored dirents. */
    if (local_cursor >= 2u && emitted < max_entries) {
        /* Subtract the synth-phase offset to reach the dirent layer's
         * cursor space. */
        uint64_t dirent_cursor = local_cursor - 2u;
        size_t dirent_max = max_entries - emitted;

        /* Heap-allocate the temp dirent batch — caller's max_entries
         * × ~280 bytes per stm_dirent_entry can be a few KB to many
         * MB; the readdir uses STM_FS_READDIR's max_entries minus the
         * already-emitted dot count, so the heap_alloc here matches
         * the caller's space discipline. */
        if (dirent_max > SIZE_MAX / sizeof(stm_dirent_entry)) {
            pthread_mutex_unlock(&fs->lock);
            return STM_ENOMEM;
        }
        stm_dirent_entry *batch = malloc(dirent_max * sizeof *batch);
        if (!batch) {
            pthread_mutex_unlock(&fs->lock);
            return STM_ENOMEM;
        }

        size_t batch_n = 0;
        stm_status rs = stm_dirent_readdir(didx, dataset_id, dir_ino,
                                              &dirent_cursor, batch, dirent_max,
                                              &batch_n);
        if (rs != STM_OK) {
            free(batch);
            pthread_mutex_unlock(&fs->lock);
            return rs;
        }

        /* Copy into out_entries. */
        for (size_t k = 0; k < batch_n; k++) {
            /* R75 P3-4: defense-in-depth name_len bound at the
             * fs.c → dirent.c trust boundary (R71 P1-1 lesson —
             * symmetric guards across trust boundaries). The dirent
             * decoder + alloc paths already reject name_len >
             * STM_DIRENT_NAME_MAX, so reaching this branch implies
             * a buggy refactor of the dirent layer. Treat as
             * STM_ECORRUPT defensively rather than memcpy past the
             * out-buffer's name[] array (which would be a stack
             * overrun in caller-allocated batch[] storage). */
            if (batch[k].name_len > STM_DIRENT_NAME_MAX) {
                free(batch);
                pthread_mutex_unlock(&fs->lock);
                return STM_ECORRUPT;
            }
            out_entries[emitted].child_ino  = batch[k].child_ino;
            out_entries[emitted].child_gen  = batch[k].child_gen;
            out_entries[emitted].child_type = batch[k].child_type;
            out_entries[emitted].name_len   = batch[k].name_len;
            memset(out_entries[emitted].name, 0, sizeof out_entries[emitted].name);
            if (batch[k].name_len > 0u)
                memcpy(out_entries[emitted].name, batch[k].name,
                          batch[k].name_len);
            emitted++;
        }
        free(batch);

        /* Translate dirent-layer cursor back into fs-layer cursor.
         * Saturate at UINT64_MAX so wraparound doesn't reset the
         * iteration in pathological cases. */
        if (dirent_cursor > UINT64_MAX - 2u) {
            local_cursor = UINT64_MAX;
        } else {
            local_cursor = dirent_cursor + 2u;
        }
    }

    *cursor = local_cursor;
    *out_returned = emitted;
    pthread_mutex_unlock(&fs->lock);
    return STM_OK;
}

/* P7-16: stm_fs_reflink. POSIX-shape FICLONE — replaces dst's empty
 * extent tree with a reflink-share of src's. Holds fs->lock across the
 * inner sync_reflink so a concurrent observer can't see a partial
 * dst. Errors propagate from stm_sync_reflink. */
stm_status stm_fs_reflink(stm_fs *fs,
                            uint64_t src_dataset_id, uint64_t src_ino,
                            uint64_t dst_dataset_id, uint64_t dst_ino)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_sync_reflink(fs->sync,
                                       src_dataset_id, src_ino,
                                       dst_dataset_id, dst_ino);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

/* P7-CAS-2: stm_fs_migrate_to_cold. Holds fs->lock across the inner
 * sync_migrate_to_cold so a concurrent observer never sees a partial
 * (some-hot-some-cold) state for the file. Errors propagate from
 * stm_sync_migrate_to_cold. */
stm_status stm_fs_migrate_to_cold(stm_fs *fs,
                                     uint64_t dataset_id, uint64_t ino)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_sync_migrate_to_cold(fs->sync, dataset_id, ino);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

/* P7-CAS-7: stm_fs_migrate_policy_step. v1 age-based migration-policy
 * primitive. Composes over stm_fs_migrate_to_cold — selects HOT inos
 * via stm_sync_migrate_policy_collect under fs->lock, drops fs->lock,
 * then calls stm_fs_migrate_to_cold per candidate (which re-takes the
 * lock fresh). The drop-between-candidates pattern means concurrent
 * writers / admin calls can interleave, which is intentional: a long
 * migration pass should not block the rest of the FS for its
 * duration.
 *
 * Concurrency drift between collect and per-ino migrate is benign:
 * already-migrated and deleted inos resolve to STM_OK no-ops. New
 * HOT writes between collect and migrate just mean the migrated set
 * is larger than the snapshot; bytes_migrated is approximate as
 * documented.
 *
 * Hard errors (STM_EWEDGED / STM_EROFS / STM_ENOMEM) abort the pass
 * and bubble up. Soft errors (STM_EBADTAG, STM_EIO, STM_ENOSPC,
 * STM_ECORRUPT) are recorded in last_err/last_err_ino and the pass
 * continues — a single corrupt file should not stall the whole tier.
 * The first soft error wins the last_err slot; subsequent errors are
 * silently swallowed (they're not the cause of the pass's outcome,
 * just incidental).
 */
stm_status stm_fs_migrate_policy_step(stm_fs *fs,
                                          uint64_t dataset_id,
                                          const stm_fs_migrate_policy_params *params,
                                          stm_fs_migrate_policy_stats *out_stats)
{
    /* R58 P3-1: zero-init out_stats BEFORE arg validation so a caller
     * observing on any STM_EINVAL early-return sees a defined value
     * (matches the documented contract). The previous order initted
     * AFTER the validation, leaving out_stats as garbage on the
     * dataset_id==0 path despite the comment claiming otherwise. */
    if (out_stats) *out_stats = (stm_fs_migrate_policy_stats){0};
    if (!fs || !params)         return STM_EINVAL;
    if (dataset_id == 0u)       return STM_EINVAL;
    /* R58 P3-7: reject non-zero `_reserved0` so the field stays
     * exclusively owned by future-version semantics. A caller passing
     * uninitialized stack memory could otherwise pre-commit to
     * arbitrary new behavior the day this field becomes meaningful;
     * locking it down today keeps forward-compat clean. */
    if (params->_reserved0 != 0u) return STM_EINVAL;

    stm_fs_migrate_policy_stats local_stats = {0};
    stm_fs_migrate_policy_stats *stats = out_stats ? out_stats : &local_stats;

    /* Step 1: take fs->lock, run the wedged/RO guards (RO is a hard
     * refusal — the policy mutates state), read current_gen, compute
     * cutoff, run the collect. Drop fs->lock. */
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    uint64_t cur_gen = stm_sync_current_gen(fs->sync);
    /* Saturating subtraction: if min_age >= cur_gen, no live extent's
     * link_gen (>= 1 for any real extent) qualifies. Use cutoff = 0
     * which excludes everything (link_gen >= 1 by the index's
     * BirthTxgBound). */
    uint64_t cutoff = (params->min_age_txgs >= cur_gen)
                        ? 0u
                        : (cur_gen - params->min_age_txgs);

    stm_sync_migrate_candidate *cands = NULL;
    size_t   n_cands       = 0u;
    uint64_t inos_visited  = 0u;
    stm_status cs = stm_sync_migrate_policy_collect(fs->sync, dataset_id,
                                                       cutoff,
                                                       &cands, &n_cands,
                                                       &inos_visited);
    pthread_mutex_unlock(&fs->lock);

    if (cs != STM_OK) {
        /* On collect failure, stats reflect zero work — leave the
         * struct zeroed. cands is guaranteed NULL on failure per
         * the collect contract. */
        return cs;
    }

    stats->inos_visited  = inos_visited;
    stats->inos_eligible = (uint64_t)n_cands;

    /* Step 2: walk candidates, applying budgets. Each per-ino migrate
     * re-takes fs->lock fresh — interleaved writers / admin calls
     * may proceed between candidates. */
    for (size_t i = 0; i < n_cands; i++) {
        if (params->max_inos != 0u
            && stats->inos_migrated >= (uint64_t)params->max_inos) break;
        if (params->max_bytes != 0u
            && stats->bytes_migrated >= params->max_bytes) break;

        uint64_t ino   = cands[i].ino;
        uint64_t bytes = cands[i].bytes;
        stm_status one = stm_fs_migrate_to_cold(fs, dataset_id, ino);
        if (one == STM_OK) {
            stats->inos_migrated++;
            stats->bytes_migrated += bytes;
            continue;
        }
        /* Hard errors abort the pass — propagate to caller. R58 P3-4:
         * also stamp last_err / last_err_ino so the operator sees
         * which ino's migration triggered the abort. The hard-error
         * return overrides any prior soft-error recording. */
        if (one == STM_EWEDGED || one == STM_EROFS || one == STM_ENOMEM) {
            stats->last_err     = one;
            stats->last_err_ino = ino;
            free(cands);
            return one;
        }
        /* Soft error: record first, continue. */
        if (stats->last_err == STM_OK) {
            stats->last_err     = one;
            stats->last_err_ino = ino;
        }
    }

    free(cands);
    return STM_OK;
}

/* P7-CAS-8: dataset-id collector for the pass-all wrapper. Filled
 * during stm_dataset_iter (which holds the dataset_index mutex);
 * the cb cannot recurse into stm_dataset_*, so property resolution
 * happens AFTER the iter returns. Geometric-grow buffer matches the
 * P7-CAS-7 candidate-list pattern. */
typedef struct {
    uint64_t  *ids;
    size_t     n;
    size_t     cap;
    stm_status err;
} pass_all_id_collect_ctx;

static bool pass_all_id_collect_cb(const stm_dataset_entry *e, void *ctx) {
    pass_all_id_collect_ctx *c = ctx;
    if (c->n == c->cap) {
        size_t new_cap = (c->cap == 0u) ? 16u : c->cap * 2u;
        uint64_t *grown = realloc(c->ids, new_cap * sizeof *grown);
        if (!grown) { c->err = STM_ENOMEM; return false; }
        c->ids = grown;
        c->cap = new_cap;
    }
    c->ids[c->n++] = e->id;
    return true;
}

stm_status stm_fs_migrate_policy_pass_all(
        stm_fs *fs,
        const stm_fs_migrate_policy_params *params,
        stm_fs_migrate_policy_pass_all_stats *out_stats)
{
    /* Uniform out-param contract: zero-init BEFORE arg validation
     * (R57 P3-5 / R58 P3-1) so a caller observing on EINVAL sees
     * defined values. */
    if (out_stats) *out_stats = (stm_fs_migrate_policy_pass_all_stats){0};
    if (!fs || !params)              return STM_EINVAL;
    if (params->_reserved0 != 0u)    return STM_EINVAL;

    stm_fs_migrate_policy_pass_all_stats local_stats = {0};
    stm_fs_migrate_policy_pass_all_stats *stats = out_stats ? out_stats : &local_stats;

    /* Phase 1: under fs->lock, enumerate every PRESENT dataset id,
     * then resolve effective STM_PROP_TIERING per id. The iter
     * cb cannot call back into stm_dataset_*, so property
     * resolution runs AFTER iter returns (still under fs->lock so
     * the dataset_index handle stays stable). Filter compacts the
     * id array in-place: enabled ids occupy [0, enabled_n). */
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *idx = stm_sync_dataset_index(fs->sync);
    pass_all_id_collect_ctx ctx = { .err = STM_OK };
    stm_status its = stm_dataset_iter(idx, pass_all_id_collect_cb, &ctx);
    if (its != STM_OK || ctx.err != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        free(ctx.ids);
        return (ctx.err != STM_OK) ? ctx.err : its;
    }

    size_t enabled_n = 0;
    stm_status filter_err = STM_OK;
    for (size_t i = 0; i < ctx.n; i++) {
        uint64_t v = 0;
        stm_status pe = stm_dataset_effective_property(
                idx, ctx.ids[i], STM_PROP_TIERING, &v);
        if (pe != STM_OK) {
            /* A dataset destroyed between iter and this call would
             * surface as STM_ENOENT here; record once and continue. */
            if (filter_err == STM_OK) filter_err = pe;
            continue;
        }
        if (v != 0u) {
            ctx.ids[enabled_n++] = ctx.ids[i];
        }
    }
    pthread_mutex_unlock(&fs->lock);

    stats->datasets_visited  = (uint64_t)ctx.n;
    stats->datasets_eligible = (uint64_t)enabled_n;
    if (filter_err != STM_OK) {
        stats->last_err = filter_err;
        /* No specific dataset id pinned — `last_err_dataset_id` stays
         * 0 to signal "phase-2 resolution error, not a per-step
         * error." */
    }

    /* Phase 2: per-dataset migrate, with SHARED budget. Adjust
     * per-step caps by the running total before each call. */
    for (size_t i = 0; i < enabled_n; i++) {
        if (params->max_inos != 0u
            && stats->inos_migrated >= (uint64_t)params->max_inos) break;
        if (params->max_bytes != 0u
            && stats->bytes_migrated >= params->max_bytes) break;

        stm_fs_migrate_policy_params adj = *params;
        if (adj.max_inos != 0u) {
            /* R59 P3-3: pre-loop check above guarantees
             * stats->inos_migrated < params->max_inos, so the
             * subtraction is positive and bounded by uint32_t —
             * no width-saturation needed. */
            adj.max_inos =
                    (uint32_t)((uint64_t)params->max_inos - stats->inos_migrated);
        }
        if (adj.max_bytes != 0u) {
            adj.max_bytes = params->max_bytes - stats->bytes_migrated;
        }

        uint64_t ds = ctx.ids[i];
        stm_fs_migrate_policy_stats per_stats = {0};
        stm_status rc = stm_fs_migrate_policy_step(fs, ds, &adj, &per_stats);

        stats->datasets_migrated++;
        stats->inos_visited   += per_stats.inos_visited;
        stats->inos_eligible  += per_stats.inos_eligible;
        stats->inos_migrated  += per_stats.inos_migrated;
        stats->bytes_migrated += per_stats.bytes_migrated;
        if (per_stats.last_err != STM_OK && stats->last_err == STM_OK) {
            stats->last_err            = per_stats.last_err;
            stats->last_err_dataset_id = ds;
            stats->last_err_ino        = per_stats.last_err_ino;
        }

        /* Hard errors abort. R59 P2-1: unconditionally override the
         * last_err slot — the hard error IS the proximate cause of
         * the abort and is what the operator most needs to see. The
         * per-step primitive (stm_fs_migrate_policy_step) follows
         * the same pattern under R58 P3-4 (overwrites any soft
         * last_err on hard return). The prior guarded version
         * silently retained an earlier soft error in the slot,
         * leaving the operator with stale dataset/ino info that
         * pointed at a different file than the one that actually
         * exhausted memory / wedged the handle. */
        if (rc == STM_EWEDGED || rc == STM_EROFS || rc == STM_ENOMEM) {
            stats->last_err            = rc;
            stats->last_err_dataset_id = ds;
            stats->last_err_ino        = per_stats.last_err_ino;
            free(ctx.ids);
            return rc;
        }
    }

    free(ctx.ids);
    return STM_OK;
}

/* ========================================================================= */
/* Promotion (cold → hot) heuristic — P7-CAS-11.                              */
/* ========================================================================= */

/* P7-CAS-11: stm_fs_promote_to_hot — wraps stm_sync_promote_to_hot
 * with the FS-layer guards (wedged/RO via FS_GUARD_WRITE) + the
 * standard fs->lock posture. The sync-layer primitive does its own
 * guards too; the FS-layer wrapper exists to (a) keep the public
 * surface symmetric with stm_fs_migrate_to_cold and (b) take fs->lock
 * so concurrent admin calls (mount/unmount path, etc.) serialize. */
stm_status stm_fs_promote_to_hot(stm_fs *fs,
                                    uint64_t dataset_id,
                                    uint64_t ino)
{
    if (!fs)                  return STM_EINVAL;
    if (dataset_id == 0u)     return STM_EINVAL;
    if (ino == 0u)            return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status rc = stm_sync_promote_to_hot(fs->sync, dataset_id, ino);
    pthread_mutex_unlock(&fs->lock);
    return rc;
}

/* P7-CAS-11: stm_fs_promote_policy_step. v1 promote-policy primitive.
 * Composes over stm_sync_promote_policy_collect (candidate selection)
 * + stm_fs_promote_to_hot (per-ino data plane). Pass shape mirrors
 * stm_fs_migrate_policy_step's INTERRUPTIBLE pattern: drops fs->lock
 * between candidate collection and per-ino promote. */
stm_status stm_fs_promote_policy_step(stm_fs *fs,
                                         uint64_t dataset_id,
                                         const stm_fs_promote_policy_params *params,
                                         stm_fs_promote_policy_stats *out_stats)
{
    /* Uniform out-param contract (R57 P3-5 et al.). */
    if (out_stats) *out_stats = (stm_fs_promote_policy_stats){0};
    if (!fs || !params)              return STM_EINVAL;
    if (dataset_id == 0u)            return STM_EINVAL;
    if (params->_reserved0 != 0u)    return STM_EINVAL;
    if (params->_reserved1 != 0u)    return STM_EINVAL;

    stm_fs_promote_policy_stats local_stats = {0};
    stm_fs_promote_policy_stats *stats = out_stats ? out_stats : &local_stats;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    uint64_t cur_gen = stm_sync_current_gen(fs->sync);
    /* Saturating subtraction for the recency cutoff. */
    uint64_t cutoff = (params->min_recency_txgs >= cur_gen)
                        ? 0u
                        : (cur_gen - params->min_recency_txgs);
    /* min_recency_txgs == 0 → "no recency filter" → cutoff = 0. */

    stm_sync_promote_candidate *cands = NULL;
    size_t   n_cands       = 0u;
    uint64_t inos_visited  = 0u;
    stm_status cs = stm_sync_promote_policy_collect(fs->sync, dataset_id,
                                                       params->min_read_count,
                                                       cutoff,
                                                       &cands, &n_cands,
                                                       &inos_visited);
    pthread_mutex_unlock(&fs->lock);
    if (cs != STM_OK) return cs;

    stats->inos_visited  = inos_visited;
    stats->inos_eligible = (uint64_t)n_cands;

    /* Per-ino promote loop. Each call re-takes fs->lock fresh — the
     * pass is INTERRUPTIBLE. */
    for (size_t i = 0; i < n_cands; i++) {
        if (params->max_inos != 0u
            && stats->inos_promoted >= (uint64_t)params->max_inos) break;
        if (params->max_bytes != 0u
            && stats->bytes_promoted >= params->max_bytes) break;

        uint64_t ino   = cands[i].ino;
        uint64_t bytes = cands[i].bytes;
        stm_status one = stm_fs_promote_to_hot(fs, dataset_id, ino);
        if (one == STM_OK) {
            stats->inos_promoted++;
            stats->bytes_promoted += bytes;
            continue;
        }
        /* Hard errors abort the pass; stamp last_err_ino. */
        if (one == STM_EWEDGED || one == STM_EROFS || one == STM_ENOMEM) {
            stats->last_err     = one;
            stats->last_err_ino = ino;
            free(cands);
            return one;
        }
        /* Soft error: record first, continue.
         *   - STM_ENOENT: the ino had no COLD extents at promote time
         *     (concurrent migrate / overwrite reclassified or removed).
         *     Benign — just count it as a failed candidate.
         *   - STM_EBADTAG / STM_EIO / STM_ECORRUPT / STM_ENOSPC: real
         *     per-ino issues that shouldn't stall the whole tier. */
        if (stats->last_err == STM_OK) {
            stats->last_err     = one;
            stats->last_err_ino = ino;
        }
    }

    free(cands);
    return STM_OK;
}

stm_status stm_fs_promote_policy_pass_all(
        stm_fs *fs,
        const stm_fs_promote_policy_params *params,
        stm_fs_promote_policy_pass_all_stats *out_stats)
{
    if (out_stats) *out_stats = (stm_fs_promote_policy_pass_all_stats){0};
    if (!fs || !params)              return STM_EINVAL;
    if (params->_reserved0 != 0u)    return STM_EINVAL;
    if (params->_reserved1 != 0u)    return STM_EINVAL;

    stm_fs_promote_policy_pass_all_stats local_stats = {0};
    stm_fs_promote_policy_pass_all_stats *stats = out_stats ? out_stats : &local_stats;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *idx = stm_sync_dataset_index(fs->sync);
    pass_all_id_collect_ctx ctx = { .err = STM_OK };
    stm_status its = stm_dataset_iter(idx, pass_all_id_collect_cb, &ctx);
    if (its != STM_OK || ctx.err != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        free(ctx.ids);
        return (ctx.err != STM_OK) ? ctx.err : its;
    }

    size_t enabled_n = 0;
    stm_status filter_err = STM_OK;
    for (size_t i = 0; i < ctx.n; i++) {
        uint64_t v = 0;
        stm_status pe = stm_dataset_effective_property(
                idx, ctx.ids[i], STM_PROP_TIERING, &v);
        if (pe != STM_OK) {
            if (filter_err == STM_OK) filter_err = pe;
            continue;
        }
        if (v != 0u) {
            ctx.ids[enabled_n++] = ctx.ids[i];
        }
    }
    pthread_mutex_unlock(&fs->lock);

    stats->datasets_visited  = (uint64_t)ctx.n;
    stats->datasets_eligible = (uint64_t)enabled_n;
    if (filter_err != STM_OK) stats->last_err = filter_err;

    /* Per-dataset promote with SHARED budget. */
    for (size_t i = 0; i < enabled_n; i++) {
        if (params->max_inos != 0u
            && stats->inos_promoted >= (uint64_t)params->max_inos) break;
        if (params->max_bytes != 0u
            && stats->bytes_promoted >= params->max_bytes) break;

        stm_fs_promote_policy_params adj = *params;
        if (adj.max_inos != 0u) {
            adj.max_inos =
                    (uint32_t)((uint64_t)params->max_inos - stats->inos_promoted);
        }
        if (adj.max_bytes != 0u) {
            adj.max_bytes = params->max_bytes - stats->bytes_promoted;
        }

        uint64_t ds = ctx.ids[i];
        stm_fs_promote_policy_stats per_stats = {0};
        stm_status rc = stm_fs_promote_policy_step(fs, ds, &adj, &per_stats);

        stats->datasets_promoted++;
        stats->inos_visited   += per_stats.inos_visited;
        stats->inos_eligible  += per_stats.inos_eligible;
        stats->inos_promoted  += per_stats.inos_promoted;
        stats->bytes_promoted += per_stats.bytes_promoted;
        if (per_stats.last_err != STM_OK && stats->last_err == STM_OK) {
            stats->last_err            = per_stats.last_err;
            stats->last_err_dataset_id = ds;
            stats->last_err_ino        = per_stats.last_err_ino;
        }

        if (rc == STM_EWEDGED || rc == STM_EROFS || rc == STM_ENOMEM) {
            /* R59 P2-1 pattern: unconditional override on hard. */
            stats->last_err            = rc;
            stats->last_err_dataset_id = ds;
            stats->last_err_ino        = per_stats.last_err_ino;
            free(ctx.ids);
            return rc;
        }
    }

    free(ctx.ids);
    return STM_OK;
}

/* ========================================================================= */
/* Dataset creation (P7-13).                                                  */
/* ========================================================================= */

/*
 * Composes stm_dataset_create_child + stm_sync_add_dataset_key under
 * fs->lock so the FS observer never sees a half-created dataset
 * (entry minted with no DEK provisioned, or DEK provisioned with no
 * entry). On add_dataset_key failure, the dataset_create_child is
 * rolled back via stm_dataset_destroy. The freshly-created leaf is
 * non-root (new_id ≥ 2 since root is id=1), PRESENT (just inserted
 * under fs->lock), and has no children, so the destroy spec's three
 * documented failure modes (STM_EINVAL on root, STM_ENOENT on
 * not-PRESENT, STM_EBUSY on has-children) are all unreachable —
 * asserted post-call.
 *
 * Wrap-key lifecycle (R45 P2-1): the wrap source is the SAME source
 * used at mount, retained on the fs handle (`fs->keyfile_path` or
 * `fs->janus_socket`, exactly one). Loading + wipe / connect +
 * disconnect happens per-call. Binding to the mount source removes
 * a footgun where a caller could have passed a different keyfile/
 * janus and silently persisted an unwrappable CURRENT entry, which
 * R42 P1-1's hard-fail-on-CURRENT-unwrap-failure would turn into a
 * permanent mount refusal on the next mount. ARCH §7.7 frames wrap
 * keys as pool-wide, so per-call overrides have no documented use
 * case — implicit binding is the right shape.
 *
 * Loading the wrap source happens BEFORE fs->lock is taken so a
 * keyfile read or janus connect failure doesn't hold up other
 * writers. Wiped / disconnected on every exit path (success and
 * failure).
 */
stm_status stm_fs_create_dataset(stm_fs *fs, uint64_t parent_id,
                                    const char *name,
                                    uint64_t *out_id)
{
    if (!fs || !name || !out_id) return STM_EINVAL;
    /* R45 P2-1: bind to the mount-time wrap source. Exactly one of
     * keyfile_path / janus_socket is non-NULL post-mount (mount opts
     * enforce the XOR + at least one); confirm the post-mount
     * invariant defensively. */
    int have_kf = fs->keyfile_path != NULL;
    int have_jn = fs->janus_socket != NULL;
    if (have_kf == have_jn) return STM_ECORRUPT;

    stm_hybrid_keys   wk    = {0};
    stm_janus_client *janus = NULL;
    if (have_kf) {
        stm_status ks = stm_keyfile_load(fs->keyfile_path, &wk);
        if (ks != STM_OK) return ks;
    } else {
        stm_status js = stm_janus_client_connect(fs->janus_socket, &janus);
        if (js != STM_OK) return js;
    }

    pthread_mutex_lock(&fs->lock);
    if (fs->wedged) {
        pthread_mutex_unlock(&fs->lock);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_EWEDGED;
    }
    if (fs->read_only) {
        pthread_mutex_unlock(&fs->lock);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_EROFS;
    }

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        /* sync_open always populates the dataset index; a NULL here
         * means a sync-internal corruption that we surface rather
         * than dereferencing. */
        pthread_mutex_unlock(&fs->lock);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_ECORRUPT;
    }

    uint64_t new_id = 0;
    stm_status s = stm_dataset_create_child(didx, parent_id, name, &new_id);
    if (s != STM_OK) {
        pthread_mutex_unlock(&fs->lock);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    uint64_t new_kid = 0;
    s = stm_sync_add_dataset_key(fs->sync, new_id,
                                    have_kf ? &wk : NULL,
                                    have_jn ? janus : NULL,
                                    &new_kid);
    if (s != STM_OK) {
        /* R45 P3-2: destroy on a freshly-created non-root leaf with
         * no children + no concurrent observer (we hold fs->lock) is
         * infallible per the dataset module's spec — its three
         * documented failure modes (root-id, not-PRESENT, has-children)
         * are all unreachable for new_id minted three lines above.
         * The return value is unused. If a future spec change adds a
         * failure mode, a regression test on fs_create_dataset's
         * rollback path will catch it. */
        (void)stm_dataset_destroy(didx, new_id);
        pthread_mutex_unlock(&fs->lock);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    *out_id = new_id;
    pthread_mutex_unlock(&fs->lock);
    stm_hybrid_keys_wipe(&wk);
    if (janus) stm_janus_client_disconnect(janus);
    return STM_OK;
}

/* ========================================================================= */
/* Dataset property wrappers (P7-CAS-13).                                     */
/*                                                                            */
/* Thin pass-through wrappers around the dataset.c property API. Take         */
/* fs->lock, apply wedged/RO guards, get the dataset_idx via the sync         */
/* handle, delegate. Closes R63 P3-4: pre-P7-CAS-13 the only callable         */
/* path was via the test-only `stm_fs_sync_for_test` accessor.                */
/* ========================================================================= */

stm_status stm_fs_set_dataset_property(stm_fs *fs, uint64_t dataset_id,
                                          stm_property prop,
                                          uint64_t value)
{
    if (!fs) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_set_property(didx, dataset_id, prop, value);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_clear_dataset_property(stm_fs *fs, uint64_t dataset_id,
                                            stm_property prop)
{
    if (!fs) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_clear_property(didx, dataset_id, prop);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_effective_dataset_property(stm_fs *fs, uint64_t dataset_id,
                                                stm_property prop,
                                                uint64_t *out_value)
{
    /* R64 P2-1: uniform out-param contract — zero-init out_value
     * BEFORE the NULL-arg check so a caller observing on STM_EINVAL
     * (e.g. NULL fs but non-NULL out_value) still sees a defined
     * zero rather than uninitialized stack. Same shape as
     * stm_fs_migrate_policy_step (fs.c:569),
     * stm_fs_migrate_policy_pass_all (fs.c:687),
     * stm_fs_promote_policy_step (fs.c:834). The prior order
     * (NULL-check first) violated the contract on the
     * `NULL fs + non-NULL out_value` path. */
    if (out_value) *out_value = 0;
    if (!fs || !out_value) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_READ(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_effective_property(didx, dataset_id,
                                                     prop, out_value);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_set_dataset_pool_default(stm_fs *fs, stm_property prop,
                                              uint64_t value)
{
    if (!fs) return STM_EINVAL;

    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_mutex_unlock(&fs->lock);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_set_pool_default(didx, prop, value);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

/* ========================================================================= */
/* Inspection + control.                                                      */
/* ========================================================================= */

stm_status stm_fs_stats_get(const stm_fs *fs, stm_fs_stats *out)
{
    if (!fs || !out) return STM_EINVAL;

    /* R7e-P2-3: zero *out so an early error leaves the caller's
     * buffer deterministic, not partially-populated. */
    memset(out, 0, sizeof *out);

    stm_fs *mfs = (stm_fs *)fs;
    pthread_mutex_lock(&mfs->lock);
    /* Allow reading stats on a wedged fs — useful for diagnostics. */

    /* R7e-P2-1: sync first, then alloc — matches the nesting used by
     * stm_fs_commit (sync_commit -> alloc_commit). Keeps a single
     * canonical lock order across all stm_fs entries. */
    stm_sync_info sinfo;
    stm_status s = stm_sync_info_get(fs->sync, &sinfo);
    if (s != STM_OK) {
        pthread_mutex_unlock(&mfs->lock);
        return s;
    }

    stm_alloc_stats astats;
    s = stm_alloc_stats_get(fs->alloc, &astats);
    if (s != STM_OK) {
        pthread_mutex_unlock(&mfs->lock);
        return s;
    }

    out->data_total_blocks     = astats.data_total_blocks;
    out->data_allocated_blocks = astats.data_allocated_blocks;
    out->data_pending_blocks   = astats.data_pending_blocks;
    out->data_free_blocks      = astats.data_free_blocks;
    out->n_allocated_ranges    = astats.n_allocated_ranges;

    out->current_gen       = sinfo.current_gen;
    out->alloc_root_paddr  = sinfo.alloc_root_paddr;

    out->read_only = fs->read_only;
    out->wedged    = fs->wedged;

    pthread_mutex_unlock(&mfs->lock);
    return STM_OK;
}

void stm_fs_mark_wedged(stm_fs *fs)
{
    if (!fs) return;
    pthread_mutex_lock(&fs->lock);
    fs->wedged = true;
    pthread_mutex_unlock(&fs->lock);
}

stm_status stm_fs_verify(const stm_fs *fs)
{
    if (!fs) return STM_EINVAL;
    /* Verify is side-effect-free: takes fs->lock so state can't
     * shift under us, but ignores read_only + wedged (both make
     * sense for scrubbing). */
    stm_fs *mfs = (stm_fs *)fs;
    pthread_mutex_lock(&mfs->lock);
    stm_status s = stm_alloc_verify(fs->alloc);
    pthread_mutex_unlock(&mfs->lock);
    return s;
}

/* ========================================================================= */
/* Test-only accessors.                                                       */
/* ========================================================================= */

/* Chunk 8: exposed to the crash-injection fuzzer. The caller must
 * not retain the pointer across stm_fs_unmount. */
stm_bdev *stm_fs_bdev_for_test(stm_fs *fs)
{
    return fs ? fs->bdev : NULL;
}

/* P7-4: tests that drive the snapshot/dataset/extent indices need
 * the sync handle. Same lifetime contract as the bdev accessor. */
stm_sync *stm_fs_sync_for_test(stm_fs *fs)
{
    return fs ? fs->sync : NULL;
}
