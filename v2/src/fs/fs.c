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
#include <stratum/janus.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/sync.h>

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
 * this; matches the existing reserve/free/commit pattern. */
stm_status stm_fs_write(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                          uint64_t off, const void *buf, size_t len)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_sync_write_extent(fs->sync, dataset_id, ino, off,
                                            buf, len);
    pthread_mutex_unlock(&fs->lock);
    return s;
}

stm_status stm_fs_read(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                         uint64_t off, void *buf, size_t len,
                         size_t *out_read)
{
    if (!fs) return STM_EINVAL;
    pthread_mutex_lock(&fs->lock);
    FS_GUARD_READ(fs);
    stm_status s = stm_sync_read_extent(fs->sync, dataset_id, ino, off,
                                           buf, len, out_read);
    pthread_mutex_unlock(&fs->lock);
    return s;
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
            uint64_t remaining = (uint64_t)params->max_inos - stats->inos_migrated;
            adj.max_inos = (remaining > UINT32_MAX) ? UINT32_MAX
                                                    : (uint32_t)remaining;
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

        /* Hard errors abort. The per-step call already stamps its
         * own last_err_ino on hard returns (R58 P3-4); we promote
         * to the pass-all error slot only if no soft error was
         * already recorded earlier. */
        if (rc == STM_EWEDGED || rc == STM_EROFS || rc == STM_ENOMEM) {
            if (stats->last_err == STM_OK || stats->last_err == filter_err) {
                stats->last_err            = rc;
                stats->last_err_dataset_id = ds;
                stats->last_err_ino        = per_stats.last_err_ino;
            }
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
