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
                       stm_alloc *a, stm_sync *sync, bool ro)
{
    stm_fs *fs = calloc(1, sizeof *fs);
    if (!fs) return NULL;
    if (pthread_mutex_init(&fs->lock, NULL) != 0) {
        free(fs);
        return NULL;
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

    stm_fs *fs = fs_new(d, pool, a, sync, opts->read_only);
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

/* ========================================================================= */
/* Dataset creation (P7-13).                                                  */
/* ========================================================================= */

/*
 * Composes stm_dataset_create_child + stm_sync_add_dataset_key under
 * fs->lock so the FS observer never sees a half-created dataset
 * (entry minted with no DEK provisioned, or DEK provisioned with no
 * entry). On add_dataset_key failure, the dataset_create_child is
 * rolled back via stm_dataset_destroy: the freshly-created leaf has
 * no children and a non-root id, so the only failure modes the
 * destroy spec documents (STM_EINVAL on root, STM_ENOENT on
 * not-PRESENT, STM_EBUSY on has-children) are all unreachable. If
 * destroy somehow returns non-OK anyway, the dataset_index has now
 * diverged from the keyschema so we wedge the fs to preserve
 * forensic state — STM_ECORRUPT propagated to the caller.
 *
 * Wrap-key lifecycle: loaded BEFORE fs->lock so a bad keyfile or
 * unreachable janus daemon doesn't hold up other writers; wiped
 * (or janus client disconnected) on every exit path including the
 * guard-refusal paths. Mirrors stm_fs_format / stm_fs_mount's
 * shape — fs->* never retains wrap-key material.
 */
stm_status stm_fs_create_dataset(stm_fs *fs, uint64_t parent_id,
                                    const char *name,
                                    const stm_fs_create_dataset_opts *opts,
                                    uint64_t *out_id)
{
    if (!fs || !name || !opts || !out_id) return STM_EINVAL;
    int have_kf = opts->keyfile_path != NULL;
    int have_jn = opts->janus_socket != NULL;
    if (have_kf == have_jn) return STM_EINVAL;

    stm_hybrid_keys   wk    = {0};
    stm_janus_client *janus = NULL;
    if (have_kf) {
        stm_status ks = stm_keyfile_load(opts->keyfile_path, &wk);
        if (ks != STM_OK) return ks;
    } else {
        stm_status js = stm_janus_client_connect(opts->janus_socket, &janus);
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
        /* Should be impossible post-mount — sync_open always populates
         * the dataset index. Surface as ECORRUPT defensively rather
         * than dereferencing NULL. */
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
        stm_status rb = stm_dataset_destroy(didx, new_id);
        if (rb != STM_OK) {
            /* Index now divergent from keyschema. Preserve forensic
             * state for offline inspection — wedge the fs. */
            fs->wedged = true;
            pthread_mutex_unlock(&fs->lock);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return STM_ECORRUPT;
        }
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
