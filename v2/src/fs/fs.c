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
 *   fs->global (rwlock, EX or SH; writer-preference attr on glibc
 *               per R133 P1-1 to prevent EX-taker starvation under
 *               sustained SH-traffic) →
 *      [per-inode handle->mu  →]      (PARALLEL-3 impl-1: SH path only)
 *      sync->lock  →  alloc->lock  →  alloc's btree rwlock
 *
 * NEVER call stm_fs_mark_wedged from inside a held fs->global wrlock —
 * recursive same-thread wrlock is POSIX-undefined and deadlocks on
 * glibc. R133 P1-2 fixed the latent rename rollback path; future
 * compound ops with internal wedge-on-failure paths MUST capture the
 * intent into a local bool and fire mark_wedged AFTER unlock.
 *
 * Public stm_fs entries:
 *   - Pre-PARALLEL-3 ops (the residual EX surface): take fs->global EX
 *     (wrlock) and dispatch under PARALLEL-2's compound-op atomicity
 *     contract. Two such ops serialize on fs->global EX exactly as the
 *     pre-PARALLEL-3 big-fs-lock did. (PARALLEL-2 baseline preserved.)
 *   - PARALLEL-3 impl-1+ ops (the per-inode SH surface — chmod / chown /
 *     utimens at impl-1; more in impl-2..5): take fs->global SH (rdlock)
 *     PLUS the per-inode mutex for each target inode via
 *     stm_inode_pin/_unpin. Two such ops on disjoint inodes proceed
 *     concurrently; on the same inode they serialize on the per-inode
 *     mutex.
 *
 * stm_sync_commit nests stm_alloc_commit under sync->lock. Every reader-
 * path inside stm_fs (stats_get) acquires the same order. Do not add a
 * path that takes alloc->lock and then sync->lock — the commit path
 * already owns the reverse, and crossing lock orders deadlocks.
 */

#include <stratum/fs.h>
#include <stratum/fs_testing.h>
#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/bootstrap.h>
#include <stratum/dataset.h>
#include <stratum/dirent.h>
#include <stratum/dirty_buffer.h>
#include <stratum/extent.h>
#include <stratum/inode.h>
#include <stratum/locks.h>
#include <stratum/xattr.h>
#include <stratum/janus.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/cas.h>
#include <stratum/snapshot.h>
#include <stratum/sync.h>

#include <sys/stat.h>            /* S_IFMT / S_IFREG / S_IFDIR */
#include <time.h>                /* clock_gettime / CLOCK_REALTIME */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* ========================================================================= */
/* In-RAM state.                                                              */
/* ========================================================================= */

/* SWISS-4q-flush: dirty-buffer caps. Per-inode cap matches recordsize
 * (the natural upper bound on a single coalesced extent); global cap
 * sized for a daily-driver workstation. See dirty_buffer.h. */
#define STM_FLUSH_INODE_CAP_BYTES   (8u * 1024u * 1024u)
#define STM_FLUSH_GLOBAL_CAP_BYTES  (256u * 1024u * 1024u)

/* SWISS-4q-flush: direct-write threshold. Writes ≥ this size bypass
 * the dirty buffer and go straight to the extent layer — they're
 * already large enough that buffering adds a memcpy without a real
 * coalescing win. Sized just below recordsize so a fragment-aligned
 * 1 MiB chunk still buffers (rare but possible — gives the next
 * adjacent fragment a chance to merge with it).
 *
 * v2 forward-note: tunable via a per-fs setting once the mount-opts
 * surface gets one. */
#define STM_FLUSH_DIRECT_THRESHOLD_BYTES  (1u * 1024u * 1024u)

struct stm_fs {
    /* P9.5-PARALLEL-3 impl-1: the big-fs-lock from PARALLEL-2 baseline
     * has been promoted to an rwlock. Existing call sites take it in
     * EXCLUSIVE mode (wrlock) — same semantics as the prior mutex.
     * Newly-ported per-inode ops (PARALLEL-3 impl-1: chmod / chown /
     * utimens) take it in SHARED mode (rdlock) and serialize on a
     * per-inode mutex via stm_inode_pin/_unpin instead. The contract:
     *
     *   - Per-inode ops take fs->global SH + their target inode lock(s).
     *   - Dataset-wide ops (snapshot, scrub, commit, mount/unmount) take
     *     fs->global EX.
     *   - Two per-inode ops on different inodes proceed concurrently
     *     (both hold fs->global SH, distinct per-inode mutexes).
     *   - A dataset-wide op blocks ALL per-inode ops by taking fs->global
     *     EX (waits for outstanding SH holders to drain).
     *
     * During impl-1 only chmod/chown/utimens are ported; the residual
     * 60+ EX call sites act as the "unported transitional EX" surface
     * per the design doc §3. impl-2..5 progressively port the remaining
     * ops; impl-5 drops the residual EX takes that were just the
     * big-fs-lock semantics. */
    pthread_rwlock_t global;

    stm_bdev  *bdev;         /* owned — closed at unmount */
    stm_pool  *pool;         /* owned — P5-1 N=1 wrapper over bdev */
    stm_alloc *alloc;        /* owned */
    stm_sync  *sync;         /* owned */
    stm_lock_table *locks;   /* P8-POSIX-7d: in-RAM advisory lock table */

    /* SWISS-4q-flush: per-inode plaintext write buffer. Realizes the
     * writeback.tla state machine — small writes land in this buffer
     * and emit as fewer/larger extents at flush time (= stm_fs_commit
     * + stm_fs_unmount). Reads check this overlay BEFORE consulting
     * the extent layer.
     *
     * This commit (SWISS-4q-flush-fs step 1) plumbs the buffer in
     * without activating it: create+destroy at lifecycle boundaries,
     * drop-on-unlink for safety. Write/read/commit hookup is the next
     * chunk. Until then this is a quiescent allocation.
     *
     * Caps: STM_FLUSH_INODE_CAP_BYTES per-inode + STM_FLUSH_GLOBAL_
     * CAP_BYTES global. See dirty_buffer.h for the spec-to-code
     * mapping. */
    stm_dirty_buffer *dirty_buffer;     /* owned */

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

    /* SWISS-4m1: cached UNWRAPPED hybrid wrap keys for any subsequent
     * stm_fs_create_dataset (or other future mutate-needing path).
     * Populated at mount AFTER the keyfile has been loaded + the
     * pool/sync layers have taken what they need; wiped + freed at
     * unmount. This replaces SWISS-4m's cached-passphrase posture:
     * the plaintext passphrase no longer lives past stm_fs_mount's
     * KDF call — only the (still-secret) hybrid keypair survives,
     * which the caller would have had to keep alive anyway. mlock'd
     * best-effort.
     *
     * The struct's storage is heap-allocated so the wipe + munlock
     * pair at unmount can target an exact extent. NULL when the fs
     * was mounted via janus (the daemon owns the unwrap path; no
     * keyfile-load reload is needed for create_dataset since the
     * janus client connects fresh each time). */
    stm_hybrid_keys *cached_keys;    /* owned (malloc + mlock) */

    bool read_only;
    bool wedged;
};

/* Guard macros. MUST be called while holding fs->global (EX or SH). On the
 * refusal path they UNLOCK fs->global and return from the enclosing
 * function. The caller's happy path is responsible for its own unlock;
 * the guard only takes ownership of the unlock when it bails.
 *
 * The same pthread_rwlock_unlock() call works for both SH and EX holders,
 * so the guard composes with EITHER the pre-PARALLEL-3 EX (wrlock) sites
 * or the new SH (rdlock) per-inode-op sites.
 *
 * R7e-P0-1: a prior revision returned without unlocking, which turned
 * the very next acquisition (from any API, including unmount) into a
 * deadlock — the bug that the removed RO/wedged end-to-end tests had
 * been tripping over and that was misdiagnosed as a POSIX-bdev thread-
 * pool hang.                                                            */
#define FS_GUARD_READ(fs) do {                                             \
    if ((fs)->wedged) {                                                    \
        pthread_rwlock_unlock(&(fs)->global);                              \
        return STM_EWEDGED;                                                \
    }                                                                      \
} while (0)

#define FS_GUARD_WRITE(fs) do {                                            \
    if ((fs)->wedged) {                                                    \
        pthread_rwlock_unlock(&(fs)->global);                              \
        return STM_EWEDGED;                                                \
    }                                                                      \
    if ((fs)->read_only) {                                                 \
        pthread_rwlock_unlock(&(fs)->global);                              \
        return STM_EROFS;                                                  \
    }                                                                      \
} while (0)

/* ========================================================================= */
/* P8-POSIX-7a: clock source + ctime/mtime/btime stamping discipline.        */
/*                                                                            */
/* Closes the P8-wide R78 P3-3 forward-noted gap. Pre-7a, every inode         */
/* came out of `stm_inode_alloc` with all timestamps zeroed and the various   */
/* fs ops (chmod / chown / link / unlink / write / truncate / setxattr) did   */
/* not touch ctime/mtime — `stm_fs_utimens` was the only stamping path,       */
/* and it required the caller to supply ctime explicitly. Post-7a, every      */
/* metadata-changing op auto-stamps ctime to "now" via CLOCK_REALTIME +       */
/* every content-changing op auto-stamps mtime + ctime, matching POSIX        */
/* semantics for ext4/XFS/APFS. btime is stamped exactly once at inode        */
/* creation (POSIX `creation time`; never modified thereafter).               */
/*                                                                            */
/* Atime-on-read is deliberately NOT stamped in this chunk (Linux `noatime`   */
/* default shape — every read becoming a write to the inode tree would        */
/* dominate the read path's cost). atime is stamped at create + via the      */
/* explicit `stm_fs_utimens` API. A future P8-POSIX-7a-relatime chunk could  */
/* add per-dataset opt-in via STM_PROP_*.                                     */
/*                                                                            */
/* Clock source: CLOCK_REALTIME via clock_gettime(2). The per-call cost is   */
/* a single VDSO syscall on Linux + macOS — negligible vs the inode_set      */
/* it bookends. Failure (extremely rare; bad arg only) leaves the timespec    */
/* at zero and stamps zero — degenerate but bounded.                          */
/*                                                                            */
/* Why CLOCK_REALTIME and not CLOCK_MONOTONIC: POSIX timestamps are wall-    */
/* clock; users compare them across reboots and across machines. A MONOTONIC */
/* source would survive clock skew but not be comparable across boots.       */
/* Future work: pin a max-skew invariant via scrub if NTP-monotonicity        */
/* becomes load-bearing (currently a soft property).                          */
/* ========================================================================= */

/* Capture CLOCK_REALTIME into LE seconds + LE nanoseconds. */
static inline void fs_clock_now_le(le64 *out_sec, le32 *out_nsec)
{
    struct timespec ts = { 0, 0 };
    /* clock_gettime errors only on bad arg / bad clock id; both are
     * compile-time wrong here. Defensive: ignore rv, ts stays zero. */
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    if (out_sec)  *out_sec  = stm_store_le64((uint64_t)ts.tv_sec);
    if (out_nsec) *out_nsec = stm_store_le32((uint32_t)ts.tv_nsec);
}

/* Stamp btime + atime + mtime + ctime to "now". Used at every inode
 * creation site so freshly-allocated inodes carry a defined creation
 * time + initial atime/mtime/ctime. POSIX requires btime be set at
 * create and never modified thereafter; subsequent stamping helpers
 * preserve btime. */
static inline void fs_stamp_create_times(struct stm_inode_value *iv)
{
    le64 sec; le32 nsec;
    fs_clock_now_le(&sec, &nsec);
    iv->si_btime_sec = sec; iv->si_btime_nsec = nsec;
    iv->si_atime_sec = sec; iv->si_atime_nsec = nsec;
    iv->si_mtime_sec = sec; iv->si_mtime_nsec = nsec;
    iv->si_ctime_sec = sec; iv->si_ctime_nsec = nsec;
}

/* Stamp mtime + ctime to "now". Used after content-change ops:
 * fs_write, fs_truncate (size or content change). POSIX: mtime
 * captures content modification + ctime captures any inode
 * metadata change (which a size/content change implies). btime
 * is preserved (immutable post-create per POSIX). */
static inline void fs_stamp_mtime_ctime_now(struct stm_inode_value *iv)
{
    le64 sec; le32 nsec;
    fs_clock_now_le(&sec, &nsec);
    iv->si_mtime_sec = sec; iv->si_mtime_nsec = nsec;
    iv->si_ctime_sec = sec; iv->si_ctime_nsec = nsec;
}

/* Stamp ctime to "now". Used after metadata-change ops: chmod,
 * chown, link, unlink (the linked/unlinked inode), setxattr,
 * removexattr, rename. POSIX: ctime captures any inode metadata
 * change without modifying mtime. btime preserved. */
static inline void fs_stamp_ctime_now(struct stm_inode_value *iv)
{
    le64 sec; le32 nsec;
    fs_clock_now_le(&sec, &nsec);
    iv->si_ctime_sec = sec; iv->si_ctime_nsec = nsec;
}

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
     * we touch the pool device. SWISS-4m: passphrase-aware variant
     * if caller supplied one (KFP1 keyfile). */
    stm_hybrid_keys wk;
    stm_status ks = (opts->keyfile_passphrase && opts->keyfile_passphrase_len > 0)
        ? stm_keyfile_load_passphrase(opts->keyfile_path,
                                          opts->keyfile_passphrase,
                                          opts->keyfile_passphrase_len,
                                          &wk)
        : stm_keyfile_load(opts->keyfile_path, &wk);
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

/* SWISS-4q-flush forward decls — referenced by stm_fs_commit /
 * stm_fs_unmount BEFORE the static definitions below. */
static stm_status fs_flush_ino_locked(stm_fs *fs, uint64_t ds, uint64_t ino);
static stm_status fs_flush_all_locked(stm_fs *fs);
/* R128 P1-1 + P1-2 helpers. The pre returns true iff it actually
 * truncated extents (i.e., reclaim work is pending); callers gate the
 * post-reclaim double-commit on that signal so inodes with no extent
 * payload (directories, symlinks, fresh-anon-then-unlinked, inline-
 * data-only files) skip the ~200 ms commit pair entirely. */
static bool fs_pre_inode_free_cleanup_locked(stm_fs *fs, uint64_t ds,
                                                  uint64_t ino,
                                                  const struct stm_inode_value *cv);
static void fs_post_inode_free_reclaim_locked(stm_fs *fs);

static stm_fs *fs_new(stm_bdev *d, stm_pool *pool,
                       stm_alloc *a, stm_sync *sync, bool ro,
                       const char *keyfile_path,
                       const char *janus_socket)
{
    stm_fs *fs = calloc(1, sizeof *fs);
    if (!fs) return NULL;
    /* R133 P1-1: glibc default rwlock attribute is reader-preference;
     * a continuous stream of SH-takers (the new PARALLEL-3 ported ops)
     * can starve a queued EX-taker (stm_fs_unmount, stm_fs_commit,
     * stm_fs_mark_wedged, every still-unported op) indefinitely. Set
     * writer-preference where the attr is available (Linux/glibc).
     * macOS / other POSIX: default attrs already give reasonable
     * scheduler fairness; pass NULL. Same posture as pool.c:274. */
#if defined(__linux__) && defined(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP)
    pthread_rwlockattr_t rwattr;
    pthread_rwlockattr_init(&rwattr);
    pthread_rwlockattr_setkind_np(&rwattr,
        PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    int rwrc = pthread_rwlock_init(&fs->global, &rwattr);
    pthread_rwlockattr_destroy(&rwattr);
#else
    int rwrc = pthread_rwlock_init(&fs->global, NULL);
#endif
    if (rwrc != 0) {
        free(fs);
        return NULL;
    }
    if (keyfile_path) {
        fs->keyfile_path = strdup(keyfile_path);
        if (!fs->keyfile_path) {
            pthread_rwlock_destroy(&fs->global);
            free(fs);
            return NULL;
        }
    }
    if (janus_socket) {
        fs->janus_socket = strdup(janus_socket);
        if (!fs->janus_socket) {
            free(fs->keyfile_path);
            pthread_rwlock_destroy(&fs->global);
            free(fs);
            return NULL;
        }
    }
    fs->bdev      = d;
    /* fs->pool and fs->sync are SET ONCE here and IMMUTABLE for the
     * lifetime of the stm_fs handle (no rebind path — mount creates a
     * fresh stm_fs; remount via mount-bump runs at sync layer). This
     * is the no-lock contract that stm_fs_pool() and stm_fs_sync()
     * depend on (R129 P3-4 doc carry): concurrent /ctl/ threads and
     * 9P FS threads read these accessors without fs->lock because
     * the pointers can't move. Any future code path that would
     * mutate either pointer post-mount MUST take fs->lock AND lift
     * the no-lock claim from the accessors' headers (fs.h L2389+). */
    fs->pool      = pool;
    fs->alloc     = a;
    fs->sync      = sync;
    fs->locks     = stm_lock_table_create();
    if (!fs->locks) {
        free(fs->janus_socket);
        free(fs->keyfile_path);
        pthread_rwlock_destroy(&fs->global);
        free(fs);
        return NULL;
    }
    /* SWISS-4q-flush: per-fs dirty buffer (writeback.tla state).
     * Quiescent at v1 step 1 — created here, drop_ino called on
     * unlink/truncate, destroyed at unmount, never inserted. Next
     * chunk activates writes + reads + commit-flush. */
    stm_status dbuf_rc = stm_dirty_buffer_create(STM_FLUSH_INODE_CAP_BYTES,
                                                  STM_FLUSH_GLOBAL_CAP_BYTES,
                                                  &fs->dirty_buffer);
    if (dbuf_rc != STM_OK) {
        stm_lock_table_close(fs->locks);
        free(fs->janus_socket);
        free(fs->keyfile_path);
        pthread_rwlock_destroy(&fs->global);
        free(fs);
        return NULL;
    }
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
        /* SWISS-4m: if caller supplied a passphrase, the keyfile is
         * KFP1-encrypted. Otherwise legacy plaintext path. */
        stm_status ks = (opts->keyfile_passphrase && opts->keyfile_passphrase_len > 0)
            ? stm_keyfile_load_passphrase(opts->keyfile_path,
                                              opts->keyfile_passphrase,
                                              opts->keyfile_passphrase_len,
                                              &wk)
            : stm_keyfile_load(opts->keyfile_path, &wk);
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

    /* SWISS-4m1: cache the UNWRAPPED hybrid keypair for later
     * stm_fs_create_dataset reloads. Eliminates the SWISS-4m cached-
     * passphrase posture — plaintext bytes no longer survive past the
     * mount's KDF call. The wrap keys are exactly as sensitive as
     * the dataset DEKs they wrap, so no new exposure here.
     * Best-effort mlock to keep the page out of swap.
     *
     * Skipped for janus-routed mounts: the janus client reconnects
     * fresh on each create_dataset call; no fs-side cache needed. */
    if (have_kf) {
        stm_hybrid_keys *cached = malloc(sizeof *cached);
        if (!cached) {
            (void)stm_fs_unmount(fs);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return STM_ENOMEM;
        }
        (void)mlock(cached, sizeof *cached);
        memcpy(cached->pk, wk.pk, sizeof wk.pk);
        memcpy(cached->sk, wk.sk, sizeof wk.sk);
        fs->cached_keys = cached;
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

    pthread_rwlock_wrlock(&fs->global);

    stm_status commit_status = STM_OK;
    if (!fs->read_only && !fs->wedged) {
        /* SWISS-4q-flush: drain dirty buffer before final commit so
         * every buffered write becomes a committed extent in the
         * three-phase sync. If drain fails, propagate but skip
         * sync_commit — partial-flush state is the caller's signal
         * that not everything made it durable. */
        commit_status = fs_flush_all_locked(fs);
        if (commit_status == STM_OK) {
            /* Final commit makes everything durable. Propagate its
             * status so the caller knows if the unmount lost data. */
            commit_status = stm_sync_commit(fs->sync);
        }
    }

    /* Close the stack regardless of commit result. Order matters:
     * sync borrows pool; pool borrows bdev. Close inside-out. */
    stm_sync_close(fs->sync);
    stm_alloc_close(fs->alloc);
    stm_pool_close(fs->pool);
    stm_bdev_close(fs->bdev);
    stm_lock_table_close(fs->locks);
    /* SWISS-4q-flush: dirty buffer must outlive sync_commit (above)
     * because the flush callback writes through sync; but its plaintext
     * pages are pure RAM and don't touch the now-closed pool. Free
     * after sync_close — any remaining bytes are silently dropped.
     *
     * R128 P3-1 doc fix: prior comment claimed "failed → fs is wedged
     * and the data wasn't durable anyway". That's wrong:
     * `fs_flush_all_locked` failure does NOT auto-wedge the fs.
     * Accurate posture: either fs_flush_all_locked + sync_commit
     * succeeded (nothing buffered post-flush) OR one of them returned
     * non-OK (partially-drained ranges are gone from RAM; the caller's
     * commit_status return is the only signal of loss). The wedge
     * transition lives on a separate code path (`stm_fs_mark_wedged`)
     * that unmount does not invoke. */
    stm_dirty_buffer_destroy(fs->dirty_buffer);

    pthread_rwlock_unlock(&fs->global);
    pthread_rwlock_destroy(&fs->global);
    free(fs->keyfile_path);
    free(fs->janus_socket);
    /* SWISS-4m1: wipe + munlock + free the cached hybrid keys on
     * unmount. Wipe BEFORE munlock so memzero hits the still-pinned
     * page. */
    if (fs->cached_keys) {
        stm_hybrid_keys_wipe(fs->cached_keys);
        (void)munlock(fs->cached_keys, sizeof *fs->cached_keys);
        free(fs->cached_keys);
    }
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
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_alloc_reserve(fs->alloc, nblocks, hint_paddr, out_paddr);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_free(stm_fs *fs, uint64_t paddr, uint64_t free_gen)
{
    if (!fs) return STM_EINVAL;
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_alloc_free(fs->alloc, paddr, free_gen);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_commit(stm_fs *fs)
{
    if (!fs) return STM_EINVAL;
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    /* SWISS-4q-flush: drain the dirty buffer FIRST so every buffered
     * write becomes a committed extent before the three-phase sync
     * makes everything durable. Per writeback.tla::Commit, this is the
     * "flush all inodes then advance durability" sequence. If the
     * drain fails (e.g., allocator out of space mid-flush), the inode's
     * buffered ranges remain in-RAM for retry — the caller sees the
     * failure and can decide whether to fsync again. */
    stm_status fr = fs_flush_all_locked(fs);
    if (fr != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return fr;
    }
    stm_status s = stm_sync_commit(fs->sync);
    pthread_rwlock_unlock(&fs->global);
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

/* SWISS-4q-flush helper: 4 KiB-aligned extent write with auto-RMW for
 * non-aligned (off, len). Does NOT update si_size or stamp timestamps
 * — that's the caller's responsibility (different for direct writes
 * vs. flush-callback writes). Used by both fs_write_regular_locked's
 * direct branch AND the dirty-buffer drain callback at flush time.
 *
 * Realizes the alignment-RMW logic SWISS-4q P1 introduced for the
 * file-tail case (extent layer requires (off, len) ≡ 0 mod 4 KiB).
 *
 * Caller holds fs->lock. */
static stm_status fs_write_extent_aligned_locked(stm_fs *fs,
                                                       uint64_t ds, uint64_t ino,
                                                       uint64_t off,
                                                       const void *buf,
                                                       size_t len)
{
    if (len == 0u) return STM_OK;
    const uint64_t BLK = 4096u;
    uint64_t end_off = off + (uint64_t)len;
    bool aligned = (off % BLK == 0u) && ((uint64_t)len % BLK == 0u);
    if (aligned) {
        return stm_sync_write_extent(fs->sync, ds, ino, off, buf, len);
    }
    uint64_t aligned_off = off & ~(BLK - 1u);
    uint64_t aligned_end = (end_off + BLK - 1u) & ~(BLK - 1u);
    if (aligned_end > (uint64_t)STM_FS_RECORDSIZE_MAX + aligned_off) {
        return STM_ERANGE;
    }
    uint64_t aligned_len = aligned_end - aligned_off;
    uint8_t *scratch = (uint8_t *)calloc(1, (size_t)aligned_len);
    if (!scratch) return STM_ENOMEM;
    size_t got = 0;
    stm_status rs = stm_sync_read_extent(fs->sync, ds, ino, aligned_off,
                                               scratch, (size_t)aligned_len, &got);
    if (rs != STM_OK && rs != STM_ENOENT) {
        free(scratch);
        return rs;
    }
    memcpy(scratch + (off - aligned_off), buf, len);
    stm_status ws = stm_sync_write_extent(fs->sync, ds, ino, aligned_off,
                                              scratch, (size_t)aligned_len);
    free(scratch);
    return ws;
}

/* SWISS-4q-flush drain callback: each buffered range becomes one
 * stm_sync_write_extent via fs_write_extent_aligned_locked. The
 * callback runs under stm_dirty_buffer's internal mutex AND under
 * fs->lock (the caller's lock). The aligned helper takes sync->lock
 * internally; lock order fs->lock → dbuf->mu → sync->lock holds. */
static stm_status fs_flush_drain_cb(void *user, uint64_t ds, uint64_t ino,
                                        uint64_t off, uint64_t len,
                                        const void *data)
{
    stm_fs *fs = (stm_fs *)user;
    return fs_write_extent_aligned_locked(fs, ds, ino, off, data, (size_t)len);
}

/* Flush one inode's buffered ranges. Caller holds fs->lock. */
static stm_status fs_flush_ino_locked(stm_fs *fs, uint64_t ds, uint64_t ino)
{
    return stm_dirty_buffer_drain_ino(fs->dirty_buffer, ds, ino,
                                            fs_flush_drain_cb, fs);
}

/* Flush every inode's buffered ranges. Caller holds fs->lock. */
static stm_status fs_flush_all_locked(stm_fs *fs)
{
    return stm_dirty_buffer_drain_all(fs->dirty_buffer,
                                            fs_flush_drain_cb, fs);
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
    /* R81 P3-3: zero-length write is a no-op; skip the stamp and the
     * inode_set entirely so spurious mtime/ctime bumps don't fool
     * `make` / build systems that probe via write(fd, buf, 0). The
     * EXTENT path's stm_sync_write_extent already rejects len==0 with
     * STM_EINVAL, so this short-circuit makes INLINE behavior
     * symmetric with EXTENT. Linux ext4/XFS short-circuit similarly. */
    if (len == 0u) return STM_OK;

    uint8_t kind = iv->si_data_kind;
    uint64_t end_off = off + (uint64_t)len;

    /* P8-POSIX-7a-seals: refuse writes per the inode's seal mask BEFORE
     * any state mutation. SEAL_WRITE / SEAL_FUTURE_WRITE block all
     * writes (Linux fcntl(2) F_SEAL_WRITE / F_SEAL_FUTURE_WRITE);
     * SEAL_GROW blocks any write that would extend si_size past its
     * current value. Refusal is STM_EPERM (POSIX errno that Linux
     * returns for the same condition).
     *
     * R82 P3-1: ordering note — the zero-length short-circuit above
     * (line 611) returns STM_OK without checking seals, matching
     * Linux's `write(fd, buf, 0)` semantics on a sealed file (write(2)
     * with count=0 is a no-op even on read-only FDs / sealed files).
     * Past line 611 we know len > 0 and the seal check is meaningful. */
    uint32_t flags = stm_load_le32(iv->si_flags);
    if (flags & (STM_INO_FLAG_SEAL_WRITE | STM_INO_FLAG_SEAL_FUTURE_WRITE)) {
        return STM_EPERM;
    }
    if (flags & STM_INO_FLAG_SEAL_GROW) {
        uint64_t cur_size = stm_load_le64(iv->si_size);
        if (end_off > cur_size) return STM_EPERM;
    }

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
            /* P8-POSIX-7a: stamp mtime + ctime on the modified inode.
             * Every successful fs_write is a content change → both
             * mtime + ctime advance per POSIX. */
            fs_stamp_mtime_ctime_now(iv);
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
        /* P8-POSIX-7a: stamp mtime + ctime on the transitioned inode.
         * The transition is both a content change (data moved into
         * extent) AND a kind transition (INLINE → EXTENT) — POSIX
         * stamps mtime + ctime on either alone. */
        fs_stamp_mtime_ctime_now(iv);
        return stm_inode_set(iidx, ds, ino, iv);
    }

    if (kind == STM_DATA_EXTENT) {
        /* SWISS-4q-flush activation: small writes (< STM_FLUSH_DIRECT_
         * THRESHOLD_BYTES) land in the dirty buffer. Large writes go
         * straight to the extent layer. Per writeback.tla, the buffer
         * absorbs many-small-writes (tarball unpack, code build, etc.)
         * and emits them as fewer/larger extents at flush time.
         *
         * Direct writes pre-flush the inode's buffered ranges so a
         * stale buffered range doesn't shadow newer direct data
         * post-overlay. */
        if (len < STM_FLUSH_DIRECT_THRESHOLD_BYTES) {
            stm_status ic = stm_dirty_buffer_insert(fs->dirty_buffer,
                                                        ds, ino, off,
                                                        (uint64_t)len, buf);
            if (ic == STM_ENOSPC) {
                /* Per writeback.tla::BufferBoundedSize retry-on-ENOSPC
                 * dance: flush this inode, retry; if still ENOSPC the
                 * global cap is the issue, flush every inode + retry. */
                stm_status fr = fs_flush_ino_locked(fs, ds, ino);
                if (fr == STM_OK) {
                    ic = stm_dirty_buffer_insert(fs->dirty_buffer,
                                                    ds, ino, off,
                                                    (uint64_t)len, buf);
                }
                if (ic == STM_ENOSPC) {
                    fr = fs_flush_all_locked(fs);
                    if (fr == STM_OK) {
                        ic = stm_dirty_buffer_insert(fs->dirty_buffer,
                                                        ds, ino, off,
                                                        (uint64_t)len, buf);
                    }
                }
            }
            if (ic != STM_OK) return ic;
        } else {
            /* Direct path: pre-flush this inode's buffered ranges so
             * the overlay at read-after-direct-write doesn't shadow
             * the just-written direct extent. */
            stm_status fr = fs_flush_ino_locked(fs, ds, ino);
            if (fr != STM_OK) return fr;
            stm_status ws = fs_write_extent_aligned_locked(fs, ds, ino,
                                                                off, buf, len);
            if (ws != STM_OK) return ws;
        }
        /* Size + timestamp update — common to both buffered and direct
         * paths. The buffered write's bytes aren't on-disk yet, but
         * the inode metadata records the LOGICAL post-write state and
         * the buffer overlay surfaces those bytes on subsequent reads.
         * Crash before sync_commit loses both the buffer AND the
         * in-memory inode update; on remount, neither has happened. */
        uint64_t cur_size = stm_load_le64(iv->si_size);
        if (end_off > cur_size) {
            iv->si_size = stm_store_le64(end_off);
        }
        /* P8-POSIX-7a: stamp mtime + ctime on every successful extent
         * write — same posture for buffered + direct. */
        fs_stamp_mtime_ctime_now(iv);
        return stm_inode_set(iidx, ds, ino, iv);
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
        /* SWISS-4q-flush: probe the dirty buffer. If this inode has
         * buffered ranges, we take the buffered read path; otherwise
         * preserve the original (non-buffer) behavior verbatim. */
        bool buffer_has_data =
            stm_dirty_buffer_has_ino(fs->dirty_buffer, ds, ino);
        if (!buffer_has_data) {
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
        /* Buffered path: zero-fill the effective range so holes +
         * buffer-only ranges read as zeros (POSIX hole semantics),
         * then read the extent layer (fills what it has, leaves the
         * rest zero), then overlay the buffer's newer bytes on top
         * (writeback.tla::ReadHidesFlushOrder). Always returns
         * effective_len so the caller's loop sees the full POSIX
         * range — a buffer-only range past the extent edge is
         * surfaced via overlay. */
        uint64_t logical_avail = cur_size - off;
        size_t effective_len = ((uint64_t)len < logical_avail)
                                  ? len : (size_t)logical_avail;
        if (effective_len > 0u) memset(buf, 0, effective_len);
        size_t got_ext = 0;
        stm_status rs = stm_sync_read_extent(fs->sync, ds, ino, off,
                                                buf, effective_len, &got_ext);
        if (rs != STM_OK && rs != STM_ENOENT) return rs;
        stm_dirty_buffer_overlay(fs->dirty_buffer, ds, ino, off,
                                    effective_len, buf);
        if (out_read) *out_read = effective_len;
        return STM_OK;
    }
    return STM_ENOTSUPPORTED;
}

stm_status stm_fs_write(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                          uint64_t off, const void *buf, size_t len)
{
    if (!fs) return STM_EINVAL;
    pthread_rwlock_wrlock(&fs->global);
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
                pthread_rwlock_unlock(&fs->global);
                return rs;
            }
            /* Not a regular file — fall through. */
        }
        /* Inode not found — fall through. */
    }

    stm_status s = stm_sync_write_extent(fs->sync, dataset_id, ino, off,
                                            buf, len);
    pthread_rwlock_unlock(&fs->global);
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
    pthread_rwlock_wrlock(&fs->global);
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
                pthread_rwlock_unlock(&fs->global);
                return rs;
            }
        }
    }

    stm_status s = stm_sync_read_extent(fs->sync, dataset_id, ino, off,
                                           buf, len, out_read);
    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    uint64_t child_ino = 0;
    stm_status ds = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          &child_ino, NULL, NULL);
    pthread_rwlock_unlock(&fs->global);
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
    /* PARALLEL-3 impl-2 CREATE-shape: SH + parent pin + fresh-child pin.
     * The new_ino isn't known until after alloc, but design doc §3.4
     * notes that pinning new_ino out-of-order is safe — no other
     * writer can have a reference until we publish via the dirent.
     * The pin on new_ino is uncontended by construction. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Pin parent first so its type + dirent set are stable across
     * the alloc + dirent install. */
    stm_inode_handle *h_parent = NULL;
    stm_status pp = stm_inode_pin(iidx, dataset_id, parent_ino, &h_parent);
    if (pp != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return pp;
    }

    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
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
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return as;
    }

    /* Pin the freshly-allocated inode. Until the dirent below
     * publishes it, no other writer can resolve to it, so this pin
     * is uncontended (design doc §3.4). */
    stm_inode_handle *h_child = NULL;
    stm_status cp = stm_inode_pin(iidx, dataset_id, child_ino, &h_child);
    if (cp != STM_OK) {
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return cp;
    }

    /* Read back the alloc'd inode's gen for the dirent's child_gen
     * field — `stm_inode_alloc` stamps gen via AllocFresh (=0) or
     * AllocReused (= prior_gen + 1); the dirent records this so
     * stale-fid detection works across the lifecycle. */
    struct stm_inode_value cv = {0};
    stm_status cs = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
    if (cs != STM_OK) {
        /* Defensive: should never happen right after alloc. Roll back. */
        stm_inode_unpin(iidx, h_child);
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return cs;
    }
    uint64_t child_gen = stm_load_le64(cv.si_gen);

    /* P8-POSIX-7a: stamp btime + atime + mtime + ctime at creation.
     * POSIX requires btime set at create and never modified thereafter.
     * The freshly-allocated inode comes out of stm_inode_alloc with
     * all timestamps zero — without this, statx would surface
     * (0, 0) as the creation time which downstream tools treat as
     * "1970-01-01 epoch" or as a sentinel for "never set". Stamp
     * BEFORE the dirent install so a successful create publishes
     * the inode with live timestamps; failed dirent rolls back the
     * inode entirely. Lock-posture infallibility: stm_inode_set
     * cannot fail here (R76 P3-1 / R78 P3-1 argument — every
     * STM_E* return presupposes a state mutation only the
     * alloc/free path can perform; under our parent + child pin
     * no other writer can race with the allocator's published state
     * for this child). */
    fs_stamp_create_times(&cv);
    stm_status ts = stm_inode_set(iidx, dataset_id, child_ino, &cv);
    if (ts != STM_OK) {
        stm_inode_unpin(iidx, h_child);
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return ts;
    }

    /* Link in parent. Roll back the inode if the dirent fails. */
    stm_status ds = stm_dirent_alloc(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          child_ino, child_gen, child_dt_type);
    if (ds != STM_OK) {
        stm_inode_unpin(iidx, h_child);
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return ds;
    }

    *out_child_ino = child_ino;
    stm_inode_unpin(iidx, h_child);
    stm_inode_unpin(iidx, h_parent);
    pthread_rwlock_unlock(&fs->global);
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

/* P8-POSIX-7a-anon: stm_fs_create_anon — Linux O_TMPFILE shape.
 * Allocates an orphan inode (nlink=0 + STM_INO_FLAG_ORPHAN) and
 * does NOT install any dirent. The orphan persists until explicitly
 * materialized via stm_fs_linkat_anon or freed via stm_fs_unlink_anon.
 * Composes inode.tla::AllocAnon. */
/* P9-9P-1a: initialize a dataset's root inode. Allocates the
 * dataset's first inode (which the allocator returns as ino=1)
 * with mode S_IFDIR | (mode & 0777). Refuses if the dataset
 * already has an inode at ino=1 (returns STM_EEXIST). The 9P
 * server's Tattach handler binds the connection's root fid to
 * (dataset_id, 1); this wrapper closes the bootstrap gap. */
stm_status stm_fs_init_dataset_root(stm_fs *fs, uint64_t dataset_id,
                                       uint32_t mode, uint32_t uid,
                                       uint32_t gid,
                                       uint64_t *out_root_ino)
{
    /* Uniform out-param contract: zero-init BEFORE arg validation. */
    if (out_root_ino) *out_root_ino = 0;
    if (!fs || !out_root_ino) return STM_EINVAL;
    if (dataset_id == 0u) return STM_EINVAL;
    uint32_t effective_mode = (mode & 07777u) | (uint32_t)S_IFDIR;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Refuse if dataset already has ino=1 — caller invoked twice or
     * the dataset was already initialized via the test seam. */
    struct stm_inode_value probe = {0};
    stm_status ps = stm_inode_lookup(iidx, dataset_id, /*ino=*/1u, &probe);
    if (ps == STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EEXIST;
    }
    if (ps != STM_ENOENT) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    uint64_t new_ino = 0;
    stm_status as = stm_inode_alloc(iidx, dataset_id, effective_mode,
                                         uid, gid, &new_ino);
    if (as != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return as;
    }
    /* Allocator state on a fresh dataset MUST yield ino=1. If not,
     * the dataset was non-fresh in a way the EEXIST probe missed
     * (e.g., ino=2 exists but ino=1 doesn't — pathological). */
    if (new_ino != 1u) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    /* Stamp creation timestamps + persist (mirrors stm_fs_create_anon
     * + the regular create-stamp shape). */
    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, new_ino, &iv);
    if (ls == STM_OK) {
        fs_stamp_create_times(&iv);
        (void)stm_inode_set(iidx, dataset_id, new_ino, &iv);
    }

    *out_root_ino = new_ino;
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

stm_status stm_fs_create_anon(stm_fs *fs, uint64_t dataset_id,
                                  uint32_t mode, uint32_t uid, uint32_t gid,
                                  uint64_t *out_child_ino)
{
    /* Uniform out-param contract: zero-init BEFORE arg validation. */
    if (out_child_ino) *out_child_ino = 0;
    if (!fs || !out_child_ino) return STM_EINVAL;
    if (dataset_id == 0u) return STM_EINVAL;
    /* Same mode-bits contract as stm_fs_create_file. */
    uint32_t mtype = mode & (uint32_t)S_IFMT;
    if (mtype != 0u && mtype != (uint32_t)S_IFREG) return STM_EINVAL;
    uint32_t effective_mode = (mode & 07777u) | (uint32_t)S_IFREG;

    /* PARALLEL-3 impl-2: orphan-create is fundamentally just an
     * allocator action — no other inode is involved, and the new_ino
     * is unreachable to other writers until the caller publishes it.
     * SH is sufficient.
     *
     * R133 P2-1 (R133 close): defense-in-depth — also pin the
     * fresh new_ino across the stamp+set sequence. Matches the
     * design doc §3.4 posture used by every other CREATE-shape
     * port (fs_create_inode_and_link, stm_fs_symlink). The pin
     * is uncontended by construction (no dirent points to new_ino
     * yet, and the caller hasn't published it) but keeps the per-
     * inode-mutex invariant uniform across the create surface so
     * a future feature that exposes new_ino mid-create (e.g., a
     * fid-bind hook for janus/9p before stamp completes) doesn't
     * become a latent race. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    uint64_t new_ino = 0;
    stm_status as = stm_inode_alloc_anon(iidx, dataset_id, effective_mode,
                                              uid, gid, &new_ino);
    if (as != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return as;
    }

    /* Pin the freshly-allocated orphan inode (R133 P2-1). Uncontended
     * by construction per design §3.4. */
    stm_inode_handle *h_child = NULL;
    stm_status cp = stm_inode_pin(iidx, dataset_id, new_ino, &h_child);
    if (cp != STM_OK) {
        (void)stm_inode_free(iidx, dataset_id, new_ino);
        pthread_rwlock_unlock(&fs->global);
        return cp;
    }

    /* Stamp creation timestamps + persist. The fresh-allocated record
     * is read back, stamped, and committed via stm_inode_set so the
     * post-create state is consistent (mirrors the regular
     * fs_create_inode_and_link's create-stamp shape). */
    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, new_ino, &iv);
    if (ls == STM_OK) {
        fs_stamp_create_times(&iv);
        /* stm_inode_set's writer-side guards exempt orphan records
         * (ORPHAN flag set + nlink=0) from the FREED⇔nlink≥1 check —
         * see the inode.c R71 P1-1 / P8-POSIX-7a-anon symmetry. */
        (void)stm_inode_set(iidx, dataset_id, new_ino, &iv);
    }

    *out_child_ino = new_ino;
    stm_inode_unpin(iidx, h_child);
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* P8-POSIX-7a-anon: stm_fs_linkat_anon — materialize an orphan inode
 * by installing the first dirent + flipping nlink 0→1 + clearing the
 * ORPHAN flag. Composes inode.tla::Materialize. */
stm_status stm_fs_linkat_anon(stm_fs *fs, uint64_t dataset_id,
                                  uint64_t ino,
                                  uint64_t parent_ino,
                                  const uint8_t *name, uint8_t name_len)
{
    if (!fs || !name) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u || parent_ino == 0u) return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;

    /* PARALLEL-3 impl-2: 2-inode op (parent + existing orphan). Both
     * ids known upfront — use sorted pin to prevent the 2-cycle
     * deadlock with a concurrent linkat_anon on the swapped pair. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Refuse the degenerate ino == parent_ino case BEFORE pin_two
     * (which refuses it with STM_EINVAL anyway — keep the message
     * surface stable). */
    if (ino == parent_ino) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_inode_handle *h_parent = NULL;
    stm_inode_handle *h_child  = NULL;
    stm_status ps2 = stm_inode_pin_two(iidx, dataset_id, parent_ino,
                                            dataset_id, ino,
                                            &h_parent, &h_child);
    if (ps2 != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps2;
    }

    /* Validate parent is a directory. */
    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    /* Validate target inode exists + is in orphan state. The detailed
     * check happens inside stm_inode_materialize (which returns
     * STM_ENOENT if not found, STM_EINVAL if not orphan); we look up
     * here too for the dirent_alloc gen + child_type. */
    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) {
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }
    uint32_t flags = stm_load_le32(iv.si_flags);
    if (!(flags & STM_INO_FLAG_ORPHAN)) {
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    uint64_t child_gen = stm_load_le64(iv.si_gen);

    /* Two-step atomicity: install the dirent FIRST (so a failed
     * dirent_alloc leaves the orphan unchanged + caller can retry).
     * On dirent_alloc success, materialize the inode (cannot fail
     * under our pin per R76 P3-1 / R78 P3-1 lock-posture argument).
     * On a hypothetical post-materialize-rollback we'd need to undo
     * the dirent — but materialize is provably infallible here (no
     * gen / nlink / FREED race), so no rollback path needed. */
    stm_status das = stm_dirent_alloc(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          ino, child_gen, STM_DT_REG);
    if (das != STM_OK) {
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
        return das;
    }
    stm_status ms = stm_inode_materialize(iidx, dataset_id, ino);
    if (ms != STM_OK) {
        /* Defense-in-depth — best-effort rollback (should never fire). */
        (void)stm_dirent_unlink(didx, dataset_id, parent_ino,
                                     name, name_len);
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
        stm_fs_mark_wedged(fs);
        return ms;
    }

    /* Stamp ctime on the now-linked inode (the materialization is a
     * metadata change). Read back since materialize mutates si_flags
     * + si_nlink. */
    struct stm_inode_value iv2 = {0};
    stm_status ls2 = stm_inode_lookup(iidx, dataset_id, ino, &iv2);
    if (ls2 == STM_OK) {
        fs_stamp_ctime_now(&iv2);
        (void)stm_inode_set(iidx, dataset_id, ino, &iv2);
    }

    stm_inode_unpin(iidx, h_parent);
    stm_inode_unpin(iidx, h_child);
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* P8-POSIX-7a-anon: stm_fs_unlink_anon — explicitly free an orphan.
 * Composes inode.tla::FreeAnon. */
stm_status stm_fs_unlink_anon(stm_fs *fs, uint64_t dataset_id,
                                  uint64_t ino)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    /* PARALLEL-3 impl-2: single-inode op (just the orphan). SH + pin. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_inode_handle *h = NULL;
    stm_status pp = stm_inode_pin(iidx, dataset_id, ino, &h);
    if (pp != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return pp;
    }

    /* Validate the target is an orphan before freeing — caller must
     * use stm_fs_unlink for linked inodes. */
    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) {
        stm_inode_unpin(iidx, h);
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }
    uint32_t flags = stm_load_le32(iv.si_flags);
    if (!(flags & STM_INO_FLAG_ORPHAN)) {
        stm_inode_unpin(iidx, h);
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* R128 P1-2: orphan-free has no nlink check (anonymous inodes
     * always have nlink=0 when reachable via this entry point). Drop
     * the dirty-buffer entry AND truncate the inode's extents BEFORE
     * the free; otherwise the buffer's (ds, ino) entry outlives the
     * inode slot's free and surfaces as a confused-deputy write into
     * whatever inode reuses the slot. Same shape as the canonical
     * unlink path and rename's overwrite branch. */
    bool cleanup_did_truncate =
        fs_pre_inode_free_cleanup_locked(fs, dataset_id, ino, &iv);

    /* stm_inode_free transitions ALLOCATED → FREED, sets FREED flag,
     * clears nlink. The ORPHAN flag survives in si_flags but is moot
     * (FREED records aren't readable via lookup). The next AllocReused
     * on this slot's records[] entry will memset the value, clearing
     * both flags. */
    stm_status fs_free = stm_inode_free(iidx, dataset_id, ino);

    /* R128 P1-2 close: reclaim trigger. Same R50 P2-1 strict-less-than
     * shape as the canonical unlink path's reclaim. Gate on (a) the
     * pre-cleanup actually truncated extents (otherwise nothing
     * PENDING needs reclaiming — anon-inode-with-no-data, inline-
     * only files, directories, symlinks ALL skip the ~200ms commit
     * pair) AND (b) fs_free == STM_OK so a failed free doesn't
     * commit half-baked state. */
    if (cleanup_did_truncate && fs_free == STM_OK) {
        fs_post_inode_free_reclaim_locked(fs);
    }

    stm_inode_unpin(iidx, h);
    pthread_rwlock_unlock(&fs->global);
    return fs_free;
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

/* R128 P1-1 + P1-2: pre-free cleanup helper. Drops the dirty_buffer
 * entry for (ds, ino) AND truncates the inode's extents to 0. Caller
 * MUST hold fs->lock, have looked up `cv`, and be about to free the
 * inode (via stm_inode_unlink-with-cascade OR direct stm_inode_free).
 *
 * The helper is the load-bearing fix for the audit's P1 class: the
 * dirty buffer is keyed by (dataset_id, ino) ONLY — no si_gen — so
 * a buffered range that outlives its inode's free path will surface
 * as a stale write to whatever inode reuses the slot next. Every
 * inode-freeing site MUST call this BEFORE the free.
 *
 * Gates internally on (regular file, EXTENT data kind). nlink check
 * is the caller's responsibility — fs_unlink_inode_and_dirent guards
 * with `nlink == 1u` (about-to-cascade-free); stm_fs_unlink_anon does
 * NO guard (orphan-free is direct); stm_fs_rename's overwrite branch
 * guards via `dst_freed_unused`'s precondition (nlink == 1 → unlink
 * cascades).
 *
 * Best-effort: a stm_sync_truncate failure here leaves leaked paddrs
 * but doesn't break the free. Returns nothing.
 */
static bool fs_pre_inode_free_cleanup_locked(stm_fs *fs,
                                                  uint64_t dataset_id,
                                                  uint64_t ino,
                                                  const struct stm_inode_value *cv)
{
    if (!cv) return false;
    uint32_t cmode = stm_load_le32(cv->si_mode);
    bool is_reg = ((cmode & (uint32_t)S_IFMT) == (uint32_t)S_IFREG);
    bool is_extent = (cv->si_data_kind == STM_DATA_EXTENT);
    if (is_reg && is_extent) {
        stm_dirty_buffer_drop_ino(fs->dirty_buffer, dataset_id, ino);
        (void)stm_sync_truncate(fs->sync, dataset_id, ino, /*new_size=*/0u);
        return true;
    }
    return false;
}

/* R128 P1-1 + P1-2: post-free reclaim helper. Double-commit to step
 * the allocator's free_gen past committed_gen (R50 P2-1 strict-less-
 * than predicate). Caller MUST hold fs->lock. Same posture as the
 * inline double-commit at the original unlink path's reclaim trigger
 * (SWISS-4q P2). Extracted so rename + unlink_anon can reuse it.
 *
 * Cost: two stm_sync_commit calls (~10-50 ms each on local NVMe).
 * Acceptable; the alternative is permanent PENDING leak per cycle.
 */
static void fs_post_inode_free_reclaim_locked(stm_fs *fs)
{
    (void)stm_sync_commit(fs->sync);
    (void)stm_sync_commit(fs->sync);
}

/* Common path for unlink / rmdir. `expect_dir` selects the type
 * filter: true → child must be S_IFDIR (rmdir), false → child must
 * NOT be S_IFDIR (unlink). On the rmdir path the child must also be
 * empty (count_for_dir == 0). */
/* P9.5-PARALLEL-3 impl-2: bound retries for the TOCTOU re-validation
 * loop in fs_unlink_inode_and_dirent. Under high contention a racing
 * rename could repeatedly change which inode the dirent points at;
 * cap re-attempts to avoid livelock. 16 attempts is wildly conservative —
 * the canonical case completes on the first try. */
#define FS_UNLINK_MAX_ATTEMPTS  16

static stm_status fs_unlink_inode_and_dirent(stm_fs *fs,
                                                  uint64_t dataset_id,
                                                  uint64_t parent_ino,
                                                  const uint8_t *name,
                                                  uint8_t name_len,
                                                  bool expect_dir)
{
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* PARALLEL-3 impl-2 lookup-pin-reverify loop. We need to pin BOTH
     * parent AND child in ascending (ds, ino) order, but child_ino is
     * only discoverable via a dirent lookup. The pre-pin lookup is
     * advisory — between it and our pin, a concurrent writer (under
     * its own pin) could rename the entry to point elsewhere. We
     * therefore lookup-pin-reverify with bounded retries. */
    stm_inode_handle *h_parent = NULL;
    stm_inode_handle *h_child  = NULL;
    uint64_t child_ino = 0;
    struct stm_inode_value cv = {0};
    int attempts = 0;

    for (;;) {
        if (attempts++ >= FS_UNLINK_MAX_ATTEMPTS) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EAGAIN;
        }

        /* Pre-pin lookup. */
        uint64_t observed_child = 0;
        stm_status ds = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                              name, name_len,
                                              &observed_child, NULL, NULL);
        if (ds != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ds;       /* STM_ENOENT if not linked */
        }

        /* Pin parent + child in ascending (ds, ino) order. */
        stm_status ps = stm_inode_pin_two(iidx,
                                              dataset_id, parent_ino,
                                              dataset_id, observed_child,
                                              &h_parent, &h_child);
        if (ps != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ps;       /* STM_ENOENT if parent or child gone */
        }

        /* Under both pins: re-validate parent is still a dir AND the
         * dirent still points to observed_child. */
        struct stm_inode_value pv = {0};
        stm_status pls = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
        if (pls != STM_OK) {
            stm_inode_unpin(iidx, h_parent);
            stm_inode_unpin(iidx, h_child);
            pthread_rwlock_unlock(&fs->global);
            return pls;
        }

        uint64_t revalidated_child = 0;
        stm_status rds = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                                name, name_len,
                                                &revalidated_child, NULL, NULL);
        if (rds != STM_OK || revalidated_child != observed_child) {
            /* Dirent changed between pre-pin lookup and pin. Drop pins
             * and retry. Common cause: a racing rename swapped the
             * entry. */
            stm_inode_unpin(iidx, h_parent);
            stm_inode_unpin(iidx, h_child);
            h_parent = NULL;
            h_child  = NULL;
            if (rds != STM_OK) {
                pthread_rwlock_unlock(&fs->global);
                return rds;
            }
            continue;
        }

        child_ino = observed_child;
        /* Load child inode value (for type discrimination + empty-check). */
        stm_status cs = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
        if (cs != STM_OK) {
            /* Dirent points at a missing inode — corruption. Pin
             * succeeded earlier, so the inode WAS allocated then —
             * a freed-between-pin-and-load is impossible under our
             * own pin. Surface the error. */
            stm_inode_unpin(iidx, h_parent);
            stm_inode_unpin(iidx, h_child);
            pthread_rwlock_unlock(&fs->global);
            return cs;
        }
        break;  /* All locks held; cv loaded; proceed below. */
    }
    uint32_t cmode = stm_load_le32(cv.si_mode);
    bool child_is_dir = ((cmode & (uint32_t)S_IFMT) == (uint32_t)S_IFDIR);
    if (expect_dir && !child_is_dir) {
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
        return STM_ENOTDIR;
    }
    if (!expect_dir && child_is_dir) {
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
        return STM_EISDIR;
    }
    if (expect_dir) {
        size_t n = 0;
        stm_status cn = stm_dirent_count_for_dir(didx, dataset_id, child_ino, &n);
        if (cn != STM_OK) {
            stm_inode_unpin(iidx, h_parent);
            stm_inode_unpin(iidx, h_child);
            pthread_rwlock_unlock(&fs->global);
            return cn;
        }
        if (n != 0u) {
            stm_inode_unpin(iidx, h_parent);
            stm_inode_unpin(iidx, h_child);
            pthread_rwlock_unlock(&fs->global);
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
        stm_inode_unpin(iidx, h_parent);
        stm_inode_unpin(iidx, h_child);
        pthread_rwlock_unlock(&fs->global);
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

    /* SWISS-4q P2: drop the inode's extents BEFORE the inode-unlink
     * cascade-frees the inode. stm_inode_unlink only mutates the
     * inode-index record (nlink-- + transition to FREED at nlink=0);
     * it does NOT walk the extent index. Without this drop, every
     * extent record + every paddr the inode owned LEAKS — the
     * allocator never reclaims the blocks, and the volume hits
     * ENOSPC after one cycle of "write 1.8 GB / rm" on a 3 GB
     * pool (user-reported 2026-05-10).
     *
     * Conditions for the drop:
     *   1. Regular file (S_IFREG) — dirs hold no extent data;
     *      symlinks store the target inline; devices have no data.
     *   2. EXTENT data_kind — INLINE data lives inside the inode
     *      record itself and is freed when the inode transitions
     *      to FREED.
     *   3. nlink == 1 — this is the LAST link. With future hard
     *      links (nlink > 1), unlinking one dirent leaves the
     *      others reachable; we must NOT drop extents until the
     *      last link goes away.
     *
     * stm_sync_truncate(ds, ino, 0) is the right primitive: it
     * walks the extent index for (ds, ino) and routes every paddr
     * through sync_drop_paddr_locked → allocator's free path. The
     * call is best-effort — a failure here leaves leaked extents
     * (worse: the inode also gets freed by the unlink below, so
     * the leak is permanent until offline scrub) but doesn't break
     * the unlink itself. Returns STM_OK on a fresh-inode no-extent
     * case (nothing to drop). */
    bool cleanup_did_truncate = false;
    {
        uint32_t cur_nlink = stm_load_le32(cv.si_nlink);
        if (cur_nlink == 1u) {
            /* SWISS-4q-flush: drop any buffered ranges for this inode
             * BEFORE the extent-layer truncate. Once the inode is
             * gone, buffered plaintext for it is unreachable —
             * destroying it here keeps total_bytes accurate AND
             * prevents a future flush from emitting extents under
             * a freed inode. R128 P1-1 close: helper extracted so
             * rename's overwrite branch + stm_fs_unlink_anon share
             * the same cleanup. Helper returns true iff it truncated
             * extents — the post-reclaim double-commit below gates on
             * that signal so dir/symlink/inline-only unlinks skip the
             * ~200 ms commit pair entirely. */
            cleanup_did_truncate = fs_pre_inode_free_cleanup_locked(
                fs, dataset_id, child_ino, &cv);
        }
    }

    /* P8-POSIX-3: nlink-aware unlink. Decrement nlink; cascade-free
     * triggers atomically when nlink reaches 0. For the MVP-single-
     * link case (no hard links yet, every alloc has nlink=1) this
     * always cascades — same observable outcome as the prior
     * unconditional stm_inode_free, but with the nlink semantics
     * that hard-link-aware paths require. */
    bool freed = false;
    (void)stm_inode_unlink(iidx, dataset_id, child_ino, &freed);

    /* P8-POSIX-7a: unlink that decrements nlink without cascade-freeing
     * is a metadata change → ctime auto-stamps to "now" on the
     * surviving inode. Cascade-freed inodes are no longer ALLOCATED
     * (FREED state), so stamping is skipped. */
    if (!freed) {
        struct stm_inode_value cv2 = {0};
        stm_status ls2 = stm_inode_lookup(iidx, dataset_id, child_ino, &cv2);
        if (ls2 == STM_OK) {
            fs_stamp_ctime_now(&cv2);
            (void)stm_inode_set(iidx, dataset_id, child_ino, &cv2);
        }
    }

    /* SWISS-4q P2 reclaim trigger: when we just freed an inode AND
     * dropped its extents (the truncate-to-0 above), the allocator
     * now holds PENDING entries with free_gen=current_gen. The
     * allocator's sweep predicate is `free_gen < committed_gen`
     * (sync.c:2412); a single commit at target_gen=current_gen
     * persists the PENDING entries but does NOT reclaim them — the
     * sweep skips because free_gen == committed_gen (strict less-
     * than). The NEXT commit at committed_gen+2 catches them.
     *
     * Without this double-commit, blocks freed via unlink remain
     * PENDING for the rest of the stratumd session; the next
     * allocation hits ENOSPC even though the volume "looks empty"
     * to the user. User-reported 2026-05-10: "copy 1.8 GB to stm,
     * delete, repeat → ENOSPC after one cycle."
     *
     * The double commit is wired here (NOT in stm_fs_commit) so
     * the public commit semantics (gen advance by 2 per call)
     * remain unchanged for tests that pin it. The unlink path is
     * the only mutator that drops extents AND assumes they're
     * immediately reusable.
     *
     * Cost: each unlink-of-regular-file takes ~2× longer for the
     * Tfsync that comes from auto-fsync. Acceptable; without this
     * the volume is unusable past one cycle.
     *
     * R128 P1-1 close: helper extracted; rename + unlink_anon share.
     *
     * R130 fix: only fire the double-commit when (a) we actually freed
     * the inode AND (b) the pre-cleanup truncated extents — i.e.,
     * there's reclaim work pending. Pre-R130 the gate was just
     * `if (freed)`, so dir/symlink/inline-only files paid the ~200ms
     * commit pair per unlink even though they had no extents to
     * reclaim. Triggered by ctest's parallel-4 timeouts when test_fs's
     * 159 tests each ran a few unlinks. */
    if (freed && cleanup_did_truncate) {
        fs_post_inode_free_reclaim_locked(fs);
    }

    stm_inode_unpin(iidx, h_parent);
    stm_inode_unpin(iidx, h_child);
    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    stm_status s = stm_inode_lookup(iidx, dataset_id, ino, out_value);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* ========================================================================= */
/* P9.5-PARALLEL-3 impl-1: per-inode-locked setattr-shape ops.               */
/*                                                                            */
/* These three ops (chmod / chown / utimens) are the proof-of-concept single- */
/* inode ports per the design doc §6 step 2. They take fs->global SH         */
/* (rdlock) + the target inode's mutex via stm_inode_pin. Two such ops on    */
/* DISJOINT inodes proceed concurrently; on the SAME inode they serialize on */
/* the per-inode mutex. An unported op (any other public stm_fs_* function)  */
/* takes fs->global EX (wrlock), which waits for outstanding SH holders to   */
/* drain — preserving PARALLEL-2's compound-op atomicity contract.           */
/*                                                                            */
/* Spec composition: realizes the "writer holds inode lock for its full      */
/* compound op body" discipline from compound_ops_per_inode.tla. Single-     */
/* inode ops trivially satisfy LockOrderPreserved (only one target) and      */
/* NoCircularWait (need ≥2 inodes for a cycle).                              */
/*                                                                            */
/* Lock-order: fs->global SH → handle->mu → idx internal mutex (taken by    */
/* stm_inode_lookup + stm_inode_set). The idx internal mutex is RELEASED    */
/* between lookup and set; another writer could re-acquire idx during that  */
/* window — but our per-inode lock excludes any other writer from looking   */
/* up THIS inode for mutation, so the lookup's value is still authoritative */
/* when we issue set. Other inodes' writers using idx concurrently is the   */
/* per-subsystem-linearizable design (PARALLEL-2 contract preserved).      */
/* ========================================================================= */

stm_status stm_fs_chmod(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                           uint32_t mode)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_inode_handle *h = NULL;
    stm_status ps = stm_inode_pin(iidx, dataset_id, ino, &h);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    struct stm_inode_value v = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &v);
    if (ls != STM_OK) {
        stm_inode_unpin(iidx, h);
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }
    /* Preserve the existing file-type bits. Caller may pass either a
     * mode with type bits zeroed (preserve current) or a mode that
     * matches the existing type. Mismatched type bits are rejected. */
    uint32_t cur_mode = stm_load_le32(v.si_mode);
    uint32_t cur_type = cur_mode & (uint32_t)S_IFMT;
    uint32_t new_type = mode & (uint32_t)S_IFMT;
    if (new_type != 0u && new_type != cur_type) {
        stm_inode_unpin(iidx, h);
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    uint32_t new_mode = cur_type | (mode & 07777u);
    v.si_mode = stm_store_le32(new_mode);

    /* P8-POSIX-7a: chmod is a metadata change → ctime auto-stamps to
     * "now" per POSIX. mtime + btime preserved. */
    fs_stamp_ctime_now(&v);

    stm_status ss = stm_inode_set(iidx, dataset_id, ino, &v);
    stm_inode_unpin(iidx, h);
    pthread_rwlock_unlock(&fs->global);
    return ss;
}

stm_status stm_fs_chown(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                           uint32_t uid, uint32_t gid)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_inode_handle *h = NULL;
    stm_status ps = stm_inode_pin(iidx, dataset_id, ino, &h);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    struct stm_inode_value v = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &v);
    if (ls != STM_OK) {
        stm_inode_unpin(iidx, h);
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }
    /* POSIX chown(-1, ...) semantics: UINT32_MAX leaves the field
     * unchanged. Both UINT32_MAX is a no-op. */
    bool changed = false;
    if (uid != UINT32_MAX) { v.si_uid = stm_store_le32(uid); changed = true; }
    if (gid != UINT32_MAX) { v.si_gid = stm_store_le32(gid); changed = true; }

    /* P8-POSIX-7a: chown is a metadata change → ctime auto-stamps to
     * "now" per POSIX, but ONLY if at least one of uid / gid actually
     * changed. The (UINT32_MAX, UINT32_MAX) no-op path leaves ctime
     * unchanged so callers can probe via chown without bumping
     * ctime. mtime + btime preserved. */
    if (changed) fs_stamp_ctime_now(&v);

    stm_status ss = stm_inode_set(iidx, dataset_id, ino, &v);
    stm_inode_unpin(iidx, h);
    pthread_rwlock_unlock(&fs->global);
    return ss;
}

stm_status stm_fs_utimens(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              uint64_t atime_sec, uint32_t atime_nsec,
                              uint64_t mtime_sec, uint32_t mtime_nsec,
                              uint64_t ctime_sec, uint32_t ctime_nsec)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    /* R81 P3-6: ctime_nsec arg is now ignored (P8-POSIX-7a auto-stamps
     * ctime to "now"); skip its validation so weird values don't
     * spuriously reject. atime_nsec / mtime_nsec are still stored
     * and need POSIX bounds. */
    if (atime_nsec >= 1000000000u || mtime_nsec >= 1000000000u)
        return STM_EINVAL;

    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_inode_handle *h = NULL;
    stm_status ps = stm_inode_pin(iidx, dataset_id, ino, &h);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    struct stm_inode_value v = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &v);
    if (ls != STM_OK) {
        stm_inode_unpin(iidx, h);
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }
    v.si_atime_sec  = stm_store_le64(atime_sec);
    v.si_atime_nsec = stm_store_le32(atime_nsec);
    v.si_mtime_sec  = stm_store_le64(mtime_sec);
    v.si_mtime_nsec = stm_store_le32(mtime_nsec);
    /* P8-POSIX-7a: ctime auto-stamps to "now" on every utimens call
     * (POSIX utimensat semantics: setting atime/mtime is a metadata
     * change → ctime updates). The historical caller-supplied
     * ctime_sec/ctime_nsec args are now IGNORED — kept in the
     * signature for API stability. Future API cleanup may drop them.
     * If caller-supplied ctime is non-zero, we still ignore it; the
     * pre-7a "0/0 = leave unchanged" semantic is gone — the closest
     * non-mutating equivalent is "don't call utimens at all". */
    (void)ctime_sec; (void)ctime_nsec;
    fs_stamp_ctime_now(&v);

    stm_status ss = stm_inode_set(iidx, dataset_id, ino, &v);
    stm_inode_unpin(iidx, h);
    pthread_rwlock_unlock(&fs->global);
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

    /* PARALLEL-3 impl-2: link is effectively a 2-inode mutation —
     * src_ino's nlink bumps, dst_parent_ino gets a new dirent.
     * src_parent_ino is only READ (dirent lookup) and stays under
     * its own dirent layer's internal mutex protection. Since
     * src_ino is discovered via dirent lookup, use the TOCTOU
     * re-verify loop pattern from fs_unlink_inode_and_dirent. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Both parents must be directories. Pre-pin check; re-verified
     * via dirent lookup under pin below. */
    struct stm_inode_value spv = {0};
    stm_status ps1 = fs_load_parent_dir(iidx, dataset_id, src_parent_ino, &spv);
    if (ps1 != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps1;
    }
    /* If src and dst share parent, skip the second lookup; otherwise
     * verify dst parent is also a directory. */
    if (dst_parent_ino != src_parent_ino) {
        struct stm_inode_value dpv = {0};
        stm_status ps2 = fs_load_parent_dir(iidx, dataset_id, dst_parent_ino, &dpv);
        if (ps2 != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ps2;
        }
    }

    /* Lookup-pin-reverify: src_ino is discovered via dirent lookup,
     * so a racing rename could move the entry between the pre-pin
     * lookup and our pin. Bounded retries via the same MAX_ATTEMPTS
     * cap as fs_unlink_inode_and_dirent. */
    stm_inode_handle *h_child  = NULL;
    stm_inode_handle *h_dst_p  = NULL;
    uint64_t child_ino = 0;
    uint64_t child_gen = 0;
    uint8_t  child_type = 0;
    int attempts = 0;

    for (;;) {
        if (attempts++ >= FS_UNLINK_MAX_ATTEMPTS) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EAGAIN;
        }

        uint64_t observed_child = 0;
        uint64_t observed_gen = 0;
        uint8_t  observed_type = 0;
        stm_status ds = stm_dirent_lookup(didx, dataset_id, src_parent_ino,
                                              src_name, src_name_len,
                                              &observed_child, &observed_gen,
                                              &observed_type);
        if (ds != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ds;     /* STM_ENOENT if src not linked */
        }
        /* Degenerate self-link case (covered by EPERM below since src
         * would have to be a dir for src == dst_parent_ino to hold —
         * S_IFDIR refuses regardless). Refuse early so pin_two doesn't
         * trip on its duplicate guard. */
        if (observed_child == dst_parent_ino) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }

        stm_status ps2 = stm_inode_pin_two(iidx,
                                                dataset_id, observed_child,
                                                dataset_id, dst_parent_ino,
                                                &h_child, &h_dst_p);
        if (ps2 != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ps2;
        }

        /* TOCTOU re-verify under pins. */
        uint64_t revalidated_child = 0;
        uint64_t revalidated_gen = 0;
        uint8_t  revalidated_type = 0;
        stm_status rds = stm_dirent_lookup(didx, dataset_id, src_parent_ino,
                                                src_name, src_name_len,
                                                &revalidated_child,
                                                &revalidated_gen,
                                                &revalidated_type);
        if (rds != STM_OK || revalidated_child != observed_child ||
            revalidated_gen != observed_gen ||
            revalidated_type != observed_type) {
            stm_inode_unpin(iidx, h_child);
            stm_inode_unpin(iidx, h_dst_p);
            h_child = NULL;
            h_dst_p = NULL;
            if (rds != STM_OK) {
                pthread_rwlock_unlock(&fs->global);
                return rds;
            }
            continue;
        }

        child_ino  = observed_child;
        child_gen  = observed_gen;
        child_type = observed_type;
        break;
    }

    /* POSIX forbids hard-link-on-directory; Linux link(2) returns EPERM.
     * Pre-R82, types.h didn't define STM_EPERM and STM_ENOTSUPPORTED was
     * the closest existing code (R74 P3-2). R82 P2-1 closes that gap:
     * P8-POSIX-7a-seals (de3a6b3) added STM_EPERM = -1 (POSIX-aligned)
     * for sealed-file rejection, and the same code is the natural fit
     * here too — both shapes are POSIX EPERM at the syscall layer. The
     * 9P/FUSE binding layer can now route the EPERM branch directly
     * without a translation hop. */
    if (child_type == STM_DT_DIR) {
        stm_inode_unpin(iidx, h_child);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return STM_EPERM;
    }

    /* Bump nlink first; rollback if dirent install fails. */
    stm_status ils = stm_inode_link(iidx, dataset_id, child_ino);
    if (ils != STM_OK) {
        stm_inode_unpin(iidx, h_child);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
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
         * (nlink underflow). Under child's pin held throughout, the
         * rollback can't actually fail — child_ino was just looked
         * up + linked above, so it's still ALLOCATED with nlink ≥ 2.
         * If the unreachable failure ever triggers, future-us should
         * stm_fs_mark_wedged the volume, since it indicates load-
         * bearing-invariant corruption (LinkedAllocatedHasPositiveNlink
         * from inode.tla). */
        bool freed_unused = false;
        (void)stm_inode_unlink(iidx, dataset_id, child_ino, &freed_unused);
        stm_inode_unpin(iidx, h_child);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return das;       /* STM_EEXIST if name already linked, etc. */
    }

    /* R81 P3-1: link bumps nlink → ctime auto-stamps to "now" per
     * POSIX (link(2) is a metadata change to the inode). Stamp ONLY
     * after the dirent_alloc has succeeded — pre-fix, the stamp
     * landed before dirent_alloc, and a failed dirent_alloc rolled
     * back nlink but left the bumped ctime persisted (POSIX divergence
     * — Linux ext4 doesn't bump ctime on failed link(2)). Lock-
     * posture infallibility applies (R76 P3-1 argument): under
     * child's pin the inode_lookup cannot fail. */
    {
        struct stm_inode_value cv2 = {0};
        stm_status ls2 = stm_inode_lookup(iidx, dataset_id, child_ino, &cv2);
        if (ls2 == STM_OK) {
            fs_stamp_ctime_now(&cv2);
            (void)stm_inode_set(iidx, dataset_id, child_ino, &cv2);
        }
    }

    stm_inode_unpin(iidx, h_child);
    stm_inode_unpin(iidx, h_dst_p);
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* P9-LIB-1d-link: stm_fs_link_by_ino — POSIX link(2) by source inode.
 *
 * Same invariants as stm_fs_link but takes the source inode directly
 * (as 9P2000.L Tlink provides via a fid). Skips the (parent, name) →
 * src_ino dirent resolution; otherwise structurally identical.
 *
 * Mirrors stm_fs_link's audit-derived posture (R74 P3-2: hardlink-on-dir
 * → STM_EPERM; R81 P3-1: ctime stamp AFTER successful dirent_alloc not
 * before; R74 P3-3: lock-posture infallibility for the rollback's
 * stm_inode_unlink (void)-cast).
 */
stm_status stm_fs_link_by_ino(stm_fs *fs, uint64_t dataset_id,
                                 uint64_t src_ino,
                                 uint64_t dst_parent_ino,
                                 const uint8_t *dst_name, uint8_t dst_name_len)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || src_ino == 0u || dst_parent_ino == 0u)
        return STM_EINVAL;
    stm_status nv = fs_validate_dirent_name(dst_name, dst_name_len);
    if (nv != STM_OK) return nv;

    /* PARALLEL-3 impl-2: 2-inode op (src + dst_parent) with both ids
     * known upfront. SH + sorted pin. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Same-inode case: src_ino == dst_parent_ino means linking an
     * inode into itself as a parent — directories are refused below
     * (S_IFDIR → STM_EPERM), and regular files / symlinks can't be
     * a parent dir, so this is degenerate. Refuse with STM_EINVAL
     * (pin_two would otherwise refuse the duplicate too). */
    if (src_ino == dst_parent_ino) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_inode_handle *h_src   = NULL;
    stm_inode_handle *h_dst_p = NULL;
    stm_status ps2 = stm_inode_pin_two(iidx, dataset_id, src_ino,
                                            dataset_id, dst_parent_ino,
                                            &h_src, &h_dst_p);
    if (ps2 != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps2;
    }

    /* Verify dst_parent is a directory. */
    struct stm_inode_value dpv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, dst_parent_ino, &dpv);
    if (ps != STM_OK) {
        stm_inode_unpin(iidx, h_src);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    /* Look up source inode + classify type. */
    struct stm_inode_value siv = {0};
    stm_status sl = stm_inode_lookup(iidx, dataset_id, src_ino, &siv);
    if (sl != STM_OK) {
        stm_inode_unpin(iidx, h_src);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return sl;     /* STM_ENOENT */
    }
    uint32_t src_mode = stm_load_le32(siv.si_mode);
    uint64_t src_gen  = stm_load_le64(siv.si_gen);
    uint8_t  src_dt;
    /* POSIX forbids hard-link-on-directory; Linux link(2) → EPERM.
     * Mirrors stm_fs_link's R82 P2-1 STM_EPERM mapping. */
    if ((src_mode & 0170000u) == 0040000u) {       /* S_IFDIR */
        stm_inode_unpin(iidx, h_src);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return STM_EPERM;
    } else if ((src_mode & 0170000u) == 0100000u) {/* S_IFREG */
        src_dt = STM_DT_REG;
    } else if ((src_mode & 0170000u) == 0120000u) {/* S_IFLNK */
        src_dt = STM_DT_LNK;
    } else {
        /* Other types (chr/blk/fifo/sock) are unreachable at v2.0 — the
         * fs API only creates regs / dirs / symlinks. Defense-in-depth:
         * refuse to link any unsupported type. */
        stm_inode_unpin(iidx, h_src);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return STM_EPERM;
    }

    /* Bump nlink first; rollback if dirent install fails (mirror
     * stm_fs_link's order so the same R74 P3-3 lock-posture argument
     * applies). */
    stm_status ils = stm_inode_link(iidx, dataset_id, src_ino);
    if (ils != STM_OK) {
        stm_inode_unpin(iidx, h_src);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return ils;     /* STM_EOVERFLOW on UINT32_MAX */
    }
    stm_status das = stm_dirent_alloc(didx, dataset_id, dst_parent_ino,
                                          dst_name, dst_name_len,
                                          src_ino, src_gen, src_dt);
    if (das != STM_OK) {
        bool freed_unused = false;
        (void)stm_inode_unlink(iidx, dataset_id, src_ino, &freed_unused);
        stm_inode_unpin(iidx, h_src);
        stm_inode_unpin(iidx, h_dst_p);
        pthread_rwlock_unlock(&fs->global);
        return das;       /* STM_EEXIST if name already linked, etc. */
    }

    /* R81 P3-1: stamp ctime to "now" AFTER dirent_alloc succeeds.
     * Lock-posture infallibility argument applies (R76 P3-1) — under
     * our src pin the inode_lookup cannot fail since src_ino was just
     * linked above. */
    {
        struct stm_inode_value cv2 = {0};
        stm_status ls2 = stm_inode_lookup(iidx, dataset_id, src_ino, &cv2);
        if (ls2 == STM_OK) {
            fs_stamp_ctime_now(&cv2);
            (void)stm_inode_set(iidx, dataset_id, src_ino, &cv2);
        }
    }

    stm_inode_unpin(iidx, h_src);
    stm_inode_unpin(iidx, h_dst_p);
    pthread_rwlock_unlock(&fs->global);
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

    /* PARALLEL-3 impl-2: CREATE-shape — SH + parent pin + fresh-child pin
     * (same posture as fs_create_inode_and_link). */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_inode_handle *h_parent = NULL;
    stm_status pp = stm_inode_pin(iidx, dataset_id, parent_ino, &h_parent);
    if (pp != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return pp;
    }

    struct stm_inode_value pv = {0};
    stm_status ps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (ps != STM_OK) {
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
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
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return as;
    }

    stm_inode_handle *h_child = NULL;
    stm_status cp = stm_inode_pin(iidx, dataset_id, child_ino, &h_child);
    if (cp != STM_OK) {
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return cp;
    }

    /* Stamp the symlink target into the inode's data union. The
     * allocator left si_data_kind=STM_DATA_INLINE + si_data_len=0;
     * we override to SYMLINK + target_len + bytes. */
    struct stm_inode_value cv = {0};
    stm_status cs = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
    if (cs != STM_OK) {
        stm_inode_unpin(iidx, h_child);
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return cs;
    }
    cv.si_data_kind = STM_DATA_SYMLINK;
    cv.si_data_len  = (uint8_t)target_len;
    memset(&cv.si_data, 0, sizeof cv.si_data);
    memcpy(cv.si_data.symlink_target, target, (size_t)target_len);
    cv.si_size = stm_store_le64((uint64_t)target_len);
    /* P8-POSIX-7a: stamp btime + atime + mtime + ctime at create. */
    fs_stamp_create_times(&cv);
    stm_status sse = stm_inode_set(iidx, dataset_id, child_ino, &cv);
    if (sse != STM_OK) {
        stm_inode_unpin(iidx, h_child);
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return sse;
    }

    uint64_t child_gen = stm_load_le64(cv.si_gen);

    /* Link in parent. Roll back on failure. */
    stm_status ds = stm_dirent_alloc(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          child_ino, child_gen, STM_DT_LNK);
    if (ds != STM_OK) {
        stm_inode_unpin(iidx, h_child);
        (void)stm_inode_free(iidx, dataset_id, child_ino);
        stm_inode_unpin(iidx, h_parent);
        pthread_rwlock_unlock(&fs->global);
        return ds;
    }

    *out_child_ino = child_ino;
    stm_inode_unpin(iidx, h_child);
    stm_inode_unpin(iidx, h_parent);
    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ls;       /* STM_ENOENT */
    }

    uint32_t mode = stm_load_le32(iv.si_mode);
    if ((mode & (uint32_t)S_IFMT) != (uint32_t)S_IFLNK) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;       /* POSIX EINVAL on non-symlink readlink */
    }
    if (iv.si_data_kind != STM_DATA_SYMLINK) {
        /* Decoder-vs-mode mismatch: the inode says S_IFLNK but the
         * data union doesn't carry SYMLINK bytes. Treat as corrupt. */
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }
    /* R77 P1-1 defense-in-depth: even though `stm_inode_set` and
     * `in_decode_value` now both bound si_data_len ≤
     * STM_INODE_INLINE_MAX for SYMLINK records, the reader checks
     * before the memcpy so a hypothetical bypass at either layer
     * (test seam, future refactor) can't OOB-read the union. */
    if (iv.si_data_len > STM_INODE_INLINE_MAX) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    size_t actual_len = (size_t)iv.si_data_len;
    size_t copy_n = (target_max < actual_len) ? target_max : actual_len;
    if (copy_n > 0u) memcpy(target_buf, iv.si_data.symlink_target, copy_n);
    *out_len = actual_len;       /* full length, even if truncated */

    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* ========================================================================= */
/* P8-POSIX-10: stm_fs_truncate.                                              */
/* ========================================================================= */

stm_status stm_fs_truncate(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              uint64_t new_size)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    /* SWISS-4q-flush: truncate operates on the extent tree directly
     * (drops extents past new_size, may rewrite a crossing extent).
     * Pre-flush the inode's buffered ranges so the extent layer
     * reflects all issued writes before the truncate acts. After
     * the flush, drop any buffered ranges past new_size (the post-
     * truncate read should NOT see them). */
    {
        stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
        if (fr != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
    }

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ls;       /* STM_ENOENT */
    }

    uint32_t mode = stm_load_le32(iv.si_mode);
    uint32_t ifmt = mode & (uint32_t)S_IFMT;
    if (ifmt == (uint32_t)S_IFDIR) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EISDIR;       /* POSIX truncate(2): EISDIR */
    }
    if (ifmt != (uint32_t)S_IFREG) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;       /* symlink / device / etc. */
    }

    /* R77 P1-1 defense-in-depth — bound si_data_len. */
    if (iv.si_data_kind == STM_DATA_INLINE &&
        iv.si_data_len > STM_INODE_INLINE_MAX) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    uint64_t cur_size = stm_load_le64(iv.si_size);
    if (new_size == cur_size) {
        pthread_rwlock_unlock(&fs->global);
        return STM_OK;       /* no-op */
    }

    /* P8-POSIX-7a-seals: refuse the truncate per the inode's seal mask
     * BEFORE any state mutation. The size delta is already known
     * (new_size != cur_size) — branch on the direction and the
     * applicable seals. SEAL_WRITE / SEAL_FUTURE_WRITE block all
     * size-changing truncate (Linux fcntl(2) F_SEAL_WRITE refuses
     * truncate(2) outright); SEAL_GROW blocks new_size > cur_size;
     * SEAL_SHRINK blocks new_size < cur_size. The same-size no-op
     * branch returned earlier above so we do NOT need to defend it
     * here. Refusal is STM_EPERM. */
    {
        uint32_t flags = stm_load_le32(iv.si_flags);
        if (flags & (STM_INO_FLAG_SEAL_WRITE | STM_INO_FLAG_SEAL_FUTURE_WRITE)) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EPERM;
        }
        if (new_size > cur_size && (flags & STM_INO_FLAG_SEAL_GROW)) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EPERM;
        }
        if (new_size < cur_size && (flags & STM_INO_FLAG_SEAL_SHRINK)) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EPERM;
        }
    }

    uint8_t kind = iv.si_data_kind;

    if (kind == STM_DATA_INLINE) {
        if (new_size <= (uint64_t)STM_INODE_INLINE_MAX) {
            /* Stays inline. Grow zero-fills; shrink truncates. */
            if (new_size > (uint64_t)iv.si_data_len) {
                memset(iv.si_data.inline_data + iv.si_data_len, 0,
                       (size_t)(new_size - iv.si_data_len));
            }
            iv.si_data_len = (uint8_t)new_size;
            iv.si_size     = stm_store_le64(new_size);
            /* P8-POSIX-7a: truncate is a content + size change →
             * stamp mtime + ctime. */
            fs_stamp_mtime_ctime_now(&iv);
            /* R76 P3-1 / R78 P3-1: stm_inode_set infallible in this
             * lock posture (see fs_write_regular_locked's annotation). */
            stm_status rs = stm_inode_set(iidx, dataset_id, ino, &iv);
            pthread_rwlock_unlock(&fs->global);
            return rs;
        }

        /* Grow past inline cap → transition to EXTENT. Build a
         * single block-aligned combined buffer (existing inline prefix
         * + zero pad to next 4 KiB boundary). Same shape as
         * fs_write_regular_locked's transition path. */
        if (new_size > (uint64_t)STM_FS_RECORDSIZE_MAX) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ERANGE;
        }

        const uint64_t BLK = 4096u;
        uint64_t aligned_size = (new_size + BLK - 1u) & ~(BLK - 1u);
        if (aligned_size == 0u) aligned_size = BLK;

        uint8_t *combined = calloc(1, (size_t)aligned_size);
        if (!combined) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOMEM;
        }
        if (iv.si_data_len > 0u) {
            memcpy(combined, iv.si_data.inline_data, iv.si_data_len);
        }
        stm_status ws = stm_sync_write_extent(fs->sync, dataset_id, ino,
                                                  /*off=*/0u,
                                                  combined,
                                                  (size_t)aligned_size);
        free(combined);
        if (ws != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ws;
        }

        iv.si_data_kind = STM_DATA_EXTENT;
        iv.si_data_len  = 0;
        memset(&iv.si_data, 0, sizeof iv.si_data);
        iv.si_size      = stm_store_le64(new_size);
        /* P8-POSIX-7a: truncate transition is a content + size + kind
         * change → stamp mtime + ctime. */
        fs_stamp_mtime_ctime_now(&iv);
        /* R76 P3-1 / R78 P3-1: stm_inode_set infallible in this lock
         * posture — fs->lock excludes every alloc/free path that
         * could mutate (state, gen, nlink, kind) behind our back. */
        stm_status rs = stm_inode_set(iidx, dataset_id, ino, &iv);
        pthread_rwlock_unlock(&fs->global);
        return rs;
    }

    if (kind == STM_DATA_EXTENT) {
        /* EXTENT mode. Per ARCH §11.3.3 / inode.tla::OneWayInlineToExtent:
         * once EXTENT, stays EXTENT — even when new_size ≤ inline cap. */
        const uint64_t BLK = 4096u;
        if ((new_size & (BLK - 1u)) != 0u) {
            /* Sub-block truncate not supported. POSIX truncate(2) accepts
             * arbitrary new_size; sync_truncate's MVP requires 4 KiB
             * alignment. Caller must align the truncate point. */
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }

        if (new_size < cur_size) {
            /* Shrink: drop past-EOF extents. */
            stm_status ts = stm_sync_truncate(fs->sync, dataset_id, ino,
                                                 new_size);
            if (ts != STM_OK) {
                pthread_rwlock_unlock(&fs->global);
                return ts;
            }
        }
        /* Grow case: just update si_size. The extent layer's sparse-
         * read semantics return 0 for offsets in [cur_size, new_size)
         * that have no extent record — POSIX-correct zero-fill. */

        iv.si_size = stm_store_le64(new_size);
        /* P8-POSIX-7a: truncate is a size change → stamp mtime + ctime
         * (per POSIX truncate(2): mtime + ctime are updated even on
         * grow; only no-op size==cur_size leaves them alone, and that
         * path returned earlier above). */
        fs_stamp_mtime_ctime_now(&iv);
        /* R76 P3-2 / R78 P3-1: stm_inode_set infallible — same lock-
         * posture argument. Only mutated field is si_size + ts. */
        stm_status rs = stm_inode_set(iidx, dataset_id, ino, &iv);
        pthread_rwlock_unlock(&fs->global);
        return rs;
    }

    /* SYMLINK / DEVICE — not a regular-file kind; rejected. */
    pthread_rwlock_unlock(&fs->global);
    return STM_ENOTSUPPORTED;
}

/* ========================================================================= */
/* P8-POSIX-7a-seals: file seals.                                             */
/* ========================================================================= */

/* R82 P3-3: drift guard between the public STM_FS_SEAL_* constants in
 * fs.h and the inode-internal STM_INO_FLAG_SEAL_* bits in inode.h.
 * The two must stay numerically identical or the seal mask check in
 * stm_fs_add_seals would let through bits that the enforcement seams
 * (fs_write_regular_locked + stm_fs_truncate) read directly off
 * si_flags. Catch any drift at compile time. */
_Static_assert(STM_FS_SEAL_MASK == STM_INO_FLAG_SEAL_MASK,
               "fs.h SEAL mask must match inode.h SEAL mask");
_Static_assert(STM_FS_SEAL_SEAL == STM_INO_FLAG_SEAL_SEAL,
               "STM_FS_SEAL_SEAL must match STM_INO_FLAG_SEAL_SEAL");
_Static_assert(STM_FS_SEAL_SHRINK == STM_INO_FLAG_SEAL_SHRINK,
               "STM_FS_SEAL_SHRINK must match STM_INO_FLAG_SEAL_SHRINK");
_Static_assert(STM_FS_SEAL_GROW == STM_INO_FLAG_SEAL_GROW,
               "STM_FS_SEAL_GROW must match STM_INO_FLAG_SEAL_GROW");
_Static_assert(STM_FS_SEAL_WRITE == STM_INO_FLAG_SEAL_WRITE,
               "STM_FS_SEAL_WRITE must match STM_INO_FLAG_SEAL_WRITE");
_Static_assert(STM_FS_SEAL_FUTURE_WRITE == STM_INO_FLAG_SEAL_FUTURE_WRITE,
               "STM_FS_SEAL_FUTURE_WRITE must match STM_INO_FLAG_SEAL_FUTURE_WRITE");

stm_status stm_fs_add_seals(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                                uint32_t seals)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    /* Reject any out-of-mask bit so future format extensions can rely
     * on every set bit being a known seal. */
    if ((seals & ~(uint32_t)STM_FS_SEAL_MASK) != 0u) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }

    uint32_t cur_flags = stm_load_le32(iv.si_flags);

    /* SEAL is sticky: once set, no further additions are accepted —
     * even no-op re-adds of already-set bits, per Linux fcntl(2)
     * behavior on a SEAL-sealed inode (every F_ADD_SEALS returns
     * EPERM regardless of the requested mask). The exception is
     * `seals == 0` which is a trivial no-op + allowed. */
    if ((cur_flags & STM_INO_FLAG_SEAL_SEAL) && seals != 0u) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EPERM;
    }

    /* No-op: every requested bit already set (or seals == 0).
     * Linux returns 0 with no inode mutation. We mirror — no ctime
     * bump, no inode_set call, no persistence churn. */
    uint32_t new_flags = cur_flags | seals;
    if (new_flags == cur_flags) {
        pthread_rwlock_unlock(&fs->global);
        return STM_OK;
    }

    iv.si_flags = stm_store_le32(new_flags);
    /* Seals are inode metadata — bump ctime (matches Linux behavior:
     * `kernel/fs/inode.c::file_seals_change` unconditionally calls
     * `inode_inc_iversion + ctime stamp` on a successful F_ADD_SEALS).
     * R76 P3-1 / R78 P3-1 lock-posture infallibility: only fields
     * touched are si_flags + ctime. */
    fs_stamp_ctime_now(&iv);
    stm_status rs = stm_inode_set(iidx, dataset_id, ino, &iv);
    pthread_rwlock_unlock(&fs->global);
    return rs;
}

stm_status stm_fs_get_seals(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                                uint32_t *out_seals)
{
    /* Uniform out-param contract (R57 P3-5 / R58 P3-1): zero-init
     * BEFORE arg validation so callers observing on STM_EINVAL see a
     * defined value (0). */
    if (out_seals) *out_seals = 0;
    if (!fs || !out_seals) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }

    *out_seals = stm_load_le32(iv.si_flags) & (uint32_t)STM_FS_SEAL_MASK;
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* ========================================================================= */
/* P8-POSIX-7c: file handles (name_to_handle_at + open_by_handle_at).         */
/* ========================================================================= */

stm_status stm_fs_name_to_handle(stm_fs *fs, uint64_t dataset_id,
                                       uint64_t parent_ino,
                                       const uint8_t *name, uint8_t name_len,
                                       stm_fs_file_handle *out_handle)
{
    /* Uniform out-param contract — zero-init BEFORE arg validation. */
    if (out_handle) memset(out_handle, 0, sizeof *out_handle);
    if (!fs || !name || !out_handle) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;

    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Validate parent is a directory + look up the child. */
    struct stm_inode_value pv = {0};
    stm_status sps = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
    if (sps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return sps;
    }

    uint64_t child_ino = 0, child_gen_ignored = 0;
    uint8_t  child_type = 0;
    stm_status ds = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                          name, name_len,
                                          &child_ino, &child_gen_ignored,
                                          &child_type);
    if (ds != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ds;
    }

    /* R83 P3-6 defense-in-depth: re-read the inode's si_gen from the
     * inode index rather than trusting the dirent's child_gen
     * snapshot. The dirent's child_gen IS provably equal to the
     * inode's current si_gen for any ALLOCATED inode (per inode.tla:
     * si_gen is immutable for the ALLOCATED lifetime; only AllocReused
     * bumps it during the FREED → ALLOCATED transition, at which point
     * any dirent referencing the old (ino, gen) pair is also gone via
     * cascade-free). The redundant lookup costs an O(records) scan but
     * provides defense-in-depth against any future invariant violation
     * — if the dirent's child_gen ever drifts from the inode's si_gen,
     * the handle should reflect the inode's authoritative value. */
    struct stm_inode_value cv = {0};
    stm_status cs = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
    if (cs != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return cs;
    }

    out_handle->h_magic      = stm_store_le32(STM_FS_HANDLE_MAGIC);
    out_handle->h_version    = stm_store_le32(STM_FS_HANDLE_VERSION);
    /* R83 P2-1: bind handle to pool_uuid for cross-pool isolation.
     * Two pools' independent ino allocators can produce identical
     * (ds=1, ino=N, gen=0) triples — without pool_uuid, a handle
     * from pool A presented to pool B would silently open a different
     * file. The structural fix forecloses this confused-deputy. */
    {
        const uint64_t *pu = stm_pool_uuid(fs->pool);
        out_handle->h_pool_uuid[0] = stm_store_le64(pu[0]);
        out_handle->h_pool_uuid[1] = stm_store_le64(pu[1]);
    }
    out_handle->h_dataset_id = stm_store_le64(dataset_id);
    out_handle->h_ino        = stm_store_le64(child_ino);
    /* R83 P3-5: cv.si_gen is already le64 + h_si_gen is le64; direct
     * assignment is bit-equivalent to the prior load+store round-trip
     * and saves a byte-swap pair on big-endian builds. */
    out_handle->h_si_gen     = cv.si_gen;

    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

stm_status stm_fs_open_by_handle(stm_fs *fs,
                                       const stm_fs_file_handle *handle,
                                       uint64_t *out_ino)
{
    /* Uniform out-param contract. */
    if (out_ino) *out_ino = 0;
    if (!fs || !handle || !out_ino) return STM_EINVAL;

    /* Validate the wire-format header BEFORE touching the inode index.
     * R83 P3-2: magic mismatch returns STM_EINVAL (was STM_EBADTAG in
     * the substantive); STM_EBADTAG's status string "aead tag mismatch"
     * doesn't fit handle-magic mismatch — that's structural validation
     * of caller-provided bytes, semantically EINVAL. Version mismatch
     * is STM_EBADVERSION (handle from a different v2 release; caller
     * must regenerate). */
    if (stm_load_le32(handle->h_magic) != STM_FS_HANDLE_MAGIC) {
        return STM_EINVAL;
    }
    if (stm_load_le32(handle->h_version) != STM_FS_HANDLE_VERSION) {
        return STM_EBADVERSION;
    }

    uint64_t ds = stm_load_le64(handle->h_dataset_id);
    uint64_t ino = stm_load_le64(handle->h_ino);
    uint64_t want_gen = stm_load_le64(handle->h_si_gen);
    if (ds == 0u || ino == 0u) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    /* R83 P2-1: cross-pool isolation. Compare the handle's pool_uuid
     * against the mounted fs's pool_uuid; mismatch → STM_ESTALE
     * (the file the handle described isn't in THIS pool — could be
     * a different mount, a different pool, or a forged tuple). */
    {
        const uint64_t *pu = stm_pool_uuid(fs->pool);
        if (stm_load_le64(handle->h_pool_uuid[0]) != pu[0] ||
            stm_load_le64(handle->h_pool_uuid[1]) != pu[1]) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ESTALE;
        }
    }

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* R83 P2-2: distinguish STM_ENOENT (never existed) from STM_ESTALE
     * (was here, gone now). stm_inode_lookup currently fuses both
     * cases (no record OR record FREED) into a single STM_ENOENT
     * return; we re-discriminate via the (ino < next_ino) heuristic.
     * If ino < next_ino, the slot was at some point allocated — the
     * inode is either FREED or never existed AT THIS ino but the
     * allocator is past it, which is structurally impossible (alloc
     * is monotonic + AllocReused returns to FREED slots). So
     * lookup-fail with ino < next_ino ⇒ FREED ⇒ STM_ESTALE. ino >=
     * next_ino ⇒ never existed in this dataset ⇒ STM_ENOENT.
     *
     * Lookup-success with gen mismatch ⇒ AllocReused since handle
     * issuance ⇒ STM_ESTALE (the new (ino, gen) is a different
     * file). Lookup-success with gen match ⇒ STM_OK. */
    struct stm_inode_value v = {0};
    stm_status ls = stm_inode_lookup(iidx, ds, ino, &v);
    if (ls == STM_ENOENT) {
        uint64_t next_ino = 0;
        stm_status ns = stm_inode_next_ino(iidx, ds, &next_ino);
        pthread_rwlock_unlock(&fs->global);
        if (ns == STM_OK && ino < next_ino) {
            /* Slot was allocated at some point; either FREED-not-
             * yet-reused or skipped-via-AllocFresh-monotonicity (no
             * collision with ino since fresh paths bump next_ino).
             * Either way, the file the handle described is gone. */
            return STM_ESTALE;
        }
        /* Allocator never reached this ino in this dataset. */
        return STM_ENOENT;
    }
    if (ls != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ls;
    }

    /* Stale-handle detection: gen must match. A mismatch means the
     * (ds, ino) tuple has been recycled via Free + AllocReused since
     * the handle was issued. inode.tla's TupleUniqueAllTime invariant
     * pins that the new (ino, gen) tuple is distinct from the old. */
    uint64_t cur_gen = stm_load_le64(v.si_gen);
    if (cur_gen != want_gen) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ESTALE;
    }

    *out_ino = ino;
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* ========================================================================= */
/* P8-POSIX-9: stm_fs_rename.                                                 */
/* ========================================================================= */

stm_status stm_fs_rename(stm_fs *fs, uint64_t dataset_id,
                            uint64_t src_parent_ino,
                            const uint8_t *src_name, uint8_t src_name_len,
                            uint64_t dst_parent_ino,
                            const uint8_t *dst_name, uint8_t dst_name_len,
                            uint32_t flags)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || src_parent_ino == 0u || dst_parent_ino == 0u) {
        return STM_EINVAL;
    }
    if ((flags & ~(uint32_t)(STM_FS_RENAME_NOREPLACE |
                              STM_FS_RENAME_EXCHANGE  |
                              STM_FS_RENAME_WHITEOUT)) != 0u) return STM_EINVAL;
    /* RENAME_EXCHANGE + RENAME_NOREPLACE are mutually exclusive
     * (POSIX-aligned: Linux returns EINVAL on the combination). */
    if ((flags & STM_FS_RENAME_EXCHANGE) &&
        (flags & STM_FS_RENAME_NOREPLACE)) {
        return STM_EINVAL;
    }
    /* P8-POSIX-9b: RENAME_WHITEOUT cannot combine with EXCHANGE
     * (the EXCHANGE-then-whiteout combination is semantically
     * incoherent — EXCHANGE preserves both names, WHITEOUT
     * replaces src with a whiteout marker). Linux refuses with
     * EINVAL. RENAME_WHITEOUT | RENAME_NOREPLACE IS allowed
     * per Linux semantics ("rename with whiteout, refuse if dst
     * exists"). */
    if ((flags & STM_FS_RENAME_WHITEOUT) &&
        (flags & STM_FS_RENAME_EXCHANGE)) {
        return STM_EINVAL;
    }

    stm_status nv = fs_validate_dirent_name(src_name, src_name_len);
    if (nv != STM_OK) return nv;
    nv = fs_validate_dirent_name(dst_name, dst_name_len);
    if (nv != STM_OK) return nv;

    /* Same-path no-op. POSIX rename(src, src) returns 0. */
    if (src_parent_ino == dst_parent_ino &&
        src_name_len == dst_name_len &&
        memcmp(src_name, dst_name, src_name_len) == 0) {
        return STM_OK;
    }

    /* R133 P1-2: capture wedge-intent through rollback failures and
     * fire the actual mark_wedged AFTER pthread_rwlock_unlock. Calling
     * stm_fs_mark_wedged from inside the held wrlock would self-
     * deadlock on glibc rwlocks (POSIX: same-thread recursive wrlock
     * is undefined). The wedge sites below are all "should not fire
     * in current code-paths" defense-in-depth, but the latent
     * deadlock was real. */
    bool should_wedge = false;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Validate src parent + dst parent are directories. */
    struct stm_inode_value spv = {0};
    stm_status sps = fs_load_parent_dir(iidx, dataset_id, src_parent_ino, &spv);
    if (sps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return sps;
    }
    struct stm_inode_value dpv = {0};
    stm_status dps = fs_load_parent_dir(iidx, dataset_id, dst_parent_ino, &dpv);
    if (dps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return dps;
    }

    /* Lookup src dirent — must exist. */
    uint64_t src_ino = 0, src_gen = 0;
    uint8_t  src_type = 0;
    stm_status srs = stm_dirent_lookup(didx, dataset_id, src_parent_ino,
                                            src_name, src_name_len,
                                            &src_ino, &src_gen, &src_type);
    if (srs != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return srs;       /* STM_ENOENT */
    }

    /* Lookup dst dirent — may or may not exist. */
    uint64_t dst_ino = 0, dst_gen = 0;
    uint8_t  dst_type = 0;
    stm_status drs = stm_dirent_lookup(didx, dataset_id, dst_parent_ino,
                                            dst_name, dst_name_len,
                                            &dst_ino, &dst_gen, &dst_type);
    bool dst_exists = (drs == STM_OK);
    if (drs != STM_OK && drs != STM_ENOENT) {
        pthread_rwlock_unlock(&fs->global);
        return drs;
    }

    if (dst_exists && (flags & STM_FS_RENAME_NOREPLACE)) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EEXIST;
    }

    /* P8-POSIX-9b: RENAME_EXCHANGE — both src + dst MUST exist.
     * Atomically swap their (ino, gen, type) at the dirent layer
     * via stm_dirent_swap_two. Stamp ctime on both swapped inodes
     * (POSIX rename ctime semantics — the operation modifies inode
     * metadata: the directory entry's ino reference). NO inode is
     * created or freed; nlink unchanged on both sides. Composes
     * over dirent.tla::Swap. */
    if (flags & STM_FS_RENAME_EXCHANGE) {
        if (!dst_exists) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOENT;
        }
        /* R86 P2-1 (P11 close): immediate-parent directory-cycle
         * detection. EXCHANGE of two directories where one is the
         * IMMEDIATE parent of the other creates a cycle: post-
         * exchange, the parent's slot points to the (former) child
         * dir, while the child's slot points to the (former) parent
         * — which now contains itself transitively. Refuse with
         * STM_EINVAL (POSIX-aligned: Linux returns EINVAL for the
         * cycle case).
         *
         * Forward-note: deeper-ancestor cycle detection (e.g.,
         * EXCHANGE(/A, /A/sub/sub)) requires ancestor-walk via
         * dirent traversal, which is O(depth) and lacks an
         * indexed parent_ino field on the inode (would be a
         * format break to add). The immediate-parent check
         * catches the most common abuse case; deeper cycles are
         * forward-noted for a future hardening chunk that adds
         * either a parent_ino index or ancestor-walk via reverse-
         * dirent lookup. */
        bool src_is_dir = (src_type == STM_DT_DIR);
        bool dst_is_dir = (dst_type == STM_DT_DIR);
        if (src_is_dir && dst_is_dir) {
            if (src_ino == dst_parent_ino || dst_ino == src_parent_ino) {
                pthread_rwlock_unlock(&fs->global);
                return STM_EINVAL;
            }
        }
        /* Atomically swap. */
        stm_status ws = stm_dirent_swap_two(didx, dataset_id,
                                                 src_parent_ino,
                                                 src_name, src_name_len,
                                                 dst_parent_ino,
                                                 dst_name, dst_name_len);
        if (ws != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ws;
        }
        /* Stamp ctime on both inodes (post-swap). The two inodes
         * have ALREADY been swapped at the dirent layer; src_ino
         * + dst_ino are the inos that were originally at src and
         * dst. Both still exist (Swap preserves nlink). Failure
         * to stamp is best-effort under R76 P3-1 / R78 P3-1
         * lock-posture infallibility — only ctime mutates. */
        struct stm_inode_value siv2 = {0};
        if (stm_inode_lookup(iidx, dataset_id, src_ino, &siv2) == STM_OK) {
            fs_stamp_ctime_now(&siv2);
            (void)stm_inode_set(iidx, dataset_id, src_ino, &siv2);
        }
        struct stm_inode_value div2 = {0};
        if (stm_inode_lookup(iidx, dataset_id, dst_ino, &div2) == STM_OK) {
            fs_stamp_ctime_now(&div2);
            (void)stm_inode_set(iidx, dataset_id, dst_ino, &div2);
        }
        pthread_rwlock_unlock(&fs->global);
        return STM_OK;
    }

    /* If dst exists, validate kind compatibility:
     *   - src is dir, dst is non-dir → STM_ENOTDIR (POSIX).
     *   - src is non-dir, dst is dir → STM_EISDIR.
     *   - src is dir, dst is dir AND dst non-empty → STM_ENOTEMPTY. */
    if (dst_exists) {
        bool src_is_dir = (src_type == STM_DT_DIR);
        bool dst_is_dir = (dst_type == STM_DT_DIR);
        if (src_is_dir && !dst_is_dir) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOTDIR;
        }
        if (!src_is_dir && dst_is_dir) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EISDIR;
        }
        if (src_is_dir && dst_is_dir) {
            size_t n = 0;
            stm_status cs = stm_dirent_count_for_dir(didx, dataset_id,
                                                          dst_ino, &n);
            if (cs == STM_OK && n > 0u) {
                pthread_rwlock_unlock(&fs->global);
                return STM_ENOTEMPTY;
            }
        }
    }

    /* If dst exists: drop dst dirent + drop dst inode (cascade-free
     * if nlink reaches 0). The dirent_unlink turns the slot into a
     * tombstone in the chain (R79 P3-2: dirent_alloc below walks
     * the chain from Hash[dst_name] and may pick this slot OR an
     * earlier install-eligible slot — either is correct because
     * the chain probes deterministically by hash, so subsequent
     * lookups of dst_name will find the new record). */
    bool dst_freed_unused = false;
    bool dst_cleanup_did_truncate = false;
    if (dst_exists) {
        /* R128 P1-1: if dst is about to cascade-free (nlink==1), drop
         * its dirty-buffer entry AND truncate its extents BEFORE the
         * inode-unlink. Otherwise the buffer's (ds, dst_ino) entry
         * outlives the inode slot's free and a future flush emits
         * extents under whatever inode reuses the slot at a bumped
         * si_gen — confused-deputy-class data corruption. Same posture
         * as fs_unlink_inode_and_dirent. Inode lookup is best-effort;
         * if it fails (e.g., dst_ino already gone — should not happen
         * since dst_exists is true), the helper is skipped. The
         * returned truncate-flag gates the post-reclaim double-commit
         * below (R130 perf: skip the ~200ms commit pair when the
         * overwritten dst has no extents to reclaim). */
        struct stm_inode_value dcv = {0};
        if (stm_inode_lookup(iidx, dataset_id, dst_ino, &dcv) == STM_OK) {
            uint32_t dst_cur_nlink = stm_load_le32(dcv.si_nlink);
            if (dst_cur_nlink == 1u) {
                dst_cleanup_did_truncate = fs_pre_inode_free_cleanup_locked(
                    fs, dataset_id, dst_ino, &dcv);
            }
        }
        stm_status du = stm_dirent_unlink(didx, dataset_id, dst_parent_ino,
                                                dst_name, dst_name_len);
        if (du != STM_OK) {
            /* Should not happen — we just looked up the entry. */
            pthread_rwlock_unlock(&fs->global);
            return du;
        }
        stm_status iu = stm_inode_unlink(iidx, dataset_id, dst_ino,
                                            &dst_freed_unused);
        if (iu != STM_OK) {
            /* Rollback: re-create dst dirent. Under fs->lock-held
             * posture, this should succeed (the slot is still a
             * tombstone we just created; alloc reuses it). */
            (void)stm_dirent_alloc(didx, dataset_id, dst_parent_ino,
                                       dst_name, dst_name_len,
                                       dst_ino, dst_gen, dst_type);
            pthread_rwlock_unlock(&fs->global);
            return iu;
        }
    }

    /* Install dirent at dst pointing at src_ino. */
    stm_status as = stm_dirent_alloc(didx, dataset_id, dst_parent_ino,
                                          dst_name, dst_name_len,
                                          src_ino, src_gen, src_type);
    if (as != STM_OK) {
        /* Rollback the dst-overwrite: re-create dst dirent + bump
         * dst inode's nlink back. If the rollback fails (memory
         * pressure / pathological state), wedge the volume — the
         * on-disk state is now incompatible with the cached invariants
         * (orphan inode that nothing points to + missing dst dirent). */
        if (dst_exists) {
            stm_status r1 = stm_dirent_alloc(didx, dataset_id, dst_parent_ino,
                                                  dst_name, dst_name_len,
                                                  dst_ino, dst_gen, dst_type);
            stm_status r2 = STM_OK;
            if (!dst_freed_unused) {
                r2 = stm_inode_link(iidx, dataset_id, dst_ino);
            } else {
                /* dst inode was cascade-freed — can't bring it back
                 * without an alloc-reuse cycle (gen bump required).
                 * Wedge: data loss has already occurred from the
                 * caller's perspective (dst's content is gone) and
                 * the original alloc was unrecoverable. */
                should_wedge = true;
            }
            if (r1 != STM_OK || r2 != STM_OK) {
                should_wedge = true;
            }
        }
        pthread_rwlock_unlock(&fs->global);
        if (should_wedge) stm_fs_mark_wedged(fs);
        return as;
    }

    /* Drop src dirent. Under fs->lock-held posture, this is the
     * straightforward write to a tombstone — should not fail.
     *
     * P8-POSIX-9b RENAME_WHITEOUT: instead of unlinking src (which
     * leaves a TOMBSTONE invisible to readdir), convert src to a
     * WHITEOUT marker (visible to readdir as STM_DT_WHITEOUT with
     * child_ino=0 — overlayfs userspace interprets the marker as
     * "hide the lower layer's same name"). Both the unlink and
     * the whiteout primitives operate on the same chain slot;
     * chain integrity is preserved by either path. */
    stm_status su;
    if (flags & STM_FS_RENAME_WHITEOUT) {
        su = stm_dirent_whiteout(didx, dataset_id, src_parent_ino,
                                       src_name, src_name_len);
    } else {
        su = stm_dirent_unlink(didx, dataset_id, src_parent_ino,
                                     src_name, src_name_len);
    }
    if (su != STM_OK) {
        /* Defensive rollback: drop the dst dirent we just created
         * and re-link the original (if overwrite). On any rollback
         * failure, wedge.
         *
         * R79 P3-1: capture the rollback dst_unlink return so the
         * "drop the freshly-installed dst" leg's failure (silent
         * 1-dirent / 2-reference desync if dst_exists=false)
         * triggers the wedge guard. In current code-paths this
         * cannot fire — we just dirent_alloc'd at dst_name, so
         * unlink will find it — but capturing the rv is defense-
         * in-depth for any future refactor that breaks the
         * invariant. */
        stm_status r0 = stm_dirent_unlink(didx, dataset_id, dst_parent_ino,
                                                dst_name, dst_name_len);
        if (r0 != STM_OK) should_wedge = true;
        if (dst_exists) {
            stm_status r1 = stm_dirent_alloc(didx, dataset_id, dst_parent_ino,
                                                  dst_name, dst_name_len,
                                                  dst_ino, dst_gen, dst_type);
            if (!dst_freed_unused) {
                stm_status r2 = stm_inode_link(iidx, dataset_id, dst_ino);
                if (r1 != STM_OK || r2 != STM_OK) should_wedge = true;
            } else {
                /* dst inode gone; can't restore. */
                should_wedge = true;
            }
        }
        pthread_rwlock_unlock(&fs->global);
        if (should_wedge) stm_fs_mark_wedged(fs);
        return su;
    }

    /* P8-POSIX-7a: rename mutates the moved inode's parent + name,
     * which POSIX models as a metadata change → ctime auto-stamps to
     * "now" on src_ino. mtime + btime preserved. Best-effort, same
     * shape as setxattr's stamp.
     *
     * R86 P2-2 (P11 close): also stamp src_parent + dst_parent
     * directories' mtime + ctime — POSIX says rename modifies both
     * parent directories (their dirent contents change). For
     * same-parent rename (src_parent == dst_parent), stamp once. */
    {
        struct stm_inode_value iv2 = {0};
        if (stm_inode_lookup(iidx, dataset_id, src_ino, &iv2) == STM_OK) {
            fs_stamp_ctime_now(&iv2);
            (void)stm_inode_set(iidx, dataset_id, src_ino, &iv2);
        }
        struct stm_inode_value spv2 = {0};
        if (stm_inode_lookup(iidx, dataset_id, src_parent_ino, &spv2) == STM_OK) {
            fs_stamp_mtime_ctime_now(&spv2);
            (void)stm_inode_set(iidx, dataset_id, src_parent_ino, &spv2);
        }
        if (src_parent_ino != dst_parent_ino) {
            struct stm_inode_value dpv2 = {0};
            if (stm_inode_lookup(iidx, dataset_id, dst_parent_ino,
                                       &dpv2) == STM_OK) {
                fs_stamp_mtime_ctime_now(&dpv2);
                (void)stm_inode_set(iidx, dataset_id, dst_parent_ino, &dpv2);
            }
        }
    }

    /* R128 P1-1 close: reclaim trigger for the overwrite-cascade-free
     * path. If dst was overwritten + cascade-freed (dst_freed_unused
     * is true), its extents were truncated above via
     * fs_pre_inode_free_cleanup_locked. The allocator now holds
     * PENDING entries with free_gen=current_gen; without the double-
     * commit, R50 P2-1's strict-less-than predicate skips the sweep
     * and the blocks leak as PENDING for the session.
     *
     * Same posture as fs_unlink_inode_and_dirent's reclaim. The
     * non-overwrite rename path (no dst_freed_unused) doesn't free
     * any extents; skip the reclaim. R130: also gate on whether the
     * pre-cleanup truncated extents — overwriting a directory or
     * symlink target (no extents) skips the ~200 ms commit pair. */
    if (dst_freed_unused && dst_cleanup_did_truncate) {
        fs_post_inode_free_reclaim_locked(fs);
    }

    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Validate dir_ino exists + is a directory. */
    struct stm_inode_value dv = {0};
    stm_status ds = fs_load_parent_dir(iidx, dataset_id, dir_ino, &dv);
    if (ds != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
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
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOMEM;
        }
        stm_dirent_entry *batch = malloc(dirent_max * sizeof *batch);
        if (!batch) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOMEM;
        }

        size_t batch_n = 0;
        stm_status rs = stm_dirent_readdir(didx, dataset_id, dir_ino,
                                              &dirent_cursor, batch, dirent_max,
                                              &batch_n);
        if (rs != STM_OK) {
            free(batch);
            pthread_rwlock_unlock(&fs->global);
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
                pthread_rwlock_unlock(&fs->global);
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
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* ========================================================================= */
/* P8-POSIX-6: extended attributes (setxattr/getxattr/listxattr/removexattr). */
/* ========================================================================= */

/* POSIX namespace prefixes per ARCH §11.5.1. The fs-layer setxattr /
 * removexattr (and getxattr, for symmetry) require name to start with
 * one of these. The xattr.c layer is namespace-agnostic — only the fs
 * wrapper enforces the prefix.
 *
 * Each entry is { prefix bytes, prefix length }. A name `n` of length
 * `nl` matches if `nl >= prefix_len` AND `memcmp(n, prefix, prefix_len) == 0`. */
static const struct { const char *prefix; uint8_t prefix_len; }
fs_xattr_namespaces[] = {
    { "user.",     5u },
    { "system.",   7u },
    { "security.", 9u },
    { "trusted.",  8u },
};

static bool fs_xattr_name_in_posix_namespace(const uint8_t *name,
                                                  uint8_t name_len) {
    if (!name || name_len == 0) return false;
    /* R80 P2-1: reject NUL bytes anywhere in the name. POSIX permits
     * arbitrary bytes in xattr names, but listxattr's NUL-separated
     * output convention means an embedded NUL would split the name
     * into a "ghost" entry on the caller side — confusion attack
     * shape. The fs-layer guard rejects pre-write so the on-disk
     * tree never carries such names. */
    for (uint8_t i = 0; i < name_len; i++) {
        if (name[i] == 0u) return false;
    }
    for (size_t i = 0;
            i < sizeof fs_xattr_namespaces / sizeof fs_xattr_namespaces[0];
            i++) {
        uint8_t pl = fs_xattr_namespaces[i].prefix_len;
        if (name_len >= pl &&
            memcmp(name, fs_xattr_namespaces[i].prefix, pl) == 0) {
            return true;
        }
    }
    return false;
}

/* Verify that an inode is present (live) at (dataset_id, ino). Returns
 * STM_OK if present + live, STM_ENOENT otherwise. Caller holds fs->lock.
 * Used by every xattr API as a precondition: xattr operations on a
 * non-existent inode must surface as ENOENT, not as an unrelated
 * xattr-layer error or a silent success that leaks records into
 * `(ds, ino, *)` for an unallocated ino. */
static stm_status fs_xattr_require_inode(stm_fs *fs,
                                              uint64_t dataset_id, uint64_t ino) {
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) return STM_EINVAL;
    struct stm_inode_value iv;
    memset(&iv, 0, sizeof iv);
    return stm_inode_lookup(iidx, dataset_id, ino, &iv);
}

stm_status stm_fs_setxattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              const uint8_t *name, uint8_t name_len,
                              const uint8_t *value, uint32_t value_len,
                              uint32_t flags,
                              bool *out_replaced) {
    /* R75 P3-1-style zero-init: out_replaced BEFORE arg validation. */
    if (out_replaced) *out_replaced = false;

    if (!fs) return STM_EINVAL;
    if (!name) return STM_EINVAL;
    if (value_len > 0u && !value) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_FS_XATTR_NAME_MAX) return STM_EINVAL;
    if (value_len > STM_FS_XATTR_VALUE_MAX) return STM_ERANGE;
    if (!fs_xattr_name_in_posix_namespace(name, name_len)) return STM_EINVAL;
    /* xattr.c re-validates flags, but reject unknown bits at the fs
     * boundary too so callers see a consistent error surface. */
    uint32_t known = STM_FS_XATTR_CREATE | STM_FS_XATTR_REPLACE;
    if ((flags & ~known) != 0u) return STM_EINVAL;
    if ((flags & STM_FS_XATTR_CREATE) &&
        (flags & STM_FS_XATTR_REPLACE)) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_status ps = fs_xattr_require_inode(fs, dataset_id, ino);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    stm_xattr_index *xidx = stm_sync_xattr_index(fs->sync);
    if (!xidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    /* Map fs flags to xattr flags. Values are the same (POSIX-aligned)
     * but go through an explicit mapping so the two layers stay
     * separable if either changes. */
    uint32_t xa_flags = 0;
    if (flags & STM_FS_XATTR_CREATE)  xa_flags |= STM_XATTR_FLAG_CREATE;
    if (flags & STM_FS_XATTR_REPLACE) xa_flags |= STM_XATTR_FLAG_REPLACE;

    stm_status s = stm_xattr_set(xidx, dataset_id, ino,
                                    name, name_len,
                                    value, value_len, xa_flags,
                                    out_replaced);
    /* P8-POSIX-7a: setxattr is a metadata change → ctime auto-stamps
     * to "now". Stamping is best-effort: if the lookup or set fails,
     * the xattr write already succeeded so we return STM_OK from the
     * primary op. The timestamp gap is bounded (worst case: ctime
     * stays at prior value while xattr is set). Lock-posture
     * infallibility argument applies (R76 P3-1) — under fs->lock
     * the inode_lookup + set cannot fail. */
    if (s == STM_OK) {
        stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
        if (iidx) {
            struct stm_inode_value iv2 = {0};
            if (stm_inode_lookup(iidx, dataset_id, ino, &iv2) == STM_OK) {
                fs_stamp_ctime_now(&iv2);
                (void)stm_inode_set(iidx, dataset_id, ino, &iv2);
            }
        }
    }
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_getxattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                              const uint8_t *name, uint8_t name_len,
                              uint8_t *value_buf, uint32_t value_max,
                              uint32_t *out_size) {
    if (out_size) *out_size = 0;

    if (!fs) return STM_EINVAL;
    if (!name || !out_size) return STM_EINVAL;
    if (value_max > 0u && !value_buf) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_FS_XATTR_NAME_MAX) return STM_EINVAL;
    if (!fs_xattr_name_in_posix_namespace(name, name_len)) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_status ps = fs_xattr_require_inode(fs, dataset_id, ino);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    stm_xattr_index *xidx = stm_sync_xattr_index(fs->sync);
    if (!xidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    stm_status s = stm_xattr_get(xidx, dataset_id, ino,
                                    name, name_len,
                                    value_buf, value_max, out_size);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_listxattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                               uint8_t *name_buf, size_t buf_max,
                               size_t *out_total_len) {
    if (out_total_len) *out_total_len = 0;

    if (!fs) return STM_EINVAL;
    if (!out_total_len) return STM_EINVAL;
    if (buf_max > 0u && !name_buf) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_status ps = fs_xattr_require_inode(fs, dataset_id, ino);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    stm_xattr_index *xidx = stm_sync_xattr_index(fs->sync);
    if (!xidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* First pass: probe the count via xa_list with max_entries=0 to
     * compute the total. */
    size_t n_total = 0;
    stm_status ps0 = stm_xattr_list(xidx, dataset_id, ino,
                                       NULL, 0, &n_total);
    if (ps0 != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps0;
    }

    if (n_total == 0) {
        *out_total_len = 0;
        pthread_rwlock_unlock(&fs->global);
        return STM_OK;
    }

    /* Allocate a temp batch to receive the entries; we don't know the
     * total byte length until we see the names. SIZE_MAX/sizeof
     * guard against overflow. */
    if (n_total > SIZE_MAX / sizeof(stm_xattr_entry)) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ENOMEM;
    }
    stm_xattr_entry *batch = malloc(n_total * sizeof *batch);
    if (!batch) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ENOMEM;
    }
    size_t got = 0;
    stm_status ls = stm_xattr_list(xidx, dataset_id, ino,
                                      batch, n_total, &got);
    if (ls != STM_OK || got != n_total) {
        free(batch);
        pthread_rwlock_unlock(&fs->global);
        return (ls != STM_OK) ? ls : STM_ECORRUPT;
    }

    /* Compute total byte length (sum of (name_len + 1)). */
    size_t total_len = 0;
    for (size_t i = 0; i < got; i++) {
        /* R77 P1-1-style defense: cap name_len at the fs → xattr
         * trust boundary even though the xattr-layer + decoder both
         * enforce ≤ STM_XATTR_NAME_MAX. Closes any future-bypass
         * surface. R80 P3-5: same cap on value_len for forward-
         * compat — fs_listxattr doesn't memcpy value bytes today,
         * but a future maintainer extending this loop to use value_len
         * would inherit the OOB shape if any future bypass slipped
         * an oversize record past the writer/decoder symmetric
         * guards. */
        if (batch[i].name_len == 0 ||
            batch[i].name_len > STM_FS_XATTR_NAME_MAX) {
            free(batch);
            pthread_rwlock_unlock(&fs->global);
            return STM_ECORRUPT;
        }
        if (batch[i].value_len > STM_FS_XATTR_VALUE_MAX) {
            free(batch);
            pthread_rwlock_unlock(&fs->global);
            return STM_ECORRUPT;
        }
        size_t entry_bytes = (size_t)batch[i].name_len + 1u;
        if (total_len > SIZE_MAX - entry_bytes) {
            free(batch);
            pthread_rwlock_unlock(&fs->global);
            return STM_EOVERFLOW;
        }
        total_len += entry_bytes;
    }
    *out_total_len = total_len;

    if (buf_max == 0) {
        /* Probe-only call. */
        free(batch);
        pthread_rwlock_unlock(&fs->global);
        return STM_OK;
    }
    if (buf_max < total_len) {
        free(batch);
        pthread_rwlock_unlock(&fs->global);
        return STM_ERANGE;
    }

    /* Copy out as NUL-separated strings. */
    size_t off = 0;
    for (size_t i = 0; i < got; i++) {
        memcpy(name_buf + off, batch[i].name, batch[i].name_len);
        off += batch[i].name_len;
        name_buf[off++] = 0;
    }
    /* off must equal total_len; abort would be harsh, so leave as
     * implicit invariant. */

    free(batch);
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

stm_status stm_fs_removexattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                                 const uint8_t *name, uint8_t name_len) {
    if (!fs) return STM_EINVAL;
    if (!name) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (name_len == 0u || name_len > STM_FS_XATTR_NAME_MAX) return STM_EINVAL;
    if (!fs_xattr_name_in_posix_namespace(name, name_len)) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_status ps = fs_xattr_require_inode(fs, dataset_id, ino);
    if (ps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return ps;
    }

    stm_xattr_index *xidx = stm_sync_xattr_index(fs->sync);
    if (!xidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    stm_status s = stm_xattr_remove(xidx, dataset_id, ino, name, name_len);
    /* P8-POSIX-7a: removexattr is a metadata change → ctime auto-stamps
     * to "now". Best-effort, same shape as setxattr's stamp above. */
    if (s == STM_OK) {
        stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
        if (iidx) {
            struct stm_inode_value iv2 = {0};
            if (stm_inode_lookup(iidx, dataset_id, ino, &iv2) == STM_OK) {
                fs_stamp_ctime_now(&iv2);
                (void)stm_inode_set(iidx, dataset_id, ino, &iv2);
            }
        }
    }
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* P7-16 / P10b: shared inner reflink under caller's fs->lock.
 *
 * Held-fs->lock helper used by stm_fs_reflink + stm_fs_copy_file_range.
 * Centralizes the lookup → guards → sync_reflink → post-success
 * stamping pipeline so callers don't drop the lock mid-operation
 * (R84 P2-1 fix: prevents the size-probe TOCTOU between cfp's
 * size-assertion lookup and the inner reflink).
 *
 * R82 P0-1: seal enforcement on dst (SEAL_WRITE / FUTURE_WRITE
 * refuse all reflinks; SEAL_GROW refuses if src would extend dst).
 *
 * R84 P2-2 fix: refuse if src or dst is not S_IFREG (matches Linux
 * FICLONE / copy_file_range — non-regular files refuse with EINVAL).
 * Closes the corruption path where a directory / symlink / device
 * dst would receive si_size=src_size + INLINE-empty stamping.
 *
 * R84 P0-1 fix: refuse if src is any non-EXTENT kind with non-zero
 * size (was: only refused INLINE-with-content). SYMLINK-with-content
 * src would otherwise silently leave dst with si_size=src_size +
 * si_data_kind=INLINE + si_data_len=0; reads return src_size zero
 * bytes — data fabrication. Generalized guard catches SYMLINK,
 * DEVICE, and any future non-EXTENT kind.
 *
 * R84 P3-1 fix: src + dst lookups happen UNCONDITIONALLY (legacy
 * mixed-state callers — dst legacy + src INLINE — would otherwise
 * skip the inline-source guard).
 *
 * R81 P3-8 / P10b: post-success stamping aligns dst's si_size +
 * si_data_kind to src's + stamps mtime/ctime to "now" — only fires
 * when dst has an inode record in the index. */
static stm_status fs_reflink_locked(stm_fs *fs,
                                          uint64_t src_dataset_id,
                                          uint64_t src_ino,
                                          uint64_t dst_dataset_id,
                                          uint64_t dst_ino)
{
    /* Caller holds fs->lock + has applied FS_GUARD_WRITE. */

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    struct stm_inode_value div = {0};
    struct stm_inode_value siv = {0};
    bool dst_has_inode = false;
    bool src_has_inode = false;
    if (iidx) {
        /* R84 P3-1: lookups run independently — neither is gated on
         * the other's success. */
        stm_status sls = stm_inode_lookup(iidx, src_dataset_id,
                                               src_ino, &siv);
        if (sls == STM_OK) src_has_inode = true;
        stm_status dls = stm_inode_lookup(iidx, dst_dataset_id,
                                               dst_ino, &div);
        if (dls == STM_OK) dst_has_inode = true;
    }

    /* R84 P2-2: refuse if either side is not S_IFREG. POSIX
     * copy_file_range / Linux FICLONE both refuse non-regular files
     * (EINVAL). v2's stm_fs_reflink previously accepted any kind,
     * which combined with stamping left a corruption surface for
     * directory / symlink / device dst. */
    if (src_has_inode) {
        uint32_t smode = stm_load_le32(siv.si_mode);
        if ((smode & (uint32_t)S_IFMT) != (uint32_t)S_IFREG) {
            return STM_EINVAL;
        }
    }
    if (dst_has_inode) {
        uint32_t dmode = stm_load_le32(div.si_mode);
        if ((dmode & (uint32_t)S_IFMT) != (uint32_t)S_IFREG) {
            return STM_EINVAL;
        }
    }

    /* R82 P0-1: seal enforcement on dst. */
    if (dst_has_inode) {
        uint32_t dflags = stm_load_le32(div.si_flags);
        if (dflags & (STM_INO_FLAG_SEAL_WRITE |
                      STM_INO_FLAG_SEAL_FUTURE_WRITE)) {
            return STM_EPERM;
        }
        if (dflags & STM_INO_FLAG_SEAL_GROW) {
            /* SEAL_GROW refuses if reflink would extend dst's
             * si_size. POSIX-conservative: refuse on any source with
             * more bytes than dst, regardless of whether dst is
             * actually empty (sync_reflink also refuses dst with
             * extents via STM_EEXIST, so this only matters for
             * empty-dst cases). */
            if (src_has_inode) {
                uint64_t src_size = stm_load_le64(siv.si_size);
                uint64_t dst_size = stm_load_le64(div.si_size);
                if (src_size > dst_size) {
                    return STM_EPERM;
                }
            }
        }
    }

    /* R84 P0-1 + R84 P3-1: refuse non-EXTENT src with non-zero size
     * REGARDLESS of dst_has_inode. The pre-fix gate was conditioned
     * on dst_has_inode; legacy mixed-state callers would skip this
     * check and hit the silent-empty-dst data-loss path.
     *
     * Catches: STM_DATA_INLINE with content (src has inline_data
     * but no extents); STM_DATA_SYMLINK with content (src has
     * symlink_target but no extents); future STM_DATA_DEVICE with
     * size > 0; any future non-EXTENT kind. STM_DATA_EXTENT is the
     * only kind reflink can correctly share. */
    if (src_has_inode &&
        siv.si_data_kind != STM_DATA_EXTENT &&
        stm_load_le64(siv.si_size) > 0) {
        return STM_ENOTSUPPORTED;
    }

    stm_status s = stm_sync_reflink(fs->sync,
                                       src_dataset_id, src_ino,
                                       dst_dataset_id, dst_ino);
    if (s != STM_OK) return s;

    /* R81 P3-8 / P10b: post-success stamping + size/kind sync. */
    if (dst_has_inode) {
        if (src_has_inode) {
            uint64_t src_size = stm_load_le64(siv.si_size);
            div.si_size = stm_store_le64(src_size);
            /* If src had extents (the only path past the non-EXTENT
             * guard), mirror on dst so subsequent reads dispatch to
             * the EXTENT path. inode.tla::OneWayInlineToExtent
             * permits this transition. */
            if (siv.si_data_kind == STM_DATA_EXTENT) {
                div.si_data_kind = STM_DATA_EXTENT;
                div.si_data_len = 0;
                memset(&div.si_data, 0, sizeof div.si_data);
            }
        }
        /* R84 P3-2 forward-note: when src_has_inode is FALSE (legacy
         * direct-extent src) but sync_reflink installed records on
         * dst, dst's si_data_kind stays at its loaded value (typically
         * INLINE). Today no production callsite mixes legacy src with
         * indexed dst, so this is latent. Future "extent-count probe"
         * fix would query stm_extent_count_for_ino post-success and
         * flip data_kind to EXTENT if non-zero. */
        fs_stamp_mtime_ctime_now(&div);
        /* R76 P3-1 / R78 P3-1 lock-posture infallibility: only fields
         * touched are si_size + si_data_kind + si_data + ts; gen /
         * nlink / seal-bits unchanged. */
        return stm_inode_set(iidx, dst_dataset_id, dst_ino, &div);
    }

    return STM_OK;
}

/* P7-16: stm_fs_reflink. POSIX-shape FICLONE — replaces dst's empty
 * extent tree with a reflink-share of src's. Holds fs->lock across
 * the entire pipeline (lookup + guards + sync_reflink + stamping)
 * via fs_reflink_locked.
 *
 * Refuses non-regular files (R84 P2-2; matches Linux FICLONE) and
 * non-EXTENT-kind sources with non-zero size (R84 P0-1; would
 * otherwise silently leave dst empty with INLINE/SYMLINK src state
 * stamped onto a regular-file dst — a data-fabrication path).
 *
 * Errors propagate from stm_sync_reflink + the inode-layer guards
 * documented in fs_reflink_locked. */
stm_status stm_fs_reflink(stm_fs *fs,
                            uint64_t src_dataset_id, uint64_t src_ino,
                            uint64_t dst_dataset_id, uint64_t dst_ino)
{
    if (!fs) return STM_EINVAL;
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    /* SWISS-4q-flush: reflink shares extents from src → dst. Both
     * inodes' buffered ranges must be in the extent tree first:
     *   - src: reflink iterates src's extent tree; buffered ranges
     *     wouldn't be included → silent data loss on the dst side.
     *   - dst: dst's buffered ranges would conflict with the new
     *     reflinked extents (latest-write-wins ambiguity). */
    {
        stm_status fr = fs_flush_ino_locked(fs, src_dataset_id, src_ino);
        if (fr != STM_OK) { pthread_rwlock_unlock(&fs->global); return fr; }
        fr = fs_flush_ino_locked(fs, dst_dataset_id, dst_ino);
        if (fr != STM_OK) { pthread_rwlock_unlock(&fs->global); return fr; }
    }
    stm_status s = fs_reflink_locked(fs, src_dataset_id, src_ino,
                                          dst_dataset_id, dst_ino);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* P8-POSIX-10b: stm_fs_copy_file_range — POSIX copy_file_range(2)
 * shape. MVP scope: whole-file copy only — caller must request the
 * exact (0, src_size) range; non-zero src/dst offsets or partial
 * lengths refuse with STM_ENOTSUPPORTED. Caller can fall back to
 * read+write loops for arbitrary ranges (the binding layer typically
 * does this naturally via the EOPNOTSUPP-fallback pattern in glibc's
 * copy_file_range wrapper). `len == 0` is a legal POSIX no-op.
 *
 * R84 P2-1 fix: holds fs->lock across BOTH the size-validation
 * lookup AND the inner reflink — closes the size-probe TOCTOU
 * window where src could grow between probe + reflink, leaving
 * out_copied < dst's actual post-reflink size. */
stm_status stm_fs_copy_file_range(stm_fs *fs,
                                    uint64_t src_dataset_id, uint64_t src_ino,
                                    uint64_t src_off,
                                    uint64_t dst_dataset_id, uint64_t dst_ino,
                                    uint64_t dst_off,
                                    uint64_t len,
                                    uint64_t *out_copied)
{
    /* Uniform out-param contract. */
    if (out_copied) *out_copied = 0;
    if (!fs) return STM_EINVAL;
    if (src_dataset_id == 0u || src_ino == 0u) return STM_EINVAL;
    if (dst_dataset_id == 0u || dst_ino == 0u) return STM_EINVAL;

    /* MVP: whole-file copy only. Caller must pass (0, 0, src_size).
     * len == 0 is a legal POSIX no-op (out_copied = 0; STM_OK). */
    if (src_off != 0u || dst_off != 0u) return STM_ENOTSUPPORTED;
    if (len == 0u) return STM_OK;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    /* R128 P2-1: pre-flush BOTH src and dst before the extent-layer
     * reflink. fs_reflink_locked iterates src's extent tree to copy
     * records into dst; buffered ranges on src are NOT in the extent
     * tree → silently dropped. Same posture as stm_fs_reflink. */
    {
        stm_status fr = fs_flush_ino_locked(fs, src_dataset_id, src_ino);
        if (fr != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
        fr = fs_flush_ino_locked(fs, dst_dataset_id, dst_ino);
        if (fr != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
    }

    /* Validate that len matches src's size + delegate to the locked
     * helper — all under the SAME fs->lock acquisition (R84 P2-1). */
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    struct stm_inode_value siv = {0};
    stm_status sls = stm_inode_lookup(iidx, src_dataset_id, src_ino, &siv);
    if (sls != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return sls;
    }
    uint64_t src_size = stm_load_le64(siv.si_size);
    if (len != src_size) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ENOTSUPPORTED;
    }

    stm_status s = fs_reflink_locked(fs, src_dataset_id, src_ino,
                                          dst_dataset_id, dst_ino);
    pthread_rwlock_unlock(&fs->global);
    if (s != STM_OK) return s;

    if (out_copied) *out_copied = src_size;
    return STM_OK;
}

/* P7-CAS-2: stm_fs_migrate_to_cold. Holds fs->lock across the inner
 * sync_migrate_to_cold so a concurrent observer never sees a partial
 * (some-hot-some-cold) state for the file. Errors propagate from
 * stm_sync_migrate_to_cold. */
stm_status stm_fs_migrate_to_cold(stm_fs *fs,
                                     uint64_t dataset_id, uint64_t ino)
{
    if (!fs) return STM_EINVAL;
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    /* R128 P2-2: pre-flush before the extent-layer migrate. Without
     * this, buffered ranges aren't visible to stm_sync_migrate_to_cold
     * (which iterates extent_idx); they'd get flushed AFTER the migrate
     * as HOT extents, leaving the file partially-cold. */
    stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
    if (fr != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return fr;
    }
    stm_status s = stm_sync_migrate_to_cold(fs->sync, dataset_id, ino);
    pthread_rwlock_unlock(&fs->global);
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
    pthread_rwlock_wrlock(&fs->global);
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
    pthread_rwlock_unlock(&fs->global);

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
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *idx = stm_sync_dataset_index(fs->sync);
    pass_all_id_collect_ctx ctx = { .err = STM_OK };
    stm_status its = stm_dataset_iter(idx, pass_all_id_collect_cb, &ctx);
    if (its != STM_OK || ctx.err != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
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
    pthread_rwlock_unlock(&fs->global);

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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    /* R128 P2-2: pre-flush before the extent-layer promote. Without
     * this, buffered ranges aren't visible to stm_sync_promote_to_hot;
     * they'd flush AFTER as HOT extents — net-benign if the default
     * tier IS hot, but the contract "this inode is now fully hot" is
     * violated if any buffered range sits in flight. Symmetric with
     * stm_fs_migrate_to_cold. */
    stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
    if (fr != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return fr;
    }
    stm_status rc = stm_sync_promote_to_hot(fs->sync, dataset_id, ino);
    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
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
    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *idx = stm_sync_dataset_index(fs->sync);
    pass_all_id_collect_ctx ctx = { .err = STM_OK };
    stm_status its = stm_dataset_iter(idx, pass_all_id_collect_cb, &ctx);
    if (its != STM_OK || ctx.err != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
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
    pthread_rwlock_unlock(&fs->global);

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
        /* SWISS-4m1: use cached UNWRAPPED keypair installed at mount.
         * No reload-from-disk; no plaintext passphrase needed
         * post-mount. Falls back to plaintext keyfile load if the
         * cache is missing — defensive (cached_keys SHOULD always be
         * non-NULL post-mount when have_kf is true; this fallback
         * preserves the old contract for any future code path that
         * fs_new's without going through stm_fs_mount). */
        if (fs->cached_keys) {
            memcpy(wk.pk, fs->cached_keys->pk, sizeof wk.pk);
            memcpy(wk.sk, fs->cached_keys->sk, sizeof wk.sk);
        } else {
            stm_status ks = stm_keyfile_load(fs->keyfile_path, &wk);
            if (ks != STM_OK) return ks;
        }
    } else {
        stm_status js = stm_janus_client_connect(fs->janus_socket, &janus);
        if (js != STM_OK) return js;
    }

    pthread_rwlock_wrlock(&fs->global);
    if (fs->wedged) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_EWEDGED;
    }
    if (fs->read_only) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_EROFS;
    }

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        /* sync_open always populates the dataset index; a NULL here
         * means a sync-internal corruption that we surface rather
         * than dereferencing. */
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_ECORRUPT;
    }

    uint64_t new_id = 0;
    stm_status s = stm_dataset_create_child(didx, parent_id, name, &new_id);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
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
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    *out_id = new_id;
    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_set_property(didx, dataset_id, prop, value);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_clear_dataset_property(stm_fs *fs, uint64_t dataset_id,
                                            stm_property prop)
{
    if (!fs) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_clear_property(didx, dataset_id, prop);
    pthread_rwlock_unlock(&fs->global);
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

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_effective_property(didx, dataset_id,
                                                     prop, out_value);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* P9-CTL-1c read-side wrappers: /ctl/datasets/ and similar consumers
 * need to enumerate, look up, and count datasets without piercing
 * fs's encapsulation via the test-only fs_testing.h chain.
 *
 * Lock posture: each wrapper takes fs->lock for the duration of the
 * dataset call. For stm_fs_dataset_iter, the user-supplied callback
 * runs WITH fs->lock held — the callback MUST NOT call back into
 * any stm_fs_* API (would deadlock). Typical usage (the /ctl/
 * readdir builder) only formats the entry into a buffer and emits
 * dirents, which is safe. */
stm_status stm_fs_dataset_lookup(stm_fs *fs, uint64_t dataset_id,
                                    stm_dataset_entry *out)
{
    if (out) memset(out, 0, sizeof *out);
    if (!fs || !out) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_lookup(didx, dataset_id, out);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_dataset_count(stm_fs *fs, size_t *out_count)
{
    if (out_count) *out_count = 0;
    if (!fs || !out_count) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_count(didx, out_count);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_dataset_iter(stm_fs *fs, stm_dataset_iter_cb cb, void *ctx)
{
    if (!fs || !cb) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_iter(didx, cb, ctx);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* P9-CTL-1d-debug: per-device alloc stats accessor for /ctl/debug/
 * allocator-state/<device_id>. Mirrors stm_fs_stats_get's wedged-OK
 * posture — alloc stats are diagnostic and operators most need them
 * exactly when fs is wedged. STM_EROFS does not apply.
 *
 * device_id is range-checked against STM_POOL_DEVICES_MAX up front so
 * an out-of-bounds caller doesn't enter sync. stm_sync_alloc returns
 * NULL for unattached or REMOVED slots; that fans out to STM_ENOENT
 * as the public-API contract on the wrapper.
 *
 * Lock posture (R102 P3-2): holds fs->lock across stm_sync_alloc +
 * stm_alloc_stats_get. The two acquire different mutexes (sync's lock
 * is internal to stm_sync_alloc) and do not coordinate. ARCH §6.5.1
 * guarantees stm_sync_alloc's return pointer is valid until the next
 * attach-table mutation (sync_create / replace_device_online); v2.0
 * is single-mutator at sync_create + serial-accept at the daemon, so
 * this is trivially safe. Future concurrent-attach-mutation paths
 * (forward-noted under Phase 8.5+) MUST either extend the lock to
 * span sync's attach table or accept stale-pointer faults — same
 * shape as stm_fs_stats_get. */
stm_status stm_fs_alloc_stats_get(const stm_fs *fs, uint16_t device_id,
                                     stm_alloc_stats *out)
{
    if (out) memset(out, 0, sizeof *out);
    if (!fs || !out) return STM_EINVAL;
    if (device_id >= STM_POOL_DEVICES_MAX) return STM_EINVAL;

    stm_fs *mfs = (stm_fs *)fs;
    pthread_rwlock_wrlock(&mfs->global);
    /* Allow reading stats on a wedged fs — matches stm_fs_stats_get
     * (fs.c:4737) for the same reason: diagnostics. */

    stm_alloc *a = stm_sync_alloc(fs->sync, device_id);
    if (!a) {
        pthread_rwlock_unlock(&mfs->global);
        return STM_ENOENT;
    }

    stm_status s = stm_alloc_stats_get(a, out);
    pthread_rwlock_unlock(&mfs->global);
    return s;
}

/* R102 P3-1: lightweight is-attached predicate. The /ctl/ readdir
 * loop probes 64 slots per call; without this, each probe would
 * trigger a full alloc-tree scan via stm_alloc_stats_get on every
 * attached slot. Bypass the scan by checking only stm_sync_alloc's
 * NULL/non-NULL return. Same wedged-OK posture as the heavy variant. */
stm_status stm_fs_alloc_attached(const stm_fs *fs, uint16_t device_id,
                                    bool *out)
{
    if (out) *out = false;
    if (!fs || !out) return STM_EINVAL;
    if (device_id >= STM_POOL_DEVICES_MAX) return STM_EINVAL;

    stm_fs *mfs = (stm_fs *)fs;
    pthread_rwlock_wrlock(&mfs->global);
    stm_alloc *a = stm_sync_alloc(fs->sync, device_id);
    *out = (a != NULL);
    pthread_rwlock_unlock(&mfs->global);
    return STM_OK;
}

/* P9-CTL-1d-actions-snapshot-create: snapshot create wrapper.
 * Resolves the snapshot index via stm_sync_snapshot_index, captures
 * sync's current_gen as extent_txg, and dispatches to stm_snapshot_
 * create. Holds fs->lock + FS_GUARD_WRITE — creating a snapshot
 * mutates the snapshot index, so wedged + read-only states refuse.
 *
 * NUL-terminates the (name, name_len) slice into a STM_SNAP_NAME_MAX+1
 * stack buffer so it can hand to stm_snapshot_create which uses
 * strlen internally. The wrapper validates length BEFORE the copy
 * (refuses 0 or > STM_SNAP_NAME_MAX) so the buffer is never
 * overflowed.
 *
 * R99 P2-1 carry: snapshot.c's snapshot_create_inner now calls
 * stm_snap_name_chars_valid which refuses bytes < 0x20 + 0x7F.
 * The wrapper relies on that source-side gate — does not duplicate
 * the check (single-source-of-truth posture per R99 P2-1's lesson). */
stm_status stm_fs_create_snapshot(stm_fs *fs, uint64_t dataset_id,
                                     const char *name, size_t name_len,
                                     uint64_t *out_id)
{
    if (out_id) *out_id = 0;
    if (!fs || !name || !out_id) return STM_EINVAL;
    if (dataset_id == 0) return STM_EINVAL;
    if (name_len == 0 || name_len > STM_SNAP_NAME_MAX) return STM_EINVAL;

    /* Wrapper-side defense-in-depth: snapshot.c's char-validation
     * runs after `strlen(name)` truncates at the first 0x00 byte.
     * If the caller passes "bad\0name" with name_len=8, snapshot.c
     * sees "bad" (3 chars) and accepts it — the embedded NUL has
     * silently truncated the name. The wrapper's contract takes a
     * (name, name_len) slice, so we MUST refuse embedded NULs
     * here to prevent the caller from being surprised.
     *
     * Refusing the full <0x20 + 0x7F class at the wrapper too is
     * defense-in-depth — the underlying check in snapshot.c is the
     * source-of-truth, but this wrapper is a trust boundary that
     * users (CLI, /ctl/, FUSE) call directly. Two checks make any
     * future API drift harder to silently introduce. */
    for (size_t i = 0; i < name_len; i++) {
        uint8_t c = (uint8_t)name[i];
        if (c < 0x20 || c == 0x7F) return STM_EINVAL;
    }

    char nbuf[STM_SNAP_NAME_MAX + 1];
    memcpy(nbuf, name, name_len);
    nbuf[name_len] = '\0';

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    /* R128 P2-3 + SWISS-4q-flush-snapshot close: drain ALL buffered
     * ranges before the snapshot's extent-tree snapshot point. Without
     * this, buffered plaintext doesn't reach the extent tree until a
     * later flush — the snapshot's recorded txg captures only what's
     * already in extents, missing the user's most recent writes.
     *
     * v1.0: over-flushes (every dataset, every inode). Snapshots are
     * infrequent so the cost is acceptable. v1.1 may add a dataset-
     * scoped drain (stm_dirty_buffer_drain_dataset). */
    {
        stm_status fr = fs_flush_all_locked(fs);
        if (fr != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
    }

    /* R105 P3-2: validate dataset_id is a PRESENT dataset before
     * creating a snapshot for it. The underlying snapshot.c uses
     * dataset_id as an opaque bucket-key without lookup; without
     * this gate, non-/ctl/ callers (CLI, FUSE, direct embedders)
     * could create orphan snapshot records keyed at never-registered
     * or destroyed dataset_ids — internally consistent but
     * occupying snapshot index slots and bumping current_txg
     * unnecessarily.
     *
     * The /ctl/ vops_walk + vops_open paths already perform the
     * lookup, so this gate is unreachable through /ctl/ today; it's
     * defense-in-depth at the public-API trust boundary. */
    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }
    stm_dataset_entry tmp;
    stm_status drc = stm_dataset_lookup(didx, dataset_id, &tmp);
    if (drc != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return drc;     /* propagates STM_ENOENT for missing dataset */
    }

    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    uint64_t cur_gen = stm_sync_current_gen(fs->sync);
    /* tree_root_paddr=0: dataset.h's stm_dataset_entry doesn't yet
     * carry a per-dataset tree-root paddr (P6/P7 follow-on). v2.0's
     * snapshot index records the value as opaque metadata; existing
     * tests (test_send_recv.c:222) pass 0 too. When the per-dataset
     * tree-root surface lands, this wrapper bumps to pass it
     * through. */
    stm_status s = stm_snapshot_create(sidx, dataset_id, nbuf,
                                          /*tree_root_paddr=*/0,
                                          cur_gen, out_id);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* P9-CTL-1d-actions-snapshot-delete: snapshot delete + dead-list
 * reclamation in one wrapper call. Holds fs->lock for the entire
 * cycle so no concurrent stm_sync_commit can race against the
 * paddr reclaim — addresses snapshot.h's "MUST be reclaimed before
 * next sync_commit" contract.
 *
 * Best-effort posture: if any individual stm_alloc_free or
 * stm_cas_deref fails, the wrapper continues with the rest and
 * returns the first non-OK status. The snapshot is GONE regardless;
 * a non-OK return means "snap deleted, but some blocks may have
 * leaked from tracking" — operator-visible at the next mount's
 * scrub. */
stm_status stm_fs_delete_snapshot(stm_fs *fs, uint64_t snapshot_id,
                                     size_t *out_freed_count)
{
    if (out_freed_count) *out_freed_count = 0;
    if (!fs) return STM_EINVAL;
    if (snapshot_id == 0) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    uint64_t free_gen = stm_sync_current_gen(fs->sync);

    uint64_t *freed = NULL;
    size_t freed_n = 0;
    uint8_t *cold_hashes = NULL;
    size_t cold_n = 0;
    stm_status del = stm_snapshot_delete(sidx, snapshot_id,
                                            &freed, &freed_n,
                                            &cold_hashes, &cold_n);
    if (del != STM_OK) {
        /* Snapshot.h contract: on non-OK return, both pairs are
         * zero/NULL. Defensive free anyway. */
        free(freed);
        free(cold_hashes);
        pthread_rwlock_unlock(&fs->global);
        return del;
    }

    if (out_freed_count) *out_freed_count = freed_n;

    /* First-failure status — propagated after the cleanup loop runs
     * to completion (best-effort reclaim). */
    stm_status first_err = STM_OK;

    /* Route freed paddrs to per-device allocators. The paddr's high
     * 16 bits encode the device id (super.h::stm_paddr_device); the
     * sync layer's attach table maps device_id → stm_alloc *. */
    for (size_t i = 0; i < freed_n; i++) {
        uint16_t did = stm_paddr_device(freed[i]);
        stm_alloc *a = stm_sync_alloc(fs->sync, did);
        if (!a) {
            /* Device unattached — paddr leaks from tracking. Record
             * the failure but keep iterating; the operator's next-
             * mount scrub catches the orphan. */
            if (first_err == STM_OK) first_err = STM_ENOENT;
            continue;
        }
        stm_status fr = stm_alloc_free(a, freed[i], free_gen);
        if (fr != STM_OK && first_err == STM_OK) first_err = fr;
    }

    /* CAS dead-list: dereference each cold hash. Auto-GC at the
     * next stm_sync_commit reclaims refcount=0 entries. If the
     * fs has no CAS index attached (rare; v2 production paths
     * mount with one), skip the deref loop. */
    if (cold_hashes && cold_n > 0) {
        stm_cas_index *cidx = stm_sync_cas_index(fs->sync);
        if (cidx) {
            for (size_t i = 0; i < cold_n; i++) {
                stm_status dr = stm_cas_deref(cidx,
                    &cold_hashes[i * STM_CAS_HASH_LEN]);
                if (dr != STM_OK && first_err == STM_OK) first_err = dr;
            }
        } else if (first_err == STM_OK) {
            /* Cold-hashes returned but no CAS index — leak. Same
             * shape as device-unattached case above. */
            first_err = STM_ENOENT;
        }
    }

    free(freed);
    free(cold_hashes);
    pthread_rwlock_unlock(&fs->global);
    return first_err;
}

/* P9-CTL-1d-actions-snapshot-hold: thin hold/release wrappers. Both
 * mutate the snapshot index's hold-count counter under fs->lock +
 * FS_GUARD_WRITE.
 *
 * R108 P2-1 fix: hold_count IS persisted across mount cycles
 * (snapshot.h's on-disk layout reserves offset 40 for it; snapshot.c
 * sets idx->dirty = true on hold/release; stm_sync_commit flushes
 * the index to disk; on next mount the encoded value is decoded
 * back). An earlier docstring incorrectly claimed in-RAM-only
 * semantics — corrected here and at the public-API site. Crash
 * window: a hold taken after the last sync but before the next is
 * lost on remount; operators wanting durable holds should commit. */
stm_status stm_fs_hold_snapshot(stm_fs *fs, uint64_t snapshot_id)
{
    if (!fs) return STM_EINVAL;
    if (snapshot_id == 0) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_snapshot_hold(sidx, snapshot_id);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_release_snapshot(stm_fs *fs, uint64_t snapshot_id)
{
    if (!fs) return STM_EINVAL;
    if (snapshot_id == 0) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_snapshot_release(sidx, snapshot_id);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_set_dataset_pool_default(stm_fs *fs, stm_property prop,
                                              uint64_t value)
{
    if (!fs) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    stm_status s = stm_dataset_set_pool_default(didx, prop, value);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* ========================================================================= */
/* P8-POSIX-7b: fallocate(2) — every FALLOC_FL_* flag.                        */
/* ========================================================================= */

/* Linux FALLOC_FL_* drift guards. Every STM_FS_FALLOC_FL_* constant
 * must match Linux's value verbatim so a 9P/FUSE binding can pass
 * the kernel's flags through. */
_Static_assert(STM_FS_FALLOC_FL_KEEP_SIZE      == 0x01u,
               "FALLOC_FL_KEEP_SIZE drift");
_Static_assert(STM_FS_FALLOC_FL_PUNCH_HOLE     == 0x02u,
               "FALLOC_FL_PUNCH_HOLE drift");
_Static_assert(STM_FS_FALLOC_FL_COLLAPSE_RANGE == 0x08u,
               "FALLOC_FL_COLLAPSE_RANGE drift");
_Static_assert(STM_FS_FALLOC_FL_ZERO_RANGE     == 0x10u,
               "FALLOC_FL_ZERO_RANGE drift");
_Static_assert(STM_FS_FALLOC_FL_INSERT_RANGE   == 0x20u,
               "FALLOC_FL_INSERT_RANGE drift");
_Static_assert(STM_FS_FALLOC_FL_UNSHARE_RANGE  == 0x40u,
               "FALLOC_FL_UNSHARE_RANGE drift");

/* R89 P3-2: alias to STM_UB_SIZE (the canonical 4 KiB block).
 * Drift-protected via Static_assert below. */
#define FS_FALLOC_BLOCK ((uint64_t)STM_UB_SIZE)
_Static_assert(STM_UB_SIZE == 4096u,
               "FS_FALLOC_BLOCK assumes STM_UB_SIZE == 4 KiB");

/* Look up the inode + verify it's a regular file. Returns the
 * inode_value via *out_iv. Caller MUST hold fs->lock. */
static stm_status fs_fallocate_validate_target(stm_fs *fs,
                                                    uint64_t dataset_id,
                                                    uint64_t ino,
                                                    struct stm_inode_value *out_iv) {
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) return STM_EINVAL;
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, out_iv);
    if (ls != STM_OK) return ls;
    uint32_t mode = stm_load_le32(out_iv->si_mode);
    if ((mode & (uint32_t)S_IFMT) != (uint32_t)S_IFREG) return STM_EINVAL;
    return STM_OK;
}

stm_status stm_fs_fallocate(stm_fs *fs,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  uint32_t flags)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (len == 0u) return STM_EINVAL;
    if (off > UINT64_MAX - len) return STM_EINVAL;
    if ((flags & ~(uint32_t)STM_FS_FALLOC_MASK) != 0u) return STM_EINVAL;

    /* Flag-combination matrix.
     *   - PUNCH_HOLE requires KEEP_SIZE.
     *   - COLLAPSE / INSERT cannot combine with any other flag.
     *   - UNSHARE may combine with KEEP_SIZE only.
     *   - ZERO_RANGE may combine with KEEP_SIZE only.
     *   - KEEP_SIZE alone is legal.
     *   - 0 (default preallocate) is legal. */
    bool keep_size = (flags & STM_FS_FALLOC_FL_KEEP_SIZE) != 0u;
    bool punch     = (flags & STM_FS_FALLOC_FL_PUNCH_HOLE) != 0u;
    bool collapse  = (flags & STM_FS_FALLOC_FL_COLLAPSE_RANGE) != 0u;
    bool zero_r    = (flags & STM_FS_FALLOC_FL_ZERO_RANGE) != 0u;
    bool insert    = (flags & STM_FS_FALLOC_FL_INSERT_RANGE) != 0u;
    bool unshare   = (flags & STM_FS_FALLOC_FL_UNSHARE_RANGE) != 0u;

    /* At most ONE of {punch, collapse, zero_r, insert, unshare} set. */
    int n_op = (int)punch + (int)collapse + (int)zero_r + (int)insert +
               (int)unshare;
    if (n_op > 1) return STM_EINVAL;

    if (punch && !keep_size) return STM_EINVAL;
    if (collapse && (flags & ~(uint32_t)STM_FS_FALLOC_FL_COLLAPSE_RANGE) != 0u)
        return STM_EINVAL;
    if (insert && (flags & ~(uint32_t)STM_FS_FALLOC_FL_INSERT_RANGE) != 0u)
        return STM_EINVAL;

    /* Block-alignment: every range op requires block-aligned off + len. */
    bool any_range_op = punch || collapse || zero_r || insert || unshare;
    if (any_range_op) {
        if ((off % FS_FALLOC_BLOCK) != 0u) return STM_EINVAL;
        if ((len % FS_FALLOC_BLOCK) != 0u) return STM_EINVAL;
    }

    /* R89 P2-3: COLLAPSE / INSERT pass `(int64_t)len` to the
     * shift-keys primitive; refuse `len > INT64_MAX` upfront so
     * the cast never produces signed overflow (UB at
     * -fsanitize=signed-integer-overflow). */
    if ((collapse || insert) && len > (uint64_t)INT64_MAX) {
        return STM_EINVAL;
    }

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    /* SWISS-4q-flush: fallocate operates on the extent tree directly
     * (PUNCH_HOLE drops extents, COLLAPSE/INSERT shifts extent keys,
     * etc.). Any buffered ranges for this inode are invisible to those
     * ops and would survive PUNCH_HOLE / get out of sync with shifted
     * extents. Pre-flush this inode so the extent layer reflects all
     * issued writes before fallocate acts. */
    {
        stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
        if (fr != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
    }

    struct stm_inode_value iv = {0};
    stm_status vs = fs_fallocate_validate_target(fs, dataset_id, ino, &iv);
    if (vs != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return vs;
    }

    /* R89 P0-1/2/3 fix: si_data_kind discrimination.
     *
     * INLINE-mode files don't have extents — they store data
     * directly in si_data.inline_data[100]. fallocate ops that
     * mutate range or extend si_size past STM_INODE_INLINE_MAX
     * would either OOB-read on subsequent reads (the INLINE read
     * path computes `avail = cur_size - off` and memcpy's from
     * inline_data) OR silently no-op without effect.
     *
     * MVP refusal posture: every range op refuses
     * STM_ENOTSUPPORTED on INLINE-mode files. The default
     * preallocate (flags=0 / KEEP_SIZE alone) is allowed but
     * refuses with STM_ERANGE if it would grow si_size past the
     * inline cap (would create the OOB shape). Callers that need
     * fallocate on INLINE files must transition the file to
     * EXTENT first via `stm_fs_truncate` (which has the
     * INLINE→EXTENT transition path baked in). */
    uint8_t kind = iv.si_data_kind;
    if (kind == STM_DATA_INLINE) {
        if (any_range_op) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOTSUPPORTED;
        }
        /* Default preallocate on INLINE: allow ONLY if not extending
         * past the inline cap. Otherwise refuse — caller must
         * truncate-up first to trigger the INLINE→EXTENT transition. */
        if (!keep_size && (off + len) > (uint64_t)STM_INODE_INLINE_MAX) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ERANGE;
        }
    }

    /* Sealed-file enforcement: F_SEAL_WRITE / FUTURE_WRITE block
     * every fallocate op (mutates content); F_SEAL_GROW blocks ops
     * that would extend the file (default preallocate without
     * KEEP_SIZE, INSERT_RANGE, ZERO_RANGE without KEEP_SIZE);
     * F_SEAL_SHRINK blocks ops that would shrink (COLLAPSE_RANGE,
     * PUNCH_HOLE without KEEP_SIZE — but we already required
     * KEEP_SIZE for PUNCH_HOLE so PUNCH never shrinks logical
     * size). Match Linux fallocate(2)'s seal enforcement at the
     * kernel-VFS layer. */
    uint32_t cur_flags = stm_load_le32(iv.si_flags);
    if (cur_flags & (uint32_t)(STM_INO_FLAG_SEAL_WRITE |
                                STM_INO_FLAG_SEAL_FUTURE_WRITE)) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EPERM;
    }
    uint64_t cur_size = stm_load_le64(iv.si_size);
    bool would_grow = false;
    if (!any_range_op && !keep_size) {
        /* Default preallocate: bump si_size to off+len if extending. */
        if (off + len > cur_size) would_grow = true;
    } else if (insert) {
        would_grow = true;
    } else if (zero_r && !keep_size) {
        if (off + len > cur_size) would_grow = true;
    }
    bool would_shrink = collapse;
    if (would_grow && (cur_flags & (uint32_t)STM_INO_FLAG_SEAL_GROW)) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EPERM;
    }
    if (would_shrink && (cur_flags & (uint32_t)STM_INO_FLAG_SEAL_SHRINK)) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EPERM;
    }

    stm_extent_index *eidx = stm_sync_extent_index(fs->sync);
    if (!eidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    stm_status s = STM_OK;

    if (punch) {
        /* PUNCH_HOLE | KEEP_SIZE: route through stm_sync_punch_range
         * which (R89 P0-4 fix) properly drops paddrs through the
         * snapshot dead-list + alloc free pool. Refuses
         * STM_ENOTSUPPORTED on crossing or COLD extents. */
        s = stm_sync_punch_range(fs->sync, dataset_id, ino, off, len);
        if (s == STM_OK) {
            fs_stamp_mtime_ctime_now(&iv);
            stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
            (void)stm_inode_set(iidx, dataset_id, ino, &iv);
        }
    } else if (collapse) {
        /* COLLAPSE_RANGE: range must already be empty + no crossing
         * boundary extents (refuse STM_ENOTSUPPORTED). Shift
         * extents above off+len down by len. Shrink si_size by len.
         *
         * R89 P2-1: Linux fallocate(2) refuses with EINVAL when
         * `off + len >= cur_size` (collapse beyond EOF is
         * undefined). Mirror that. */
        if (off + len > cur_size) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        s = stm_extent_shift_range_keys(eidx, dataset_id, ino,
                                             off + len,
                                             -(int64_t)len);
        if (s == STM_OK) {
            uint64_t new_size = cur_size - len;
            iv.si_size = stm_store_le64(new_size);
            fs_stamp_mtime_ctime_now(&iv);
            stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
            (void)stm_inode_set(iidx, dataset_id, ino, &iv);
        }
    } else if (insert) {
        /* INSERT_RANGE: shift extents at off' >= off up by len.
         * Refuse if extent crosses off (STM_ENOTSUPPORTED).
         * si_size grows by len.
         *
         * R89 P2-2: Linux fallocate(2) refuses with EINVAL when
         * `off >= cur_size` (inserting past EOF is undefined —
         * inserting at exactly cur_size is also refused since
         * that's just appending). */
        if (off >= cur_size) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        if (cur_size > UINT64_MAX - len) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EOVERFLOW;
        }
        s = stm_extent_shift_range_keys(eidx, dataset_id, ino,
                                             off, (int64_t)len);
        if (s == STM_OK) {
            iv.si_size = stm_store_le64(cur_size + len);
            fs_stamp_mtime_ctime_now(&iv);
            stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
            (void)stm_inode_set(iidx, dataset_id, ino, &iv);
        }
    } else if (zero_r) {
        /* ZERO_RANGE: punch via stm_sync_punch_range (R89 P0-4
         * paddr-routing fix) + (if !keep_size and would_grow) bump
         * si_size. MVP: equivalent to PUNCH_HOLE structurally — the
         * extent slots are dropped; subsequent reads return zeros
         * via sparse-extent semantics. */
        s = stm_sync_punch_range(fs->sync, dataset_id, ino, off, len);
        if (s == STM_OK) {
            if (!keep_size && (off + len) > cur_size) {
                iv.si_size = stm_store_le64(off + len);
            }
            fs_stamp_mtime_ctime_now(&iv);
            stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
            (void)stm_inode_set(iidx, dataset_id, ino, &iv);
        }
    } else if (unshare) {
        /* UNSHARE_RANGE: composes via stm_fs_promote_to_hot —
         * promote_to_hot promotes EVERY COLD extent at the ino
         * (broader than POSIX requires for a partial range, but
         * correct + conservative). Drop fs->lock first since
         * promote_to_hot takes fs->lock. */
        pthread_rwlock_unlock(&fs->global);
        stm_status ps = stm_fs_promote_to_hot(fs, dataset_id, ino);
        /* STM_ENOENT is "no COLD extents to promote" — already
         * unshared, return OK. Other errors bubble up. */
        if (ps == STM_ENOENT) return STM_OK;
        return ps;
    } else {
        /* Default preallocate (flags == 0 OR flags == KEEP_SIZE).
         * MVP: stratum is sparse-by-construction so "preallocate"
         * is a metadata-only op. Bump si_size to off+len if not
         * KEEP_SIZE and extending. */
        if (!keep_size) {
            if ((off + len) > cur_size) {
                iv.si_size = stm_store_le64(off + len);
                fs_stamp_mtime_ctime_now(&iv);
                stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
                (void)stm_inode_set(iidx, dataset_id, ino, &iv);
            }
        }
        s = STM_OK;
    }

    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* ========================================================================= */
/* P8-POSIX-7d: advisory locks — flock(2) + fcntl(2) F_OFD_SETLK shape.       */
/* ========================================================================= */

/* Drift guards: STM_FS_LOCK_* in fs.h must match STM_LOCK_* in
 * locks.h numerically so callers can pass the fs.h alias straight
 * through. */
_Static_assert(STM_FS_LOCK_SHARED    == STM_LOCK_SHARED,
               "STM_FS_LOCK_SHARED drift");
_Static_assert(STM_FS_LOCK_EXCLUSIVE == STM_LOCK_EXCLUSIVE,
               "STM_FS_LOCK_EXCLUSIVE drift");

/* R90 P1-1 fix: every lock wrapper HOLDS fs->lock through the
 * inner stm_lock_* call. The earlier "drop fs->lock before
 * delegating" posture created a UAF window vs concurrent
 * stm_fs_unmount (which holds fs->lock through stm_lock_table_close
 * + free(fs)). Holding fs->lock serializes lock-table ops behind
 * other fs ops, which is the same posture every other v2 fs API
 * uses (stm_fs_reserve / stm_fs_lookup / etc). The lock-table's
 * own internal mutex is then a fast path under fs->lock — its
 * primary purpose post-fix is to guard the records[] array
 * against the (admittedly now-impossible) concurrent caller. */

stm_status stm_fs_lock(stm_fs *fs,
                              uint64_t dataset_id, uint64_t ino,
                              uint64_t owner_id, uint8_t type,
                              uint64_t off, uint64_t len)
{
    if (!fs) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);
    stm_status s = stm_lock_acquire(fs->locks, dataset_id, ino,
                                          owner_id, type, off, len);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_unlock(stm_fs *fs,
                                uint64_t dataset_id, uint64_t ino,
                                uint64_t owner_id,
                                uint64_t off, uint64_t len)
{
    if (!fs) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);
    stm_status s = stm_lock_release(fs->locks, dataset_id, ino,
                                          owner_id, off, len);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_lock_test(stm_fs *fs,
                                   uint64_t dataset_id, uint64_t ino,
                                   uint64_t owner_id, uint8_t type,
                                   uint64_t off, uint64_t len,
                                   bool *out_would_grant,
                                   uint64_t *out_conflicting_owner)
{
    /* Uniform out-param zero-init contract. */
    if (out_would_grant) *out_would_grant = false;
    if (out_conflicting_owner) *out_conflicting_owner = 0;
    if (!fs || !out_would_grant) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);
    stm_status s = stm_lock_test(fs->locks, dataset_id, ino,
                                       owner_id, type, off, len,
                                       out_would_grant,
                                       out_conflicting_owner);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_release_lock_owner(stm_fs *fs, uint64_t owner_id)
{
    if (!fs) return STM_EINVAL;

    /* (R92 P2-2) Lock release is RAM-only cleanup with no fs-durability
     * implications; tolerate wedged + RO state. The previous
     * FS_GUARD_READ gate refused on wedged, which silently dropped
     * lock-cleanup-on-clunk in the wedged window — DoS shape (lock-
     * table grows unbounded as long as the wedged fs stays mounted).
     * Take the lock to serialize against unmount, then release without
     * the wedge guard. */
    pthread_rwlock_wrlock(&fs->global);
    stm_status s = stm_lock_release_owner(fs->locks, owner_id);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_lock_count(stm_fs *fs, size_t *out_count)
{
    if (out_count) *out_count = 0;
    if (!fs || !out_count) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);
    stm_status s = stm_lock_count(fs->locks, out_count);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* ========================================================================= */
/* P8-POSIX-7e: posix_fadvise(2) pass-through.                                */
/* ========================================================================= */

/* Drift guard between the public STM_FS_FADV_* constants and Linux's
 * POSIX_FADV_* values. They are numerically identical so a binding
 * layer (9P/FUSE) can pass the kernel's advice through untranslated.
 * See `man 2 posix_fadvise` — values are stable since Linux 2.5.60. */
_Static_assert(STM_FS_FADV_NORMAL     == 0u, "POSIX_FADV_NORMAL drift");
_Static_assert(STM_FS_FADV_RANDOM     == 1u, "POSIX_FADV_RANDOM drift");
_Static_assert(STM_FS_FADV_SEQUENTIAL == 2u, "POSIX_FADV_SEQUENTIAL drift");
_Static_assert(STM_FS_FADV_WILLNEED   == 3u, "POSIX_FADV_WILLNEED drift");
_Static_assert(STM_FS_FADV_DONTNEED   == 4u, "POSIX_FADV_DONTNEED drift");
_Static_assert(STM_FS_FADV_NOREUSE    == 5u, "POSIX_FADV_NOREUSE drift");

stm_status stm_fs_fadvise(stm_fs *fs,
                                  uint64_t dataset_id, uint64_t ino,
                                  uint64_t off, uint64_t len,
                                  uint32_t advice)
{
    (void)off;
    (void)len;

    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;

    switch (advice) {
    case STM_FS_FADV_NORMAL:
    case STM_FS_FADV_RANDOM:
    case STM_FS_FADV_SEQUENTIAL:
    case STM_FS_FADV_WILLNEED:
    case STM_FS_FADV_DONTNEED:
    case STM_FS_FADV_NOREUSE:
        break;
    default:
        return STM_EINVAL;
    }

    /* Wedged check via FS_GUARD_READ. RO mounts pass — the
     * WILLNEED/DONTNEED delegate's own FS_GUARD_WRITE will refuse
     * with STM_EROFS, which we then SWALLOW (advisory). No
     * existence check: posix_fadvise(2) doesn't validate file
     * contents, and stratum's legacy direct-extent files have no
     * inode-index entry but are valid fadvise targets (the inner
     * promote/migrate primitives accept them). The delegate's
     * own ino-not-found path is also swallowed. */
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_READ(fs);
    pthread_rwlock_unlock(&fs->global);

    /* Drop fs->lock BEFORE delegating — stm_fs_promote_to_hot /
     * stm_fs_migrate_to_cold take fs->lock + FS_GUARD_WRITE themselves;
     * holding it nested would deadlock.
     *
     * R87 P3-5 acknowledgment: the swallow contract intentionally
     * masks every inner status (STM_ENOENT for all-HOT inos on
     * WILLNEED, STM_EROFS on RO mounts, STM_EBADTAG/STM_EIO on
     * per-extent corruption, STM_ENOSPC on cold-tier exhaustion,
     * STM_EWEDGED if the FS becomes wedged after the front-check
     * unlock). No fault-injection test pins this — the dispatch
     * shape is a self-evident `(void)rc` discard, not a status-
     * dependent branch — but a future refactor that introduces
     * status-dependent behavior here MUST land with a fault-
     * injection regression test that pins the swallow surface. */
    switch (advice) {
    case STM_FS_FADV_WILLNEED: {
        stm_status rc = stm_fs_promote_to_hot(fs, dataset_id, ino);
        (void)rc;  /* advisory — swallow per POSIX posix_fadvise(2) */
        return STM_OK;
    }
    case STM_FS_FADV_DONTNEED: {
        stm_status rc = stm_fs_migrate_to_cold(fs, dataset_id, ino);
        (void)rc;  /* advisory — swallow */
        return STM_OK;
    }
    default:
        /* NORMAL / RANDOM / SEQUENTIAL / NOREUSE — no-op. Stratum has
         * no userspace page cache to bias by access pattern. */
        return STM_OK;
    }
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
    pthread_rwlock_wrlock(&mfs->global);
    /* Allow reading stats on a wedged fs — useful for diagnostics. */

    /* R7e-P2-1: sync first, then alloc — matches the nesting used by
     * stm_fs_commit (sync_commit -> alloc_commit). Keeps a single
     * canonical lock order across all stm_fs entries. */
    stm_sync_info sinfo;
    stm_status s = stm_sync_info_get(fs->sync, &sinfo);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&mfs->global);
        return s;
    }

    stm_alloc_stats astats;
    s = stm_alloc_stats_get(fs->alloc, &astats);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&mfs->global);
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

    pthread_rwlock_unlock(&mfs->global);
    return STM_OK;
}

void stm_fs_mark_wedged(stm_fs *fs)
{
    if (!fs) return;
    pthread_rwlock_wrlock(&fs->global);
    fs->wedged = true;
    pthread_rwlock_unlock(&fs->global);
}

stm_status stm_fs_verify(const stm_fs *fs)
{
    if (!fs) return STM_EINVAL;
    /* Verify is side-effect-free: takes fs->lock so state can't
     * shift under us, but ignores read_only + wedged (both make
     * sense for scrubbing). */
    stm_fs *mfs = (stm_fs *)fs;
    pthread_rwlock_wrlock(&mfs->global);
    stm_status s = stm_alloc_verify(fs->alloc);
    pthread_rwlock_unlock(&mfs->global);
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

/* S5-PRE-A: production-shape pool accessor. Borrowed pointer, same
 * lifetime as the fs handle (set at mount, never rebound). Daemon
 * code (stratumd) uses this to call stm_ctl_attach_pool against the
 * /ctl/ instance it surfaces over the wire. */
stm_pool *stm_fs_pool(stm_fs *fs)
{
    return fs ? fs->pool : NULL;
}

/* S5-PRE-A: production-shape sync accessor. Counterpart to
 * stm_fs_sync_for_test. Daemon code uses this to construct a
 * sibling stm_scrub against the fs's sync handle for surface at
 * /ctl/pools/<uuid>/scrub. */
stm_sync *stm_fs_sync(stm_fs *fs)
{
    return fs ? fs->sync : NULL;
}
