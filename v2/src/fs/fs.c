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
 *   - PARALLEL-3 impl-1..5 mutators (the per-inode SH surface — chmod /
 *     chown / utimens / unlink / rename / reflink / truncate / write /
 *     ...): take fs->global SH (rdlock) PLUS the per-inode mutex for
 *     each target inode via stm_inode_pin/_unpin. Two such ops on
 *     disjoint inodes proceed concurrently; on the same inode they
 *     serialize on the per-inode mutex.
 *   - PARALLEL-3 impl-6 pure-read ops (the "v2 baseline" residual SH
 *     surface): take fs->global SH (rdlock) and NO per-inode pin.
 *
 *   - 9.8-LF-3 wait-free pure-read ops (stm_fs_read INLINE / stat /
 *     lookup / readlink / readdir / get_seals / getxattr / listxattr /
 *     fadvise / name_to_handle / open_by_handle / dataset getters /
 *     aggregate getters): take FS_GUARD_READ_LOCKLESS (atomic wedge
 *     check, NO rwlock) + per-thread EBR pin around the engine
 *     descent. A wait-free read issues a concurrent inode/dirent/xattr
 *     lookup that descends mvcc_root via atomic-acquire-load.
 *     R171 P1-1 SH-fallback: on transient STM_ECORRUPT (a torn-state
 *     observation under same-engine concurrent writer), the reader
 *     drops EBR + acquires fs->global SH + retries via the serial
 *     subsystem call (the idx-mutex excludes the writer's torn
 *     window). The user-visible result is a slow-path retry on
 *     contention, not propagation of a spurious STM_ECORRUPT.
 *
 *     **R171 caller obligation** (P1-3): the wait-free path's atomic
 *     wedge gate does NOT exclude stm_fs_unmount. Embedded callers
 *     MUST quiesce all in-flight stm_fs_* read calls before invoking
 *     stm_fs_unmount; LF-3 wait-free readers do not synchronize
 *     against unmount. Stratumd's accept-loop shutdown drains workers
 *     before unmount, so the obligation is satisfied in production.
 *     The same wait-free regime also lacks EBR retire for the engine
 *     struct freed by rollback / dataset_destroy / sync_close — these
 *     are R171 P0-2/P0-3/P0-4 closure items, deferred to a dedicated
 *     R171-followup chunk + BE-prepend (#1218).
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
#include <stratum/ebr.h>             /* 9.8-LF-3: per-thread EBR handle */
#include <stratum/extent.h>
#include <stratum/inode.h>
#include <stratum/locks.h>
#include <stratum/xattr.h>
#include <stratum/corvus_client.h>
#include <stratum/janus.h>
#include <stratum/keyfile.h>
#include <stratum/pool.h>
#include <stratum/super.h>
#include <stratum/cas.h>
#include <stratum/snapshot.h>
#include <stratum/crypto.h>          /* TLY-A1: stm_random_bytes */
#include <stratum/sync.h>

#include <sys/stat.h>            /* S_IFMT / S_IFREG / S_IFDIR */
#include <time.h>                /* clock_gettime / CLOCK_REALTIME */
#include <unistd.h>              /* geteuid (TLY-A3-keyslot token-mode gate) */

#include <pthread.h>
#include <stdatomic.h>           /* 9.8-LF-3: atomic wedged + read_only */
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

    /* 9.8-LF-3: wedged + read_only are atomic so 9.8 wait-free read ops
     * can check them without holding fs->global. The ONLY writer is
     * stm_fs_mark_wedged (which holds fs->global EX) — the EX
     * exclusion serialises writer-vs-writer; the atomic provides
     * reader-side acquire/release pairing.
     *
     * R171 P3-3: stm_fs_unmount does NOT transition wedged/read_only;
     * it reads them only. Unmount tears the fs down without a wedge
     * transition + without quiescing wait-free readers — the caller
     * MUST ensure no concurrent stm_fs_* calls are in flight before
     * invoking stm_fs_unmount (R171 P0-3, forward-noted to task
     * #1232 R171-followup: "draining" flag + EBR-advance-until-empty
     * loop in unmount). Stratumd's accept-loop shutdown drain
     * provides this quiesce in production; embedded callers must
     * mirror that pattern.
     *
     * Race window vs mark_wedged: a reader's `atomic_load_explicit(
     * acquire)` can return `false` an instant before a wedge-firing
     * write does `store(true, release)`. The reader then proceeds,
     * may touch state about to be declared wedged, and either (a)
     * succeeds on data still coherent or (b) hits a downstream
     * subsystem error that surfaces as some other status. Both
     * outcomes are acceptable — the wedge transition only defines
     * behavior FORWARD from the store. POSIX precedent: stat()
     * concurrent with fs going read-only on disk error returns
     * whatever was true at the syscall boundary. */
    _Atomic(bool) read_only;
    _Atomic(bool) wedged;
};

/* Guard macros. The lock-holding variants (FS_GUARD_READ / FS_GUARD_WRITE)
 * MUST be called while holding fs->global (EX or SH). On the refusal path
 * they UNLOCK fs->global and return from the enclosing function. The
 * caller's happy path is responsible for its own unlock; the guard only
 * takes ownership of the unlock when it bails.
 *
 * The same pthread_rwlock_unlock() call works for both SH and EX holders,
 * so the guard composes with EITHER the pre-PARALLEL-3 EX (wrlock) sites
 * or the new SH (rdlock) per-inode-op sites.
 *
 * R7e-P0-1: a prior revision returned without unlocking, which turned
 * the very next acquisition (from any API, including unmount) into a
 * deadlock — the bug that the removed RO/wedged end-to-end tests had
 * been tripping over and that was misdiagnosed as a POSIX-bdev thread-
 * pool hang.
 *
 * 9.8-LF-3 adds FS_GUARD_READ_LOCKLESS for the wait-free read path: no
 * rwlock acquired; checks fs->wedged via atomic acquire-load. Used by the
 * 21 pure-read ops that drop fs->global SH per the design doc §7.1.    */
#define FS_GUARD_READ(fs) do {                                             \
    if (atomic_load_explicit(&(fs)->wedged, memory_order_acquire)) {       \
        pthread_rwlock_unlock(&(fs)->global);                              \
        return STM_EWEDGED;                                                \
    }                                                                      \
} while (0)

#define FS_GUARD_WRITE(fs) do {                                            \
    if (atomic_load_explicit(&(fs)->wedged, memory_order_acquire)) {       \
        pthread_rwlock_unlock(&(fs)->global);                              \
        return STM_EWEDGED;                                                \
    }                                                                      \
    if (atomic_load_explicit(&(fs)->read_only, memory_order_acquire)) {    \
        pthread_rwlock_unlock(&(fs)->global);                              \
        return STM_EROFS;                                                  \
    }                                                                      \
} while (0)

/* 9.8-LF-3: lock-free wedge gate for the 21 pure-read ops. Pairs with
 * stm_ebr_enter/exit at the caller — does NOT acquire fs->global. The
 * caller invokes this BEFORE stm_ebr_enter, so a wedge refusal returns
 * without entering an epoch (cheaper) and without unlocking anything.
 *
 * Atomic acquire-load synchronises with stm_fs_mark_wedged's release-
 * store. A reader that sees `wedged=false` is guaranteed to be ordered
 * before the wedge transition in modification order — any wedge fired
 * AFTER this load is the reader's race window, and the reader is allowed
 * to proceed (POSIX precedent — clause 9.8-LF-3 atomic-wedged comment
 * block on the struct). */
#define FS_GUARD_READ_LOCKLESS(fs) do {                                    \
    if (atomic_load_explicit(&(fs)->wedged, memory_order_acquire))         \
        return STM_EWEDGED;                                                \
} while (0)

/* ========================================================================= */
/* 9.8-LF-3: per-thread EBR handle cache (pthread_getspecific).               */
/*                                                                            */
/* The 21 pure-read ops drop fs->global SH and instead pin EBR for memory    */
/* safety against retired engine nodes (the LF-2 substrate). EBR's contract  */
/* is one stm_ebr_register() per thread, NOT per call — register-per-call    */
/* would defeat the cost target (5 ns enter/exit vs ~500 ns alloc).          */
/*                                                                            */
/* We cache the handle in TLS via pthread_getspecific. First call on a       */
/* thread lazily registers; the pthread destructor releases at thread exit.  */
/* Initialization of the key is a one-shot pthread_once.                     */
/*                                                                            */
/* Caller contract: fs_ebr_thread_current() returns a stm_ebr_thread *      */
/* the caller MUST stm_ebr_enter / _exit around shared-data access. NULL on  */
/* allocation failure — caller refuses with STM_ENOMEM.                      */
/*                                                                            */
/* Lifecycle: stm_ebr_init() is called from stm_fs_mount on the first mount; */
/* it's idempotent. Per-thread registration is lazy on first use. The key's  */
/* destructor runs at thread exit and calls stm_ebr_thread_free, which is    */
/* safe to call outside an enter/exit pair. Process exit destroys the key    */
/* itself (pthread_key_create has no matching destroy — keys leak, which is  */
/* fine at process scope).                                                   */
/* ========================================================================= */

static pthread_key_t  fs_ebr_key;
static pthread_once_t fs_ebr_key_once = PTHREAD_ONCE_INIT;

static void fs_ebr_destructor(void *handle)
{
    if (handle) stm_ebr_thread_free((stm_ebr_thread *)handle);
}

static void fs_ebr_key_init(void)
{
    /* Failure to create the key would force every reader through the
     * stm_ebr_register/free pair per call. We accept the alloc cost over
     * a crash here — the key allocation failing at process startup is
     * basically OOM territory, which the system has bigger problems
     * with. Caller surfaces it as STM_ENOMEM downstream. */
    (void)pthread_key_create(&fs_ebr_key, fs_ebr_destructor);
}

static stm_ebr_thread *fs_ebr_thread_current(void)
{
    pthread_once(&fs_ebr_key_once, fs_ebr_key_init);
    stm_ebr_thread *t = (stm_ebr_thread *)pthread_getspecific(fs_ebr_key);
    if (t != NULL) return t;
    t = stm_ebr_register();
    if (t == NULL) return NULL;
    if (pthread_setspecific(fs_ebr_key, t) != 0) {
        /* Setspecific failure is rare (the key must be valid). Don't leak
         * the handle — free it and report failure. */
        stm_ebr_thread_free(t);
        return NULL;
    }
    return t;
}

/* ========================================================================= */
/* 9.7-impl-5: synthetic inode encoding for .snaps/ mount surface.            */
/*                                                                            */
/* The .snaps/ namespace is a stateless namespace projection of frozen        */
/* snapshot trees onto the live mount. Synthetic inodes occupy the high      */
/* half of the 64-bit ino space (bit 63 = 1); live inodes always have bit    */
/* 63 = 0 because the allocator grows from 1 monotonically and would need    */
/* ~2^63 inodes per dataset before colliding with the synthetic range.       */
/*                                                                            */
/* Encoding (within bit 63 = 1):                                              */
/*   - The sentinel value `1ULL << 63` (i.e., snap_id=0 + frozen_ino=0) is   */
/*     SNAPS_PARENT — the synthetic ".snaps" dir at every dataset root.      */
/*     The dataset_id arg to the fs API call discriminates per-dataset.     */
/*   - All other synth values: bits 62..32 = snap_id (31 bits, range        */
/*     [1, 2^31)); bits 31..0 = frozen_ino (32 bits, range [1, 2^32)).      */
/*     This is a SNAP_VIEW inode in snap_id's frozen tree.                   */
/*                                                                            */
/* Saturation: snap_id ≥ 2^31 OR frozen_ino ≥ 2^32 cannot be projected;     */
/* synthesis returns STM_EOVERFLOW. At practical scales (millions of snaps   */
/* + billions of inodes per dataset) these caps are unreachable; the gates  */
/* exist so a hypothetical pathological pool surfaces an error rather than  */
/* silently corrupting the encoding.                                         */
/*                                                                            */
/* Resolution: the fs.c layer recognizes synth inos at the top of each      */
/* public op, routes reads through throwaway-engine helpers against the     */
/* snapshot's captured (root_paddr, root_gen, root_csum) triple, and        */
/* refuses writes with STM_EROFS. v1.0 scope: lookup / stat / readdir /     */
/* readlink / INLINE read. EXTENT (regular-file) reads are deferred to     */
/* impl-5b. See docs/phase-9.7-design.md §8.                                 */
/* ========================================================================= */

#define FS_SYNTH_TAG          (1ULL << 63)
#define FS_SYNTH_INO_BITS     32u
#define FS_SYNTH_SNAP_BITS    31u
#define FS_SYNTH_INO_MASK     ((1ULL << FS_SYNTH_INO_BITS) - 1u)
#define FS_SYNTH_SNAP_MASK    ((1ULL << FS_SYNTH_SNAP_BITS) - 1u)
#define FS_SYNTH_SNAP_SHIFT   FS_SYNTH_INO_BITS

/* The SNAPS_PARENT sentinel — synth tag + snap_id=0 + frozen_ino=0.
 * Lookup at (dataset_root_ino, ".snaps") returns this; readdir on it
 * enumerates the dataset's PRESENT snaps. */
#define FS_SNAPS_PARENT_INO   FS_SYNTH_TAG

/* The literal ".snaps" name we recognize at every dataset root. The
 * length is 6; longer / shorter names with the same prefix fall through
 * to regular dirent lookup as ordinary file names. */
static const uint8_t FS_SNAPS_NAME[6] = { '.', 's', 'n', 'a', 'p', 's' };
#define FS_SNAPS_NAME_LEN     6u

static inline bool fs_ino_is_synth(uint64_t ino) {
    return (ino & FS_SYNTH_TAG) != 0u;
}

static inline bool fs_ino_is_snaps_parent(uint64_t ino) {
    return ino == FS_SNAPS_PARENT_INO;
}

static inline uint64_t fs_synth_snap_id(uint64_t ino) {
    return (ino >> FS_SYNTH_SNAP_SHIFT) & FS_SYNTH_SNAP_MASK;
}

static inline uint64_t fs_synth_frozen_ino(uint64_t ino) {
    return ino & FS_SYNTH_INO_MASK;
}

/* Encode a (snap_id, frozen_ino) pair as a synthetic inode. Refuses
 * STM_EOVERFLOW on saturation; refuses STM_EINVAL on the zero-snap
 * AND zero-ino case (which would collide with FS_SNAPS_PARENT_INO).
 * The bits-31..0 result fits in `*out_ino`. */
static inline stm_status fs_synth_encode(uint64_t snap_id, uint64_t frozen_ino,
                                            uint64_t *out_ino) {
    if (!out_ino) return STM_EINVAL;
    *out_ino = 0;
    if (snap_id == 0u || frozen_ino == 0u) return STM_EINVAL;
    if (snap_id > FS_SYNTH_SNAP_MASK) return STM_EOVERFLOW;
    if (frozen_ino > FS_SYNTH_INO_MASK) return STM_EOVERFLOW;
    *out_ino = FS_SYNTH_TAG | (snap_id << FS_SYNTH_SNAP_SHIFT) | frozen_ino;
    return STM_OK;
}

/* Predicate matching ".snaps" exactly. A lookup with this name at
 * (live) ino=1 of any dataset returns FS_SNAPS_PARENT_INO; at any
 * other parent ino, it falls through to regular dirent lookup (in
 * which case it would normally STM_ENOENT — ".snaps" isn't a stored
 * dirent). */
static inline bool fs_name_eq_snaps(const uint8_t *name, uint8_t name_len) {
    return name_len == FS_SNAPS_NAME_LEN
        && memcmp(name, FS_SNAPS_NAME, FS_SNAPS_NAME_LEN) == 0;
}

/* Synthesize a stat value for the SNAPS_PARENT directory: a synthetic
 * dir with mode 0555 (r-xr-xr-x), root-owned, size 0. Timestamps are
 * stamped from CLOCK_REALTIME so callers don't see all-zero times. */
static void fs_synth_stat_snaps_parent(struct stm_inode_value *out_iv) {
    memset(out_iv, 0, sizeof *out_iv);
    out_iv->si_ino        = stm_store_le64(FS_SNAPS_PARENT_INO);
    out_iv->si_dataset_id = stm_store_le64(0u);
    out_iv->si_gen        = stm_store_le64(0u);
    out_iv->si_mode       = stm_store_le32((uint32_t)S_IFDIR | 0555u);
    out_iv->si_uid        = stm_store_le32(0u);
    out_iv->si_gid        = stm_store_le32(0u);
    out_iv->si_nlink      = stm_store_le32(2u);     /* "." + ".." */
    /* Timestamps left zero (epoch) — synthetic dir has no meaningful
     * mtime/btime; callers presenting the dir via stat(2) get
     * 1970-01-01 which is the conventional "synthetic" marker. A
     * future v1.x could stamp these from CLOCK_REALTIME for a more
     * natural display; deferred since the value is non-load-bearing. */
    out_iv->si_size       = stm_store_le64(0u);
    out_iv->si_allocated  = stm_store_le64(0u);
    out_iv->si_data_kind  = STM_DATA_EXTENT;        /* nominal — synth dir */
    out_iv->si_data_len   = 0u;
}

/* Lookup a snapshot by id AND verify it belongs to `dataset_id`.
 * Mirrors `stm_snapshot_lookup` plus the dataset-membership check.
 * Returns STM_ENOENT on missing OR on dataset mismatch (defense-in-
 * depth — a caller passing the wrong dataset_id with a valid snap_id
 * shouldn't expose the snap's data). */
static stm_status fs_synth_snap_lookup(stm_fs *fs,
                                          uint64_t dataset_id,
                                          uint64_t snap_id,
                                          stm_snapshot_entry *out_entry) {
    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) return STM_EINVAL;
    stm_status s = stm_snapshot_lookup(sidx, snap_id, out_entry);
    if (s != STM_OK) return s;
    if (out_entry->dataset_id != dataset_id) return STM_ENOENT;
    return STM_OK;
}

/* Stat a SNAP_VIEW inode: look up the frozen-tree inode value at
 * (snap.tree_root_*, frozen_ino) via the throwaway-engine path.
 * Returns the 256-byte inode value verbatim (frozen mode bits / size /
 * times) — the read-only contract is enforced at write entry, not by
 * masking the displayed mode bits. */
static stm_status fs_snap_view_stat(stm_fs *fs,
                                       uint64_t dataset_id,
                                       uint64_t synth_ino,
                                       struct stm_inode_value *out_iv) {
    if (!fs_ino_is_synth(synth_ino)) return STM_EINVAL;
    if (fs_ino_is_snaps_parent(synth_ino)) {
        fs_synth_stat_snaps_parent(out_iv);
        return STM_OK;
    }
    uint64_t snap_id    = fs_synth_snap_id(synth_ino);
    uint64_t frozen_ino = fs_synth_frozen_ino(synth_ino);
    if (snap_id == 0u || frozen_ino == 0u) return STM_EINVAL;

    stm_snapshot_entry e;
    stm_status ss = fs_synth_snap_lookup(fs, dataset_id, snap_id, &e);
    if (ss != STM_OK) return ss;

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) return STM_EINVAL;
    return stm_inode_lookup_at_root(iidx, dataset_id,
                                       e.tree_root_paddr, e.root_gen,
                                       e.root_csum,
                                       frozen_ino, out_iv);
}

/* Lookup `name` under SNAPS_PARENT for `dataset_id`: walks the snap
 * index, finds the PRESENT snap whose `name` matches, returns its
 * synthetic root inode. Mirrors the regular `stm_fs_lookup` shape
 * (out_child_ino on success; STM_ENOENT on miss). */
typedef struct {
    uint64_t        dataset_id;
    const uint8_t  *name;
    uint8_t         name_len;
    uint64_t        out_snap_id;
    bool            found;
} fs_snap_by_name_ctx;

static bool fs_snap_by_name_cb(const stm_snapshot_entry *e, void *ctx_) {
    fs_snap_by_name_ctx *c = ctx_;
    if (e->dataset_id != c->dataset_id) return true;     /* keep iterating */
    if (e->name_len != (uint32_t)c->name_len) return true;
    if (memcmp(e->name, c->name, c->name_len) != 0) return true;
    c->out_snap_id = e->snapshot_id;
    c->found = true;
    return false;                                          /* stop iteration */
}

static stm_status fs_snaps_parent_lookup_by_name(stm_fs *fs,
                                                    uint64_t dataset_id,
                                                    const uint8_t *name,
                                                    uint8_t name_len,
                                                    uint64_t *out_synth_ino) {
    *out_synth_ino = 0;
    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) return STM_EINVAL;

    fs_snap_by_name_ctx c = {
        .dataset_id  = dataset_id,
        .name        = name,
        .name_len    = name_len,
        .out_snap_id = 0,
        .found       = false,
    };
    stm_status s = stm_snapshot_iter(sidx, fs_snap_by_name_cb, &c);
    if (s != STM_OK) return s;
    if (!c.found) return STM_ENOENT;

    /* Snap root ino = frozen_ino = 1 (the dataset root) inside the
     * captured tree. */
    return fs_synth_encode(c.out_snap_id, 1u, out_synth_ino);
}

/* Lookup `name` inside a SNAP_VIEW directory (synth_parent_ino with
 * snap_id>0 + frozen_ino>0). Routes the dirent walk to the frozen
 * tree via stm_dirent_lookup_at_root. The result is encoded back as
 * SNAP_VIEW(snap_id, child_frozen_ino). */
static stm_status fs_snap_view_lookup(stm_fs *fs,
                                         uint64_t dataset_id,
                                         uint64_t synth_parent_ino,
                                         const uint8_t *name,
                                         uint8_t name_len,
                                         uint64_t *out_synth_child_ino) {
    *out_synth_child_ino = 0;
    uint64_t snap_id    = fs_synth_snap_id(synth_parent_ino);
    uint64_t parent_frozen = fs_synth_frozen_ino(synth_parent_ino);
    if (snap_id == 0u || parent_frozen == 0u) return STM_EINVAL;

    stm_snapshot_entry e;
    stm_status ss = fs_synth_snap_lookup(fs, dataset_id, snap_id, &e);
    if (ss != STM_OK) return ss;

    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!didx) return STM_EINVAL;

    uint64_t child_frozen = 0;
    stm_status ls = stm_dirent_lookup_at_root(didx, dataset_id,
                                                 e.tree_root_paddr, e.root_gen,
                                                 e.root_csum,
                                                 parent_frozen,
                                                 name, name_len,
                                                 &child_frozen, NULL, NULL);
    if (ls != STM_OK) return ls;

    return fs_synth_encode(snap_id, child_frozen, out_synth_child_ino);
}

/* Readdir of the SNAPS_PARENT dir: list PRESENT snaps of `dataset_id`.
 * Cursor is the next snap_id to emit (ascending). Each entry's child_ino
 * is SNAP_VIEW(snap_id, 1); name is the snap's name; type is DT_DIR. */
typedef struct {
    uint64_t                 dataset_id;
    uint64_t                 cursor;       /* min snap_id to emit */
    stm_fs_dirent_entry     *out;
    size_t                   out_max;
    size_t                   out_n;
    uint64_t                 last_emit_id; /* for next cursor */
    stm_status               err;
} fs_snaps_readdir_ctx;

static bool fs_snaps_readdir_cb(const stm_snapshot_entry *e, void *ctx_) {
    fs_snaps_readdir_ctx *c = ctx_;
    if (e->dataset_id != c->dataset_id) return true;        /* keep iterating */
    if (e->snapshot_id < c->cursor) return true;
    if (c->out_n >= c->out_max) return false;               /* batch full */

    /* R71 P1-1 defense-in-depth: refuse anomalous frozen records. The
     * snap name decoder already enforces these (see snapshot.c
     * stm_snap_name_chars_valid), but a buggy refactor could let
     * a record slip through with bytes outside [0x20, 0x7E]. */
    if (e->name_len == 0u || e->name_len > STM_DIRENT_NAME_MAX) {
        c->err = STM_ECORRUPT;
        return false;
    }

    uint64_t synth = 0;
    stm_status es = fs_synth_encode(e->snapshot_id, /*frozen_ino=*/1u, &synth);
    if (es != STM_OK) {
        /* Saturation — snap_id >= 2^31. Skip this entry; the readdir
         * surfaces successful entries + the cursor saturates on the
         * highest emitted id. A future v1.x could expose an explicit
         * "snap unavailable in .snaps namespace" error to callers. */
        return true;
    }

    stm_fs_dirent_entry *o = &c->out[c->out_n];
    memset(o, 0, sizeof *o);
    o->child_ino  = synth;
    o->child_gen  = 0u;          /* synth */
    o->child_type = STM_DT_DIR;
    o->name_len   = (uint8_t)e->name_len;
    memcpy(o->name, e->name, e->name_len);
    c->out_n++;
    c->last_emit_id = e->snapshot_id;
    return true;
}

static stm_status fs_snaps_parent_readdir(stm_fs *fs,
                                             uint64_t dataset_id,
                                             uint64_t *cursor,
                                             stm_fs_dirent_entry *out_entries,
                                             size_t max_entries,
                                             size_t *out_returned) {
    *out_returned = 0;
    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) return STM_EINVAL;

    fs_snaps_readdir_ctx c = {
        .dataset_id   = dataset_id,
        .cursor       = *cursor,
        .out          = out_entries,
        .out_max      = max_entries,
        .out_n        = 0,
        .last_emit_id = 0,
        .err          = STM_OK,
    };
    stm_status s = stm_snapshot_iter(sidx, fs_snaps_readdir_cb, &c);
    if (s != STM_OK) return s;
    if (c.err != STM_OK) return c.err;

    *out_returned = c.out_n;
    if (c.out_n > 0u) {
        /* Advance cursor past the last emitted id; saturate at UINT64_MAX
         * so callers can detect end-of-iteration via the same sentinel
         * the live readdir uses. */
        *cursor = (c.last_emit_id == UINT64_MAX)
                     ? UINT64_MAX
                     : (c.last_emit_id + 1u);
    }
    /* On empty batch we leave *cursor unchanged; the live readdir does
     * the same (returns STM_OK with out_returned=0 to signal done). */
    return STM_OK;
}

/* Readdir of a SNAP_VIEW dir: route the dirent_readdir to the frozen
 * tree, translate each child_ino → SNAP_VIEW(snap_id, child_frozen_ino).
 * The cursor + max_entries semantics carry verbatim from
 * stm_dirent_readdir_at_root. */
static stm_status fs_snap_view_readdir(stm_fs *fs,
                                          uint64_t dataset_id,
                                          uint64_t synth_dir_ino,
                                          uint64_t *cursor,
                                          stm_fs_dirent_entry *out_entries,
                                          size_t max_entries,
                                          size_t *out_returned) {
    *out_returned = 0;
    uint64_t snap_id     = fs_synth_snap_id(synth_dir_ino);
    uint64_t dir_frozen  = fs_synth_frozen_ino(synth_dir_ino);
    if (snap_id == 0u || dir_frozen == 0u) return STM_EINVAL;

    stm_snapshot_entry e;
    stm_status ss = fs_synth_snap_lookup(fs, dataset_id, snap_id, &e);
    if (ss != STM_OK) return ss;

    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!didx) return STM_EINVAL;

    /* Borrow the caller's batch buffer for the underlying readdir,
     * then translate child_ino in place + copy into the fs_layer
     * dirent shape. */
    if (max_entries > SIZE_MAX / sizeof(stm_dirent_entry)) return STM_ENOMEM;
    stm_dirent_entry *batch = malloc(max_entries * sizeof *batch);
    if (!batch) return STM_ENOMEM;

    size_t got = 0;
    stm_status rs = stm_dirent_readdir_at_root(didx, dataset_id,
                                                  e.tree_root_paddr, e.root_gen,
                                                  e.root_csum,
                                                  dir_frozen, cursor,
                                                  batch, max_entries, &got);
    if (rs != STM_OK) {
        free(batch);
        return rs;
    }

    for (size_t k = 0; k < got; k++) {
        if (batch[k].name_len > STM_DIRENT_NAME_MAX) {
            free(batch);
            return STM_ECORRUPT;
        }
        uint64_t synth_child = 0;
        stm_status es = fs_synth_encode(snap_id, batch[k].child_ino,
                                            &synth_child);
        if (es != STM_OK) {
            /* Saturation — frozen_ino >= 2^32. Skip this entry. */
            continue;
        }
        stm_fs_dirent_entry *o = &out_entries[*out_returned];
        memset(o, 0, sizeof *o);
        o->child_ino  = synth_child;
        o->child_gen  = 0u;       /* not exposed for snap-view */
        o->child_type = batch[k].child_type;
        o->name_len   = batch[k].name_len;
        memcpy(o->name, batch[k].name, batch[k].name_len);
        (*out_returned)++;
    }
    free(batch);
    return STM_OK;
}

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

stm_status stm_fs_format(const char *path, stm_fs_format_opts *opts)
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

    /* TLY-A1: bind the pool_serial BEFORE the first commit so it
     * lands in the initial uberblock. If caller passed all-zero (or
     * zero-init'd opts), CSPRNG-generate 16 bytes AND write them back
     * into `opts->pool_serial` so the caller can read the bound
     * value (the Thylacine-installer flow per §3.5 of the API spec).
     * Caller's explicit non-zero value passes through unchanged.
     *
     * R137 P2-3 close: `opts` is now non-const at the signature so
     * the write-back is documented in the type system. */
    {
        bool all_zero = true;
        for (int i = 0; i < 16; i++) {
            if (opts->pool_serial[i] != 0) { all_zero = false; break; }
        }
        if (all_zero) {
            stm_random_bytes(opts->pool_serial, 16);
        }
        stm_sync_set_pool_serial(sync, opts->pool_serial);
    }

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
static bool fs_post_inode_free_reclaim_locked(stm_fs *fs);

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
    /* 9.8-LF-3: atomic init at fs allocation (single-threaded — no race
     * with the wait-free readers, which never see fs until fs_new returns). */
    atomic_init(&fs->read_only, ro);
    atomic_init(&fs->wedged, false);
    return fs;
}

stm_status stm_fs_mount(const char *path,
                         const stm_fs_mount_opts *opts,
                         stm_fs **out_fs)
{
    if (!path || !opts || !out_fs) return STM_EINVAL;

    /* 9.8-LF-3: ensure EBR substrate is initialised before any code path
     * that might enter an epoch. Idempotent — safe to call on every mount.
     * The first mount after process start does the real init; subsequent
     * mounts are a noop. */
    stm_status ers = stm_ebr_init();
    if (ers != STM_OK) return ers;

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

    /* TLY-A1: pool_serial binding check, before any further state
     * touches. STRATUM-API-V1.md §3.3 comparison matrix:
     *   - opts->expected_pool_serial == NULL:
     *       mount succeeds regardless of on-disk value (caller did
     *       not ask for binding).
     *   - both on-disk and expected all-zero:
     *       mount succeeds (legitimate unbound pool, caller passed
     *       all-zero — vacuously satisfied).
     *   - on-disk all-zero, expected non-zero:
     *       STM_ESERIAL (don't silently mount an unbound pool when
     *       binding was requested — the spec's explicit guarantee).
     *   - both non-zero, equal:
     *       mount succeeds.
     *   - both non-zero, unequal:
     *       STM_ESERIAL.
     *
     * Constant-time compare via stm_ct_memequal would be overkill —
     * this isn't a secret; the attacker model is "tampered device,"
     * not "side-channel on a running process." memcmp is fine. */
    if (opts->expected_pool_serial) {
        const uint8_t *exp = opts->expected_pool_serial;
        bool exp_zero  = true;
        bool disk_zero = true;
        for (int i = 0; i < 16; i++) {
            if (exp[i] != 0)                   exp_zero = false;
            if (peek_ub.ub_pool_serial[i] != 0) disk_zero = false;
        }
        bool refused = false;
        if (disk_zero && !exp_zero) {
            /* "on-disk all-zero but arg non-zero: mount fails with
             * STM_ESERIAL (don't silently mount an unbound pool
             * when binding was requested)" — §3.3 of the API spec. */
            refused = true;
        } else if (!disk_zero && !exp_zero) {
            if (memcmp(peek_ub.ub_pool_serial, exp, 16) != 0) {
                refused = true;
            }
        }
        /* (disk_zero && exp_zero) and (!disk_zero && exp_zero) both
         * succeed: the first is "unbound pool, caller didn't bind"
         * (vacuous OK); the second is "bound pool, caller didn't ask
         * to check" — but we got here via expected_pool_serial != NULL,
         * so we DO want to check. The all-zero arg case has to mean
         * something explicit. The spec's row "all-zero arg vs bound
         * pool: STM_ESERIAL" makes this concrete — caller's all-zero
         * is NOT a wildcard. */
        if (!disk_zero && exp_zero) {
            refused = true;
        }
        if (refused) {
            stm_bdev_close(d);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return STM_ESERIAL;
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

    /* TLY-A3-keyslot: load the corvus session token (if configured)
     * into an mlock'd buffer for the mount-time unwrap of any
     * CORVUS-tagged keyschema slot. corvus is configured iff a token
     * file was given; the socket path defaults inside the corvus
     * client when NULL. */
    uint8_t *corvus_token = NULL;
    stm_corvus_mount_cfg corvus_cfg = {0};
    const stm_corvus_mount_cfg *corvus_cfg_p = NULL;
    if (opts->corvus_session_token_file) {
        /* R145 P2-1: the corvus session token is a bearer credential —
         * anyone who can read the file can unwrap every per-dataset
         * DEK over corvus. Refuse a token file that is not a regular
         * file owned by the caller with no group/other access bits
         * (0400/0600 posture). `stm_corvus_load_token` explicitly
         * defers this check to its caller; mirrors the `.key`
         * second-factor + SO_PEERCRED fail-closed doctrine. */
        struct stat tok_st;
        if (stat(opts->corvus_session_token_file, &tok_st) != 0) {
            stm_alloc_close(a);
            stm_pool_close(pool);
            stm_bdev_close(d);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return STM_ENOENT;
        }
        if (!S_ISREG(tok_st.st_mode) ||
            tok_st.st_uid != geteuid() ||
            (tok_st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
            stm_alloc_close(a);
            stm_pool_close(pool);
            stm_bdev_close(d);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return STM_EACCES;
        }
        corvus_token = malloc(STM_CORVUS_TOKEN_LEN);
        if (!corvus_token) {
            stm_alloc_close(a);
            stm_pool_close(pool);
            stm_bdev_close(d);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return STM_ENOMEM;
        }
        (void)mlock(corvus_token, STM_CORVUS_TOKEN_LEN);
        stm_status ts = stm_corvus_load_token(opts->corvus_session_token_file,
                                                corvus_token);
        if (ts != STM_OK) {
            stm_ct_memzero(corvus_token, STM_CORVUS_TOKEN_LEN);
            (void)munlock(corvus_token, STM_CORVUS_TOKEN_LEN);
            free(corvus_token);
            stm_alloc_close(a);
            stm_pool_close(pool);
            stm_bdev_close(d);
            stm_hybrid_keys_wipe(&wk);
            if (janus) stm_janus_client_disconnect(janus);
            return ts;
        }
        corvus_cfg.socket_path   = opts->corvus_socket;
        corvus_cfg.session_token = corvus_token;
        /* Timeouts 0 → the corvus client substitutes its
         * production-safe defaults (R144 P2-1); n_retries 3 is the
         * full Q9 backoff schedule [100, 500, 2000] ms. */
        corvus_cfg.n_retries = 3;
        corvus_cfg_p = &corvus_cfg;
    }

    stm_sync *sync = NULL;
    s = stm_sync_open(pool, a,
                        have_kf ? &wk : NULL,
                        have_jn ? janus : NULL,
                        corvus_cfg_p,
                        &sync);
    /* The session token is needed only for the mount-time unwrap;
     * the resulting DEKs now live in the sync DEK map (zeroed at
     * unmount via sync_dek_wipe_all). Scrub + release the token
     * regardless of outcome — it is not retained past mount. */
    if (corvus_token) {
        stm_ct_memzero(corvus_token, STM_CORVUS_TOKEN_LEN);
        (void)munlock(corvus_token, STM_CORVUS_TOKEN_LEN);
        free(corvus_token);
        corvus_token = NULL;
    }
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

    /* 9.7-impl-6e: clone_check_cb wiring is ALREADY done by
     * stm_sync_open + stm_sync_create (sync.c::sync_clone_check_cb).
     * No fs.c install needed — the snapshot index in fs->sync already
     * has the cb bound to fs->sync's dataset_idx by the time we
     * return here. The design's "fs.c installs a callback at mount"
     * note (§9.1.5) was historical drift; sync.c got there first at
     * P6-clone time. clone.tla::SnapWithClonesUndeletable enforcement
     * is therefore live at mount with no impl-6e wiring required. */

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
    /* 9.8-LF-3: read under fs->global EX; relaxed is sufficient (no
     * reader-thread synchronisation needed — the EX excludes everything
     * but ourselves). Acquire-load works too, just unnecessary. */
    if (!atomic_load_explicit(&fs->read_only, memory_order_relaxed) &&
        !atomic_load_explicit(&fs->wedged, memory_order_relaxed)) {
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
    /* R154 P2-1: a failed stm_sync_commit is crash-equivalent — the
     * inode engine's three-phase abort dropped the in-memory tree
     * (9.6-impl-4b design §5.5). Wedge so a retry (fsync IS retryable;
     * the 9P Tfsync / Tsync handlers + /ctl/'s seal-bit commit re-issue
     * it) is refused with STM_EWEDGED instead of silently committing
     * the reverted-to-previous-durable inode tree. Deferred past the
     * unlock — stm_fs_mark_wedged itself takes fs->global (fs.c:31).
     * The fs_flush_all_locked failure above is deliberately NOT wedged:
     * it leaves the dirty buffer intact for retry — only the inode-
     * engine abort makes a failure unrecoverable. */
    bool should_wedge = (s != STM_OK);
    pthread_rwlock_unlock(&fs->global);
    if (should_wedge) stm_fs_mark_wedged(fs);
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

/* Read-side counterpart to fs_write_extent_aligned_locked: the extent layer
 * requires the read offset to be 4 KiB-aligned (stm_sync_read_extent rejects
 * (off % STM_UB_SIZE != 0) with STM_EINVAL). A client reading at a non-aligned
 * offset -- e.g. the 2nd chunk of a multi-chunk 9P Tread, which starts at 2048
 * -- would otherwise fail. Align the offset down, read the covering aligned
 * span into scratch, and copy out the caller's [off, off+len) slice. `len`
 * need not be aligned (the extent layer only constrains the offset). Returns
 * the number of real bytes copied in *out_read (the caller clamps to EOF).
 * Caller holds fs->lock. */
static stm_status fs_read_extent_aligned_locked(stm_fs *fs,
                                                     uint64_t ds, uint64_t ino,
                                                     uint64_t off,
                                                     void *buf, size_t len,
                                                     size_t *out_read)
{
    if (out_read) *out_read = 0;
    if (len == 0u) return STM_OK;
    const uint64_t BLK = 4096u;
    if (off % BLK == 0u) {
        return stm_sync_read_extent(fs->sync, ds, ino, off, buf, len, out_read);
    }
    uint64_t aligned_off = off & ~(BLK - 1u);
    uint64_t end_off     = off + (uint64_t)len;
    uint64_t aligned_end = (end_off + BLK - 1u) & ~(BLK - 1u);
    /* Bound the scratch allocation, symmetric to fs_write_extent_aligned_locked.
     * Unreachable via 9P (h_read clamps count to iounit_for_msize before
     * stm_fs_read), but a future direct caller passing a huge non-aligned len
     * would otherwise attempt an unbounded calloc. */
    if (aligned_end > (uint64_t)STM_FS_RECORDSIZE_MAX + aligned_off) {
        return STM_ERANGE;
    }
    uint64_t aligned_len = aligned_end - aligned_off;
    uint8_t *scratch = (uint8_t *)calloc(1, (size_t)aligned_len);
    if (!scratch) return STM_ENOMEM;
    size_t got = 0;
    stm_status rs = stm_sync_read_extent(fs->sync, ds, ino, aligned_off,
                                               scratch, (size_t)aligned_len, &got);
    if (rs != STM_OK && rs != STM_ENOENT) { free(scratch); return rs; }
    uint64_t skip   = off - aligned_off;
    size_t   avail  = (got > skip) ? (size_t)(got - skip) : 0u;
    size_t   copy_n = (len < avail) ? len : avail;
    if (copy_n > 0u) memcpy(buf, scratch + skip, copy_n);
    free(scratch);
    if (out_read) *out_read = copy_n;
    return STM_OK;
}

/* SWISS-4q-flush drain callback: each buffered range becomes one
 * stm_sync_write_extent via fs_write_extent_aligned_locked. The
 * callback runs under stm_dirty_buffer's internal mutex AND under
 * the caller's outer fs lock context. Post-PARALLEL-3 impl-5 the
 * outer can be either fs->global EX (pre-impl-1 ops; commit / sync
 * paths) OR fs->global SH + per-inode pin (impl-1..5 ports —
 * truncate/fallocate/migrate/promote/write call this UNDER the
 * target inode's pin). The aligned helper takes sync->lock
 * internally; lock order fs->global → per-inode-mutex → dbuf->mu
 * → sync->lock holds. See header doctrine block lines 23-39. */
static stm_status fs_flush_drain_cb(void *user, uint64_t ds, uint64_t ino,
                                        uint64_t off, uint64_t len,
                                        const void *data)
{
    stm_fs *fs = (stm_fs *)user;
    return fs_write_extent_aligned_locked(fs, ds, ino, off, data, (size_t)len);
}

/* Flush one inode's buffered ranges. Caller holds the outer fs lock
 * (fs->global EX, or fs->global SH + this (ds,ino)'s pin per impl-1..5
 * doctrine). */
static stm_status fs_flush_ino_locked(stm_fs *fs, uint64_t ds, uint64_t ino)
{
    return stm_dirty_buffer_drain_ino(fs->dirty_buffer, ds, ino,
                                            fs_flush_drain_cb, fs);
}

/* Flush every inode's buffered ranges. Caller holds fs->global
 * (EX or SH; SH callers do NOT need to pin every inode — dbuf->mu
 * serializes the drain itself, and the drained extents land at the
 * sync layer's own mutex). */
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
            stm_status rs = fs_read_extent_aligned_locked(fs, ds, ino, off,
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
        stm_status rs = fs_read_extent_aligned_locked(fs, ds, ino, off,
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

    /* 9.7-impl-5: write to a snap-view inode is structurally forbidden. */
    if (fs_ino_is_synth(ino)) return STM_EROFS;

    /* P9.5-PARALLEL-3 impl-5: SH (rdlock) + per-inode pin happy path
     * for regular files in the inode index. Falls back to EX (wrlock —
     * pre-impl-5 posture) on STM_ENOENT from pin OR on non-regular
     * inodes so legacy direct-extent callers (older tests + dataset
     * metadata test seam) and non-S_IFREG inode kinds keep going
     * through the unbuffered stm_sync_write_extent path verbatim. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (iidx) {
        stm_inode_handle *h = NULL;
        stm_status pp = stm_inode_pin(iidx, dataset_id, ino, &h);
        if (pp == STM_OK) {
            struct stm_inode_value iv = {0};
            stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
            if (ls == STM_OK) {
                uint32_t mode = stm_load_le32(iv.si_mode);
                if ((mode & (uint32_t)S_IFMT) == (uint32_t)S_IFREG) {
                    stm_status rs = fs_write_regular_locked(fs, iidx,
                                                                  dataset_id, ino,
                                                                  &iv, off, buf, len);
                    stm_inode_unpin(iidx, h);
                    pthread_rwlock_unlock(&fs->global);
                    return rs;
                }
                /* Not a regular file — drop SH and fall through to EX. */
            }
            stm_inode_unpin(iidx, h);
        } else if (pp != STM_ENOENT) {
            pthread_rwlock_unlock(&fs->global);
            return pp;
        }
        /* STM_ENOENT or non-S_IFREG — fall through to legacy EX path. */
    }
    /* Legacy direct-extent / non-regular fallback: release SH and
     * reacquire EX so concurrent unported writers still serialize.
     * Same shape as impl-4 reflink/cfr. */
    pthread_rwlock_unlock(&fs->global);
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
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
     * R57 P3-5 / R58 P3-1 uniform out-param contract. */
    if (out_read) *out_read = 0;
    if (!fs) return STM_EINVAL;

    /* 9.8-LF-3 port (split-branch):
     *   - synth-ino reads stay on fs->global SH (throwaway-engine
     *     surface; impl-5/5b infrastructure).
     *   - Live-tree INLINE read goes wait-free via EBR + concurrent
     *     inode lookup — pure inode-value read, no extent/sync I/O.
     *   - Live-tree EXTENT read stays on fs->global SH; the path
     *     composes with writer-side SH+pin (PARALLEL-3 impl-5) +
     *     stm_sync_read_extent's internal s->lock + dirty_buffer
     *     overlay. Retiring SH here needs same-inode reader-pin to
     *     exclude truncate/write mid-read — forward-noted to LF-3
     *     followup or 9.8-BE-fs.c. */
    if (fs_ino_is_synth(ino)) {
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);

        if (fs_ino_is_snaps_parent(ino)) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EISDIR;
        }
        uint64_t snap_id    = fs_synth_snap_id(ino);
        uint64_t frozen_ino = fs_synth_frozen_ino(ino);
        if (snap_id == 0u || frozen_ino == 0u) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        stm_snapshot_entry e;
        stm_status ss = fs_synth_snap_lookup(fs, dataset_id, snap_id, &e);
        if (ss != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ss;
        }
        stm_inode_index *snap_iidx = stm_sync_inode_index(fs->sync);
        if (!snap_iidx) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        struct stm_inode_value iv = {0};
        stm_status is = stm_inode_lookup_at_root(snap_iidx, dataset_id,
                                                    e.tree_root_paddr,
                                                    e.root_gen, e.root_csum,
                                                    frozen_ino, &iv);
        if (is != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return is;
        }
        uint32_t smode = stm_load_le32(iv.si_mode);
        if ((smode & (uint32_t)S_IFMT) == (uint32_t)S_IFDIR) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EISDIR;
        }
        if ((smode & (uint32_t)S_IFMT) != (uint32_t)S_IFREG) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        uint64_t cur_size = stm_load_le64(iv.si_size);
        if (off >= cur_size) {
            pthread_rwlock_unlock(&fs->global);
            return STM_OK;
        }
        if (iv.si_data_kind == STM_DATA_INLINE) {
            if (iv.si_data_len > STM_INODE_INLINE_MAX) {
                pthread_rwlock_unlock(&fs->global);
                return STM_ECORRUPT;
            }
            size_t avail = (size_t)(cur_size - off);
            size_t copy_n = (len < avail) ? len : avail;
            if (copy_n > 0u && buf) {
                memcpy(buf, iv.si_data.inline_data + off, copy_n);
            }
            if (out_read) *out_read = copy_n;
            pthread_rwlock_unlock(&fs->global);
            return STM_OK;
        }
        if (iv.si_data_kind == STM_DATA_EXTENT) {
            size_t got = 0;
            stm_status rs = stm_sync_read_extent_at_snap(
                    fs->sync, dataset_id,
                    e.tree_root_paddr, e.root_gen, e.root_csum,
                    frozen_ino, off, buf, len, &got);
            if (rs == STM_OK) {
                uint64_t logical_avail = cur_size - off;
                if ((uint64_t)got > logical_avail) {
                    got = (size_t)logical_avail;
                }
                if (out_read) *out_read = got;
            }
            pthread_rwlock_unlock(&fs->global);
            return rs;
        }
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Live-tree branch. Probe via EBR + concurrent inode lookup; if
     * inode is INLINE-mode S_IFREG, serve from inode-value bytes
     * directly (wait-free). All other paths (EXTENT, non-REG, missing
     * from iidx) fall through to the SH-rdlock path. */
    {
        stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
        if (iidx) {
            FS_GUARD_READ_LOCKLESS(fs);

            stm_ebr_thread *ebr = fs_ebr_thread_current();
            if (!ebr) return STM_ENOMEM;
            stm_ebr_enter(ebr);

            struct stm_inode_value iv = {0};
            stm_status ls = stm_inode_lookup_concurrent(iidx, ebr,
                                                          dataset_id, ino, &iv);
            if (ls == STM_OK) {
                uint32_t mode = stm_load_le32(iv.si_mode);
                if ((mode & (uint32_t)S_IFMT) == (uint32_t)S_IFREG
                    && iv.si_data_kind == STM_DATA_INLINE) {
                    /* INLINE wait-free serve. R171 P2-6: a torn-state
                     * si_data_len > MAX read can come from a concurrent
                     * writer mid-stm_inode_set. Fall back to the SH
                     * path rather than propagating a spurious
                     * STM_ECORRUPT — the serial path re-reads under the
                     * idx mutex and either confirms or refutes the
                     * torn-state observation.
                     *
                     * R172 P1-2 / P2-5: ALSO check cur_size <=
                     * STM_INODE_INLINE_MAX. A torn read where bytes pass
                     * in_validate_value with (kind=INLINE,
                     * si_data_len <= 100, si_size > 100) — theoretically
                     * reachable via the R171 P0-1 UAF window if freed-
                     * buffer bytes happen to mix a current INLINE
                     * lifetime's small data_len with a prior EXTENT
                     * lifetime's large si_size — would otherwise memcpy
                     * (cur_size - off) bytes past the 100-byte
                     * inline_data[] array end into adjacent stack memory
                     * (an OOB-stack-read leaking caller-buffer-visible
                     * bytes). Gate the memcpy on BOTH bounds. */
                    uint64_t cur_size = stm_load_le64(iv.si_size);
                    if (iv.si_data_len <= STM_INODE_INLINE_MAX
                        && cur_size <= (uint64_t)STM_INODE_INLINE_MAX) {
                        if (off >= cur_size) {
                            stm_ebr_exit(ebr);
                            return STM_OK;
                        }
                        size_t avail = (size_t)(cur_size - off);
                        size_t copy_n = (len < avail) ? len : avail;
                        if (copy_n > 0u && buf) {
                            memcpy(buf, iv.si_data.inline_data + off, copy_n);
                        }
                        if (out_read) *out_read = copy_n;
                        stm_ebr_exit(ebr);
                        return STM_OK;
                    }
                    /* torn data_len > MAX OR torn si_size > MAX → fall
                     * through to SH path. R172 P1-2 closure. */
                }
            }
            stm_ebr_exit(ebr);
            /* Fall through to SH path for EXTENT / non-REG / missing /
             * R171 P2-6 torn-state. */
        }
    }

    /* EXTENT branch (and legacy direct-extent fallback): SH-rdlock +
     * stm_sync_read_extent composes with writer-side per-inode pin. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_READ(fs);

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

/* 9.8-LF-3b: EBR-pinned variant of fs_load_parent_dir for ports that
 * drop fs->global SH. Same return shape as the serial helper; the
 * caller is responsible for the EBR enter/exit bracket. */
static stm_status fs_load_parent_dir_concurrent(stm_inode_index *iidx,
                                                   stm_ebr_thread *ebr,
                                                   uint64_t dataset_id,
                                                   uint64_t parent_ino,
                                                   struct stm_inode_value *out_pv)
{
    stm_status ps = stm_inode_lookup_concurrent(iidx, ebr, dataset_id,
                                                  parent_ino, out_pv);
    if (ps != STM_OK) return ps;
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

    /* 9.8-LF-3c: synth branches use throwaway engines + snapshot index
     * (still need fs->global SH); live-tree branch is wait-free via
     * EBR-pinned concurrent lookups.
     *
     * 9.7-impl-5 .snaps namespace cases (unchanged shape, routed lock
     * choice):
     * 1. Lookup of ".snaps" at the LIVE dataset-root inode (=1) returns
     *    the synthetic SNAPS_PARENT sentinel. R166 P2-4: verify the
     *    parent ino=1 actually exists as a directory in `dataset_id`
     *    before returning the sentinel — matches the "parent must be a
     *    dir" contract; refuses a "phantom .snaps" surface on uninit'd
     *    datasets.
     * 2. Lookup under SNAPS_PARENT resolves a snap name to the
     *    SNAP_VIEW root inode (snap_id, frozen_ino=1).
     * 3. Lookup under a SNAP_VIEW inode routes through the snapshot's
     *    frozen tree via stm_dirent_lookup_at_root. */
    if (parent_ino == 1u && fs_name_eq_snaps(name, name_len)) {
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        stm_inode_index *iidx_chk = stm_sync_inode_index(fs->sync);
        if (!iidx_chk) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        struct stm_inode_value pv = {0};
        stm_status pcs = fs_load_parent_dir(iidx_chk, dataset_id, 1u, &pv);
        if (pcs != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return pcs;     /* STM_ENOENT for uninit'd dataset / freed root */
        }
        *out_child_ino = FS_SNAPS_PARENT_INO;
        pthread_rwlock_unlock(&fs->global);
        return STM_OK;
    }
    if (fs_ino_is_snaps_parent(parent_ino)) {
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        stm_status s = fs_snaps_parent_lookup_by_name(fs, dataset_id,
                                                          name, name_len,
                                                          out_child_ino);
        pthread_rwlock_unlock(&fs->global);
        return s;
    }
    if (fs_ino_is_synth(parent_ino)) {
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        stm_status s = fs_snap_view_lookup(fs, dataset_id, parent_ino,
                                              name, name_len,
                                              out_child_ino);
        pthread_rwlock_unlock(&fs->global);
        return s;
    }

    /* Live-tree fast path — wait-free EBR. */
    FS_GUARD_READ_LOCKLESS(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;

    struct stm_inode_value pv = {0};
    stm_ebr_enter(ebr);
    stm_status ps = stm_inode_lookup_concurrent(iidx, ebr, dataset_id,
                                                   parent_ino, &pv);
    if (ps == STM_OK) {
        uint32_t pmode = stm_load_le32(pv.si_mode);
        if ((pmode & (uint32_t)S_IFMT) != (uint32_t)S_IFDIR) {
            stm_ebr_exit(ebr);
            return STM_ENOTDIR;
        }
    } else if (ps != STM_ECORRUPT) {
        stm_ebr_exit(ebr);
        return ps;
    } else {
        /* fall through to SH-fallback below */
        stm_ebr_exit(ebr);
        goto lookup_fallback;
    }

    uint64_t child_ino = 0;
    stm_status ds = stm_dirent_lookup_concurrent(didx, ebr, dataset_id,
                                                     parent_ino,
                                                     name, name_len,
                                                     &child_ino, NULL, NULL);
    stm_ebr_exit(ebr);
    if (ds == STM_OK) {
        *out_child_ino = child_ino;
        return STM_OK;
    }
    if (ds != STM_ECORRUPT) return ds;

    /* R171 P1-1 SH-fallback. See stm_fs_stat for rationale. */
lookup_fallback:
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_READ(fs);
    iidx = stm_sync_inode_index(fs->sync);
    didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    {
        struct stm_inode_value pv2 = {0};
        stm_status ps2 = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv2);
        if (ps2 != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ps2;
        }
        uint64_t ci = 0;
        stm_status ds2 = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                              name, name_len,
                                              &ci, NULL, NULL);
        pthread_rwlock_unlock(&fs->global);
        if (ds2 == STM_OK) *out_child_ino = ci;
        return ds2;
    }
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
    if (fs_ino_is_synth(parent_ino)) return STM_EROFS;  /* 9.7-impl-5 */
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
    /* 9.7-impl-5: refuse if either target is a snap-view inode. */
    if (fs_ino_is_synth(ino) || fs_ino_is_synth(parent_ino)) return STM_EROFS;
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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */

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
    bool needs_wedge = false;
    if (cleanup_did_truncate && fs_free == STM_OK) {
        needs_wedge = fs_post_inode_free_reclaim_locked(fs);
    }

    stm_inode_unpin(iidx, h);
    pthread_rwlock_unlock(&fs->global);
    /* R154 P1-1: a failed reclaim commit is crash-equivalent — wedge
     * AFTER the unlock (stm_fs_mark_wedged takes fs->global; fs.c:31). */
    if (needs_wedge) stm_fs_mark_wedged(fs);
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
    if (fs_ino_is_synth(parent_ino)) return STM_EROFS;  /* 9.7-impl-5 */
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
 * than predicate). Caller MUST hold fs->global. Same posture as the
 * inline double-commit at the original unlink path's reclaim trigger
 * (SWISS-4q P2). Extracted so rename + unlink_anon can reuse it.
 *
 * Cost: two stm_sync_commit calls (~10-50 ms each on local NVMe).
 * Acceptable; the alternative is permanent PENDING leak per cycle.
 *
 * R154 P1-1: returns `true` if the fs MUST be wedged. 9.6-impl-4b-ii
 * made the inode engine's commit-abort drop the in-memory tree, so a
 * failed stm_sync_commit is crash-equivalent (4b design §5.5) — it
 * can no longer be retried in-process. The pre-4b code issued the
 * second commit UNCONDITIONALLY; if the first failed (aborting the
 * inode flush — the engine reverts to its previous durable root),
 * that retry would re-commit a tree in which the just-FREED inode is
 * ALLOCATED again while its extents are already reclaimed — corruption
 * / an unmountable pool. So: on the first commit's failure, STOP — do
 * NOT issue the retry — and signal the caller to wedge. A failed
 * second commit also wedges (any failed stm_sync_commit is crash-
 * equivalent per §5.5). The caller fires stm_fs_mark_wedged AFTER its
 * own pthread_rwlock_unlock — the fs.c:31 deferred-wedge doctrine,
 * since stm_fs_mark_wedged itself takes fs->global.
 */
static bool fs_post_inode_free_reclaim_locked(stm_fs *fs)
{
    if (stm_sync_commit(fs->sync) != STM_OK) return true;
    if (stm_sync_commit(fs->sync) != STM_OK) return true;
    return false;
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
    bool needs_wedge = false;
    if (freed && cleanup_did_truncate) {
        needs_wedge = fs_post_inode_free_reclaim_locked(fs);
    }

    stm_inode_unpin(iidx, h_parent);
    stm_inode_unpin(iidx, h_child);
    pthread_rwlock_unlock(&fs->global);
    /* R154 P1-1: a failed reclaim commit is crash-equivalent — wedge
     * AFTER the unlock (stm_fs_mark_wedged takes fs->global; fs.c:31). */
    if (needs_wedge) stm_fs_mark_wedged(fs);
    return STM_OK;
}

stm_status stm_fs_unlink(stm_fs *fs, uint64_t dataset_id,
                            uint64_t parent_ino,
                            const uint8_t *name, uint8_t name_len)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0u || parent_ino == 0u) return STM_EINVAL;
    if (fs_ino_is_synth(parent_ino)) return STM_EROFS;  /* 9.7-impl-5 */
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
    if (fs_ino_is_synth(parent_ino)) return STM_EROFS;  /* 9.7-impl-5 */
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

    /* 9.8-LF-3: wait-free read path. Atomic wedge check + EBR pin
     * around the engine descent. NO fs->global SH acquire. The 9.7-impl-5
     * synth-ino branch goes through fs_snap_view_stat which uses a
     * throwaway engine — that path still takes fs->global SH internally
     * (deferred to a follow-on LF-3 chunk; synth-ino reads are rare). */
    FS_GUARD_READ_LOCKLESS(fs);

    if (fs_ino_is_synth(ino)) {
        /* Throwaway-engine path. v1.0 keeps the rwlock path for this
         * branch; lift to EBR at LF-3 follow-on. */
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        stm_status s = fs_snap_view_stat(fs, dataset_id, ino, out_value);
        pthread_rwlock_unlock(&fs->global);
        return s;
    }

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;
    stm_ebr_enter(ebr);
    stm_status s = stm_inode_lookup_concurrent(iidx, ebr, dataset_id, ino,
                                                out_value);
    stm_ebr_exit(ebr);
    if (s != STM_ECORRUPT) return s;

    /* R171 P1-1 SH-fallback. A wait-free reader can observe a torn
     * inode-value decode (in_validate_value → STM_ECORRUPT) when a
     * concurrent writer is mid-stm_inode_set on the same record. The
     * underlying disk state is NOT corrupt; only the wait-free read
     * was torn. Re-read under fs->global SH so the writer's serial
     * idx-mutex excludes us from the torn window. The fallback turns
     * a transient STM_ECORRUPT into a coherent answer at the cost of
     * one round-trip on the slow path. BE-prepend (#1218) closes the
     * underlying race; this fallback becomes a no-op once it lands. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_READ(fs);
    iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    s = stm_inode_lookup(iidx, dataset_id, ino, out_value);
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

    /* 9.7-impl-5: snap-view inodes are read-only. */
    if (fs_ino_is_synth(ino)) return STM_EROFS;

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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */

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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */
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
    /* 9.7-impl-5: any synth ino in src/dst → EROFS. */
    if (fs_ino_is_synth(src_parent_ino) || fs_ino_is_synth(dst_parent_ino))
        return STM_EROFS;
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
    /* 9.7-impl-5: any synth ino → EROFS. */
    if (fs_ino_is_synth(src_ino) || fs_ino_is_synth(dst_parent_ino))
        return STM_EROFS;
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
    if (fs_ino_is_synth(parent_ino)) return STM_EROFS;  /* 9.7-impl-5 */
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

    struct stm_inode_value iv = {0};

    /* 9.8-LF-3c: synth-ino branch uses throwaway engines (snap-view
     * stat), which still need fs->global SH; live-tree branch uses
     * the wait-free EBR path. */
    if (fs_ino_is_synth(ino)) {
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        stm_status vs = fs_snap_view_stat(fs, dataset_id, ino, &iv);
        pthread_rwlock_unlock(&fs->global);
        if (vs != STM_OK) return vs;
    } else {
        FS_GUARD_READ_LOCKLESS(fs);
        stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
        if (!iidx) return STM_EINVAL;
        stm_ebr_thread *ebr = fs_ebr_thread_current();
        if (!ebr) return STM_ENOMEM;
        stm_ebr_enter(ebr);
        stm_status ls = stm_inode_lookup_concurrent(iidx, ebr, dataset_id,
                                                       ino, &iv);
        stm_ebr_exit(ebr);
        if (ls == STM_ECORRUPT) {
            /* R171 P1-1 SH-fallback. See stm_fs_stat for rationale. */
            pthread_rwlock_rdlock(&fs->global);
            FS_GUARD_READ(fs);
            iidx = stm_sync_inode_index(fs->sync);
            if (!iidx) {
                pthread_rwlock_unlock(&fs->global);
                return STM_EINVAL;
            }
            ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
            pthread_rwlock_unlock(&fs->global);
        }
        if (ls != STM_OK) return ls;       /* STM_ENOENT */
    }

    uint32_t mode = stm_load_le32(iv.si_mode);
    if ((mode & (uint32_t)S_IFMT) != (uint32_t)S_IFLNK) {
        return STM_EINVAL;       /* POSIX EINVAL on non-symlink readlink */
    }
    if (iv.si_data_kind != STM_DATA_SYMLINK) {
        /* Decoder-vs-mode mismatch: the inode says S_IFLNK but the
         * data union doesn't carry SYMLINK bytes. Treat as corrupt. */
        return STM_ECORRUPT;
    }
    /* R77 P1-1 defense-in-depth: even though `stm_inode_set` and
     * `in_decode_value` now both bound si_data_len ≤
     * STM_INODE_INLINE_MAX for SYMLINK records, the reader checks
     * before the memcpy so a hypothetical bypass at either layer
     * (test seam, future refactor) can't OOB-read the union. */
    if (iv.si_data_len > STM_INODE_INLINE_MAX) {
        return STM_ECORRUPT;
    }

    size_t actual_len = (size_t)iv.si_data_len;
    size_t copy_n = (target_max < actual_len) ? target_max : actual_len;
    if (copy_n > 0u) memcpy(target_buf, iv.si_data.symlink_target, copy_n);
    *out_len = actual_len;       /* full length, even if truncated */
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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */

    /* P9.5-PARALLEL-3 impl-5: SH (rdlock) + per-inode pin. truncate is
     * a single-inode mutator — the (load + size-check + flush + extent
     * mutate + inode_set) compound serializes per-inode on the pin
     * mutex; two truncates on disjoint inodes run in parallel. The
     * inode index is required (legacy direct-extent inodes can't be
     * truncated — they have no si_size to update). On STM_ENOENT from
     * pin, surface ENOENT (preserves the pre-impl-5 contract). */
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
        return pp;       /* STM_ENOENT */
    }

    /* SWISS-4q-flush: truncate operates on the extent tree directly
     * (drops extents past new_size, may rewrite a crossing extent).
     * Pre-flush the inode's buffered ranges so the extent layer
     * reflects all issued writes before the truncate acts. */
    {
        stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
        if (fr != STM_OK) {
            stm_inode_unpin(iidx, h);
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
    }

    /* Single-exit pattern (impl-5): every path below sets `rs` and
     * jumps to `out` which unpins + unlocks. */
    stm_status rs = STM_OK;

    struct stm_inode_value iv = {0};
    stm_status ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (ls != STM_OK) { rs = ls; goto out; }       /* STM_ENOENT */

    uint32_t mode = stm_load_le32(iv.si_mode);
    uint32_t ifmt = mode & (uint32_t)S_IFMT;
    if (ifmt == (uint32_t)S_IFDIR) { rs = STM_EISDIR; goto out; }
    if (ifmt != (uint32_t)S_IFREG) { rs = STM_EINVAL; goto out; }

    /* R77 P1-1 defense-in-depth — bound si_data_len. */
    if (iv.si_data_kind == STM_DATA_INLINE &&
        iv.si_data_len > STM_INODE_INLINE_MAX) {
        rs = STM_ECORRUPT; goto out;
    }

    uint64_t cur_size = stm_load_le64(iv.si_size);
    if (new_size == cur_size) { rs = STM_OK; goto out; }       /* no-op */

    /* P8-POSIX-7a-seals: refuse the truncate per the inode's seal mask
     * BEFORE any state mutation. SEAL_WRITE / SEAL_FUTURE_WRITE block
     * all size-changing truncate; SEAL_GROW blocks new_size > cur_size;
     * SEAL_SHRINK blocks new_size < cur_size. Refusal is STM_EPERM. */
    {
        uint32_t flags = stm_load_le32(iv.si_flags);
        if (flags & (STM_INO_FLAG_SEAL_WRITE | STM_INO_FLAG_SEAL_FUTURE_WRITE)) {
            rs = STM_EPERM; goto out;
        }
        if (new_size > cur_size && (flags & STM_INO_FLAG_SEAL_GROW)) {
            rs = STM_EPERM; goto out;
        }
        if (new_size < cur_size && (flags & STM_INO_FLAG_SEAL_SHRINK)) {
            rs = STM_EPERM; goto out;
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
            fs_stamp_mtime_ctime_now(&iv);
            /* R76 P3-1 / R78 P3-1: stm_inode_set infallible in this
             * lock posture (see fs_write_regular_locked's annotation). */
            rs = stm_inode_set(iidx, dataset_id, ino, &iv);
            goto out;
        }

        /* Grow past inline cap → transition to EXTENT. Build a
         * single block-aligned combined buffer (existing inline prefix
         * + zero pad to next 4 KiB boundary). Same shape as
         * fs_write_regular_locked's transition path. */
        if (new_size > (uint64_t)STM_FS_RECORDSIZE_MAX) {
            rs = STM_ERANGE; goto out;
        }

        const uint64_t BLK = 4096u;
        uint64_t aligned_size = (new_size + BLK - 1u) & ~(BLK - 1u);
        if (aligned_size == 0u) aligned_size = BLK;

        uint8_t *combined = calloc(1, (size_t)aligned_size);
        if (!combined) { rs = STM_ENOMEM; goto out; }
        if (iv.si_data_len > 0u) {
            memcpy(combined, iv.si_data.inline_data, iv.si_data_len);
        }
        stm_status ws = stm_sync_write_extent(fs->sync, dataset_id, ino,
                                                  /*off=*/0u,
                                                  combined,
                                                  (size_t)aligned_size);
        free(combined);
        if (ws != STM_OK) { rs = ws; goto out; }

        iv.si_data_kind = STM_DATA_EXTENT;
        iv.si_data_len  = 0;
        memset(&iv.si_data, 0, sizeof iv.si_data);
        iv.si_size      = stm_store_le64(new_size);
        fs_stamp_mtime_ctime_now(&iv);
        rs = stm_inode_set(iidx, dataset_id, ino, &iv);
        goto out;
    }

    if (kind == STM_DATA_EXTENT) {
        /* EXTENT mode. Per ARCH §11.3.3 / inode.tla::OneWayInlineToExtent:
         * once EXTENT, stays EXTENT — even when new_size ≤ inline cap. */
        const uint64_t BLK = 4096u;
        if ((new_size & (BLK - 1u)) != 0u) {
            /* Sub-block truncate not supported. POSIX truncate(2) accepts
             * arbitrary new_size; sync_truncate's MVP requires 4 KiB
             * alignment. */
            rs = STM_EINVAL; goto out;
        }

        if (new_size < cur_size) {
            stm_status ts = stm_sync_truncate(fs->sync, dataset_id, ino,
                                                 new_size);
            if (ts != STM_OK) { rs = ts; goto out; }
        }
        /* Grow case: just update si_size. The extent layer's sparse-
         * read semantics return 0 for offsets in [cur_size, new_size)
         * that have no extent record — POSIX-correct zero-fill. */

        iv.si_size = stm_store_le64(new_size);
        fs_stamp_mtime_ctime_now(&iv);
        rs = stm_inode_set(iidx, dataset_id, ino, &iv);
        goto out;
    }

    /* SYMLINK / DEVICE — not a regular-file kind; rejected. */
    rs = STM_ENOTSUPPORTED;

out:
    stm_inode_unpin(iidx, h);
    pthread_rwlock_unlock(&fs->global);
    return rs;
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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */
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
    /* 9.7-impl-5 R166 P2-1: seal reads on snap-view not surfaced at
     * v1.0 — explicit STM_ENOTSUPPORTED. */
    if (fs_ino_is_synth(ino)) return STM_ENOTSUPPORTED;

    /* 9.8-LF-3c: wait-free read — atomic wedge gate + EBR pin around
     * the concurrent inode lookup. No fs->global rwlock held. */
    FS_GUARD_READ_LOCKLESS(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;

    struct stm_inode_value iv = {0};
    stm_ebr_enter(ebr);
    stm_status ls = stm_inode_lookup_concurrent(iidx, ebr, dataset_id, ino, &iv);
    stm_ebr_exit(ebr);
    if (ls == STM_ECORRUPT) {
        /* R171 P1-1 SH-fallback. See stm_fs_stat for rationale. */
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        iidx = stm_sync_inode_index(fs->sync);
        if (!iidx) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        ls = stm_inode_lookup(iidx, dataset_id, ino, &iv);
        pthread_rwlock_unlock(&fs->global);
    }
    if (ls != STM_OK) return ls;

    *out_seals = stm_load_le32(iv.si_flags) & (uint32_t)STM_FS_SEAL_MASK;
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
    /* 9.7-impl-5 R166 P2-3: refuse synth parent up-front for clarity.
     * The downstream `fs_load_parent_dir` against the live iidx
     * returns STM_ENOENT for synth inos anyway; this gate documents
     * the intent ("file handles are for live-tree inodes only"). */
    if (fs_ino_is_synth(parent_ino)) return STM_ENOTSUPPORTED;

    stm_status nv = fs_validate_dirent_name(name, name_len);
    if (nv != STM_OK) return nv;

    /* 9.8-LF-3c: wait-free name-to-handle. All three subsystem reads
     * (parent inode, dirent lookup, child inode) under a single EBR
     * critical section. */
    FS_GUARD_READ_LOCKLESS(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;

    stm_ebr_enter(ebr);

    /* Validate parent is a directory + look up the child. */
    struct stm_inode_value pv = {0};
    struct stm_inode_value cv = {0};
    uint64_t child_ino = 0, child_gen_ignored = 0;
    uint8_t  child_type = 0;
    bool need_fallback = false;
    stm_status sps = stm_inode_lookup_concurrent(iidx, ebr, dataset_id,
                                                    parent_ino, &pv);
    if (sps == STM_ECORRUPT) {
        need_fallback = true;
    } else if (sps != STM_OK) {
        stm_ebr_exit(ebr);
        return sps;
    } else {
        uint32_t pmode = stm_load_le32(pv.si_mode);
        if ((pmode & (uint32_t)S_IFMT) != (uint32_t)S_IFDIR) {
            stm_ebr_exit(ebr);
            return STM_ENOTDIR;
        }
    }

    if (!need_fallback) {
        stm_status ds = stm_dirent_lookup_concurrent(didx, ebr, dataset_id,
                                                         parent_ino,
                                                         name, name_len,
                                                         &child_ino, &child_gen_ignored,
                                                         &child_type);
        if (ds == STM_ECORRUPT) {
            need_fallback = true;
        } else if (ds != STM_OK) {
            stm_ebr_exit(ebr);
            return ds;
        }
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
    if (!need_fallback) {
        stm_status cs = stm_inode_lookup_concurrent(iidx, ebr, dataset_id,
                                                       child_ino, &cv);
        if (cs == STM_ECORRUPT) {
            need_fallback = true;
        } else if (cs != STM_OK) {
            stm_ebr_exit(ebr);
            return cs;
        }
    }
    stm_ebr_exit(ebr);

    if (need_fallback) {
        /* R171 P1-1 SH-fallback. See stm_fs_stat for rationale. */
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        iidx = stm_sync_inode_index(fs->sync);
        didx = stm_sync_dirent_index(fs->sync);
        if (!iidx || !didx) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        stm_status ps2 = fs_load_parent_dir(iidx, dataset_id, parent_ino, &pv);
        if (ps2 != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ps2;
        }
        stm_status ds2 = stm_dirent_lookup(didx, dataset_id, parent_ino,
                                              name, name_len,
                                              &child_ino, &child_gen_ignored,
                                              &child_type);
        if (ds2 != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ds2;
        }
        stm_status cs2 = stm_inode_lookup(iidx, dataset_id, child_ino, &cv);
        pthread_rwlock_unlock(&fs->global);
        if (cs2 != STM_OK) return cs2;
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
    /* 9.7-impl-5 R166 P2-3: refuse synth-encoded handle. A forged
     * handle with bit 63 set would otherwise miss the live iidx +
     * surface STM_ENOENT; STM_ESTALE matches POSIX semantics for
     * "handle describes nothing under this mount". */
    if (fs_ino_is_synth(ino)) return STM_ESTALE;

    /* 9.8-LF-3c: wait-free open-by-handle. fs->pool is immutable
     * post-mount (set in fs_new + never reassigned), so pool_uuid can
     * be read outside any rwlock. */
    FS_GUARD_READ_LOCKLESS(fs);

    /* R83 P2-1: cross-pool isolation. */
    {
        const uint64_t *pu = stm_pool_uuid(fs->pool);
        if (stm_load_le64(handle->h_pool_uuid[0]) != pu[0] ||
            stm_load_le64(handle->h_pool_uuid[1]) != pu[1]) {
            return STM_ESTALE;
        }
    }

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!iidx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;

    /* R83 P2-2: distinguish STM_ENOENT (never existed) from STM_ESTALE
     * (was here, gone now). stm_inode_lookup currently fuses both
     * cases (no record OR record FREED) into a single STM_ENOENT
     * return; we re-discriminate via the (ino < next_ino) heuristic. */
    struct stm_inode_value v = {0};
    stm_ebr_enter(ebr);
    stm_status ls = stm_inode_lookup_concurrent(iidx, ebr, ds, ino, &v);
    stm_ebr_exit(ebr);
    if (ls == STM_ECORRUPT) {
        /* R171 P1-1 SH-fallback. See stm_fs_stat for rationale. */
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        iidx = stm_sync_inode_index(fs->sync);
        if (!iidx) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        ls = stm_inode_lookup(iidx, ds, ino, &v);
        pthread_rwlock_unlock(&fs->global);
    }
    if (ls == STM_ENOENT) {
        /* stm_inode_next_ino takes its own subsystem-internal mutex;
         * safe without fs->global. */
        uint64_t next_ino = 0;
        stm_status ns = stm_inode_next_ino(iidx, ds, &next_ino);
        if (ns == STM_OK && ino < next_ino) return STM_ESTALE;
        return STM_ENOENT;
    }
    if (ls != STM_OK) return ls;

    /* Stale-handle detection: gen must match. */
    uint64_t cur_gen = stm_load_le64(v.si_gen);
    if (cur_gen != want_gen) return STM_ESTALE;

    *out_ino = ino;
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
    /* 9.7-impl-5: any synth parent → EROFS. */
    if (fs_ino_is_synth(src_parent_ino) || fs_ino_is_synth(dst_parent_ino))
        return STM_EROFS;
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
     * stm_fs_mark_wedged from inside the held rdlock would self-
     * deadlock on glibc rwlocks (POSIX: same-thread recursive lock is
     * undefined; readers waiting on a queued writer block here). The
     * wedge sites below are all "should not fire in current code-
     * paths" defense-in-depth, but the latent deadlock was real. */
    bool should_wedge = false;

    /* PARALLEL-3 impl-3: SH path. Pin up to four inodes
     * (src_parent + dst_parent + src_ino + dst_ino if overwrite/
     * EXCHANGE) in canonical ascending (dataset_id, ino) order via
     * stm_inode_pin_many — the first place NoCircularWait in
     * compound_ops_per_inode.tla becomes load-bearing under more
     * than 2 inodes. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }

    /* Pre-pin parent validation — fast-path STM_ENOENT/STM_ENOTDIR
     * before pinning. Post-pin we re-load both parents under pin and
     * re-check si_mode (TOCTOU defense — between this load and the
     * pin acquisition a concurrent writer holding the parent's pin
     * could rmdir it). */
    struct stm_inode_value spv = {0};
    stm_status sps = fs_load_parent_dir(iidx, dataset_id, src_parent_ino, &spv);
    if (sps != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return sps;
    }
    if (src_parent_ino != dst_parent_ino) {
        struct stm_inode_value dpv = {0};
        stm_status dps = fs_load_parent_dir(iidx, dataset_id,
                                                dst_parent_ino, &dpv);
        if (dps != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return dps;
        }
    }

    /* Retry-restart loop for TOCTOU re-verify of src + dst dirents
     * under pin. Matches fs_unlink_inode_and_dirent's discipline
     * (PARALLEL-3 impl-2 lookup-pin-reverify), generalised to the
     * two-dirent case. FS_UNLINK_MAX_ATTEMPTS bounds livelock
     * potential under high contention. */
    uint64_t src_ino = 0, src_gen = 0;
    uint8_t  src_type = 0;
    uint64_t dst_ino = 0, dst_gen = 0;
    uint8_t  dst_type = 0;
    bool dst_exists = false;
    stm_inode_handle *handles[4] = {0};
    size_t n_handles = 0;
    int attempts = 0;

    for (;;) {
        if (attempts++ >= FS_UNLINK_MAX_ATTEMPTS) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EAGAIN;
        }

        /* Pre-pin lookup of src. */
        uint64_t src_ino_obs = 0, src_gen_obs = 0;
        uint8_t  src_type_obs = 0;
        stm_status srs = stm_dirent_lookup(didx, dataset_id, src_parent_ino,
                                                src_name, src_name_len,
                                                &src_ino_obs, &src_gen_obs,
                                                &src_type_obs);
        if (srs != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return srs;
        }

        /* Pre-pin lookup of dst. */
        uint64_t dst_ino_obs = 0, dst_gen_obs = 0;
        uint8_t  dst_type_obs = 0;
        stm_status drs = stm_dirent_lookup(didx, dataset_id, dst_parent_ino,
                                                dst_name, dst_name_len,
                                                &dst_ino_obs, &dst_gen_obs,
                                                &dst_type_obs);
        bool dst_exists_obs = (drs == STM_OK);
        if (drs != STM_OK && drs != STM_ENOENT) {
            pthread_rwlock_unlock(&fs->global);
            return drs;
        }

        /* Pre-pin flag checks that don't depend on inode state. */
        if (dst_exists_obs && (flags & STM_FS_RENAME_NOREPLACE)) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EEXIST;
        }
        if ((flags & STM_FS_RENAME_EXCHANGE) && !dst_exists_obs) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOENT;
        }

        /* Build the pin set, deduplicating against earlier entries.
         * In canonical-output ordering: src_parent, dst_parent (if
         * distinct), src_ino (if distinct from parents), dst_ino (if
         * dst_exists_obs && distinct). The pin_many helper sorts
         * internally; we only need correctness of the set + the
         * de-dup. We rely on caller-side dedup because pin_many
         * refuses duplicate (ds, ino) pairs with STM_EINVAL. */
        struct stm_inode_pin_request reqs[4];
        size_t n_reqs = 0;
        reqs[n_reqs].dataset_id = dataset_id;
        reqs[n_reqs].ino        = src_parent_ino;
        n_reqs++;
        if (dst_parent_ino != src_parent_ino) {
            reqs[n_reqs].dataset_id = dataset_id;
            reqs[n_reqs].ino        = dst_parent_ino;
            n_reqs++;
        }
        {
            bool seen = false;
            for (size_t i = 0u; i < n_reqs; i++) {
                if (reqs[i].ino == src_ino_obs) { seen = true; break; }
            }
            if (!seen) {
                reqs[n_reqs].dataset_id = dataset_id;
                reqs[n_reqs].ino        = src_ino_obs;
                n_reqs++;
            }
        }
        if (dst_exists_obs) {
            bool seen = false;
            for (size_t i = 0u; i < n_reqs; i++) {
                if (reqs[i].ino == dst_ino_obs) { seen = true; break; }
            }
            if (!seen) {
                reqs[n_reqs].dataset_id = dataset_id;
                reqs[n_reqs].ino        = dst_ino_obs;
                n_reqs++;
            }
        }

        stm_inode_handle *new_handles[4] = {0};
        stm_status pp = stm_inode_pin_many(iidx, reqs, n_reqs, new_handles);
        if (pp == STM_ENOENT) {
            /* Some target inode disappeared between lookup and pin —
             * retry from lookup (the dirent may now resolve to a
             * different inode, or src/dst may have moved). */
            continue;
        }
        if (pp != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return pp;
        }

        /* Re-verify under pin: re-lookup src + dst, confirm they
         * resolve to the same (ino, gen, type) we observed pre-pin.
         * Any divergence means a concurrent writer mutated between
         * our lookup + pin — unpin + retry. */
        uint64_t src_ino_chk = 0, src_gen_chk = 0;
        uint8_t  src_type_chk = 0;
        stm_status srs_chk = stm_dirent_lookup(didx, dataset_id,
                                                    src_parent_ino,
                                                    src_name, src_name_len,
                                                    &src_ino_chk, &src_gen_chk,
                                                    &src_type_chk);
        if (srs_chk != STM_OK || src_ino_chk != src_ino_obs ||
            src_gen_chk != src_gen_obs || src_type_chk != src_type_obs) {
            for (size_t i = 0u; i < n_reqs; i++) {
                stm_inode_unpin(iidx, new_handles[i]);
            }
            if (srs_chk != STM_OK && srs_chk != STM_ENOENT) {
                pthread_rwlock_unlock(&fs->global);
                return srs_chk;
            }
            continue;
        }
        uint64_t dst_ino_chk = 0, dst_gen_chk = 0;
        uint8_t  dst_type_chk = 0;
        stm_status drs_chk = stm_dirent_lookup(didx, dataset_id,
                                                    dst_parent_ino,
                                                    dst_name, dst_name_len,
                                                    &dst_ino_chk, &dst_gen_chk,
                                                    &dst_type_chk);
        bool dst_exists_chk = (drs_chk == STM_OK);
        if ((drs_chk != STM_OK && drs_chk != STM_ENOENT) ||
            dst_exists_chk != dst_exists_obs ||
            (dst_exists_chk && (dst_ino_chk != dst_ino_obs ||
                                 dst_gen_chk != dst_gen_obs ||
                                 dst_type_chk != dst_type_obs))) {
            for (size_t i = 0u; i < n_reqs; i++) {
                stm_inode_unpin(iidx, new_handles[i]);
            }
            if (drs_chk != STM_OK && drs_chk != STM_ENOENT) {
                pthread_rwlock_unlock(&fs->global);
                return drs_chk;
            }
            continue;
        }

        /* Re-verify parents are still dirs under their pins. */
        struct stm_inode_value spv_chk = {0};
        stm_status sp_chk = fs_load_parent_dir(iidx, dataset_id,
                                                    src_parent_ino, &spv_chk);
        if (sp_chk != STM_OK) {
            for (size_t i = 0u; i < n_reqs; i++) {
                stm_inode_unpin(iidx, new_handles[i]);
            }
            if (sp_chk == STM_ENOENT) continue;
            pthread_rwlock_unlock(&fs->global);
            return sp_chk;
        }
        if (src_parent_ino != dst_parent_ino) {
            struct stm_inode_value dpv_chk = {0};
            stm_status dp_chk = fs_load_parent_dir(iidx, dataset_id,
                                                        dst_parent_ino,
                                                        &dpv_chk);
            if (dp_chk != STM_OK) {
                for (size_t i = 0u; i < n_reqs; i++) {
                    stm_inode_unpin(iidx, new_handles[i]);
                }
                if (dp_chk == STM_ENOENT) continue;
                pthread_rwlock_unlock(&fs->global);
                return dp_chk;
            }
        }

        /* TOCTOU re-verify passed; commit to this set of pins. */
        src_ino    = src_ino_obs;
        src_gen    = src_gen_obs;
        src_type   = src_type_obs;
        dst_ino    = dst_ino_obs;
        dst_gen    = dst_gen_obs;
        dst_type   = dst_type_obs;
        dst_exists = dst_exists_obs;
        for (size_t i = 0u; i < n_reqs; i++) {
            handles[i] = new_handles[i];
        }
        n_handles = n_reqs;
        break;
    }

    /* Helper macro: unpin every successfully-acquired handle in
     * handles[0..n_handles). Defensive against duplicates: pin_many
     * refused them upfront, so each slot is unique. */
    #define FS_RENAME_UNPIN_ALL()                              \
        do {                                                    \
            for (size_t _i = 0u; _i < n_handles; _i++) {        \
                stm_inode_unpin(iidx, handles[_i]);             \
                handles[_i] = NULL;                             \
            }                                                   \
            n_handles = 0u;                                     \
        } while (0)

    /* P8-POSIX-9b: RENAME_EXCHANGE — both src + dst MUST exist.
     * Atomically swap their (ino, gen, type) at the dirent layer
     * via stm_dirent_swap_two. NO inode is created or freed; nlink
     * unchanged on both sides. Composes over dirent.tla::Swap. */
    if (flags & STM_FS_RENAME_EXCHANGE) {
        /* R86 P2-1 (P11 close): immediate-parent directory-cycle
         * detection. EXCHANGE of two directories where one is the
         * IMMEDIATE parent of the other creates a cycle: post-
         * exchange, the parent's slot points to the (former) child
         * dir, while the child's slot points to the (former) parent
         * — which now contains itself transitively. Refuse with
         * STM_EINVAL.
         *
         * Forward-note: deeper-ancestor cycle detection requires
         * O(depth) ancestor-walk via dirent traversal; not yet
         * implemented. The immediate-parent check catches the most
         * common abuse case. */
        bool src_is_dir = (src_type == STM_DT_DIR);
        bool dst_is_dir = (dst_type == STM_DT_DIR);
        if (src_is_dir && dst_is_dir) {
            if (src_ino == dst_parent_ino || dst_ino == src_parent_ino) {
                FS_RENAME_UNPIN_ALL();
                pthread_rwlock_unlock(&fs->global);
                return STM_EINVAL;
            }
        }
        stm_status ws = stm_dirent_swap_two(didx, dataset_id,
                                                 src_parent_ino,
                                                 src_name, src_name_len,
                                                 dst_parent_ino,
                                                 dst_name, dst_name_len);
        if (ws != STM_OK) {
            FS_RENAME_UNPIN_ALL();
            pthread_rwlock_unlock(&fs->global);
            return ws;
        }
        /* Stamp ctime on both inodes (post-swap). Best-effort under
         * R76 P3-1 / R78 P3-1 lock-posture infallibility — only
         * ctime mutates. Both inodes are pinned. */
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
        FS_RENAME_UNPIN_ALL();
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
            FS_RENAME_UNPIN_ALL();
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOTDIR;
        }
        if (!src_is_dir && dst_is_dir) {
            FS_RENAME_UNPIN_ALL();
            pthread_rwlock_unlock(&fs->global);
            return STM_EISDIR;
        }
        if (src_is_dir && dst_is_dir) {
            size_t n = 0;
            stm_status cs = stm_dirent_count_for_dir(didx, dataset_id,
                                                          dst_ino, &n);
            if (cs == STM_OK && n > 0u) {
                FS_RENAME_UNPIN_ALL();
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
         * si_gen — confused-deputy-class data corruption. Inode lookup
         * is best-effort; the returned truncate-flag gates the post-
         * reclaim double-commit below (R130 perf: skip the ~200ms
         * commit pair when the overwritten dst has no extents). Runs
         * under dst_ino's pin (acquired above via pin_many). */
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
            /* Should not happen — we just looked up the entry under
             * the parent's pin AND re-verified it under pin. */
            FS_RENAME_UNPIN_ALL();
            pthread_rwlock_unlock(&fs->global);
            return du;
        }
        stm_status iu = stm_inode_unlink(iidx, dataset_id, dst_ino,
                                            &dst_freed_unused);
        if (iu != STM_OK) {
            /* Rollback: re-create dst dirent. Under dst_parent's pin
             * the slot is still a tombstone we just created; alloc
             * reuses it. */
            (void)stm_dirent_alloc(didx, dataset_id, dst_parent_ino,
                                       dst_name, dst_name_len,
                                       dst_ino, dst_gen, dst_type);
            FS_RENAME_UNPIN_ALL();
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
         * dst inode's nlink back. R133 P1-2 captures wedge intent
         * here; the actual mark_wedged fires AFTER unlock. */
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
                 * caller's perspective. */
                should_wedge = true;
            }
            if (r1 != STM_OK || r2 != STM_OK) {
                should_wedge = true;
            }
        }
        FS_RENAME_UNPIN_ALL();
        pthread_rwlock_unlock(&fs->global);
        if (should_wedge) stm_fs_mark_wedged(fs);
        return as;
    }

    /* Drop src dirent (or convert to whiteout). Under src_parent's
     * pin this is the straightforward write to a tombstone — should
     * not fail.
     *
     * P8-POSIX-9b RENAME_WHITEOUT: instead of unlinking src (which
     * leaves a TOMBSTONE invisible to readdir), convert src to a
     * WHITEOUT marker. */
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
         * and re-link the original (if overwrite). R79 P3-1 + R133
         * P1-2: capture wedge intent. */
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
                should_wedge = true;
            }
        }
        FS_RENAME_UNPIN_ALL();
        pthread_rwlock_unlock(&fs->global);
        if (should_wedge) stm_fs_mark_wedged(fs);
        return su;
    }

    /* P8-POSIX-7a: rename mutates the moved inode's parent + name,
     * which POSIX models as a metadata change → ctime auto-stamps to
     * "now" on src_ino. mtime + btime preserved.
     *
     * R86 P2-2 (P11 close): also stamp src_parent + dst_parent
     * directories' mtime + ctime — POSIX says rename modifies both
     * parent directories. For same-parent rename, stamp once. All
     * targets are pinned. */
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
     * and the blocks leak as PENDING for the session. R130: also
     * gate on whether the pre-cleanup truncated extents — overwriting
     * a directory or symlink target (no extents) skips the ~200 ms
     * commit pair. */
    if (dst_freed_unused && dst_cleanup_did_truncate) {
        /* R154 P1-1: capture wedge-intent; a failed reclaim commit is
         * crash-equivalent. Reuses rename's should_wedge — fired AFTER
         * the unlock per the R133 P1-2 deferred-wedge doctrine. */
        if (fs_post_inode_free_reclaim_locked(fs)) should_wedge = true;
    }

    FS_RENAME_UNPIN_ALL();
    pthread_rwlock_unlock(&fs->global);
    if (should_wedge) stm_fs_mark_wedged(fs);
    return STM_OK;
    #undef FS_RENAME_UNPIN_ALL
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

    /* 9.8-LF-3 port: synth-namespace branches keep fs->global SH
     * (throwaway-engine surface); live-tree branch goes wait-free via
     * EBR + concurrent inode lookup + concurrent readdir.
     *
     * 9.7-impl-5 .snaps namespace readdir routes through SH because
     * the SNAPS_PARENT + SNAP_VIEW paths use snapshot index lookups +
     * throwaway-engine readdirs that are not yet on the LF path. */
    if (fs_ino_is_synth(dir_ino)) {
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);

        bool no_dots = (flags & STM_FS_READDIR_FLAG_NO_DOTS) != 0u;
        uint64_t local_cursor = *cursor;
        size_t emitted = 0;

        if (local_cursor == 0u) {
            if (!no_dots && emitted < max_entries) {
                fs_readdir_synth_dot(&out_entries[emitted], dir_ino, 1);
                emitted++;
            }
            local_cursor = 1u;
        }
        if (local_cursor == 1u && emitted < max_entries) {
            if (!no_dots) {
                fs_readdir_synth_dot(&out_entries[emitted], parent_ino, 2);
                emitted++;
            }
            local_cursor = 2u;
        }

        size_t batch_returned = 0;
        if (emitted < max_entries) {
            uint64_t inner_cursor = local_cursor - 2u;
            size_t max_inner = max_entries - emitted;
            stm_status s;
            if (fs_ino_is_snaps_parent(dir_ino)) {
                s = fs_snaps_parent_readdir(fs, dataset_id, &inner_cursor,
                                                out_entries + emitted,
                                                max_inner, &batch_returned);
            } else {
                s = fs_snap_view_readdir(fs, dataset_id, dir_ino,
                                            &inner_cursor,
                                            out_entries + emitted,
                                            max_inner, &batch_returned);
            }
            if (s != STM_OK) {
                pthread_rwlock_unlock(&fs->global);
                return s;
            }
            emitted += batch_returned;
            local_cursor = (inner_cursor > UINT64_MAX - 2u)
                              ? UINT64_MAX : (inner_cursor + 2u);
        }
        *cursor = local_cursor;
        *out_returned = emitted;
        pthread_rwlock_unlock(&fs->global);
        return STM_OK;
    }

    /* Live-tree branch: wait-free path. Atomic wedge gate + EBR pin
     * for both the parent-dir-validation + the dirent readdir. */
    FS_GUARD_READ_LOCKLESS(fs);

    stm_inode_index  *iidx = stm_sync_inode_index(fs->sync);
    stm_dirent_index *didx = stm_sync_dirent_index(fs->sync);
    if (!iidx || !didx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;
    stm_ebr_enter(ebr);

    bool no_dots = (flags & STM_FS_READDIR_FLAG_NO_DOTS) != 0u;
    bool need_fallback = false;
    struct stm_inode_value dv = {0};
    stm_status ds = fs_load_parent_dir_concurrent(iidx, ebr, dataset_id,
                                                     dir_ino, &dv);
    if (ds == STM_ECORRUPT) need_fallback = true;
    else if (ds != STM_OK) {
        stm_ebr_exit(ebr);
        return ds;
    }

    uint64_t local_cursor = *cursor;
    size_t emitted = 0;

    if (!need_fallback) {
        if (local_cursor == 0u) {
            if (!no_dots) {
                if (emitted < max_entries) {
                    fs_readdir_synth_dot(&out_entries[emitted], dir_ino, 1);
                    emitted++;
                    local_cursor = 1u;
                }
            } else {
                local_cursor = 1u;
            }
        }

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

        if (local_cursor >= 2u && emitted < max_entries) {
            uint64_t dirent_cursor = local_cursor - 2u;
            size_t dirent_max = max_entries - emitted;

            if (dirent_max > SIZE_MAX / sizeof(stm_dirent_entry)) {
                stm_ebr_exit(ebr);
                return STM_ENOMEM;
            }
            stm_dirent_entry *batch = malloc(dirent_max * sizeof *batch);
            if (!batch) {
                stm_ebr_exit(ebr);
                return STM_ENOMEM;
            }

            size_t batch_n = 0;
            stm_status rs = stm_dirent_readdir_concurrent(didx, ebr, dataset_id,
                                                             dir_ino, &dirent_cursor,
                                                             batch, dirent_max,
                                                             &batch_n);
            if (rs == STM_ECORRUPT) {
                free(batch);
                need_fallback = true;
            } else if (rs != STM_OK) {
                free(batch);
                stm_ebr_exit(ebr);
                return rs;
            } else {
                for (size_t k = 0; k < batch_n; k++) {
                    /* R75 P3-4: defense-in-depth name_len bound. */
                    if (batch[k].name_len > STM_DIRENT_NAME_MAX) {
                        free(batch);
                        stm_ebr_exit(ebr);
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

                if (dirent_cursor > UINT64_MAX - 2u) {
                    local_cursor = UINT64_MAX;
                } else {
                    local_cursor = dirent_cursor + 2u;
                }
            }
        }
    }
    stm_ebr_exit(ebr);

    if (need_fallback) {
        /* R171 P1-1 SH-fallback. See stm_fs_stat for rationale.
         * Reset emitted + local_cursor so the serial path replays
         * the synth-dot + scan from the caller's *cursor. */
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        iidx = stm_sync_inode_index(fs->sync);
        didx = stm_sync_dirent_index(fs->sync);
        if (!iidx || !didx) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        memset(&dv, 0, sizeof dv);
        ds = fs_load_parent_dir(iidx, dataset_id, dir_ino, &dv);
        if (ds != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ds;
        }
        local_cursor = *cursor;
        emitted = 0;
        if (local_cursor == 0u) {
            if (!no_dots) {
                if (emitted < max_entries) {
                    fs_readdir_synth_dot(&out_entries[emitted], dir_ino, 1);
                    emitted++;
                    local_cursor = 1u;
                }
            } else {
                local_cursor = 1u;
            }
        }
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
        if (local_cursor >= 2u && emitted < max_entries) {
            uint64_t dirent_cursor = local_cursor - 2u;
            size_t dirent_max = max_entries - emitted;
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
                                                  &dirent_cursor,
                                                  batch, dirent_max, &batch_n);
            if (rs != STM_OK) {
                free(batch);
                pthread_rwlock_unlock(&fs->global);
                return rs;
            }
            for (size_t k = 0; k < batch_n; k++) {
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
            if (dirent_cursor > UINT64_MAX - 2u) {
                local_cursor = UINT64_MAX;
            } else {
                local_cursor = dirent_cursor + 2u;
            }
        }
        pthread_rwlock_unlock(&fs->global);
    }

    *cursor = local_cursor;
    *out_returned = emitted;
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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */
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
    /* 9.7-impl-5 R166 P2-1: xattr reads on snap-view not surfaced
     * at v1.0 — explicit STM_ENOTSUPPORTED instead of a confusing
     * STM_ENOENT fall-through through the live xattr index. */
    if (fs_ino_is_synth(ino)) return STM_ENOTSUPPORTED;
    if (name_len == 0u || name_len > STM_FS_XATTR_NAME_MAX) return STM_EINVAL;
    if (!fs_xattr_name_in_posix_namespace(name, name_len)) return STM_EINVAL;

    /* 9.8-LF-3c: wait-free getxattr — inode existence check + xattr
     * lookup both run under a single EBR critical section. No
     * fs->global rwlock. */
    FS_GUARD_READ_LOCKLESS(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    stm_xattr_index *xidx = stm_sync_xattr_index(fs->sync);
    if (!iidx || !xidx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;

    stm_ebr_enter(ebr);

    /* Require the inode exists (POSIX getxattr on a freed inode is
     * ENOENT, NOT ENODATA). */
    struct stm_inode_value iv;
    memset(&iv, 0, sizeof iv);
    stm_status is = stm_inode_lookup_concurrent(iidx, ebr, dataset_id,
                                                   ino, &iv);
    stm_status s = STM_ECORRUPT;
    if (is == STM_OK) {
        s = stm_xattr_get_concurrent(xidx, ebr, dataset_id, ino,
                                        name, name_len,
                                        value_buf, value_max, out_size);
    }
    stm_ebr_exit(ebr);
    if (is != STM_OK && is != STM_ECORRUPT) return is;
    if (is == STM_OK && s != STM_ECORRUPT) return s;

    /* R171 P1-1 SH-fallback. See stm_fs_stat for rationale. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_READ(fs);
    iidx = stm_sync_inode_index(fs->sync);
    xidx = stm_sync_xattr_index(fs->sync);
    if (!iidx || !xidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    memset(&iv, 0, sizeof iv);
    stm_status is2 = stm_inode_lookup(iidx, dataset_id, ino, &iv);
    if (is2 != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return is2;
    }
    if (out_size) *out_size = 0;
    s = stm_xattr_get(xidx, dataset_id, ino, name, name_len,
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
    /* 9.7-impl-5 R166 P2-1: xattr reads on snap-view not surfaced
     * at v1.0 — explicit STM_ENOTSUPPORTED. */
    if (fs_ino_is_synth(ino)) return STM_ENOTSUPPORTED;

    /* 9.8-LF-3 port: drop fs->global SH; atomic wedge gate + EBR pin
     * for the inode-existence check + the two xattr_list_concurrent
     * passes (probe count + materialise). Inode existence + listing
     * both happen under a single EBR critical section so the inode
     * cannot be unlinked between the require check + the listing. */
    FS_GUARD_READ_LOCKLESS(fs);

    stm_xattr_index *xidx = stm_sync_xattr_index(fs->sync);
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (!xidx || !iidx) return STM_EINVAL;

    stm_ebr_thread *ebr = fs_ebr_thread_current();
    if (!ebr) return STM_ENOMEM;
    stm_ebr_enter(ebr);

    bool need_fallback = false;
    struct stm_inode_value iv;
    memset(&iv, 0, sizeof iv);
    stm_status ps = stm_inode_lookup_concurrent(iidx, ebr,
                                                  dataset_id, ino, &iv);
    if (ps == STM_ECORRUPT) need_fallback = true;
    else if (ps != STM_OK) {
        stm_ebr_exit(ebr);
        return ps;
    }

    size_t n_total = 0;
    size_t got = 0;
    stm_xattr_entry *batch = NULL;
    if (!need_fallback) {
        /* First pass: probe the count. */
        stm_status ps0 = stm_xattr_list_concurrent(xidx, ebr, dataset_id, ino,
                                                      NULL, 0, &n_total);
        if (ps0 == STM_ECORRUPT) need_fallback = true;
        else if (ps0 != STM_OK) {
            stm_ebr_exit(ebr);
            return ps0;
        }
    }

    if (!need_fallback && n_total == 0) {
        *out_total_len = 0;
        stm_ebr_exit(ebr);
        return STM_OK;
    }

    if (!need_fallback) {
        if (n_total > SIZE_MAX / sizeof(stm_xattr_entry)) {
            stm_ebr_exit(ebr);
            return STM_ENOMEM;
        }
        batch = malloc(n_total * sizeof *batch);
        if (!batch) {
            stm_ebr_exit(ebr);
            return STM_ENOMEM;
        }
        stm_status ls = stm_xattr_list_concurrent(xidx, ebr, dataset_id, ino,
                                                     batch, n_total, &got);
        /* R171 P1-2 / R172 P1-1: count-vs-materialize TOCTOU under
         * same-engine concurrent writer. THREE symptoms:
         *   - STM_ECORRUPT: writer mid-record-mutation → torn decode.
         *   - STM_OK + got != n_total: writer REMOVED an xattr between
         *     passes (materialize saw fewer).
         *   - STM_ERANGE: writer ADDED an xattr between passes; the
         *     materialize's xattr.c-level count saw n_total+1 >
         *     max_entries (sized to the wait-free pass-1 count) and
         *     refused. R172 P1-1: pre-R172 this propagated as a
         *     spurious "buffer too small" lie to the caller.
         * All three fall to the SH-fallback, where fs->global SH
         * excludes fs->global EX (writers) so the two passes see a
         * consistent index. */
        if (ls == STM_ECORRUPT || ls == STM_ERANGE
            || (ls == STM_OK && got != n_total)) {
            free(batch);
            batch = NULL;
            need_fallback = true;
        } else if (ls != STM_OK) {
            free(batch);
            stm_ebr_exit(ebr);
            return ls;
        }
    }
    stm_ebr_exit(ebr);

    if (need_fallback) {
        /* R171 P1-1/P1-2 + R172 P1-1 SH-fallback. The fs->global SH
         * here excludes the EX-holding xattr writers (setxattr /
         * removexattr both take EX), so the two-pass count + materialize
         * sees a consistent xattr-index for this inode. R172 P2-2: this
         * exclusion is provided by fs->global SH-vs-EX, NOT by the xattr
         * index's internal mutex (which serializes individual calls
         * but NOT the call SEQUENCE). If a future xattr writer is
         * lifted to SH (PARALLEL-3-style), the two-pass shape MUST be
         * revisited — wrap both passes in a per-inode pin or fold into
         * a single-pass primitive. See stm_fs_stat for the general
         * SH-fallback rationale. */
        pthread_rwlock_rdlock(&fs->global);
        FS_GUARD_READ(fs);
        iidx = stm_sync_inode_index(fs->sync);
        xidx = stm_sync_xattr_index(fs->sync);
        if (!iidx || !xidx) {
            pthread_rwlock_unlock(&fs->global);
            return STM_EINVAL;
        }
        memset(&iv, 0, sizeof iv);
        stm_status ps2 = stm_inode_lookup(iidx, dataset_id, ino, &iv);
        if (ps2 != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ps2;
        }
        stm_status ls2 = stm_xattr_list(xidx, dataset_id, ino, NULL, 0,
                                             &n_total);
        if (ls2 != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return ls2;
        }
        if (n_total == 0) {
            *out_total_len = 0;
            pthread_rwlock_unlock(&fs->global);
            return STM_OK;
        }
        if (n_total > SIZE_MAX / sizeof(stm_xattr_entry)) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOMEM;
        }
        batch = malloc(n_total * sizeof *batch);
        if (!batch) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOMEM;
        }
        ls2 = stm_xattr_list(xidx, dataset_id, ino, batch, n_total, &got);
        pthread_rwlock_unlock(&fs->global);
        if (ls2 != STM_OK || got != n_total) {
            free(batch);
            return (ls2 != STM_OK) ? ls2 : STM_ECORRUPT;
        }
    }

    /* Compute total byte length (sum of (name_len + 1)). */
    size_t total_len = 0;
    for (size_t i = 0; i < got; i++) {
        /* R77 P1-1-style defense: cap name_len at the fs → xattr
         * trust boundary even though the xattr-layer + decoder both
         * enforce ≤ STM_XATTR_NAME_MAX. */
        if (batch[i].name_len == 0 ||
            batch[i].name_len > STM_FS_XATTR_NAME_MAX) {
            free(batch);
            return STM_ECORRUPT;
        }
        if (batch[i].value_len > STM_FS_XATTR_VALUE_MAX) {
            free(batch);
            return STM_ECORRUPT;
        }
        size_t entry_bytes = (size_t)batch[i].name_len + 1u;
        if (total_len > SIZE_MAX - entry_bytes) {
            free(batch);
            return STM_EOVERFLOW;
        }
        total_len += entry_bytes;
    }
    *out_total_len = total_len;

    if (buf_max == 0) {
        free(batch);
        return STM_OK;
    }
    if (buf_max < total_len) {
        free(batch);
        return STM_ERANGE;
    }

    size_t off = 0;
    for (size_t i = 0; i < got; i++) {
        memcpy(name_buf + off, batch[i].name, batch[i].name_len);
        off += batch[i].name_len;
        name_buf[off++] = 0;
    }

    free(batch);
    return STM_OK;
}

stm_status stm_fs_removexattr(stm_fs *fs, uint64_t dataset_id, uint64_t ino,
                                 const uint8_t *name, uint8_t name_len) {
    if (!fs) return STM_EINVAL;
    if (!name) return STM_EINVAL;
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */
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
    if (src_dataset_id == 0u || src_ino == 0u) return STM_EINVAL;
    if (dst_dataset_id == 0u || dst_ino == 0u) return STM_EINVAL;
    /* 9.7-impl-5: any synth ino → EROFS (dst write OR src read deferred). */
    if (fs_ino_is_synth(src_ino) || fs_ino_is_synth(dst_ino))
        return STM_EROFS;
    /* Same-(ds, ino) refused upfront with STM_EINVAL. Required to
     * preserve test_9p.c::p9_r94_p3_2_reflink_src_eq_dst_returns_einval
     * semantics + matches stm_sync_reflink's own guard. */
    if (src_dataset_id == dst_dataset_id && src_ino == dst_ino) {
        return STM_EINVAL;
    }

    /* P9.5-PARALLEL-3 impl-4: try SH (rdlock) + per-inode pin on (src,
     * dst). Falls back to EX (wrlock — pre-impl-4 posture) when either
     * inode has no index record (legacy direct-extent path: some tests
     * + some non-POSIX writers go through stm_sync_write_extent without
     * registering an inode record — see stm_fs_write's fall-through at
     * line 1227). pin_two requires both inodes to exist in the index;
     * absent that, the legacy mode still requires full big-lock
     * serialization because there's no per-inode mutex to acquire. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (iidx) {
        stm_inode_handle *h_src = NULL, *h_dst = NULL;
        stm_status ps = stm_inode_pin_two(iidx,
                                              src_dataset_id, src_ino,
                                              dst_dataset_id, dst_ino,
                                              &h_src, &h_dst);
        if (ps == STM_OK) {
            /* SH+pin happy path. */
            stm_status s = fs_flush_ino_locked(fs, src_dataset_id, src_ino);
            if (s == STM_OK) {
                s = fs_flush_ino_locked(fs, dst_dataset_id, dst_ino);
            }
            if (s == STM_OK) {
                s = fs_reflink_locked(fs, src_dataset_id, src_ino,
                                          dst_dataset_id, dst_ino);
            }
            stm_inode_unpin(iidx, h_dst);
            stm_inode_unpin(iidx, h_src);
            pthread_rwlock_unlock(&fs->global);
            return s;
        }
        /* STM_ENOENT (either inode missing from index) ⇒ legacy mode;
         * other errors propagate. */
        if (ps != STM_ENOENT) {
            pthread_rwlock_unlock(&fs->global);
            return ps;
        }
    }
    /* Legacy / transitional EX path: release SH and reacquire EX. */
    pthread_rwlock_unlock(&fs->global);
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_status s = fs_flush_ino_locked(fs, src_dataset_id, src_ino);
    if (s == STM_OK) {
        s = fs_flush_ino_locked(fs, dst_dataset_id, dst_ino);
    }
    if (s == STM_OK) {
        s = fs_reflink_locked(fs, src_dataset_id, src_ino,
                                  dst_dataset_id, dst_ino);
    }
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
    /* 9.7-impl-5: any synth ino → EROFS. */
    if (fs_ino_is_synth(src_ino) || fs_ino_is_synth(dst_ino))
        return STM_EROFS;

    /* MVP: whole-file copy only. Caller must pass (0, 0, src_size).
     * len == 0 is a legal POSIX no-op (out_copied = 0; STM_OK). */
    if (src_off != 0u || dst_off != 0u) return STM_ENOTSUPPORTED;
    if (len == 0u) return STM_OK;

    /* Same-(ds, ino) refused upfront — same posture as stm_fs_reflink. */
    if (src_dataset_id == dst_dataset_id && src_ino == dst_ino) {
        return STM_EINVAL;
    }

    /* P9.5-PARALLEL-3 impl-4: try SH+pin_two; fall back to EX for
     * legacy direct-extent inodes (see stm_fs_reflink for the same
     * pattern + rationale). */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    uint64_t src_size = 0;
    if (iidx) {
        stm_inode_handle *h_src = NULL, *h_dst = NULL;
        stm_status ps = stm_inode_pin_two(iidx,
                                              src_dataset_id, src_ino,
                                              dst_dataset_id, dst_ino,
                                              &h_src, &h_dst);
        if (ps == STM_OK) {
            /* SH+pin happy path. R128 P2-1 pre-flush + R84 P2-1 TOCTOU
             * size-check under the pins. */
            stm_status s = fs_flush_ino_locked(fs, src_dataset_id, src_ino);
            if (s == STM_OK) {
                s = fs_flush_ino_locked(fs, dst_dataset_id, dst_ino);
            }
            if (s == STM_OK) {
                struct stm_inode_value siv = {0};
                s = stm_inode_lookup(iidx, src_dataset_id, src_ino, &siv);
                if (s == STM_OK) {
                    src_size = stm_load_le64(siv.si_size);
                    if (len != src_size) s = STM_ENOTSUPPORTED;
                }
            }
            if (s == STM_OK) {
                s = fs_reflink_locked(fs, src_dataset_id, src_ino,
                                          dst_dataset_id, dst_ino);
            }
            stm_inode_unpin(iidx, h_dst);
            stm_inode_unpin(iidx, h_src);
            pthread_rwlock_unlock(&fs->global);
            if (s != STM_OK) return s;
            if (out_copied) *out_copied = src_size;
            return STM_OK;
        }
        if (ps != STM_ENOENT) {
            pthread_rwlock_unlock(&fs->global);
            return ps;
        }
    }

    /* Legacy / transitional EX path. */
    pthread_rwlock_unlock(&fs->global);
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_status s = fs_flush_ino_locked(fs, src_dataset_id, src_ino);
    if (s == STM_OK) {
        s = fs_flush_ino_locked(fs, dst_dataset_id, dst_ino);
    }
    if (s == STM_OK) {
        iidx = stm_sync_inode_index(fs->sync);
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
        src_size = stm_load_le64(siv.si_size);
        if (len != src_size) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOTSUPPORTED;
        }
        s = fs_reflink_locked(fs, src_dataset_id, src_ino,
                                  dst_dataset_id, dst_ino);
    }
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
    if (dataset_id == 0u || ino == 0u) return STM_EINVAL;
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */

    /* P9.5-PARALLEL-3 impl-5: SH (rdlock) + per-inode pin. Migrate is
     * a single-inode mutator (extent-layer flip + per-extent rewrite).
     * Falls back to EX (wrlock — pre-impl-5 posture) on STM_ENOENT
     * from pin so legacy direct-extent inodes (no index record) keep
     * working — same shape as impl-4 reflink/cfr. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (iidx) {
        stm_inode_handle *h = NULL;
        stm_status pp = stm_inode_pin(iidx, dataset_id, ino, &h);
        if (pp == STM_OK) {
            /* R128 P2-2 pre-flush: buffered ranges must reach the
             * extent layer before migrate-to-cold iterates extent_idx. */
            stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
            stm_status s = (fr == STM_OK)
                ? stm_sync_migrate_to_cold(fs->sync, dataset_id, ino)
                : fr;
            stm_inode_unpin(iidx, h);
            pthread_rwlock_unlock(&fs->global);
            return s;
        }
        if (pp != STM_ENOENT) {
            pthread_rwlock_unlock(&fs->global);
            return pp;
        }
    }
    /* Legacy / transitional EX path. */
    pthread_rwlock_unlock(&fs->global);
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */

    /* P9.5-PARALLEL-3 impl-5: SH (rdlock) + per-inode pin. Symmetric
     * with stm_fs_migrate_to_cold (clause 18 of CLAUDE.md inode-alloc
     * row carries; impl-5 adds the migrate/promote pair). Legacy EX
     * fallback on STM_ENOENT from pin. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_inode_index *iidx = stm_sync_inode_index(fs->sync);
    if (iidx) {
        stm_inode_handle *h = NULL;
        stm_status pp = stm_inode_pin(iidx, dataset_id, ino, &h);
        if (pp == STM_OK) {
            stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
            stm_status rc = (fr == STM_OK)
                ? stm_sync_promote_to_hot(fs->sync, dataset_id, ino)
                : fr;
            stm_inode_unpin(iidx, h);
            pthread_rwlock_unlock(&fs->global);
            return rc;
        }
        if (pp != STM_ENOENT) {
            pthread_rwlock_unlock(&fs->global);
            return pp;
        }
    }
    /* Legacy / transitional EX path. */
    pthread_rwlock_unlock(&fs->global);
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
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
    if (atomic_load_explicit(&fs->wedged, memory_order_relaxed)) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_EWEDGED;
    }
    if (atomic_load_explicit(&fs->read_only, memory_order_relaxed)) {
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

/*
 * TLY-A3-keyslot-wrap: the corvus-encrypted-dataset creation path —
 * the provisioning counterpart of stm_fs_create_dataset (see fs.h for
 * the contract). Simpler than the sibling: no mount-time wrap source
 * to load (the per-dataset DEK is sealed by corvus, supplied via the
 * `corvus` cfg per call), so there is no keyfile / janus lifecycle to
 * wind up + tear down. stm_sync_add_dataset_key_corvus performs the
 * WRAP (a corvus network round-trip) under sync's lock; fs->global is
 * held EX across it — the same posture stm_fs_create_dataset already
 * has for the janus-wrap network round-trip, and dataset creation is
 * a rare operation.
 */
stm_status stm_fs_create_dataset_corvus(stm_fs *fs, uint64_t parent_id,
                                           const char *name,
                                           const char *corvus_dataset_path,
                                           size_t corvus_dataset_path_len,
                                           const stm_corvus_mount_cfg *corvus,
                                           uint64_t *out_id)
{
    if (!fs || !name || !corvus_dataset_path || !corvus || !out_id)
        return STM_EINVAL;
    /* Path validation (length, control bytes, embedded NUL) and
     * token-presence validation are delegated to
     * stm_sync_add_dataset_key_corvus -> validate_corvus_path, which
     * refuse STM_EINVAL on any violation. */

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        /* sync_open always populates the dataset index; a NULL here
         * means sync-internal corruption — surface it rather than
         * dereferencing. */
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    uint64_t new_id = 0;
    stm_status s = stm_dataset_create_child(didx, parent_id, name, &new_id);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return s;
    }

    uint64_t new_kid = 0;
    s = stm_sync_add_dataset_key_corvus(fs->sync, new_id,
                                           corvus_dataset_path,
                                           corvus_dataset_path_len,
                                           corvus, &new_kid);
    if (s != STM_OK) {
        /* Roll back the freshly-created leaf. Infallible for a
         * non-root, no-children, PRESENT id minted under fs->global
         * (the dataset module's three documented destroy failure
         * modes — root-id, not-PRESENT, has-children — are all
         * unreachable here); same argument as stm_fs_create_dataset's
         * R45 P3-2 rollback. */
        (void)stm_dataset_destroy(didx, new_id);
        pthread_rwlock_unlock(&fs->global);
        return s;
    }

    *out_id = new_id;
    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
}

/* ========================================================================= */
/* Clones (9.7-impl-6e).                                                      */
/* ========================================================================= */

stm_status stm_fs_create_clone(stm_fs *fs, uint64_t parent_id,
                                  const char *name,
                                  uint64_t origin_snap_id,
                                  uint64_t *out_clone_id)
{
    if (!fs || !name || !out_clone_id) return STM_EINVAL;
    if (parent_id == 0) return STM_EINVAL;
    if (origin_snap_id == STM_DATASET_NO_ORIGIN) return STM_EINVAL;
    *out_clone_id = 0;

    /* Wrap-key source — same R45 P2-1 binding as stm_fs_create_dataset. */
    int have_kf = fs->keyfile_path != NULL;
    int have_jn = fs->janus_socket != NULL;
    if (have_kf == have_jn) return STM_ECORRUPT;

    stm_hybrid_keys   wk    = {0};
    stm_janus_client *janus = NULL;
    if (have_kf) {
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
    if (atomic_load_explicit(&fs->wedged, memory_order_relaxed)) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_EWEDGED;
    }
    if (atomic_load_explicit(&fs->read_only, memory_order_relaxed)) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_EROFS;
    }

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!didx || !sidx) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return STM_ECORRUPT;
    }

    /* Resolve the origin snap — must be PRESENT (else STM_ENOENT). The
     * lookup captures the snap's (tree_root_paddr, root_gen, root_csum)
     * triple, which we will stamp into the clone's slot below. */
    stm_snapshot_entry origin;
    stm_status s = stm_snapshot_lookup(sidx, origin_snap_id, &origin);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    /* Mint the clone dataset entry. stm_dataset_create_clone refuses
     * STM_EINVAL on origin == about-to-be-allocated id (self-reference),
     * STM_ENOENT on parent-not-PRESENT, STM_EEXIST on sibling-name
     * collision, STM_EOVERFLOW on counter saturation, STM_ENOMEM on
     * alloc failure. On success: present=true, origin_snap_id stamped,
     * di_tree_root triple all-zero (the next step swaps it). */
    uint64_t new_id = 0;
    s = stm_dataset_create_clone(didx, parent_id, name, origin_snap_id,
                                    &new_id);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    /* Hold the origin snap so it stays PRESENT for the clone's lifetime.
     * The clone_check_cb installed at mount ALSO gates delete on
     * "any PRESENT clone references this snap", but the explicit hold
     * is defense-in-depth + a clean rollback signal (if hold succeeds
     * then we know we own a release we can pair with on rollback). */
    s = stm_snapshot_hold(sidx, origin_snap_id);
    if (s != STM_OK) {
        /* Origin snap deleted between lookup + hold under our EX lock
         * is impossible (snapshot mutators take EX); a hold failure is
         * therefore STM_ECORRUPT or an unexpected internal error. Roll
         * back the freshly-created clone. */
        (void)stm_dataset_destroy(didx, new_id);
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    /* Stamp the origin snap's captured triple into the clone's slot
     * (the share-root mechanism per phase-9.7-design.md §9.1.2). The
     * clone's next engine open will then create no fresh tree but open
     * AT the origin's captured root — the engine's COW machinery will
     * COW every diverged node on first mutation. set_engine_root
     * refuses STM_EBUSY if a commit-flush is pending on the slot; that
     * cannot happen on a freshly-created PRESENT slot (no engine has
     * opened it yet). */
    s = stm_dataset_index_set_engine_root(didx, new_id,
                                             origin.tree_root_paddr,
                                             origin.root_gen,
                                             origin.root_csum);
    if (s != STM_OK) {
        (void)stm_snapshot_release(sidx, origin_snap_id);
        (void)stm_dataset_destroy(didx, new_id);
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    /* Provision the clone's per-dataset DEK (§9.1.3). The clone's new
     * writes will stamp the clone's key_id; reads of shared extents
     * use the origin's stamped key_id via the pool-global keyschema. */
    uint64_t new_kid = 0;
    s = stm_sync_add_dataset_key(fs->sync, new_id,
                                    have_kf ? &wk : NULL,
                                    have_jn ? janus : NULL,
                                    &new_kid);
    if (s != STM_OK) {
        (void)stm_snapshot_release(sidx, origin_snap_id);
        (void)stm_dataset_destroy(didx, new_id);
        pthread_rwlock_unlock(&fs->global);
        stm_hybrid_keys_wipe(&wk);
        if (janus) stm_janus_client_disconnect(janus);
        return s;
    }

    *out_clone_id = new_id;
    pthread_rwlock_unlock(&fs->global);
    stm_hybrid_keys_wipe(&wk);
    if (janus) stm_janus_client_disconnect(janus);
    return STM_OK;
}

stm_status stm_fs_promote_clone(stm_fs *fs, uint64_t clone_dataset_id)
{
    if (!fs) return STM_EINVAL;
    if (clone_dataset_id == 0) return STM_EINVAL;
    /* v1.0 stub — phase-9.7-design.md §9.1.4. Promote requires the
     * ARCH §8.6.2 snap-chain reshuffling (the snap that was the origin
     * becomes a "descendant of the clone") + per-block-birth deadlist
     * tracking to keep shared paddrs sound across the chain reversal.
     * Deferred to v1.x; this stub surfaces the surface so callers can
     * adopt the API once the v1.x mechanism lands. */
    return STM_ENOTSUPPORTED;
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

    /* 9.8-LF-3c: wait-free dataset property read. The dataset index has
     * its own internal mutex; the read is atomic per-call without
     * holding fs->global. EX mutators (stm_fs_create_dataset, set/clear
     * property) still take fs->global EX AND the dataset index's
     * internal mutex — the table-level mutex provides the cross-EX-mutator
     * serialization. */
    FS_GUARD_READ_LOCKLESS(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) return STM_ECORRUPT;

    return stm_dataset_effective_property(didx, dataset_id, prop, out_value);
}

/* P9-CTL-1c read-side wrappers: /ctl/datasets/ and similar consumers
 * need to enumerate, look up, and count datasets without piercing
 * fs's encapsulation via the test-only fs_testing.h chain.
 *
 * 9.8-LF-3c: wait-free against fs->global. The dataset index has its
 * own internal mutex so each call is atomic at the table layer. For
 * stm_fs_dataset_iter, the user-supplied callback runs WITH dataset
 * index's internal lock held — the callback MUST NOT call back into
 * any stm_fs_* API that touches the dataset index (would deadlock).
 * Typical usage (the /ctl/ readdir builder) only formats the entry
 * into a buffer and emits dirents, which is safe. */
stm_status stm_fs_dataset_lookup(stm_fs *fs, uint64_t dataset_id,
                                    stm_dataset_entry *out)
{
    if (out) memset(out, 0, sizeof *out);
    if (!fs || !out) return STM_EINVAL;

    FS_GUARD_READ_LOCKLESS(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) return STM_ECORRUPT;
    return stm_dataset_lookup(didx, dataset_id, out);
}

stm_status stm_fs_dataset_count(stm_fs *fs, size_t *out_count)
{
    if (out_count) *out_count = 0;
    if (!fs || !out_count) return STM_EINVAL;

    FS_GUARD_READ_LOCKLESS(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) return STM_ECORRUPT;
    return stm_dataset_count(didx, out_count);
}

stm_status stm_fs_dataset_iter(stm_fs *fs, stm_dataset_iter_cb cb, void *ctx)
{
    if (!fs || !cb) return STM_EINVAL;

    FS_GUARD_READ_LOCKLESS(fs);

    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) return STM_ECORRUPT;
    return stm_dataset_iter(didx, cb, ctx);
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

    /* 9.8-LF-3c: wait-free + wedged-OK (matches stm_fs_stats_get).
     * stm_sync_alloc returns a pointer that is valid for the lifetime
     * of the mount: v2.0 has single-mutator attach (sync_create at
     * mount + serial-accept at the daemon), so the pointer is stable.
     * Forward-note (carries R102): future concurrent-attach-mutation
     * paths MUST EITHER add per-call refcounting on stm_alloc OR
     * extend this wrapper to take the attach-table mutex. */
    stm_alloc *a = stm_sync_alloc(fs->sync, device_id);
    if (!a) return STM_ENOENT;
    return stm_alloc_stats_get(a, out);
}

/* R102 P3-1: lightweight is-attached predicate. Same posture as
 * stm_fs_alloc_stats_get. */
stm_status stm_fs_alloc_attached(const stm_fs *fs, uint16_t device_id,
                                    bool *out)
{
    if (out) *out = false;
    if (!fs || !out) return STM_EINVAL;
    if (device_id >= STM_POOL_DEVICES_MAX) return STM_EINVAL;

    stm_alloc *a = stm_sync_alloc(fs->sync, device_id);
    *out = (a != NULL);
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

    /* R105 P3-2 gate (R159 P2: BEFORE the commit): validate that
     * dataset_id names a PRESENT dataset. The underlying snapshot.c
     * uses dataset_id as an opaque bucket-key without lookup, so
     * without this gate a non-/ctl/ caller (CLI, FUSE, direct
     * embedder) could create an orphan snapshot record keyed at a
     * never-registered dataset_id. The /ctl/ vops_walk + vops_open
     * paths already pre-validate; this is defense-in-depth at the
     * public-API trust boundary.
     *
     * R159 P2: the gate runs BEFORE the stm_sync_commit below so an
     * invalid dataset_id fails with NO durable side effect (parity
     * with pre-9.7-impl-3). Committing first would force a pool-wide
     * three-phase commit + uberblock write + fsync before returning
     * STM_ENOENT — a wear/IOPS-amplification hazard on the public
     * API and a surprising "failed op bumped fs->gen". */
    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }
    {
        stm_dataset_entry de_gate;
        stm_status pgrc = stm_dataset_lookup(didx, dataset_id, &de_gate);
        if (pgrc != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            return pgrc;     /* STM_ENOENT for a missing dataset */
        }
        /* 9.7-impl-6e: snap-of-clone refusal — phase-9.7-design.md
         * §9.1.4. Taking a snapshot of a clone needs per-block-birth
         * deadlist tracking (the clone's tree shares blocks with the
         * origin snap; a naive snap of the clone would either
         * double-count those blocks in dead-lists or fail to reclaim
         * post-snap divergence correctly). Deferred to v1.x; v1.0
         * refuses STM_ENOTSUPPORTED. The gate runs BEFORE
         * stm_sync_commit so a refused snap-of-clone has NO durable
         * side effect (R160 P1-1 doctrine — same posture as the
         * presence gate above). */
        if (de_gate.origin_snap_id != STM_DATASET_NO_ORIGIN) {
            pthread_rwlock_unlock(&fs->global);
            return STM_ENOTSUPPORTED;
        }
    }

    /* 9.7-impl-3: commit the per-dataset engine cascade so the
     * dataset's (di_tree_root, di_root_gen, di_root_csum) triple is
     * DURABLE and reflects the just-flushed writes. A snapshot must
     * capture a *recoverable* root — the pre-commit di_tree_root is
     * stale (the previous commit's root, or all-zero for a never-
     * committed dataset). The three-phase sync_commit makes each
     * dataset engine's root durable and re-stamps every dataset
     * entry's triple; the post-commit stm_dataset_lookup below then
     * reads the fresh values.
     *
     * R154 Q2: a failed stm_sync_commit is crash-equivalent (the
     * engines' three-phase abort dropped the in-memory trees), so we
     * wedge the fs — mirroring stm_fs_commit. The wedge is deferred
     * past the unlock since stm_fs_mark_wedged itself takes
     * fs->global. */
    {
        stm_status cr = stm_sync_commit(fs->sync);
        if (cr != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            stm_fs_mark_wedged(fs);
            return cr;
        }
    }

    /* 9.7-impl-3 capture: re-look-up the dataset entry AFTER the
     * commit so its triple reflects the committed engine root. The
     * dataset table cannot change between the gate above and here —
     * fs->global wrlock is held continuously and dataset-table
     * mutators are EX-takers — so this re-lookup is purely to pick
     * up the post-commit triple. */
    stm_dataset_entry de;
    stm_status drc = stm_dataset_lookup(didx, dataset_id, &de);
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
    /* 9.7-impl-3: capture the dataset's real committed engine-root
     * triple. An all-zero triple (a never-written dataset) is a
     * valid "empty dataset" snapshot — the snapshot module stores
     * the triple opaquely; stm_btree_engine_open validates it at
     * the consuming chunks (9.7-impl-4 rollback / 9.7-impl-5
     * readable .snaps). */
    stm_status s = stm_snapshot_create(sidx, dataset_id, nbuf,
                                          de.di_tree_root,
                                          de.di_root_gen,
                                          de.di_root_csum,
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
    /* 9.7-impl-2-routing: also consume the engine NODE (bootstrap-tier)
     * dead-list. Those paddrs are unknown to stm_alloc; they're routed
     * through stm_bootstrap_free per device below. */
    uint64_t *freed_boot = NULL;
    size_t freed_boot_n  = 0;
    stm_status del = stm_snapshot_delete(sidx, snapshot_id,
                                            &freed, &freed_n,
                                            &cold_hashes, &cold_n,
                                            &freed_boot, &freed_boot_n);
    if (del != STM_OK) {
        /* Snapshot.h contract: on non-OK return, ALL pairs are zero/NULL.
         * Defensive free anyway. */
        free(freed);
        free(cold_hashes);
        free(freed_boot);
        pthread_rwlock_unlock(&fs->global);
        return del;
    }

    if (out_freed_count) *out_freed_count = freed_n + freed_boot_n;

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

    /* 9.7-impl-2-routing: route bootstrap-tier paddrs through the
     * per-device bootstrap allocator (reached via
     * `stm_alloc_bootstrap(stm_sync_alloc(fs->sync, did))`). These
     * are engine NODE paddrs (16-KiB bootstrap reservations); each is
     * returned to the bootstrap deferred-free pool at `free_gen`. */
    for (size_t i = 0; i < freed_boot_n; i++) {
        uint16_t did = stm_paddr_device(freed_boot[i]);
        stm_alloc *a = stm_sync_alloc(fs->sync, did);
        if (!a) {
            if (first_err == STM_OK) first_err = STM_ENOENT;
            continue;
        }
        stm_bootstrap *boot = stm_alloc_bootstrap(a);
        if (!boot) {
            if (first_err == STM_OK) first_err = STM_ENOENT;
            continue;
        }
        stm_status fr = stm_bootstrap_free(boot, freed_boot[i],
                                              STM_BOOTSTRAP_NODE_BLOCKS,
                                              free_gen);
        if (fr != STM_OK && first_err == STM_OK) first_err = fr;
    }

    free(freed);
    free(cold_hashes);
    free(freed_boot);
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

/* TLY-A5 / R146 P2-1+P2-2: shared body for mark (set=true) /
 * unmark (set=false). Resolves snapshot_id, binds it to dataset_id
 * (cross-dataset → STM_ENOENT), toggles the marker, and reports
 * whether the bit actually changed so the caller can skip a needless
 * commit and revert cleanly on commit failure. */
static stm_status fs_set_snapshot_compromised(stm_fs *fs,
                                                uint64_t dataset_id,
                                                uint64_t snapshot_id,
                                                bool set,
                                                bool *out_changed)
{
    if (out_changed) *out_changed = false;
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0 || snapshot_id == 0) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    /* Resolve + dataset-bind the target. The snapshot index is
     * pool-global; refuse a snapshot that lives in a different
     * dataset than the one the caller addressed (R146 P2-2). */
    stm_snapshot_entry entry;
    stm_status s = stm_snapshot_lookup(sidx, snapshot_id, &entry);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return s;
    }
    if (entry.dataset_id != dataset_id) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ENOENT;
    }

    bool was_set =
        (entry.flags & STM_SNAP_FLAG_ROLLBACK_COMPROMISED) != 0;
    s = set ? stm_snapshot_mark_compromised(sidx, snapshot_id)
            : stm_snapshot_unmark_compromised(sidx, snapshot_id);
    if (s == STM_OK && out_changed)
        *out_changed = (was_set != set);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_mark_snapshot_compromised(stm_fs *fs, uint64_t dataset_id,
                                              uint64_t snapshot_id,
                                              bool *out_changed)
{
    return fs_set_snapshot_compromised(fs, dataset_id, snapshot_id,
                                          true, out_changed);
}

stm_status stm_fs_unmark_snapshot_compromised(stm_fs *fs, uint64_t dataset_id,
                                                uint64_t snapshot_id,
                                                bool *out_changed)
{
    return fs_set_snapshot_compromised(fs, dataset_id, snapshot_id,
                                          false, out_changed);
}

/* TLY-A5b: runtime DEK install / evict (per-user encrypted home).
 * fs->global EX serializes the sync-layer DEK-map mutation against the
 * rest of the fs, matching every other fs mutator. The install's corvus
 * UNWRAP round-trip runs under EX -- acceptable because the /ctl/ driver
 * already serializes DEK lifecycle ops on its own lease lock and logins
 * are console-paced (see src/ctl/synfs.c). */
stm_status stm_fs_install_dek(stm_fs *fs, uint64_t dataset_id,
                                const stm_corvus_mount_cfg *corvus)
{
    if (!fs) return STM_EINVAL;
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_sync_install_dek(fs->sync, dataset_id, corvus);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

stm_status stm_fs_evict_dek(stm_fs *fs, uint64_t dataset_id)
{
    if (!fs) return STM_EINVAL;
    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);
    stm_status s = stm_sync_evict_dek(fs->sync, dataset_id);
    pthread_rwlock_unlock(&fs->global);
    return s;
}

/* ========================================================================= */
/* 9.7-impl-4b: rollback metadata-node reclamation.                            */
/* ========================================================================= */

/* A growable paddr set — the collector sink for one engine tree's node
 * + spill-block walk. `oom` records a push that hit ENOMEM: the set is
 * then INCOMPLETE and MUST NOT inform a free decision — an incomplete
 * snap-side set would mis-classify a shared node as diverged. */
typedef struct {
    uint64_t *v;
    size_t    n;
    size_t    cap;
    bool      oom;
} fs_rb_paddr_set;

/* stm_btree_engine_paddr_cb — append `paddr`, doubling on demand. A
 * nonzero return aborts the walk (ENOMEM only). */
static int fs_rb_paddr_collect_cb(uint64_t paddr, void *ctx)
{
    fs_rb_paddr_set *set = ctx;
    if (set->n == set->cap) {
        size_t ncap = set->cap ? set->cap * 2u : 128u;
        /* R161 P3-1: overflow guard — route an oversize grow through the
         * same `oom` "set incomplete, free nothing" signal. Cosmetic
         * defense-in-depth; unreachable in practice (the engine-node
         * count is bounded far below SIZE_MAX / 8 by the device size). */
        if (ncap > SIZE_MAX / sizeof *set->v) { set->oom = true; return 1; }
        uint64_t *g = realloc(set->v, ncap * sizeof *g);
        if (!g) { set->oom = true; return 1; }   /* stop the walk */
        set->v   = g;
        set->cap = ncap;
    }
    set->v[set->n++] = paddr;
    return 0;
}

static int fs_rb_paddr_cmp(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/*
 * Reclaim the pre-rollback live tree's metadata-node divergence — every
 * engine NODE / large-value spill-chain block reachable from the OLD
 * live root but NOT from the snapshot's frozen root. Those blocks were
 * COW'd onto live AFTER the snapshot was taken; once the dataset entry
 * is swapped to the snapshot root nothing references them.
 *
 * SPEC: dead_list.tla::Rollback — the boot-tier projection of the
 *       live-divergence term `live_blocks \ snap_view_blocks[s]`. The
 *       data-extent (stm_alloc) + cold-extent (CAS) tiers are reclaimed
 *       by the sibling fs_rollback_reclaim_diverged_extents (4c) +
 *       fs_rollback_reclaim_diverged_cold (4c-ii); the snapshot's own
 *       cleared dead-list garbage stays forward-noted to 9.7-impl-4c-iii.
 *
 * SAFETY (load-bearing): a block is freed ONLY when it is in old_set
 * AND NOT in snap_set AND BOTH walks completed in full. Incremental COW
 * SHARES every unchanged subtree between the two trees — the shared
 * nodes ARE the snapshot's tree after the swap, so freeing one would
 * corrupt the rolled-back dataset. If either walk fails or is truncated
 * (ENOMEM / STM_ECORRUPT / device error) NOTHING is freed.
 *
 * Correct ONLY because the caller already refused the rollback when a
 * newer snapshot of the dataset exists: with `s` the most-recent
 * snapshot, every block reachable-from-old-live-but-not-from-`s` was
 * allocated AFTER `s` (incremental COW only ever writes fresh paddrs),
 * so no older snapshot can reference it. Lifting the newer-snapshot
 * refusal (9.7-impl-4d) needs the `\ newer_dead` filter
 * dead_list.tla::Rollback also carries.
 *
 * BEST-EFFORT: any walk / collect / per-paddr free failure leaves the
 * unreclaimed remainder LEAKED — a space cost, never a corruption (a
 * leaked block stays ALLOCATED, so the allocator never reissues it and
 * the AEAD (paddr, write_gen) nonce stays unique — exactly impl-4's
 * full-leak posture). The rollback itself still succeeds.
 *
 * Freed paddrs are bootstrap-class (engine NODE reservations); each is
 * routed to its device's bootstrap deferred-free pool at the sync's
 * current gen — exactly stm_fs_delete_snapshot's freed_boot loop. The
 * caller's stm_sync_commit persists the frees; the strict
 * `free_gen < committed_gen` predicate (R50 P2-1) keeps the block out
 * of reuse until a later commit, so no (paddr, write_gen) is reissued.
 *
 * Caller holds fs->global EX.
 */
static void fs_rollback_reclaim_diverged_nodes(
        stm_fs *fs, stm_dataset_index *didx, uint64_t dataset_id,
        uint64_t old_paddr, uint64_t old_gen, const uint8_t old_csum[32],
        uint64_t snap_paddr, uint64_t snap_gen, const uint8_t snap_csum[32])
{
    fs_rb_paddr_set old_set  = {0};
    fs_rb_paddr_set snap_set = {0};

    /* Snapshot tree first: an incomplete snap_set must abort the whole
     * reclaim — a missing snap paddr would mis-classify a shared node
     * as diverged and free live storage. */
    stm_status w = stm_dataset_index_collect_engine_paddrs_at(
            didx, dataset_id, snap_paddr, snap_gen, snap_csum,
            fs_rb_paddr_collect_cb, &snap_set);
    if (w != STM_OK || snap_set.oom) goto done;

    w = stm_dataset_index_collect_engine_paddrs_at(
            didx, dataset_id, old_paddr, old_gen, old_csum,
            fs_rb_paddr_collect_cb, &old_set);
    if (w != STM_OK || old_set.oom) goto done;

    /* old \ snap via a sorted merge — sorting old_set too dedups it
     * (defence against a corrupt tree presenting one paddr twice,
     * which would otherwise double-free). */
    /* Skip the sort for an empty / single-element set — already sorted,
     * and it keeps a NULL base out of qsort (strict-C-clean; R163 P3-2). */
    if (snap_set.n > 1)
        qsort(snap_set.v, snap_set.n, sizeof *snap_set.v, fs_rb_paddr_cmp);
    if (old_set.n > 1)
        qsort(old_set.v,  old_set.n,  sizeof *old_set.v,  fs_rb_paddr_cmp);

    uint64_t free_gen = stm_sync_current_gen(fs->sync);
    size_t   j = 0;
    for (size_t i = 0; i < old_set.n; i++) {
        uint64_t p = old_set.v[i];
        if (i > 0 && p == old_set.v[i - 1]) continue;       /* dedup */
        while (j < snap_set.n && snap_set.v[j] < p) j++;
        if (j < snap_set.n && snap_set.v[j] == p) continue; /* shared — KEEP */

        /* p is diverged: bootstrap-class, per-device routed. A free
         * failure (device gone / no bootstrap) leaks p — best-effort,
         * continue. */
        uint16_t did = stm_paddr_device(p);
        stm_alloc *a = stm_sync_alloc(fs->sync, did);
        if (!a) continue;
        stm_bootstrap *boot = stm_alloc_bootstrap(a);
        if (!boot) continue;
        (void)stm_bootstrap_free(boot, p, STM_BOOTSTRAP_NODE_BLOCKS, free_gen);
    }

done:
    free(old_set.v);
    free(snap_set.v);
}

/*
 * 9.7-impl-4c: reclaim the pre-rollback live tree's DATA-extent
 * divergence — every HOT-extent replica block (stm_alloc class)
 * referenced by the OLD live tree's EXTENT keyspace but NOT by the
 * snapshot's. Those data blocks were allocated for writes that landed
 * AFTER the snapshot was taken; once the dataset entry is swapped to
 * the snapshot root nothing references them.
 *
 * SPEC: dead_list.tla::Rollback — the data-tier projection of the
 *       live-divergence term `live_blocks \ snap_view_blocks[s]`. The
 *       siblings fs_rollback_reclaim_diverged_nodes (9.7-impl-4b)
 *       cover the metadata-NODE (bootstrap) tier and
 *       fs_rollback_reclaim_diverged_cold (9.7-impl-4c-ii) the
 *       COLD-extent (CAS) tier. Still leaked, forward-noted: the
 *       snapshot's cleared dead-list garbage — 9.7-impl-4c-iii.
 *
 * SAFETY (load-bearing): a paddr is freed ONLY when it is in old_set
 * AND NOT in snap_set AND BOTH walks completed in full — identical to
 * fs_rollback_reclaim_diverged_nodes. A paddr a HOT extent reflink-
 * SHARES across the snapshot boundary is referenced by a snapshot-tree
 * extent, so it lands in snap_set and is excluded — the set-difference
 * handles cohabitation. Sorting old_set dedups it, so a paddr two
 * reflink-siblings in the OLD tree share is freed at most once (a
 * double stm_alloc_free would corrupt the allocator). If either walk
 * fails or is truncated NOTHING is freed.
 *
 * Correct ONLY because the caller already refused the rollback when a
 * newer snapshot of the dataset exists — see the matching note on
 * fs_rollback_reclaim_diverged_nodes.
 *
 * BEST-EFFORT: any walk / collect / per-paddr free failure leaves the
 * unreclaimed remainder LEAKED — a space cost, never a corruption (a
 * leaked block stays ALLOCATED, so the allocator never reissues it and
 * the AEAD (paddr, write_gen) nonce stays unique).
 *
 * Freed paddrs are data-area (stm_alloc class) — each is routed to its
 * device's allocator deferred-free pool at the sync's current gen
 * (exactly stm_fs_delete_snapshot's paddr-tier free loop). The caller's
 * stm_sync_commit persists the frees; the strict
 * `free_gen < committed_gen` predicate (R50 P2-1) keeps the block out
 * of reuse until a later commit, so no (paddr, write_gen) is reissued.
 *
 * Caller holds fs->global EX.
 */
static void fs_rollback_reclaim_diverged_extents(
        stm_fs *fs, stm_extent_index *eidx, uint64_t dataset_id,
        uint64_t old_paddr, uint64_t old_gen, const uint8_t old_csum[32],
        uint64_t snap_paddr, uint64_t snap_gen, const uint8_t snap_csum[32])
{
    fs_rb_paddr_set old_set  = {0};
    fs_rb_paddr_set snap_set = {0};

    /* Snapshot tree first: an incomplete snap_set must abort the whole
     * reclaim — a missing snap paddr would mis-classify a shared data
     * block as diverged and free live storage. */
    stm_status w = stm_extent_index_collect_engine_data_paddrs_at(
            eidx, dataset_id, snap_paddr, snap_gen, snap_csum,
            fs_rb_paddr_collect_cb, &snap_set);
    if (w != STM_OK || snap_set.oom) goto done;

    w = stm_extent_index_collect_engine_data_paddrs_at(
            eidx, dataset_id, old_paddr, old_gen, old_csum,
            fs_rb_paddr_collect_cb, &old_set);
    if (w != STM_OK || old_set.oom) goto done;

    /* old \ snap via a sorted merge — sorting old_set too dedups it
     * (a paddr two reflink-siblings in the old tree share, or a corrupt
     * tree presenting one paddr twice, would otherwise double-free).
     * R162 P3-1: the dedup trades a refcount-exact free for double-free
     * safety. stm_alloc_free is refcount-aware (one call = one decrement);
     * a paddr N reflink-siblings WITHIN the old tree share carries
     * allocator refcount N, and the single dedup'd free leaves it at
     * N-1 — an under-free. That is a phantom-refcount LEAK, never a
     * corruption (the block stays allocated, so never reissued, so the
     * AEAD nonce stays unique), and it is covered by this function's
     * BEST-EFFORT posture. A refcount-exact reclaim would need the same
     * counted-multiset machinery the cold-extent tier needs — forward-
     * noted to 9.7-impl-4c-ii alongside the CAS-refcount work. */
    /* Skip the sort for an empty / single-element set — already sorted,
     * and it keeps a NULL base out of qsort (strict-C-clean; R163 P3-2). */
    if (snap_set.n > 1)
        qsort(snap_set.v, snap_set.n, sizeof *snap_set.v, fs_rb_paddr_cmp);
    if (old_set.n > 1)
        qsort(old_set.v,  old_set.n,  sizeof *old_set.v,  fs_rb_paddr_cmp);

    uint64_t free_gen = stm_sync_current_gen(fs->sync);
    size_t   j = 0;
    for (size_t i = 0; i < old_set.n; i++) {
        uint64_t p = old_set.v[i];
        if (i > 0 && p == old_set.v[i - 1]) continue;       /* dedup */
        while (j < snap_set.n && snap_set.v[j] < p) j++;
        if (j < snap_set.n && snap_set.v[j] == p) continue; /* shared — KEEP */

        /* p is diverged: data-area, per-device routed. A free failure
         * (device gone) leaks p — best-effort, continue. */
        uint16_t did = stm_paddr_device(p);
        stm_alloc *a = stm_sync_alloc(fs->sync, did);
        if (!a) continue;
        (void)stm_alloc_free(a, p, free_gen);
    }

done:
    free(old_set.v);
    free(snap_set.v);
}

/* A growable COLD-extent-record set — the collector sink for one
 * engine tree's EXTENT-keyspace walk. `oom` records a push that hit
 * ENOMEM: the set is then INCOMPLETE and MUST NOT inform a deref
 * decision — an incomplete snap-side set would mis-classify a shared
 * cold record as diverged and OVER-deref its CAS hash. */
typedef struct {
    stm_extent_cold_ref *v;
    size_t               n;
    size_t               cap;
    bool                 oom;
} fs_rb_cold_set;

/* stm_extent_cold_record_cb — append `rec`, doubling on demand. A
 * nonzero return aborts the walk (ENOMEM only). */
static int fs_rb_cold_collect_cb(const stm_extent_cold_ref *rec, void *ctx)
{
    fs_rb_cold_set *set = ctx;
    if (set->n == set->cap) {
        size_t ncap = set->cap ? set->cap * 2u : 64u;
        if (ncap > SIZE_MAX / sizeof *set->v) { set->oom = true; return 1; }
        stm_extent_cold_ref *g = realloc(set->v, ncap * sizeof *g);
        if (!g) { set->oom = true; return 1; }   /* stop the walk */
        set->v   = g;
        set->cap = ncap;
    }
    set->v[set->n++] = *rec;
    return 0;
}

/* qsort comparator — order cold refs by (ino, off) ascending. */
static int fs_rb_cold_cmp(const void *a, const void *b)
{
    const stm_extent_cold_ref *x = a, *y = b;
    if (x->ino != y->ino) return (x->ino > y->ino) - (x->ino < y->ino);
    return (x->off > y->off) - (x->off < y->off);
}

/*
 * 9.7-impl-4c-ii: reclaim the pre-rollback live tree's COLD-extent
 * divergence — the CAS refcount every COLD extent record reachable
 * from the OLD live tree's EXTENT keyspace but NOT from the snapshot's
 * holds. Those cold records were created for migrations / cold writes
 * that landed AFTER the snapshot was taken; once the dataset entry is
 * swapped to the snapshot root nothing references them, so the one
 * stm_cas_ref each took at creation must be released.
 *
 * SPEC: dead_list.tla::Rollback — the cold-tier projection of the
 *       live-divergence term `live_blocks \ snap_view_blocks[s]`. The
 *       siblings fs_rollback_reclaim_diverged_nodes (9.7-impl-4b,
 *       bootstrap NODE tier) and fs_rollback_reclaim_diverged_extents
 *       (9.7-impl-4c, stm_alloc HOT-replica tier) cover the two
 *       physical-block tiers. With this tier the rollback reclaims the
 *       whole live-divergence; the snapshot's own cleared dead-list
 *       garbage stays forward-noted to 9.7-impl-4c-iii.
 *
 * WHY A PER-KEY STRUCTURAL MERGE, NOT A HASH-COUNT DIFFERENCE.
 * Content-defined dedup lets DISTINCT cold records share a content
 * hash. A reclaim that merely subtracted per-hash occurrence counts
 * ("deref H, max(0, count_old(H) - count_snap(H)) times") is WRONG: a
 * post-snapshot diverged record and an unrelated snapshot record that
 * happen to share hash H cancel each other in the subtraction, leaving
 * the diverged record's refcount un-released — a CAS-refcount leak
 * that compounds across every rollback. The correct unit is the
 * RECORD: walk both trees' EXTENT keyspaces and, for each key, decide
 * shared-vs-diverged structurally.
 *
 * SAFETY (load-bearing): a cold record's hash is dereffed ONLY when
 * the record is in old_set, is NOT the same logical record as a
 * snapshot-tree record at the same (ino, off), AND BOTH walks
 * completed in full. Two COLD records at the same key are the SAME
 * logical record iff their (content_hash, gen, link_gen) identity is
 * byte-identical. link_gen — the gen at which a record entered the
 * live extent index — is the load-bearing separator: snapshot creation
 * forces a commit, so every cold record in the snapshot carries
 * link_gen <= the snapshot's gen, while any post-snapshot (diverged)
 * record entered the index at a strictly higher gen. A shared record
 * therefore ALWAYS matches its snapshot counterpart and is never
 * mis-classified as diverged — this reclaim NEVER over-derefs (which
 * would prematurely GC live cold storage). The only residual failure
 * mode is an under-deref (a leak), consistent with the best-effort
 * posture. If either walk fails or is truncated NOTHING is dereffed.
 *
 * Correct ONLY because the caller already refused the rollback when a
 * newer snapshot of the dataset exists — see the matching note on
 * fs_rollback_reclaim_diverged_nodes.
 *
 * BEST-EFFORT: any walk / collect / per-record deref failure leaves
 * the unreleased remainder as a CAS-refcount leak — a space cost (the
 * cold chunk's storage is never GC'd), never a corruption. The
 * rollback itself still succeeds.
 *
 * The deref drops the CAS entry's refcount; the caller's
 * stm_sync_commit runs the auto-GC sweep that reclaims any entry whose
 * refcount reaches 0 (and routes its chunk paddrs through the
 * allocator) — exactly stm_fs_delete_snapshot's cold-hash path.
 *
 * Caller holds fs->global EX.
 */
static void fs_rollback_reclaim_diverged_cold(
        stm_fs *fs, stm_extent_index *eidx, uint64_t dataset_id,
        uint64_t old_paddr, uint64_t old_gen, const uint8_t old_csum[32],
        uint64_t snap_paddr, uint64_t snap_gen, const uint8_t snap_csum[32])
{
    fs_rb_cold_set old_set  = {0};
    fs_rb_cold_set snap_set = {0};

    /* Snapshot tree first: an incomplete snap_set could mis-classify a
     * shared cold record as diverged and OVER-deref its CAS hash — a
     * premature GC that frees live cold storage. Abort on any
     * incompleteness. */
    stm_status w = stm_extent_index_collect_engine_cold_records_at(
            eidx, dataset_id, snap_paddr, snap_gen, snap_csum,
            fs_rb_cold_collect_cb, &snap_set);
    if (w != STM_OK || snap_set.oom) goto done;

    w = stm_extent_index_collect_engine_cold_records_at(
            eidx, dataset_id, old_paddr, old_gen, old_csum,
            fs_rb_cold_collect_cb, &old_set);
    if (w != STM_OK || old_set.oom) goto done;

    stm_cas_index *cidx = stm_sync_cas_index(fs->sync);
    if (!cidx) goto done;   /* no CAS index attached — nothing to deref */

    /* Skip the sort for an empty / single-element set — already sorted,
     * and it keeps a NULL base out of qsort (strict-C-clean; R163 P3-2). */
    if (snap_set.n > 1)
        qsort(snap_set.v, snap_set.n, sizeof *snap_set.v, fs_rb_cold_cmp);
    if (old_set.n > 1)
        qsort(old_set.v,  old_set.n,  sizeof *old_set.v,  fs_rb_cold_cmp);

    size_t j = 0;
    for (size_t i = 0; i < old_set.n; i++) {
        const stm_extent_cold_ref *o = &old_set.v[i];

        /* Defensive dedup: the extent index holds at most one record
         * per (ino, off), so adjacent-equal keys can only appear in a
         * corrupt tree. Skipping the duplicate errs toward an
         * under-deref (a leak) — never a double-deref (a corruption). */
        if (i > 0 && o->ino == old_set.v[i - 1].ino
                  && o->off == old_set.v[i - 1].off) continue;

        /* Advance the snapshot cursor to o's key. */
        while (j < snap_set.n &&
               (snap_set.v[j].ino < o->ino ||
                (snap_set.v[j].ino == o->ino &&
                 snap_set.v[j].off < o->off))) j++;

        bool shared = false;
        if (j < snap_set.n &&
            snap_set.v[j].ino == o->ino && snap_set.v[j].off == o->off) {
            const stm_extent_cold_ref *sref = &snap_set.v[j];
            /* SAME logical record iff its identity is byte-identical.
             * link_gen is the load-bearing separator (see the function
             * comment); gen + content_hash are compared too so the
             * decision needs no reasoning beyond "identical record". */
            shared = (sref->link_gen == o->link_gen &&
                      sref->gen      == o->gen      &&
                      memcmp(sref->content_hash, o->content_hash,
                             STM_EXTENT_HASH_LEN) == 0);
        }
        if (shared) continue;   /* o survives the rollback — keep */

        /* o is a post-snapshot (diverged) cold record: release the one
         * CAS refcount it took at creation. A deref failure leaks the
         * refcount — best-effort, continue. */
        (void)stm_cas_deref(cidx, o->content_hash);
    }

done:
    free(old_set.v);
    free(snap_set.v);
}

/* qsort comparator — raw 32-byte hash bytes (memcmp order). */
static int fs_rb_hash_cmp_raw(const void *a, const void *b)
{
    return memcmp(a, b, STM_EXTENT_HASH_LEN);
}

/*
 * 9.7-impl-4c-iii: reclaim the snapshot's own cleared dead-list garbage —
 * the second `to_free` term of `dead_list.tla::Rollback`:
 *   `snap_dead[s] \ s_view`.
 *
 * impl-4's `stm_snapshot_clear_dead_lists` empties S's three dead-lists
 * (boot / data / cold) by DISCARD — the rollback can't tell now-live
 * (resurrected) entries from intermediate-COW garbage, so it discharges
 * neither, and the garbage leaks until this reclaim runs. 4c-iii reads
 * each dead-list BEFORE clear_dead_lists fires and reclaims the
 * survivors.
 *
 * WHY THE DEAD-LIST HOLDS NON-S_VIEW GARBAGE.
 * impl-2's snap-aware COW free routes every freed paddr/record through
 * `stm_snapshot_index_overwrite_{block,bootstrap_block,cold_block}`,
 * which always sends to the MOST-RECENT PRESENT snap regardless of
 * whether THAT snap actually references the freed block. With S = the
 * most-recent at rollback time (under impl-4's newer-snapshot refusal),
 * S's dead-list collects EVERY post-S COW free, including both:
 *   (a) blocks/records IN S's view (RESURRECT on rollback — must NOT
 *       be freed/dereffed), and
 *   (b) blocks/records created post-S and freed post-S (intermediate
 *       COW garbage — SHOULD be freed/dereffed).
 *
 * Boot + Data tiers — simple set-difference on paddrs (paddrs are
 * unique IDs; no dedup at this level). For each paddr P on dead_S:
 *   - P ∈ snap_paddr_set  ⇒ case-(a), KEEP (P resurrects in live).
 *   - P ∉ snap_paddr_set  ⇒ case-(b), FREE.
 *
 * Cold tier — per-key structural merge to compute snap_unique[hash]
 * (the multiset of hashes whose snap-tree record at (ino, off) is NOT
 * the same logical record as the old tree's record at the same key —
 * these are the case-(a) entries on the cold dead-list). Then for each
 * unique hash H run the COUNTED subtraction:
 *
 *     deref_count(H) = dead_S_cold(H) − snap_unique(H)       [≥ 0]
 *
 * Why a counted subtraction is SAFE for the cold dead-list (distinct
 * from 4c-ii's live-divergence case): every snap_unique record has a
 * corresponding dead-list entry — its drop fired the snap-aware deref
 * routing while S was most-recent — so `snap_unique(H) ≤ dead_S(H)`
 * always holds per hash. The 4c-ii live-divergence case had no such
 * pairing — an old-tree diverged record and an unrelated snap-tree
 * record could coincide on hash H via content-defined dedup, breaking
 * the counted subtraction; 4c-ii had to use a per-key structural
 * merge for the deref decision itself. HERE the per-key merge is
 * used only to count snap_unique; the deref decision uses the count.
 *
 * SAFETY (load-bearing): a paddr is freed / hash dereffed ONLY when
 *   - boot/data: the dead-list paddr is NOT in the snapshot's
 *     corresponding paddr set AND the snap walk completed in full;
 *   - cold: per-hash deref count is dead_S_cold(H) − snap_unique(H)
 *     AND BOTH the snap-cold + old-cold walks completed in full.
 * If any walk fails / collects ENOMEM, THAT TIER aborts (no freeing
 * / no derefing for the tier) — best-effort, per-tier. The other
 * tiers proceed.
 *
 * BEST-EFFORT: any walk / per-paddr-free / per-hash-deref failure
 * leaves the unreclaimed remainder as a LEAK — paddrs stay allocated
 * (so the allocator never reissues them, AEAD nonce stays unique);
 * cold-hash refcounts stay up (so CAS never auto-GCs the live chunk).
 * A space cost, never a corruption. The rollback itself still
 * succeeds.
 *
 * Freed paddrs ride the SAME stm_sync_commit as the swap; strict
 * `free_gen < committed_gen` (R50 P2-1) keeps the block out of reuse
 * one tick. Dereffed cold hashes feed the commit's CAS auto-GC sweep.
 *
 * Caller holds fs->global EX.
 */
static void fs_rollback_reclaim_cleared_dead_list_garbage(
        stm_fs *fs,
        stm_snapshot_index *sidx,
        stm_dataset_index *didx,
        stm_extent_index *eidx,
        uint64_t dataset_id,
        uint64_t snapshot_id,
        uint64_t old_paddr, uint64_t old_gen, const uint8_t old_csum[32],
        uint64_t snap_paddr, uint64_t snap_gen, const uint8_t snap_csum[32])
{
    uint64_t free_gen = stm_sync_current_gen(fs->sync);

    /* ---------- Boot tier (engine NODE paddrs / stm_bootstrap) -------- */
    uint64_t *dead_boot = NULL;
    size_t    n_dead_boot = 0;
    (void)stm_snapshot_bootstrap_dead_list_get(sidx, snapshot_id,
                                                 &dead_boot, &n_dead_boot);
    if (n_dead_boot > 0) {
        fs_rb_paddr_set snap_nodes = {0};
        stm_status w = stm_dataset_index_collect_engine_paddrs_at(
                didx, dataset_id, snap_paddr, snap_gen, snap_csum,
                fs_rb_paddr_collect_cb, &snap_nodes);
        bool ok = (w == STM_OK && !snap_nodes.oom);
        if (ok && snap_nodes.n > 1) {
            qsort(snap_nodes.v, snap_nodes.n,
                  sizeof *snap_nodes.v, fs_rb_paddr_cmp);
        }
        if (ok) {
            for (size_t i = 0; i < n_dead_boot; i++) {
                uint64_t p = dead_boot[i];
                if (bsearch(&p, snap_nodes.v, snap_nodes.n,
                            sizeof p, fs_rb_paddr_cmp) != NULL)
                    continue;   /* case-(a): resurrects */
                uint16_t did = stm_paddr_device(p);
                stm_alloc *a = stm_sync_alloc(fs->sync, did);
                if (!a) continue;
                stm_bootstrap *boot = stm_alloc_bootstrap(a);
                if (!boot) continue;
                (void)stm_bootstrap_free(boot, p,
                        STM_BOOTSTRAP_NODE_BLOCKS, free_gen);
            }
        }
        free(snap_nodes.v);
    }
    free(dead_boot);

    /* ---------- Data tier (HOT-extent replicas / stm_alloc) ----------- */
    uint64_t *dead_data = NULL;
    size_t    n_dead_data = 0;
    (void)stm_snapshot_dead_list_get(sidx, snapshot_id,
                                       &dead_data, &n_dead_data);
    if (n_dead_data > 0 && eidx) {
        fs_rb_paddr_set snap_data = {0};
        stm_status w = stm_extent_index_collect_engine_data_paddrs_at(
                eidx, dataset_id, snap_paddr, snap_gen, snap_csum,
                fs_rb_paddr_collect_cb, &snap_data);
        bool ok = (w == STM_OK && !snap_data.oom);
        if (ok && snap_data.n > 1) {
            qsort(snap_data.v, snap_data.n,
                  sizeof *snap_data.v, fs_rb_paddr_cmp);
        }
        if (ok) {
            for (size_t i = 0; i < n_dead_data; i++) {
                uint64_t p = dead_data[i];
                if (bsearch(&p, snap_data.v, snap_data.n,
                            sizeof p, fs_rb_paddr_cmp) != NULL)
                    continue;   /* case-(a): resurrects */
                uint16_t did = stm_paddr_device(p);
                stm_alloc *a = stm_sync_alloc(fs->sync, did);
                if (!a) continue;
                (void)stm_alloc_free(a, p, free_gen);
            }
        }
        free(snap_data.v);
    }
    free(dead_data);

    /* ---------- Cold tier (CAS hashes — per-key snap_unique merge) ---- */
    uint8_t *dead_cold = NULL;
    size_t   n_dead_cold = 0;
    (void)stm_snapshot_cold_dead_list_get(sidx, snapshot_id,
                                            &dead_cold, &n_dead_cold);
    if (n_dead_cold > 0 && eidx) {
        fs_rb_cold_set snap_cold = {0};
        fs_rb_cold_set old_cold  = {0};
        stm_status w1 = stm_extent_index_collect_engine_cold_records_at(
                eidx, dataset_id, snap_paddr, snap_gen, snap_csum,
                fs_rb_cold_collect_cb, &snap_cold);
        stm_status w2 = stm_extent_index_collect_engine_cold_records_at(
                eidx, dataset_id, old_paddr,  old_gen,  old_csum,
                fs_rb_cold_collect_cb, &old_cold);
        bool ok = (w1 == STM_OK && !snap_cold.oom
                   && w2 == STM_OK && !old_cold.oom);
        stm_cas_index *cidx = stm_sync_cas_index(fs->sync);
        if (ok && cidx) {
            if (snap_cold.n > 1)
                qsort(snap_cold.v, snap_cold.n,
                      sizeof *snap_cold.v, fs_rb_cold_cmp);
            if (old_cold.n > 1)
                qsort(old_cold.v, old_cold.n,
                      sizeof *old_cold.v, fs_rb_cold_cmp);

            /* Compute snap_unique[]: walk SNAP cold records in (ino,off)
             * order; for each, see whether OLD has the SAME LOGICAL
             * record at the same key. Same-logical = byte-identical
             * (content_hash, gen, link_gen) — the 4c-ii record-identity
             * discriminator. If not the same logical record, the snap
             * record's hash is "unique to snap"; collect into a flat
             * multiset buffer. */
            uint8_t *snap_unique = NULL;
            size_t   n_snap_unique = 0;
            if (snap_cold.n > 0) {
                snap_unique = malloc(snap_cold.n * STM_EXTENT_HASH_LEN);
            }
            if (snap_cold.n == 0 || snap_unique != NULL) {
                size_t oi = 0;
                for (size_t si = 0; si < snap_cold.n; si++) {
                    const stm_extent_cold_ref *sr = &snap_cold.v[si];
                    /* Advance oi past old records with key < sr's. */
                    while (oi < old_cold.n) {
                        const stm_extent_cold_ref *ro = &old_cold.v[oi];
                        if (ro->ino < sr->ino
                            || (ro->ino == sr->ino && ro->off < sr->off)) {
                            oi++;
                        } else {
                            break;
                        }
                    }
                    bool same_logical = false;
                    if (oi < old_cold.n) {
                        const stm_extent_cold_ref *ro = &old_cold.v[oi];
                        if (ro->ino == sr->ino && ro->off == sr->off
                            && ro->link_gen == sr->link_gen
                            && ro->gen      == sr->gen
                            && memcmp(ro->content_hash, sr->content_hash,
                                       STM_EXTENT_HASH_LEN) == 0) {
                            same_logical = true;
                        }
                    }
                    if (!same_logical) {
                        memcpy(&snap_unique[n_snap_unique * STM_EXTENT_HASH_LEN],
                                sr->content_hash, STM_EXTENT_HASH_LEN);
                        n_snap_unique++;
                    }
                }

                /* Sort both flat hash arrays for the merge-walk by hash. */
                if (n_snap_unique > 1) {
                    qsort(snap_unique, n_snap_unique,
                          STM_EXTENT_HASH_LEN, fs_rb_hash_cmp_raw);
                }
                if (n_dead_cold > 1) {
                    qsort(dead_cold, n_dead_cold,
                          STM_EXTENT_HASH_LEN, fs_rb_hash_cmp_raw);
                }

                /* Per-hash merge: for each run-of-equal hashes H in the
                 * dead-list, count the matching run in snap_unique[],
                 * and deref `dead_count − unique_count` (clamped at 0).
                 *
                 * Defense-in-depth clamp at 0: by the snap_unique →
                 * dead_S correspondence proof, unique_count ≤ dead_count
                 * always. A deviation would mean a snap-tree record has
                 * no matching dead-list entry — i.e. an upstream COW
                 * path missed the snap-aware routing. Clamping to 0
                 * preserves the safety (NEVER over-deref) at the cost
                 * of an under-deref (a CAS-refcount leak), consistent
                 * with the best-effort posture. */
                size_t ui = 0, dj = 0;
                while (dj < n_dead_cold) {
                    const uint8_t *H = &dead_cold[dj * STM_EXTENT_HASH_LEN];
                    size_t dj_end = dj + 1;
                    while (dj_end < n_dead_cold
                           && memcmp(&dead_cold[dj_end * STM_EXTENT_HASH_LEN],
                                      H, STM_EXTENT_HASH_LEN) == 0) {
                        dj_end++;
                    }
                    size_t dead_count = dj_end - dj;

                    while (ui < n_snap_unique
                           && memcmp(&snap_unique[ui * STM_EXTENT_HASH_LEN],
                                      H, STM_EXTENT_HASH_LEN) < 0) {
                        ui++;
                    }
                    size_t ui_end = ui;
                    while (ui_end < n_snap_unique
                           && memcmp(&snap_unique[ui_end * STM_EXTENT_HASH_LEN],
                                      H, STM_EXTENT_HASH_LEN) == 0) {
                        ui_end++;
                    }
                    size_t unique_count = ui_end - ui;

                    size_t deref_count = (unique_count <= dead_count)
                                          ? (dead_count - unique_count) : 0;
                    for (size_t k = 0; k < deref_count; k++) {
                        (void)stm_cas_deref(cidx, H);
                    }

                    dj = dj_end;
                    ui = ui_end;
                }
            }
            free(snap_unique);
        }
        free(snap_cold.v);
        free(old_cold.v);
    }
    free(dead_cold);
}

/* 9.7-impl-4d: reclaim the NEWER-SNAPSHOT-CASCADE tier — for each PRESENT
 * snapshot newer than the rollback target, delete it via
 * stm_snapshot_delete and reclaim the surviving (case-(b)) garbage in its
 * three dead-lists. The garbage is the third `to_free` term in
 * dead_list.tla::Rollback: `newer_dead \ s_view`.
 *
 * WHY NEWER SNAPS' DEAD-LISTS HOLD CASE-(a) ENTRIES (not just garbage)
 * — same shape as 4c-iii's target-side argument lifted one chain link:
 * impl-2's snap-aware COW free routes EVERY freed paddr/record to the
 * MOST-RECENT PRESENT snap regardless of whether THAT snap actually
 * references it. So when live (post-s-creation but pre-rollback) COW'd
 * a (ino, off) record whose old value is IN s.view, the freed
 * paddr/record landed in WHATEVER newer snap was most-recent at COW
 * time. After rollback, s.view ⇒ live again — the freed value is
 * resurrected. Its dead-list entry MUST NOT be reclaimed.
 *
 * MECHANISM by tier:
 *
 *   Boot tier — set-difference on PADDRS: walk s.view's bootstrap
 *   (engine NODE + spill) paddr set once via
 *   stm_dataset_index_collect_engine_paddrs_at, sort, then for each
 *   newer snap's boot dead-list reclaim every paddr NOT in s.view's
 *   set. Identical to 4c-iii's boot-tier filter.
 *
 *   Data tier — set-difference on PADDRS: walk s.view's HOT-extent
 *   replica paddr set via stm_extent_index_collect_engine_data_paddrs_at,
 *   sort, then for each newer snap's data dead-list reclaim every
 *   paddr NOT in s.view's set. Identical to 4c-iii's data-tier filter.
 *
 *   Cold tier — per-hash COUNTED subtraction `agg_cold(H) − snap_unique(H)`,
 *   clamped at 0. Why counted (NOT structural-merge): newer-snap
 *   cold dead-lists are streams of HASHES with no (ino, off) attached;
 *   we can only filter at the hash level. The snap_unique(H) count
 *   ("records in s.view whose (ino, off) has different identity in
 *   OLD-live") is identical to 4c-iii's because the OLD-live tree is
 *   the same; the divergence shape is unchanged by the cascade.
 *
 * SAFETY of the cold-tier counted subtraction (R165 P3-1 — refined):
 * snap_unique[H] is the multiset of hashes whose drop fired the
 * snap-aware deref routing. Each such drop went EITHER to the target's
 * cold_dead (case-(1) — the drop happened while the target was
 * most-recent, BEFORE any newer snap existed) OR to some newer snap's
 * cold_dead (case-(2)). agg_cold[H] sums case-(2)(H) plus case-(b)(H)
 * (pure post-newer-snap garbage). Therefore
 *   agg_cold[H] − snap_unique[H] = case-(b)[H] − case-(1)[H].
 * The clamp-at-0 gives `deref = max(0, case-(b) − case-(1))`. This
 * NEVER over-derefs (the absolute correctness invariant we need), but
 * under-derefs by `min(case-(1)[H], case-(b)[H])` — a CAS-refcount
 * leak when case-(1) drops + case-(b) garbage share a hash via
 * content-defined dedup. The leak is a space cost (the CAS entry stays
 * past when it should be GC'd), never a corruption, and is consistent
 * with the best-effort posture. case-(1) drops are themselves the
 * target's own dead-list garbage that 4c-iii already reclaimed
 * (target.cold_dead is cleared by clear_dead_lists), so the leak only
 * persists until the next CAS-refcount scrub.
 *
 * SAFETY (load-bearing): identical posture as the 4b/4c/4c-ii/4c-iii
 * tiers — best-effort, walk-must-complete, NEVER over-deref / over-free.
 * If a walk fails the corresponding tier is skipped entirely (no partial
 * filtering — that would risk freeing case-(a) survivors). If a per-snap
 * stm_snapshot_delete fails THAT SNAP's reclaim is skipped; the
 * remaining snaps in the cascade still process. Leaked paddrs / cold
 * refcounts are a space cost, never a corruption — a leaked paddr stays
 * ALLOCATED so the AEAD-nonce (paddr, write_gen) pair stays unique.
 *
 * R165 P2-1 — CASCADE-FAILURE LATENT CORRUPTION WINDOW (forward-compat):
 * 4b/4c/4c-ii already ran by the time this helper executes. They freed
 * `OLD ∖ s_target.view` paddrs — which INCLUDES paddrs that a newer
 * snap `s_a` references in its frozen tree (a paddr allocated post-s_
 * target but pre-s_a is in s_a.view AND in OLD-live ∖ s_target.view,
 * so 4b/4c freed it). The cascade's `stm_snapshot_delete` of s_a must
 * succeed for s_a's frozen tree to disappear; if it fails best-effort,
 * s_a stays PRESENT and its tree references freed paddrs. The rollback
 * commit advances gen → after the next commit those paddrs become
 * REUSABLE → any later read of s_a's frozen tree decrypts with a stale
 * `(paddr, write_gen)` pair → AEAD verify fails → STM_ECORRUPT on
 * any access to s_a. No nonce REUSE (each (paddr, write_gen) is
 * still unique), but s_a is silently CORRUPTED. **Currently unreachable
 * in production at v2.0** — the only `stm_snapshot_delete` failure
 * modes are STM_EBUSY-on-hold (we pre-validate under fs->global EX, so
 * the hold can't appear between validate and delete) and
 * STM_EBUSY-on-clone (clones don't exist yet). Both gates are tight
 * enough that the failure path is unreachable for v2.0 callers.
 * **Forward-compat hazard** — when 9.7-impl-6 (clones) lands OR a new
 * `stm_snapshot_delete` failure mode is introduced, this window opens.
 * Proper fix at that point: either (a) extend the pre-validate to
 * enumerate every refusable precondition, OR (b) reorder so the
 * cascade-delete happens BEFORE 4b/4c/4c-ii (the spec-faithful order —
 * spec marks newer ABSENT first, then computes to_free against the
 * post-state). (b) is the architectural fix; (a) is the minimum gate.
 * Forward-noted to the impl-6 (clones) chunk.
 *
 * AGGREGATION (cold tier only): newer snaps' cold dead-lists are
 * accumulated into a single agg_cold buffer (one realloc-growth pass),
 * sorted ONCE, then the per-hash merge-walk against snap_unique runs
 * ONCE. This is the COMBINED-newer_dead the spec models (`newer_dead ==
 * UNION { snap_dead[s2] : s2 ∈ newer_snaps }`). Per-snap subtraction
 * would over-deref under cross-snap dedup (snap_unique credit gets
 * applied to each snap's cold_dead independently).
 *
 * ORDERING (cosmetic, not load-bearing): we iterate newer snaps in
 * ascending snapshot_id order — the order stm_snapshot_collect_newer
 * emits. Boot/data tier per-snap reclaim is order-independent
 * (set-difference); the cold-tier aggregation absorbs all snaps before
 * the single subtraction, so ordering doesn't affect the result. The
 * ascending order is the natural one (oldest-newer-first) and matches
 * the spec's per-snap iteration.
 *
 * Caller holds fs->global EX.
 *
 * The caller calls this helper AFTER 4b/4c/4c-ii/4c-iii on the target
 * + clear_dead_lists on the target, BEFORE the stm_sync_commit that
 * makes the rollback durable. All freed-paddr derefs ride the same
 * commit (deferred-free at free_gen = current_gen; the next commit's
 * R50 P2-1 strict `free_gen < committed_gen` predicate gates reuse —
 * so AEAD-nonce (paddr, write_gen) stays unique across the rollback). */
static void fs_rollback_reclaim_newer_snap_cascade(
        stm_fs *fs,
        stm_snapshot_index *sidx,
        stm_dataset_index *didx,
        stm_extent_index *eidx,
        uint64_t dataset_id,
        const uint64_t *newer_snap_ids,
        size_t n_newer,
        uint64_t old_paddr, uint64_t old_gen, const uint8_t old_csum[32],
        uint64_t snap_paddr, uint64_t snap_gen, const uint8_t snap_csum[32])
{
    if (n_newer == 0) return;

    uint64_t free_gen = stm_sync_current_gen(fs->sync);

    /* ---------- Walk s.view paddr sets + (s.view, OLD-live) cold ----- */
    fs_rb_paddr_set snap_nodes = {0};       /* s.view bootstrap */
    fs_rb_paddr_set snap_data  = {0};       /* s.view data */
    fs_rb_cold_set  snap_cold  = {0};       /* s.view cold */
    fs_rb_cold_set  old_cold   = {0};       /* OLD-live cold */
    bool boot_ok = false;
    bool data_ok = false;
    bool cold_ok = false;

    {
        stm_status w = stm_dataset_index_collect_engine_paddrs_at(
                didx, dataset_id, snap_paddr, snap_gen, snap_csum,
                fs_rb_paddr_collect_cb, &snap_nodes);
        boot_ok = (w == STM_OK && !snap_nodes.oom);
        if (boot_ok && snap_nodes.n > 1) {
            qsort(snap_nodes.v, snap_nodes.n,
                  sizeof *snap_nodes.v, fs_rb_paddr_cmp);
        }
    }

    if (eidx) {
        stm_status w = stm_extent_index_collect_engine_data_paddrs_at(
                eidx, dataset_id, snap_paddr, snap_gen, snap_csum,
                fs_rb_paddr_collect_cb, &snap_data);
        data_ok = (w == STM_OK && !snap_data.oom);
        if (data_ok && snap_data.n > 1) {
            qsort(snap_data.v, snap_data.n,
                  sizeof *snap_data.v, fs_rb_paddr_cmp);
        }

        stm_status w1 = stm_extent_index_collect_engine_cold_records_at(
                eidx, dataset_id, snap_paddr, snap_gen, snap_csum,
                fs_rb_cold_collect_cb, &snap_cold);
        stm_status w2 = stm_extent_index_collect_engine_cold_records_at(
                eidx, dataset_id, old_paddr, old_gen, old_csum,
                fs_rb_cold_collect_cb, &old_cold);
        cold_ok = (w1 == STM_OK && !snap_cold.oom
                   && w2 == STM_OK && !old_cold.oom);
        if (cold_ok) {
            if (snap_cold.n > 1)
                qsort(snap_cold.v, snap_cold.n,
                      sizeof *snap_cold.v, fs_rb_cold_cmp);
            if (old_cold.n > 1)
                qsort(old_cold.v, old_cold.n,
                      sizeof *old_cold.v, fs_rb_cold_cmp);
        }
    }

    /* Compute snap_unique (multiset of hashes): walk SNAP cold in
     * (ino, off) order, compare to OLD at same key by identity tuple
     * (content_hash, gen, link_gen). Append hash to snap_unique iff
     * NOT same logical record. Sort snap_unique by hash for the
     * subtraction merge-walk below. Same algorithm as 4c-iii. */
    uint8_t *snap_unique = NULL;
    size_t   n_snap_unique = 0;
    if (cold_ok && snap_cold.n > 0) {
        snap_unique = malloc(snap_cold.n * STM_EXTENT_HASH_LEN);
    }
    if (cold_ok && (snap_cold.n == 0 || snap_unique != NULL)) {
        size_t oi = 0;
        for (size_t si = 0; si < snap_cold.n; si++) {
            const stm_extent_cold_ref *sr = &snap_cold.v[si];
            while (oi < old_cold.n) {
                const stm_extent_cold_ref *ro = &old_cold.v[oi];
                if (ro->ino < sr->ino
                    || (ro->ino == sr->ino && ro->off < sr->off)) {
                    oi++;
                } else {
                    break;
                }
            }
            bool same_logical = false;
            if (oi < old_cold.n) {
                const stm_extent_cold_ref *ro = &old_cold.v[oi];
                if (ro->ino == sr->ino && ro->off == sr->off
                    && ro->link_gen == sr->link_gen
                    && ro->gen      == sr->gen
                    && memcmp(ro->content_hash, sr->content_hash,
                               STM_EXTENT_HASH_LEN) == 0) {
                    same_logical = true;
                }
            }
            if (!same_logical) {
                memcpy(&snap_unique[n_snap_unique * STM_EXTENT_HASH_LEN],
                        sr->content_hash, STM_EXTENT_HASH_LEN);
                n_snap_unique++;
            }
        }
        if (n_snap_unique > 1) {
            qsort(snap_unique, n_snap_unique,
                  STM_EXTENT_HASH_LEN, fs_rb_hash_cmp_raw);
        }
    } else if (cold_ok && snap_unique == NULL && snap_cold.n > 0) {
        /* malloc failure — drop the cold tier wholesale (best-effort). */
        cold_ok = false;
    }

    /* ---------- Aggregate cold-dead across the cascade ---------------- */
    /* Grows via realloc-doubling; the per-snap reclaim still copies each
     * snap's cold buffer into agg, even on a malloc failure (so we don't
     * silently drop the per-snap bytes — the agg array's failure mode is
     * a partial reclaim, identical to a walk failure above). */
    uint8_t *agg_cold = NULL;
    size_t   n_agg_cold = 0;
    size_t   cap_agg_cold = 0;

    stm_cas_index *cidx = stm_sync_cas_index(fs->sync);

    /* ---------- Per-snap delete + boot/data reclaim ------------------- */
    for (size_t i = 0; i < n_newer; i++) {
        uint64_t sid = newer_snap_ids[i];

        uint64_t *freed_paddrs = NULL;
        size_t    freed_n      = 0;
        uint8_t  *cold_hashes  = NULL;
        size_t    cold_n       = 0;
        uint64_t *freed_boot   = NULL;
        size_t    freed_boot_n = 0;

        stm_status del = stm_snapshot_delete(sidx, sid,
                                                &freed_paddrs, &freed_n,
                                                &cold_hashes, &cold_n,
                                                &freed_boot, &freed_boot_n);
        if (del != STM_OK) {
            /* Best-effort: this snap stays present + retains its dead-
             * lists; the other newer snaps' reclaims still proceed.
             * stm_snapshot_delete already zeroed the out buffers on
             * non-OK return; defensive free is harmless. */
            free(freed_paddrs);
            free(cold_hashes);
            free(freed_boot);
            continue;
        }

        /* Boot tier (engine NODE paddrs / stm_bootstrap_free): filter
         * vs s.view's bootstrap paddr set. */
        if (boot_ok) {
            for (size_t j = 0; j < freed_boot_n; j++) {
                uint64_t p = freed_boot[j];
                if (bsearch(&p, snap_nodes.v, snap_nodes.n,
                            sizeof p, fs_rb_paddr_cmp) != NULL)
                    continue;   /* case-(a): paddr is in s.view; resurrects */
                uint16_t did = stm_paddr_device(p);
                stm_alloc *a = stm_sync_alloc(fs->sync, did);
                if (!a) continue;
                stm_bootstrap *boot = stm_alloc_bootstrap(a);
                if (!boot) continue;
                (void)stm_bootstrap_free(boot, p,
                        STM_BOOTSTRAP_NODE_BLOCKS, free_gen);
            }
        }
        /* Else: walk failed; can't filter safely → leak the entire
         * snap's boot dead-list. Space cost, not corruption. */

        /* Data tier (HOT-extent replicas / stm_alloc_free): filter vs
         * s.view's data paddr set. */
        if (data_ok) {
            for (size_t j = 0; j < freed_n; j++) {
                uint64_t p = freed_paddrs[j];
                if (bsearch(&p, snap_data.v, snap_data.n,
                            sizeof p, fs_rb_paddr_cmp) != NULL)
                    continue;   /* case-(a): paddr in s.view; resurrects */
                uint16_t did = stm_paddr_device(p);
                stm_alloc *a = stm_sync_alloc(fs->sync, did);
                if (!a) continue;
                (void)stm_alloc_free(a, p, free_gen);
            }
        }

        /* Cold tier: append into the aggregation buffer for the
         * post-loop counted subtraction. R165 P3-3: reorder the
         * overflow guards so the size_t addition `n_agg_cold + cold_n`
         * is checked BEFORE the multiplication (a wrapped addition's
         * product satisfies the multiplication-overflow self-check, so
         * the prior order missed adversarial input — defense-in-depth
         * only; the per-snap dead-list is bounded by
         * STM_SNAP_COLD_DEAD_LIST_MAX = 256 so SIZE_MAX is unreachable
         * in production). */
        if (cold_ok && cold_n > 0) {
            if (n_agg_cold > SIZE_MAX - cold_n) {
                /* addition would overflow */
                cold_ok = false;
            } else if ((n_agg_cold + cold_n) > SIZE_MAX / STM_EXTENT_HASH_LEN) {
                /* multiplication would overflow */
                cold_ok = false;
            } else if (n_agg_cold + cold_n > cap_agg_cold) {
                size_t ncap;
                if (cap_agg_cold == 0) {
                    ncap = 128u;
                } else if (cap_agg_cold > SIZE_MAX / 2u) {
                    /* R165 P3-3: doubling pre-check, NOT post-check —
                     * a wrapped product re-enters the loop with a
                     * smaller capacity than the true target. */
                    ncap = n_agg_cold + cold_n;
                } else {
                    ncap = cap_agg_cold * 2u;
                }
                while (ncap < n_agg_cold + cold_n) {
                    if (ncap > SIZE_MAX / 2u) {
                        ncap = n_agg_cold + cold_n;
                        break;
                    }
                    ncap *= 2u;
                }
                if (ncap > SIZE_MAX / STM_EXTENT_HASH_LEN) {
                    cold_ok = false;
                } else {
                    uint8_t *grown = realloc(agg_cold,
                                                ncap * STM_EXTENT_HASH_LEN);
                    if (!grown) {
                        cold_ok = false;
                    } else {
                        agg_cold     = grown;
                        cap_agg_cold = ncap;
                    }
                }
            }
            if (cold_ok) {
                memcpy(&agg_cold[n_agg_cold * STM_EXTENT_HASH_LEN],
                        cold_hashes, cold_n * STM_EXTENT_HASH_LEN);
                n_agg_cold += cold_n;
            }
        }

        free(freed_paddrs);
        free(cold_hashes);
        free(freed_boot);
    }

    /* ---------- Cold tier post-loop counted subtraction --------------- */
    if (cold_ok && cidx && agg_cold && n_agg_cold > 0) {
        if (n_agg_cold > 1) {
            qsort(agg_cold, n_agg_cold,
                  STM_EXTENT_HASH_LEN, fs_rb_hash_cmp_raw);
        }
        /* Merge-walk by hash run — identical algorithm to 4c-iii.
         * Defense-in-depth clamp at 0 — counted subtraction is safe HERE
         * (every snap_unique record has at least one matching agg_cold
         * entry from its drop event, so `unique_count ≤ dead_count`
         * always holds per hash). The clamp guards against a future
         * upstream bug that would otherwise over-deref. */
        size_t ui = 0, dj = 0;
        while (dj < n_agg_cold) {
            const uint8_t *H = &agg_cold[dj * STM_EXTENT_HASH_LEN];
            size_t dj_end = dj + 1;
            while (dj_end < n_agg_cold
                   && memcmp(&agg_cold[dj_end * STM_EXTENT_HASH_LEN],
                              H, STM_EXTENT_HASH_LEN) == 0) {
                dj_end++;
            }
            size_t dead_count = dj_end - dj;

            while (ui < n_snap_unique
                   && memcmp(&snap_unique[ui * STM_EXTENT_HASH_LEN],
                              H, STM_EXTENT_HASH_LEN) < 0) {
                ui++;
            }
            size_t ui_end = ui;
            while (ui_end < n_snap_unique
                   && memcmp(&snap_unique[ui_end * STM_EXTENT_HASH_LEN],
                              H, STM_EXTENT_HASH_LEN) == 0) {
                ui_end++;
            }
            size_t unique_count = ui_end - ui;

            size_t deref_count = (unique_count <= dead_count)
                                  ? (dead_count - unique_count) : 0;
            for (size_t k = 0; k < deref_count; k++) {
                (void)stm_cas_deref(cidx, H);
            }

            dj = dj_end;
            ui = ui_end;
        }
    }

    free(snap_nodes.v);
    free(snap_data.v);
    free(snap_cold.v);
    free(old_cold.v);
    free(snap_unique);
    free(agg_cold);
}

stm_status stm_fs_rollback_snapshot(stm_fs *fs, uint64_t dataset_id,
                                      uint64_t snapshot_id, bool force)
{
    if (!fs) return STM_EINVAL;
    if (dataset_id == 0 || snapshot_id == 0) return STM_EINVAL;

    pthread_rwlock_wrlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_snapshot_index *sidx = stm_sync_snapshot_index(fs->sync);
    if (!sidx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }

    /* Resolve the target — STM_ENOENT for unknown/deleted snaps. */
    stm_snapshot_entry entry;
    stm_status s = stm_snapshot_lookup(sidx, snapshot_id, &entry);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return s;
    }
    /* Dataset-bind: the rollback cannot cross the dataset boundary
     * the /ctl/ verb was addressed to (R146 P2-2). */
    if (entry.dataset_id != dataset_id) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ENOENT;
    }

    /* Consultation gate (snapshot.tla::RollbackBlockedIffCompromised):
     * a rollback to a corvus-flagged snapshot proceeds ONLY via the
     * operator's explicit `force`. The lookup + this check run under
     * fs->global EX, so a racing unmark either fully precedes (gate
     * sees clear) or fully follows (gate sees set) — never torn. */
    if ((entry.flags & STM_SNAP_FLAG_ROLLBACK_COMPROMISED) && !force) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECOMPROMISED;
    }

    /* ====================================================================
     * 9.7-impl-4: rollback mechanism — validate-then-swap.
     *
     * SPEC: snapshot.tla::Rollback (live_tree_root' = snap_tree_root[s])
     *       + dead_list.tla::Rollback.
     *
     * The dataset's per-dataset btree_engine root is swapped to the
     * snapshot's captured triple (impl-3 made that triple REAL); after
     * the commit the dataset reads the snapshot's frozen view and the
     * post-snapshot live tree is discarded.
     *
     * Step order is LOAD-BEARING (R160 P1-1): every refusal — the
     * newer-snapshot gate and the snapshot-triple VALIDATION — runs
     * BEFORE the destructive dirty-buffer drain. A refused rollback is
     * therefore a true no-op: no buffered write is touched. Only after
     * validation passes does drain → swap → commit run; a failure past
     * the drain is crash-equivalent and wedges (R154 Q2). Validating
     * after the drain would be silent data loss disguised as a clean
     * refusal — the drain pops buffered writes into the engine in-memory
     * tree, which the swap then destroys.
     *
     * Scope — impl-4 shipped the SWAP only. 9.7-impl-4b + 4c + 4c-ii +
     * 4c-iii reclaim the whole post-snapshot live-divergence + the
     * target's own dead-list garbage: 4b the metadata-NODE / spill tier
     * (fs_rollback_reclaim_diverged_nodes, bootstrap class), 4c the
     * DATA-extent replica tier (fs_rollback_reclaim_diverged_extents,
     * stm_alloc class), 4c-ii the COLD-extent tier
     * (fs_rollback_reclaim_diverged_cold, CAS refcount), 4c-iii the
     * snapshot's own dead-list garbage
     * (fs_rollback_reclaim_cleared_dead_list_garbage). 9.7-impl-4d adds
     * the NEWER-SNAPSHOT cascade (fs_rollback_reclaim_newer_snap_cascade)
     * — together with 4b/4c/4c-ii/4c-iii the rollback realises
     * dead_list.tla::Rollback in full. A leak is a space cost, never a
     * corruption — a leaked block stays ALLOCATED (or its CAS entry
     * refcount stays > 0), so the allocator never reissues it, so the
     * AEAD-nonce (paddr, write_gen) pair is never reused.
     *
     * 9.7-impl-4d — newer-snapshot CASCADE: ZFS-style rollback destroys
     * every snapshot newer than the target (operators no longer have to
     * `stm_fs_delete_snapshot` the newer snaps manually first). Each
     * newer snap's dead-list is filtered by `\ s_view` — entries the
     * target's frozen tree references stay live (case-(a) resurrection);
     * the survivors (case-(b) garbage + intermediate-COW garbage) are
     * reclaimed. R160 P1-1: every refusable precondition (newer snap
     * held → STM_EBUSY) is checked BEFORE the destructive drain.
     * ==================================================================== */

    /* 9.7-impl-4d: collect every newer-than-target PRESENT snap. Then
     * pre-validate (R160 P1-1) that NONE is held — a held snap is a
     * refusable precondition; refuse with STM_EBUSY BEFORE the
     * destructive dirty-buffer drain.
     *
     * 9.7-impl-6e — phase-9.7-design.md §9.1.6: the gate ALSO refuses
     * when ANY newer snap has a PRESENT clone referencing it. Without
     * this, the cascade's stm_snapshot_delete on a cloned newer snap
     * would either fire the clone-check cb (STM_EBUSY post-drain — a
     * best-effort, space-only failure that leaves the rollback half-
     * done) OR (if the cb were skipped) leave a clone dangling with no
     * extant origin snap, breaking clone.tla::CloneOriginPresent. The
     * pre-validate is the load-bearing refusal: a refused rollback is
     * a true no-op (no destructive step taken). */
    stm_dataset_index *didx = stm_sync_dataset_index(fs->sync);
    if (!didx) {
        pthread_rwlock_unlock(&fs->global);
        return STM_ECORRUPT;
    }
    uint64_t *newer_ids = NULL;
    size_t    n_newer   = 0;
    s = stm_snapshot_collect_newer(sidx, dataset_id, snapshot_id,
                                      &newer_ids, &n_newer);
    if (s != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return s;
    }
    for (size_t i = 0; i < n_newer; i++) {
        stm_snapshot_entry ne;
        stm_status ls = stm_snapshot_lookup(sidx, newer_ids[i], &ne);
        if (ls != STM_OK) {
            /* Raced — collected ids were a snapshot under the lock; a
             * concurrent delete-before-our-rwlock-acquire is impossible
             * (we hold fs->global EX through both the collect and the
             * lookup), so a lookup miss here is STM_ECORRUPT. Refuse. */
            free(newer_ids);
            pthread_rwlock_unlock(&fs->global);
            return ls == STM_ENOENT ? STM_ECORRUPT : ls;
        }
        if (ne.hold_count > 0) {
            free(newer_ids);
            pthread_rwlock_unlock(&fs->global);
            return STM_EBUSY;
        }
        /* 9.7-impl-6e clone-refusal: refuse if any PRESENT clone
         * references this newer snap. Fail-closed on count-lookup
         * error (STM_ECORRUPT propagates, NOT silent ALLOW — the
         * cascade itself would later observe the clone via the
         * clone_check_cb post-drain, where the refusal becomes
         * space-only). */
        size_t n_clones = 0;
        stm_status cs = stm_dataset_clones_count_for_snap(didx,
                                                             newer_ids[i],
                                                             &n_clones);
        if (cs != STM_OK) {
            free(newer_ids);
            pthread_rwlock_unlock(&fs->global);
            return cs;
        }
        if (n_clones > 0) {
            free(newer_ids);
            pthread_rwlock_unlock(&fs->global);
            return STM_EBUSY;
        }
    }

    /* 9.7-impl-4b: capture the pre-rollback live root triple BEFORE the
     * swap below overwrites the dataset slot — it is the source tree of
     * the metadata-node divergence walk. A lookup miss here only
     * disables reclamation (the leak is nonce-safe — see
     * fs_rollback_reclaim_diverged_nodes); the authoritative dataset-
     * presence refusal is set_engine_root's, below. */
    stm_dataset_entry de_old;
    bool have_old_root =
        (stm_dataset_lookup(didx, dataset_id, &de_old) == STM_OK);

    /* VALIDATE the snapshot's captured triple — BEFORE any destructive
     * step (R160 P1-1). impl-3 stores the triple OPAQUELY (faithful-
     * transport posture); this is the first chunk that interprets it.
     * stm_dataset_index_verify_engine_at opens a throwaway engine at the
     * triple, Merkle/AEAD-walks it, and destroys it — no dataset slot is
     * touched. An all-zero "empty dataset" triple verifies trivially. A
     * mismatch means the snapshot's frozen tree is unrecoverable: refuse
     * with the verify error, fs NOT wedged — a true no-op (the drain +
     * swap below have not run, so no caller data is at risk). This is the
     * impl realisation of dead_list.tla::Rollback's precondition
     * `snap_view_blocks[s] \cap freed = {}` (a snapshot whose tree
     * references reclaimed storage cannot be rolled back to). */
    s = stm_dataset_index_verify_engine_at(didx, dataset_id,
                                              entry.tree_root_paddr,
                                              entry.root_gen,
                                              entry.root_csum);
    if (s != STM_OK) {
        free(newer_ids);
        pthread_rwlock_unlock(&fs->global);
        return s;
    }

    /* R128 P2-3 carry: drain every dirty buffer before touching the
     * metadata tree. The post-snapshot buffered writes are exactly what
     * the rollback discards; draining empties the buffer so no stale
     * write can later flush into the rolled-back tree. (Over-flushes —
     * every dataset, every inode — mirroring create_snapshot; rollback
     * is rare, the cost is acceptable.) This is the FIRST destructive
     * step — every refusal above it was a true no-op. */
    {
        stm_status fr = fs_flush_all_locked(fs);
        if (fr != STM_OK) {
            free(newer_ids);
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
    }

    /* Swap the dataset entry's triple to the snapshot's (already
     * validated) captured triple. set_engine_root drops the live in-RAM
     * engine so (a) the next get_engine re-opens at the swapped triple
     * and (b) the M-cascade — which flushes only slots whose engine is
     * OPEN — skips this slot, so the stamped triple survives untouched
     * to the dataset_index_commit. The engine stays CLOSED until the
     * next post-rollback access opens it lazily at the swapped root. */
    s = stm_dataset_index_set_engine_root(didx, dataset_id,
                                             entry.tree_root_paddr,
                                             entry.root_gen,
                                             entry.root_csum);
    if (s != STM_OK) {
        /* set_engine_root fails here only with STM_ENOENT (the dataset
         * is not PRESENT) — and it refuses as a clean no-op (it bails
         * before mutating the slot). The drain above is non-durable
         * (buffered writes sit in engine in-memory trees, recoverable by
         * the next commit), so this is not crash-equivalent — no wedge. */
        free(newer_ids);
        pthread_rwlock_unlock(&fs->global);
        return s;
    }

    /* Reclaim the post-snapshot divergence — blocks reachable from the
     * pre-rollback live tree but not from the snapshot's frozen tree.
     * FOUR tiers run here:
     *   - 9.7-impl-4b: the metadata-NODE / spill blocks (bootstrap
     *     class) via fs_rollback_reclaim_diverged_nodes;
     *   - 9.7-impl-4c: the DATA-extent replica blocks (stm_alloc class)
     *     via fs_rollback_reclaim_diverged_extents;
     *   - 9.7-impl-4c-ii: the COLD-extent CAS refcounts via
     *     fs_rollback_reclaim_diverged_cold;
     *   - 9.7-impl-4c-iii: the snapshot's own dead-list garbage
     *     (`snap_dead[s] \ s_view`) via
     *     fs_rollback_reclaim_cleared_dead_list_garbage — reads each
     *     of S's three dead-lists BEFORE clear_dead_lists discards them
     *     and frees survivors (case-(b) intermediate-COW garbage that
     *     impl-2's COW routing dropped onto S's dead-list under "most-
     *     recent snap" but which S's tree never references). The
     *     case-(a) resurrection entries (whose paddrs/hashes are live
     *     again post-swap) are KEPT, then discarded by the
     *     clear_dead_lists call below.
     * All four are best-effort (a failure leaks, never corrupts — see
     * the helpers). The node + data frees are deferred and ride the
     * SAME stm_sync_commit as the swap; the cold derefs feed that
     * commit's CAS auto-GC sweep — all-or-nothing on a commit failure.
     * With 4c-iii in place, the rollback fully realises
     * dead_list.tla::Rollback's `to_free` minus the `newer_dead \ s_view`
     * term — which the impl-4d newer-snapshot cascade picks up after the
     * newer-snapshot refusal lifts. */
    if (have_old_root) {
        fs_rollback_reclaim_diverged_nodes(fs, didx, dataset_id,
                de_old.di_tree_root, de_old.di_root_gen, de_old.di_root_csum,
                entry.tree_root_paddr, entry.root_gen, entry.root_csum);

        /* The data-extent reclaim re-opens a throwaway engine at the
         * SAME de_old triple the node reclaim above just walked + freed
         * nodes from. Safe: stm_bootstrap_free is a DEFERRED free — the
         * bitmap bit stays set and the on-disk node bytes stay intact
         * until a commit sweep, so the Merkle/AEAD descent here still
         * verifies on the unchanged bytes. */
        stm_extent_index *eidx = stm_sync_extent_index(fs->sync);
        if (eidx) {
            fs_rollback_reclaim_diverged_extents(fs, eidx, dataset_id,
                de_old.di_tree_root, de_old.di_root_gen, de_old.di_root_csum,
                entry.tree_root_paddr, entry.root_gen, entry.root_csum);

            /* 9.7-impl-4c-ii: the COLD-extent (CAS) tier — release the
             * CAS refcount of every cold record reachable from the old
             * live tree but not the snapshot's. Same throwaway-engine
             * EXTENT-keyspace re-walk as the data reclaim above (the
             * deferred-free safety note there covers this third walk);
             * deref touches only the CAS index, never the allocator. */
            fs_rollback_reclaim_diverged_cold(fs, eidx, dataset_id,
                de_old.di_tree_root, de_old.di_root_gen, de_old.di_root_csum,
                entry.tree_root_paddr, entry.root_gen, entry.root_csum);
        }

        /* 9.7-impl-4c-iii: the snapshot's own dead-list garbage. Runs
         * AFTER 4b/4c/4c-ii so the live-divergence walks have already
         * completed; reads each of S's three dead-lists from sidx
         * BEFORE clear_dead_lists below discards them; filters each by
         * `\ s_view` (boot/data — set-difference on paddrs; cold —
         * per-key snap_unique merge + counted subtraction); frees
         * the survivors per resource class. The helper consults eidx
         * for the data + cold tiers; passing NULL is the documented
         * skip-those-tiers path (boot tier still runs through didx). */
        fs_rollback_reclaim_cleared_dead_list_garbage(
                fs, sidx, didx, stm_sync_extent_index(fs->sync),
                dataset_id, snapshot_id,
                de_old.di_tree_root, de_old.di_root_gen, de_old.di_root_csum,
                entry.tree_root_paddr, entry.root_gen, entry.root_csum);
    }

    /* Clear the target snapshot's dead-lists. MOVED here from
     * pre-reclaim (impl-4 original position) at 9.7-impl-4c-iii: the
     * 4c-iii reclaim above already discharged the case-(b) garbage
     * entries (freed / dereffed them); the remaining case-(a)
     * resurrection entries DO NOT need their deferred-free fired
     * because their paddrs/hashes are live in the post-swap tree.
     * Clearing now drops both classes from the in-RAM index in one
     * shot — exactly matching the just-created dead-list state, which
     * is correct since no divergence sits between S and live anymore.
     *
     * Why this order is safe vs the impl-4 (clear-first) order:
     * 4b/4c/4c-ii/4c-iii are PURE READERS of sidx (and 4c-iii reads
     * dead_list contents only — it doesn't mutate the snapshot index),
     * so moving clear from pre-reclaim to post-reclaim doesn't change
     * the reclaim's observed state. The R160 correctness invariant —
     * "post-rollback S's dead-list must not retain live-paddr
     * entries" — is preserved: clear_dead_lists drops everything in
     * one shot just as before, only later. */
    s = stm_snapshot_clear_dead_lists(sidx, snapshot_id);
    if (s != STM_OK) {
        /* Unreachable: snapshot_id is validated + PRESENT under the held
         * fs->global EX. Defensive — the in-RAM triple is swapped but
         * not durable, crash-equivalent inconsistent state → wedge
         * (R154 Q2). */
        free(newer_ids);
        pthread_rwlock_unlock(&fs->global);
        stm_fs_mark_wedged(fs);
        return s;
    }

    /* 9.7-impl-4d: newer-snapshot CASCADE. With the target's tier 4b/4c/
     * 4c-ii/4c-iii reclaim + clear_dead_lists already done, iterate the
     * newer-than-target PRESENT snapshots collected earlier. Each is
     * deleted via stm_snapshot_delete; its three dead-lists are filtered
     * by `\ s_view` (boot/data set-difference; cold per-hash counted
     * subtraction against snap_unique) and survivors reclaimed. Best-
     * effort per snap — a fail on one snap leaves the others reclaimed.
     * Runs BEFORE the commit so every per-snap delete + every reclaim
     * frees / derefs in the SAME atomic commit as the swap. */
    if (n_newer > 0) {
        stm_extent_index *eidx_n = stm_sync_extent_index(fs->sync);
        uint64_t old_paddr_n   = have_old_root ? de_old.di_tree_root  : 0;
        uint64_t old_gen_n     = have_old_root ? de_old.di_root_gen   : 0;
        const uint8_t *old_csum_n = have_old_root ? de_old.di_root_csum
                                                  : (const uint8_t[32]){0};
        fs_rollback_reclaim_newer_snap_cascade(
                fs, sidx, didx, eidx_n,
                dataset_id, newer_ids, n_newer,
                old_paddr_n, old_gen_n, old_csum_n,
                entry.tree_root_paddr, entry.root_gen, entry.root_csum);
    }
    free(newer_ids);
    newer_ids = NULL;

    /* Commit the swap. stm_sync_commit drives the three-phase cascade;
     * the dataset_index — marked dirty by set_engine_root — re-serialises
     * the slot with the swapped triple (the rolled-back dataset's engine
     * is closed, so the M-cascade skips it and cannot un-stamp it). The
     * commit advances the sync gen, so every post-rollback write lands at
     * a strictly-higher gen than any pre-rollback write — the AEAD-nonce
     * (paddr, write_gen) pair stays fresh even though the snapshot's
     * older paddrs are live again. (The v1 R9-1 "bump fs->gen before the
     * allocator swap" doctrine: v2's rollback does NOT roll back the
     * allocator — diverged blocks leak rather than free — so there is no
     * allocator swap to bump before; the commit's gen advance subsumes
     * it.)
     *
     * R154 Q2: a failed commit is crash-equivalent (the engines' three-
     * phase abort dropped the in-memory trees) — wedge the fs. The wedge
     * is deferred past the unlock; stm_fs_mark_wedged itself takes
     * fs->global. */
    {
        stm_status cr = stm_sync_commit(fs->sync);
        if (cr != STM_OK) {
            pthread_rwlock_unlock(&fs->global);
            stm_fs_mark_wedged(fs);
            return cr;
        }
    }

    pthread_rwlock_unlock(&fs->global);
    return STM_OK;
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
    if (fs_ino_is_synth(ino)) return STM_EROFS;        /* 9.7-impl-5 */
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

    /* P9.5-PARALLEL-3 impl-5: SH (rdlock) + per-inode pin. fallocate is
     * a single-inode mutator — the (load + validate + flush + extent
     * mutate + inode_set) compound serializes per-inode on the pin
     * mutex; fallocate on disjoint inodes runs in parallel. iidx is
     * required (legacy direct-extent inodes have no si_size to update).
     *
     * UNSHARE_RANGE drops the lock + pin BEFORE chaining into
     * stm_fs_promote_to_hot — see that branch below. */
    pthread_rwlock_rdlock(&fs->global);
    FS_GUARD_WRITE(fs);

    stm_inode_index *iidx_pin = stm_sync_inode_index(fs->sync);
    if (!iidx_pin) {
        pthread_rwlock_unlock(&fs->global);
        return STM_EINVAL;
    }
    stm_inode_handle *h_falloc = NULL;
    stm_status pp_falloc = stm_inode_pin(iidx_pin, dataset_id, ino, &h_falloc);
    if (pp_falloc != STM_OK) {
        pthread_rwlock_unlock(&fs->global);
        return pp_falloc;       /* STM_ENOENT */
    }

    /* SWISS-4q-flush: fallocate operates on the extent tree directly
     * (PUNCH_HOLE drops extents, COLLAPSE/INSERT shifts extent keys,
     * etc.). Any buffered ranges for this inode are invisible to those
     * ops and would survive PUNCH_HOLE / get out of sync with shifted
     * extents. Pre-flush this inode so the extent layer reflects all
     * issued writes before fallocate acts. */
    {
        stm_status fr = fs_flush_ino_locked(fs, dataset_id, ino);
        if (fr != STM_OK) {
            stm_inode_unpin(iidx_pin, h_falloc);
            pthread_rwlock_unlock(&fs->global);
            return fr;
        }
    }

    struct stm_inode_value iv = {0};
    stm_status vs = fs_fallocate_validate_target(fs, dataset_id, ino, &iv);
    if (vs != STM_OK) {
        stm_inode_unpin(iidx_pin, h_falloc);
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
    /* impl-5 single-exit: every refusal below uses `goto falloc_out`
     * which unpins + unlocks (the labels live at end of function). */
    stm_status s = STM_OK;

    uint8_t kind = iv.si_data_kind;
    if (kind == STM_DATA_INLINE) {
        if (any_range_op) { s = STM_ENOTSUPPORTED; goto falloc_out; }
        /* Default preallocate on INLINE: allow ONLY if not extending
         * past the inline cap. Otherwise refuse — caller must
         * truncate-up first to trigger the INLINE→EXTENT transition. */
        if (!keep_size && (off + len) > (uint64_t)STM_INODE_INLINE_MAX) {
            s = STM_ERANGE; goto falloc_out;
        }
    }

    /* Sealed-file enforcement: F_SEAL_WRITE / FUTURE_WRITE block
     * every fallocate op (mutates content); F_SEAL_GROW blocks ops
     * that would extend the file; F_SEAL_SHRINK blocks ops that
     * would shrink. Match Linux fallocate(2)'s seal enforcement at
     * the kernel-VFS layer. */
    uint32_t cur_flags = stm_load_le32(iv.si_flags);

    if (cur_flags & (uint32_t)(STM_INO_FLAG_SEAL_WRITE |
                                STM_INO_FLAG_SEAL_FUTURE_WRITE)) {
        s = STM_EPERM; goto falloc_out;
    }
    uint64_t cur_size = stm_load_le64(iv.si_size);
    bool would_grow = false;
    if (!any_range_op && !keep_size) {
        if (off + len > cur_size) would_grow = true;
    } else if (insert) {
        would_grow = true;
    } else if (zero_r && !keep_size) {
        if (off + len > cur_size) would_grow = true;
    }
    bool would_shrink = collapse;
    if (would_grow && (cur_flags & (uint32_t)STM_INO_FLAG_SEAL_GROW)) {
        s = STM_EPERM; goto falloc_out;
    }
    if (would_shrink && (cur_flags & (uint32_t)STM_INO_FLAG_SEAL_SHRINK)) {
        s = STM_EPERM; goto falloc_out;
    }

    stm_extent_index *eidx = stm_sync_extent_index(fs->sync);
    if (!eidx) { s = STM_EINVAL; goto falloc_out; }

    if (punch) {
        /* PUNCH_HOLE | KEEP_SIZE: route through stm_sync_punch_range
         * which (R89 P0-4 fix) properly drops paddrs through the
         * snapshot dead-list + alloc free pool. Refuses
         * STM_ENOTSUPPORTED on crossing or COLD extents. */
        s = stm_sync_punch_range(fs->sync, dataset_id, ino, off, len);
        if (s == STM_OK) {
            fs_stamp_mtime_ctime_now(&iv);
            (void)stm_inode_set(iidx_pin, dataset_id, ino, &iv);
        }
    } else if (collapse) {
        /* COLLAPSE_RANGE: range must already be empty + no crossing
         * boundary extents (refuse STM_ENOTSUPPORTED). Shift
         * extents above off+len down by len. Shrink si_size by len.
         *
         * R89 P2-1: Linux fallocate(2) refuses with EINVAL when
         * `off + len >= cur_size` (collapse beyond EOF is undefined). */
        if (off + len > cur_size) { s = STM_EINVAL; goto falloc_out; }
        s = stm_extent_shift_range_keys(eidx, dataset_id, ino,
                                             off + len,
                                             -(int64_t)len);
        if (s == STM_OK) {
            uint64_t new_size = cur_size - len;
            iv.si_size = stm_store_le64(new_size);
            fs_stamp_mtime_ctime_now(&iv);
            (void)stm_inode_set(iidx_pin, dataset_id, ino, &iv);
        }
    } else if (insert) {
        /* INSERT_RANGE: shift extents at off' >= off up by len.
         * Refuse if extent crosses off (STM_ENOTSUPPORTED).
         * si_size grows by len.
         *
         * R89 P2-2: Linux fallocate(2) refuses with EINVAL when
         * `off >= cur_size` (inserting past EOF is undefined). */
        if (off >= cur_size) { s = STM_EINVAL; goto falloc_out; }
        if (cur_size > UINT64_MAX - len) {
            s = STM_EOVERFLOW; goto falloc_out;
        }
        s = stm_extent_shift_range_keys(eidx, dataset_id, ino,
                                             off, (int64_t)len);
        if (s == STM_OK) {
            iv.si_size = stm_store_le64(cur_size + len);
            fs_stamp_mtime_ctime_now(&iv);
            (void)stm_inode_set(iidx_pin, dataset_id, ino, &iv);
        }
    } else if (zero_r) {
        /* ZERO_RANGE: punch via stm_sync_punch_range (R89 P0-4
         * paddr-routing fix) + (if !keep_size and would_grow) bump
         * si_size. */
        s = stm_sync_punch_range(fs->sync, dataset_id, ino, off, len);
        if (s == STM_OK) {
            if (!keep_size && (off + len) > cur_size) {
                iv.si_size = stm_store_le64(off + len);
            }
            fs_stamp_mtime_ctime_now(&iv);
            (void)stm_inode_set(iidx_pin, dataset_id, ino, &iv);
        }
    } else if (unshare) {
        /* UNSHARE_RANGE: composes via stm_fs_promote_to_hot —
         * promote_to_hot promotes EVERY COLD extent at the ino
         * (broader than POSIX requires for a partial range, but
         * correct + conservative). Drop pin + SH BEFORE chaining
         * since stm_fs_promote_to_hot takes both fresh. */
        stm_inode_unpin(iidx_pin, h_falloc);
        pthread_rwlock_unlock(&fs->global);
        stm_status ps = stm_fs_promote_to_hot(fs, dataset_id, ino);
        /* STM_ENOENT is "no COLD extents to promote" — already
         * unshared, return OK. */
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
                (void)stm_inode_set(iidx_pin, dataset_id, ino, &iv);
            }
        }
        s = STM_OK;
    }

falloc_out:
    stm_inode_unpin(iidx_pin, h_falloc);
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
    /* 9.7-impl-5 R166 P2-2: advisory locks on snap-view inodes have
     * no semantic meaning — the snap is frozen. Refuse STM_EROFS. */
    if (fs_ino_is_synth(ino)) return STM_EROFS;

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
    /* 9.7-impl-5 R166 P2-2: symmetric to lock — synth ino refusal. */
    if (fs_ino_is_synth(ino)) return STM_EROFS;

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
    /* 9.7-impl-5 R166 P2-2: synth ino lock-test is meaningless. The
     * RO probe semantically is "would acquire succeed?" — and acquire
     * itself refuses STM_EROFS — so probe surfaces STM_EROFS too for
     * symmetry. */
    if (fs_ino_is_synth(ino)) return STM_EROFS;

    /* 9.8-LF-3c: stm_lock_test takes its own internal mutex; safe to
     * call without holding fs->global. fs->locks is set at mount + never
     * reassigned. */
    FS_GUARD_READ_LOCKLESS(fs);
    return stm_lock_test(fs->locks, dataset_id, ino,
                            owner_id, type, off, len,
                            out_would_grant,
                            out_conflicting_owner);
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

    /* 9.8-LF-3c: stm_lock_count takes its own internal mutex. */
    FS_GUARD_READ_LOCKLESS(fs);
    return stm_lock_count(fs->locks, out_count);
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

    /* 9.8-LF-3: wedged check is now lockless via atomic acquire-load.
     * No EBR enter needed — this function does not descend any engine
     * (the WILLNEED / DONTNEED delegates take their own EX locks).
     * RO mounts pass — the delegate's own FS_GUARD_WRITE refuses with
     * STM_EROFS, which we SWALLOW (advisory). */
    FS_GUARD_READ_LOCKLESS(fs);

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

    /* 9.8-LF-3c: wait-free + wedged-OK. fs->sync + fs->alloc are
     * immutable post-mount; stm_sync_info_get + stm_alloc_stats_get
     * each take their own internal mutex. No fs->global needed. */
    stm_sync_info sinfo;
    stm_status s = stm_sync_info_get(fs->sync, &sinfo);
    if (s != STM_OK) return s;

    stm_alloc_stats astats;
    s = stm_alloc_stats_get(fs->alloc, &astats);
    if (s != STM_OK) return s;

    out->data_total_blocks     = astats.data_total_blocks;
    out->data_allocated_blocks = astats.data_allocated_blocks;
    out->data_pending_blocks   = astats.data_pending_blocks;
    out->data_free_blocks      = astats.data_free_blocks;
    out->n_allocated_ranges    = astats.n_allocated_ranges;

    out->current_gen       = sinfo.current_gen;
    out->alloc_root_paddr  = sinfo.alloc_root_paddr;

    /* Acquire-load for wedged/read_only pairs with the release-store
     * in stm_fs_mark_wedged + the EX-held flips in unmount paths. */
    out->read_only = atomic_load_explicit(&fs->read_only, memory_order_acquire);
    out->wedged    = atomic_load_explicit(&fs->wedged, memory_order_acquire);

    return STM_OK;
}

void stm_fs_mark_wedged(stm_fs *fs)
{
    if (!fs) return;
    /* 9.8-LF-3: hold fs->global EX to serialise with other writers (e.g.,
     * a concurrent unmount), AND release-store the atomic flag so 9.8
     * wait-free readers (which check this WITHOUT taking fs->global)
     * synchronise via acquire-load. EX excludes other writers; the atomic
     * provides the reader-side pairing. */
    pthread_rwlock_wrlock(&fs->global);
    atomic_store_explicit(&fs->wedged, true, memory_order_release);
    pthread_rwlock_unlock(&fs->global);
}

stm_status stm_fs_verify(const stm_fs *fs)
{
    if (!fs) return STM_EINVAL;
    /* 9.8-LF-3c: side-effect-free + wedged-OK. fs->alloc is immutable
     * post-mount and stm_alloc_verify takes the allocator's internal
     * mutex. No fs->global needed. */
    return stm_alloc_verify(fs->alloc);
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

/* TLY-A1 (R137 P2-2 close): zero the on-disk ub_pool_serial in every
 * committed slot at `path`, recomputing each slot's BLAKE3 csum so
 * the on-disk image still validates at mount. Used to fabricate the
 * "unbound pool" back-compat carve-out — production format-time
 * always CSPRNG-fills, so there's no other way to test the
 * (disk_zero && exp_zero) success path in the §3.3 matrix.
 *
 * Walks STM_LABELS_PER_DEVICE × STM_UB_SLOTS_PER_LABEL slots. Skips
 * the mirror slot (consistent with stm_sb_mount_scan). Slots that
 * fail to decode (blank / wrong-version / corrupt) are left alone —
 * we only rewrite slots that currently hold a valid UB. */
stm_status stm_fs_test_clear_pool_serial(const char *path)
{
    if (!path) return STM_EINVAL;
    stm_bdev_open_opts bopts = stm_bdev_open_opts_default();
    bopts.read_only = false;
    stm_bdev *d = NULL;
    stm_status s = stm_bdev_open(path, &bopts, &d);
    if (s != STM_OK) return s;

    for (uint32_t lbl = 0; lbl < STM_LABELS_PER_DEVICE; lbl++) {
        for (uint32_t slot = 0; slot < STM_UB_SLOTS_PER_LABEL; slot++) {
            stm_uberblock ub;
            stm_status rs = stm_sb_label_read(d, lbl, slot, &ub);
            if (rs == STM_ENOENT || rs == STM_EBADVERSION ||
                rs == STM_ECORRUPT) {
                continue;  /* blank / wrong-version / corrupt — skip. */
            }
            if (rs != STM_OK) {
                stm_bdev_close(d);
                return rs;
            }
            memset(ub.ub_pool_serial, 0, 16);
            /* stm_sb_label_write re-encodes (recomputes the csum)
             * before issuing the bdev write, so the on-disk slot
             * stays csum-valid after the field is zeroed. */
            rs = stm_sb_label_write(d, lbl, slot, &ub);
            if (rs != STM_OK) {
                stm_bdev_close(d);
                return rs;
            }
        }
    }

    stm_bdev_close(d);
    return STM_OK;
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

void stm_fs_pool_serial(stm_fs *fs, uint8_t out[16])
{
    /* TLY-A1 (R137 P3-2 close): public surface delegating to the
     * sync-level accessor. NULL fs/out are no-ops. */
    if (!fs || !out) return;
    stm_sync_pool_serial(fs->sync, out);
}
