/*
 * stratum-fuse — userspace FUSE daemon that serves a Stratum volume at a
 * POSIX mount point.
 *
 * Architecture:
 *   - Kernel FUSE module (fuse.ko on Linux, macFUSE on macOS) is the VFS
 *     entry point. It forwards each VFS operation as a message over
 *     /dev/fuse to this daemon, receives the reply, and returns to the
 *     caller.
 *   - libfuse3 handles the wire protocol; we supply a callback table of
 *     `struct fuse_lowlevel_ops`, one function per FUSE op.
 *   - Every callback is a thin wrapper over the corresponding stm_fs_*
 *     API. Inode numbers are passed through directly (fuse_ino_t is u64,
 *     matches stm_fs inode type). FUSE_ROOT_ID == 1 == STM_ROOT_INO —
 *     no translation needed.
 *
 * Single-threaded:
 *   fuse_session_loop() runs one request at a time. Stratum's stm_fs_*
 *   API is not thread-safe (see SOTA #14), so single-threaded is both
 *   correct and simpler. A multi-threaded variant would need a mutex
 *   around every stm_fs_* call.
 *
 * Unmount:
 *   fuse_set_signal_handlers() catches SIGINT/SIGTERM and exits the loop
 *   cleanly. fuse_session_unmount() then releases the mount point.
 *   Abnormal termination leaves a stale mount that the user clears with
 *   `fusermount -u <mountpoint>` (Linux) or `umount <mountpoint>` (macOS).
 *
 * Security:
 *   Mount is per-user (no -o allow_other by default). FUSE passes
 *   caller uid/gid via fuse_req_ctx(); Stratum today stores uid/gid in
 *   si_uid / si_gid but doesn't enforce them — until SOTA #5 POSIX
 *   completion wires ownership through, every file is effectively
 *   owned by the mounting user.
 */

#define FUSE_USE_VERSION 31
/* macFUSE defaults to Darwin-extended op signatures (setattr uses
 * `struct fuse_darwin_attr *`, statfs takes `struct statfs *`, etc.)
 * which diverges from vanilla Linux libfuse3. Force the vanilla API so
 * this single source file compiles the same way on both platforms. */
#define FUSE_DARWIN_ENABLE_EXTENSIONS 0
#include <fuse_lowlevel.h>

#include "stratum/fs.h"
#include "stratum/inode.h"
#include "stratum/types.h"
#include "cli_common.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

/* Process-global fs handle. Set in main() before fuse_session_loop,
 * torn down after the loop exits. Single-threaded access. */
static struct stm_fs *g_fs = NULL;

/* ── attribute conversion ──────────────────────────────────────────── */

/* Fill a POSIX `struct stat` from a Stratum inode. Returns 0 on success,
 * -errno on lookup failure. */
static int fill_attr(uint64_t ino, struct stat *st)
{
    struct stm_inode in;
    int rc = stm_fs_stat(g_fs, ino, &in);
    if (rc) return rc;  /* negative errno from stm_fs_* */

    memset(st, 0, sizeof(*st));
    st->st_ino   = ino;
    st->st_mode  = le32_to_cpu(in.si_mode);
    st->st_nlink = le32_to_cpu(in.si_nlink);
    /* Return the inode's stored uid/gid. On a freshly-mkfs'd volume
     * every file is 0:0; ll_create/ll_mkdir chown to the caller's
     * identity immediately after create, so ordinary use sees real
     * ownership. Pre-Group-A volumes saw getuid()/getgid() here — the
     * stored values were ignored. */
    st->st_uid   = le32_to_cpu(in.si_uid);
    st->st_gid   = le32_to_cpu(in.si_gid);
    st->st_size  = le64_to_cpu(in.si_size);
    st->st_atime = le64_to_cpu(in.si_atime_sec);
    st->st_mtime = le64_to_cpu(in.si_mtime_sec);
    st->st_ctime = le64_to_cpu(in.si_ctime_sec);
    st->st_blksize = 4096;
    st->st_blocks  = (st->st_size + 511) / 512;
    return 0;
}

static void make_entry(fuse_ino_t ino, struct fuse_entry_param *e)
{
    memset(e, 0, sizeof(*e));
    e->ino = ino;
    e->generation = 1;
    /* 1 second attr/entry cache matches libfuse defaults; safe because
     * this daemon is the only writer to the volume. */
    e->attr_timeout  = 1.0;
    e->entry_timeout = 1.0;
    fill_attr(ino, &e->attr);
}

/* ── low-level FUSE callbacks ──────────────────────────────────────── */

static void ll_init(void *userdata, struct fuse_conn_info *conn)
{
    (void)userdata; (void)conn;
    /* Nothing — state is set before the loop starts. */
}

/* lookup(parent, name) — the kernel's dcache miss path. Translate a
 * (parent_ino, name) pair into (child_ino, attrs). */
static void ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    uint64_t child_ino;
    int rc = stm_fs_lookup(g_fs, parent, name, &child_ino);
    if (rc) { fuse_reply_err(req, -rc); return; }

    struct fuse_entry_param e;
    make_entry(child_ino, &e);
    fuse_reply_entry(req, &e);
}

static void ll_getattr(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi)
{
    (void)fi;
    struct stat st;
    int rc = fill_attr(ino, &st);
    if (rc) { fuse_reply_err(req, -rc); return; }
    fuse_reply_attr(req, &st, 1.0);
}

/* setattr: POSIX chmod/chown/utimens/truncate all route through here.
 * `to_set` is a bitmask of FUSE_SET_ATTR_* flags indicating which fields
 * in `attr` the caller wants to change. We dispatch each bit to the
 * corresponding stm_fs_* mutation (SOTA #5 Group A) and then reply with
 * the refreshed attrs so FUSE's cache stays consistent. */
static void ll_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                       int to_set, struct fuse_file_info *fi)
{
    (void)fi;
    int rc;

    if (to_set & FUSE_SET_ATTR_MODE) {
        rc = stm_fs_chmod(g_fs, ino, attr->st_mode);
        if (rc) { fuse_reply_err(req, -rc); return; }
    }

    if (to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
        uint32_t uid = (to_set & FUSE_SET_ATTR_UID) ? attr->st_uid : (uint32_t)-1;
        uint32_t gid = (to_set & FUSE_SET_ATTR_GID) ? attr->st_gid : (uint32_t)-1;
        rc = stm_fs_chown(g_fs, ino, uid, gid);
        if (rc) { fuse_reply_err(req, -rc); return; }
    }

    /* atime / mtime. FUSE splits the "set to now" from "set to specific
     * value" via separate flags (*_NOW); we resolve _NOW to the current
     * wall-clock before passing to stm_fs_utimes. */
    int set_at = (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_ATIME_NOW)) != 0;
    int set_mt = (to_set & (FUSE_SET_ATTR_MTIME | FUSE_SET_ATTR_MTIME_NOW)) != 0;
    if (set_at || set_mt) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        uint64_t as = 0, ms = 0;
        uint32_t an = 0, mn = 0;
        if (to_set & FUSE_SET_ATTR_ATIME_NOW) {
            as = (uint64_t)now.tv_sec; an = (uint32_t)now.tv_nsec;
        } else if (to_set & FUSE_SET_ATTR_ATIME) {
            as = (uint64_t)attr->st_atime; an = 0;
        }
        if (to_set & FUSE_SET_ATTR_MTIME_NOW) {
            ms = (uint64_t)now.tv_sec; mn = (uint32_t)now.tv_nsec;
        } else if (to_set & FUSE_SET_ATTR_MTIME) {
            ms = (uint64_t)attr->st_mtime; mn = 0;
        }
        rc = stm_fs_utimes(g_fs, ino, set_at, as, an, set_mt, ms, mn);
        if (rc) { fuse_reply_err(req, -rc); return; }
    }

    if (to_set & FUSE_SET_ATTR_SIZE) {
        rc = stm_fs_truncate(g_fs, ino, (uint64_t)attr->st_size);
        if (rc) { fuse_reply_err(req, -rc); return; }
    }

    /* Reply with the post-mutation attrs so FUSE's cache refreshes. */
    struct stat st;
    rc = fill_attr(ino, &st);
    if (rc) { fuse_reply_err(req, -rc); return; }
    fuse_reply_attr(req, &st, 1.0);
}

/* After a successful create/mkdir, stamp the new inode's uid/gid with
 * the caller's identity (from the FUSE request context). stm_fs_create_*
 * don't take uid/gid params today, so we do a follow-up chown. Failure
 * is non-fatal — the inode exists, just with 0:0 ownership; caller can
 * chown explicitly. */
static void stamp_ownership(fuse_req_t req, uint64_t ino)
{
    const struct fuse_ctx *ctx = fuse_req_ctx(req);
    if (ctx) (void)stm_fs_chown(g_fs, ino, ctx->uid, ctx->gid);
}

static void ll_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                     mode_t mode)
{
    uint64_t new_ino;
    int rc = stm_fs_mkdir(g_fs, parent, name, mode & 0777, &new_ino);
    if (rc) { fuse_reply_err(req, -rc); return; }
    stamp_ownership(req, new_ino);
    struct fuse_entry_param e;
    make_entry(new_ino, &e);
    fuse_reply_entry(req, &e);
}

static void ll_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode, struct fuse_file_info *fi)
{
    uint64_t new_ino;
    int rc = stm_fs_create_file(g_fs, parent, name, mode & 0777, &new_ino);
    if (rc) { fuse_reply_err(req, -rc); return; }
    stamp_ownership(req, new_ino);
    struct fuse_entry_param e;
    make_entry(new_ino, &e);
    fuse_reply_create(req, &e, fi);
}

static void ll_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    int rc = stm_fs_unlink(g_fs, parent, name);
    fuse_reply_err(req, rc ? -rc : 0);
}

static void ll_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    /* stm_fs_unlink handles both files and directories; refuses non-empty
     * dirs with -ENOTEMPTY (R2-era fix). */
    int rc = stm_fs_unlink(g_fs, parent, name);
    fuse_reply_err(req, rc ? -rc : 0);
}

static void ll_open(fuse_req_t req, fuse_ino_t ino,
                    struct fuse_file_info *fi)
{
    (void)ino;
    /* No per-handle state needed; leave fi->fh untouched. */
    fuse_reply_open(req, fi);
}

static void ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                    struct fuse_file_info *fi)
{
    (void)fi;
    char *buf = malloc(size);
    if (!buf) { fuse_reply_err(req, ENOMEM); return; }
    uint32_t nread = 0;
    int rc = stm_fs_read(g_fs, ino, (uint64_t)off, buf, (uint32_t)size, &nread);
    if (rc) { free(buf); fuse_reply_err(req, -rc); return; }
    fuse_reply_buf(req, buf, nread);
    free(buf);
}

static void ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                     size_t size, off_t off, struct fuse_file_info *fi)
{
    (void)fi;
    int rc = stm_fs_write(g_fs, ino, (uint64_t)off, buf, (uint32_t)size);
    if (rc) { fuse_reply_err(req, -rc); return; }
    fuse_reply_write(req, size);
}

static void ll_flush(fuse_req_t req, fuse_ino_t ino,
                     struct fuse_file_info *fi)
{
    (void)ino; (void)fi;
    /* FUSE flush fires on close(2) of every fd. Don't sync here — it's
     * too aggressive (every cat/cp/vim close would trigger a full sync).
     * Durability is achieved via release + explicit fsync. */
    fuse_reply_err(req, 0);
}

static void ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
                     struct fuse_file_info *fi)
{
    (void)ino; (void)datasync; (void)fi;
    int rc = stm_fs_sync(g_fs);
    fuse_reply_err(req, rc ? -rc : 0);
}

static void ll_release(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi)
{
    (void)ino; (void)fi;
    /* Release fires on the LAST close of an inode. Sync here so a user
     * workflow like `echo hi > foo; cat foo` sees the write durably
     * before the read (mirrors 9P's h_clunk sync-on-dirty). Best-effort;
     * a sync failure is reported but doesn't change release semantics. */
    int rc = stm_fs_sync(g_fs);
    fuse_reply_err(req, rc ? -rc : 0);
}

/* ── directory iteration ───────────────────────────────────────────── */

struct dirfill {
    fuse_req_t   req;
    char        *buf;
    size_t       cap;
    size_t       pos;
};

static int dirfill_cb(const char *name, uint64_t ino, uint8_t type, void *ctx)
{
    struct dirfill *d = ctx;
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino  = ino;
    st.st_mode = (type == STM_DT_DIR) ? S_IFDIR : S_IFREG;
    /* fuse_add_direntry returns the size the entry WOULD need; if > cap
     * remaining, we stop and caller retries with the current offset. The
     * "offset" we hand back is pos+1 so the next readdir continues after
     * this entry. */
    size_t need = fuse_add_direntry(d->req, d->buf + d->pos, d->cap - d->pos,
                                     name, &st, (off_t)(d->pos + 1));
    if (need > d->cap - d->pos) return 1;  /* stop the scan */
    d->pos += need;
    return 0;
}

static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                       struct fuse_file_info *fi)
{
    (void)fi;
    char *buf = malloc(size);
    if (!buf) { fuse_reply_err(req, ENOMEM); return; }
    struct dirfill d = { .req = req, .buf = buf, .cap = size, .pos = 0 };
    int rc = stm_fs_readdir(g_fs, ino, dirfill_cb, &d);
    if (rc) { free(buf); fuse_reply_err(req, -rc); return; }
    /* off=0 returns the first page; subsequent calls with off=d.pos would
     * repeat entries. For simplicity we always return the full listing
     * from the current walk and let the kernel handle offset semantics
     * via the per-entry off values fuse_add_direntry recorded. */
    if ((size_t)off >= d.pos) fuse_reply_buf(req, NULL, 0);  /* EOF */
    else                      fuse_reply_buf(req, buf + off, d.pos - off);
    free(buf);
}

/* ── statfs ────────────────────────────────────────────────────────── */

static void ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
    (void)ino;
    struct statvfs s;
    memset(&s, 0, sizeof(s));
    /* Stratum doesn't yet expose block accounting through a public API;
     * report generic sane values so `df` and similar tools don't choke.
     * Real accounting lands with SOTA #2 (persistent allocator). */
    s.f_bsize   = 4096;
    s.f_frsize  = 4096;
    s.f_blocks  = 1;  /* placeholder — prevents "0/0" divide-by-zero */
    s.f_bfree   = 0;
    s.f_bavail  = 0;
    s.f_namemax = 255;
    fuse_reply_statfs(req, &s);
}

/* ── callback table ────────────────────────────────────────────────── */

static const struct fuse_lowlevel_ops ops = {
    .init     = ll_init,
    .lookup   = ll_lookup,
    .getattr  = ll_getattr,
    .setattr  = ll_setattr,
    .mkdir    = ll_mkdir,
    .rmdir    = ll_rmdir,
    .unlink   = ll_unlink,
    .create   = ll_create,
    .open     = ll_open,
    .read     = ll_read,
    .write    = ll_write,
    .flush    = ll_flush,
    .fsync    = ll_fsync,
    .release  = ll_release,
    .readdir  = ll_readdir,
    .statfs   = ll_statfs,
    /* Unimplemented (SOTA #5 POSIX completion):
     *   rename, link, symlink, readlink, mknod, access,
     *   setxattr, getxattr, listxattr, removexattr, bmap.
     * libfuse returns ENOSYS for any op left NULL. */
};

/* ── main ──────────────────────────────────────────────────────────── */

static void usage(void)
{
    fprintf(stderr,
        "Usage: stratum-fuse <volume> <mountpoint> [options]\n"
        "\n"
        "Options:\n"
        "  --pass <p>      volume passphrase on command line\n"
        "  --pass-stdin    read passphrase from stdin (one line)\n"
        "  -f              foreground mode (do not daemonize)\n"
        "  -d              debug mode (verbose libfuse trace)\n"
        "\n"
        "Unmount with `fusermount -u <mountpoint>` (Linux) or\n"
        "`umount <mountpoint>` (macOS).\n"
    );
}

int main(int argc, char **argv)
{
    const char *volume = NULL;
    const char *mountpoint = NULL;
    const char *pass = NULL;
    int foreground = 0;
    int debug = 0;

    /* Argument parsing: first positional is volume, second is mountpoint. */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pass") && i + 1 < argc) { pass = argv[++i]; continue; }
        if (!strcmp(argv[i], "--pass-stdin")) { pass = stm_cli_read_pass_stdin(); continue; }
        if (!strcmp(argv[i], "-f")) { foreground = 1; continue; }
        if (!strcmp(argv[i], "-d")) { debug = 1; foreground = 1; continue; }
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(); return 0; }
        if      (!volume)      volume = argv[i];
        else if (!mountpoint)  mountpoint = argv[i];
        else { fprintf(stderr, "stratum-fuse: unexpected arg: %s\n", argv[i]); return 2; }
    }
    if (!volume || !mountpoint) { usage(); return 2; }

    int rc = stm_fs_open(volume, pass, &g_fs);
    if (rc) {
        fprintf(stderr, "stratum-fuse: cannot open %s: %s\n",
                volume, strerror(-rc));
        return 1;
    }

    /* Build the libfuse argv: first slot is argv[0] for identity, then
     * the mountpoint, then optional flags. libfuse parses these via
     * fuse_parse_cmdline + fuse_session_new. */
    char *fargv[8];
    int fargc = 0;
    fargv[fargc++] = argv[0];
    if (debug) fargv[fargc++] = "-d";
    fargv[fargc] = NULL;
    struct fuse_args fa = FUSE_ARGS_INIT(fargc, fargv);

    struct fuse_session *se = fuse_session_new(&fa, &ops, sizeof(ops), NULL);
    if (!se) {
        fprintf(stderr, "stratum-fuse: fuse_session_new failed\n");
        stm_fs_close(g_fs);
        return 1;
    }
    if (fuse_set_signal_handlers(se) != 0) {
        fprintf(stderr, "stratum-fuse: failed to set signal handlers\n");
        fuse_session_destroy(se);
        stm_fs_close(g_fs);
        return 1;
    }
    if (fuse_session_mount(se, mountpoint) != 0) {
        fprintf(stderr, "stratum-fuse: failed to mount %s\n", mountpoint);
        fuse_remove_signal_handlers(se);
        fuse_session_destroy(se);
        stm_fs_close(g_fs);
        return 1;
    }

    if (!foreground && !debug) {
        /* fuse_daemonize forks, redirects stdio, returns in the child.
         * Caller's terminal is freed; on SIGINT the daemon unmounts. */
        if (fuse_daemonize(0) != 0) {
            fprintf(stderr, "stratum-fuse: daemonize failed\n");
            fuse_session_unmount(se);
            fuse_remove_signal_handlers(se);
            fuse_session_destroy(se);
            stm_fs_close(g_fs);
            return 1;
        }
    } else {
        fprintf(stderr, "stratum-fuse: mounted %s at %s (foreground)\n",
                volume, mountpoint);
    }

    /* Single-threaded event loop. stm_fs_* is not thread-safe; running
     * fuse_session_loop_mt would require fine-grained locking that's out
     * of scope for v1 (see SOTA #14 concurrent writers). */
    int loop_rc = fuse_session_loop(se);

    fuse_session_unmount(se);
    fuse_remove_signal_handlers(se);
    fuse_session_destroy(se);
    fuse_opt_free_args(&fa);
    stm_fs_close(g_fs);
    return loop_rc < 0 ? 1 : 0;
}
