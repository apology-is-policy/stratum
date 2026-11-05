/* SPDX-License-Identifier: ISC */
/*
 * host_fs — POSIX directory tree exported as 9P2000.L, read-only.
 *
 * Architecture:
 *
 *   The lp9 server's per-fid table maps fid → qid_path. Our vops
 *   table is keyed by qid_path (most ops) and by fid (open-state
 *   ops: lopen / read / readdir / clunk). qid_path encodes
 *   `(st_dev, st_ino)` of the host file: high 32 bits = device, low
 *   32 bits = inode. This collides on devices with > 4G inodes
 *   OR > 4G dev numbers — neither realistic on macOS / Linux today,
 *   but worth a forward-note.
 *
 *   We maintain a `paths` map (qid_path -> the absolute host path a
 *   walk last reached the file by, with the file's dev and ino). A
 *   walk replaces the entry: the client is naming the file now. Every
 *   use checks that the name still leads to that dev and ino, and
 *   answers ENOENT when it does not, so a rename or a reused inode is
 *   refused, never served as another file. The map is a cache of at
 *   most HOST_FS_MAX_PATHS names: when full, names unused for a while
 *   are dropped (never the root's, nor one behind an open fid), and a
 *   fid left without a name answers ENOENT the same way.
 *
 *   Per-fid open state (fd / DIR*) is tracked in `fids` keyed by
 *   fid. Cleared on clunk.
 */

#include <stratum/host_fs.h>
#include <stratum/lp9.h>
#include <stratum/types.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HOST_FS_FID_BUCKETS   64u
#define HOST_FS_PATH_BUCKETS  256u
#define HOST_FS_MAX_PATHS     4096u
#define HOST_FS_PATH_MAX      4095u

typedef struct host_fs_path {
    uint64_t qid_path;
    uint64_t dev, ino;      /* the file abs_path led to when it was walked */
    uint64_t used;          /* h->clock at the last store or lookup */
    char *abs_path;
    struct host_fs_path *next;
} host_fs_path;

typedef struct host_fs_fid {
    uint32_t fid;
    uint64_t qid_path;
    int fd;       /* -1 if not open */
    DIR *dir;     /* NULL if not opendir'd */
    struct host_fs_fid *next;
} host_fs_fid;

struct stm_host_fs {
    char *root;             /* absolute, NUL-terminated, resolved (no trailing /) */
    size_t root_len;
    uint64_t root_qid_path;
    pthread_mutex_t mu;
    host_fs_path *paths[HOST_FS_PATH_BUCKETS];
    uint32_t paths_count;
    uint64_t clock;         /* one tick per path store or lookup */
    host_fs_fid *fids[HOST_FS_FID_BUCKETS];
};

/* ────────────────────────────────────────────────────────────────────── */
/* qid_path encoding.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

static uint64_t qid_path_from_stat(const struct stat *st)
{
    /* (dev hi) | (ino lo) — collision-free on every realistic macOS /
     * Linux deployment. Forward-note: combine with FNV-1a hash for
     * larger inode spaces. */
    uint64_t dev = (uint64_t)st->st_dev;
    uint64_t ino = (uint64_t)st->st_ino;
    return (dev << 32) ^ ino;
}

static uint8_t qid_type_from_mode(mode_t mode)
{
    if (S_ISDIR(mode))  return STM_LP9_QTDIR;
    if (S_ISLNK(mode))  return STM_LP9_QTSYMLINK;
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Path map (qid_path → host path).                                       */
/* ────────────────────────────────────────────────────────────────────── */

static uint32_t path_hash(uint64_t qid)
{
    /* Fast Fibonacci hash. */
    return (uint32_t)((qid * 0x9E3779B97F4A7C15ull) >> 32) % HOST_FS_PATH_BUCKETS;
}

static bool same_file(const struct stat *st, uint64_t dev, uint64_t ino)
{
    return (uint64_t)st->st_dev == dev && (uint64_t)st->st_ino == ino;
}

/* Caller holds h->mu. Returns NULL if not found. */
static host_fs_path *path_lookup_locked(stm_host_fs *h, uint64_t qid)
{
    uint32_t b = path_hash(qid);
    for (host_fs_path *p = h->paths[b]; p; p = p->next) {
        if (p->qid_path == qid) {
            p->used = ++h->clock;
            return p;
        }
    }
    return NULL;
}

/* Caller holds h->mu. */
static bool qid_has_open_fid_locked(const stm_host_fs *h, uint64_t qid)
{
    for (uint32_t i = 0; i < HOST_FS_FID_BUCKETS; i++) {
        for (const host_fs_fid *f = h->fids[i]; f; f = f->next) {
            if (f->qid_path == qid) return true;
        }
    }
    return false;
}

/* Caller holds h->mu. Drops every name not stored or looked up in the last
 * HOST_FS_MAX_PATHS/2 ticks. A tick touches one name, so at most that many
 * survive besides the root and names behind an open fid, and the next drop is
 * at least as many stores away. */
static void paths_evict_locked(stm_host_fs *h)
{
    const uint64_t window = HOST_FS_MAX_PATHS / 2u;
    uint64_t keep_from = h->clock > window ? h->clock - window : 0;
    for (uint32_t i = 0; i < HOST_FS_PATH_BUCKETS; i++) {
        host_fs_path **link = &h->paths[i];
        while (*link) {
            host_fs_path *p = *link;
            if (p->used < keep_from && p->qid_path != h->root_qid_path
                && !qid_has_open_fid_locked(h, p->qid_path)) {
                *link = p->next;
                free(p->abs_path);
                free(p);
                h->paths_count--;
            } else {
                link = &p->next;
            }
        }
    }
}

/* Caller holds h->mu. Records that `abs_path` leads to the file `st`
 * describes, replacing whatever name the qid had. The root keeps its name. */
static stm_status path_store_locked(stm_host_fs *h, uint64_t qid,
                                    const struct stat *st, const char *abs_path)
{
    host_fs_path *p = path_lookup_locked(h, qid);
    if (p && qid == h->root_qid_path && p->abs_path) {
        /* Another file whose number folds onto the root's cannot be served. */
        return same_file(st, p->dev, p->ino) ? STM_OK : STM_EIO;
    }
    char *copy = strdup(abs_path);
    if (!copy) return STM_ENOMEM;
    if (!p) {
        if (h->paths_count >= HOST_FS_MAX_PATHS) paths_evict_locked(h);
        if (h->paths_count >= HOST_FS_MAX_PATHS) {
            free(copy);
            return STM_ENOMEM;
        }
        p = calloc(1, sizeof *p);
        if (!p) {
            free(copy);
            return STM_ENOMEM;
        }
        uint32_t b = path_hash(qid);
        p->qid_path = qid;
        p->used = ++h->clock;
        p->next = h->paths[b];
        h->paths[b] = p;
        h->paths_count++;
    }
    free(p->abs_path);
    p->abs_path = copy;
    p->dev = (uint64_t)st->st_dev;
    p->ino = (uint64_t)st->st_ino;
    return STM_OK;
}

/* Copies the name stored for `qid` into `out`, with the file it led to. */
static stm_status path_snapshot(stm_host_fs *h, uint64_t qid,
                                char out[HOST_FS_PATH_MAX + 1],
                                uint64_t *dev, uint64_t *ino)
{
    pthread_mutex_lock(&h->mu);
    const host_fs_path *p = path_lookup_locked(h, qid);
    if (!p) {
        pthread_mutex_unlock(&h->mu);
        return STM_ENOENT;
    }
    size_t plen = strlen(p->abs_path);
    if (plen > HOST_FS_PATH_MAX) {
        pthread_mutex_unlock(&h->mu);
        return STM_EINVAL;
    }
    memcpy(out, p->abs_path, plen + 1);
    *dev = p->dev;
    *ino = p->ino;
    pthread_mutex_unlock(&h->mu);
    return STM_OK;
}

static void paths_free_locked(stm_host_fs *h)
{
    for (uint32_t i = 0; i < HOST_FS_PATH_BUCKETS; i++) {
        host_fs_path *p = h->paths[i];
        while (p) {
            host_fs_path *n = p->next;
            free(p->abs_path);
            free(p);
            p = n;
        }
        h->paths[i] = NULL;
    }
    h->paths_count = 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Per-fid table.                                                          */
/* ────────────────────────────────────────────────────────────────────── */

static uint32_t fid_hash(uint32_t fid)
{
    return (fid * 2654435761u) % HOST_FS_FID_BUCKETS;
}

/* Caller holds h->mu. */
static host_fs_fid *fid_get_locked(stm_host_fs *h, uint32_t fid)
{
    uint32_t b = fid_hash(fid);
    for (host_fs_fid *f = h->fids[b]; f; f = f->next) {
        if (f->fid == fid) return f;
    }
    return NULL;
}

/* Caller holds h->mu. Returns existing OR newly-allocated entry. */
static host_fs_fid *fid_alloc_locked(stm_host_fs *h, uint32_t fid, uint64_t qid_path)
{
    host_fs_fid *f = fid_get_locked(h, fid);
    if (f) return f;
    f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->fid = fid;
    f->qid_path = qid_path;
    f->fd = -1;
    f->dir = NULL;
    uint32_t b = fid_hash(fid);
    f->next = h->fids[b];
    h->fids[b] = f;
    return f;
}

/* Caller holds h->mu. Closes fd / DIR* + removes entry. Safe on missing fid. */
static void fid_free_locked(stm_host_fs *h, uint32_t fid)
{
    uint32_t b = fid_hash(fid);
    host_fs_fid **link = &h->fids[b];
    while (*link) {
        if ((*link)->fid == fid) {
            host_fs_fid *dead = *link;
            *link = dead->next;
            if (dead->dir) closedir(dead->dir);
            else if (dead->fd >= 0) close(dead->fd);
            free(dead);
            return;
        }
        link = &(*link)->next;
    }
}

static void fids_free_all_locked(stm_host_fs *h)
{
    for (uint32_t i = 0; i < HOST_FS_FID_BUCKETS; i++) {
        host_fs_fid *f = h->fids[i];
        while (f) {
            host_fs_fid *n = f->next;
            if (f->dir) closedir(f->dir);
            else if (f->fd >= 0) close(f->fd);
            free(f);
            f = n;
        }
        h->fids[i] = NULL;
    }
}

/* ────────────────────────────────────────────────────────────────────── */
/* Lifecycle.                                                              */
/* ────────────────────────────────────────────────────────────────────── */

stm_status stm_host_fs_create(const char *root_path, stm_host_fs **out)
{
    if (!root_path || !out) return STM_EINVAL;
    *out = NULL;

    /* Resolve root to an absolute path with no symlinks (realpath).
     * This pins the root prefix the walk-time containment check uses. */
    char *resolved = realpath(root_path, NULL);
    if (!resolved) return STM_EINVAL;

    struct stat st;
    if (lstat(resolved, &st) < 0) {
        free(resolved);
        return STM_EINVAL;
    }
    if (!S_ISDIR(st.st_mode)) {
        free(resolved);
        return STM_ENOTDIR;
    }

    stm_host_fs *h = calloc(1, sizeof *h);
    if (!h) {
        free(resolved);
        return STM_ENOMEM;
    }
    h->root = resolved;
    h->root_len = strlen(resolved);
    h->root_qid_path = qid_path_from_stat(&st);
    if (pthread_mutex_init(&h->mu, NULL) != 0) {
        free(h->root);
        free(h);
        return STM_EIO;
    }

    /* Pre-populate the path map with the root. */
    pthread_mutex_lock(&h->mu);
    stm_status rc = path_store_locked(h, h->root_qid_path, &st, resolved);
    pthread_mutex_unlock(&h->mu);
    if (rc != STM_OK) {
        pthread_mutex_destroy(&h->mu);
        free(h->root);
        free(h);
        return rc;
    }
    *out = h;
    return STM_OK;
}

void stm_host_fs_destroy(stm_host_fs *h)
{
    if (!h) return;
    pthread_mutex_lock(&h->mu);
    fids_free_all_locked(h);
    paths_free_locked(h);
    pthread_mutex_unlock(&h->mu);
    pthread_mutex_destroy(&h->mu);
    free(h->root);
    free(h);
}

uint64_t stm_host_fs_root(const stm_host_fs *h)
{
    return h ? h->root_qid_path : 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* vops.                                                                  */
/* ────────────────────────────────────────────────────────────────────── */

/* Containment check: ensure `path` is the root OR strictly under it.
 *
 * R127 P1-2: root="/" was previously rejecting all subpaths because
 * the `path[h->root_len] == '/'` check looked at index 1 (a non-'/'
 * char) instead of treating "/" as a special case. Special-case
 * here so `stratum host-fs /` works. */
static bool path_within_root(const stm_host_fs *h, const char *path)
{
    size_t plen = strlen(path);
    if (plen == h->root_len && strcmp(path, h->root) == 0) return true;
    /* Root is "/": every absolute path is within. */
    if (h->root_len == 1 && h->root[0] == '/') {
        return path[0] == '/';
    }
    if (plen > h->root_len + 1
        && strncmp(path, h->root, h->root_len) == 0
        && path[h->root_len] == '/') return true;
    return false;
}

/* Build child path = parent + "/" + name. Refuses ".." and embedded NUL.
 * Returns malloc'd string (caller frees) or NULL on bad input / OOM. */
static char *child_path(const char *parent, const char *name, size_t name_len)
{
    if (name_len == 0) return NULL;
    /* R125 P1-1 doctrine carry: refuse path-traversal components. */
    if (name_len == 2 && name[0] == '.' && name[1] == '.') return NULL;
    for (size_t i = 0; i < name_len; i++) {
        if (name[i] == '\0' || name[i] == '/') return NULL;
    }
    size_t plen = strlen(parent);
    bool need_sep = (plen > 0 && parent[plen - 1] != '/');
    size_t total = plen + (need_sep ? 1 : 0) + name_len + 1;
    if (total > HOST_FS_PATH_MAX) return NULL;
    char *out = malloc(total);
    if (!out) return NULL;
    memcpy(out, parent, plen);
    size_t off = plen;
    if (need_sep) out[off++] = '/';
    memcpy(out + off, name, name_len);
    out[off + name_len] = '\0';
    return out;
}

static void fill_attr(stm_lp9_attr *out, const struct stat *st,
                       uint64_t qid_path)
{
    memset(out, 0, sizeof *out);
    out->qid.qtype = qid_type_from_mode(st->st_mode);
    out->qid.version = 0;
    out->qid.path = qid_path;
    /* Mode is the full mode word including type bits, per .L. */
    out->mode = st->st_mode;
    out->uid = st->st_uid;
    out->gid = st->st_gid;
    out->nlink = st->st_nlink;
    out->rdev = st->st_rdev;
    out->size = st->st_size;
    out->blksize = (uint64_t)st->st_blksize;
    out->blocks = (uint64_t)st->st_blocks;
#if defined(__APPLE__)
    out->atime_sec = st->st_atimespec.tv_sec;
    out->atime_nsec = st->st_atimespec.tv_nsec;
    out->mtime_sec = st->st_mtimespec.tv_sec;
    out->mtime_nsec = st->st_mtimespec.tv_nsec;
    out->ctime_sec = st->st_ctimespec.tv_sec;
    out->ctime_nsec = st->st_ctimespec.tv_nsec;
    out->btime_sec = st->st_birthtimespec.tv_sec;
    out->btime_nsec = st->st_birthtimespec.tv_nsec;
#else
    out->atime_sec = st->st_atim.tv_sec;
    out->atime_nsec = st->st_atim.tv_nsec;
    out->mtime_sec = st->st_mtim.tv_sec;
    out->mtime_nsec = st->st_mtim.tv_nsec;
    out->ctime_sec = st->st_ctim.tv_sec;
    out->ctime_nsec = st->st_ctim.tv_nsec;
    /* btime not portably available on Linux; leave 0. */
#endif
    out->valid = STM_LP9_GETATTR_BASIC;
}

static stm_status vops_getattr(void *ctx, uint64_t qid_path,
                                 uint64_t request_mask, stm_lp9_attr *out)
{
    (void)request_mask;
    stm_host_fs *h = ctx;
    char copy[HOST_FS_PATH_MAX + 1];
    uint64_t dev, ino;
    stm_status rc = path_snapshot(h, qid_path, copy, &dev, &ino);
    if (rc != STM_OK) return rc;

    struct stat st;
    if (lstat(copy, &st) < 0 || !same_file(&st, dev, ino)) return STM_ENOENT;
    fill_attr(out, &st, qid_path);
    return STM_OK;
}

static stm_status vops_walk(void *ctx, uint64_t dir_qid_path,
                              const char *name, size_t name_len,
                              stm_lp9_qid *out_qid)
{
    stm_host_fs *h = ctx;

    char parent_copy[HOST_FS_PATH_MAX + 1];
    uint64_t pdev, pino;
    stm_status prc = path_snapshot(h, dir_qid_path, parent_copy, &pdev, &pino);
    if (prc != STM_OK) return prc;
    struct stat pst;
    if (lstat(parent_copy, &pst) < 0 || !same_file(&pst, pdev, pino)) return STM_ENOENT;

    char *child = child_path(parent_copy, name, name_len);
    if (!child) return STM_EINVAL;

    struct stat st;
    if (lstat(child, &st) < 0) {
        free(child);
        return (errno == ENOENT) ? STM_ENOENT : STM_EIO;
    }

    /* R127 P1-1 / P2-2 closure: refuse-to-bind if the resolved path
     * leaves the root, OR if realpath fails (broken symlink, EACCES,
     * etc.). The previous "accept lstat'd path on realpath failure"
     * branch enabled an attack where a broken-symlink walk binds the
     * fid + a late-arriving target then makes vops_lopen's follow-
     * symlink open(2) reach outside root. Refusing here closes that
     * vector at the source. Real-world cost: dangling symlinks become
     * unwalkable (Treaddir surfaces them; Twalk fails STM_EACCES). */
    char *resolved = realpath(child, NULL);
    if (!resolved) {
        free(child);
        return STM_EACCES;
    }
    if (!path_within_root(h, resolved)) {
        free(resolved);
        free(child);
        return STM_EACCES;
    }
    free(resolved);

    uint64_t cqid = qid_path_from_stat(&st);
    pthread_mutex_lock(&h->mu);
    stm_status rc = path_store_locked(h, cqid, &st, child);
    pthread_mutex_unlock(&h->mu);
    free(child);
    if (rc != STM_OK) return rc;

    out_qid->qtype = qid_type_from_mode(st.st_mode);
    out_qid->version = 0;
    out_qid->path = cqid;
    return STM_OK;
}

static stm_status vops_readdir(void *ctx, uint64_t dir_qid_path,
                                 uint64_t cookie_start,
                                 stm_lp9_dirent_cb cb, void *cb_ctx)
{
    stm_host_fs *h = ctx;

    char copy[HOST_FS_PATH_MAX + 1];
    uint64_t dev, ino;
    stm_status src = path_snapshot(h, dir_qid_path, copy, &dev, &ino);
    if (src != STM_OK) return src;

    /* lp9 reads only an lopen'd fid, and lopen refuses a symlink, so the
     * directory is opened without following one; fstat says it is still
     * the directory the fid was walked to. */
    int dfd = open(copy, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) return STM_ENOENT;
    struct stat dst;
    if (fstat(dfd, &dst) < 0 || !same_file(&dst, dev, ino)) {
        close(dfd);
        return STM_ENOENT;
    }
    DIR *d = fdopendir(dfd);
    if (!d) {
        close(dfd);
        return STM_EIO;
    }

    /* R125 doctrine on stable resume: telldir/seekdir cookies are
     * NOT portable across DIR* reopens (the lp9 server may call
     * vops_readdir multiple times to satisfy one Treaddir; we
     * opendir fresh each time). Use 1-based entry index as the
     * cookie -- stable across reopens and simple to compute; a resume
     * reads past the entries before the cookie again.
     * Skip "." and ".." server-side; 9P clients (and the slate-tty
     * renderer) don't expect them. */
    int rc = STM_OK;
    uint64_t idx = 0;
    while (1) {
        errno = 0;
        struct dirent *ent = readdir(d);
        if (!ent) {
            if (errno != 0) rc = STM_EIO;
            break;
        }
        if (ent->d_name[0] == '.'
            && (ent->d_name[1] == '\0'
                || (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) {
            continue;
        }
        idx++;
        if (idx <= cookie_start) continue;
        uint64_t cookie = idx;
        size_t name_len = strlen(ent->d_name);

        /* No name is stored here: a walk finds a child from its parent's. */
        struct stat st;
        if (fstatat(dirfd(d), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) continue;
        uint64_t cqid = qid_path_from_stat(&st);

        stm_lp9_dirent dent;
        memset(&dent, 0, sizeof dent);
        dent.qid.qtype = qid_type_from_mode(st.st_mode);
        dent.qid.version = 0;
        dent.qid.path = cqid;
        dent.cookie = cookie;
        dent.dt_type = ent->d_type;
        if (name_len > STM_LP9_NAME_MAX) {
            /* APFS holds 255 characters, up to 765 bytes. A bare cut can be a
             * sibling's whole name, so the cut ends on a character boundary
             * with U+FFFD after it, which names nothing and the manager
             * refuses. */
            size_t keep = STM_LP9_NAME_MAX - 3u;
            while (keep > 0 && ((unsigned char)ent->d_name[keep] & 0xC0u) == 0x80u) keep--;
            memcpy(dent.name, ent->d_name, keep);
            memcpy(dent.name + keep, "\xEF\xBF\xBD", 3);
            name_len = keep + 3u;
        } else {
            memcpy(dent.name, ent->d_name, name_len);
        }
        dent.name_len = (uint16_t)name_len;
        dent.name[name_len] = '\0';
        stm_status crc = cb(&dent, cb_ctx);
        if (crc != STM_OK) {
            rc = crc;
            break;
        }
    }
    closedir(d);
    return rc;
}

static stm_status vops_lopen(void *ctx, uint32_t fid, uint64_t qid_path,
                               uint32_t flags)
{
    stm_host_fs *h = ctx;

    /* R125 read-only posture: reject any flags suggesting write. */
    uint32_t accmode = flags & 0x3; /* O_RDONLY=0 / O_WRONLY=1 / O_RDWR=2 */
    if (accmode != 0) return STM_EROFS;
    if (flags & (0x40 /*O_CREAT*/ | 0x200 /*O_TRUNC on Linux*/ | 0x400 /*O_TRUNC on macOS*/)) {
        return STM_EROFS;
    }

    char copy[HOST_FS_PATH_MAX + 1];
    uint64_t dev, ino;
    stm_status rc = path_snapshot(h, qid_path, copy, &dev, &ino);
    if (rc != STM_OK) return rc;

    /* Only a regular file or a directory is opened: opening a FIFO blocks
     * the server, and opening a device can act on it. */
    struct stat st;
    if (lstat(copy, &st) < 0 || !same_file(&st, dev, ino)) return STM_ENOENT;
    if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) return STM_EINVAL;

    /* R127 P1-1: open WITHOUT following symlinks at the leaf. The
     * walk-time containment check validated the resolved path, but
     * a TOCTOU between walk and lopen could have replaced the file
     * with a symlink-to-outside. O_NOFOLLOW returns ELOOP if the leaf
     * is a symlink; O_NONBLOCK keeps a FIFO swapped in since the lstat
     * from blocking, and fstat says the file opened is the one walked. */
    int fd = open(copy, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? STM_ENOENT : STM_EIO;
    struct stat ost;
    if (fstat(fd, &ost) < 0 || !same_file(&ost, dev, ino)
        || (ost.st_mode & S_IFMT) != (st.st_mode & S_IFMT)) {
        close(fd);
        return STM_ENOENT;
    }
    DIR *d = NULL;
    if (S_ISDIR(ost.st_mode)) {
        d = fdopendir(fd);
        if (!d) {
            close(fd);
            return STM_EIO;
        }
    }

    pthread_mutex_lock(&h->mu);
    host_fs_fid *f = NULL;
    if (fid_get_locked(h, fid)) {
        rc = STM_EINVAL;              /* already open; lp9 refuses this first */
    } else if (!(f = fid_alloc_locked(h, fid, qid_path))) {
        rc = STM_ENOMEM;
    } else if (d) {
        f->dir = d;
    } else {
        f->fd = fd;
    }
    pthread_mutex_unlock(&h->mu);
    if (rc != STM_OK) {
        if (d) closedir(d);
        else close(fd);
    }
    return rc;
}

static stm_status vops_read(void *ctx, uint32_t fid, uint64_t qid_path,
                              uint64_t offset, void *buf, uint32_t *inout_len)
{
    (void)qid_path;
    stm_host_fs *h = ctx;
    pthread_mutex_lock(&h->mu);
    host_fs_fid *f = fid_get_locked(h, fid);
    int fd = f ? f->fd : -1;
    pthread_mutex_unlock(&h->mu);
    if (fd < 0) return STM_EBACKEND;
    ssize_t n = pread(fd, buf, *inout_len, (off_t)offset);
    if (n < 0) return STM_EIO;
    *inout_len = (uint32_t)n;
    return STM_OK;
}

static void vops_clunk(void *ctx, uint32_t fid, uint64_t qid_path)
{
    (void)qid_path;
    stm_host_fs *h = ctx;
    pthread_mutex_lock(&h->mu);
    fid_free_locked(h, fid);
    pthread_mutex_unlock(&h->mu);
}

static stm_status vops_readlink(void *ctx, uint64_t qid_path,
                                  char *buf, size_t *inout_len)
{
    stm_host_fs *h = ctx;
    char copy[HOST_FS_PATH_MAX + 1];
    uint64_t dev, ino;
    stm_status rc = path_snapshot(h, qid_path, copy, &dev, &ino);
    if (rc != STM_OK) return rc;
    struct stat st;
    if (lstat(copy, &st) < 0 || !same_file(&st, dev, ino)) return STM_ENOENT;

    /* readlink does NOT NUL-terminate; we report length back. R125
     * caller-cap-bound: pass exactly *inout_len bytes. */
    ssize_t n = readlink(copy, buf, *inout_len);
    if (n < 0) return STM_EIO;
    *inout_len = (size_t)n;
    return STM_OK;
}

static const stm_lp9_vops HOST_FS_VOPS = {
    .getattr  = vops_getattr,
    .walk     = vops_walk,
    .readdir  = vops_readdir,
    .lopen    = vops_lopen,
    .read     = vops_read,
    .write    = NULL,        /* read-only at v1.0 → ENOSYS */
    .clunk    = vops_clunk,
    .lcreate  = NULL,
    .mkdir    = NULL,
    .unlinkat = NULL,
    .setattr  = NULL,
    .fsync    = NULL,
    .symlink  = NULL,
    .readlink = vops_readlink,
};

const stm_lp9_vops *stm_host_fs_vops(void)
{
    return &HOST_FS_VOPS;
}
