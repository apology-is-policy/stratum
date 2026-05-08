/* SPDX-License-Identifier: ISC */
/*
 * stratum-fs — thin CLI wrapping libstratum-9p (P9-CLI-1 FS-only).
 *
 * Plan-9-shaped subcommand interface. Each subcommand opens a fresh
 * connection to stratumd, performs the op, and exits. Multi-op
 * batching is left to shell scripts that invoke us repeatedly — the
 * cost is one Tversion+Tattach per call (~1ms local Unix socket).
 *
 * Socket selection (in priority order):
 *   1. -s SOCKET command-line flag.
 *   2. STRATUM_SOCKET environment variable.
 *   3. /var/run/stratum.sock (default).
 *
 * Path semantics:
 *   - Always absolute (must start with '/').
 *   - "." and ".." components refused (security: path traversal
 *     prevention; server-side stratumd validates again, but lib-side
 *     pre-rejection saves a round-trip + gives a stable status).
 *   - Component count ≤ STM_9P_MAX_WALK (16). Deep paths require
 *     iterative walks; this MVP refuses them.
 *
 * Exit codes:
 *   0  success
 *   1  usage error (argv parsing / bad path)
 *   2  I/O or server error
 *   3  not found (ENOENT)
 *
 * /ctl/-using subcommands (pool / dataset / snapshot / scrub /
 * key) are deferred until /ctl/-on-stratumd integration lands.
 */
#include <stratum/cmds.h>
#include <stratum/9p_client.h>
#include <stratum/9p.h>
#include <stratum/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ────────────────────────────────────────────────────────────────────── */
/* Exit codes.                                                            */
/* ────────────────────────────────────────────────────────────────────── */

#define EXIT_USAGE     1
#define EXIT_IO        2
#define EXIT_NOTFOUND  3

/* Default Unix socket path. */
#define DEFAULT_SOCKET "/var/run/stratum.sock"

/* Root fid the dial path attaches to. Caller-managed beyond that. */
#define ROOT_FID  100u
/* Worker fid for ops that need a per-call walk target. */
#define WORK_FID  101u

/* ────────────────────────────────────────────────────────────────────── */
/* Path utility.                                                          */
/*                                                                         */
/* Splits an absolute path "/a/b/c" into a sequence of (count, names[])  */
/* entries suitable for stm_9p_walk. Refuses non-absolute, "." / "..",    */
/* embedded "//" runs, and paths exceeding STM_9P_MAX_WALK components.    */
/* The names array points into a contiguous storage buffer; both have      */
/* lifetime tied to the caller's path_t.                                   */
/* ────────────────────────────────────────────────────────────────────── */

typedef struct {
    /* Pointers into `storage`. */
    const char *names[STM_9P_MAX_WALK];
    uint16_t    count;
    /* Backing store: copy of the input path with NULs replacing
     * separators. Capped at PATH_MAX-shape; paths longer than this
     * are refused at parse time. */
    char        storage[STM_9P_NAME_MAX * STM_9P_MAX_WALK + STM_9P_MAX_WALK + 1];
} path_t;

static int parse_path(const char *path, path_t *out)
{
    if (!path || path[0] != '/') {
        fprintf(stderr, "stratum-fs: path must be absolute (start with '/')\n");
        return -1;
    }
    out->count = 0;
    size_t plen = strlen(path);
    if (plen >= sizeof out->storage) {
        fprintf(stderr, "stratum-fs: path too long\n");
        return -1;
    }
    memcpy(out->storage, path, plen + 1);
    /* Walk the storage in-place, NUL-terminating each component. */
    size_t i = 1;       /* skip leading '/' */
    while (i < plen) {
        /* Skip consecutive '/'s (treat as one). */
        while (i < plen && out->storage[i] == '/') i++;
        if (i >= plen) break;
        size_t start = i;
        while (i < plen && out->storage[i] != '/') i++;
        size_t comp_len = i - start;
        if (comp_len == 0) continue;
        if (comp_len > STM_9P_NAME_MAX) {
            fprintf(stderr, "stratum-fs: path component too long (max %u)\n",
                    STM_9P_NAME_MAX);
            return -1;
        }
        if (comp_len == 1 && out->storage[start] == '.') {
            fprintf(stderr, "stratum-fs: '.' components not allowed\n");
            return -1;
        }
        if (comp_len == 2 && out->storage[start] == '.' &&
            out->storage[start + 1] == '.') {
            fprintf(stderr, "stratum-fs: '..' components not allowed\n");
            return -1;
        }
        if (out->count >= STM_9P_MAX_WALK) {
            fprintf(stderr, "stratum-fs: path has more than %u components\n",
                    STM_9P_MAX_WALK);
            return -1;
        }
        /* NUL-terminate the component in-place + record pointer. */
        if (i < plen) out->storage[i++] = '\0';
        out->names[out->count++] = &out->storage[start];
    }
    return 0;
}

/* Split a path into (parent, name) tuple. Useful for ops that walk to
 * the parent dir + operate on a child name (mkdir, create, rm, etc).
 * Returns -1 on error (e.g. root has no parent + name). On success
 * `*out_parent` holds the parent (may have count=0 for root) and
 * `*out_name` points into out_parent->storage at the leaf component. */
static int split_parent_name(const char *path, path_t *out_parent,
                                const char **out_name)
{
    if (parse_path(path, out_parent) < 0) return -1;
    if (out_parent->count == 0) {
        fprintf(stderr, "stratum-fs: '/' has no parent + name\n");
        return -1;
    }
    *out_name = out_parent->names[out_parent->count - 1];
    out_parent->count--;
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Connection management.                                                 */
/* ────────────────────────────────────────────────────────────────────── */

static stm_9p_client *open_connection(const char *socket_path)
{
    stm_9p_dial_opts o = {0};
    o.msize    = STM_9P_MSIZE_DEFAULT;
    o.uname    = "";
    o.aname    = "";
    o.n_uname  = (uint32_t)-1;
    o.root_fid = ROOT_FID;
    stm_9p_client *c = NULL;
    /* Retry-on-ECONNREFUSED: tolerate the daemon's accept loop
     * being slow to call accept() on the very first connection.
     * 50 × 10ms = 500ms cap is plenty under any reasonable
     * scheduling delay; longer = misconfiguration the user can
     * see directly. */
    stm_status rc = STM_EIO;
    int saved_errno = 0;
    for (int attempt = 0; attempt < 50; attempt++) {
        rc = stm_9p_dial_unix(socket_path, &o, &c);
        if (rc == STM_OK) return c;
        saved_errno = errno;
        if (rc != STM_EIO || saved_errno != ECONNREFUSED) break;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (rc == STM_EIO) {
        fprintf(stderr,
                "stratum-fs: connect to %s failed: %s\n",
                socket_path, strerror(saved_errno));
    } else {
        fprintf(stderr,
                "stratum-fs: dial %s: status=%d\n",
                socket_path, (int)rc);
    }
    return NULL;
}

/* Map stm_status → exit code. ENOENT → EXIT_NOTFOUND; everything else
 * → EXIT_IO. */
static int status_to_exit(stm_status rc)
{
    if (rc == STM_OK) return 0;
    if (rc == STM_ENOENT) return EXIT_NOTFOUND;
    return EXIT_IO;
}

static void perr(const char *op, stm_status rc)
{
    fprintf(stderr, "stratum-fs: %s: status=%d\n", op, (int)rc);
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: ls.                                                        */
/* ────────────────────────────────────────────────────────────────────── */

static stm_status ls_cb(const stm_9p_qid *qid, uint64_t cookie,
                            uint8_t type, const char *name, size_t name_len,
                            void *ctx)
{
    (void)cookie; (void)ctx; (void)name_len;
    char tag = '?';
    switch (type) {
    case 4:  tag = 'd'; break;   /* DT_DIR */
    case 8:  tag = '-'; break;   /* DT_REG */
    case 10: tag = 'l'; break;   /* DT_LNK */
    default: tag = '?'; break;
    }
    if (qid->type & STM_9P_QTDIR)      tag = 'd';
    else if (qid->type & STM_9P_QTSYMLINK) tag = 'l';
    printf("%c %s\n", tag, name);
    return STM_OK;
}

static int cmd_ls(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs ls PATH\n");
        return EXIT_USAGE;
    }
    path_t p;
    if (parse_path(argv[0], &p) < 0) return EXIT_USAGE;

    /* Walk root → WORK_FID over `p.count` components. */
    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    p.count, p.names, qids, &walked);
    if (rc != STM_OK) {
        perr("walk", rc);
        return status_to_exit(rc);
    }

    /* Open + readdir. */
    stm_9p_qid qid;
    rc = stm_9p_lopen(c, WORK_FID, STM_9P_O_RDONLY | STM_9P_O_DIRECTORY,
                          &qid, NULL);
    if (rc != STM_OK) {
        perr("open dir", rc);
        (void)stm_9p_clunk(c, WORK_FID);
        return status_to_exit(rc);
    }

    uint64_t offset = 0;
    /* Bounded loop: bail if next_offset doesn't advance OR after a
     * generous safety cap. Mirrors test_9p_client's pattern — the
     * server may report stable cookies that don't advance under
     * synth-only directories or pagination edge cases. */
    for (int iter = 0; iter < 1024; iter++) {
        uint32_t entries = 0;
        uint64_t next_offset = 0;
        uint64_t prev = offset;
        rc = stm_9p_readdir(c, WORK_FID, offset, /*count=*/0,
                                ls_cb, NULL, &entries, &next_offset);
        if (rc != STM_OK) {
            perr("readdir", rc);
            (void)stm_9p_clunk(c, WORK_FID);
            return status_to_exit(rc);
        }
        if (entries == 0) break;
        if (next_offset == prev) break;     /* defensive */
        offset = next_offset;
    }
    (void)stm_9p_clunk(c, WORK_FID);
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: stat.                                                      */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_stat(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs stat PATH\n");
        return EXIT_USAGE;
    }
    path_t p;
    if (parse_path(argv[0], &p) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    p.count, p.names, qids, &walked);
    if (rc != STM_OK) {
        perr("walk", rc);
        return status_to_exit(rc);
    }

    stm_9p_attr a = {0};
    rc = stm_9p_getattr(c, WORK_FID, STM_9P_GETATTR_BASIC, &a);
    if (rc != STM_OK) {
        perr("getattr", rc);
        (void)stm_9p_clunk(c, WORK_FID);
        return status_to_exit(rc);
    }

    printf("path:   %s\n", argv[0]);
    printf("ino:    %llu\n", (unsigned long long)a.qid.path);
    printf("mode:   %#o\n", (unsigned)(a.mode & 07777));
    printf("type:   ");
    if (a.qid.type & STM_9P_QTDIR)          printf("dir\n");
    else if (a.qid.type & STM_9P_QTSYMLINK) printf("symlink\n");
    else                                     printf("file\n");
    printf("uid:    %u\n", (unsigned)a.uid);
    printf("gid:    %u\n", (unsigned)a.gid);
    printf("nlink:  %llu\n", (unsigned long long)a.nlink);
    printf("size:   %llu\n", (unsigned long long)a.size);
    (void)stm_9p_clunk(c, WORK_FID);
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: read (cat).                                                */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_read(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs read PATH\n");
        return EXIT_USAGE;
    }
    path_t p;
    if (parse_path(argv[0], &p) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    p.count, p.names, qids, &walked);
    if (rc != STM_OK) {
        perr("walk", rc);
        return status_to_exit(rc);
    }

    stm_9p_qid qid;
    rc = stm_9p_lopen(c, WORK_FID, STM_9P_O_RDONLY, &qid, NULL);
    if (rc != STM_OK) {
        perr("open", rc);
        (void)stm_9p_clunk(c, WORK_FID);
        return status_to_exit(rc);
    }

    uint64_t offset = 0;
    uint8_t  buf[8192];
    while (1) {
        uint32_t got = 0;
        rc = stm_9p_read(c, WORK_FID, offset, buf, sizeof buf, &got);
        if (rc != STM_OK) {
            perr("read", rc);
            (void)stm_9p_clunk(c, WORK_FID);
            return status_to_exit(rc);
        }
        if (got == 0) break;
        if (fwrite(buf, 1, got, stdout) != got) {
            fprintf(stderr, "stratum-fs: short stdout write\n");
            (void)stm_9p_clunk(c, WORK_FID);
            return EXIT_IO;
        }
        offset += got;
    }
    (void)stm_9p_clunk(c, WORK_FID);
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: write (cat-stdin-into-file).                              */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_write(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs write PATH < input\n");
        return EXIT_USAGE;
    }
    path_t parent;
    const char *name = NULL;
    if (split_parent_name(argv[0], &parent, &name) < 0) return EXIT_USAGE;

    /* Walk root → WORK_FID for the parent dir. */
    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    parent.count, parent.names, qids, &walked);
    if (rc != STM_OK) {
        perr("walk parent", rc);
        return status_to_exit(rc);
    }

    /* lcreate name (which rebinds WORK_FID to the new file, opened
     * RDWR + TRUNC). If name already exists, fall back to walk + open
     * + truncate. */
    stm_9p_qid q;
    rc = stm_9p_lcreate(c, WORK_FID, name,
                            STM_9P_O_WRONLY | STM_9P_O_TRUNC,
                            0644u, (uint32_t)getgid(), &q, NULL);
    /* SWISS-4a: synthetic-FS servers (slate, /ctl/) don't implement
     * Tlcreate at all — they expose pre-existing virtual files only.
     * Falling back to walk-then-lopen on ENOTSUPPORTED treats them
     * the same as EEXIST does for real filesystems. */
    if (rc == STM_EEXIST || rc == STM_ENOTSUPPORTED) {
        /* Already exists — clunk parent, walk to file, open + truncate.
         *
         * R128 P1-1 (user-reported 2026-05-08 EINVAL on host→stm copy
         * when destination existed as a directory): before lopen with
         * O_TRUNC, getattr to verify the existing entry is a regular
         * file. If it's a dir or symlink, surface a clean error
         * BEFORE the server's TRUNC-on-non-regular path fires. The
         * server's posture (with this commit) returns EISDIR on dir,
         * but the client-side pre-check gives a friendlier message
         * AND saves a round-trip on the always-failing path. Symlinks
         * stay EINVAL (Linux behavior: O_TRUNC on symlink is unspec). */
        (void)stm_9p_clunk(c, WORK_FID);
        path_t p_full;
        if (parse_path(argv[0], &p_full) < 0) return EXIT_USAGE;
        rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                             p_full.count, p_full.names, qids, &walked);
        if (rc != STM_OK) { perr("walk file", rc); return status_to_exit(rc); }
        stm_9p_attr a;
        rc = stm_9p_getattr(c, WORK_FID, STM_9P_GETATTR_MODE, &a);
        if (rc != STM_OK) {
            perr("getattr", rc);
            (void)stm_9p_clunk(c, WORK_FID);
            return status_to_exit(rc);
        }
        uint32_t typ = a.mode & 0170000u;
        if (typ == 0040000u) {                      /* S_IFDIR */
            fprintf(stderr,
                "stratum-fs: %s is a directory; refusing to overwrite with file\n",
                argv[0]);
            (void)stm_9p_clunk(c, WORK_FID);
            return EXIT_IO;
        }
        if (typ != 0100000u && typ != 0u) {         /* not S_IFREG */
            fprintf(stderr,
                "stratum-fs: %s is not a regular file (mode=0%o); "
                "refusing to overwrite\n",
                argv[0], a.mode);
            (void)stm_9p_clunk(c, WORK_FID);
            return EXIT_IO;
        }
        rc = stm_9p_lopen(c, WORK_FID,
                              STM_9P_O_WRONLY | STM_9P_O_TRUNC, &q, NULL);
        if (rc != STM_OK) {
            perr("open", rc);
            (void)stm_9p_clunk(c, WORK_FID);
            return status_to_exit(rc);
        }
    } else if (rc != STM_OK) {
        perr("lcreate", rc);
        (void)stm_9p_clunk(c, WORK_FID);
        return status_to_exit(rc);
    }

    /* Stream stdin → fid. */
    uint64_t offset = 0;
    uint8_t  buf[8192];
    while (1) {
        size_t got = fread(buf, 1, sizeof buf, stdin);
        if (got == 0) break;
        uint32_t pos = 0;
        while (pos < (uint32_t)got) {
            uint32_t written = 0;
            rc = stm_9p_write(c, WORK_FID, offset + pos,
                                  buf + pos, (uint32_t)got - pos, &written);
            if (rc != STM_OK) {
                perr("write", rc);
                (void)stm_9p_clunk(c, WORK_FID);
                return status_to_exit(rc);
            }
            if (written == 0) {
                fprintf(stderr, "stratum-fs: server returned written=0\n");
                (void)stm_9p_clunk(c, WORK_FID);
                return EXIT_IO;
            }
            pos += written;
        }
        offset += got;
    }
    (void)stm_9p_clunk(c, WORK_FID);
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: mkdir.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_mkdir(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs mkdir PATH\n");
        return EXIT_USAGE;
    }
    path_t parent;
    const char *name = NULL;
    if (split_parent_name(argv[0], &parent, &name) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    parent.count, parent.names, qids, &walked);
    if (rc != STM_OK) { perr("walk parent", rc); return status_to_exit(rc); }

    stm_9p_qid q;
    rc = stm_9p_mkdir(c, WORK_FID, name, 0755u, (uint32_t)getgid(), &q);
    (void)stm_9p_clunk(c, WORK_FID);
    if (rc != STM_OK) { perr("mkdir", rc); return status_to_exit(rc); }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: create (touch).                                            */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_create(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs create PATH\n");
        return EXIT_USAGE;
    }
    path_t parent;
    const char *name = NULL;
    if (split_parent_name(argv[0], &parent, &name) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    parent.count, parent.names, qids, &walked);
    if (rc != STM_OK) { perr("walk parent", rc); return status_to_exit(rc); }

    stm_9p_qid q;
    rc = stm_9p_lcreate(c, WORK_FID, name, STM_9P_O_RDWR,
                            0644u, (uint32_t)getgid(), &q, NULL);
    (void)stm_9p_clunk(c, WORK_FID);
    if (rc != STM_OK) { perr("create", rc); return status_to_exit(rc); }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommands: rm + rmdir.                                               */
/* ────────────────────────────────────────────────────────────────────── */

static int unlink_with_flag(stm_9p_client *c, const char *path, uint32_t flags,
                              const char *opname)
{
    path_t parent;
    const char *name = NULL;
    if (split_parent_name(path, &parent, &name) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    parent.count, parent.names, qids, &walked);
    if (rc != STM_OK) { perr("walk parent", rc); return status_to_exit(rc); }

    rc = stm_9p_unlinkat(c, WORK_FID, name, flags);
    (void)stm_9p_clunk(c, WORK_FID);
    if (rc != STM_OK) { perr(opname, rc); return status_to_exit(rc); }
    return 0;
}

static int cmd_rm(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs rm PATH\n");
        return EXIT_USAGE;
    }
    return unlink_with_flag(c, argv[0], /*flags=*/0, "rm");
}

static int cmd_rmdir(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs rmdir PATH\n");
        return EXIT_USAGE;
    }
    return unlink_with_flag(c, argv[0], STM_9P_AT_REMOVEDIR, "rmdir");
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: chmod.                                                     */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_chmod(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: stratum-fs chmod MODE PATH\n");
        return EXIT_USAGE;
    }
    /* Parse mode as octal. */
    char *end = NULL;
    unsigned long mode = strtoul(argv[0], &end, 8);
    if (!end || *end != '\0' || mode > 07777) {
        fprintf(stderr, "stratum-fs: chmod: bad mode %s (must be octal ≤ 7777)\n",
                argv[0]);
        return EXIT_USAGE;
    }
    path_t p;
    if (parse_path(argv[1], &p) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    p.count, p.names, qids, &walked);
    if (rc != STM_OK) { perr("walk", rc); return status_to_exit(rc); }

    stm_9p_setattr_in in = {0};
    in.valid = STM_9P_SETATTR_MODE;
    in.mode  = (uint32_t)mode;
    rc = stm_9p_setattr(c, WORK_FID, &in);
    (void)stm_9p_clunk(c, WORK_FID);
    if (rc != STM_OK) { perr("chmod", rc); return status_to_exit(rc); }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommands: mv + ln + lns + readlink.                                 */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_mv(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: stratum-fs mv OLDPATH NEWPATH\n");
        return EXIT_USAGE;
    }
    path_t old_parent, new_parent;
    const char *old_name = NULL, *new_name = NULL;
    if (split_parent_name(argv[0], &old_parent, &old_name) < 0) return EXIT_USAGE;
    if (split_parent_name(argv[1], &new_parent, &new_name) < 0) return EXIT_USAGE;

    /* Walk old parent → WORK_FID, new parent → WORK_FID + 1. */
    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    old_parent.count, old_parent.names,
                                    qids, &walked);
    if (rc != STM_OK) { perr("walk old parent", rc); return status_to_exit(rc); }
    rc = stm_9p_walk(c, ROOT_FID, WORK_FID + 1,
                         new_parent.count, new_parent.names, qids, &walked);
    if (rc != STM_OK) {
        perr("walk new parent", rc);
        (void)stm_9p_clunk(c, WORK_FID);
        return status_to_exit(rc);
    }

    rc = stm_9p_renameat(c, WORK_FID, old_name, WORK_FID + 1, new_name);
    (void)stm_9p_clunk(c, WORK_FID);
    (void)stm_9p_clunk(c, WORK_FID + 1);
    if (rc != STM_OK) { perr("mv", rc); return status_to_exit(rc); }
    return 0;
}

static int cmd_ln(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: stratum-fs ln SRCPATH DSTPATH\n");
        return EXIT_USAGE;
    }
    path_t src, dst_parent;
    const char *dst_name = NULL;
    if (parse_path(argv[0], &src) < 0) return EXIT_USAGE;
    if (split_parent_name(argv[1], &dst_parent, &dst_name) < 0) return EXIT_USAGE;

    /* Walk src → WORK_FID, dst parent → WORK_FID + 1. */
    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    src.count, src.names, qids, &walked);
    if (rc != STM_OK) { perr("walk src", rc); return status_to_exit(rc); }
    rc = stm_9p_walk(c, ROOT_FID, WORK_FID + 1,
                         dst_parent.count, dst_parent.names, qids, &walked);
    if (rc != STM_OK) {
        perr("walk dst parent", rc);
        (void)stm_9p_clunk(c, WORK_FID);
        return status_to_exit(rc);
    }

    rc = stm_9p_link(c, WORK_FID + 1, WORK_FID, dst_name);
    (void)stm_9p_clunk(c, WORK_FID);
    (void)stm_9p_clunk(c, WORK_FID + 1);
    if (rc != STM_OK) { perr("ln", rc); return status_to_exit(rc); }
    return 0;
}

static int cmd_lns(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: stratum-fs lns TARGET LINKPATH\n");
        return EXIT_USAGE;
    }
    const char *target = argv[0];
    path_t parent;
    const char *name = NULL;
    if (split_parent_name(argv[1], &parent, &name) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    parent.count, parent.names, qids, &walked);
    if (rc != STM_OK) { perr("walk parent", rc); return status_to_exit(rc); }

    stm_9p_qid q;
    rc = stm_9p_symlink(c, WORK_FID, name, target,
                            (uint32_t)getgid(), &q);
    (void)stm_9p_clunk(c, WORK_FID);
    if (rc != STM_OK) { perr("lns", rc); return status_to_exit(rc); }
    return 0;
}

static int cmd_readlink(stm_9p_client *c, int argc, char **argv)
{
    if (argc != 1) {
        fprintf(stderr, "usage: stratum-fs readlink PATH\n");
        return EXIT_USAGE;
    }
    path_t p;
    if (parse_path(argv[0], &p) < 0) return EXIT_USAGE;

    stm_9p_qid qids[STM_9P_MAX_WALK];
    uint16_t walked = 0;
    stm_status rc = stm_9p_walk(c, ROOT_FID, WORK_FID,
                                    p.count, p.names, qids, &walked);
    if (rc != STM_OK) { perr("walk", rc); return status_to_exit(rc); }

    char  buf[4096];
    size_t got = 0;
    rc = stm_9p_readlink(c, WORK_FID, buf, sizeof buf, &got);
    (void)stm_9p_clunk(c, WORK_FID);
    if (rc != STM_OK) { perr("readlink", rc); return status_to_exit(rc); }
    printf("%s\n", buf);
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Subcommand: sync.                                                       */
/* ────────────────────────────────────────────────────────────────────── */

static int cmd_sync(stm_9p_client *c, int argc, char **argv)
{
    (void)argv;
    if (argc != 0) {
        fprintf(stderr, "usage: stratum-fs sync\n");
        return EXIT_USAGE;
    }
    /* Tfsync targets a fid; root suffices. v2.0 server routes to
     * stm_fs_commit (whole-pool) regardless of fid. */
    stm_status rc = stm_9p_fsync(c, ROOT_FID, /*datasync=*/0);
    if (rc != STM_OK) { perr("sync", rc); return status_to_exit(rc); }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────── */
/* Top-level dispatcher.                                                  */
/* ────────────────────────────────────────────────────────────────────── */

typedef int (*cmd_fn)(stm_9p_client *, int, char **);

typedef struct {
    const char *name;
    cmd_fn      fn;
    const char *brief;
    bool        mutates;       /* SWISS-4l: auto-fsync after success */
} cmd_entry;

static const cmd_entry CMDS[] = {
    { "ls",       cmd_ls,       "list directory entries",                        false },
    { "stat",     cmd_stat,     "show inode metadata",                           false },
    { "read",     cmd_read,     "write file contents to stdout",                 false },
    { "write",    cmd_write,    "write stdin to file (creates / truncates)",     true  },
    { "mkdir",    cmd_mkdir,    "create directory",                              true  },
    { "create",   cmd_create,   "create empty file (touch)",                     true  },
    { "rm",       cmd_rm,       "remove file",                                   true  },
    { "rmdir",    cmd_rmdir,    "remove empty directory",                        true  },
    { "chmod",    cmd_chmod,    "change permission bits (octal)",                true  },
    { "mv",       cmd_mv,       "rename",                                        true  },
    { "ln",       cmd_ln,       "hard link",                                     true  },
    { "lns",      cmd_lns,      "symbolic link",                                 true  },
    { "readlink", cmd_readlink, "read symlink target",                           false },
    { "sync",     cmd_sync,     "fsync (whole-pool commit)",                     false },
};

#define N_CMDS (sizeof(CMDS) / sizeof(CMDS[0]))

static void print_usage(void)
{
    fprintf(stderr,
        "usage: stratum-fs [-s SOCKET] CMD [ARGS...]\n"
        "       stratum-fs help\n"
        "\n"
        "Socket selection: -s SOCKET, $STRATUM_SOCKET, or %s.\n"
        "\n"
        "Commands:\n", DEFAULT_SOCKET);
    for (size_t i = 0; i < N_CMDS; i++) {
        fprintf(stderr, "  %-9s — %s\n", CMDS[i].name, CMDS[i].brief);
    }
}

int stm_cmd_fs_main(int argc, char **argv)
{
    /* Parse global flags before the subcommand. Only -s SOCKET. */
    const char *socket_path = getenv("STRATUM_SOCKET");
    if (!socket_path || socket_path[0] == '\0') socket_path = DEFAULT_SOCKET;

    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-s") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "stratum-fs: -s requires an argument\n");
                return EXIT_USAGE;
            }
            socket_path = argv[argi + 1];
            argi += 2;
        } else if (strcmp(argv[argi], "-h") == 0 ||
                   strcmp(argv[argi], "--help") == 0) {
            print_usage();
            return 0;
        } else if (strcmp(argv[argi], "--") == 0) {
            argi++;
            break;
        } else {
            fprintf(stderr, "stratum-fs: unknown flag %s\n", argv[argi]);
            print_usage();
            return EXIT_USAGE;
        }
    }

    if (argi >= argc) {
        print_usage();
        return EXIT_USAGE;
    }

    const char *subcmd = argv[argi++];
    if (strcmp(subcmd, "help") == 0) {
        print_usage();
        return 0;
    }

    /* Look up subcommand. */
    const cmd_entry *entry = NULL;
    for (size_t i = 0; i < N_CMDS; i++) {
        if (strcmp(subcmd, CMDS[i].name) == 0) {
            entry = &CMDS[i];
            break;
        }
    }
    if (!entry) {
        fprintf(stderr, "stratum-fs: unknown command %s\n", subcmd);
        print_usage();
        return EXIT_USAGE;
    }

    /* Open connection + dispatch. */
    stm_9p_client *c = open_connection(socket_path);
    if (!c) return EXIT_IO;
    int rc = entry->fn(c, argc - argi, argv + argi);

    /* SWISS-4l (user-reported 2026-05-08 lost-data-on-TUI-close +
     * user request "flush after a completed operation"): every
     * mutating subcommand gets an automatic Tfsync at the end. The
     * server routes Tfsync to whole-pool stm_fs_commit, so a single
     * call after the mutation makes the entire write durable on disk.
     *
     * This guarantees that every successful `stratum fs <mutator>`
     * invocation leaves the volume in a state recoverable across:
     *   - clean stratumd shutdown (already worked before, now reliable)
     *   - SIGKILL of stratumd (data still lands because each mutating
     *     CLI call has already issued a Tfsync that committed the
     *     three-phase sync to disk)
     *   - host crash (the last successful CLI call is the recovery
     *     boundary; partial in-flight writes still under torn-write
     *     recovery from the superblock + Merkle root)
     *
     * Cost: one extra round-trip + a 3-phase sync per mutating CLI
     * call. For batch ops (multi-select F5) this is N syncs for N
     * items. v1.0 acceptable; SWISS-4d2's BackendClient could batch
     * the syncs if performance matters.
     *
     * Skipped on rc != 0 — the mutation didn't complete, no point
     * forcing a sync. */
    if (rc == 0 && entry->mutates) {
        stm_status srv = stm_9p_fsync(c, ROOT_FID, /*datasync=*/0);
        if (srv != STM_OK) {
            fprintf(stderr,
                "stratum-fs: post-op sync failed: status=%d "
                "(your write succeeded but is NOT yet durable on disk)\n",
                (int)srv);
            rc = EXIT_IO;
        }
    }

    stm_9p_close(c);
    return rc;
}
