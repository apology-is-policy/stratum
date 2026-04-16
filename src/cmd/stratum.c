/*
 * stratum — CLI for creating and serving Stratum filesystems.
 *
 * Usage:
 *   stratum mkfs <path> <size>  [--pass <passphrase>]
 *   stratum serve <path> [--pass <passphrase>] [--listen <addr>]
 *   stratum info <path>  [--pass <passphrase>]
 *   stratum snap <path>  [--pass <passphrase>] <create|list|delete|rollback> [name|id]
 *
 * Listen address formats:
 *   unix:/tmp/stratum.sock   (default)
 *   tcp:localhost:5640
 */

#include "stratum/fs.h"
#include "stratum/snap.h"
#include "stratum/p9.h"
#include "stratum/alloc.h"
#include "stratum/btree.h"
#include "stratum/inode.h"
#include "stratum/key.h"
#include "stratum/block.h"
#include "stratum/crypto.h"
#include "../fs/fs_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static volatile int running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

/* Read password from stdin (one line, no trailing newline). */
static char stdin_pass_buf[256];
static const char *read_pass_stdin(void)
{
    if (!fgets(stdin_pass_buf, sizeof(stdin_pass_buf), stdin))
        return NULL;
    size_t len = strlen(stdin_pass_buf);
    while (len > 0 && (stdin_pass_buf[len-1] == '\n' || stdin_pass_buf[len-1] == '\r'))
        stdin_pass_buf[--len] = '\0';
    return len > 0 ? stdin_pass_buf : NULL;
}


static int print_snap_cb(uint64_t id, const char *name, uint64_t gen, void *ctx)
{
    if (ctx) { (*(int *)ctx)++; }
    printf("  #%llu  %-20s  (gen %llu)\n",
           (unsigned long long)id, name, (unsigned long long)gen);
    return 0;
}

/* ── parse size string (e.g. "256M", "1G", "4096") ─────────────────── */

static uint64_t parse_size(const char *s)
{
    char *end;
    uint64_t v = strtoull(s, &end, 10);
    switch (*end) {
    case 'k': case 'K': v *= 1024; break;
    case 'm': case 'M': v *= 1024 * 1024; break;
    case 'g': case 'G': v *= 1024 * 1024 * 1024; break;
    case 't': case 'T': v *= (uint64_t)1024 * 1024 * 1024 * 1024; break;
    }
    return v;
}

/* ── 9P socket server ───────────────────────────────────────────────── */

/* read exactly `len` bytes, looping on partial reads */
static int read_exact(int fd, void *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t n = read(fd, (uint8_t *)buf + done, len - done);
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static int serve_client(int fd, struct stm_fs *fs)
{
    struct stm_9p *srv = NULL;
    uint8_t *req = NULL, *resp = NULL;
    uint32_t msize = P9_MSIZE_DEFAULT;
    int rc = 0;

    if (stm_9p_create(fs, &srv) != 0) return -1;

    req  = malloc(msize);
    resp = malloc(msize);
    if (!req || !resp) { rc = -1; goto out; }

    while (running) {
        uint32_t size, resp_len;

        /* read 4-byte size header */
        if (read_exact(fd, req, 4) != 0) {
            fprintf(stderr, "[9p] client disconnected (read header)\n");
            break;
        }

        size = (uint32_t)req[0] | ((uint32_t)req[1] << 8) |
               ((uint32_t)req[2] << 16) | ((uint32_t)req[3] << 24);
        if (size < 7 || size > msize) {
            fprintf(stderr, "[9p] bad message size: %u (msize=%u)\n", size, msize);
            rc = -1; break;
        }

        /* read rest of message */
        if (read_exact(fd, req + 4, size - 4) != 0) {
            fprintf(stderr, "[9p] client disconnected (read body, size=%u)\n", size);
            rc = -1; break;
        }

        resp_len = msize;
        stm_9p_handle(srv, req, size, resp, &resp_len);

        /* write response */
        {
            uint32_t written = 0;
            while (written < resp_len) {
                ssize_t w = write(fd, resp + written, resp_len - written);
                if (w <= 0) {
                    fprintf(stderr, "[9p] write response failed (errno=%d)\n", errno);
                    rc = -1; goto out;
                }
                written += (uint32_t)w;
            }
        }
    }

out:
    free(req);
    free(resp);
    stm_9p_destroy(srv);
    return rc;
}

static int listen_unix(const char *path)
{
    struct sockaddr_un addr;
    int fd;

    unlink(path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, 4) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

static int listen_tcp(const char *host, int port)
{
    struct sockaddr_in addr;
    int fd, opt = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return -1; }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (host && *host)
        inet_pton(AF_INET, host, &addr.sin_addr);
    else
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(fd); return -1;
    }
    if (listen(fd, 4) < 0) {
        perror("listen"); close(fd); return -1;
    }
    return fd;
}

/* ── commands ───────────────────────────────────────────────────────── */

static int cmd_mkfs(int argc, char **argv)
{
    const char *path = NULL, *pass = NULL;
    uint64_t size = 0;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) { pass = argv[++i]; continue; }
        if (strcmp(argv[i], "--pass-stdin") == 0) { pass = read_pass_stdin(); continue; }
        if (!path) path = argv[i];
        else if (!size) size = parse_size(argv[i]);
    }

    if (!path || !size) {
        fprintf(stderr, "Usage: stratum mkfs <path> <size> [--pass <passphrase>]\n");
        fprintf(stderr, "  Size: e.g. 256M, 1G, 4096\n");
        return 1;
    }

    int rc = stm_fs_create(path, size, pass);
    if (rc) {
        fprintf(stderr, "mkfs failed: %s\n", strerror(-rc));
        return 1;
    }
    printf("Created %s (%.1f MiB)\n", path, (double)size / (1024 * 1024));
    return 0;
}

static int cmd_serve(int argc, char **argv)
{
    const char *path = NULL, *pass = NULL, *listen_addr = "unix:/tmp/stratum.sock";
    struct stm_fs *fs = NULL;
    int listen_fd = -1, client_fd, i, rc;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) { pass = argv[++i]; continue; }
        if (strcmp(argv[i], "--pass-stdin") == 0) { pass = read_pass_stdin(); continue; }
        if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc) { listen_addr = argv[++i]; continue; }
        if (!path) path = argv[i];
    }

    if (!path) {
        fprintf(stderr, "Usage: stratum serve <path> [--pass <pass>|--pass-stdin] [--listen <addr>]\n");
        fprintf(stderr, "  Addr: unix:/path  or  tcp:host:port (default: unix:/tmp/stratum.sock)\n");
        return 1;
    }

    rc = stm_fs_open(path, pass, &fs);
    if (rc) {
        fprintf(stderr, "open failed: %s\n", strerror(-rc));
        return 1;
    }

    if (strncmp(listen_addr, "unix:", 5) == 0) {
        listen_fd = listen_unix(listen_addr + 5);
    } else if (strncmp(listen_addr, "tcp:", 4) == 0) {
        char host[256] = {0};
        int port = 5640;
        const char *hp = listen_addr + 4;
        const char *colon = strrchr(hp, ':');
        if (colon) {
            memcpy(host, hp, (size_t)(colon - hp));
            port = atoi(colon + 1);
        } else {
            strncpy(host, hp, sizeof(host) - 1);
        }
        listen_fd = listen_tcp(host, port);
    } else {
        fprintf(stderr, "Unknown listen address format: %s\n", listen_addr);
        stm_fs_close(fs);
        return 1;
    }

    if (listen_fd < 0) { stm_fs_close(fs); return 1; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("Serving %s on %s\n", path, listen_addr);
    printf("Press Ctrl+C to stop.\n");

    while (running) {
        client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (!running) break;
            perror("accept");
            continue;
        }
        printf("Client connected.\n");
        serve_client(client_fd, fs);
        close(client_fd);
        printf("Client disconnected.\n");

        /* sync after each client session */
        stm_fs_sync(fs);
    }

    printf("\nShutting down...\n");
    stm_fs_sync(fs);
    close(listen_fd);
    if (strncmp(listen_addr, "unix:", 5) == 0)
        unlink(listen_addr + 5);
    stm_fs_close(fs);
    return 0;
}

static int cmd_info(int argc, char **argv)
{
    const char *path = NULL, *pass = NULL;
    struct stm_fs *fs = NULL;
    int i, rc;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) { pass = argv[++i]; continue; }
        if (strcmp(argv[i], "--pass-stdin") == 0) { pass = read_pass_stdin(); continue; }
        if (!path) path = argv[i];
    }

    if (!path) {
        fprintf(stderr, "Usage: stratum info <path> [--pass <pass>|--pass-stdin]\n");
        return 1;
    }

    rc = stm_fs_open(path, pass, &fs);
    if (rc) {
        fprintf(stderr, "open failed: %s\n", strerror(-rc));
        return 1;
    }

    printf("Stratum filesystem: %s\n", path);

    /* list snapshots */
    printf("\nSnapshots:\n");
    {
        int count = 0;
        stm_snap_list(fs, print_snap_cb, &count);
        if (count == 0) printf("  (none)\n");
    }

    stm_fs_close(fs);
    return 0;
}

static int cmd_snap(int argc, char **argv)
{
    const char *path = NULL, *pass = NULL, *subcmd = NULL, *arg = NULL;
    struct stm_fs *fs = NULL;
    int i, rc;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) { pass = argv[++i]; continue; }
        if (strcmp(argv[i], "--pass-stdin") == 0) { pass = read_pass_stdin(); continue; }
        if (!path) path = argv[i];
        else if (!subcmd) subcmd = argv[i];
        else if (!arg) arg = argv[i];
    }

    if (!path || !subcmd) {
        fprintf(stderr, "Usage: stratum snap <path> [--pass <pass>] <create|list|delete|rollback> [name|id]\n");
        return 1;
    }

    rc = stm_fs_open(path, pass, &fs);
    if (rc) { fprintf(stderr, "open failed: %s\n", strerror(-rc)); return 1; }

    if (strcmp(subcmd, "create") == 0) {
        if (!arg) { fprintf(stderr, "snap create requires a name\n"); stm_fs_close(fs); return 1; }
        uint64_t id;
        rc = stm_snap_create(fs, arg, &id);
        if (rc) { fprintf(stderr, "snap create failed: %s\n", strerror(-rc)); }
        else { printf("Snapshot #%llu '%s' created.\n", (unsigned long long)id, arg); }
        stm_fs_sync(fs);
    } else if (strcmp(subcmd, "list") == 0) {
        stm_snap_list(fs, print_snap_cb, NULL);
    } else if (strcmp(subcmd, "delete") == 0) {
        if (!arg) { fprintf(stderr, "snap delete requires an id\n"); stm_fs_close(fs); return 1; }
        rc = stm_snap_delete(fs, (uint64_t)atoll(arg));
        if (rc) fprintf(stderr, "snap delete failed: %s\n", strerror(-rc));
        else printf("Snapshot deleted.\n");
        stm_fs_sync(fs);
    } else if (strcmp(subcmd, "rollback") == 0) {
        if (!arg) { fprintf(stderr, "snap rollback requires an id\n"); stm_fs_close(fs); return 1; }
        rc = stm_snap_rollback(fs, (uint64_t)atoll(arg));
        if (rc) fprintf(stderr, "rollback failed: %s\n", strerror(-rc));
        else { printf("Rolled back.\n"); stm_fs_sync(fs); }
    } else {
        fprintf(stderr, "Unknown snap command: %s\n", subcmd);
    }

    stm_fs_close(fs);
    return rc ? 1 : 0;
}

/* ── check (fsck) ──────────────────────────────────────────────────── */

static const char *human_size_buf(uint64_t bytes);  /* forward decl */

struct check_ctx {
    struct stm_fs *fs;
    uint64_t dev_blocks;
    int errors;
    int warnings;
    uint64_t node_count;
    uint64_t entry_count;
    uint64_t extent_count;
    uint64_t extent_bytes;
    uint64_t inode_count;
};

static int check_node_cb(uint64_t paddr, uint32_t csize, void *ctx)
{
    struct check_ctx *c = ctx;
    uint64_t block = paddr / STM_BLOCK_SIZE;
    uint32_t nblocks = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;

    c->node_count++;

    if (block + nblocks > c->dev_blocks) {
        fprintf(stderr, "  ERROR: node at 0x%llx (%u bytes) extends past device end (%llu blocks)\n",
                (unsigned long long)paddr, csize, (unsigned long long)c->dev_blocks);
        c->errors++;
    }
    if (csize == 0) {
        fprintf(stderr, "  ERROR: node at 0x%llx has zero compressed size\n",
                (unsigned long long)paddr);
        c->errors++;
    }
    return 0;
}

static int check_entry_cb(const struct stm_key *key, const void *val,
                          uint32_t vlen, void *ctx)
{
    struct check_ctx *c = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);

    c->entry_count++;

    if (kc.type == STM_KEY_INODE) {
        c->inode_count++;
        if (vlen != sizeof(struct stm_inode)) {
            fprintf(stderr, "  ERROR: inode %llu: bad value size %u (expected %zu)\n",
                    (unsigned long long)kc.ino, vlen, sizeof(struct stm_inode));
            c->errors++;
        }
    } else if (kc.type == STM_KEY_DATA) {
        c->extent_count++;
        if (vlen != sizeof(struct stm_extent)) {
            fprintf(stderr, "  ERROR: ino %llu offset %llu: bad extent size %u (expected %zu)\n",
                    (unsigned long long)kc.ino, (unsigned long long)kc.offset,
                    vlen, sizeof(struct stm_extent));
            c->errors++;
            return 0;
        }
        struct stm_extent ext;
        memcpy(&ext, val, sizeof(ext));
        uint64_t paddr = le64_to_cpu(ext.se_paddr);
        uint32_t dlen = le32_to_cpu(ext.se_dlen);
        c->extent_bytes += dlen;

        if (paddr == 0) {
            fprintf(stderr, "  ERROR: ino %llu offset %llu: extent paddr is 0 (superblock area)\n",
                    (unsigned long long)kc.ino, (unsigned long long)kc.offset);
            c->errors++;
        }
        if (dlen == 0) {
            fprintf(stderr, "  WARN: ino %llu offset %llu: zero-length extent\n",
                    (unsigned long long)kc.ino, (unsigned long long)kc.offset);
            c->warnings++;
        }
        if (dlen > STM_EXTENT_SIZE) {
            fprintf(stderr, "  ERROR: ino %llu offset %llu: extent dlen %u exceeds max %u\n",
                    (unsigned long long)kc.ino, (unsigned long long)kc.offset,
                    dlen, (uint32_t)STM_EXTENT_SIZE);
            c->errors++;
        }

        struct stm_crypto *crypto = stm_btree_get_crypto(c->fs->tree);
        uint32_t disk_len = crypto ? (dlen + STM_CRYPTO_TAG_LEN) : dlen;
        uint32_t nblocks = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
        uint64_t block = paddr / STM_BLOCK_SIZE;

        if (block + nblocks > c->dev_blocks) {
            fprintf(stderr, "  ERROR: ino %llu offset %llu: extent at 0x%llx (%u bytes) past device end\n",
                    (unsigned long long)kc.ino, (unsigned long long)kc.offset,
                    (unsigned long long)paddr, disk_len);
            c->errors++;
        }
    }
    return 0;
}

static int cmd_check(int argc, char **argv)
{
    const char *path = NULL, *pass = NULL;
    struct stm_fs *fs = NULL;
    int i, rc;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) { pass = argv[++i]; continue; }
        if (strcmp(argv[i], "--pass-stdin") == 0) { pass = read_pass_stdin(); continue; }
        if (!path) path = argv[i];
    }

    if (!path) {
        fprintf(stderr, "Usage: stratum check <path> [--pass <pass>|--pass-stdin]\n");
        return 1;
    }

    printf("Checking %s...\n\n", path);

    /* Phase 1: superblocks */
    {
        struct stm_block_dev dev;
        struct stm_superblock sa, sb;
        rc = stm_file_backend_open(path, 0, 0, &dev);
        if (rc) { fprintf(stderr, "Cannot open: %s\n", strerror(-rc)); return 1; }

        stm_block_read(&dev, STM_SB_OFFSET_A, &sa, sizeof(sa));
        stm_block_read(&dev, STM_SB_OFFSET_B, &sb, sizeof(sb));

        int a_ok = (le64_to_cpu(sa.ss_magic) == STM_MAGIC);
        int b_ok = (le64_to_cpu(sb.ss_magic) == STM_MAGIC);

        printf("Superblock A: %s", a_ok ? "valid" : "INVALID");
        if (a_ok) printf(" (gen %llu)", (unsigned long long)le64_to_cpu(sa.ss_gen));
        printf("\n");

        printf("Superblock B: %s", b_ok ? "valid" : "INVALID");
        if (b_ok) printf(" (gen %llu)", (unsigned long long)le64_to_cpu(sb.ss_gen));
        printf("\n");

        if (!a_ok && !b_ok) {
            printf("\nFATAL: no valid superblock found.\n");
            stm_block_close(&dev);
            return 1;
        }

        struct stm_superblock *chosen = NULL;
        if (a_ok && b_ok) {
            chosen = (le64_to_cpu(sa.ss_gen) >= le64_to_cpu(sb.ss_gen)) ? &sa : &sb;
            printf("Using: %s (higher gen)\n",
                   chosen == &sa ? "A" : "B");
        } else {
            chosen = a_ok ? &sa : &sb;
            printf("Using: %s (only valid)\n", a_ok ? "A" : "B");
        }

        uint64_t dev_bytes = 0;
        stm_block_size(&dev, &dev_bytes);
        printf("Device size: %llu bytes (%llu blocks)\n",
               (unsigned long long)dev_bytes,
               (unsigned long long)(dev_bytes / STM_BLOCK_SIZE));
        printf("Encryption: %s\n",
               chosen->ss_enc_algo != 0 ? "yes" : "no");
        printf("Next inode: %llu\n",
               (unsigned long long)le64_to_cpu(chosen->ss_next_ino));

        stm_block_close(&dev);
    }

    /* Phase 2: open and walk */
    printf("\nOpening filesystem...\n");
    rc = stm_fs_open(path, pass, &fs);
    if (rc) {
        fprintf(stderr, "FATAL: cannot open: %s\n", strerror(-rc));
        return 1;
    }

    uint64_t dev_bytes = 0;
    stm_block_size(&fs->dev, &dev_bytes);

    struct check_ctx ctx = {
        .fs = fs,
        .dev_blocks = dev_bytes / STM_BLOCK_SIZE,
    };

    printf("Walking btree nodes and entries...\n");
    rc = stm_btree_walk_entries(fs->tree, stm_btree_root(fs->tree),
                                check_node_cb, check_entry_cb, &ctx);
    if (rc) {
        fprintf(stderr, "  ERROR: tree walk failed: %s\n", strerror(-rc));
        ctx.errors++;
    }

    /* Phase 3: check root directory exists */
    {
        struct stm_inode root_in;
        rc = stm_fs_stat(fs, STM_ROOT_INO, &root_in);
        if (rc) {
            fprintf(stderr, "  ERROR: root directory (ino 1) not found\n");
            ctx.errors++;
        } else {
            printf("Root directory: OK\n");
        }
    }

    /* Phase 4: summary */
    printf("\n--- Summary ---\n");
    printf("Btree nodes:  %llu\n", (unsigned long long)ctx.node_count);
    printf("Leaf entries:  %llu\n", (unsigned long long)ctx.entry_count);
    printf("  Inodes:      %llu\n", (unsigned long long)ctx.inode_count);
    printf("  Extents:     %llu (%s of data)\n",
           (unsigned long long)ctx.extent_count,
           human_size_buf(ctx.extent_bytes));
    printf("Allocator:     %llu / %llu blocks free\n",
           (unsigned long long)stm_alloc_free_count(fs->alloc),
           (unsigned long long)ctx.dev_blocks);

    if (ctx.errors == 0 && ctx.warnings == 0) {
        printf("\nFilesystem is clean.\n");
    } else {
        printf("\n%d error(s), %d warning(s).\n", ctx.errors, ctx.warnings);
    }

    stm_fs_close(fs);
    return ctx.errors > 0 ? 1 : 0;
}

static const char *human_size_buf(uint64_t bytes)
{
    static char buf[32];
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double val = (double)bytes;
    int u = 0;
    while (val >= 1024.0 && u < 4) { val /= 1024.0; u++; }
    snprintf(buf, sizeof(buf), "%.1f %s", val, units[u]);
    return buf;
}

/* ── main ───────────────────────────────────────────────────────────── */

static void usage(void)
{
    fprintf(stderr,
        "Usage: stratum <command> [options]\n"
        "\n"
        "Commands:\n"
        "  mkfs  <path> <size> [--pass <p>|--pass-stdin]   Create a new filesystem\n"
        "  serve <path> [--pass <p>|--pass-stdin] [--listen <addr>]  Serve over 9P\n"
        "  info  <path> [--pass <p>|--pass-stdin]        Show filesystem info\n"
        "  check <path> [--pass <p>|--pass-stdin]        Check filesystem integrity\n"
        "  snap  <path> [--pass <p>|--pass-stdin] <create|list|delete|rollback> [name]\n"
        "\n"
        "Listen address: unix:/path (default: unix:/tmp/stratum.sock) or tcp:host:port\n"
    );
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }

    const char *cmd = argv[1];
    if (strcmp(cmd, "mkfs") == 0)  return cmd_mkfs(argc - 2, argv + 2);
    if (strcmp(cmd, "serve") == 0) return cmd_serve(argc - 2, argv + 2);
    if (strcmp(cmd, "info") == 0)  return cmd_info(argc - 2, argv + 2);
    if (strcmp(cmd, "check") == 0) return cmd_check(argc - 2, argv + 2);
    if (strcmp(cmd, "snap") == 0)  return cmd_snap(argc - 2, argv + 2);
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0) { usage(); return 0; }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage();
    return 1;
}
