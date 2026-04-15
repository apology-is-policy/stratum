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

static int serve_client(int fd, struct stm_fs *fs)
{
    struct stm_9p *srv = NULL;
    uint8_t *req = NULL, *resp = NULL;
    uint32_t msize = 65536;
    int rc = 0;

    if (stm_9p_create(fs, &srv) != 0) return -1;

    req  = malloc(msize);
    resp = malloc(msize);
    if (!req || !resp) { rc = -1; goto out; }

    while (running) {
        uint8_t hdr[4];
        ssize_t n;
        uint32_t size, resp_len;

        /* read 4-byte size */
        n = read(fd, hdr, 4);
        if (n <= 0) break;
        if (n < 4) { rc = -1; break; }

        size = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) |
               ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
        if (size < 7 || size > msize) { rc = -1; break; }

        memcpy(req, hdr, 4);
        n = read(fd, req + 4, size - 4);
        if (n < (ssize_t)(size - 4)) { rc = -1; break; }

        resp_len = msize;
        stm_9p_handle(srv, req, size, resp, &resp_len);

        /* write response */
        {
            uint32_t written = 0;
            while (written < resp_len) {
                n = write(fd, resp + written, resp_len - written);
                if (n <= 0) { rc = -1; goto out; }
                written += (uint32_t)n;
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
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc)
            pass = argv[++i];
        else if (!path) path = argv[i];
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
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc)
            pass = argv[++i];
        else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc)
            listen_addr = argv[++i];
        else if (!path)
            path = argv[i];
    }

    if (!path) {
        fprintf(stderr, "Usage: stratum serve <path> [--pass <pass>] [--listen <addr>]\n");
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
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc)
            pass = argv[++i];
        else if (!path) path = argv[i];
    }

    if (!path) {
        fprintf(stderr, "Usage: stratum info <path> [--pass <passphrase>]\n");
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
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc)
            pass = argv[++i];
        else if (!path) path = argv[i];
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

/* ── main ───────────────────────────────────────────────────────────── */

static void usage(void)
{
    fprintf(stderr,
        "Usage: stratum <command> [options]\n"
        "\n"
        "Commands:\n"
        "  mkfs  <path> <size> [--pass <passphrase>]    Create a new filesystem\n"
        "  serve <path> [--pass <pass>] [--listen <addr>] Serve over 9P\n"
        "  info  <path> [--pass <passphrase>]            Show filesystem info\n"
        "  snap  <path> [--pass <p>] <create|list|delete|rollback> [name|id]\n"
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
    if (strcmp(cmd, "snap") == 0)  return cmd_snap(argc - 2, argv + 2);
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0) { usage(); return 0; }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage();
    return 1;
}
