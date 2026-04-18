/*
 * stratum scrub — online integrity sweep.
 *
 * Walks every btree node (forces xxHash3 csum and AEAD tag verification via
 * stm_btree_read_node) and every DATA extent (forces AEAD tag verification
 * via extent_read_data). Read-only: opens via stm_fs_open_ro so no disk
 * writes, suitable for cron-style periodic verification.
 *
 * On encrypted volumes, scrub is airtight — every bit of data is
 * AEAD-authenticated, so bitrot surfaces as an Rerror on first read. On
 * unencrypted volumes today, extent payload bytes have no per-extent
 * integrity field (SOTA #7 adds xxHash3 to each extent record); scrub still
 * exercises btree-node csums but reports extent payload as "unverifiable."
 *
 * Exit code:  0 = clean, 1 = errors found, 2 = couldn't run (bad path,
 * wrong passphrase, etc.) — matches fsck convention.
 */

#include "stratum/fs.h"
#include "stratum/btree.h"
#include "stratum/key.h"
#include "stratum/snapshot.h"
#include "../btree/btree_internal.h"
#include "../fs/fs_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

struct scrub_ctx {
    struct stm_fs *fs;
    uint8_t       *buf;           /* STM_EXTENT_SIZE scratch */
    uint64_t       nodes;
    uint64_t       extents;
    uint64_t       bytes;
    uint64_t       errors;
    int            verbose;
    int            encrypted;     /* mirrors fs->encrypted */
    struct timespec last_progress;
};

static const char *human_bytes(uint64_t b, char *buf, size_t cap)
{
    static const char *u[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    int i = 0;
    double v = (double)b;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    snprintf(buf, cap, "%.1f %s", v, u[i]);
    return buf;
}

static void progress_maybe(struct scrub_ctx *c)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - c->last_progress.tv_sec)
                   + (now.tv_nsec - c->last_progress.tv_nsec) / 1e9;
    if (elapsed < 1.0) return;
    c->last_progress = now;
    char hb[32];
    human_bytes(c->bytes, hb, sizeof(hb));
    fprintf(stderr,
            "\r  %llu nodes, %llu extents, %s verified, %llu errors",
            (unsigned long long)c->nodes,
            (unsigned long long)c->extents,
            hb,
            (unsigned long long)c->errors);
    fflush(stderr);
}

/* Per-node visit. The walk framework has already called stm_btree_read_node
 * on this paddr by the time it invokes us — csum + AEAD already verified
 * (or failed, in which case entry_cb / visit never fires and the walk
 * returns non-zero). So here we just count. */
static int visit_node(uint64_t paddr, uint32_t csize, void *ctx)
{
    (void)paddr; (void)csize;
    struct scrub_ctx *c = ctx;
    c->nodes++;
    progress_maybe(c);
    return 0;
}

/* Per-leaf-entry visit. For DATA keys we force a full extent read, which
 * exercises the AEAD tag (encrypted volumes), compression decode, and
 * length bounds (unencrypted). For INODE/DIRENT/SNAP/other keys we just
 * acknowledge — the enclosing node's csum already covered them. */
static int visit_entry(const struct stm_key *key, const void *val,
                       uint32_t vlen, void *ctx)
{
    struct scrub_ctx *c = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (kc.type != STM_KEY_DATA) return 0;
    if (vlen != sizeof(struct stm_extent)) return 0;

    struct stm_extent ext;
    memcpy(&ext, val, sizeof(ext));

    int rc = extent_read_data(c->fs, &ext, c->buf, STM_EXTENT_SIZE);
    c->extents++;
    if (rc == 0) {
        /* extent_read_data returns the logical (dlen) length on success;
         * we don't get it as a separate output, so read se_dlen from the
         * record itself. */
        uint32_t dlen = le32_to_cpu(ext.se_dlen);
        c->bytes += dlen;
    } else {
        c->errors++;
        uint64_t paddr = le64_to_cpu(ext.se_paddr);
        fprintf(stderr,
                "\n  EXTENT FAIL ino=%llu offset=%llu paddr=%llu rc=%d\n",
                (unsigned long long)kc.ino,
                (unsigned long long)kc.offset,
                (unsigned long long)paddr,
                rc);
    }
    progress_maybe(c);
    return 0;  /* continue the walk even after a failure — we want a full report */
}

/* Walk a saved snapshot's tree. Called once per SNAP descriptor. */
static int scrub_snap_cb(const struct stm_key *key, const void *val,
                         uint32_t vlen, void *ctx)
{
    struct scrub_ctx *c = ctx;
    struct stm_snapshot snap;
    (void)key;
    if (vlen < sizeof(snap)) return 0;
    memcpy(&snap, val, sizeof(snap));

    int rc = stm_btree_walk_entries(c->fs->tree, snap.ssp_root,
                                    visit_node, visit_entry, c);
    if (rc) {
        c->errors++;
        fprintf(stderr,
                "\n  SNAPSHOT WALK FAIL id=%llu rc=%d\n",
                (unsigned long long)le64_to_cpu(snap.ssp_id), rc);
    }
    return 0;
}

static const char *read_pass_stdin_local(void)
{
    static char buf[256];
    if (!fgets(buf, sizeof(buf), stdin)) return NULL;
    size_t n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') buf[n - 1] = 0;
    return buf;
}

int stm_cmd_scrub(int argc, char **argv)
{
    const char *path = NULL, *pass = NULL;
    int verbose = 0;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) { pass = argv[++i]; continue; }
        if (strcmp(argv[i], "--pass-stdin") == 0) { pass = read_pass_stdin_local(); continue; }
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) { verbose = 1; continue; }
        if (!path) path = argv[i];
    }

    if (!path) {
        fprintf(stderr,
                "Usage: stratum scrub <path> [--pass <p>|--pass-stdin] [--verbose]\n");
        return 2;
    }

    struct stm_fs *fs = NULL;
    int rc = stm_fs_open_ro(path, pass, &fs);
    if (rc) {
        fprintf(stderr, "stratum scrub: cannot open %s: %s\n", path, strerror(-rc));
        return 2;
    }

    struct scrub_ctx c;
    memset(&c, 0, sizeof(c));
    c.fs = fs;
    c.buf = malloc(STM_EXTENT_SIZE);
    c.verbose = verbose;
    c.encrypted = fs->encrypted;
    clock_gettime(CLOCK_MONOTONIC, &c.last_progress);
    if (!c.buf) {
        fprintf(stderr, "stratum scrub: out of memory\n");
        stm_fs_close(fs);
        return 2;
    }

    printf("Scrubbing %s (%s)...\n", path,
           c.encrypted ? "encrypted — full AEAD verification"
                       : "unencrypted — metadata only, extent data unverifiable");

    /* Main tree. */
    rc = stm_btree_walk_entries(fs->tree, stm_btree_root(fs->tree),
                                visit_node, visit_entry, &c);
    if (rc) {
        c.errors++;
        fprintf(stderr, "\n  MAIN TREE WALK FAIL rc=%d\n", rc);
    }

    /* Snap tree structure (descriptors + name index). */
    if (fs->snap_tree) {
        rc = stm_btree_walk_entries(fs->snap_tree, stm_btree_root(fs->snap_tree),
                                    visit_node, NULL, &c);
        if (rc) {
            c.errors++;
            fprintf(stderr, "\n  SNAP TREE WALK FAIL rc=%d\n", rc);
        }
        /* Every saved snapshot's subtree. */
        struct stm_key lo = stm_mk_key(0, STM_KEY_SNAP, 0);
        struct stm_key hi = stm_mk_key(UINT64_MAX, STM_KEY_SNAP, UINT64_MAX);
        rc = stm_btree_scan(fs->snap_tree, &lo, &hi, scrub_snap_cb, &c);
        if (rc) {
            c.errors++;
            fprintf(stderr, "\n  SNAP DESCRIPTOR SCAN FAIL rc=%d\n", rc);
        }
    }

    /* Flush the progress line and emit summary. */
    char hb[32];
    human_bytes(c.bytes, hb, sizeof(hb));
    fprintf(stderr, "\r%*s\r", 72, "");  /* clear the progress line */
    printf("\n  Nodes verified:   %llu\n", (unsigned long long)c.nodes);
    printf("  Extents verified: %llu\n",   (unsigned long long)c.extents);
    printf("  Bytes scrubbed:   %s\n",     hb);
    printf("  Errors:           %llu\n",   (unsigned long long)c.errors);

    if (c.errors == 0) printf("\nClean.\n");
    else               printf("\n%llu error(s) — volume has bitrot or corruption.\n",
                              (unsigned long long)c.errors);

    free(c.buf);
    stm_fs_close(fs);
    return c.errors == 0 ? 0 : 1;
}
