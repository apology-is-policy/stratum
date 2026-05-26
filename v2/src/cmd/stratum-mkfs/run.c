/* SPDX-License-Identifier: ISC */
/*
 * stratum-mkfs — create a fresh stratum volume image (v2).
 *
 * Wraps stm_fs_format + initial dataset-root setup so users can
 * `stratum-mkfs vol.stm` and immediately point stratumd at it.
 *
 * Default behaviour:
 *   - 64 MiB device size, 16 MiB bootstrap pool.
 *   - Generates a fresh PQ-hybrid keyfile at <image>.key (override
 *     via --keyfile PATH).
 *   - Initialises dataset id=1 with a single root inode (mode 0755,
 *     uid/gid 0). stratumd's --root-dataset defaults to 1, so the
 *     resulting image is ready to serve.
 *
 * Volume identity: pool/device UUIDs derived from the current time +
 * pid. Good enough for v1.0; cryptographic random UUIDs are a
 * forward-note for v1.1.
 *
 * Usage:
 *   stratum-mkfs IMAGE [--size SIZE] [--keyfile PATH]
 *
 *   --size SIZE     Image size; suffix K/M/G accepted.
 *                   Default: 64M.
 *   --keyfile PATH  Path to write the PQ-hybrid keyfile (or use an
 *                   existing one if PATH already exists). Default:
 *                   <IMAGE>.key.
 *
 * Exit codes:
 *   0  success
 *   1  usage error
 *   2  format failed
 */
#include <stratum/cmds.h>
#include <stratum/fs.h>
#include <stratum/keyfile.h>
#include <stratum/types.h>

#include "../cli_passphrase.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Default sizes — matches test scaffold defaults scaled up so a fresh
 * image has comfortable headroom for browsing. */
#define DEFAULT_DEVICE_BYTES     (UINT64_C(64) * 1024 * 1024)   /* 64 MiB */
#define MIN_DEVICE_BYTES         (UINT64_C(16) * 1024 * 1024)   /* lower bound — bootstrap won't fit smaller */
/* SWISS-4n3 (user-reported 2026-05-08 ENOMEM/-12 + ENOSPC/-28 on a
 * 500 MB write to a 3 GB volume): the bootstrap pool holds the
 * allocator + extent + inode metadata btrees. A hardcoded 16 MiB
 * default exhausted on any non-trivial write because it didn't scale
 * with volume size. Auto-scale instead: floor of 8 MiB, ceiling of
 * 256 MiB, target = device/64. For 3 GB → 48 MiB, for 64 GiB →
 * 256 MiB capped, for tiny test volumes (16-64 MiB) → 8 MiB floor.
 *
 * The `--bootstrap` flag still allows manual override for users
 * who want to tune for very-many-small-files workloads. */
static uint64_t default_bootstrap_for(uint64_t device_bytes)
{
    /* SWISS-4n3 v2: bumped target ratio from /64 to /16 because /64
     * caused STM_EOVERFLOW on a 1.5 GB write to a 3 GB volume (the
     * extent btree's per-inode metadata grew past what 48 MiB could
     * index). /16 with a 256 MiB ceiling tracks better:
     *   - 32 MiB device     → 8 MiB  (floor)
     *   - 1 GiB device      → 64 MiB
     *   - 3 GiB device      → 192 MiB
     *   - 16 GiB device     → 256 MiB (ceiling — usually enough)
     * Forward-noted: server-side metadata-density work (larger
     * default extents, btree fanout tuning) is the proper fix; this
     * is just the closest knob the CLI controls. */
    const uint64_t MIN_BOOT = UINT64_C(8)   * 1024 * 1024;   /*  8 MiB */
    const uint64_t MAX_BOOT = UINT64_C(256) * 1024 * 1024;   /* 256 MiB */
    uint64_t target = device_bytes / 16u;
    if (target < MIN_BOOT) target = MIN_BOOT;
    if (target > MAX_BOOT) target = MAX_BOOT;
    return target;
}

static void usage(void)
{
    fputs(
"usage: stratum-mkfs IMAGE [options]\n"
"\n"
"Creates a fresh stratum volume image with one initial dataset (id=1).\n"
"After mkfs, point stratumd at it:\n"
"\n"
"    stratumd IMAGE --listen unix:/tmp/stm.sock\n"
"\n"
"Options:\n"
"  --size SIZE      Image size with K/M/G suffix. Default: 64M.\n"
"  --keyfile PATH   Path to read/write the PQ-hybrid keyfile.\n"
"                   If file exists, it's used as-is. If missing, one is\n"
"                   generated. Default: IMAGE.key.\n"
"  --passphrase-stdin  Read a passphrase line from stdin and use it to\n"
"                   wrap the keyfile (KFP1 format). The passphrase is\n"
"                   required at every stratumd open after this. Mutually\n"
"                   exclusive with the unencrypted-keyfile path.\n"
"  --bootstrap SIZE Bootstrap pool size. Default: 16M (auto-scaled to\n"
"                   max(64MiB, device/1024) by libfs if 0).\n"
"  --seed HEX64     Pin the UUID-derivation seed to a fixed 64-bit\n"
"                   hex value (optional 0x prefix; up to 16 hex chars).\n"
"                   Same seed -> identical pool/device UUIDs but pool\n"
"                   on-disk bytes are still NOT byte-identical because\n"
"                   the keyfile + libsodium nonces add per-run entropy.\n"
"                   For full byte reproduction, pin the keyfile (use\n"
"                   --keyfile with an existing file) AND the seed.\n"
"                   When omitted, derives from time+pid (default).\n"
"  -h, --help       Print this help.\n",
        stderr);
}

/* Optional seed for derive_uuid (Thylacine-pouch-arm: pin pool.img
 * byte layout for content-sensitive bug reproduction). Set by
 * --seed; consumed by derive_uuid. */
static bool     g_mkfs_seed_set = false;
static uint64_t g_mkfs_seed     = 0;

/* Parse a hex string up to 16 chars into a uint64_t. Returns false
 * on empty / non-hex / overlong input. Tolerates a leading "0x". */
static bool parse_hex64(const char *s, uint64_t *out)
{
    if (!s) return false;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (*s == '\0') return false;
    uint64_t v = 0;
    int      n = 0;
    for (; *s; s++, n++) {
        if (n >= 16) return false;
        char c = *s;
        unsigned d;
        if (c >= '0' && c <= '9')      d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
        else return false;
        v = (v << 4) | d;
    }
    *out = v;
    return true;
}

/* Parse a size like "64M", "1G", "512K", "1048576". Returns 0 on
 * failure. */
static uint64_t parse_size(const char *s)
{
    if (!s || !*s) return 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (!end || end == s || v == 0) return 0;
    /* Allow trailing K/M/G (case-insensitive). */
    if (*end == 'K' || *end == 'k') { v *= 1024ULL;                end++; }
    else if (*end == 'M' || *end == 'm') { v *= 1024ULL * 1024ULL; end++; }
    else if (*end == 'G' || *end == 'g') { v *= 1024ULL * 1024ULL * 1024ULL; end++; }
    if (*end != '\0') return 0;
    return (uint64_t)v;
}

/* Derive a 128-bit UUID-shape value from current time + pid (or from
 * the --seed value if set). Not cryptographically random;
 * "unique enough" for early v2. The --seed path lets callers pin the
 * derivation across runs (Thylacine-pouch-arm extension: same seed ->
 * same pool/device UUIDs -> reproducible on-disk byte layout for
 * content-sensitive bug investigation). */
static void derive_uuid(uint64_t out[2], uint64_t salt)
{
    uint64_t hi, lo;
    if (g_mkfs_seed_set) {
        /* Seed-pinned: mix the seed into hi/lo with two distinct
         * multiplicative constants so the two halves don't collapse
         * into the same value. Salt then differentiates per-UUID
         * (POOL vs DEV). */
        hi = g_mkfs_seed;
        lo = g_mkfs_seed * 0x9e3779b97f4a7c15ULL;
    } else {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        uint64_t pid = (uint64_t)getpid();
        hi = ((uint64_t)ts.tv_sec << 32)
           ^ ((uint64_t)ts.tv_nsec)
           ^ (pid << 16);
        lo = ((uint64_t)ts.tv_nsec * 0x9e3779b97f4a7c15ULL)
           ^ (pid * 0x100000001b3ULL);
    }
    out[0] = hi ^ salt;
    out[1] = lo ^ ~salt;
}

int stm_cmd_mkfs_main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }

    const char *image_path = argv[1];
    uint64_t   device_bytes      = DEFAULT_DEVICE_BYTES;
    uint64_t   bootstrap_bytes   = 0;   /* 0 = auto from device_bytes */
    const char *keyfile_path     = NULL;
    bool       passphrase_stdin  = false;

    /* Parse remaining flags. */
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--size") == 0) {
            if (i + 1 >= argc) { fputs("--size requires an argument\n", stderr); return 1; }
            uint64_t v = parse_size(argv[i + 1]);
            if (v == 0) {
                fprintf(stderr, "stratum-mkfs: bad --size: %s\n", argv[i + 1]);
                return 1;
            }
            device_bytes = v;
            i++;
        } else if (strcmp(argv[i], "--bootstrap") == 0) {
            if (i + 1 >= argc) { fputs("--bootstrap requires an argument\n", stderr); return 1; }
            uint64_t v = parse_size(argv[i + 1]);
            if (v == 0) {
                fprintf(stderr, "stratum-mkfs: bad --bootstrap: %s\n", argv[i + 1]);
                return 1;
            }
            bootstrap_bytes = v;
            i++;
        } else if (strcmp(argv[i], "--keyfile") == 0) {
            if (i + 1 >= argc) { fputs("--keyfile requires an argument\n", stderr); return 1; }
            keyfile_path = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "--passphrase-stdin") == 0) {
            passphrase_stdin = true;
        } else if (strcmp(argv[i], "--seed") == 0) {
            if (i + 1 >= argc) {
                fputs("--seed requires a hex64 argument\n", stderr);
                return 1;
            }
            if (!parse_hex64(argv[i + 1], &g_mkfs_seed)) {
                fprintf(stderr,
                    "stratum-mkfs: bad --seed: %s (expect <=16 hex chars, "
                    "optional 0x prefix)\n",
                    argv[i + 1]);
                return 1;
            }
            g_mkfs_seed_set = true;
            i++;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else {
            fprintf(stderr, "stratum-mkfs: unknown argument: %s\n", argv[i]);
            usage();
            return 1;
        }
    }

    if (device_bytes < MIN_DEVICE_BYTES) {
        fprintf(stderr,
            "stratum-mkfs: --size %llu too small (minimum 16M to fit bootstrap pool)\n",
            (unsigned long long)device_bytes);
        return 1;
    }
    /* SWISS-4n3: derive bootstrap-pool size from --size when the user
     * didn't specify --bootstrap explicitly. The libfs heuristic
     * (max(64 MiB, dev/1024)) is too generous for tiny test volumes
     * (would refuse 16-MiB images); ours scales floor → 8 MiB,
     * ceiling → 256 MiB, target → device/64. */
    if (bootstrap_bytes == 0) {
        bootstrap_bytes = default_bootstrap_for(device_bytes);
    }
    if (bootstrap_bytes >= device_bytes) {
        fprintf(stderr,
            "stratum-mkfs: --bootstrap %llu must be < --size %llu\n",
            (unsigned long long)bootstrap_bytes,
            (unsigned long long)device_bytes);
        return 1;
    }

    /* Default keyfile path is <image>.key. */
    char default_key_path[1024];
    if (!keyfile_path) {
        int n = snprintf(default_key_path, sizeof default_key_path,
                          "%s.key", image_path);
        if (n < 0 || (size_t)n >= sizeof default_key_path) {
            fputs("stratum-mkfs: image path too long for default keyfile\n", stderr);
            return 1;
        }
        keyfile_path = default_key_path;
    }

    /* SWISS-4m: passphrase buffer kept across format + post-mount
     * + dataset-init + commit + unmount. Wiped once at function
     * exit. */
    char   passbuf[STM_CLI_PASSPHRASE_MAX + 1];
    size_t plen = 0;
    bool   have_pass = false;
    if (passphrase_stdin) {
        stm_cli_passphrase_lock_best_effort(passbuf, sizeof passbuf);
        stm_status rs = stm_cli_read_passphrase_stdin(passbuf, sizeof passbuf, &plen);
        if (rs != STM_OK || plen == 0) {
            stm_ct_memzero(passbuf, sizeof passbuf);
            stm_cli_passphrase_unlock(passbuf, sizeof passbuf);
            fprintf(stderr,
                "stratum-mkfs: failed to read passphrase from stdin "
                "(empty or > %u bytes)\n",
                (unsigned)STM_CLI_PASSPHRASE_MAX);
            return 1;
        }
        have_pass = true;
    }

    /* Generate keyfile if missing. With --passphrase-stdin, we ALWAYS
     * generate a fresh KFP1-encrypted file (refusing to overwrite
     * pre-existing would surprise the user). */
    struct stat st;
    if (have_pass) {
        stm_status rc = stm_keyfile_generate_passphrase(keyfile_path,
                                                              passbuf, plen);
        if (rc != STM_OK) {
            stm_ct_memzero(passbuf, sizeof passbuf);
            stm_cli_passphrase_unlock(passbuf, sizeof passbuf);
            fprintf(stderr,
                "stratum-mkfs: stm_keyfile_generate_passphrase(%s) failed: "
                "status=%d\n", keyfile_path, (int)rc);
            return 2;
        }
        fprintf(stderr, "generated encrypted keyfile: %s\n", keyfile_path);
    } else if (stat(keyfile_path, &st) != 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "stratum-mkfs: cannot stat keyfile %s: %s\n",
                    keyfile_path, strerror(errno));
            return 1;
        }
        stm_status rc = stm_keyfile_generate(keyfile_path);
        if (rc != STM_OK) {
            fprintf(stderr, "stratum-mkfs: stm_keyfile_generate(%s) failed: status=%d\n",
                    keyfile_path, (int)rc);
            return 2;
        }
        fprintf(stderr, "generated keyfile: %s\n", keyfile_path);
    } else {
        fprintf(stderr, "using existing keyfile: %s\n", keyfile_path);
    }

    /* Derive distinct UUIDs for pool + device with different salts. */
    uint64_t pool_uuid[2], device_uuid[2];
    derive_uuid(pool_uuid,   0x504F4F4C);  /* 'POOL' */
    derive_uuid(device_uuid, 0x44455600);  /* 'DEV\0' */
    if (g_mkfs_seed_set) {
        fprintf(stderr, "stratum-mkfs: seed=0x%016llx (pinned via --seed)\n",
                (unsigned long long)g_mkfs_seed);
    } else {
        fprintf(stderr, "stratum-mkfs: pool_uuid=%016llx%016llx "
                "(time+pid; pass --seed HEX to pin)\n",
                (unsigned long long)pool_uuid[0],
                (unsigned long long)pool_uuid[1]);
    }

    stm_fs_format_opts fopts = {
        .device_size_bytes        = device_bytes,
        .bootstrap_size_bytes     = bootstrap_bytes,
        .pool_uuid                = { pool_uuid[0],   pool_uuid[1]   },
        .device_uuid              = { device_uuid[0], device_uuid[1] },
        .keyfile_path             = keyfile_path,
        .keyfile_passphrase       = have_pass ? passbuf : NULL,
        .keyfile_passphrase_len   = have_pass ? plen    : 0,
    };

    /* Phase 1: format. */
    int exit_code = 0;
    fprintf(stderr, "formatting %s (%llu bytes)...\n",
            image_path, (unsigned long long)device_bytes);
    stm_status rc = stm_fs_format(image_path, &fopts);
    if (rc != STM_OK) {
        fprintf(stderr, "stratum-mkfs: stm_fs_format failed: status=%d\n", (int)rc);
        exit_code = 2;
        goto cleanup;
    }

    /* Phase 2: mount, init dataset root id=1, unmount. */
    stm_fs_mount_opts mopts = {
        .read_only                = false,
        .keyfile_path             = keyfile_path,
        .keyfile_passphrase       = have_pass ? passbuf : NULL,
        .keyfile_passphrase_len   = have_pass ? plen    : 0,
    };
    stm_fs *fs = NULL;
    rc = stm_fs_mount(image_path, &mopts, &fs);
    if (rc != STM_OK) {
        fprintf(stderr, "stratum-mkfs: stm_fs_mount post-format failed: status=%d\n",
                (int)rc);
        exit_code = 2;
        goto cleanup;
    }
    uint64_t root_ino = 0;
    rc = stm_fs_init_dataset_root(fs, /*ds=*/1u,
                                       /*mode=*/0755u,
                                       /*uid=*/0, /*gid=*/0,
                                       &root_ino);
    if (rc != STM_OK) {
        fprintf(stderr, "stratum-mkfs: init_dataset_root failed: status=%d\n", (int)rc);
        (void)stm_fs_unmount(fs);
        exit_code = 2;
        goto cleanup;
    }
    rc = stm_fs_commit(fs);
    if (rc != STM_OK) {
        fprintf(stderr, "stratum-mkfs: commit failed: status=%d\n", (int)rc);
        (void)stm_fs_unmount(fs);
        exit_code = 2;
        goto cleanup;
    }
    rc = stm_fs_unmount(fs);
    if (rc != STM_OK) {
        fprintf(stderr, "stratum-mkfs: unmount failed: status=%d\n", (int)rc);
        exit_code = 2;
        goto cleanup;
    }

    fprintf(stderr,
        "ok: %s ready (dataset 1 root ino=%llu)\n"
        "    next: stratumd %s --listen unix:/tmp/stm.sock\n",
        image_path,
        (unsigned long long)root_ino,
        image_path);

cleanup:
    /* SWISS-4m: wipe + munlock the passphrase buffer regardless of
     * exit path. Stack-allocated, so munlock + memzero is enough —
     * the storage is freed when this stack frame unwinds. */
    if (have_pass) {
        stm_ct_memzero(passbuf, sizeof passbuf);
        stm_cli_passphrase_unlock(passbuf, sizeof passbuf);
    }
    return exit_code;
}
