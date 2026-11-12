/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * stratum-mkfs — create a fresh stratum volume image (v2).
 *
 * Wraps stm_fs_format + initial dataset-root setup so users can
 * `stratum-mkfs vol.stm` and immediately point stratumd at it.
 *
 * Default behaviour:
 *   - 64 MiB device size, and a bootstrap pool of a sixteenth of it,
 *     no less than 8 MiB and no more than 256 MiB.
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
 *   --keyfile PATH  Path to write the PQ-hybrid keyfile (or, with no
 *                   passphrase, use one already there that is the
 *                   user's alone, or any regular file under
 *                   --key-as-is).
 *                   Default: <IMAGE>.key.
 *
 * Exit codes:
 *   0  success
 *   1  a usage error, or a refusal that made nothing
 *   2  the format failed, or the volume is formatted and its key did not take, or
 *      is not reached by, the name it was to have
 */
#include <stratum/block.h>
#include <stratum/cmds.h>
#include <stratum/fs.h>
#include <stratum/keyfile.h>
#include <stratum/takename.h>
#include <stratum/types.h>

#include "../cli_passphrase.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#include <sys/param.h>
#endif
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
 * 256 MiB, target = device/16. For 3 GiB, 192 MiB; for 64 GiB,
 * 256 MiB capped; for tiny test volumes (16-64 MiB), the 8 MiB floor.
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

/* Thylacine has no root: uid 0 is its invalid principal. */
#if defined(__thylacine__)
#define LINK_OWNERS "the user"
#else
#define LINK_OWNERS "the user or root"
#endif

static void usage(void)
{
    fputs(
"usage: stratum-mkfs IMAGE [options]\n"
"\n"
"Creates a fresh stratum volume image with one initial dataset (id=1).\n"
"After mkfs, point stratumd at it:\n"
"\n"
"    stratum serve IMAGE --listen /tmp/stm.sock\n"
"\n"
"Options:\n"
"  --size SIZE      Image size with K/M/G suffix. Default: 64M.\n"
"  --force          Format over what is already at IMAGE, a file another user\n"
"                   owns too, and with --passphrase-stdin replace an existing\n"
"                   keyfile. Whatever they held is gone. Also follows any key\n"
"                   link it can read, whoever owns it, however many names it\n"
"                   has and wherever it leads, and uses a keyfile that is not\n"
"                   the user's alone. A new key is not sent through a link\n"
"                   that cannot be read: it takes that link's place.\n"
"                   Never overrides a daemon using IMAGE, and a format\n"
"                   cannot shrink a file: --size must reach it.\n"
"  --key-as-is      Use the keyfile that is there although another user owns\n"
"                   it or its mode gives others access; it must still be a\n"
"                   regular file. Nothing else of what --force does: no\n"
"                   format over data, no key replaced, no link of another\n"
"                   user's followed. Not with --passphrase-stdin, where the\n"
"                   key is always new.\n"
"  --keyfile PATH   Path to read/write the PQ-hybrid keyfile.\n"
"                   If file exists, it's used as-is when it is a regular\n"
"                   file the user owns whose mode gives no one else access\n"
"                   (chmod go-rwx) or, under --key-as-is, any regular file,\n"
"                   and with --passphrase-stdin it is refused, unless\n"
"                   --force. If missing, one is generated where its\n"
"                   links point. Links at PATH, to a key that exists or to\n"
"                   where one is to go, are followed when they are seven at\n"
"                   most, " LINK_OWNERS " owns each, and each can be\n"
"                   read and has no other name. Where they lead out of\n"
"                   PATH's directory, it must be to one that only\n"
"                   " LINK_OWNERS " can change.\n"
"                   Default: IMAGE.key.\n"
"  --passphrase-stdin  Read a passphrase line from stdin and use it to\n"
"                   wrap the keyfile (KFP1 format). The passphrase is\n"
"                   required at every stratumd open after this. Mutually\n"
"                   exclusive with the unencrypted-keyfile path.\n"
"  --bootstrap SIZE Bootstrap pool size. Default: a sixteenth of --size,\n"
"                   no less than 8M and no more than 256M.\n"
"  --root-uid N     Owner uid for the dataset root inode (default 0).\n"
"  --root-gid N     Owner gid for the dataset root inode (default 0).\n"
"                   N <= 4294967294. Used by Thylacine's host-bake to own\n"
"                   the root as PRINCIPAL_SYSTEM so the boot chain can\n"
"                   populate it once the OS enforces 9P-mount rwx.\n"
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
    unsigned long long unit = 1ULL;
    if (*end == 'K' || *end == 'k') { unit = 1024ULL;                end++; }
    else if (*end == 'M' || *end == 'm') { unit = 1024ULL * 1024ULL; end++; }
    else if (*end == 'G' || *end == 'g') { unit = 1024ULL * 1024ULL * 1024ULL; end++; }
    if (*end != '\0' || v > UINT64_MAX / unit) return 0;
    return (uint64_t)(v * unit);
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

/* Nothing but zeros anywhere: a fresh or sparse file, safe to format. A volume's
 * first MiB can be blank, and a file need not be a volume. Holes cost nothing to pass. */
static bool image_holds_data(int fd, bool *out)
{
    static unsigned char buf[65536];
    off_t off = 0;
    *out = false;
    for (;;) {
#ifdef SEEK_DATA
        off_t data = lseek(fd, off, SEEK_DATA);
        if (data < 0 && errno == ENXIO) return true; /* a hole to the end */
        if (data >= 0) off = data;                   /* no such call here: read through */
#endif
        ssize_t n = pread(fd, buf, sizeof buf, off);
        if (n < 0) return false;
        if (n == 0) return true;
        for (ssize_t i = 0; i < n; i++) {
            if (buf[i] != 0) { *out = true; return true; }
        }
        off += n;
    }
}

/* Why the links at the key's name were not followed to where they end. */
enum key_links {
    KEY_LINKS_FOLLOWED,
    KEY_LINKS_TOO_MANY,
    KEY_LINKS_ANOTHERS,
    KEY_LINKS_MANY_NAMES,
    KEY_LINKS_UNREAD,
    KEY_LINKS_CHANGED,
};

/* What a reading of those links came to. */
struct key_walk {
    enum key_links why;
    int err;        /* KEY_LINKS_UNREAD: what readlink said */
    int links;      /* how many were followed */
    bool there;     /* whether anything is where they end */
    struct stat st; /* what is there */
};

static const char *key_destination(const char *path, char *buf, size_t n, bool force,
                                   struct key_walk *walk);
static bool link_is_trusted(const struct stat *st);

/* What a name is the name of, for what is said of the links at it. */
struct named {
    const char *what;   /* before the path */
    const char *goes;   /* what another user's link would decide */
    const char *itself; /* what to name in place of a link */
    const char *loss;   /* what whoever can change the directory it leads to could do */
};
static const struct named NAMED_KEY = {
    "keyfile", "the key", "the key file itself", "could remove the key, and the volume with it",
};
static const struct named NAMED_IMAGE = {
    "image", "the volume", "the image itself",
    "could remove the volume, or put an older copy of it back",
};

/* A key used as it is decides who can open the volume: one another user owns, or that
 * its mode lets others read or write, is theirs as much as the user's. The corvus token
 * is held to the same. NULL when the key is the user's alone, or is a file the user said
 * to use as it is, else what is wrong with it and what mends that. */
static const char *key_not_the_users(const struct stat *st, bool as_is)
{
    if (!S_ISREG(st->st_mode)) return "is not a regular file, so no key to use";
    if (as_is) return NULL;
    if (st->st_uid != geteuid())
        return "belongs to another user, who could open any volume made with it: run as "
               "its owner or make it the user's own, or, if it can be read, pass "
               "--key-as-is to use it as it is";
    if ((st->st_mode & (S_IRWXG | S_IRWXO)) != 0)
        return "can be read or written by others, going by its mode, and the volume "
               "would be theirs to open: chmod go-rwx it, or pass --key-as-is to use it as "
               "it is";
    return NULL;
}

/* Why the links at a name were not followed. */
static void say_links_refused(const struct named *n, const char *path,
                              const struct key_walk *walk)
{
    switch (walk->why) {
    case KEY_LINKS_ANOTHERS:
        fprintf(stderr,
            "stratum-mkfs: %s %s is reached through a symlink another user owns, who "
            "would decide where %s goes; pass --force to follow it\n",
            n->what, path, n->goes);
        break;
    case KEY_LINKS_MANY_NAMES:
        fprintf(stderr,
            "stratum-mkfs: %s %s is reached through a symlink that has another name "
            "besides this one, and any user may have given it either: name %s, or make "
            "the link again\n", n->what, path, n->itself);
        break;
    case KEY_LINKS_UNREAD:
        fprintf(stderr,
            "stratum-mkfs: %s %s is reached through a link that cannot be read (%s), "
            "so where it leads cannot be asked about: see why, or name %s\n",
            n->what, path, strerror(walk->err), n->itself);
        break;
    case KEY_LINKS_CHANGED:
        fprintf(stderr,
            "stratum-mkfs: a link on the way to %s %s changed while it was being read, "
            "so nothing was asked of what is there now: see who changed it before running "
            "again\n", n->what, path);
        break;
    default:
        fprintf(stderr,
            "stratum-mkfs: %s %s is reached through more than seven links or a loop of "
            "them, or names a path too long: name %s\n", n->what, path, n->itself);
        break;
    }
}

/* Where the name reaches something the links read from it do not end in. */
static void say_name_leads_elsewhere(const struct named *n, const char *path)
{
    /* Chosen out here: fprintf can be a macro, and a directive among a macro's arguments
     * is undefined. */
#if defined(__thylacine__)
    const char *whose = "a share's, whose text the kernel reads from the share's root";
#else
    const char *whose = "a descriptor's, whose text names no file (a pipe's, an unlinked file's)";
#endif
    fprintf(stderr,
        "stratum-mkfs: %s %s does not lead where its links were read to end: a link "
        "or a file was left or changed on its way while it was looked at, or one of its "
        "links is %s: name %s, or see what was left, before running "
        "again\n", n->what, path, whose, n->itself);
}

/* The directory part of a path, "." where it has none. False when it does not fit. */
static bool dir_part(const char *path, char *dir, size_t n)
{
    const char *slash = strrchr(path, '/');
    size_t len = !slash || slash == path ? 1u : (size_t)(slash - path);
    if (len >= n) return false;
    memcpy(dir, slash ? path : ".", len);
    dir[len] = '\0';
    return true;
}

/* A directory to make a key in, or to take an unfinished image out of. One the user
 * may write and search but not read still takes a key, so where it cannot be opened
 * for reading it is opened for the search alone. Linux does not sync a directory
 * opened so, which is said; macOS does. */
static int open_key_dir(const char *dir)
{
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#if defined(O_SEARCH)
    if (fd < 0 && errno == EACCES) fd = open(dir, O_SEARCH | O_DIRECTORY | O_CLOEXEC);
#elif defined(O_PATH)
    if (fd < 0 && errno == EACCES) fd = open(dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
#endif
    return fd;
}

/* Links that lead a key out of the directory it was named in decide where it is kept,
 * and their owner says less of that than it seems: a link of the user's or root's that
 * once had a second name can be put anywhere by whoever gave it that name, and its text
 * leads on from there. So the directory they lead to is asked about itself. NULL when
 * it is the one the key was named in, which the user chose, or one where only the user
 * or root can take a name away: theirs, with nobody else let to write it or, sticky,
 * to do more than add names. Else what is wrong with it. */
static const char *led_to_dir_refused(const struct stat *dd, const char *keyfile_path)
{
    char named[4096];
    struct stat nd;
    if (dir_part(keyfile_path, named, sizeof named) && stat(named, &nd) == 0
            && nd.st_dev == dd->st_dev && nd.st_ino == dd->st_ino)
        return NULL;
    if (!link_is_trusted(dd)) return "belongs to another user";
    if ((dd->st_mode & (S_IWGRP | S_IWOTH)) != 0 && (dd->st_mode & S_ISVTX) == 0)
        return "others can change, going by its mode (chmod go-w mends that)";
    return NULL;
}

static void say_dir_refused(const struct named *n, const char *path, const char *dir,
                            const char *why, bool since_the_claim)
{
    fprintf(stderr,
        "stratum-mkfs: %s%s %s is led by its links to the directory %s, which %s: "
        "whoever can change that directory %s; "
        "name %s, or pass --force to follow the links\n",
        since_the_claim ? "since the volume was claimed, " : "", n->what, path, dir, why,
        n->loss, n->itself);
}

/* At the claim, by its path. Where a new key is made the directory is asked about
 * again, through the descriptor the key is made in. */
static bool led_to_dir_in_the_way(const struct named *n, const char *path,
                                  const char *leads_to, bool reached)
{
    char dir[4096];
    struct stat dd;
    if (!dir_part(leads_to, dir, sizeof dir)) return false;
    if (stat(dir, &dd) != 0 || !S_ISDIR(dd.st_mode)) {
        /* No directory yet for a key that is not there either. */
        if (!reached) return false;
        say_name_leads_elsewhere(n, path);
        return true;
    }
    const char *why = led_to_dir_refused(&dd, path);
    if (!why) return false;
    say_dir_refused(n, path, dir, why, false);
    return true;
}

/*
 * Formatting over a pool loses it, and over a pool's key loses it just as
 * surely, so neither happens by naming the wrong path. The claim is held until
 * the process ends: a daemon cannot start on the image between the look and the
 * format, and --force does not reach past a daemon already on it.
 */
static bool key_in_the_way(const char *keyfile_path, bool replaces_key, bool force,
                           bool key_as_is, bool *key_there, struct stat *key_seen)
{
    struct stat st;
    char dest[4096];
    struct key_walk walk;
    *key_there = false;
    const char *leads_to = key_destination(keyfile_path, dest, sizeof dest, force, &walk);
    /* Past where that gives up, the stat below would follow links nobody asked about. */
    if (!leads_to && !force) {
        say_links_refused(&NAMED_KEY, keyfile_path, &walk);
        return true;
    }
    if (force) return false;
    /* The links were followed here by their text; the kernel follows them itself when
     * the key is opened. What the name reaches has to be what they were read to end
     * in: it is not where a link to something, or a file, was left or changed after
     * the reading, nor where a link's text is no path to what it opens, as a
     * descriptor's is not for a pipe or an unlinked file. A link to nothing left at a
     * free name passes, as the free name does: it is asked about where the new key's
     * place is. */
    bool reached = stat(keyfile_path, &st) == 0;
    if (reached != walk.there
            || (reached && (st.st_dev != walk.st.st_dev || st.st_ino != walk.st.st_ino))) {
        say_name_leads_elsewhere(&NAMED_KEY, keyfile_path);
        return true;
    }
    if (walk.links > 0 && led_to_dir_in_the_way(&NAMED_KEY, keyfile_path, leads_to, reached))
        return true;
    if (!reached) return false;
    if (!replaces_key) {
        const char *why = key_not_the_users(&st, key_as_is);
        if (!why) {
            *key_there = true;
            *key_seen = st;
            return false;
        }
        fprintf(stderr, "stratum-mkfs: keyfile %s %s\n", keyfile_path, why);
        return true;
    }
    fprintf(stderr,
        "stratum-mkfs: keyfile %s already exists, and replacing it loses any "
        "volume it opens; pass --force to replace it\n", keyfile_path);
    return true;
}

/* The claim's open followed whatever links are at the image's name. They are asked
 * about as a key's are, and the file the claim has open has to be the one they were
 * read to end in: a link left or changed between the open and the reading is one that
 * nothing was asked of. */
static bool image_links_in_the_way(const char *image_path, int claimed)
{
    char dest[4096];
    struct key_walk walk;
    struct stat st;
    const char *leads_to = key_destination(image_path, dest, sizeof dest, false, &walk);
    if (!leads_to) {
        say_links_refused(&NAMED_IMAGE, image_path, &walk);
        return true;
    }
    if (fstat(claimed, &st) != 0 || !walk.there
            || st.st_dev != walk.st.st_dev || st.st_ino != walk.st.st_ino) {
        say_name_leads_elsewhere(&NAMED_IMAGE, image_path);
        return true;
    }
    return walk.links > 0 && led_to_dir_in_the_way(&NAMED_IMAGE, image_path, leads_to, true);
}

/* 0 with the volume claimed: *claim_fd is the descriptor the claim holds on it, which
 * the format and the mount go through, or -1 where there is none. */
static int mkfs_claim(const char *image_path, const char *keyfile_path,
                      bool replaces_key, bool force, bool key_as_is,
                      uint64_t device_bytes, bool *created, int *claim_fd,
                      bool *key_there, struct stat *key_seen)
{
    int fd = -1;
    *created = false;
    *claim_fd = -1;
    stm_status s = stm_bdev_claim_image(image_path, false, &fd);
    if (s == STM_ENOENT) {
        /* Asked now, so that a refusal leaves no empty image behind. */
        if (key_in_the_way(keyfile_path, replaces_key, force, key_as_is, key_there, key_seen))
            return 1;
        s = stm_bdev_claim_image(image_path, true, &fd);
        *created = s == STM_OK || s == STM_ENOLCK;
    }
    if (s == STM_EBUSY) {
        fprintf(stderr, "stratum-mkfs: %s is open in a running stratumd\n", image_path);
        return 1;
    }
    if (s == STM_ENOLCK && !force) {
        fprintf(stderr,
            "stratum-mkfs: cannot lock %s (%s), so nothing shows whether a daemon has it; "
            "pass --force to format it anyway\n", image_path, strerror(errno));
        return 1;
    }
    if (s != STM_OK && s != STM_ENOLCK) {
        fprintf(stderr, "stratum-mkfs: cannot open %s: %s\n", image_path, strerror(errno));
        return 1;
    }

    *claim_fd = fd;
    /* A name this run made was free, and takes no link. */
    if (fd >= 0 && !*created && !force && image_links_in_the_way(image_path, fd)) return 1;

    /* Asked before the look as well, which reads all of an empty disk. */
    if (!*created
            && key_in_the_way(keyfile_path, replaces_key, force, key_as_is, key_there, key_seen))
        return 1;

    /* Where the platform has no lock there is no descriptor to look through. */
    int look = fd >= 0 ? fd : open(image_path, O_RDONLY | O_CLOEXEC);
    if (look < 0 && errno != ENOENT) {
        fprintf(stderr, "stratum-mkfs: cannot read %s: %s\n", image_path, strerror(errno));
        return 1;
    }
    if (look >= 0) {
        struct stat st;
        bool is_file = fstat(look, &st) == 0 && S_ISREG(st.st_mode);
        /* A file another user owns is theirs to remove or to put an older copy over,
         * whatever the key keeps unread, and an empty one left at a free name is how a
         * volume comes to be in one. A disk is root's, formatted by a group's right. */
        if (is_file && !*created && !force && st.st_uid != geteuid()) {
            fprintf(stderr,
                "stratum-mkfs: %s belongs to another user, who could remove the volume or "
                "put an older copy of it back: remove the file or run as its owner, or pass "
                "--force to format it\n", image_path);
            if (look != fd) close(look);
            return 1;
        }
#if !defined(__thylacine__)
        /* Nothing ends /dev/zero for the scan, and a format could not size it. */
        if (!is_file && stm_bdev_device_bytes(look) == 0) {
            fprintf(stderr, "stratum-mkfs: %s is neither a file nor a disk\n", image_path);
            return 1;
        }
#endif
        if (!is_file && !force) {
            fprintf(stderr, "stratum-mkfs: reading %s to see that it is empty; "
                            "--force skips this\n", image_path);
        }
        bool holds = false;
        bool read_ok = force || image_holds_data(look, &holds);
        int e = errno;
        bool too_big = is_file && (uint64_t)st.st_size > device_bytes;
        if (look != fd) close(look);
        if (!read_ok) {
            fprintf(stderr, "stratum-mkfs: cannot read %s: %s\n", image_path, strerror(e));
            return 1;
        }
        if (holds) {
            fprintf(stderr,
                "stratum-mkfs: %s already holds data; pass --force to format over it\n",
                image_path);
            return 1;
        }
        if (too_big) {
            fprintf(stderr,
                "stratum-mkfs: %s is %llu bytes and the size asked for is %llu; a format "
                "cannot shrink a file, so name a size of at least %llu or remove it\n",
                image_path, (unsigned long long)st.st_size,
                (unsigned long long)device_bytes, (unsigned long long)st.st_size);
            return 1;
        }
    }
    return key_in_the_way(keyfile_path, replaces_key, force, key_as_is, key_there, key_seen)
        ? 1 : 0;
}

/* A key file to load. Opened without waiting: a FIFO left at the name is no key, and
 * must not hold the run until somebody writes to it. */
static int open_key_to_read(const char *path)
{
#if defined(__thylacine__)
    return open(path, O_RDONLY | O_CLOEXEC);
#else
    return open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
#endif
}

/* Where the directory, or the file, `dfd` has open is now, for telling where what
 * was made there is: the path it was opened by may lead elsewhere by then. False where
 * the system does not say. */
static bool dir_path_now(int dfd, char *buf, size_t n)
{
#if defined(__APPLE__)
    char now[MAXPATHLEN];
    if (fcntl(dfd, F_GETPATH, now) != 0) return false;
    return snprintf(buf, n, "%s", now) < (int)n;
#elif defined(__linux__)
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", dfd);
    ssize_t len = readlink(link, buf, n - 1);
    if (len <= 0 || buf[0] != '/') return false;
    buf[len] = '\0';
    return true;
#else
    (void)dfd; (void)buf; (void)n;
    return false;
#endif
}

/* Whether `name` in the directory `dfd` is the very file `fd` has open. */
static bool names_the_file(int dfd, const char *name, int fd)
{
    struct stat held, named;
    return fstat(fd, &held) == 0 && fstatat(dfd, name, &named, AT_SYMLINK_NOFOLLOW) == 0
        && named.st_dev == held.st_dev && named.st_ino == held.st_ino;
}

/* The directory an image this run made is in, held for removing the image should the
 * run fail: the path may lead elsewhere by then, and a removal by the path would take
 * whatever it reaches. -1 where the directory cannot be opened or does not hold the
 * file. */
static int hold_image_dir(const char *image_path, const char *base, int claim_fd)
{
    char dir[4096];
    if (!dir_part(image_path, dir, sizeof dir)) return -1;
    int dfd = open_key_dir(dir);
    if (dfd >= 0 && !names_the_file(dfd, base, claim_fd)) {
        close(dfd);
        dfd = -1;
    }
    return dfd;
}

/* An image this run made and did not finish is removed through the directory it was
 * made in, and only while its name there is still that file. Anywhere else it is left,
 * and said: a name alone may reach a file this run never made. */
static void remove_made_image(const char *image_path, int dir_fd, const char *base,
                              int claim_fd)
{
    if (claim_fd < 0) {
        fprintf(stderr,
            "stratum-mkfs: %s was made by this run and is left: it could not be locked, so "
            "this run holds nothing that says which file it is, and it removes none by a "
            "name alone\n", image_path);
        return;
    }
    char now[4096];
    bool said = dir_path_now(claim_fd, now, sizeof now);
    if (dir_fd >= 0 && names_the_file(dir_fd, base, claim_fd)) {
        if (unlinkat(dir_fd, base, 0) == 0) return;
        fprintf(stderr, "stratum-mkfs: the image this run made could not be removed (%s); "
                        "it is %s\n", strerror(errno), said ? now : image_path);
        return;
    }
    struct stat held;
    if (fstat(claim_fd, &held) == 0 && held.st_nlink == 0) {
        fprintf(stderr,
            "stratum-mkfs: the image this run made has no name any more and goes as the "
            "run ends: nothing is removed by the name it was made by, which may reach "
            "another file\n");
        return;
    }
    fprintf(stderr,
        "stratum-mkfs: the image this run made is left, %s%s: the name it was made by no "
        "longer leads to it, and nothing is removed by a name that may reach another "
        "file\n", said ? "at " : "wherever it is now", said ? now : "");
}

/* Where the key that `name` names in the directory `dfd` is, in words: by the
 * directory's path as it is now where the system says it, else by the path it was
 * asked about under. */
static void key_place(int dfd, const char *name, const char *asked_dir, char *buf, size_t n)
{
    char now[4096];
    if (dir_path_now(dfd, now, sizeof now))
        snprintf(buf, n, "%s/%s", now, name);
    else
        snprintf(buf, n, "%s in the directory that %s named when the key was made, "
                         "wherever that directory is now", name, asked_dir);
}

/* Without --force the name is taken only if it is still free: a plain rename would
 * replace a key that appeared during the format. */
static int take_key_name(int dir, const char *from, const char *to, bool force)
{
    return force ? renameat(dir, from, dir, to) : stm_take_name_at(dir, from, to);
}

/* Whether a link is one only its owner, the user, or root controls. The links on the
 * key's way are read here, so the kernel's protected_symlinks, which refuses to
 * follow another user's link in a shared sticky directory, never asks: there whoever
 * left the link would hold the key, and the volume is lost with it. */
static bool link_is_trusted(const struct stat *st)
{
    if (st->st_uid == geteuid()) return true;
#if !defined(__thylacine__)
    /* Thylacine has no root: uid 0 is its invalid principal. */
    if (st->st_uid == 0) return true;
#endif
    return false;
}

/* Whether what readlink said of a link just looked at tells that it went, or is no
 * link any more, and not that it cannot be read. On Thylacine a share's link answers
 * EINVAL and ENOENT for reasons of the share's own, so nothing there tells a change. */
static bool link_went(int e)
{
#if defined(__thylacine__)
    (void)e;
    return false;
#else
    return e == ENOENT || e == EINVAL || e == ENOTDIR || e == ELOOP || e == ENAMETOOLONG
        || e == ESTALE;
#endif
}

/* A key named through a symlink belongs where the link points: replacing the link
 * would leave it beside the volume instead. A link is looked at before it is read, so
 * another user's is refused unread, and again after, so one put in its place meanwhile
 * and still there is not the one whose text is followed. Where another user cannot
 * replace an entry of the user's or root's, as in a sticky directory, the first look
 * settles that alone; where they can, no look here settles it. The owner is the
 * link's, not of whoever gave it the name it has here: where nothing forbids it any
 * user can give a link of the user's or root's a second name, and its text, joined to
 * a directory of their choosing, would be followed. So a link with more than one name
 * is refused; one that had a second name once is not told from any other here, and
 * what is asked of the directory the links lead to is what holds against it. NULL with
 * walk->why saying which: more than seven links or a path too
 * long, a link another user owns, one with more than one name, one that cannot be
 * read, one that changed. Forced, nothing is asked and a link that cannot be read is
 * taken for the end. */
static const char *key_destination(const char *path, char *buf, size_t n, bool force,
                                   struct key_walk *walk)
{
    char here[4096];
    walk->why = KEY_LINKS_TOO_MANY;
    walk->err = 0;
    walk->links = 0;
    walk->there = false;
    if (snprintf(here, sizeof here, "%s", path) >= (int)sizeof here) return NULL;
    for (int hops = 0; hops < 8; hops++) {
        struct stat st;
        char target[4096];
        ssize_t len = -1;
        bool there = lstat(here, &st) == 0;
        if (there && S_ISLNK(st.st_mode)) {
            if (!force && !link_is_trusted(&st)) {
                walk->why = KEY_LINKS_ANOTHERS;
                return NULL;
            }
            if (!force && st.st_nlink > 1) {
                walk->why = KEY_LINKS_MANY_NAMES;
                return NULL;
            }
            len = readlink(here, target, sizeof target - 1);
            if (len < 0 && !force) {
                int e = errno;
                walk->why = link_went(e) ? KEY_LINKS_CHANGED : KEY_LINKS_UNREAD;
                walk->err = e;
                return NULL;
            }
        }
        if (len < 0) {
            if (snprintf(buf, n, "%s", here) >= (int)n) return NULL;
            walk->why = KEY_LINKS_FOLLOWED;
            walk->there = there;
            if (there) walk->st = st;
            return buf;
        }
        if (!force) {
            struct stat again;
            if (lstat(here, &again) != 0 || !S_ISLNK(again.st_mode)
                    || again.st_dev != st.st_dev || again.st_ino != st.st_ino) {
                walk->why = KEY_LINKS_CHANGED;
                return NULL;
            }
        }
        target[len] = '\0';
        const char *slash = strrchr(here, '/');
        char next[4096];
        int w = (target[0] == '/' || !slash)
            ? snprintf(next, sizeof next, "%s", target)
            : snprintf(next, sizeof next, "%.*s/%s", (int)(slash - here), here, target);
        if (w < 0 || w >= (int)sizeof next) return NULL;
        memcpy(here, next, (size_t)w + 1);
        walk->links++;
    }
    return NULL;
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
    bool       force             = false;
    bool       key_as_is         = false;
    /* Dataset-root owner. Default 0/0 (historical behavior). Thylacine's
     * A-3 host-bake passes --root-uid/--root-gid = PRINCIPAL_SYSTEM so the
     * root is owned by the boot chain once the OS enforces 9P-mount rwx --
     * otherwise the boot chain, judged as `other` on the 0755 root, cannot
     * create top-level entries and the boot bricks. */
    uint32_t   root_uid          = 0;
    uint32_t   root_gid          = 0;

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
        } else if (strcmp(argv[i], "--force") == 0) {
            force = true;
        } else if (strcmp(argv[i], "--key-as-is") == 0) {
            key_as_is = true;
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
        } else if (strcmp(argv[i], "--root-uid") == 0) {
            if (i + 1 >= argc) { fputs("--root-uid requires an argument\n", stderr); return 1; }
            char *end = NULL;
            unsigned long long v = strtoull(argv[i + 1], &end, 10);
            if (!end || *end != '\0' || v > 0xFFFFFFFEULL) {
                fprintf(stderr, "stratum-mkfs: bad --root-uid: %s (<= 4294967294)\n", argv[i + 1]);
                return 1;
            }
            root_uid = (uint32_t)v;
            i++;
        } else if (strcmp(argv[i], "--root-gid") == 0) {
            if (i + 1 >= argc) { fputs("--root-gid requires an argument\n", stderr); return 1; }
            char *end = NULL;
            unsigned long long v = strtoull(argv[i + 1], &end, 10);
            if (!end || *end != '\0' || v > 0xFFFFFFFEULL) {
                fprintf(stderr, "stratum-mkfs: bad --root-gid: %s (<= 4294967294)\n", argv[i + 1]);
                return 1;
            }
            root_gid = (uint32_t)v;
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
     * (would refuse 16-MiB images); ours is default_bootstrap_for's. */
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

    if (key_as_is && passphrase_stdin) {
        fputs("stratum-mkfs: --key-as-is uses a key file that is there as it is, and with "
              "--passphrase-stdin the key is always made new: give one or the other\n", stderr);
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

    int  exit_code = 0;
    bool created = false;
    /* Above every jump to the cleanup, which reads them. */
    char new_key_path[4096] = "";
    char new_key_name[4096] = "";
    char key_target_buf[4096] = "";
    const char *key_base = "";
    char key_dir[4096] = "";
    int  key_dir_fd = -1;
    const char *key_target = keyfile_path;
    bool key_is_new = false;
    bool temp_key_made = false;
    bool key_was_there = false;
    struct stat key_seen;
    int  new_key_fd = -1;
    int  old_key_fd = -1;
    int  claim_fd = -1;
    int  image_dir_fd = -1;
    const char *image_base = strrchr(image_path, '/');
    image_base = image_base ? image_base + 1 : image_path;
    /* The key the volume is wrapped under, read through the descriptor it was asked
     * about or made through, and never by its name. */
    stm_hybrid_keys wrap;
    memset(&key_seen, 0, sizeof key_seen);
    int refused = mkfs_claim(image_path, keyfile_path, have_pass, force, key_as_is,
                             device_bytes, &created, &claim_fd, &key_was_there, &key_seen);
    if (created && claim_fd >= 0)
        image_dir_fd = hold_image_dir(image_path, image_base, claim_fd);
    if (refused != 0) {
        exit_code = 1;
        goto cleanup;
    }

    /* A new key takes its name only once the volume it opens exists, so a format
     * that fails has replaced nothing. With --passphrase-stdin it is always new,
     * mkfs_claim having refused one that exists unless forced. */
    key_is_new = have_pass;
    struct stat st;
    /* A key that is there is opened once, here: what is asked of it is asked of the
     * file this descriptor has open, and that file is the one the key is read from. */
    if (!have_pass) old_key_fd = open_key_to_read(keyfile_path);
    if (!have_pass && old_key_fd < 0 && errno == ENOENT) {
        key_is_new = true;
    } else if (!have_pass && (old_key_fd < 0 || fstat(old_key_fd, &st) != 0)) {
        fprintf(stderr, "stratum-mkfs: cannot open keyfile %s: %s\n",
                keyfile_path, strerror(errno));
        exit_code = 1;
        goto cleanup;
    } else if (!have_pass && !force && !key_was_there) {
        /* What is asked of a key, and of the links to it, was asked at the claim, of
         * what was there then: a link left at a free name since would be followed
         * here unasked. */
        fprintf(stderr,
            "stratum-mkfs: keyfile %s turned up after the volume was claimed, so nothing "
            "was asked of it: see what is there, who owns it and where a link leads, "
            "before running again\n", keyfile_path);
        exit_code = 1;
        goto cleanup;
    } else if (!have_pass && !force && key_not_the_users(&st, key_as_is)) {
        /* Changed since the claim. */
        fprintf(stderr, "stratum-mkfs: since the volume was claimed, keyfile %s %s\n",
                keyfile_path, key_not_the_users(&st, key_as_is));
        exit_code = 1;
        goto cleanup;
    } else if (!have_pass && !force
               && (st.st_dev != key_seen.st_dev || st.st_ino != key_seen.st_ino)) {
        /* A key of the user's own, and not the one the claim asked about. */
        fprintf(stderr,
            "stratum-mkfs: since the volume was claimed, keyfile %s leads to another file "
            "than the one that was asked about: see what is there, and who changed it, "
            "before running again\n", keyfile_path);
        exit_code = 1;
        goto cleanup;
    }
    if (key_is_new) {
        struct key_walk walk;
        key_target = key_destination(keyfile_path, key_target_buf, sizeof key_target_buf, force,
                                     &walk);
        if (!key_target) {
            /* A link left there since the claim: nothing there was asked about then. */
            say_links_refused(&NAMED_KEY, keyfile_path, &walk);
            key_is_new = false;
            exit_code = 1;
            goto cleanup;
        }
        key_base = strrchr(key_target, '/');
        key_base = key_base ? key_base + 1 : key_target;
        int n = snprintf(new_key_path, sizeof new_key_path, "%s.new.%ld",
                         key_target, (long)getpid());
        int m = snprintf(new_key_name, sizeof new_key_name, "%s.new.%ld",
                         key_base, (long)getpid());
        if (n < 0 || (size_t)n >= sizeof new_key_path || m < 0
                || (size_t)m >= sizeof new_key_name
                || !dir_part(key_target, key_dir, sizeof key_dir)) {
            fprintf(stderr, "stratum-mkfs: keyfile path too long: %s\n", keyfile_path);
            key_is_new = false;
            exit_code = 1;
            goto cleanup;
        }
        /* The key is made in its directory through the directory's descriptor, and takes
         * its name there: what is asked of the directory is asked of the one the key is
         * in, wherever a path to it leads afterwards. */
        key_dir_fd = open_key_dir(key_dir);
        if (key_dir_fd < 0) {
            fprintf(stderr, "stratum-mkfs: cannot make %s: %s\n", new_key_path, strerror(errno));
            key_is_new = false;
            exit_code = 1;
            goto cleanup;
        }
        if (!force && walk.links > 0) {
            struct stat dd;
            const char *why = fstat(key_dir_fd, &dd) != 0 ? "cannot be looked at"
                                                          : led_to_dir_refused(&dd, keyfile_path);
            if (why) {
                say_dir_refused(&NAMED_KEY, keyfile_path, key_dir, why, true);
                key_is_new = false;
                exit_code = 1;
                goto cleanup;
            }
        }
        /* Made here, O_EXCL, so a file already at that name (a killed run's only key,
         * perhaps) is neither truncated nor removed: cleanup removes what this run made. */
        int tfd = openat(key_dir_fd, new_key_name,
                         O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (tfd < 0) {
            fprintf(stderr, "stratum-mkfs: cannot make %s: %s\n", new_key_path, strerror(errno));
            key_is_new = false;
            exit_code = 1;
            goto cleanup;
        }
        temp_key_made = true;
        fprintf(stderr, "stratum-mkfs: the new key is at %s until the format is done\n",
                new_key_path);
        /* Through the descriptor that made the file: a name swapped since then does not
         * receive the key. */
        stm_status ks = have_pass
            ? stm_keyfile_generate_passphrase_fd(tfd, passbuf, plen)
            : stm_keyfile_generate_fd(tfd);
        /* Kept open: once the key has taken its name, this is what the name has to reach. */
        new_key_fd = tfd;
        if (ks != STM_OK) {
            fprintf(stderr, "stratum-mkfs: cannot write a new key at %s: status=%d\n",
                    new_key_path, (int)ks);
            exit_code = 2;
            goto cleanup;
        }
        /* Read back through the descriptor that made it: the volume is wrapped under
         * the key this run made, whatever is at that key's path by now. */
        ks = have_pass ? stm_keyfile_load_passphrase_fd(tfd, passbuf, plen, &wrap)
                       : stm_keyfile_load_fd(tfd, &wrap);
        if (ks != STM_OK) {
            fprintf(stderr, "stratum-mkfs: cannot read the new key back at %s: status=%d\n",
                    new_key_path, (int)ks);
            exit_code = 2;
            goto cleanup;
        }
    } else {
        fprintf(stderr, "using existing keyfile: %s\n", keyfile_path);
        stm_status ks = stm_keyfile_load_fd(old_key_fd, &wrap);
        if (ks != STM_OK) {
            fprintf(stderr, "stratum-mkfs: keyfile %s could not be loaded as a key: "
                            "status=%d\n", keyfile_path, (int)ks);
            exit_code = 2;
            goto cleanup;
        }
    }
    const char *key_name = key_is_new ? new_key_path : keyfile_path;

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
        .keyfile_path             = key_name,
        .wrap_keys                = &wrap,
        .claimed_fd               = &claim_fd,
    };

    /* Phase 1: format. */
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
        .keyfile_path             = key_name,
        .wrap_keys                = &wrap,
        .claimed_fd               = &claim_fd,
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
                                       /*uid=*/root_uid, /*gid=*/root_gid,
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

    /* The volume is in the file the claim had open, and every later command is given
     * the name. Asked before the key takes its name, so that a run that fails here has
     * replaced nothing. */
    if (claim_fd >= 0) {
        struct stat claimed, named;
        bool leads = fstat(claim_fd, &claimed) == 0 && stat(image_path, &named) == 0
            && named.st_dev == claimed.st_dev && named.st_ino == claimed.st_ino;
        if (!leads) {
            fprintf(stderr,
                "stratum-mkfs: %s does not lead to the file it led to when the volume was "
                "claimed: that file was formatted, and nothing was written to what the name "
                "reaches now. See what is at the name, and who changed it, before running "
                "again; a key this run made is removed, and so is an image it made, where "
                "that is still in the directory it was made in\n", image_path);
            exit_code = 2;
            goto cleanup;
        }
    }

    if (key_is_new) {
        /* From here the only key to this volume is the new file: it is never removed. */
        key_is_new = false;
        temp_key_made = false;
        created = false;
        char place[8400];
        if (take_key_name(key_dir_fd, new_key_name, key_base, force) != 0) {
            int e = errno;
            key_place(key_dir_fd, new_key_name, key_dir, place, sizeof place);
            fprintf(stderr,
                "stratum-mkfs: %s is formatted, but its key could not take the name %s (%s); "
                "the key is %s, keep it\n",
                image_path, keyfile_path, strerror(e), place);
            exit_code = 2;
            goto cleanup;
        }
        /* The rename is not durable until the directory holding it is. */
        if (fsync(key_dir_fd) != 0) {
            /* What a descriptor opened for the search alone answers is of the
             * descriptor, and reads as a fault. */
            const char *why = errno == EBADF
                ? "it cannot be read, and one opened for the search alone is not synced here"
                : strerror(errno);
            fprintf(stderr, "stratum-mkfs: warning: cannot sync the directory of %s (%s), so "
                            "a power cut could still lose the key's new name\n",
                    key_target, why);
        }
        /* The links to the key's place were followed by their text. Where that is not
         * the path the kernel follows, the name does not lead to the key, and every
         * later command is given the name. */
        struct stat made, named;
        int made_err = fstat(new_key_fd, &made) != 0 ? errno : 0;
        int named_err = stat(keyfile_path, &named) != 0 ? errno : 0;
        bool leads_nowhere = named_err == ENOENT || named_err == ENOTDIR;
        if (made_err != 0 || (named_err != 0 && !leads_nowhere)) {
            key_place(key_dir_fd, key_base, key_dir, place, sizeof place);
            fprintf(stderr,
                "stratum-mkfs: %s is formatted and its key is %s, but whether the "
                "name %s leads to it could not be seen (%s: %s): look for the key there, "
                "keep it, and see what the name reaches before using it\n",
                image_path, place, keyfile_path,
                made_err != 0 ? "the key made" : "the name",
                strerror(made_err != 0 ? made_err : named_err));
            exit_code = 2;
            goto cleanup;
        }
        if (leads_nowhere || named.st_dev != made.st_dev || named.st_ino != made.st_ino) {
            key_place(key_dir_fd, key_base, key_dir, place, sizeof place);
            fprintf(stderr,
                "stratum-mkfs: %s is formatted and its key is %s, but the name %s "
                "does not lead to it: look for the key there, keep it, and name it by that "
                "path\n",
                image_path, place, keyfile_path);
            exit_code = 2;
            goto cleanup;
        }
        fprintf(stderr, "generated %skeyfile: %s\n", have_pass ? "encrypted " : "", keyfile_path);
    }

    fprintf(stderr,
        "ok: %s ready (dataset 1 root ino=%llu)\n"
        "    next: stratum tui --vol %s\n"
        "      or: stratum serve %s --listen /tmp/stm.sock --keyfile %s%s\n",
        image_path,
        (unsigned long long)root_ino,
        image_path,
        image_path, keyfile_path,
        passphrase_stdin ? " --passphrase-stdin" : "");

cleanup:
    stm_hybrid_keys_wipe(&wrap);
    if (new_key_fd >= 0) close(new_key_fd);
    if (old_key_fd >= 0) close(old_key_fd);
    /* What this run made and failed to finish, and nothing it found. */
    if (exit_code != 0) {
        if (temp_key_made) unlinkat(key_dir_fd, new_key_name, 0);
        if (created) remove_made_image(image_path, image_dir_fd, image_base, claim_fd);
    }
    if (image_dir_fd >= 0) close(image_dir_fd);
    if (key_dir_fd >= 0) close(key_dir_fd);
    /* SWISS-4m: wipe + munlock the passphrase buffer regardless of
     * exit path. Stack-allocated, so munlock + memzero is enough —
     * the storage is freed when this stack frame unwinds. */
    if (have_pass) {
        stm_ct_memzero(passbuf, sizeof passbuf);
        stm_cli_passphrase_unlock(passbuf, sizeof passbuf);
    }
    return exit_code;
}
