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
 *   2  format failed
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
"  --force          Format over what is already at IMAGE, and with\n"
"                   --passphrase-stdin replace an existing keyfile. Whatever\n"
"                   they held is gone. Also follows any key link it can read,\n"
"                   whoever owns it and however many names it has, and uses\n"
"                   a keyfile that is not the user's alone. A new key is not\n"
"                   sent through a link that cannot be read: it takes that\n"
"                   link's place.\n"
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
"                   read and has no other name.\n"
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
    bool there;     /* whether anything is where they end */
    struct stat st; /* what is there */
};

static const char *key_destination(const char *path, char *buf, size_t n, bool force,
                                   struct key_walk *walk);

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

/* Why the links at the key's name were not followed. */
static void say_links_refused(const char *keyfile_path, const struct key_walk *walk)
{
    switch (walk->why) {
    case KEY_LINKS_ANOTHERS:
        fprintf(stderr,
            "stratum-mkfs: keyfile %s is reached through a symlink another user owns, who "
            "would decide where the key goes; pass --force to follow it\n", keyfile_path);
        break;
    case KEY_LINKS_MANY_NAMES:
        fprintf(stderr,
            "stratum-mkfs: keyfile %s is reached through a symlink that has more than one "
            "name, and whoever gave it the one here would decide where the key goes: name "
            "the key file itself, or pass --force to follow it\n", keyfile_path);
        break;
    case KEY_LINKS_UNREAD:
        fprintf(stderr,
            "stratum-mkfs: keyfile %s is reached through a link that cannot be read (%s), "
            "so where it leads cannot be asked about: name the key file itself\n",
            keyfile_path, strerror(walk->err));
        break;
    case KEY_LINKS_CHANGED:
        fprintf(stderr,
            "stratum-mkfs: a link on the way to keyfile %s changed while it was being read, "
            "so nothing was asked of what is there now: see who changed it before running "
            "again\n", keyfile_path);
        break;
    default:
        fprintf(stderr,
            "stratum-mkfs: keyfile %s is reached through more than seven links or a loop of "
            "them, or names a path too long: name the key file itself\n", keyfile_path);
        break;
    }
}

/* Where the name reaches something the links read from it do not end in. */
static void say_name_leads_elsewhere(const char *keyfile_path)
{
    fprintf(stderr,
        "stratum-mkfs: keyfile %s does not lead where its links were read to end: a link "
        "or a file was left or changed on its way while it was looked at, or one of its "
        "links is a descriptor's, whose text names no file (a pipe's, an unlinked file's): "
        "name the key file itself, or see what was left, before running again\n",
        keyfile_path);
}

/*
 * Formatting over a pool loses it, and over a pool's key loses it just as
 * surely, so neither happens by naming the wrong path. The claim is held until
 * the process ends: a daemon cannot start on the image between the look and the
 * format, and --force does not reach past a daemon already on it.
 */
static bool key_in_the_way(const char *keyfile_path, bool replaces_key, bool force,
                           bool key_as_is, bool *key_there)
{
    struct stat st;
    char dest[4096];
    struct key_walk walk;
    *key_there = false;
    const char *leads_to = key_destination(keyfile_path, dest, sizeof dest, force, &walk);
    /* Past where that gives up, the stat below would follow links nobody asked about. */
    if (!leads_to && !force) {
        say_links_refused(keyfile_path, &walk);
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
        say_name_leads_elsewhere(keyfile_path);
        return true;
    }
    if (!reached) return false;
    if (!replaces_key) {
        const char *why = key_not_the_users(&st, key_as_is);
        if (!why) {
            *key_there = true;
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

static int mkfs_claim(const char *image_path, const char *keyfile_path,
                      bool replaces_key, bool force, bool key_as_is,
                      uint64_t device_bytes, bool *created, bool *key_there)
{
    int fd = -1;
    *created = false;
    stm_status s = stm_bdev_claim_image(image_path, false, &fd);
    if (s == STM_ENOENT) {
        /* Asked now, so that a refusal leaves no empty image behind. */
        if (key_in_the_way(keyfile_path, replaces_key, force, key_as_is, key_there)) return 1;
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

    /* Asked before the look as well, which reads all of an empty disk. */
    if (!*created && key_in_the_way(keyfile_path, replaces_key, force, key_as_is, key_there))
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
    return key_in_the_way(keyfile_path, replaces_key, force, key_as_is, key_there) ? 1 : 0;
}

/* Without --force the name is taken only if it is still free: a plain rename would
 * replace a key that appeared during the format. */
static int take_key_name(const char *from, const char *to, bool force)
{
    return force ? rename(from, to) : stm_take_name(from, to);
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

/* A key named through a symlink belongs where the link points: replacing the link
 * would leave it beside the volume instead. A link is looked at before it is read, so
 * another user's is refused unread, and again after, so one put in its place meanwhile
 * and still there is not the one whose text is followed. Where another user cannot
 * replace an entry of the user's or root's, as in a sticky directory, the first look
 * settles that alone; where they can, no look here settles it. The owner is the
 * link's, not of whoever gave it the name it has here: where nothing forbids it any
 * user can give a link of the user's or root's a second name, and its text, joined to
 * a directory of their choosing, would be followed. So a link with more than one name
 * is refused. NULL with walk->why saying which: more than seven links or a path too
 * long, a link another user owns, one with more than one name, one that cannot be
 * read, one that changed. Forced, nothing is asked and a link that cannot be read is
 * taken for the end. */
static const char *key_destination(const char *path, char *buf, size_t n, bool force,
                                   struct key_walk *walk)
{
    char here[4096];
    walk->why = KEY_LINKS_TOO_MANY;
    walk->err = 0;
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
                /* Gone, or no link any more: not one that cannot be read. */
                int e = errno;
                walk->why = (e == ENOENT || e == EINVAL) ? KEY_LINKS_CHANGED : KEY_LINKS_UNREAD;
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
    }
    return NULL;
}

/* The rename is not durable until the directory holding it is. */
static void sync_dir_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    char dir[4096] = ".";
    if (slash) {
        size_t n = slash == path ? 1u : (size_t)(slash - path);
        if (n >= sizeof dir) return;
        memcpy(dir, path, n);
        dir[n] = '\0';
    }
    int fd = open(dir, O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fsync(fd) != 0) {
        fprintf(stderr, "stratum-mkfs: warning: cannot sync %s (%s), so a power cut "
                        "could still lose the key's new name\n", dir, strerror(errno));
    }
    if (fd >= 0) close(fd);
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
    char key_target_buf[4096] = "";
    const char *key_target = keyfile_path;
    const char *format_key = keyfile_path;
    bool key_is_new = false;
    bool temp_key_made = false;
    bool key_was_there = false;
    int  new_key_fd = -1;
    if (mkfs_claim(image_path, keyfile_path, have_pass, force, key_as_is, device_bytes,
                   &created, &key_was_there) != 0) {
        exit_code = 1;
        goto cleanup;
    }

    /* A new key takes its name only once the volume it opens exists, so a format
     * that fails has replaced nothing. With --passphrase-stdin it is always new,
     * mkfs_claim having refused one that exists unless forced. */
    key_is_new = have_pass;
    struct stat st;
    if (!have_pass && stat(keyfile_path, &st) != 0) {
        if (errno != ENOENT) {
            fprintf(stderr, "stratum-mkfs: cannot stat keyfile %s: %s\n",
                    keyfile_path, strerror(errno));
            exit_code = 1;
            goto cleanup;
        }
        key_is_new = true;
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
    }
    if (key_is_new) {
        struct key_walk walk;
        key_target = key_destination(keyfile_path, key_target_buf, sizeof key_target_buf, force,
                                     &walk);
        if (!key_target) {
            /* A link left there since the claim: nothing there was asked about then. */
            say_links_refused(keyfile_path, &walk);
            key_is_new = false;
            exit_code = 1;
            goto cleanup;
        }
        int n = snprintf(new_key_path, sizeof new_key_path, "%s.new.%ld",
                         key_target, (long)getpid());
        if (n < 0 || (size_t)n >= sizeof new_key_path) {
            fprintf(stderr, "stratum-mkfs: keyfile path too long: %s\n", keyfile_path);
            key_is_new = false;
            exit_code = 1;
            goto cleanup;
        }
        /* Made here, O_EXCL, so a file already at that name (a killed run's only key,
         * perhaps) is neither truncated nor removed: cleanup removes what this run made. */
        int tfd = open(new_key_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
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
        format_key = new_key_path;
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
        .keyfile_path             = format_key,
        .keyfile_passphrase       = have_pass ? passbuf : NULL,
        .keyfile_passphrase_len   = have_pass ? plen    : 0,
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
        .keyfile_path             = format_key,
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

    if (key_is_new) {
        /* From here the only key to this volume is the new file: it is never removed. */
        key_is_new = false;
        temp_key_made = false;
        created = false;
        if (take_key_name(new_key_path, key_target, force) != 0) {
            fprintf(stderr,
                "stratum-mkfs: %s is formatted, but its key could not take the name %s (%s); "
                "the key is at %s, keep it\n",
                image_path, keyfile_path, strerror(errno), new_key_path);
            exit_code = 2;
            goto cleanup;
        }
        sync_dir_of(key_target);
        /* The links to the key's place were followed by their text. Where that is not
         * the path the kernel follows, the name does not lead to the key, and every
         * later command is given the name. */
        struct stat made, named;
        if (fstat(new_key_fd, &made) != 0 || stat(keyfile_path, &named) != 0
                || named.st_dev != made.st_dev || named.st_ino != made.st_ino) {
            fprintf(stderr,
                "stratum-mkfs: %s is formatted and its key was put at %s, but the name %s "
                "does not lead to it: look for the key there, keep it, and name it by that "
                "path\n",
                image_path, key_target, keyfile_path);
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
    if (new_key_fd >= 0) close(new_key_fd);
    /* What this run made and failed to finish, and nothing it found. */
    if (exit_code != 0) {
        if (temp_key_made) unlink(new_key_path);
        if (created) unlink(image_path);
    }
    /* SWISS-4m: wipe + munlock the passphrase buffer regardless of
     * exit path. Stack-allocated, so munlock + memzero is enough —
     * the storage is freed when this stack frame unwinds. */
    if (have_pass) {
        stm_ct_memzero(passbuf, sizeof passbuf);
        stm_cli_passphrase_unlock(passbuf, sizeof passbuf);
    }
    return exit_code;
}
