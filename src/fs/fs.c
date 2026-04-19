#include "fs_internal.h"
#include "stratum/csum.h"
#include "stratum/compress.h"

#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* ── local aliases ──────────────────────────────────────────────────── */

#include "stratum/snapshot.h"

#define mk_key   stm_mk_key
#define fnv1a    stm_fnv1a

/* ── allocator reconstruction callbacks ─────────────────────────────── */

static int mark_block_fs(uint64_t paddr, uint32_t csize, void *ctx)
{
    struct stm_fs *fs = ctx;
    uint32_t nblocks = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_mark(fs->alloc, paddr / STM_BLOCK_SIZE, nblocks);
    return 0;
}

/* Per-entry callback used during the mount-time tree walk. Three jobs:
 *  1. Mark blocks referenced by extent records (R3-era allocator rebuild).
 *  2. R13-2: track the highest inode number observed across all INODE keys,
 *     so a post-walk clamp can repair adversarial `ss_next_ino` that would
 *     otherwise cause the next create to alias an existing inode.
 *  3. R13-4: track the highest snap_id observed across all SNAP keys, for
 *     the same reason against `ss_next_snap_id`. */
static int mark_extent_entry(const struct stm_key *key, const void *val,
                             uint32_t vlen, void *ctx)
{
    struct stm_fs *fs = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);

    if (kc.type == STM_KEY_INODE) {
        /* R14-1: refuse adversarial INODE keys planted near UINT64_MAX
         * that would cause (kc.ino + 1) to wrap when raising
         * fs->next_ino. Walk abort propagates to mount-abort via the
         * existing fail_alloc path — safer than silently wrapping. */
        if (kc.ino > UINT64_MAX - (UINT64_C(1) << 32)) return -EINVAL;
        if (kc.ino >= fs->next_ino) fs->next_ino = kc.ino + 1;
        return 0;
    }
    if (kc.type == STM_KEY_SNAP) {
        if (kc.ino > UINT64_MAX - (UINT64_C(1) << 32)) return -EINVAL;
        if (kc.ino >= fs->next_snap_id) fs->next_snap_id = kc.ino + 1;
        return 0;
    }
    if (kc.type != STM_KEY_DATA || vlen != sizeof(struct stm_extent))
        return 0;
    struct stm_extent ext;
    memcpy(&ext, val, sizeof(ext));
    struct stm_crypto *crypto = stm_btree_get_crypto(fs->tree);
    uint64_t paddr = le64_to_cpu(ext.se_paddr);
    uint32_t clen  = stm_extent_clen(&ext);
    uint32_t disk_len = crypto ? (clen + STM_CRYPTO_TAG_LEN) : clen;
    uint32_t nblocks = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_mark(fs->alloc, paddr / STM_BLOCK_SIZE, nblocks);
    return 0;
}

static int walk_snap_cb(const struct stm_key *key, const void *val,
                        uint32_t vlen, void *ctx)
{
    struct stm_fs *fs = ctx;
    struct stm_snapshot snap;
    int rc;
    (void)key;
    if (vlen < sizeof(snap)) return 0;
    memcpy(&snap, val, sizeof(snap));
    /* Propagate the walk return — if any saved snapshot's tree has a
     * corrupt node, we'd otherwise silently mark only the reachable
     * prefix, and blocks exclusively owned by the broken snapshot
     * stay at refcount 0 → the next write reallocates them. */
    rc = stm_btree_walk_entries(fs->tree, snap.ssp_root,
                                mark_block_fs, mark_extent_entry, fs);
    return rc;
}

static void stm_now(uint64_t *sec, uint32_t *nsec)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    *sec  = (uint64_t)ts.tv_sec;
    *nsec = (uint32_t)ts.tv_nsec;
}

/*
 * Dirent value layout:
 *   [le64 child_ino][uint8 type][name bytes...]
 *   total = 9 + name_len
 *
 * Tombstone: vlen == 1. Any value byte. Distinct from real dirents
 * (which always have vlen >= DIRENT_HDR == 9). See `tombstone_dirent`
 * and the lookup_dirent / find_dirent_slot probing discussion.
 */
#define DIRENT_HDR 9
#define DIRENT_TOMBSTONE_VLEN 1

static void encode_dirent(uint64_t ino, uint8_t type,
                          const char *name, size_t nlen,
                          uint8_t *buf, uint32_t *out_len)
{
    le64 ino_le = cpu_to_le64(ino);
    memcpy(buf, &ino_le, 8);
    buf[8] = type;
    memcpy(buf + 9, name, nlen);
    *out_len = (uint32_t)(9 + nlen);
}

static void decode_dirent(const uint8_t *buf, uint32_t blen,
                          uint64_t *ino, uint8_t *type,
                          const char **name, uint32_t *nlen)
{
    le64 ino_le;
    memcpy(&ino_le, buf, 8);
    *ino  = le64_to_cpu(ino_le);
    *type = buf[8];
    *name = (const char *)buf + 9;
    *nlen = blen - 9;
}

/* Look up a directory entry by name, handling hash collisions.
 *
 * A slot can be in one of three states:
 *   - never used (btree lookup returns -ENOENT) → probe chain ends
 *   - tombstone  (vlen == 1, set on unlink)     → keep probing
 *   - live dirent (vlen >= DIRENT_HDR)          → match name or keep probing
 */
static int lookup_dirent(struct stm_btree *tree, uint64_t parent,
                         const char *name, size_t nlen,
                         uint64_t *out_ino, struct stm_key *out_key)
{
    uint64_t h = fnv1a(name, nlen);
    int attempt;

    for (attempt = 0; attempt < 256; attempt++) {
        struct stm_key k = mk_key(parent, STM_KEY_DIRENT, h + (uint64_t)attempt);
        uint8_t vbuf[STM_NAME_MAX + 16];
        uint32_t vlen = sizeof(vbuf);
        int rc = stm_btree_lookup(tree, &k, vbuf, &vlen);

        if (rc == -ENOENT) return -ENOENT;  /* end of probe chain */
        if (rc < 0) return rc;

        if (vlen == DIRENT_TOMBSTONE_VLEN) continue;  /* tombstone → keep probing */

        if (vlen >= DIRENT_HDR) {
            uint32_t elen = vlen - DIRENT_HDR;
            if (elen == nlen && memcmp(vbuf + 9, name, nlen) == 0) {
                le64 ino_le;
                memcpy(&ino_le, vbuf, 8);
                *out_ino = le64_to_cpu(ino_le);
                if (out_key) *out_key = k;
                return 0;
            }
        }
        /* collision — try next slot */
    }
    return -ENOENT;
}

/* Find a free dirent slot for a new name.
 *
 * To avoid duplicate inserts when an older tombstone shares the probe
 * chain with a live entry for the same name, we scan the full chain:
 *   - if we find a live dirent with the same name → -EEXIST
 *   - otherwise, reuse the first tombstone we saw (if any)
 *   - else, use the first never-used slot
 */
static int find_dirent_slot(struct stm_btree *tree, uint64_t parent,
                            const char *name, size_t nlen,
                            struct stm_key *out_key)
{
    uint64_t h = fnv1a(name, nlen);
    int attempt;
    int have_tombstone = 0;
    struct stm_key tombstone_key;

    for (attempt = 0; attempt < 256; attempt++) {
        struct stm_key k = mk_key(parent, STM_KEY_DIRENT, h + (uint64_t)attempt);
        uint8_t vbuf[STM_NAME_MAX + 16];
        uint32_t vlen = sizeof(vbuf);
        int rc = stm_btree_lookup(tree, &k, vbuf, &vlen);

        if (rc == -ENOENT) {
            /* End of probe chain. Reuse a tombstone if we saw one,
             * otherwise use this fresh slot. */
            *out_key = have_tombstone ? tombstone_key : k;
            return 0;
        }
        if (rc < 0) return rc;

        if (vlen == DIRENT_TOMBSTONE_VLEN) {
            if (!have_tombstone) {
                tombstone_key = k;
                have_tombstone = 1;
            }
            continue;
        }

        /* Live dirent — is it a duplicate? */
        if (vlen >= DIRENT_HDR) {
            uint32_t elen = vlen - DIRENT_HDR;
            if (elen == nlen && memcmp(vbuf + 9, name, nlen) == 0)
                return -EEXIST;
        }
    }
    return -ENOSPC;
}

/* Replace a dirent with a tombstone so the probe chain stays intact. */
static int tombstone_dirent(struct stm_btree *tree,
                            const struct stm_key *key, uint64_t gen)
{
    uint8_t marker = 0;
    return stm_btree_insert(tree, key, &marker, DIRENT_TOMBSTONE_VLEN, gen);
}

static uint64_t alloc_ino(struct stm_fs *fs)
{
    /* Defensive skip of STM_ROOT_INO and 0. Mount-time high clamp
     * (R14-1) should prevent fs->next_ino from reaching a value that
     * would wrap to these, but a runtime bug or intentional overflow
     * downstream could still hand out 0 or STM_ROOT_INO. Skipping them
     * costs nothing (u64 counter) and hardens against the
     * root-inode-overwrite vector at the allocation site. */
    while (fs->next_ino == 0 || fs->next_ino == STM_ROOT_INO)
        fs->next_ino++;
    return fs->next_ino++;
}

/* ── format ─────────────────────────────────────────────────────────── */

int stm_fs_create(const char *path, uint64_t size_bytes,
                  const char *passphrase)
{
#ifdef STM_HAVE_LZ4
    return stm_fs_create_ex(path, size_bytes, passphrase, STM_COMP_LZ4);
#else
    return stm_fs_create_ex(path, size_bytes, passphrase, STM_COMP_NONE);
#endif
}

int stm_fs_create_ex(const char *path, uint64_t size_bytes,
                     const char *passphrase, uint8_t comp_algo)
{
    struct stm_block_dev dev;
    struct stm_btree *tree = NULL;
    struct stm_bptr null_root = stm_bptr_null();
    struct stm_superblock sb;
    struct stm_inode root_ino;
    struct stm_key k;
    uint64_t ts; uint32_t tns;
    int rc;

    /* Reject codecs not compiled into this build. */
    if (comp_algo == STM_COMP_LZ4) {
#ifndef STM_HAVE_LZ4
        return -ENOTSUP;
#endif
    } else if (comp_algo == STM_COMP_ZSTD) {
#ifndef STM_HAVE_ZSTD
        return -ENOTSUP;
#endif
    } else if (comp_algo != STM_COMP_NONE) {
        return -EINVAL;
    }

    rc = stm_file_backend_open(path, 1, size_bytes, &dev);
    if (rc) return rc;

    rc = stm_btree_open(&dev, null_root, 0, &tree);
    if (rc) goto fail_dev;

    stm_btree_set_id(tree, STM_TREE_ID_MAIN);

#ifdef STM_HAVE_LZ4
    stm_btree_set_compression(tree, STM_COMP_LZ4);
#endif

    /* encryption setup */
    memset(&sb, 0, sizeof(sb));
    if (passphrase && passphrase[0]) {
#ifdef STM_HAVE_CRYPTO
        uint8_t dek[STM_CRYPTO_KEY_LEN], kek[STM_CRYPTO_KEY_LEN];
        uint8_t salt[STM_CRYPTO_SALT_LEN];
        struct stm_crypto *crypto = NULL;

        stm_crypto_random(dek, sizeof(dek));
        stm_crypto_random(salt, sizeof(salt));

        rc = stm_crypto_derive_key(passphrase, strlen(passphrase), salt, kek);
        if (rc) {
            memset(kek, 0, sizeof(kek));
            memset(dek, 0, sizeof(dek));
            goto fail_tree;
        }

        memcpy(sb.ss_enc_kdf_salt, salt, STM_CRYPTO_SALT_LEN);
        rc = stm_crypto_wrap_key(kek, dek, sb.ss_enc_wrapped_key,
                                 sb.ss_enc_nonce);
        if (rc) {
            memset(kek, 0, sizeof(kek));
            memset(dek, 0, sizeof(dek));
            goto fail_tree;
        }
        sb.ss_enc_algo = STM_ENC_XCHACHA;

        rc = stm_crypto_init(dek, &crypto);
        /* stm_crypto_init copies dek into its own context; we can
         * safely wipe the stack copy now regardless of outcome. */
        memset(kek, 0, sizeof(kek));
        memset(dek, 0, sizeof(dek));
        if (rc) goto fail_tree;
        stm_btree_set_crypto(tree, crypto);
#else
        rc = -ENOTSUP; goto fail_tree;
#endif
    }

    /* create root directory inode */
    stm_now(&ts, &tns);
    memset(&root_ino, 0, sizeof(root_ino));
    root_ino.si_ino       = cpu_to_le64(STM_ROOT_INO);
    root_ino.si_gen       = cpu_to_le64(1);
    root_ino.si_mode      = cpu_to_le32(STM_S_IFDIR | 0755);
    root_ino.si_nlink     = cpu_to_le32(2);
    root_ino.si_uid       = cpu_to_le32(0);
    root_ino.si_gid       = cpu_to_le32(0);
    root_ino.si_atime_sec = cpu_to_le64(ts);
    root_ino.si_atime_nsec= cpu_to_le32(tns);
    root_ino.si_mtime_sec = cpu_to_le64(ts);
    root_ino.si_mtime_nsec= cpu_to_le32(tns);
    root_ino.si_ctime_sec = cpu_to_le64(ts);
    root_ino.si_ctime_nsec= cpu_to_le32(tns);

    k = mk_key(STM_ROOT_INO, STM_KEY_INODE, 0);
    rc = stm_btree_insert(tree, &k, &root_ino, sizeof(root_ino), 1);
    if (rc) goto fail_tree;

    rc = stm_btree_flush(tree, 1);  /* gen=1 for initial mkfs */
    if (rc) goto fail_tree;

    /* build superblock (sb was zeroed above, enc fields already set) */
    sb.ss_magic        = cpu_to_le64(STM_MAGIC);
    sb.ss_version      = cpu_to_le32(2);
    sb.ss_gen          = cpu_to_le64(1);
    sb.ss_root         = stm_btree_root(tree);
    sb.ss_snap_root    = stm_bptr_null();
    sb.ss_space_root   = stm_bptr_null();
    sb.ss_tree_height  = cpu_to_le16(stm_btree_height(tree));
    sb.ss_block_size   = cpu_to_le32(STM_BLOCK_SIZE);
    sb.ss_node_size    = cpu_to_le32(STM_NODE_SIZE);
    sb.ss_total_blocks = cpu_to_le64(size_bytes / STM_BLOCK_SIZE);
    sb.ss_free_blocks  = cpu_to_le64(size_bytes / STM_BLOCK_SIZE);
    sb.ss_next_ino     = cpu_to_le64(STM_ROOT_INO + 1);
    sb.ss_alloc_next   = cpu_to_le64(stm_btree_next_alloc(tree));
    sb.ss_snap_height  = cpu_to_le16(0);
    sb.ss_next_snap_id = cpu_to_le64(1);
    sb.ss_comp_algo    = comp_algo;

    memset(sb.ss_csum, 0, sizeof(sb.ss_csum));
    stm_csum_compute(&sb, sizeof(sb), sb.ss_csum);
    rc = stm_block_write(&dev, STM_SB_OFFSET_A, &sb, sizeof(sb));
    if (rc) goto fail_tree;
    rc = stm_block_write(&dev, STM_SB_OFFSET_B, &sb, sizeof(sb));
    if (rc) goto fail_tree;
    rc = stm_block_sync(&dev);
    if (rc) goto fail_tree;

    stm_btree_close(tree);
    stm_block_close(&dev);
    return 0;

fail_tree: stm_btree_close(tree);
fail_dev:
    stm_block_close(&dev);
    /* Don't leave a half-initialized volume on disk — the user will
     * mount it, fail with -EINVAL, and have to reformat. Remove the
     * backing file so `mkfs` is effectively atomic. */
    unlink(path);
    return rc;
}

/* Forward declaration — build_sb is defined further down but needed in
 * stm_fs_open for the mount-time gen bump (R8-1). */
static void build_sb(struct stm_fs *fs, struct stm_superblock *sb,
                     uint64_t gen, struct stm_bptr root,
                     struct stm_bptr snap_root,
                     uint64_t dev_sz);

/* ── open / close / sync ────────────────────────────────────────────── */

static int stm_fs_open_impl(const char *path, const char *passphrase,
                            int read_only, struct stm_fs **out);

int stm_fs_open(const char *path, const char *passphrase, struct stm_fs **out)
{
    return stm_fs_open_impl(path, passphrase, 0, out);
}

int stm_fs_open_ro(const char *path, const char *passphrase, struct stm_fs **out)
{
    return stm_fs_open_impl(path, passphrase, 1, out);
}

static int stm_fs_open_impl(const char *path, const char *passphrase,
                            int read_only, struct stm_fs **out)
{
    struct stm_fs *fs = calloc(1, sizeof(*fs));
    struct stm_superblock sa, sb;
    struct stm_superblock *chosen;
    int rc;

    if (!fs) return -ENOMEM;
    fs->read_only = read_only ? 1 : 0;

    rc = stm_file_backend_open(path, 0, 0, &fs->dev);
    if (rc) { free(fs); return rc; }

    stm_block_read(&fs->dev, STM_SB_OFFSET_A, &sa, sizeof(sa));
    stm_block_read(&fs->dev, STM_SB_OFFSET_B, &sb, sizeof(sb));

    {
        int a_ok = (le64_to_cpu(sa.ss_magic) == STM_MAGIC);
        int b_ok = (le64_to_cpu(sb.ss_magic) == STM_MAGIC);
        /* Verify superblock checksums (all-zeros = old volume, passes) */
        if (a_ok) {
            uint8_t saved[STM_CSUM_LEN];
            memcpy(saved, sa.ss_csum, STM_CSUM_LEN);
            memset(sa.ss_csum, 0, STM_CSUM_LEN);
            if (stm_csum_verify(&sa, sizeof(sa), saved) != 0) a_ok = 0;
            memcpy(sa.ss_csum, saved, STM_CSUM_LEN);
        }
        if (b_ok) {
            uint8_t saved[STM_CSUM_LEN];
            memcpy(saved, sb.ss_csum, STM_CSUM_LEN);
            memset(sb.ss_csum, 0, STM_CSUM_LEN);
            if (stm_csum_verify(&sb, sizeof(sb), saved) != 0) b_ok = 0;
            memcpy(sb.ss_csum, saved, STM_CSUM_LEN);
        }
        if (!a_ok && !b_ok) { stm_block_close(&fs->dev); free(fs); return -EINVAL; }

        /* R10-6: version-aware tiebreak. If both slots pass csum but
         * the higher-gen one has an unsupported ss_version, the lower-
         * gen slot may still be recoverable — an attacker with raw disk
         * access could tamper one slot to a bogus version with a higher
         * gen specifically to DoS mount. Prefer the v2 slot. */
        if (a_ok && b_ok) {
            int a_v2 = (le32_to_cpu(sa.ss_version) == 2);
            int b_v2 = (le32_to_cpu(sb.ss_version) == 2);
            if (a_v2 && b_v2)
                chosen = (le64_to_cpu(sa.ss_gen) >= le64_to_cpu(sb.ss_gen))
                       ? (fs->sb_slot = 0, &sa) : (fs->sb_slot = 1, &sb);
            else if (a_v2)
                chosen = (fs->sb_slot = 0, &sa);
            else if (b_v2)
                chosen = (fs->sb_slot = 1, &sb);
            else { stm_block_close(&fs->dev); free(fs); return -ENOTSUP; }
        } else {
            chosen = a_ok ? (fs->sb_slot = 0, &sa) : (fs->sb_slot = 1, &sb);
        }
    }

    /* R9-4: reject on-disk format versions we don't understand. v2
     * introduced AEAD associated-data binding (Phase D) on extents +
     * nodes — a v1 volume has ciphertexts produced with empty AD, which
     * would fail AEAD decrypt under the v2 code path. We refuse rather
     * than silently mis-decrypt. Recreate the volume with mkfs to get v2. */
    if (le32_to_cpu(chosen->ss_version) != 2) {
        fprintf(stderr,
                "stratum: volume is ss_version=%u; this build requires v2 "
                "(AEAD AD binding). Recreate the volume with stratum mkfs.\n",
                le32_to_cpu(chosen->ss_version));
        stm_block_close(&fs->dev); free(fs); return -ENOTSUP;
    }

    fs->gen         = le64_to_cpu(chosen->ss_gen);
    /* R13-3: reject extreme ss_gen. The AEAD nonce uniqueness invariant
     * requires fs->gen + 1 (mount-bump) and fs->gen + 2 (sync's
     * gen_final) to not wrap. At UINT64_MAX a single bump wraps to 0,
     * the tampered UINT64_MAX slot stays the tiebreak winner forever,
     * and every future session pins fs->gen at UINT64_MAX — reusing
     * the same nonce across sessions. Leave generous margin; legitimate
     * workloads can't approach even 2^32 syncs in any human timeframe. */
    if (fs->gen > UINT64_MAX - (UINT64_C(1) << 32)) {
        stm_block_close(&fs->dev); free(fs); return -ENOTSUP;
    }
    fs->next_ino    = le64_to_cpu(chosen->ss_next_ino);
    /* R12-1 + R13-2 + R14-1: defense-in-depth against adversarial
     * ss_next_ino. Low clamp (> STM_ROOT_INO) prevents root-inode
     * overwrite on first create. Walk-derived raise (via
     * mark_extent_entry) closes the "alias any live inode" case.
     * High clamp here closes the wraparound case: attacker sets
     * ss_next_ino near UINT64_MAX, alloc_ino returns max, increments
     * wrap to 0/1 (= STM_ROOT_INO) on subsequent creates, overwriting
     * root. 2^32 headroom is astronomical (no legitimate workload
     * creates 4 billion inodes in a reasonable timeframe). */
    if (fs->next_ino <= STM_ROOT_INO) fs->next_ino = STM_ROOT_INO + 1;
    if (fs->next_ino > UINT64_MAX - (UINT64_C(1) << 32)) {
        stm_block_close(&fs->dev); free(fs); return -ENOTSUP;
    }
    fs->next_snap_id = le64_to_cpu(chosen->ss_next_snap_id);
    /* R13-4 + R14-2: same low-then-high pattern for snap_id. */
    if (fs->next_snap_id == 0) fs->next_snap_id = 1;
    if (fs->next_snap_id > UINT64_MAX - (UINT64_C(1) << 32)) {
        stm_block_close(&fs->dev); free(fs); return -ENOTSUP;
    }
    fs->enc_algo = chosen->ss_enc_algo;
    memcpy(fs->enc_kdf_salt, chosen->ss_enc_kdf_salt, sizeof(fs->enc_kdf_salt));
    memcpy(fs->enc_wrapped_key, chosen->ss_enc_wrapped_key, sizeof(fs->enc_wrapped_key));
    memcpy(fs->enc_nonce, chosen->ss_enc_nonce, sizeof(fs->enc_nonce));

    /* decrypt volume key if encrypted */
    if (chosen->ss_enc_algo != STM_ENC_NONE) {
#ifdef STM_HAVE_CRYPTO
        uint8_t kek[STM_CRYPTO_KEY_LEN];
        if (!passphrase || !passphrase[0]) {
            stm_block_close(&fs->dev); free(fs); return -EACCES;
        }
        rc = stm_crypto_derive_key(passphrase, strlen(passphrase),
                                   chosen->ss_enc_kdf_salt, kek);
        if (rc) {
            memset(kek, 0, sizeof(kek));
            stm_block_close(&fs->dev); free(fs); return rc;
        }
        rc = stm_crypto_unwrap_key(kek, chosen->ss_enc_wrapped_key,
                                   chosen->ss_enc_nonce, fs->dek);
        memset(kek, 0, sizeof(kek));
        if (rc) {
            /* unwrap writes into fs->dek; wipe it on failure too */
            memset(fs->dek, 0, sizeof(fs->dek));
            stm_block_close(&fs->dev); free(fs); return rc;
        }
        fs->encrypted = 1;
#else
        stm_block_close(&fs->dev); free(fs); return -ENOTSUP;
#endif
    }

    /* open main tree */
    rc = stm_btree_open(&fs->dev, chosen->ss_root,
                        le16_to_cpu(chosen->ss_tree_height), &fs->tree);
    if (rc) {
        memset(fs->dek, 0, sizeof(fs->dek));
        stm_block_close(&fs->dev); free(fs); return rc;
    }
    stm_btree_set_alloc(fs->tree, le64_to_cpu(chosen->ss_alloc_next));
    rc = stm_fs_configure_tree(fs, fs->tree, STM_TREE_ID_MAIN);
    if (rc) {
        memset(fs->dek, 0, sizeof(fs->dek));
        stm_btree_close(fs->tree); stm_block_close(&fs->dev); free(fs); return rc;
    }

    /* open snapshot tree if it exists */
    if (!stm_bptr_is_null(&chosen->ss_snap_root)) {
        rc = stm_btree_open(&fs->dev, chosen->ss_snap_root,
                            le16_to_cpu(chosen->ss_snap_height), &fs->snap_tree);
        if (rc) {
            memset(fs->dek, 0, sizeof(fs->dek));
            stm_btree_close(fs->tree); stm_block_close(&fs->dev); free(fs); return rc;
        }
        stm_btree_set_alloc(fs->snap_tree, le64_to_cpu(chosen->ss_alloc_next));
        rc = stm_fs_configure_tree(fs, fs->snap_tree, STM_TREE_ID_SNAP);
        if (rc) {
            memset(fs->dek, 0, sizeof(fs->dek));
            stm_btree_close(fs->snap_tree); stm_btree_close(fs->tree);
            stm_block_close(&fs->dev); free(fs); return rc;
        }
    }

    /* build allocator from tree walks */
    {
        uint64_t dev_bytes = 0;
        stm_block_size(&fs->dev, &dev_bytes);
        rc = stm_alloc_open(&fs->dev, dev_bytes / STM_BLOCK_SIZE, &fs->alloc);
        if (rc) {
            memset(fs->dek, 0, sizeof(fs->dek));
            stm_btree_close(fs->snap_tree); stm_btree_close(fs->tree);
            stm_block_close(&fs->dev); free(fs); return rc;
        }
        /* mark superblock blocks */
        stm_alloc_mark(fs->alloc, 0, 2);
        /* Walk main tree — marks btree node blocks AND data extent blocks.
         * Any walk failure (corrupt node, AEAD tag mismatch, torn write)
         * means the allocator would only be marked for the reachable
         * prefix; unreachable-but-live blocks would be handed out for
         * reuse on the next write → mass silent overwrite. Refuse the
         * mount instead. The user's fallback is `stratum check`, which
         * performs the same walk as a diagnostic with deeper reporting. */
        rc = stm_btree_walk_entries(fs->tree, stm_btree_root(fs->tree),
                                    mark_block_fs, mark_extent_entry, fs);
        if (rc) goto fail_alloc;
        if (fs->snap_tree) {
            rc = stm_btree_walk_entries(fs->snap_tree, stm_btree_root(fs->snap_tree),
                                        mark_block_fs, mark_extent_entry, fs);
            if (rc) goto fail_alloc;
            /* Walk each snapshot's saved tree. walk_snap_cb now propagates
             * its inner walk error as a non-zero return, so stm_btree_scan
             * stops at the first broken snapshot. */
            struct stm_key lo = stm_mk_key(0, STM_KEY_SNAP, 0);
            struct stm_key hi = stm_mk_key(UINT64_MAX, STM_KEY_SNAP, UINT64_MAX);
            rc = stm_btree_scan(fs->snap_tree, &lo, &hi, walk_snap_cb, fs);
            if (rc) goto fail_alloc;
        }
        stm_alloc_commit(fs->alloc);
        stm_btree_set_allocator(fs->tree, fs->alloc);
        if (fs->snap_tree)
            stm_btree_set_allocator(fs->snap_tree, fs->alloc);
        goto alloc_ok;

    fail_alloc:
        memset(fs->dek, 0, sizeof(fs->dek));
        stm_alloc_close(fs->alloc);
        stm_btree_close(fs->snap_tree);
        stm_btree_close(fs->tree);
        stm_block_close(&fs->dev);
        free(fs);
        return rc;
    }
alloc_ok:

    /* R12-2: check scratch-buffer allocations. NULL here would segfault
     * the first stm_fs_write/read; mount failure is the correct response. */
    fs->extent_buf = malloc(STM_EXTENT_SIZE);
    fs->cipher_buf = malloc(STM_EXTENT_SIZE + STM_CRYPTO_TAG_LEN);
    if (!fs->extent_buf || !fs->cipher_buf) {
        rc = -ENOMEM;
        goto fail_bufs;
    }

    /* Compression algo from superblock. Refuse to mount if the persisted
     * codec isn't in this build — otherwise we'd silently fail to decode
     * existing compressed extents. */
    fs->comp_algo = chosen->ss_comp_algo;
    if (fs->comp_algo == STM_COMP_LZ4) {
#ifndef STM_HAVE_LZ4
        rc = -ENOTSUP; goto fail_bufs;
#endif
    } else if (fs->comp_algo == STM_COMP_ZSTD) {
#ifndef STM_HAVE_ZSTD
        rc = -ENOTSUP; goto fail_bufs;
#endif
    }

    {
        /* comp_buf sized to hold worst-case compressed output for any extent */
        uint32_t cbound = STM_EXTENT_SIZE;
        if (fs->comp_algo != STM_COMP_NONE) {
            uint32_t b = stm_compress_bound(fs->comp_algo, STM_EXTENT_SIZE);
            if (b > cbound) cbound = b;
        }
        fs->comp_buf = malloc(cbound);
        if (!fs->comp_buf) { rc = -ENOMEM; goto fail_bufs; }
    }

    /* Mount-time gen bump. Extends R7-1's crash-safety invariant from
     * "sync-internal windows" to "every session". R7-1 alone guarantees
     * ss_gen > max_write_gen across a sync's Phase 1 → Phase 3 — but
     * *after* a successful sync, fs->gen equals disk ss_gen. Any
     * inter-sync write (user-driven stm_fs_write, btree flush triggered
     * by message-buffer overflow on insert/delete, snap_create's pre-sync
     * flush) encrypts ciphertexts at write_gen = fs->gen = disk ss_gen.
     * A crash before the next sync leaves those orphan ciphertexts on
     * disk; next mount reads the same disk ss_gen and reuses it, and the
     * allocator hands out the freed orphan paddrs. Fresh writes at those
     * paddrs produce (DEK, nonce=paddr‖write_gen) collisions with the
     * orphan ciphertexts — classic stream-cipher nonce-reuse leak.
     *
     * Fix: immediately after loading the volume, write an SB at
     * ss_gen = chosen_gen + 1 to the opposite slot and fsync. fs->gen
     * stays at chosen_gen (used for session writes). Invariant becomes
     * disk ss_gen (= chosen_gen + 1) STRICTLY GREATER than fs->gen
     * (= chosen_gen) — holds from mount through first sync. Subsequent
     * syncs maintain the same offset: Phase 1 reservation at ss_gen =
     * fs->gen + 1 (already durable from mount-bump; Phase 1 just refreshes
     * the root field), Phase 3 final at ss_gen = fs->gen + 2, and
     * fs->gen advances by 1 (to fs->gen + 1), preserving the strict
     * inequality.
     *
     * Only needed on encrypted volumes — unencrypted volumes have no
     * AEAD-nonce invariant to protect. If the bump write fails, refuse
     * the mount: we cannot safely write ciphertexts without the floor
     * established. (RO-only use cases that must tolerate write failure
     * — e.g., `stratum check` on a degraded volume — can re-audit this
     * later, but currently all callers expect RW semantics.) */
    if (fs->encrypted && !read_only) {
        rc = stm_fs_gen_bump_disk(fs);
        if (rc) goto fail_bump;
    }

    *out = fs;
    return 0;

fail_bufs:
fail_bump:
    memset(fs->dek, 0, sizeof(fs->dek));
    free(fs->comp_buf);
    free(fs->extent_buf);
    free(fs->cipher_buf);
    stm_alloc_close(fs->alloc);
    stm_btree_close(fs->snap_tree);
    stm_btree_close(fs->tree);
    stm_block_close(&fs->dev);
    free(fs);
    return rc;
}

/* Serialize an on-disk SB at the given gen + current metadata. The caller
 * fills the root fields before/after this returns — this centralizes the
 * invariant fields and the csum computation. */
static void build_sb(struct stm_fs *fs, struct stm_superblock *sb,
                     uint64_t gen, struct stm_bptr root,
                     struct stm_bptr snap_root,
                     uint64_t dev_sz)
{
    memset(sb, 0, sizeof(*sb));
    sb->ss_magic        = cpu_to_le64(STM_MAGIC);
    sb->ss_version      = cpu_to_le32(2);
    sb->ss_gen          = cpu_to_le64(gen);
    sb->ss_root         = root;
    sb->ss_snap_root    = snap_root;
    sb->ss_space_root   = stm_bptr_null();
    sb->ss_tree_height  = cpu_to_le16(stm_btree_height(fs->tree));
    sb->ss_block_size   = cpu_to_le32(STM_BLOCK_SIZE);
    sb->ss_node_size    = cpu_to_le32(STM_NODE_SIZE);
    sb->ss_total_blocks = cpu_to_le64(dev_sz / STM_BLOCK_SIZE);
    sb->ss_free_blocks  = cpu_to_le64(0);
    sb->ss_next_ino     = cpu_to_le64(fs->next_ino);
    sb->ss_alloc_next   = cpu_to_le64(stm_btree_next_alloc(fs->tree));
    sb->ss_snap_height  = fs->snap_tree
                        ? cpu_to_le16(stm_btree_height(fs->snap_tree)) : cpu_to_le16(0);
    sb->ss_next_snap_id = cpu_to_le64(fs->next_snap_id);
    sb->ss_enc_algo     = fs->enc_algo;
    memcpy(sb->ss_enc_kdf_salt, fs->enc_kdf_salt, sizeof(sb->ss_enc_kdf_salt));
    memcpy(sb->ss_enc_wrapped_key, fs->enc_wrapped_key, sizeof(sb->ss_enc_wrapped_key));
    memcpy(sb->ss_enc_nonce, fs->enc_nonce, sizeof(sb->ss_enc_nonce));
    sb->ss_comp_algo    = fs->comp_algo;

    memset(sb->ss_csum, 0, sizeof(sb->ss_csum));
    stm_csum_compute(sb, sizeof(*sb), sb->ss_csum);
}

int stm_fs_gen_bump_disk(struct stm_fs *fs)
{
    struct stm_superblock sb;
    uint64_t dev_sz = 0;
    int bump_slot, rc;
    stm_block_size(&fs->dev, &dev_sz);
    build_sb(fs, &sb, fs->gen + 1,
             stm_btree_root(fs->tree),
             fs->snap_tree ? stm_btree_root(fs->snap_tree) : stm_bptr_null(),
             dev_sz);
    bump_slot = 1 - fs->sb_slot;
    rc = stm_block_write(&fs->dev,
                         bump_slot ? STM_SB_OFFSET_B : STM_SB_OFFSET_A,
                         &sb, sizeof(sb));
    if (rc) return rc;
    return stm_block_sync(&fs->dev);
}

/* Two-phase durable sync. Cross-mount AEAD nonce uniqueness depends on:
 *
 *   INVARIANT: on-disk ss_gen (at least one valid SB) is STRICTLY GREATER
 *              than the max write_gen ever used to encrypt a block that
 *              could become a reachable orphan after a crash.
 *
 * Before R7-1, a single failed SB write after a successful flush left
 * orphan ciphertexts at gen G on disk while the SB still said G. R7-1
 * fixed the sync-internal window; R8-1 extends it with a mount-time
 * gen bump (stm_fs_open) so the invariant also holds across inter-sync
 * writes — otherwise user data writes between syncs encrypt at write_gen
 * equal to disk ss_gen, and a crash before the next sync leaves orphan
 * ciphertexts at the same gen the next mount would reuse.
 *
 * The overall invariant maintained by mount-bump + sync: disk ss_gen is
 * always >= fs->gen + 1. Sync preserves this as follows:
 *
 * Entry state: fs->gen = G, disk ss_gen = G+1 (from mount-bump OR the
 * prior sync's Phase 3). Session writes in this sync use write_gen = G.
 *
 * Phase 1 (reservation): write an SB at ss_gen = G+1 (same as mount-bump
 * or prior reservation) with the PRE-flush root to the opposite slot;
 * fsync. This refreshes the reservation with the session's pre-flush
 * root — important because the root may have changed since mount-bump
 * via buffered inserts/deletes.
 *
 * Phase 2 (flush): tree flush at write_gen = G. All ciphertexts produced
 * have nonce (paddr ‖ G). Invariant holds: disk ss_gen = G+1 > G.
 *
 * Phase 3 (final): write an SB at ss_gen = G+2 with the post-flush root
 * to the current slot; fsync. fs->gen advances to G+1. Invariant holds:
 * disk ss_gen = G+2 > fs->gen = G+1.
 *
 * Crash-safety:
 *   - Crash after Phase 1: disk has (G+1, pre-flush root) at opposite
 *     slot, (G, old root) at current. Mount picks (G+1). fs->gen = G.
 *     Mount-bump establishes new disk ss_gen = G+1 (no advance because
 *     the SB was already at G+1 — but the opposite slot now has the
 *     bumped version with NEW mount-time state). Actually this crash
 *     means session's modifications are LOST (pre-flush root), and
 *     next session writes at G. Old session's orphans (from Phase 2
 *     if it started) at G. SAME GEN — possible collision!
 *
 * To avoid this: mount-bump must write at ss_gen = chosen_gen + 1, but
 * session writes must use chosen_gen. So if mount reads G+1 (from a
 * failed-mid-sync state), session writes at G+1, mount-bump establishes
 * disk ss_gen = G+2. Orphans from the failed sync at G (Phase 2 writes
 * before the crash) have different gen from G+1. Safe.
 *
 * On torn-write of Phase 3: opposite slot survives with (G+1, pre-flush
 * root). Same as above — safe.
 */
/* R10-2 / R10-3: guard macros applied at the top of each public API. */
#define STM_FS_GUARD_READ(fs)  do { \
    if ((fs)->wedged) return -EIO; \
} while (0)
#define STM_FS_GUARD_WRITE(fs) do { \
    if ((fs)->wedged) return -EIO; \
    if ((fs)->read_only) return -EROFS; \
} while (0)

int stm_fs_sync(struct stm_fs *fs)
{
    STM_FS_GUARD_WRITE(fs);
    struct stm_superblock sb;
    uint64_t dev_sz = 0;
    int new_slot, rc;
    uint64_t gen_used = fs->gen;            /* writes in this sync use this */
    uint64_t gen_reserve = gen_used + 1;    /* disk ss_gen during flush (matches mount-bump / prior reservation) */
    uint64_t gen_final   = gen_used + 2;    /* disk ss_gen after success */

    stm_block_size(&fs->dev, &dev_sz);

    /* Phase 1: reservation. ss_gen = gen_reserve = G+1 (same as mount-bump
     * or prior reservation). Refresh the reservation SB with the session's
     * current pre-flush root so a crash between Phase 1 and Phase 3 lands
     * at a consistent tree snapshot. Write to opposite of current sb_slot
     * — if this write torns, the prior good SB at fs->sb_slot remains. */
    new_slot = 1 - fs->sb_slot;
    build_sb(fs, &sb, gen_reserve,
             stm_btree_root(fs->tree),
             fs->snap_tree ? stm_btree_root(fs->snap_tree) : stm_bptr_null(),
             dev_sz);
    rc = stm_block_write(&fs->dev,
                         new_slot ? STM_SB_OFFSET_B : STM_SB_OFFSET_A,
                         &sb, sizeof(sb));
    if (rc) return rc;
    rc = stm_block_sync(&fs->dev);
    if (rc) return rc;

    /* Phase 2: flush at write_gen = gen_used = G. Disk ss_gen = G+1 > G
     * already (from Phase 1 / mount-bump), so orphans from an aborted
     * flush can't collide with next session's writes at G+1. */
    rc = stm_btree_flush(fs->tree, gen_used);
    if (rc) return rc;

    if (fs->snap_tree) {
        uint64_t a = stm_btree_next_alloc(fs->tree);
        uint64_t b = stm_btree_next_alloc(fs->snap_tree);
        if (b < a) stm_btree_set_alloc(fs->snap_tree, a);
        rc = stm_btree_flush(fs->snap_tree, gen_used);
        if (rc) return rc;
        a = stm_btree_next_alloc(fs->snap_tree);
        if (stm_btree_next_alloc(fs->tree) < a)
            stm_btree_set_alloc(fs->tree, a);
    }

    /* Phase 3: final commit. ss_gen = gen_final = G+2 (strictly greater
     * than reservation, so mount's gen tiebreak picks this SB). Write to
     * current sb_slot (overwriting prior final): if this torns, the
     * reservation at opposite slot survives with ss_gen = G+1 > G.
     * Advance fs->gen to G+1 — still one less than the new disk ss_gen,
     * preserving the invariant for inter-sync writes in the NEXT window. */
    build_sb(fs, &sb, gen_final,
             stm_btree_root(fs->tree),
             fs->snap_tree ? stm_btree_root(fs->snap_tree) : stm_bptr_null(),
             dev_sz);
    rc = stm_block_write(&fs->dev,
                         fs->sb_slot ? STM_SB_OFFSET_B : STM_SB_OFFSET_A,
                         &sb, sizeof(sb));
    if (rc) return rc;
    rc = stm_block_sync(&fs->dev);
    if (rc) return rc;

    fs->gen = gen_used + 1;  /* advance by 1; disk ss_gen = G+2 stays ahead */
    if (fs->alloc) stm_alloc_commit(fs->alloc);
    return 0;
}

void stm_fs_close(struct stm_fs *fs)
{
    if (!fs) return;
    stm_btree_close(fs->snap_tree);
    stm_btree_close(fs->tree);
    stm_alloc_close(fs->alloc);
    stm_block_close(&fs->dev);
    memset(fs->dek, 0, sizeof(fs->dek));
    free(fs->extent_buf);
    free(fs->cipher_buf);
    free(fs->comp_buf);
    free(fs);
}

/* ── inode helpers ───────────────────────────────────────────────────── */

static int read_inode(struct stm_fs *fs, uint64_t ino, struct stm_inode *out)
{
    struct stm_key k = mk_key(ino, STM_KEY_INODE, 0);
    uint32_t vlen = sizeof(*out);
    return stm_btree_lookup(fs->tree, &k, out, &vlen);
}

static int write_inode(struct stm_fs *fs, uint64_t ino,
                       const struct stm_inode *in)
{
    struct stm_key k = mk_key(ino, STM_KEY_INODE, 0);
    return stm_btree_insert(fs->tree, &k, in, sizeof(*in), fs->gen);
}

/* ── public operations ──────────────────────────────────────────────── */

int stm_fs_stat(struct stm_fs *fs, uint64_t ino, struct stm_inode *out)
{
    STM_FS_GUARD_READ(fs);
    return read_inode(fs, ino, out);
}

int stm_fs_lookup(struct stm_fs *fs, uint64_t parent_ino,
                  const char *name, uint64_t *out_ino)
{
    STM_FS_GUARD_READ(fs);
    return lookup_dirent(fs->tree, parent_ino, name, strlen(name),
                         out_ino, NULL);
}

static int create_entry(struct stm_fs *fs, uint64_t parent_ino,
                        const char *name, uint32_t mode, uint8_t dtype,
                        uint64_t *out_ino)
{
    size_t nlen = strlen(name);
    struct stm_key dkey;
    struct stm_inode ino_data;
    uint64_t new_ino, ts;
    uint32_t tns;
    uint8_t dbuf[STM_NAME_MAX + 16];
    uint32_t dlen;
    int rc;

    if (nlen == 0 || nlen > STM_NAME_MAX) return -EINVAL;

    rc = find_dirent_slot(fs->tree, parent_ino, name, nlen, &dkey);
    if (rc) return rc;

    new_ino = alloc_ino(fs);
    stm_now(&ts, &tns);

    /* create inode */
    memset(&ino_data, 0, sizeof(ino_data));
    ino_data.si_ino       = cpu_to_le64(new_ino);
    ino_data.si_gen       = cpu_to_le64(fs->gen);
    ino_data.si_mode      = cpu_to_le32(mode);
    ino_data.si_nlink     = cpu_to_le32(dtype == STM_DT_DIR ? 2 : 1);
    ino_data.si_atime_sec = cpu_to_le64(ts);
    ino_data.si_atime_nsec= cpu_to_le32(tns);
    ino_data.si_mtime_sec = cpu_to_le64(ts);
    ino_data.si_mtime_nsec= cpu_to_le32(tns);
    ino_data.si_ctime_sec = cpu_to_le64(ts);
    ino_data.si_ctime_nsec= cpu_to_le32(tns);

    rc = write_inode(fs, new_ino, &ino_data);
    if (rc) return rc;

    /* create dirent in parent */
    encode_dirent(new_ino, dtype, name, nlen, dbuf, &dlen);
    rc = stm_btree_insert(fs->tree, &dkey, dbuf, dlen, fs->gen);
    if (rc) return rc;

    if (out_ino) *out_ino = new_ino;
    return 0;
}

int stm_fs_mkdir(struct stm_fs *fs, uint64_t parent_ino, const char *name,
                 uint32_t mode, uint64_t *out_ino)
{
    STM_FS_GUARD_WRITE(fs);
    return create_entry(fs, parent_ino, name, STM_S_IFDIR | mode,
                        STM_DT_DIR, out_ino);
}

int stm_fs_create_file(struct stm_fs *fs, uint64_t parent_ino,
                       const char *name, uint32_t mode, uint64_t *out_ino)
{
    STM_FS_GUARD_WRITE(fs);
    return create_entry(fs, parent_ino, name, STM_S_IFREG | mode,
                        STM_DT_REG, out_ino);
}

/* ── extent helpers ─────────────────────────────────────────────────── */

/* Build the AEAD associated-data struct for a file-data extent. The AD
 * binds (inode, offset) to the ciphertext so an attacker who rewrites
 * an extent record to point at a different ciphertext — or who copies
 * one extent's ciphertext to a different (ino, offset) btree key —
 * gets a tag mismatch on decrypt. */
static void build_extent_ad(struct stm_ad_extent *ad,
                            uint64_t ino, uint64_t offset)
{
    ad->ad_magic   = cpu_to_le32(STM_AD_MAGIC_EXTENT);
    ad->ad_version = cpu_to_le32(1);
    ad->ad_ino     = cpu_to_le64(ino);
    ad->ad_offset  = cpu_to_le64(offset);
}

/* Write an extent with optional compression + encryption.
 *
 * Pipeline:
 *   plaintext ──(optional)compress──► payload ──(optional)encrypt──► disk
 *
 * If compression is configured but doesn't shrink the data, we fall back
 * to storing uncompressed. The extent record encodes the final state
 * (clen = stored bytes pre-AEAD-tag, comp = algorithm used). */
static int extent_write_data(struct stm_fs *fs, const void *data,
                             uint32_t dlen, uint64_t ino, uint64_t ext_off,
                             struct stm_extent *out_ext)
{
    struct stm_crypto *crypto = stm_btree_get_crypto(fs->tree);
    uint8_t  comp = STM_COMP_NONE;
    const uint8_t *payload = data;
    uint32_t clen = dlen;
    int rc;

    /* Try compression. Only keep the result if it saves space.
     * comp_buf is sized to the worst-case compressed bound, so the output
     * always fits. */
    if (fs->comp_algo != STM_COMP_NONE && dlen > 0) {
        uint32_t csize = stm_compress_bound(fs->comp_algo, dlen);
        if (stm_compress(fs->comp_algo, data, dlen,
                         fs->comp_buf, &csize) == 0 && csize < dlen) {
            payload = fs->comp_buf;
            clen = csize;
            comp = fs->comp_algo;
        }
    }

    uint32_t disk_len = crypto ? (clen + STM_CRYPTO_TAG_LEN) : clen;
    uint32_t nblocks = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    uint64_t paddr;
    rc = stm_alloc_extent(fs->alloc, nblocks, &paddr);
    if (rc) return rc;

    /* Phase D #7: per-extent xxHash3-64 of the on-disk payload (post-
     * compression, pre-encryption) — i.e. exactly the `clen` bytes at
     * `paddr`. Verified on read for unencrypted volumes. Always
     * populated so the format doesn't branch on encrypted-ness. */
    uint64_t xxh = stm_xxh64(payload, clen);

    if (crypto) {
        struct stm_ad_extent ad;
        build_extent_ad(&ad, ino, ext_off);
        uint32_t enc_len;
        rc = stm_crypto_encrypt(crypto, paddr, fs->gen,
                                &ad, sizeof(ad),
                                payload, clen,
                                fs->cipher_buf, &enc_len);
        if (rc) goto fail_free;
        rc = stm_block_write(&fs->dev, paddr, fs->cipher_buf, enc_len);
    } else {
        rc = stm_block_write(&fs->dev, paddr, payload, clen);
    }
    if (rc) goto fail_free;

    stm_extent_set(out_ext, paddr, fs->gen, dlen, clen, comp, xxh);
    return 0;

fail_free:
    /* Encrypt or write failed — no btree entry will reference these
     * blocks, so return them to the allocator (deferred pool; PENDING
     * until the next successful sync). */
    stm_alloc_free(fs->alloc, paddr / STM_BLOCK_SIZE, nblocks);
    return rc;
}

/* Read an extent into buf (at least STM_EXTENT_SIZE bytes).
 *
 * Pipeline: disk ──(optional)decrypt──► payload ──(optional)decompress──► buf
 *
 * For uncompressed, unencrypted data we read directly into buf (no extra copy).
 *
 * The `ino` / `ext_off` parameters bind the extent's AEAD tag to its (file,
 * offset) location. Callers MUST pass the same values at read as were used
 * at write; any mismatch fails decrypt with -EIO, which is the whole point
 * (ss_version>=2 defense against extent-record swap attacks).
 *
 * Non-static so the scrub CLI (src/cmd/scrub.c) can verify every extent's
 * AEAD tag + compress/decompress bounds by forcing a full read-back.
 * Still internal API — consumers include fs_internal.h. */
int extent_read_data(struct stm_fs *fs, const struct stm_extent *ext,
                     uint64_t ino, uint64_t ext_off,
                     void *buf, uint32_t buf_len)
{
    struct stm_crypto *crypto = stm_btree_get_crypto(fs->tree);
    uint64_t paddr = le64_to_cpu(ext->se_paddr);
    uint32_t dlen  = le32_to_cpu(ext->se_dlen);
    uint32_t clen  = stm_extent_clen(ext);
    uint8_t  comp  = stm_extent_comp(ext);
    int rc;

    /* Defense-in-depth: on encrypted volumes a corrupted extent record
     * can't slip through (AEAD catches any bit flip) but on unencrypted
     * volumes the extent record is only protected by the surrounding
     * btree-node xxHash3. Adversarial disk edits could produce dlen /
     * clen values that would overflow the output / scratch buffers
     * below. Reject anything beyond what we allocate. */
    if (dlen > STM_EXTENT_SIZE) return -EIO;
    if (dlen > buf_len)         return -EIO;
    if (comp == STM_COMP_NONE && clen != dlen) return -EIO;
    /* Tight upper bound on clen. The compress-bound formula admits values
     * up to ~131628 (LZ4) / ~131714 (ZSTD) for a 128 KiB input, which would
     * make disk_len = clen + tag exceed fs->cipher_buf capacity
     * (STM_EXTENT_SIZE + STM_CRYPTO_TAG_LEN = 131088). A legitimate
     * extent_write_data never stores clen >= dlen (it drops the compressed
     * form and stores plaintext instead), so clen < dlen <= STM_EXTENT_SIZE
     * is an invariant of writer-produced extents. Adversarial extents can
     * still have large clen; rejecting them here prevents heap OOB reads
     * into fs->cipher_buf. */
    if (clen > STM_EXTENT_SIZE) return -EIO;

    /* Determine compression destination: if uncompressed, decrypt/read
     * straight into buf. Otherwise use comp_buf as an intermediate. */
    uint8_t *payload;
    if (comp == STM_COMP_NONE) {
        payload = (uint8_t *)buf;
    } else {
        payload = fs->comp_buf;
    }

    if (crypto) {
        uint32_t disk_len = clen + STM_CRYPTO_TAG_LEN;
        uint32_t plain_len;
        uint64_t write_gen = le64_to_cpu(ext->se_write_gen);
        struct stm_ad_extent ad;
        build_extent_ad(&ad, ino, ext_off);
        rc = stm_block_read(&fs->dev, paddr, fs->cipher_buf, disk_len);
        if (rc) return rc;
        rc = stm_crypto_decrypt(crypto, paddr, write_gen,
                                &ad, sizeof(ad),
                                fs->cipher_buf, disk_len,
                                payload, &plain_len);
        if (rc) return rc;
        /* No se_xxh verify: AEAD tag already authenticated the on-disk
         * ciphertext cryptographically. xxHash of the plaintext would be
         * redundant, and verifying xxHash of ciphertext would still only
         * catch accidents AEAD already caught. */
    } else {
        uint32_t to_read = clen;
        if (comp == STM_COMP_NONE && to_read > buf_len) to_read = buf_len;
        rc = stm_block_read(&fs->dev, paddr, payload, to_read);
        if (rc) return rc;
        /* Phase D #7: verify per-extent xxHash3-64 of the on-disk bytes
         * before decompress. Catches bit rot / torn writes / media
         * errors on unencrypted volumes. A whole-extent read must hash
         * all `clen` bytes — any buf_len-truncated read would hash less
         * and give a false negative; the adjacency above (to_read may be
         * clamped only when comp==NONE && to_read > buf_len) means
         * clamping can only happen when buf_len < clen, which callers
         * currently never do (every caller allocates STM_EXTENT_SIZE and
         * dlen ≤ STM_EXTENT_SIZE → clen ≤ STM_EXTENT_SIZE ≤ buf_len).
         * Assert that invariant here; if a future caller shrinks buf
         * we'd need to verify the FULL ciphertext separately. */
        if (to_read != clen) return -EIO;
        uint64_t expected = le64_to_cpu(ext->se_xxh);
        uint64_t actual   = stm_xxh64(payload, clen);
        if (expected != actual) return -EIO;
    }

    if (comp != STM_COMP_NONE) {
        rc = stm_decompress(comp, payload, clen, buf, dlen);
        if (rc) return rc;
    }
    return 0;
}

static void extent_free_blocks(struct stm_fs *fs, const struct stm_extent *ext)
{
    struct stm_crypto *crypto = stm_btree_get_crypto(fs->tree);
    uint64_t paddr = le64_to_cpu(ext->se_paddr);
    uint32_t clen  = stm_extent_clen(ext);
    uint32_t disk_len = crypto ? (clen + STM_CRYPTO_TAG_LEN) : clen;
    uint32_t nblocks = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_free(fs->alloc, paddr / STM_BLOCK_SIZE, nblocks);
}

/* ── file I/O ───────────────────────────────────────────────────────── */

int stm_fs_write(struct stm_fs *fs, uint64_t ino, uint64_t offset,
                 const void *buf, uint32_t len)
{
    const uint8_t *src = buf;
    uint32_t remaining = len;
    uint64_t pos = offset;
    int rc;

    STM_FS_GUARD_WRITE(fs);

    /* Reject offset + len that would wrap uint64. Without this guard a
     * malicious or buggy client can plant extent records at both ends of
     * the 64-bit offset space (the inner loop wraps through zero), and
     * the inode size update silently does nothing (new_end also wraps).
     * End up with ghost extents the inode can't see. */
    if (len > 0 && offset > UINT64_MAX - (uint64_t)len)
        return -EFBIG;

    /* Verify the inode exists before touching the extent loop. Propagate
     * read errors: swallowing an EIO here would silently do no work and
     * then skip the inode-size update at the end → ghost extents +
     * orphaned blocks. (cur_size itself is no longer consulted because
     * both extent branches always look up the old record unconditionally,
     * per R7-6.) */
    {
        struct stm_inode sz_in;
        rc = read_inode(fs, ino, &sz_in);
        if (rc) return rc;
    }

    uint8_t *ebuf = fs->extent_buf;

    while (remaining > 0) {
        uint64_t ext_off = pos & ~((uint64_t)(STM_EXTENT_SIZE - 1));
        uint32_t inner   = (uint32_t)(pos - ext_off);
        uint32_t towrite = STM_EXTENT_SIZE - inner;
        if (towrite > remaining) towrite = remaining;

        struct stm_key k = mk_key(ino, STM_KEY_DATA, ext_off);
        struct stm_extent old_ext, new_ext;
        uint32_t extent_data_len;
        int had_old = 0;

        if (inner != 0 || towrite != (uint32_t)STM_EXTENT_SIZE) {
            /* partial extent: read-modify-write. Always look up the old
             * record (not conditional on ext_off < cur_size) to handle
             * retry-after-failure: if a prior partial write inserted a
             * ghost extent at this key but failed before bumping
             * si_size, cur_size stays old. Skipping the lookup would
             * leak the ghost extent's blocks when btree_insert replaces
             * it. Symmetric to the same fix on the full-extent branch. */
            uint32_t vlen = sizeof(old_ext);
            rc = stm_btree_lookup(fs->tree, &k, &old_ext, &vlen);
            if (rc == 0) {
                had_old = 1;
                rc = extent_read_data(fs, &old_ext, ino, ext_off,
                                      ebuf, STM_EXTENT_SIZE);
                if (rc) return rc;
                uint32_t old_dlen = le32_to_cpu(old_ext.se_dlen);
                /* extent_read_data only populates [0..old_dlen]; the tail
                 * still holds residue from a previous extent operation on
                 * this or any other file (fs->extent_buf is shared and
                 * never zeroed between uses). If the new write leaves a
                 * gap past old_dlen, that residue would be encrypted into
                 * the new ciphertext and become cross-file plaintext
                 * leakage on encrypted volumes. Purge it. */
                if (old_dlen < STM_EXTENT_SIZE)
                    memset(ebuf + old_dlen, 0, STM_EXTENT_SIZE - old_dlen);
                extent_data_len = old_dlen;
                if (extent_data_len < inner + towrite)
                    extent_data_len = inner + towrite;
            } else if (rc == -ENOENT) {
                memset(ebuf, 0, STM_EXTENT_SIZE);
                extent_data_len = inner + towrite;
            } else {
                return rc;
            }
        } else {
            /* Full extent write. Must always look up the old record —
             * without this, a retry after a partial-write failure would
             * see cur_size unchanged (inode size is only bumped after
             * all extents succeed) and skip the lookup for extent
             * offsets from the first attempt. The old extent's blocks
             * would then leak as btree_insert replaces the record. */
            uint32_t vlen = sizeof(old_ext);
            rc = stm_btree_lookup(fs->tree, &k, &old_ext, &vlen);
            if (rc == 0) had_old = 1;
            else if (rc != -ENOENT) return rc;
            extent_data_len = STM_EXTENT_SIZE;
        }

        memcpy(ebuf + inner, src, towrite);

        rc = extent_write_data(fs, ebuf, extent_data_len,
                               ino, ext_off, &new_ext);
        if (rc) return rc;

        /* Insert the new extent record BEFORE freeing the old extent's
         * blocks. If btree_insert fails (e.g. -ENOMEM), the file's
         * btree record is unchanged — it still points at old_ext which
         * still owns its blocks. We roll back by freeing the new
         * extent's just-allocated blocks. Net effect: file state is
         * unchanged, no data lost.
         *
         * If we freed old_ext first (the previous ordering) and then
         * btree_insert failed, the file's btree record would still
         * point at old_ext (no insert happened), but old_ext's blocks
         * would be PENDING → freed → reallocated at next alloc —
         * permanent silent data loss at that offset. */
        rc = stm_btree_insert(fs->tree, &k, &new_ext, sizeof(new_ext), fs->gen);
        if (rc) {
            extent_free_blocks(fs, &new_ext);
            return rc;
        }

        if (had_old) extent_free_blocks(fs, &old_ext);

        src       += towrite;
        pos       += towrite;
        remaining -= towrite;
    }

    /* update inode size */
    {
        uint64_t new_end = offset + len;
        struct stm_inode in;
        rc = read_inode(fs, ino, &in);
        if (rc) return rc;
        if (new_end > le64_to_cpu(in.si_size)) {
            in.si_size = cpu_to_le64(new_end);
            rc = write_inode(fs, ino, &in);
            if (rc) return rc;
        }
    }

    return 0;
}

int stm_fs_read(struct stm_fs *fs, uint64_t ino, uint64_t offset,
                void *buf, uint32_t len, uint32_t *out_read)
{
    struct stm_inode in;
    uint8_t *dst = buf;
    uint32_t remaining;
    uint64_t pos, fsize;
    int rc;

    STM_FS_GUARD_READ(fs);

    rc = read_inode(fs, ino, &in);
    if (rc) return rc;

    fsize = le64_to_cpu(in.si_size);
    if (offset >= fsize) { *out_read = 0; return 0; }
    if (offset + len > fsize) len = (uint32_t)(fsize - offset);

    pos = offset;
    remaining = len;

    while (remaining > 0) {
        uint64_t ext_off = pos & ~((uint64_t)(STM_EXTENT_SIZE - 1));
        uint32_t inner   = (uint32_t)(pos - ext_off);
        uint32_t toread  = STM_EXTENT_SIZE - inner;
        if (toread > remaining) toread = remaining;

        struct stm_key k = mk_key(ino, STM_KEY_DATA, ext_off);
        struct stm_extent ext;
        uint32_t vlen = sizeof(ext);

        rc = stm_btree_lookup(fs->tree, &k, &ext, &vlen);
        if (rc == -ENOENT) {
            memset(dst, 0, toread);  /* sparse: zeros */
        } else if (rc < 0) {
            return rc;
        } else {
            uint32_t dlen, avail, copy;
            rc = extent_read_data(fs, &ext, ino, ext_off,
                                  fs->extent_buf, STM_EXTENT_SIZE);
            if (rc) return rc;
            dlen = le32_to_cpu(ext.se_dlen);
            avail = (dlen > inner) ? dlen - inner : 0;
            copy  = (toread < avail) ? toread : avail;
            if (copy > 0) memcpy(dst, fs->extent_buf + inner, copy);
            if (copy < toread) memset(dst + copy, 0, toread - copy);
        }

        dst       += toread;
        pos       += toread;
        remaining -= toread;
    }

    *out_read = len;
    return 0;
}

/* ── readdir ────────────────────────────────────────────────────────── */

struct readdir_ctx {
    int (*user_cb)(const char *name, uint64_t ino, uint8_t type, void *ctx);
    void *user_ctx;
};

static int readdir_scan_cb(const struct stm_key *key, const void *val,
                           uint32_t vlen, void *ctx)
{
    struct readdir_ctx *rd = ctx;
    uint64_t child_ino;
    uint8_t dtype;
    const char *name;
    uint32_t nlen;
    char namebuf[STM_NAME_MAX + 1];

    (void)key;
    if (vlen < DIRENT_HDR) return 0;
    decode_dirent(val, vlen, &child_ino, &dtype, &name, &nlen);
    if (nlen > STM_NAME_MAX) nlen = STM_NAME_MAX;
    memcpy(namebuf, name, nlen);
    namebuf[nlen] = '\0';

    return rd->user_cb(namebuf, child_ino, dtype, rd->user_ctx);
}

int stm_fs_readdir(struct stm_fs *fs, uint64_t dir_ino,
                   int (*cb)(const char *name, uint64_t ino,
                             uint8_t type, void *ctx),
                   void *ctx)
{
    STM_FS_GUARD_READ(fs);
    struct stm_key lo = mk_key(dir_ino, STM_KEY_DIRENT, 0);
    struct stm_key hi = mk_key(dir_ino, STM_KEY_DATA, 0);
    struct readdir_ctx rd = { .user_cb = cb, .user_ctx = ctx };
    int rc = stm_btree_scan(fs->tree, &lo, &hi, readdir_scan_cb, &rd);
    /* Callback convention: positive return = caller stopped early
     * (e.g. FUSE's fuse_add_direntry ran out of buffer and signalled
     * overflow). That is NOT an error — only negative returns are.
     * Callers observe "stopped early" via their own state (e.g. the
     * dirfill buffer position / overflow flag). See the parallel
     * treatment in stm_fs_xattr_list for the xattr scan. */
    if (rc > 0) return 0;
    return rc;
}

/* ── unlink ─────────────────────────────────────────────────────────── */

/* ── unlink helpers ─────────────────────────────────────────────────── */

struct unlink_ctx {
    struct stm_fs     *fs;
    struct stm_key    *keys;
    struct stm_extent *exts;    /* parallel array to keys */
    uint32_t           count;
    uint32_t           cap;
};

/* Collect extent keys + records. Does NOT free extent blocks — that's
 * done only after all btree deletes succeed, so a mid-delete failure
 * can't leave us with PENDING-freed blocks while stale records still
 * point at them. */
static int collect_extent_cb(const struct stm_key *key, const void *val,
                             uint32_t vlen, void *ctx)
{
    struct unlink_ctx *uc = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (kc.type != STM_KEY_DATA) return 0;
    if (vlen != sizeof(struct stm_extent)) return 0;

    if (uc->count >= uc->cap) {
        uint32_t nc = uc->cap ? uc->cap * 2 : 64;
        /* Check each realloc return BEFORE the next call. Doing both then
         * checking after would leave us with one array reallocated (old
         * pointer possibly freed) and the other stale — the outer free()
         * would touch a dangling pointer. */
        struct stm_key *nk = realloc(uc->keys, nc * sizeof(*nk));
        if (!nk) return -ENOMEM;
        uc->keys = nk;
        struct stm_extent *nx = realloc(uc->exts, nc * sizeof(*nx));
        if (!nx) return -ENOMEM;
        uc->exts = nx;
        uc->cap  = nc;
    }
    uc->keys[uc->count] = *key;
    memcpy(&uc->exts[uc->count], val, sizeof(struct stm_extent));
    uc->count++;
    return 0;
}

/* Scan callback that flips a flag on the first live-dirent hit and stops.
 * Tombstones (vlen == DIRENT_TOMBSTONE_VLEN) don't count as "present". */
static int empty_check_cb(const struct stm_key *key, const void *val,
                          uint32_t vlen, void *ctx)
{
    (void)key; (void)val;
    if (vlen == DIRENT_TOMBSTONE_VLEN) return 0;  /* keep scanning */
    *(int *)ctx = 1;
    return 1;  /* stop the scan — found a live dirent */
}

/* ── POSIX Group A: chmod / chown / utimes / truncate ──────────────── */

/* Set the permission bits on an inode, preserving the IFMT (file-type)
 * bits. Updates ctime to now (POSIX: any attribute change bumps ctime).
 * mode is the new permission word; only the low 12 bits (rwx + setuid /
 * setgid / sticky) are taken, file-type bits retained from the existing
 * inode. */
int stm_fs_chmod(struct stm_fs *fs, uint64_t ino, uint32_t mode)
{
    STM_FS_GUARD_WRITE(fs);
    struct stm_inode in;
    int rc = read_inode(fs, ino, &in);
    if (rc) return rc;
    uint32_t cur = le32_to_cpu(in.si_mode);
    uint32_t new_mode = (cur & STM_S_IFMT) | (mode & 07777);
    in.si_mode = cpu_to_le32(new_mode);
    uint64_t ts; uint32_t tns;
    stm_now(&ts, &tns);
    in.si_ctime_sec  = cpu_to_le64(ts);
    in.si_ctime_nsec = cpu_to_le32(tns);
    return write_inode(fs, ino, &in);
}

/* Change ownership of an inode. A uid or gid of 0xFFFFFFFF means "leave
 * this field alone" (matches POSIX chown(-1, gid) and chown(uid, -1)
 * semantics — the kernel translates these to UINT_MAX). */
int stm_fs_chown(struct stm_fs *fs, uint64_t ino, uint32_t uid, uint32_t gid)
{
    STM_FS_GUARD_WRITE(fs);
    struct stm_inode in;
    int rc = read_inode(fs, ino, &in);
    if (rc) return rc;
    if (uid != (uint32_t)-1) in.si_uid = cpu_to_le32(uid);
    if (gid != (uint32_t)-1) in.si_gid = cpu_to_le32(gid);
    uint64_t ts; uint32_t tns;
    stm_now(&ts, &tns);
    in.si_ctime_sec  = cpu_to_le64(ts);
    in.si_ctime_nsec = cpu_to_le32(tns);
    return write_inode(fs, ino, &in);
}

/* Set atime and mtime. Each (sec, nsec) pair is applied only if
 * `set_atime` / `set_mtime` is non-zero — lets callers change one without
 * disturbing the other. ctime always updates (POSIX). */
int stm_fs_utimes(struct stm_fs *fs, uint64_t ino,
                  int set_atime, uint64_t atime_sec, uint32_t atime_nsec,
                  int set_mtime, uint64_t mtime_sec, uint32_t mtime_nsec)
{
    STM_FS_GUARD_WRITE(fs);
    struct stm_inode in;
    int rc = read_inode(fs, ino, &in);
    if (rc) return rc;
    if (set_atime) {
        in.si_atime_sec  = cpu_to_le64(atime_sec);
        in.si_atime_nsec = cpu_to_le32(atime_nsec);
    }
    if (set_mtime) {
        in.si_mtime_sec  = cpu_to_le64(mtime_sec);
        in.si_mtime_nsec = cpu_to_le32(mtime_nsec);
    }
    uint64_t ts; uint32_t tns;
    stm_now(&ts, &tns);
    in.si_ctime_sec  = cpu_to_le64(ts);
    in.si_ctime_nsec = cpu_to_le32(tns);
    return write_inode(fs, ino, &in);
}

/* Resize a file.
 *
 * Extend (new_size > cur_size): no extent allocation — stratum's
 * extent-based read path already returns zeros for unreferenced ranges
 * (sparse semantics). Just update si_size.
 *
 * Shrink (new_size < cur_size): walk DATA extents at offset ≥ new_size
 * and drop them; the extent that STRADDLES new_size (if any) is
 * read-modify-written to its truncated shorter form.
 *
 * Follows the R3-3 unlink pattern for crash safety: collect extent
 * records and keys, perform btree deletes first, then free allocator
 * blocks last. If anything fails mid-way the extents stay live and the
 * operation is retriable. */
int stm_fs_truncate(struct stm_fs *fs, uint64_t ino, uint64_t new_size)
{
    STM_FS_GUARD_WRITE(fs);

    /* Reject file sizes too close to UINT64_MAX. The shrink path
     * computes `align + STM_EXTENT_SIZE` which would wrap to 0 for
     * new_size > UINT64_MAX - STM_EXTENT_SIZE, turning the scan bound
     * into [0, UINT64_MAX) and wiping every extent. FUSE limits sizes
     * to INT64_MAX (off_t), so this is unreachable via a POSIX mount,
     * but the C API is callable directly and should reject pathological
     * inputs rather than corrupt the tree. */
    if (new_size > UINT64_MAX - STM_EXTENT_SIZE) return -EFBIG;

    struct stm_inode in;
    int rc = read_inode(fs, ino, &in);
    if (rc) return rc;
    uint64_t cur_size = le64_to_cpu(in.si_size);
    if (new_size == cur_size) return 0;

    if (new_size > cur_size) {
        /* Extend: pure metadata update; sparse bytes read as zero. */
        in.si_size = cpu_to_le64(new_size);
        uint64_t ts; uint32_t tns;
        stm_now(&ts, &tns);
        in.si_mtime_sec  = cpu_to_le64(ts);
        in.si_mtime_nsec = cpu_to_le32(tns);
        in.si_ctime_sec  = cpu_to_le64(ts);
        in.si_ctime_nsec = cpu_to_le32(tns);
        return write_inode(fs, ino, &in);
    }

    /* Shrink. Collect extents entirely past new_size; handle the
     * straddling extent (if any) separately via read-modify-write. */
    uint64_t align = new_size & ~((uint64_t)(STM_EXTENT_SIZE - 1));
    uint32_t inner = (uint32_t)(new_size - align);  /* bytes to keep in
                                                      * the straddling ext */

    struct unlink_ctx uc = { .fs = fs, .keys = NULL, .exts = NULL,
                             .count = 0, .cap = 0 };
    /* Scan range: the FIRST extent whose offset > new_size (i.e. wholly
     * past the new end) starts at `align + STM_EXTENT_SIZE`. Inclusive
     * at both ends via UINT64_MAX. */
    uint64_t first_full_off = align + STM_EXTENT_SIZE;
    if (inner == 0) first_full_off = align;  /* new_size is extent-aligned
                                              * → the extent at `align`
                                              * is wholly past too */
    struct stm_key lo = mk_key(ino, STM_KEY_DATA, first_full_off);
    struct stm_key hi = mk_key(ino, STM_KEY_DATA, UINT64_MAX);
    rc = stm_btree_scan(fs->tree, &lo, &hi, collect_extent_cb, &uc);
    if (rc) { free(uc.keys); free(uc.exts); return rc; }

    /* Handle the straddling extent (only when new_size is NOT aligned). */
    if (inner != 0) {
        struct stm_key sk = mk_key(ino, STM_KEY_DATA, align);
        struct stm_extent old_ext;
        uint32_t vlen = sizeof(old_ext);
        rc = stm_btree_lookup(fs->tree, &sk, &old_ext, &vlen);
        if (rc == 0 && vlen == sizeof(old_ext)) {
            uint32_t old_dlen = le32_to_cpu(old_ext.se_dlen);
            if (old_dlen > inner) {
                /* Read the extent into the scratch buffer, truncate it
                 * to `inner` bytes, write a new shorter replacement.
                 * Zero the tail past `inner` BEFORE writing — same
                 * R6-1 hygiene as stm_fs_write: unencrypted extent_buf
                 * residue would otherwise leak into the new ciphertext
                 * as cross-extent plaintext on encrypted volumes. */
                uint8_t *ebuf = fs->extent_buf;
                rc = extent_read_data(fs, &old_ext, ino, align,
                                      ebuf, STM_EXTENT_SIZE);
                if (rc) { free(uc.keys); free(uc.exts); return rc; }
                if (inner < STM_EXTENT_SIZE)
                    memset(ebuf + inner, 0, STM_EXTENT_SIZE - inner);
                struct stm_extent new_ext;
                rc = extent_write_data(fs, ebuf, inner,
                                       ino, align, &new_ext);
                if (rc) { free(uc.keys); free(uc.exts); return rc; }
                rc = stm_btree_insert(fs->tree, &sk, &new_ext,
                                      sizeof(new_ext), fs->gen);
                if (rc) {
                    extent_free_blocks(fs, &new_ext);
                    free(uc.keys); free(uc.exts); return rc;
                }
                extent_free_blocks(fs, &old_ext);
            }
        } else if (rc != -ENOENT) {
            free(uc.keys); free(uc.exts); return rc;
        }
    }

    /* Delete all wholly-past extents' btree records first, then free
     * their blocks (R3-3 ordering). */
    for (uint32_t i = 0; i < uc.count; i++) {
        rc = stm_btree_delete(fs->tree, &uc.keys[i], fs->gen);
        if (rc) { free(uc.keys); free(uc.exts); return rc; }
    }
    for (uint32_t i = 0; i < uc.count; i++)
        extent_free_blocks(fs, &uc.exts[i]);
    free(uc.keys); free(uc.exts);

    /* Finally update inode size + timestamps. */
    in.si_size = cpu_to_le64(new_size);
    uint64_t ts; uint32_t tns;
    stm_now(&ts, &tns);
    in.si_mtime_sec  = cpu_to_le64(ts);
    in.si_mtime_nsec = cpu_to_le32(tns);
    in.si_ctime_sec  = cpu_to_le64(ts);
    in.si_ctime_nsec = cpu_to_le32(tns);
    return write_inode(fs, ino, &in);
}

/* ── POSIX Group C: extended attributes ────────────────────────────── */

/* Xattr key/value layout.
 *
 * Key: (ino, STM_KEY_XATTR, fnv1a(name) + probe_distance). Hash +
 * linear probing mirrors the dirent scheme (§8.3 STRATUM.md), which is
 * already validated by the R-audit-era dirent-tombstone fixes.
 *
 * Value (live entry):
 *   [u16 name_len][name bytes][u32 val_len][val bytes]
 * Value (tombstone): single zero byte (vlen == 1).
 *
 * Limits: name ≤ STM_NAME_MAX (255); value ≤ STM_XATTR_VALUE_MAX (64 KiB).
 * Larger values would fit in the btree but could fragment leaves; bump
 * later if real workloads demand it. */
#define STM_XATTR_VALUE_MAX  65536u
#define XATTR_TOMBSTONE_VLEN 1

static void encode_xattr(const char *name, size_t nlen,
                         const void *val, uint32_t vlen,
                         uint8_t *buf, uint32_t *out_len)
{
    le16 nlen_le = cpu_to_le16((uint16_t)nlen);
    le32 vlen_le = cpu_to_le32(vlen);
    memcpy(buf, &nlen_le, 2);
    memcpy(buf + 2, name, nlen);
    memcpy(buf + 2 + nlen, &vlen_le, 4);
    memcpy(buf + 6 + nlen, val, vlen);
    *out_len = (uint32_t)(6 + nlen + vlen);
}

static int decode_xattr(const uint8_t *buf, uint32_t blen,
                        const char **name_out, uint16_t *nlen_out,
                        const uint8_t **val_out, uint32_t *vlen_out)
{
    if (blen < 6) return -EIO;
    le16 nlen_le;
    memcpy(&nlen_le, buf, 2);
    uint16_t nlen = le16_to_cpu(nlen_le);
    if (nlen == 0 || nlen > STM_NAME_MAX) return -EIO;
    if (blen < 6u + (uint32_t)nlen) return -EIO;
    le32 vlen_le;
    memcpy(&vlen_le, buf + 2 + nlen, 4);
    uint32_t vlen = le32_to_cpu(vlen_le);
    if (vlen > STM_XATTR_VALUE_MAX) return -EIO;
    if (blen != 6u + (uint32_t)nlen + vlen) return -EIO;
    *name_out = (const char *)(buf + 2);
    *nlen_out = nlen;
    *val_out = buf + 6 + nlen;
    *vlen_out = vlen;
    return 0;
}

/* Two-phase xattr lookup:
 *   Phase 1 uses a small stack buffer sized to (hdr + max name) so we
 *   can check the name prefix without decoding the full value. If the
 *   name matches and out_key is requested, we're done.
 *   Phase 2 (only if want_value) re-reads with a full-size heap buffer,
 *   decodes, and gives back the value.
 *
 * Returns 0 on hit, -ENOENT on probe-chain exhausted without match,
 * -EIO on a corrupt encoding, other errors from stm_btree_lookup. On a
 * want_value hit, `*val_out_buf` is set to a heap-allocated buffer the
 * caller must free(); `*vlen_out` is the value length. */
static int xattr_lookup(struct stm_btree *tree, uint64_t ino,
                        const char *name, size_t nlen,
                        struct stm_key *out_key,
                        int want_value,
                        uint8_t **val_out_buf, uint32_t *vlen_out)
{
    uint64_t h = fnv1a(name, nlen);
    uint8_t pbuf[STM_NAME_MAX + 16];  /* 271 bytes — fits hdr + name */
    for (int attempt = 0; attempt < 256; attempt++) {
        struct stm_key k = mk_key(ino, STM_KEY_XATTR, h + (uint64_t)attempt);
        uint32_t plen = sizeof(pbuf);
        int rc = stm_btree_lookup(tree, &k, pbuf, &plen);
        if (rc == -ENOENT) return -ENOENT;
        if (rc < 0) return rc;
        if (plen == XATTR_TOMBSTONE_VLEN) continue;
        /* Guard against reading past the truncated prefix copy. The
         * stm_btree_lookup copies min(capacity, actual) bytes but
         * returns `actual` in *vlen. We can only safely inspect bytes
         * up to min(actual, sizeof(pbuf)). */
        uint32_t prefix_have = plen < sizeof(pbuf) ? plen : (uint32_t)sizeof(pbuf);
        if (prefix_have < 6) continue;  /* malformed, skip */

        le16 nlen_le;
        memcpy(&nlen_le, pbuf, 2);
        uint16_t got_nlen = le16_to_cpu(nlen_le);
        if (got_nlen == 0 || got_nlen > STM_NAME_MAX) continue;
        if (prefix_have < 2u + got_nlen) continue;  /* prefix truncated */

        if (got_nlen != nlen || memcmp(pbuf + 2, name, nlen) != 0) {
            /* hash collision — different name */
            continue;
        }

        if (out_key) *out_key = k;
        if (!want_value) return 0;

        /* Phase 2: re-fetch with a full-size buffer to get the value. */
        uint8_t *big = malloc(plen);
        if (!big) return -ENOMEM;
        uint32_t blen = plen;
        rc = stm_btree_lookup(tree, &k, big, &blen);
        if (rc) { free(big); return rc; }
        if (blen != plen) { free(big); return -EIO; }  /* race? */

        const char *dn; uint16_t dnl;
        const uint8_t *dv; uint32_t dvl;
        rc = decode_xattr(big, blen, &dn, &dnl, &dv, &dvl);
        if (rc) { free(big); return rc; }
        /* Hand the value back as a heap copy so the caller's buffer
         * lifetime is independent of pbuf/big. */
        uint8_t *vcopy = malloc(dvl ? dvl : 1);
        if (!vcopy) { free(big); return -ENOMEM; }
        if (dvl) memcpy(vcopy, dv, dvl);
        free(big);
        *val_out_buf = vcopy;
        *vlen_out = dvl;
        return 0;
    }
    return -ENOENT;
}

/* Find a slot for a new xattr: first tombstone seen (if any) or the
 * first never-used slot at end-of-chain. Rejects -EEXIST if a live
 * entry with the same name is already present. */
static int xattr_find_slot(struct stm_btree *tree, uint64_t ino,
                           const char *name, size_t nlen,
                           struct stm_key *out_key, int *exists)
{
    uint64_t h = fnv1a(name, nlen);
    int have_tomb = 0;
    struct stm_key tomb_key;
    *exists = 0;
    for (int attempt = 0; attempt < 256; attempt++) {
        struct stm_key k = mk_key(ino, STM_KEY_XATTR, h + (uint64_t)attempt);
        uint8_t vbuf[STM_NAME_MAX + 16];
        uint32_t vlen = sizeof(vbuf);
        int rc = stm_btree_lookup(tree, &k, vbuf, &vlen);
        if (rc == -ENOENT) {
            *out_key = have_tomb ? tomb_key : k;
            return 0;
        }
        if (rc < 0) return rc;
        if (vlen == XATTR_TOMBSTONE_VLEN) {
            if (!have_tomb) { tomb_key = k; have_tomb = 1; }
            continue;
        }
        /* Live entry — is it a duplicate? We only need the name
         * prefix, not the value. */
        if (vlen >= 6) {
            le16 nlen_le;
            memcpy(&nlen_le, vbuf, 2);
            uint16_t got_nlen = le16_to_cpu(nlen_le);
            if (got_nlen == nlen && vlen >= 2u + got_nlen &&
                memcmp(vbuf + 2, name, nlen) == 0) {
                *out_key = k;
                *exists = 1;
                return 0;
            }
        }
    }
    return -ENOSPC;
}

/* POSIX Group C: setxattr. `flags`:
 *   0              — create or replace (default)
 *   XATTR_CREATE   — fail -EEXIST if already set (Linux #define = 1)
 *   XATTR_REPLACE  — fail -ENODATA if not already set (#define = 2)
 * The header here doesn't depend on sys/xattr.h to stay portable; the
 * FUSE caller passes Linux-style flags through unchanged. */
int stm_fs_xattr_set(struct stm_fs *fs, uint64_t ino,
                     const char *name, const void *val, uint32_t val_len,
                     int flags)
{
    STM_FS_GUARD_WRITE(fs);
    if (!name || !name[0]) return -EINVAL;
    size_t nlen = strlen(name);
    if (nlen > STM_NAME_MAX) return -ENAMETOOLONG;
    if (val_len > STM_XATTR_VALUE_MAX) return -E2BIG;

    /* Existence check + slot resolution in one pass. */
    struct stm_key slot;
    int exists;
    int rc = xattr_find_slot(fs->tree, ino, name, nlen, &slot, &exists);
    if (rc) return rc;

    if ((flags & 1) && exists)       return -EEXIST;      /* XATTR_CREATE */
    if ((flags & 2) && !exists)      return -ENODATA;     /* XATTR_REPLACE */

    uint8_t *buf = malloc(6 + nlen + val_len);
    if (!buf) return -ENOMEM;
    uint32_t dlen;
    encode_xattr(name, nlen, val, val_len, buf, &dlen);
    rc = stm_btree_insert(fs->tree, &slot, buf, dlen, fs->gen);
    free(buf);
    return rc;
}

/* getxattr: probe the chain, match by name. `*inout_len` on entry is
 * the caller's buffer capacity; on exit it's the actual value length.
 * If the caller passes 0, we return the size without copying (classic
 * "query size" pattern). Returns -ERANGE if the caller's buffer is
 * non-zero but too small. */
int stm_fs_xattr_get(struct stm_fs *fs, uint64_t ino,
                     const char *name, void *out, uint32_t *inout_len)
{
    if (fs->wedged) return -EIO;
    if (!name || !name[0] || !inout_len) return -EINVAL;
    /* A non-zero buffer size without a buffer is malformed; memcpy(NULL, …)
     * is UB even when the copy is truncated by ERANGE in other paths. */
    if (*inout_len > 0 && !out) return -EINVAL;
    size_t nlen = strlen(name);
    if (nlen > STM_NAME_MAX) return -ENAMETOOLONG;

    uint8_t *val_buf = NULL;
    uint32_t vlen = 0;
    int rc = xattr_lookup(fs->tree, ino, name, nlen, NULL,
                          1, &val_buf, &vlen);
    if (rc) return rc;

    if (*inout_len == 0) {
        /* Size-query: caller just wants to know how big the value is. */
        *inout_len = vlen;
        free(val_buf);
        return 0;
    }
    if (*inout_len < vlen) { free(val_buf); return -ERANGE; }
    memcpy(out, val_buf, vlen);
    *inout_len = vlen;
    free(val_buf);
    return 0;
}

/* listxattr iterator. For each live xattr on this inode, invokes cb with
 * the name (null-terminated). cb returns non-zero to stop. */
struct xattr_list_ctx {
    int (*user_cb)(const char *name, void *ctx);
    void *user_ctx;
    int stopped;
};

static int xattr_list_scan_cb(const struct stm_key *key, const void *val,
                              uint32_t vlen, void *ctx)
{
    (void)key;
    struct xattr_list_ctx *lc = ctx;
    if (vlen == XATTR_TOMBSTONE_VLEN) return 0;  /* skip tombstones */
    const char *name; uint16_t nlen;
    const uint8_t *v; uint32_t vl;
    if (decode_xattr(val, vlen, &name, &nlen, &v, &vl) != 0) return 0;
    char nbuf[STM_NAME_MAX + 1];
    if (nlen > STM_NAME_MAX) return 0;
    memcpy(nbuf, name, nlen);
    nbuf[nlen] = '\0';
    if (lc->user_cb(nbuf, lc->user_ctx)) { lc->stopped = 1; return 1; }
    return 0;
}

int stm_fs_xattr_list(struct stm_fs *fs, uint64_t ino,
                      int (*cb)(const char *name, void *ctx), void *ctx)
{
    if (fs->wedged) return -EIO;
    struct stm_key lo = mk_key(ino, STM_KEY_XATTR, 0);
    struct stm_key hi = mk_key(ino, STM_KEY_SNAP, 0);  /* next type after XATTR */
    struct xattr_list_ctx lc = { .user_cb = cb, .user_ctx = ctx, .stopped = 0 };
    int rc = stm_btree_scan(fs->tree, &lo, &hi, xattr_list_scan_cb, &lc);
    /* stm_btree_scan returns the callback's non-zero return verbatim.
     * A positive return from the callback (early stop from caller; e.g.
     * FUSE's buffer-full signal) is NOT an error — only negative returns
     * are. Callers distinguish "stopped early" via their own state
     * (e.g. listbuf->overflow flag). */
    if (rc > 0) return 0;
    return rc;
}

/* removexattr: locate the entry, replace with a tombstone to preserve
 * the probe chain (same pattern as dirents). */
int stm_fs_xattr_remove(struct stm_fs *fs, uint64_t ino, const char *name)
{
    STM_FS_GUARD_WRITE(fs);
    if (!name || !name[0]) return -EINVAL;
    size_t nlen = strlen(name);
    if (nlen > STM_NAME_MAX) return -ENAMETOOLONG;

    /* want_value=0 — we just need the key to overwrite with a
     * tombstone; the existing value is thrown away. */
    struct stm_key slot;
    int rc = xattr_lookup(fs->tree, ino, name, nlen, &slot,
                          0, NULL, NULL);
    if (rc) return rc;
    uint8_t marker = 0;
    return stm_btree_insert(fs->tree, &slot, &marker,
                            XATTR_TOMBSTONE_VLEN, fs->gen);
}

/* POSIX Group B: rename.
 *
 * rename(old_parent/old_name, new_parent/new_name) atomically moves or
 * renames a directory entry. The inode number is preserved — only the
 * dirent's (parent, hash, name) record changes. POSIX semantics require:
 *
 *   - Success iff the source exists, source name is valid, target can
 *     be replaced (doesn't exist OR is a non-dir OR is an empty dir).
 *   - If target exists, it's atomically unlinked (nlink decremented;
 *     data freed if nlink hits 0).
 *   - Rename-to-self (same parent + same name) is a no-op.
 *   - Crash atomicity: after recovery, state is either pre- or
 *     post-rename. Stratum's two-phase sync gives this for free —
 *     all three btree ops below are buffered in the tree's message
 *     buffer and commit together on the next sync.
 *
 * Ordering:
 *   1. Look up source; validate it exists.
 *   2. Rename-to-self → 0.
 *   3. Check target: if present, stm_fs_unlink it (propagates
 *      -ENOTEMPTY for non-empty directories, matching POSIX).
 *   4. find_dirent_slot for the new name.
 *   5. Insert new dirent pointing at source's ino.
 *   6. Tombstone the old dirent.
 *
 * Failure modes between (5) and (6): new dirent inserted but old not
 * yet tombstoned → inode is reachable via both paths (a transient
 * hardlink-like state). Subsequent unlink of either path would decrement
 * nlink to 0 and free the inode, breaking the other path. We return
 * the tombstone error; retry typically succeeds. In-session-only, no
 * disk state yet.
 *
 * Failure at (3) → no change yet (target unchanged, source unchanged).
 * Failure at (5) → target already gone but source still exists; caller
 * sees -ENOSPC/ENOMEM and knows data was lost. Real POSIX filesystems
 * have the same issue under ENOSPC. For Stratum's COW model the target's
 * extent blocks are PENDING (freed on next sync commit); they don't
 * reappear as the new dirent's data. */
int stm_fs_rename(struct stm_fs *fs,
                  uint64_t old_parent, const char *old_name,
                  uint64_t new_parent, const char *new_name)
{
    STM_FS_GUARD_WRITE(fs);

    /* NOTE: no ancestor-loop check (renaming a directory into its own
     * subtree creates a cycle). See caller-contract comment in fs.h.
     * FUSE callers are covered by the Linux VFS pre-check; other callers
     * MUST guard themselves. */

    size_t old_nlen = strlen(old_name);
    size_t new_nlen = strlen(new_name);
    if (old_nlen == 0 || old_nlen > STM_NAME_MAX) return -EINVAL;
    if (new_nlen == 0 || new_nlen > STM_NAME_MAX) return -EINVAL;

    /* 1. Source must exist. */
    uint64_t old_ino;
    struct stm_key old_dkey;
    int rc = lookup_dirent(fs->tree, old_parent, old_name, old_nlen,
                           &old_ino, &old_dkey);
    if (rc) return rc;  /* -ENOENT if missing */

    /* 2. Rename-to-self: POSIX says this must return success with no
     *    side effects. */
    if (old_parent == new_parent && old_nlen == new_nlen &&
        memcmp(old_name, new_name, old_nlen) == 0) {
        return 0;
    }

    /* 3. If the target exists, remove it first. Same-inode target (the
     *    source and destination names alias the same ino, e.g. via a
     *    hardlink — not created today but possible once Group D lands)
     *    is a no-op: just tombstone the old name. */
    uint64_t tgt_ino;
    rc = lookup_dirent(fs->tree, new_parent, new_name, new_nlen,
                       &tgt_ino, NULL);
    if (rc == 0) {
        if (tgt_ino == old_ino) {
            return tombstone_dirent(fs->tree, &old_dkey, fs->gen);
        }
        /* stm_fs_unlink handles both files and dirs — dirs get the
         * ENOTEMPTY check, nlink-0 files get fully reaped. */
        rc = stm_fs_unlink(fs, new_parent, new_name);
        if (rc) return rc;
    } else if (rc != -ENOENT) {
        return rc;
    }

    /* 4. Read source inode to derive the dirent type byte (DT_DIR vs
     *    DT_REG). Needed for the encoded dirent value. */
    struct stm_inode old_in;
    rc = read_inode(fs, old_ino, &old_in);
    if (rc) return rc;
    uint32_t old_mode = le32_to_cpu(old_in.si_mode);
    uint8_t dtype = ((old_mode & STM_S_IFMT) == STM_S_IFDIR)
                  ? STM_DT_DIR : STM_DT_REG;

    /* 5. Find a slot for the new name and insert the dirent. If the
     *    name's probe chain is full (256 collisions) we return -ENOSPC
     *    without modifying anything further. */
    struct stm_key new_dkey;
    rc = find_dirent_slot(fs->tree, new_parent, new_name, new_nlen, &new_dkey);
    if (rc) return rc;

    uint8_t dbuf[STM_NAME_MAX + 16];
    uint32_t dlen;
    encode_dirent(old_ino, dtype, new_name, new_nlen, dbuf, &dlen);
    rc = stm_btree_insert(fs->tree, &new_dkey, dbuf, dlen, fs->gen);
    if (rc) return rc;

    /* 6. Tombstone the old dirent. If this fails the inode is reachable
     *    via both old and new paths — a logical hardlink with nlink=1.
     *    Retry-safe: a second rename() with the same arguments will
     *    find the new dirent already in place (tgt_ino == old_ino) and
     *    succeed by just tombstoning the old dirent. */
    return tombstone_dirent(fs->tree, &old_dkey, fs->gen);
}

/* POSIX Group D: hardlinks.
 *
 * stm_fs_link inserts a new dirent at (new_parent, new_name) pointing at
 * an existing inode, and bumps si_nlink on that inode. The existing
 * stm_fs_unlink already honors nlink > 1 (it decrements, tombstones one
 * dirent, and only reaps data when nlink reaches 0), so hardlinks
 * "just work" once stm_fs_link is in place.
 *
 * POSIX-strict: hardlinks are legal only on NON-directory files.
 * Directory hardlinks would create cycles and break readdir + orphan
 * detection; the kernel VFS has always rejected them with -EPERM.
 * We do the same.
 *
 * Ordering for crash safety:
 *   1. Read target inode (source of the link).
 *   2. Reject -EPERM for directories.
 *   3. find_dirent_slot for the new name (returns -EEXIST if live).
 *   4. Insert new dirent → after this, two dirents point at target,
 *      nlink is still stale (= old value).
 *   5. Bump nlink and write the inode → after this, nlink matches
 *      the dirent count.
 *
 * Failure modes:
 *   - find_dirent_slot fails → no changes, retry-safe.
 *   - btree_insert fails after slot resolution → nlink unchanged,
 *     no new dirent, retry-safe.
 *   - write_inode fails AFTER the new dirent insert → volume has
 *     two dirents with nlink still = old value. Subsequent unlink
 *     of either path decrements nlink below the real count, and
 *     eventually nlink hits 0 while a dirent still lives. `stratum
 *     check` would flag this as "dangling dirent" / "nlink mismatch"
 *     mismatch. Practically this only triggers on btree-level OOM
 *     mid-insert, which is extremely rare. Retry of stm_fs_link
 *     hits -EEXIST on find_dirent_slot because the new dirent is
 *     already there; the caller can detect this and issue a
 *     follow-up write_inode itself.
 *
 * The reverse order (write_inode first, then insert dirent) would
 * leave a stale bump on failure — nlink N+1 with only N dirents, and
 * a later unlink would see nlink=1 and skip the reap when in fact
 * this was the last dirent. Worse outcome. Insert-then-bump is
 * correct: too-low-nlink reports an inconsistency statically without
 * hiding data reachable from unbalanced dirents. */
int stm_fs_link(struct stm_fs *fs, uint64_t target_ino,
                uint64_t new_parent, const char *new_name)
{
    STM_FS_GUARD_WRITE(fs);
    if (!new_name || !new_name[0]) return -EINVAL;
    size_t nlen = strlen(new_name);
    if (nlen > STM_NAME_MAX) return -ENAMETOOLONG;

    struct stm_inode in;
    int rc = read_inode(fs, target_ino, &in);
    if (rc) return rc;

    uint32_t mode = le32_to_cpu(in.si_mode);
    if ((mode & STM_S_IFMT) == STM_S_IFDIR) return -EPERM;

    /* Overflow guard: si_nlink is u32; practically unreachable but
     * worth rejecting symbolically. 2^32 hardlinks would require 2^32
     * dirents which would blow the address space long before. */
    uint32_t cur_nl = le32_to_cpu(in.si_nlink);
    if (cur_nl >= 0xFFFFFFFEu) return -EMLINK;

    struct stm_key new_dkey;
    rc = find_dirent_slot(fs->tree, new_parent, new_name, nlen, &new_dkey);
    if (rc) return rc;  /* -EEXIST if name already in use */

    /* Directory was rejected at the -EPERM above; all surviving inodes are
     * non-directories for dirent-type purposes. */
    uint8_t dtype = STM_DT_REG;
    uint8_t dbuf[STM_NAME_MAX + 16];
    uint32_t dlen;
    encode_dirent(target_ino, dtype, new_name, nlen, dbuf, &dlen);
    rc = stm_btree_insert(fs->tree, &new_dkey, dbuf, dlen, fs->gen);
    if (rc) return rc;

    /* Bump nlink + ctime (attr change). */
    in.si_nlink = cpu_to_le32(cur_nl + 1);
    uint64_t ts; uint32_t tns;
    stm_now(&ts, &tns);
    in.si_ctime_sec  = cpu_to_le64(ts);
    in.si_ctime_nsec = cpu_to_le32(tns);
    return write_inode(fs, target_ino, &in);
}

int stm_fs_unlink(struct stm_fs *fs, uint64_t parent_ino, const char *name)
{
    struct stm_key dkey;
    uint64_t child_ino;
    int rc;

    STM_FS_GUARD_WRITE(fs);

    rc = lookup_dirent(fs->tree, parent_ino, name, strlen(name),
                       &child_ino, &dkey);
    if (rc) return rc;

    /* Validate the inode BEFORE deleting the dirent. If we can't read
     * the inode we must bail out with the dirent still in place —
     * otherwise we'd orphan the inode and all its extents with no
     * path back. (Pre-fix behavior was: delete dirent first, read
     * inode second; any EIO in the read left the volume with a
     * permanent leak and the dirent gone.) */
    struct stm_inode in;
    rc = read_inode(fs, child_ino, &in);
    if (rc) return rc;

    /* Refuse to unlink a non-empty directory. Without this guard the
     * caller-visible behavior would be "dir removed successfully" but
     * the dir's children become permanently unreachable — every dirent
     * and inode under it stays live in the btree, and on encrypted
     * volumes their ciphertext stays allocated too. */
    uint32_t mode = le32_to_cpu(in.si_mode);
    if ((mode & STM_S_IFDIR) == STM_S_IFDIR) {
        int found = 0;
        struct stm_key lo = mk_key(child_ino, STM_KEY_DIRENT, 0);
        struct stm_key hi = mk_key(child_ino, STM_KEY_DATA, 0);
        /* scan returns 1 on "stop"; treat that as "found" signal, not
         * an error. A real error propagates as before. */
        int srv = stm_btree_scan(fs->tree, &lo, &hi, empty_check_cb, &found);
        if (srv < 0) return srv;
        if (found) return -ENOTEMPTY;

        /* Empty directory: tombstone the dirent in the parent (preserves
         * the probe chain for any collided names) and delete the inode
         * record. Skip the nlink dance below — directories don't
         * participate in hardlinking in this FS. */
        rc = tombstone_dirent(fs->tree, &dkey, fs->gen);
        if (rc) return rc;
        struct stm_key ik = mk_key(child_ino, STM_KEY_INODE, 0);
        return stm_btree_delete(fs->tree, &ik, fs->gen);
    }

    uint32_t nl = le32_to_cpu(in.si_nlink);
    if (nl > 0) nl--;
    in.si_nlink = cpu_to_le32(nl);

    /* If nlink will hit 0, pre-scan the data extents (collect keys +
     * records; do NOT free blocks yet). If the scan fails we bail
     * before touching the dirent. */
    struct unlink_ctx uc = { .fs = fs, .keys = NULL, .exts = NULL,
                             .count = 0, .cap = 0 };
    if (nl == 0) {
        struct stm_key lo = mk_key(child_ino, STM_KEY_DATA, 0);
        struct stm_key hi = mk_key(child_ino, STM_KEY_DATA, UINT64_MAX);
        rc = stm_btree_scan(fs->tree, &lo, &hi, collect_extent_cb, &uc);
        if (rc) { free(uc.keys); free(uc.exts); return rc; }
    }

    /* Mutations in this order:
     *   1. tombstone the dirent in parent
     *   2. delete every extent record (btree-level)
     *   3. delete the inode record
     *   4. finally, free extent blocks to the allocator (deferred)
     *
     * Freeing blocks is the ONLY thing that's unrecoverable if something
     * fails later: a PENDING block + an extent record still pointing at
     * it is a soon-to-be-silent-corruption pair. By doing all btree
     * deletes first, any failure leaves extent blocks live and the
     * state retriable. */
    rc = tombstone_dirent(fs->tree, &dkey, fs->gen);
    if (rc) { free(uc.keys); free(uc.exts); return rc; }

    if (nl == 0) {
        for (uint32_t i = 0; i < uc.count; i++) {
            rc = stm_btree_delete(fs->tree, &uc.keys[i], fs->gen);
            if (rc) { free(uc.keys); free(uc.exts); return rc; }
        }
        struct stm_key ik = mk_key(child_ino, STM_KEY_INODE, 0);
        rc = stm_btree_delete(fs->tree, &ik, fs->gen);
        if (rc) { free(uc.keys); free(uc.exts); return rc; }

        /* All btree deletes committed in-memory; now release the data
         * blocks. extent_free_blocks goes through the deferred list, so
         * a later OOM there is tolerable — the blocks stay live at the
         * allocator refcount and just leak until the next mount walk. */
        for (uint32_t i = 0; i < uc.count; i++)
            extent_free_blocks(fs, &uc.exts[i]);
        free(uc.keys); free(uc.exts);
        return 0;
    }
    free(uc.keys); free(uc.exts);
    return write_inode(fs, child_ino, &in);
}
