#include "fs_internal.h"

#include <time.h>

/* ── local aliases ──────────────────────────────────────────────────── */

#include "stratum/snapshot.h"

#define mk_key   stm_mk_key
#define fnv1a    stm_fnv1a

/* allocator reconstruction callbacks */
static int mark_block(uint64_t paddr, uint32_t csize, void *ctx)
{
    struct stm_alloc *a = ctx;
    uint32_t nblocks = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_mark(a, paddr / STM_BLOCK_SIZE, nblocks);
    return 0;
}

static int walk_snap_cb(const struct stm_key *key, const void *val,
                        uint32_t vlen, void *ctx)
{
    struct stm_fs *fs = ctx;
    struct stm_snapshot snap;
    (void)key;
    if (vlen < sizeof(snap)) return 0;
    memcpy(&snap, val, sizeof(snap));
    stm_btree_walk_from(fs->tree, snap.ssp_root, mark_block, fs->alloc);
    return 0;
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
 */
#define DIRENT_HDR 9

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

/* Look up a directory entry by name, handling hash collisions. */
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

        if (rc == -ENOENT) return -ENOENT;
        if (rc < 0) return rc;

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

/* Find a free dirent slot for a new name. */
static int find_dirent_slot(struct stm_btree *tree, uint64_t parent,
                            const char *name, size_t nlen,
                            struct stm_key *out_key)
{
    uint64_t h = fnv1a(name, nlen);
    int attempt;

    for (attempt = 0; attempt < 256; attempt++) {
        struct stm_key k = mk_key(parent, STM_KEY_DIRENT, h + (uint64_t)attempt);
        uint8_t vbuf[STM_NAME_MAX + 16];
        uint32_t vlen = sizeof(vbuf);
        int rc = stm_btree_lookup(tree, &k, vbuf, &vlen);

        if (rc == -ENOENT) { *out_key = k; return 0; }
        if (rc < 0) return rc;

        /* slot taken — same name? */
        if (vlen >= DIRENT_HDR) {
            uint32_t elen = vlen - DIRENT_HDR;
            if (elen == nlen && memcmp(vbuf + 9, name, nlen) == 0)
                return -EEXIST;
        }
    }
    return -ENOSPC;
}

static uint64_t alloc_ino(struct stm_fs *fs)
{
    return fs->next_ino++;
}

/* ── format ─────────────────────────────────────────────────────────── */

int stm_fs_create(const char *path, uint64_t size_bytes,
                  const char *passphrase)
{
    struct stm_block_dev dev;
    struct stm_btree *tree = NULL;
    struct stm_bptr null_root = stm_bptr_null();
    struct stm_superblock sb;
    struct stm_inode root_ino;
    struct stm_key k;
    uint64_t ts; uint32_t tns;
    int rc;

    rc = stm_file_backend_open(path, 1, size_bytes, &dev);
    if (rc) return rc;

    rc = stm_btree_open(&dev, null_root, 0, &tree);
    if (rc) goto fail_dev;

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
        if (rc) goto fail_tree;

        memcpy(sb.ss_enc_kdf_salt, salt, STM_CRYPTO_SALT_LEN);
        rc = stm_crypto_wrap_key(kek, dek, sb.ss_enc_wrapped_key,
                                 sb.ss_enc_nonce);
        if (rc) goto fail_tree;
        sb.ss_enc_algo = STM_ENC_XCHACHA;

        rc = stm_crypto_init(dek, &crypto);
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

    rc = stm_btree_flush(tree);
    if (rc) goto fail_tree;

    /* build superblock (sb was zeroed above, enc fields already set) */
    sb.ss_magic        = cpu_to_le64(STM_MAGIC);
    sb.ss_version      = cpu_to_le32(1);
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

    stm_block_write(&dev, STM_SB_OFFSET_A, &sb, sizeof(sb));
    stm_block_write(&dev, STM_SB_OFFSET_B, &sb, sizeof(sb));
    stm_block_sync(&dev);

    stm_btree_close(tree);
    stm_block_close(&dev);
    return 0;

fail_tree: stm_btree_close(tree);
fail_dev:  stm_block_close(&dev);
    return rc;
}

/* ── open / close / sync ────────────────────────────────────────────── */

int stm_fs_open(const char *path, const char *passphrase, struct stm_fs **out)
{
    struct stm_fs *fs = calloc(1, sizeof(*fs));
    struct stm_superblock sa, sb;
    struct stm_superblock *chosen;
    int rc;

    if (!fs) return -ENOMEM;

    rc = stm_file_backend_open(path, 0, 0, &fs->dev);
    if (rc) { free(fs); return rc; }

    stm_block_read(&fs->dev, STM_SB_OFFSET_A, &sa, sizeof(sa));
    stm_block_read(&fs->dev, STM_SB_OFFSET_B, &sb, sizeof(sb));

    {
        int a_ok = (le64_to_cpu(sa.ss_magic) == STM_MAGIC);
        int b_ok = (le64_to_cpu(sb.ss_magic) == STM_MAGIC);
        if (!a_ok && !b_ok) { stm_block_close(&fs->dev); free(fs); return -EINVAL; }

        if (a_ok && b_ok)
            chosen = (le64_to_cpu(sa.ss_gen) >= le64_to_cpu(sb.ss_gen))
                   ? (fs->sb_slot = 0, &sa) : (fs->sb_slot = 1, &sb);
        else
            chosen = a_ok ? (fs->sb_slot = 0, &sa) : (fs->sb_slot = 1, &sb);
    }

    fs->gen         = le64_to_cpu(chosen->ss_gen);
    fs->next_ino    = le64_to_cpu(chosen->ss_next_ino);
    fs->next_snap_id = le64_to_cpu(chosen->ss_next_snap_id);
    if (fs->next_snap_id == 0) fs->next_snap_id = 1;
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
        if (rc) { stm_block_close(&fs->dev); free(fs); return rc; }
        rc = stm_crypto_unwrap_key(kek, chosen->ss_enc_wrapped_key,
                                   chosen->ss_enc_nonce, fs->dek);
        if (rc) { stm_block_close(&fs->dev); free(fs); return rc; }
        fs->encrypted = 1;
#else
        stm_block_close(&fs->dev); free(fs); return -ENOTSUP;
#endif
    }

    /* open main tree */
    rc = stm_btree_open(&fs->dev, chosen->ss_root,
                        le16_to_cpu(chosen->ss_tree_height), &fs->tree);
    if (rc) { stm_block_close(&fs->dev); free(fs); return rc; }
    stm_btree_set_alloc(fs->tree, le64_to_cpu(chosen->ss_alloc_next));
    stm_fs_configure_tree(fs, fs->tree);

    /* open snapshot tree if it exists */
    if (!stm_bptr_is_null(&chosen->ss_snap_root)) {
        rc = stm_btree_open(&fs->dev, chosen->ss_snap_root,
                            le16_to_cpu(chosen->ss_snap_height), &fs->snap_tree);
        if (rc) { stm_btree_close(fs->tree); stm_block_close(&fs->dev); free(fs); return rc; }
        stm_btree_set_alloc(fs->snap_tree, le64_to_cpu(chosen->ss_alloc_next));
        stm_fs_configure_tree(fs, fs->snap_tree);
    }

    /* build allocator from tree walks */
    {
        uint64_t dev_bytes = 0;
        stm_block_size(&fs->dev, &dev_bytes);
        rc = stm_alloc_open(&fs->dev, dev_bytes / STM_BLOCK_SIZE, &fs->alloc);
        if (rc) { stm_btree_close(fs->snap_tree); stm_btree_close(fs->tree);
                   stm_block_close(&fs->dev); free(fs); return rc; }
        /* mark superblock blocks */
        stm_alloc_mark(fs->alloc, 0, 2);
        /* walk main tree */
        stm_btree_walk_from(fs->tree, stm_btree_root(fs->tree), mark_block, fs->alloc);
        /* walk snapshot tree */
        if (fs->snap_tree)
            stm_btree_walk_from(fs->snap_tree, stm_btree_root(fs->snap_tree),
                                mark_block, fs->alloc);
        /* walk each snapshot's saved tree */
        if (fs->snap_tree) {
            struct stm_key lo = stm_mk_key(0, STM_KEY_SNAP, 0);
            struct stm_key hi = stm_mk_key(UINT64_MAX, STM_KEY_SNAP, UINT64_MAX);
            stm_btree_scan(fs->snap_tree, &lo, &hi, walk_snap_cb, fs);
        }
        stm_alloc_commit(fs->alloc);
        stm_btree_set_allocator(fs->tree, fs->alloc);
        if (fs->snap_tree)
            stm_btree_set_allocator(fs->snap_tree, fs->alloc);
    }

    *out = fs;
    return 0;
}

int stm_fs_sync(struct stm_fs *fs)
{
    struct stm_superblock sb;
    uint64_t dev_sz = 0;
    int new_slot, rc;

    /* flush main tree */
    rc = stm_btree_flush(fs->tree);
    if (rc) return rc;

    /* flush snap tree, synchronize allocators */
    if (fs->snap_tree) {
        uint64_t a = stm_btree_next_alloc(fs->tree);
        uint64_t b = stm_btree_next_alloc(fs->snap_tree);
        if (b < a) stm_btree_set_alloc(fs->snap_tree, a);
        rc = stm_btree_flush(fs->snap_tree);
        if (rc) return rc;
        a = stm_btree_next_alloc(fs->snap_tree);
        if (stm_btree_next_alloc(fs->tree) < a)
            stm_btree_set_alloc(fs->tree, a);
    }

    stm_block_size(&fs->dev, &dev_sz);

    memset(&sb, 0, sizeof(sb));
    sb.ss_magic        = cpu_to_le64(STM_MAGIC);
    sb.ss_version      = cpu_to_le32(1);
    fs->gen++;
    sb.ss_gen          = cpu_to_le64(fs->gen);
    sb.ss_root         = stm_btree_root(fs->tree);
    sb.ss_snap_root    = fs->snap_tree
                       ? stm_btree_root(fs->snap_tree) : stm_bptr_null();
    sb.ss_space_root   = stm_bptr_null();
    sb.ss_tree_height  = cpu_to_le16(stm_btree_height(fs->tree));
    sb.ss_block_size   = cpu_to_le32(STM_BLOCK_SIZE);
    sb.ss_node_size    = cpu_to_le32(STM_NODE_SIZE);
    sb.ss_total_blocks = cpu_to_le64(dev_sz / STM_BLOCK_SIZE);
    sb.ss_free_blocks  = cpu_to_le64(0);
    sb.ss_next_ino     = cpu_to_le64(fs->next_ino);
    sb.ss_alloc_next   = cpu_to_le64(stm_btree_next_alloc(fs->tree));
    sb.ss_snap_height  = fs->snap_tree
                       ? cpu_to_le16(stm_btree_height(fs->snap_tree)) : cpu_to_le16(0);
    sb.ss_next_snap_id = cpu_to_le64(fs->next_snap_id);
    sb.ss_enc_algo     = fs->enc_algo;
    memcpy(sb.ss_enc_kdf_salt, fs->enc_kdf_salt, sizeof(sb.ss_enc_kdf_salt));
    memcpy(sb.ss_enc_wrapped_key, fs->enc_wrapped_key, sizeof(sb.ss_enc_wrapped_key));
    memcpy(sb.ss_enc_nonce, fs->enc_nonce, sizeof(sb.ss_enc_nonce));

    new_slot = 1 - fs->sb_slot;
    rc = stm_block_write(&fs->dev,
                         new_slot ? STM_SB_OFFSET_B : STM_SB_OFFSET_A,
                         &sb, sizeof(sb));
    if (rc) return rc;
    rc = stm_block_sync(&fs->dev);
    if (rc) return rc;
    fs->sb_slot = new_slot;
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
    return read_inode(fs, ino, out);
}

int stm_fs_lookup(struct stm_fs *fs, uint64_t parent_ino,
                  const char *name, uint64_t *out_ino)
{
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
    return create_entry(fs, parent_ino, name, STM_S_IFDIR | mode,
                        STM_DT_DIR, out_ino);
}

int stm_fs_create_file(struct stm_fs *fs, uint64_t parent_ino,
                       const char *name, uint32_t mode, uint64_t *out_ino)
{
    return create_entry(fs, parent_ino, name, STM_S_IFREG | mode,
                        STM_DT_REG, out_ino);
}

/* ── file I/O ───────────────────────────────────────────────────────── */

int stm_fs_write(struct stm_fs *fs, uint64_t ino, uint64_t offset,
                 const void *buf, uint32_t len)
{
    const uint8_t *src = buf;
    uint32_t remaining = len;
    uint64_t pos = offset;
    int rc;

    while (remaining > 0) {
        uint64_t chunk_off = pos & ~((uint64_t)(STM_DATA_CHUNK - 1));
        uint32_t inner     = (uint32_t)(pos - chunk_off);
        uint32_t towrite   = STM_DATA_CHUNK - inner;
        if (towrite > remaining) towrite = remaining;

        struct stm_key k = mk_key(ino, STM_KEY_DATA, chunk_off);
        uint8_t chunk[STM_DATA_CHUNK];

        if (inner != 0 || towrite != STM_DATA_CHUNK) {
            /* partial chunk: read-modify-write */
            uint32_t vlen = STM_DATA_CHUNK;
            rc = stm_btree_lookup(fs->tree, &k, chunk, &vlen);
            if (rc == -ENOENT) { memset(chunk, 0, STM_DATA_CHUNK); vlen = 0; }
            else if (rc < 0) return rc;
            /* extend with zeros if needed */
            if (vlen < inner + towrite) memset(chunk + vlen, 0, inner + towrite - vlen);
        }

        memcpy(chunk + inner, src, towrite);

        {
            uint32_t clen = inner + towrite;
            if (clen < STM_DATA_CHUNK) {
                /* store only what we need */
            }
            rc = stm_btree_insert(fs->tree, &k, chunk, clen, fs->gen);
            if (rc) return rc;
        }

        src       += towrite;
        pos       += towrite;
        remaining -= towrite;
    }

    /* update inode size */
    {
        struct stm_inode in;
        rc = read_inode(fs, ino, &in);
        if (rc) return rc;
        if (offset + len > le64_to_cpu(in.si_size)) {
            uint64_t ts; uint32_t tns;
            stm_now(&ts, &tns);
            in.si_size       = cpu_to_le64(offset + len);
            in.si_mtime_sec  = cpu_to_le64(ts);
            in.si_mtime_nsec = cpu_to_le32(tns);
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

    rc = read_inode(fs, ino, &in);
    if (rc) return rc;

    fsize = le64_to_cpu(in.si_size);
    if (offset >= fsize) { *out_read = 0; return 0; }
    if (offset + len > fsize) len = (uint32_t)(fsize - offset);

    pos = offset;
    remaining = len;

    while (remaining > 0) {
        uint64_t chunk_off = pos & ~((uint64_t)(STM_DATA_CHUNK - 1));
        uint32_t inner     = (uint32_t)(pos - chunk_off);
        uint32_t toread    = STM_DATA_CHUNK - inner;
        if (toread > remaining) toread = remaining;

        struct stm_key k = mk_key(ino, STM_KEY_DATA, chunk_off);
        uint8_t chunk[STM_DATA_CHUNK];
        uint32_t vlen = STM_DATA_CHUNK;

        rc = stm_btree_lookup(fs->tree, &k, chunk, &vlen);
        if (rc == -ENOENT) {
            memset(dst, 0, toread);  /* sparse: zeros */
        } else if (rc < 0) {
            return rc;
        } else {
            uint32_t avail = (vlen > inner) ? vlen - inner : 0;
            uint32_t copy  = (toread < avail) ? toread : avail;
            if (copy > 0) memcpy(dst, chunk + inner, copy);
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
    struct stm_key lo = mk_key(dir_ino, STM_KEY_DIRENT, 0);
    struct stm_key hi = mk_key(dir_ino, STM_KEY_DATA, 0);
    struct readdir_ctx rd = { .user_cb = cb, .user_ctx = ctx };
    return stm_btree_scan(fs->tree, &lo, &hi, readdir_scan_cb, &rd);
}

/* ── unlink ─────────────────────────────────────────────────────────── */

int stm_fs_unlink(struct stm_fs *fs, uint64_t parent_ino, const char *name)
{
    struct stm_key dkey;
    uint64_t child_ino;
    int rc;

    rc = lookup_dirent(fs->tree, parent_ino, name, strlen(name),
                       &child_ino, &dkey);
    if (rc) return rc;

    /* remove dirent */
    rc = stm_btree_delete(fs->tree, &dkey, fs->gen);
    if (rc) return rc;

    /* decrement nlink; if 0, remove inode (but not data — no GC yet) */
    {
        struct stm_inode in;
        rc = read_inode(fs, child_ino, &in);
        if (rc) return rc;
        uint32_t nl = le32_to_cpu(in.si_nlink);
        if (nl > 0) nl--;
        in.si_nlink = cpu_to_le32(nl);
        if (nl == 0) {
            struct stm_key ik = mk_key(child_ino, STM_KEY_INODE, 0);
            stm_btree_delete(fs->tree, &ik, fs->gen);
        } else {
            write_inode(fs, child_ino, &in);
        }
    }
    return 0;
}
