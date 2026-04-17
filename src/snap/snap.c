#include "stratum/snap.h"
#include "stratum/snapshot.h"
#include "fs/fs_internal.h"

#include <time.h>

#define mk_key   stm_mk_key
#define fnv1a    stm_fnv1a

/* allocator mark callbacks (for rollback rebuild) */
static int mark_block_snap(uint64_t paddr, uint32_t csize, void *ctx)
{
    struct stm_fs *fs = ctx;
    uint32_t nb = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_mark(fs->alloc, paddr / STM_BLOCK_SIZE, nb);
    return 0;
}

static int mark_extent_snap(const struct stm_key *key, const void *val,
                            uint32_t vlen, void *ctx)
{
    struct stm_fs *fs = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (kc.type != STM_KEY_DATA || vlen != sizeof(struct stm_extent))
        return 0;
    struct stm_extent ext;
    memcpy(&ext, val, sizeof(ext));
    struct stm_crypto *crypto = stm_btree_get_crypto(fs->tree);
    uint32_t dlen = le32_to_cpu(ext.se_dlen);
    uint32_t disk_len = crypto ? (dlen + STM_CRYPTO_TAG_LEN) : dlen;
    uint32_t nb = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_mark(fs->alloc, le64_to_cpu(ext.se_paddr) / STM_BLOCK_SIZE, nb);
    return 0;
}

/* allocator callbacks for snapshot refcount management */
static int ref_block_fs(uint64_t paddr, uint32_t csize, void *ctx)
{
    struct stm_fs *fs = ctx;
    uint32_t nb = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_ref(fs->alloc, paddr / STM_BLOCK_SIZE, nb);
    return 0;
}

static int ref_extent_entry(const struct stm_key *key, const void *val,
                            uint32_t vlen, void *ctx)
{
    struct stm_fs *fs = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (kc.type != STM_KEY_DATA || vlen != sizeof(struct stm_extent))
        return 0;
    struct stm_extent ext;
    memcpy(&ext, val, sizeof(ext));
    struct stm_crypto *crypto = stm_btree_get_crypto(fs->tree);
    uint32_t dlen = le32_to_cpu(ext.se_dlen);
    uint32_t disk_len = crypto ? (dlen + STM_CRYPTO_TAG_LEN) : dlen;
    uint32_t nb = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_ref(fs->alloc, le64_to_cpu(ext.se_paddr) / STM_BLOCK_SIZE, nb);
    return 0;
}

static int free_block_fs(uint64_t paddr, uint32_t csize, void *ctx)
{
    struct stm_fs *fs = ctx;
    uint32_t nb = (csize + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_free(fs->alloc, paddr / STM_BLOCK_SIZE, nb);
    return 0;
}

static int free_extent_entry(const struct stm_key *key, const void *val,
                             uint32_t vlen, void *ctx)
{
    struct stm_fs *fs = ctx;
    struct stm_key_cpu kc = stm_key_to_cpu(key);
    if (kc.type != STM_KEY_DATA || vlen != sizeof(struct stm_extent))
        return 0;
    struct stm_extent ext;
    memcpy(&ext, val, sizeof(ext));
    struct stm_crypto *crypto = stm_btree_get_crypto(fs->tree);
    uint32_t dlen = le32_to_cpu(ext.se_dlen);
    uint32_t disk_len = crypto ? (dlen + STM_CRYPTO_TAG_LEN) : dlen;
    uint32_t nb = (disk_len + STM_BLOCK_SIZE - 1) / STM_BLOCK_SIZE;
    stm_alloc_free(fs->alloc, le64_to_cpu(ext.se_paddr) / STM_BLOCK_SIZE, nb);
    return 0;
}

/*
 * Snapshot values in the snap tree:
 *   Key (id, STM_KEY_SNAP, 0):
 *     [struct stm_snapshot][uint8_t name_len][name bytes]
 *
 *   Key (fnv1a(name)+attempt, STM_KEY_SNAP_NAME, 0):
 *     [le64 snap_id][name bytes]
 */

/* ── helpers ────────────────────────────────────────────────────────── */

static int ensure_snap_tree(struct stm_fs *fs)
{
    int rc;
    if (fs->snap_tree) return 0;
    rc = stm_btree_open(&fs->dev, stm_bptr_null(), 0, &fs->snap_tree);
    if (rc) return rc;
    stm_btree_set_alloc(fs->snap_tree, stm_btree_next_alloc(fs->tree));
    stm_fs_configure_tree(fs, fs->snap_tree);
    return 0;
}

static int lookup_snap_name(struct stm_btree *tree,
                            const char *name, size_t nlen,
                            uint64_t *out_id)
{
    uint64_t h = fnv1a(name, nlen);
    int attempt;

    for (attempt = 0; attempt < 256; attempt++) {
        struct stm_key k = mk_key(h + (uint64_t)attempt, STM_KEY_SNAP_NAME, 0);
        uint8_t vbuf[STM_NAME_MAX + 16];
        uint32_t vlen = sizeof(vbuf);
        int rc = stm_btree_lookup(tree, &k, vbuf, &vlen);
        if (rc == -ENOENT) return -ENOENT;
        if (rc < 0) return rc;
        if (vlen >= 8) {
            uint32_t elen = vlen - 8;
            if (elen == nlen && memcmp(vbuf + 8, name, nlen) == 0) {
                le64 id_le;
                memcpy(&id_le, vbuf, 8);
                *out_id = le64_to_cpu(id_le);
                return 0;
            }
        }
    }
    return -ENOENT;
}

static int find_snap_name_slot(struct stm_btree *tree,
                               const char *name, size_t nlen,
                               struct stm_key *out_key)
{
    uint64_t h = fnv1a(name, nlen);
    int attempt;

    for (attempt = 0; attempt < 256; attempt++) {
        struct stm_key k = mk_key(h + (uint64_t)attempt, STM_KEY_SNAP_NAME, 0);
        uint8_t vbuf[STM_NAME_MAX + 16];
        uint32_t vlen = sizeof(vbuf);
        int rc = stm_btree_lookup(tree, &k, vbuf, &vlen);
        if (rc == -ENOENT) { *out_key = k; return 0; }
        if (rc < 0) return rc;
        if (vlen >= 8) {
            uint32_t elen = vlen - 8;
            if (elen == nlen && memcmp(vbuf + 8, name, nlen) == 0)
                return -EEXIST;
        }
    }
    return -ENOSPC;
}

/* ── create ─────────────────────────────────────────────────────────── */

int stm_snap_create(struct stm_fs *fs, const char *name, uint64_t *out_id)
{
    size_t nlen;
    struct stm_key nkey;
    struct stm_snapshot snap;
    uint64_t id;
    uint8_t vbuf[sizeof(struct stm_snapshot) + 1 + STM_NAME_MAX];
    uint32_t vlen;
    uint8_t nbuf[8 + STM_NAME_MAX];
    uint32_t nblen;
    int rc;

    if (!name || !name[0]) return -EINVAL;
    nlen = strlen(name);
    if (nlen > STM_NAME_MAX) return -EINVAL;

    /* flush main tree so the root reflects current state */
    rc = stm_btree_flush(fs->tree);
    if (rc) return rc;

    rc = ensure_snap_tree(fs);
    if (rc) return rc;

    /* check name collision */
    {
        uint64_t dummy;
        rc = lookup_snap_name(fs->snap_tree, name, nlen, &dummy);
        if (rc == 0) return -EEXIST;
        if (rc != -ENOENT) return rc;
    }

    rc = find_snap_name_slot(fs->snap_tree, name, nlen, &nkey);
    if (rc) return rc;

    id = fs->next_snap_id++;

    /* build snapshot descriptor */
    memset(&snap, 0, sizeof(snap));
    snap.ssp_id          = cpu_to_le64(id);
    snap.ssp_gen         = cpu_to_le64(fs->gen);
    snap.ssp_root        = stm_btree_root(fs->tree);
    snap.ssp_refcount    = cpu_to_le32(1);
    snap.ssp_tree_height = cpu_to_le16(stm_btree_height(fs->tree));

    /* value = [snapshot][name_len][name] */
    memcpy(vbuf, &snap, sizeof(snap));
    vbuf[sizeof(snap)] = (uint8_t)nlen;
    memcpy(vbuf + sizeof(snap) + 1, name, nlen);
    vlen = (uint32_t)(sizeof(snap) + 1 + nlen);

    {
        struct stm_key skey = mk_key(id, STM_KEY_SNAP, 0);
        rc = stm_btree_insert(fs->snap_tree, &skey, vbuf, vlen, fs->gen);
        if (rc) return rc;
    }

    /* name-to-ID index */
    {
        le64 id_le = cpu_to_le64(id);
        memcpy(nbuf, &id_le, 8);
        memcpy(nbuf + 8, name, nlen);
        nblen = (uint32_t)(8 + nlen);
        rc = stm_btree_insert(fs->snap_tree, &nkey, nbuf, nblen, fs->gen);
        if (rc) return rc;
    }

    /* increment refcounts on all blocks in the snapshotted tree,
     * so COW doesn't reclaim shared blocks */
    if (fs->alloc) {
        stm_btree_walk_entries(fs->tree, snap.ssp_root,
                               ref_block_fs, ref_extent_entry, fs);
    }

    if (out_id) *out_id = id;
    return 0;
}

/* ── list ───────────────────────────────────────────────────────────── */

struct snap_list_ctx {
    int (*user_cb)(uint64_t snap_id, const char *name,
                   uint64_t gen, void *ctx);
    void *user_ctx;
};

static int snap_scan_cb(const struct stm_key *key, const void *val,
                        uint32_t vlen, void *ctx)
{
    struct snap_list_ctx *sl = ctx;
    const uint8_t *p = val;
    struct stm_snapshot snap;
    uint8_t name_len;
    char namebuf[STM_NAME_MAX + 1];

    (void)key;
    if (vlen < sizeof(snap) + 1) return 0;

    memcpy(&snap, p, sizeof(snap));
    name_len = p[sizeof(snap)];
    if (name_len > STM_NAME_MAX) name_len = STM_NAME_MAX;
    if (sizeof(snap) + 1 + name_len > vlen) return 0;
    memcpy(namebuf, p + sizeof(snap) + 1, name_len);
    namebuf[name_len] = '\0';

    return sl->user_cb(le64_to_cpu(snap.ssp_id), namebuf,
                       le64_to_cpu(snap.ssp_gen), sl->user_ctx);
}

int stm_snap_list(struct stm_fs *fs,
                  int (*cb)(uint64_t snap_id, const char *name,
                            uint64_t gen, void *ctx),
                  void *ctx)
{
    struct stm_key lo, hi;
    struct snap_list_ctx sl;

    if (!fs->snap_tree) return 0;

    lo = mk_key(0, STM_KEY_SNAP, 0);
    hi = mk_key(UINT64_MAX, STM_KEY_SNAP, UINT64_MAX);
    sl.user_cb  = cb;
    sl.user_ctx = ctx;
    return stm_btree_scan(fs->snap_tree, &lo, &hi, snap_scan_cb, &sl);
}

/* ── rollback ───────────────────────────────────────────────────────── */

int stm_snap_rollback(struct stm_fs *fs, uint64_t snap_id)
{
    struct stm_key skey = mk_key(snap_id, STM_KEY_SNAP, 0);
    uint8_t vbuf[sizeof(struct stm_snapshot) + 1 + STM_NAME_MAX];
    uint32_t vlen = sizeof(vbuf);
    struct stm_snapshot snap;
    int rc;

    if (!fs->snap_tree) return -ENOENT;

    rc = stm_btree_lookup(fs->snap_tree, &skey, vbuf, &vlen);
    if (rc) return rc;
    if (vlen < sizeof(snap)) return -EINVAL;
    memcpy(&snap, vbuf, sizeof(snap));

    /* close current main tree, open from snapshot root */
    stm_btree_close(fs->tree);
    fs->tree = NULL;

    rc = stm_btree_open(&fs->dev, snap.ssp_root,
                        le16_to_cpu(snap.ssp_tree_height), &fs->tree);
    if (rc) return rc;

    stm_btree_set_alloc(fs->tree,
        fs->snap_tree ? stm_btree_next_alloc(fs->snap_tree)
                      : stm_btree_next_alloc(fs->tree));
    stm_fs_configure_tree(fs, fs->tree);

    /* Rebuild allocator for the restored tree — old refcounts are stale.
     * Without this, the allocator thinks pre-rollback blocks are in use
     * and the restored tree's blocks are free → double allocation. */
    if (fs->alloc) {
        uint64_t dev_bytes = 0;
        stm_alloc_close(fs->alloc);
        fs->alloc = NULL;
        stm_block_size(&fs->dev, &dev_bytes);
        rc = stm_alloc_open(&fs->dev, dev_bytes / STM_BLOCK_SIZE, &fs->alloc);
        if (rc) return rc;
        stm_alloc_mark(fs->alloc, 0, 2); /* superblocks */
        stm_btree_walk_entries(fs->tree, stm_btree_root(fs->tree),
                               mark_block_snap, mark_extent_snap, fs);
        if (fs->snap_tree) {
            stm_btree_walk_entries(fs->snap_tree, stm_btree_root(fs->snap_tree),
                                   mark_block_snap, mark_extent_snap, fs);
        }
        stm_alloc_commit(fs->alloc);
        stm_btree_set_allocator(fs->tree, fs->alloc);
        if (fs->snap_tree)
            stm_btree_set_allocator(fs->snap_tree, fs->alloc);
    }

    return 0;
}

/* ── delete (stub) ──────────────────────────────────────────────────── */

int stm_snap_delete(struct stm_fs *fs, uint64_t snap_id)
{
    struct stm_key skey = mk_key(snap_id, STM_KEY_SNAP, 0);
    uint8_t vbuf[sizeof(struct stm_snapshot) + 1 + STM_NAME_MAX];
    uint32_t vlen = sizeof(vbuf);
    struct stm_snapshot snap;
    int rc;

    if (!fs->snap_tree) return -ENOENT;

    rc = stm_btree_lookup(fs->snap_tree, &skey, vbuf, &vlen);
    if (rc) return rc;
    if (vlen < sizeof(snap)) return -EINVAL;
    memcpy(&snap, vbuf, sizeof(snap));

    /* decrement refcounts on all blocks in the snapshot's tree */
    if (fs->alloc) {
        stm_btree_walk_entries(fs->tree, snap.ssp_root,
                               free_block_fs, free_extent_entry, fs);
    }

    /* remove snapshot descriptor and name index */
    stm_btree_delete(fs->snap_tree, &skey, fs->gen);

    /* remove name index entry — extract name from value */
    if (vlen > sizeof(snap) + 1) {
        uint8_t name_len = vbuf[sizeof(snap)];
        const char *name = (const char *)vbuf + sizeof(snap) + 1;
        uint64_t h = fnv1a(name, name_len);
        int attempt;
        for (attempt = 0; attempt < 256; attempt++) {
            struct stm_key nk = mk_key(h + (uint64_t)attempt, STM_KEY_SNAP_NAME, 0);
            uint8_t nb[STM_NAME_MAX + 16];
            uint32_t nl = sizeof(nb);
            rc = stm_btree_lookup(fs->snap_tree, &nk, nb, &nl);
            if (rc) break;
            if (nl >= 8 && nl - 8 == name_len &&
                memcmp(nb + 8, name, name_len) == 0) {
                stm_btree_delete(fs->snap_tree, &nk, fs->gen);
                break;
            }
        }
    }

    return 0;
}
