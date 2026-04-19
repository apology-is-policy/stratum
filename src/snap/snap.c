#include "stratum/snap.h"
#include "stratum/snapshot.h"
#include "fs/fs_internal.h"

#include <time.h>

#define mk_key   stm_mk_key
#define fnv1a    stm_fnv1a

/* Walk visitor that does nothing — used to dry-run a tree to verify every
 * node reads cleanly before we start mutating refcounts. */
static int noop_visit(uint64_t paddr, uint32_t csize, void *ctx)
{
    (void)paddr; (void)csize; (void)ctx;
    return 0;
}

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
    uint32_t clen = stm_extent_clen(&ext);
    uint32_t disk_len = crypto ? (clen + STM_CRYPTO_TAG_LEN) : clen;
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
    uint32_t clen = stm_extent_clen(&ext);
    uint32_t disk_len = crypto ? (clen + STM_CRYPTO_TAG_LEN) : clen;
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
    uint32_t clen = stm_extent_clen(&ext);
    uint32_t disk_len = crypto ? (clen + STM_CRYPTO_TAG_LEN) : clen;
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
    rc = stm_fs_configure_tree(fs, fs->snap_tree, STM_TREE_ID_SNAP);
    if (rc) {
        /* Without crypto wired up, the snap tree would write plaintext
         * on an encrypted volume — refuse cleanly instead. */
        stm_btree_close(fs->snap_tree);
        fs->snap_tree = NULL;
        return rc;
    }
    /* CRITICAL: wire the refcount allocator. Without this, the snap tree
     * falls through to bump allocation and writes its nodes on top of
     * blocks the main tree is using — corrupting the main tree the
     * moment the first snapshot is created on a volume that has prior
     * writes. (See test_snap_create_doesnt_corrupt_main_tree.) */
    if (fs->alloc) stm_btree_set_allocator(fs->snap_tree, fs->alloc);
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

/* R10-2 / R10-3 guards mirroring fs.c: snap ops mutate, refuse on wedged
 * or read-only fs. snap_list is read-only so it only checks wedged. */
#define STM_SNAP_GUARD_WRITE(fs) do { \
    if ((fs)->wedged) return -EIO; \
    if ((fs)->read_only) return -EROFS; \
} while (0)
#define STM_SNAP_GUARD_READ(fs) do { \
    if ((fs)->wedged) return -EIO; \
} while (0)

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

    STM_SNAP_GUARD_WRITE(fs);

    if (!name || !name[0]) return -EINVAL;
    nlen = strlen(name);
    if (nlen > STM_NAME_MAX) return -EINVAL;

    /* flush main tree so the root reflects current state */
    rc = stm_btree_flush(fs->tree, fs->gen);
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

    /* Dry-run the main-tree walk before we commit the snapshot.
     * If any node of the just-flushed main tree can't be read, we must
     * bail BEFORE inserting the descriptor — otherwise the snap_tree
     * would hold a descriptor pointing at a root whose subtree is
     * only partially ref-protected, and COW on any unwalked block
     * would silently free a block the descriptor still references. */
    {
        struct stm_bptr root = stm_btree_root(fs->tree);
        rc = stm_btree_walk_entries(fs->tree, root, noop_visit, NULL, NULL);
        if (rc) return rc;
    }

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

    /* Bump refcounts FIRST. If we inserted the descriptor first and
     * then an ENOMEM on name-index (or refcount walk) left us with a
     * persisted descriptor whose blocks were never ref-protected, the
     * next COW would silently reclaim them → next mount corruption.
     * With this ordering, a failure after the bump leaves only a
     * benign "orphan ref-count" (blocks stay live until next mount
     * rebuild); no descriptor references them yet, so no corruption. */
    if (fs->alloc) {
        rc = stm_btree_walk_entries(fs->tree, snap.ssp_root,
                                    ref_block_fs, ref_extent_entry, fs);
        if (rc) return rc;
    }

    {
        struct stm_key skey = mk_key(id, STM_KEY_SNAP, 0);
        rc = stm_btree_insert(fs->snap_tree, &skey, vbuf, vlen, fs->gen);
        if (rc) {
            /* Undo the refcount bumps so blocks don't stay live forever. */
            if (fs->alloc) {
                stm_btree_walk_entries(fs->tree, snap.ssp_root,
                                       free_block_fs, free_extent_entry, fs);
            }
            return rc;
        }
    }

    /* name-to-ID index */
    {
        le64 id_le = cpu_to_le64(id);
        memcpy(nbuf, &id_le, 8);
        memcpy(nbuf + 8, name, nlen);
        nblen = (uint32_t)(8 + nlen);
        rc = stm_btree_insert(fs->snap_tree, &nkey, nbuf, nblen, fs->gen);
        if (rc) {
            /* Undo both the descriptor insert and the refcount bumps.
             * The descriptor-delete itself can fail with another ENOMEM;
             * if it does we'd leave a nameless-but-valid snapshot — the
             * user can still roll back by id. That's worse than success
             * but not corruption: the descriptor's blocks ARE protected
             * by the earlier ref walk. */
            struct stm_key skey = mk_key(id, STM_KEY_SNAP, 0);
            (void)stm_btree_delete(fs->snap_tree, &skey, fs->gen);
            if (fs->alloc) {
                stm_btree_walk_entries(fs->tree, snap.ssp_root,
                                       free_block_fs, free_extent_entry, fs);
            }
            return rc;
        }
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

    STM_SNAP_GUARD_READ(fs);
    if (!fs->snap_tree) return 0;

    lo = mk_key(0, STM_KEY_SNAP, 0);
    hi = mk_key(UINT64_MAX, STM_KEY_SNAP, UINT64_MAX);
    sl.user_cb  = cb;
    sl.user_ctx = ctx;
    return stm_btree_scan(fs->snap_tree, &lo, &hi, snap_scan_cb, &sl);
}

/* For each SNAP descriptor in the snap tree, walk its saved root and
 * mark every reachable block. Parallel to walk_snap_cb in fs.c, but
 * uses the snap-side mark callbacks for log labeling consistency. */
static int mark_saved_snap_cb(const struct stm_key *key, const void *val,
                              uint32_t vlen, void *ctx)
{
    struct stm_fs *fs = ctx;
    struct stm_snapshot snap;
    int rc;
    (void)key;
    if (vlen < sizeof(snap)) return 0;
    memcpy(&snap, val, sizeof(snap));
    /* Walk this snapshot's tree under the main tree's config (same volume,
     * same crypto). Propagate the walk return — otherwise a corrupt node
     * in a specific snapshot's saved tree silently leaves its exclusive
     * blocks unmarked, so the next write after rollback reallocates them. */
    rc = stm_btree_walk_entries(fs->tree, snap.ssp_root,
                                mark_block_snap, mark_extent_snap, fs);
    return rc;
}

/* ── rollback ───────────────────────────────────────────────────────── */

int stm_snap_rollback(struct stm_fs *fs, uint64_t snap_id)
{
    struct stm_key skey = mk_key(snap_id, STM_KEY_SNAP, 0);
    uint8_t vbuf[sizeof(struct stm_snapshot) + 1 + STM_NAME_MAX];
    uint32_t vlen = sizeof(vbuf);
    struct stm_snapshot snap;
    int rc;

    STM_SNAP_GUARD_WRITE(fs);
    if (!fs->snap_tree) return -ENOENT;

    rc = stm_btree_lookup(fs->snap_tree, &skey, vbuf, &vlen);
    if (rc) return rc;
    if (vlen < sizeof(snap)) return -EINVAL;
    memcpy(&snap, vbuf, sizeof(snap));

    /* Save the CURRENT tree's root bptr + height before closing, so that
     * any failure in the open-and-configure sequence below can reopen
     * the original tree and leave fs->tree pointing at a usable struct.
     * Without this, the server would be left with fs->tree == NULL and
     * every subsequent op would SEGV. */
    struct stm_bptr orig_root    = stm_btree_root(fs->tree);
    uint16_t        orig_height  = stm_btree_height(fs->tree);

    /* close current main tree, open from snapshot root */
    stm_btree_close(fs->tree);
    fs->tree = NULL;

    rc = stm_btree_open(&fs->dev, snap.ssp_root,
                        le16_to_cpu(snap.ssp_tree_height), &fs->tree);
    if (rc) goto reopen_original;

    stm_btree_set_alloc(fs->tree,
        fs->snap_tree ? stm_btree_next_alloc(fs->snap_tree)
                      : stm_btree_next_alloc(fs->tree));
    rc = stm_fs_configure_tree(fs, fs->tree, STM_TREE_ID_MAIN);
    if (rc) {
        stm_btree_close(fs->tree);
        fs->tree = NULL;
        goto reopen_original;
    }
    goto after_reopen;

reopen_original:
    {
        /* Put fs->tree back where it was. If this fails too the fs is
         * genuinely wedged; mark it so public APIs refuse further
         * mutations instead of dereferencing NULL. */
        int rc2 = stm_btree_open(&fs->dev, orig_root, orig_height, &fs->tree);
        if (rc2 == 0) {
            /* R9-2: propagate configure_tree failure. If crypto_init
             * fails (OOM on encrypted volumes), leaving fs->tree with
             * NULL crypto context would make subsequent writes emit
             * PLAINTEXT to disk on what the user considers an encrypted
             * volume. Close the tree and fail hard; fs->wedged = 1
             * ensures no future op touches the invalid state. */
            int rc3 = stm_fs_configure_tree(fs, fs->tree, STM_TREE_ID_MAIN);
            if (rc3) {
                stm_btree_close(fs->tree);
                fs->tree = NULL;
                fs->wedged = 1;  /* R10-2 */
                if (!rc) rc = rc3;
            } else if (fs->alloc) {
                stm_btree_set_allocator(fs->tree, fs->alloc);
            }
        } else {
            fs->wedged = 1;  /* R10-2: fs->tree stays NULL */
            if (!rc) rc = rc2;
        }
        return rc;
    }
after_reopen:

    /* The freshly-reopened fs->tree was calloc'd, so its alloc pointer
     * is NULL. Connect it to the CURRENT allocator (A_old) up front —
     * if the allocator rebuild below fails, the restored state must
     * leave fs->tree->alloc pointing at a valid allocator, not NULL.
     * Without this, rollback_restore would leave tree->alloc as NULL,
     * and the next write through fs->tree would fall into the bump-
     * allocator branch and silently trample live blocks. */
    if (fs->alloc) stm_btree_set_allocator(fs->tree, fs->alloc);

    /* Rebuild allocator for the restored tree — old refcounts are stale.
     * Without this, the allocator thinks pre-rollback blocks are in use
     * and the restored tree's blocks are free → double allocation.
     *
     * Careful: fs->tree->alloc and fs->snap_tree->alloc both point at
     * the *current* allocator (A_old). If we free A_old first and an
     * intermediate step then fails, those tree pointers dangle — any
     * subsequent write (e.g. another snap op on the same session) is
     * a use-after-free. Build the new allocator FIRST, then atomically
     * swap, then free the old one. */
    if (fs->alloc) {
        struct stm_alloc *old_alloc = fs->alloc;
        struct stm_alloc *new_alloc = NULL;
        uint64_t dev_bytes = 0;
        stm_block_size(&fs->dev, &dev_bytes);
        rc = stm_alloc_open(&fs->dev, dev_bytes / STM_BLOCK_SIZE, &new_alloc);
        if (rc) goto rollback_alloc_open_fail;

        /* Mark superblocks + walk trees against the new allocator.
         * Temporarily point fs->alloc at the new one so the walk
         * callbacks (mark_block_snap / mark_extent_snap) target it.
         * On failure, restore the old allocator binding and free the
         * half-built new one — trees stay connected to the still-valid
         * old allocator. */
        fs->alloc = new_alloc;
        stm_alloc_mark(new_alloc, 0, 2);
        rc = stm_btree_walk_entries(fs->tree, stm_btree_root(fs->tree),
                                    mark_block_snap, mark_extent_snap, fs);
        if (rc) goto rollback_restore;
        if (fs->snap_tree) {
            rc = stm_btree_walk_entries(fs->snap_tree,
                                        stm_btree_root(fs->snap_tree),
                                        mark_block_snap, mark_extent_snap, fs);
            if (rc) goto rollback_restore;
            struct stm_key lo = mk_key(0, STM_KEY_SNAP, 0);
            struct stm_key hi = mk_key(UINT64_MAX, STM_KEY_SNAP, UINT64_MAX);
            rc = stm_btree_scan(fs->snap_tree, &lo, &hi, mark_saved_snap_cb, fs);
            if (rc) goto rollback_restore;
        }
        stm_alloc_commit(new_alloc);

        /* R9-1 / R10-1: rollback-bump — advance fs->gen so post-rollback
         * writes use a distinct write_gen from any pre-rollback in-session
         * orphan ciphertexts (those paddrs are marked FREE in new_alloc),
         * then persist a disk ss_gen bump to preserve R8-1's invariant
         * (disk ss_gen > fs->gen).
         *
         * CRITICAL: this MUST happen BEFORE the allocator swap and before
         * old_alloc is freed. If the disk bump write fails, we want to
         * abort the whole rollback cleanly — restore fs->alloc to
         * old_alloc, close new_alloc, and reopen the original tree. The
         * old allocator still holds live refcounts for the pre-rollback
         * paddrs so no nonce collision is possible on subsequent writes.
         *
         * If the bump were after the swap (R9-1 pre-R10-1 ordering),
         * old_alloc would already be destroyed and the trees bound to
         * new_alloc, with no way to revert — a bump failure would leave
         * the fs in exactly the state that causes nonce collision. */
        if (fs->encrypted) {
            fs->gen += 1;
            rc = stm_fs_gen_bump_disk(fs);
            if (rc) {
                fs->gen -= 1;
                goto rollback_restore;
            }
        }

        /* Commit the swap: point both trees at the new allocator, then
         * free the old one. After this point no dangling pointers. */
        stm_btree_set_allocator(fs->tree, new_alloc);
        if (fs->snap_tree)
            stm_btree_set_allocator(fs->snap_tree, new_alloc);
        stm_alloc_close(old_alloc);
        return 0;

    rollback_restore:
        fs->alloc = old_alloc;                   /* trees still connected here */
        stm_alloc_close(new_alloc);
        /* fall through to tree restore */

    rollback_alloc_open_fail:
        /* R9-3: fs->tree currently points at the rolled-back snapshot
         * tree (opened at the top of this function). Caller was told
         * rollback failed; they must see the pre-rollback tree. Close
         * the snap tree and reopen from orig_root — matching the
         * reopen_original path's semantics. */
        stm_btree_close(fs->tree);
        fs->tree = NULL;
        {
            int rc2 = stm_btree_open(&fs->dev, orig_root, orig_height, &fs->tree);
            if (rc2 == 0) {
                int rc3 = stm_fs_configure_tree(fs, fs->tree, STM_TREE_ID_MAIN);
                if (rc3) {
                    stm_btree_close(fs->tree);
                    fs->tree = NULL;
                    fs->wedged = 1;  /* R10-2 */
                    if (!rc) rc = rc3;
                } else if (fs->alloc) {
                    stm_btree_set_allocator(fs->tree, fs->alloc);
                }
            } else {
                fs->wedged = 1;  /* R10-2: fs->tree stays NULL */
                if (!rc) rc = rc2;
            }
        }
        return rc;
    }

    return 0;
}

/* ── delete ─────────────────────────────────────────────────────────── */

int stm_snap_delete(struct stm_fs *fs, uint64_t snap_id)
{
    struct stm_key skey = mk_key(snap_id, STM_KEY_SNAP, 0);
    uint8_t vbuf[sizeof(struct stm_snapshot) + 1 + STM_NAME_MAX];
    uint32_t vlen = sizeof(vbuf);
    struct stm_snapshot snap;
    int rc;

    STM_SNAP_GUARD_WRITE(fs);
    if (!fs->snap_tree) return -ENOENT;

    rc = stm_btree_lookup(fs->snap_tree, &skey, vbuf, &vlen);
    if (rc) return rc;
    if (vlen < sizeof(snap)) return -EINVAL;
    memcpy(&snap, vbuf, sizeof(snap));

    /* Dry-run the saved tree to prove every node is readable before
     * we start mutating anything. */
    if (fs->alloc) {
        rc = stm_btree_walk_entries(fs->tree, snap.ssp_root,
                                    noop_visit, NULL, NULL);
        if (rc) return rc;
    }

    /* Remove descriptor + name index BEFORE the refcount walk.
     * Rationale: if either delete fails (typically -ENOMEM from the
     * msg-buffer growing), the saved tree is still fully referenced —
     * every block retains its refcount, and the descriptor is still
     * consulted on next mount. We can safely retry the whole operation.
     *
     * If instead we decremented refcounts first and then hit an OOM
     * on the descriptor-delete, we'd be stuck with a still-present
     * descriptor whose subtree has decremented refcounts — next sync
     * could commit that to disk and the next write could reallocate
     * blocks the descriptor still claims. */
    rc = stm_btree_delete(fs->snap_tree, &skey, fs->gen);
    if (rc) return rc;

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
                rc = stm_btree_delete(fs->snap_tree, &nk, fs->gen);
                if (rc) return rc;
                break;
            }
        }
    }

    /* Decrement refcounts. Dry-run above proved all nodes read OK;
     * the callback only decrements, so it cannot fail. Even in the
     * unlikely event of a later failure, the descriptor is already
     * gone — the next mount rebuild sees the now-smaller tree and
     * correctly assigns refcounts to the surviving blocks. */
    if (fs->alloc) {
        rc = stm_btree_walk_entries(fs->tree, snap.ssp_root,
                                    free_block_fs, free_extent_entry, fs);
        if (rc) return rc;
    }
    return 0;
}
