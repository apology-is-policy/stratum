/* SPDX-License-Identifier: ISC */
/*
 * Four-phase commit (Phase 3 chunk 6).
 *
 *   see include/stratum/sync.h for the surface + phase diagram.
 *   see v2/specs/sync.tla          for the formal spec.
 *
 * What this module does:
 *   - owns uberblock ring rotation (label + slot selection per commit).
 *   - calls stm_alloc_commit during Reserve+Flush to persist the
 *     data-area tree, then reads back the tree root paddr.
 *   - builds the new uberblock, writes it to the next ring slot with
 *     an fsync barrier (DoFinal — the commit point per sync.tla).
 *   - advances current_gen on success (DoPublish).
 *
 * Mount logic:
 *   - stm_sb_mount_scan picks the highest-valid-gen uberblock.
 *   - MountGenBump: current_gen = authoritative_gen + 1 (strictly
 *     greater than any durable gen; preserves nonce uniqueness).
 *   - If the authoritative uberblock has a valid ub_alloc_root, the
 *     allocator-tree is loaded from that paddr via
 *     stm_alloc_load_tree_at. This is the ub_alloc_root → durable
 *     handoff from chunk 5d's user_data slot.
 *
 * Ring rotation (MVP):
 *   label = gen % STM_LABELS_PER_DEVICE   (0..3)
 *   slot  = gen % STM_UB_SLOTS_PER_LABEL  (0..62)
 * Consecutive commits land on different labels. After
 * 4 × 63 = 252 commits the (label, slot) pair wraps, but by then the
 * history is dense and mount-time selection always picks the newest.
 */

#include <stratum/sync.h>
#include <stratum/alloc.h>
#include <stratum/block.h>
#include <stratum/crypto.h>
#include <stratum/hash.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct stm_sync {
    pthread_mutex_t lock;

    stm_bdev  *bdev;        /* borrowed */
    stm_alloc *alloc;       /* borrowed — not owned */

    uint64_t   pool_uuid[2];
    uint64_t   device_uuid[2];

    /* Commit state. */
    uint64_t   current_gen;         /* last-committed gen; next commit is +1.
                                     * 0 before any commit lands.          */
    uint64_t   mount_max_durable;   /* maximum gen observed at mount time  */

    /* Most recent uberblock location (valid once current_gen > 0). */
    uint32_t   live_label_idx;
    uint32_t   live_slot_idx;

    /* Allocator-tree root paddr recorded in the last committed
     * uberblock. 0 if no commits yet. */
    uint64_t   alloc_root_paddr;

    /* P4-1: Merkle state.
     *
     *   merkle_salt      — 32-byte per-pool random value set at
     *                      sync_create (first commit) and persisted
     *                      in ub_merkle_root_salt. Stable for the
     *                      pool's lifetime. Mixes into every
     *                      ub_merkle_root computation.
     *   alloc_root_csum  — BLAKE3 self-csum of the live allocator-
     *                      tree root node, mirrored from
     *                      ub_alloc_root.bp_csum.
     *   merkle_root      — most recently computed pool Merkle root
     *                      (mirror of ub_merkle_root).
     */
    uint8_t    merkle_salt[32];
    uint8_t    alloc_root_csum[32];
    uint8_t    merkle_root[32];

    /* P4-3a: per-pool metadata-encryption key.
     *
     * Generated at sync_create from the OS CSPRNG (libsodium). Stored
     * raw in ub_key_schema[0..32] for the MVP — no PQ-hybrid wrap
     * yet; that's P4-4's job. When P4-3b lands, this key encrypts
     * every metadata node (btnode) at write time and decrypts them
     * at read time via an AEAD wrapper around the btree_store
     * serialize / deserialize path.
     *
     * Format note (to revisit in P4-4): the first 32 bytes of
     * ub_key_schema currently hold a plaintext raw key. ub_key_schema
     * is 512 bytes total, so there is room for a proper header
     * (magic + version + wrap metadata + wrapped payload) once the
     * key hierarchy + key agent land. The P4-3a layout is
     * "raw[0..32]" with the rest zero-filled; future readers detecting
     * all-zero after offset 32 can infer raw-MVP format. */
    uint8_t    metadata_key[32];
};

/* ========================================================================= */
/* Merkle root construction (P4-1).                                           */
/* ========================================================================= */

/* Compute pool_merkle_root = BLAKE3-256(
 *     main_root_csum || alloc_root_csum || snap_root_csum ||
 *     cas_root_csum || salt
 * ). Unpopulated tree roots contribute 32 zero bytes.
 *
 * Phase 3 has only the allocator tree; the other three are zero.
 * The field placement mirrors ARCH §7.11.3's formula, so when we
 * wire main/snap/cas in Phase 5/6 the math doesn't change.
 *
 * R8-P1-1: returns STM_ENOMEM on BLAKE3 context allocation failure
 * so callers can refuse the commit/mount rather than silently write
 * (and recompute-match) an all-zero root — which would be a narrow
 * but real Merkle-bypass window under persistent OOM. */
static stm_status compute_merkle_root(const uint8_t main_csum[32],
                                        const uint8_t alloc_csum[32],
                                        const uint8_t snap_csum[32],
                                        const uint8_t cas_csum[32],
                                        const uint8_t salt[32],
                                        uint8_t out[32])
{
    stm_blake3_ctx *h = stm_blake3_new();
    if (!h) return STM_ENOMEM;
    stm_blake3_update(h, main_csum,  32);
    stm_blake3_update(h, alloc_csum, 32);
    stm_blake3_update(h, snap_csum,  32);
    stm_blake3_update(h, cas_csum,   32);
    stm_blake3_update(h, salt,       32);
    stm_blake3_final(h, out, 32);
    stm_blake3_free(h);
    return STM_OK;
}

/* ========================================================================= */
/* Ring rotation.                                                             */
/* ========================================================================= */

static inline uint32_t ring_label_for_gen(uint64_t gen)
{
    return (uint32_t)(gen % (uint64_t)STM_LABELS_PER_DEVICE);
}

static inline uint32_t ring_slot_for_gen(uint64_t gen)
{
    return (uint32_t)(gen % (uint64_t)STM_UB_SLOTS_PER_LABEL);
}

/* ========================================================================= */
/* Uberblock construction.                                                    */
/* ========================================================================= */

/* Build an uberblock in `out` from sync state + caller's inputs.
 * Fills pool_uuid / device_uuid / gen / txg / ub_alloc_root
 * (paddr + kind + bp_csum) + ub_merkle_root + ub_merkle_root_salt
 * for P4-1, and ub_key_schema[0..32] with the raw metadata key
 * for P4-3a. Allocator stats populate total_blocks / free_blocks. */
static void build_uberblock(stm_uberblock *out,
                              const stm_sync *s,
                              uint64_t new_gen,
                              uint64_t alloc_root_paddr,
                              const uint8_t alloc_root_csum[32],
                              const uint8_t merkle_root[32],
                              const stm_alloc_stats *astats)
{
    memset(out, 0, sizeof *out);

    out->ub_magic   = stm_store_le64(STM_UB_MAGIC);
    out->ub_version = stm_store_le32(STM_UB_VERSION);

    out->ub_pool_uuid[0]   = stm_store_le64(s->pool_uuid[0]);
    out->ub_pool_uuid[1]   = stm_store_le64(s->pool_uuid[1]);
    out->ub_device_uuid[0] = stm_store_le64(s->device_uuid[0]);
    out->ub_device_uuid[1] = stm_store_le64(s->device_uuid[1]);

    out->ub_gen         = stm_store_le64(new_gen);
    out->ub_txg         = stm_store_le64(new_gen);     /* chunk 6 keeps
                                                         * gen == txg */
    out->ub_device_count = stm_store_le16(1);
    out->ub_device_id    = stm_store_le16(0);

    /* Allocator tree root (paddr + kind + Merkle csum). */
    if (alloc_root_paddr != 0) {
        out->ub_alloc_root.bp_paddr = stm_store_le64(alloc_root_paddr);
        out->ub_alloc_root.bp_kind  = STM_BPTR_KIND_ALLOC;
        memcpy(out->ub_alloc_root.bp_csum, alloc_root_csum, 32);
    }

    /* P4-1: Merkle root + per-pool salt. Both are stored; mount-time
     * verifier recomputes the root against on-disk tree-root csums +
     * stored salt, and fails STM_ECORRUPT on mismatch. */
    memcpy(out->ub_merkle_root,        merkle_root,     32);
    memcpy(out->ub_merkle_root_salt,   s->merkle_salt,  32);

    /* P4-3a: metadata-encryption key at ub_key_schema[0..32].
     * Remaining 480 bytes of ub_key_schema are reserved for the
     * P4-4 PQ-hybrid wrapped key hierarchy. Stays zero in the MVP. */
    memcpy(out->ub_key_schema,         s->metadata_key, 32);

    /* Data-area totals (in blocks). */
    out->ub_total_blocks = stm_store_le64(astats->data_total_blocks);
    out->ub_free_blocks  = stm_store_le64(astats->data_free_blocks);

    /* Chunk 6 MVP: single-device, no redundancy, no encryption
     * schema. Those fields stay zero. */
    out->ub_redundancy_kind = STM_RED_NONE;
    out->ub_device_class    = STM_DEV_CLASS_UNSET;
    out->ub_device_role     = STM_DEV_ROLE_UNSET;
}

/* ========================================================================= */
/* Lifecycle.                                                                 */
/* ========================================================================= */

static stm_sync *sync_new(stm_bdev *d, stm_alloc *a,
                           const uint64_t pool_uuid[2],
                           const uint64_t device_uuid[2])
{
    stm_sync *s = calloc(1, sizeof *s);
    if (!s) return NULL;

    if (pthread_mutex_init(&s->lock, NULL) != 0) {
        free(s);
        return NULL;
    }

    s->bdev  = d;
    s->alloc = a;
    memcpy(s->pool_uuid,   pool_uuid,   sizeof s->pool_uuid);
    memcpy(s->device_uuid, device_uuid, sizeof s->device_uuid);
    return s;
}

stm_status stm_sync_create(stm_bdev *d, stm_alloc *a,
                            const uint64_t pool_uuid[2],
                            const uint64_t device_uuid[2],
                            stm_sync **out_sync)
{
    if (!d || !a || !pool_uuid || !device_uuid || !out_sync) return STM_EINVAL;

    stm_sync *s = sync_new(d, a, pool_uuid, device_uuid);
    if (!s) return STM_ENOMEM;

    /* Fresh pool: no uberblocks written yet. First stm_sync_commit
     * will write gen=1 (matches sync.tla: Mount bumps to
     * MaxDurableTxg+1 = 0+1 = 1). */
    s->current_gen = 0;

    /* P4-1: generate the pool's Merkle salt once, at format time.
     * The salt is persisted in ub_merkle_root_salt and stays stable
     * across the pool's lifetime. R8-P2-2: use libsodium via
     * stm_random_bytes instead of reading /dev/urandom directly —
     * gives us getrandom(2) on Linux, arc4random on BSD, and
     * consistent cross-platform behavior. */
    stm_random_bytes(s->merkle_salt, 32);

    /* P4-3a: generate the pool's metadata-encryption key. Like the
     * merkle salt, this is stable across the pool's lifetime for MVP.
     * Key rotation is P4-4's job. */
    stm_random_bytes(s->metadata_key, 32);

    /* P4-3b: install the crypt ctx on the allocator so its next
     * stm_alloc_commit encrypts every metadata node. Order matters:
     * this must happen BEFORE the first commit. sync_create returns
     * s without having committed yet — callers always commit through
     * stm_sync_commit which drives stm_alloc_commit. */
    stm_status cs = stm_alloc_set_crypt_ctx(a, s->metadata_key,
                                              s->pool_uuid, s->device_uuid);
    if (cs != STM_OK) {
        stm_sync_close(s);
        return cs;
    }

    *out_sync = s;
    return STM_OK;
}

stm_status stm_sync_open(stm_bdev *d, stm_alloc *a, stm_sync **out_sync)
{
    if (!d || !a || !out_sync) return STM_EINVAL;

    /* Scan for the authoritative uberblock. */
    stm_uberblock ub;
    uint32_t      live_label = 0, live_slot = 0;
    stm_status s = stm_sb_mount_scan(d, &ub, &live_label, &live_slot);
    if (s != STM_OK) return s;

    uint64_t durable_gen = stm_load_le64(ub.ub_gen);

    /* R7d P2-5: bound durable_gen so the +1 below doesn't wrap. */
    if (durable_gen >= UINT64_MAX - 1) return STM_ERANGE;

    uint64_t pool_uuid[2] = {
        stm_load_le64(ub.ub_pool_uuid[0]),
        stm_load_le64(ub.ub_pool_uuid[1]),
    };
    uint64_t device_uuid[2] = {
        stm_load_le64(ub.ub_device_uuid[0]),
        stm_load_le64(ub.ub_device_uuid[1]),
    };

    stm_sync *s2 = sync_new(d, a, pool_uuid, device_uuid);
    if (!s2) return STM_ENOMEM;

    /* MountGenBump (sync.tla): next commit's gen must be strictly
     * greater than any durable gen. Convention: `current_gen` is
     * the next-commit's-gen, so set it to durable_gen + 1. */
    s2->current_gen       = durable_gen + 1;
    s2->mount_max_durable = durable_gen;
    s2->live_label_idx    = live_label;
    s2->live_slot_idx     = live_slot;

    /* P4-1: carry Merkle state forward from the durable uberblock.
     * Salt is per-pool and stable; alloc_root_csum + merkle_root
     * are the last-committed values. */
    memcpy(s2->merkle_salt,      ub.ub_merkle_root_salt, 32);
    memcpy(s2->alloc_root_csum,  ub.ub_alloc_root.bp_csum, 32);
    memcpy(s2->merkle_root,      ub.ub_merkle_root,      32);

    /* P4-3a: recover the metadata key from ub_key_schema[0..32]. The
     * key is plaintext in the MVP — P4-4's key hierarchy will wrap
     * it (ML-KEM-768 + X25519 hybrid) and the unwrap path moves here. */
    memcpy(s2->metadata_key,     ub.ub_key_schema,       32);

    /* P4-3b: install the crypt ctx on the allocator so
     * stm_alloc_load_tree_at below can decrypt nodes. MUST happen
     * before load_tree_at. */
    stm_status cs = stm_alloc_set_crypt_ctx(a, s2->metadata_key,
                                              s2->pool_uuid, s2->device_uuid);
    if (cs != STM_OK) {
        stm_sync_close(s2);
        return cs;
    }

    /* P4-1: verify the on-disk ub_merkle_root is self-consistent
     * with the per-tree-root csums + salt recorded in the SAME
     * uberblock. An offline edit that swapped either the salt,
     * a tree-root csum, or the merkle_root field would break this.
     * (A coordinated edit to all three would pass this check but
     * fails the tree-node self-csum check on the first read.)
     *
     * R8-P1-1: on BLAKE3 OOM, refuse the mount entirely (rather
     * than computing an all-zero root which might coincidentally
     * match a tampered UB). */
    uint8_t  zeros32[32] = { 0 };
    uint8_t  recomputed[32];
    stm_status ms = compute_merkle_root(zeros32,     /* main */
                                          ub.ub_alloc_root.bp_csum,
                                          zeros32,     /* snap */
                                          zeros32,     /* cas  */
                                          ub.ub_merkle_root_salt,
                                          recomputed);
    if (ms != STM_OK) {
        stm_sync_close(s2);
        return ms;
    }
    if (memcmp(recomputed, ub.ub_merkle_root, 32) != 0) {
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }

    /* Rehydrate the allocator tree from ub_alloc_root. R7d P1-1:
     * a valid-csum uberblock with a nonzero ub_alloc_root.bp_paddr
     * but wrong kind indicates tampering — surface as STM_ECORRUPT
     * rather than silently returning a handle with an empty tree
     * that would alias the real (on-disk but unreferenced) data. */
    uint64_t alloc_root = stm_load_le64(ub.ub_alloc_root.bp_paddr);
    uint8_t  kind       = ub.ub_alloc_root.bp_kind;
    if (alloc_root != 0) {
        if (kind != STM_BPTR_KIND_ALLOC) {
            stm_sync_close(s2);
            return STM_ECORRUPT;
        }
        /* P4-1 / P4-3b: pass the expected csum + durable_gen through
         * so the tree loader verifies ciphertext BLAKE3 against
         * ub_alloc_root.bp_csum and AEAD-decrypts every node under
         * gen = ub_gen. */
        stm_status ls = stm_alloc_load_tree_at(a, alloc_root, durable_gen,
                                                  ub.ub_alloc_root.bp_csum);
        if (ls != STM_OK) {
            stm_sync_close(s2);
            return ls;
        }
        s2->alloc_root_paddr = alloc_root;
    }

    *out_sync = s2;
    return STM_OK;
}

void stm_sync_close(stm_sync *s)
{
    if (!s) return;
    /* P4-3b: wipe key material before free. The alloc's copy is
     * wiped independently in stm_alloc_close. */
    stm_ct_memzero(s->metadata_key, sizeof s->metadata_key);
    pthread_mutex_destroy(&s->lock);
    free(s);
}

/* ========================================================================= */
/* Commit.                                                                    */
/* ========================================================================= */

stm_status stm_sync_commit(stm_sync *s)
{
    if (!s) return STM_EINVAL;

    pthread_mutex_lock(&s->lock);

    /* Convention: s->current_gen = 0 means "fresh pool, no commits yet";
     * post-mount it's (max_durable + 1), i.e. next-commit's-gen. Force
     * the first commit to gen=1 so on-disk gens are strictly positive
     * (matches sync.tla's Mount bumping txg from 0 to 1). */
    uint64_t commit_gen = s->current_gen;
    if (commit_gen == 0) commit_gen = 1;

    /* R7d P2-5: refuse to commit if advancing current_gen would wrap
     * past UINT64_MAX. 2^64 commits is astronomically unreachable, but
     * bounded gen arithmetic is the project norm. */
    if (commit_gen >= UINT64_MAX) {
        pthread_mutex_unlock(&s->lock);
        return STM_ERANGE;
    }

    /* Phase: Reserve + Flush.
     *
     * stm_alloc_commit(committed_gen = commit_gen) persists the
     * allocator-tree to the bootstrap pool. It reserves node paddrs
     * (Reserve), writes nodes to the bdev (Flush), records PENDING
     * entries for the old tree's nodes (to be swept at the next
     * commit), and fsyncs via stm_bootstrap_commit. */
    stm_status s_alloc = stm_alloc_commit(s->alloc, commit_gen);
    if (s_alloc != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return s_alloc;
    }

    /* Pull the now-durable allocator tree root + its BLAKE3 self-csum
     * for ub_alloc_root.bp_paddr and .bp_csum (P4-1). */
    uint64_t alloc_root = 0;
    uint8_t  alloc_root_csum[32] = { 0 };
    stm_status sr = stm_alloc_get_tree_root(s->alloc,
                                              &alloc_root, alloc_root_csum);
    if (sr != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return sr;
    }

    /* Pull allocator stats for uberblock's total/free block counters. */
    stm_alloc_stats astats;
    sr = stm_alloc_stats_get(s->alloc, &astats);
    if (sr != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return sr;
    }

    /* P4-1: compute the pool Merkle root over the set of tree-root
     * csums + the per-pool salt. Phase 3 populates only the
     * allocator tree; main/snap/cas contribute zeros and will
     * populate in Phase 5+.
     *
     * R8-P1-1: refuse to commit if BLAKE3 context allocation fails.
     * Writing a zero merkle_root on OOM would match a future mount
     * that also OOMs → silent integrity bypass. */
    uint8_t zeros32[32] = { 0 };
    uint8_t new_merkle_root[32];
    stm_status ms = compute_merkle_root(zeros32,   /* main */
                                          alloc_root_csum,
                                          zeros32,   /* snap */
                                          zeros32,   /* cas  */
                                          s->merkle_salt,
                                          new_merkle_root);
    if (ms != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return ms;
    }

    /* Phase: Final — write the new uberblock to the next ring slot,
     * fsynced. This is the commit point per sync.tla. Ring rotation:
     * label = gen % 4, slot = gen % 63. */
    stm_uberblock ub;
    build_uberblock(&ub, s, commit_gen, alloc_root, alloc_root_csum,
                     new_merkle_root, &astats);

    uint32_t next_label = ring_label_for_gen(commit_gen);
    uint32_t next_slot  = ring_slot_for_gen(commit_gen);

    stm_status sw = stm_sb_label_write(s->bdev, next_label, next_slot, &ub);
    if (sw != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return sw;
    }

    /* Phase: Publish — advance in-RAM state. Done under our mutex so
     * any concurrent reader of stm_sync_info_get observes a
     * consistent snapshot. */
    s->current_gen       = commit_gen + 1;
    s->live_label_idx    = next_label;
    s->live_slot_idx     = next_slot;
    s->alloc_root_paddr  = alloc_root;
    memcpy(s->alloc_root_csum, alloc_root_csum, 32);
    memcpy(s->merkle_root,     new_merkle_root, 32);

    pthread_mutex_unlock(&s->lock);
    return STM_OK;
}

/* ========================================================================= */
/* Inspection.                                                                */
/* ========================================================================= */

stm_status stm_sync_info_get(const stm_sync *s, stm_sync_info *out)
{
    if (!s || !out) return STM_EINVAL;
    stm_sync *ms = (stm_sync *)s;
    pthread_mutex_lock(&ms->lock);

    out->current_gen           = s->current_gen;
    out->mount_max_durable_gen = s->mount_max_durable;
    out->live_label_idx        = s->live_label_idx;
    out->live_slot_idx         = s->live_slot_idx;
    out->alloc_root_paddr      = s->alloc_root_paddr;

    pthread_mutex_unlock(&ms->lock);
    return STM_OK;
}
