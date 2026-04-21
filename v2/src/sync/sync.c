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
#include <stratum/keyfile.h>
#include <stratum/keyschema.h>
#include <stratum/super.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* Dataset id used by the P4-4a single-pool-key MVP. Multi-dataset
 * arrives with P4-4c; for now every pool has dataset 0 implicitly. */
#define STM_SYNC_POOL_DATASET_ID   UINT64_C(0)
#define STM_SYNC_POOL_KEY_ID       UINT64_C(0)

/* Size of a hybrid-wrapped 32-byte dek. Pinned at build time so
 * caller buffers are deterministic. */
#define STM_SYNC_WRAPPED_KEY_LEN   (32u + STM_HYBRID_WRAP_OVERHEAD)
_Static_assert(STM_SYNC_WRAPPED_KEY_LEN <= STM_KEYSCHEMA_WRAPPED_MAX,
               "wrapped pool key must fit a keyschema entry");

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

    /* Gen at which the referenced alloc tree was AEAD-encrypted
     * (P4-3b R9 P0-1). May be less than current_gen when a
     * mount-claim UB advanced the durable gen past orphan data
     * without rewriting the tree. */
    uint64_t   alloc_root_gen;

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

    /* Per-pool metadata-encryption key.
     *
     * P4-3a generated this at sync_create and stored it in plaintext
     * in ub_key_schema[0..32]. P4-4a moved the on-disk storage into
     * the key-schema sub-tree in PQ-hybrid-wrapped form; the raw key
     * stays in RAM (needed by every btree_store encrypt/decrypt) but
     * never hits disk in plaintext. */
    uint8_t           metadata_key[32];

    /* P4-4a: key-schema sub-tree holding the wrapped pool key (and,
     * in P4-4c, per-dataset keys + retired keys). Owned by
     * stm_sync; closed on stm_sync_close. */
    stm_keyschema    *keyschema;

    /* Durable root of the key-schema sub-tree — mirror of the bptr
     * stored in ub_key_schema.ks_root. Zero/zeros before the first
     * commit. */
    uint64_t          keyschema_root_paddr;
    uint8_t           keyschema_root_csum[32];
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
                                        const uint8_t keyschema_csum[32],
                                        const uint8_t salt[32],
                                        uint8_t out[32])
{
    stm_blake3_ctx *h = stm_blake3_new();
    if (!h) return STM_ENOMEM;
    stm_blake3_update(h, main_csum,      32);
    stm_blake3_update(h, alloc_csum,     32);
    stm_blake3_update(h, snap_csum,      32);
    stm_blake3_update(h, cas_csum,       32);
    stm_blake3_update(h, keyschema_csum, 32);
    stm_blake3_update(h, salt,           32);
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
 * for P4-1, ub_alloc_root_gen for P4-3b R9 P0-1, and
 * ub_key_schema[0..32] with the raw metadata key for P4-3a.
 * Allocator stats populate total_blocks / free_blocks.
 *
 * `alloc_root_gen` is the gen at which the referenced tree was
 * AEAD-encrypted. Usually equals `new_gen` (a fresh tree commit),
 * but a mount-claim UB advances new_gen past durable gen without
 * rewriting the tree — in that case alloc_root_gen carries the
 * OLDER gen so AEAD decrypt still works. */
static void build_uberblock(stm_uberblock *out,
                              const stm_sync *s,
                              uint64_t new_gen,
                              uint64_t alloc_root_paddr,
                              const uint8_t alloc_root_csum[32],
                              uint64_t alloc_root_gen,
                              uint64_t keyschema_root_paddr,
                              const uint8_t keyschema_root_csum[32],
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
    out->ub_alloc_root_gen = stm_store_le64(alloc_root_gen);

    /* P4-1: Merkle root + per-pool salt. Both are stored; mount-time
     * verifier recomputes the root against on-disk tree-root csums +
     * stored salt, and fails STM_ECORRUPT on mismatch. */
    memcpy(out->ub_merkle_root,        merkle_root,     32);
    memcpy(out->ub_merkle_root_salt,   s->merkle_salt,  32);

    /* P4-4a: key-schema sub-tree pointer in ub_key_schema. Packed
     * via the v4 header format (magic 'TSCH' + version + flags +
     * bptr). Tree nodes themselves are plaintext Merkle-covered;
     * wrapped keys inside leaves are what's cryptographically
     * protected. */
    stm_ub_key_schema_hdr ks_hdr;
    memset(&ks_hdr, 0, sizeof ks_hdr);
    ks_hdr.ks_magic   = STM_UB_KEY_SCHEMA_MAGIC;
    ks_hdr.ks_version = STM_UB_KEY_SCHEMA_VERSION;
    ks_hdr.ks_flags   = 0;
    if (keyschema_root_paddr != 0) {
        ks_hdr.ks_root.bp_paddr = stm_store_le64(keyschema_root_paddr);
        ks_hdr.ks_root.bp_kind  = STM_BPTR_KIND_KEYSCHEMA;
        memcpy(ks_hdr.ks_root.bp_csum, keyschema_root_csum, 32);
    }
    stm_ub_key_schema_pack(&ks_hdr, out->ub_key_schema);

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
                            const stm_hybrid_keys *wk,
                            stm_sync **out_sync)
{
    if (!d || !a || !pool_uuid || !device_uuid || !out_sync) return STM_EINVAL;
    /* P4-4a: wk is mandatory — the pool's metadata key must be
     * PQ-hybrid-wrapped before persistence, so the wrap-public-key
     * half has to be available at create time. */
    if (!wk) return STM_EINVAL;

    /* R9 P1-1: the rest of this function calls stm_random_bytes /
     * stm_aead_* transitively via stm_alloc_set_crypt_ctx; libsodium
     * must be initialized. Idempotent. */
    stm_status ci = stm_crypto_init();
    if (ci != STM_OK) return ci;

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
     * Key rotation is P4-4c's job. */
    stm_random_bytes(s->metadata_key, 32);

    /* P4-4a: PQ-hybrid-wrap the freshly-minted metadata key and park
     * it in a new in-RAM key-schema handle. The wrapped bytes
     * persist to disk on the first commit (via stm_keyschema_commit);
     * the raw `metadata_key` never leaves RAM. */
    {
        stm_bootstrap *boot = stm_alloc_bootstrap(a);
        if (!boot) { stm_sync_close(s); return STM_EINVAL; }
        stm_keyschema *ks = NULL;
        stm_status ks_s = stm_keyschema_create(d, boot, &ks);
        if (ks_s != STM_OK) { stm_sync_close(s); return ks_s; }
        s->keyschema = ks;

        uint8_t wrapped[STM_SYNC_WRAPPED_KEY_LEN];
        size_t  wrapped_len = 0;
        stm_status ws = stm_hybrid_wrap(wk->pk,
                                           s->metadata_key, 32,
                                           wrapped, &wrapped_len);
        if (ws != STM_OK) { stm_sync_close(s); return ws; }
        if (wrapped_len != STM_SYNC_WRAPPED_KEY_LEN) {
            stm_ct_memzero(wrapped, sizeof wrapped);
            stm_sync_close(s);
            return STM_EBACKEND;
        }
        ws = stm_keyschema_insert_wrapped(ks,
                                            STM_SYNC_POOL_DATASET_ID,
                                            STM_SYNC_POOL_KEY_ID,
                                            STM_KS_STATE_CURRENT,
                                            wrapped, wrapped_len);
        stm_ct_memzero(wrapped, sizeof wrapped);
        if (ws != STM_OK) { stm_sync_close(s); return ws; }
    }

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

stm_status stm_sync_open(stm_bdev *d, stm_alloc *a,
                          const stm_hybrid_keys *wk,
                          stm_sync **out_sync)
{
    if (!d || !a || !out_sync) return STM_EINVAL;
    /* P4-4a: unwrap the pool key via wk->sk. Mandatory. */
    if (!wk) return STM_EINVAL;

    /* R9 P1-1: make sure libsodium is up before any crypto op. */
    stm_status ci = stm_crypto_init();
    if (ci != STM_OK) return ci;

    /* Scan for the authoritative uberblock. */
    stm_uberblock ub;
    uint32_t      live_label = 0, live_slot = 0;
    stm_status s = stm_sb_mount_scan(d, &ub, &live_label, &live_slot);
    if (s != STM_OK) return s;

    uint64_t durable_gen    = stm_load_le64(ub.ub_gen);
    uint64_t alloc_root_gen = stm_load_le64(ub.ub_alloc_root_gen);

    /* R9 P0-1: bound durable_gen so the +2 mount-claim dance below
     * doesn't wrap. Commit at gen UINT64_MAX - 2 already refuses
     * via R7d P2-5; a mount that would need to write a claim UB
     * at UINT64_MAX - 1 leaves no headroom for the first commit at
     * UINT64_MAX. Refuse early. */
    if (durable_gen >= UINT64_MAX - 2) return STM_ERANGE;

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

    /* R9 P0-1 — mount-claim UB protocol.
     *
     * sync.tla's MountGenBump models MaxDurableTxg as the max over
     * BOTH the UB ring AND the durable data area. The pre-fix
     * implementation only inspected the UB ring, so orphan
     * encrypted metadata writes at gen=durable_gen+1 that happened
     * to flush to disk before the UB (e.g. page-cache eviction
     * preceding fsync) went unnoticed — and the next commit reused
     * gen=durable_gen+1 for a DIFFERENT plaintext at the same
     * paddr → AEAD nonce reuse under AEGIS-256, a cryptographic
     * catastrophe.
     *
     * Fix: at mount, durably claim gen=durable_gen+1 by writing a
     * "mount-claim" uberblock at that gen with the SAME tree roots
     * as the durable UB (no commit happening yet — just advancing
     * the gen counter). `ub_alloc_root_gen` carries the ORIGINAL
     * encryption gen so AEAD decrypt on subsequent reads still
     * matches. current_gen then starts at durable_gen+2, one past
     * the claim.
     *
     * If this mount itself crashes between the claim UB write and
     * the first commit: the next mount observes durable_gen'=
     * durable_gen+1 and claims durable_gen+2, so the same-gen
     * problem cannot recur. Consecutive crashed mounts burn one
     * gen each — UINT64_MAX / 2^? astronomic. */
    s2->current_gen       = durable_gen + 2;
    s2->mount_max_durable = durable_gen;
    s2->live_label_idx    = live_label;
    s2->live_slot_idx     = live_slot;
    s2->alloc_root_gen    = alloc_root_gen;

    /* P4-1: carry Merkle state forward from the durable uberblock.
     * Salt is per-pool and stable; alloc_root_csum + merkle_root
     * are the last-committed values. */
    memcpy(s2->merkle_salt,      ub.ub_merkle_root_salt, 32);
    memcpy(s2->alloc_root_csum,  ub.ub_alloc_root.bp_csum, 32);
    memcpy(s2->merkle_root,      ub.ub_merkle_root,      32);

    /* P4-4a: unpack the key-schema header, load the sub-tree into
     * a keyschema handle, find the CURRENT wrapped key for dataset
     * 0, and unwrap it with wk->sk. The raw metadata_key stays in
     * RAM and gets installed on the allocator below. */
    stm_ub_key_schema_hdr ks_hdr;
    stm_status hs = stm_ub_key_schema_unpack(ub.ub_key_schema, &ks_hdr);
    if (hs != STM_OK) {
        stm_sync_close(s2);
        return hs;
    }
    uint64_t ks_root_paddr = stm_load_le64(ks_hdr.ks_root.bp_paddr);
    uint8_t  ks_root_kind  = ks_hdr.ks_root.bp_kind;
    /* A pool that was sync_create'd but never sync_commit'd would
     * have no keyschema on disk yet — but also no durable uberblock,
     * so mount_scan above would have returned STM_ENOENT. A valid
     * durable UB at v4 MUST have a non-zero keyschema bptr (or,
     * conservatively, we treat zero as corruption). */
    if (ks_root_paddr == 0 ||
        ks_root_kind  != STM_BPTR_KIND_KEYSCHEMA) {
        stm_sync_close(s2);
        return STM_ECORRUPT;
    }

    stm_bootstrap *boot = stm_alloc_bootstrap(a);
    if (!boot) { stm_sync_close(s2); return STM_EINVAL; }
    stm_status kos = stm_keyschema_open(d, boot, &s2->keyschema);
    if (kos != STM_OK) { stm_sync_close(s2); return kos; }
    kos = stm_keyschema_load_at(s2->keyschema, ks_root_paddr,
                                  ks_hdr.ks_root.bp_csum);
    if (kos != STM_OK) { stm_sync_close(s2); return kos; }
    s2->keyschema_root_paddr = ks_root_paddr;
    memcpy(s2->keyschema_root_csum, ks_hdr.ks_root.bp_csum, 32);

    uint8_t wrapped[STM_SYNC_WRAPPED_KEY_LEN];
    size_t  wrapped_len = 0;
    uint64_t found_key_id = 0;
    kos = stm_keyschema_lookup_current(s2->keyschema,
                                         STM_SYNC_POOL_DATASET_ID,
                                         &found_key_id,
                                         wrapped, sizeof wrapped, &wrapped_len);
    if (kos != STM_OK) {
        stm_ct_memzero(wrapped, sizeof wrapped);
        stm_sync_close(s2);
        return kos;
    }

    size_t dek_out_len = 0;
    stm_status us = stm_hybrid_unwrap(wk->sk, wrapped, wrapped_len,
                                        s2->metadata_key, &dek_out_len);
    stm_ct_memzero(wrapped, sizeof wrapped);
    if (us != STM_OK) {
        stm_sync_close(s2);
        return us;
    }
    if (dek_out_len != 32) {
        stm_sync_close(s2);
        return STM_EBACKEND;
    }

    /* P4-3b: install the crypt ctx on the allocator so
     * stm_alloc_load_tree_at below can decrypt nodes. MUST happen
     * before load_tree_at. */
    stm_status cs = stm_alloc_set_crypt_ctx(a, s2->metadata_key,
                                              s2->pool_uuid, s2->device_uuid);
    if (cs != STM_OK) {
        stm_sync_close(s2);
        return cs;
    }

    /* P4-1 / P4-4a: verify the on-disk ub_merkle_root is
     * self-consistent with the per-tree-root csums (now including
     * the key-schema root) + salt recorded in the SAME uberblock.
     * An offline edit that swapped any of those inputs breaks this.
     *
     * R8-P1-1: on BLAKE3 OOM, refuse the mount entirely. */
    uint8_t  zeros32[32] = { 0 };
    uint8_t  recomputed[32];
    stm_status ms = compute_merkle_root(zeros32,     /* main */
                                          ub.ub_alloc_root.bp_csum,
                                          zeros32,     /* snap */
                                          zeros32,     /* cas  */
                                          ks_hdr.ks_root.bp_csum,
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
        /* P4-1 / P4-3b: pass the expected csum + alloc_root_gen
         * through so the tree loader verifies ciphertext BLAKE3
         * against ub_alloc_root.bp_csum and AEAD-decrypts every
         * node under the ORIGINAL encryption gen (which is NOT
         * necessarily ub_gen if a prior mount wrote a claim UB). */
        stm_status ls = stm_alloc_load_tree_at(a, alloc_root, alloc_root_gen,
                                                  ub.ub_alloc_root.bp_csum);
        if (ls != STM_OK) {
            stm_sync_close(s2);
            return ls;
        }
        s2->alloc_root_paddr = alloc_root;
    }

    /* Write the mount-claim UB at durable_gen+1. Same roots +
     * merkle state + alloc_root_gen as the durable UB; only ub_gen
     * advances. Fsynced via stm_sb_label_write. After this write
     * returns, mount has durably claimed gen=durable_gen+1 — the
     * next commit at current_gen (= durable_gen+2) cannot collide
     * with any orphan metadata writes from a prior crashed mount.
     *
     * Read-only mount skips the claim UB (the bdev refuses writes
     * with STM_EROFS). Safe because an RO mount never issues any
     * new AEAD write — `current_gen` is unused. We stash it anyway
     * for stm_sync_info_get callers that want to know "what the
     * next RW mount would start at." */
    {
        stm_alloc_stats astats_claim;
        stm_status gs = stm_alloc_stats_get(a, &astats_claim);
        if (gs != STM_OK) {
            stm_sync_close(s2);
            return gs;
        }
        stm_uberblock claim_ub;
        build_uberblock(&claim_ub, s2,
                         /*new_gen=*/           durable_gen + 1,
                         /*alloc_root=*/        alloc_root,
                         /*alloc_csum=*/        ub.ub_alloc_root.bp_csum,
                         /*alloc_root_gen=*/    alloc_root_gen,
                         /*keyschema_root=*/    ks_root_paddr,
                         /*keyschema_csum=*/    ks_hdr.ks_root.bp_csum,
                         /*merkle_root=*/       ub.ub_merkle_root,
                         &astats_claim);
        uint32_t lbl  = ring_label_for_gen(durable_gen + 1);
        uint32_t slot = ring_slot_for_gen(durable_gen + 1);
        stm_status cw = stm_sb_label_write(d, lbl, slot, &claim_ub);
        if (cw == STM_OK) {
            s2->live_label_idx = lbl;
            s2->live_slot_idx  = slot;
        } else if (cw != STM_EROFS) {
            stm_sync_close(s2);
            return cw;
        }
        /* For STM_EROFS we leave live_label/slot pointing at the
         * DURABLE UB (set earlier from mount_scan). */
        s2->alloc_root_paddr = alloc_root;
        memcpy(s2->alloc_root_csum, ub.ub_alloc_root.bp_csum, 32);
        memcpy(s2->merkle_root,     ub.ub_merkle_root,        32);
    }

    *out_sync = s2;
    return STM_OK;
}

void stm_sync_close(stm_sync *s)
{
    if (!s) return;
    /* P4-4a: close the keyschema (frees its in-RAM entries too). */
    if (s->keyschema) stm_keyschema_close(s->keyschema);
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
     * Order matters — key-schema first, allocator second. Both
     * share the bootstrap pool for node storage; bootstrap_commit
     * runs at the END of stm_alloc_commit (fsyncs the bitmap).
     * If we ran alloc_commit first, keyschema's subsequent reserves
     * would stamp the bitmap in RAM but never reach durable state,
     * and the next mount would see keyschema's paddr as free — a
     * recipe for paddr collisions on the next commit.
     *
     * P4-4a: commit the key-schema sub-tree. For P4-4a the schema
     * state is usually unchanged across commits (no rotation yet),
     * but we re-serialize unconditionally — the node is tiny by
     * metadata standards (1 × 128 KiB) and the always-fresh-paddr
     * shape matches the alloc-tree's commit pattern (simpler
     * reasoning, no special "clean" skip path). */
    uint64_t ks_root_paddr = 0;
    uint8_t  ks_root_csum[32] = { 0 };
    stm_status kcs = stm_keyschema_commit(s->keyschema, commit_gen,
                                            &ks_root_paddr, ks_root_csum);
    if (kcs != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return kcs;
    }

    /* stm_alloc_commit(committed_gen = commit_gen) persists the
     * allocator-tree to the bootstrap pool AND fsyncs via
     * stm_bootstrap_commit at the end — finalizing both alloc's
     * and keyschema's reserves/frees in one durable transaction. */
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

    /* P4-1 / P4-4a: compute the pool Merkle root over all five
     * sub-tree csums + the per-pool salt. Phase 4 populates
     * allocator + key-schema; main/snap/cas contribute zeros and
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
                                          ks_root_csum,
                                          s->merkle_salt,
                                          new_merkle_root);
    if (ms != STM_OK) {
        pthread_mutex_unlock(&s->lock);
        return ms;
    }

    /* Phase: Final — write the new uberblock to the next ring slot,
     * fsynced. This is the commit point per sync.tla. Ring rotation:
     * label = gen % 4, slot = gen % 63.
     *
     * R9 P0-1: alloc_root_gen = commit_gen because this commit DID
     * rewrite the tree under commit_gen's AEAD nonce. */
    stm_uberblock ub;
    build_uberblock(&ub, s, commit_gen,
                     alloc_root, alloc_root_csum, commit_gen,
                     ks_root_paddr, ks_root_csum,
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
    s->current_gen           = commit_gen + 1;
    s->live_label_idx        = next_label;
    s->live_slot_idx         = next_slot;
    s->alloc_root_paddr      = alloc_root;
    s->alloc_root_gen        = commit_gen;
    s->keyschema_root_paddr  = ks_root_paddr;
    memcpy(s->alloc_root_csum,     alloc_root_csum, 32);
    memcpy(s->keyschema_root_csum, ks_root_csum,   32);
    memcpy(s->merkle_root,         new_merkle_root, 32);

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
